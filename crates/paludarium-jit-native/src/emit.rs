//! Cranelift IR of a block's forms. Safe code only: the function it builds
//! reads and writes the registers through the pointer it is given, and
//! reaches guest memory only through the helpers of [`crate::exec`].
//!
//! Each form means what `paludarium_cpu`'s interpreter does with it
//! (`exec/fast.rs`). A form that can fail changes no register before the
//! helper that can fail has succeeded, so leaving before it leaves the
//! state as the interpreter expects.

use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::{
    AbiParam, Function, InstBuilder, MemFlagsData, Signature, Type, UserFuncName, Value, types,
};
use cranelift_codegen::isa::CallConv;
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use paludarium_cpu::compile::{Address, Alu, Fast, Form, Shift, Source, Unary};
use paludarium_cpu::flag;
use paludarium_decoder::{Condition, Mnemonic, Register, Segment};

/// Words of the register block the code runs on: the general registers,
/// then RFLAGS, RIP, the FS and GS bases (read only), and the xmm
/// registers, each as its low word and its high word.
pub(crate) const RFLAGS: usize = 16;
pub(crate) const RIP: usize = 17;
pub(crate) const FS_BASE: usize = 18;
pub(crate) const GS_BASE: usize = 19;
pub(crate) const XMM: usize = 20;
pub(crate) const WORDS: usize = XMM + 32;

/// What a helper reports: the access was made, it failed (nothing was
/// done), or it was made and the code generation changed.
pub(crate) const DONE: i64 = 0;
pub(crate) const FAILED: i64 = 1;
pub(crate) const CODE_CHANGED: i64 = 2;

/// The addresses of the helpers the code calls.
#[derive(Clone, Copy)]
pub(crate) struct Helpers {
    /// `(context, address, size) -> (value, status)`.
    pub load: u64,
    /// `(context, address, size, value) -> status`.
    pub store: u64,
    /// `(context, address, to) -> status`: 16 bytes into the two words at
    /// `to`, which it leaves alone when it fails.
    pub load128: u64,
    /// `(context, address, from) -> status`: the two words at `from`.
    pub store128: u64,
    /// `(context, address, size, kind, a, b) -> (old, status)`: a locked
    /// exchange (`kind` 0) or compare and exchange.
    pub atomic: u64,
}

const I64: Type = types::I64;

fn mask(size: u8) -> i64 {
    paludarium_cpu::size_mask(size) as i64
}

fn sign(size: u8) -> i64 {
    (1u64 << (u32::from(size) * 8 - 1)) as i64
}

struct Emitter<'a, 'b> {
    b: &'a mut FunctionBuilder<'b>,
    /// The register block: registers are read and written there, so that
    /// leaving needs nothing but the count and RIP.
    registers: Value,
    /// Takes the count and RIP to leave with.
    exit: cranelift_codegen::ir::Block,
    context: Value,
    fs_base: Value,
    gs_base: Value,
    helpers: Helpers,
    load_sig: cranelift_codegen::ir::SigRef,
    store_sig: cranelift_codegen::ir::SigRef,
    move128_sig: cranelift_codegen::ir::SigRef,
    atomic_sig: cranelift_codegen::ir::SigRef,
    /// Whether the code reaches the xmm words of the register block.
    vector: bool,
}

impl Emitter<'_, '_> {
    fn constant(&mut self, v: i64) -> Value {
        self.b.ins().iconst(I64, v)
    }

    /// Leaves with `count` instructions run and RIP at `rip`.
    fn leave(&mut self, count: usize, rip: Value) {
        let count = self.constant(count as i64);
        self.b.ins().jump(self.exit, &[count.into(), rip.into()]);
    }

    fn leave_at(&mut self, count: usize, rip: u64) {
        let rip = self.constant(rip as i64);
        self.leave(count, rip);
    }

    /// Goes on in a new block when `status` is not [`FAILED`], and leaves
    /// with `count` run at `rip` otherwise.
    fn unless_failed(&mut self, status: Value, count: usize, rip: u64) {
        let failed = self.b.create_block();
        let go_on = self.b.create_block();
        let is_failed = self.b.ins().icmp_imm_s(IntCC::Equal, status, FAILED);
        self.b.ins().brif(is_failed, failed, &[], go_on, &[]);
        self.b.switch_to_block(failed);
        self.leave_at(count, rip);
        self.b.switch_to_block(go_on);
    }

    /// Leaves after the instruction just emitted, the `count`th, when
    /// `status` says the code changed.
    fn unless_changed(&mut self, status: Value, count: usize, next: u64) {
        let changed = self.b.create_block();
        let go_on = self.b.create_block();
        let is_changed = self.b.ins().icmp_imm_s(IntCC::Equal, status, CODE_CHANGED);
        self.b.ins().brif(is_changed, changed, &[], go_on, &[]);
        self.b.switch_to_block(changed);
        self.leave_at(count, next);
        self.b.switch_to_block(go_on);
    }

    fn word(&mut self, word: usize) -> Value {
        self.vector |= word >= XMM;
        self.b.ins().load(
            I64,
            MemFlagsData::trusted(),
            self.registers,
            (word * 8) as i32,
        )
    }

    fn set_word(&mut self, word: usize, v: Value) {
        self.vector |= word >= XMM;
        self.b.ins().store(
            MemFlagsData::trusted(),
            v,
            self.registers,
            (word * 8) as i32,
        );
    }

    fn gpr(&mut self, index: u8) -> Value {
        self.word(usize::from(index & 15))
    }

    fn set_gpr(&mut self, index: u8, v: Value) {
        self.set_word(usize::from(index & 15), v);
    }

    /// The value of `r`, masked to its size.
    fn read(&mut self, r: Register) -> Value {
        let (index, size) = match r {
            Register::Gpr { index, size } => (index, size),
            Register::GprHigh8 { index } => {
                let v = self.gpr(index & 3);
                let v = self.b.ins().ushr_imm_s(v, 8);
                return self.b.ins().band_imm_s(v, 0xff);
            }
            _ => unreachable!("forms hold general or high-byte registers only"),
        };
        let v = self.gpr(index);
        if size == 8 {
            v
        } else {
            self.b.ins().band_imm_s(v, mask(size))
        }
    }

    /// Writes `v` to `r` as `write_reg` does: whole, zero-extended from
    /// 32 bits, or merged into the low 8 or 16 bits or into bits 8 to 15.
    fn write(&mut self, r: Register, v: Value) {
        let (index, size) = match r {
            Register::Gpr { index, size } => (index, size),
            Register::GprHigh8 { index } => {
                let old = self.gpr(index & 3);
                let kept = self.b.ins().band_imm_s(old, !0xff00);
                let low = self.b.ins().band_imm_s(v, 0xff);
                let new = self.b.ins().ishl_imm_s(low, 8);
                let value = self.b.ins().bor(kept, new);
                self.set_gpr(index & 3, value);
                return;
            }
            _ => unreachable!("forms hold general or high-byte registers only"),
        };
        let value = match size {
            8 => v,
            4 => self.b.ins().band_imm_s(v, mask(4)),
            _ => {
                let old = self.gpr(index);
                let kept = self.b.ins().band_imm_s(old, !mask(size));
                let new = self.b.ins().band_imm_s(v, mask(size));
                self.b.ins().bor(kept, new)
            }
        };
        self.set_gpr(index, value);
    }

    /// `v`, masked to `size` bytes, sign-extended from them.
    fn sign_extended(&mut self, v: Value, size: u8) -> Value {
        if size == 8 {
            return v;
        }
        let up = 64 - i64::from(size) * 8;
        let high = self.b.ins().ishl_imm_s(v, up);
        self.b.ins().sshr_imm_s(high, up)
    }

    /// `v` masked to `size` bytes.
    fn masked(&mut self, v: Value, size: u8) -> Value {
        if size == 8 {
            v
        } else {
            self.b.ins().band_imm_s(v, mask(size))
        }
    }

    fn source(&mut self, src: Source, size: u8) -> Value {
        match src {
            Source::Register(r) => {
                let v = self.read(r);
                if size == 8 {
                    v
                } else {
                    self.b.ins().band_imm_s(v, mask(size))
                }
            }
            Source::Immediate(v) => self.constant((v & paludarium_cpu::size_mask(size)) as i64),
        }
    }

    /// The effective address of `m`, without the segment base.
    fn address(&mut self, m: &Address) -> Value {
        let mut ea = self.constant(m.displacement as i64);
        if let Some(base) = m.base {
            let v = self.gpr(base);
            ea = self.b.ins().iadd(ea, v);
        }
        if let Some(index) = m.index {
            let v = self.gpr(index);
            let scaled = if m.scale == 1 {
                v
            } else {
                self.b.ins().imul_imm_s(v, i64::from(m.scale))
            };
            ea = self.b.ins().iadd(ea, scaled);
        }
        if m.address_size_32 {
            ea = self.b.ins().band_imm_s(ea, mask(4));
        }
        ea
    }

    fn linear(&mut self, m: &Address) -> Value {
        let ea = self.address(m);
        match m.segment {
            Segment::Fs => self.b.ins().iadd(ea, self.fs_base),
            Segment::Gs => self.b.ins().iadd(ea, self.gs_base),
            Segment::None => ea,
        }
    }

    /// Loads `size` bytes at `address`: the value and the status.
    fn load(&mut self, address: Value, size: u8) -> (Value, Value) {
        let size = self.constant(i64::from(size.min(8)));
        let callee = self.constant(self.helpers.load as i64);
        let call =
            self.b
                .ins()
                .call_indirect(self.load_sig, callee, &[self.context, address, size]);
        let results = self.b.inst_results(call);
        (results[0], results[1])
    }

    fn store(&mut self, address: Value, size: u8, value: Value) -> Value {
        let size = self.constant(i64::from(size.min(8)));
        let callee = self.constant(self.helpers.store as i64);
        let call = self.b.ins().call_indirect(
            self.store_sig,
            callee,
            &[self.context, address, size, value],
        );
        self.b.inst_results(call)[0]
    }

    /// The locked access of `kind` (0: exchange with `a`; 1: compare with
    /// `a` and exchange with `b`) of `size` bytes at `address`: the old
    /// value and the status.
    fn atomic(
        &mut self,
        address: Value,
        size: u8,
        kind: i64,
        a: Value,
        b: Value,
    ) -> (Value, Value) {
        let size = self.constant(i64::from(size));
        let kind = self.constant(kind);
        let callee = self.constant(self.helpers.atomic as i64);
        let call = self.b.ins().call_indirect(
            self.atomic_sig,
            callee,
            &[self.context, address, size, kind, a, b],
        );
        let results = self.b.inst_results(call);
        (results[0], results[1])
    }

    /// The address of xmm register `n` in the register block.
    fn xmm_slot(&mut self, n: u8) -> Value {
        self.vector = true;
        let offset = ((XMM + 2 * usize::from(n & 15)) * 8) as i64;
        self.b.ins().iadd_imm_s(self.registers, offset)
    }

    /// Moves 16 bytes between `address` and xmm register `n` with
    /// `helper` (`load128` or `store128`); leaves at `rip` before it when
    /// `aligned` and the address is not a multiple of 16.
    fn move128(
        &mut self,
        helper: u64,
        address: Value,
        n: u8,
        aligned: bool,
        count: usize,
        rip: u64,
    ) -> Value {
        if aligned {
            let low = self.b.ins().band_imm_s(address, 15);
            let off = self.b.ins().icmp_imm_s(IntCC::NotEqual, low, 0);
            let wide = self.b.ins().uextend(I64, off);
            // FAILED is 1: a misaligned address fails as the helper would.
            self.unless_failed(wide, count, rip);
        }
        let slot = self.xmm_slot(n);
        let callee = self.constant(helper as i64);
        let call =
            self.b
                .ins()
                .call_indirect(self.move128_sig, callee, &[self.context, address, slot]);
        self.b.inst_results(call)[0]
    }

    /// The low 32 bits of `v` with byte `n` moved to byte `2n`, the
    /// other bytes 0.
    fn spread_bytes(&mut self, v: Value) -> Value {
        let t = self.b.ins().band_imm_s(v, 0xffff_ffff);
        let up = self.b.ins().ishl_imm_s(t, 16);
        let t = self.b.ins().bor(t, up);
        let t = self.b.ins().band_imm_s(t, 0x0000_ffff_0000_ffff);
        let up = self.b.ins().ishl_imm_s(t, 8);
        let t = self.b.ins().bor(t, up);
        self.b.ins().band_imm_s(t, 0x00ff_00ff_00ff_00ff)
    }

    /// The low 32 bits of `v` with word `n` moved to word `2n`, the other
    /// words 0.
    fn spread_words(&mut self, v: Value) -> Value {
        let t = self.b.ins().band_imm_s(v, 0xffff_ffff);
        let up = self.b.ins().ishl_imm_s(t, 16);
        let t = self.b.ins().bor(t, up);
        self.b.ins().band_imm_s(t, 0x0000_ffff_0000_ffff)
    }

    /// The interleave of the low halves of `a` and `b` (64-bit words) in
    /// lanes of `bits`, as `punpckl` has it for one word of output: the
    /// low 32 bits of each when `upper` is false, the high 32 otherwise.
    fn interleave(&mut self, a: Value, b: Value, bits: u32, upper: bool) -> Value {
        let (a, b) = if upper {
            (
                self.b.ins().ushr_imm_s(a, 32),
                self.b.ins().ushr_imm_s(b, 32),
            )
        } else {
            (a, b)
        };
        match bits {
            8 => {
                let a = self.spread_bytes(a);
                let b = self.spread_bytes(b);
                let b = self.b.ins().ishl_imm_s(b, 8);
                self.b.ins().bor(a, b)
            }
            16 => {
                let a = self.spread_words(a);
                let b = self.spread_words(b);
                let b = self.b.ins().ishl_imm_s(b, 16);
                self.b.ins().bor(a, b)
            }
            _ => {
                let a = self.b.ins().band_imm_s(a, 0xffff_ffff);
                let b = self.b.ins().ishl_imm_s(b, 32);
                self.b.ins().bor(a, b)
            }
        }
    }

    /// The `source`-bit signed lanes of the 128-bit value `(low, high)`
    /// saturated to `destination` bits (unsigned when `unsigned`), packed
    /// into one 64-bit word, as `sse::pack` has them.
    fn pack(
        &mut self,
        low: Value,
        high: Value,
        source: u32,
        destination: u32,
        unsigned: bool,
    ) -> Value {
        let lanes = 128 / source;
        let per_word = lanes / 2;
        let (least, most) = if unsigned {
            (0i64, (1i64 << destination) - 1)
        } else {
            (
                -(1i64 << (destination - 1)),
                (1i64 << (destination - 1)) - 1,
            )
        };
        let least = self.constant(least);
        let most = self.constant(most);
        let mut out = self.constant(0);
        for n in 0..lanes {
            let word = if n < per_word { low } else { high };
            let shift = i64::from((n % per_word) * source);
            let lane = if shift == 0 {
                word
            } else {
                self.b.ins().ushr_imm_s(word, shift)
            };
            let up = i64::from(64 - source);
            let lane = self.b.ins().ishl_imm_s(lane, up);
            let lane = self.b.ins().sshr_imm_s(lane, up);
            let lane = self.b.ins().smax(lane, least);
            let lane = self.b.ins().smin(lane, most);
            let lane = self.b.ins().band_imm_s(lane, (1i64 << destination) - 1);
            let lane = self.b.ins().ishl_imm_s(lane, i64::from(n * destination));
            out = self.b.ins().bor(out, lane);
        }
        out
    }

    /// The top bits of the 8 bytes of `w`, as an 8-bit mask: the bits,
    /// moved to the low bit of each byte, multiplied so that bit `56 + n`
    /// collects byte `n`'s without any carry.
    fn byte_signs(&mut self, w: Value) -> Value {
        let t = self.b.ins().ushr_imm_s(w, 7);
        let t = self.b.ins().band_imm_s(t, 0x0101_0101_0101_0101);
        let t = self.b.ins().imul_imm_s(t, 0x0102_0408_1020_4080);
        self.b.ins().ushr_imm_s(t, 56)
    }

    /// The two words of xmm register `n`.
    fn xmm_words(&mut self, n: u8) -> (Value, Value) {
        let w = XMM + 2 * usize::from(n & 15);
        (self.word(w), self.word(w + 1))
    }

    fn set_xmm_words(&mut self, n: u8, low: Value, high: Value) {
        let w = XMM + 2 * usize::from(n & 15);
        self.set_word(w, low);
        self.set_word(w + 1, high);
    }

    /// `op` of [`Fast::XmmPacked`] on xmm registers `dst` and `src`, as
    /// `sse::packed` has it.
    fn packed(&mut self, op: Mnemonic, dst: u8, src: u8, imm: u8) {
        let (a0, a1) = self.xmm_words(dst);
        let (b0, b1) = self.xmm_words(src);
        let (low, high) = match op {
            Mnemonic::Punpcklqdq => (a0, b0),
            Mnemonic::Punpckhqdq => (a1, b1),
            Mnemonic::Punpcklwd => (
                self.interleave(a0, b0, 16, false),
                self.interleave(a0, b0, 16, true),
            ),
            Mnemonic::Punpckhbw | Mnemonic::Punpckhwd | Mnemonic::Punpckhdq => {
                let bits = match op {
                    Mnemonic::Punpckhbw => 8,
                    Mnemonic::Punpckhwd => 16,
                    _ => 32,
                };
                (
                    self.interleave(a1, b1, bits, false),
                    self.interleave(a1, b1, bits, true),
                )
            }
            Mnemonic::Packuswb => (
                self.pack(a0, a1, 16, 8, true),
                self.pack(b0, b1, 16, 8, true),
            ),
            Mnemonic::Packsswb => (
                self.pack(a0, a1, 16, 8, false),
                self.pack(b0, b1, 16, 8, false),
            ),
            Mnemonic::Packssdw => (
                self.pack(a0, a1, 32, 16, false),
                self.pack(b0, b1, 32, 16, false),
            ),
            Mnemonic::Paddq => (self.b.ins().iadd(a0, b0), self.b.ins().iadd(a1, b1)),
            Mnemonic::Psubq => (self.b.ins().isub(a0, b0), self.b.ins().isub(a1, b1)),
            Mnemonic::Pand => (self.b.ins().band(a0, b0), self.b.ins().band(a1, b1)),
            Mnemonic::Por => (self.b.ins().bor(a0, b0), self.b.ins().bor(a1, b1)),
            Mnemonic::Pandn => (self.b.ins().band_not(b0, a0), self.b.ins().band_not(b1, a1)),
            Mnemonic::Paddd | Mnemonic::Psubd => {
                let add = op == Mnemonic::Paddd;
                let mut out = [a0, a1];
                for (w, (a, b)) in out.iter_mut().zip([(a0, b0), (a1, b1)]) {
                    // Each dword on its own, so that no carry or borrow
                    // crosses into the other.
                    let low = if add {
                        self.b.ins().iadd(a, b)
                    } else {
                        self.b.ins().isub(a, b)
                    };
                    let low = self.b.ins().band_imm_s(low, 0xffff_ffff);
                    let a_up = self.b.ins().ushr_imm_s(a, 32);
                    let b_up = self.b.ins().ushr_imm_s(b, 32);
                    let up = if add {
                        self.b.ins().iadd(a_up, b_up)
                    } else {
                        self.b.ins().isub(a_up, b_up)
                    };
                    let up = self.b.ins().ishl_imm_s(up, 32);
                    *w = self.b.ins().bor(low, up);
                }
                (out[0], out[1])
            }
            Mnemonic::Pmuludq => {
                let mut out = [a0, a1];
                for (w, (a, b)) in out.iter_mut().zip([(a0, b0), (a1, b1)]) {
                    let a = self.b.ins().band_imm_s(a, 0xffff_ffff);
                    let b = self.b.ins().band_imm_s(b, 0xffff_ffff);
                    *w = self.b.ins().imul(a, b);
                }
                (out[0], out[1])
            }
            Mnemonic::Punpckldq => {
                let a = self.b.ins().band_imm_s(a0, 0xffff_ffff);
                let b = self.b.ins().ishl_imm_s(b0, 32);
                let low = self.b.ins().bor(a, b);
                let a = self.b.ins().ushr_imm_s(a0, 32);
                let b = self.b.ins().ushr_imm_s(b0, 32);
                let b = self.b.ins().ishl_imm_s(b, 32);
                (low, self.b.ins().bor(a, b))
            }
            Mnemonic::Punpcklbw => {
                let a = self.spread_bytes(a0);
                let b = self.spread_bytes(b0);
                let b = self.b.ins().ishl_imm_s(b, 8);
                let low = self.b.ins().bor(a, b);
                let a_up = self.b.ins().ushr_imm_s(a0, 32);
                let b_up = self.b.ins().ushr_imm_s(b0, 32);
                let a = self.spread_bytes(a_up);
                let b = self.spread_bytes(b_up);
                let b = self.b.ins().ishl_imm_s(b, 8);
                (low, self.b.ins().bor(a, b))
            }
            Mnemonic::Pshufd => {
                let mut dwords = [a0; 4];
                for (n, d) in dwords.iter_mut().enumerate() {
                    let k = (imm >> (n * 2)) & 3;
                    let w = if k < 2 { b0 } else { b1 };
                    let shifted = if k & 1 == 1 {
                        self.b.ins().ushr_imm_s(w, 32)
                    } else {
                        w
                    };
                    *d = self.b.ins().band_imm_s(shifted, 0xffff_ffff);
                }
                let up = self.b.ins().ishl_imm_s(dwords[1], 32);
                let low = self.b.ins().bor(dwords[0], up);
                let up = self.b.ins().ishl_imm_s(dwords[3], 32);
                (low, self.b.ins().bor(dwords[2], up))
            }
            Mnemonic::Pslld | Mnemonic::Psrld => {
                if imm >= 32 {
                    let zero = self.constant(0);
                    (zero, zero)
                } else {
                    let c = i64::from(imm);
                    let left = op == Mnemonic::Pslld;
                    let lane: u64 = if left {
                        (0xffff_ffffu64 << c) & 0xffff_ffff
                    } else {
                        0xffff_ffffu64 >> c
                    };
                    let keep = (lane | (lane << 32)) as i64;
                    let mut out = [a0, a1];
                    for w in &mut out {
                        let moved = if left {
                            self.b.ins().ishl_imm_s(*w, c)
                        } else {
                            self.b.ins().ushr_imm_s(*w, c)
                        };
                        *w = self.b.ins().band_imm_s(moved, keep);
                    }
                    (out[0], out[1])
                }
            }
            _ => unreachable!("XmmPacked holds only these operations"),
        };
        self.set_xmm_words(dst, low, high);
    }

    /// A flag bit: `bit` when `condition` (an `i8` truth value) holds.
    fn bit(&mut self, condition: Value, bit: u64) -> Value {
        let wide = self.b.ins().uextend(I64, condition);
        self.b
            .ins()
            .ishl_imm_s(wide, i64::from(bit.trailing_zeros()))
    }

    /// ZF, SF and PF of `r`, already masked to `size`.
    fn zf_sf_pf(&mut self, r: Value, size: u8) -> Value {
        let zero = self.b.ins().icmp_imm_s(IntCC::Equal, r, 0);
        let zf = self.bit(zero, flag::ZF);
        let top = self
            .b
            .ins()
            .ushr_imm_s(r, i64::from(u32::from(size) * 8 - 1));
        let sf = self
            .b
            .ins()
            .ishl_imm_s(top, i64::from(flag::SF.trailing_zeros()));
        let low = self.b.ins().band_imm_s(r, 0xff);
        let ones = self.b.ins().popcnt(low);
        let odd = self.b.ins().band_imm_s(ones, 1);
        let even = self.b.ins().icmp_imm_s(IntCC::Equal, odd, 0);
        let pf = self.bit(even, flag::PF);
        let f = self.b.ins().bor(zf, sf);
        self.b.ins().bor(f, pf)
    }

    /// The result (masked to `size`) and status flags of `op` on `a` and
    /// `b`, both masked to `size`, as `alu::add`, `alu::sub` and
    /// `alu::logic` have them.
    fn alu(&mut self, op: Alu, a: Value, b: Value, size: u8) -> (Value, Value) {
        match op {
            Alu::Add | Alu::Sub | Alu::Cmp => {
                let add = op == Alu::Add;
                let wide = if add {
                    self.b.ins().iadd(a, b)
                } else {
                    self.b.ins().isub(a, b)
                };
                let r = if size == 8 {
                    wide
                } else {
                    self.b.ins().band_imm_s(wide, mask(size))
                };
                let mut f = self.zf_sf_pf(r, size);
                let carry = if add {
                    if size == 8 {
                        self.b.ins().icmp(IntCC::UnsignedLessThan, r, a)
                    } else {
                        self.b
                            .ins()
                            .icmp_imm_s(IntCC::UnsignedGreaterThan, wide, mask(size))
                    }
                } else {
                    self.b.ins().icmp(IntCC::UnsignedLessThan, a, b)
                };
                let cf = self.bit(carry, flag::CF);
                f = self.b.ins().bor(f, cf);
                // OF: add when both operands differ in sign from the result,
                // sub when the operands differ in sign and the result
                // differs from the first.
                let ar = self.b.ins().bxor(a, r);
                let other = if add {
                    self.b.ins().bxor(b, r)
                } else {
                    self.b.ins().bxor(a, b)
                };
                let both = self.b.ins().band(ar, other);
                let signed = self.b.ins().band_imm_s(both, sign(size));
                let overflow = self.b.ins().icmp_imm_s(IntCC::NotEqual, signed, 0);
                let of = self.bit(overflow, flag::OF);
                f = self.b.ins().bor(f, of);
                let ab = self.b.ins().bxor(a, b);
                let abr = self.b.ins().bxor(ab, r);
                let af = self.b.ins().band_imm_s(abr, flag::AF as i64);
                f = self.b.ins().bor(f, af);
                (r, f)
            }
            Alu::And | Alu::Test | Alu::Or | Alu::Xor => {
                let r = match op {
                    Alu::Or => self.b.ins().bor(a, b),
                    Alu::Xor => self.b.ins().bxor(a, b),
                    _ => self.b.ins().band(a, b),
                };
                let f = self.zf_sf_pf(r, size);
                (r, f)
            }
        }
    }

    fn set_status(&mut self, f: Value) {
        self.set_flags(flag::STATUS, f);
    }

    /// Sets the flags of `update` to those of `f`.
    fn set_flags(&mut self, update: u64, f: Value) {
        if update == 0 {
            return;
        }
        let old = self.word(RFLAGS);
        let kept = self.b.ins().band_imm_s(old, !(update as i64));
        let f = if update == flag::STATUS {
            f
        } else {
            self.b.ins().band_imm_s(f, update as i64)
        };
        let new = self.b.ins().bor(kept, f);
        self.set_word(RFLAGS, new);
    }

    /// The result of `op` on `a` (masked to `size`), the flags it changes
    /// and their values, as `Unary::apply` has them.
    fn unary(&mut self, op: Unary, a: Value, size: u8) -> (Value, u64, Value) {
        match op {
            Unary::Inc | Unary::Dec => {
                let one = self.constant(1);
                let alu = if op == Unary::Inc { Alu::Add } else { Alu::Sub };
                let (r, f) = self.alu(alu, a, one, size);
                (r, flag::STATUS & !flag::CF, f)
            }
            Unary::Neg => {
                let zero = self.constant(0);
                let (r, f) = self.alu(Alu::Sub, zero, a, size);
                (r, flag::STATUS, f)
            }
            Unary::Not => {
                let r = self.b.ins().bxor_imm_s(a, mask(size));
                let zero = self.constant(0);
                (r, 0, zero)
            }
        }
    }

    /// Bit `n` of `v` as 0 or 1.
    fn bit_of(&mut self, v: Value, n: u32) -> Value {
        let down = if n == 0 {
            v
        } else {
            self.b.ins().ushr_imm_s(v, i64::from(n))
        };
        self.b.ins().band_imm_s(down, 1)
    }

    /// The low and high halves (each masked to `size`) of `a` times `b`,
    /// both masked to `size`, and whether the high half is needed (CF and
    /// OF), as `mul`, `imul r` and `alu::imul` have them.
    fn multiply(&mut self, a: Value, b: Value, size: u8, signed: bool) -> (Value, Value, Value) {
        if size == 8 {
            let low = self.b.ins().imul(a, b);
            let (high, expected) = if signed {
                let high = self.b.ins().smulhi(a, b);
                (high, self.b.ins().sshr_imm_s(low, 63))
            } else {
                (self.b.ins().umulhi(a, b), self.constant(0))
            };
            let overflow = self.b.ins().icmp(IntCC::NotEqual, high, expected);
            return (low, high, overflow);
        }
        // Both factors fit in 32 bits, so the whole product fits in 64.
        let bits = i64::from(size) * 8;
        let (a, b) = if signed {
            (self.sign_extended(a, size), self.sign_extended(b, size))
        } else {
            (a, b)
        };
        let full = self.b.ins().imul(a, b);
        let low = self.masked(full, size);
        let up = if signed {
            self.b.ins().sshr_imm_s(full, bits)
        } else {
            self.b.ins().ushr_imm_s(full, bits)
        };
        let high = self.masked(up, size);
        let overflow = if signed {
            let back = self.sign_extended(low, size);
            self.b.ins().icmp(IntCC::NotEqual, back, full)
        } else {
            self.b.ins().icmp_imm_s(IntCC::NotEqual, up, 0)
        };
        (low, high, overflow)
    }

    /// Sets CF and OF to `overflow` (an `i8` truth value).
    fn set_carry_overflow(&mut self, overflow: Value) {
        let cf = self.bit(overflow, flag::CF);
        let of = self.bit(overflow, flag::OF);
        let f = self.b.ins().bor(cf, of);
        self.set_flags(flag::CF | flag::OF, f);
    }

    /// The result of `shl`, `shr` or `sar` of `a` (masked to `size`) by
    /// `count`, a value already masked to 31 or 63, and the status flags of
    /// a count that is not 0, as `Shift::apply` has them. A count of 0
    /// gives back `a`.
    fn shift_by(&mut self, op: Shift, a: Value, count: Value, size: u8) -> (Value, Value) {
        let width = i64::from(size) * 8;
        let one = self.constant(1);
        let less = self.b.ins().isub(count, one);
        let (r, cf, of) = match op {
            Shift::Shl => {
                // `a` has `width` bits and the count is at most 63, so the
                // bits that leave stay in `wide` unless `width` is 64.
                let wide = self.b.ins().ishl(a, count);
                let r = self.masked(wide, size);
                let cf = if size == 8 {
                    let w = self.constant(64);
                    let back = self.b.ins().isub(w, count);
                    let out = self.b.ins().ushr(a, back);
                    self.b.ins().band_imm_s(out, 1)
                } else {
                    let out = self.b.ins().ushr_imm_s(wide, width);
                    self.b.ins().band_imm_s(out, 1)
                };
                let top = self.bit_of(r, (width - 1) as u32);
                let of = self.b.ins().bxor(top, cf);
                (r, cf, Some(of))
            }
            Shift::Shr => {
                let r = self.b.ins().ushr(a, count);
                let out = self.b.ins().ushr(a, less);
                let cf = self.b.ins().band_imm_s(out, 1);
                let of = self.bit_of(a, (width - 1) as u32);
                (r, cf, Some(of))
            }
            Shift::Sar => {
                let signed = self.sign_extended(a, size);
                let shifted = self.b.ins().sshr(signed, count);
                let r = self.masked(shifted, size);
                let out = self.b.ins().sshr(signed, less);
                let cf = self.b.ins().band_imm_s(out, 1);
                (r, cf, None)
            }
            Shift::Rol | Shift::Ror => unreachable!("rotates by cl have no form"),
        };
        let mut f = self.zf_sf_pf(r, size);
        f = self.b.ins().bor(f, cf);
        if let Some(of) = of {
            let of = self
                .b
                .ins()
                .ishl_imm_s(of, i64::from(flag::OF.trailing_zeros()));
            f = self.b.ins().bor(f, of);
        }
        (r, f)
    }

    /// The result of `op` on `a` (masked to `size`) by `count` (already
    /// masked, not 0), the flags it changes and their values, as
    /// `Shift::apply` has them.
    fn shift(&mut self, op: Shift, a: Value, count: u8, size: u8) -> (Value, u64, Value) {
        let width = u32::from(size) * 8;
        let c = u32::from(count);
        let cf_bit = flag::CF.trailing_zeros();
        let of_bit = flag::OF.trailing_zeros();
        let (r, cf, of) = match op {
            Shift::Shl => {
                let r = if c >= width {
                    self.constant(0)
                } else {
                    let r = self.b.ins().ishl_imm_s(a, i64::from(c));
                    self.masked(r, size)
                };
                let cf = if c <= width {
                    self.bit_of(a, width - c)
                } else {
                    self.constant(0)
                };
                let top = self.bit_of(r, width - 1);
                let of = self.b.ins().bxor(top, cf);
                (r, cf, Some(of))
            }
            Shift::Shr => {
                let r = if c >= width {
                    self.constant(0)
                } else {
                    self.b.ins().ushr_imm_s(a, i64::from(c))
                };
                let cf = if c <= width {
                    self.bit_of(a, c - 1)
                } else {
                    self.constant(0)
                };
                let of = self.bit_of(a, width - 1);
                (r, cf, Some(of))
            }
            Shift::Sar => {
                let up = 64 - width;
                let signed = if up == 0 {
                    a
                } else {
                    let high = self.b.ins().ishl_imm_s(a, i64::from(up));
                    self.b.ins().sshr_imm_s(high, i64::from(up))
                };
                let shifted = self.b.ins().sshr_imm_s(signed, i64::from(c.min(63)));
                let r = self.masked(shifted, size);
                let out = self.b.ins().sshr_imm_s(signed, i64::from((c - 1).min(63)));
                let cf = self.b.ins().band_imm_s(out, 1);
                (r, cf, None)
            }
            Shift::Rol | Shift::Ror => {
                let left = op == Shift::Rol;
                let turn = c % width;
                let r = if turn == 0 {
                    a
                } else if width == 64 {
                    if left {
                        self.b.ins().rotl_imm_s(a, i64::from(turn))
                    } else {
                        self.b.ins().rotr_imm_s(a, i64::from(turn))
                    }
                } else {
                    let (l, rr) = if left {
                        (turn, width - turn)
                    } else {
                        (width - turn, turn)
                    };
                    let high = self.b.ins().ishl_imm_s(a, i64::from(l));
                    let low = self.b.ins().ushr_imm_s(a, i64::from(rr));
                    let both = self.b.ins().bor(high, low);
                    self.masked(both, size)
                };
                let cf = if left {
                    self.bit_of(r, 0)
                } else {
                    self.bit_of(r, width - 1)
                };
                let of = if left {
                    let top = self.bit_of(r, width - 1);
                    self.b.ins().bxor(top, cf)
                } else {
                    let top = self.bit_of(r, width - 1);
                    let next = self.bit_of(r, width - 2);
                    self.b.ins().bxor(top, next)
                };
                let cf_flag = self.b.ins().ishl_imm_s(cf, i64::from(cf_bit));
                if count == 1 {
                    let of_flag = self.b.ins().ishl_imm_s(of, i64::from(of_bit));
                    let f = self.b.ins().bor(cf_flag, of_flag);
                    return (r, flag::CF | flag::OF, f);
                }
                return (r, flag::CF, cf_flag);
            }
        };
        let mut f = self.zf_sf_pf(r, size);
        let cf_flag = self.b.ins().ishl_imm_s(cf, i64::from(cf_bit));
        f = self.b.ins().bor(f, cf_flag);
        if let Some(of) = of {
            let of_flag = self.b.ins().ishl_imm_s(of, i64::from(of_bit));
            f = self.b.ins().bor(f, of_flag);
        }
        (r, flag::STATUS, f)
    }

    /// Whether `condition` holds for the current flags, as `alu::condition`.
    fn condition(&mut self, condition: Condition) -> Value {
        let flags = self.word(RFLAGS);
        let set = |e: &mut Self, f: u64| {
            let v = e.b.ins().band_imm_s(flags, f as i64);
            e.b.ins().icmp_imm_s(IntCC::NotEqual, v, 0)
        };
        let cf = set(self, flag::CF);
        let zf = set(self, flag::ZF);
        let sf = set(self, flag::SF);
        let of = set(self, flag::OF);
        let pf = set(self, flag::PF);
        let not = |e: &mut Self, v: Value| e.b.ins().bxor_imm_s(v, 1);
        match condition {
            Condition::O => of,
            Condition::No => not(self, of),
            Condition::B => cf,
            Condition::Ae => not(self, cf),
            Condition::E => zf,
            Condition::Ne => not(self, zf),
            Condition::Be => self.b.ins().bor(cf, zf),
            Condition::A => {
                let v = self.b.ins().bor(cf, zf);
                not(self, v)
            }
            Condition::S => sf,
            Condition::Ns => not(self, sf),
            Condition::P => pf,
            Condition::Np => not(self, pf),
            Condition::L => self.b.ins().bxor(sf, of),
            Condition::Ge => {
                let v = self.b.ins().bxor(sf, of);
                not(self, v)
            }
            Condition::Le => {
                let v = self.b.ins().bxor(sf, of);
                self.b.ins().bor(zf, v)
            }
            Condition::G => {
                let v = self.b.ins().bxor(sf, of);
                let v = self.b.ins().bor(zf, v);
                not(self, v)
            }
        }
    }

    /// Emits the `n`th form (from 0). Returns false when it ends the code:
    /// it always leaves.
    fn form(&mut self, n: usize, form: &Form) -> bool {
        let (rip, next) = (form.rip, form.next);
        match form.fast {
            Fast::None => unreachable!("forms offered to a compiler have a form"),
            Fast::Nop => {}
            Fast::Move { dst, src } => {
                let v = self.source(src, dst.size());
                self.write(dst, v);
            }
            Fast::Load { dst, mem } | Fast::LoadZeroExtended { dst, mem } => {
                let address = self.linear(&mem);
                let (v, status) = self.load(address, mem.size);
                self.unless_failed(status, n, rip);
                let v = if dst.size() == 8 {
                    v
                } else {
                    self.b.ins().band_imm_s(v, mask(dst.size()))
                };
                self.write(dst, v);
                self.unless_changed(status, n + 1, next);
            }
            Fast::Store { mem, src } => {
                let v = self.source(src, mem.size);
                let address = self.linear(&mem);
                let status = self.store(address, mem.size, v);
                self.unless_failed(status, n, rip);
                self.unless_changed(status, n + 1, next);
            }
            Fast::Lea { dst, mem } => {
                let v = self.address(&mem);
                self.set_gpr(dst, v);
            }
            Fast::Push(r) => {
                let v = self.gpr(r);
                let rsp = self.gpr(4);
                let rsp = self.b.ins().iadd_imm_s(rsp, -8);
                let status = self.store(rsp, 8, v);
                self.unless_failed(status, n, rip);
                self.set_gpr(4, rsp);
                self.unless_changed(status, n + 1, next);
            }
            Fast::PushImmediate(v) => {
                let v = self.constant(v as i64);
                let rsp = self.gpr(4);
                let rsp = self.b.ins().iadd_imm_s(rsp, -8);
                let status = self.store(rsp, 8, v);
                self.unless_failed(status, n, rip);
                self.set_gpr(4, rsp);
                self.unless_changed(status, n + 1, next);
            }
            Fast::MulWide { src, signed } => {
                let size = src.size();
                let b = self.read(src);
                let rax = self.gpr(0);
                let a = self.masked(rax, size);
                let (low, high, overflow) = self.multiply(a, b, size, signed);
                if size == 1 {
                    let up = self.b.ins().ishl_imm_s(high, 8);
                    let ax = self.b.ins().bor(up, low);
                    self.write(Register::Gpr { index: 0, size: 2 }, ax);
                } else {
                    self.write(Register::Gpr { index: 0, size }, low);
                    self.write(Register::Gpr { index: 2, size }, high);
                }
                self.set_carry_overflow(overflow);
            }
            Fast::CmpxchgStore { mem, src } => {
                let size = mem.size;
                let rax = self.gpr(0);
                let expected = self.masked(rax, size);
                let new = self.read(src);
                let address = self.linear(&mem);
                let (old, status) = self.atomic(address, size, 1, expected, new);
                self.unless_failed(status, n, rip);
                let (_, f) = self.alu(Alu::Sub, expected, old, size);
                self.set_status(f);
                // rax takes the old value only when the compare failed; a
                // 32-bit write would otherwise clear its upper half.
                let merged = if size >= 4 {
                    old
                } else {
                    let kept = self.b.ins().band_imm_s(rax, !mask(size));
                    self.b.ins().bor(kept, old)
                };
                let same = self.b.ins().icmp(IntCC::Equal, expected, old);
                let value = self.b.ins().select(same, rax, merged);
                self.set_gpr(0, value);
                self.unless_changed(status, n + 1, next);
            }
            Fast::XchgStore { mem, src } => {
                let value = self.read(src);
                let address = self.linear(&mem);
                let zero = self.constant(0);
                let (old, status) = self.atomic(address, mem.size, 0, value, zero);
                self.unless_failed(status, n, rip);
                self.write(src, old);
                self.unless_changed(status, n + 1, next);
            }
            Fast::XmmMove { dst, src } => {
                let low = self.word(XMM + 2 * usize::from(src));
                let high = self.word(XMM + 2 * usize::from(src) + 1);
                self.set_word(XMM + 2 * usize::from(dst), low);
                self.set_word(XMM + 2 * usize::from(dst) + 1, high);
            }
            Fast::XmmLoad { dst, mem, aligned } => {
                let address = self.linear(&mem);
                let status = self.move128(self.helpers.load128, address, dst, aligned, n, rip);
                self.unless_failed(status, n, rip);
                self.unless_changed(status, n + 1, next);
            }
            Fast::XmmStore { mem, src, aligned } => {
                let address = self.linear(&mem);
                let status = self.move128(self.helpers.store128, address, src, aligned, n, rip);
                self.unless_failed(status, n, rip);
                self.unless_changed(status, n + 1, next);
            }
            Fast::XmmXor { dst, src } => {
                for half in 0..2 {
                    let a = self.word(XMM + 2 * usize::from(dst) + half);
                    let b = self.word(XMM + 2 * usize::from(src) + half);
                    let v = self.b.ins().bxor(a, b);
                    self.set_word(XMM + 2 * usize::from(dst) + half, v);
                }
            }
            Fast::XmmPacked { op, dst, src, imm } => self.packed(op, dst, src, imm),
            Fast::Pmovmskb { dst, src } => {
                let (low, high) = self.xmm_words(src);
                let low = self.byte_signs(low);
                let high = self.byte_signs(high);
                let high = self.b.ins().ishl_imm_s(high, 8);
                let mask = self.b.ins().bor(low, high);
                self.write(dst, mask);
            }
            Fast::MoveScalar { dst, src, size } => {
                let v = match src {
                    Register::Xmm(n) => self.word(XMM + 2 * usize::from(n & 15)),
                    r => self.read(r),
                };
                let v = self.masked(v, size);
                match dst {
                    Register::Xmm(n) => {
                        let zero = self.constant(0);
                        self.set_word(XMM + 2 * usize::from(n & 15), v);
                        self.set_word(XMM + 2 * usize::from(n & 15) + 1, zero);
                    }
                    r => self.write(r, v),
                }
            }
            Fast::Imul { dst, a, b } => {
                let size = dst.size();
                let a = self.read(a);
                let b = self.source(b, size);
                let (low, _, overflow) = self.multiply(a, b, size, true);
                self.write(dst, low);
                self.set_carry_overflow(overflow);
            }
            Fast::Pop(r) => {
                let rsp = self.gpr(4);
                let (v, status) = self.load(rsp, 8);
                self.unless_failed(status, n, rip);
                let up = self.b.ins().iadd_imm_s(rsp, 8);
                self.set_gpr(4, up);
                self.set_gpr(r, v);
                self.unless_changed(status, n + 1, next);
            }
            Fast::Jcc { condition, target } => {
                let taken = self.condition(condition);
                let jump = self.b.create_block();
                let go_on = self.b.create_block();
                self.b.ins().brif(taken, jump, &[], go_on, &[]);
                self.b.switch_to_block(jump);
                self.leave_at(n + 1, target);
                self.b.switch_to_block(go_on);
            }
            Fast::Jmp(target) => {
                self.leave_at(n + 1, target);
                return false;
            }
            Fast::Call(target) => {
                let rsp = self.gpr(4);
                let rsp = self.b.ins().iadd_imm_s(rsp, -8);
                let v = self.constant(next as i64);
                let status = self.store(rsp, 8, v);
                self.unless_failed(status, n, rip);
                self.set_gpr(4, rsp);
                self.leave_at(n + 1, target);
                return false;
            }
            Fast::Ret => {
                let rsp = self.gpr(4);
                let (v, status) = self.load(rsp, 8);
                self.unless_failed(status, n, rip);
                let up = self.b.ins().iadd_imm_s(rsp, 8);
                self.set_gpr(4, up);
                self.leave(n + 1, v);
                return false;
            }
            Fast::Alu { op, dst, src } => {
                let size = dst.size();
                let b = self.source(src, size);
                let a = self.read(dst);
                let (r, f) = self.alu(op, a, b, size);
                if op.writes() {
                    self.write(dst, r);
                }
                self.set_status(f);
            }
            Fast::Extend { dst, src, signed } => {
                let v = self.read(src);
                let v = if signed {
                    self.sign_extended(v, src.size())
                } else {
                    v
                };
                self.write(dst, v);
            }
            Fast::LoadSignExtended { dst, mem } => {
                let address = self.linear(&mem);
                let (v, status) = self.load(address, mem.size);
                self.unless_failed(status, n, rip);
                let v = self.sign_extended(v, mem.size);
                let v = if dst.size() == 8 {
                    v
                } else {
                    self.b.ins().band_imm_s(v, mask(dst.size()))
                };
                self.write(dst, v);
                self.unless_changed(status, n + 1, next);
            }
            Fast::LeaTruncated { dst, mem } => {
                let v = self.address(&mem);
                self.write(dst, v);
            }
            Fast::Set { condition, dst } => {
                let holds = self.condition(condition);
                let v = self.b.ins().uextend(I64, holds);
                self.write(dst, v);
            }
            Fast::SetStore { condition, mem } => {
                let holds = self.condition(condition);
                let v = self.b.ins().uextend(I64, holds);
                let address = self.linear(&mem);
                let status = self.store(address, 1, v);
                self.unless_failed(status, n, rip);
                self.unless_changed(status, n + 1, next);
            }
            Fast::Cmov {
                condition,
                dst,
                src,
            } => {
                let v = self.read(src);
                let old = self.read(dst);
                let holds = self.condition(condition);
                let v = self.b.ins().select(holds, v, old);
                self.write(dst, v);
            }
            Fast::CmovLoad {
                condition,
                dst,
                mem,
            } => {
                let address = self.linear(&mem);
                let (v, status) = self.load(address, dst.size());
                self.unless_failed(status, n, rip);
                let v = if dst.size() == 8 {
                    v
                } else {
                    self.b.ins().band_imm_s(v, mask(dst.size()))
                };
                let old = self.read(dst);
                let holds = self.condition(condition);
                let v = self.b.ins().select(holds, v, old);
                self.write(dst, v);
                self.unless_changed(status, n + 1, next);
            }
            Fast::Unary { op, dst } => {
                let a = self.read(dst);
                let (r, update, f) = self.unary(op, a, dst.size());
                self.write(dst, r);
                self.set_flags(update, f);
            }
            Fast::UnaryStore { op, mem } => {
                let size = mem.size;
                let address = self.linear(&mem);
                let (a, loaded) = self.load(address, size);
                self.unless_failed(loaded, n, rip);
                let a = if size == 8 {
                    a
                } else {
                    self.b.ins().band_imm_s(a, mask(size))
                };
                let (r, update, f) = self.unary(op, a, size);
                let status = self.store(address, size, r);
                self.unless_failed(status, n, rip);
                self.set_flags(update, f);
                self.unless_changed(status, n + 1, next);
            }
            Fast::Shift { op, dst, count } => {
                let a = self.read(dst);
                if count == 0 {
                    self.write(dst, a);
                } else {
                    let (r, update, f) = self.shift(op, a, count, dst.size());
                    self.write(dst, r);
                    self.set_flags(update, f);
                }
            }
            Fast::ShiftByCl { op, dst } => {
                let size = dst.size();
                let a = self.read(dst);
                let rcx = self.gpr(1);
                let count = self
                    .b
                    .ins()
                    .band_imm_s(rcx, if size == 8 { 63 } else { 31 });
                let (r, f) = self.shift_by(op, a, count, size);
                self.write(dst, r);
                // A count of 0 changes no flag.
                let old = self.word(RFLAGS);
                let kept = self.b.ins().band_imm_s(old, !(flag::STATUS as i64));
                let new = self.b.ins().bor(kept, f);
                let zero = self.b.ins().icmp_imm_s(IntCC::Equal, count, 0);
                let flags = self.b.ins().select(zero, old, new);
                self.set_word(RFLAGS, flags);
            }
            Fast::Compare { op, mem, src } => {
                let size = mem.size;
                let b = self.source(src, size);
                let address = self.linear(&mem);
                let (a, status) = self.load(address, size);
                self.unless_failed(status, n, rip);
                let a = if size == 8 {
                    a
                } else {
                    self.b.ins().band_imm_s(a, mask(size))
                };
                let (_, f) = self.alu(op, a, b, size);
                self.set_status(f);
                self.unless_changed(status, n + 1, next);
            }
            Fast::AluLoad { op, dst, mem } => {
                let size = dst.size();
                let address = self.linear(&mem);
                let (b, status) = self.load(address, size);
                self.unless_failed(status, n, rip);
                let b = self.masked(b, size);
                let a = self.read(dst);
                let (r, f) = self.alu(op, a, b, size);
                if op.writes() {
                    self.write(dst, r);
                }
                self.set_status(f);
                self.unless_changed(status, n + 1, next);
            }
            Fast::AluStore { op, mem, src } => {
                let size = mem.size;
                let b = self.source(src, size);
                let address = self.linear(&mem);
                let (a, loaded) = self.load(address, size);
                self.unless_failed(loaded, n, rip);
                let a = self.masked(a, size);
                let (r, f) = self.alu(op, a, b, size);
                let status = self.store(address, size, r);
                self.unless_failed(status, n, rip);
                self.set_status(f);
                self.unless_changed(status, n + 1, next);
            }
        }
        true
    }
}

/// The signature of a block's code: `(registers, context) -> count`.
pub(crate) fn block_signature() -> Signature {
    let mut sig = Signature::new(CallConv::SystemV);
    sig.params.push(AbiParam::new(I64));
    sig.params.push(AbiParam::new(I64));
    sig.returns.push(AbiParam::new(I64));
    sig
}

/// The function that runs `forms`, and whether it reaches the xmm words
/// of the register block: the block it is given has [`WORDS`] words then,
/// and [`XMM`] otherwise.
pub(crate) fn function(
    forms: &[Form],
    helpers: Helpers,
    config: cranelift_codegen::isa::TargetFrontendConfig,
) -> (Function, bool) {
    let mut func = Function::with_name_signature(UserFuncName::user(0, 0), block_signature());
    let mut context = FunctionBuilderContext::new();
    let mut b = FunctionBuilder::new(&mut func, &mut context);

    let mut load_sig = Signature::new(CallConv::SystemV);
    load_sig.params.extend([AbiParam::new(I64); 3]);
    load_sig.returns.extend([AbiParam::new(I64); 2]);
    let load_sig = b.import_signature(load_sig);
    let mut store_sig = Signature::new(CallConv::SystemV);
    store_sig.params.extend([AbiParam::new(I64); 4]);
    store_sig.returns.push(AbiParam::new(I64));
    let store_sig = b.import_signature(store_sig);
    let mut move128_sig = Signature::new(CallConv::SystemV);
    move128_sig.params.extend([AbiParam::new(I64); 3]);
    move128_sig.returns.push(AbiParam::new(I64));
    let move128_sig = b.import_signature(move128_sig);
    let mut atomic_sig = Signature::new(CallConv::SystemV);
    atomic_sig.params.extend([AbiParam::new(I64); 6]);
    atomic_sig.returns.extend([AbiParam::new(I64); 2]);
    let atomic_sig = b.import_signature(atomic_sig);

    let entry = b.create_block();
    b.append_block_params_for_function_params(entry);
    b.switch_to_block(entry);
    let registers = b.block_params(entry)[0];
    let context_value = b.block_params(entry)[1];
    let flags = MemFlagsData::trusted();
    let fs_base = b.ins().load(I64, flags, registers, (FS_BASE * 8) as i32);
    let gs_base = b.ins().load(I64, flags, registers, (GS_BASE * 8) as i32);
    let exit = b.create_block();
    let count = b.append_block_param(exit, I64);
    let rip = b.append_block_param(exit, I64);

    let mut e = Emitter {
        b: &mut b,
        registers,
        exit,
        context: context_value,
        fs_base,
        gs_base,
        helpers,
        load_sig,
        store_sig,
        move128_sig,
        atomic_sig,
        vector: false,
    };
    let mut open = true;
    for (n, form) in forms.iter().enumerate() {
        if !e.form(n, form) {
            open = false;
            break;
        }
    }
    if open && let Some(last) = forms.last() {
        e.leave_at(forms.len(), last.next);
    }

    let vector = e.vector;
    b.switch_to_block(exit);
    b.ins().store(flags, rip, registers, (RIP * 8) as i32);
    b.ins().return_(&[count]);
    b.seal_all_blocks();
    b.finalize(config);
    (func, vector)
}
