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
use paludarium_cpu::compile::{Address, Alu, Fast, Form, Source};
use paludarium_cpu::flag;
use paludarium_decoder::{Condition, Register, Segment};

/// Words of the register block the code runs on: the general registers,
/// then RFLAGS, RIP, and the FS and GS bases (read only).
pub(crate) const RFLAGS: usize = 16;
pub(crate) const RIP: usize = 17;
pub(crate) const FS_BASE: usize = 18;
pub(crate) const GS_BASE: usize = 19;
pub(crate) const WORDS: usize = 20;

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
        self.b.ins().load(
            I64,
            MemFlagsData::trusted(),
            self.registers,
            (word * 8) as i32,
        )
    }

    fn set_word(&mut self, word: usize, v: Value) {
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

    /// The value of `r` (a general register, not a high byte), masked to
    /// its size.
    fn read(&mut self, r: Register) -> Value {
        let Register::Gpr { index, size } = r else {
            unreachable!("forms hold general registers only");
        };
        let v = self.gpr(index);
        if size == 8 {
            v
        } else {
            self.b.ins().band_imm_s(v, mask(size))
        }
    }

    /// Writes `v` to `r` as `write_reg` does: whole, zero-extended from
    /// 32 bits, or merged into the low 8 or 16 bits.
    fn write(&mut self, r: Register, v: Value) {
        let Register::Gpr { index, size } = r else {
            unreachable!("forms hold general registers only");
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
        let old = self.word(RFLAGS);
        let kept = self.b.ins().band_imm_s(old, !(flag::STATUS as i64));
        let new = self.b.ins().bor(kept, f);
        self.set_word(RFLAGS, new);
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

/// The function that runs `forms`.
pub(crate) fn function(
    forms: &[Form],
    helpers: Helpers,
    config: cranelift_codegen::isa::TargetFrontendConfig,
) -> Function {
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

    b.switch_to_block(exit);
    b.ins().store(flags, rip, registers, (RIP * 8) as i32);
    b.ins().return_(&[count]);
    b.seal_all_blocks();
    b.finalize(config);
    func
}
