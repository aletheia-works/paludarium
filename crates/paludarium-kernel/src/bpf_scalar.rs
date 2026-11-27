//! A scalar as Linux 7.0's verifier follows it: the bits it knows
//! (`struct tnum`, `kernel/bpf/tnum.c`) and its unsigned and signed bounds
//! as 64 and as 32 bits (`umin_value` to `s32_max_value` of `struct
//! bpf_reg_state`), with the operations of `kernel/bpf/verifier.c` that
//! change them: `reg_bounds_sync` and what it calls, the ALU operations of
//! `adjust_scalar_min_max_vals`, the casts of a load (`coerce_reg_to_size`
//! and the sign-extending ones) and what a conditional jump tells
//! (`is_scalar_branch_taken`, `regs_refine_cond_op`).
//!
//! Master follows a scalar otherwise (circular ranges and steps), which
//! this is not; [`crate::bpf_verifier`] says where that matters.

/// What a scalar's bits are known to be (`struct tnum`): a bit set in
/// `mask` is unknown, any other is the bit of `value`, whose unknown bits
/// are 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tnum {
    pub(crate) value: u64,
    pub(crate) mask: u64,
}

/// The highest set bit's number counted from 1, 0 for 0 (`fls64`).
fn fls64(x: u64) -> u32 {
    64 - x.leading_zeros()
}

impl Tnum {
    /// `tnum_unknown`.
    pub(crate) const UNKNOWN: Tnum = Tnum {
        value: 0,
        mask: u64::MAX,
    };

    const fn new(value: u64, mask: u64) -> Tnum {
        Tnum { value, mask }
    }

    /// `tnum_const`.
    pub(crate) const fn known(value: u64) -> Tnum {
        Tnum::new(value, 0)
    }

    /// `tnum_range`: the bits every value from `min` to `max` shares.
    fn range(min: u64, max: u64) -> Tnum {
        let bits = fls64(min ^ max);
        if bits > 63 {
            return Tnum::UNKNOWN;
        }
        let delta = (1u64 << bits) - 1;
        Tnum::new(min & !delta, delta)
    }

    pub(crate) fn is_const(self) -> bool {
        self.mask == 0
    }

    /// `tnum_is_aligned` of these bits plus `off` (`tnum_add` of a
    /// constant): every value is a multiple of `size`, a power of 2.
    pub(crate) fn aligned_at(self, off: u64, size: u64) -> bool {
        let t = self.add(Tnum::known(off));
        (t.value | t.mask) & (size - 1) == 0
    }

    fn lshift(self, shift: u32) -> Tnum {
        Tnum::new(self.value << shift, self.mask << shift)
    }

    fn rshift(self, shift: u32) -> Tnum {
        Tnum::new(self.value >> shift, self.mask >> shift)
    }

    /// `tnum_arshift` of a value of `bits` bits.
    fn arshift(self, shift: u32, bits: u32) -> Tnum {
        if bits == 32 {
            Tnum::new(
                u64::from(((self.value as u32 as i32) >> shift) as u32),
                u64::from(((self.mask as u32 as i32) >> shift) as u32),
            )
        } else {
            Tnum::new(
                ((self.value as i64) >> shift) as u64,
                ((self.mask as i64) >> shift) as u64,
            )
        }
    }

    fn add(self, b: Tnum) -> Tnum {
        let sm = self.mask.wrapping_add(b.mask);
        let sv = self.value.wrapping_add(b.value);
        let sigma = sm.wrapping_add(sv);
        let chi = sigma ^ sv;
        let mu = chi | self.mask | b.mask;
        Tnum::new(sv & !mu, mu)
    }

    fn sub(self, b: Tnum) -> Tnum {
        let dv = self.value.wrapping_sub(b.value);
        let alpha = dv.wrapping_add(self.mask);
        let beta = dv.wrapping_sub(b.mask);
        let chi = alpha ^ beta;
        let mu = chi | self.mask | b.mask;
        Tnum::new(dv & !mu, mu)
    }

    fn neg(self) -> Tnum {
        Tnum::known(0).sub(self)
    }

    fn and(self, b: Tnum) -> Tnum {
        let alpha = self.value | self.mask;
        let beta = b.value | b.mask;
        let v = self.value & b.value;
        Tnum::new(v, alpha & beta & !v)
    }

    fn or(self, b: Tnum) -> Tnum {
        let v = self.value | b.value;
        let mu = self.mask | b.mask;
        Tnum::new(v, mu & !v)
    }

    fn xor(self, b: Tnum) -> Tnum {
        let v = self.value ^ b.value;
        let mu = self.mask | b.mask;
        Tnum::new(v & !mu, mu)
    }

    /// `tnum_mul`: long multiplication, bit by bit of `self`, where an
    /// unknown bit takes the union of adding `b` and not.
    fn mul(self, b: Tnum) -> Tnum {
        let (mut a, mut b) = (self, b);
        let mut acc = Tnum::known(0);
        while a.value != 0 || a.mask != 0 {
            if a.value & 1 != 0 {
                acc = acc.add(b);
            } else if a.mask & 1 != 0 {
                acc = acc.union(acc.add(b));
            }
            a = a.rshift(1);
            b = b.lshift(1);
        }
        acc
    }

    /// `tnum_overlap`: whether some value is in both.
    fn overlap(self, b: Tnum) -> bool {
        let mu = !self.mask & !b.mask;
        self.value & mu == b.value & mu
    }

    /// `tnum_intersect`.
    fn intersect(self, b: Tnum) -> Tnum {
        let v = self.value | b.value;
        let mu = self.mask & b.mask;
        Tnum::new(v & !mu, mu)
    }

    /// `tnum_union`.
    fn union(self, b: Tnum) -> Tnum {
        let v = self.value & b.value;
        let mu = (self.value ^ b.value) | self.mask | b.mask;
        Tnum::new(v & !mu, mu)
    }

    /// `tnum_cast` to `size` bytes, fewer than 8.
    fn cast(self, size: u32) -> Tnum {
        let keep = (1u64 << (size * 8)) - 1;
        Tnum::new(self.value & keep, self.mask & keep)
    }

    /// `tnum_subreg`: the low 32 bits.
    pub(crate) fn subreg(self) -> Tnum {
        self.cast(4)
    }

    fn clear_subreg(self) -> Tnum {
        self.rshift(32).lshift(32)
    }

    fn with_subreg(self, subreg: Tnum) -> Tnum {
        self.clear_subreg().or(subreg.subreg())
    }

    fn const_subreg(self, value: u32) -> Tnum {
        self.with_subreg(Tnum::known(u64::from(value)))
    }

    /// `tnum_step`: the smallest value of `self` above `z`, for `z` from its
    /// smallest to below its largest; its largest from there up, its
    /// smallest below it.
    fn step(self, z: u64) -> u64 {
        let tmax = self.value | self.mask;
        if z >= tmax {
            return tmax;
        }
        if z < self.value {
            return self.value;
        }
        let j = self.value | (z & self.mask);
        if j > z {
            let p = !z & self.value & !self.mask;
            let q = shl_or_zero(u64::MAX, fls64(p));
            (q & z) | (!q & self.value)
        } else {
            let p = z & !self.value & !self.mask;
            let k = fls64(p);
            let q = shl_or_zero(u64::MAX, k);
            let v = (q & self.mask & z) | (q & !self.mask);
            let u = v.wrapping_add(shl_or_zero(1, k));
            (u & self.mask) | self.value
        }
    }
}

/// `x << n` as the kernel's x86-64 build computes it for `n` up to 64: the
/// shift count is taken modulo 64 by the CPU.
fn shl_or_zero(x: u64, n: u32) -> u64 {
    x.wrapping_shl(n)
}

/// `BPF_ADD_CONST64` and `BPF_ADD_CONST32` of a scalar's ID: it is a
/// linked register's plus `off`, from a 64-bit or a 32-bit addition.
pub(crate) const ADD_CONST64: u32 = 1 << 31;
pub(crate) const ADD_CONST32: u32 = 1 << 30;
pub(crate) const ADD_CONST: u32 = ADD_CONST64 | ADD_CONST32;

/// A scalar register's state: what its bits and bounds are known to be,
/// and the ID it shares with the registers it was copied to or from
/// (with `off`, the constant added since), which a jump's bounds then go
/// to (`sync_linked_regs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Scalar {
    pub(crate) var: Tnum,
    pub(crate) umin: u64,
    pub(crate) umax: u64,
    pub(crate) smin: i64,
    pub(crate) smax: i64,
    pub(crate) u32_min: u32,
    pub(crate) u32_max: u32,
    pub(crate) s32_min: i32,
    pub(crate) s32_max: i32,
    pub(crate) id: u32,
    pub(crate) off: i32,
}

/// The BPF ALU operations, as `BPF_OP` gives them.
pub(crate) mod op {
    pub const ADD: u8 = 0x00;
    pub const SUB: u8 = 0x10;
    pub const MUL: u8 = 0x20;
    pub const DIV: u8 = 0x30;
    pub const OR: u8 = 0x40;
    pub const AND: u8 = 0x50;
    pub const LSH: u8 = 0x60;
    pub const RSH: u8 = 0x70;
    pub const NEG: u8 = 0x80;
    pub const MOD: u8 = 0x90;
    pub const XOR: u8 = 0xa0;
    pub const ARSH: u8 = 0xc0;
    pub const END: u8 = 0xd0;
}

/// The conditional jumps, as `BPF_OP` gives them, and the reverse of
/// `BPF_JSET` (`BPF_JSET | BPF_X`, as `rev_opcode` makes it).
pub(crate) mod jmp {
    pub const JEQ: u8 = 0x10;
    pub const JGT: u8 = 0x20;
    pub const JGE: u8 = 0x30;
    pub const JSET: u8 = 0x40;
    pub const JNE: u8 = 0x50;
    pub const JSGT: u8 = 0x60;
    pub const JSGE: u8 = 0x70;
    pub const JLT: u8 = 0xa0;
    pub const JLE: u8 = 0xb0;
    pub const JSLT: u8 = 0xc0;
    pub const JSLE: u8 = 0xd0;
    pub const NOT_JSET: u8 = JSET | 0x08;
}

impl Scalar {
    /// `__mark_reg_unknown`: nothing known, and no ID.
    pub(crate) const UNKNOWN: Scalar = Scalar {
        var: Tnum::UNKNOWN,
        umin: 0,
        umax: u64::MAX,
        smin: i64::MIN,
        smax: i64::MAX,
        u32_min: 0,
        u32_max: u32::MAX,
        s32_min: i32::MIN,
        s32_max: i32::MAX,
        id: 0,
        off: 0,
    };

    /// `__mark_reg_known`: the value, and no ID.
    pub(crate) fn known(value: u64) -> Scalar {
        let mut s = Scalar::UNKNOWN;
        s.set_known(value);
        s
    }

    /// `___mark_reg_known`, which keeps the ID.
    fn set_known(&mut self, value: u64) {
        self.var = Tnum::known(value);
        self.smin = value as i64;
        self.smax = value as i64;
        self.umin = value;
        self.umax = value;
        self.set_known32(value as u32);
    }

    /// The 32-bit part of `__mark_reg32_known`.
    fn set_known32(&mut self, value: u32) {
        self.s32_min = value as i32;
        self.s32_max = value as i32;
        self.u32_min = value;
        self.u32_max = value;
    }

    /// `__mark_reg32_known`.
    fn mark_known32(&mut self, value: u32) {
        self.var = self.var.const_subreg(value);
        self.set_known32(value);
    }

    /// The value, where every bit is known (`tnum_is_const`).
    pub(crate) fn value(&self) -> Option<u64> {
        self.var.is_const().then_some(self.var.value)
    }

    /// `is_reg_const` and `reg_const_value` of the whole register or of its
    /// low 32 bits.
    pub(crate) fn constant(&self, subreg: bool) -> Option<u64> {
        let var = if subreg { self.var.subreg() } else { self.var };
        var.is_const().then_some(var.value)
    }

    /// `get_reg_width`: the bits its largest value needs.
    pub(crate) fn width(&self) -> u32 {
        fls64(self.umax)
    }

    /// Whether it is 0 (`register_is_null` of a scalar).
    pub(crate) fn is_zero(&self) -> bool {
        self.value() == Some(0)
    }

    fn unbounded64(&mut self) {
        self.smin = i64::MIN;
        self.smax = i64::MAX;
        self.umin = 0;
        self.umax = u64::MAX;
    }

    fn unbounded32(&mut self) {
        self.s32_min = i32::MIN;
        self.s32_max = i32::MAX;
        self.u32_min = 0;
        self.u32_max = u32::MAX;
    }

    /// `__mark_reg_unbounded`.
    fn unbounded(&mut self) {
        self.unbounded64();
        self.unbounded32();
    }

    /// `__update_reg32_bounds`: what the known bits tell of the 32-bit
    /// bounds.
    fn update_bounds32(&mut self) {
        let var = self.var.subreg();
        let (value, mask) = (var.value as u32, var.mask as u32);
        self.s32_min = self.s32_min.max((value | (mask & i32::MIN as u32)) as i32);
        self.s32_max = self.s32_max.min((value | (mask & i32::MAX as u32)) as i32);
        self.u32_min = self.u32_min.max(value);
        self.u32_max = self.u32_max.min(value | mask);
    }

    /// `__update_reg64_bounds`: what the known bits tell of the 64-bit
    /// bounds, and the value where the two meet in one.
    fn update_bounds64(&mut self) {
        let Tnum { value, mask } = self.var;
        self.smin = self.smin.max((value | (mask & i64::MIN as u64)) as i64);
        self.smax = self.smax.min((value | (mask & i64::MAX as u64)) as i64);
        self.umin = self.umin.max(value);
        self.umax = self.umax.min(value | mask);
        let next = self.var.step(self.umin);
        let umin_in = self.umin & !mask == value;
        let tmax = value | mask;
        if umin_in && next > self.umax {
            self.set_known(self.umin);
        } else if !umin_in && next == tmax {
            self.set_known(tmax);
        } else if !umin_in && next <= self.umax && self.var.step(next) > self.umax {
            self.set_known(next);
        }
    }

    /// `__update_reg_bounds`.
    fn update_bounds(&mut self) {
        self.update_bounds32();
        self.update_bounds64();
    }

    /// `__reg32_deduce_bounds`.
    fn deduce32(&mut self) {
        if self.umin >> 32 == self.umax >> 32 {
            self.u32_min = self.u32_min.max(self.umin as u32);
            self.u32_max = self.u32_max.min(self.umax as u32);
            if (self.umin as i32) <= (self.umax as i32) {
                self.s32_min = self.s32_min.max(self.umin as i32);
                self.s32_max = self.s32_max.min(self.umax as i32);
            }
        }
        if self.smin >> 32 == self.smax >> 32 {
            if (self.smin as u32) <= (self.smax as u32) {
                self.u32_min = self.u32_min.max(self.smin as u32);
                self.u32_max = self.u32_max.min(self.smax as u32);
            }
            if (self.smin as i32) <= (self.smax as i32) {
                self.s32_min = self.s32_min.max(self.smin as i32);
                self.s32_max = self.s32_max.min(self.smax as i32);
            }
        }
        if ((self.umin >> 32) as u32).wrapping_add(1) == (self.umax >> 32) as u32
            && (self.umin as i32) < 0
            && (self.umax as i32) >= 0
        {
            self.s32_min = self.s32_min.max(self.umin as i32);
            self.s32_max = self.s32_max.min(self.umax as i32);
        }
        if ((self.smin >> 32) as u32).wrapping_add(1) == (self.smax >> 32) as u32
            && (self.smin as i32) < 0
            && (self.smax as i32) >= 0
        {
            self.s32_min = self.s32_min.max(self.smin as i32);
            self.s32_max = self.s32_max.min(self.smax as i32);
        }
        if (self.u32_min as i32) <= (self.u32_max as i32) {
            self.s32_min = self.s32_min.max(self.u32_min as i32);
            self.s32_max = self.s32_max.min(self.u32_max as i32);
        }
        if (self.s32_min as u32) <= (self.s32_max as u32) {
            self.u32_min = self.u32_min.max(self.s32_min as u32);
            self.u32_max = self.u32_max.min(self.s32_max as u32);
        } else if self.u32_max < self.s32_min as u32 {
            self.s32_min = self.u32_min as i32;
            self.u32_max = self.u32_max.min(self.s32_max as u32);
        } else if (self.s32_max as u32) < self.u32_min {
            self.s32_max = self.u32_max as i32;
            self.u32_min = self.u32_min.max(self.s32_min as u32);
        }
    }

    /// `__reg64_deduce_bounds`.
    fn deduce64(&mut self) {
        if (self.umin as i64) <= (self.umax as i64) {
            self.smin = self.smin.max(self.umin as i64);
            self.smax = self.smax.min(self.umax as i64);
        }
        if (self.smin as u64) <= (self.smax as u64) {
            self.umin = self.umin.max(self.smin as u64);
            self.umax = self.umax.min(self.smax as u64);
        } else if self.umax < self.smin as u64 {
            self.smin = self.umin as i64;
            self.umax = self.umax.min(self.smax as u64);
        } else if (self.smax as u64) < self.umin {
            self.smax = self.umax as i64;
            self.umin = self.umin.max(self.smin as u64);
        }
    }

    /// `__reg_deduce_mixed_bounds`: the 64-bit bounds with the 32-bit ones
    /// as their low halves.
    fn deduce_mixed(&mut self) {
        const HIGH: u64 = !0xffff_ffff;
        let new_umin = (self.umin & HIGH) | u64::from(self.u32_min);
        let new_umax = (self.umax & HIGH) | u64::from(self.u32_max);
        self.umin = self.umin.max(new_umin);
        self.umax = self.umax.min(new_umax);
        let new_smin = ((self.smin as u64 & HIGH) | u64::from(self.u32_min)) as i64;
        let new_smax = ((self.smax as u64 & HIGH) | u64::from(self.u32_max)) as i64;
        self.smin = self.smin.max(new_smin);
        self.smax = self.smax.min(new_smax);
        if self.s32_min >= 0 && self.smin >= i64::from(i32::MIN) && self.smax <= i64::from(i32::MAX)
        {
            self.smin = i64::from(self.s32_min);
            self.smax = i64::from(self.s32_max);
            self.umin = self.s32_min as u64;
            self.umax = self.s32_max as u64;
            self.var = self
                .var
                .intersect(Tnum::range(self.smin as u64, self.smax as u64));
        }
    }

    /// `__reg_deduce_bounds`.
    fn deduce(&mut self) {
        self.deduce32();
        self.deduce64();
        self.deduce_mixed();
    }

    /// `__reg_bound_offset`: the bits the bounds tell.
    fn bound_offset(&mut self) {
        let var64 = self.var.intersect(Tnum::range(self.umin, self.umax));
        let var32 = var64.subreg().intersect(Tnum::range(
            u64::from(self.u32_min),
            u64::from(self.u32_max),
        ));
        self.var = var64.clear_subreg().or(var32);
    }

    /// `reg_bounds_sync`.
    pub(crate) fn sync(&mut self) {
        self.update_bounds();
        self.deduce();
        self.deduce();
        self.deduce();
        self.bound_offset();
        self.update_bounds();
    }

    /// Whether `reg_bounds_sanity_check` finds the bounds and the known
    /// bits agree.
    pub(crate) fn sane(&self) -> bool {
        if self.umin > self.umax
            || self.smin > self.smax
            || self.u32_min > self.u32_max
            || self.s32_min > self.s32_max
        {
            return false;
        }
        if let Some(v) = self.value()
            && (self.umin != v || self.umax != v || self.smin != v as i64 || self.smax != v as i64)
        {
            return false;
        }
        if let Some(v) = self.constant(true) {
            let v = v as u32;
            if self.u32_min != v
                || self.u32_max != v
                || self.s32_min != v as i32
                || self.s32_max != v as i32
            {
                return false;
            }
        }
        true
    }

    /// `__reg_assign_32_into_64`.
    fn assign_32_into_64(&mut self) {
        self.umin = u64::from(self.u32_min);
        self.umax = u64::from(self.u32_max);
        if self.s32_min >= 0 && self.s32_max >= 0 {
            self.smin = i64::from(self.s32_min);
            self.smax = i64::from(self.s32_max);
        } else {
            self.smin = 0;
            self.smax = i64::from(u32::MAX);
        }
    }

    /// `zext_32_to_64`: the low 32 bits, zero-extended.
    pub(crate) fn zext(&mut self) {
        self.var = self.var.subreg();
        self.assign_32_into_64();
    }

    /// `coerce_reg_to_size`: the low `size` bytes, fewer than 8,
    /// zero-extended, as a load of them gives.
    pub(crate) fn coerce(&mut self, size: u32) {
        self.var = self.var.cast(size);
        let keep = (1u64 << (size * 8)) - 1;
        if self.umin & !keep == self.umax & !keep {
            self.umin &= keep;
            self.umax &= keep;
        } else {
            self.umin = 0;
            self.umax = keep;
        }
        self.smin = self.umin as i64;
        self.smax = self.umax as i64;
        if size < 4 {
            self.unbounded32();
        }
        self.sync();
    }

    /// `set_sext64_default_val`.
    fn sext64_default(&mut self, size: u32) {
        let (min, max) = match size {
            1 => (i64::from(i8::MIN), i64::from(i8::MAX)),
            2 => (i64::from(i16::MIN), i64::from(i16::MAX)),
            _ => (i64::from(i32::MIN), i64::from(i32::MAX)),
        };
        self.smin = min;
        self.s32_min = min as i32;
        self.smax = max;
        self.s32_max = max as i32;
        self.umin = 0;
        self.u32_min = 0;
        self.umax = u64::MAX;
        self.u32_max = u32::MAX;
        self.var = Tnum::UNKNOWN;
    }

    /// `coerce_reg_to_size_sx`: the low `size` bytes (1, 2 or 4),
    /// sign-extended to 64 bits.
    pub(crate) fn coerce_sx(&mut self, size: u32) {
        let bits = size * 8;
        let sext = |v: u64| -> i64 {
            match size {
                1 => i64::from(v as i8),
                2 => i64::from(v as i16),
                _ => i64::from(v as i32),
            }
        };
        if self.var.is_const() {
            let v = sext(self.var.value) as u64;
            self.var = Tnum::known(v);
            self.smin = v as i64;
            self.smax = v as i64;
            self.umin = v;
            self.umax = v;
            self.s32_min = v as i32;
            self.s32_max = v as i32;
            self.u32_min = v as u32;
            self.u32_max = v as u32;
            return;
        }
        let top = |v: i64| (v as u64 >> bits) << bits;
        if top(self.smax) == top(self.smin) {
            let (a, b) = (sext(self.smax as u64), sext(self.smin as u64));
            let (max, min) = (a.max(b), a.min(b));
            if (max >= 0) == (min >= 0) {
                self.smin = min;
                self.s32_min = min as i32;
                self.smax = max;
                self.s32_max = max as i32;
                self.umin = min as u64;
                self.u32_min = min as u32;
                self.umax = max as u64;
                self.u32_max = max as u32;
                self.var = Tnum::range(min as u64, max as u64);
                return;
            }
        }
        self.sext64_default(size);
    }

    /// `coerce_subreg_to_size_sx`: the low `size` bytes (1 or 2),
    /// sign-extended to 32 bits.
    pub(crate) fn coerce_subreg_sx(&mut self, size: u32) {
        let bits = size * 8;
        let sext = |v: u32| -> i32 {
            if size == 1 {
                i32::from(v as i8)
            } else {
                i32::from(v as i16)
            }
        };
        if self.var.is_const() {
            let v = sext(self.var.value as u32);
            self.var = Tnum::known(v as i64 as u64);
            self.s32_min = v;
            self.s32_max = v;
            self.u32_min = v as u32;
            self.u32_max = v as u32;
            return;
        }
        let top = |v: i32| (v as u32 >> bits) << bits;
        if top(self.s32_max) == top(self.s32_min) {
            let (a, b) = (sext(self.s32_max as u32), sext(self.s32_min as u32));
            let (max, min) = (a.max(b), a.min(b));
            if (min >= 0) == (max >= 0) {
                self.s32_min = min;
                self.s32_max = max;
                self.u32_min = min as u32;
                self.u32_max = max as u32;
                self.var = Tnum::range(min as i64 as u64, max as i64 as u64).subreg();
                return;
            }
        }
        // set_sext32_default_val
        if size == 1 {
            self.s32_min = i32::from(i8::MIN);
            self.s32_max = i32::from(i8::MAX);
        } else {
            self.s32_min = i32::from(i16::MIN);
            self.s32_max = i32::from(i16::MAX);
        }
        self.u32_min = 0;
        self.u32_max = u32::MAX;
        self.var = Tnum::UNKNOWN.subreg();
    }
}

/// `is_safe_to_compute_dst_reg_range`: whether the operation's bounds can
/// be followed with this source; a division, a modulo or a shift only by a
/// constant, and a shift by less than the width.
fn safe_range(op: u8, alu32: bool, src: &Scalar) -> bool {
    let constant = if alu32 {
        src.var.subreg().is_const() && src.s32_min == src.s32_max && src.u32_min == src.u32_max
    } else {
        src.var.is_const() && src.smin == src.smax && src.umin == src.umax
    };
    match op {
        op::ADD | op::SUB | op::NEG | op::AND | op::XOR | op::OR | op::MUL | op::END => true,
        op::DIV | op::MOD => constant,
        op::LSH | op::RSH | op::ARSH => constant && src.umax < if alu32 { 32 } else { 64 },
        _ => false,
    }
}

/// Whether `maybe_fork_scalars` splits the walk before a `BPF_AND` or
/// `BPF_OR` with a constant of a register that is -1 or 0: the 64-bit
/// register, or its low 32 bits.
pub(crate) fn forks(op: u8, dst: &Scalar, src: &Scalar) -> Option<bool> {
    if !matches!(op, op::AND | op::OR) || !src.var.is_const() {
        return None;
    }
    if dst.smin == -1 && dst.smax == 0 {
        Some(false)
    } else if dst.s32_min == -1 && dst.s32_max == 0 {
        Some(true)
    } else {
        None
    }
}

impl Scalar {
    /// The two sides of `maybe_fork_scalars`: the register 0, which the
    /// other path starts the instruction again with, and -1, which this
    /// one goes on with; the low 32 bits only for `alu32`.
    pub(crate) fn forked(&self, alu32: bool) -> (Scalar, Scalar) {
        let (mut zero, mut ones) = (*self, *self);
        if alu32 {
            zero.mark_known32(0);
            ones.mark_known32(u32::MAX);
        } else {
            zero = Scalar::known(0);
            ones = Scalar::known(u64::MAX);
        }
        (zero, ones)
    }

    fn add32(&mut self, src: &Scalar) {
        let (smin, a) = self.s32_min.overflowing_add(src.s32_min);
        let (smax, b) = self.s32_max.overflowing_add(src.s32_max);
        if a || b {
            self.s32_min = i32::MIN;
            self.s32_max = i32::MAX;
        } else {
            self.s32_min = smin;
            self.s32_max = smax;
        }
        let (umin, min_over) = self.u32_min.overflowing_add(src.u32_min);
        let (umax, max_over) = self.u32_max.overflowing_add(src.u32_max);
        self.u32_min = umin;
        self.u32_max = umax;
        if !min_over && max_over {
            self.u32_min = 0;
            self.u32_max = u32::MAX;
        }
    }

    fn add64(&mut self, src: &Scalar) {
        let (smin, a) = self.smin.overflowing_add(src.smin);
        let (smax, b) = self.smax.overflowing_add(src.smax);
        if a || b {
            self.smin = i64::MIN;
            self.smax = i64::MAX;
        } else {
            self.smin = smin;
            self.smax = smax;
        }
        let (umin, min_over) = self.umin.overflowing_add(src.umin);
        let (umax, max_over) = self.umax.overflowing_add(src.umax);
        self.umin = umin;
        self.umax = umax;
        if !min_over && max_over {
            self.umin = 0;
            self.umax = u64::MAX;
        }
    }

    fn sub32(&mut self, src: &Scalar) {
        let (smin, a) = self.s32_min.overflowing_sub(src.s32_max);
        let (smax, b) = self.s32_max.overflowing_sub(src.s32_min);
        if a || b {
            self.s32_min = i32::MIN;
            self.s32_max = i32::MAX;
        } else {
            self.s32_min = smin;
            self.s32_max = smax;
        }
        let (umin, min_under) = self.u32_min.overflowing_sub(src.u32_max);
        let (umax, max_under) = self.u32_max.overflowing_sub(src.u32_min);
        self.u32_min = umin;
        self.u32_max = umax;
        if min_under && !max_under {
            self.u32_min = 0;
            self.u32_max = u32::MAX;
        }
    }

    fn sub64(&mut self, src: &Scalar) {
        let (smin, a) = self.smin.overflowing_sub(src.smax);
        let (smax, b) = self.smax.overflowing_sub(src.smin);
        if a || b {
            self.smin = i64::MIN;
            self.smax = i64::MAX;
        } else {
            self.smin = smin;
            self.smax = smax;
        }
        let (umin, min_under) = self.umin.overflowing_sub(src.umax);
        let (umax, max_under) = self.umax.overflowing_sub(src.umin);
        self.umin = umin;
        self.umax = umax;
        if min_under && !max_under {
            self.umin = 0;
            self.umax = u64::MAX;
        }
    }

    fn mul32(&mut self, src: &Scalar) {
        match (
            self.u32_max.checked_mul(src.u32_max),
            self.u32_min.checked_mul(src.u32_min),
        ) {
            (Some(umax), Some(umin)) => {
                self.u32_max = umax;
                self.u32_min = umin;
            }
            _ => {
                self.u32_min = 0;
                self.u32_max = u32::MAX;
            }
        }
        let products = [
            self.s32_min.checked_mul(src.s32_min),
            self.s32_min.checked_mul(src.s32_max),
            self.s32_max.checked_mul(src.s32_min),
            self.s32_max.checked_mul(src.s32_max),
        ];
        if let [Some(a), Some(b), Some(c), Some(d)] = products {
            self.s32_min = a.min(b).min(c).min(d);
            self.s32_max = a.max(b).max(c).max(d);
        } else {
            self.s32_min = i32::MIN;
            self.s32_max = i32::MAX;
        }
    }

    fn mul64(&mut self, src: &Scalar) {
        match (
            self.umax.checked_mul(src.umax),
            self.umin.checked_mul(src.umin),
        ) {
            (Some(umax), Some(umin)) => {
                self.umax = umax;
                self.umin = umin;
            }
            _ => {
                self.umin = 0;
                self.umax = u64::MAX;
            }
        }
        let products = [
            self.smin.checked_mul(src.smin),
            self.smin.checked_mul(src.smax),
            self.smax.checked_mul(src.smin),
            self.smax.checked_mul(src.smax),
        ];
        if let [Some(a), Some(b), Some(c), Some(d)] = products {
            self.smin = a.min(b).min(c).min(d);
            self.smax = a.max(b).max(c).max(d);
        } else {
            self.smin = i64::MIN;
            self.smax = i64::MAX;
        }
    }

    /// The signed 32-bit bounds from the unsigned ones where they do not
    /// cross the sign, else none.
    fn signed32_from_unsigned(&mut self) {
        if (self.u32_min as i32) <= (self.u32_max as i32) {
            self.s32_min = self.u32_min as i32;
            self.s32_max = self.u32_max as i32;
        } else {
            self.s32_min = i32::MIN;
            self.s32_max = i32::MAX;
        }
    }

    fn signed64_from_unsigned(&mut self) {
        if (self.umin as i64) <= (self.umax as i64) {
            self.smin = self.umin as i64;
            self.smax = self.umax as i64;
        } else {
            self.smin = i64::MIN;
            self.smax = i64::MAX;
        }
    }

    fn and32(&mut self, src: &Scalar) {
        let var = self.var.subreg();
        if src.var.subreg().is_const() && var.is_const() {
            self.mark_known32(var.value as u32);
            return;
        }
        self.u32_min = var.value as u32;
        self.u32_max = self.u32_max.min(src.u32_max);
        self.signed32_from_unsigned();
    }

    fn and64(&mut self, src: &Scalar) {
        if src.var.is_const() && self.var.is_const() {
            *self = Scalar::known(self.var.value);
            return;
        }
        self.umin = self.var.value;
        self.umax = self.umax.min(src.umax);
        self.signed64_from_unsigned();
        self.update_bounds();
    }

    fn or32(&mut self, src: &Scalar) {
        let var = self.var.subreg();
        if src.var.subreg().is_const() && var.is_const() {
            self.mark_known32(var.value as u32);
            return;
        }
        self.u32_min = self.u32_min.max(src.u32_min);
        self.u32_max = (var.value | var.mask) as u32;
        self.signed32_from_unsigned();
    }

    fn or64(&mut self, src: &Scalar) {
        if src.var.is_const() && self.var.is_const() {
            *self = Scalar::known(self.var.value);
            return;
        }
        self.umin = self.umin.max(src.umin);
        self.umax = self.var.value | self.var.mask;
        self.signed64_from_unsigned();
        self.update_bounds();
    }

    fn xor32(&mut self, src: &Scalar) {
        let var = self.var.subreg();
        if src.var.subreg().is_const() && var.is_const() {
            self.mark_known32(var.value as u32);
            return;
        }
        self.u32_min = var.value as u32;
        self.u32_max = (var.value | var.mask) as u32;
        self.signed32_from_unsigned();
    }

    fn xor64(&mut self, src: &Scalar) {
        if src.var.is_const() && self.var.is_const() {
            *self = Scalar::known(self.var.value);
            return;
        }
        self.umin = self.var.value;
        self.umax = self.var.value | self.var.mask;
        self.signed64_from_unsigned();
        self.update_bounds();
    }

    /// `__scalar32_min_max_lsh` by `umin` to `umax`.
    fn lsh32_bounds(&mut self, umin: u64, umax: u64) {
        self.s32_min = i32::MIN;
        self.s32_max = i32::MAX;
        if umax > 31 || u64::from(self.u32_max) > 1u64 << (31 - umax) {
            self.u32_min = 0;
            self.u32_max = u32::MAX;
        } else {
            self.u32_min <<= umin;
            self.u32_max <<= umax;
        }
    }

    fn lsh32(&mut self, src: &Scalar) {
        let (umin, umax) = (u64::from(src.u32_min), u64::from(src.u32_max));
        let subreg = self.var.subreg();
        self.lsh32_bounds(umin, umax);
        self.var = subreg.lshift(umin as u32).subreg();
        self.unbounded64();
        self.update_bounds32();
    }

    fn lsh64(&mut self, src: &Scalar) {
        let (umin, umax) = (src.umin, src.umax);
        if umin == 32 && umax == 32 {
            self.smax = ((i64::from(self.s32_max) as u64) << 32) as i64;
            self.smin = ((i64::from(self.s32_min) as u64) << 32) as i64;
        } else {
            self.smax = i64::MAX;
            self.smin = i64::MIN;
        }
        if self.umax > 1u64 << (63 - umax) {
            self.umin = 0;
            self.umax = u64::MAX;
        } else {
            self.umin <<= umin;
            self.umax <<= umax;
        }
        self.lsh32_bounds(umin, umax);
        self.var = self.var.lshift(umin as u32);
        self.update_bounds();
    }

    fn rsh32(&mut self, src: &Scalar) {
        let subreg = self.var.subreg();
        let (umin, umax) = (src.u32_min, src.u32_max);
        self.s32_min = i32::MIN;
        self.s32_max = i32::MAX;
        self.var = subreg.rshift(umin);
        self.u32_min >>= umax;
        self.u32_max >>= umin;
        self.unbounded64();
        self.update_bounds32();
    }

    fn rsh64(&mut self, src: &Scalar) {
        let (umin, umax) = (src.umin as u32, src.umax as u32);
        self.smin = i64::MIN;
        self.smax = i64::MAX;
        self.var = self.var.rshift(umin);
        self.umin >>= umax;
        self.umax >>= umin;
        self.unbounded32();
        self.update_bounds();
    }

    fn arsh32(&mut self, src: &Scalar) {
        let shift = src.u32_min;
        self.s32_min >>= shift;
        self.s32_max >>= shift;
        self.var = self.var.subreg().arshift(shift, 32);
        self.u32_min = 0;
        self.u32_max = u32::MAX;
        self.unbounded64();
        self.update_bounds32();
    }

    fn arsh64(&mut self, src: &Scalar) {
        let shift = src.umin as u32;
        self.smin >>= shift;
        self.smax >>= shift;
        self.var = self.var.arshift(shift, 64);
        self.umin = 0;
        self.umax = u64::MAX;
        self.unbounded32();
        self.update_bounds();
    }

    /// `reset_reg64_and_tnum`.
    fn reset64_and_var(&mut self) {
        self.unbounded64();
        self.var = Tnum::UNKNOWN;
    }

    /// `reset_reg32_and_tnum`.
    fn reset32_and_var(&mut self) {
        self.unbounded32();
        self.var = Tnum::UNKNOWN;
    }

    fn udiv32(&mut self, src: &Scalar) {
        let d = src.u32_min;
        self.u32_min /= d;
        self.u32_max /= d;
        self.s32_min = i32::MIN;
        self.s32_max = i32::MAX;
        self.reset64_and_var();
    }

    fn udiv64(&mut self, src: &Scalar) {
        let d = src.umin;
        self.umin /= d;
        self.umax /= d;
        self.smin = i64::MIN;
        self.smax = i64::MAX;
        self.reset32_and_var();
    }

    fn sdiv32(&mut self, src: &Scalar) {
        let d = src.s32_min;
        if self.s32_min == i32::MIN && d == -1 {
            if self.s32_max != i32::MIN {
                self.s32_min = i32::MIN;
                self.s32_max = i32::MAX;
            }
        } else {
            let (a, b) = (self.s32_min.wrapping_div(d), self.s32_max.wrapping_div(d));
            self.s32_min = a.min(b);
            self.s32_max = a.max(b);
        }
        self.u32_min = 0;
        self.u32_max = u32::MAX;
        self.reset64_and_var();
    }

    fn sdiv64(&mut self, src: &Scalar) {
        let d = src.smin;
        if self.smin == i64::MIN && d == -1 {
            if self.smax != i64::MIN {
                self.smin = i64::MIN;
                self.smax = i64::MAX;
            }
        } else {
            let (a, b) = (self.smin.wrapping_div(d), self.smax.wrapping_div(d));
            self.smin = a.min(b);
            self.smax = a.max(b);
        }
        self.umin = 0;
        self.umax = u64::MAX;
        self.reset32_and_var();
    }

    fn umod32(&mut self, src: &Scalar) {
        let most = src.u32_min - 1;
        if self.u32_max <= most {
            return;
        }
        self.u32_min = 0;
        self.u32_max = self.u32_max.min(most);
        self.s32_min = i32::MIN;
        self.s32_max = i32::MAX;
        self.reset64_and_var();
    }

    fn umod64(&mut self, src: &Scalar) {
        let most = src.umin - 1;
        if self.umax <= most {
            return;
        }
        self.umin = 0;
        self.umax = self.umax.min(most);
        self.smin = i64::MIN;
        self.smax = i64::MAX;
        self.reset32_and_var();
    }

    fn smod32(&mut self, src: &Scalar) {
        let most = (src.s32_min.unsigned_abs() - 1) as i32;
        if self.s32_min >= -most && self.s32_max <= most {
            return;
        }
        if self.s32_min >= 0 {
            self.s32_min = 0;
            self.s32_max = self.s32_max.min(most);
        } else if self.s32_max <= 0 {
            self.s32_max = 0;
            self.s32_min = self.s32_min.max(-most);
        } else {
            self.s32_min = -most;
            self.s32_max = most;
        }
        self.u32_min = 0;
        self.u32_max = u32::MAX;
        self.reset64_and_var();
    }

    fn smod64(&mut self, src: &Scalar) {
        let most = (src.smin.unsigned_abs() - 1) as i64;
        if self.smin >= -most && self.smax <= most {
            return;
        }
        if self.smin >= 0 {
            self.smin = 0;
            self.smax = self.smax.min(most);
        } else if self.smax <= 0 {
            self.smax = 0;
            self.smin = self.smin.max(-most);
        } else {
            self.smin = -most;
            self.smax = most;
        }
        self.umin = 0;
        self.umax = u64::MAX;
        self.reset32_and_var();
    }

    /// `scalar_byte_swap` of a `BPF_END` of `bits` bits, which swaps the
    /// bytes when `swap` (a 64-bit one, or `BPF_TO_BE` here).
    fn byte_swap(&mut self, swap: bool, bits: u32) {
        if swap || bits == 16 || bits == 32 {
            self.id = 0;
        }
        if swap {
            let Tnum { value, mask } = self.var;
            self.var = match bits {
                16 => Tnum::new(
                    u64::from((value as u16).swap_bytes()),
                    u64::from((mask as u16).swap_bytes()),
                ),
                32 => Tnum::new(
                    u64::from((value as u32).swap_bytes()),
                    u64::from((mask as u32).swap_bytes()),
                ),
                _ => Tnum::new(value.swap_bytes(), mask.swap_bytes()),
            };
            self.unbounded();
        }
        if bits == 16 || bits == 32 {
            self.coerce(bits / 8);
        }
    }

    /// `adjust_scalar_min_max_vals` of `op` with `src`: a 32-bit operation
    /// for `alu32`, a signed division or modulo for `signed`. A `BPF_END`
    /// takes `swap` and `bits` (the immediate).
    pub(crate) fn alu(
        &mut self,
        op: u8,
        alu32: bool,
        signed: bool,
        src: &Scalar,
        end: (bool, u32),
    ) {
        if !safe_range(op, alu32, src) {
            *self = Scalar::UNKNOWN;
            return;
        }
        match op {
            op::ADD => {
                self.add32(src);
                self.add64(src);
                self.var = self.var.add(src.var);
            }
            op::SUB => {
                self.sub32(src);
                self.sub64(src);
                self.var = self.var.sub(src.var);
            }
            op::NEG => {
                let old = *self;
                *self = Scalar::known(0);
                self.sub32(&old);
                self.sub64(&old);
                self.var = old.var.neg();
            }
            op::MUL => {
                self.var = self.var.mul(src.var);
                self.mul32(src);
                self.mul64(src);
            }
            op::DIV => {
                let zero = if alu32 {
                    src.u32_min == 0
                } else {
                    src.umin == 0
                };
                if zero {
                    self.set_known(0);
                } else {
                    match (alu32, signed) {
                        (true, true) => self.sdiv32(src),
                        (true, false) => self.udiv32(src),
                        (false, true) => self.sdiv64(src),
                        (false, false) => self.udiv64(src),
                    }
                }
            }
            op::MOD => {
                let zero = if alu32 {
                    src.u32_min == 0
                } else {
                    src.umin == 0
                };
                if !zero {
                    match (alu32, signed) {
                        (true, true) => self.smod32(src),
                        (true, false) => self.umod32(src),
                        (false, true) => self.smod64(src),
                        (false, false) => self.umod64(src),
                    }
                }
            }
            op::AND => {
                self.var = self.var.and(src.var);
                self.and32(src);
                self.and64(src);
            }
            op::OR => {
                self.var = self.var.or(src.var);
                self.or32(src);
                self.or64(src);
            }
            op::XOR => {
                self.var = self.var.xor(src.var);
                self.xor32(src);
                self.xor64(src);
            }
            op::LSH if alu32 => self.lsh32(src),
            op::LSH => self.lsh64(src),
            op::RSH if alu32 => self.rsh32(src),
            op::RSH => self.rsh64(src),
            op::ARSH if alu32 => self.arsh32(src),
            op::ARSH => self.arsh64(src),
            op::END => self.byte_swap(end.0, end.1),
            _ => {}
        }
        if alu32 && op != op::END {
            self.zext();
        }
        self.sync();
    }

    /// The ID `adjust_reg_min_max_vals` leaves after a scalar operation
    /// whose destination's `umax` was `umax_before`: a linked register's
    /// plus a constant for a `BPF_ADD` or `BPF_SUB` of one (once), else
    /// none.
    pub(crate) fn link_after(&mut self, op: u8, alu32: bool, src: &Scalar, umax_before: u64) {
        let constant = src.constant(alu32);
        if !matches!(op, op::ADD | op::SUB) || self.id == 0 {
            self.id = 0;
            return;
        }
        let Some(value) = constant else {
            self.id = 0;
            return;
        };
        let clear = |s: &mut Scalar| {
            s.off = 0;
            s.id = 0;
        };
        if !alu32 && !(i64::from(i32::MIN)..=i64::from(i32::MAX)).contains(&(value as i64)) {
            return clear(self);
        }
        if alu32 && umax_before > u64::from(u32::MAX) {
            return clear(self);
        }
        let mut off = value as i32;
        if op == op::SUB {
            if off == i32::MIN {
                return clear(self);
            }
            off = -off;
        }
        if self.id & ADD_CONST != 0 {
            return clear(self);
        }
        self.id |= if alu32 { ADD_CONST32 } else { ADD_CONST64 };
        self.off = off;
    }

    /// `sync_linked_regs` of this register from `known`, which shares its
    /// ID: `known` itself, or `known` plus the difference of their
    /// constants.
    pub(crate) fn follow(&mut self, known: &Scalar) {
        if (self.id ^ known.id) & ADD_CONST == ADD_CONST {
            return;
        }
        if (self.id & ADD_CONST == 0 && known.id & ADD_CONST == 0) || self.off == known.off {
            *self = *known;
            return;
        }
        let (off, id) = (self.off, self.id);
        let delta = Scalar::known((i64::from(off) - i64::from(known.off)) as u64);
        *self = *known;
        self.off = off;
        self.id = id;
        self.add32(&delta);
        self.add64(&delta);
        self.var = self.var.add(delta.var);
        if (self.id | known.id) & ADD_CONST32 != 0 {
            self.zext();
        }
        self.sync();
    }
}

/// `flip_opcode`: the jump of `b <op> a` for `a <op> b`.
fn flip(op: u8) -> u8 {
    match op {
        jmp::JGE => jmp::JLE,
        jmp::JGT => jmp::JLT,
        jmp::JLE => jmp::JGE,
        jmp::JLT => jmp::JGT,
        jmp::JSGE => jmp::JSLE,
        jmp::JSGT => jmp::JSLT,
        jmp::JSLE => jmp::JSGE,
        jmp::JSLT => jmp::JSGT,
        op => op,
    }
}

/// `rev_opcode`: the jump that is taken where `op`'s is not.
pub(crate) fn reverse(op: u8) -> u8 {
    match op {
        jmp::JEQ => jmp::JNE,
        jmp::JNE => jmp::JEQ,
        jmp::JSET => jmp::NOT_JSET,
        jmp::NOT_JSET => jmp::JSET,
        jmp::JGE => jmp::JLT,
        jmp::JGT => jmp::JLE,
        jmp::JLE => jmp::JGT,
        jmp::JLT => jmp::JGE,
        jmp::JSGE => jmp::JSLT,
        jmp::JSGT => jmp::JSLE,
        jmp::JSLE => jmp::JSGT,
        jmp::JSLT => jmp::JSGE,
        _ => 0,
    }
}

/// `is_scalar_branch_taken`: whether `a <op> b` holds (`Some(true)`),
/// does not (`Some(false)`) or may either way; `same` when the two are
/// one register.
pub(crate) fn taken(a: &Scalar, b: &Scalar, op: u8, jmp32: bool, same: bool) -> Option<bool> {
    let (t1, t2) = if jmp32 {
        (a.var.subreg(), b.var.subreg())
    } else {
        (a.var, b.var)
    };
    let bounds = |s: &Scalar| {
        if jmp32 {
            (
                u64::from(s.u32_min),
                u64::from(s.u32_max),
                i64::from(s.s32_min),
                i64::from(s.s32_max),
            )
        } else {
            (s.umin, s.umax, s.smin, s.smax)
        }
    };
    let (umin1, umax1, smin1, smax1) = bounds(a);
    let (umin2, umax2, smin2, smax2) = bounds(b);
    if same {
        return match op {
            jmp::JGE | jmp::JLE | jmp::JSGE | jmp::JSLE | jmp::JEQ => Some(true),
            jmp::JGT | jmp::JLT | jmp::JSGT | jmp::JSLT | jmp::JNE => Some(false),
            jmp::JSET if t1.is_const() => Some(t1.value != 0),
            jmp::JSET => (smin1 > 0 || smax1 < 0).then_some(true),
            _ => None,
        };
    }
    let apart = || {
        !t1.overlap(t2)
            || umin1 > umax2
            || umax1 < umin2
            || smin1 > smax2
            || smax1 < smin2
            || (!jmp32
                && (a.u32_min > b.u32_max
                    || a.u32_max < b.u32_min
                    || a.s32_min > b.s32_max
                    || a.s32_max < b.s32_min))
    };
    match op {
        jmp::JEQ => {
            if t1.is_const() && t2.is_const() {
                return Some(t1.value == t2.value);
            }
            apart().then_some(false)
        }
        jmp::JNE => {
            if t1.is_const() && t2.is_const() {
                return Some(t1.value != t2.value);
            }
            apart().then_some(true)
        }
        jmp::JSET => {
            let (t1, t2) = if b.constant(jmp32).is_none() {
                (t2, t1)
            } else {
                (t1, t2)
            };
            if a.constant(jmp32).is_none() && b.constant(jmp32).is_none() {
                return None;
            }
            if (!t1.mask & t1.value) & t2.value != 0 {
                Some(true)
            } else if (t1.mask | t1.value) & t2.value == 0 {
                Some(false)
            } else {
                None
            }
        }
        jmp::JGT => order(umin1 > umax2, umax1 <= umin2),
        jmp::JSGT => order(smin1 > smax2, smax1 <= smin2),
        jmp::JLT => order(umax1 < umin2, umin1 >= umax2),
        jmp::JSLT => order(smax1 < smin2, smin1 >= smax2),
        jmp::JGE => order(umin1 >= umax2, umax1 < umin2),
        jmp::JSGE => order(smin1 >= smax2, smax1 < smin2),
        jmp::JLE => order(umax1 <= umin2, umin1 > umax2),
        jmp::JSLE => order(smax1 <= smin2, smin1 > smax2),
        _ => None,
    }
}

fn order(yes: bool, no: bool) -> Option<bool> {
    if yes {
        Some(true)
    } else if no {
        Some(false)
    } else {
        None
    }
}

/// `regs_refine_cond_op` of `a <op> b` holding, then `reg_bounds_sync` of
/// both, as `reg_set_min_max` does on each side of a jump.
pub(crate) fn refine(a: &mut Scalar, b: &mut Scalar, op: u8, jmp32: bool) {
    refine_cond(a, b, op, jmp32);
    a.sync();
    b.sync();
}

fn refine_cond(a: &mut Scalar, b: &mut Scalar, op: u8, jmp32: bool) {
    let (a, b, op) = match op {
        jmp::JGE | jmp::JGT | jmp::JSGE | jmp::JSGT => (b, a, flip(op)),
        _ => (a, b, op),
    };
    match op {
        jmp::JEQ => {
            if jmp32 {
                a.u32_min = a.u32_min.max(b.u32_min);
                a.u32_max = a.u32_max.min(b.u32_max);
                a.s32_min = a.s32_min.max(b.s32_min);
                a.s32_max = a.s32_max.min(b.s32_max);
                b.u32_min = a.u32_min;
                b.u32_max = a.u32_max;
                b.s32_min = a.s32_min;
                b.s32_max = a.s32_max;
                let t = a.var.subreg().intersect(b.var.subreg());
                a.var = a.var.with_subreg(t);
                b.var = b.var.with_subreg(t);
            } else {
                a.umin = a.umin.max(b.umin);
                a.umax = a.umax.min(b.umax);
                a.smin = a.smin.max(b.smin);
                a.smax = a.smax.min(b.smax);
                b.umin = a.umin;
                b.umax = a.umax;
                b.smin = a.smin;
                b.smax = a.smax;
                a.var = a.var.intersect(b.var);
                b.var = a.var;
            }
        }
        jmp::JNE => {
            let (a, b) = if b.constant(jmp32).is_none() {
                (b, a)
            } else {
                (a, b)
            };
            let Some(val) = b.constant(jmp32) else {
                return;
            };
            if jmp32 {
                if a.u32_min == val as u32 {
                    a.u32_min = a.u32_min.wrapping_add(1);
                }
                if a.u32_max == val as u32 {
                    a.u32_max = a.u32_max.wrapping_sub(1);
                }
                if a.s32_min == val as i32 {
                    a.s32_min = a.s32_min.wrapping_add(1);
                }
                if a.s32_max == val as i32 {
                    a.s32_max = a.s32_max.wrapping_sub(1);
                }
            } else {
                if a.umin == val {
                    a.umin = a.umin.wrapping_add(1);
                }
                if a.umax == val {
                    a.umax = a.umax.wrapping_sub(1);
                }
                if a.smin == val as i64 {
                    a.smin = a.smin.wrapping_add(1);
                }
                if a.smax == val as i64 {
                    a.smax = a.smax.wrapping_sub(1);
                }
            }
        }
        jmp::JSET => {
            let (a, b) = if b.constant(jmp32).is_none() {
                (b, a)
            } else {
                (a, b)
            };
            let Some(val) = b.constant(jmp32) else {
                return;
            };
            if !val.is_power_of_two() {
                return;
            }
            if jmp32 {
                let t = a.var.subreg().or(Tnum::known(val));
                a.var = a.var.with_subreg(t);
            } else {
                a.var = a.var.or(Tnum::known(val));
            }
        }
        jmp::NOT_JSET => {
            let (a, b) = if b.constant(jmp32).is_none() {
                (b, a)
            } else {
                (a, b)
            };
            let Some(val) = b.constant(jmp32) else {
                return;
            };
            a.unbounded();
            if jmp32 {
                let t = a.var.subreg().and(Tnum::known(!val));
                a.var = a.var.with_subreg(t);
            } else {
                a.var = a.var.and(Tnum::known(!val));
            }
        }
        jmp::JLE => {
            if jmp32 {
                a.u32_max = a.u32_max.min(b.u32_max);
                b.u32_min = a.u32_min.max(b.u32_min);
            } else {
                a.umax = a.umax.min(b.umax);
                b.umin = a.umin.max(b.umin);
            }
        }
        jmp::JLT => {
            if jmp32 {
                a.u32_max = a.u32_max.min(b.u32_max.wrapping_sub(1));
                b.u32_min = a.u32_min.wrapping_add(1).max(b.u32_min);
            } else {
                a.umax = a.umax.min(b.umax.wrapping_sub(1));
                b.umin = a.umin.wrapping_add(1).max(b.umin);
            }
        }
        jmp::JSLE => {
            if jmp32 {
                a.s32_max = a.s32_max.min(b.s32_max);
                b.s32_min = a.s32_min.max(b.s32_min);
            } else {
                a.smax = a.smax.min(b.smax);
                b.smin = a.smin.max(b.smin);
            }
        }
        jmp::JSLT => {
            if jmp32 {
                a.s32_max = a.s32_max.min(b.s32_max.wrapping_sub(1));
                b.s32_min = a.s32_min.wrapping_add(1).max(b.s32_min);
            } else {
                a.smax = a.smax.min(b.smax.wrapping_sub(1));
                b.smin = a.smin.wrapping_add(1).max(b.smin);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether `v` is one of the values `s` may hold.
    fn holds(s: &Scalar, v: u64) -> bool {
        let (v32, s32) = (v as u32, v as u32 as i32);
        v & !s.var.mask == s.var.value
            && (s.umin..=s.umax).contains(&v)
            && (s.smin..=s.smax).contains(&(v as i64))
            && (s.u32_min..=s.u32_max).contains(&v32)
            && (s.s32_min..=s.s32_max).contains(&s32)
    }

    /// The scalar of exactly these values' bits and bounds, then synced.
    fn of(values: &[u64]) -> Scalar {
        let mut s = Scalar::known(values[0]);
        for &v in &values[1..] {
            let k = Scalar::known(v);
            s.var = s.var.union(k.var);
            s.umin = s.umin.min(v);
            s.umax = s.umax.max(v);
            s.smin = s.smin.min(v as i64);
            s.smax = s.smax.max(v as i64);
            s.u32_min = s.u32_min.min(v as u32);
            s.u32_max = s.u32_max.max(v as u32);
            s.s32_min = s.s32_min.min(v as i32);
            s.s32_max = s.s32_max.max(v as i32);
        }
        s.sync();
        s
    }

    /// A seeded xorshift, for values near the edges as often as not.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn value(&mut self) -> u64 {
            let r = self.next();
            match r % 6 {
                0 => r >> (r % 64),
                1 => (r >> 8) % 16,
                2 => (((r >> 8) % 16) as i64).wrapping_neg() as u64,
                3 => u64::from(r as u32),
                4 => 1 << (r % 64),
                _ => r,
            }
        }
    }

    /// What the operation gives of two values, as the interpreter runs it.
    fn concrete(op: u8, alu32: bool, signed: bool, a: u64, b: u64) -> u64 {
        if alu32 {
            let (a, b) = (a as u32, b as u32);
            u64::from(match op {
                op::ADD => a.wrapping_add(b),
                op::SUB => a.wrapping_sub(b),
                op::MUL => a.wrapping_mul(b),
                op::DIV if b == 0 => 0,
                op::DIV if signed => (a as i32).wrapping_div(b as i32) as u32,
                op::DIV => a / b,
                op::MOD if b == 0 => a,
                op::MOD if signed => (a as i32).wrapping_rem(b as i32) as u32,
                op::MOD => a % b,
                op::AND => a & b,
                op::OR => a | b,
                op::XOR => a ^ b,
                op::LSH => a << (b & 31),
                op::RSH => a >> (b & 31),
                op::ARSH => ((a as i32) >> (b & 31)) as u32,
                op::NEG => a.wrapping_neg(),
                _ => unreachable!(),
            })
        } else {
            match op {
                op::ADD => a.wrapping_add(b),
                op::SUB => a.wrapping_sub(b),
                op::MUL => a.wrapping_mul(b),
                op::DIV if b == 0 => 0,
                op::DIV if signed => (a as i64).wrapping_div(b as i64) as u64,
                op::DIV => a / b,
                op::MOD if b == 0 => a,
                op::MOD if signed => (a as i64).wrapping_rem(b as i64) as u64,
                op::MOD => a % b,
                op::AND => a & b,
                op::OR => a | b,
                op::XOR => a ^ b,
                op::LSH => a << (b & 63),
                op::RSH => a >> (b & 63),
                op::ARSH => ((a as i64) >> (b & 63)) as u64,
                op::NEG => a.wrapping_neg(),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn every_operation_s_bounds_hold_its_results() {
        let ops = [
            op::ADD,
            op::SUB,
            op::MUL,
            op::DIV,
            op::MOD,
            op::AND,
            op::OR,
            op::XOR,
            op::LSH,
            op::RSH,
            op::ARSH,
            op::NEG,
        ];
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for round in 0..20_000 {
            let op = ops[round % ops.len()];
            let alu32 = round / ops.len() % 2 == 1;
            let signed = matches!(op, op::DIV | op::MOD) && round / 7 % 2 == 1;
            let dst: Vec<u64> = (0..1 + rng.next() % 4).map(|_| rng.value()).collect();
            let shifts = matches!(op, op::LSH | op::RSH | op::ARSH);
            let src: Vec<u64> = if shifts {
                vec![rng.next() % if alu32 { 32 } else { 64 }]
            } else if matches!(op, op::DIV | op::MOD) || rng.next().is_multiple_of(2) {
                vec![rng.value()]
            } else {
                (0..1 + rng.next() % 3).map(|_| rng.value()).collect()
            };
            let (a, b) = (of(&dst), of(&src));
            let mut r = a;
            r.alu(op, alu32, signed, &b, (false, 0));
            assert!(r.sane(), "{op:#x} {alu32} {a:?} {b:?} -> {r:?}");
            for &x in &dst {
                for &y in &src {
                    let v = concrete(op, alu32, signed, x, y);
                    assert!(
                        holds(&r, v),
                        "{op:#x} alu32={alu32} signed={signed} {x:#x} {y:#x} = {v:#x} not in {r:?}"
                    );
                }
            }
        }
    }

    /// `a <op> b` of two values.
    fn holds_jump(op: u8, a: u64, b: u64, jmp32: bool) -> bool {
        let (a, b) = if jmp32 {
            (u64::from(a as u32), u64::from(b as u32))
        } else {
            (a, b)
        };
        let (sa, sb) = if jmp32 {
            (i64::from(a as u32 as i32), i64::from(b as u32 as i32))
        } else {
            (a as i64, b as i64)
        };
        match op {
            jmp::JEQ => a == b,
            jmp::JNE => a != b,
            jmp::JSET => a & b != 0,
            jmp::JGT => a > b,
            jmp::JGE => a >= b,
            jmp::JLT => a < b,
            jmp::JLE => a <= b,
            jmp::JSGT => sa > sb,
            jmp::JSGE => sa >= sb,
            jmp::JSLT => sa < sb,
            _ => sa <= sb,
        }
    }

    #[test]
    fn a_jump_is_decided_only_where_it_goes_one_way_and_each_side_holds_its_values() {
        let ops = [
            jmp::JEQ,
            jmp::JNE,
            jmp::JSET,
            jmp::JGT,
            jmp::JGE,
            jmp::JLT,
            jmp::JLE,
            jmp::JSGT,
            jmp::JSGE,
            jmp::JSLT,
            jmp::JSLE,
        ];
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        for round in 0..20_000 {
            let op = ops[round % ops.len()];
            let jmp32 = round / ops.len() % 2 == 1;
            let xs: Vec<u64> = (0..1 + rng.next() % 4).map(|_| rng.value()).collect();
            let ys: Vec<u64> = (0..1 + rng.next() % 2).map(|_| rng.value()).collect();
            let (a, b) = (of(&xs), of(&ys));
            let outcomes: Vec<(u64, u64, bool)> = xs
                .iter()
                .flat_map(|&x| ys.iter().map(move |&y| (x, y, holds_jump(op, x, y, jmp32))))
                .collect();
            match taken(&a, &b, op, jmp32, false) {
                Some(way) => assert!(
                    outcomes.iter().all(|&(_, _, o)| o == way),
                    "{op:#x} {jmp32} {xs:x?} {ys:x?} decided {way}"
                ),
                None => {
                    for (side, op) in [(true, op), (false, reverse(op))] {
                        let (mut ra, mut rb) = (a, b);
                        refine(&mut ra, &mut rb, op, jmp32);
                        for &(x, y, o) in &outcomes {
                            if o == side {
                                assert!(
                                    holds(&ra, x) && holds(&rb, y),
                                    "{op:#x} {jmp32} {x:#x} {y:#x} lost on the {side} side: {ra:?} {rb:?}"
                                );
                            }
                        }
                    }
                }
            }
            if xs.len() == 1 && ys.len() == 1 {
                assert_eq!(
                    taken(&a, &b, op, jmp32, false),
                    Some(outcomes[0].2),
                    "{op:#x} {jmp32} {xs:x?} {ys:x?}"
                );
            }
        }
    }

    #[test]
    fn the_bounds_of_common_operations_are_7_0_s() {
        let alu = |mut s: Scalar, op: u8, k: u64| {
            s.alu(op, false, false, &Scalar::known(k), (false, 0));
            s
        };
        let and = alu(Scalar::UNKNOWN, op::AND, 0xff);
        assert_eq!((and.umin, and.umax, and.smin, and.smax), (0, 0xff, 0, 0xff));
        let rsh = alu(Scalar::UNKNOWN, op::RSH, 60);
        assert_eq!((rsh.umin, rsh.umax), (0, 15));
        let mul = alu(alu(Scalar::UNKNOWN, op::AND, 7), op::MUL, 3);
        assert_eq!((mul.umin, mul.umax), (0, 21));
        let sub = alu(alu(Scalar::UNKNOWN, op::AND, 7), op::SUB, 1);
        assert_eq!(
            (sub.smin, sub.smax, sub.umin, sub.umax),
            (-1, 6, 0, u64::MAX)
        );
        let sign = alu(Scalar::UNKNOWN, op::ARSH, 63);
        assert_eq!((sign.smin, sign.smax), (-1, 0));
        assert_eq!(forks(op::AND, &sign, &Scalar::known(5)), Some(false));
        let mut smod = Scalar::UNKNOWN;
        smod.alu(op::MOD, false, true, &Scalar::known(10), (false, 0));
        assert_eq!((smod.smin, smod.smax), (-9, 9));
        // A 16-bit swap of a byte: the byte's bits move up.
        let mut swap = alu(Scalar::UNKNOWN, op::AND, 0xff);
        swap.alu(op::END, true, false, &swap.clone(), (true, 16));
        assert_eq!(
            (swap.var.value, swap.var.mask, swap.umax),
            (0, 0xff00, 0xff00)
        );
        // A 32-bit load of an unknown value, then its high half.
        let mut low = Scalar::UNKNOWN;
        low.coerce(4);
        assert_eq!(alu(low, op::RSH, 32).value(), Some(0));
        // The sign extension of a byte of 0 to 255.
        let mut sx = alu(Scalar::UNKNOWN, op::AND, 0xff);
        sx.coerce_sx(1);
        assert_eq!((sx.smin, sx.smax), (-128, 127));
    }

    #[test]
    fn a_register_linked_with_a_constant_follows_with_it() {
        let mut known = Scalar::UNKNOWN;
        known.id = 7;
        let mut copy = known;
        let before = copy.umax;
        copy.alu(op::ADD, false, false, &Scalar::known(1), (false, 0));
        copy.link_after(op::ADD, false, &Scalar::known(1), before);
        assert_eq!((copy.id, copy.off), (7 | ADD_CONST64, 1));
        let mut nine = Scalar::known(9);
        refine(&mut known, &mut nine, jmp::JLE, false);
        copy.follow(&known);
        assert_eq!((copy.umin, copy.umax), (1, 10));
        // Another constant is not followed: the ID goes.
        let before = copy.umax;
        copy.link_after(op::ADD, false, &Scalar::known(1), before);
        assert_eq!((copy.id, copy.off), (0, 0));
    }

    #[test]
    fn the_known_bits_step_to_the_next_value() {
        let t = Tnum::new(0b0111_0000, 0b1000_0010);
        assert_eq!(t.step(0b1111_0001), 0b1111_0010);
        assert_eq!(t.step(0), t.value);
        assert_eq!(t.step(u64::MAX), t.value | t.mask);
    }
}
