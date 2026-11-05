//! Integer IEEE-754 arithmetic with explicit SSE rounding and status bits.
//! No host floating-point environment participates in guest execution.
#[derive(Clone, Copy)]
pub(crate) struct Format {
    pub fraction: u32,
    exponent: u32,
    bias: i32,
}
pub(crate) const F32: Format = Format {
    fraction: 23,
    exponent: 8,
    bias: 127,
};
pub(crate) const F64: Format = Format {
    fraction: 52,
    exponent: 11,
    bias: 1023,
};
impl Format {
    pub(crate) fn bias(self) -> i32 {
        self.bias
    }
    pub(crate) fn sign(self) -> u64 {
        1 << (self.fraction + self.exponent)
    }
    pub(crate) fn mantissa(self) -> u64 {
        (1 << self.fraction) - 1
    }
    pub(crate) fn infinity(self) -> u64 {
        ((1 << self.exponent) - 1) << self.fraction
    }
    fn nan(self, x: u64) -> bool {
        x & !self.sign() > self.infinity()
    }
    fn snan(self, x: u64) -> bool {
        self.nan(x) && x & (1 << (self.fraction - 1)) == 0
    }
    fn quiet(self, x: u64) -> u64 {
        x | (1 << (self.fraction - 1))
    }
    pub(crate) fn indefinite(self) -> u64 {
        self.sign() | self.infinity() | (1 << (self.fraction - 1))
    }
    fn finite(self, x: u64) -> (bool, u128, i32) {
        let exponent = ((x & !self.sign()) >> self.fraction) as i32;
        (
            x & self.sign() != 0,
            u128::from(x & self.mantissa()) | if exponent == 0 { 0 } else { 1 << self.fraction },
            exponent.max(1) - self.bias - self.fraction as i32,
        )
    }
    fn input(self, x: u64, mxcsr: u32) -> (u64, u32) {
        let x = x & (self.sign() | self.infinity() | self.mantissa());
        if x & self.infinity() == 0 && x & self.mantissa() != 0 {
            if mxcsr & (1 << 6) != 0 {
                (x & self.sign(), 0)
            } else {
                (x, 2)
            }
        } else {
            (x, 0)
        }
    }
}

fn sticky(value: u128, count: u32) -> u128 {
    if count == 0 {
        value
    } else if count >= 128 {
        u128::from(value != 0)
    } else {
        (value >> count) | u128::from(value & ((1u128 << count) - 1) != 0)
    }
}
pub(crate) fn round(
    f: Format,
    negative: bool,
    magnitude: u128,
    power: i32,
    mxcsr: u32,
) -> (u64, u32) {
    let sign = if negative { f.sign() } else { 0 };
    if magnitude == 0 {
        return (sign, 0);
    }
    let high = 127 - magnitude.leading_zeros() as i32;
    let normal_shift = high - f.fraction as i32;
    let intrinsic_inexact = normal_shift > 0 && magnitude & ((1u128 << normal_shift) - 1) != 0;
    let exponent = high + power;
    let minimum = 1 - f.bias;
    let shift = (high - f.fraction as i32).max(minimum - f.fraction as i32 - power);
    let (mut result, remainder, half) = if shift > 0 {
        let shift = shift as u32;
        if shift >= 128 {
            (
                0,
                magnitude,
                if shift == 128 {
                    1u128 << 127
                } else {
                    u128::MAX
                },
            )
        } else {
            (
                magnitude >> shift,
                magnitude & ((1u128 << shift) - 1),
                1u128 << (shift - 1),
            )
        }
    } else {
        (magnitude << (-shift as u32), 0, 0)
    };
    let mode = (mxcsr >> 13) & 3;
    let increment = remainder != 0
        && match mode {
            0 => remainder > half || (remainder == half && result & 1 != 0),
            1 => negative,
            2 => !negative,
            _ => false,
        };
    result += u128::from(increment);
    let mut final_exponent = exponent.max(minimum);
    if result >= (1u128 << (f.fraction + 1)) {
        result >>= 1;
        final_exponent += 1;
    }
    if final_exponent > f.bias {
        let infinity = mode == 0 || (mode == 1 && negative) || (mode == 2 && !negative);
        let precision = mxcsr & (1 << 10) != 0 || intrinsic_inexact;
        return (
            sign | if infinity {
                f.infinity()
            } else {
                f.infinity() - 1
            },
            8 | if precision { 32 } else { 0 },
        );
    }
    let subnormal = result < (1u128 << f.fraction);
    let mut flags = if remainder != 0 { 32 } else { 0 };
    if subnormal && remainder != 0 {
        flags |= 16;
    }
    if subnormal && mxcsr & (1 << 11) == 0 {
        flags = 16 | if intrinsic_inexact { 32 } else { 0 };
    }
    if subnormal && result != 0 && mxcsr & (1 << 15) != 0 {
        return (sign, flags | 16 | 32);
    }
    let exponent_bits = if subnormal {
        0
    } else {
        (final_exponent + f.bias) as u64
    };
    (
        sign | (exponent_bits << f.fraction) | (result as u64 & f.mantissa()),
        flags,
    )
}

#[derive(Clone, Copy)]
pub(crate) enum Operation {
    Add,
    Sub,
    Mul,
    Div,
    Sqrt,
    Min,
    Max,
}
pub(crate) fn arithmetic(
    f: Format,
    operation: Operation,
    a: u64,
    b: u64,
    mxcsr: u32,
) -> (u64, u32) {
    let (a, af) = f.input(a, mxcsr);
    let (b, bf) = f.input(b, mxcsr);
    let flags = af | bf;
    if matches!(operation, Operation::Min | Operation::Max) {
        if f.nan(a) || f.nan(b) {
            return (b, 1);
        }
        let order = compare_bits(f, a, b);
        return (
            if (matches!(operation, Operation::Min) && order < 0)
                || (matches!(operation, Operation::Max) && order > 0)
            {
                a
            } else {
                b
            },
            flags,
        );
    }
    if f.nan(a) || f.nan(b) {
        let chosen = if f.nan(a) { a } else { b };
        return (f.quiet(chosen), u32::from(f.snan(a) || f.snan(b)));
    }
    if flags & 2 != 0 && mxcsr & (1 << 8) == 0 {
        return (a, 2);
    }
    let (an, am, ap) = f.finite(a);
    let (mut bn, bm, bp) = f.finite(b);
    let ai = a & !f.sign() == f.infinity();
    let bi = b & !f.sign() == f.infinity();
    let invalid = || (f.indefinite(), (flags & !2) | 1);
    let result = match operation {
        Operation::Add | Operation::Sub => {
            if matches!(operation, Operation::Sub) {
                bn = !bn;
            }
            if ai || bi {
                if ai && bi && an != bn {
                    return invalid();
                }
                return (
                    (if ai {
                        a
                    } else {
                        (b & !f.sign()) | if bn { f.sign() } else { 0 }
                    }),
                    flags,
                );
            }
            let power = ap.max(bp) - 4;
            let aa = sticky(am << 4, (ap.max(bp) - ap) as u32) as i128 * if an { -1 } else { 1 };
            let bb = sticky(bm << 4, (ap.max(bp) - bp) as u32) as i128 * if bn { -1 } else { 1 };
            let sum = aa + bb;
            let negative = sum < 0
                || (sum == 0
                    && if am == 0 && bm == 0 && an == bn {
                        an
                    } else {
                        (mxcsr >> 13) & 3 == 1
                    });
            round(f, negative, sum.unsigned_abs(), power, mxcsr)
        }
        Operation::Mul => {
            if (ai && bm == 0) || (bi && am == 0) {
                return invalid();
            }
            if ai || bi {
                return (f.infinity() | if an != bn { f.sign() } else { 0 }, flags);
            }
            round(f, an != bn, am * bm, ap + bp, mxcsr)
        }
        Operation::Div => {
            if (ai && bi) || (am == 0 && bm == 0 && !ai && !bi) {
                return invalid();
            }
            if ai || bm == 0 {
                return (
                    f.infinity() | if an != bn { f.sign() } else { 0 },
                    (if bm == 0 { flags & !2 } else { flags }) | if bm == 0 && !ai { 4 } else { 0 },
                );
            }
            if bi || am == 0 {
                return (if an != bn { f.sign() } else { 0 }, flags);
            }
            // Normalize quotient precision even for a subnormal numerator or
            // divisor. A fixed shift loses tiny-but-representable quotients.
            let numerator_high = 127 - am.leading_zeros();
            let divisor_high = 127 - bm.leading_zeros();
            let scale = f.fraction + 5 + divisor_high - numerator_high;
            let numerator = am << scale;
            let quotient = numerator / bm;
            round(
                f,
                an != bn,
                quotient | u128::from(!numerator.is_multiple_of(bm)),
                ap - bp - scale as i32,
                mxcsr,
            )
        }
        Operation::Sqrt => {
            if an && am != 0 || an && ai {
                return invalid();
            }
            if ai || am == 0 {
                return (a, flags);
            }
            let mut power = ap;
            let mut mag = am;
            if power & 1 != 0 {
                mag <<= 1;
                power -= 1;
            }
            let high = 127 - mag.leading_zeros();
            let scale = (f.fraction + 4) * 2 - high;
            let scale = scale & !1;
            let value = mag << scale;
            let mut low = 0u128;
            let mut high = 1u128 << 64;
            while low + 1 < high {
                let mid = low + (high - low) / 2;
                if mid <= value / mid {
                    low = mid;
                } else {
                    high = mid;
                }
            }
            round(
                f,
                false,
                low | u128::from(low * low != value),
                power / 2 - scale as i32 / 2,
                mxcsr,
            )
        }
        Operation::Min | Operation::Max => unreachable!(),
    };
    (result.0, result.1 | flags)
}

fn compare_bits(f: Format, a: u64, b: u64) -> i8 {
    if a & !f.sign() == 0 && b & !f.sign() == 0 {
        return 0;
    }
    let key = |v: u64| if v & f.sign() != 0 { !v } else { v | f.sign() };
    match key(a).cmp(&key(b)) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

pub(crate) fn compare(f: Format, a: u64, b: u64, mxcsr: u32, signaling: bool) -> (Option<i8>, u32) {
    let (a, af) = f.input(a, mxcsr);
    let (b, bf) = f.input(b, mxcsr);
    let nan = f.nan(a) || f.nan(b);
    (
        if nan {
            None
        } else {
            Some(compare_bits(f, a, b))
        },
        if nan {
            u32::from(f.snan(a) || f.snan(b) || signaling)
        } else {
            af | bf
        },
    )
}

pub(crate) fn from_integer(f: Format, value: i64, mxcsr: u32) -> (u64, u32) {
    round(f, value < 0, u128::from(value.unsigned_abs()), 0, mxcsr)
}
pub(crate) fn convert(from: Format, to: Format, value: u64, mxcsr: u32) -> (u64, u32) {
    let (value, flags) = from.input(value, mxcsr);
    let sign = if value & from.sign() != 0 {
        to.sign()
    } else {
        0
    };
    if from.nan(value) {
        let payload = value & from.mantissa();
        let payload = if from.fraction > to.fraction {
            payload >> (from.fraction - to.fraction)
        } else {
            payload << (to.fraction - from.fraction)
        };
        return (
            sign | to.infinity() | payload | (1 << (to.fraction - 1)),
            flags | u32::from(from.snan(value)),
        );
    }
    if value & !from.sign() == from.infinity() {
        return (sign | to.infinity(), flags);
    }
    let (negative, magnitude, power) = from.finite(value);
    let (value, rounding) = round(to, negative, magnitude, power, mxcsr);
    (value, flags | rounding)
}
pub(crate) fn to_integer(f: Format, value: u64, width: u32, mxcsr: u32) -> (u64, u32) {
    let (value, flags) = f.input(value, mxcsr);
    // CVTT conversions signal precision for tiny fractions, not DE.
    let flags = flags & !2;
    let indefinite = 1u64 << (width - 1);
    if f.nan(value) || value & !f.sign() == f.infinity() {
        return (indefinite, flags | 1);
    }
    let (negative, magnitude, power) = f.finite(value);
    let (integer, fraction) = if power >= 0 {
        if power >= 128 || magnitude > (u128::MAX >> power) {
            return (indefinite, flags | 1);
        }
        (magnitude << power, false)
    } else {
        let shift = (-power) as u32;
        if shift >= 128 {
            (0, magnitude != 0)
        } else {
            (magnitude >> shift, magnitude & ((1u128 << shift) - 1) != 0)
        }
    };
    let limit = 1u128 << (width - 1);
    if integer > limit || integer == limit && !negative {
        return (indefinite, flags | 1);
    }
    let result = integer as u64;
    (
        if negative {
            result.wrapping_neg()
        } else {
            result
        },
        flags | if fraction { 32 } else { 0 },
    )
}
