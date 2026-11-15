//! Wide binary values for the x87 unit's transcendental instructions, in
//! integers: a sign, a 256-bit mantissa and a power of two. Every step keeps
//! 256 bits, and where it drops bits that are not zero it sets the lowest bit
//! it keeps (rounding to odd). A value that is not exact so never looks exact,
//! and the one rounding into the 80-bit format knows which way to go.
use core::cmp::Ordering;

const LIMBS: usize = 4;
/// What a step works in before it keeps 256 bits, lowest limb first.
type Long = [u64; 8];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Wide {
    pub(crate) negative: bool,
    /// Lowest limb first, with its top bit set unless the value is zero.
    mantissa: [u64; LIMBS],
    /// What the mantissa, as an integer, is multiplied by as a power of two.
    power: i32,
}

/// π/2, ln 2 and log2(e), each below its true value by less than its last
/// bit, which is set: none of them is exact.
pub(crate) const HALF_PI: Wide = Wide {
    negative: false,
    mantissa: [
        0x020b_bea6_3b13_9b23,
        0x2902_4e08_8a67_cc74,
        0xc4c6_628b_80dc_1cd1,
        0xc90f_daa2_2168_c234,
    ],
    power: -255,
};
pub(crate) const LN_2: Wide = Wide {
    negative: false,
    mantissa: [
        0x8a0d_175b_8baa_fa2b,
        0x40f3_4326_7298_b62d,
        0xc9e3_b398_03f2_f6af,
        0xb172_17f7_d1cf_79ab,
    ],
    power: -256,
};
pub(crate) const LOG2_E: Wide = Wide {
    negative: false,
    mantissa: [
        0x8b25_166c_d1a1_3247,
        0xeb57_7aa8_dd69_5a58,
        0xbe87_fed0_691d_3e88,
        0xb8aa_3b29_5c17_f0bb,
    ],
    power: -255,
};
pub(crate) const ONE: Wide = Wide {
    negative: false,
    mantissa: [0, 0, 0, 1 << 63],
    power: -255,
};
const ZERO: Wide = Wide {
    negative: false,
    mantissa: [0; LIMBS],
    power: 0,
};

fn leading_zeros(value: &Long) -> u32 {
    value
        .iter()
        .rev()
        .position(|&limb| limb != 0)
        .map_or(512, |at| at as u32 * 64 + value[7 - at].leading_zeros())
}

fn shift_left(value: Long, amount: u32) -> Long {
    let (limbs, bits) = ((amount / 64) as usize, amount % 64);
    let mut out = [0; 8];
    for at in limbs..8 {
        let low = value[at - limbs];
        let below = if at > limbs && bits != 0 {
            value[at - limbs - 1] >> (64 - bits)
        } else {
            0
        };
        out[at] = if bits == 0 { low } else { low << bits | below };
    }
    out
}

/// A shift to the right whose lost bits, if any is set, set the lowest bit.
fn shift_right_sticky(value: Long, amount: u32) -> Long {
    if amount == 0 {
        return value;
    }
    if amount >= 512 {
        return [u64::from(value != [0; 8]), 0, 0, 0, 0, 0, 0, 0];
    }
    let (limbs, bits) = ((amount / 64) as usize, amount % 64);
    let mut out = [0; 8];
    for at in 0..8 - limbs {
        let high = if at + limbs + 1 < 8 {
            value[at + limbs + 1]
        } else {
            0
        };
        out[at] = if bits == 0 {
            value[at + limbs]
        } else {
            value[at + limbs] >> bits | high << (64 - bits)
        };
    }
    let lost = value[..limbs].iter().any(|&limb| limb != 0)
        || (bits != 0 && value[limbs] << (64 - bits) != 0);
    out[0] |= u64::from(lost);
    out
}

fn add_long(a: &Long, b: &Long) -> Long {
    let mut out = [0; 8];
    let mut carry = false;
    for at in 0..8 {
        let (sum, first) = a[at].overflowing_add(b[at]);
        let (sum, second) = sum.overflowing_add(u64::from(carry));
        out[at] = sum;
        carry = first || second;
    }
    out
}

/// `a - b`, where `a` is not the smaller.
fn subtract_long(a: &Long, b: &Long) -> Long {
    let mut out = [0; 8];
    let mut borrow = false;
    for at in 0..8 {
        let (difference, first) = a[at].overflowing_sub(b[at]);
        let (difference, second) = difference.overflowing_sub(u64::from(borrow));
        out[at] = difference;
        borrow = first || second;
    }
    out
}

fn compare_long(a: &Long, b: &Long) -> Ordering {
    a.iter().rev().cmp(b.iter().rev())
}

impl Wide {
    /// `value * 2^power`, rounded to odd into 256 bits.
    fn from_long(negative: bool, value: Long, power: i32) -> Wide {
        let zeros = leading_zeros(&value);
        if zeros == 512 {
            return Wide { negative, ..ZERO };
        }
        let top = shift_left(value, zeros);
        let lost = top[..4].iter().any(|&limb| limb != 0);
        let mut mantissa = [top[4], top[5], top[6], top[7]];
        mantissa[0] |= u64::from(lost);
        Wide {
            negative,
            mantissa,
            power: power - zeros as i32 + 256,
        }
    }
    /// `value * 2^power`, which is exact.
    pub(crate) fn new(negative: bool, value: u128, power: i32) -> Wide {
        let mut long = [0; 8];
        long[0] = value as u64;
        long[1] = (value >> 64) as u64;
        Wide::from_long(negative, long, power)
    }
    pub(crate) fn zero(self) -> bool {
        self.mantissa == [0; LIMBS]
    }
    fn long(self) -> Long {
        let mut long = [0; 8];
        long[..4].copy_from_slice(&self.mantissa);
        long
    }
    /// The power of two of its top bit, which only zero lacks.
    pub(crate) fn magnitude(self) -> i32 {
        self.power + 255
    }
    #[must_use]
    pub(crate) fn negate(self) -> Wide {
        Wide {
            negative: !self.negative,
            ..self
        }
    }
    #[must_use]
    pub(crate) fn scale(self, power: i32) -> Wide {
        Wide {
            power: self.power + power,
            ..self
        }
    }
    /// Compares the sizes, leaving the signs out.
    pub(crate) fn compare_size(self, other: Wide) -> Ordering {
        match (self.zero(), other.zero()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => self
                .power
                .cmp(&other.power)
                .then_with(|| self.mantissa.iter().rev().cmp(other.mantissa.iter().rev())),
        }
    }
    #[must_use]
    pub(crate) fn add(self, other: Wide) -> Wide {
        if other.zero() {
            return self;
        }
        if self.zero() {
            return other;
        }
        let (large, small) = if self.compare_size(other) == Ordering::Less {
            (other, self)
        } else {
            (self, other)
        };
        // 192 bits below each mantissa, and room above for a carry.
        let place = |v: Wide| shift_left(v.long(), 192);
        let distance = (large.power - small.power) as u32;
        let (a, b) = (place(large), shift_right_sticky(place(small), distance));
        let sum = if large.negative == small.negative {
            add_long(&a, &b)
        } else {
            subtract_long(&a, &b)
        };
        Wide::from_long(large.negative, sum, large.power - 192)
    }
    #[must_use]
    pub(crate) fn subtract(self, other: Wide) -> Wide {
        self.add(other.negate())
    }
    #[must_use]
    pub(crate) fn multiply(self, other: Wide) -> Wide {
        let negative = self.negative != other.negative;
        if self.zero() || other.zero() {
            return Wide { negative, ..ZERO };
        }
        let mut product = [0u64; 8];
        for (i, &a) in self.mantissa.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &b) in other.mantissa.iter().enumerate() {
                let sum = u128::from(a) * u128::from(b) + u128::from(product[i + j]) + carry;
                product[i + j] = sum as u64;
                carry = sum >> 64;
            }
            product[i + LIMBS] = carry as u64;
        }
        Wide::from_long(negative, product, self.power + other.power)
    }
    #[must_use]
    pub(crate) fn divide(self, other: Wide) -> Wide {
        let negative = self.negative != other.negative;
        if self.zero() {
            return Wide { negative, ..ZERO };
        }
        // 512 bits over 256, by bits: a quotient of 256 or 257 bits.
        let dividend = shift_left(self.long(), 256);
        let divisor = other.long();
        let (mut quotient, mut rest) = ([0u64; 8], [0u64; 8]);
        for bit in (0..512).rev() {
            rest = shift_left(rest, 1);
            rest[0] |= dividend[bit / 64] >> (bit % 64) & 1;
            if compare_long(&rest, &divisor) != Ordering::Less {
                rest = subtract_long(&rest, &divisor);
                quotient[bit / 64] |= 1 << (bit % 64);
            }
        }
        quotient[0] |= u64::from(rest != [0; 8]);
        Wide::from_long(negative, quotient, self.power - 256 - other.power)
    }
    /// Divided by a small whole number, which is not zero.
    #[must_use]
    pub(crate) fn divide_small(self, divisor: u64) -> Wide {
        let dividend = shift_left(self.long(), 256);
        let mut quotient = [0u64; 8];
        let mut rest = 0u128;
        for at in (0..8).rev() {
            let part = rest << 64 | u128::from(dividend[at]);
            quotient[at] = (part / u128::from(divisor)) as u64;
            rest = part % u128::from(divisor);
        }
        quotient[0] |= u64::from(rest != 0);
        Wide::from_long(self.negative, quotient, self.power - 256)
    }
    /// The square root of a value that is not negative.
    #[must_use]
    pub(crate) fn square_root(self) -> Wide {
        if self.zero() {
            return self;
        }
        // The radicand with 511 or 512 bits and an even power, so that its
        // root has 256 bits.
        let (radicand, power) = if self.power & 1 == 0 {
            (shift_left(self.long(), 256), self.power - 256)
        } else {
            (shift_left(self.long(), 255), self.power - 255)
        };
        let (mut root, mut rest) = ([0u64; 8], [0u64; 8]);
        for pair in (0..256).rev() {
            rest = shift_left(rest, 2);
            rest[0] |= radicand[pair * 2 / 64] >> (pair * 2 % 64) & 3;
            let mut trial = shift_left(root, 2);
            trial[0] |= 1;
            root = shift_left(root, 1);
            if compare_long(&rest, &trial) != Ordering::Less {
                rest = subtract_long(&rest, &trial);
                root[0] |= 1;
            }
        }
        root[0] |= u64::from(rest != [0; 8]);
        Wide::from_long(false, root, power / 2)
    }
    /// Its top 128 bits, the lowest of them set if any bit below is, and what
    /// they are multiplied by as a power of two: what the 80-bit rounding
    /// takes.
    pub(crate) fn rounding(self) -> (u128, i32) {
        let top = u128::from(self.mantissa[3]) << 64 | u128::from(self.mantissa[2]);
        let lost = self.mantissa[0] | self.mantissa[1] != 0;
        (top | u128::from(lost), self.power + 128)
    }
    /// Whether a term just added to `sum` was too small to change any bit
    /// but the lowest, with room to spare: what is left of a series after it
    /// is smaller still.
    fn negligible(self, sum: Wide) -> bool {
        self.zero() || self.magnitude() < sum.magnitude() - 264
    }
}

/// sin(r) and cos(r), for |r| no more than about π/4, by their series.
pub(crate) fn sine_cosine(r: Wide) -> (Wide, Wide) {
    let square = r.multiply(r);
    let (mut sine, mut term) = (r, r);
    for k in 1u64.. {
        term = term
            .multiply(square)
            .divide_small(2 * k * (2 * k + 1))
            .negate();
        sine = sine.add(term);
        if term.negligible(sine) {
            break;
        }
    }
    let (mut cosine, mut term) = (ONE, ONE);
    for k in 1u64.. {
        term = term
            .multiply(square)
            .divide_small((2 * k - 1) * 2 * k)
            .negate();
        cosine = cosine.add(term);
        if term.negligible(cosine) {
            break;
        }
    }
    (sine, cosine)
}

/// e^z - 1, for |z| no more than ln 2, by its series.
pub(crate) fn exponential_minus_one(z: Wide) -> Wide {
    let (mut sum, mut term) = (z, z);
    for n in 2u64.. {
        term = term.multiply(z).divide_small(n);
        sum = sum.add(term);
        if term.negligible(sum) {
            break;
        }
    }
    sum
}

/// 2 atanh(s) = ln((1 + s) / (1 - s)), for |s| no more than about 0.18.
pub(crate) fn double_inverse_tanh(s: Wide) -> Wide {
    let square = s.multiply(s);
    let (mut sum, mut power) = (s, s);
    for k in 1u64.. {
        power = power.multiply(square);
        let term = power.divide_small(2 * k + 1);
        sum = sum.add(term);
        if term.negligible(sum) {
            break;
        }
    }
    sum.scale(1)
}

/// atan(t), for t from 0 to 1. Halved twice, by atan(t) = 2 atan(t / (1 +
/// sqrt(1 + t²))), t is at most tan(π/16), and then its series is short.
pub(crate) fn inverse_tangent(t: Wide) -> Wide {
    let mut u = t;
    for _ in 0..2 {
        let root = ONE.add(u.multiply(u)).square_root();
        u = u.divide(ONE.add(root));
    }
    let square = u.multiply(u);
    let (mut sum, mut power) = (u, u);
    for k in 1u64.. {
        power = power.multiply(square).negate();
        let term = power.divide_small(2 * k + 1);
        sum = sum.add(term);
        if term.negligible(sum) {
            break;
        }
    }
    sum.scale(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn top(value: Wide) -> u64 {
        value.mantissa[3]
    }

    #[test]
    fn the_operations_keep_what_is_exact_and_mark_what_is_not() {
        let three = Wide::new(false, 3, 0);
        assert_eq!(three.add(Wide::new(false, 5, 0)), Wide::new(false, 8, 0));
        assert_eq!(
            three.subtract(three),
            Wide {
                negative: false,
                ..ZERO
            }
        );
        assert_eq!(three.multiply(three), Wide::new(false, 9, 0));
        assert_eq!(Wide::new(false, 9, 0).square_root(), three);
        assert_eq!(
            Wide::new(false, 12, 0).divide(three),
            Wide::new(false, 4, 0)
        );
        assert_eq!(
            Wide::new(false, 12, 0).divide_small(3),
            Wide::new(false, 4, 0)
        );
        // A third is not exact: its last bit is set.
        let third = ONE.divide(three);
        assert_eq!(third.mantissa[0] & 1, 1);
        assert_eq!(ONE.divide_small(3), third);
        assert_eq!(third.magnitude(), -2);
        // What is far below is not lost: it marks the sum, on the side it is.
        let tiny = Wide::new(false, 1, -1000);
        assert_eq!(ONE.add(tiny).mantissa, [1, 0, 0, 1 << 63]);
        let below = ONE.subtract(tiny);
        assert_eq!(below.mantissa, [u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
        assert_eq!(below.magnitude(), -1);
        assert_eq!(Wide::new(false, 2, 0).square_root().mantissa[0] & 1, 1);
    }

    #[test]
    fn the_constants_are_what_the_series_give() {
        // π/4 = 4 atan(1/5) - atan(1/239), and ln 2 = 2 atanh(1/3).
        let fifth = inverse_tangent(ONE.divide_small(5));
        let other = inverse_tangent(ONE.divide_small(239));
        let quarter_pi = fifth.scale(2).subtract(other);
        let close = |a: Wide, b: Wide| {
            let difference = a.subtract(b);
            difference.zero() || difference.magnitude() < a.magnitude() - 250
        };
        assert!(close(quarter_pi.scale(1), HALF_PI));
        assert!(close(inverse_tangent(ONE), HALF_PI.scale(-1)));
        let ln_2 = double_inverse_tanh(ONE.divide_small(3));
        assert!(close(ln_2, LN_2));
        assert!(close(ONE.divide(LN_2), LOG2_E));
        // e^ln2 - 1 = 1, sin²+cos² = 1.
        assert!(close(exponential_minus_one(LN_2), ONE));
        let (sine, cosine) = sine_cosine(Wide::new(false, 3, -2));
        assert!(close(sine.multiply(sine).add(cosine.multiply(cosine)), ONE));
        assert_eq!(top(sine), 0xae7f_e0b5_fc78_6b2d);
    }
}
