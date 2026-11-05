//! The x87 unit: its eight 80-bit registers as a stack, and its control and
//! status words. Values stay in their 80-bit images, in integers, so no host
//! floating-point environment takes part. Exceptions all take their masked
//! response: an unmasked one is noted in the status word, and does not fault.
use core::cmp::Ordering;

use crate::softfloat::{self, Format};

const INVALID: u16 = 1;
const DENORMAL: u16 = 1 << 1;
const ZERO_DIVIDE: u16 = 1 << 2;
const OVERFLOW: u16 = 1 << 3;
const UNDERFLOW: u16 = 1 << 4;
const INEXACT: u16 = 1 << 5;
const STACK_FAULT: u16 = 1 << 6;
const SUMMARY: u16 = 1 << 7 | 1 << 15;
const C0: u16 = 1 << 8;
const C1: u16 = 1 << 9;
const C2: u16 = 1 << 10;
const C3: u16 = 1 << 14;
const EXCEPTIONS: u16 = 0x3f;
const TOP: u16 = 7 << 11;

/// The control word's bits that exist, and the one that always reads as set.
const CONTROL_BITS: u16 = 0x1f3f;
const CONTROL_SET: u16 = 0x40;
pub(crate) const INITIAL_CONTROL: u16 = 0x37f;

const EXPONENT_MAX: u16 = 0x7fff;
const INTEGER_BIT: u64 = 1 << 63;
const QUIET_BIT: u64 = 1 << 62;
/// The exponent an 80-bit value has as a 1 in the integer bit.
const BIAS: i32 = 16383;
/// The QNaN that stands for an invalid result.
const INDEFINITE: u128 = 0xffff_c000_0000_0000_0000;
const ONE: u128 = 0x3fff_8000_0000_0000_0000;

/// A constant's 80-bit image rounded toward zero, and whether the bits after
/// it round up to the nearest.
#[derive(Clone, Copy)]
pub(crate) struct Constant {
    exponent: u16,
    mantissa: u64,
    nearest_is_up: bool,
}
pub(crate) const PI: Constant = Constant {
    exponent: 0x4000,
    mantissa: 0xc90f_daa2_2168_c234,
    nearest_is_up: true,
};
pub(crate) const LN_2: Constant = Constant {
    exponent: 0x3ffe,
    mantissa: 0xb172_17f7_d1cf_79ab,
    nearest_is_up: true,
};
pub(crate) const LOG10_2: Constant = Constant {
    exponent: 0x3ffd,
    mantissa: 0x9a20_9a84_fbcf_f798,
    nearest_is_up: true,
};
pub(crate) const LOG2_E: Constant = Constant {
    exponent: 0x3fff,
    mantissa: 0xb8aa_3b29_5c17_f0bb,
    nearest_is_up: true,
};
pub(crate) const LOG2_10: Constant = Constant {
    exponent: 0x4000,
    mantissa: 0xd49a_784b_cd1b_8afe,
    nearest_is_up: false,
};

/// What the arithmetic instructions compute.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arithmetic {
    Add,
    Subtract,
    Multiply,
    Divide,
}

/// Where `fxsave` keeps the registers, 16 bytes each.
const IMAGE_REGISTERS: usize = 32;
/// The 64-bit `fnstenv` image.
pub(crate) const ENVIRONMENT: usize = 28;

/// One 80-bit value in its parts.
#[derive(Clone, Copy)]
struct Parts {
    negative: bool,
    exponent: u16,
    mantissa: u64,
}

fn parts(value: u128) -> Parts {
    Parts {
        negative: value >> 79 & 1 != 0,
        exponent: (value >> 64) as u16 & EXPONENT_MAX,
        mantissa: value as u64,
    }
}

fn join(negative: bool, exponent: u16, mantissa: u64) -> u128 {
    u128::from(negative) << 79 | u128::from(exponent) << 64 | u128::from(mantissa)
}

impl Parts {
    /// A value with no integer bit where it needs one. These encodings are
    /// not supported since the 80387: using them is invalid.
    fn unsupported(self) -> bool {
        self.exponent != 0 && self.mantissa & INTEGER_BIT == 0
    }
    fn infinity(self) -> bool {
        self.exponent == EXPONENT_MAX && self.mantissa == INTEGER_BIT
    }
    fn nan(self) -> bool {
        self.exponent == EXPONENT_MAX && !self.unsupported() && !self.infinity()
    }
    fn zero(self) -> bool {
        self.exponent == 0 && self.mantissa == 0
    }
    fn denormal(self) -> bool {
        self.exponent == 0 && self.mantissa != 0
    }
    fn signaling(self) -> bool {
        self.nan() && self.mantissa & QUIET_BIT == 0
    }
    /// What a finite value is multiplied by, as a power of two, from its
    /// mantissa as an integer.
    fn power(self) -> i32 {
        i32::from(self.exponent.max(1)) - BIAS - 63
    }
}

/// The state of the unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X87 {
    /// The physical registers, in their low 80 bits.
    registers: [u128; 8],
    top: u8,
    control: u16,
    /// The status word, without the top of the stack.
    status: u16,
    /// Which physical registers are not empty.
    used: u8,
}

impl Default for X87 {
    fn default() -> Self {
        X87 {
            registers: [0; 8],
            top: 0,
            control: INITIAL_CONTROL,
            status: 0,
            used: 0,
        }
    }
}

/// An 80-bit value from a smaller format's bits, and the exceptions that
/// raises: it always fits.
fn widen(f: Format, bits: u64) -> (u128, u16) {
    let negative = bits & f.sign() != 0;
    let fraction = bits & f.mantissa();
    let to_top = 63 - f.fraction;
    let exponent = bits & f.infinity();
    if exponent == f.infinity() {
        if fraction == 0 {
            return (join(negative, EXPONENT_MAX, INTEGER_BIT), 0);
        }
        let quiet = fraction >> (f.fraction - 1) != 0;
        let mantissa = INTEGER_BIT | QUIET_BIT | fraction << to_top;
        return (
            join(negative, EXPONENT_MAX, mantissa),
            if quiet { 0 } else { INVALID },
        );
    }
    let bias = f.bias();
    if exponent == 0 {
        if fraction == 0 {
            return (join(negative, 0, 0), 0);
        }
        // A denormal is normal in the wider format.
        let shift = fraction.leading_zeros();
        let power = 1 - bias - (shift as i32 - to_top as i32);
        return (
            join(negative, (power + BIAS) as u16, fraction << shift),
            DENORMAL,
        );
    }
    let power = (exponent >> f.fraction) as i32 - bias;
    (
        join(
            negative,
            (power + BIAS) as u16,
            INTEGER_BIT | fraction << to_top,
        ),
        0,
    )
}

/// A smaller format's bits from an 80-bit value, the exceptions that raises,
/// and whether its size went up in rounding as `control` asks.
fn narrow(f: Format, value: u128, control: u16) -> (u64, u16, bool) {
    let v = parts(value);
    let sign = if v.negative { f.sign() } else { 0 };
    if v.unsupported() {
        return (f.indefinite(), INVALID, false);
    }
    if v.infinity() {
        return (sign | f.infinity(), 0, false);
    }
    if v.nan() {
        let payload = (v.mantissa >> (63 - f.fraction)) & f.mantissa();
        let quiet = 1 << (f.fraction - 1);
        let invalid = v.mantissa & QUIET_BIT == 0;
        return (
            sign | f.infinity() | payload | quiet,
            if invalid { INVALID } else { 0 },
            false,
        );
    }
    if v.zero() {
        return (sign, 0, false);
    }
    let rounding = |mode: u16| {
        let mxcsr = 0x1f80 | u32::from(mode) << 13;
        softfloat::round(f, v.negative, u128::from(v.mantissa), v.power(), mxcsr)
    };
    let (bits, flags) = rounding(control >> 10 & 3);
    let (toward_zero, _) = rounding(3);
    (
        bits,
        flags as u16,
        bits & !f.sign() > toward_zero & !f.sign(),
    )
}

/// An integer of `width` bits from an 80-bit value, rounded as `control`
/// asks: the exceptions that raises, and whether its size went up. What does
/// not fit is invalid, and the lowest integer.
fn to_integer(value: u128, width: u32, control: u16) -> (u64, u16, bool) {
    let lowest = 1u64 << (width - 1);
    let v = parts(value);
    if v.unsupported() || v.exponent == EXPONENT_MAX {
        return (lowest, INVALID, false);
    }
    if v.zero() {
        return (0, 0, false);
    }
    let power = v.power();
    if power >= 64 {
        return (lowest, INVALID, false);
    }
    let (whole, rest, half) = whole_part(v);
    let up = rounds_away(control, v.negative, whole, rest, half);
    let size = whole + u128::from(up);
    let limit = u128::from(lowest) - u128::from(!v.negative);
    if size > limit {
        return (lowest, INVALID, false);
    }
    let flags = if rest != 0 { INEXACT } else { 0 };
    let signed = if v.negative {
        (size as u64).wrapping_neg()
    } else {
        size as u64
    };
    let mask = if width == 64 {
        u64::MAX
    } else {
        (1 << width) - 1
    };
    (signed & mask, flags, up)
}

/// A finite value's whole part, what is left of it, and what half of a unit
/// is on the scale of what is left. The tiniest value is below any half, as
/// what is left is 1 of 2^127.
fn whole_part(v: Parts) -> (u128, u128, u128) {
    let power = v.power();
    let mantissa = u128::from(v.mantissa);
    if power >= 0 {
        (mantissa << power, 0, 1)
    } else if power <= -127 {
        (0, 1, 1 << 126)
    } else {
        let shift = power.unsigned_abs();
        (
            mantissa >> shift,
            mantissa & ((1u128 << shift) - 1),
            1u128 << (shift - 1),
        )
    }
}

/// Whether a size goes up by one, as `control` asks, for what is below it.
fn rounds_away(control: u16, negative: bool, size: u128, rest: u128, half: u128) -> bool {
    rest != 0
        && match control >> 10 & 3 {
            0 => rest > half || (rest == half && size & 1 != 0),
            1 => negative,
            2 => !negative,
            _ => false,
        }
}

/// How many bits the control word's precision keeps. Only the four operations
/// and `fsqrt` follow it. Its reserved value keeps them all.
fn precision(control: u16) -> u32 {
    match control >> 8 & 3 {
        0 => 24,
        2 => 53,
        _ => 64,
    }
}

/// `magnitude * 2^power` in the 80-bit format, keeping `bits` of its mantissa:
/// the exceptions that raises, and whether its size went up. The lowest bit of
/// `magnitude` may stand for all that is below it, if at least 66 bits are
/// above that. A result is tiny if it would be, rounded with no limit on its
/// exponent: below the normal range, it is shifted down first and then rounded
/// at the same place.
fn round_extended(
    negative: bool,
    magnitude: u128,
    power: i32,
    control: u16,
    bits: u32,
) -> (u128, u16, bool) {
    if magnitude == 0 {
        return (join(negative, 0, 0), 0, false);
    }
    let shift = magnitude.leading_zeros();
    let normal = magnitude << shift;
    let exponent = power + 127 - shift as i32 + BIAS;
    let dropped = 64 - bits;
    // What is kept of a 128-bit value with the mantissa on top, what is below
    // it, and half of what is kept.
    let split = |value: u128| {
        (
            value >> (64 + dropped),
            value & ((1u128 << (64 + dropped)) - 1),
            1u128 << (63 + dropped),
        )
    };
    let (kept, rest, half) = split(normal);
    let up = rounds_away(control, negative, kept, rest, half);
    let carries = (kept + u128::from(up)) >> bits != 0;
    if exponent >= 1 {
        let (mantissa, exponent) = if carries {
            (INTEGER_BIT, exponent + 1)
        } else {
            (((kept + u128::from(up)) as u64) << dropped, exponent)
        };
        if exponent >= i32::from(EXPONENT_MAX) {
            let flags = OVERFLOW | INEXACT;
            let to_infinity = match control >> 10 & 3 {
                0 => true,
                1 => negative,
                2 => !negative,
                _ => false,
            };
            return if to_infinity {
                (join(negative, EXPONENT_MAX, INTEGER_BIT), flags, true)
            } else {
                let largest = (u64::MAX >> dropped) << dropped;
                (join(negative, EXPONENT_MAX - 1, largest), flags, false)
            };
        }
        let flags = if rest != 0 { INEXACT } else { 0 };
        return (join(negative, exponent as u16, mantissa), flags, up);
    }
    let tiny = !(exponent == 0 && carries);
    let (kept, rest, half) = split(softfloat::sticky(normal, (1 - exponent) as u32));
    let up = rounds_away(control, negative, kept, rest, half);
    let mantissa = ((kept + u128::from(up)) as u64) << dropped;
    let flags = match (rest != 0, tiny) {
        (false, _) => 0,
        (true, false) => INEXACT,
        (true, true) => INEXACT | UNDERFLOW,
    };
    let exponent = u16::from(mantissa & INTEGER_BIT != 0);
    (join(negative, exponent, mantissa), flags, up)
}

/// The result of an operation where an operand is no number, and the
/// exceptions that raises. A signaling NaN gives way to a quiet one, and
/// between two of a kind the larger mantissa wins, then the positive one.
fn not_numbers(first: u128, second: u128) -> Option<(u128, u16)> {
    let (a, b) = (parts(first), parts(second));
    if a.unsupported() || b.unsupported() {
        return Some((INDEFINITE, INVALID));
    }
    let chosen = match (a.nan(), b.nan()) {
        (false, false) => return None,
        (true, false) => first,
        (false, true) => second,
        (true, true) => match (a.signaling(), b.signaling()) {
            (true, false) => second,
            (false, true) => first,
            _ => match a.mantissa.cmp(&b.mantissa) {
                Ordering::Greater => first,
                Ordering::Less => second,
                Ordering::Equal if a.negative => second,
                Ordering::Equal => first,
            },
        },
    };
    let flags = if a.signaling() || b.signaling() {
        INVALID
    } else {
        0
    };
    Some((chosen | u128::from(QUIET_BIT), flags))
}

/// A finite value that is not zero as a mantissa with its integer bit, and
/// what that is multiplied by as a power of two.
fn normalized(v: Parts) -> (u64, i32) {
    let shift = v.mantissa.leading_zeros();
    (v.mantissa << shift, v.power() - shift as i32)
}

fn add(negative_a: bool, a: Parts, negative_b: bool, b: Parts, control: u16) -> (u128, u16, bool) {
    let (power_a, power_b) = (a.power(), b.power());
    let top = power_a.max(power_b);
    // Only the larger one can lose bits, and it then has its integer bit.
    let place = |v: Parts, power: i32| {
        softfloat::sticky(u128::from(v.mantissa) << 60, (top - power) as u32)
    };
    let (x, y) = (place(a, power_a), place(b, power_b));
    let (negative, size) = if negative_a == negative_b {
        (negative_a, x + y)
    } else if x >= y {
        (negative_a, x - y)
    } else {
        (negative_b, y - x)
    };
    let negative = if size != 0 {
        negative
    } else if a.zero() && b.zero() && negative_a == negative_b {
        negative_a
    } else {
        control >> 10 & 3 == 1
    };
    round_extended(negative, size, top - 60, control, precision(control))
}

fn divide(a: Parts, b: Parts, negative: bool, control: u16) -> (u128, u16, bool) {
    let (mantissa_a, power_a) = normalized(a);
    let (mantissa_b, power_b) = normalized(b);
    let divisor = u128::from(mantissa_b);
    let dividend = u128::from(mantissa_a) << 64;
    let (whole, rest) = (dividend / divisor, dividend % divisor);
    let more = rest << 62;
    let quotient = (whole << 62) | (more / divisor) | u128::from(!more.is_multiple_of(divisor));
    let power = power_a - power_b - 64 - 62;
    round_extended(negative, quotient, power, control, precision(control))
}

/// One of the four operations, from the values on its operands. `denormal`
/// says one came from memory as a denormal in its own format, which it no
/// longer is. Whatever is invalid comes before a denormal is noted.
fn calculate(
    operation: Arithmetic,
    first: u128,
    second: u128,
    denormal: bool,
    control: u16,
) -> (u128, u16, bool) {
    if let Some((value, flags)) = not_numbers(first, second) {
        return (value, flags, false);
    }
    let (a, b) = (parts(first), parts(second));
    let invalid = (INDEFINITE, INVALID, false);
    let flags = if denormal || a.denormal() || b.denormal() {
        DENORMAL
    } else {
        0
    };
    let negative = a.negative != b.negative;
    let infinity = |negative: bool| join(negative, EXPONENT_MAX, INTEGER_BIT);
    let (value, more, up) = match operation {
        // A CPU notes no denormal where it divides by zero.
        Arithmetic::Divide if b.zero() && !a.zero() && !a.infinity() => {
            return (infinity(negative), ZERO_DIVIDE, false);
        }
        Arithmetic::Add | Arithmetic::Subtract => {
            let negative_b = b.negative != (operation == Arithmetic::Subtract);
            match (a.infinity(), b.infinity()) {
                (true, true) if a.negative != negative_b => return invalid,
                (true, _) => (infinity(a.negative), 0, false),
                (false, true) => (infinity(negative_b), 0, false),
                (false, false) => add(a.negative, a, negative_b, b, control),
            }
        }
        Arithmetic::Multiply => {
            if (a.infinity() && b.zero()) || (a.zero() && b.infinity()) {
                return invalid;
            }
            if a.infinity() || b.infinity() {
                (infinity(negative), 0, false)
            } else {
                let size = u128::from(a.mantissa) * u128::from(b.mantissa);
                let power = a.power() + b.power();
                round_extended(negative, size, power, control, precision(control))
            }
        }
        Arithmetic::Divide => {
            if (a.infinity() && b.infinity()) || (a.zero() && b.zero()) {
                return invalid;
            }
            if a.infinity() {
                (infinity(negative), 0, false)
            } else if b.infinity() || a.zero() {
                (join(negative, 0, 0), 0, false)
            } else {
                divide(a, b, negative, control)
            }
        }
    };
    (value, flags | more, up)
}

fn square_root(value: u128, control: u16) -> (u128, u16, bool) {
    if let Some((value, flags)) = not_numbers(value, value) {
        return (value, flags, false);
    }
    let v = parts(value);
    if v.zero() {
        return (value, 0, false);
    }
    if v.negative {
        return (INDEFINITE, INVALID, false);
    }
    if v.infinity() {
        return (value, 0, false);
    }
    let flags = if v.denormal() { DENORMAL } else { 0 };
    let (mantissa, power) = normalized(v);
    let (radicand, power) = if power & 1 != 0 {
        (u128::from(mantissa) << 1, power - 1)
    } else {
        (u128::from(mantissa), power)
    };
    // By pairs of bits: all of them, then as many zeros, for 35 bits more.
    let (mut root, mut rest) = (0u128, 0u128);
    for pair in (0..70).rev() {
        let next = if pair >= 35 {
            radicand >> ((pair - 35) * 2) & 3
        } else {
            0
        };
        rest = rest << 2 | next;
        let trial = root << 2 | 1;
        root <<= 1;
        if rest >= trial {
            rest -= trial;
            root |= 1;
        }
    }
    let (value, more, up) = round_extended(
        false,
        root | u128::from(rest != 0),
        power / 2 - 35,
        control,
        precision(control),
    );
    (value, flags | more, up)
}

/// What `fprem` and, for `nearest`, `fprem1` leave.
struct Remainder {
    value: u128,
    flags: u16,
    quotient: u64,
    partial: bool,
}

fn remainder(first: u128, second: u128, nearest: bool) -> Remainder {
    let whole = |value, flags| Remainder {
        value,
        flags,
        quotient: 0,
        partial: false,
    };
    if let Some((value, flags)) = not_numbers(first, second) {
        return whole(value, flags);
    }
    let (a, b) = (parts(first), parts(second));
    if a.infinity() || b.zero() {
        return whole(INDEFINITE, INVALID);
    }
    let flags = if a.denormal() || b.denormal() {
        DENORMAL
    } else {
        0
    };
    if a.zero() {
        return whole(first, flags);
    }
    let exact =
        |size, power, negative| round_extended(negative, size, power, INITIAL_CONTROL, 64).0;
    let (mantissa_a, power_a) = normalized(a);
    if b.infinity() {
        return whole(exact(u128::from(mantissa_a), power_a, a.negative), flags);
    }
    let (mantissa_b, power_b) = normalized(b);
    let difference = power_a - power_b;
    if difference < -1 || (difference == -1 && !nearest) {
        return whole(exact(u128::from(mantissa_a), power_a, a.negative), flags);
    }
    // Far apart, this goes part of the way, and is to be run again. How far is
    // the CPU's choice.
    let partial = difference >= 64;
    let skipped = if partial {
        difference - (32 + difference % 32)
    } else {
        0
    };
    let steps = difference - skipped;
    let (mut rest, mut divisor) = (u128::from(mantissa_a), u128::from(mantissa_b));
    let mut unit = power_b + skipped;
    let mut quotient = 0u64;
    if steps < 0 {
        divisor <<= 1;
        unit -= 1;
    }
    for step in 0..=steps {
        quotient <<= 1;
        if rest >= divisor {
            rest -= divisor;
            quotient |= 1;
        }
        if step < steps {
            rest <<= 1;
        }
    }
    let mut negative = a.negative;
    if nearest && !partial && (rest * 2 > divisor || (rest * 2 == divisor && quotient & 1 != 0)) {
        rest = divisor - rest;
        quotient = quotient.wrapping_add(1);
        negative = !negative;
    }
    // Nothing left has the sign of what was divided.
    let negative = if rest == 0 { a.negative } else { negative };
    Remainder {
        value: exact(rest, unit, negative),
        flags,
        quotient,
        partial,
    }
}

/// `frndint`.
fn round_to_whole(value: u128, control: u16) -> (u128, u16, bool) {
    if let Some((value, flags)) = not_numbers(value, value) {
        return (value, flags, false);
    }
    let v = parts(value);
    if v.zero() || v.infinity() {
        return (value, 0, false);
    }
    let flags = if v.denormal() { DENORMAL } else { 0 };
    if v.power() >= 0 {
        return (value, flags, false);
    }
    let (whole, rest, half) = whole_part(v);
    let up = rounds_away(control, v.negative, whole, rest, half);
    let size = whole + u128::from(up);
    let (result, _, _) = round_extended(v.negative, size, 0, control, 64);
    let inexact = if rest != 0 { INEXACT } else { 0 };
    (result, flags | inexact, up)
}

/// `fscale`: the first value times two to the power of the second, cut to a
/// whole number. Past the range of any result, the power stops mattering.
fn scale(first: u128, second: u128, control: u16) -> (u128, u16, bool) {
    if let Some((value, flags)) = not_numbers(first, second) {
        return (value, flags, false);
    }
    let (a, b) = (parts(first), parts(second));
    let flags = if a.denormal() || b.denormal() {
        DENORMAL
    } else {
        0
    };
    if b.infinity() {
        return match (b.negative, a.zero(), a.infinity()) {
            (false, true, _) | (true, _, true) => (INDEFINITE, INVALID, false),
            (false, ..) => (join(a.negative, EXPONENT_MAX, INTEGER_BIT), flags, false),
            (true, ..) => (join(a.negative, 0, 0), flags, false),
        };
    }
    if a.zero() || a.infinity() {
        return (first, flags, false);
    }
    const BEYOND: i32 = 1 << 16;
    let power = b.power();
    let size = if power >= -47 {
        BEYOND
    } else if power <= -64 {
        0
    } else {
        (b.mantissa >> power.unsigned_abs()) as i32
    };
    let amount = if b.negative { -size } else { size };
    let (value, more, up) = round_extended(
        a.negative,
        u128::from(a.mantissa),
        a.power() + amount,
        control,
        64,
    );
    (value, flags | more, up)
}

/// An integer in the 80-bit format, which always holds it.
pub(crate) fn integer_value(value: i64) -> u128 {
    if value == 0 {
        return 0;
    }
    let size = value.unsigned_abs();
    let shift = size.leading_zeros();
    let exponent = BIAS + 63 - shift as i32;
    join(value < 0, exponent as u16, size << shift)
}

/// A smaller format's value for an operation: it stays signaling until the
/// operation has looked at it, and whether it was a denormal is said apart.
pub(crate) fn float_operand(f: Format, bits: u64) -> (u128, bool) {
    let (value, flags) = widen(f, bits);
    let value = if flags & INVALID != 0 {
        value & !u128::from(QUIET_BIT)
    } else {
        value
    };
    (value, flags & DENORMAL != 0)
}

/// How two values compare, or `None` when they do not, and the exceptions that
/// raises. A quiet NaN is invalid unless `quiet`.
fn order(first: u128, second: u128, denormal: bool, quiet: bool) -> (Option<Ordering>, u16) {
    let (a, b) = (parts(first), parts(second));
    if a.unsupported() || b.unsupported() {
        return (None, INVALID);
    }
    if a.nan() || b.nan() {
        let invalid = !quiet || a.signaling() || b.signaling();
        return (None, if invalid { INVALID } else { 0 });
    }
    let flags = if denormal || a.denormal() || b.denormal() {
        DENORMAL
    } else {
        0
    };
    // Zeros are equal whatever their signs. A pseudo-denormal has the
    // value of the normal with its bits.
    let size = |v: Parts| (v.exponent.max(1), v.mantissa);
    let signed = |v: Parts| v.negative && !v.zero();
    let result = match (signed(a), signed(b)) {
        (false, true) => Ordering::Greater,
        (true, false) => Ordering::Less,
        (false, false) => size(a).cmp(&size(b)),
        (true, true) => size(b).cmp(&size(a)),
    };
    (Some(result), flags)
}

impl X87 {
    /// The status word as the program sees it.
    #[must_use]
    pub(crate) fn status_word(&self) -> u16 {
        self.status & !TOP | u16::from(self.top) << 11
    }
    #[must_use]
    pub(crate) fn control_word(&self) -> u16 {
        self.control
    }
    pub(crate) fn set_control(&mut self, value: u16) {
        self.control = value & CONTROL_BITS | CONTROL_SET;
        self.summarize();
    }
    /// The status word's summary: a set exception that is not masked.
    fn summarize(&mut self) {
        if self.status & !self.control & EXCEPTIONS != 0 {
            self.status |= SUMMARY;
        } else {
            self.status &= !SUMMARY;
        }
    }
    fn raise(&mut self, flags: u16) {
        self.status |= flags;
        self.summarize();
    }
    fn condition(&mut self, bit: u16, on: bool) {
        if on {
            self.status |= bit;
        } else {
            self.status &= !bit;
        }
    }
    fn physical(&self, index: u8) -> usize {
        usize::from((self.top + index) & 7)
    }
    fn get(&self, index: u8) -> Option<u128> {
        let at = self.physical(index);
        (self.used >> at & 1 != 0).then(|| self.registers[at])
    }
    fn put(&mut self, index: u8, value: u128) {
        let at = self.physical(index);
        self.registers[at] = value;
        self.used |= 1 << at;
    }
    /// Reading an empty register: the invalid result, as C1 says it was no
    /// overflow.
    fn read(&mut self, index: u8) -> u128 {
        self.get(index).unwrap_or_else(|| {
            self.raise(INVALID | STACK_FAULT);
            INDEFINITE
        })
    }
    /// A value on the stack, or on a full one the invalid result.
    fn push(&mut self, value: u128) {
        let top = self.top.wrapping_sub(1) & 7;
        let full = self.used >> top & 1 != 0;
        if full {
            self.raise(INVALID | STACK_FAULT);
        }
        self.condition(C1, full);
        self.top = top;
        self.put(0, if full { INDEFINITE } else { value });
    }
    pub(crate) fn pop(&mut self) {
        self.used &= !(1 << self.top);
        self.top = (self.top + 1) & 7;
    }
    /// `fld` of a register, read before the stack moves.
    pub(crate) fn load_register(&mut self, index: u8) {
        self.condition(C1, false);
        let value = self.read(index);
        self.push(value);
    }
    /// `fld` of a smaller format, which is converted.
    pub(crate) fn load_float(&mut self, f: Format, bits: u64) {
        let (value, flags) = widen(f, bits);
        self.raise(flags);
        self.push(value);
    }
    /// `fld` of the 80-bit format, which is taken as it is.
    pub(crate) fn load_extended(&mut self, value: u128) {
        self.push(value);
    }
    pub(crate) fn load_integer(&mut self, value: i64) {
        self.push(integer_value(value));
    }
    pub(crate) fn load_zero(&mut self) {
        self.push(0);
    }
    pub(crate) fn load_one(&mut self) {
        self.push(ONE);
    }
    /// A constant, which raises no exception however it rounds.
    pub(crate) fn load_constant(&mut self, constant: Constant) {
        let up = match self.control >> 10 & 3 {
            0 => constant.nearest_is_up,
            2 => true,
            _ => false,
        };
        let mantissa = constant.mantissa + u64::from(up);
        self.push(join(false, constant.exponent, mantissa));
    }
    /// What `fst` writes to memory in a smaller format.
    pub(crate) fn store_float(&mut self, f: Format) -> u64 {
        self.condition(C1, false);
        let Some(value) = self.get(0) else {
            self.raise(INVALID | STACK_FAULT);
            return f.indefinite();
        };
        let (bits, flags, up) = narrow(f, value, self.control);
        self.raise(flags);
        self.condition(C1, up);
        bits
    }
    /// What `fstp` writes to memory in the 80-bit format, which is the
    /// register as it is.
    pub(crate) fn store_extended(&mut self) -> u128 {
        self.condition(C1, false);
        self.read(0)
    }
    /// What `fist` writes to memory, in `width` bits.
    pub(crate) fn store_integer(&mut self, width: u32) -> u64 {
        self.condition(C1, false);
        let Some(value) = self.get(0) else {
            self.raise(INVALID | STACK_FAULT);
            return 1 << (width - 1);
        };
        let (bits, flags, up) = to_integer(value, width, self.control);
        self.raise(flags);
        self.condition(C1, up);
        bits
    }
    /// `fst` to a register.
    pub(crate) fn store_register(&mut self, index: u8) {
        self.condition(C1, false);
        let value = self.read(0);
        self.put(index, value);
    }
    pub(crate) fn exchange(&mut self, index: u8) {
        self.condition(C1, false);
        let (first, second) = (self.read(0), self.read(index));
        self.put(0, second);
        self.put(index, first);
    }
    pub(crate) fn negate(&mut self) {
        self.condition(C1, false);
        let value = self.get(0).map_or_else(
            || {
                self.raise(INVALID | STACK_FAULT);
                INDEFINITE
            },
            |value| value ^ 1 << 79,
        );
        self.put(0, value);
    }
    pub(crate) fn absolute(&mut self) {
        self.condition(C1, false);
        let value = self.get(0).map_or_else(
            || {
                self.raise(INVALID | STACK_FAULT);
                INDEFINITE
            },
            |value| value & !(1 << 79),
        );
        self.put(0, value);
    }
    /// `fxam`: what kind of value the top is, in C0, C2 and C3, and its sign
    /// in C1.
    pub(crate) fn examine(&mut self) {
        let raw = self.registers[self.physical(0)];
        let v = parts(raw);
        let (c3, c2, c0) = if self.get(0).is_none() {
            (true, false, true)
        } else if v.unsupported() {
            (false, false, false)
        } else if v.infinity() {
            (false, true, true)
        } else if v.nan() {
            (false, false, true)
        } else if v.zero() {
            (true, false, false)
        } else if v.exponent == 0 {
            (true, true, false)
        } else {
            (false, true, false)
        };
        self.condition(C0, c0);
        self.condition(C1, v.negative);
        self.condition(C2, c2);
        self.condition(C3, c3);
    }
    /// A result, into a register.
    fn finish(&mut self, target: u8, (value, flags, up): (u128, u16, bool)) {
        self.raise(flags);
        self.condition(C1, up);
        self.put(target, value);
    }
    fn calculate(
        &mut self,
        (operation, reversed): (Arithmetic, bool),
        target: u8,
        other: Option<u128>,
        denormal: bool,
    ) {
        self.condition(C1, false);
        let (Some(value), Some(other)) = (self.get(target), other) else {
            self.raise(INVALID | STACK_FAULT);
            self.put(target, INDEFINITE);
            return;
        };
        let (first, second) = if reversed {
            (other, value)
        } else {
            (value, other)
        };
        let result = calculate(operation, first, second, denormal, self.control);
        self.finish(target, result);
    }
    /// One of the four operations on two registers, into the first.
    pub(crate) fn calculate_registers(
        &mut self,
        operation: (Arithmetic, bool),
        target: u8,
        source: u8,
    ) {
        let other = self.get(source);
        self.calculate(operation, target, other, false);
    }
    /// One of the four operations on st(0) and a value from memory.
    pub(crate) fn calculate_memory(
        &mut self,
        operation: (Arithmetic, bool),
        value: u128,
        denormal: bool,
    ) {
        self.calculate(operation, 0, Some(value), denormal);
    }
    pub(crate) fn square_root(&mut self) {
        self.condition(C1, false);
        let Some(value) = self.get(0) else {
            self.raise(INVALID | STACK_FAULT);
            self.put(0, INDEFINITE);
            return;
        };
        let result = square_root(value, self.control);
        self.finish(0, result);
    }
    pub(crate) fn round_to_whole(&mut self) {
        self.condition(C1, false);
        let Some(value) = self.get(0) else {
            self.raise(INVALID | STACK_FAULT);
            self.put(0, INDEFINITE);
            return;
        };
        let result = round_to_whole(value, self.control);
        self.finish(0, result);
    }
    pub(crate) fn scale(&mut self) {
        self.condition(C1, false);
        let (Some(first), Some(second)) = (self.get(0), self.get(1)) else {
            self.raise(INVALID | STACK_FAULT);
            self.put(0, INDEFINITE);
            return;
        };
        let result = scale(first, second, self.control);
        self.finish(0, result);
    }
    /// `fprem` or, for `nearest`, `fprem1`: C2 says it is to be run again, and
    /// otherwise C0, C3 and C1 are the quotient's last three bits.
    pub(crate) fn remainder(&mut self, nearest: bool) {
        for bit in [C0, C1, C2, C3] {
            self.condition(bit, false);
        }
        let (Some(first), Some(second)) = (self.get(0), self.get(1)) else {
            self.raise(INVALID | STACK_FAULT);
            self.put(0, INDEFINITE);
            return;
        };
        let result = remainder(first, second, nearest);
        self.raise(result.flags);
        self.put(0, result.value);
        if result.partial {
            self.condition(C2, true);
        } else {
            self.condition(C0, result.quotient & 4 != 0);
            self.condition(C3, result.quotient & 2 != 0);
            self.condition(C1, result.quotient & 1 != 0);
        }
    }
    /// `fxtract`: the exponent stays below what the mantissa pushes. Where the
    /// stack is empty or full, both are the invalid result.
    pub(crate) fn extract(&mut self) {
        self.condition(C1, false);
        let (Some(value), None) = (self.get(0), self.get(7)) else {
            self.raise(INVALID | STACK_FAULT);
            self.put(0, INDEFINITE);
            self.push(INDEFINITE);
            return;
        };
        let v = parts(value);
        let infinity = |negative| join(negative, EXPONENT_MAX, INTEGER_BIT);
        let (exponent, mantissa, flags) = if let Some((value, flags)) = not_numbers(value, value) {
            (value, value, flags)
        } else if v.infinity() {
            (infinity(false), value, 0)
        } else if v.zero() {
            (infinity(true), value, ZERO_DIVIDE)
        } else {
            let (mantissa, power) = normalized(v);
            let flags = if v.denormal() { DENORMAL } else { 0 };
            (
                integer_value(i64::from(power + 63)),
                join(v.negative, BIAS as u16, mantissa),
                flags,
            )
        };
        self.raise(flags);
        self.put(0, exponent);
        self.push(mantissa);
    }
    /// `fcmov`: empty registers are invalid whether it moves or not.
    pub(crate) fn conditional_move(&mut self, index: u8, taken: bool) {
        self.condition(C1, false);
        let (Some(_), Some(value)) = (self.get(0), self.get(index)) else {
            self.raise(INVALID | STACK_FAULT);
            self.put(0, INDEFINITE);
            return;
        };
        if taken {
            self.put(0, value);
        }
    }
    fn compare_values(
        &mut self,
        first: Option<u128>,
        second: Option<u128>,
        denormal: bool,
        quiet: bool,
    ) -> Option<Ordering> {
        self.condition(C1, false);
        let (Some(first), Some(second)) = (first, second) else {
            self.raise(INVALID | STACK_FAULT);
            return None;
        };
        let (result, flags) = order(first, second, denormal, quiet);
        self.raise(flags);
        result
    }
    /// `fcomi` or, for `quiet`, `fucomi`: how st(0) compares with a register,
    /// or `None` when they do not. A quiet NaN is invalid only for `fcomi`.
    pub(crate) fn compare(&mut self, index: u8, quiet: bool) -> Option<Ordering> {
        let (first, second) = (self.get(0), self.get(index));
        self.compare_values(first, second, false, quiet)
    }
    /// What `fcom` says of an order, in C0, C2 and C3.
    fn condition_order(&mut self, result: Option<Ordering>) {
        let (c3, c2, c0) = match result {
            Some(Ordering::Greater) => (false, false, false),
            Some(Ordering::Less) => (false, false, true),
            Some(Ordering::Equal) => (true, false, false),
            None => (true, true, true),
        };
        self.condition(C0, c0);
        self.condition(C2, c2);
        self.condition(C3, c3);
    }
    /// `fcom` or, for `quiet`, `fucom`, of a register.
    pub(crate) fn compare_register(&mut self, index: u8, quiet: bool) {
        let result = self.compare(index, quiet);
        self.condition_order(result);
    }
    /// `fcom`, `ficom` or `ftst`: st(0) with a value that is not a register.
    pub(crate) fn compare_value(&mut self, value: u128, denormal: bool) {
        let first = self.get(0);
        let result = self.compare_values(first, Some(value), denormal, false);
        self.condition_order(result);
    }
    pub(crate) fn free(&mut self, index: u8) {
        self.used &= !(1 << self.physical(index));
    }
    pub(crate) fn increment_top(&mut self) {
        self.condition(C1, false);
        self.top = (self.top + 1) & 7;
    }
    pub(crate) fn decrement_top(&mut self) {
        self.condition(C1, false);
        self.top = self.top.wrapping_sub(1) & 7;
    }
    pub(crate) fn clear_exceptions(&mut self) {
        self.status &= !(EXCEPTIONS | STACK_FAULT | SUMMARY);
    }
    /// `fninit`, which leaves what the registers hold.
    pub(crate) fn initialize(&mut self) {
        *self = X87 {
            registers: self.registers,
            ..X87::default()
        };
    }
    /// The tag word of `fnstenv`, of two bits for each physical register.
    fn full_tags(&self) -> u16 {
        (0..8).fold(0, |tags, at| {
            let v = parts(self.registers[at]);
            let tag = if self.used >> at & 1 == 0 {
                3
            } else if v.zero() {
                1
            } else if v.exponent == 0 || v.exponent == EXPONENT_MAX || v.unsupported() {
                2
            } else {
                0
            };
            tags | tag << (at * 2)
        })
    }
    /// `fnstenv`'s image in 64-bit mode: three words, each followed by a
    /// reserved one of all ones, as the x87 case compares with a real CPU;
    /// where the last instruction and operand were, which nothing here keeps;
    /// and one more reserved word. It then masks every exception.
    pub(crate) fn store_environment(&mut self) -> [u8; ENVIRONMENT] {
        let mut image = [0; ENVIRONMENT];
        for (at, word) in [
            (0, self.control),
            (4, self.status_word()),
            (8, self.full_tags()),
        ] {
            image[at..at + 2].copy_from_slice(&word.to_le_bytes());
            image[at + 2..at + 4].fill(0xff);
        }
        image[26..28].fill(0xff);
        self.control |= EXCEPTIONS;
        self.summarize();
        image
    }
    /// `fldenv`, which takes the status word as it is, with its summary, as a
    /// CPU does.
    pub(crate) fn load_environment(&mut self, image: &[u8; ENVIRONMENT]) {
        let word = |at: usize| u16::from_le_bytes([image[at], image[at + 1]]);
        self.control = word(0) & CONTROL_BITS | CONTROL_SET;
        let status = word(4);
        self.top = (status >> 11 & 7) as u8;
        self.status = status & !TOP;
        let tags = word(8);
        self.used = (0..8).fold(0, |used, at| {
            used | u8::from(tags >> (at * 2) & 3 != 3) << at
        });
    }
    /// The first 160 bytes of `fxsave`'s area: the words, one bit for each
    /// physical register that is not empty, and the registers from the top.
    pub(crate) fn write_image(&self, area: &mut [u8]) {
        area[..2].copy_from_slice(&self.control.to_le_bytes());
        area[2..4].copy_from_slice(&self.status_word().to_le_bytes());
        area[4] = self.used;
        for index in 0..8u8 {
            let at = IMAGE_REGISTERS + usize::from(index) * 16;
            let value = self.registers[self.physical(index)];
            area[at..at + 16].copy_from_slice(&value.to_le_bytes());
        }
    }
    /// What `fxrstor` takes from the area [`X87::write_image`] writes, with the
    /// status word's summary as it is, as a CPU does.
    pub(crate) fn read_image(&mut self, area: &[u8]) {
        let word = |at: usize| u16::from_le_bytes([area[at], area[at + 1]]);
        self.control = word(0) & CONTROL_BITS | CONTROL_SET;
        let status = word(2);
        self.top = (status >> 11 & 7) as u8;
        self.status = status & !TOP;
        self.used = area[4];
        for index in 0..8u8 {
            let at = IMAGE_REGISTERS + usize::from(index) * 16;
            let mut value = [0; 16];
            value[..10].copy_from_slice(&area[at..at + 10]);
            self.registers[self.physical(index)] = u128::from_le_bytes(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::softfloat::{F32, F64};

    const UP: u16 = 2 << 10;
    const DOWN: u16 = 1 << 10;
    const TOWARD_ZERO: u16 = 3 << 10;

    #[test]
    fn widening_keeps_every_value() {
        let cases: [(u64, u128, u16); 8] = [
            (0, 0, 0),
            (1 << 63, 1 << 79, 0),
            (0x3ff0_0000_0000_0000, ONE, 0),
            (0x7ff0_0000_0000_0000, 0x7fff_8000_0000_0000_0000, 0),
            // The smallest denormal, normal here.
            (1, join(false, (BIAS - 1074) as u16, INTEGER_BIT), DENORMAL),
            // A quiet NaN, whose payload moves up.
            (0x7ff8_0000_0000_0123, 0x7fff_c000_0000_0009_1800, 0),
            // A signaling NaN comes out quiet.
            (0x7ff0_0000_0000_0001, 0x7fff_c000_0000_0000_0800, INVALID),
            (0xc000_0000_0000_0000, 0xc000_8000_0000_0000_0000, 0),
        ];
        for (bits, value, flags) in cases {
            assert_eq!(widen(F64, bits), (value, flags), "{bits:x}");
        }
        assert_eq!(widen(F32, 0x3f80_0000), (ONE, 0));
        assert_eq!(
            widen(F32, 1),
            (join(false, (BIAS - 149) as u16, INTEGER_BIT), DENORMAL)
        );
    }

    #[test]
    fn narrowing_rounds_as_the_control_word_asks() {
        // 1 + 2^-63 is between doubles.
        let above_one = join(false, BIAS as u16, INTEGER_BIT | 1);
        let one = 0x3ff0_0000_0000_0000;
        let inexact = INEXACT;
        assert_eq!(narrow(F64, above_one, 0), (one, inexact, false));
        assert_eq!(narrow(F64, above_one, UP), (one + 1, inexact, true));
        assert_eq!(narrow(F64, above_one, DOWN), (one, inexact, false));
        assert_eq!(narrow(F64, above_one, TOWARD_ZERO), (one, inexact, false));
        let below = above_one | 1 << 79;
        let minus = one | 1 << 63;
        assert_eq!(narrow(F64, below, DOWN), (minus + 1, inexact, true));
        assert_eq!(narrow(F64, below, UP), (minus, inexact, false));
    }

    #[test]
    fn narrowing_what_is_not_a_number_or_is_not_supported() {
        let infinity = 0x7fff_8000_0000_0000_0000;
        assert_eq!(narrow(F64, infinity, 0), (0x7ff0 << 48, 0, false));
        assert_eq!(narrow(F64, 1 << 79, 0), (1 << 63, 0, false));
        assert_eq!(
            narrow(F64, 0x7fff_c000_0000_0000_0800, 0),
            (0x7ff8_0000_0000_0001, 0, false)
        );
        assert_eq!(
            narrow(F64, 0x7fff_8000_0000_0000_0800, 0),
            (0x7ff8_0000_0000_0001, INVALID, false)
        );
        assert_eq!(
            narrow(F64, 0x3fff_0000_0000_0000_0000, 0),
            (F64.indefinite(), INVALID, false)
        );
        // Too large for a double: overflow, or the largest one toward zero.
        let huge = join(false, 0x7000, INTEGER_BIT);
        let (bits, flags, up) = narrow(F64, huge, 0);
        assert_eq!((bits, up), (0x7ff0 << 48, true));
        assert_ne!(flags & 1 << 3, 0, "overflow");
        let (bits, flags, up) = narrow(F64, huge, TOWARD_ZERO);
        assert_eq!((bits, up), (0x7fef_ffff_ffff_ffff, false));
        assert_ne!(flags & 1 << 3, 0, "overflow");
    }

    #[test]
    fn integers_round_as_the_control_word_asks() {
        let value = |text: i64, power: i32| {
            let mut x = X87::default();
            x.load_integer(text);
            let v = parts(x.get(0).unwrap());
            join(
                v.negative,
                (i32::from(v.exponent) + power) as u16,
                v.mantissa,
            )
        };
        let inexact = INEXACT;
        // 2.5, -2.5 and 3.5.
        let (a, b, c) = (value(5, -1), value(-5, -1), value(7, -1));
        assert_eq!(to_integer(a, 32, 0), (2, inexact, false));
        assert_eq!(to_integer(c, 32, 0), (4, inexact, true));
        assert_eq!(to_integer(a, 32, UP), (3, inexact, true));
        assert_eq!(to_integer(a, 32, DOWN), (2, inexact, false));
        assert_eq!(to_integer(a, 32, TOWARD_ZERO), (2, inexact, false));
        assert_eq!(to_integer(b, 32, UP), (0xffff_fffe, inexact, false));
        assert_eq!(to_integer(b, 32, DOWN), (0xffff_fffd, inexact, true));
        assert_eq!(to_integer(b, 64, DOWN), (-3i64 as u64, inexact, true));
        assert_eq!(to_integer(value(5, 0), 16, 0), (5, 0, false));
    }

    #[test]
    fn integers_that_do_not_fit_are_the_lowest() {
        let of = |n: i64| {
            let mut x = X87::default();
            x.load_integer(n);
            x.get(0).unwrap()
        };
        assert_eq!(to_integer(of(32767), 16, 0), (0x7fff, 0, false));
        assert_eq!(to_integer(of(32768), 16, 0), (0x8000, INVALID, false));
        assert_eq!(to_integer(of(-32768), 16, 0), (0x8000, 0, false));
        assert_eq!(to_integer(of(-32769), 16, 0), (0x8000, INVALID, false));
        assert_eq!(to_integer(of(i64::MIN), 64, 0), (1 << 63, 0, false));
        assert_eq!(to_integer(of(i64::MAX), 64, 0), (i64::MAX as u64, 0, false));
        let inexact = INEXACT;
        // The tiniest values round to 0, or to 1 away from it.
        let tiny = join(false, 1, INTEGER_BIT);
        assert_eq!(to_integer(tiny, 32, 0), (0, inexact, false));
        assert_eq!(to_integer(tiny, 32, UP), (1, inexact, true));
        let large = join(false, (BIAS + 64) as u16, INTEGER_BIT);
        assert_eq!(to_integer(large, 64, 0), (1 << 63, INVALID, false));
        let nan = 0x7fff_c000_0000_0000_0000;
        assert_eq!(to_integer(nan, 16, 0), (0x8000, INVALID, false));
    }

    #[test]
    fn the_stack_wraps_and_overflows_into_the_invalid_result() {
        let mut x = X87::default();
        for n in 1..=8 {
            x.load_integer(n);
            assert_eq!(x.status_word() & C1, 0);
        }
        assert_eq!(x.status_word() >> 11 & 7, 0);
        x.load_integer(9);
        let status = x.status_word();
        assert_ne!(status & INVALID, 0);
        assert_ne!(status & STACK_FAULT, 0);
        assert_ne!(status & C1, 0, "an overflow");
        assert_eq!(status >> 11 & 7, 7);
        assert_eq!(x.get(0), Some(INDEFINITE));
        assert_eq!(status & SUMMARY, 0, "masked");
    }

    #[test]
    fn reading_empty_is_invalid_and_no_overflow() {
        let mut x = X87::default();
        x.status |= C1;
        assert_eq!(x.store_float(F64), F64.indefinite());
        let status = x.status_word();
        assert_eq!(status & (INVALID | STACK_FAULT), INVALID | STACK_FAULT);
        assert_eq!(status & C1, 0);
        assert_eq!(x.store_integer(16), 0x8000);
        assert_eq!(x.store_extended(), INDEFINITE);
        x.load_register(3);
        assert_eq!(x.get(0), Some(INDEFINITE));
        assert_eq!(x.status_word() & C1, 0);
        x.negate();
        assert_eq!(x.get(0), Some(INDEFINITE ^ 1 << 79));
    }

    #[test]
    fn negate_and_absolute_of_empty_give_the_invalid_result() {
        let mut x = X87::default();
        x.negate();
        assert_eq!(x.get(0), Some(INDEFINITE));
        let mut x = X87::default();
        x.absolute();
        assert_eq!(x.get(0), Some(INDEFINITE));
        x.absolute();
        assert_eq!(x.get(0), Some(INDEFINITE & !(1 << 79)));
    }

    #[test]
    fn exchange_fills_what_was_empty_with_the_invalid_result() {
        let mut x = X87::default();
        x.load_integer(1);
        x.exchange(1);
        assert_eq!(x.get(1), Some(ONE));
        assert_eq!(x.get(0), Some(INDEFINITE));
        assert_ne!(x.status_word() & STACK_FAULT, 0);
        x.clear_exceptions();
        assert_eq!(x.status_word() & (STACK_FAULT | INVALID), 0);
        x.exchange(1);
        assert_eq!(x.get(0), Some(ONE));
        assert_eq!(x.status_word() & INVALID, 0);
    }

    #[test]
    fn examine_says_what_kind_of_value_it_is() {
        let kind = |value: Option<u128>| {
            let mut x = X87::default();
            if let Some(value) = value {
                x.load_extended(value);
            }
            x.examine();
            let s = x.status_word();
            (s & C3 != 0, s & C2 != 0, s & C0 != 0, s & C1 != 0)
        };
        assert_eq!(kind(None), (true, false, true, false));
        assert_eq!(kind(Some(ONE)), (false, true, false, false));
        assert_eq!(kind(Some(ONE | 1 << 79)), (false, true, false, true));
        assert_eq!(kind(Some(0)), (true, false, false, false));
        assert_eq!(kind(Some(1)), (true, true, false, false));
        assert_eq!(
            kind(Some(0x7fff_8000_0000_0000_0000)),
            (false, true, true, false)
        );
        assert_eq!(kind(Some(INDEFINITE)), (false, false, true, true));
        assert_eq!(
            kind(Some(0x3fff_0000_0000_0000_0000)),
            (false, false, false, false)
        );
    }

    #[test]
    fn comparing_orders_by_value_and_says_what_is_invalid() {
        let compare = |first: u128, second: u128, quiet: bool| {
            let mut x = X87::default();
            x.load_extended(second);
            x.load_extended(first);
            let order = x.compare(1, quiet);
            (order, x.status_word() & (INVALID | DENORMAL | STACK_FAULT))
        };
        let two = 0x4000_8000_0000_0000_0000;
        let minus = |v: u128| v | 1 << 79;
        let infinity = 0x7fff_8000_0000_0000_0000;
        let quiet_nan = 0x7fff_c000_0000_0000_0000;
        let signaling = 0x7fff_8000_0000_0000_0001;
        for quiet in [false, true] {
            assert_eq!(compare(ONE, two, quiet), (Some(Ordering::Less), 0));
            assert_eq!(compare(two, ONE, quiet), (Some(Ordering::Greater), 0));
            assert_eq!(compare(ONE, ONE, quiet), (Some(Ordering::Equal), 0));
            assert_eq!(
                compare(minus(ONE), minus(two), quiet),
                (Some(Ordering::Greater), 0)
            );
            assert_eq!(compare(minus(ONE), ONE, quiet), (Some(Ordering::Less), 0));
            assert_eq!(
                compare(ONE, minus(ONE), quiet),
                (Some(Ordering::Greater), 0)
            );
            assert_eq!(compare(0, minus(0), quiet), (Some(Ordering::Equal), 0));
            assert_eq!(compare(minus(0), ONE, quiet), (Some(Ordering::Less), 0));
            assert_eq!(compare(infinity, two, quiet), (Some(Ordering::Greater), 0));
            assert_eq!(compare(1, 0, quiet), (Some(Ordering::Greater), DENORMAL));
            assert_eq!(compare(0, 1, quiet), (Some(Ordering::Less), DENORMAL));
            assert_eq!(compare(signaling, ONE, quiet), (None, INVALID));
            assert_eq!(compare(ONE, signaling, quiet), (None, INVALID));
            assert_eq!(
                compare(0x3fff_0000_0000_0000_0000, ONE, quiet),
                (None, INVALID)
            );
            // A pseudo-denormal is the smallest normal.
            assert_eq!(
                compare(1 << 63, 0x0001_8000_0000_0000_0000, quiet),
                (Some(Ordering::Equal), DENORMAL)
            );
        }
        assert_eq!(compare(quiet_nan, ONE, true), (None, 0));
        assert_eq!(compare(ONE, quiet_nan, true), (None, 0));
        assert_eq!(compare(quiet_nan, ONE, false), (None, INVALID));
        assert_eq!(compare(ONE, quiet_nan, false), (None, INVALID));
        let mut x = X87::default();
        x.load_one();
        assert_eq!(x.compare(1, true), None);
        let status = x.status_word();
        assert_eq!(status & (INVALID | STACK_FAULT), INVALID | STACK_FAULT);
    }

    /// 80-bit images of small numbers: `n * 2^power`.
    fn number(n: i64, power: i32) -> u128 {
        let v = parts(integer_value(n));
        join(
            v.negative,
            (i32::from(v.exponent) + power) as u16,
            v.mantissa,
        )
    }
    const EXTENDED: u16 = 0x37f;
    const INFINITY: u128 = 0x7fff_8000_0000_0000_0000;
    const LARGEST: u128 = 0x7ffe_ffff_ffff_ffff_ffff;
    const SMALLEST_NORMAL: u128 = 0x0001_8000_0000_0000_0000;

    #[test]
    fn adding_is_exact_where_it_can_be_and_rounds_where_it_cannot() {
        let add = |a, b, control| calculate(Arithmetic::Add, a, b, false, control);
        assert_eq!(add(ONE, ONE, EXTENDED), (number(2, 0), 0, false));
        assert_eq!(
            add(number(3, 0), number(-5, 0), EXTENDED),
            (number(-2, 0), 0, false)
        );
        // 1 + 2^-64 is half of a unit: to even, or up if asked.
        let half = number(1, -64);
        assert_eq!(add(ONE, half, EXTENDED), (ONE, INEXACT, false));
        let above = join(false, BIAS as u16, INTEGER_BIT | 1);
        assert_eq!(add(ONE, half, EXTENDED | UP), (above, INEXACT, true));
        assert_eq!(add(ONE, half, EXTENDED | DOWN), (ONE, INEXACT, false));
        // Far below any bit kept, it still counts.
        let tiny = number(1, -5000);
        assert_eq!(add(ONE, tiny, EXTENDED | UP), (above, INEXACT, true));
        let below = join(false, BIAS as u16 - 1, u64::MAX);
        assert_eq!(
            add(ONE, tiny | 1 << 79, EXTENDED | TOWARD_ZERO),
            (below, INEXACT, false)
        );
        assert_eq!(add(ONE, tiny | 1 << 79, EXTENDED), (ONE, INEXACT, true));
    }

    #[test]
    fn nothing_left_has_the_sign_the_rounding_gives_it() {
        let add = |a, b, control| calculate(Arithmetic::Add, a, b, false, control).0;
        let minus = |v: u128| v | 1 << 79;
        assert_eq!(add(ONE, minus(ONE), EXTENDED), 0);
        assert_eq!(add(ONE, minus(ONE), EXTENDED | DOWN), 1 << 79);
        assert_eq!(add(0, minus(0), EXTENDED), 0);
        assert_eq!(add(0, minus(0), EXTENDED | DOWN), 1 << 79);
        assert_eq!(add(minus(0), minus(0), EXTENDED), 1 << 79);
        assert_eq!(add(0, 0, EXTENDED | DOWN), 0);
        let subtract = |a, b| calculate(Arithmetic::Subtract, a, b, false, EXTENDED).0;
        assert_eq!(subtract(0, 0), 0);
        assert_eq!(subtract(minus(0), 0), 1 << 79);
    }

    #[test]
    fn the_precision_keeps_fewer_bits_of_the_four_operations_and_the_root() {
        let single = 0x07f;
        let double = 0x27f;
        let above = number((1 << 24) + 1, -24);
        let add = |a, b, control| calculate(Arithmetic::Add, a, b, false, control);
        // 1 + 2^-24 is half of a single's unit.
        assert_eq!(add(ONE, number(1, -24), single), (ONE, INEXACT, false));
        assert_eq!(
            add(ONE, number(1, -24), single | UP),
            (number((1 << 23) + 1, -23), INEXACT, true)
        );
        assert_eq!(add(ONE, number(1, -24), double), (above, 0, false));
        let third = calculate(Arithmetic::Divide, ONE, number(3, 0), false, double).0;
        assert_eq!(third, join(false, BIAS as u16 - 2, 0xaaaa_aaaa_aaaa_a800));
        let (root, _, _) = square_root(number(2, 0), single);
        assert_eq!(root, join(false, BIAS as u16, 0xb504_f300_0000_0000));
        // The largest is what the precision can hold.
        let (value, flags, up) = calculate(
            Arithmetic::Multiply,
            LARGEST,
            number(2, 0),
            false,
            double | TOWARD_ZERO,
        );
        assert_eq!(value, 0x7ffe_ffff_ffff_ffff_f800);
        assert_eq!((flags, up), (OVERFLOW | INEXACT, false));
    }

    #[test]
    fn multiplying_and_dividing_round_their_whole_results() {
        let multiply = |a, b, control| calculate(Arithmetic::Multiply, a, b, false, control);
        let divide = |a, b, control| calculate(Arithmetic::Divide, a, b, false, control);
        assert_eq!(
            multiply(number(3, 0), number(-5, 0), EXTENDED).0,
            number(-15, 0)
        );
        assert_eq!(
            divide(number(15, 0), number(-5, 0), EXTENDED),
            (number(-3, 0), 0, false)
        );
        // 1/3 rounds up in the last bit.
        let third = join(false, BIAS as u16 - 2, 0xaaaa_aaaa_aaaa_aaab);
        assert_eq!(divide(ONE, number(3, 0), EXTENDED), (third, INEXACT, true));
        assert_eq!(
            divide(ONE, number(3, 0), EXTENDED | DOWN),
            (third - 1, INEXACT, false)
        );
        // A denormal counts as what it is, and the result is normal.
        let denormal = 1 << 40;
        assert_eq!(
            multiply(denormal, number(1, 16000), EXTENDED),
            (number(1, 40 + 16000 - 16445), DENORMAL, false)
        );
        assert_eq!(divide(denormal, denormal, EXTENDED), (ONE, DENORMAL, false));
    }

    #[test]
    fn what_is_too_large_overflows_as_the_rounding_says() {
        let double =
            |control| calculate(Arithmetic::Multiply, LARGEST, number(2, 0), false, control);
        let flags = OVERFLOW | INEXACT;
        assert_eq!(double(EXTENDED), (INFINITY, flags, true));
        assert_eq!(double(EXTENDED | UP), (INFINITY, flags, true));
        assert_eq!(double(EXTENDED | DOWN), (LARGEST, flags, false));
        assert_eq!(double(EXTENDED | TOWARD_ZERO), (LARGEST, flags, false));
        let minus = LARGEST | 1 << 79;
        let double = |control| calculate(Arithmetic::Multiply, minus, number(2, 0), false, control);
        assert_eq!(double(EXTENDED | UP), (minus, flags, false));
        assert_eq!(double(EXTENDED | DOWN), (INFINITY | 1 << 79, flags, true));
    }

    #[test]
    fn what_is_too_small_is_denormal_and_underflows_only_if_it_rounds() {
        let half = number(1, -1);
        let multiply = |a, b, control| calculate(Arithmetic::Multiply, a, b, false, control);
        // Exactly half of the smallest normal.
        assert_eq!(
            multiply(SMALLEST_NORMAL, half, EXTENDED),
            (1 << 62, 0, false)
        );
        // Half of the smallest denormal: to even, or up if asked.
        assert_eq!(
            multiply(1, half, EXTENDED),
            (0, DENORMAL | INEXACT | UNDERFLOW, false)
        );
        assert_eq!(
            multiply(1, half, EXTENDED | UP),
            (1, DENORMAL | INEXACT | UNDERFLOW, true)
        );
        // Just below the smallest normal, rounding up to it is not tiny.
        let under = join(false, 0, u64::MAX >> 1);
        assert_eq!(
            multiply(under | 1, ONE, EXTENDED),
            (under | 1, DENORMAL, false)
        );
        let close = round_extended(
            false,
            u128::from(u64::MAX) << 1 | 1,
            -16446 - 1,
            EXTENDED,
            64,
        );
        assert_eq!(close, (SMALLEST_NORMAL, INEXACT, true));
        // Rounding at the place of the precision, shifted or not.
        let single = 0x07f;
        let shifted = round_extended(false, (1 << 63) | 1, -16445 - 63 - 3, single, 24);
        assert_eq!(shifted.0, 0, "below the kept bits");
        assert_eq!(shifted.1, INEXACT | UNDERFLOW);
        // A shift too far to count still rounds, away if asked.
        let gone = round_extended(false, 1, -100_000, EXTENDED | UP, 64);
        assert_eq!(gone, (1, INEXACT | UNDERFLOW, true));
    }

    #[test]
    fn what_is_invalid_comes_before_a_denormal_and_a_nan_comes_before_both() {
        let calc = |operation, a, b| calculate(operation, a, b, false, EXTENDED);
        let minus = INFINITY | 1 << 79;
        let invalid = (INDEFINITE, INVALID, false);
        assert_eq!(calc(Arithmetic::Add, INFINITY, minus), invalid);
        assert_eq!(calc(Arithmetic::Subtract, INFINITY, INFINITY), invalid);
        assert_eq!(calc(Arithmetic::Multiply, INFINITY, 0), invalid);
        assert_eq!(calc(Arithmetic::Multiply, 1 << 79, minus), invalid);
        assert_eq!(calc(Arithmetic::Divide, 0, 1 << 79), invalid);
        assert_eq!(calc(Arithmetic::Divide, INFINITY, minus), invalid);
        assert_eq!(
            calc(Arithmetic::Add, INFINITY, INFINITY),
            (INFINITY, 0, false)
        );
        assert_eq!(calc(Arithmetic::Subtract, ONE, INFINITY), (minus, 0, false));
        assert_eq!(calc(Arithmetic::Multiply, minus, ONE), (minus, 0, false));
        assert_eq!(calc(Arithmetic::Divide, ONE, minus), (1 << 79, 0, false));
        assert_eq!(calc(Arithmetic::Divide, minus, ONE), (minus, 0, false));
        assert_eq!(calc(Arithmetic::Divide, 0, ONE), (0, 0, false));
        assert_eq!(
            calc(Arithmetic::Divide, ONE, 0),
            (INFINITY, ZERO_DIVIDE, false)
        );
        assert_eq!(
            calc(Arithmetic::Divide, ONE, 1 << 79),
            (minus, ZERO_DIVIDE, false)
        );
        assert_eq!(
            calc(Arithmetic::Divide, 1, 0),
            (INFINITY, ZERO_DIVIDE, false)
        );
        assert_eq!(
            calc(Arithmetic::Multiply, 1, INFINITY),
            (INFINITY, DENORMAL, false)
        );
        let quiet = 0x7fff_c000_0000_0000_0005;
        assert_eq!(calc(Arithmetic::Add, 1, quiet), (quiet, 0, false));
        assert_eq!(
            calc(Arithmetic::Add, 0x3fff_0000_0000_0000_0000, quiet),
            invalid
        );
    }

    #[test]
    fn a_nan_is_chosen_by_kind_then_by_size_then_by_sign() {
        let pick = |a, b| calculate(Arithmetic::Add, a, b, false, EXTENDED);
        let quiet = 0x7fff_c000_0000_0000_0005;
        let larger = 0x7fff_c000_0000_0000_0006;
        let signaling = 0x7fff_8000_0000_0000_0009;
        let bigger = 0x7fff_8000_0000_0000_000a;
        let quieted = |v: u128| v | u128::from(QUIET_BIT);
        assert_eq!(pick(signaling, ONE), (quieted(signaling), INVALID, false));
        assert_eq!(pick(ONE, signaling), (quieted(signaling), INVALID, false));
        assert_eq!(pick(signaling, quiet), (quiet, INVALID, false));
        assert_eq!(pick(quiet, signaling), (quiet, INVALID, false));
        assert_eq!(pick(quiet, larger), (larger, 0, false));
        assert_eq!(pick(larger, quiet), (larger, 0, false));
        assert_eq!(pick(signaling, bigger), (quieted(bigger), INVALID, false));
        assert_eq!(pick(quiet | 1 << 79, quiet), (quiet, 0, false));
        assert_eq!(pick(quiet, quiet | 1 << 79), (quiet, 0, false));
    }

    #[test]
    fn an_operand_from_memory_is_signaling_until_it_is_used() {
        let (value, denormal) = float_operand(F64, 0x7ff0_0000_0000_0001);
        assert!(parts(value).signaling());
        assert!(!denormal);
        let quiet = 0x7fff_c000_0000_0000_0005;
        let mut x = X87::default();
        x.load_extended(quiet);
        x.calculate_memory((Arithmetic::Add, false), value, denormal);
        assert_eq!(x.get(0), Some(quiet));
        assert_ne!(x.status_word() & INVALID, 0);
        let mut x = X87::default();
        x.load_one();
        let (value, denormal) = float_operand(F64, 1);
        assert!(denormal);
        x.calculate_memory((Arithmetic::Multiply, false), value, denormal);
        assert_ne!(x.status_word() & DENORMAL, 0);
        assert_eq!(float_operand(F32, 0x3f80_0000), (ONE, false));
    }

    #[test]
    fn the_operations_read_their_operands_in_order_and_empty_is_invalid() {
        let mut x = X87::default();
        x.load_integer(2);
        x.load_integer(8);
        x.calculate_registers((Arithmetic::Divide, false), 0, 1);
        assert_eq!(x.get(0), Some(number(4, 0)));
        x.calculate_registers((Arithmetic::Divide, true), 0, 1);
        assert_eq!(x.get(0), Some(number(1, -1)));
        x.calculate_registers((Arithmetic::Subtract, false), 1, 0);
        assert_eq!(x.get(1), Some(number(3, -1)));
        x.calculate_memory((Arithmetic::Subtract, true), number(1, 0), false);
        assert_eq!(x.get(0), Some(number(1, -1)));
        assert_eq!(x.status_word() & 0x3f, 0);
        x.calculate_registers((Arithmetic::Add, false), 0, 3);
        assert_eq!(x.get(0), Some(INDEFINITE));
        assert_eq!(x.status_word() & 0x41, 0x41);
        let mut x = X87::default();
        x.status |= C1;
        x.calculate_memory((Arithmetic::Add, false), ONE, false);
        assert_eq!(x.get(0), Some(INDEFINITE));
        assert_eq!(x.status_word() & C1, 0);
        // C1 says the size went up, and the next one clears it.
        let mut x = X87::default();
        x.load_integer(3);
        x.load_one();
        x.calculate_registers((Arithmetic::Divide, false), 0, 1);
        assert_ne!(x.status_word() & C1, 0);
        x.calculate_registers((Arithmetic::Add, false), 1, 1);
        assert_eq!(x.status_word() & C1, 0);
    }

    #[test]
    fn roots_are_correct_to_the_last_bit() {
        let root = |v, control| square_root(v, control);
        assert_eq!(root(number(4, 0), EXTENDED), (number(2, 0), 0, false));
        assert_eq!(root(number(9, 2), EXTENDED), (number(6, 0), 0, false));
        let two = join(false, BIAS as u16, 0xb504_f333_f9de_6484);
        assert_eq!(root(number(2, 0), EXTENDED), (two, INEXACT, false));
        assert_eq!(root(number(2, 0), EXTENDED | UP), (two + 1, INEXACT, true));
        // Of a denormal, 2^-16445: an odd power.
        assert_eq!(
            root(1, EXTENDED),
            (
                join(false, (BIAS - 8223) as u16, 0xb504_f333_f9de_6484),
                DENORMAL | INEXACT,
                false
            )
        );
        assert_eq!(root(1 << 79, EXTENDED), (1 << 79, 0, false));
        assert_eq!(root(INFINITY, EXTENDED), (INFINITY, 0, false));
        assert_eq!(root(ONE | 1 << 79, EXTENDED), (INDEFINITE, INVALID, false));
        assert_eq!(
            root(INFINITY | 1 << 79, EXTENDED),
            (INDEFINITE, INVALID, false)
        );
        assert_eq!(root(1 | 1 << 79, EXTENDED), (INDEFINITE, INVALID, false));
    }

    #[test]
    fn remainders_keep_the_quotients_last_bits() {
        let chopped = |a, b| {
            let r = remainder(a, b, false);
            (r.value, r.quotient, r.partial)
        };
        assert_eq!(chopped(number(7, 0), number(3, 0)), (ONE, 2, false));
        assert_eq!(
            chopped(number(-7, 0), number(3, 0)),
            (number(-1, 0), 2, false)
        );
        assert_eq!(chopped(number(7, 0), number(-3, 0)), (ONE, 2, false));
        assert_eq!(chopped(number(6, 0), number(3, 0)), (0, 2, false));
        assert_eq!(chopped(number(-6, 0), number(3, 0)), (1 << 79, 2, false));
        assert_eq!(chopped(ONE, number(3, 0)), (ONE, 0, false));
        assert_eq!(chopped(ONE, INFINITY), (ONE, 0, false));
        // A pseudo-denormal comes out as the normal it is, and a denormal stays.
        assert_eq!(chopped(1 << 63, INFINITY), (SMALLEST_NORMAL, 0, false));
        assert_eq!(chopped(1, INFINITY), (1, 0, false));
        let nearest = |a, b| {
            let r = remainder(a, b, true);
            (r.value, r.quotient, r.partial)
        };
        assert_eq!(nearest(number(7, 0), number(3, 0)), (ONE, 2, false));
        assert_eq!(
            nearest(number(8, 0), number(3, 0)),
            (number(-1, 0), 3, false)
        );
        // Half way goes to the even quotient: 2.5 and 3.5.
        assert_eq!(nearest(number(5, 0), number(2, 0)), (ONE, 2, false));
        assert_eq!(
            nearest(number(7, 0), number(2, 0)),
            (number(-1, 0), 4, false)
        );
        assert_eq!(nearest(number(-8, 0), number(3, 0)), (ONE, 3, false));
        // Just over half of it: its exponent is one below.
        assert_eq!(
            nearest(number(3, 0), number(4, 0)),
            (number(-1, 0), 1, false)
        );
        assert_eq!(
            chopped(number(3, 0), number(4, 0)),
            (number(3, 0), 0, false)
        );
        // Half of it, to the even quotient 0.
        assert_eq!(
            nearest(number(2, 0), number(4, 0)),
            (number(2, 0), 0, false)
        );
        assert_eq!(nearest(ONE, number(4, 0)), (ONE, 0, false));
    }

    #[test]
    fn a_remainder_of_what_is_far_apart_goes_in_parts_to_the_same_end() {
        for nearest in [false, true] {
            let mut x = X87::default();
            x.load_integer(3);
            x.load_extended(number(1, 1000));
            let mut rounds = 0;
            loop {
                x.remainder(nearest);
                rounds += 1;
                if x.status_word() & C2 == 0 {
                    break;
                }
                assert_ne!(rounds, 100);
            }
            assert!(rounds > 1);
            // 2^1000 is 1 more than a multiple of 3.
            assert_eq!(x.get(0), Some(ONE));
        }
    }

    #[test]
    fn a_remainder_says_what_it_cannot_do() {
        let of = |a, b| {
            let r = remainder(a, b, false);
            (r.value, r.flags)
        };
        assert_eq!(of(INFINITY, ONE), (INDEFINITE, INVALID));
        assert_eq!(of(ONE, 0), (INDEFINITE, INVALID));
        assert_eq!(of(0, 0), (INDEFINITE, INVALID));
        assert_eq!(of(0, ONE), (0, 0));
        assert_eq!(of(1 << 79, ONE), (1 << 79, 0));
        assert_eq!(of(1, ONE), (1, DENORMAL));
        assert_eq!(of(ONE, 1), (0, DENORMAL));
        let mut x = X87::default();
        x.load_one();
        x.status |= C0 | C1 | C3;
        x.remainder(false);
        assert_eq!(x.get(0), Some(INDEFINITE));
        assert_eq!(x.status_word() & (C0 | C1 | C2 | C3), 0);
    }

    #[test]
    fn rounding_to_whole_numbers_follows_the_control_word() {
        let whole = |v, control| round_to_whole(v, control);
        assert_eq!(
            whole(number(5, -1), EXTENDED),
            (number(2, 0), INEXACT, false)
        );
        assert_eq!(
            whole(number(7, -1), EXTENDED),
            (number(4, 0), INEXACT, true)
        );
        assert_eq!(
            whole(number(5, -1), EXTENDED | UP),
            (number(3, 0), INEXACT, true)
        );
        assert_eq!(
            whole(number(-5, -1), EXTENDED | DOWN),
            (number(-3, 0), INEXACT, true)
        );
        assert_eq!(
            whole(number(-5, -1), EXTENDED | UP),
            (number(-2, 0), INEXACT, false)
        );
        assert_eq!(
            whole(number(5, -1), EXTENDED | TOWARD_ZERO),
            (number(2, 0), INEXACT, false)
        );
        assert_eq!(whole(number(-1, -1), EXTENDED), (1 << 79, INEXACT, false));
        assert_eq!(whole(number(1, -1), EXTENDED | UP), (ONE, INEXACT, true));
        assert_eq!(whole(number(5, 0), EXTENDED), (number(5, 0), 0, false));
        assert_eq!(whole(number(1, 70), EXTENDED), (number(1, 70), 0, false));
        assert_eq!(whole(1, EXTENDED), (0, DENORMAL | INEXACT, false));
        assert_eq!(whole(1, EXTENDED | UP), (ONE, DENORMAL | INEXACT, true));
        assert_eq!(whole(INFINITY, EXTENDED), (INFINITY, 0, false));
        assert_eq!(whole(1 << 79, EXTENDED), (1 << 79, 0, false));
        // Precision does not apply.
        let long = join(false, BIAS as u16 + 40, u64::MAX << 23);
        assert_eq!(whole(long, 0x07f).0, long);
    }

    #[test]
    fn scaling_cuts_its_power_to_a_whole_number() {
        let of = |a, b| scale(a, b, EXTENDED);
        assert_eq!(of(ONE, number(3, 0)), (number(8, 0), 0, false));
        assert_eq!(of(ONE, number(7, -1)), (number(8, 0), 0, false));
        assert_eq!(of(ONE, number(-7, -1)), (number(1, -3), 0, false));
        assert_eq!(of(ONE, number(1, -1)), (ONE, 0, false));
        assert_eq!(of(ONE, 0), (ONE, 0, false));
        assert_eq!(of(ONE, 1), (ONE, DENORMAL, false));
        assert_eq!(
            of(1, number(20000, 0)),
            (number(1, 20000 - 16445), DENORMAL, false)
        );
        assert_eq!(
            of(1, number(1, 20)),
            (INFINITY, DENORMAL | OVERFLOW | INEXACT, true)
        );
        assert_eq!(
            of(ONE, number(1, 200)),
            (INFINITY, OVERFLOW | INEXACT, true)
        );
        assert_eq!(of(ONE, number(-1, 200)), (0, UNDERFLOW | INEXACT, false));
        assert_eq!(of(0, INFINITY), (INDEFINITE, INVALID, false));
        assert_eq!(
            of(INFINITY, INFINITY | 1 << 79),
            (INDEFINITE, INVALID, false)
        );
        assert_eq!(of(ONE, INFINITY), (INFINITY, 0, false));
        assert_eq!(of(ONE | 1 << 79, INFINITY | 1 << 79), (1 << 79, 0, false));
        assert_eq!(of(0, number(5, 0)), (0, 0, false));
        assert_eq!(of(INFINITY, number(-5, 0)), (INFINITY, 0, false));
        assert_eq!(of(0, INFINITY | 1 << 79), (0, 0, false));
    }

    #[test]
    fn extracting_leaves_the_exponent_under_the_mantissa() {
        let of = |value| {
            let mut x = X87::default();
            x.load_extended(value);
            x.extract();
            (x.get(0), x.get(1), x.status_word() & EXCEPTIONS)
        };
        assert_eq!(of(number(8, 0)), (Some(ONE), Some(number(3, 0)), 0));
        assert_eq!(of(number(-3, 0)), (Some(number(-3, -1)), Some(ONE), 0));
        assert_eq!(of(number(1, -1)), (Some(ONE), Some(number(-1, 0)), 0));
        assert_eq!(of(1), (Some(ONE), Some(number(-16445, 0)), DENORMAL));
        assert_eq!(
            of(1 << 79),
            (Some(1 << 79), Some(INFINITY | 1 << 79), ZERO_DIVIDE)
        );
        assert_eq!(
            of(INFINITY | 1 << 79),
            (Some(INFINITY | 1 << 79), Some(INFINITY), 0)
        );
        let quieted = 0x7fff_c000_0000_0000_0009;
        assert_eq!(
            of(0x7fff_8000_0000_0000_0009),
            (Some(quieted), Some(quieted), INVALID)
        );
        let mut x = X87::default();
        x.extract();
        assert_eq!((x.get(0), x.get(1)), (Some(INDEFINITE), Some(INDEFINITE)));
        assert_eq!(x.status_word() & 0x41, 0x41);
        let mut x = X87::default();
        for _ in 0..8 {
            x.load_one();
        }
        x.extract();
        assert_eq!((x.get(0), x.get(1)), (Some(INDEFINITE), Some(INDEFINITE)));
        assert_eq!(x.get(2), Some(ONE));
        assert_ne!(x.status_word() & C1, 0);
    }

    #[test]
    fn constants_round_as_the_control_word_asks_and_raise_nothing() {
        let of = |constant, control| {
            let mut x = X87::default();
            x.set_control(control);
            x.load_constant(constant);
            assert_eq!(x.status_word() & EXCEPTIONS, 0);
            x.get(0).unwrap() as u64 & 0xffff
        };
        assert_eq!(of(PI, EXTENDED), 0xc235);
        assert_eq!(of(PI, EXTENDED | UP), 0xc235);
        assert_eq!(of(PI, EXTENDED | DOWN), 0xc234);
        assert_eq!(of(PI, EXTENDED | TOWARD_ZERO), 0xc234);
        assert_eq!(of(LN_2, EXTENDED), 0x79ac);
        assert_eq!(of(LOG10_2, EXTENDED), 0xf799);
        assert_eq!(of(LOG2_E, EXTENDED), 0xf0bc);
        assert_eq!(of(LOG2_10, EXTENDED), 0x8afe);
        assert_eq!(of(LOG2_10, EXTENDED | UP), 0x8aff);
    }

    #[test]
    fn comparing_says_its_order_in_the_condition_bits() {
        let of = |first: i64, second: u128, denormal| {
            let mut x = X87::default();
            x.load_integer(first);
            x.compare_value(second, denormal);
            x.status_word() & (C0 | C1 | C2 | C3 | DENORMAL | INVALID)
        };
        assert_eq!(of(2, ONE, false), 0);
        assert_eq!(of(0, ONE, false), C0);
        assert_eq!(of(1, ONE, false), C3);
        assert_eq!(of(2, ONE, true), DENORMAL);
        let quiet = 0x7fff_c000_0000_0000_0000;
        assert_eq!(of(1, quiet, false), C0 | C2 | C3 | INVALID);
        let mut x = X87::default();
        x.load_extended(quiet);
        x.load_one();
        x.compare_register(1, true);
        assert_eq!(x.status_word() & (C0 | C2 | C3 | INVALID), C0 | C2 | C3);
        x.compare_register(1, false);
        assert_ne!(x.status_word() & INVALID, 0);
        let mut x = X87::default();
        x.compare_register(1, false);
        assert_eq!(
            x.status_word() & (C0 | C2 | C3 | INVALID | STACK_FAULT),
            C0 | C2 | C3 | INVALID | STACK_FAULT
        );
    }

    #[test]
    fn a_conditional_move_moves_only_if_it_is_taken() {
        let mut x = X87::default();
        x.load_integer(2);
        x.load_one();
        x.conditional_move(1, false);
        assert_eq!(x.get(0), Some(ONE));
        x.conditional_move(1, true);
        assert_eq!(x.get(0), Some(number(2, 0)));
        assert_eq!(x.status_word() & INVALID, 0);
        x.conditional_move(3, false);
        assert_eq!(x.get(0), Some(INDEFINITE));
        assert_ne!(x.status_word() & STACK_FAULT, 0);
    }

    #[test]
    fn an_empty_top_gives_the_invalid_result_for_every_one_operand_form() {
        let check: [fn(&mut X87); 4] = [
            X87::square_root,
            X87::round_to_whole,
            X87::scale,
            X87::extract,
        ];
        for run in check {
            let mut x = X87::default();
            x.status |= C1;
            run(&mut x);
            assert_eq!(x.get(0), Some(INDEFINITE));
            assert_eq!(
                x.status_word() & (C1 | INVALID | STACK_FAULT),
                INVALID | STACK_FAULT
            );
        }
    }

    #[test]
    fn the_control_word_keeps_the_bits_that_exist() {
        let mut x = X87::default();
        assert_eq!(x.control_word(), 0x37f);
        x.set_control(0xffff);
        assert_eq!(x.control_word(), 0x1f7f);
        x.set_control(0);
        assert_eq!(x.control_word(), 0x40);
    }

    #[test]
    fn an_unmasked_exception_is_summarized_and_clearing_ends_it() {
        let mut x = X87::default();
        x.store_float(F64);
        assert_eq!(x.status_word() & SUMMARY, 0);
        x.set_control(0x37f & !1);
        assert_eq!(x.status_word() & SUMMARY, SUMMARY);
        x.clear_exceptions();
        assert_eq!(x.status_word() & (SUMMARY | INVALID | STACK_FAULT), 0);
    }

    #[test]
    fn popping_empties_the_register_and_free_leaves_the_top() {
        let mut x = X87::default();
        x.load_one();
        x.load_zero();
        x.free(0);
        assert_eq!(x.status_word() >> 11 & 7, 6);
        assert_eq!(x.get(0), None);
        x.increment_top();
        assert_eq!(x.get(0), Some(ONE));
        x.decrement_top();
        assert_eq!(x.status_word() >> 11 & 7, 6);
        x.increment_top();
        x.pop();
        assert_eq!(x.get(0), None);
        assert_eq!(x.status_word() >> 11 & 7, 0);
    }

    #[test]
    fn the_environment_says_each_register_kind_and_masks_all() {
        let mut x = X87::default();
        x.set_control(0x27f);
        x.load_one();
        x.load_zero();
        x.load_extended(INDEFINITE);
        let image = x.store_environment();
        assert_eq!(u16::from_le_bytes([image[0], image[1]]), 0x27f);
        assert_eq!(u16::from_le_bytes([image[4], image[5]]) >> 11 & 7, 5);
        // R7 valid, R6 zero, R5 special, the rest empty.
        let expected = 0b00_01_10_11_11_11_11_11;
        assert_eq!(u16::from_le_bytes([image[8], image[9]]), expected);
        for at in [2, 6, 10, 26] {
            assert_eq!(&image[at..at + 2], &[0xff, 0xff], "reserved at {at}");
        }
        assert_eq!(&image[12..26], &[0; 14], "nothing kept of where it was");
        assert_eq!(x.control_word(), 0x27f | 0x3f);
        x.set_control(0x260);
        x.store_environment();
        assert_eq!(x.control_word(), 0x27f, "every exception masked");
        let mut other = X87::default();
        other.load_environment(&image);
        assert_eq!(other.control_word(), 0x27f);
        assert_eq!(other.status_word() >> 11 & 7, 5);
        assert_eq!(other.used, x.used);
    }

    #[test]
    fn the_image_keeps_the_registers_from_the_top() {
        let mut x = X87::default();
        x.set_control(0x27f);
        x.load_one();
        x.load_extended(INDEFINITE);
        let mut area = [0; 160];
        x.write_image(&mut area);
        assert_eq!(area[4], 0b1100_0000);
        assert_eq!(&area[32..42], &INDEFINITE.to_le_bytes()[..10]);
        assert_eq!(&area[48..58], &ONE.to_le_bytes()[..10]);
        let mut other = X87::default();
        other.read_image(&area);
        assert_eq!(other.get(0), Some(INDEFINITE));
        assert_eq!(other.get(1), Some(ONE));
        assert_eq!(other.control_word(), 0x27f);
        assert_eq!(other.status_word(), x.status_word());
    }

    #[test]
    fn initializing_leaves_what_the_registers_hold() {
        let mut x = X87::default();
        x.load_one();
        x.set_control(0);
        x.initialize();
        assert_eq!(x.control_word(), INITIAL_CONTROL);
        assert_eq!((x.status_word(), x.used), (0, 0));
        assert_eq!(x.registers[7], ONE);
    }
}
