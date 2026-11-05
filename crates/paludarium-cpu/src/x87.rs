//! The x87 unit: its eight 80-bit registers as a stack, and its control and
//! status words. Values stay in their 80-bit images, in integers, so no host
//! floating-point environment takes part. Exceptions all take their masked
//! response: an unmasked one is noted in the status word, and does not fault.
use core::cmp::Ordering;

use crate::softfloat::{self, Format};

const INVALID: u16 = 1;
const DENORMAL: u16 = 1 << 1;
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
    let mantissa = u128::from(v.mantissa);
    let (whole, rest, half) = if power >= 0 {
        if power >= 64 {
            return (lowest, INVALID, false);
        }
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
    };
    // The tiniest value is below any half here, as `rest` is 1 of 2^127.
    let up = rest != 0
        && match control >> 10 & 3 {
            0 => rest > half || (rest == half && whole & 1 != 0),
            1 => v.negative,
            2 => !v.negative,
            _ => false,
        };
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
        if value == 0 {
            self.push(0);
            return;
        }
        let size = value.unsigned_abs();
        let shift = size.leading_zeros();
        let exponent = BIAS + 63 - shift as i32;
        self.push(join(value < 0, exponent as u16, size << shift));
    }
    pub(crate) fn load_zero(&mut self) {
        self.push(0);
    }
    pub(crate) fn load_one(&mut self) {
        self.push(ONE);
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
    /// `fcomi` or, for `quiet`, `fucomi`: how st(0) compares with a register,
    /// or `None` when they do not. A quiet NaN is invalid only for `fcomi`.
    pub(crate) fn compare(&mut self, index: u8, quiet: bool) -> Option<Ordering> {
        self.condition(C1, false);
        let (Some(first), Some(second)) = (self.get(0), self.get(index)) else {
            self.raise(INVALID | STACK_FAULT);
            return None;
        };
        let (a, b) = (parts(first), parts(second));
        if a.unsupported() || b.unsupported() {
            self.raise(INVALID);
            return None;
        }
        if a.nan() || b.nan() {
            let signaling = |v: Parts| v.nan() && v.mantissa & QUIET_BIT == 0;
            if !quiet || signaling(a) || signaling(b) {
                self.raise(INVALID);
            }
            return None;
        }
        if (a.exponent == 0 && !a.zero()) || (b.exponent == 0 && !b.zero()) {
            self.raise(DENORMAL);
        }
        // Zeros are equal whatever their signs. A pseudo-denormal has the
        // value of the normal with its bits.
        let size = |v: Parts| (v.exponent.max(1), v.mantissa);
        let signed = |v: Parts| v.negative && !v.zero();
        Some(match (signed(a), signed(b)) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => size(a).cmp(&size(b)),
            (true, true) => size(b).cmp(&size(a)),
        })
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
