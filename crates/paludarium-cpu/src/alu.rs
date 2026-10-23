//! Pure arithmetic and flag computations. Every function takes the operand
//! size in bytes (1, 2, 4 or 8) and works on values already truncated to it.
//! Returned flag words contain only status-flag bits.

use paludarium_decoder::Condition;

use crate::state::flag;

/// All-ones mask for an operand of `size` bytes.
#[must_use]
pub const fn size_mask(size: u8) -> u64 {
    match size {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

/// The sign bit of an operand of `size` bytes.
#[must_use]
pub const fn sign_bit(size: u8) -> u64 {
    match size {
        1 => 0x80,
        2 => 0x8000,
        4 => 0x8000_0000,
        _ => 1 << 63,
    }
}

/// Width in bits.
#[must_use]
pub const fn bits(size: u8) -> u32 {
    match size {
        1 => 8,
        2 => 16,
        4 => 32,
        _ => 64,
    }
}

/// Sign-extends a `size`-byte value to 64 bits.
#[must_use]
pub const fn sign_extend(value: u64, size: u8) -> u64 {
    let shift = 64 - bits(size);
    (((value << shift) as i64) >> shift) as u64
}

/// ZF, SF and PF of a result.
///
/// The operand is shifted to the top of the word rather than masked: with a
/// mask per size, LLVM merges the masked values in one wasm local, and
/// JavaScriptCore on x86-64 (WebKit 27.2) then tests only its low 32 bits,
/// setting ZF for `0x8000_0000_0000_0000`.
#[must_use]
pub fn zf_sf_pf(result: u64, size: u8) -> u64 {
    let top = result << (64 - bits(size));
    let mut f = 0;
    if top == 0 {
        f |= flag::ZF;
    }
    if top >> 63 != 0 {
        f |= flag::SF;
    }
    // PF is set when the low byte has an even number of one bits.
    if (result as u8).count_ones().is_multiple_of(2) {
        f |= flag::PF;
    }
    f
}

/// `a + b + carry` with CF, PF, AF, ZF, SF, OF.
#[must_use]
pub fn add(a: u64, b: u64, carry: bool, size: u8) -> (u64, u64) {
    let mask = size_mask(size);
    let wide = u128::from(a) + u128::from(b) + u128::from(carry);
    let r = (wide as u64) & mask;
    let mut f = zf_sf_pf(r, size);
    if wide > u128::from(mask) {
        f |= flag::CF;
    }
    if (a ^ r) & (b ^ r) & sign_bit(size) != 0 {
        f |= flag::OF;
    }
    if (a ^ b ^ r) & 0x10 != 0 {
        f |= flag::AF;
    }
    (r, f)
}

/// `a - b - borrow` with CF, PF, AF, ZF, SF, OF.
#[must_use]
pub fn sub(a: u64, b: u64, borrow: bool, size: u8) -> (u64, u64) {
    let mask = size_mask(size);
    let r = a.wrapping_sub(b).wrapping_sub(u64::from(borrow)) & mask;
    let mut f = zf_sf_pf(r, size);
    if u128::from(a) < u128::from(b) + u128::from(borrow) {
        f |= flag::CF;
    }
    if (a ^ b) & (a ^ r) & sign_bit(size) != 0 {
        f |= flag::OF;
    }
    if (a ^ b ^ r) & 0x10 != 0 {
        f |= flag::AF;
    }
    (r, f)
}

/// Flags of a logical operation: CF = OF = 0, AF = 0 (undefined on x86).
#[must_use]
pub fn logic(result: u64, size: u8) -> u64 {
    zf_sf_pf(result, size)
}

/// Result and flags of a shift. `None` when the masked count is zero, in
/// which case neither the destination nor the flags change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShiftKind {
    Shl,
    Shr,
    Sar,
}

/// Shifts `a` by `count` (masked to 5 bits, 6 for 64-bit operands).
/// Undefined flags (AF; OF when the count is not 1) are computed as zero /
/// as for a count of 1 respectively.
#[must_use]
pub fn shift(kind: ShiftKind, a: u64, count: u64, size: u8) -> Option<(u64, u64)> {
    let count = u32::try_from(count & if size == 8 { 63 } else { 31 }).ok()?;
    if count == 0 {
        return None;
    }
    let width = bits(size);
    let mask = size_mask(size);
    let (r, cf) = match kind {
        ShiftKind::Shl => {
            let r = if count >= width {
                0
            } else {
                (a << count) & mask
            };
            let cf = count <= width && (a >> (width - count)) & 1 != 0;
            (r, cf)
        }
        ShiftKind::Shr => {
            let r = if count >= width { 0 } else { a >> count };
            let cf = count <= width && (a >> (count - 1)) & 1 != 0;
            (r, cf)
        }
        ShiftKind::Sar => {
            let signed = sign_extend(a, size) as i64;
            let r = (signed >> count.min(63)) as u64 & mask;
            let cf = (signed >> (count - 1).min(63)) & 1 != 0;
            (r, cf)
        }
    };
    let mut f = zf_sf_pf(r, size);
    if cf {
        f |= flag::CF;
    }
    let of = match kind {
        ShiftKind::Shl => (r & sign_bit(size) != 0) != cf,
        ShiftKind::Shr => a & sign_bit(size) != 0,
        ShiftKind::Sar => false,
    };
    if of {
        f |= flag::OF;
    }
    Some((r, f))
}

/// Signed multiply truncated to `size`; the flag is CF = OF (the result did
/// not fit).
#[must_use]
pub fn imul(a: u64, b: u64, size: u8) -> (u64, bool) {
    let full = i128::from(sign_extend(a, size) as i64) * i128::from(sign_extend(b, size) as i64);
    let r = (full as u64) & size_mask(size);
    let overflow = i128::from(sign_extend(r, size) as i64) != full;
    (r, overflow)
}

/// Evaluates a condition code against `rflags`.
#[must_use]
pub fn condition(rflags: u64, cond: Condition) -> bool {
    let cf = rflags & flag::CF != 0;
    let zf = rflags & flag::ZF != 0;
    let sf = rflags & flag::SF != 0;
    let of = rflags & flag::OF != 0;
    let pf = rflags & flag::PF != 0;
    match cond {
        Condition::O => of,
        Condition::No => !of,
        Condition::B => cf,
        Condition::Ae => !cf,
        Condition::E => zf,
        Condition::Ne => !zf,
        Condition::Be => cf || zf,
        Condition::A => !cf && !zf,
        Condition::S => sf,
        Condition::Ns => !sf,
        Condition::P => pf,
        Condition::Np => !pf,
        Condition::L => sf != of,
        Condition::Ge => sf == of,
        Condition::Le => zf || sf != of,
        Condition::G => !zf && sf == of,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zf_sf_pf_looks_at_the_whole_operand() {
        // A zero low half does not make ZF: JavaScriptCore on x86-64 once
        // tested only the low 32 bits of the masked result.
        for value in [1 << 63, 1 << 62, 1 << 32] {
            assert_eq!(zf_sf_pf(value, 8) & flag::ZF, 0, "{value:#x}");
        }
        assert_eq!(zf_sf_pf(1 << 63, 8) & flag::SF, flag::SF);
        assert_eq!(zf_sf_pf(1 << 62, 8) & flag::SF, 0);
        // Bits above the operand size are ignored.
        assert_eq!(zf_sf_pf(0x1_0000_0000, 4), flag::ZF | flag::PF);
        assert_eq!(zf_sf_pf(0x8000_0000, 4) & flag::SF, flag::SF);
        assert_eq!(zf_sf_pf(0x1_0000, 2), flag::ZF | flag::PF);
        assert_eq!(zf_sf_pf(0x180, 1), flag::SF);
    }
    #[test]
    fn add_sets_carry_overflow_and_adjust() {
        // 0x7f + 1 (8-bit): signed overflow, AF, no carry.
        let (r, f) = add(0x7f, 1, false, 1);
        assert_eq!(r, 0x80);
        assert_eq!(f, flag::OF | flag::AF | flag::SF);
        // 0xff + 1: carry, zero, AF, PF.
        let (r, f) = add(0xff, 1, false, 1);
        assert_eq!(r, 0);
        assert_eq!(f, flag::CF | flag::ZF | flag::AF | flag::PF);
        // 64-bit with carry-in.
        let (r, f) = add(u64::MAX, 0, true, 8);
        assert_eq!(r, 0);
        assert!(f & flag::CF != 0);
    }

    #[test]
    fn sub_sets_borrow_and_overflow() {
        let (r, f) = sub(0, 1, false, 4);
        assert_eq!(r, 0xffff_ffff);
        assert_eq!(f & (flag::CF | flag::SF | flag::OF), flag::CF | flag::SF);
        let (r, f) = sub(0x8000_0000, 1, false, 4);
        assert_eq!(r, 0x7fff_ffff);
        assert!(f & flag::OF != 0);
        let (_, f) = sub(5, 5, false, 8);
        assert_eq!(f & (flag::ZF | flag::CF), flag::ZF);
    }

    #[test]
    fn shifts_follow_x86_semantics() {
        assert_eq!(shift(ShiftKind::Shl, 1, 0, 8), None);
        assert_eq!(shift(ShiftKind::Shl, 1, 64, 8), None); // masked to 0
        let (r, f) = shift(ShiftKind::Shl, 0x8000_0000, 1, 4).unwrap();
        assert_eq!(r, 0);
        assert_eq!(
            f & (flag::CF | flag::ZF | flag::OF),
            flag::CF | flag::ZF | flag::OF
        );
        let (r, f) = shift(ShiftKind::Shr, 0x81, 1, 1).unwrap();
        assert_eq!(r, 0x40);
        assert_eq!(f & (flag::CF | flag::OF), flag::CF | flag::OF);
        let (r, _) = shift(ShiftKind::Sar, 0x80, 3, 1).unwrap();
        assert_eq!(r, 0xf0);
        // 8-bit shift by 9: result 0.
        let (r, _) = shift(ShiftKind::Shr, 0xff, 9, 1).unwrap();
        assert_eq!(r, 0);
        let (r, _) = shift(ShiftKind::Sar, 0x8000, 31, 2).unwrap();
        assert_eq!(r, 0xffff);
    }

    #[test]
    fn imul_detects_overflow() {
        assert_eq!(imul(3, (-4i64) as u64, 8), ((-12i64) as u64, false));
        assert_eq!(imul(0x4000_0000, 4, 4), (0, true));
        assert_eq!(imul(u64::MAX, u64::MAX, 8), (1, false));
    }

    #[test]
    fn conditions_read_flags() {
        let f = flag::SF; // SF=1, OF=0 -> less
        assert!(condition(f, Condition::L));
        assert!(!condition(f, Condition::Ge));
        assert!(condition(flag::CF | flag::ZF, Condition::Be));
        assert!(!condition(flag::CF, Condition::A));
        assert!(condition(flag::PF, Condition::P));
        assert!(condition(0, Condition::G));
    }

    #[test]
    fn parity_counts_low_byte_only() {
        assert_eq!(zf_sf_pf(0x0300, 2) & flag::PF, flag::PF); // low byte 0
        assert_eq!(zf_sf_pf(0x01, 1) & flag::PF, 0);
        assert_eq!(sign_extend(0x80, 1), u64::MAX - 0x7f);
    }
}
