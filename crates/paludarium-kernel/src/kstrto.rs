//! Numbers written to the kernel's files, read as its `kstrto*` functions
//! are documented to read them, and as the tmpfs and BPF file systems read
//! their mount options:
//! - The string ends at its first NUL, and the whole of it is the number.
//!   One newline may follow the number; nothing else may, and no space may
//!   come before it (callers that allow spaces strip them first, with
//!   [`strstrip`]).
//! - An unsigned number may start with `+`; a signed one with `+` or `-`.
//! - Base 0 takes the base from the number's prefix: `0x` or `0X` followed
//!   by a hex digit is hexadecimal, another leading `0` octal, anything else
//!   decimal. Base 16 lets a `0x` prefix stand before the digits.
//! - Digits past 64 bits are `ERANGE`, whatever follows them; any other
//!   string that is not a number is `EINVAL`; and a number that does not
//!   fit a narrower type is `ERANGE`.
use paludarium_types::Errno;

/// What C reads of the string: the bytes before its first NUL.
fn c_string(s: &[u8]) -> &[u8] {
    s.split(|&b| b == 0).next().unwrap_or(s)
}
/// A space as the kernel's `isspace` counts it: the C spaces and the
/// Latin-1 no-break space.
fn space(b: u8) -> bool {
    matches!(b, b' ' | b'\t'..=b'\r' | 0xa0)
}
/// `strstrip`: the string without the spaces at either end.
pub(crate) fn strstrip(s: &[u8]) -> &[u8] {
    let s = c_string(s);
    let start = s.iter().take_while(|&&b| space(b)).count();
    let s = &s[start..];
    let kept = s.len() - s.iter().rev().take_while(|&&b| space(b)).count();
    &s[..kept]
}

/// The base the digits of `s` are in, and the digits with any prefix that
/// names the base taken off.
fn base_and_digits(s: &[u8], base: u32) -> (u32, &[u8]) {
    let after_0x = match s {
        [b'0', b'x' | b'X', rest @ ..] => Some(rest),
        _ => None,
    };
    match (base, after_0x) {
        (0, Some(rest)) if rest.first().is_some_and(u8::is_ascii_hexdigit) => (16, rest),
        (0, _) if s.first() == Some(&b'0') => (8, s),
        (0, _) => (10, s),
        (16, Some(rest)) => (16, rest),
        (base, _) => (base, s),
    }
}

/// The value of a number without a sign, in base `base` (0, 8, 10 or 16).
fn magnitude(s: &[u8], base: u32) -> Result<u64, Errno> {
    debug_assert!(base == 0 || (2..=16).contains(&base));
    let (base, digits) = base_and_digits(s, base);
    let digit = |b: &u8| char::from(*b).to_digit(base);
    let count = digits.iter().take_while(|b| digit(b).is_some()).count();
    if count == 0 {
        return Err(Errno::EINVAL);
    }
    let value = digits[..count]
        .iter()
        .try_fold(0u64, |value, b| {
            value
                .checked_mul(u64::from(base))?
                .checked_add(u64::from(digit(b)?))
        })
        .ok_or(Errno::ERANGE)?;
    match &digits[count..] {
        [] | [b'\n'] => Ok(value),
        _ => Err(Errno::EINVAL),
    }
}

/// `kstrtoull`: an unsigned 64-bit number, a `+` allowed before it.
pub(crate) fn ull(s: &[u8], base: u32) -> Result<u64, Errno> {
    let s = c_string(s);
    magnitude(s.strip_prefix(b"+").unwrap_or(s), base)
}
/// `kstrtoll`: a signed 64-bit number, a `+` or a `-` allowed before it.
pub(crate) fn ll(s: &[u8], base: u32) -> Result<i64, Errno> {
    let s = c_string(s);
    match s.strip_prefix(b"-") {
        Some(digits) => 0i64
            .checked_sub_unsigned(magnitude(digits, base)?)
            .ok_or(Errno::ERANGE),
        None => i64::try_from(ull(s, base)?).map_err(|_| Errno::ERANGE),
    }
}
/// `kstrtoint`: a signed 32-bit number.
pub(crate) fn int(s: &[u8], base: u32) -> Result<i32, Errno> {
    i32::try_from(ll(s, base)?).map_err(|_| Errno::ERANGE)
}
/// `kstrtouint`: an unsigned 32-bit number.
pub(crate) fn uint(s: &[u8], base: u32) -> Result<u32, Errno> {
    u32::try_from(ull(s, base)?).map_err(|_| Errno::ERANGE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_number_is_read_whole_in_the_base_its_prefix_gives() {
        assert_eq!(int(b"-1000", 0), Ok(-1000));
        assert_eq!(int(b"+15\n", 0), Ok(15));
        assert_eq!(int(b"0x1f", 0), Ok(31));
        assert_eq!(int(b"010", 0), Ok(8));
        assert_eq!(int(b"0", 0), Ok(0));
        assert_eq!(uint(b"0X33", 0), Ok(0x33));
        // `0x` with no hex digit after it is octal 0, and the `x` is left.
        assert_eq!(uint(b"0x", 0), Err(Errno::EINVAL));
        assert_eq!(uint(b"08", 0), Err(Errno::EINVAL));
        assert_eq!(int(b"5\n\n", 0), Err(Errno::EINVAL));
        assert_eq!(int(b"", 0), Err(Errno::EINVAL));
        assert_eq!(int(b"-", 0), Err(Errno::EINVAL));
        assert_eq!(int(b"-+5", 0), Err(Errno::EINVAL));
        assert_eq!(int(b" 5", 0), Err(Errno::EINVAL));
        // The string ends at a NUL.
        assert_eq!(int(b"7\0junk", 0), Ok(7));
    }

    #[test]
    fn a_number_past_its_type_is_erange() {
        assert_eq!(int(b"2147483648", 0), Err(Errno::ERANGE));
        assert_eq!(int(b"-2147483648", 0), Ok(i32::MIN));
        assert_eq!(int(b"-2147483649", 0), Err(Errno::ERANGE));
        assert_eq!(uint(b"4294967296", 0), Err(Errno::ERANGE));
        assert_eq!(uint(b"-1", 0), Err(Errno::EINVAL));
        // Past 64 bits is ERANGE before the rest of the string is looked at.
        assert_eq!(ull(b"99999999999999999999x", 0), Err(Errno::ERANGE));
        assert_eq!(ll(b"-9223372036854775808", 0), Ok(i64::MIN));
        assert_eq!(ll(b"-9223372036854775809", 0), Err(Errno::ERANGE));
    }

    #[test]
    fn a_base_given_reads_only_its_digits() {
        // Octal, as `mode=` takes it.
        assert_eq!(uint(b"0750", 8), Ok(0o750));
        assert_eq!(uint(b"+17\n", 8), Ok(0o17));
        assert_eq!(uint(b"8", 8), Err(Errno::EINVAL));
        assert_eq!(uint(b"", 8), Err(Errno::EINVAL));
        // Base 16 takes a `0x` prefix too.
        assert_eq!(uint(b"0x10", 16), Ok(16));
        assert_eq!(uint(b"10", 16), Ok(16));
        assert_eq!(ull(b"017\n", 0), Ok(15));
        assert_eq!(ull(b"12x", 0), Err(Errno::EINVAL));
        assert_eq!(ull(b"0x10000000000000000", 0), Err(Errno::ERANGE));
        // Past 64 bits in a base given is ERANGE before a digit of no base.
        assert_eq!(ull(b"7777777777777777777777779", 8), Err(Errno::ERANGE));
    }

    #[test]
    fn the_prefix_names_the_base_only_for_base_0() {
        assert_eq!(ull(b"0x1F", 0), Ok(31));
        assert_eq!(ull(b"0XfF", 0), Ok(255));
        assert_eq!(ull(b"0777", 0), Ok(0o777));
        assert_eq!(ull(b"00", 0), Ok(0));
        assert_eq!(ull(b"909", 0), Ok(909));
        // A base given is kept: a leading 0 is a digit, `0x` is no prefix.
        assert_eq!(ull(b"0777", 10), Ok(777));
        assert_eq!(ull(b"0x10", 10), Err(Errno::EINVAL));
        assert_eq!(ull(b"0x10", 8), Err(Errno::EINVAL));
        // `0x` names base 16 only when a hex digit follows it.
        assert_eq!(ull(b"0xg", 0), Err(Errno::EINVAL));
        assert_eq!(ull(b"0x", 16), Err(Errno::EINVAL));
        assert_eq!(ull(b"ff", 16), Ok(255));
        assert_eq!(ull(b"0xff", 16), Ok(255));
    }

    #[test]
    fn a_sign_is_one_character_before_the_number() {
        assert_eq!(ull(b"+0x10", 0), Ok(16));
        assert_eq!(ull(b"-1", 0), Err(Errno::EINVAL));
        assert_eq!(ull(b"++1", 0), Err(Errno::EINVAL));
        assert_eq!(ll(b"+7", 0), Ok(7));
        assert_eq!(ll(b"-0x10", 0), Ok(-16));
        assert_eq!(ll(b"-0", 0), Ok(0));
        assert_eq!(ll(b"--1", 0), Err(Errno::EINVAL));
        assert_eq!(ll(b"+-1", 0), Err(Errno::EINVAL));
        assert_eq!(int(b"- 1", 0), Err(Errno::EINVAL));
    }

    #[test]
    fn one_newline_may_end_the_number_and_nothing_else() {
        assert_eq!(ull(b"42\n", 10), Ok(42));
        assert_eq!(ull(b"42\n\0junk", 10), Ok(42));
        assert_eq!(ull(b"\n", 10), Err(Errno::EINVAL));
        assert_eq!(ull(b"42 ", 10), Err(Errno::EINVAL));
        assert_eq!(ull(b"42\r\n", 10), Err(Errno::EINVAL));
        assert_eq!(ull(b"4 2", 10), Err(Errno::EINVAL));
        assert_eq!(ull(b"\0", 10), Err(Errno::EINVAL));
    }

    #[test]
    fn each_type_has_its_own_range() {
        assert_eq!(ull(b"18446744073709551615", 0), Ok(u64::MAX));
        assert_eq!(ull(b"18446744073709551616", 0), Err(Errno::ERANGE));
        assert_eq!(ull(b"0xffffffffffffffff", 0), Ok(u64::MAX));
        assert_eq!(ull(b"01777777777777777777777", 0), Ok(u64::MAX));
        assert_eq!(ull(b"02000000000000000000000", 0), Err(Errno::ERANGE));
        assert_eq!(ll(b"9223372036854775807", 0), Ok(i64::MAX));
        assert_eq!(ll(b"9223372036854775808", 0), Err(Errno::ERANGE));
        assert_eq!(ll(b"-18446744073709551615", 0), Err(Errno::ERANGE));
        assert_eq!(int(b"2147483647", 0), Ok(i32::MAX));
        assert_eq!(int(b"-0x80000000", 0), Ok(i32::MIN));
        assert_eq!(uint(b"4294967295", 0), Ok(u32::MAX));
        assert_eq!(uint(b"0x100000000", 0), Err(Errno::ERANGE));
        // Past 64 bits is ERANGE even when junk follows; junk after a
        // number that fits 64 bits is EINVAL, whatever the type.
        assert_eq!(ull(b"18446744073709551616x", 0), Err(Errno::ERANGE));
        assert_eq!(uint(b"4294967296x", 0), Err(Errno::EINVAL));
        assert_eq!(uint(b"4294967295x", 0), Err(Errno::EINVAL));
        // Leading zeros take no room.
        assert_eq!(ull(b"00000000000000000000000000001", 10), Ok(1));
    }

    #[test]
    fn strstrip_takes_the_spaces_off_both_ends() {
        assert_eq!(strstrip(b"  -5 \n"), b"-5");
        assert_eq!(strstrip(b"\xa05\xa0"), b"5");
        assert_eq!(strstrip(b" \n"), b"");
        assert_eq!(strstrip(b"1 \0 2"), b"1");
    }
}
