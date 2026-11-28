//! The kernel's number parsers of `lib/kstrtox.c`, as the files of
//! `/proc/<pid>` read what is written to them and the tmpfs and BPF file
//! systems read their mount options: the whole string, which ends
//! at its first NUL, in the base given or, for base 0, the one its prefix
//! gives (`0x` for 16, `0` for 8, else 10), with one newline allowed at its
//! end; `EINVAL` for anything else and `ERANGE` for a number past the type.
use paludarium_types::Errno;

/// The string as C reads it, up to its first NUL.
fn c_string(s: &[u8]) -> &[u8] {
    s.iter().position(|&b| b == 0).map_or(s, |end| &s[..end])
}
/// The kernel's `isspace`, which takes the Latin-1 no-break space too.
fn space(b: u8) -> bool {
    matches!(b, b' ' | b'\t'..=b'\r' | 0xa0)
}
/// `strstrip`: the string without the spaces at either end.
pub(crate) fn strstrip(s: &[u8]) -> &[u8] {
    let s = c_string(s);
    let end = s.iter().rposition(|&b| !space(b)).map_or(0, |at| at + 1);
    let start = s[..end].iter().position(|&b| !space(b)).unwrap_or(end);
    &s[start..end]
}
/// `_kstrtoull`: no sign.
fn unsigned(s: &[u8], base: u64) -> Result<u64, Errno> {
    // `_parse_integer_fixup_radix`.
    let hex =
        |s: &[u8]| s.first() == Some(&b'0') && s.get(1).map(u8::to_ascii_lowercase) == Some(b'x');
    let base = match base {
        0 if hex(s) && s.get(2).is_some_and(u8::is_ascii_hexdigit) => 16,
        0 if s.first() == Some(&b'0') => 8,
        0 => 10,
        base => base,
    };
    let s = if base == 16 && hex(s) { &s[2..] } else { s };
    // `_parse_integer`.
    let mut value: u64 = 0;
    let mut overflow = false;
    let mut count = 0;
    for &b in s {
        let digit = match b {
            b'0'..=b'9' => u64::from(b - b'0'),
            b'a'..=b'f' | b'A'..=b'F' => u64::from(b.to_ascii_lowercase() - b'a') + 10,
            _ => break,
        };
        if digit >= base {
            break;
        }
        match value.checked_mul(base).and_then(|v| v.checked_add(digit)) {
            Some(v) => value = v,
            None => {
                overflow = true;
                value = value.wrapping_mul(base).wrapping_add(digit);
            }
        }
        count += 1;
    }
    if overflow {
        return Err(Errno::ERANGE);
    }
    let rest = &s[count..];
    if count == 0 || !(rest.is_empty() || rest == b"\n") {
        return Err(Errno::EINVAL);
    }
    Ok(value)
}
/// `kstrtoull`: a `+` allowed before the number.
pub(crate) fn ull(s: &[u8], base: u64) -> Result<u64, Errno> {
    let s = c_string(s);
    unsigned(s.strip_prefix(b"+").unwrap_or(s), base)
}
/// `kstrtoll`: a `+` or a `-` before the number.
pub(crate) fn ll(s: &[u8], base: u64) -> Result<i64, Errno> {
    let s = c_string(s);
    if let Some(digits) = s.strip_prefix(b"-") {
        let value = unsigned(digits, base)?;
        // `(long long)-tmp > 0` is ERANGE.
        let negated = value.wrapping_neg() as i64;
        if negated > 0 {
            return Err(Errno::ERANGE);
        }
        return Ok(negated);
    }
    i64::try_from(ull(s, base)?).map_err(|_| Errno::ERANGE)
}
/// `kstrtoint`.
pub(crate) fn int(s: &[u8], base: u64) -> Result<i32, Errno> {
    i32::try_from(ll(s, base)?).map_err(|_| Errno::ERANGE)
}
/// `kstrtouint`.
pub(crate) fn uint(s: &[u8], base: u64) -> Result<u32, Errno> {
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
    fn strstrip_takes_the_spaces_off_both_ends() {
        assert_eq!(strstrip(b"  -5 \n"), b"-5");
        assert_eq!(strstrip(b"\xa05\xa0"), b"5");
        assert_eq!(strstrip(b" \n"), b"");
        assert_eq!(strstrip(b"1 \0 2"), b"1");
    }
}
