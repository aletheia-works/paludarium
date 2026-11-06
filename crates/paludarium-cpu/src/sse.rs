//! Portable legacy packed operations. No host SIMD or floating-point state.
use paludarium_decoder::Mnemonic as M;

fn mask(bits: u32) -> u128 {
    (1u128 << bits) - 1
}
fn signed(value: u128, bits: u32) -> i128 {
    ((value << (128 - bits)) as i128) >> (128 - bits)
}
fn lanes(a: u128, b: u128, bits: u32, mut operation: impl FnMut(u128, u128) -> u128) -> u128 {
    let mut out = 0;
    for n in 0..128 / bits {
        let shift = n * bits;
        out |=
            (operation((a >> shift) & mask(bits), (b >> shift) & mask(bits)) & mask(bits)) << shift;
    }
    out
}
fn saturate(value: i128, bits: u32) -> u128 {
    value.clamp(-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1) as u128 & mask(bits)
}
fn unpack(a: u128, b: u128, bits: u32, high: bool) -> u128 {
    let mut out = 0;
    let count = 64 / bits;
    let first = if high { count } else { 0 };
    for n in 0..count {
        out |= ((a >> ((first + n) * bits)) & mask(bits)) << (n * 2 * bits);
        out |= ((b >> ((first + n) * bits)) & mask(bits)) << ((n * 2 + 1) * bits);
    }
    out
}
fn pack(a: u128, b: u128, source: u32, destination: u32, unsigned: bool) -> u128 {
    let mut out = 0;
    let count = 128 / source;
    for n in 0..count * 2 {
        let input = if n < count { a } else { b };
        let lane = n % count;
        let value = signed((input >> (lane * source)) & mask(source), source);
        let value = if unsigned {
            value.clamp(0, mask(destination) as i128) as u128
        } else {
            saturate(value, destination)
        };
        out |= (value & mask(destination)) << (n * destination);
    }
    out
}

/// None means this is not a packed/bitwise operation in the assigned set.
pub(crate) fn packed(m: M, a: u128, b: u128, imm: u8, implicit: u128) -> Option<u128> {
    Some(match m {
        M::Pand | M::Andps | M::Andpd => a & b,
        M::Pandn | M::Andnpd | M::Andnps => (!a) & b,
        M::Por | M::Orps | M::Orpd => a | b,
        M::Pxor | M::Xorps | M::Xorpd => a ^ b,
        M::Paddb => lanes(a, b, 8, u128::wrapping_add),
        M::Paddw => lanes(a, b, 16, u128::wrapping_add),
        M::Paddd => lanes(a, b, 32, u128::wrapping_add),
        M::Paddq => lanes(a, b, 64, u128::wrapping_add),
        M::Psubb => lanes(a, b, 8, u128::wrapping_sub),
        M::Psubw => lanes(a, b, 16, u128::wrapping_sub),
        M::Psubd => lanes(a, b, 32, u128::wrapping_sub),
        M::Psubq => lanes(a, b, 64, u128::wrapping_sub),
        M::Paddusb => lanes(a, b, 8, |x, y| (x + y).min(255)),
        M::Paddusw => lanes(a, b, 16, |x, y| (x + y).min(65535)),
        M::Paddsb => lanes(a, b, 8, |x, y| saturate(signed(x, 8) + signed(y, 8), 8)),
        M::Paddsw => lanes(a, b, 16, |x, y| saturate(signed(x, 16) + signed(y, 16), 16)),
        M::Psubsb => lanes(a, b, 8, |x, y| saturate(signed(x, 8) - signed(y, 8), 8)),
        M::Psubsw => lanes(a, b, 16, |x, y| saturate(signed(x, 16) - signed(y, 16), 16)),
        M::Pavgb => lanes(a, b, 8, |x, y| (x + y + 1) >> 1),
        M::Pavgw => lanes(a, b, 16, |x, y| (x + y + 1) >> 1),
        M::Pminsw => lanes(a, b, 16, |x, y| signed(x, 16).min(signed(y, 16)) as u128),
        M::Pmaxsw => lanes(a, b, 16, |x, y| signed(x, 16).max(signed(y, 16)) as u128),
        M::Psubusb => lanes(a, b, 8, u128::saturating_sub),
        M::Psubusw => lanes(a, b, 16, u128::saturating_sub),
        M::Pcmpeqb => lanes(a, b, 8, |x, y| if x == y { 255 } else { 0 }),
        M::Pcmpeqw => lanes(a, b, 16, |x, y| if x == y { 65535 } else { 0 }),
        M::Pcmpeqd => lanes(a, b, 32, |x, y| if x == y { 0xffff_ffff } else { 0 }),
        M::Pcmpgtb => lanes(
            a,
            b,
            8,
            |x, y| if signed(x, 8) > signed(y, 8) { 255 } else { 0 },
        ),
        M::Pcmpgtw => lanes(a, b, 16, |x, y| {
            if signed(x, 16) > signed(y, 16) {
                65535
            } else {
                0
            }
        }),
        M::Pcmpgtd => lanes(a, b, 32, |x, y| {
            if signed(x, 32) > signed(y, 32) {
                0xffff_ffff
            } else {
                0
            }
        }),
        M::Pminub => lanes(a, b, 8, u128::min),
        M::Pmaxub => lanes(a, b, 8, u128::max),
        M::Packsswb => pack(a, b, 16, 8, false),
        M::Packssdw => pack(a, b, 32, 16, false),
        M::Packuswb => pack(a, b, 16, 8, true),
        M::Punpcklbw => unpack(a, b, 8, false),
        M::Punpckhbw => unpack(a, b, 8, true),
        M::Punpcklwd => unpack(a, b, 16, false),
        M::Punpckhwd => unpack(a, b, 16, true),
        M::Punpckldq => unpack(a, b, 32, false),
        M::Punpckhdq => unpack(a, b, 32, true),
        M::Punpcklqdq | M::Unpcklpd => unpack(a, b, 64, false),
        M::Punpckhqdq | M::Unpckhpd => unpack(a, b, 64, true),
        M::Unpcklps => unpack(a, b, 32, false),
        M::Unpckhps => unpack(a, b, 32, true),
        M::Pslldq => {
            if imm < 16 {
                a << (u32::from(imm) * 8)
            } else {
                0
            }
        }
        M::Psrldq => {
            if imm < 16 {
                a >> (u32::from(imm) * 8)
            } else {
                0
            }
        }
        M::Psllw | M::Pslld | M::Psllq | M::Psrlw | M::Psrld | M::Psrlq | M::Psraw | M::Psrad => {
            let bits = match m {
                M::Psllw | M::Psrlw | M::Psraw => 16,
                M::Pslld | M::Psrld | M::Psrad => 32,
                _ => 64,
            };
            let count = b as u64;
            lanes(a, 0, bits, |x, _| match m {
                M::Psraw | M::Psrad => (signed(x, bits) >> count.min(u64::from(bits - 1))) as u128,
                M::Psllw | M::Pslld | M::Psllq => {
                    if count < u64::from(bits) {
                        x << count
                    } else {
                        0
                    }
                }
                _ => {
                    if count < u64::from(bits) {
                        x >> count
                    } else {
                        0
                    }
                }
            })
        }
        M::Palignr => match imm {
            0 => b,
            1..=15 => (b >> (u32::from(imm) * 8)) | (a << (128 - u32::from(imm) * 8)),
            16 => a,
            17..=31 => a >> (u32::from(imm - 16) * 8),
            _ => 0,
        },
        M::Pshufb => {
            let input = a.to_le_bytes();
            let control = b.to_le_bytes();
            let mut out = [0; 16];
            for n in 0..16 {
                out[n] = if control[n] & 128 != 0 {
                    0
                } else {
                    input[usize::from(control[n] & 15)]
                };
            }
            u128::from_le_bytes(out)
        }
        M::Pshufd => {
            let mut out = 0;
            for n in 0..4 {
                out |= ((b >> (u32::from((imm >> (n * 2)) & 3) * 32)) & mask(32)) << (n * 32);
            }
            out
        }
        M::Pshuflw | M::Pshufhw => {
            let high = m == M::Pshufhw;
            let offset = if high { 64 } else { 0 };
            let mut out = b & !(u128::from(u64::MAX) << offset);
            for n in 0..4 {
                out |= ((b >> (offset + u32::from((imm >> (n * 2)) & 3) * 16)) & mask(16))
                    << (offset + n * 16);
            }
            out
        }
        M::Shufpd => {
            ((a >> (u32::from(imm & 1) * 64)) & mask(64))
                | (((b >> (u32::from((imm >> 1) & 1) * 64)) & mask(64)) << 64)
        }
        M::Shufps => {
            let mut out = 0;
            for n in 0..4 {
                let source = if n < 2 { a } else { b };
                out |= ((source >> (u32::from((imm >> (n * 2)) & 3) * 32)) & mask(32)) << (n * 32);
            }
            out
        }
        M::Pblendw => lanes(a, b, 16, {
            let mut n = 0;
            move |x, y| {
                let value = if imm & (1 << n) != 0 { y } else { x };
                n += 1;
                value
            }
        }),
        M::Blendvps => lanes(a, b, 32, {
            let mut n = 0;
            move |x, y| {
                let value = if (implicit >> (n * 32 + 31)) & 1 != 0 {
                    y
                } else {
                    x
                };
                n += 1;
                value
            }
        }),
        M::Pmullw => lanes(a, b, 16, u128::wrapping_mul),
        M::Pmulhuw => lanes(a, b, 16, |x, y| (x * y) >> 16),
        M::Pmulhw => lanes(a, b, 16, |x, y| {
            ((signed(x, 16) * signed(y, 16)) >> 16) as u128
        }),
        M::Pmuludq => {
            let low = (a & mask(32)) * (b & mask(32));
            let high = ((a >> 64) & mask(32)) * ((b >> 64) & mask(32));
            low | (high << 64)
        }
        M::Pmaddwd | M::Pmaddubsw => {
            let bits = if m == M::Pmaddwd { 16 } else { 8 };
            let mut out = 0;
            for n in 0..128 / (bits * 2) {
                let mut sum = 0i128;
                for k in 0..2 {
                    let shift = (n * 2 + k) * bits;
                    let x = (a >> shift) & mask(bits);
                    let y = (b >> shift) & mask(bits);
                    sum += if bits == 8 {
                        x as i128 * signed(y, 8)
                    } else {
                        signed(x, 16) * signed(y, 16)
                    };
                }
                let value = if bits == 8 {
                    saturate(sum, 16)
                } else {
                    sum as u128 & mask(32)
                };
                out |= value << (n * bits * 2);
            }
            out
        }
        M::Psadbw => {
            let a = a.to_le_bytes();
            let b = b.to_le_bytes();
            let mut out = 0;
            for group in 0..2 {
                let mut sum = 0u128;
                for n in group * 8..group * 8 + 8 {
                    sum += u128::from(a[n].abs_diff(b[n]));
                }
                out |= sum << (group * 64);
            }
            out
        }
        M::Pmovzxdq => (b & mask(32)) | (((b >> 32) & mask(32)) << 64),
        _ => return None,
    })
}
