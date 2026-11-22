#![no_main]
//! BPF socket filters: programs built from the input, loaded with
//! `BPF_PROG_LOAD`, and those the verifier takes attached to an AF_UNIX
//! datagram socket and run on a message; or classic programs attached with
//! `SO_ATTACH_FILTER`, which the kernel checks and converts to eBPF. The
//! kernel's `fuzzing` feature makes a load or store of a verified or
//! converted program outside what it points to panic, so this checks that
//! the checks, the conversion and the interpreter agree. A message is
//! short, or 20,000 bytes, most of them in pages.
use libfuzzer_sys::fuzz_target;
use paludarium_cpu::{CpuState, reg};
use paludarium_kernel::{Kernel, Thread};
use paludarium_mmu::{AddressSpace, MappingKind, Prot};
use paludarium_types::{ExitReason, GuestAddr};
use std::sync::Arc;

const MEMORY: u64 = 0x600000;
const ATTR: u64 = MEMORY;
const LICENSE: u64 = MEMORY + 0x200;
const PAIR: u64 = MEMORY + 0x300;
const OPTION: u64 = MEMORY + 0x308;
const KEY: u64 = MEMORY + 0x310;
const VALUE: u64 = MEMORY + 0x320;
const INSNS: u64 = MEMORY + 0x1000;
const LENGTH: u64 = MEMORY + 0x330;
const PACKET: u64 = MEMORY + 0x2000;
/// A datagram longer than an skb's linear part, which the packet starts.
const LARGE: usize = 20_000;
const MAPPED: u64 = 0x2000 + 0x5000;
const MAX_INSNS: usize = 128;

fn call(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, n: u64, args: [u64; 6]) -> u64 {
    t.cpu.gpr[reg::RAX] = n;
    for (r, v) in [reg::RDI, reg::RSI, reg::RDX, reg::R10, reg::R8, reg::R9]
        .into_iter()
        .zip(args)
    {
        t.cpu.gpr[r] = v;
    }
    let _ = k.handle(
        t,
        m,
        ExitReason::Syscall {
            rip: GuestAddr(0x400000),
        },
    );
    t.cpu.gpr[reg::RAX]
}

fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut b = [0; 8];
    b[0] = code;
    b[1] = (dst & 15) | (src & 15) << 4;
    b[2..4].copy_from_slice(&off.to_le_bytes());
    b[4..].copy_from_slice(&imm.to_le_bytes());
    b
}

/// A map's descriptor: `bpf(BPF_MAP_CREATE)` of 4-byte keys and 16-byte
/// values.
fn map(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, kind: u32) -> Option<i32> {
    let mut attr = [0u8; 72];
    for (i, v) in [kind, 4, 16, 4].into_iter().enumerate() {
        attr[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    m.write(GuestAddr(ATTR), &attr).ok()?;
    let fd = call(k, t, m, 321, [0, ATTR, 72, 0, 0, 0]) as i64;
    i32::try_from(fd).ok().filter(|fd| *fd >= 0)
}

/// The instructions of `data`, four bytes each: a kind and three bytes of
/// registers, offset and value, near what the verifier takes, so that
/// many of them load.
fn program(data: &[u8], maps: [i32; 2]) -> Vec<[u8; 8]> {
    const EDGES: [i32; 12] = [0, 1, -1, 7, 8, 16, 31, 32, 63, 64, i32::MIN, i32::MAX];
    let mut insns = vec![insn(0xbf, 6, 1, 0, 0)];
    for c in data.as_chunks::<4>().0 {
        if insns.len() + 3 > MAX_INSNS {
            break;
        }
        let (dst, src) = (c[1] % 11, (c[1] >> 4) % 11);
        let imm = if c[3] & 0x80 != 0 {
            EDGES[usize::from(c[3]) % EDGES.len()]
        } else {
            i32::from(c[3] as i8) * i32::from(c[2])
        };
        let size = [0x18, 0x00, 0x08, 0x10][usize::from(c[2] & 3)];
        let off = -8 * i16::from(c[2] >> 2 & 63) - i16::from(c[3] & 7);
        let alu = (c[2] >> 4) << 4;
        let next = match c[0] % 16 {
            0 => insn(0xb7, dst, 0, 0, imm),
            1 => insn(0x07 | alu, dst, 0, i16::from(c[3] & 1), imm),
            2 => insn(0x04 | alu, dst, 0, i16::from(c[3] & 1), imm),
            3 => insn(0x0f | alu, dst, src, i16::from(c[3] & 1), 0),
            4 => insn(0x0c | alu, dst, src, 0, 0),
            5 => insn(0x63 | size, 10, src, off, 0),
            6 => insn(0x61 | size, dst, 10, off, 0),
            7 => insn(0x62 | size, 10, 0, off, imm),
            8 => insn(0x61 | size, dst, src, i16::from(c[3] as i8), 0),
            9 => insn(0x63 | size, dst, src, i16::from(c[3] as i8), 0),
            10 => insn(0x05 | alu, dst, 0, i16::from(c[3] & 7), imm),
            11 => insn(0x0d | alu, dst, src, i16::from(c[3] & 7), 0),
            12 => insn(
                0x85,
                0,
                0,
                0,
                [1, 2, 3, 5, 7, 8, 14, 15, 26, 46, 47, 68][usize::from(c[2]) % 12],
            ),
            13 => {
                // A map, or a value of the array at an offset.
                let pseudo = 1 + (c[2] & 1);
                insns.push(insn(0x18, dst, pseudo, 0, maps[usize::from(c[3] & 1)]));
                insn(0, 0, 0, 0, i32::from(c[3] >> 1 & 31))
            }
            14 => insn(
                0xd4 | (c[2] & 8),
                dst,
                0,
                0,
                [16, 32, 64][usize::from(c[3]) % 3],
            ),
            _ => insn(0xbf, dst, if c[3] & 1 == 0 { 10 } else { 6 }, 0, 0),
        };
        insns.push(next);
    }
    insns.push(insn(0xb7, 0, 0, 0, 64));
    insns.push(insn(0x95, 0, 0, 0, 0));
    insns
}

/// The codes Linux's `chk_code_allowed` takes: the ALU operations with K
/// and X, neg, the loads, the stores, tax and txa, the returns, and the
/// jumps.
const CLASSIC_CODES: [u16; 49] = [
    0x04, 0x0c, 0x14, 0x1c, 0x24, 0x2c, 0x34, 0x3c, 0x94, 0x9c, 0x54, 0x5c, 0x44, 0x4c, 0xa4, 0xac,
    0x64, 0x6c, 0x74, 0x7c, 0x84, 0x20, 0x28, 0x30, 0x80, 0x40, 0x48, 0x50, 0x00, 0x60, 0x81, 0xb1,
    0x01, 0x61, 0x02, 0x03, 0x07, 0x87, 0x06, 0x16, 0x05, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d, 0x45,
    0x4d,
];

/// A classic program of `data`, four bytes each: a code, the jumps'
/// offsets, and a value near an edge (the scratch words, shift counts,
/// `SKF_AD_OFF` and its ancillary loads, `SKF_NET_OFF`, `SKF_LL_OFF`),
/// ending in a return.
fn classic(data: &[u8]) -> Vec<[u8; 8]> {
    const EDGES: [u32; 12] = [
        0,
        1,
        3,
        15,
        16,
        31,
        32,
        0x7fff_ffff,
        0x8000_0000,
        0xfff0_0000,
        0xffe0_0000,
        u32::MAX,
    ];
    let mut insns = Vec::new();
    for c in data.as_chunks::<4>().0 {
        if insns.len() + 1 >= MAX_INSNS {
            break;
        }
        let code = CLASSIC_CODES[usize::from(c[0]) % CLASSIC_CODES.len()];
        let k = match c[3] >> 6 {
            0 => EDGES[usize::from(c[3]) % EDGES.len()],
            1 => 0xffff_f000 + u32::from(c[2] % 17) * 4,
            2 => u32::from(c[2]) + 256 * u32::from(c[3] & 0x3f),
            _ => (i32::from(c[2] as i8) * 64) as u32,
        };
        let mut b = [0; 8];
        b[..2].copy_from_slice(&code.to_le_bytes());
        b[2] = c[1] & 7;
        b[3] = c[1] >> 4 & 7;
        b[4..].copy_from_slice(&k.to_le_bytes());
        insns.push(b);
    }
    // ret a, or ret k of all.
    let last = data.last().copied().unwrap_or(0);
    insns.push(if last & 1 == 0 {
        [0x16, 0, 0, 0, 0, 0, 0, 0]
    } else {
        [6, 0, 0, 0, 0xff, 0xff, 0, 0]
    });
    insns
}

fuzz_target!(|data: &[u8]| {
    let m = AddressSpace::new();
    if m.map_shared(
        Some(GuestAddr(MEMORY)),
        MAPPED,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .is_err()
    {
        return;
    }
    let mut k = Kernel::new(Arc::new(paludarium_host::NativeHost));
    let mut t = Thread::new(1, CpuState::default());
    let (Some(array), Some(hash)) = (map(&mut k, &mut t, &m, 2), map(&mut k, &mut t, &m, 1)) else {
        return;
    };
    // The hash holds a value at key 0, so a lookup can find one.
    let _ = m.write(GuestAddr(KEY), &[0; 4]);
    let _ = m.write(GuestAddr(VALUE), &[0x5a; 16]);
    let mut update = [0u8; 32];
    update[..4].copy_from_slice(&(hash as u32).to_le_bytes());
    update[8..16].copy_from_slice(&KEY.to_le_bytes());
    update[16..24].copy_from_slice(&VALUE.to_le_bytes());
    let _ = m.write(GuestAddr(ATTR), &update);
    call(&mut k, &mut t, &m, 321, [2, ATTR, 32, 0, 0, 0]);

    // The first byte: the packet's length, whether the program is
    // classic, and whether the message is large.
    let first = data.first().copied().unwrap_or(0);
    let (packet, code) = data.split_at(usize::from(first % 65).min(data.len()));
    let is_classic = first & 0x40 != 0;
    let length = if first & 0x80 != 0 {
        LARGE
    } else {
        packet.len()
    };
    let insns = if is_classic {
        classic(code)
    } else {
        program(code, [hash, array])
    };
    let bytes: Vec<u8> = insns.iter().flatten().copied().collect();
    if m.write(GuestAddr(INSNS), &bytes).is_err() || m.write(GuestAddr(PACKET), packet).is_err() {
        return;
    }
    let prog = if is_classic {
        0
    } else {
        let mut attr = [0u8; 168];
        attr[..4].copy_from_slice(&1u32.to_le_bytes());
        attr[4..8].copy_from_slice(&(insns.len() as u32).to_le_bytes());
        attr[8..16].copy_from_slice(&INSNS.to_le_bytes());
        attr[16..24].copy_from_slice(&LICENSE.to_le_bytes());
        if m.write(GuestAddr(LICENSE), b"GPL\0").is_err()
            || m.write(GuestAddr(ATTR), &attr).is_err()
        {
            return;
        }
        let prog = call(&mut k, &mut t, &m, 321, [5, ATTR, 168, 0, 0, 0]) as i64;
        if prog < 0 {
            return;
        }
        prog
    };
    // socketpair(AF_UNIX, SOCK_DGRAM), the filter on the second end, and a
    // message through it.
    if call(&mut k, &mut t, &m, 53, [1, 2, 0, PAIR, 0, 0]) != 0 {
        return;
    }
    let mut fds = [0u8; 8];
    if m.read(GuestAddr(PAIR), &mut fds).is_err() {
        return;
    }
    let a = u64::from(u32::from_le_bytes(fds[..4].try_into().unwrap()));
    let b = u64::from(u32::from_le_bytes(fds[4..].try_into().unwrap()));
    if is_classic {
        // SO_ATTACH_FILTER with a struct sock_fprog; one the checks refuse
        // goes no further. SO_GET_FILTER then gives it back.
        let mut fprog = [0u8; 16];
        fprog[..2].copy_from_slice(&(insns.len() as u16).to_le_bytes());
        fprog[8..].copy_from_slice(&INSNS.to_le_bytes());
        let _ = m.write(GuestAddr(ATTR), &fprog);
        if call(&mut k, &mut t, &m, 54, [b, 1, 26, ATTR, 16, 0]) != 0 {
            return;
        }
        let _ = m.write(GuestAddr(LENGTH), &(MAX_INSNS as u32).to_le_bytes());
        call(&mut k, &mut t, &m, 55, [b, 1, 26, INSNS, LENGTH, 0]);
    } else {
        let _ = m.write(GuestAddr(OPTION), &(prog as u32).to_le_bytes());
        call(&mut k, &mut t, &m, 54, [b, 1, 50, OPTION, 4, 0]);
    }
    for _ in 0..2 {
        // sendto and recvfrom with MSG_DONTWAIT.
        call(
            &mut k,
            &mut t,
            &m,
            44,
            [a, PACKET, length as u64, 0x40, 0, 0],
        );
        call(&mut k, &mut t, &m, 45, [b, PACKET, 64, 0x40, 0, 0]);
    }
});
