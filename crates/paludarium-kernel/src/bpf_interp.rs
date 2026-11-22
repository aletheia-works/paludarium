//! The interpreter of verified BPF programs, as Linux's `___bpf_prog_run`
//! (`kernel/bpf/core.c`) runs them after the verifier's rewrites
//! (`do_misc_fixups` in `kernel/bpf/verifier.c`), for socket filters: the
//! instructions [`crate::bpf_verifier`] takes, the context (`struct
//! __sk_buff`) of a packet, the stack and the values of maps.
//!
//! Registers hold numbers. A pointer is a number too, an address in a space
//! of the interpreter's own: a region (the stack, the context, a map, or a
//! value a lookup gave) in the upper bits and the offset in it in the lower
//! 32, with the top byte set, as a kernel address has it. The verifier
//! lets a program move a pointer only by constants, so an address keeps its
//! region; a load or store is checked against its region all the same, and
//! one outside it stops the program ([`Fault`]), which the verifier should
//! make impossible. [`crate::bpf_prog::Program::run`] panics on one in a
//! debug build and with the `fuzzing` feature, so the unit test
//! `programs_the_verifier_takes_never_fault` and the `kernel_bpf` fuzz
//! target check the verifier and the interpreter together.
//!
//! What Linux's rewrites decide, the interpreter does as they do:
//! - a division by a register that is 0 gives 0, and a remainder by one
//!   keeps the dividend (its lower half, zero-extended, in 32 bits);
//! - a signed division by -1 negates, and a signed remainder by -1 is 0,
//!   for a register and an immediate alike;
//! - a shift by a register takes its count modulo the width.
//!
//! The context's fields that a socket filter may read are those of an
//! AF_UNIX datagram's `sk_buff`: its length, and 0 for the rest, which such
//! a packet does not set; `cb[]` starts at 0 (`bpf_prog_run_save_cb`).
//!
//! It runs classic filters too, as [`crate::bpf_classic`] converts them,
//! which read what the verifier keeps from eBPF programs: the packet's
//! linear part, the fields after the context ([`classic::field`]), and
//! Linux's internal helpers ([`classic`]).
use std::collections::BTreeMap;
use std::sync::Arc;

use paludarium_types::Errno;

use crate::bpf::{Map, ValueRef};
use crate::bpf_verifier::Insn;

/// `sizeof(struct __sk_buff)`.
pub(crate) const CONTEXT_SIZE: usize = 192;
/// The context with the `sk_buff` fields after it that only converted
/// classic programs read.
const CONTEXT_WITH_TAIL: usize = CONTEXT_SIZE + 24;
/// `offsetof(struct __sk_buff, cb)` and its end.
const CB: std::ops::Range<usize> = 48..68;
/// `MAX_BPF_STACK`.
const STACK_SIZE: usize = 512;

/// The top byte of every address, as a kernel pointer has it set.
const SPACE: u64 = 0xff00_0000_0000_0000;
/// The regions below the maps': the stack and the context.
const STACK: u64 = 0;
const CONTEXT: u64 = 1;
/// The maps a program uses, from this region on, one each.
const MAPS: u64 = 2;
/// The values the program reached, from this region on.
const VALUES: u64 = MAPS + 64;
/// The regions an address can name: the bits between the top byte and the
/// offset.
const REGIONS: u64 = 1 << 24;
/// The packet's linear part (`skb->data`), the last region, which only
/// converted classic programs read.
const PACKET: u64 = REGIONS - 1;

const fn address(region: u64, offset: u64) -> u64 {
    SPACE | region << 32 | offset
}

/// A load or store outside what the verifier let the program reach: the
/// program stops, and the packet is dropped.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Fault;

/// The helpers' numbers (`enum bpf_func_id`).
mod func {
    pub const MAP_LOOKUP_ELEM: i32 = 1;
    pub const MAP_UPDATE_ELEM: i32 = 2;
    pub const MAP_DELETE_ELEM: i32 = 3;
    pub const KTIME_GET_NS: i32 = 5;
    pub const GET_PRANDOM_U32: i32 = 7;
    pub const GET_SMP_PROCESSOR_ID: i32 = 8;
    pub const GET_CURRENT_PID_TGID: i32 = 14;
    pub const GET_CURRENT_UID_GID: i32 = 15;
    pub const SKB_LOAD_BYTES: i32 = 26;
    pub const GET_NUMA_NODE_ID: i32 = 42;
    pub const GET_SOCKET_COOKIE: i32 = 46;
    pub const GET_SOCKET_UID: i32 = 47;
    pub const SKB_LOAD_BYTES_RELATIVE: i32 = 68;
    pub const GET_NETNS_COOKIE: i32 = 122;
    pub const KTIME_GET_BOOT_NS: i32 = 125;
    pub const KTIME_GET_COARSE_NS: i32 = 160;
    pub const KTIME_GET_TAI_NS: i32 = 208;
}

/// What a classic program converts to and eBPF programs never reach.
pub(crate) mod classic {
    /// Linux's internal helpers of converted programs, by numbers no
    /// helper of `enum bpf_func_id` has: `bpf_skb_load_helper_8`, `_16`
    /// and `_32`, `bpf_skb_get_pay_offset`, `bpf_skb_get_nlattr`, its
    /// `_nest`, `bpf_get_raw_cpu_id` and `bpf_user_rnd_u32`.
    pub const LOAD_BYTE: i32 = -1;
    pub const LOAD_HALF: i32 = -2;
    pub const LOAD_WORD: i32 = -3;
    pub const PAY_OFFSET: i32 = -4;
    pub const NLATTR: i32 = -5;
    pub const NLATTR_NEST: i32 = -6;
    pub const CPU: i32 = -7;
    pub const RANDOM: i32 = -8;

    /// Where the `sk_buff` fields a converted program reads are: those
    /// `struct __sk_buff` has, at its offsets, and after it the data's
    /// address, `data_len` and `dev`.
    pub mod field {
        pub const LEN: i16 = 0;
        pub const PKT_TYPE: i16 = 4;
        pub const MARK: i16 = 8;
        pub const QUEUE_MAPPING: i16 = 12;
        pub const PROTOCOL: i16 = 16;
        pub const VLAN_ALL: i16 = 20;
        pub const VLAN_TCI: i16 = 24;
        pub const VLAN_PROTO: i16 = 28;
        pub const HASH: i16 = 68;
        pub const DATA: i16 = 192;
        pub const DATA_LEN: i16 = 200;
        pub const DEV: i16 = 208;
    }
}

/// `SKF_NET_OFF`, where a classic load's negative offsets from the network
/// header start, and `SKF_LL_OFF`, from the MAC header, which an AF_UNIX
/// message has not set.
const NET_OFF: i32 = -0x10_0000;

/// The clocks the `bpf_ktime_get_*` helpers read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Clock {
    Monotonic,
    Boot,
    MonotonicCoarse,
    Tai,
}

/// What the helpers ask of the kernel around the program: the running
/// task, the clocks, and the socket the packet is for (`skb->sk`, the
/// receiver's while its filter runs, as `sk_filter_trim_cap` sets it).
pub(crate) trait Kernel {
    fn clock(&mut self, clock: Clock) -> u64;
    fn random(&mut self) -> u32;
    fn processor(&mut self) -> u32;
    /// `bpf_get_current_pid_tgid`: the thread group's ID above the
    /// thread's, as the initial PID namespace sees them.
    fn pid_tgid(&mut self) -> u64;
    /// `bpf_get_current_uid_gid`: the group ID above the user ID, as the
    /// initial user namespace sees them.
    fn uid_gid(&mut self) -> u64;
    /// `__sock_gen_cookie` of the socket.
    fn socket_cookie(&mut self) -> u64;
    /// `bpf_get_socket_uid`: the socket's owner (`sk_uid`), as its network
    /// namespace's user namespace sees it, or the overflow ID.
    fn socket_uid(&mut self) -> u32;
    /// `net_cookie` of the socket's network namespace, or of the initial
    /// one when the program gives no context.
    fn netns_cookie(&mut self, of_socket: bool) -> u64;
}

/// The packet a socket filter runs on.
pub(crate) struct Packet<'a> {
    /// Every byte of it (`skb->len`).
    pub(crate) data: &'a [u8],
    /// How many of them are in the linear part (`skb_headlen`), which
    /// `bpf_skb_load_bytes_relative` reads from the network header on.
    pub(crate) linear: usize,
}

impl<'a> Packet<'a> {
    /// The linear part.
    fn head(&self) -> &'a [u8] {
        &self.data[..self.linear.min(self.data.len())]
    }
}

/// A verified program, with what the verifier resolved: the maps it uses
/// and, for each `BPF_LD_IMM64` of a map, the map's index among them and
/// the offset in a `BPF_PSEUDO_MAP_VALUE`'s value.
pub(crate) struct Program<'a> {
    pub(crate) insns: &'a [Insn],
    pub(crate) maps: &'a [Arc<Map>],
    pub(crate) loads: &'a BTreeMap<usize, (u8, Option<u32>)>,
}

struct Machine<'a, 'k> {
    program: &'a Program<'a>,
    packet: &'a Packet<'a>,
    kernel: &'k mut dyn Kernel,
    regs: [u64; 11],
    stack: [u8; STACK_SIZE],
    context: [u8; CONTEXT_WITH_TAIL],
    values: Vec<ValueRef>,
}

/// Runs `program` on `packet` and gives `R0` when it exits, which a socket
/// filter takes as the bytes of the packet to keep.
pub(crate) fn run(
    program: &Program<'_>,
    packet: &Packet<'_>,
    kernel: &mut dyn Kernel,
) -> Result<u64, Fault> {
    let mut context = [0; CONTEXT_WITH_TAIL];
    let len = u32::try_from(packet.data.len()).map_err(|_| Fault)?;
    context[0..4].copy_from_slice(&len.to_le_bytes());
    let data = address(PACKET, 0).to_le_bytes();
    let at = classic::field::DATA as usize;
    context[at..at + 8].copy_from_slice(&data);
    let paged = (packet.data.len() - packet.linear.min(packet.data.len())) as u32;
    let at = classic::field::DATA_LEN as usize;
    context[at..at + 4].copy_from_slice(&paged.to_le_bytes());
    let mut m = Machine {
        program,
        packet,
        kernel,
        regs: [0; 11],
        stack: [0; STACK_SIZE],
        context,
        values: Vec::new(),
    };
    m.regs[1] = address(CONTEXT, 0);
    m.regs[10] = address(STACK, STACK_SIZE as u64);
    m.run()
}

/// The classes, sizes and modes of `struct bpf_insn`'s code.
const LD: u8 = 0x00;
const LDX: u8 = 0x01;
const ST: u8 = 0x02;
const STX: u8 = 0x03;
const ALU: u8 = 0x04;
const JMP: u8 = 0x05;
const JMP32: u8 = 0x06;
const ALU64: u8 = 0x07;
const MEM: u8 = 0x60;
const MEMSX: u8 = 0x80;
const ATOMIC: u8 = 0xc0;
const IMM: u8 = 0x00;
const DW: u8 = 0x18;
/// `BPF_X`, and for `BPF_END` `BPF_TO_BE`.
const X: u8 = 0x08;

fn width(code: u8) -> usize {
    match code & 0x18 {
        0x00 => 4,
        0x08 => 2,
        0x10 => 1,
        _ => 8,
    }
}

impl Machine<'_, '_> {
    fn run(&mut self) -> Result<u64, Fault> {
        let insns = self.program.insns;
        let mut pc = 0usize;
        // The verifier takes no back-edge, so a program ends within as many
        // steps as it has instructions.
        for _ in 0..=insns.len() {
            let insn = *insns.get(pc).ok_or(Fault)?;
            let next = pc + 1;
            let dst = usize::from(insn.dst);
            let src = usize::from(insn.src);
            if dst > 10 || src > 10 {
                return Err(Fault);
            }
            let imm = i64::from(insn.imm) as u64;
            match insn.code & 0x07 {
                ALU | ALU64 => {
                    self.alu(insn, dst, src, imm);
                    pc = next;
                }
                JMP | JMP32 => {
                    let op = insn.code & 0xf0;
                    match op {
                        0x00 => {
                            let by = if insn.code & 0x07 == JMP32 {
                                i64::from(insn.imm)
                            } else {
                                i64::from(insn.off)
                            };
                            pc = target(next, by)?;
                        }
                        0x80 => {
                            self.regs[0] = self.call(insn.imm)?;
                            pc = next;
                        }
                        0x90 => return Ok(self.regs[0]),
                        _ => {
                            let a = self.regs[dst];
                            let b = if insn.code & X != 0 {
                                self.regs[src]
                            } else {
                                imm
                            };
                            let taken = if insn.code & 0x07 == JMP32 {
                                condition(op, u64::from(a as u32), u64::from(b as u32), true)
                            } else {
                                condition(op, a, b, false)
                            }
                            .ok_or(Fault)?;
                            pc = if taken {
                                target(next, i64::from(insn.off))?
                            } else {
                                next
                            };
                        }
                    }
                }
                LD => {
                    if insn.code != LD | IMM | DW {
                        return Err(Fault);
                    }
                    let high = insns.get(next).ok_or(Fault)?;
                    self.regs[dst] = match self.program.loads.get(&pc) {
                        None if insn.src == 0 => {
                            u64::from(insn.imm as u32) | u64::from(high.imm as u32) << 32
                        }
                        None => return Err(Fault),
                        Some(&(map, None)) => address(MAPS + u64::from(map), 0),
                        Some(&(map, Some(offset))) => {
                            let map = self.program.maps.get(usize::from(map)).ok_or(Fault)?;
                            let value = map.prog_lookup(&0u32.to_le_bytes()).ok_or(Fault)?;
                            self.value(value, u64::from(offset))?
                        }
                    };
                    pc = next + 1;
                }
                LDX => {
                    let size = width(insn.code);
                    let at = self.regs[src].wrapping_add(i64::from(insn.off) as u64);
                    let mut bytes = [0; 8];
                    self.read(at, &mut bytes[..size])?;
                    let v = u64::from_le_bytes(bytes);
                    self.regs[dst] = match insn.code & 0xe0 {
                        MEM => v,
                        MEMSX => match size {
                            1 => v as i8 as u64,
                            2 => v as i16 as u64,
                            4 => v as i32 as u64,
                            _ => return Err(Fault),
                        },
                        _ => return Err(Fault),
                    };
                    pc = next;
                }
                STX if insn.code & 0xe0 == ATOMIC => {
                    self.atomic(insn, dst, src)?;
                    pc = next;
                }
                ST | STX => {
                    if insn.code & 0xe0 != MEM {
                        return Err(Fault);
                    }
                    let size = width(insn.code);
                    let at = self.regs[dst].wrapping_add(i64::from(insn.off) as u64);
                    let v = if insn.code & 0x07 == STX {
                        self.regs[src]
                    } else {
                        imm
                    };
                    self.write(at, &v.to_le_bytes()[..size])?;
                    pc = next;
                }
                _ => return Err(Fault),
            }
        }
        Err(Fault)
    }

    /// One `BPF_ALU` or `BPF_ALU64` instruction.
    fn alu(&mut self, insn: Insn, dst: usize, src: usize, imm: u64) {
        let wide = insn.code & 0x07 == ALU64;
        let op = insn.code & 0xf0;
        let d = self.regs[dst];
        let s = if insn.code & X != 0 {
            self.regs[src]
        } else {
            imm
        };
        let signed = insn.off == 1;
        let v = if wide {
            match op {
                0x00 => d.wrapping_add(s),
                0x10 => d.wrapping_sub(s),
                0x20 => d.wrapping_mul(s),
                0x30 if signed => match s as i64 {
                    0 => 0,
                    -1 => d.wrapping_neg(),
                    s => (d as i64).wrapping_div(s) as u64,
                },
                0x30 => d.checked_div(s).unwrap_or(0),
                0x40 => d | s,
                0x50 => d & s,
                0x60 => d << (s & 63),
                0x70 => d >> (s & 63),
                0x80 => d.wrapping_neg(),
                0x90 if signed => match s as i64 {
                    0 => d,
                    -1 => 0,
                    s => (d as i64).wrapping_rem(s) as u64,
                },
                0x90 => d.checked_rem(s).unwrap_or(d),
                0xa0 => d ^ s,
                0xb0 => match insn.off {
                    8 => s as i8 as u64,
                    16 => s as i16 as u64,
                    32 => s as i32 as u64,
                    _ => s,
                },
                0xc0 => ((d as i64) >> (s & 63)) as u64,
                // BPF_ALU64 | BPF_END: a swap whatever the order.
                0xd0 => swap(d, insn.imm),
                _ => d,
            }
        } else {
            let (d32, s32) = (d as u32, s as u32);
            let v: u32 = match op {
                0x00 => d32.wrapping_add(s32),
                0x10 => d32.wrapping_sub(s32),
                0x20 => d32.wrapping_mul(s32),
                0x30 if signed => match s32 as i32 {
                    0 => 0,
                    -1 => d32.wrapping_neg(),
                    _ => signed32(d32, s32, true),
                },
                0x30 => d32.checked_div(s32).unwrap_or(0),
                0x40 => d32 | s32,
                0x50 => d32 & s32,
                0x60 => d32 << (s32 & 31),
                0x70 => d32 >> (s32 & 31),
                0x80 => d32.wrapping_neg(),
                0x90 if signed => match s32 as i32 {
                    0 => d32,
                    -1 => 0,
                    _ => signed32(d32, s32, false),
                },
                0x90 => d32.checked_rem(s32).unwrap_or(d32),
                0xa0 => d32 ^ s32,
                0xb0 => match insn.off {
                    8 => s32 as i8 as u32,
                    16 => s32 as i16 as u32,
                    _ => s32,
                },
                0xc0 => ((d32 as i32) >> (s32 & 31)) as u32,
                0xd0 => {
                    // BPF_END: to little-endian truncates, to big-endian
                    // swaps and truncates, on a little-endian machine.
                    let swapped = if insn.code & X != 0 {
                        swap(d, insn.imm)
                    } else {
                        truncate(d, insn.imm)
                    };
                    self.regs[dst] = swapped;
                    return;
                }
                _ => d32,
            };
            u64::from(v)
        };
        self.regs[dst] = v;
    }

    /// The address of `value` at `offset`, in a region of its own unless
    /// the program reached that value before.
    fn value(&mut self, value: ValueRef, offset: u64) -> Result<u64, Fault> {
        let i = match self.values.iter().position(|v| v.same(&value)) {
            Some(i) => i,
            None => {
                self.values.push(value);
                self.values.len() - 1
            }
        };
        let region = VALUES + i as u64;
        if region >= PACKET {
            return Err(Fault);
        }
        Ok(address(region, offset))
    }

    /// The region `at` is in and the offset, for `len` bytes there.
    fn place(&self, at: u64, len: usize) -> Result<(u64, usize), Fault> {
        if at & 0xff00_0000_0000_0000 != SPACE {
            return Err(Fault);
        }
        let region = (at >> 32) & (REGIONS - 1);
        let offset = (at & 0xffff_ffff) as usize;
        offset.checked_add(len).ok_or(Fault)?;
        Ok((region, offset))
    }

    fn read(&self, at: u64, out: &mut [u8]) -> Result<(), Fault> {
        let (region, offset) = self.place(at, out.len())?;
        let end = offset + out.len();
        match region {
            STACK => out.copy_from_slice(self.stack.get(offset..end).ok_or(Fault)?),
            CONTEXT => out.copy_from_slice(self.context.get(offset..end).ok_or(Fault)?),
            PACKET => out.copy_from_slice(self.packet.head().get(offset..end).ok_or(Fault)?),
            r if r >= VALUES => {
                let value = self.values.get((r - VALUES) as usize).ok_or(Fault)?;
                value.read(offset, out).map_err(|_| Fault)?;
            }
            // The verifier lets no program read a map's own fields.
            _ => return Err(Fault),
        }
        Ok(())
    }

    fn write(&mut self, at: u64, bytes: &[u8]) -> Result<(), Fault> {
        let (region, offset) = self.place(at, bytes.len())?;
        let end = offset + bytes.len();
        match region {
            STACK => self
                .stack
                .get_mut(offset..end)
                .ok_or(Fault)?
                .copy_from_slice(bytes),
            // Only `cb[]` is written.
            CONTEXT if offset >= CB.start && end <= CB.end => {
                self.context[offset..end].copy_from_slice(bytes)
            }
            r if (VALUES..PACKET).contains(&r) => {
                let value = self.values.get((r - VALUES) as usize).ok_or(Fault)?;
                value.write(offset, bytes).map_err(|_| Fault)?;
            }
            _ => return Err(Fault),
        }
        Ok(())
    }

    /// A `BPF_ATOMIC` of 4 or 8 bytes, as `___bpf_prog_run` runs it: the
    /// operation with the source, or with `BPF_CMPXCHG` the source in place
    /// of a value equal to R0's. The old value, zero-extended from 32 bits,
    /// goes to the source with `BPF_FETCH` and to R0 with `BPF_CMPXCHG`.
    fn atomic(&mut self, insn: Insn, dst: usize, src: usize) -> Result<(), Fault> {
        let size = width(insn.code);
        if size < 4 {
            return Err(Fault);
        }
        let mask = if size == 4 {
            u64::from(u32::MAX)
        } else {
            u64::MAX
        };
        let at = self.regs[dst].wrapping_add(i64::from(insn.off) as u64);
        let (operand, expected) = (self.regs[src] & mask, self.regs[0] & mask);
        let op = insn.imm;
        let change = |old: u64| -> Option<u64> {
            Some(
                match op & !1 {
                    0x00 => old.wrapping_add(operand),
                    0x40 => old | operand,
                    0x50 => old & operand,
                    0xa0 => old ^ operand,
                    0xe0 if op & 1 != 0 => operand,
                    0xf0 if op & 1 != 0 => {
                        if old == expected {
                            operand
                        } else {
                            old
                        }
                    }
                    _ => return None,
                } & mask,
            )
        };
        let (region, offset) = self.place(at, size)?;
        let old = if region == STACK {
            let place = self.stack.get_mut(offset..offset + size).ok_or(Fault)?;
            let mut bytes = [0; 8];
            bytes[..size].copy_from_slice(place);
            let old = u64::from_le_bytes(bytes);
            let new = change(old).ok_or(Fault)?;
            place.copy_from_slice(&new.to_le_bytes()[..size]);
            old
        } else if (VALUES..PACKET).contains(&region) {
            let value = self.values.get((region - VALUES) as usize).ok_or(Fault)?;
            let mut known = true;
            let before = value
                .update(offset, size, |place| {
                    let mut bytes = [0; 8];
                    bytes[..size].copy_from_slice(place);
                    let new = change(u64::from_le_bytes(bytes));
                    known = new.is_some();
                    new.unwrap_or(u64::from_le_bytes(bytes)).to_le_bytes()[..size].to_vec()
                })
                .map_err(|_| Fault)?;
            if !known {
                return Err(Fault);
            }
            let mut bytes = [0; 8];
            bytes[..size].copy_from_slice(&before);
            u64::from_le_bytes(bytes)
        } else {
            // The verifier lets no atomic reach the context or a map.
            return Err(Fault);
        };
        if op == 0xf1 {
            self.regs[0] = old;
        } else if op & 1 != 0 {
            self.regs[src] = old;
        }
        Ok(())
    }

    fn bytes(&self, at: u64, len: usize) -> Result<Vec<u8>, Fault> {
        let mut out = vec![0; len];
        self.read(at, &mut out)?;
        Ok(out)
    }

    /// The map `R1` points at.
    fn map(&self) -> Result<Arc<Map>, Fault> {
        let at = self.regs[1];
        let (region, offset) = self.place(at, 0)?;
        if offset != 0 || !(MAPS..VALUES).contains(&region) {
            return Err(Fault);
        }
        self.program
            .maps
            .get((region - MAPS) as usize)
            .cloned()
            .ok_or(Fault)
    }

    /// `R1` is the context.
    fn context_arg(&self) -> Result<(), Fault> {
        if self.regs[1] == address(CONTEXT, 0) {
            Ok(())
        } else {
            Err(Fault)
        }
    }

    /// A helper call (`BPF_CALL`), which gives `R0`.
    fn call(&mut self, id: i32) -> Result<u64, Fault> {
        let error = |e: Errno| (-i64::from(e.0)) as u64;
        let [_, r1, r2, r3, r4, r5, ..] = self.regs;
        Ok(match id {
            func::MAP_LOOKUP_ELEM => {
                let map = self.map()?;
                let key = self.bytes(r2, map.meta().key_size as usize)?;
                match map.prog_lookup(&key) {
                    Some(value) => self.value(value, 0)?,
                    None => 0,
                }
            }
            func::MAP_UPDATE_ELEM => {
                let map = self.map()?;
                let meta = map.meta();
                let key = self.bytes(r2, meta.key_size as usize)?;
                let value = self.bytes(r3, meta.value_size as usize)?;
                map.prog_update(&key, &value, r4).map_or_else(error, |()| 0)
            }
            func::MAP_DELETE_ELEM => {
                let map = self.map()?;
                let key = self.bytes(r2, map.meta().key_size as usize)?;
                map.prog_delete(&key).map_or_else(error, |()| 0)
            }
            func::KTIME_GET_NS => self.kernel.clock(Clock::Monotonic),
            func::KTIME_GET_BOOT_NS => self.kernel.clock(Clock::Boot),
            func::KTIME_GET_COARSE_NS => self.kernel.clock(Clock::MonotonicCoarse),
            func::KTIME_GET_TAI_NS => self.kernel.clock(Clock::Tai),
            func::GET_PRANDOM_U32 => u64::from(self.kernel.random()),
            func::GET_SMP_PROCESSOR_ID => u64::from(self.kernel.processor()),
            // One NUMA node.
            func::GET_NUMA_NODE_ID => 0,
            func::GET_CURRENT_PID_TGID => self.kernel.pid_tgid(),
            func::GET_CURRENT_UID_GID => self.kernel.uid_gid(),
            func::GET_SOCKET_COOKIE => {
                self.context_arg()?;
                self.kernel.socket_cookie()
            }
            func::GET_SOCKET_UID => {
                self.context_arg()?;
                u64::from(self.kernel.socket_uid())
            }
            func::GET_NETNS_COOKIE => {
                let of_socket = r1 != 0;
                if of_socket {
                    self.context_arg()?;
                }
                self.kernel.netns_cookie(of_socket)
            }
            func::SKB_LOAD_BYTES => {
                self.context_arg()?;
                let (offset, len) = (r2 as u32, r4 as u32 as usize);
                let data = self.packet.data;
                // `skb_header_pointer`, and an offset past `INT_MAX`.
                let bytes = (offset <= i32::MAX as u32)
                    .then(|| data.get(offset as usize..(offset as usize).checked_add(len)?))
                    .flatten();
                self.give(r3, len, bytes)?
            }
            func::SKB_LOAD_BYTES_RELATIVE => {
                self.context_arg()?;
                let (offset, len) = (r2 as u32, r4 as u32 as usize);
                let linear = self.packet.head();
                // No MAC header is set; the network header is where the
                // data starts; anything else is EFAULT.
                let bytes = (offset <= 0xffff && r5 as u32 == 1)
                    .then(|| linear.get(offset as usize..(offset as usize).checked_add(len)?))
                    .flatten();
                self.give(r3, len, bytes)?
            }
            classic::LOAD_BYTE | classic::LOAD_HALF | classic::LOAD_WORD => {
                self.context_arg()?;
                let size = match id {
                    classic::LOAD_BYTE => 1,
                    classic::LOAD_HALF => 2,
                    _ => 4,
                };
                self.load(r4 as i32, size)
            }
            classic::NLATTR | classic::NLATTR_NEST => {
                self.context_arg()?;
                self.nlattr(r2 as u32, r3 as u32, id == classic::NLATTR_NEST)
            }
            // The flow dissector knows no AF_UNIX message's protocol.
            classic::PAY_OFFSET => {
                self.context_arg()?;
                0
            }
            classic::CPU => u64::from(self.kernel.processor()),
            classic::RANDOM => u64::from(self.kernel.random()),
            _ => return Err(Fault),
        })
    }

    /// `bpf_skb_load_helper_8`, `_16` and `_32`: the packet's `size` bytes
    /// at `offset`, big-endian, where a negative one is from the network
    /// header (the data's start, `SKF_NET_OFF`) or the MAC header (not set,
    /// `SKF_LL_OFF`); `-EFAULT` past the end, or for no header.
    fn load(&self, offset: i32, size: usize) -> u64 {
        let offset = match offset {
            o if o >= 0 => Some(o),
            o if o >= NET_OFF => Some(o - NET_OFF),
            _ => None,
        };
        let bytes = offset.and_then(|o| {
            let o = o as usize;
            self.packet.data.get(o..o.checked_add(size)?)
        });
        match bytes {
            Some(b) => b.iter().fold(0, |v, &b| v << 8 | u64::from(b)),
            None => (-i64::from(Errno::EFAULT.0)) as u64,
        }
    }

    /// `bpf_skb_get_nlattr` and `bpf_skb_get_nlattr_nest`: the offset of
    /// the first netlink attribute of type `x` at `a` on, or among those
    /// nested in the attribute at `a`; 0 for none, or for a packet in pages.
    fn nlattr(&self, a: u32, x: u32, nested: bool) -> u64 {
        let data = self.packet.data;
        if self.packet.linear < data.len() || data.len() < 4 || a as usize > data.len() - 4 {
            return 0;
        }
        let a = a as usize;
        let length = |at: usize| usize::from(u16::from_le_bytes([data[at], data[at + 1]]));
        // nla_ok: room for a header, and a length from it to what remains.
        let ok = |at: usize, remaining: isize| {
            remaining >= 4 && length(at) >= 4 && length(at) as isize <= remaining
        };
        let (mut at, mut remaining) = (a, (data.len() - a) as isize);
        if nested {
            if !ok(at, remaining) {
                return 0;
            }
            remaining = length(at) as isize - 4;
            at += 4;
        }
        // nla_find, with nla_type's mask of the nested and byte-order flags.
        while ok(at, remaining) {
            let kind = u16::from_le_bytes([data[at + 2], data[at + 3]]) & 0x3fff;
            if i32::from(kind) == x as i32 {
                return at as u64;
            }
            let total = length(at).next_multiple_of(4);
            remaining -= total as isize;
            at += total;
        }
        0
    }

    /// The end of `bpf_skb_load_bytes`: the bytes at `to`, or `len` zeros
    /// and `EFAULT`.
    fn give(&mut self, to: u64, len: usize, bytes: Option<&[u8]>) -> Result<u64, Fault> {
        match bytes {
            Some(bytes) => {
                let bytes = bytes.to_vec();
                self.write(to, &bytes)?;
                Ok(0)
            }
            None => {
                self.write(to, &vec![0; len])?;
                Ok((-i64::from(Errno::EFAULT.0)) as u64)
            }
        }
    }
}

fn target(next: usize, by: i64) -> Result<usize, Fault> {
    usize::try_from(next as i64 + by).map_err(|_| Fault)
}

/// A conditional jump's test, on 32-bit operands when `narrow`.
fn condition(op: u8, a: u64, b: u64, narrow: bool) -> Option<bool> {
    let (sa, sb) = if narrow {
        (i64::from(a as u32 as i32), i64::from(b as u32 as i32))
    } else {
        (a as i64, b as i64)
    };
    Some(match op {
        0x10 => a == b,
        0x20 => a > b,
        0x30 => a >= b,
        0x40 => a & b != 0,
        0x50 => a != b,
        0x60 => sa > sb,
        0x70 => sa >= sb,
        0xa0 => a < b,
        0xb0 => a <= b,
        0xc0 => sa < sb,
        0xd0 => sa <= sb,
        _ => return None,
    })
}

/// A 32-bit signed division or remainder, as the interpreter does it on
/// magnitudes (`abs_s32` and `do_div`), for a divisor neither 0 nor -1.
fn signed32(d: u32, s: u32, divide: bool) -> u32 {
    let (dn, sn) = ((d as i32) < 0, (s as i32) < 0);
    let (a, b) = ((d as i32).unsigned_abs(), (s as i32).unsigned_abs());
    if divide {
        let q = a / b;
        if dn == sn { q } else { q.wrapping_neg() }
    } else {
        let r = a % b;
        if dn { r.wrapping_neg() } else { r }
    }
}

/// `__swab16`, `__swab32` and `__swab64`, by `imm`.
fn swap(v: u64, imm: i32) -> u64 {
    match imm {
        16 => u64::from((v as u16).swap_bytes()),
        32 => u64::from((v as u32).swap_bytes()),
        _ => v.swap_bytes(),
    }
}

/// `cpu_to_le16` and the rest on a little-endian machine: the lower bits.
fn truncate(v: u64, imm: i32) -> u64 {
    match imm {
        16 => u64::from(v as u16),
        32 => u64::from(v as u32),
        _ => v,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A kernel of fixed answers, which the classic filters' tests use too.
    pub(crate) struct Quiet;

    impl Kernel for Quiet {
        fn clock(&mut self, clock: Clock) -> u64 {
            match clock {
                Clock::Monotonic => 5,
                Clock::Boot => 125,
                Clock::MonotonicCoarse => 160,
                Clock::Tai => 208,
            }
        }
        fn random(&mut self) -> u32 {
            7
        }
        fn processor(&mut self) -> u32 {
            0
        }
        fn pid_tgid(&mut self) -> u64 {
            3 << 32 | 4
        }
        fn uid_gid(&mut self) -> u64 {
            1000 << 32 | 1001
        }
        fn socket_cookie(&mut self) -> u64 {
            46
        }
        fn socket_uid(&mut self) -> u32 {
            47
        }
        fn netns_cookie(&mut self, of_socket: bool) -> u64 {
            if of_socket { 122 } else { 1 }
        }
    }

    fn i(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
        Insn {
            code,
            dst,
            src,
            off,
            imm,
        }
    }
    fn exit() -> Insn {
        i(0x95, 0, 0, 0, 0)
    }

    fn run_on(insns: &[Insn], data: &[u8]) -> Result<u64, Fault> {
        let loads = BTreeMap::new();
        let program = Program {
            insns,
            maps: &[],
            loads: &loads,
        };
        let packet = Packet {
            data,
            linear: data.len(),
        };
        run(&program, &packet, &mut Quiet)
    }

    /// `R0 = dst op src` in 64 or 32 bits, with `off` for the signed forms.
    fn alu(code: u8, off: i16, d: u64, s: u64) -> u64 {
        let ld = |r: u8, v: u64| {
            [
                i(0x18, r, 0, 0, v as u32 as i32),
                i(0, 0, 0, 0, (v >> 32) as u32 as i32),
            ]
        };
        let mut p = Vec::new();
        p.extend(ld(0, d));
        p.extend(ld(2, s));
        p.push(i(code | X, 0, 2, off, 0));
        p.push(exit());
        run_on(&p, &[]).unwrap()
    }

    #[test]
    fn division_by_zero_and_minus_one_is_what_linux_s_rewrites_make_it() {
        const DIV64: u8 = 0x37;
        const MOD64: u8 = 0x97;
        const DIV32: u8 = 0x34;
        const MOD32: u8 = 0x94;
        let min = i64::MIN as u64;
        assert_eq!(alu(DIV64, 0, 7, 0), 0);
        assert_eq!(alu(MOD64, 0, 7, 0), 7);
        assert_eq!(alu(DIV32, 0, 0x1_0000_0007, 0), 0);
        // The remainder by 0 keeps the lower half, zero-extended.
        assert_eq!(alu(MOD32, 0, 0x1_0000_0007, 0), 7);
        assert_eq!(alu(DIV64, 1, min, u64::MAX), min);
        assert_eq!(alu(MOD64, 1, min, u64::MAX), 0);
        assert_eq!(alu(DIV64, 1, 7, 0), 0);
        assert_eq!(alu(MOD64, 1, (-7i64) as u64, 0), (-7i64) as u64);
        assert_eq!(alu(DIV32, 1, 0x8000_0000, 0xffff_ffff), 0x8000_0000);
        assert_eq!(alu(MOD32, 1, 0x8000_0000, 0xffff_ffff), 0);
        // Signed 32-bit division and remainder follow the dividend's and the
        // divisor's signs.
        assert_eq!(
            alu(DIV32, 1, (-7i32) as u32 as u64, 2),
            (-3i32) as u32 as u64
        );
        assert_eq!(
            alu(MOD32, 1, (-7i32) as u32 as u64, 2),
            (-1i32) as u32 as u64
        );
        assert_eq!(alu(MOD32, 1, 7, (-2i32) as u32 as u64), 1);
        // Unsigned 64-bit by an immediate takes it sign-extended.
        let p = [i(0xb7, 0, 0, 0, -1), i(0x37, 0, 0, 0, -2), exit()];
        assert_eq!(run_on(&p, &[]), Ok(1));
    }

    #[test]
    fn shifts_moves_and_swaps_are_linux_s() {
        assert_eq!(alu(0x6f, 0, 1, 65), 2);
        assert_eq!(alu(0x6c, 0, 1, 33), 2);
        assert_eq!(alu(0xcf, 0, 1 << 63, 63), u64::MAX);
        // MOVSX.
        assert_eq!(alu(0xbf, 8, 0, 0x80), (-128i64) as u64);
        assert_eq!(alu(0xbc, 16, 0, 0x8000), 0xffff_8000);
        assert_eq!(alu(0xbf, 32, 0, 0x8000_0000), 0xffff_ffff_8000_0000);
        let end = |code: u8, imm: i32| {
            run_on(
                &[
                    i(0x18, 0, 0, 0, 0x0403_0201),
                    i(0, 0, 0, 0, 0x0807_0605),
                    i(code, 0, 0, 0, imm),
                    exit(),
                ],
                &[],
            )
            .unwrap()
        };
        assert_eq!(end(0xd4, 16), 0x0201);
        assert_eq!(end(0xdc, 16), 0x0102);
        assert_eq!(end(0xdc, 64), 0x0102_0304_0506_0708);
        assert_eq!(end(0xd7, 32), 0x0102_0304);
    }

    /// A `BPF_ATOMIC` of `code`'s size and `imm` at fp-8, which holds
    /// `memory`, with `src` in R2 and `r0` in R0: the 8 bytes at fp-8, R2
    /// and R0 after it.
    fn atomic(code: u8, imm: i32, memory: u64, src: u64, r0: u64) -> [u64; 3] {
        let ld = |r: u8, v: u64| {
            [
                i(0x18, r, 0, 0, v as u32 as i32),
                i(0, 0, 0, 0, (v >> 32) as u32 as i32),
            ]
        };
        [
            i(0x79, 0, 10, -8, 0),
            i(0xbf, 0, 2, 0, 0),
            i(0x05, 0, 0, 0, 0),
        ]
        .map(|result| {
            let mut p = Vec::new();
            p.extend(ld(3, memory));
            p.push(i(0x7b, 10, 3, -8, 0));
            p.extend(ld(2, src));
            p.extend(ld(0, r0));
            p.push(i(code, 10, 2, -8, imm));
            p.push(result);
            p.push(exit());
            run_on(&p, &[]).unwrap()
        })
    }

    #[test]
    fn atomics_change_memory_as_linux_s_do() {
        const W: u8 = 0xc3;
        const DW: u8 = 0xdb;
        let m = 0x1111_2222_f000_000f;
        // Without BPF_FETCH the registers stay.
        assert_eq!(atomic(DW, 0x00, m, 1, 9), [m + 1, 1, 9]);
        assert_eq!(atomic(DW, 0x40, m, 0xf0, 9), [m | 0xf0, 0xf0, 9]);
        assert_eq!(atomic(DW, 0x50, m, 0xff, 9), [0x0f, 0xff, 9]);
        assert_eq!(atomic(DW, 0xa0, m, u64::MAX, 9), [!m, u64::MAX, 9]);
        // With it the source takes the old value.
        assert_eq!(atomic(DW, 0x01, m, 1, 9), [m + 1, m, 9]);
        assert_eq!(atomic(DW, 0x51, m, 0xff, 9), [0x0f, m, 9]);
        assert_eq!(atomic(DW, 0xe1, m, 5, 9), [5, m, 9]);
        // CMPXCHG writes the source only where R0 holds what is there, and
        // R0 takes the old value either way.
        assert_eq!(atomic(DW, 0xf1, m, 5, m), [5, 5, m]);
        assert_eq!(atomic(DW, 0xf1, m, 5, 9), [m, 5, m]);
        // 32 bits change the lower half, take the source's lower half and
        // give the old value zero-extended.
        let high = m & !0xffff_ffff;
        assert_eq!(
            atomic(W, 0x01, m, 0x7_1000_0001, 9),
            [high | 0x0000_0010, 0xf000_000f, 9]
        );
        assert_eq!(
            atomic(W, 0xa1, m, u64::MAX, 9),
            [high | 0x0fff_fff0, 0xf000_000f, 9]
        );
        assert_eq!(
            atomic(W, 0xe1, m, 0x9_0000_0005, 9),
            [high | 5, 0xf000_000f, 9]
        );
        // R0's upper half does not take part in the comparison.
        assert_eq!(
            atomic(W, 0xf1, m, 5, 0x3_f000_000f),
            [high | 5, 5, 0xf000_000f]
        );
        assert_eq!(atomic(W, 0xf1, m, 5, 1), [m, 5, 0xf000_000f]);
    }

    #[test]
    fn the_context_and_the_stack() {
        // R0 = len; cb[0] = len + 1; R0 = cb[0] as one byte.
        let p = [
            i(0x61, 2, 1, 0, 0),
            i(0x07, 2, 0, 0, 1),
            i(0x63, 1, 2, 48, 0),
            i(0x71, 0, 1, 48, 0),
            exit(),
        ];
        assert_eq!(run_on(&p, &[0; 9]), Ok(10));
        // Spill the context, fill it, read len through it.
        let p = [
            i(0x7b, 10, 1, -8, 0),
            i(0x79, 3, 10, -8, 0),
            i(0x61, 0, 3, 0, 0),
            exit(),
        ];
        assert_eq!(run_on(&p, &[0; 3]), Ok(3));
        // Writing outside cb[] or reading past the stack is a fault.
        assert_eq!(run_on(&[i(0x62, 1, 0, 0, 1), exit()], &[]), Err(Fault));
        assert_eq!(run_on(&[i(0x79, 0, 10, 0, 0), exit()], &[]), Err(Fault));
    }

    #[test]
    fn the_skb_helpers_read_the_packet_or_give_efault() {
        let efault = (-14i64) as u64;
        // bpf_skb_load_bytes(ctx, R2, fp - 8, 4), then R0 = the 4 bytes or
        // the error.
        let load = |offset: i32, relative: Option<i32>| {
            let mut p = vec![
                i(0xb7, 2, 0, 0, offset),
                i(0xbf, 3, 10, 0, 0),
                i(0x07, 3, 0, 0, -8),
                i(0xb7, 4, 0, 0, 4),
            ];
            match relative {
                Some(start) => {
                    p.push(i(0xb7, 5, 0, 0, start));
                    p.push(i(0x85, 0, 0, 0, func::SKB_LOAD_BYTES_RELATIVE));
                }
                None => p.push(i(0x85, 0, 0, 0, func::SKB_LOAD_BYTES)),
            }
            p.extend([i(0x55, 0, 0, 1, 0), i(0x61, 0, 10, -8, 0), exit()]);
            run_on(&p, &[1, 2, 3, 4, 5, 6]).unwrap()
        };
        assert_eq!(load(2, None), 0x0605_0403);
        assert_eq!(load(3, None), efault);
        assert_eq!(load(-1, None), efault);
        assert_eq!(load(1, Some(1)), 0x0504_0302);
        assert_eq!(load(1, Some(0)), efault);
        assert_eq!(load(1, Some(2)), efault);
        assert_eq!(load(3, Some(1)), efault);
    }

    #[test]
    fn the_helpers_of_no_arguments_and_of_the_socket() {
        let call = |id: i32, r1: Option<i32>| {
            let mut p = Vec::new();
            if let Some(v) = r1 {
                p.push(i(0xb7, 1, 0, 0, v));
            }
            p.push(i(0x85, 0, 0, 0, id));
            p.push(exit());
            run_on(&p, &[]).unwrap()
        };
        assert_eq!(call(func::KTIME_GET_NS, None), 5);
        assert_eq!(call(func::KTIME_GET_TAI_NS, None), 208);
        assert_eq!(call(func::GET_PRANDOM_U32, None), 7);
        assert_eq!(call(func::GET_NUMA_NODE_ID, None), 0);
        assert_eq!(call(func::GET_CURRENT_PID_TGID, None), 3 << 32 | 4);
        assert_eq!(call(func::GET_SOCKET_COOKIE, None), 46);
        assert_eq!(call(func::GET_SOCKET_UID, None), 47);
        assert_eq!(call(func::GET_NETNS_COOKIE, None), 122);
        assert_eq!(call(func::GET_NETNS_COOKIE, Some(0)), 1);
    }

    #[test]
    fn jumps_compare_as_linux_does() {
        // if (s32)R1 < 0 goto +1; R0 = 1; exit; R0 = 2 at the target.
        let p = |code: u8, r1: i32| {
            run_on(
                &[
                    i(0xb7, 1, 0, 0, r1),
                    i(0xb7, 0, 0, 0, 2),
                    i(code, 1, 0, 1, 0),
                    i(0xb7, 0, 0, 0, 1),
                    exit(),
                ],
                &[],
            )
            .unwrap()
        };
        assert_eq!(p(0xc6, -1), 2);
        assert_eq!(p(0xc6, 1), 1);
        assert_eq!(p(0xc5, -1), 2);
        // Unsigned: -1 is not below 0.
        assert_eq!(p(0xa5, -1), 1);
        // gotol by imm.
        assert_eq!(
            run_on(
                &[
                    i(0xb7, 0, 0, 0, 1),
                    i(0x06, 0, 0, 0, 1),
                    i(0xb7, 0, 0, 0, 3),
                    exit()
                ],
                &[]
            ),
            Ok(1)
        );
    }

    /// The soundness the verifier gives the interpreter: random programs
    /// near what it takes, of registers, the stack, the context, jumps,
    /// atomics and the helpers without maps, and every one it takes runs on packets of
    /// a few lengths without a load or store outside what it points to.
    #[test]
    fn programs_the_verifier_takes_never_fault() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move |n: u32| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % u64::from(n)) as u32
        };
        const EDGES: [i32; 12] = [0, 1, -1, 7, 8, 16, 31, 32, 63, 64, i32::MIN, i32::MAX];
        let (mut taken, mut atomics) = (0, 0);
        for _ in 0..120_000 {
            let mut p = vec![i(0xbf, 6, 1, 0, 0)];
            for _ in 0..1 + next(12) {
                let dst = next(10) as u8;
                let src = next(11) as u8;
                let imm = if next(2) == 0 {
                    EDGES[next(12) as usize]
                } else {
                    next(200) as i32 - 100
                };
                let size = [0x18, 0x00, 0x08, 0x10][next(4) as usize];
                let at = -8 * (1 + next(64) as i16) + next(8) as i16;
                let alu = (next(14) as u8) << 4;
                let insn = match next(13) {
                    0 => i(0xb7, dst, 0, 0, imm),
                    1 => i(0x07 | alu, dst, 0, next(2) as i16, imm),
                    2 => i(0x04 | alu, dst, 0, 0, imm),
                    3 => i(0x0f | alu, dst, src, next(2) as i16, 0),
                    4 => i(0x63 | size, 10, src, at, 0),
                    5 => i(0x61 | size, dst, 10, at, 0),
                    6 => i(0x62 | size, 10, 0, at, imm),
                    7 => i(
                        0x61 | size,
                        dst,
                        6,
                        [0, 4, 48, 52, 64, 66, 67][next(7) as usize],
                        0,
                    ),
                    8 => i(0x63 | size, 6, src, [48, 52, 64, 66][next(4) as usize], 0),
                    9 => i(
                        [0x15, 0x25, 0x35, 0x45, 0x55, 0xa5, 0xc5][next(7) as usize],
                        dst,
                        0,
                        next(4) as i16,
                        imm,
                    ),
                    10 => {
                        // bpf_skb_load_bytes of the context to the stack.
                        p.push(i(0xbf, 1, 6, 0, 0));
                        p.push(i(0xb7, 2, 0, 0, [0, 1, 7, 60, -1][next(5) as usize]));
                        p.push(i(0xbf, 3, 10, 0, 0));
                        p.push(i(0x07, 3, 0, 0, -16));
                        p.push(i(0xb7, 4, 0, 0, [1, 4, 8, 16][next(4) as usize]));
                        i(0x85, 0, 0, 0, 26)
                    }
                    // Mostly what the verifier takes: 4 or 8 bytes of the
                    // stack aligned, rarely the context or another size.
                    11 => i(
                        [0xc3, 0xdb, 0xc3, 0xdb, 0xd3][next(5) as usize],
                        if next(8) == 0 { 6 } else { 10 },
                        src,
                        -8 * (1 + next(64) as i16) + 4 * next(2) as i16,
                        [
                            0x00, 0x01, 0x40, 0x41, 0x50, 0x51, 0xa0, 0xa1, 0xe1, 0xf1, 0x100, 0x03,
                        ][next(12) as usize],
                    ),
                    _ => i(0x85, 0, 0, 0, [5, 7, 8, 14, 15, 46, 47][next(7) as usize]),
                };
                p.push(insn);
            }
            p.push(i(0xb7, 0, 0, 0, 1));
            p.push(exit());
            let Ok(verified) = crate::bpf_verifier::check(
                &p,
                crate::bpf_verifier::Options::default(),
                &mut |_| Err(Errno::EBADF),
            ) else {
                continue;
            };
            taken += 1;
            if p.iter().any(|insn| insn.code & 0xe7 == STX | ATOMIC) {
                atomics += 1;
            }
            for len in [0, 1, 7, 64] {
                let data = vec![0x5a; len];
                let program = Program {
                    insns: &p,
                    maps: &[],
                    loads: &verified.loads,
                };
                let packet = Packet {
                    data: &data,
                    linear: data.len(),
                };
                assert!(
                    run(&program, &packet, &mut Quiet).is_ok(),
                    "{p:?} faulted on {len} bytes"
                );
            }
        }
        // Enough of them load for the check to mean something: 6,444 with
        // this seed and this verifier, 204 of them with an atomic. A change
        // to either that loads fewer than 6,000, or fewer than 150 with an
        // atomic, should look again at what the programs cover.
        assert!(taken >= 6_000, "only {taken} programs loaded");
        assert!(
            atomics >= 150,
            "only {atomics} programs with an atomic loaded"
        );
    }
}
