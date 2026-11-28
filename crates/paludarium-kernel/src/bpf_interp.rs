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
//! - a shift by a register takes its count modulo the width;
//! - a bpf-to-bpf call gives the callee a frame of its own, 512 bytes after
//!   its caller's in the stack's region, and R6 to R9 and the frame pointer
//!   back after it;
//! - a `BPF_LD_ABS` or `BPF_LD_IND` loads the packet's bytes big-endian
//!   through `bpf_skb_load_helper_8`, `_16` or `_32` (`bpf_gen_ld_abs`),
//!   and where they are not there the program returns 0.
//!
//! The context's fields that a socket filter may read are those of an
//! AF_UNIX datagram's `sk_buff`: its length, and 0 for the rest, which such
//! a packet does not set; `cb[]` starts at 0 (`bpf_prog_run_save_cb`), or
//! as `BPF_PROG_TEST_RUN`'s context gives it.
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
/// `MAX_CALL_FRAMES`: the main program's frame and its callees'.
const FRAMES: usize = 8;
/// `BPF_COMPLEXITY_LIMIT_INSNS`. The verifier walks every path a program
/// may take and takes no back-edge, so no run goes further.
const STEPS: usize = 1_000_000;

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
/// The packet's device (`skb->dev`), below the packet's region, which only
/// converted classic programs read: its index, then its type
/// ([`classic::field::DEV_TYPE`]).
const DEVICE: u64 = PACKET - 1;
/// The stacks of the callees' frames, frame `f` in region `CALLEES + f`
/// (the main program's is [`STACK`]), below the device's.
const CALLEES: u64 = DEVICE - FRAMES as u64;

/// The region of frame `f`'s stack.
fn frame_region(f: usize) -> u64 {
    if f == 0 { STACK } else { CALLEES + f as u64 }
}

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
    /// The helpers of converted programs, by numbers no helper of `enum
    /// bpf_func_id` has: the payload's offset, the netlink attribute
    /// searches, the CPU and a random number, which Linux has as
    /// `bpf_skb_get_pay_offset`, `bpf_skb_get_nlattr`, its `_nest`,
    /// `bpf_get_raw_cpu_id` and `bpf_user_rnd_u32`. A converted program's
    /// packet loads are eBPF's `BPF_LD | BPF_ABS` and `BPF_IND`.
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
        pub const PRIORITY: i16 = 32;
        pub const INGRESS_IFINDEX: i16 = 36;
        pub const IFINDEX: i16 = 40;
        pub const HASH: i16 = 68;
        pub const GSO_SEGS: i16 = 164;
        pub const GSO_SIZE: i16 = 176;
        pub const DATA: i16 = 192;
        pub const DATA_LEN: i16 = 200;
        pub const DEV: i16 = 208;
        /// Where `dev->type` is in the device's region, after its index.
        pub const DEV_TYPE: i16 = 4;
    }
}

/// `SKF_NET_OFF`, where a classic load's negative offsets from the network
/// header start, and `SKF_LL_OFF`, from the MAC header.
const NET_OFF: i32 = -0x10_0000;
const LL_OFF: i32 = -0x20_0000;

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
    /// Every byte of it from `skb->data` on (`skb->len`).
    pub(crate) data: &'a [u8],
    /// How many of them are in the linear part (`skb_headlen`).
    pub(crate) linear: usize,
    /// The headers before `skb->data`, which the linear part holds too:
    /// the MAC header, if one is set, and the network header.
    pub(crate) headers: &'a [u8],
    /// Where in [`Self::headers`] the MAC header starts
    /// (`skb_mac_header`), if it is set (`skb_mac_header_was_set`).
    pub(crate) mac: Option<usize>,
    /// Where in [`Self::headers`] the network header starts
    /// (`skb_network_header`).
    pub(crate) network: usize,
    /// Its `sk_buff`'s fields.
    pub(crate) skb: Skb,
}

/// The `sk_buff` fields of a packet that a filter reads, other than its
/// bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Skb {
    /// `pkt_type` (`PACKET_HOST`, `PACKET_BROADCAST`, `PACKET_LOOPBACK`
    /// and so on).
    pub(crate) pkt_type: u32,
    pub(crate) mark: u32,
    pub(crate) priority: u32,
    /// `protocol`, as it is in memory: in network order.
    pub(crate) protocol: [u8; 2],
    /// `skb_iif`.
    pub(crate) ingress_ifindex: u32,
    pub(crate) hash: u32,
    /// `dev`: its index and type (`ARPHRD_*`), if there is one.
    pub(crate) device: Option<(u32, u16)>,
    /// What `__skb_get_poff` finds: where the payload past the transport
    /// header starts, from `skb->data`, or 0 when the flow dissector does
    /// not know the protocol.
    pub(crate) payload_offset: u32,
    /// `gso_segs` and `gso_size`.
    pub(crate) gso: (u32, u32),
    /// `cb[]` as the program finds it: 0 where a filter runs on what a
    /// socket receives (`bpf_prog_run_save_cb`), and what
    /// `BPF_PROG_TEST_RUN`'s context gives there.
    pub(crate) cb: [u8; CB.end - CB.start],
}

impl<'a> Packet<'a> {
    /// An AF_UNIX message of `data`, `linear` of its bytes in the linear
    /// part: its network header is where the data starts, and it has no
    /// MAC header, device or protocol.
    pub(crate) fn message(data: &'a [u8], linear: usize) -> Self {
        Self {
            data,
            linear,
            headers: &[],
            mac: None,
            network: 0,
            skb: Skb::default(),
        }
    }

    /// The linear part from `skb->data` on.
    fn head(&self) -> &'a [u8] {
        &self.data[..self.linear.min(self.data.len())]
    }

    /// `size` bytes at `offset` from the header that starts at `start` in
    /// [`Self::headers`], which must end by the linear part's end
    /// (`skb_tail_pointer`), or with `paged` by the packet's.
    fn header_bytes(
        &self,
        start: usize,
        offset: usize,
        size: usize,
        paged: bool,
    ) -> Option<Vec<u8>> {
        let at = start.checked_add(offset)?;
        let end = at.checked_add(size)?;
        let data = if paged { self.data } else { self.head() };
        if end > self.headers.len() + data.len() {
            return None;
        }
        let mut out = Vec::with_capacity(size);
        for i in at..end {
            out.push(match self.headers.get(i) {
                Some(&b) => b,
                None => self.data[i - self.headers.len()],
            });
        }
        Some(out)
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
    stack: [[u8; STACK_SIZE]; FRAMES],
    /// The frames of the functions that called the running one: where
    /// each goes on, and its R6 to R9 and frame pointer.
    callers: Vec<(usize, [u64; 5])>,
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
    run_with_cb(program, packet, kernel).map(|(r0, _)| r0)
}

/// [`run`], with `cb[]` as the program left it.
pub(crate) fn run_with_cb(
    program: &Program<'_>,
    packet: &Packet<'_>,
    kernel: &mut dyn Kernel,
) -> Result<(u64, [u8; CB.end - CB.start]), Fault> {
    let mut context = [0; CONTEXT_WITH_TAIL];
    let len = u32::try_from(packet.data.len()).map_err(|_| Fault)?;
    context[0..4].copy_from_slice(&len.to_le_bytes());
    let skb = &packet.skb;
    let mut put = |at: i16, value: u32| {
        let at = at as usize;
        context[at..at + 4].copy_from_slice(&value.to_le_bytes());
    };
    put(classic::field::PKT_TYPE, skb.pkt_type);
    put(classic::field::MARK, skb.mark);
    put(
        classic::field::PROTOCOL,
        u32::from(u16::from_le_bytes(skb.protocol)),
    );
    put(classic::field::PRIORITY, skb.priority);
    put(classic::field::INGRESS_IFINDEX, skb.ingress_ifindex);
    put(classic::field::IFINDEX, skb.device.map_or(0, |d| d.0));
    put(classic::field::HASH, skb.hash);
    put(classic::field::GSO_SEGS, skb.gso.0);
    put(classic::field::GSO_SIZE, skb.gso.1);
    context[CB].copy_from_slice(&skb.cb);
    if skb.device.is_some() {
        let at = classic::field::DEV as usize;
        context[at..at + 8].copy_from_slice(&address(DEVICE, 0).to_le_bytes());
    }
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
        stack: [[0; STACK_SIZE]; FRAMES],
        callers: Vec::new(),
        context,
        values: Vec::new(),
    };
    m.regs[1] = address(CONTEXT, 0);
    m.regs[10] = address(STACK, STACK_SIZE as u64);
    let r0 = m.run()?;
    let mut cb = [0; CB.end - CB.start];
    cb.copy_from_slice(&m.context[CB]);
    Ok((r0, cb))
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
const ABS: u8 = 0x20;
const IND: u8 = 0x40;
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
        for _ in 0..=STEPS {
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
                        // A bpf-to-bpf call: the callee's frame pointer is
                        // its own, and R6 to R9 come back as they were.
                        0x80 if insn.src == 1 => {
                            let depth = self.callers.len() + 1;
                            if depth >= FRAMES {
                                return Err(Fault);
                            }
                            let mut saved = [0; 5];
                            saved.copy_from_slice(&self.regs[6..=10]);
                            self.callers.push((next, saved));
                            self.stack[depth] = [0; STACK_SIZE];
                            self.regs[10] = address(frame_region(depth), STACK_SIZE as u64);
                            pc = target(next, i64::from(insn.imm))?;
                        }
                        0x80 => {
                            self.regs[0] = self.call(insn.imm)?;
                            pc = next;
                        }
                        0x90 => match self.callers.pop() {
                            Some((ret, saved)) => {
                                self.regs[6..=10].copy_from_slice(&saved);
                                pc = ret;
                            }
                            None => return Ok(self.regs[0]),
                        },
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
                LD if matches!(insn.code & 0xe0, ABS | IND) => {
                    // bpf_gen_ld_abs: bpf_skb_load_helper_8, _16 or _32 of
                    // the context in R6 and the offset, as an int, and an
                    // exit with R0 = 0 where it fails.
                    if self.regs[6] != address(CONTEXT, 0) || insn.code & 0x18 == DW {
                        return Err(Fault);
                    }
                    let offset = if insn.code & 0xe0 == IND {
                        self.regs[src].wrapping_add(imm)
                    } else {
                        imm
                    };
                    let r0 = self.load(offset as i32, width(insn.code));
                    if (r0 as i64) < 0 {
                        return Ok(0);
                    }
                    self.regs[0] = r0;
                    pc = next;
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
        if region >= CALLEES {
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

    /// The stack of the frame whose region is `region`.
    fn frame(&mut self, region: u64) -> Option<&mut [u8; STACK_SIZE]> {
        match region {
            STACK => Some(&mut self.stack[0]),
            r if r > CALLEES && r < DEVICE => Some(&mut self.stack[(r - CALLEES) as usize]),
            _ => None,
        }
    }

    fn read(&self, at: u64, out: &mut [u8]) -> Result<(), Fault> {
        let (region, offset) = self.place(at, out.len())?;
        let end = offset + out.len();
        match region {
            STACK => out.copy_from_slice(self.stack[0].get(offset..end).ok_or(Fault)?),
            r if r > CALLEES && r < DEVICE => out.copy_from_slice(
                self.stack[(r - CALLEES) as usize]
                    .get(offset..end)
                    .ok_or(Fault)?,
            ),
            CONTEXT => out.copy_from_slice(self.context.get(offset..end).ok_or(Fault)?),
            PACKET => out.copy_from_slice(self.packet.head().get(offset..end).ok_or(Fault)?),
            DEVICE => {
                let (index, kind) = self.packet.skb.device.ok_or(Fault)?;
                let mut device = [0; 8];
                device[..4].copy_from_slice(&index.to_le_bytes());
                let at = classic::field::DEV_TYPE as usize;
                device[at..at + 2].copy_from_slice(&kind.to_le_bytes());
                out.copy_from_slice(device.get(offset..end).ok_or(Fault)?);
            }
            r if (VALUES..CALLEES).contains(&r) => {
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
        if let Some(frame) = self.frame(region) {
            frame
                .get_mut(offset..end)
                .ok_or(Fault)?
                .copy_from_slice(bytes);
            return Ok(());
        }
        match region {
            // Only `cb[]` is written.
            CONTEXT if offset >= CB.start && end <= CB.end => {
                self.context[offset..end].copy_from_slice(bytes)
            }
            r if (VALUES..CALLEES).contains(&r) => {
                let value = self.values.get((r - VALUES) as usize).ok_or(Fault)?;
                value.write(offset, bytes).map_err(|_| Fault)?;
            }
            _ => return Err(Fault),
        }
        Ok(())
    }

    /// A `BPF_ATOMIC`, as `___bpf_prog_run` runs it.
    ///
    /// `BPF_LOAD_ACQ` loads the destination from the memory at the source,
    /// zero-extended, and `BPF_STORE_REL` stores the source's lower bytes
    /// at the destination, of any size. Each is one read or write, which
    /// for a map's value is under the value's lock, so it is ordered with
    /// every other access to the value as an acquire or a release is.
    ///
    /// The others, of 4 or 8 bytes: the operation with the source, or with
    /// `BPF_CMPXCHG` the source in place of a value equal to R0's. The old
    /// value, zero-extended from 32 bits, goes to the source with
    /// `BPF_FETCH` and to R0 with `BPF_CMPXCHG`.
    fn atomic(&mut self, insn: Insn, dst: usize, src: usize) -> Result<(), Fault> {
        let size = width(insn.code);
        match insn.imm {
            0x100 => {
                let at = self.regs[src].wrapping_add(i64::from(insn.off) as u64);
                let mut bytes = [0; 8];
                self.read(at, &mut bytes[..size])?;
                self.regs[dst] = u64::from_le_bytes(bytes);
                return Ok(());
            }
            0x110 => {
                let at = self.regs[dst].wrapping_add(i64::from(insn.off) as u64);
                let v = self.regs[src];
                return self.write(at, &v.to_le_bytes()[..size]);
            }
            _ => {}
        }
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
        let old = if let Some(frame) = self.frame(region) {
            let place = frame.get_mut(offset..offset + size).ok_or(Fault)?;
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
                // From the MAC header (`BPF_HDR_START_MAC`), if one is
                // set, or the network header (`BPF_HDR_START_NET`), to the
                // linear part's end; anything else is EFAULT.
                let start = match r5 as u32 {
                    0 => self.packet.mac,
                    1 => Some(self.packet.network),
                    _ => None,
                };
                let bytes = start
                    .filter(|_| offset <= 0xffff)
                    .and_then(|start| self.packet.header_bytes(start, offset as usize, len, false));
                self.give(r3, len, bytes.as_deref())?
            }
            classic::NLATTR | classic::NLATTR_NEST => {
                self.context_arg()?;
                self.nlattr(r2 as u32, r3 as u32, id == classic::NLATTR_NEST)
            }
            classic::PAY_OFFSET => {
                self.context_arg()?;
                u64::from(self.packet.skb.payload_offset)
            }
            classic::CPU => u64::from(self.kernel.processor()),
            classic::RANDOM => u64::from(self.kernel.random()),
            _ => return Err(Fault),
        })
    }

    /// `bpf_skb_load_helper_8`, `_16` and `_32`: the packet's `size` bytes
    /// at `offset`, big-endian, from the data, or for a negative one from
    /// the network header (`SKF_NET_OFF`) or the MAC header, if one is set
    /// (`SKF_LL_OFF`), as `bpf_skb_load_helper_convert_offset` takes it
    /// and `skb_copy_bits` reads it, to the packet's end; `-EFAULT` past
    /// the end, or for no header.
    fn load(&self, offset: i32, size: usize) -> u64 {
        let bytes = match offset {
            o if o >= 0 => {
                let o = o as usize;
                self.packet
                    .data
                    .get(o..o.saturating_add(size))
                    .map(<[u8]>::to_vec)
            }
            o if o >= NET_OFF => {
                self.packet
                    .header_bytes(self.packet.network, (o - NET_OFF) as usize, size, true)
            }
            o if o >= LL_OFF => self.packet.mac.and_then(|mac| {
                self.packet
                    .header_bytes(mac, (o - LL_OFF) as usize, size, true)
            }),
            _ => None,
        };
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
        let packet = Packet::message(data, data.len());
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
    fn load_acquire_and_store_release_move_bytes_as_linux_s_do() {
        let m = 0x8877_6655_4433_2211_u64;
        let s = 0xffee_ddcc_bbaa_9988_u64;
        let ld = |r: u8, v: u64| {
            [
                i(0x18, r, 0, 0, v as u32 as i32),
                i(0, 0, 0, 0, (v >> 32) as u32 as i32),
            ]
        };
        for (code, mask) in [
            (0xd3, 0xff_u64),
            (0xcb, 0xffff),
            (0xc3, 0xffff_ffff),
            (0xdb, u64::MAX),
        ] {
            // The store changes the lower bytes only.
            let mut p = ld(3, m).to_vec();
            p.push(i(0x7b, 10, 3, -8, 0));
            p.extend(ld(2, s));
            p.extend([i(code, 10, 2, -8, 0x110), i(0x79, 0, 10, -8, 0), exit()]);
            assert_eq!(run_on(&p, &[]).unwrap(), m & !mask | s & mask);
            // The load zero-extends into a register that held all ones.
            let mut p = ld(3, m).to_vec();
            p.push(i(0x7b, 10, 3, -8, 0));
            p.extend(ld(0, u64::MAX));
            p.extend([i(code, 0, 10, -8, 0x100), exit()]);
            assert_eq!(run_on(&p, &[]).unwrap(), m & mask);
        }
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
    fn ld_abs_and_ld_ind_load_big_endian_or_return_0() {
        let data: Vec<u8> = (1..=8).collect();
        // R6 = ctx, R7 = 2, R0 = the load, then R0 + 0x100 so that the
        // program's own exit shows.
        let ld = |code: u8, src: u8, imm: i32| {
            let p = [
                i(0xbf, 6, 1, 0, 0),
                i(0xb7, 7, 0, 0, 2),
                i(0xb7, 0, 0, 0, -1),
                i(code, 0, src, 0, imm),
                i(0x07, 0, 0, 0, 0x100),
                exit(),
            ];
            let packet = Packet::message(&data, 3);
            let loads = BTreeMap::new();
            let program = Program {
                insns: &p,
                maps: &[],
                loads: &loads,
            };
            run(&program, &packet, &mut Quiet).unwrap()
        };
        assert_eq!(ld(0x20, 0, 0), 0x0102_0304 + 0x100);
        assert_eq!(ld(0x28, 0, 6), 0x0708 + 0x100);
        assert_eq!(ld(0x30, 0, 7), 0x08 + 0x100);
        assert_eq!(ld(0x30, 0, 8), 0);
        assert_eq!(ld(0x20, 0, 5), 0);
        assert_eq!(ld(0x30, 0, -1), 0);
        // From the network header, the data's start; no MAC header.
        assert_eq!(ld(0x28, 0, -0x10_0000 + 1), 0x0203 + 0x100);
        assert_eq!(ld(0x30, 0, -0x20_0000), 0);
        // R7 + imm, which is an int.
        assert_eq!(ld(0x40, 7, 1), 0x0405_0607 + 0x100);
        assert_eq!(ld(0x50, 7, -2), 0x01 + 0x100);
        assert_eq!(ld(0x50, 7, -3), 0);
        assert_eq!(ld(0x48, 7, -0x10_0000 - 1), 0x0203 + 0x100);
    }

    #[test]
    fn headers_before_the_data_reach_the_linear_part_s_end() {
        let data: Vec<u8> = (1..=8).collect();
        // A MAC header of 2 bytes and a network header of 2 before the
        // data, of which 3 bytes are linear.
        let headers = [0x0a, 0x0b, 0x0c, 0x0d];
        let skb = Skb {
            protocol: [0x08, 0x00],
            device: Some((7, 772)),
            ..Skb::default()
        };
        let run_one = |p: &[Insn]| {
            let packet = Packet {
                data: &data,
                linear: 3,
                headers: &headers,
                mac: Some(0),
                network: 2,
                skb,
            };
            let loads = BTreeMap::new();
            let program = Program {
                insns: p,
                maps: &[],
                loads: &loads,
            };
            run(&program, &packet, &mut Quiet).unwrap()
        };
        // R6 = ctx, R0 = the load + 0x100, or 0.
        let ld = |code: u8, imm: i32| {
            run_one(&[
                i(0xbf, 6, 1, 0, 0),
                i(code, 0, 0, 0, imm),
                i(0x07, 0, 0, 0, 0x100),
                exit(),
            ])
        };
        assert_eq!(ld(0x30, -0x10_0000), 0x0c + 0x100);
        assert_eq!(ld(0x30, -0x10_0000 + 2), 0x01 + 0x100);
        assert_eq!(ld(0x30, -0x10_0000 + 4), 0x03 + 0x100);
        // Past the linear part too, to the packet's end.
        assert_eq!(ld(0x30, -0x10_0000 + 9), 0x08 + 0x100);
        assert_eq!(ld(0x30, -0x10_0000 + 10), 0);
        assert_eq!(ld(0x30, -0x20_0000), 0x0a + 0x100);
        assert_eq!(ld(0x20, -0x20_0000 + 1), 0x0b0c_0d01 + 0x100);
        assert_eq!(ld(0x30, -0x20_0000 - 1), 0);
        // Past the linear part from the data's start is fine.
        assert_eq!(ld(0x30, 7), 0x08 + 0x100);
        // The context's fields, and the device a converted program reads.
        let field = |off: i16| run_one(&[i(0x61, 0, 1, off, 0), exit()]);
        assert_eq!(field(classic::field::PROTOCOL), 8);
        assert_eq!(field(classic::field::IFINDEX), 7);
        let device = |off: i16| {
            run_one(&[
                i(0x79, 2, 1, classic::field::DEV, 0),
                i(0x69, 0, 2, off, 0),
                exit(),
            ])
        };
        assert_eq!(device(0), 7);
        assert_eq!(device(classic::field::DEV_TYPE), 772);
    }

    #[test]
    fn calls_have_frames_of_their_own() {
        let call = |by: i32| i(0x85, 0, 1, 0, by);
        // R1 in, R0 out, R6 kept across the call.
        let p = [
            i(0xb7, 6, 0, 0, 10),
            i(0xb7, 1, 0, 0, 3),
            call(2),
            i(0x0f, 0, 6, 0, 0),
            exit(),
            i(0xbf, 0, 1, 0, 0),
            i(0x27, 0, 0, 0, 2),
            i(0xb7, 6, 0, 0, 99),
            exit(),
        ];
        assert_eq!(run_on(&p, &[]).unwrap(), 16);
        // A pointer to the caller's stack, and the callee's own.
        let p = [
            i(0x7a, 10, 0, -8, 5),
            i(0xbf, 1, 10, 0, 0),
            i(0x07, 1, 0, 0, -8),
            call(2),
            i(0x79, 0, 10, -8, 0),
            exit(),
            i(0x7a, 10, 0, -8, 100),
            i(0x79, 2, 1, 0, 0),
            i(0x07, 2, 0, 0, 1),
            i(0x7b, 1, 2, 0, 0),
            i(0x79, 0, 10, -8, 0),
            exit(),
        ];
        assert_eq!(run_on(&p, &[]).unwrap(), 6);
        // Seven calls deep, each frame's slot its own: the main program's
        // R0 is 1 + 2 + ... + 8.
        let mut p = Vec::new();
        for f in 0..8 {
            p.push(i(0x7a, 10, 0, -8, f + 1));
            if f < 7 {
                p.push(call(3));
            } else {
                p.push(i(0xb7, 0, 0, 0, 0));
            }
            p.push(i(0x79, 1, 10, -8, 0));
            p.push(i(0x0f, 0, 1, 0, 0));
            p.push(exit());
        }
        assert_eq!(run_on(&p, &[]).unwrap(), 36);
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
    /// atomics, load-acquires, store-releases, packet loads, the helpers
    /// without maps and calls of a function, and every one it takes runs on
    /// packets of a few lengths without a load or store outside what it
    /// points to.
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
        let (mut taken, mut atomics, mut ordered, mut packet_loads, mut calls) = (0, 0, 0, 0, 0);
        for _ in 0..120_000 {
            let mut p = vec![i(0xbf, 6, 1, 0, 0)];
            // The calls of the function after the main program, whose
            // offsets are known once it is.
            let mut sites = Vec::new();
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
                let insn = match next(16) {
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
                            0x00, 0x01, 0x40, 0x41, 0x50, 0x51, 0xa0, 0xa1, 0xe1, 0xf1, 0x03,
                        ][next(11) as usize],
                    ),
                    // A load-acquire or store-release of any size, mostly
                    // of the stack, sometimes misaligned.
                    12 => {
                        let base = if next(8) == 0 { 6 } else { 10 };
                        if next(2) == 0 {
                            i(0xc3 | size, dst, base, at, 0x100)
                        } else {
                            i(0xc3 | size, base, src, at, 0x110)
                        }
                    }
                    // A BPF_LD_ABS or BPF_LD_IND of 1, 2 or 4 bytes, in the
                    // packet, past it, or from the network or MAC header.
                    13 => {
                        let mode = [0x20, 0x40][next(2) as usize];
                        let size = [0x00, 0x08, 0x10][next(3) as usize];
                        let src = if mode == 0x40 { src } else { 0 };
                        let imm =
                            [0, 1, 6, 63, 64, -1, -0x10_0000, -0x20_0000, imm][next(9) as usize];
                        i(mode | size, 0, src, 0, imm)
                    }
                    // A call of the function, sometimes with a pointer to
                    // the caller's stack in R1.
                    14 => {
                        if next(2) == 0 {
                            p.push(i(0xbf, 1, 10, 0, 0));
                            p.push(i(0x07, 1, 0, 0, -8 * (1 + next(64) as i32)));
                        }
                        sites.push(p.len());
                        i(0x85, 0, 1, 0, 0)
                    }
                    _ => i(0x85, 0, 0, 0, [5, 7, 8, 14, 15, 46, 47][next(7) as usize]),
                };
                p.push(insn);
            }
            p.push(i(0xb7, 0, 0, 0, 1));
            p.push(exit());
            if !sites.is_empty() {
                let start = p.len();
                for &site in &sites {
                    p[site].imm = (start - site - 1) as i32;
                }
                // The function: its own stack, its caller's through R1, a
                // helper, and R0.
                let at = -8 * (1 + next(64) as i16) + next(8) as i16;
                let size = [0x18, 0x00, 0x08, 0x10][next(4) as usize];
                for _ in 0..1 + next(4) {
                    p.push(match next(6) {
                        0 => i(0x62 | size, 10, 0, at, 7),
                        1 => i(0x61 | size, 0, 10, at, 0),
                        2 => i(0x61 | size, 0, 1, [0, -4, 8][next(3) as usize], 0),
                        3 => i(0x63 | size, 1, 1, 0, 0),
                        4 => i(0x85, 0, 0, 0, 7),
                        _ => i(0xbf, 6, 1, 0, 0),
                    });
                }
                p.push(i(0xb7, 0, 0, 0, next(3) as i32));
                p.push(exit());
            }
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
            if p.iter()
                .any(|insn| insn.code & 0xe7 == STX | ATOMIC && insn.imm & 0x100 != 0)
            {
                ordered += 1;
            }
            if p.iter().any(|insn| matches!(insn.code & 0xe7, 0x20 | 0x40)) {
                packet_loads += 1;
            }
            if !sites.is_empty() {
                calls += 1;
            }
            for len in [0, 1, 7, 64] {
                let data = vec![0x5a; len];
                let program = Program {
                    insns: &p,
                    maps: &[],
                    loads: &verified.loads,
                };
                let packet = Packet::message(&data, data.len());
                assert!(
                    run(&program, &packet, &mut Quiet).is_ok(),
                    "{p:?} faulted on {len} bytes"
                );
            }
        }
        // Enough of them load for the check to mean something: 6,362 with
        // this seed and this verifier, 536 of them with an atomic, 378 with
        // a load-acquire or store-release, 951 with a BPF_LD_ABS or
        // BPF_LD_IND and 479 with a call. A change to either that loads
        // fewer than 6,000, fewer than 150 with an atomic, fewer than 300
        // with a load-acquire or store-release, fewer than 800 with a
        // packet load or fewer than 300 with a call, should look again at
        // what the programs cover.
        assert!(taken >= 6_000, "only {taken} programs loaded");
        assert!(
            atomics >= 150,
            "only {atomics} programs with an atomic loaded"
        );
        assert!(
            ordered >= 300,
            "only {ordered} programs with a load-acquire or store-release loaded"
        );
        assert!(
            packet_loads >= 800,
            "only {packet_loads} programs with a BPF_LD_ABS or BPF_LD_IND loaded"
        );
        assert!(calls >= 300, "only {calls} programs with a call loaded");
    }
}
