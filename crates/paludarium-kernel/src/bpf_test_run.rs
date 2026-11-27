//! `BPF_PROG_TEST_RUN` of a socket filter, as Linux master's
//! `bpf_prog_test_run` (`kernel/bpf/syscall.c`) and `bpf_prog_test_run_skb`
//! (`net/bpf/test_run.c`) run one: on a packet the caller gives, which
//! starts with an Ethernet header, as the loopback (or the device the
//! context names) receives it, `repeat` times.
//!
//! The packet is the caller's bytes: as many in the linear part as fit in a
//! page with the headroom and tailroom Linux keeps (or as the context's
//! `data_end` says), the rest in pages, of which there may be
//! `MAX_SKB_FRAGS`. `eth_type_trans` takes the Ethernet header off and
//! finds the packet's type and protocol, master's way: with no IPX
//! (6451576b5396), and an IPv4 or IPv6 packet shorter than its header
//! refused (12bec2bd4b76). The program then runs on what follows; what
//! comes back is the packet with the Ethernet header zeroed, and the
//! context's fields Linux gives back (`convert_skb_to___skb`). A socket
//! filter cannot change the packet, so `BPF_F_TEST_SKB_CHECKSUM_COMPLETE`
//! never finds a checksum that differs (`EBADMSG`).
//!
//! What a socket filter reads of the socket (`skb->sk`) is a socket of its
//! own (`bpf_dummy_proto`), whose owner is root of the user namespace that
//! owns the network namespace (`sock_init_data` with no `struct socket`):
//! the overflow ID while that namespace maps no root.

use std::sync::Arc;

use paludarium_types::{Errno, GuestAddr, PAGE_SIZE};

use crate::bpf_interp::{Packet, Skb};
use crate::syscalls::Context;

const EINTR: Errno = Errno(4);
const E2BIG: Errno = Errno(7);
const ENOMEM: Errno = Errno(12);
const ENODEV: Errno = Errno(19);
const ENOSPC: Errno = Errno(28);
/// `ENOTSUPP`, which a program type with no `test_run` gives.
const ENOTSUPP: Errno = Errno(524);

/// Where `attr->test`'s fields are, and the end of the last
/// (`BPF_PROG_TEST_RUN_LAST_FIELD`, `test.batch_size`).
mod field {
    pub const PROG_FD: usize = 0;
    pub const RETVAL: usize = 4;
    pub const DATA_SIZE_IN: usize = 8;
    pub const DATA_SIZE_OUT: usize = 12;
    pub const DATA_IN: usize = 16;
    pub const DATA_OUT: usize = 24;
    pub const REPEAT: usize = 32;
    pub const DURATION: usize = 36;
    pub const CTX_SIZE_IN: usize = 40;
    pub const CTX_SIZE_OUT: usize = 44;
    pub const CTX_IN: usize = 48;
    pub const CTX_OUT: usize = 56;
    pub const FLAGS: usize = 64;
    pub const CPU: usize = 68;
    pub const BATCH_SIZE: usize = 72;
    pub const END: usize = 76;
}

/// The fields of `struct __sk_buff` that the context in and out has.
mod skb {
    pub const SIZE: usize = 192;
    pub const MARK: usize = 8;
    pub const PRIORITY: usize = 32;
    pub const INGRESS_IFINDEX: usize = 36;
    pub const IFINDEX: usize = 40;
    pub const CB: std::ops::Range<usize> = 48..68;
    pub const DATA: usize = 76;
    pub const DATA_END: usize = 80;
    pub const DATA_META: usize = 140;
    pub const WIRE_LEN: usize = 160;
    pub const GSO_SEGS: usize = 164;
    pub const GSO_SIZE: usize = 176;
    /// What `convert___skb_to_skb` takes from the caller: `mark`,
    /// `priority`, `ingress_ifindex`, `ifindex`, `cb[]`, `data_end`,
    /// `tstamp`, `wire_len`, `gso_segs`, `gso_size` and `hwtstamp`. Every
    /// other byte must be 0.
    pub const TAKEN: [std::ops::Range<usize>; 7] =
        [8..12, 32..44, 48..68, 80..84, 152..168, 176..180, 184..192];
}

/// `BPF_F_TEST_SKB_CHECKSUM_COMPLETE`, the one flag a socket filter's run
/// takes.
const F_CHECKSUM_COMPLETE: u32 = 1 << 2;
const ETH_HLEN: usize = 14;
/// What `bpf_prog_test_run_skb` keeps around a linear part, in a page:
/// `NET_SKB_PAD` + `NET_IP_ALIGN` before it (64 on x86-64) and
/// `SKB_DATA_ALIGN(sizeof(struct skb_shared_info))` after it.
const HEADROOM: usize = 64;
const LINEAR_MAX: usize = PAGE_SIZE as usize - HEADROOM - crate::skb::SHARED_INFO;
/// `MAX_SKB_FRAGS`.
const MAX_FRAGS: usize = 17;
/// `GSO_LEGACY_MAX_SIZE` and `GSO_MAX_SEGS`, the bounds of `wire_len` and
/// `gso_segs`.
const GSO_LEGACY_MAX_SIZE: u32 = 65536;
const GSO_MAX_SEGS: u32 = 65535;
/// `ETH_P_IP`, `ETH_P_IPV6`, `ETH_P_802_3_MIN` and `ETH_P_802_2`.
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_802_3_MIN: u16 = 0x0600;
const ETH_P_802_2: u16 = 0x0004;
/// `sizeof(struct iphdr)` and `sizeof(struct ipv6hdr)`.
const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
/// `PACKET_HOST`, `PACKET_BROADCAST`, `PACKET_MULTICAST` and
/// `PACKET_OTHERHOST`.
const HOST: u32 = 0;
const BROADCAST: u32 = 1;
const MULTICAST: u32 = 2;
const OTHERHOST: u32 = 3;
/// `ARPHRD_ETHER` and `ARPHRD_LOOPBACK`.
const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;
/// The loopback's index (`LOOPBACK_IFINDEX`).
const LOOPBACK_INDEX: u32 = 1;

fn half(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap_or_default())
}
fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or_default())
}
fn read(c: &Context<'_>, at: u64, out: &mut [u8]) -> Result<(), Errno> {
    c.mem.read(GuestAddr(at), out).map_err(|_| Errno::EFAULT)
}
fn write(c: &Context<'_>, at: u64, bytes: &[u8]) -> Result<(), Errno> {
    c.mem.write(GuestAddr(at), bytes).map_err(|_| Errno::EFAULT)
}

/// `bpf_prog_test_run`: `attr` from the caller's `at`, whose fields past
/// `batch_size` [`crate::bpf`] has found 0. The context's size and its
/// address go together, in and out (`EINVAL`), then the program
/// (`bpf_prog_get`), whose type must have a test run (`ENOTSUPP`).
pub(crate) fn test_run(c: &mut Context<'_>, attr: &[u8], at: u64) -> Result<u64, Errno> {
    crate::bpf::check_attr(attr, field::END)?;
    let pairs = [
        (field::CTX_SIZE_IN, field::CTX_IN),
        (field::CTX_SIZE_OUT, field::CTX_OUT),
    ];
    if pairs
        .iter()
        .any(|&(size, address)| (half(attr, size) == 0) != (word(attr, address) == 0))
    {
        return Err(Errno::EINVAL);
    }
    let program = crate::bpf_prog::program(c, half(attr, field::PROG_FD))?;
    if !program.is_socket_filter() {
        return Err(ENOTSUPP);
    }
    run_skb(c, &program, attr, at)
}

/// The device a packet comes in on: its index, type, address and
/// broadcast address (`dev_addr` and `broadcast`, which the loopback has
/// all zeros).
struct Device {
    index: u32,
    kind: u16,
    address: [u8; 6],
    broadcast: [u8; 6],
}

impl Device {
    fn loopback() -> Self {
        Self {
            index: LOOPBACK_INDEX,
            kind: ARPHRD_LOOPBACK,
            address: [0; 6],
            broadcast: [0; 6],
        }
    }
}

/// `dev_get_by_index` in the caller's network namespace: `ENODEV` for a
/// device there is not.
fn device(c: &Context<'_>, index: u32) -> Result<Device, Errno> {
    let network = c.network().ok_or(ENODEV)?;
    let devices = network.devices();
    let device = i32::try_from(index)
        .ok()
        .and_then(|index| devices.by_index(index))
        .ok_or(ENODEV)?;
    Ok(match &device.veth {
        Some(veth) => Device {
            index,
            kind: ARPHRD_ETHER,
            address: veth.mac,
            broadcast: [0xff; 6],
        },
        None => Device::loopback(),
    })
}

/// The owner `bpf_get_socket_uid` gives of the run's own socket: root of
/// the user namespace that owns the caller's network namespace
/// (`make_kuid(net->user_ns, 0)`), as that namespace sees it
/// (`from_kuid_munged`): 0, or the overflow ID while it maps no root.
fn lone_owner(c: &Context<'_>) -> u32 {
    let maps_root = c.network().is_none_or(|network| {
        network
            .owner()
            .kernel_of(crate::users::Ids::User, 0)
            .is_some()
    });
    if maps_root { 0 } else { crate::users::OVERFLOW }
}

/// `bpf_prog_test_run_skb` of a socket filter, which is neither an L2
/// program nor one with direct packet access.
fn run_skb(
    c: &mut Context<'_>,
    program: &Arc<crate::bpf_prog::Program>,
    attr: &[u8],
    at: u64,
) -> Result<u64, Errno> {
    let flags = half(attr, field::FLAGS);
    if flags & !F_CHECKSUM_COMPLETE != 0
        || half(attr, field::CPU) != 0
        || half(attr, field::BATCH_SIZE) != 0
    {
        return Err(Errno::EINVAL);
    }
    let size_in = half(attr, field::DATA_SIZE_IN) as usize;
    if size_in < ETH_HLEN {
        return Err(Errno::EINVAL);
    }
    let mut context = context_in(c, attr)?;
    let mut linear = size_in;
    if let Some(ctx) = &context {
        let data_end = half(ctx, skb::DATA_END) as usize;
        if data_end > size_in || half(ctx, skb::DATA) != 0 || half(ctx, skb::DATA_META) != 0 {
            return Err(Errno::EINVAL);
        }
        if data_end != 0 {
            linear = data_end.max(ETH_HLEN);
        }
    }
    let linear = linear.min(LINEAR_MAX);
    // `bpf_test_init` copies the linear part, then each page of the rest
    // comes while there is room for one.
    let data_in = word(attr, field::DATA_IN);
    let mut bytes = vec![0; linear];
    read(c, data_in, &mut bytes)?;
    let mut frags = 0;
    while bytes.len() < size_in {
        if frags == MAX_FRAGS {
            return Err(ENOMEM);
        }
        let take = (size_in - bytes.len()).min(PAGE_SIZE as usize);
        let mut page = vec![0; take];
        read(c, data_in + bytes.len() as u64, &mut page)?;
        bytes.extend(page);
        frags += 1;
    }
    let index = context.as_ref().map_or(0, |ctx| half(ctx, skb::IFINDEX));
    let device = if index > LOOPBACK_INDEX {
        device(c, index)?
    } else {
        Device::loopback()
    };
    let (headers, data) = bytes.split_at(ETH_HLEN);
    let protocol = protocol(headers);
    let head = linear - ETH_HLEN;
    if (protocol == ETH_P_IP && head < IPV4_HEADER)
        || (protocol == ETH_P_IPV6 && head < IPV6_HEADER)
    {
        return Err(Errno::EINVAL);
    }
    let len = data.len() as u32;
    let mut skb = Skb {
        pkt_type: packet_type(headers, &device),
        protocol: protocol.to_be_bytes(),
        device: Some((device.index, device.kind)),
        ..Skb::default()
    };
    let mut wire_len = len;
    if let Some(ctx) = &context {
        wire_len = convert_in(ctx, len, &mut skb)?;
    }
    let packet_of = |skb: Skb| Packet {
        data,
        linear: head,
        headers,
        mac: Some(0),
        network: ETH_HLEN,
        skb,
    };
    let mut kernel = crate::bpf_prog::Receiving {
        host: Some(c.shared_host),
        uid: c.process.credentials.uid,
        gid: c.process.credentials.gid,
        socket: crate::bpf_prog::FilterSocket::Lone(Arc::default()),
        owner: lone_owner(c),
    };
    // `bpf_test_run`: the same packet each time, whose `cb[]` the program
    // may change for the next, until `repeat` runs or a signal comes
    // between them (`bpf_test_timer_continue`).
    let repeat = half(attr, field::REPEAT).max(1);
    let clock = |c: &Context<'_>| {
        c.host
            .clock(paludarium_host::ClockId::Monotonic)
            .unwrap_or(0)
    };
    let start = clock(c);
    let mut retval;
    let mut runs = 0u32;
    loop {
        let (r0, cb) = program.run_with_cb(&packet_of(skb), &mut kernel);
        retval = r0;
        skb.cb = cb;
        runs += 1;
        if runs >= repeat {
            break;
        }
        if crate::events::signalled(c) {
            return Err(EINTR);
        }
    }
    let spent = clock(c).saturating_sub(start) / u64::from(runs);
    let duration = u32::try_from(spent).unwrap_or(u32::MAX);
    let mut out = vec![0; ETH_HLEN];
    out.extend_from_slice(data);
    finish(c, attr, at, &out, linear, (retval, duration))?;
    if let Some(ctx) = &mut context {
        convert_out(ctx, &skb, device.index, wire_len);
        context_finish(c, attr, at, ctx)?;
    }
    Ok(0)
}

/// `bpf_ctx_init`: the context the caller gives, if it gives one in or
/// out, zeroed where it gives none; past `struct __sk_buff` only zeros
/// (`bpf_check_uarg_tail_zero`, `E2BIG`).
fn context_in(c: &Context<'_>, attr: &[u8]) -> Result<Option<[u8; skb::SIZE]>, Errno> {
    let address = word(attr, field::CTX_IN);
    if address == 0 && word(attr, field::CTX_OUT) == 0 {
        return Ok(None);
    }
    let mut ctx = [0; skb::SIZE];
    if address != 0 {
        let size = half(attr, field::CTX_SIZE_IN) as usize;
        if size > PAGE_SIZE as usize {
            return Err(E2BIG);
        }
        if size > skb::SIZE {
            let mut tail = vec![0; size - skb::SIZE];
            read(c, address + skb::SIZE as u64, &mut tail)?;
            if tail.iter().any(|&b| b != 0) {
                return Err(E2BIG);
            }
        }
        read(c, address, &mut ctx[..size.min(skb::SIZE)])?;
    }
    Ok(Some(ctx))
}

/// `eth_type_trans`'s protocol: the Ethernet header's type when it is one
/// (`eth_proto_is_802_3`, which looks at its high byte alone), else
/// `ETH_P_802_2`, as master has it with no IPX (6451576b5396).
fn protocol(header: &[u8]) -> u16 {
    let kind = u16::from_be_bytes([header[12], header[13]]);
    if kind & 0xff00 >= ETH_P_802_3_MIN {
        kind
    } else {
        ETH_P_802_2
    }
}

/// `eth_skb_pkt_type`: the packet's type by its destination.
fn packet_type(header: &[u8], device: &Device) -> u32 {
    let destination = &header[..6];
    if destination == device.address {
        HOST
    } else if destination[0] & 1 == 0 {
        OTHERHOST
    } else if destination == device.broadcast {
        BROADCAST
    } else {
        MULTICAST
    }
}

/// `convert___skb_to_skb`: the fields the context gives the packet, of
/// `len` bytes after its Ethernet header, and its `wire_len`
/// (`qdisc_skb_cb.pkt_len`). A byte of the context outside those fields
/// that is not 0, a `wire_len` shorter than the packet or past
/// `GSO_LEGACY_MAX_SIZE`, and more than `GSO_MAX_SEGS` segments are
/// `EINVAL`.
fn convert_in(ctx: &[u8; skb::SIZE], len: u32, skb: &mut Skb) -> Result<u32, Errno> {
    let taken = |at: usize| skb::TAKEN.iter().any(|range| range.contains(&at));
    if (0..skb::SIZE).any(|at| !taken(at) && ctx[at] != 0) {
        return Err(Errno::EINVAL);
    }
    skb.mark = half(ctx, skb::MARK);
    skb.priority = half(ctx, skb::PRIORITY);
    skb.ingress_ifindex = half(ctx, skb::INGRESS_IFINDEX);
    skb.cb.copy_from_slice(&ctx[skb::CB]);
    let wire_len = match half(ctx, skb::WIRE_LEN) {
        0 => len,
        wire if wire < len || wire > GSO_LEGACY_MAX_SIZE => return Err(Errno::EINVAL),
        wire => wire,
    };
    let segments = half(ctx, skb::GSO_SEGS);
    if segments > GSO_MAX_SEGS {
        return Err(Errno::EINVAL);
    }
    skb.gso = (segments, half(ctx, skb::GSO_SIZE));
    Ok(wire_len)
}

/// `convert_skb_to___skb`: what the context gets back. Its other bytes
/// (`tstamp`, `hwtstamp`, `gso_size` and `data_end` among them) stay as
/// they came, which the program cannot change.
fn convert_out(ctx: &mut [u8; skb::SIZE], skb: &Skb, index: u32, wire_len: u32) {
    let mut put = |at: usize, value: u32| ctx[at..at + 4].copy_from_slice(&value.to_le_bytes());
    put(skb::MARK, skb.mark);
    put(skb::PRIORITY, skb.priority);
    put(skb::INGRESS_IFINDEX, skb.ingress_ifindex);
    put(skb::IFINDEX, index);
    put(skb::WIRE_LEN, wire_len);
    put(skb::GSO_SEGS, skb.gso.0);
    ctx[skb::CB].copy_from_slice(&skb.cb);
}

/// `bpf_test_finish`, as master has it (b5f3534268e3): the packet, as much
/// as `data_size_out` takes if it is not 0 (else `ENOSPC`, once the rest is
/// written), its linear part first, then its pages; then its size, the
/// program's result and the time a run took.
fn finish(
    c: &Context<'_>,
    attr: &[u8],
    at: u64,
    out: &[u8],
    linear: usize,
    (retval, duration): (u32, u32),
) -> Result<(), Errno> {
    let size = out.len();
    let room = half(attr, field::DATA_SIZE_OUT) as usize;
    let mut result = Ok(());
    let mut copy = size;
    if room != 0 && copy > room {
        copy = room;
        result = Err(ENOSPC);
    }
    let address = word(attr, field::DATA_OUT);
    if address != 0 {
        let head = copy.min(linear);
        write(c, address, &out[..head])?;
        let mut offset = head;
        for page in out[linear..].chunks(PAGE_SIZE as usize) {
            if offset >= copy {
                result = Err(ENOSPC);
                break;
            }
            let take = (copy - offset).min(page.len());
            write(c, address + offset as u64, &page[..take])?;
            offset += take;
        }
    }
    write(
        c,
        at + field::DATA_SIZE_OUT as u64,
        &(size as u32).to_le_bytes(),
    )?;
    write(c, at + field::RETVAL as u64, &retval.to_le_bytes())?;
    write(c, at + field::DURATION as u64, &duration.to_le_bytes())?;
    result
}

/// `bpf_ctx_finish`: the context, as much as `ctx_size_out` takes (else
/// `ENOSPC`), and its size.
fn context_finish(c: &Context<'_>, attr: &[u8], at: u64, ctx: &[u8]) -> Result<(), Errno> {
    let address = word(attr, field::CTX_OUT);
    if address == 0 {
        return Ok(());
    }
    let room = half(attr, field::CTX_SIZE_OUT) as usize;
    let copy = ctx.len().min(room);
    write(c, address, &ctx[..copy])?;
    write(
        c,
        at + field::CTX_SIZE_OUT as u64,
        &(ctx.len() as u32).to_le_bytes(),
    )?;
    if copy < ctx.len() {
        Err(ENOSPC)
    } else {
        Ok(())
    }
}
