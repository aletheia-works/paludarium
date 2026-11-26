//! The options of multicast memberships and their source filters
//! (`IP_ADD_SOURCE_MEMBERSHIP` and the like, `IP_MSFILTER`, and the
//! `MCAST_` ones of both families), which TCP sockets take too.

use super::{Context, InetSocket};
use crate::multicast::{
    Filter, MAX_SOURCES4, MAX_SOURCES6, Membership, Membership6, Mode, filter_of6,
};
use core::net::{Ipv4Addr, Ipv6Addr};
use paludarium_types::{Errno, GuestAddr};

const EADDRINUSE: Errno = Errno(98);
const EADDRNOTAVAIL: Errno = Errno(99);
const ENOBUFS: Errno = Errno(105);
const ENOPROTOOPT: Errno = Errno(92);

const IP_UNBLOCK_SOURCE: u64 = 37;
const IP_BLOCK_SOURCE: u64 = 38;
const IP_ADD_SOURCE_MEMBERSHIP: u64 = 39;
const IP_DROP_SOURCE_MEMBERSHIP: u64 = 40;
const IP_MSFILTER: u64 = 41;
const MCAST_JOIN_GROUP: u64 = 42;
const MCAST_BLOCK_SOURCE: u64 = 43;
const MCAST_UNBLOCK_SOURCE: u64 = 44;
const MCAST_LEAVE_GROUP: u64 = 45;
const MCAST_JOIN_SOURCE_GROUP: u64 = 46;
const MCAST_LEAVE_SOURCE_GROUP: u64 = 47;
const MCAST_MSFILTER: u64 = 48;

/// `net.core.optmem_max`.
const OPTMEM_MAX: usize = 128 << 10;
/// A `sockaddr_storage`.
const STORAGE: usize = 128;
/// A `group_filter` and an `ip_msfilter` of no sources.
const GROUP_FILTER: usize = 144;
const MSFILTER: usize = 16;

fn read(c: &Context<'_>, at: u64, len: usize) -> Result<Vec<u8>, Errno> {
    let mut raw = vec![0; len];
    c.mem
        .read(GuestAddr(at), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    Ok(raw)
}
/// The bytes of `raw` at `at`, all of which an option has read.
fn bytes<const N: usize>(raw: &[u8], at: usize) -> [u8; N] {
    raw.get(at..at + N)
        .and_then(|b| b.try_into().ok())
        .unwrap_or([0; N])
}
fn word(raw: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes(raw, at))
}
/// The IPv4 or IPv6 address of the `sockaddr` at `at`, none of another
/// family.
fn address4(raw: &[u8], at: usize) -> Option<Ipv4Addr> {
    (u16::from_le_bytes(bytes(raw, at)) == 2).then(|| bytes::<4>(raw, at + 4).into())
}
fn address6(raw: &[u8], at: usize) -> Option<Ipv6Addr> {
    (u16::from_le_bytes(bytes(raw, at)) == 10).then(|| bytes6(raw, at))
}
fn bytes6(raw: &[u8], at: usize) -> Ipv6Addr {
    bytes::<16>(raw, at + 8).into()
}
/// Whether a source option adds, and to a filter of which mode; none for
/// another option.
fn source_option(name: u64) -> Option<(bool, Mode)> {
    match name {
        IP_BLOCK_SOURCE | MCAST_BLOCK_SOURCE => Some((true, Mode::Exclude)),
        IP_UNBLOCK_SOURCE | MCAST_UNBLOCK_SOURCE => Some((false, Mode::Exclude)),
        IP_ADD_SOURCE_MEMBERSHIP | MCAST_JOIN_SOURCE_GROUP => Some((true, Mode::Include)),
        IP_DROP_SOURCE_MEMBERSHIP | MCAST_LEAVE_SOURCE_GROUP => Some((false, Mode::Include)),
        _ => None,
    }
}
/// Reads a filter of `len` bytes with `fixed` before its sources, `each` of
/// them, as many as its word at `count` says: `EINVAL` for a shorter one or
/// one too short for them, `ENOBUFS` for one past `net.core.optmem_max` or
/// of more than `most`.
fn read_filter(
    c: &Context<'_>,
    (at, len): (u64, usize),
    (fixed, count, each): (usize, usize, usize),
    most: u32,
) -> Result<Vec<u8>, Errno> {
    if len < fixed {
        return Err(Errno::EINVAL);
    }
    if len > OPTMEM_MAX {
        return Err(ENOBUFS);
    }
    let raw = read(c, at, len)?;
    let sources = word(&raw, count);
    if sources > most {
        return Err(ENOBUFS);
    }
    let size = fixed + sources as usize * each;
    if size > len {
        return Err(Errno::EINVAL);
    }
    Ok(raw[..size].to_vec())
}

/// Sets one of IPv4's, as `do_ip_setsockopt` does.
pub(super) fn set4(
    c: &Context<'_>,
    socket: &InetSocket,
    name: u64,
    (at, len): (u64, u64),
) -> Result<(), Errno> {
    let len = usize::try_from(len as u32 as i32).map_err(|_| Errno::EINVAL)?;
    let network = &socket.network;
    let by_index = |group: Ipv4Addr, index: u32| Membership {
        group,
        address: Ipv4Addr::UNSPECIFIED,
        index: index.cast_signed(),
    };
    // A socket joins first with a source, which it may have done already.
    let source = |asked: Membership, source: Ipv4Addr| {
        let change = source_option(name).ok_or(ENOPROTOOPT)?;
        let now = socket.now();
        let mut s = socket.lock();
        if change == (true, Mode::Include) {
            match network.join4(&mut s.groups4, asked, Mode::Include, now) {
                Ok(()) | Err(EADDRINUSE) => {}
                Err(e) => return Err(e),
            }
        }
        network.source4(&mut s.groups4, asked, change, source, now)
    };
    match name {
        MCAST_JOIN_GROUP | MCAST_LEAVE_GROUP => {
            if len < 8 + STORAGE {
                return Err(Errno::EINVAL);
            }
            let raw = read(c, at, 8 + STORAGE)?;
            let group = address4(&raw, 8).ok_or(Errno::EINVAL)?;
            let asked = by_index(group, word(&raw, 0));
            let now = socket.now();
            let mut s = socket.lock();
            if name == MCAST_JOIN_GROUP {
                network.join4(&mut s.groups4, asked, Mode::Exclude, now)
            } else {
                network.leave4(&mut s.groups4, asked, now)
            }
        }
        IP_MSFILTER => {
            let raw = read_filter(c, (at, len), (MSFILTER, 12, 4), MAX_SOURCES4)?;
            let asked = Membership::read(&raw[..8]);
            let sources = raw[MSFILTER..].chunks(4).map(|s| bytes::<4>(s, 0).into());
            let now = socket.now();
            let mut s = socket.lock();
            network.filter4(&mut s.groups4, asked, word(&raw, 8), sources.collect(), now)
        }
        MCAST_MSFILTER => {
            let raw = read_filter(c, (at, len), (GROUP_FILTER, 140, STORAGE), MAX_SOURCES4)?;
            let group = address4(&raw, 8).ok_or(EADDRNOTAVAIL)?;
            let sources = raw[GROUP_FILTER..]
                .chunks(STORAGE)
                .map(|s| address4(s, 0))
                .collect::<Option<Vec<_>>>()
                .ok_or(EADDRNOTAVAIL)?;
            let asked = by_index(group, word(&raw, 0));
            let now = socket.now();
            let mut s = socket.lock();
            network.filter4(&mut s.groups4, asked, word(&raw, 136), sources, now)
        }
        IP_UNBLOCK_SOURCE..=IP_DROP_SOURCE_MEMBERSHIP => {
            if len != 12 {
                return Err(Errno::EINVAL);
            }
            let raw = read(c, at, 12)?;
            source(Membership::read(&raw[..8]), bytes::<4>(&raw, 8).into())
        }
        _ => {
            if len != 8 + 2 * STORAGE {
                return Err(Errno::EINVAL);
            }
            let raw = read(c, at, len)?;
            let (Some(group), Some(from)) = (address4(&raw, 8), address4(&raw, 8 + STORAGE)) else {
                return Err(EADDRNOTAVAIL);
            };
            source(by_index(group, word(&raw, 0)), from)
        }
    }
}

/// Sets one of IPv6's, as `do_ipv6_setsockopt` does.
pub(super) fn set6(
    c: &Context<'_>,
    socket: &InetSocket,
    name: u64,
    (at, len): (u64, u64),
) -> Result<(), Errno> {
    let len = usize::try_from(len as u32 as i32).map_err(|_| Errno::EINVAL)?;
    let network = &socket.network;
    let member = |group: Ipv6Addr, raw: &[u8]| Membership6 {
        group,
        index: word(raw, 0).cast_signed(),
    };
    match name {
        MCAST_JOIN_GROUP | MCAST_LEAVE_GROUP => {
            if len < 8 + STORAGE {
                return Err(Errno::EINVAL);
            }
            let raw = read(c, at, 8 + STORAGE)?;
            let asked = member(address6(&raw, 8).ok_or(EADDRNOTAVAIL)?, &raw);
            let now = socket.now();
            let mut s = socket.lock();
            if name == MCAST_JOIN_GROUP {
                network.join6(&mut s.groups6, asked, Mode::Exclude, now)
            } else {
                network.leave6(&mut s.groups6, asked)
            }
        }
        // Its addresses are IPv6 ones, whatever family they say.
        MCAST_MSFILTER => {
            let raw = read_filter(c, (at, len), (GROUP_FILTER, 140, STORAGE), MAX_SOURCES6)?;
            let asked = member(bytes6(&raw, 8), &raw);
            let sources = raw[GROUP_FILTER..].chunks(STORAGE).map(|s| bytes6(s, 0));
            let now = socket.now();
            let mut s = socket.lock();
            network.filter6(
                &mut s.groups6,
                asked,
                word(&raw, 136),
                sources.collect(),
                now,
            )
        }
        _ => {
            if len < 8 + 2 * STORAGE {
                return Err(Errno::EINVAL);
            }
            let raw = read(c, at, 8 + 2 * STORAGE)?;
            let (Some(group), Some(source)) = (address6(&raw, 8), address6(&raw, 8 + STORAGE))
            else {
                return Err(EADDRNOTAVAIL);
            };
            let asked = member(group, &raw);
            let change = source_option(name).ok_or(ENOPROTOOPT)?;
            let now = socket.now();
            let mut s = socket.lock();
            if change == (true, Mode::Include) {
                match network.join6(&mut s.groups6, asked, Mode::Include, now) {
                    Ok(()) | Err(EADDRINUSE) => {}
                    Err(e) => return Err(e),
                }
            }
            network.source6(&mut s.groups6, asked, change, source, now)
        }
    }
}

/// What a filter asked for in `raw`, with its mode and the number of its
/// sources from `mode` on, is answered with: those, and as many sources as
/// `raw` asked for, however little room the option has
/// (`ip_mc_msfget`, `ip_mc_gsfget`, `ip6_mc_msfget`).
fn answer<A: Copy + PartialEq>(
    mut raw: Vec<u8>,
    mode: usize,
    filter: &Filter<A>,
    put: impl Fn(A) -> Vec<u8>,
) -> Vec<u8> {
    let asked = word(&raw, mode + 4) as usize;
    let sources = filter.sources();
    raw[mode..mode + 4].copy_from_slice(&(filter.mode as u32).to_le_bytes());
    raw[mode + 4..mode + 8].copy_from_slice(&(sources.len() as u32).to_le_bytes());
    raw.extend(sources.iter().take(asked).flat_map(|&s| put(s)));
    raw
}
fn storage(family: u16, at: usize, address: &[u8]) -> Vec<u8> {
    let mut raw = vec![0; STORAGE];
    raw[..2].copy_from_slice(&family.to_le_bytes());
    raw[at..at + address.len()].copy_from_slice(address);
    raw
}
/// Writes an option and its length.
fn give(c: &mut Context<'_>, (at, len_at): (u64, u64), value: &[u8]) -> Result<u64, Errno> {
    let len = (value.len() as u32).to_le_bytes();
    c.mem
        .write(GuestAddr(len_at), &len)
        .map_err(|_| Errno::EFAULT)?;
    c.mem
        .write(GuestAddr(at), value)
        .map_err(|_| Errno::EFAULT)?;
    Ok(0)
}
/// `IP_MSFILTER` (`ip_mc_msfget`) or IPv4's `MCAST_MSFILTER`
/// (`ip_get_mcast_msfilter`).
pub(super) fn get4(
    c: &mut Context<'_>,
    socket: &InetSocket,
    name: u64,
    (at, len_at, room): (u64, u64, usize),
) -> Result<u64, Errno> {
    let by_index = name == MCAST_MSFILTER;
    let (size, mode) = if by_index {
        (GROUP_FILTER, 136)
    } else {
        (MSFILTER, 8)
    };
    if room < size {
        return Err(Errno::EINVAL);
    }
    let raw = read(c, at, size)?;
    let asked = if by_index {
        Membership {
            group: address4(&raw, 8).ok_or(Errno::EINVAL)?,
            address: Ipv4Addr::UNSPECIFIED,
            index: word(&raw, 0).cast_signed(),
        }
    } else {
        Membership::read(&raw[..8])
    };
    let value = {
        let now = socket.now();
        let s = socket.lock();
        let filter = socket
            .network
            .filter_of4(&s.groups4, asked, by_index, now)?;
        answer(raw, mode, filter, |source| {
            let source = source.octets();
            if by_index {
                storage(2, 4, &source)
            } else {
                source.to_vec()
            }
        })
    };
    give(c, (at, len_at), &value)
}
/// IPv6's `MCAST_MSFILTER` (`ipv6_get_msfilter`).
pub(super) fn get6(
    c: &mut Context<'_>,
    socket: &InetSocket,
    (at, len_at, room): (u64, u64, usize),
) -> Result<u64, Errno> {
    if room < GROUP_FILTER {
        return Err(Errno::EINVAL);
    }
    let raw = read(c, at, GROUP_FILTER)?;
    let asked = Membership6 {
        group: address6(&raw, 8).ok_or(EADDRNOTAVAIL)?,
        index: word(&raw, 0).cast_signed(),
    };
    let value = {
        let s = socket.lock();
        let filter = filter_of6(&s.groups6, asked)?;
        answer(raw, 136, filter, |source| storage(10, 8, &source.octets()))
    };
    give(c, (at, len_at), &value)
}
