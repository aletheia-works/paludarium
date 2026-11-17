//! `BPF_PROG_LOAD`'s checks of its arguments, in the order of Linux's
//! `bpf_prog_load` (`kernel/bpf/syscall.c`), which is the same there in the
//! x86-64 test machines' kernel (Ubuntu's Linux 7.0) and in master, with
//! their errors. No program is ever loaded: the emulator has no verifier
//! and runs no BPF, so a load that passes every check here is refused with
//! `EINVAL`, as a kernel built without the program's type refuses it
//! (`find_prog_type` finds no ops), which is the check where a real
//! kernel would go on to make the program.
//!
//! What the order means for a caller: a permission error, a size error or
//! a fault comes back exactly as Linux gives it; only a program that Linux
//! would go on to verify gets `EINVAL` where Linux would load it or give
//! the verifier's error.
use crate::syscalls::Context;
use paludarium_types::{Errno, GuestAddr};

const E2BIG: Errno = Errno(7);
const CAP_NET_ADMIN: u64 = 1 << 12;
const CAP_SYS_ADMIN: u64 = 1 << 21;
const CAP_PERFMON: u64 = 1 << 38;
const CAP_BPF: u64 = 1 << 39;

/// `BPF_PROG_LOAD`'s last field, `keyring_id`, ends the union: every byte
/// of it is a field (`BPF_PROG_LOAD_LAST_FIELD`).
const LAST_FIELD_END: usize = 168;

/// The program flags `bpf_prog_load` takes.
mod flag {
    pub const STRICT_ALIGNMENT: u32 = 1 << 0;
    pub const ANY_ALIGNMENT: u32 = 1 << 1;
    pub const TEST_RND_HI32: u32 = 1 << 2;
    pub const TEST_STATE_FREQ: u32 = 1 << 3;
    pub const SLEEPABLE: u32 = 1 << 4;
    pub const XDP_HAS_FRAGS: u32 = 1 << 5;
    pub const XDP_DEV_BOUND_ONLY: u32 = 1 << 6;
    pub const TEST_REG_INVARIANTS: u32 = 1 << 7;
    pub const TOKEN_FD: u32 = 1 << 16;
    pub const KNOWN: u32 = STRICT_ALIGNMENT
        | ANY_ALIGNMENT
        | TEST_STATE_FREQ
        | SLEEPABLE
        | TEST_RND_HI32
        | XDP_HAS_FRAGS
        | XDP_DEV_BOUND_ONLY
        | TEST_REG_INVARIANTS
        | TOKEN_FD;
}

/// `BPF_MAXINSNS`, without `CAP_BPF`, and `BPF_COMPLEXITY_LIMIT_INSNS`,
/// with it.
const MAX_INSNS: u32 = 4096;
const COMPLEXITY_LIMIT_INSNS: u32 = 1_000_000;
/// The size of one instruction, `struct bpf_insn`.
const INSN_SIZE: u64 = 8;
/// The license buffer, of which `bpf_prog_load` copies up to one byte less.
const LICENSE: usize = 128;

/// `enum bpf_prog_type`.
mod kind {
    pub const SOCKET_FILTER: u32 = 1;
    pub const KPROBE: u32 = 2;
    pub const SCHED_CLS: u32 = 3;
    pub const SCHED_ACT: u32 = 4;
    pub const TRACEPOINT: u32 = 5;
    pub const XDP: u32 = 6;
    pub const PERF_EVENT: u32 = 7;
    pub const CGROUP_SKB: u32 = 8;
    pub const CGROUP_SOCK: u32 = 9;
    pub const LWT_IN: u32 = 10;
    pub const LWT_OUT: u32 = 11;
    pub const LWT_XMIT: u32 = 12;
    pub const SOCK_OPS: u32 = 13;
    pub const SK_SKB: u32 = 14;
    pub const CGROUP_DEVICE: u32 = 15;
    pub const SK_MSG: u32 = 16;
    pub const RAW_TRACEPOINT: u32 = 17;
    pub const CGROUP_SOCK_ADDR: u32 = 18;
    pub const LWT_SEG6LOCAL: u32 = 19;
    pub const FLOW_DISSECTOR: u32 = 22;
    pub const CGROUP_SYSCTL: u32 = 23;
    pub const RAW_TRACEPOINT_WRITABLE: u32 = 24;
    pub const CGROUP_SOCKOPT: u32 = 25;
    pub const TRACING: u32 = 26;
    pub const STRUCT_OPS: u32 = 27;
    pub const EXT: u32 = 28;
    pub const LSM: u32 = 29;
    pub const NETFILTER: u32 = 32;
}

fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]))
}
fn half(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap_or([0; 4]))
}

/// `bpf_token_capable` without a token: the capability, or `CAP_SYS_ADMIN`
/// in its place (`bpf_ns_capable`).
fn capable(c: &Context<'_>, cap: u64) -> bool {
    let credentials = &c.process.credentials;
    credentials.capable(cap) || credentials.capable(CAP_SYS_ADMIN)
}

/// `is_net_admin_prog_type`: the types that also need `CAP_NET_ADMIN`.
fn net_admin(kind: u32) -> bool {
    matches!(
        kind,
        kind::SCHED_CLS
            | kind::SCHED_ACT
            | kind::XDP
            | kind::LWT_IN
            | kind::LWT_OUT
            | kind::LWT_XMIT
            | kind::LWT_SEG6LOCAL
            | kind::SK_SKB
            | kind::SK_MSG
            | kind::FLOW_DISSECTOR
            | kind::CGROUP_DEVICE
            | kind::CGROUP_SOCK
            | kind::CGROUP_SOCK_ADDR
            | kind::CGROUP_SOCKOPT
            | kind::CGROUP_SYSCTL
            | kind::SOCK_OPS
            | kind::EXT
            | kind::NETFILTER
    )
}

/// `is_perfmon_prog_type`: the types that also need `CAP_PERFMON`.
fn perfmon(kind: u32) -> bool {
    matches!(
        kind,
        kind::KPROBE
            | kind::TRACEPOINT
            | kind::PERF_EVENT
            | kind::RAW_TRACEPOINT
            | kind::RAW_TRACEPOINT_WRITABLE
            | kind::TRACING
            | kind::LSM
            | kind::STRUCT_OPS
            | kind::EXT
    )
}

/// What a descriptor that must be a BPF object is, for one that is not:
/// `EBADF` for no descriptor, `EINVAL` for another file
/// (`bpf_token_get_from_fd`, `btf_get_by_fd`).
fn not_an_object(c: &Context<'_>, fd: u32) -> Errno {
    match c.files.descriptor(u64::from(fd)) {
        Ok(_) => Errno::EINVAL,
        Err(e) => e,
    }
}

/// `copy_from_bpfptr` of the instructions: `EFAULT` unless every byte can
/// be read. Read a page at a time, as the count may be large.
fn readable(c: &Context<'_>, at: u64, len: u64) -> Result<(), Errno> {
    let mut chunk = [0; 4096];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(chunk.len() as u64);
        c.mem
            .read(GuestAddr(at.wrapping_add(done)), &mut chunk[..n as usize])
            .map_err(|_| Errno::EFAULT)?;
        done += n;
    }
    Ok(())
}

/// `strncpy_from_bpfptr` of the license, up to `LICENSE - 1` bytes:
/// `EFAULT` for a byte before its end that cannot be read.
fn license(c: &Context<'_>, at: u64) -> Result<(), Errno> {
    for i in 0..LICENSE as u64 - 1 {
        let mut byte = [0];
        c.mem
            .read(GuestAddr(at.wrapping_add(i)), &mut byte)
            .map_err(|_| Errno::EFAULT)?;
        if byte[0] == 0 {
            break;
        }
    }
    Ok(())
}

/// `BPF_PROG_LOAD`, in the order of Linux's `bpf_prog_load`.
pub(crate) fn load(c: &mut Context<'_>, attr: &[u8]) -> Result<u64, Errno> {
    let kind = half(attr, 0);
    let insn_cnt = half(attr, 4);
    let insns = word(attr, 8);
    let license_at = word(attr, 16);
    let prog_flags = half(attr, 44);
    let attach_btf_id = half(attr, 108);
    let attach_prog_fd = half(attr, 112);
    let token_fd = half(attr, 144);

    crate::bpf::check_attr(attr, LAST_FIELD_END)?;
    if prog_flags & !flag::KNOWN != 0 {
        return Err(Errno::EINVAL);
    }
    // A token would grant what it allows in place of the capabilities;
    // the emulator has none, so any descriptor here is not one.
    if prog_flags & flag::TOKEN_FD != 0 {
        return Err(not_an_object(c, token_fd));
    }
    let bpf_cap = capable(c, CAP_BPF);
    // x86-64 has efficient unaligned access, so BPF_F_ANY_ALIGNMENT needs
    // no capability.
    if c.processes.sysctls.unprivileged_bpf_disabled() != 0 && !bpf_cap {
        return Err(Errno::EPERM);
    }
    let limit = if bpf_cap {
        COMPLEXITY_LIMIT_INSNS
    } else {
        MAX_INSNS
    };
    if insn_cnt == 0 || insn_cnt > limit {
        return Err(E2BIG);
    }
    if kind != kind::SOCKET_FILTER && kind != kind::CGROUP_SKB && !bpf_cap {
        return Err(Errno::EPERM);
    }
    if net_admin(kind) && !capable(c, CAP_NET_ADMIN) {
        return Err(Errno::EPERM);
    }
    if perfmon(kind) && !capable(c, CAP_PERFMON) {
        return Err(Errno::EPERM);
    }
    // An attach_prog_fd that is no program is taken as a BTF object's
    // descriptor, and the emulator has none (EINVAL either way); an
    // attach_btf_id needs BTF, and a type that is not a tracing one may
    // not have it (bpf_prog_load_check_attach).
    if attach_prog_fd != 0 || attach_btf_id != 0 {
        return Err(Errno::EINVAL);
    }
    readable(c, insns, u64::from(insn_cnt) * INSN_SIZE)?;
    license(c, license_at)?;
    // find_prog_type: no type has ops here, so the load ends as on a
    // kernel built without the program's type. A type Linux does not
    // know is EINVAL at the same check; the program's name and the
    // verifier's arguments, which come after it, are not reached.
    Err(Errno::EINVAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_capability_lists_are_linuxs() {
        assert!(net_admin(kind::XDP) && net_admin(kind::EXT) && net_admin(kind::NETFILTER));
        assert!(!net_admin(kind::SOCKET_FILTER) && !net_admin(kind::CGROUP_SKB));
        // SK_REUSEPORT (21) needs CAP_BPF only.
        assert!(!net_admin(21) && !perfmon(21));
        assert!(perfmon(kind::KPROBE) && perfmon(kind::EXT) && !perfmon(kind::XDP));
    }

    #[test]
    fn the_known_flags_are_linuxs() {
        assert_eq!(flag::KNOWN, 0x1_00ff);
    }
}
