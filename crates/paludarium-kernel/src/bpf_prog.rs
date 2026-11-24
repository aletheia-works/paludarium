//! `BPF_PROG_LOAD`, in the order of Linux's `bpf_prog_load`
//! (`kernel/bpf/syscall.c`) and its `bpf_check`, with their errors, for
//! `BPF_PROG_TYPE_SOCKET_FILTER`: its arguments, the verifier
//! ([`crate::bpf_verifier`]) with its log, the program's ID and its file
//! (`anon_inode:bpf-prog`) with fdinfo. The order is master's, where the
//! x86-64 test machines' kernel (Ubuntu's Linux 7.0) differs: master
//! checks the log's arguments before all else, 7.0 as the verifier starts.
//!
//! Every other program type Linux knows is refused with `EINVAL`, as a
//! kernel built without it refuses it (`find_prog_type` finds no ops),
//! after the checks of its arguments that come before.
//!
//! A socket filter runs once `SO_ATTACH_BPF` attaches it to an AF_UNIX
//! datagram or packet socket ([`sk_filter`]), in the interpreter
//! ([`crate::bpf_interp`]).
//!
//! Where the emulator refuses what Linux takes (the safe direction):
//! - a loader without `CAP_PERFMON` gets `EPERM` once its program's type
//!   is known, as the verifier here has only the privileged rules (Linux
//!   lets one with `CAP_BPF` alone, or anyone when
//!   `kernel.unprivileged_bpf_disabled` is 0, load a socket filter, and
//!   checks it more strictly);
//! - a BTF object (`prog_btf_fd` with func or line info, or CO-RE
//!   relocations), `fd_array_cnt` and a signature are refused: the
//!   emulator has no BTF objects or keys;
//! - what the verifier does not check yet ([`crate::bpf_verifier`]).
//!
//! The log gets the line of the check that refuses a program and the
//! `processed ... insns` line, not Linux's trace of each instruction (at
//! log level 1) or of each state (level 2), whose text each kernel
//! changes.
use crate::bpf_verifier::{self, Insn, Options};
use crate::syscalls::Context;
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr, PAGE_SIZE};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

const E2BIG: Errno = Errno(7);
const ENOSPC: Errno = Errno(28);
const CAP_NET_ADMIN: u64 = 1 << 12;
const CAP_SYS_ADMIN: u64 = 1 << 21;
const CAP_PERFMON: u64 = 1 << 38;
const CAP_BPF: u64 = 1 << 39;
const O_RDWR: u32 = 2;

/// `BPF_PROG_LOAD`'s last field, `keyring_id`, ends the union: every byte
/// of it is a field (`BPF_PROG_LOAD_LAST_FIELD`).
const LAST_FIELD_END: usize = 168;
/// Where `log_true_size` is, and where it ends.
const LOG_TRUE_SIZE: usize = 140;

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

/// The log levels: `BPF_LOG_LEVEL1`, `BPF_LOG_LEVEL2`, `BPF_LOG_STATS`
/// and `BPF_LOG_FIXED` (`BPF_LOG_MASK`).
mod log_level {
    pub const STATS: u32 = 4;
    pub const FIXED: u32 = 8;
    pub const MASK: u32 = 15;
}

/// `BPF_MAXINSNS`, without `CAP_BPF`, and `BPF_COMPLEXITY_LIMIT_INSNS`,
/// with it.
const MAX_INSNS: u32 = 4096;
const COMPLEXITY_LIMIT_INSNS: u32 = 1_000_000;
/// The size of one instruction, `struct bpf_insn`.
const INSN_SIZE: u64 = 8;
/// The license buffer, of which `bpf_prog_load` copies up to one byte less.
const LICENSE: usize = 128;
/// `offsetof(struct bpf_prog, insns)` on x86-64, in 7.0 and master: the
/// program's memory is that and its instructions, in pages
/// (`bpf_prog_size`).
const PROG_HEADER: u64 = 96;

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

/// Master's `is_tracing_multi` attach types (`BPF_TRACE_FENTRY_MULTI`,
/// `BPF_TRACE_FEXIT_MULTI`, `BPF_TRACE_FSESSION_MULTI`), which only a
/// tracing program may have; 7.0 does not know them.
const TRACING_MULTI: [u32; 3] = [59, 60, 61];

fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]))
}
fn half(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap_or([0; 4]))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
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
fn instructions(c: &Context<'_>, at: u64, count: u32) -> Result<Vec<Insn>, Errno> {
    let len = u64::from(count) * INSN_SIZE;
    let mut bytes = vec![0; len as usize];
    for (i, chunk) in bytes.chunks_mut(PAGE_SIZE as usize).enumerate() {
        c.mem
            .read(GuestAddr(at.wrapping_add(i as u64 * PAGE_SIZE)), chunk)
            .map_err(|_| Errno::EFAULT)?;
    }
    Ok(bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|&b| Insn::decode(b))
        .collect())
}

/// `strncpy_from_bpfptr` of the license, up to `LICENSE - 1` bytes:
/// `EFAULT` for a byte before its end that cannot be read.
fn license(c: &Context<'_>, at: u64) -> Result<Vec<u8>, Errno> {
    let mut text = Vec::new();
    for i in 0..LICENSE as u64 - 1 {
        let mut byte = [0];
        c.mem
            .read(GuestAddr(at.wrapping_add(i)), &mut byte)
            .map_err(|_| Errno::EFAULT)?;
        if byte[0] == 0 {
            break;
        }
        text.push(byte[0]);
    }
    Ok(text)
}

/// `license_is_gpl_compatible`, which decides the `gpl_only` helpers.
fn gpl_compatible(license: &[u8]) -> bool {
    [
        &b"GPL"[..],
        b"GPL v2",
        b"GPL and additional rights",
        b"Dual BSD/GPL",
        b"Dual MIT/GPL",
        b"Dual MPL/GPL",
    ]
    .contains(&license)
}

/// The verifier's log: `log_level`, `log_buf` and `log_size`.
struct Log {
    level: u32,
    buf: u64,
    size: u32,
}

impl Log {
    /// `bpf_verifier_log_attr_valid`: a buffer and its size go together,
    /// a buffer needs a level, and the level and size are bounded
    /// (`EINVAL`).
    fn of(attr: &[u8]) -> Result<Log, Errno> {
        let log = Log {
            level: half(attr, 24),
            size: half(attr, 28),
            buf: word(attr, 32),
        };
        if (log.buf != 0) != (log.size != 0)
            || (log.buf != 0 && log.level == 0)
            || log.level & !log_level::MASK != 0
            || log.size > u32::MAX >> 2
        {
            return Err(Errno::EINVAL);
        }
        Ok(log)
    }

    /// `bpf_vlog_finalize` of `text`: what fits of it is written, its
    /// beginning in a fixed log (`BPF_LOG_FIXED`) and its end in a
    /// rotating one, with a NUL; `ENOSPC` if it did not all fit, and
    /// `EFAULT` if the buffer cannot be written. Gives `log_true_size`.
    fn finish(&self, c: &Context<'_>, text: &[u8]) -> (u32, Result<(), Errno>) {
        if self.level == 0 {
            return (0, Ok(()));
        }
        let len_max = u32::try_from(text.len() + 1).unwrap_or(u32::MAX);
        if self.buf == 0 {
            return (len_max, Ok(()));
        }
        let room = self.size as usize - 1;
        let kept = if text.len() <= room {
            text
        } else if self.level & log_level::FIXED != 0 {
            &text[..room]
        } else {
            &text[text.len() - room..]
        };
        let mut out = kept.to_vec();
        out.push(0);
        if c.mem.write(GuestAddr(self.buf), &out).is_err() {
            return (len_max, Err(Errno::EFAULT));
        }
        if len_max > self.size {
            return (len_max, Err(ENOSPC));
        }
        (len_max, Ok(()))
    }
}

/// `BPF_PROG_LOAD`, in the order of Linux's `bpf_prog_load`. `at` and
/// `size` are the caller's union, where `log_true_size` is written back.
pub(crate) fn load(c: &mut Context<'_>, attr: &[u8], at: u64, size: u32) -> Result<u64, Errno> {
    let kind = half(attr, 0);
    let insn_cnt = half(attr, 4);
    let insns_at = word(attr, 8);
    let license_at = word(attr, 16);
    let prog_flags = half(attr, 44);
    let prog_ifindex = half(attr, 64);
    let expected_attach_type = half(attr, 68);
    let attach_btf_id = half(attr, 108);
    let attach_prog_fd = half(attr, 112);
    let token_fd = half(attr, 144);

    // Master's __sys_bpf checks the log's arguments first.
    let log = Log::of(attr)?;
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
    // attach_btf_id, or one of master's multi-function attach types, needs
    // BTF, and a type that is not a tracing one may have neither
    // (bpf_prog_load_check_attach).
    if attach_prog_fd != 0 || attach_btf_id != 0 || TRACING_MULTI.contains(&expected_attach_type) {
        return Err(Errno::EINVAL);
    }
    let insns = instructions(c, insns_at, insn_cnt)?;
    let gpl = gpl_compatible(&license(c, license_at)?);
    // bpf_prog_dev_bound_init: only XDP and TC programs are bound to a
    // device.
    if prog_ifindex != 0 {
        return Err(Errno::EINVAL);
    }
    // find_prog_type: only a socket filter has ops here. A type Linux does
    // not know is EINVAL at the same check.
    if kind != kind::SOCKET_FILTER {
        return Err(Errno::EINVAL);
    }
    let name = crate::bpf::name(&attr[48..64])?;
    // The verifier here has a privileged loader's rules only.
    if !capable(c, CAP_PERFMON) {
        return Err(Errno::EPERM);
    }
    let options = Options {
        sleepable: prog_flags & flag::SLEEPABLE != 0,
        strict_alignment: prog_flags & flag::STRICT_ALIGNMENT != 0
            && prog_flags & flag::ANY_ALIGNMENT == 0,
        test_reg_invariants: prog_flags & flag::TEST_REG_INVARIANTS != 0,
        fd_array: word(attr, 120) != 0,
        rnd_hi32: prog_flags & flag::TEST_RND_HI32 != 0,
    };
    let (verified, maps) = verify(c, attr, &log, &insns, options, at, size)?;
    let program = c.processes.bpf_progs.publish(|id| Program {
        id,
        kind,
        tag: tag(&insns),
        // bpf_prog_alloc of the instructions as loaded, which the
        // rewrites' bpf_prog_realloc only grows.
        pages: prog_size(insn_cnt as usize)
            .max(prog_size(verified.len))
            .div_ceil(PAGE_SIZE),
        len: verified.len,
        verified: verified.processed,
        gpl,
        name,
        insns,
        maps,
        loads: verified.loads,
        ids: Arc::clone(&c.processes.bpf_progs),
    })?;
    // bpf_prog_new_fd: read and write, close-on-exec.
    c.files
        .install(
            Arc::new(ProgFile {
                program,
                status: Default::default(),
            }),
            true,
            c.group.nofile(),
        )
        .map(u64::from)
}

/// `bpf_check` from the log on: the arguments only the verifier reads,
/// the verifier, and the log with `log_true_size`. Gives the maps the
/// program uses, which it keeps.
fn verify(
    c: &Context<'_>,
    attr: &[u8],
    log: &Log,
    insns: &[Insn],
    options: Options,
    at: u64,
    size: u32,
) -> Result<(bpf_verifier::Verified, Vec<Arc<crate::bpf::Map>>), Errno> {
    let mut lines: Vec<String> = Vec::new();
    let mut named: Vec<(u32, Arc<crate::bpf::Map>)> = Vec::new();
    let mut maps = |fd: i32| {
        let (map, shape) = crate::bpf::program_map(c, fd as u32)?;
        named.push((shape.id, map));
        Ok(shape)
    };
    let result = early(c, attr, insns)
        .and_then(|()| bpf_verifier::check(insns, options, &mut maps))
        .inspect_err(|rejection| {
            if !rejection.line.is_empty() {
                lines.push(rejection.line.clone());
            }
        });
    let (processed, stack_depth, max) = match &result {
        Ok(v) => (v.processed, &v.stack_depth, v.max_stack_depth),
        Err(r) => (r.processed, &r.stack_depth, r.max_stack_depth),
    };
    if log.level & log_level::STATS != 0 {
        lines.push("verification time 0 usec".into());
        // The test machines' 7.0's line: each function's, joined by '+',
        // and the most a chain of calls takes (`max_stack_depth`), which
        // 7.0 as released does not write and master writes on a line of
        // its own.
        let depths: Vec<String> = stack_depth.iter().map(u32::to_string).collect();
        lines.push(format!("stack depth {} max {max}", depths.join("+")));
    }
    // print_verification_stats: the walk keeps no states to prune with.
    lines.push(format!(
        "processed {processed} insns (limit {COMPLEXITY_LIMIT_INSNS}) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0"
    ));
    let mut text = String::new();
    for line in &lines {
        text.push_str(line);
        text.push('\n');
    }
    let (true_size, logged) = log.finish(c, text.as_bytes());
    let mut outcome = result.map_err(|r| r.errno);
    if let Err(e) = logged {
        outcome = Err(e);
    }
    let outcome = outcome.map(|v| {
        let used = v
            .maps
            .iter()
            .filter_map(|id| {
                named
                    .iter()
                    .find(|(i, _)| i == id)
                    .map(|(_, m)| Arc::clone(m))
            })
            .collect();
        (v, used)
    });
    if size as usize >= LOG_TRUE_SIZE + 4
        && c.mem
            .write(
                GuestAddr(at.wrapping_add(LOG_TRUE_SIZE as u64)),
                &true_size.to_le_bytes(),
            )
            .is_err()
    {
        return Err(Errno::EFAULT);
    }
    outcome
}

/// The checks `bpf_check` makes before the instructions: the last one is
/// not half of a BPF_LD_IMM64, then `process_fd_array`, the signature
/// (master's place) and BTF. The emulator has no BTF objects and no keys.
fn early(c: &Context<'_>, attr: &[u8], insns: &[Insn]) -> Result<(), bpf_verifier::Rejection> {
    let refuse = |errno: Errno, line: &str| bpf_verifier::Rejection {
        errno,
        line: line.into(),
        processed: 0,
        stack_depth: vec![0],
        max_stack_depth: 0,
    };
    let fd_array_cnt = half(attr, 148);
    let signature = word(attr, 152);
    let prog_btf_fd = half(attr, 72);
    let func_info_cnt = half(attr, 88);
    let line_info_cnt = half(attr, 104);
    let core_relo_cnt = half(attr, 116);
    if bpf_verifier::ends_in_half(insns) {
        return Err(refuse(Errno::EINVAL, "invalid bpf_ld_imm64 insn"));
    }
    if fd_array_cnt != 0 {
        return Err(refuse(
            Errno::EINVAL,
            "paludarium: fd_array_cnt is not verified yet",
        ));
    }
    if signature != 0 {
        return Err(refuse(
            Errno::EINVAL,
            "paludarium: signed programs are not verified yet",
        ));
    }
    if func_info_cnt != 0 || line_info_cnt != 0 || core_relo_cnt != 0 {
        return Err(refuse(not_an_object(c, prog_btf_fd), ""));
    }
    Ok(())
}

/// `bpf_prog_calc_tag`: the first 8 bytes of the SHA-256 of the
/// instructions, with the descriptors of maps in BPF_LD_IMM64 taken out.
fn tag(insns: &[Insn]) -> [u8; 8] {
    let mut bytes = Vec::with_capacity(insns.len() * 8);
    let mut was_ld_map = false;
    for insn in insns {
        let mut imm = insn.imm;
        if !was_ld_map && insn.code == 0x18 && matches!(insn.src, 1 | 2) {
            was_ld_map = true;
            imm = 0;
        } else if was_ld_map && insn.code == 0 && insn.dst == 0 && insn.src == 0 && insn.off == 0 {
            was_ld_map = false;
            imm = 0;
        } else {
            was_ld_map = false;
        }
        bytes.push(insn.code);
        bytes.push(insn.src << 4 | insn.dst);
        bytes.extend(insn.off.to_le_bytes());
        bytes.extend(imm.to_le_bytes());
    }
    let digest = sha256(&bytes);
    let mut out = [0; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// SHA-256 (FIPS 180-4).
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend((data.len() as u64 * 8).to_be_bytes());
    for block in message.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, &word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0; 32];
    for (i, x) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

/// A loaded program: Linux's `struct bpf_prog` with its `aux`.
pub(crate) struct Program {
    id: u32,
    kind: u32,
    tag: [u8; 8],
    /// `prog->pages`.
    pages: u64,
    /// `prog->len`, after the verifier's rewrites.
    len: usize,
    /// `aux->verified_insns`.
    verified: u32,
    /// `gpl_compatible`, for the helpers that need it.
    #[allow(dead_code)]
    gpl: bool,
    /// `aux->name`.
    #[allow(dead_code)]
    name: [u8; 16],
    /// The instructions, for the interpreter.
    insns: Vec<Insn>,
    /// `aux->used_maps`, which the program keeps while it is there.
    maps: Vec<Arc<crate::bpf::Map>>,
    /// Each `BPF_LD_IMM64` of a map, as the verifier resolved it: the map's
    /// index in `maps`, and the offset of a `BPF_PSEUDO_MAP_VALUE`.
    loads: BTreeMap<usize, (u8, Option<u32>)>,
    ids: Arc<Ids>,
}

impl Program {
    /// `bpf_prog_size` of the program as `sk_attach_bpf` charges it to the
    /// socket: of its instructions after Linux's rewrites, which only
    /// their number is made of here.
    pub(crate) fn filter_size(&self) -> u64 {
        prog_size(self.len)
    }

    /// Runs the socket filter on `packet`: the bytes to keep (`R0`, as
    /// `bpf_prog_run` gives it, 32 bits). A load or store the verifier
    /// should have refused stops it, which drops the packet.
    pub(crate) fn run(
        &self,
        packet: &crate::bpf_interp::Packet<'_>,
        kernel: &mut dyn crate::bpf_interp::Kernel,
    ) -> u32 {
        let program = crate::bpf_interp::Program {
            insns: &self.insns,
            maps: &self.maps,
            loads: &self.loads,
        };
        let result = crate::bpf_interp::run(&program, packet, kernel);
        // The fuzz targets build without debug assertions.
        assert!(
            !cfg!(any(debug_assertions, feature = "fuzzing")) || result.is_ok(),
            "a verified program faulted"
        );
        result.map_or(0, |r0| r0 as u32)
    }
}

/// `bpf_prog_size`: what a program of `insns` instructions takes, and what
/// a socket is charged for it as its filter.
pub(crate) fn prog_size(insns: usize) -> u64 {
    PROG_HEADER + INSN_SIZE * insns as u64
}

/// A socket's filter (`sk_filter->prog`): a program `SO_ATTACH_BPF` gave,
/// or a classic one `SO_ATTACH_FILTER` gave, converted.
#[derive(Clone)]
pub(crate) enum Attached {
    Program(Arc<Program>),
    Classic(Arc<crate::bpf_classic::Classic>),
}

impl Attached {
    /// What the socket is charged for it (`sk_filter_charge`).
    pub(crate) fn filter_size(&self) -> u64 {
        match self {
            Attached::Program(p) => p.filter_size(),
            Attached::Classic(c) => c.filter_size(),
        }
    }

    /// The classic program as given (`orig_prog`), which a program
    /// `SO_ATTACH_BPF` gave has none of.
    pub(crate) fn classic(&self) -> Option<&crate::bpf_classic::Classic> {
        match self {
            Attached::Program(_) => None,
            Attached::Classic(c) => Some(c),
        }
    }

    /// Runs the program on `packet`: the bytes of it to keep, or 0 to
    /// drop it.
    pub(crate) fn run(
        &self,
        packet: &crate::bpf_interp::Packet<'_>,
        kernel: &mut dyn crate::bpf_interp::Kernel,
    ) -> u32 {
        let classic = match self {
            Attached::Program(p) => return p.run(packet, kernel),
            Attached::Classic(c) => c,
        };
        let program = crate::bpf_interp::Program {
            insns: &classic.insns,
            maps: &[],
            loads: &BTreeMap::new(),
        };
        let result = crate::bpf_interp::run(&program, packet, kernel);
        assert!(
            !cfg!(any(debug_assertions, feature = "fuzzing")) || result.is_ok(),
            "a converted classic program faulted"
        );
        result.map_or(0, |r0| r0 as u32)
    }
}

/// How many of an AF_UNIX datagram's `len` bytes `unix_dgram_sendmsg` puts
/// in page fragments: none up to `SKB_MAX_ALLOC` ([`crate::skb::MAX_ALLOC`]),
/// the most it keeps in its linear part, else what is past it in whole
/// pages, at most `MAX_SKB_FRAGS` of them ([`crate::skb::MAX_FRAGS_SIZE`]).
pub(crate) fn unix_paged(len: usize) -> usize {
    use crate::skb::{MAX_ALLOC, MAX_FRAGS_SIZE, PAGE};
    if len <= MAX_ALLOC {
        return 0;
    }
    (len - MAX_ALLOC).min(MAX_FRAGS_SIZE).next_multiple_of(PAGE)
}

/// How many of an AF_UNIX message's `len` bytes are in its linear part:
/// what [`unix_paged`] leaves.
fn unix_linear(len: usize) -> usize {
    len.saturating_sub(unix_paged(len))
}

/// The kernel around a socket filter as an AF_UNIX send runs it
/// (`sk_filter_trim_cap`): the sending task, and the receiving socket as
/// `skb->sk`.
pub(crate) struct Receiving<'a> {
    pub(crate) host: Option<&'a Arc<dyn paludarium_host::Host>>,
    /// The sending task's real user and group IDs.
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    /// The socket the message is for, and its owner (`sk_uid`).
    pub(crate) socket: FilterSocket,
    pub(crate) owner: u32,
}

/// The socket a filter runs for (`skb->sk`).
#[derive(Clone)]
pub(crate) enum FilterSocket {
    Unix(std::sync::Weak<crate::unix::UnixSocket>),
    Inet(std::sync::Weak<crate::inet::InetSocket>),
}

impl FilterSocket {
    /// Its cookie (`__sock_gen_cookie`), or 0 when it is gone.
    fn cookie(&self) -> u64 {
        match self {
            FilterSocket::Unix(s) => s.upgrade().map_or(0, |s| s.cookie()),
            FilterSocket::Inet(s) => s.upgrade().map_or(0, |s| s.cookie()),
        }
    }
}

impl crate::bpf_interp::Kernel for Receiving<'_> {
    /// The emulator's boot time runs as its monotonic clock, `CLOCK_TAI` as
    /// its real time, and the coarse clock as the fine one.
    fn clock(&mut self, clock: crate::bpf_interp::Clock) -> u64 {
        use crate::bpf_interp::Clock;
        let id = match clock {
            Clock::Monotonic | Clock::Boot | Clock::MonotonicCoarse => {
                paludarium_host::ClockId::Monotonic
            }
            Clock::Tai => paludarium_host::ClockId::Realtime,
        };
        self.host.and_then(|h| h.clock(id).ok()).unwrap_or(0)
    }
    fn random(&mut self) -> u32 {
        let mut b = [0; 4];
        if let Some(h) = self.host {
            let _ = h.random_bytes(&mut b);
        }
        u32::from_le_bytes(b)
    }
    /// The emulator runs on one processor.
    fn processor(&mut self) -> u32 {
        0
    }
    fn pid_tgid(&mut self) -> u64 {
        let (pid, tid) = crate::proc::caller();
        u64::from(pid) << 32 | u64::from(tid)
    }
    fn uid_gid(&mut self) -> u64 {
        u64::from(self.gid) << 32 | u64::from(self.uid)
    }
    fn socket_cookie(&mut self) -> u64 {
        self.socket.cookie()
    }
    fn socket_uid(&mut self) -> u32 {
        self.owner
    }
    /// The emulator's network namespaces have no cookies: each is the
    /// initial one's, 1.
    fn netns_cookie(&mut self, _: bool) -> u64 {
        1
    }
}

/// `sk_filter` of an AF_UNIX message, `sk_filter_trim_cap` with a cap of 1:
/// how many of its bytes the receiving socket keeps, or `None` when the
/// filter drops it.
pub(crate) fn sk_filter(
    program: &Attached,
    buf: &[u8],
    kernel: &mut Receiving<'_>,
) -> Option<usize> {
    let packet = crate::bpf_interp::Packet::message(buf, unix_linear(buf.len()));
    match program.run(&packet, kernel) {
        0 => None,
        keep => Some(buf.len().min(keep as usize)),
    }
}

/// `bpf_prog_get_type(fd, BPF_PROG_TYPE_SOCKET_FILTER)`, as `SO_ATTACH_BPF`
/// takes it: `EBADF` for no descriptor, `EINVAL` for a file that is no
/// program or a program of another type.
pub(crate) fn socket_filter(c: &Context<'_>, fd: u32) -> Result<Arc<Program>, Errno> {
    let file = c.files.descriptor(u64::from(fd))?.file;
    match of(&file) {
        Some(p) if p.program.kind == kind::SOCKET_FILTER => Ok(Arc::clone(&p.program)),
        _ => Err(Errno::EINVAL),
    }
}

/// The machine's programs by ID: Linux's `prog_idr`, which shares nothing
/// with the maps' IDs.
#[derive(Default)]
pub(crate) struct Ids {
    table: Mutex<IdTable>,
}

#[derive(Default)]
struct IdTable {
    /// Where the next search starts (`idr_next`).
    next: u32,
    programs: BTreeMap<u32, Weak<Program>>,
}

/// The IDs `bpf_prog_alloc_id` hands out: 1 up to `INT_MAX`, less 1.
const LAST_ID: u32 = i32::MAX as u32 - 1;

impl Ids {
    /// `bpf_prog_alloc_id`: `idr_alloc_cyclic` from 1 to `INT_MAX`, the
    /// first free ID from where the last search ended, around to 1
    /// (`ENOSPC` with none free).
    fn publish(&self, make: impl FnOnce(u32) -> Program) -> Result<Arc<Program>, Errno> {
        let mut table = lock(&self.table);
        let start = table.next.max(1);
        let id = (start..=LAST_ID)
            .chain(1..start)
            .find(|id| !table.programs.contains_key(id))
            .ok_or(ENOSPC)?;
        let program = Arc::new(make(id));
        table.programs.insert(id, Arc::downgrade(&program));
        table.next = id + 1;
        Ok(program)
    }
}

impl Drop for Program {
    /// `bpf_prog_free_id`, as the last reference goes.
    fn drop(&mut self) {
        let mut table = lock(&self.ids.table);
        if table
            .programs
            .get(&self.id)
            .is_some_and(|p| p.strong_count() == 0)
        {
            table.programs.remove(&self.id);
        }
    }
}

/// The open file: Linux's `bpf-prog`.
pub(crate) struct ProgFile {
    program: Arc<Program>,
    /// What `F_SETFL` set on it ([`crate::files::StatusFlags`]).
    status: crate::files::StatusFlags,
}

fn of(file: &Arc<dyn FileHandle>) -> Option<&ProgFile> {
    file.as_any()?.downcast_ref::<ProgFile>()
}

/// What `/proc/self/fdinfo` adds for a program, as Linux's
/// `bpf_prog_show_fdinfo`. Nothing is compiled or run, so `prog_jited` and
/// the statistics are 0.
pub(crate) fn fdinfo(file: &Arc<dyn FileHandle>) -> Option<Vec<u8>> {
    let p = &of(file)?.program;
    let tag: String = p.tag.iter().map(|b| format!("{b:02x}")).collect();
    Some(
        format!(
            "prog_type:\t{}\nprog_jited:\t0\nprog_tag:\t{tag}\nmemlock:\t{}\nprog_id:\t{}\nrun_time_ns:\t0\nrun_cnt:\t0\nrecursion_misses:\t0\nverified_insns:\t{}\n",
            p.kind,
            p.pages * PAGE_SIZE,
            p.id,
            p.verified
        )
        .into_bytes(),
    )
}

impl FileHandle for ProgFile {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    /// `bpf_dummy_read`.
    fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
    /// `bpf_dummy_write`.
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Ok(0)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(crate::files::anon_inode_stat())
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn flags(&self) -> u32 {
        self.status.of(O_RDWR)
    }
    /// `F_SETFL`, as Linux's `setfl`.
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.status.set(flags);
        Ok(())
    }
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
    fn a_datagram_s_linear_part_is_what_its_pages_leave() {
        // As `truesize` counts the same datagrams: whole, then past
        // SKB_MAX_ALLOC the rest after whole pages, at most 17 of them.
        let expected = [
            (0, 0),
            (16064, 16064),
            (16065, 11969),
            (85696, 16064),
            (85697, 16065),
            (212_960, 143_328),
        ];
        for (len, linear) in expected {
            assert_eq!(unix_linear(len), linear, "{len} bytes");
        }
    }

    #[test]
    fn the_known_flags_are_linuxs() {
        assert_eq!(flag::KNOWN, 0x1_00ff);
    }

    #[test]
    fn sha256_gives_the_standards_digests() {
        let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Two blocks.
        assert_eq!(
            hex(sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn a_tag_leaves_out_the_descriptors_of_maps() {
        let insn = |code, src, imm| Insn {
            code,
            dst: 1,
            src,
            off: 0,
            imm,
        };
        let pair = |fd| {
            vec![
                insn(0x18, 1, fd),
                Insn {
                    code: 0,
                    dst: 0,
                    src: 0,
                    off: 0,
                    imm: 0,
                },
            ]
        };
        assert_eq!(tag(&pair(3)), tag(&pair(9)));
        assert_ne!(
            tag(&[insn(0x18, 0, 3), insn(0, 0, 0)]),
            tag(&[insn(0x18, 0, 9), insn(0, 0, 0)])
        );
    }

    #[test]
    fn the_gpl_compatible_licenses_are_linuxs() {
        assert!(gpl_compatible(b"GPL") && gpl_compatible(b"Dual BSD/GPL"));
        assert!(!gpl_compatible(b"MIT") && !gpl_compatible(b"GPL "));
    }
}
