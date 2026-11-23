//! The BPF file system's mounts (Linux's `kernel/bpf/inode.c`): the
//! options `bpf_parse_param` takes, the root `bpf_fill_super` makes and
//! what `bpf_show_options` shows of them. Its files, the objects
//! `BPF_OBJ_PIN` leaves there, are [`crate::bpf`]'s.
use std::sync::Arc;

use paludarium_host::{ClockId, HostFs};
use paludarium_types::Errno;
use paludarium_vfs::{MemFs, NewTmpfs, Settings};

use super::{Refused, Value, common_flag, common_options, kstrtouint};
use crate::syscalls::Context;

/// Its type's name, as `mount` takes it and mountinfo shows it.
pub(super) const KIND: &str = "bpf";

const S_IALLUGO: u32 = 0o7777;
const S_IRWXUGO: u32 = 0o777;
const S_ISVTX: u32 = 0o1000;
const MS_RDONLY: u64 = 1;
const CAP_SYS_ADMIN: u64 = 21;

/// What a mount was asked for (`struct bpf_mount_opts`).
#[derive(Clone)]
pub(super) struct Bpffs {
    uid: u32,
    gid: u32,
    mode: u32,
    /// `delegate_cmds`, `delegate_maps`, `delegate_progs` and
    /// `delegate_attachs`, the BPF tokens' masks.
    delegates: [u64; 4],
    source: Option<Vec<u8>>,
    /// The superblock flags the options set and clear.
    sb_set: u64,
    sb_clear: u64,
    pub(super) sb_flags: u64,
}

/// The delegation options, with the enum each names its bits by and the
/// prefix those names drop (`bpf_parse_param`'s `enum_t` and
/// `enum_pfx`), in `bpf_show_options`' order.
/// An enum's constants: each name and its value.
type Names = &'static [(&'static str, u32)];
/// A delegation option: its name, the enum, the prefix and the enum's end.
type Delegate = (&'static str, Names, &'static str, u32);

const DELEGATES: [Delegate; 4] = [
    ("delegate_cmds", COMMANDS, "BPF_", MAX_COMMAND),
    ("delegate_maps", MAP_TYPES, "BPF_MAP_TYPE_", MAX_MAP_TYPE),
    (
        "delegate_progs",
        PROG_TYPES,
        "BPF_PROG_TYPE_",
        MAX_PROG_TYPE,
    ),
    ("delegate_attachs", ATTACH_TYPES, "BPF_", MAX_ATTACH_TYPE),
];

impl Bpffs {
    /// `bpf_init_fs_context`: the caller's filesystem IDs, mode 0777 and
    /// nothing delegated.
    pub(super) fn fresh(c: &Context<'_>, source: Option<Vec<u8>>) -> Self {
        let creds = &c.process.credentials;
        Self {
            uid: creds.fsuid,
            gid: creds.fsgid,
            mode: S_IRWXUGO,
            delegates: [0; 4],
            source,
            sb_set: 0,
            sb_clear: 0,
            sb_flags: 0,
        }
    }
    /// One parameter (`vfs_parse_fs_param`): a common superblock flag, then
    /// the BPF file system's own (`bpf_parse_param`), then the source; any
    /// other is ignored, as the BPF file system always has.
    pub(super) fn parse(
        &mut self,
        c: &Context<'_>,
        key: &[u8],
        value: Value<'_>,
    ) -> Result<(), Refused> {
        if let Some((on, off)) = common_flag(key) {
            self.sb_set = (self.sb_set | on) & !off;
            self.sb_clear = (self.sb_clear | off) & !on;
            return Ok(());
        }
        let creds = &c.process.credentials;
        let name = String::from_utf8_lossy(key).into_owned();
        let bad = || Refused::plain(format!("bpf: Bad value for '{name}'"));
        // `fs_param_is_string` and those of numbers: a string, not empty.
        let string = || match value {
            Value::String(v) if !v.is_empty() => Ok(v),
            _ => Err(bad()),
        };
        match key {
            b"uid" | b"gid" => {
                let ids = if key == b"uid" {
                    crate::users::Ids::User
                } else {
                    crate::users::Ids::Group
                };
                let id = kstrtouint(string()?, 0).ok_or_else(bad)?;
                // make_kuid in the caller's namespace, which must map it.
                let kernel = creds.user.kernel_of(ids, id).ok_or_else(bad)?;
                if key == b"uid" {
                    self.uid = kernel;
                } else {
                    self.gid = kernel;
                }
            }
            b"mode" => self.mode = kstrtouint(string()?, 8).ok_or_else(bad)? & S_IALLUGO,
            b"delegate_cmds" | b"delegate_maps" | b"delegate_progs" | b"delegate_attachs" => {
                let which = DELEGATES
                    .iter()
                    .position(|(option, ..)| option.as_bytes() == key)
                    .unwrap_or(0);
                let (_, names, prefix, _) = DELEGATES[which];
                let mut mask = 0u64;
                for part in string()?.split(|&b| b == b':') {
                    if part == b"any" {
                        mask |= !0;
                    } else if let Some(value) = named(names, prefix, part) {
                        // `1ULL << val`, whose count x86-64 takes modulo 64.
                        mask |= 1u64.wrapping_shl(value);
                    } else {
                        // `kstrtou64(p, 0, &msk)`, which replaces the mask.
                        mask = kstrtou64(part)?;
                    }
                }
                if mask != 0 && !creds.capable(CAP_SYS_ADMIN) {
                    return Err(Errno::EPERM.into());
                }
                self.delegates[which] |= mask;
            }
            // vfs_parse_fs_param_source.
            b"source" => {
                let Value::String(value) = value else {
                    return Err(Refused::plain("Non-string source".into()));
                };
                if self.source.is_some() {
                    return Err(Refused::plain("Multiple sources".into()));
                }
                self.source = Some(value.to_vec());
            }
            _ => {}
        }
        Ok(())
    }
    /// `bpf_fill_super`: privileged in the first user namespace unless the
    /// caller's is it (`EPERM`), a root directory of the mode asked for
    /// with the sticky bit, owned as asked, with the superblock flags
    /// `sb_flags` and the mount flags `mount_flags`.
    pub(super) fn built(
        mut self,
        c: &Context<'_>,
        sb_flags: u64,
        mount_flags: u32,
    ) -> Result<NewTmpfs, Errno> {
        let creds = &c.process.credentials;
        if !creds.user.is_first_user() && !creds.capable(CAP_SYS_ADMIN) {
            return Err(Errno::EPERM);
        }
        let sb_flags = (sb_flags | self.sb_set) & !self.sb_clear;
        self.sb_flags = sb_flags;
        let host = Arc::clone(c.shared_host);
        let fs = MemFs::with_clock(Arc::new(move || host.clock(ClockId::Realtime)));
        fs.set_mode(b"/", S_ISVTX | self.mode)?;
        fs.set_owner(b"/", true, Some(self.uid), Some(self.gid))?;
        let now = c.host.clock(ClockId::Realtime)?;
        fs.set_times(b"/", true, Some(i128::from(now)), Some(i128::from(now)))?;
        let source = self.source.take().unwrap_or_else(|| b"none".to_vec());
        Ok(NewTmpfs {
            fs,
            read_only: sb_flags & MS_RDONLY != 0,
            settings: self.settings(),
            flags: mount_flags,
            source,
            owner: Some(Arc::clone(&creds.user.0) as Arc<dyn std::any::Any + Send + Sync>),
            kind: KIND,
        })
    }
    /// What `statfs` and mountinfo report: no size or inodes
    /// (`simple_statfs`), and the options `bpf_show_options` shows.
    pub(super) fn settings(self) -> Settings {
        Settings {
            blocks: 0,
            inodes: 0,
            common_options: common_options(self.sb_flags),
            super_options: self.shown(),
            parsed: Arc::new(self),
        }
    }
    /// `bpf_show_options`: an owner other than root, a mode other than
    /// 0777 (the sticky bit aside), and each delegation mask by its names,
    /// `any` for every bit there is, and in hex what no name gives. The
    /// root's mode and owner are those it was mounted with.
    fn shown(&self) -> String {
        let mut out = String::new();
        if self.uid != 0 {
            out.push_str(&format!(",uid={}", self.uid));
        }
        if self.gid != 0 {
            out.push_str(&format!(",gid={}", self.gid));
        }
        if self.mode & !S_ISVTX != S_IRWXUGO {
            out.push_str(&format!(",mode={:o}", self.mode & !S_ISVTX));
        }
        for (&(option, names, prefix, max), &delegated) in DELEGATES.iter().zip(&self.delegates) {
            let any = (1u64 << max) - 1;
            let mut left = delegated & any;
            if left == 0 {
                continue;
            }
            out.push(',');
            out.push_str(option);
            if left == any {
                out.push_str("=any");
                continue;
            }
            let mut first = true;
            for &(name, value) in names {
                let Some(short) = strip_prefix_ignoring_case(name, prefix) else {
                    continue;
                };
                let bit = 1u64.wrapping_shl(value);
                if left & bit != 0 {
                    out.push(if first { '=' } else { ':' });
                    out.push_str(&short.to_ascii_lowercase());
                    left &= !bit;
                    first = false;
                }
            }
            if left != 0 {
                out.push_str(&format!("{}{left:#x}", if first { '=' } else { ':' }));
            }
        }
        out
    }
}

/// `name` without `prefix`, which it starts with in any case
/// (`strncasecmp`), or `None`.
fn strip_prefix_ignoring_case<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    let head = name.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &name[prefix.len()..])
}

/// `find_btf_enum_const`: the value of the first of `names` with `prefix`
/// whose rest is `part` in any case.
fn named(names: &[(&str, u32)], prefix: &str, part: &[u8]) -> Option<u32> {
    names.iter().find_map(|&(name, value)| {
        let short = strip_prefix_ignoring_case(name, prefix)?;
        short.as_bytes().eq_ignore_ascii_case(part).then_some(value)
    })
}

/// `kstrtou64(s, 0)`: the whole string (a `+` and a newline allowed) in
/// the base its prefix gives; `ERANGE` past 64 bits, else `EINVAL`.
fn kstrtou64(s: &[u8]) -> Result<u64, Errno> {
    let s = s.strip_prefix(b"+").unwrap_or(s);
    let (base, digits) = match s {
        [b'0', x, d, ..] if x.eq_ignore_ascii_case(&b'x') && d.is_ascii_hexdigit() => (16, &s[2..]),
        [b'0', ..] => (8, s),
        _ => (10, s),
    };
    let digits = digits.strip_suffix(b"\n").unwrap_or(digits);
    if digits.is_empty() {
        return Err(Errno::EINVAL);
    }
    let mut value: u64 = 0;
    let mut overflow = false;
    for &b in digits {
        let digit = match b {
            b'0'..=b'9' => u64::from(b - b'0'),
            b'a'..=b'f' | b'A'..=b'F' => u64::from(b.to_ascii_lowercase() - b'a') + 10,
            _ => return Err(Errno::EINVAL),
        };
        if digit >= base {
            return Err(Errno::EINVAL);
        }
        match value.checked_mul(base).and_then(|v| v.checked_add(digit)) {
            Some(v) => value = v,
            None => overflow = true,
        }
    }
    if overflow {
        Err(Errno::ERANGE)
    } else {
        Ok(value)
    }
}

/// `__MAX_BPF_CMD` and the other ends of the enums, which bound `any`.
const MAX_COMMAND: u32 = 40;
const MAX_MAP_TYPE: u32 = 36;
const MAX_PROG_TYPE: u32 = 33;
const MAX_ATTACH_TYPE: u32 = 62;

/// The names and values of the UAPI enums the delegation options name,
/// in their order there, as the kernel's BTF of them lists them (Linux
/// master's `include/uapi/linux/bpf.h`; the `__MAX_` ends left out).
/// `enum bpf_cmd`.
const COMMANDS: &[(&str, u32)] = &[
    ("BPF_MAP_CREATE", 0),
    ("BPF_MAP_LOOKUP_ELEM", 1),
    ("BPF_MAP_UPDATE_ELEM", 2),
    ("BPF_MAP_DELETE_ELEM", 3),
    ("BPF_MAP_GET_NEXT_KEY", 4),
    ("BPF_PROG_LOAD", 5),
    ("BPF_OBJ_PIN", 6),
    ("BPF_OBJ_GET", 7),
    ("BPF_PROG_ATTACH", 8),
    ("BPF_PROG_DETACH", 9),
    ("BPF_PROG_TEST_RUN", 10),
    ("BPF_PROG_RUN", 10),
    ("BPF_PROG_GET_NEXT_ID", 11),
    ("BPF_MAP_GET_NEXT_ID", 12),
    ("BPF_PROG_GET_FD_BY_ID", 13),
    ("BPF_MAP_GET_FD_BY_ID", 14),
    ("BPF_OBJ_GET_INFO_BY_FD", 15),
    ("BPF_PROG_QUERY", 16),
    ("BPF_RAW_TRACEPOINT_OPEN", 17),
    ("BPF_BTF_LOAD", 18),
    ("BPF_BTF_GET_FD_BY_ID", 19),
    ("BPF_TASK_FD_QUERY", 20),
    ("BPF_MAP_LOOKUP_AND_DELETE_ELEM", 21),
    ("BPF_MAP_FREEZE", 22),
    ("BPF_BTF_GET_NEXT_ID", 23),
    ("BPF_MAP_LOOKUP_BATCH", 24),
    ("BPF_MAP_LOOKUP_AND_DELETE_BATCH", 25),
    ("BPF_MAP_UPDATE_BATCH", 26),
    ("BPF_MAP_DELETE_BATCH", 27),
    ("BPF_LINK_CREATE", 28),
    ("BPF_LINK_UPDATE", 29),
    ("BPF_LINK_GET_FD_BY_ID", 30),
    ("BPF_LINK_GET_NEXT_ID", 31),
    ("BPF_ENABLE_STATS", 32),
    ("BPF_ITER_CREATE", 33),
    ("BPF_LINK_DETACH", 34),
    ("BPF_PROG_BIND_MAP", 35),
    ("BPF_TOKEN_CREATE", 36),
    ("BPF_PROG_STREAM_READ_BY_FD", 37),
    ("BPF_PROG_ASSOC_STRUCT_OPS", 38),
    ("BPF_PROG_STREAM_OPEN", 39),
    ("BPF_COMMON_ATTRS", 65536),
];
/// `enum bpf_map_type`.
const MAP_TYPES: &[(&str, u32)] = &[
    ("BPF_MAP_TYPE_UNSPEC", 0),
    ("BPF_MAP_TYPE_HASH", 1),
    ("BPF_MAP_TYPE_ARRAY", 2),
    ("BPF_MAP_TYPE_PROG_ARRAY", 3),
    ("BPF_MAP_TYPE_PERF_EVENT_ARRAY", 4),
    ("BPF_MAP_TYPE_PERCPU_HASH", 5),
    ("BPF_MAP_TYPE_PERCPU_ARRAY", 6),
    ("BPF_MAP_TYPE_STACK_TRACE", 7),
    ("BPF_MAP_TYPE_CGROUP_ARRAY", 8),
    ("BPF_MAP_TYPE_LRU_HASH", 9),
    ("BPF_MAP_TYPE_LRU_PERCPU_HASH", 10),
    ("BPF_MAP_TYPE_LPM_TRIE", 11),
    ("BPF_MAP_TYPE_ARRAY_OF_MAPS", 12),
    ("BPF_MAP_TYPE_HASH_OF_MAPS", 13),
    ("BPF_MAP_TYPE_DEVMAP", 14),
    ("BPF_MAP_TYPE_SOCKMAP", 15),
    ("BPF_MAP_TYPE_CPUMAP", 16),
    ("BPF_MAP_TYPE_XSKMAP", 17),
    ("BPF_MAP_TYPE_SOCKHASH", 18),
    ("BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED", 19),
    ("BPF_MAP_TYPE_CGROUP_STORAGE", 19),
    ("BPF_MAP_TYPE_REUSEPORT_SOCKARRAY", 20),
    ("BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED", 21),
    ("BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE", 21),
    ("BPF_MAP_TYPE_QUEUE", 22),
    ("BPF_MAP_TYPE_STACK", 23),
    ("BPF_MAP_TYPE_SK_STORAGE", 24),
    ("BPF_MAP_TYPE_DEVMAP_HASH", 25),
    ("BPF_MAP_TYPE_STRUCT_OPS", 26),
    ("BPF_MAP_TYPE_RINGBUF", 27),
    ("BPF_MAP_TYPE_INODE_STORAGE", 28),
    ("BPF_MAP_TYPE_TASK_STORAGE", 29),
    ("BPF_MAP_TYPE_BLOOM_FILTER", 30),
    ("BPF_MAP_TYPE_USER_RINGBUF", 31),
    ("BPF_MAP_TYPE_CGRP_STORAGE", 32),
    ("BPF_MAP_TYPE_ARENA", 33),
    ("BPF_MAP_TYPE_INSN_ARRAY", 34),
    ("BPF_MAP_TYPE_RHASH", 35),
];
/// `enum bpf_prog_type`.
const PROG_TYPES: &[(&str, u32)] = &[
    ("BPF_PROG_TYPE_UNSPEC", 0),
    ("BPF_PROG_TYPE_SOCKET_FILTER", 1),
    ("BPF_PROG_TYPE_KPROBE", 2),
    ("BPF_PROG_TYPE_SCHED_CLS", 3),
    ("BPF_PROG_TYPE_SCHED_ACT", 4),
    ("BPF_PROG_TYPE_TRACEPOINT", 5),
    ("BPF_PROG_TYPE_XDP", 6),
    ("BPF_PROG_TYPE_PERF_EVENT", 7),
    ("BPF_PROG_TYPE_CGROUP_SKB", 8),
    ("BPF_PROG_TYPE_CGROUP_SOCK", 9),
    ("BPF_PROG_TYPE_LWT_IN", 10),
    ("BPF_PROG_TYPE_LWT_OUT", 11),
    ("BPF_PROG_TYPE_LWT_XMIT", 12),
    ("BPF_PROG_TYPE_SOCK_OPS", 13),
    ("BPF_PROG_TYPE_SK_SKB", 14),
    ("BPF_PROG_TYPE_CGROUP_DEVICE", 15),
    ("BPF_PROG_TYPE_SK_MSG", 16),
    ("BPF_PROG_TYPE_RAW_TRACEPOINT", 17),
    ("BPF_PROG_TYPE_CGROUP_SOCK_ADDR", 18),
    ("BPF_PROG_TYPE_LWT_SEG6LOCAL", 19),
    ("BPF_PROG_TYPE_LIRC_MODE2", 20),
    ("BPF_PROG_TYPE_SK_REUSEPORT", 21),
    ("BPF_PROG_TYPE_FLOW_DISSECTOR", 22),
    ("BPF_PROG_TYPE_CGROUP_SYSCTL", 23),
    ("BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE", 24),
    ("BPF_PROG_TYPE_CGROUP_SOCKOPT", 25),
    ("BPF_PROG_TYPE_TRACING", 26),
    ("BPF_PROG_TYPE_STRUCT_OPS", 27),
    ("BPF_PROG_TYPE_EXT", 28),
    ("BPF_PROG_TYPE_LSM", 29),
    ("BPF_PROG_TYPE_SK_LOOKUP", 30),
    ("BPF_PROG_TYPE_SYSCALL", 31),
    ("BPF_PROG_TYPE_NETFILTER", 32),
];
/// `enum bpf_attach_type`.
const ATTACH_TYPES: &[(&str, u32)] = &[
    ("BPF_CGROUP_INET_INGRESS", 0),
    ("BPF_CGROUP_INET_EGRESS", 1),
    ("BPF_CGROUP_INET_SOCK_CREATE", 2),
    ("BPF_CGROUP_SOCK_OPS", 3),
    ("BPF_SK_SKB_STREAM_PARSER", 4),
    ("BPF_SK_SKB_STREAM_VERDICT", 5),
    ("BPF_CGROUP_DEVICE", 6),
    ("BPF_SK_MSG_VERDICT", 7),
    ("BPF_CGROUP_INET4_BIND", 8),
    ("BPF_CGROUP_INET6_BIND", 9),
    ("BPF_CGROUP_INET4_CONNECT", 10),
    ("BPF_CGROUP_INET6_CONNECT", 11),
    ("BPF_CGROUP_INET4_POST_BIND", 12),
    ("BPF_CGROUP_INET6_POST_BIND", 13),
    ("BPF_CGROUP_UDP4_SENDMSG", 14),
    ("BPF_CGROUP_UDP6_SENDMSG", 15),
    ("BPF_LIRC_MODE2", 16),
    ("BPF_FLOW_DISSECTOR", 17),
    ("BPF_CGROUP_SYSCTL", 18),
    ("BPF_CGROUP_UDP4_RECVMSG", 19),
    ("BPF_CGROUP_UDP6_RECVMSG", 20),
    ("BPF_CGROUP_GETSOCKOPT", 21),
    ("BPF_CGROUP_SETSOCKOPT", 22),
    ("BPF_TRACE_RAW_TP", 23),
    ("BPF_TRACE_FENTRY", 24),
    ("BPF_TRACE_FEXIT", 25),
    ("BPF_MODIFY_RETURN", 26),
    ("BPF_LSM_MAC", 27),
    ("BPF_TRACE_ITER", 28),
    ("BPF_CGROUP_INET4_GETPEERNAME", 29),
    ("BPF_CGROUP_INET6_GETPEERNAME", 30),
    ("BPF_CGROUP_INET4_GETSOCKNAME", 31),
    ("BPF_CGROUP_INET6_GETSOCKNAME", 32),
    ("BPF_XDP_DEVMAP", 33),
    ("BPF_CGROUP_INET_SOCK_RELEASE", 34),
    ("BPF_XDP_CPUMAP", 35),
    ("BPF_SK_LOOKUP", 36),
    ("BPF_XDP", 37),
    ("BPF_SK_SKB_VERDICT", 38),
    ("BPF_SK_REUSEPORT_SELECT", 39),
    ("BPF_SK_REUSEPORT_SELECT_OR_MIGRATE", 40),
    ("BPF_PERF_EVENT", 41),
    ("BPF_TRACE_KPROBE_MULTI", 42),
    ("BPF_LSM_CGROUP", 43),
    ("BPF_STRUCT_OPS", 44),
    ("BPF_NETFILTER", 45),
    ("BPF_TCX_INGRESS", 46),
    ("BPF_TCX_EGRESS", 47),
    ("BPF_TRACE_UPROBE_MULTI", 48),
    ("BPF_CGROUP_UNIX_CONNECT", 49),
    ("BPF_CGROUP_UNIX_SENDMSG", 50),
    ("BPF_CGROUP_UNIX_RECVMSG", 51),
    ("BPF_CGROUP_UNIX_GETPEERNAME", 52),
    ("BPF_CGROUP_UNIX_GETSOCKNAME", 53),
    ("BPF_NETKIT_PRIMARY", 54),
    ("BPF_NETKIT_PEER", 55),
    ("BPF_TRACE_KPROBE_SESSION", 56),
    ("BPF_TRACE_UPROBE_SESSION", 57),
    ("BPF_TRACE_FSESSION", 58),
    ("BPF_TRACE_FENTRY_MULTI", 59),
    ("BPF_TRACE_FEXIT_MULTI", 60),
    ("BPF_TRACE_FSESSION_MULTI", 61),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn options(delegates: [u64; 4]) -> Bpffs {
        Bpffs {
            uid: 0,
            gid: 0,
            mode: S_IRWXUGO,
            delegates,
            source: None,
            sb_set: 0,
            sb_clear: 0,
            sb_flags: 0,
        }
    }

    #[test]
    fn kstrtou64_takes_a_whole_number_in_its_base() {
        assert_eq!(kstrtou64(b"0x1f"), Ok(31));
        assert_eq!(kstrtou64(b"017\n"), Ok(15));
        assert_eq!(kstrtou64(b"+9"), Ok(9));
        assert_eq!(kstrtou64(b"08"), Err(Errno::EINVAL));
        assert_eq!(kstrtou64(b""), Err(Errno::EINVAL));
        assert_eq!(kstrtou64(b"12x"), Err(Errno::EINVAL));
        assert_eq!(kstrtou64(b"0x10000000000000000"), Err(Errno::ERANGE));
    }

    #[test]
    fn names_are_any_case_without_their_prefix() {
        assert_eq!(named(MAP_TYPES, "BPF_MAP_TYPE_", b"Array"), Some(2));
        assert_eq!(named(COMMANDS, "BPF_", b"PROG_LOAD"), Some(5));
        assert_eq!(named(COMMANDS, "BPF_", b"map_type_array"), None);
        // An alias names its value too, after the name it follows.
        assert_eq!(named(COMMANDS, "BPF_", b"prog_run"), Some(10));
    }

    #[test]
    fn masks_show_by_name_then_in_hex() {
        assert_eq!(options([0; 4]).shown(), "");
        let all = options([!0, 1 << 2 | 1 << 1, 1 << 40 | 1, 0]).shown();
        assert_eq!(
            all,
            ",delegate_cmds=any,delegate_maps=hash:array,delegate_progs=unspec"
        );
        let mut owned = options([0; 4]);
        owned.uid = 1000;
        owned.mode = S_ISVTX | 0o700;
        assert_eq!(owned.shown(), ",uid=1000,mode=700");
        assert_eq!(options([1 << 60, 0, 0, 0]).shown(), "");
        assert_eq!(
            options([0, 0, 0, 1 << 61 | 1]).shown(),
            ",delegate_attachs=cgroup_inet_ingress:trace_fsession_multi"
        );
        assert_eq!(
            options([1 << 39 | 1 << 5, 0, 0, 0]).shown(),
            ",delegate_cmds=prog_load:prog_stream_open"
        );
    }
}
