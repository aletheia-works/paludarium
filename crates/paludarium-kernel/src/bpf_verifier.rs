//! The verifier of `BPF_PROG_LOAD`, for `BPF_PROG_TYPE_SOCKET_FILTER`, as
//! Linux's `kernel/bpf/verifier.c` and, in master, `cfg.c` check a
//! program: its structure first (`check_subprogs`, the checks of every
//! instruction's fields in `check_and_resolve_insns`, `check_cfg`), then
//! every path from the first instruction (`do_check`), with the state of
//! the registers and of the 512-byte stack along it.
//!
//! The rule is that a program Linux rejects is never accepted. "Linux" is
//! two kernels here: master, which the checks follow, and the x86-64 test
//! machines' Linux 7.0. Where they decide differently, the program is
//! rejected, so that the emulator accepts only what both accept:
//! - master takes a stack of up to `MAX_BPF_STACK_JIT` bytes where its JIT
//!   can, 7.0 512;
//! - with `allow_ptr_leaks`, master makes a number of a pointer that a
//!   multiplication, a shift or a bitwise operation is applied to, where
//!   7.0 refuses it;
//! - master takes an exit whose `src_reg` is `BPF_UNWIND_EXIT`;
//! - with no BTF, master takes `BPF_LD_ABS`, `BPF_LD_IND` and
//!   `bpf_tail_call` in a function other than the main program, where 7.0
//!   refuses them (`check_abnormal_return`);
//! - master refuses a recursive call before the walk ("recursive call from
//!   %s() to %s()", `sort_subprogs_topo`, `EINVAL`), where 7.0 and the test
//!   machines' kernel refuse it as the walk goes 9 frames deep (`E2BIG`),
//!   which is what is done here, as the differential tests compare it with
//!   that kernel; master's check comes once that kernel has it.
//!
//! Every function is static, as no program here has BTF: a call gives the
//! callee a frame of its own, up to 8 frames, whose stacks add up to 512
//! bytes, each rounded up to 16 as with the JIT the test machines run.
//!
//! The log lines are 7.0's where the two kernels word them differently
//! (the misaligned stack access, a sleepable program), as the differential
//! tests compare them with it. Master also writes a diagnostic after some
//! errors at log level 1 or more; that is not written here.
//!
//! What the verifier here does not do is a gap of the safe direction: it
//! rejects programs Linux accepts, and never the other way round.
//! - A scalar register is a value the verifier knows or none at all,
//!   where Linux keeps bounds and a tnum: so a value Linux knows, from a
//!   division or a comparison, say, is not known here, and both sides of
//!   a conditional jump are walked unless both operands are known. A
//!   value known here is known to Linux too, with the same value.
//! - No state is pruned: every path is walked, against the same limit of
//!   1,000,000 instructions and 8,192 pending branches, which Linux's
//!   pruning only keeps it further from.
//! - A lookup's result is null until the program compares it with 0 in a
//!   64-bit `BPF_JEQ` or `BPF_JNE` of an immediate, where Linux also knows
//!   an array's element by a constant key is there, and compares two
//!   pointers.
//! - Rejected outright, with a line of the emulator's own ("paludarium:
//!   ..."; a helper call's starts "unknown func", which tells libbpf and
//!   bpftool the helper is not there): the helpers a socket filter may
//!   call other than the map helpers, `bpf_skb_load_bytes`,
//!   `bpf_skb_load_bytes_relative`, `bpf_get_socket_cookie`,
//!   `bpf_get_socket_uid`, `bpf_get_netns_cookie` and those of no
//!   arguments (the clocks, `bpf_get_prandom_u32`, the processor and NUMA
//!   node, the current task's IDs), the map helpers of maps of maps,
//!   queues, stacks and bloom filters, a helper's size argument whose value
//!   is not known here, `bpf_get_netns_cookie` of a scalar not known to be
//!   0, kfuncs, the context's socket pointer
//!   (`__sk_buff.sk`) and a map's own fields (`struct bpf_map`), maps from
//!   `fd_array` and maps made with `excl_prog_hash`, BTF IDs and functions
//!   in `BPF_LD_IMM64` (and so callbacks), `may_goto`, indirect jumps, a
//!   back-edge (Linux takes a bounded loop from a privileged loader), a
//!   pointer with a variable offset, and
//!   `BPF_F_TEST_REG_INVARIANTS` with a conditional jump.
//! - The loader has `CAP_BPF` and `CAP_PERFMON` ([`crate::bpf_prog`]
//!   refuses others), so the verifier allows what Linux allows them:
//!   pointer leaks, uninitialized stack reads and no Spectre sanitizing.
use paludarium_types::Errno;

const EACCES: Errno = Errno(13);
const EPROTO: Errno = Errno(71);
/// The kernel's own `ENOTSUPP`, which reaches user space as it is.
const ENOTSUPP: Errno = Errno(524);
const E2BIG: Errno = Errno(7);

/// `BPF_COMPLEXITY_LIMIT_INSNS`.
const COMPLEXITY_LIMIT_INSNS: u32 = 1_000_000;
/// `BPF_COMPLEXITY_LIMIT_JMP_SEQ`.
const COMPLEXITY_LIMIT_JMP_SEQ: usize = 8192;
/// `MAX_BPF_STACK`.
const MAX_STACK: i64 = 512;
/// `BPF_MAX_VAR_OFF`.
const MAX_VAR_OFF: i64 = 1 << 29;
/// `BPF_MAX_VAR_SIZ`.
const MAX_VAR_SIZE: u64 = 1 << 29;
/// The largest number `tnum_strn` writes in decimal (`U16_MAX`).
const UNUM_MAX_DECIMAL: u64 = 0xffff;
/// `MAX_BPF_REG`: R0 to R10.
const REGS: usize = 11;
/// The frame pointer, R10.
const FP: usize = 10;

mod class {
    pub const LD: u8 = 0x00;
    pub const LDX: u8 = 0x01;
    pub const ST: u8 = 0x02;
    pub const STX: u8 = 0x03;
    pub const ALU: u8 = 0x04;
    pub const JMP: u8 = 0x05;
    pub const JMP32: u8 = 0x06;
    pub const ALU64: u8 = 0x07;
}

mod size {
    pub const W: u8 = 0x00;
    pub const H: u8 = 0x08;
    pub const B: u8 = 0x10;
    pub const DW: u8 = 0x18;
}

mod mode {
    pub const IMM: u8 = 0x00;
    pub const ABS: u8 = 0x20;
    pub const IND: u8 = 0x40;
    pub const MEM: u8 = 0x60;
    pub const MEMSX: u8 = 0x80;
    pub const ATOMIC: u8 = 0xc0;
}

/// `BPF_K` and `BPF_X`, which for `BPF_END` are `BPF_TO_LE` and
/// `BPF_TO_BE`.
const X: u8 = 0x08;

/// The operations of a `BPF_ATOMIC`, in its `imm`.
mod atomic {
    pub const ADD: i32 = 0x00;
    pub const OR: i32 = 0x40;
    pub const AND: i32 = 0x50;
    pub const XOR: i32 = 0xa0;
    /// `BPF_FETCH`: the old value goes to the source register.
    pub const FETCH: i32 = 0x01;
    pub const XCHG: i32 = 0xe0 | FETCH;
    pub const CMPXCHG: i32 = 0xf0 | FETCH;
    pub const LOAD_ACQ: i32 = 0x100;
    pub const STORE_REL: i32 = 0x110;
}

mod alu {
    pub const ADD: u8 = 0x00;
    pub const SUB: u8 = 0x10;
    pub const MUL: u8 = 0x20;
    pub const DIV: u8 = 0x30;
    pub const OR: u8 = 0x40;
    pub const AND: u8 = 0x50;
    pub const LSH: u8 = 0x60;
    pub const RSH: u8 = 0x70;
    pub const NEG: u8 = 0x80;
    pub const MOD: u8 = 0x90;
    pub const XOR: u8 = 0xa0;
    pub const MOV: u8 = 0xb0;
    pub const ARSH: u8 = 0xc0;
    pub const END: u8 = 0xd0;
    /// The operations of two operands, with `BPF_K` and `BPF_X` both.
    pub const BINARY: [u8; 12] = [ADD, SUB, MUL, DIV, OR, AND, LSH, RSH, MOD, XOR, MOV, ARSH];
}

mod jmp {
    pub const JA: u8 = 0x00;
    pub const JEQ: u8 = 0x10;
    pub const JGT: u8 = 0x20;
    pub const JGE: u8 = 0x30;
    pub const JSET: u8 = 0x40;
    pub const JNE: u8 = 0x50;
    pub const JSGT: u8 = 0x60;
    pub const JSGE: u8 = 0x70;
    pub const CALL: u8 = 0x80;
    pub const EXIT: u8 = 0x90;
    pub const JLT: u8 = 0xa0;
    pub const JLE: u8 = 0xb0;
    pub const JSLT: u8 = 0xc0;
    pub const JSLE: u8 = 0xd0;
    pub const JCOND: u8 = 0xe0;
    pub const CONDITIONS: [u8; 11] = [JEQ, JGT, JGE, JSET, JNE, JSGT, JSGE, JLT, JLE, JSLT, JSLE];
}

/// `BPF_PSEUDO_*`, in `src_reg`.
mod pseudo {
    pub const MAP_FD: u8 = 1;
    pub const MAP_VALUE: u8 = 2;
    pub const BTF_ID: u8 = 3;
    pub const FUNC: u8 = 4;
    pub const MAP_IDX: u8 = 5;
    pub const MAP_IDX_VALUE: u8 = 6;
    pub const CALL: u8 = 1;
    pub const KFUNC_CALL: u8 = 2;
}

/// `BPF_ADDR_SPACE_CAST`, in a 64-bit `BPF_MOV`'s `off`.
const ADDR_SPACE_CAST: i16 = 1;

/// One `struct bpf_insn`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Insn {
    pub(crate) code: u8,
    pub(crate) dst: u8,
    pub(crate) src: u8,
    pub(crate) off: i16,
    pub(crate) imm: i32,
}

impl Insn {
    pub(crate) fn decode(b: [u8; 8]) -> Insn {
        Insn {
            code: b[0],
            dst: b[1] & 0x0f,
            src: b[1] >> 4,
            off: i16::from_le_bytes([b[2], b[3]]),
            imm: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
    fn class(self) -> u8 {
        self.code & 0x07
    }
    fn op(self) -> u8 {
        self.code & 0xf0
    }
    fn mode(self) -> u8 {
        self.code & 0xe0
    }
    fn size(self) -> u8 {
        self.code & 0x18
    }
    fn x(self) -> bool {
        self.code & X != 0
    }
    fn jumps(self) -> bool {
        matches!(self.class(), class::JMP | class::JMP32)
    }
    /// `bpf_is_ldimm64`.
    fn ldimm64(self) -> bool {
        self.code == class::LD | mode::IMM | size::DW
    }
    /// `bpf_jmp_offset`: a 32-bit `BPF_JA` jumps by `imm`.
    fn jump(self) -> i64 {
        if self.code == class::JMP32 | jmp::JA {
            i64::from(self.imm)
        } else {
            i64::from(self.off)
        }
    }
}

/// What the loader asked for that the checks depend on.
#[derive(Clone, Copy, Default)]
pub(crate) struct Options {
    /// `BPF_F_SLEEPABLE`.
    pub(crate) sleepable: bool,
    /// `BPF_F_STRICT_ALIGNMENT` without `BPF_F_ANY_ALIGNMENT`.
    pub(crate) strict_alignment: bool,
    /// `BPF_F_TEST_REG_INVARIANTS`.
    pub(crate) test_reg_invariants: bool,
    /// Whether `fd_array` is given.
    pub(crate) fd_array: bool,
}

/// What the verifier needs of a map a program names by its descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MapShape {
    /// The map's ID, which tells two descriptors of one map apart from two
    /// maps (`used_maps` holds each map once).
    pub(crate) id: u32,
    pub(crate) kind: u32,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) flags: u32,
    /// Made with `excl_prog_hash`.
    pub(crate) exclusive: bool,
}

/// `__bpf_map_get` of a descriptor: the map's shape, or `EBADF` for no
/// descriptor and `EINVAL` for one of no map.
pub(crate) type Maps<'a> = dyn FnMut(i32) -> Result<MapShape, Errno> + 'a;

/// `MAX_USED_MAPS`.
const MAX_USED_MAPS: usize = 64;

mod map_type {
    pub const HASH: u32 = 1;
    pub const ARRAY: u32 = 2;
    pub const LRU_HASH: u32 = 9;
    pub const LPM_TRIE: u32 = 11;
    pub const ARRAY_OF_MAPS: u32 = 12;
    pub const HASH_OF_MAPS: u32 = 13;
    pub const QUEUE: u32 = 22;
    pub const STACK: u32 = 23;
}

/// The map flags a program's access depends on (`bpf_map_flags_to_cap`).
const F_RDONLY_PROG: u32 = 1 << 7;
const F_WRONLY_PROG: u32 = 1 << 8;

/// The helpers in range, `enum bpf_func_id`.
mod func {
    pub const MAP_LOOKUP_ELEM: i32 = 1;
    pub const TAIL_CALL: i32 = 12;
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

/// The names of `enum bpf_func_id`, by ID, without the `bpf_` that
/// `func_id_name` puts before each: the helpers Linux 7.0 knows
/// (`__BPF_FUNC_MAX_ID` is 212).
const HELPER_NAMES: &str = "\
    unspec map_lookup_elem map_update_elem map_delete_elem probe_read ktime_get_ns \
    trace_printk get_prandom_u32 get_smp_processor_id skb_store_bytes \
    l3_csum_replace l4_csum_replace tail_call clone_redirect get_current_pid_tgid \
    get_current_uid_gid get_current_comm get_cgroup_classid skb_vlan_push \
    skb_vlan_pop skb_get_tunnel_key skb_set_tunnel_key perf_event_read redirect \
    get_route_realm perf_event_output skb_load_bytes get_stackid csum_diff \
    skb_get_tunnel_opt skb_set_tunnel_opt skb_change_proto skb_change_type \
    skb_under_cgroup get_hash_recalc get_current_task probe_write_user \
    current_task_under_cgroup skb_change_tail skb_pull_data csum_update \
    set_hash_invalid get_numa_node_id skb_change_head xdp_adjust_head probe_read_str \
    get_socket_cookie get_socket_uid set_hash setsockopt skb_adjust_room \
    redirect_map sk_redirect_map sock_map_update xdp_adjust_meta \
    perf_event_read_value perf_prog_read_value getsockopt override_return \
    sock_ops_cb_flags_set msg_redirect_map msg_apply_bytes msg_cork_bytes \
    msg_pull_data bind xdp_adjust_tail skb_get_xfrm_state get_stack \
    skb_load_bytes_relative fib_lookup sock_hash_update msg_redirect_hash \
    sk_redirect_hash lwt_push_encap lwt_seg6_store_bytes lwt_seg6_adjust_srh \
    lwt_seg6_action rc_repeat rc_keydown skb_cgroup_id get_current_cgroup_id \
    get_local_storage sk_select_reuseport skb_ancestor_cgroup_id sk_lookup_tcp \
    sk_lookup_udp sk_release map_push_elem map_pop_elem map_peek_elem msg_push_data \
    msg_pop_data rc_pointer_rel spin_lock spin_unlock sk_fullsock tcp_sock \
    skb_ecn_set_ce get_listener_sock skc_lookup_tcp tcp_check_syncookie \
    sysctl_get_name sysctl_get_current_value sysctl_get_new_value \
    sysctl_set_new_value strtol strtoul sk_storage_get sk_storage_delete send_signal \
    tcp_gen_syncookie skb_output probe_read_user probe_read_kernel \
    probe_read_user_str probe_read_kernel_str tcp_send_ack send_signal_thread \
    jiffies64 read_branch_records get_ns_current_pid_tgid xdp_output \
    get_netns_cookie get_current_ancestor_cgroup_id sk_assign ktime_get_boot_ns \
    seq_printf seq_write sk_cgroup_id sk_ancestor_cgroup_id ringbuf_output \
    ringbuf_reserve ringbuf_submit ringbuf_discard ringbuf_query csum_level \
    skc_to_tcp6_sock skc_to_tcp_sock skc_to_tcp_timewait_sock \
    skc_to_tcp_request_sock skc_to_udp6_sock get_task_stack load_hdr_opt \
    store_hdr_opt reserve_hdr_opt inode_storage_get inode_storage_delete d_path \
    copy_from_user snprintf_btf seq_printf_btf skb_cgroup_classid redirect_neigh \
    per_cpu_ptr this_cpu_ptr redirect_peer task_storage_get task_storage_delete \
    get_current_task_btf bprm_opts_set ktime_get_coarse_ns ima_inode_hash \
    sock_from_file check_mtu for_each_map_elem snprintf sys_bpf \
    btf_find_by_name_kind sys_close timer_init timer_set_callback timer_start \
    timer_cancel get_func_ip get_attach_cookie task_pt_regs get_branch_snapshot \
    trace_vprintk skc_to_unix_sock kallsyms_lookup_name find_vma loop strncmp \
    get_func_arg get_func_ret get_func_arg_cnt get_retval set_retval \
    xdp_get_buff_len xdp_load_bytes xdp_store_bytes copy_from_user_task \
    skb_set_tstamp ima_file_hash kptr_xchg map_lookup_percpu_elem skc_to_mptcp_sock \
    dynptr_from_mem ringbuf_reserve_dynptr ringbuf_submit_dynptr \
    ringbuf_discard_dynptr dynptr_read dynptr_write dynptr_data \
    tcp_raw_gen_syncookie_ipv4 tcp_raw_gen_syncookie_ipv6 \
    tcp_raw_check_syncookie_ipv4 tcp_raw_check_syncookie_ipv6 ktime_get_tai_ns \
    user_ringbuf_drain cgrp_storage_get cgrp_storage_delete";

/// `func_id_name`, or `None` for an ID out of range.
fn helper_name(id: i32) -> Option<&'static str> {
    HELPER_NAMES
        .split_whitespace()
        .nth(usize::try_from(id).ok()?)
}

/// Whether `sk_filter_func_proto` gives a helper to a loader with
/// `CAP_BPF` and `CAP_PERFMON`: its own, then `bpf_sk_base_func_proto`'s
/// and `bpf_base_func_proto`'s (the same in master).
fn socket_filter_helper(id: i32) -> bool {
    matches!(
        id,
        // sk_filter_func_proto.
        25 | 26 | 46 | 47 | 68 | 122
        // bpf_sk_base_func_proto.
        | 136..=140 | 160 | 178 | 196
        // bpf_base_func_proto, for every loader.
        | 1..=3 | 5 | 7 | 8 | 12 | 14 | 15 | 42 | 87..=89 | 105 | 106 | 120 | 125
        | 130..=134 | 182 | 195 | 208
        // With CAP_BPF.
        | 17 | 37 | 80 | 93 | 94 | 118 | 123 | 153 | 154 | 156 | 157 | 164 | 169..=172
        | 181 | 194 | 197..=203 | 209..=211
        // With CAP_PERFMON.
        | 6 | 16 | 22 | 35 | 55 | 109 | 112..=115 | 117 | 141 | 148 | 149 | 158 | 165
        | 175..=177 | 180 | 191
    )
}

/// The offsets in `struct __sk_buff` that a socket filter's access to it
/// depends on.
mod skb {
    pub const SIZE: i64 = 192;
    /// `cb[0]` to the end of `cb[4]`.
    pub const CB: std::ops::Range<i64> = 48..68;
    /// `sk`, a pointer.
    pub const SK: std::ops::Range<i64> = 168..176;
}

/// What a valid access to the context gives.
enum Field {
    Scalar,
    /// `__sk_buff.sk`, `PTR_TO_SOCK_COMMON_OR_NULL`.
    Socket,
}

/// `sk_filter_is_valid_access` and `bpf_skb_is_valid_access` (the same in
/// master) of `size` bytes at `off`.
fn context_field(off: i64, size: i64, write: bool) -> Option<Field> {
    // A socket filter's own refusals: tc_classid, data, data_end, family
    // to local_port, data_meta, tstamp, wire_len and hwtstamp.
    if matches!(off, 72..=83 | 88..=143 | 152..=163 | 184..=191) {
        return None;
    }
    if write && !skb::CB.contains(&off) {
        return None;
    }
    if !(0..skb::SIZE).contains(&off) || off % size != 0 {
        return None;
    }
    match off {
        _ if skb::CB.contains(&off) => (off + size <= skb::CB.end).then_some(Field::Scalar),
        // flow_keys, tstamp_type and the padding after it.
        144..=151 | 180..=183 => None,
        _ if skb::SK.contains(&off) => (size == 8).then_some(Field::Socket),
        // The rest are 4-byte fields that may be read narrower
        // (bpf_ctx_narrow_access_ok).
        _ => (size <= 4).then_some(Field::Scalar),
    }
}

/// A program that passed.
#[derive(Debug)]
pub(crate) struct Verified {
    /// `insn_processed`, which fdinfo's `verified_insns` gives.
    pub(crate) processed: u32,
    /// The stack each function uses (`stack_depth`), in bytes, rounded up
    /// to 8, the main program's first.
    pub(crate) stack_depth: Vec<u32>,
    /// `max_stack_depth`: the most stack a chain of calls takes.
    pub(crate) max_stack_depth: u32,
    /// The maps the program uses (`used_maps`), by ID.
    pub(crate) maps: Vec<u32>,
    /// Each `BPF_LD_IMM64` of a map: the map's index in `maps`, and the
    /// offset in the value of a `BPF_PSEUDO_MAP_VALUE`.
    pub(crate) loads: std::collections::BTreeMap<usize, (u8, Option<u32>)>,
}

/// Why a program is refused: the error and the line the log gets.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Rejection {
    pub(crate) errno: Errno,
    pub(crate) line: String,
    /// `insn_processed` when it was refused.
    pub(crate) processed: u32,
    pub(crate) stack_depth: Vec<u32>,
    pub(crate) max_stack_depth: u32,
}

type Checked<T> = Result<T, (Errno, String)>;

fn refuse<T>(errno: Errno, line: impl Into<String>) -> Checked<T> {
    Err((errno, line.into()))
}

/// What the emulator does not verify yet, which Linux may take.
fn gap<T>(what: &str) -> Checked<T> {
    refuse(
        Errno::EINVAL,
        format!("paludarium: {what} are not verified yet"),
    )
}

/// `bpf_check`'s first check of the instructions, which comes before
/// `process_fd_array` and the rest ([`crate::bpf_prog`] makes it): the
/// last one may not be the first half of a BPF_LD_IMM64.
pub(crate) fn ends_in_half(insns: &[Insn]) -> bool {
    insns.last().is_some_and(|i| i.ldimm64())
}

/// `bpf_check` for a socket filter, from the checks of the instructions on,
/// for a program [`ends_in_half`] took. `BPF_PROG_LOAD` refuses no
/// instructions at all (`E2BIG`) before it gets here.
pub(crate) fn check(
    insns: &[Insn],
    options: Options,
    maps: &mut Maps<'_>,
) -> Result<Verified, Rejection> {
    debug_assert!(!insns.is_empty() && !ends_in_half(insns));
    let mut walk = Walk::default();
    let result = structure(insns, options, maps, &mut walk)
        .and_then(|()| walk.run(insns, options))
        .and_then(|()| walk.max_stack_depth(insns));
    let mut stack_depth: Vec<u32> = walk.depth.iter().map(|d| d.div_ceil(8) * 8).collect();
    if stack_depth.is_empty() {
        stack_depth.push(0);
    }
    match result {
        Ok(()) => Ok(Verified {
            processed: walk.processed,
            stack_depth,
            max_stack_depth: walk.max_depth,
            maps: walk.maps.iter().map(|m| m.id).collect(),
            loads: std::mem::take(&mut walk.loads),
        }),
        Err((errno, line)) => Err(Rejection {
            errno,
            line,
            processed: walk.processed,
            stack_depth,
            max_stack_depth: walk.max_depth,
        }),
    }
}

/// The checks before any path is walked, in master's order.
fn structure(
    insns: &[Insn],
    options: Options,
    maps: &mut Maps<'_>,
    walk: &mut Walk,
) -> Checked<()> {
    // add_subprogs, then kfuncs and references to functions.
    walk.starts = add_subprogs(insns)?;
    walk.depth = vec![0; walk.starts.len()];
    for insn in insns {
        if insn.code == class::JMP | jmp::CALL && insn.src == pseudo::KFUNC_CALL {
            return gap("kfuncs");
        }
        if insn.ldimm64() && insn.src == pseudo::FUNC {
            return gap("references to functions");
        }
    }
    subprogs(insns, &walk.starts)?;
    abnormal_return(insns, &walk.starts)?;
    let mut i = 0;
    while i < insns.len() {
        // A BPF_LD_IMM64's second half is checked with its first.
        i += fields(insns, i, options, maps, walk)?;
    }
    cfg(insns)?;
    // check_attach_btf_id: a socket filter cannot sleep. 7.0's words.
    if options.sleepable {
        return refuse(
            Errno::EINVAL,
            "Only fentry/fexit/fmod_ret, lsm, iter, uprobe, and struct_ops programs can be sleepable",
        );
    }
    if options.test_reg_invariants
        && insns
            .iter()
            .any(|i| i.jumps() && !matches!(i.op(), jmp::JA | jmp::CALL | jmp::EXIT))
    {
        return gap("register invariants (BPF_F_TEST_REG_INVARIANTS) of conditional jumps");
    }
    Ok(())
}

/// `BPF_MAX_SUBPROGS`.
const MAX_SUBPROGS: usize = 256;
/// `MAX_CALL_FRAMES`.
const MAX_CALL_FRAMES: usize = 8;

/// `add_subprogs`: where each function starts, in order, the main
/// program's at 0 and one at each target of a `BPF_PSEUDO_CALL`. The
/// loader has `CAP_BPF`.
fn add_subprogs(insns: &[Insn]) -> Checked<Vec<usize>> {
    let mut starts = vec![0];
    for (i, insn) in insns.iter().enumerate() {
        if insn.code != class::JMP | jmp::CALL || insn.src != pseudo::CALL {
            continue;
        }
        let to = i as i64 + i64::from(insn.imm) + 1;
        if to < 0 || to >= insns.len() as i64 {
            return refuse(Errno::EINVAL, "call to invalid destination");
        }
        let to = to as usize;
        if let Err(at) = starts.binary_search(&to) {
            if starts.len() >= MAX_SUBPROGS {
                return refuse(E2BIG, "too many subprograms");
            }
            starts.insert(at, to);
        }
    }
    Ok(starts)
}

/// The instructions of function `f`.
fn body(starts: &[usize], n: usize, f: usize) -> std::ops::Range<usize> {
    starts[f]..starts.get(f + 1).copied().unwrap_or(n)
}

/// `check_subprogs`: jumps stay in their function, and each function's
/// last instruction is an exit or a jump.
fn subprogs(insns: &[Insn], starts: &[usize]) -> Checked<()> {
    for f in 0..starts.len() {
        let range = body(starts, insns.len(), f);
        for i in range.clone() {
            let insn = insns[i];
            if insn.jumps() && !matches!(insn.op(), jmp::CALL | jmp::EXIT) {
                let to = i as i64 + insn.jump() + 1;
                if to < range.start as i64 || to >= range.end as i64 {
                    return refuse(
                        Errno::EINVAL,
                        format!("jump out of range from insn {i} to {to}"),
                    );
                }
            }
        }
        let last = insns[range.end - 1].code;
        if last != class::JMP | jmp::EXIT
            && last != class::JMP32 | jmp::JA
            && last != class::JMP | jmp::JA
        {
            return refuse(Errno::EINVAL, "last insn is not an exit or jmp");
        }
    }
    Ok(())
}

/// 7.0's `check_abnormal_return`, which `check_btf_func` makes of a
/// program with no `func_info`, as every program is here: no function but
/// the main program may use `BPF_LD_ABS` or `BPF_LD_IND`, or call
/// `bpf_tail_call`. Master takes them.
fn abnormal_return(insns: &[Insn], starts: &[usize]) -> Checked<()> {
    for f in 1..starts.len() {
        let body = &insns[body(starts, insns.len(), f)];
        if body
            .iter()
            .any(|i| i.class() == class::LD && matches!(i.mode(), mode::ABS | mode::IND))
        {
            return refuse(
                Errno::EINVAL,
                "LD_ABS is not allowed in subprogs without BTF",
            );
        }
        if body
            .iter()
            .any(|i| i.code == class::JMP | jmp::CALL && i.src == 0 && i.imm == func::TAIL_CALL)
        {
            return refuse(
                Errno::EINVAL,
                "tail_call is not allowed in subprogs without BTF",
            );
        }
    }
    Ok(())
}

/// `bpf_opcode_in_insntable`, master's (which also has `BPF_CALL|BPF_X`).
fn known(code: u8) -> bool {
    let op = code & 0xf0;
    match code & 0x07 {
        class::ALU => alu::BINARY.contains(&op) || code == class::ALU | alu::NEG || op == alu::END,
        class::ALU64 => {
            alu::BINARY.contains(&op)
                || code == class::ALU64 | alu::NEG
                || code == class::ALU64 | alu::END
        }
        class::JMP => {
            jmp::CONDITIONS.contains(&op)
                || code == class::JMP | jmp::CALL
                || code == class::JMP | jmp::EXIT
                || code == class::JMP | jmp::JA
                // UAPI-exposed: an indirect jump, may_goto, and master's
                // indirect call.
                || code == class::JMP | jmp::JA | X
                || code == class::JMP | jmp::JCOND
                || code == class::JMP | jmp::CALL | X
        }
        class::JMP32 => jmp::CONDITIONS.contains(&op) || code == class::JMP32 | jmp::JA,
        class::STX => matches!(code & 0xe0, mode::MEM | mode::ATOMIC),
        class::ST => code & 0xe0 == mode::MEM,
        class::LDX => {
            code & 0xe0 == mode::MEM || (code & 0xe0 == mode::MEMSX && code & 0x18 != size::DW)
        }
        _ => {
            code == class::LD | mode::IMM | size::DW
                || (matches!(code & 0xe0, mode::ABS | mode::IND) && code & 0x18 != size::DW)
        }
    }
}

/// `check_and_resolve_insns` for the instruction at `i`: its registers,
/// a BPF_LD_IMM64's second half, the opcode, and `check_insn_fields`.
/// Gives how many instructions it took.
fn fields(
    insns: &[Insn],
    i: usize,
    options: Options,
    maps: &mut Maps<'_>,
    walk: &mut Walk,
) -> Checked<usize> {
    let insn = insns[i];
    if usize::from(insn.dst) >= REGS {
        return refuse(Errno::EINVAL, format!("R{} is invalid", insn.dst));
    }
    if usize::from(insn.src) >= REGS {
        return refuse(Errno::EINVAL, format!("R{} is invalid", insn.src));
    }
    if insn.ldimm64() {
        let next = insns.get(i + 1);
        if next.is_none_or(|n| n.code != 0 || n.dst != 0 || n.src != 0 || n.off != 0) {
            return refuse(Errno::EINVAL, "invalid bpf_ld_imm64 insn");
        }
        // Master's place; 7.0 refuses it as it walks the instruction.
        if insn.off != 0 {
            return refuse(Errno::EINVAL, "BPF_LD_IMM64 uses reserved fields");
        }
        let second = next.map_or(0, |n| n.imm);
        match insn.src {
            0 => return Ok(2),
            pseudo::BTF_ID => return gap("BTF IDs in BPF_LD_IMM64"),
            pseudo::FUNC => return gap("references to functions"),
            pseudo::MAP_VALUE | pseudo::MAP_IDX_VALUE => {}
            pseudo::MAP_FD | pseudo::MAP_IDX if second == 0 => {}
            _ => return refuse(Errno::EINVAL, "unrecognized bpf_ld_imm64 insn"),
        }
        if matches!(insn.src, pseudo::MAP_IDX | pseudo::MAP_IDX_VALUE) {
            if !options.fd_array {
                return refuse(EPROTO, "fd_idx without fd_array is invalid");
            }
            return gap("maps from fd_array");
        }
        let map = walk.use_map(insn.imm, options, maps)?;
        let value = if insn.src == pseudo::MAP_VALUE {
            // map_direct_value_addr: an array of one element alone.
            let shape = walk.maps[usize::from(map)];
            let off = second as u32;
            if shape.kind != map_type::ARRAY {
                return refuse(
                    Errno::EINVAL,
                    "no direct value access support for this map type",
                );
            }
            let errno = if shape.max_entries != 1 {
                Some(ENOTSUPP)
            } else if off >= shape.value_size {
                Some(Errno::EINVAL)
            } else {
                None
            };
            if let Some(errno) = errno {
                return refuse(
                    errno,
                    format!(
                        "invalid access to map value pointer, value_size={} off={off}",
                        shape.value_size
                    ),
                );
            }
            Some(off)
        } else {
            None
        };
        walk.loads.insert(i, (map, value));
        return Ok(2);
    }
    if !known(insn.code) {
        return refuse(Errno::EINVAL, format!("unknown opcode {:02x}", insn.code));
    }
    insn_fields(insn).map(|()| 1)
}

/// `check_insn_fields`.
fn insn_fields(insn: Insn) -> Checked<()> {
    match insn.class() {
        class::ALU | class::ALU64 => alu_fields(insn),
        class::LDX => {
            if !matches!(insn.mode(), mode::MEM | mode::MEMSX) || insn.imm != 0 {
                return refuse(Errno::EINVAL, "BPF_LDX uses reserved fields");
            }
            Ok(())
        }
        class::STX => {
            if insn.mode() == mode::ATOMIC {
                return Ok(());
            }
            if insn.mode() != mode::MEM || insn.imm != 0 {
                return refuse(Errno::EINVAL, "BPF_STX uses reserved fields");
            }
            Ok(())
        }
        class::ST => {
            if insn.mode() != mode::MEM || insn.src != 0 {
                return refuse(Errno::EINVAL, "BPF_ST uses reserved fields");
            }
            Ok(())
        }
        class::JMP | class::JMP32 => jmp_fields(insn),
        _ => {
            // BPF_LD_ABS and BPF_LD_IND: BPF_LD_IMM64 was dealt with above.
            if insn.dst != 0
                || insn.off != 0
                || insn.size() == size::DW
                || (insn.mode() == mode::ABS && insn.src != 0)
            {
                return refuse(Errno::EINVAL, "BPF_LD_[ABS|IND] uses reserved fields");
            }
            Ok(())
        }
    }
}

/// `check_alu_fields`.
fn alu_fields(insn: Insn) -> Checked<()> {
    let op = insn.op();
    let wide = insn.class() == class::ALU64;
    match op {
        alu::NEG => {
            if insn.x() || insn.src != 0 || insn.off != 0 || insn.imm != 0 {
                return refuse(Errno::EINVAL, "BPF_NEG uses reserved fields");
            }
        }
        alu::END => {
            if insn.src != 0
                || insn.off != 0
                || !matches!(insn.imm, 16 | 32 | 64)
                || (wide && insn.x())
            {
                return refuse(Errno::EINVAL, "BPF_END uses reserved fields");
            }
        }
        alu::MOV => {
            if insn.x() {
                if !wide {
                    if !matches!(insn.off, 0 | 8 | 16) || insn.imm != 0 {
                        return refuse(Errno::EINVAL, "BPF_MOV uses reserved fields");
                    }
                } else if insn.off == ADDR_SPACE_CAST {
                    if insn.imm != 1 && insn.imm != 1 << 16 {
                        return refuse(
                            Errno::EINVAL,
                            "addr_space_cast insn can only convert between address space 1 and 0",
                        );
                    }
                } else if !matches!(insn.off, 0 | 8 | 16 | 32) || insn.imm != 0 {
                    return refuse(Errno::EINVAL, "BPF_MOV uses reserved fields");
                }
            } else if insn.src != 0 || insn.off != 0 {
                return refuse(Errno::EINVAL, "BPF_MOV uses reserved fields");
            }
        }
        _ => {
            let signed = insn.off == 1 && matches!(op, alu::DIV | alu::MOD);
            let bad = if insn.x() {
                insn.imm != 0
            } else {
                insn.src != 0
            };
            if bad || (insn.off != 0 && !signed) {
                return refuse(Errno::EINVAL, "BPF_ALU uses reserved fields");
            }
        }
    }
    Ok(())
}

/// `check_jmp_fields`. An exit's `src_reg` is 0, as 7.0 has it.
fn jmp_fields(insn: Insn) -> Checked<()> {
    let wide = insn.class() == class::JMP;
    match insn.op() {
        jmp::CALL => {
            if insn.code == class::JMP | jmp::CALL | X {
                if insn.src != 0 || insn.imm != 0 || insn.off != 0 {
                    return refuse(Errno::EINVAL, "BPF_CALL|BPF_X uses reserved fields");
                }
                return Ok(());
            }
            if insn.x()
                || (insn.src != pseudo::KFUNC_CALL && insn.off != 0)
                || !matches!(insn.src, 0 | pseudo::CALL | pseudo::KFUNC_CALL)
                || insn.dst != 0
                || !wide
            {
                return refuse(Errno::EINVAL, "BPF_CALL uses reserved fields");
            }
        }
        jmp::JA => {
            if insn.x() {
                if insn.src != 0 || insn.imm != 0 || insn.off != 0 {
                    return refuse(Errno::EINVAL, "BPF_JA|BPF_X uses reserved fields");
                }
            } else if insn.src != 0
                || insn.dst != 0
                || (wide && insn.imm != 0)
                || (!wide && insn.off != 0)
            {
                return refuse(Errno::EINVAL, "BPF_JA uses reserved fields");
            }
        }
        jmp::EXIT => {
            if insn.x() || insn.imm != 0 || insn.src != 0 || insn.dst != 0 || !wide {
                return refuse(Errno::EINVAL, "BPF_EXIT uses reserved fields");
            }
        }
        jmp::JCOND => {
            if insn.code != class::JMP | jmp::JCOND
                || insn.src != 0
                || insn.dst != 0
                || insn.imm != 0
            {
                return refuse(Errno::EINVAL, format!("invalid may_goto imm {}", insn.imm));
            }
        }
        _ => {
            if (insn.x() && insn.imm != 0) || (!insn.x() && insn.src != 0) {
                return refuse(Errno::EINVAL, "BPF_JMP/JMP32 uses reserved fields");
            }
        }
    }
    Ok(())
}

/// `check_cfg`: a depth-first walk of the instructions' edges, which
/// finds jumps out of the program, back-edges, instructions no path
/// reaches and jumps into the middle of a BPF_LD_IMM64.
fn cfg(insns: &[Insn]) -> Checked<()> {
    const DISCOVERED: u8 = 0x10;
    const EXPLORED: u8 = 0x20;
    const FALLTHROUGH: u8 = 1;
    const BRANCH: u8 = 2;
    enum Next {
        Done,
        Keep,
    }
    let n = insns.len();
    let mut state = vec![0u8; n];
    let mut stack = vec![0usize];
    state[0] = DISCOVERED;
    // A call's edge to its function may reach one the walk is in: that is
    // recursion, which the walk refuses as it goes 9 frames deep.
    let push = |state: &mut Vec<u8>,
                stack: &mut Vec<usize>,
                t: usize,
                w: i64,
                e: u8,
                call: bool|
     -> Checked<Next> {
        if state[t] >= DISCOVERED | e {
            return Ok(Next::Done);
        }
        if w < 0 || w >= n as i64 {
            return refuse(
                Errno::EINVAL,
                format!("jump out of range from insn {t} to {w}"),
            );
        }
        let w = w as usize;
        if state[w] == 0 {
            state[t] = DISCOVERED | e;
            state[w] = DISCOVERED;
            stack.push(w);
            Ok(Next::Keep)
        } else if state[w] & 0xf0 == DISCOVERED && call {
            Ok(Next::Done)
        } else if state[w] & 0xf0 == DISCOVERED {
            // Linux takes the back-edge from a privileged loader and checks
            // the loop as it walks it; it is not walked here.
            refuse(Errno::EINVAL, format!("back-edge from insn {t} to {w}"))
        } else {
            state[t] = DISCOVERED | e;
            Ok(Next::Done)
        }
    };
    while let Some(&t) = stack.last() {
        let insn = insns[t];
        let t64 = t as i64;
        let next = if !insn.jumps() {
            let width = if insn.ldimm64() { 2 } else { 1 };
            push(&mut state, &mut stack, t, t64 + width, FALLTHROUGH, false)?
        } else {
            match insn.op() {
                jmp::EXIT => Next::Done,
                // visit_func_call_insn: after the call, then the function.
                jmp::CALL if insn.src == pseudo::CALL => {
                    match push(&mut state, &mut stack, t, t64 + 1, FALLTHROUGH, false)? {
                        Next::Keep => Next::Keep,
                        Next::Done => push(
                            &mut state,
                            &mut stack,
                            t,
                            t64 + i64::from(insn.imm) + 1,
                            BRANCH,
                            true,
                        )?,
                    }
                }
                jmp::CALL => push(&mut state, &mut stack, t, t64 + 1, FALLTHROUGH, false)?,
                jmp::JA if insn.x() => return gap("indirect jumps"),
                jmp::JA => push(
                    &mut state,
                    &mut stack,
                    t,
                    t64 + insn.jump() + 1,
                    FALLTHROUGH,
                    false,
                )?,
                _ => match push(&mut state, &mut stack, t, t64 + 1, FALLTHROUGH, false)? {
                    Next::Keep => Next::Keep,
                    Next::Done => push(
                        &mut state,
                        &mut stack,
                        t,
                        t64 + i64::from(insn.off) + 1,
                        BRANCH,
                        false,
                    )?,
                },
            }
        };
        if let Next::Done = next {
            state[t] = EXPLORED;
            stack.pop();
        }
    }
    let mut i = 0;
    while i < n {
        if state[i] != EXPLORED {
            return refuse(Errno::EINVAL, format!("unreachable insn {i}"));
        }
        if insns[i].ldimm64() {
            if state[i + 1] != 0 {
                return refuse(
                    Errno::EINVAL,
                    format!("jump into the middle of ldimm64 insn {i}"),
                );
            }
            i += 1;
        }
        i += 1;
    }
    Ok(())
}

/// What a register holds: Linux's `enum bpf_reg_type`, for the types in
/// range, with a pointer's fixed offset (`reg->off`) and a scalar's value
/// when the verifier knows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reg {
    NotInit,
    Scalar(Option<u64>),
    Ptr(Ptr, i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ptr {
    /// `PTR_TO_CTX`, the `struct __sk_buff` R1 starts with.
    Ctx,
    /// `PTR_TO_STACK`, from the frame pointer of the frame of this number
    /// (`frameno`, 0 the main program's).
    Stack(u8),
    /// `CONST_PTR_TO_MAP`, the map of an index into `used_maps`.
    Map(u8),
    /// `PTR_TO_MAP_VALUE`, into a value of the map.
    Value(u8),
    /// `PTR_TO_MAP_VALUE | PTR_MAYBE_NULL`, a lookup's result before the
    /// program compares it with 0, with the ID every copy of it shares.
    MaybeNull(u8, u32),
}

impl Ptr {
    /// `reg_type_str`.
    fn name(self) -> &'static str {
        match self {
            Ptr::Ctx => "ctx",
            Ptr::Stack(_) => "fp",
            Ptr::Map(_) => "map_ptr",
            Ptr::Value(_) => "map_value",
            Ptr::MaybeNull(..) => "map_value_or_null",
        }
    }
}

/// `reg_type_str` of a register.
fn reg_name(reg: Reg) -> &'static str {
    match reg {
        Reg::NotInit => "?",
        Reg::Scalar(_) => "scalar",
        Reg::Ptr(p, _) => p.name(),
    }
}

/// An 8-byte stack slot: a register spilled whole (`STACK_SPILL`), or
/// bytes a read takes as a scalar. A privileged loader may read slots
/// never written (`allow_uninit_stack`), so those are bytes too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    Bytes,
    Spill(Reg),
}

/// A frame's 512-byte stack, by 8-byte slot from the frame pointer down.
type Stack = [Slot; (MAX_STACK / 8) as usize];

/// A frame below the current one: the caller's registers as the call
/// left them, its stack, its function and where it goes on.
#[derive(Clone)]
struct Caller {
    regs: [Reg; REGS],
    stack: Stack,
    subprog: usize,
    ret: usize,
}

/// A path's state (`bpf_verifier_state`): the current frame's registers,
/// stack and function, and the frames of its callers, as many as its
/// number (`curframe`).
#[derive(Clone)]
struct State {
    insn: usize,
    regs: [Reg; REGS],
    stack: Stack,
    subprog: usize,
    callers: Vec<Caller>,
}

impl State {
    /// The current frame's number.
    fn frame(&self) -> u8 {
        self.callers.len() as u8
    }
    /// The stack of frame `frame` and its function.
    fn stack_of(&mut self, frame: u8) -> (&mut Stack, usize) {
        match self.callers.get_mut(usize::from(frame)) {
            Some(caller) => (&mut caller.stack, caller.subprog),
            None => (&mut self.stack, self.subprog),
        }
    }
    /// `mark_ptr_or_null_regs`: every copy of the lookup's result `id`, in
    /// a register or spilled, in any frame, is 0 (a scalar) or a pointer to
    /// a value.
    fn null_check(&mut self, id: u32, null: bool) {
        let mark = |reg: &mut Reg| {
            if let Reg::Ptr(Ptr::MaybeNull(map, i), _) = *reg
                && i == id
            {
                *reg = if null {
                    Reg::Scalar(Some(0))
                } else {
                    Reg::Ptr(Ptr::Value(map), 0)
                };
            }
        };
        let frames = std::iter::once((&mut self.regs, &mut self.stack)).chain(
            self.callers
                .iter_mut()
                .map(|caller| (&mut caller.regs, &mut caller.stack)),
        );
        for (regs, stack) in frames {
            regs.iter_mut().for_each(mark);
            for slot in stack.iter_mut() {
                if let Slot::Spill(reg) = slot {
                    mark(reg);
                }
            }
        }
    }
}

/// `bpf_alu_string`.
fn alu_name(op: u8) -> &'static str {
    match op {
        alu::ADD => "+=",
        alu::SUB => "-=",
        alu::MUL => "*=",
        alu::DIV => "/=",
        alu::OR => "|=",
        alu::AND => "&=",
        alu::LSH => "<<=",
        alu::RSH => ">>=",
        alu::NEG => "neg",
        alu::MOD => "%=",
        alu::XOR => "^=",
        alu::MOV => "=",
        alu::ARSH => "s>>=",
        _ => "endian",
    }
}

/// What a store writes: a register, a BPF_ST's immediate, or a value the
/// verifier does not follow (a `BPF_ATOMIC`'s, whose `value_regno` is -1).
#[derive(Clone, Copy)]
enum Store {
    Reg(Reg),
    Imm(i32),
    Bytes,
}

/// How an instruction leaves the walk.
enum Step {
    Next(usize),
    /// The fall-through, the target, and the ID of a lookup's result that
    /// the jump tells is 0 on the target's side (`true`) or the other.
    Branch(usize, usize, Option<(u32, bool)>),
    Exit,
}

#[derive(Default)]
struct Walk {
    /// `insn_processed`.
    processed: u32,
    /// Where each function starts (`subprog_info`), the main program's
    /// first.
    starts: Vec<usize>,
    /// The deepest stack byte each function's frames accessed
    /// (`stack_depth`).
    depth: Vec<u32>,
    /// The deepest chain of calls' stack, each function's rounded up to 16
    /// (`max_stack_depth`), once `check_max_stack_depth` has run.
    max_depth: u32,
    /// `used_maps`.
    maps: Vec<MapShape>,
    /// Each BPF_LD_IMM64 of a map: its index in `maps`, and the offset in
    /// the value of a `BPF_PSEUDO_MAP_VALUE`.
    loads: std::collections::BTreeMap<usize, (u8, Option<u32>)>,
    /// `id_gen`.
    ids: u32,
    /// Each load or store reached so far, and whether through the context
    /// (`insn_aux_data`'s `ptr_type`, which tells only that apart).
    through_ctx: std::collections::BTreeMap<usize, bool>,
}

impl Walk {
    /// `add_used_map`: the map of `fd`, once however many times the
    /// program names it, and `check_map_prog_compatibility`.
    fn use_map(&mut self, fd: i32, options: Options, maps: &mut Maps<'_>) -> Checked<u8> {
        let shape = match maps(fd) {
            Ok(shape) => shape,
            Err(errno) => {
                return refuse(errno, format!("fd {fd} is not pointing to valid bpf_map"));
            }
        };
        if let Some(i) = self.maps.iter().position(|m| m.id == shape.id) {
            return Ok(i as u8);
        }
        if self.maps.len() >= MAX_USED_MAPS {
            return refuse(
                E2BIG,
                format!(
                    "The total number of maps per program has reached the limit of {MAX_USED_MAPS}"
                ),
            );
        }
        // 7.0 refuses one whose hash is another program's here, and master
        // after all the instructions.
        if shape.exclusive {
            return gap("maps made with excl_prog_hash");
        }
        // A sleepable program, which is refused later anyway, uses only
        // the types 7.0 lists.
        if options.sleepable
            && !matches!(
                shape.kind,
                map_type::HASH
                    | map_type::LRU_HASH
                    | map_type::ARRAY
                    | map_type::ARRAY_OF_MAPS
                    | map_type::HASH_OF_MAPS
                    | map_type::QUEUE
                    | map_type::STACK
            )
        {
            return refuse(
                Errno::EINVAL,
                "Sleepable programs can only use array, hash, ringbuf and local storage maps",
            );
        }
        self.maps.push(shape);
        Ok((self.maps.len() - 1) as u8)
    }

    /// `do_check`: every path from the first instruction, the fall-through
    /// first and the jumps' targets after, last pushed first.
    fn run(&mut self, insns: &[Insn], options: Options) -> Checked<()> {
        let mut regs = [Reg::NotInit; REGS];
        regs[1] = Reg::Ptr(Ptr::Ctx, 0);
        regs[FP] = Reg::Ptr(Ptr::Stack(0), 0);
        let mut state = State {
            insn: 0,
            regs,
            stack: [Slot::Bytes; (MAX_STACK / 8) as usize],
            subprog: 0,
            callers: Vec::new(),
        };
        let mut pending: Vec<State> = Vec::new();
        loop {
            self.processed += 1;
            if self.processed > COMPLEXITY_LIMIT_INSNS {
                return refuse(
                    E2BIG,
                    format!(
                        "BPF program is too large. Processed {} insn",
                        self.processed
                    ),
                );
            }
            match self.step(insns, &mut state, options)? {
                Step::Next(next) => state.insn = next,
                Step::Branch(fall, target, null) => {
                    let mut other = state.clone();
                    other.insn = target;
                    if let Some((id, on_target)) = null {
                        // mark_ptr_or_null_regs on both sides.
                        other.null_check(id, on_target);
                        state.null_check(id, !on_target);
                    }
                    pending.push(other);
                    if pending.len() > COMPLEXITY_LIMIT_JMP_SEQ {
                        return refuse(
                            E2BIG,
                            format!("The sequence of {} jumps is too complex.", pending.len()),
                        );
                    }
                    state.insn = fall;
                }
                Step::Exit => match pending.pop() {
                    Some(next) => state = next,
                    None => return Ok(()),
                },
            }
        }
    }

    fn step(&mut self, insns: &[Insn], s: &mut State, options: Options) -> Checked<Step> {
        let i = s.insn;
        let insn = insns[i];
        let next = Step::Next(i + 1);
        match insn.class() {
            class::ALU | class::ALU64 => {
                alu_op(s, insn)?;
                Ok(next)
            }
            class::LDX => {
                self.load(s, insn, i, options)?;
                Ok(next)
            }
            class::STX => {
                if insn.mode() == mode::ATOMIC {
                    self.atomic(s, insn, i, options)?;
                } else {
                    self.store(s, insn, i, options)?;
                }
                Ok(next)
            }
            class::ST => {
                read_ok(s, insn.dst)?;
                let value = Store::Imm(insn.imm);
                let pointer = s.regs[usize::from(insn.dst)];
                self.access(s, insn.dst, insn.off, insn.size(), Some(value), options)?;
                self.same_pointers(i, pointer)?;
                Ok(next)
            }
            class::JMP | class::JMP32 => self.jmp_op(s, insn, i),
            _ => {
                if insn.mode() != mode::IMM {
                    ld_abs(s, insn)?;
                    return Ok(next);
                }
                // check_ld_imm: a 64-bit constant, a map or a map's value.
                write_ok(insn.dst)?;
                let low = u64::from(insn.imm as u32);
                let high = u64::from(insns[i + 1].imm as u32);
                s.regs[usize::from(insn.dst)] = match self.loads.get(&i) {
                    None => Reg::Scalar(Some(high << 32 | low)),
                    Some(&(map, None)) => Reg::Ptr(Ptr::Map(map), 0),
                    Some(&(map, Some(off))) => Reg::Ptr(Ptr::Value(map), off as i32),
                };
                Ok(Step::Next(i + 2))
            }
        }
    }

    /// `check_load_mem`: the instruction at `i` loads the destination from
    /// the memory at the source.
    fn load(&mut self, s: &mut State, insn: Insn, i: usize, options: Options) -> Checked<()> {
        read_ok(s, insn.src)?;
        write_ok(insn.dst)?;
        let pointer = s.regs[usize::from(insn.src)];
        let value = self.access(s, insn.src, insn.off, insn.size(), None, options)?;
        s.regs[usize::from(insn.dst)] = value;
        self.same_pointers(i, pointer)
    }

    /// `check_store_reg`: the instruction at `i` stores the source into the
    /// memory at the destination.
    fn store(&mut self, s: &mut State, insn: Insn, i: usize, options: Options) -> Checked<()> {
        read_ok(s, insn.src)?;
        read_ok(s, insn.dst)?;
        let value = Store::Reg(s.regs[usize::from(insn.src)]);
        let pointer = s.regs[usize::from(insn.dst)];
        self.access(s, insn.dst, insn.off, insn.size(), Some(value), options)?;
        self.same_pointers(i, pointer)
    }

    /// `check_atomic`: the operation, then `check_atomic_rmw`,
    /// `check_atomic_load` or `check_atomic_store`.
    ///
    /// A read-modify-write is 4 or 8 bytes. Its registers are read, the
    /// destination may not be the context, the register the old value goes
    /// to (the source with `BPF_FETCH`, R0 for `BPF_CMPXCHG`) is unknown
    /// from then on, even when it is the destination, and the memory is
    /// read and then written, always aligned (`strict_alignment_once`).
    /// The loader may leak pointers, so the source and R0 may be pointers.
    /// Master and 7.0 check it alike.
    ///
    /// A load-acquire or store-release, of any size, is checked as a load
    /// or a store is, always aligned, and may not go through the context
    /// (`atomic_ptr_type_ok`). Master refuses the context for a load once
    /// the source is read, before the load, and the test machines' 7.0
    /// does too; 7.0 as released refuses it after the load, which also
    /// lets a load into the register it loads from through. A store is
    /// refused after it is checked, in both.
    fn atomic(&mut self, s: &mut State, insn: Insn, i: usize, options: Options) -> Checked<()> {
        let aligned = Options {
            strict_alignment: true,
            ..options
        };
        let ctx = |s: &State, r: u8| matches!(s.regs[usize::from(r)], Reg::Ptr(Ptr::Ctx, _));
        let not_allowed = |what: &str, r: u8| {
            refuse(
                EACCES,
                format!("BPF_ATOMIC {what} R{r} {} is not allowed", Ptr::Ctx.name()),
            )
        };
        match insn.imm {
            atomic::LOAD_ACQ => {
                read_ok(s, insn.src)?;
                if ctx(s, insn.src) {
                    return not_allowed("loads from", insn.src);
                }
                return self.load(s, insn, i, aligned);
            }
            atomic::STORE_REL => {
                self.store(s, insn, i, aligned)?;
                return if ctx(s, insn.dst) {
                    not_allowed("stores into", insn.dst)
                } else {
                    Ok(())
                };
            }
            _ => {}
        }
        let old = match insn.imm {
            atomic::ADD | atomic::AND | atomic::OR | atomic::XOR => None,
            op if op & atomic::FETCH != 0
                && matches!(
                    op & !atomic::FETCH,
                    atomic::ADD | atomic::AND | atomic::OR | atomic::XOR
                ) =>
            {
                Some(insn.src)
            }
            atomic::XCHG => Some(insn.src),
            atomic::CMPXCHG => Some(0),
            op => {
                return refuse(
                    Errno::EINVAL,
                    format!("BPF_ATOMIC uses invalid atomic opcode {:02x}", op as u32),
                );
            }
        };
        if !matches!(insn.size(), size::W | size::DW) {
            return refuse(Errno::EINVAL, "invalid atomic operand size");
        }
        read_ok(s, insn.src)?;
        read_ok(s, insn.dst)?;
        if insn.imm == atomic::CMPXCHG {
            read_ok(s, 0)?;
        }
        // atomic_ptr_type_ok: of the types here, only the context is
        // refused.
        if ctx(s, insn.dst) {
            return not_allowed("stores into", insn.dst);
        }
        if let Some(r) = old {
            write_ok(r)?;
            s.regs[usize::from(r)] = Reg::Scalar(None);
        }
        let value = self.access(s, insn.dst, insn.off, insn.size(), None, aligned)?;
        if let Some(r) = old {
            s.regs[usize::from(r)] = value;
        }
        self.access(
            s,
            insn.dst,
            insn.off,
            insn.size(),
            Some(Store::Bytes),
            aligned,
        )?;
        Ok(())
    }

    /// `check_mem_access` through the register `ptr` at `off`: a read
    /// gives the value, a write stores `value`.
    fn access(
        &mut self,
        s: &mut State,
        ptr: u8,
        off: i16,
        width: u8,
        value: Option<Store>,
        options: Options,
    ) -> Checked<Reg> {
        let bytes: i64 = match width {
            size::B => 1,
            size::H => 2,
            size::W => 4,
            _ => 8,
        };
        let reg = s.regs[usize::from(ptr)];
        match reg {
            Reg::Ptr(Ptr::Stack(frame), base) => {
                let total = i64::from(base) + i64::from(off);
                // check_ptr_alignment: stack accesses are always strict.
                if bytes > 1 && total % bytes != 0 {
                    return refuse(
                        EACCES,
                        format!("misaligned stack access off 0+{base}+{off} size {bytes}"),
                    );
                }
                let what = if value.is_some() {
                    " write to"
                } else {
                    " read from"
                };
                if !(-MAX_STACK..=-1).contains(&total) {
                    return refuse(
                        EACCES,
                        format!("invalid{what} stack R{ptr} off={total} size={bytes}"),
                    );
                }
                if total + bytes > 0 {
                    return refuse(
                        Errno::EINVAL,
                        format!("invalid{what} stack R{ptr} off={total} size={bytes}"),
                    );
                }
                let caller = frame != s.frame();
                let (stack, subprog) = s.stack_of(frame);
                self.deepen(subprog, -total);
                let slot = ((-total - 1) / 8) as usize;
                let aligned = total % 8 == 0;
                match value {
                    Some(value) => {
                        stack_write(stack, caller, slot, aligned, bytes, value)?;
                        Ok(Reg::NotInit)
                    }
                    None => stack_read(stack, slot, bytes),
                }
            }
            Reg::Ptr(Ptr::Ctx, base) => {
                // check_ptr_alignment, check_ptr_off_reg, check_ctx_access.
                let total = i64::from(base) + i64::from(off);
                if options.strict_alignment && bytes > 1 && total % bytes != 0 {
                    return refuse(
                        EACCES,
                        format!("misaligned context access off 0+{base}+{off} size {bytes}"),
                    );
                }
                ctx_offset(ptr, base)?;
                match context_field(total, bytes, value.is_some()) {
                    None => refuse(
                        EACCES,
                        format!("invalid bpf_context access off={total} size={bytes}"),
                    ),
                    Some(Field::Socket) => gap("the context's socket pointers"),
                    Some(Field::Scalar) if value.is_some() => Ok(Reg::NotInit),
                    Some(Field::Scalar) => Ok(Reg::Scalar(None)),
                }
            }
            Reg::Ptr(Ptr::Map(_), _) => gap("the fields of struct bpf_map"),
            Reg::Ptr(p @ Ptr::MaybeNull(..), base) => {
                // check_generic_ptr_alignment, with no word for the type.
                let total = i64::from(base) + i64::from(off);
                if options.strict_alignment && bytes > 1 && total % bytes != 0 {
                    return refuse(
                        EACCES,
                        format!("misaligned access off 0+{base}+{off} size {bytes}"),
                    );
                }
                refuse(EACCES, format!("R{ptr} invalid mem access '{}'", p.name()))
            }
            Reg::Ptr(Ptr::Value(map), base) => {
                let total = i64::from(base) + i64::from(off);
                if options.strict_alignment && bytes > 1 && total % bytes != 0 {
                    return refuse(
                        EACCES,
                        format!("misaligned value access off 0+{base}+{off} size {bytes}"),
                    );
                }
                let write = value.is_some();
                self.value_access(ptr, map, total, bytes, write)?;
                Ok(Reg::Scalar(None))
            }
            Reg::Scalar(known) => {
                if options.strict_alignment && bytes > 1 {
                    match known {
                        Some(v) if v.wrapping_add(off as i64 as u64) % bytes as u64 == 0 => {}
                        Some(v) => {
                            return refuse(
                                EACCES,
                                format!(
                                    "misaligned access off {}+0+{off} size {bytes}",
                                    known_value(v)
                                ),
                            );
                        }
                        None => {
                            return refuse(
                                EACCES,
                                format!(
                                    "misaligned access off (0x0; 0xffffffffffffffff)+0+{off} size {bytes}"
                                ),
                            );
                        }
                    }
                }
                refuse(EACCES, format!("R{ptr} invalid mem access 'scalar'"))
            }
            Reg::NotInit => refuse(EACCES, format!("R{ptr} !read_ok")),
        }
    }
}

impl Walk {
    /// `check_map_access_type` and `check_map_access` of `bytes` at `off`
    /// in a value of the map through the register `r`: what
    /// `BPF_F_RDONLY_PROG` and `BPF_F_WRONLY_PROG` forbid, and the value's
    /// bounds, for which `check_mem_region_access` writes a second line.
    fn value_access(&self, r: u8, map: u8, off: i64, bytes: i64, write: bool) -> Checked<()> {
        let shape = self.maps[usize::from(map)];
        let size = i64::from(shape.value_size);
        if write && shape.flags & F_RDONLY_PROG != 0 {
            return refuse(
                EACCES,
                format!("write into map forbidden, value_size={size} off={off} size={bytes}"),
            );
        }
        if !write && shape.flags & F_WRONLY_PROG != 0 {
            return refuse(
                EACCES,
                format!("read from map forbidden, value_size={size} off={off} size={bytes}"),
            );
        }
        if off < 0 || off + bytes > size {
            return refuse(
                EACCES,
                format!(
                    "invalid access to map value, value_size={size} off={off} size={bytes}\nR{r} min value is outside of the allowed memory range"
                ),
            );
        }
        Ok(())
    }

    /// `check_helper_mem_access` of a helper's argument in `r`, which
    /// reads `bytes`: a fixed place on the stack, or in a map's value.
    fn helper_read(&mut self, s: &mut State, r: u8, bytes: u32) -> Checked<()> {
        read_ok(s, r)?;
        let bytes = i64::from(bytes);
        match s.regs[usize::from(r)] {
            Reg::Ptr(Ptr::Stack(frame), base) => {
                let base = i64::from(base);
                // check_stack_range_initialized: a privileged loader may
                // pass bytes it never wrote.
                if !(-MAX_STACK..=-1).contains(&base) {
                    return refuse(
                        EACCES,
                        format!("invalid read from stack R{r} off={base} size={bytes}"),
                    );
                }
                if base + bytes > 0 {
                    return refuse(
                        Errno::EINVAL,
                        format!("invalid read from stack R{r} off={base} size={bytes}"),
                    );
                }
                let subprog = s.stack_of(frame).1;
                self.deepen(subprog, -base);
                Ok(())
            }
            Reg::Ptr(Ptr::Value(map), base) => {
                self.value_access(r, map, i64::from(base), bytes, false)
            }
            reg => memory_type(r, reg),
        }
    }

    /// `check_helper_call` of a helper in range: its arguments, then R1 to
    /// R5 are gone and R0 is the result.
    fn helper(&mut self, s: &mut State, id: i32) -> Checked<()> {
        let Some(name) = helper_name(id) else {
            return refuse(Errno::EINVAL, format!("invalid func unknown#{id}"));
        };
        let result = match id {
            func::MAP_LOOKUP_ELEM | func::MAP_UPDATE_ELEM | func::MAP_DELETE_ELEM => {
                self.map_helper(s, id)?
            }
            func::SKB_LOAD_BYTES | func::SKB_LOAD_BYTES_RELATIVE => {
                self.load_bytes(s, id == func::SKB_LOAD_BYTES_RELATIVE)?;
                Reg::Scalar(None)
            }
            func::GET_SOCKET_COOKIE | func::GET_SOCKET_UID => {
                ctx_arg(s, 1, false)?;
                Reg::Scalar(None)
            }
            func::GET_NETNS_COOKIE => {
                ctx_arg(s, 1, true)?;
                Reg::Scalar(None)
            }
            func::KTIME_GET_NS
            | func::GET_PRANDOM_U32
            | func::GET_SMP_PROCESSOR_ID
            | func::GET_CURRENT_PID_TGID
            | func::GET_CURRENT_UID_GID
            | func::GET_NUMA_NODE_ID
            | func::KTIME_GET_BOOT_NS
            | func::KTIME_GET_COARSE_NS
            | func::KTIME_GET_TAI_NS => Reg::Scalar(None),
            // libbpf and bpftool take a helper as there unless the log
            // says "unknown func" (or Linux's other words for one a type
            // cannot use), so the line starts with Linux's for an unknown
            // helper.
            _ if socket_filter_helper(id) => {
                return refuse(
                    Errno::EINVAL,
                    format!(
                        "unknown func bpf_{name}#{id} (paludarium: this helper is not verified yet)"
                    ),
                );
            }
            _ => {
                return refuse(
                    Errno::EINVAL,
                    format!("program of this type cannot use helper bpf_{name}#{id}"),
                );
            }
        };
        // The caller-saved registers.
        s.regs[1..=5].fill(Reg::NotInit);
        s.regs[0] = result;
        Ok(())
    }

    /// The map helpers' arguments, and the lookup's result.
    fn map_helper(&mut self, s: &mut State, id: i32) -> Checked<Reg> {
        // check_func_arg of ARG_CONST_MAP_PTR.
        read_ok(s, 1)?;
        let map = match s.regs[1] {
            Reg::Ptr(Ptr::Map(map), _) => map,
            reg => {
                return refuse(
                    EACCES,
                    format!("R1 type={} expected=map_ptr", reg_name(reg)),
                );
            }
        };
        let shape = self.maps[usize::from(map)];
        if !matches!(
            shape.kind,
            map_type::ARRAY | map_type::HASH | map_type::LRU_HASH | map_type::LPM_TRIE
        ) {
            return gap("map helpers of maps of maps, queues, stacks and bloom filters");
        }
        // ARG_PTR_TO_MAP_KEY, and ARG_PTR_TO_MAP_VALUE and ARG_ANYTHING.
        self.helper_read(s, 2, shape.key_size)?;
        if id == func::MAP_UPDATE_ELEM {
            self.helper_read(s, 3, shape.value_size)?;
            read_ok(s, 4)?;
        }
        // record_func_map.
        if id != func::MAP_LOOKUP_ELEM && shape.flags & F_RDONLY_PROG != 0 {
            return refuse(EACCES, "write into map forbidden");
        }
        Ok(if id == func::MAP_LOOKUP_ELEM {
            self.ids += 1;
            Reg::Ptr(Ptr::MaybeNull(map, self.ids), 0)
        } else {
            Reg::Scalar(None)
        })
    }

    /// The arguments of `bpf_skb_load_bytes(ctx, offset, to, len)` and of
    /// `bpf_skb_load_bytes_relative`, which adds `start_header`: `to` is
    /// `ARG_PTR_TO_UNINIT_MEM` and `len` its `ARG_CONST_SIZE`, whose bytes
    /// the helper writes.
    fn load_bytes(&mut self, s: &mut State, relative: bool) -> Checked<()> {
        ctx_arg(s, 1, false)?;
        read_ok(s, 2)?;
        read_ok(s, 3)?;
        let to = s.regs[3];
        if !matches!(to, Reg::Ptr(Ptr::Stack(_) | Ptr::Value(_), _)) {
            return memory_type(3, to);
        }
        // check_reg_type and check_mem_size_reg of the size.
        read_ok(s, 4)?;
        let len = match s.regs[4] {
            Reg::Scalar(Some(len)) => len,
            Reg::Scalar(None) => return gap("helper sizes the verifier does not know"),
            reg => {
                return refuse(EACCES, format!("R4 type={} expected=scalar", reg_name(reg)));
            }
        };
        if (len as i64) < 0 {
            return refuse(
                EACCES,
                "R4 min value is negative, either use unsigned or 'var &= const'",
            );
        }
        if len == 0 {
            return refuse(EACCES, "R4 invalid zero-sized read: u64=[0,0]");
        }
        if len >= MAX_VAR_SIZE {
            return refuse(
                EACCES,
                "R4 unbounded memory access, use 'var &= const' or 'if (var < const)'",
            );
        }
        let len = len as i64;
        // check_helper_mem_access of a write.
        let written = match to {
            Reg::Ptr(Ptr::Stack(frame), base) => {
                // check_stack_access_within_bounds.
                let base = i64::from(base);
                if !(-MAX_STACK..=-1).contains(&base) {
                    return refuse(
                        EACCES,
                        format!("invalid write to stack R3 off={base} size={len}"),
                    );
                }
                if base + len > 0 {
                    return refuse(
                        Errno::EINVAL,
                        format!("invalid write to stack R3 off={base} size={len}"),
                    );
                }
                Some((frame, base))
            }
            Reg::Ptr(Ptr::Value(map), base) => {
                self.value_access(3, map, i64::from(base), len, true)?;
                None
            }
            _ => unreachable!("the type is checked above"),
        };
        if relative {
            read_ok(s, 5)?;
        }
        // The raw mode's writes, a byte at a time, after every argument:
        // the bytes are bytes the program may read.
        if let Some((frame, base)) = written {
            let (stack, subprog) = s.stack_of(frame);
            self.deepen(subprog, -base);
            for at in base..base + len {
                stack[((-at - 1) / 8) as usize] = Slot::Bytes;
            }
        }
        Ok(())
    }

    /// `save_aux_ptr_type` of the pointer a load or store at `i` went
    /// through: an instruction may not go through the context on one path
    /// and another pointer on another.
    fn same_pointers(&mut self, i: usize, pointer: Reg) -> Checked<()> {
        let ctx = matches!(pointer, Reg::Ptr(Ptr::Ctx, _));
        match self.through_ctx.insert(i, ctx) {
            Some(before) if before != ctx => refuse(
                Errno::EINVAL,
                "same insn cannot be used with different pointers",
            ),
            _ => Ok(()),
        }
    }

    /// The jumps: `BPF_JA`, `BPF_EXIT`, a call, and `check_cond_jmp_op`.
    fn jmp_op(&mut self, s: &mut State, insn: Insn, i: usize) -> Checked<Step> {
        if insn.op() == jmp::CALL && insn.src == pseudo::CALL {
            return self.call(s, insn, i);
        }
        if insn.op() == jmp::CALL {
            self.helper(s, insn.imm)?;
            return Ok(Step::Next(i + 1));
        }
        if insn.op() == jmp::EXIT && !s.callers.is_empty() {
            return func_exit(s);
        }
        jmp_op(s, insn, i)
    }

    /// `check_func_call` of a static function, the only kind without BTF
    /// (`setup_func_entry`, `set_callee_state`): the callee's frame gets
    /// R1 to R5 and a frame pointer of its own, and the caller's R0 to R5
    /// are gone.
    fn call(&mut self, s: &mut State, insn: Insn, i: usize) -> Checked<Step> {
        let start = (i as i64 + i64::from(insn.imm) + 1) as usize;
        let subprog = self
            .starts
            .binary_search(&start)
            .map_err(|_| (Errno::EFAULT, String::new()))?;
        let frame = s.callers.len();
        if frame + 1 >= MAX_CALL_FRAMES {
            return refuse(
                E2BIG,
                format!("the call stack of {} frames is too deep", frame + 2),
            );
        }
        let mut regs = [Reg::NotInit; REGS];
        regs[1..=5].copy_from_slice(&s.regs[1..=5]);
        regs[FP] = Reg::Ptr(Ptr::Stack(frame as u8 + 1), 0);
        let mut caller = std::mem::replace(&mut s.regs, regs);
        caller[0..=5].fill(Reg::NotInit);
        s.callers.push(Caller {
            regs: caller,
            stack: std::mem::replace(&mut s.stack, [Slot::Bytes; (MAX_STACK / 8) as usize]),
            subprog: std::mem::replace(&mut s.subprog, subprog),
            ret: i + 1,
        });
        Ok(Step::Next(start))
    }

    /// `grow_stack_state`: the frames of `subprog` reach `bytes` below
    /// their frame pointer.
    fn deepen(&mut self, subprog: usize, bytes: i64) {
        let depth = &mut self.depth[subprog];
        *depth = (*depth).max(bytes as u32);
    }

    /// `check_max_stack_depth`, after the walk: along every chain of calls
    /// from the main program, in the instructions' order, each function's
    /// stack rounded up to 16 bytes, as Linux does with the JIT on, adds up
    /// to 512 bytes at most, and no chain is 8 frames deep. A chain is
    /// followed only where it may go past either, so that the first one
    /// that does is the one Linux finds.
    fn max_stack_depth(&mut self, insns: &[Insn]) -> Checked<()> {
        let n = self.starts.len();
        let round = |f: usize| i64::from((self.depth[f].div_ceil(8) * 8).next_multiple_of(16));
        let calls = |f: usize| {
            body(&self.starts, insns.len(), f)
                .filter(|&i| {
                    insns[i].code == class::JMP | jmp::CALL && insns[i].src == pseudo::CALL
                })
                .map(|i| {
                    let start = (i as i64 + i64::from(insns[i].imm) + 1) as usize;
                    self.starts.binary_search(&start).unwrap_or(0)
                })
                .collect::<Vec<_>>()
        };
        let callees: Vec<Vec<usize>> = (0..n).map(calls).collect();
        // For each function at each frame (1 the main program's), the
        // deepest stack of the chains below it and whether one of them goes
        // past 8 frames. A recursive call, which the walk refuses as it goes
        // 9 frames deep, may be in code the walk does not take: the frames
        // keep this finite.
        let mut below = vec![[None::<(i64, bool)>; MAX_CALL_FRAMES + 1]; n];
        fn measure(
            f: usize,
            frame: usize,
            callees: &[Vec<usize>],
            round: &dyn Fn(usize) -> i64,
            below: &mut [[Option<(i64, bool)>; MAX_CALL_FRAMES + 1]],
        ) -> (i64, bool) {
            if let Some(m) = below[f][frame] {
                return m;
            }
            let mut m = (round(f), false);
            if frame >= MAX_CALL_FRAMES {
                m.1 = !callees[f].is_empty();
            } else {
                for &g in &callees[f] {
                    let (depth, deep) = measure(g, frame + 1, callees, round, below);
                    m = (m.0.max(round(f) + depth), m.1 || deep);
                }
            }
            below[f][frame] = Some(m);
            m
        }
        fn walk(
            f: usize,
            depth: i64,
            frames: usize,
            callees: &[Vec<usize>],
            round: &dyn Fn(usize) -> i64,
            below: &mut [[Option<(i64, bool)>; MAX_CALL_FRAMES + 1]],
            max: &mut i64,
        ) -> Checked<()> {
            let depth = depth + round(f);
            *max = (*max).max(depth);
            if depth > MAX_STACK {
                return refuse(
                    EACCES,
                    format!("combined stack size of {frames} calls is {depth}. Too large"),
                );
            }
            for &g in &callees[f] {
                if frames >= MAX_CALL_FRAMES {
                    return refuse(
                        E2BIG,
                        format!("the call stack of {frames} frames is too deep !"),
                    );
                }
                // A chain that cannot fail adds only its deepest stack to
                // the maximum, as Linux's walk of it would.
                let (d, deep) = measure(g, frames + 1, callees, round, below);
                if depth + d <= MAX_STACK && !deep {
                    *max = (*max).max(depth + d);
                    continue;
                }
                walk(g, depth, frames + 1, callees, round, below, max)?;
            }
            Ok(())
        }
        let mut max = 0;
        let result = walk(0, 0, 1, &callees, &round, &mut below, &mut max);
        self.max_depth = max as u32;
        result
    }
}

/// 7.0's `tnum_strn` of a known value: in decimal up to
/// `UNUM_MAX_DECIMAL`, else in hexadecimal (master writes negative ones in
/// decimal too). The kernel's `%#llx` writes 0 as `0x0`, unlike C's.
fn known_value(v: u64) -> String {
    if v <= UNUM_MAX_DECIMAL {
        v.to_string()
    } else {
        format!("{v:#x}")
    }
}

/// `__check_ptr_off_reg` of the context in `r`, whose offset must be 0.
fn ctx_offset(r: u8, off: i32) -> Checked<()> {
    if off < 0 {
        return refuse(
            EACCES,
            format!("negative offset ctx ptr R{r} off={off} disallowed"),
        );
    }
    if off > 0 {
        return refuse(
            EACCES,
            format!("dereference of modified ctx ptr R{r} off={off} disallowed"),
        );
    }
    Ok(())
}

/// `check_func_arg` of `ARG_PTR_TO_CTX` in `r`, or of
/// `ARG_PTR_TO_CTX_OR_NULL` when `nullable`, which takes 0 too.
fn ctx_arg(s: &State, r: u8, nullable: bool) -> Checked<()> {
    read_ok(s, r)?;
    match s.regs[usize::from(r)] {
        Reg::Scalar(Some(0)) if nullable => Ok(()),
        // Linux may know it is 0.
        Reg::Scalar(None) if nullable => gap("helper arguments the verifier does not know are 0"),
        Reg::Ptr(Ptr::Ctx, off) => ctx_offset(r, off),
        reg => refuse(EACCES, format!("R{r} type={} expected=ctx", reg_name(reg))),
    }
}

/// `check_reg_type` of a memory argument in `r` that is none of the types
/// in range (`mem_types`): 7.0's line, which master's list (that takes the
/// context as well) only lengthens.
fn memory_type(r: u8, reg: Reg) -> Checked<()> {
    refuse(
        EACCES,
        format!(
            "R{r} type={} expected=fp, pkt, pkt_meta, map_key, map_value, mem, ringbuf_mem, buf, trusted_ptr_",
            reg_name(reg)
        ),
    )
}

/// `check_ld_abs` of a socket filter's `BPF_LD_ABS` or `BPF_LD_IND`, whose
/// fields [`insn_fields`] checked (where master does; 7.0 checks them
/// here, after the program type, which a socket filter passes): a call of
/// a helper that loads the packet's bytes at `imm`, or at `src + imm`,
/// from the context in R6, into R0, and clobbers R1 to R5.
fn ld_abs(s: &mut State, insn: Insn) -> Checked<()> {
    const CTX: u8 = 6;
    read_ok(s, CTX)?;
    // check_resource_leak: no helper that takes a reference or a lock is
    // verified yet, so none is held.
    let Reg::Ptr(Ptr::Ctx, off) = s.regs[usize::from(CTX)] else {
        return refuse(
            Errno::EINVAL,
            "at the time of BPF_LD_ABS|IND R6 != pointer to skb",
        );
    };
    if insn.mode() == mode::IND {
        read_ok(s, insn.src)?;
    }
    // check_ptr_off_reg.
    ctx_offset(CTX, off)?;
    s.regs[1..=5].fill(Reg::NotInit);
    s.regs[0] = Reg::Scalar(None);
    Ok(())
}

/// `check_reg_arg` of a source: the register has been written.
fn read_ok(s: &State, r: u8) -> Checked<()> {
    if s.regs[usize::from(r)] == Reg::NotInit {
        return refuse(EACCES, format!("R{r} !read_ok"));
    }
    Ok(())
}

/// `check_reg_arg` of a destination: not the frame pointer.
fn write_ok(r: u8) -> Checked<()> {
    if usize::from(r) == FP {
        return refuse(EACCES, "frame pointer is read only");
    }
    Ok(())
}

/// `check_stack_write_fixed_off`, for a privileged loader: a register
/// or an immediate that fills an aligned slot is spilled whole, a pointer
/// only so, and anything else leaves bytes. A narrower spill of a scalar,
/// which Linux keeps, is bytes here, so its value is unknown. A pointer to
/// a stack may not go into a caller's frame (`caller`).
fn stack_write(
    stack: &mut Stack,
    caller: bool,
    slot: usize,
    aligned: bool,
    bytes: i64,
    value: Store,
) -> Checked<()> {
    let stored = match value {
        Store::Reg(Reg::Ptr(..)) if bytes != 8 => {
            return refuse(EACCES, "invalid size of register spill");
        }
        Store::Reg(Reg::Ptr(Ptr::Stack(_), _)) if caller => {
            return refuse(
                Errno::EINVAL,
                "cannot spill pointers to stack into stack frame of the caller",
            );
        }
        Store::Reg(reg @ Reg::Ptr(..)) => Slot::Spill(reg),
        Store::Reg(reg @ Reg::Scalar(_)) if aligned && bytes == 8 => Slot::Spill(reg),
        Store::Imm(imm) if aligned && bytes == 8 => {
            Slot::Spill(Reg::Scalar(Some(i64::from(imm) as u64)))
        }
        _ => Slot::Bytes,
    };
    stack[slot] = stored;
    Ok(())
}

/// `check_stack_read_fixed_off`, for a privileged loader.
fn stack_read(stack: &Stack, slot: usize, bytes: i64) -> Checked<Reg> {
    match stack[slot] {
        Slot::Spill(reg @ Reg::Ptr(..)) => {
            if bytes != 8 {
                return refuse(EACCES, "invalid size of register fill");
            }
            Ok(reg)
        }
        Slot::Spill(reg) if bytes == 8 => Ok(reg),
        _ => Ok(Reg::Scalar(None)),
    }
}

/// `check_alu_op`.
fn alu_op(s: &mut State, insn: Insn) -> Checked<()> {
    let op = insn.op();
    let wide = insn.class() == class::ALU64;
    let dst = usize::from(insn.dst);
    match op {
        alu::NEG | alu::END => {
            read_ok(s, insn.dst)?;
            match s.regs[dst] {
                Reg::Scalar(v) => {
                    write_ok(insn.dst)?;
                    s.regs[dst] = Reg::Scalar(if op == alu::NEG {
                        v.map(|v| {
                            if wide {
                                v.wrapping_neg()
                            } else {
                                u64::from((v as u32).wrapping_neg())
                            }
                        })
                    } else {
                        None
                    });
                }
                _ => {
                    // A pointer becomes an unknown scalar, or the frame
                    // pointer refuses the write.
                    write_ok(insn.dst)?;
                    s.regs[dst] = Reg::Scalar(None);
                }
            }
            Ok(())
        }
        alu::MOV => {
            if insn.x() {
                if wide && insn.off == ADDR_SPACE_CAST {
                    return refuse(
                        Errno::EINVAL,
                        "addr_space_cast insn can only be used in a program that has an associated arena",
                    );
                }
                read_ok(s, insn.src)?;
            }
            write_ok(insn.dst)?;
            let value = if insn.x() {
                let src = s.regs[usize::from(insn.src)];
                match (wide, insn.off, src) {
                    (true, 0, src) => src,
                    (false, 0, Reg::Scalar(v)) => Reg::Scalar(v.map(|v| u64::from(v as u32))),
                    // A sign extension, or a pointer's low half.
                    _ => Reg::Scalar(None),
                }
            } else if wide {
                Reg::Scalar(Some(i64::from(insn.imm) as u64))
            } else {
                Reg::Scalar(Some(u64::from(insn.imm as u32)))
            };
            s.regs[dst] = value;
            Ok(())
        }
        _ => {
            if insn.x() {
                read_ok(s, insn.src)?;
            }
            read_ok(s, insn.dst)?;
            if matches!(op, alu::DIV | alu::MOD) && !insn.x() && insn.imm == 0 {
                return refuse(Errno::EINVAL, "div by zero");
            }
            if matches!(op, alu::LSH | alu::RSH | alu::ARSH) && !insn.x() {
                let bits = if wide { 64 } else { 32 };
                if insn.imm < 0 || insn.imm >= bits {
                    return refuse(Errno::EINVAL, format!("invalid shift {}", insn.imm));
                }
            }
            write_ok(insn.dst)?;
            let d = s.regs[dst];
            let src = if insn.x() {
                s.regs[usize::from(insn.src)]
            } else {
                Reg::Scalar(Some(i64::from(insn.imm) as u64))
            };
            s.regs[dst] = match (d, src) {
                (Reg::Ptr(..), Reg::Ptr(..)) => {
                    if op == alu::SUB {
                        Reg::Scalar(None)
                    } else {
                        return refuse(
                            EACCES,
                            format!("R{dst} pointer {} pointer prohibited", alu_name(op)),
                        );
                    }
                }
                (Reg::Scalar(v), Reg::Ptr(p, off)) => pointer_math(insn, p, off, v, true)?,
                (Reg::Ptr(p, off), Reg::Scalar(v)) => pointer_math(insn, p, off, v, false)?,
                (Reg::Scalar(a), Reg::Scalar(b)) => Reg::Scalar(scalar_math(insn, a, b)),
                _ => Reg::Scalar(None),
            };
            Ok(())
        }
    }
}

/// `adjust_ptr_min_max_vals` of a pointer and a scalar (`scalar` is the
/// destination when `scalar_is_dst`), for a privileged loader, refusing
/// what 7.0 refuses.
fn pointer_math(
    insn: Insn,
    ptr: Ptr,
    base: i32,
    scalar: Option<u64>,
    scalar_is_dst: bool,
) -> Checked<Reg> {
    let op = insn.op();
    let dst = insn.dst;
    if insn.class() != class::ALU64 {
        if op == alu::SUB {
            return Ok(Reg::Scalar(None));
        }
        return refuse(
            EACCES,
            format!("R{dst} 32-bit pointer arithmetic prohibited"),
        );
    }
    if let Ptr::MaybeNull(..) = ptr {
        return refuse(
            EACCES,
            format!(
                "R{dst} pointer arithmetic on {} prohibited, null-check it first",
                ptr.name()
            ),
        );
    }
    if let Ptr::Map(_) = ptr
        && !(scalar == Some(0) && op == alu::ADD)
    {
        return refuse(
            EACCES,
            format!("R{dst} pointer arithmetic on {} prohibited", ptr.name()),
        );
    }
    // check_reg_sane_offset of the scalar, then of the pointer.
    let Some(value) = scalar else {
        return gap("pointers with a variable offset");
    };
    let value = value as i64;
    if !(-MAX_VAR_OFF + 1..MAX_VAR_OFF).contains(&value) {
        return refuse(
            Errno::EINVAL,
            format!(
                "math between {} pointer and {value} is not allowed",
                ptr.name()
            ),
        );
    }
    let base64 = i64::from(base);
    if !(-MAX_VAR_OFF + 1..MAX_VAR_OFF).contains(&base64) {
        return refuse(
            Errno::EINVAL,
            format!("{} pointer offset {base} is not allowed", ptr.name()),
        );
    }
    let off = match op {
        alu::ADD => base64 + value,
        alu::SUB => {
            if scalar_is_dst {
                return refuse(
                    EACCES,
                    format!("R{dst} tried to subtract pointer from scalar"),
                );
            }
            if matches!(ptr, Ptr::Stack(_)) {
                return refuse(
                    EACCES,
                    format!("R{dst} subtraction from stack pointer prohibited"),
                );
            }
            base64 - value
        }
        alu::AND | alu::OR | alu::XOR => {
            return refuse(
                EACCES,
                format!(
                    "R{dst} bitwise operator {} on pointer prohibited",
                    alu_name(op)
                ),
            );
        }
        _ => {
            return refuse(
                EACCES,
                format!(
                    "R{dst} pointer arithmetic with {} operator prohibited",
                    alu_name(op)
                ),
            );
        }
    };
    if !(-MAX_VAR_OFF + 1..MAX_VAR_OFF).contains(&off) {
        return refuse(
            Errno::EINVAL,
            format!("{} pointer offset {off} is not allowed", ptr.name()),
        );
    }
    Ok(Reg::Ptr(ptr, off as i32))
}

/// The value of an operation of two scalars, where Linux's tnum gives it
/// exactly; any other is unknown here.
fn scalar_math(insn: Insn, a: Option<u64>, b: Option<u64>) -> Option<u64> {
    let (a, b) = (a?, b?);
    let wide = insn.class() == class::ALU64;
    let bits = if wide { 64 } else { 32 };
    let op = insn.op();
    // is_safe_to_compute_dst_reg_range: a shift by a register is known
    // only when all of its 64 bits are below the width.
    if matches!(op, alu::LSH | alu::RSH | alu::ARSH) && b >= bits {
        return None;
    }
    if wide {
        Some(match op {
            alu::ADD => a.wrapping_add(b),
            alu::SUB => a.wrapping_sub(b),
            alu::MUL => a.wrapping_mul(b),
            alu::AND => a & b,
            alu::OR => a | b,
            alu::XOR => a ^ b,
            alu::LSH => a << b,
            alu::RSH => a >> b,
            alu::ARSH => ((a as i64) >> b) as u64,
            _ => return None,
        })
    } else {
        let (a, b) = (a as u32, b as u32);
        Some(u64::from(match op {
            alu::ADD => a.wrapping_add(b),
            alu::SUB => a.wrapping_sub(b),
            alu::MUL => a.wrapping_mul(b),
            alu::AND => a & b,
            alu::OR => a | b,
            alu::XOR => a ^ b,
            alu::LSH => a << b,
            alu::RSH => a >> b,
            alu::ARSH => ((a as i32) >> b) as u32,
            _ => return None,
        }))
    }
}

/// The jumps: `BPF_JA`, `BPF_EXIT`, a call, and `check_cond_jmp_op`.
fn jmp_op(s: &mut State, insn: Insn, i: usize) -> Checked<Step> {
    match insn.op() {
        jmp::CALL => unreachable!("Walk::jmp_op calls the helpers"),
        jmp::JA if insn.x() => gap("indirect jumps"),
        jmp::JA => Ok(Step::Next((i as i64 + insn.jump() + 1) as usize)),
        jmp::EXIT => {
            // check_return_code: R0 is readable; a socket filter's may be
            // any value, and a privileged loader's a pointer.
            read_ok(s, 0)?;
            Ok(Step::Exit)
        }
        jmp::JCOND => gap("may_goto"),
        op => {
            read_ok(s, insn.dst)?;
            let b = if insn.x() {
                read_ok(s, insn.src)?;
                s.regs[usize::from(insn.src)]
            } else {
                Reg::Scalar(Some(i64::from(insn.imm) as u64))
            };
            let target = (i as i64 + i64::from(insn.off) + 1) as usize;
            let a = s.regs[usize::from(insn.dst)];
            match (a, b) {
                (Reg::Scalar(Some(a)), Reg::Scalar(Some(b))) => {
                    if taken(op, a, b, insn.class() == class::JMP32) {
                        Ok(Step::Next(target))
                    } else {
                        Ok(Step::Next(i + 1))
                    }
                }
                // A 64-bit comparison of a lookup's result with 0 tells
                // whether it is null.
                (Reg::Ptr(Ptr::MaybeNull(_, id), _), _)
                    if insn.class() == class::JMP
                        && !insn.x()
                        && insn.imm == 0
                        && matches!(op, jmp::JEQ | jmp::JNE) =>
                {
                    Ok(Step::Branch(i + 1, target, Some((id, op == jmp::JEQ))))
                }
                _ => Ok(Step::Branch(i + 1, target, None)),
            }
        }
    }
}

/// `prepare_func_exit`: the callee's R0, which may not point into a stack,
/// goes back to its caller, after the call.
fn func_exit(s: &mut State) -> Checked<Step> {
    let r0 = s.regs[0];
    if let Reg::Ptr(Ptr::Stack(_), _) = r0 {
        return refuse(Errno::EINVAL, "cannot return stack pointer to the caller");
    }
    // Walk::jmp_op comes here only from a callee.
    let Some(caller) = s.callers.pop() else {
        return refuse(Errno::EFAULT, "");
    };
    s.regs = caller.regs;
    s.regs[0] = r0;
    s.stack = caller.stack;
    s.subprog = caller.subprog;
    Ok(Step::Next(caller.ret))
}

/// `is_branch_taken` of two known values.
fn taken(op: u8, a: u64, b: u64, narrow: bool) -> bool {
    let (a, b) = if narrow {
        (u64::from(a as u32), u64::from(b as u32))
    } else {
        (a, b)
    };
    let (sa, sb) = if narrow {
        (i64::from(a as u32 as i32), i64::from(b as u32 as i32))
    } else {
        (a as i64, b as i64)
    };
    match op {
        jmp::JEQ => a == b,
        jmp::JNE => a != b,
        jmp::JSET => a & b != 0,
        jmp::JGT => a > b,
        jmp::JGE => a >= b,
        jmp::JLT => a < b,
        jmp::JLE => a <= b,
        jmp::JSGT => sa > sb,
        jmp::JSGE => sa >= sb,
        jmp::JSLT => sa < sb,
        _ => sa <= sb,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn i(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
        Insn {
            code,
            dst,
            src,
            off,
            imm,
        }
    }
    /// `r = imm`, 64-bit.
    fn mov(dst: u8, imm: i32) -> Insn {
        i(0xb7, dst, 0, 0, imm)
    }
    /// `dst = src`, 64-bit.
    fn mov_reg(dst: u8, src: u8) -> Insn {
        i(0xbf, dst, src, 0, 0)
    }
    fn exit() -> Insn {
        i(0x95, 0, 0, 0, 0)
    }
    fn stx_dw(dst: u8, src: u8, off: i16) -> Insn {
        i(0x7b, dst, src, off, 0)
    }
    fn ldx(size: u8, dst: u8, src: u8, off: i16) -> Insn {
        i(0x61 | size, dst, src, off, 0)
    }
    /// The maps of the tests, by descriptor: 3 an array of one 8-byte
    /// value with 4-byte keys, 4 a hash with 8-byte keys and values, 5 a
    /// read-only array, 6 a queue; any other is no map.
    fn maps(fd: i32) -> Result<MapShape, Errno> {
        let shape = |id, kind, key_size, value_size, max_entries, flags| MapShape {
            id,
            kind,
            key_size,
            value_size,
            max_entries,
            flags,
            exclusive: false,
        };
        match fd {
            3 => Ok(shape(30, map_type::ARRAY, 4, 8, 1, 0)),
            4 => Ok(shape(40, map_type::HASH, 8, 8, 16, 0)),
            5 => Ok(shape(50, map_type::ARRAY, 4, 8, 1, F_RDONLY_PROG)),
            6 => Ok(shape(60, map_type::QUEUE, 0, 8, 4, 0)),
            7 => Err(Errno::EINVAL),
            _ => Err(Errno::EBADF),
        }
    }
    fn verify(insns: &[Insn], options: Options) -> Result<Verified, Rejection> {
        check(insns, options, &mut maps)
    }
    fn ok(insns: &[Insn]) -> u32 {
        match verify(insns, Options::default()) {
            Ok(v) => v.processed,
            Err(r) => panic!("refused: {} ({:?})", r.line, r.errno),
        }
    }
    fn refused(insns: &[Insn]) -> (Errno, String) {
        let r = verify(insns, Options::default()).expect_err("accepted");
        (r.errno, r.line)
    }

    #[test]
    fn a_constant_return_loads() {
        assert_eq!(ok(&[mov(0, 0), exit()]), 2);
        // A 64-bit constant counts once.
        assert_eq!(ok(&[i(0x18, 0, 0, 0, 1), i(0, 0, 0, 0, 2), exit()]), 2);
    }

    #[test]
    fn r0_must_be_written_before_the_exit() {
        assert_eq!(refused(&[exit()]), (EACCES, "R0 !read_ok".into()));
        // A privileged loader may return a pointer.
        ok(&[mov_reg(0, 10), exit()]);
    }

    #[test]
    fn the_structure_is_checked_first() {
        let einval = |line: &str| (Errno::EINVAL, line.to_string());
        assert_eq!(
            refused(&[i(0x8c, 0, 0, 0, 0), exit()]),
            einval("unknown opcode 8c")
        );
        assert_eq!(
            refused(&[mov(0, 0), i(0x05, 0, 0, 5, 0)]),
            einval("jump out of range from insn 1 to 7")
        );
        assert_eq!(
            refused(&[mov(0, 0)]),
            einval("last insn is not an exit or jmp")
        );
        assert_eq!(
            refused(&[mov(0, 0), exit(), exit()]),
            einval("unreachable insn 2")
        );
        assert_eq!(
            refused(&[mov(0, 0), i(0x05, 0, 0, -2, 0)]),
            einval("back-edge from insn 1 to 0")
        );
        assert!(ends_in_half(&[mov(0, 0), i(0x18, 0, 0, 0, 0)]));
        assert!(!ends_in_half(&[i(0x18, 0, 0, 0, 0), i(0, 0, 0, 0, 0)]));
        assert_eq!(
            refused(&[i(0x18, 0, 0, 0, 0), i(0, 1, 0, 0, 0), exit()]),
            einval("invalid bpf_ld_imm64 insn")
        );
        assert_eq!(
            refused(&[i(0x18, 0, 0, 1, 0), i(0, 0, 0, 0, 0), exit()]),
            einval("BPF_LD_IMM64 uses reserved fields")
        );
        assert_eq!(
            refused(&[i(0x18, 0, 7, 0, 0), i(0, 0, 0, 0, 0), exit()]),
            einval("unrecognized bpf_ld_imm64 insn")
        );
        assert_eq!(
            refused(&[
                mov(0, 0),
                i(0x15, 0, 0, 1, 0),
                i(0x18, 0, 0, 0, 0),
                i(0, 0, 0, 0, 0),
                exit()
            ]),
            einval("jump into the middle of ldimm64 insn 2")
        );
        assert_eq!(
            refused(&[mov(0, 0), i(0x95, 0, 1, 0, 0)]),
            einval("BPF_EXIT uses reserved fields")
        );
        assert_eq!(refused(&[mov(11, 0), exit()]), einval("R11 is invalid"));
        assert_eq!(
            refused(&[mov(0, 0), i(0x37, 0, 0, 0, 0), exit()]),
            einval("div by zero")
        );
        assert_eq!(
            refused(&[mov(0, 0), i(0x67, 0, 0, 0, 64), exit()]),
            einval("invalid shift 64")
        );
        assert_eq!(
            refused(&[mov(0, 0), i(0x64, 0, 0, 0, 32), exit()]),
            einval("invalid shift 32")
        );
    }

    #[test]
    fn the_frame_pointer_is_read_only() {
        assert_eq!(
            refused(&[mov(10, 0), mov(0, 0), exit()]),
            (EACCES, "frame pointer is read only".into())
        );
        assert_eq!(
            refused(&[i(0x07, 10, 0, 0, -8), mov(0, 0), exit()]),
            (EACCES, "frame pointer is read only".into())
        );
    }

    #[test]
    fn a_pointer_spilled_whole_comes_back() {
        ok(&[stx_dw(10, 10, -8), ldx(0x18, 0, 10, -8), exit()]);
        assert_eq!(
            refused(&[stx_dw(10, 10, -8), ldx(0x00, 0, 10, -8), exit()]),
            (EACCES, "invalid size of register fill".into())
        );
        assert_eq!(
            refused(&[i(0x63, 10, 10, -8, 0), mov(0, 0), exit()]),
            (EACCES, "invalid size of register spill".into())
        );
        // A scalar written over part of it leaves a number.
        ok(&[
            stx_dw(10, 10, -8),
            mov(1, 0),
            i(0x63, 10, 1, -4, 0),
            ldx(0x18, 0, 10, -8),
            i(0x27, 0, 0, 0, 3),
            exit(),
        ]);
        // So does a stack slot never written, for a privileged loader.
        ok(&[ldx(0x18, 0, 10, -512), exit()]);
    }

    #[test]
    fn the_stack_is_512_aligned_bytes_below_the_frame() {
        assert_eq!(
            refused(&[mov(0, 0), stx_dw(10, 0, -520), exit()]),
            (EACCES, "invalid write to stack R10 off=-520 size=8".into())
        );
        assert_eq!(
            refused(&[ldx(0x18, 0, 10, 0), exit()]),
            (EACCES, "invalid read from stack R10 off=0 size=8".into())
        );
        assert_eq!(
            refused(&[mov(0, 0), stx_dw(10, 0, -4), exit()]),
            (EACCES, "misaligned stack access off 0+0+-4 size 8".into())
        );
        assert_eq!(
            refused(&[
                mov_reg(1, 10),
                i(0x07, 1, 0, 0, -6),
                ldx(0x00, 0, 1, 0),
                exit()
            ]),
            (EACCES, "misaligned stack access off 0+-6+0 size 4".into())
        );
        // A pointer the program moves keeps its offset.
        ok(&[
            mov_reg(1, 10),
            i(0x07, 1, 0, 0, -16),
            mov(2, 7),
            stx_dw(1, 2, 8),
            ldx(0x18, 0, 10, -8),
            exit(),
        ]);
    }

    #[test]
    fn pointer_arithmetic_is_7_0s() {
        let eacces = |line: &str| (EACCES, line.to_string());
        assert_eq!(
            refused(&[mov_reg(1, 10), i(0x17, 1, 0, 0, 8), mov(0, 0), exit()]),
            eacces("R1 subtraction from stack pointer prohibited")
        );
        assert_eq!(
            refused(&[mov_reg(1, 10), i(0x27, 1, 0, 0, 2), mov(0, 0), exit()]),
            eacces("R1 pointer arithmetic with *= operator prohibited")
        );
        assert_eq!(
            refused(&[mov_reg(1, 10), i(0x57, 1, 0, 0, 2), mov(0, 0), exit()]),
            eacces("R1 bitwise operator &= on pointer prohibited")
        );
        assert_eq!(
            refused(&[mov_reg(1, 10), i(0x04, 1, 0, 0, 2), mov(0, 0), exit()]),
            eacces("R1 32-bit pointer arithmetic prohibited")
        );
        assert_eq!(
            refused(&[mov_reg(1, 10), i(0x0f, 1, 10, 0, 0), mov(0, 0), exit()]),
            eacces("R1 pointer += pointer prohibited")
        );
        assert_eq!(
            refused(&[mov(1, 8), i(0x1f, 1, 10, 0, 0), mov(0, 0), exit()]),
            eacces("R1 tried to subtract pointer from scalar")
        );
        assert_eq!(
            refused(&[mov_reg(1, 10), i(0x07, 1, 0, 0, 1 << 29), mov(0, 0), exit()]),
            (
                Errno::EINVAL,
                "math between fp pointer and 536870912 is not allowed".into()
            )
        );
        // Pointers less pointers, and 32-bit differences, are numbers.
        ok(&[mov_reg(0, 10), i(0x1f, 0, 1, 0, 0), exit()]);
        ok(&[mov_reg(0, 10), i(0x14, 0, 0, 0, 1), exit()]);
        // A known scalar plus the frame pointer is a stack pointer.
        ok(&[
            mov(1, -8),
            i(0x0f, 1, 10, 0, 0),
            mov(0, 0),
            stx_dw(1, 0, 0),
            exit(),
        ]);
    }

    #[test]
    fn a_scalar_is_no_pointer() {
        assert_eq!(
            refused(&[mov(1, 0), ldx(0x18, 0, 1, 0), exit()]),
            (EACCES, "R1 invalid mem access 'scalar'".into())
        );
    }

    #[test]
    fn a_branch_both_operands_know_goes_one_way() {
        // The fall-through would read through a scalar.
        ok(&[mov(0, 0), i(0x15, 0, 0, 1, 0), ldx(0x18, 1, 0, 0), exit()]);
        // Not knowing R0, both ways are walked.
        assert_eq!(
            refused(&[
                ldx(0x18, 0, 10, -8),
                i(0x15, 0, 0, 1, 0),
                ldx(0x18, 1, 0, 0),
                exit()
            ]),
            (EACCES, "R0 invalid mem access 'scalar'".into())
        );
        // A 32-bit jump compares the low halves.
        ok(&[
            i(0x18, 0, 0, 0, 5),
            i(0, 0, 0, 0, 1),
            i(0x16, 0, 0, 1, 5),
            ldx(0x18, 1, 0, 0),
            exit(),
        ]);
    }

    #[test]
    fn known_values_follow_the_operations() {
        // (3 * 4 - 2) << 1 == 20, 32-bit -1 >> 28 == 15.
        ok(&[
            mov(1, 3),
            i(0x27, 1, 0, 0, 4),
            i(0x17, 1, 0, 0, 2),
            i(0x67, 1, 0, 0, 1),
            i(0x55, 1, 0, 2, 20),
            i(0xb4, 2, 0, 0, -1),
            i(0x74, 2, 0, 0, 28),
            i(0x55, 2, 0, 1, 15),
            mov(0, 0),
            exit(),
        ]);
        // A division is not followed here, so both ways are walked.
        assert!(
            verify(
                &[
                    mov(1, 8),
                    i(0x37, 1, 0, 0, 2),
                    i(0x55, 1, 0, 1, 4),
                    ldx(0x18, 0, 1, 0),
                    mov(0, 0),
                    exit()
                ],
                Options::default()
            )
            .is_err()
        );
    }

    #[test]
    fn what_is_not_verified_yet_is_refused() {
        let gap = |insns: &[Insn]| {
            let (errno, line) = refused(insns);
            assert_eq!(errno, Errno::EINVAL);
            assert!(line.contains("paludarium: "), "{line}");
        };
        // bpf_tail_call, which Linux gives a socket filter.
        gap(&[i(0x85, 0, 0, 0, 12), exit()]);
        // A kfunc, and a reference to a function.
        gap(&[i(0x85, 0, 2, 0, 1), exit()]);
        gap(&[
            i(0x18, 1, 4, 0, 1),
            i(0, 0, 0, 0, 0),
            mov(0, 0),
            exit(),
            mov(0, 0),
            exit(),
        ]);
        // The context's socket.
        gap(&[ldx(0x18, 0, 1, 168), exit()]);
        // A queue's helpers are push, pop and peek.
        gap(&[
            i(0x18, 1, 1, 0, 6),
            i(0, 0, 0, 0, 0),
            mov_reg(2, 10),
            i(0x07, 2, 0, 0, -8),
            i(0x85, 0, 0, 0, 1),
            exit(),
        ]);
        gap(&[
            mov(1, -8),
            ldx(0x18, 0, 10, -8),
            i(0x0f, 0, 10, 0, 0),
            exit(),
        ]);
    }

    #[test]
    fn a_sleepable_socket_filter_is_refused() {
        let options = Options {
            sleepable: true,
            ..Options::default()
        };
        let r = verify(&[mov(0, 0), exit()], options).expect_err("accepted");
        assert_eq!(r.errno, Errno::EINVAL);
        assert!(r.line.ends_with("can be sleepable"));
    }

    #[test]
    fn the_walk_stops_at_the_pending_branch_limit() {
        // Each unknown jump leaves its target to walk later.
        let mut insns = vec![ldx(0x18, 0, 10, -8)];
        for _ in 0..=COMPLEXITY_LIMIT_JMP_SEQ {
            insns.push(i(0x15, 0, 0, 0, 0));
        }
        insns.push(exit());
        let r = verify(&insns, Options::default()).expect_err("accepted");
        assert_eq!(r.errno, E2BIG);
        assert_eq!(r.line, "The sequence of 8193 jumps is too complex.");
    }

    /// `r = map fd`, two instructions.
    fn ld_map(dst: u8, fd: i32) -> [Insn; 2] {
        [i(0x18, dst, 1, 0, fd), i(0, 0, 0, 0, 0)]
    }
    fn call(id: i32) -> Insn {
        i(0x85, 0, 0, 0, id)
    }
    /// A lookup of the key 0 at fp-4 in the map of `fd`, leaving R0.
    fn lookup(fd: i32) -> Vec<Insn> {
        let mut v = vec![i(0x62, 10, 0, -4, 0)];
        v.extend(ld_map(1, fd));
        v.extend([mov_reg(2, 10), i(0x07, 2, 0, 0, -4), call(1)]);
        v
    }

    #[test]
    fn atomics_are_checked_as_check_atomic_does() {
        const W: u8 = 0xc3;
        const DW: u8 = 0xdb;
        let einval = |line: &str| (Errno::EINVAL, line.to_string());
        let eacces = |line: &str| (EACCES, line.to_string());
        // fp-8 = 1; r1 = 1; then `last`, and exit with 0.
        let with = |last: &[Insn]| {
            let mut p = vec![mov(1, 1), stx_dw(10, 1, -8)];
            p.extend_from_slice(last);
            p.extend([mov(0, 0), exit()]);
            p
        };
        for imm in [0x00, 0x01, 0x40, 0x41, 0x50, 0x51, 0xa0, 0xa1, 0xe1] {
            ok(&with(&[i(DW, 10, 1, -8, imm)]));
            ok(&with(&[i(W, 10, 1, -4, imm)]));
        }
        ok(&with(&[mov(0, 1), i(DW, 10, 1, -8, 0xf1)]));
        // The operation, then its size.
        assert_eq!(
            refused(&with(&[i(DW, 10, 1, -8, 0x02)])),
            einval("BPF_ATOMIC uses invalid atomic opcode 02")
        );
        assert_eq!(
            refused(&with(&[i(DW, 10, 1, -8, -1)])),
            einval("BPF_ATOMIC uses invalid atomic opcode ffffffff")
        );
        assert_eq!(
            refused(&with(&[i(0xd3, 10, 1, -8, 0x01)])),
            einval("invalid atomic operand size")
        );
        assert_eq!(
            refused(&with(&[i(0xcb, 10, 1, -8, 0x07)])),
            einval("BPF_ATOMIC uses invalid atomic opcode 07")
        );
        // The source, the destination, and R0 for CMPXCHG must be written.
        assert_eq!(
            refused(&with(&[i(DW, 10, 2, -8, 0)])),
            eacces("R2 !read_ok")
        );
        assert_eq!(refused(&with(&[i(DW, 3, 1, -8, 0)])), eacces("R3 !read_ok"));
        assert_eq!(
            refused(&[mov(1, 1), stx_dw(10, 1, -8), i(DW, 10, 1, -8, 0xf1), exit()]),
            eacces("R0 !read_ok")
        );
        // Not into the context, even into cb[].
        assert_eq!(
            refused(&[mov(2, 1), i(W, 1, 2, 48, 0), mov(0, 0), exit()]),
            eacces("BPF_ATOMIC stores into R1 ctx is not allowed")
        );
        // Aligned on the stack and in a map's value, unasked.
        assert_eq!(
            refused(&with(&[i(DW, 10, 1, -12, 0)])),
            eacces("misaligned stack access off 0+0+-12 size 8")
        );
        let mut p = lookup(3);
        p.extend([
            i(0x15, 0, 0, 3, 0),
            mov(1, 1),
            i(W, 0, 1, 2, 0x01),
            mov(0, 0),
            exit(),
        ]);
        assert_eq!(
            refused(&p),
            eacces("misaligned value access off 0+0+2 size 4")
        );
        let mut p = lookup(3);
        p.extend([
            i(0x15, 0, 0, 3, 0),
            mov(1, 1),
            i(W, 0, 1, 4, 0x01),
            mov(0, 0),
            exit(),
        ]);
        ok(&p);
        // A hash's lookup result before its check, which Linux too takes to
        // be null (an array's of a constant key it knows is not).
        let mut p = vec![i(0x7a, 10, 0, -8, 0)];
        p.extend(ld_map(1, 4));
        p.extend([mov_reg(2, 10), i(0x07, 2, 0, 0, -8), call(1)]);
        p.extend([mov(1, 1), i(W, 0, 1, 2, 0), mov(0, 0), exit()]);
        assert_eq!(refused(&p), eacces("misaligned access off 0+0+2 size 4"));
        // A read-only value is read, then refused the write.
        let mut p = lookup(5);
        p.extend([
            i(0x15, 0, 0, 3, 0),
            mov(1, 1),
            i(DW, 0, 1, 0, 0),
            mov(0, 0),
            exit(),
        ]);
        assert_eq!(
            refused(&p),
            eacces("write into map forbidden, value_size=8 off=0 size=8")
        );
        assert_eq!(
            refused(&with(&[i(DW, 10, 1, 0, 0)])),
            eacces("invalid read from stack R10 off=0 size=8")
        );
        // The old value's register is written before the memory is read:
        // as the destination it is then a scalar Linux knows nothing of,
        // which is not aligned.
        assert_eq!(
            refused(&with(&[i(DW, 10, 10, -8, 0x01)])),
            eacces("frame pointer is read only")
        );
        let unknown = "misaligned access off (0x0; 0xffffffffffffffff)+0+-8 size 8";
        assert_eq!(
            refused(&with(&[mov_reg(2, 10), i(DW, 2, 2, -8, 0x01)])),
            eacces(unknown)
        );
        assert_eq!(
            refused(&with(&[mov_reg(0, 10), i(DW, 0, 1, -8, 0xf1)])),
            eacces(unknown)
        );
        // It takes what the stack holds, here a pointer, and leaves the
        // slot bytes.
        let p = [
            stx_dw(10, 10, -8),
            mov(1, 0),
            i(DW, 10, 1, -8, 0x01),
            ldx(size::DW, 0, 1, -16),
            ldx(size::DW, 2, 10, -8),
            ldx(size::DW, 0, 2, 0),
            exit(),
        ];
        assert_eq!(refused(&p), eacces("R2 invalid mem access 'scalar'"));
        ok(&p[..4].iter().copied().chain([exit()]).collect::<Vec<_>>());
        assert_eq!(
            refused(&[
                stx_dw(10, 10, -8),
                mov(1, 0),
                i(W, 10, 1, -8, 0x01),
                mov(0, 0),
                exit()
            ]),
            eacces("invalid size of register fill")
        );
        // A pointer may be the source.
        ok(&with(&[i(DW, 10, 10, -8, 0x00)]));
    }

    #[test]
    fn load_acquire_and_store_release_are_checked_as_linux_does() {
        const ACQ: i32 = 0x100;
        const REL: i32 = 0x110;
        let eacces = |line: &str| (EACCES, line.to_string());
        let with = |last: &[Insn]| {
            let mut p = vec![mov(1, 1)];
            p.extend_from_slice(last);
            p.extend([mov(0, 0), exit()]);
            p
        };
        // Every size, on the stack.
        for (code, off) in [(0xd3, -1), (0xcb, -4), (0xc3, -8), (0xdb, -8)] {
            ok(&with(&[i(code, 10, 1, off, REL), i(code, 2, 10, off, ACQ)]));
        }
        // Registers as a load's and a store's.
        assert_eq!(
            refused(&with(&[i(0xdb, 2, 3, -8, ACQ)])),
            eacces("R3 !read_ok")
        );
        assert_eq!(
            refused(&with(&[i(0xdb, 10, 10, -8, ACQ)])),
            eacces("frame pointer is read only")
        );
        assert_eq!(
            refused(&with(&[i(0xdb, 10, 3, -8, REL)])),
            eacces("R3 !read_ok")
        );
        // Always aligned, in a map's value too.
        for imm in [ACQ, REL] {
            let (dst, src) = if imm == ACQ { (1, 0) } else { (0, 1) };
            let mut p = lookup(3);
            p.extend([i(0x15, 0, 0, 3, 0), mov(1, 1), i(0xc3, dst, src, 2, imm)]);
            p.extend([mov(0, 0), exit()]);
            assert_eq!(
                refused(&p),
                eacces("misaligned value access off 0+0+2 size 4")
            );
        }
        // A read-only value can be loaded from, not stored into.
        let mut p = lookup(5);
        p.extend([i(0x15, 0, 0, 3, 0), mov(1, 1), i(0xdb, 1, 0, 0, ACQ)]);
        p.extend([mov(0, 0), exit()]);
        ok(&p);
        let n = p.len();
        p[n - 3] = i(0xdb, 0, 1, 0, REL);
        assert_eq!(
            refused(&p),
            eacces("write into map forbidden, value_size=8 off=0 size=8")
        );
        // Not through the context: a load is refused before the access,
        // into the register it loads from too, and a store after it.
        for (dst, off) in [(2, 0), (2, 2), (1, 0), (1, 2), (10, 0)] {
            assert_eq!(
                refused(&[i(0xc3, dst, 1, off, ACQ), mov(0, 0), exit()]),
                eacces("BPF_ATOMIC loads from R1 ctx is not allowed")
            );
        }
        assert_eq!(
            refused(&[mov(2, 1), i(0xc3, 1, 2, 48, REL), mov(0, 0), exit()]),
            eacces("BPF_ATOMIC stores into R1 ctx is not allowed")
        );
        assert_eq!(
            refused(&[mov(2, 1), i(0xc3, 1, 2, 0, REL), mov(0, 0), exit()]),
            eacces("invalid bpf_context access off=0 size=4")
        );
        // A pointer stored is loaded back, whole only.
        let p = [
            i(0xdb, 10, 10, -8, REL),
            i(0xdb, 2, 10, -8, ACQ),
            ldx(size::DW, 0, 2, -16),
            exit(),
        ];
        ok(&p);
        assert_eq!(
            refused(&[
                i(0xdb, 10, 10, -8, REL),
                i(0xc3, 2, 10, -8, ACQ),
                mov(0, 0),
                exit()
            ]),
            eacces("invalid size of register fill")
        );
    }

    #[test]
    fn a_lookup_must_be_null_checked() {
        let mut p = lookup(3);
        p.extend([ldx(0x18, 0, 0, 0), exit()]);
        assert_eq!(
            refused(&p),
            (EACCES, "R0 invalid mem access 'map_value_or_null'".into())
        );
        // if r0 == 0 goto exit; r0 = *(u64 *)(r0 + 0)
        let mut p = lookup(3);
        p.extend([i(0x15, 0, 0, 1, 0), ldx(0x18, 0, 0, 0), exit()]);
        ok(&p);
        // A copy spilled before the check is checked with it.
        let mut p = lookup(3);
        p.extend([
            stx_dw(10, 0, -16),
            i(0x55, 0, 0, 2, 0),
            mov(0, 0),
            exit(),
            ldx(0x18, 1, 10, -16),
            ldx(0x18, 0, 1, 0),
            exit(),
        ]);
        ok(&p);
        // A 32-bit comparison does not tell.
        let mut p = lookup(3);
        p.extend([i(0x16, 0, 0, 1, 0), ldx(0x18, 0, 0, 0), exit()]);
        assert_eq!(refused(&p).1, "R0 invalid mem access 'map_value_or_null'");
        let mut p = lookup(3);
        p.extend([i(0x07, 0, 0, 0, 1), exit()]);
        assert_eq!(
            refused(&p),
            (
                EACCES,
                "R0 pointer arithmetic on map_value_or_null prohibited, null-check it first".into()
            )
        );
    }

    #[test]
    fn a_maps_value_has_its_bounds_and_access() {
        let mut p = lookup(3);
        p.extend([i(0x15, 0, 0, 1, 0), ldx(0x18, 0, 0, 4), exit()]);
        assert_eq!(
            refused(&p),
            (
                EACCES,
                "invalid access to map value, value_size=8 off=4 size=8\nR0 min value is outside of the allowed memory range".into()
            )
        );
        let mut p = lookup(5);
        p.extend([i(0x15, 0, 0, 1, 0), i(0x7a, 0, 0, 0, 1), exit()]);
        assert_eq!(
            refused(&p),
            (
                EACCES,
                "write into map forbidden, value_size=8 off=0 size=8".into()
            )
        );
        // The direct value of an array of one element.
        let mut p = vec![i(0x18, 1, 2, 0, 3), i(0, 0, 0, 0, 4)];
        p.extend([ldx(0x00, 0, 1, 0), exit()]);
        ok(&p);
        let mut p = vec![i(0x18, 1, 2, 0, 3), i(0, 0, 0, 0, 8)];
        p.extend([mov(0, 0), exit()]);
        assert_eq!(
            refused(&p),
            (
                Errno::EINVAL,
                "invalid access to map value pointer, value_size=8 off=8".into()
            )
        );
        let mut p = vec![i(0x18, 1, 2, 0, 4), i(0, 0, 0, 0, 0)];
        p.extend([mov(0, 0), exit()]);
        assert_eq!(
            refused(&p),
            (
                Errno::EINVAL,
                "no direct value access support for this map type".into()
            )
        );
    }

    #[test]
    fn a_map_is_named_by_its_descriptor() {
        let mut p = ld_map(1, 9).to_vec();
        p.extend([mov(0, 0), exit()]);
        assert_eq!(
            refused(&p),
            (Errno::EBADF, "fd 9 is not pointing to valid bpf_map".into())
        );
        let mut p = ld_map(1, 7).to_vec();
        p.extend([mov(0, 0), exit()]);
        assert_eq!(refused(&p).0, Errno::EINVAL);
        let mut p = vec![i(0x18, 1, 5, 0, 0), i(0, 0, 0, 0, 0)];
        p.extend([mov(0, 0), exit()]);
        assert_eq!(
            refused(&p),
            (EPROTO, "fd_idx without fd_array is invalid".into())
        );
        // The map pointer itself takes only += 0.
        let mut p = ld_map(1, 3).to_vec();
        p.extend([i(0x07, 1, 0, 0, 0), i(0x07, 1, 0, 0, 8), mov(0, 0), exit()]);
        assert_eq!(
            refused(&p),
            (EACCES, "R1 pointer arithmetic on map_ptr prohibited".into())
        );
        // One map named twice is one map.
        let mut p = ld_map(1, 3).to_vec();
        p.extend(ld_map(2, 3));
        p.extend([mov(0, 0), exit()]);
        assert_eq!(
            verify(&p, Options::default()).map(|v| v.maps).ok(),
            Some(vec![30])
        );
    }

    #[test]
    fn the_map_helpers_check_their_arguments() {
        // update(map, key, value, flags), then the arguments are gone.
        let mut p = vec![stx_dw(10, 10, -8), i(0x62, 10, 0, -12, 0)];
        p.extend(ld_map(1, 3));
        p.extend([
            mov_reg(2, 10),
            i(0x07, 2, 0, 0, -12),
            mov_reg(3, 10),
            i(0x07, 3, 0, 0, -8),
            mov(4, 0),
            call(2),
            mov_reg(0, 1),
            exit(),
        ]);
        assert_eq!(refused(&p), (EACCES, "R1 !read_ok".into()));
        let n = p.len();
        p[n - 2] = mov(0, 0);
        ok(&p);
        // The key must be within the stack.
        let mut p = ld_map(1, 4).to_vec();
        p.extend([
            mov_reg(2, 10),
            i(0x07, 2, 0, 0, -4),
            call(1),
            mov(0, 0),
            exit(),
        ]);
        assert_eq!(
            refused(&p),
            (
                Errno::EINVAL,
                "invalid read from stack R2 off=-4 size=8".into()
            )
        );
        assert_eq!(
            refused(&[mov(1, 0), mov(2, 0), call(1), exit()]),
            (EACCES, "R1 type=scalar expected=map_ptr".into())
        );
        let mut p = vec![i(0x62, 10, 0, -4, 0)];
        p.extend(ld_map(1, 5));
        p.extend([mov_reg(2, 10), i(0x07, 2, 0, 0, -4), call(3), exit()]);
        assert_eq!(refused(&p), (EACCES, "write into map forbidden".into()));
    }

    #[test]
    fn the_context_is_a_socket_filters_sk_buff() {
        let invalid = |off: i64, size: i64| {
            (
                EACCES,
                format!("invalid bpf_context access off={off} size={size}"),
            )
        };
        ok(&[ldx(size::W, 0, 1, 0), exit()]);
        ok(&[ldx(size::H, 0, 1, 6), ldx(size::B, 2, 1, 11), exit()]);
        ok(&[i(0x62, 1, 0, 48, 7), ldx(size::DW, 0, 1, 56), exit()]);
        ok(&[mov(2, 1), stx_dw(1, 2, 56), ldx(size::W, 0, 1, 64), exit()]);
        ok(&[ldx(size::W, 0, 1, 176), exit()]);
        assert_eq!(refused(&[ldx(size::W, 0, 1, 192), exit()]), invalid(192, 4));
        assert_eq!(refused(&[ldx(size::W, 0, 1, 76), exit()]), invalid(76, 4));
        assert_eq!(refused(&[ldx(size::DW, 0, 1, 0), exit()]), invalid(0, 8));
        assert_eq!(refused(&[ldx(size::W, 0, 1, 2), exit()]), invalid(2, 4));
        assert_eq!(refused(&[ldx(size::B, 0, 1, 180), exit()]), invalid(180, 1));
        assert_eq!(
            refused(&[ldx(size::DW, 0, 1, 144), exit()]),
            invalid(144, 8)
        );
        assert_eq!(refused(&[ldx(size::W, 0, 1, 92), exit()]), invalid(92, 4));
        // bpf_ctx_range_ptr: every offset of sk is sk, which is read whole.
        assert_eq!(refused(&[ldx(size::W, 0, 1, 168), exit()]), invalid(168, 4));
        assert_eq!(refused(&[ldx(size::W, 0, 1, 172), exit()]), invalid(172, 4));
        assert_eq!(refused(&[ldx(size::B, 0, 1, 175), exit()]), invalid(175, 1));
        assert_eq!(
            refused(&[mov(2, 1), i(0x63, 1, 2, 0, 0), mov(0, 0), exit()]),
            invalid(0, 4)
        );
        assert_eq!(
            refused(&[mov(2, 1), stx_dw(1, 2, 64), mov(0, 0), exit()]),
            invalid(64, 8)
        );
        // Only the context as it came may be read through.
        assert_eq!(
            refused(&[i(0x07, 1, 0, 0, 4), ldx(size::W, 0, 1, 0), exit()]),
            (
                EACCES,
                "dereference of modified ctx ptr R1 off=4 disallowed".into()
            )
        );
        assert_eq!(
            refused(&[i(0x07, 1, 0, 0, -4), ldx(size::W, 0, 1, 4), exit()]),
            (
                EACCES,
                "negative offset ctx ptr R1 off=-4 disallowed".into()
            )
        );
        ok(&[
            i(0x07, 1, 0, 0, 4),
            i(0x07, 1, 0, 0, -4),
            ldx(size::W, 0, 1, 0),
            exit(),
        ]);
        // One load through the context on a path and the stack on another.
        assert_eq!(
            refused(&[
                mov_reg(2, 1),
                ldx(size::DW, 0, 10, -8),
                i(0x15, 0, 0, 2, 0),
                mov_reg(2, 10),
                i(0x07, 2, 0, 0, -16),
                ldx(size::W, 0, 2, 0),
                exit(),
            ]),
            (
                Errno::EINVAL,
                "same insn cannot be used with different pointers".into()
            )
        );
        let strict = Options {
            strict_alignment: true,
            ..Options::default()
        };
        let r = verify(&[ldx(size::H, 0, 1, 5), exit()], strict).expect_err("accepted");
        assert_eq!(r.line, "misaligned context access off 0+0+5 size 2");
    }

    #[test]
    fn ld_abs_and_ld_ind_are_checked_as_check_ld_abs_does() {
        let einval = |line: &str| (Errno::EINVAL, line.to_string());
        let eacces = |line: &str| (EACCES, line.to_string());
        let abs = |size: u8, imm: i32| i(0x20 | size, 0, 0, 0, imm);
        let ind = |size: u8, src: u8, imm: i32| i(0x40 | size, 0, src, 0, imm);
        let ctx = mov_reg(6, 1);
        // Each size, from the context in R6, and R0 is a scalar after it.
        for size in [size::W, size::H, size::B] {
            ok(&[ctx, abs(size, 0), exit()]);
            ok(&[ctx, mov(7, 3), ind(size, 7, -1), exit()]);
            ok(&[ctx, ind(size, 6, 0), exit()]);
            ok(&[ctx, ind(size, 10, 0), exit()]);
            ok(&[
                ctx,
                abs(size, -0x10_0000),
                mov_reg(2, 0),
                mov_reg(0, 2),
                exit(),
            ]);
        }
        // R6 to R9 stay; R1 to R5 do not.
        ok(&[
            ctx,
            mov(9, 1),
            abs(size::B, 0),
            mov_reg(0, 9),
            ldx(size::W, 2, 6, 0),
            exit(),
        ]);
        for r in 1..=5 {
            assert_eq!(
                refused(&[ctx, abs(size::B, 0), mov_reg(0, r), exit()]),
                eacces(&format!("R{r} !read_ok"))
            );
        }
        // R6 must be the context, at its start.
        assert_eq!(refused(&[abs(size::B, 0), exit()]), eacces("R6 !read_ok"));
        let skb = "at the time of BPF_LD_ABS|IND R6 != pointer to skb";
        assert_eq!(refused(&[mov(6, 0), abs(size::B, 0), exit()]), einval(skb));
        assert_eq!(
            refused(&[mov_reg(6, 10), abs(size::W, 0), exit()]),
            einval(skb)
        );
        let mut lookup = lookup(3);
        lookup.extend([mov_reg(6, 0), abs(size::B, 0), exit()]);
        assert_eq!(refused(&lookup), einval(skb));
        assert_eq!(
            refused(&[ctx, i(0x07, 6, 0, 0, 4), abs(size::B, 0), exit()]),
            eacces("dereference of modified ctx ptr R6 off=4 disallowed")
        );
        assert_eq!(
            refused(&[ctx, i(0x07, 6, 0, 0, -4), ind(size::B, 1, 0), exit()]),
            eacces("negative offset ctx ptr R6 off=-4 disallowed")
        );
        // The source is checked after R6's type and before its offset.
        assert_eq!(
            refused(&[ctx, ind(size::B, 7, 0), exit()]),
            eacces("R7 !read_ok")
        );
        assert_eq!(
            refused(&[mov(6, 0), ind(size::B, 7, 0), exit()]),
            einval(skb)
        );
        assert_eq!(
            refused(&[ctx, i(0x07, 6, 0, 0, 4), ind(size::B, 7, 0), exit()]),
            eacces("R7 !read_ok")
        );
        // The fields, before any path is walked.
        let reserved = einval("BPF_LD_[ABS|IND] uses reserved fields");
        assert_eq!(refused(&[i(0x30, 1, 0, 0, 0), exit()]), reserved);
        assert_eq!(refused(&[i(0x30, 0, 0, 1, 0), exit()]), reserved);
        assert_eq!(refused(&[i(0x30, 0, 1, 0, 0), exit()]), reserved);
        assert_eq!(
            refused(&[i(0x38, 0, 0, 0, 0), exit()]),
            einval("unknown opcode 38")
        );
        assert_eq!(
            refused(&[i(0x58, 0, 1, 0, 0), exit()]),
            einval("unknown opcode 58")
        );
    }

    /// A call of the function `by` instructions after it.
    fn call_by(by: i32) -> Insn {
        i(0x85, 0, 1, 0, by)
    }
    fn stack_depth(insns: &[Insn]) -> Vec<u32> {
        verify(insns, Options::default()).unwrap().stack_depth
    }

    #[test]
    fn functions_are_found_and_checked_before_the_walk() {
        let einval = |line: &str| (Errno::EINVAL, line.to_string());
        // add_subprogs.
        assert_eq!(
            refused(&[call_by(1), exit()]),
            einval("call to invalid destination")
        );
        assert_eq!(
            refused(&[call_by(-2), exit()]),
            einval("call to invalid destination")
        );
        let mut many = Vec::new();
        for k in 0..256 {
            many.push(call_by(257 + k));
        }
        many.push(mov(0, 0));
        many.push(exit());
        for _ in 0..256 {
            many.extend([mov(0, 0), exit()]);
        }
        assert_eq!(refused(&many), (E2BIG, "too many subprograms".into()));
        // check_subprogs: a jump into another function, and one that falls
        // into the next.
        assert_eq!(
            refused(&[call_by(2), mov(0, 0), i(0x05, 0, 0, 1, 0), exit(), exit()]),
            einval("jump out of range from insn 2 to 4")
        );
        assert_eq!(
            refused(&[call_by(1), exit(), mov(0, 0)]),
            einval("last insn is not an exit or jmp")
        );
        assert_eq!(
            refused(&[call_by(2), mov(0, 0), mov(1, 0), exit()]),
            einval("last insn is not an exit or jmp")
        );
        // 7.0's check_abnormal_return.
        assert_eq!(
            refused(&[
                call_by(1),
                exit(),
                mov_reg(6, 1),
                i(0x30, 0, 0, 0, 0),
                exit()
            ]),
            einval("LD_ABS is not allowed in subprogs without BTF")
        );
        assert_eq!(
            refused(&[call_by(1), exit(), i(0x85, 0, 0, 0, 12), exit()]),
            einval("tail_call is not allowed in subprogs without BTF")
        );
        // check_cfg: code no path reaches, with a call in it; and recursion,
        // direct or not, which the walk refuses 9 frames deep, as 7.0 does.
        assert_eq!(
            refused(&[mov(0, 0), exit(), mov(0, 0), call_by(-4), exit()]),
            einval("unreachable insn 2")
        );
        let recursive = (E2BIG, "the call stack of 9 frames is too deep".to_string());
        assert_eq!(
            refused(&[call_by(1), exit(), call_by(-1), exit()]),
            recursive
        );
        assert_eq!(
            refused(&[call_by(1), exit(), call_by(1), exit(), call_by(-3), exit()]),
            recursive
        );
        assert_eq!(
            refused(&[call_by(1), exit(), mov(0, 0), call_by(-4), exit()]),
            recursive
        );
        // Recursion where the walk does not go: the stack check after it
        // goes 8 frames deep.
        assert_eq!(
            refused(&[
                mov(0, 0),
                i(0x15, 0, 0, 1, 0),
                call_by(1),
                exit(),
                call_by(-1),
                exit(),
            ]),
            (E2BIG, "the call stack of 8 frames is too deep !".into())
        );
        // A jump back is still a back-edge.
        assert_eq!(
            refused(&[mov(0, 0), i(0x05, 0, 0, -2, 0), exit()]),
            einval("back-edge from insn 1 to 0")
        );
    }

    #[test]
    fn a_call_passes_r1_to_r5_and_gets_r0() {
        let eacces = |line: &str| (EACCES, line.to_string());
        // The callee reads R1 to R5 and returns R0; the caller keeps R6 to R9
        // and loses R1 to R5.
        let callee = [mov_reg(0, 1), i(0x0f, 0, 5, 0, 0), exit()];
        let program = |after: Insn| {
            let mut p = vec![mov(1, 1), mov(5, 5), mov(6, 6), call_by(2), after, exit()];
            p.extend(callee);
            p
        };
        ok(&program(mov_reg(0, 6)));
        ok(&program(i(0x07, 0, 0, 0, 1)));
        for r in 1..=5 {
            assert_eq!(
                refused(&program(mov_reg(0, r))),
                eacces(&format!("R{r} !read_ok"))
            );
        }
        // R0 and R6 to R9 are not the callee's to read, nor an argument the
        // caller did not write.
        for (r, set) in [(0, 1), (6, 1), (9, 1), (2, 1)] {
            let p = [mov(set, 1), call_by(1), exit(), mov_reg(0, r), exit()];
            assert_eq!(refused(&p), eacces(&format!("R{r} !read_ok")));
        }
        // The callee's own R0 must be written before the caller reads it.
        assert_eq!(
            refused(&[call_by(1), exit(), exit()]),
            eacces("R0 !read_ok")
        );
        ok(&[call_by(2), mov(0, 0), exit(), exit()]);
    }

    #[test]
    fn a_callee_s_frame_is_its_own() {
        // The callee's frame pointer is its own stack; a pointer to the
        // caller's reaches the caller's, whose slot keeps its spill.
        ok(&[
            mov_reg(1, 10),
            i(0x07, 1, 0, 0, -8),
            stx_dw(1, 1, 0),
            call_by(2),
            ldx(size::DW, 0, 10, -8),
            exit(),
            // A spill of a scalar into the caller's slot, then a read.
            mov(2, 7),
            stx_dw(1, 2, 0),
            ldx(size::DW, 0, 1, 0),
            stx_dw(10, 0, -16),
            exit(),
        ]);
        // A pointer to a stack may not go into the caller's frame, even
        // the caller's own frame pointer.
        assert_eq!(
            refused(&[
                mov_reg(1, 10),
                i(0x07, 1, 0, 0, -8),
                call_by(2),
                mov(0, 0),
                exit(),
                stx_dw(1, 10, 0),
                mov(0, 0),
                exit(),
            ]),
            (
                Errno::EINVAL,
                "cannot spill pointers to stack into stack frame of the caller".into()
            )
        );
        // A callee may not return a pointer to a stack.
        assert_eq!(
            refused(&[call_by(2), mov(0, 0), exit(), mov_reg(0, 10), exit()]),
            (
                Errno::EINVAL,
                "cannot return stack pointer to the caller".into()
            )
        );
        assert_eq!(
            refused(&[
                mov_reg(1, 10),
                call_by(2),
                mov(0, 0),
                exit(),
                mov_reg(0, 1),
                exit()
            ]),
            (
                Errno::EINVAL,
                "cannot return stack pointer to the caller".into()
            )
        );
        // Each function's stack depth is its own frames', rounded to 8,
        // and a pointer into the caller's counts for the caller.
        assert_eq!(
            stack_depth(&[
                i(0x7a, 10, 0, -8, 0),
                mov_reg(1, 10),
                call_by(2),
                mov(0, 0),
                exit(),
                i(0x72, 1, 0, -40, 0),
                i(0x72, 10, 0, -3, 0),
                mov(0, 0),
                exit(),
            ]),
            vec![40, 8]
        );
    }

    #[test]
    fn the_calls_go_8_frames_and_512_bytes_deep_at_most() {
        // A chain of `n` functions, each calling the next, each with `bytes`
        // of its stack written.
        let chain = |n: usize, bytes: i16| {
            let mut p = Vec::new();
            for f in 0..n {
                if bytes > 0 {
                    p.push(i(0x72, 10, 0, -bytes, 0));
                }
                if f + 1 < n {
                    p.push(call_by(2));
                }
                p.extend([mov(0, 0), exit()]);
            }
            p
        };
        ok(&chain(8, 0));
        assert_eq!(
            refused(&chain(9, 0)),
            (E2BIG, "the call stack of 9 frames is too deep".into())
        );
        // 64 bytes each, rounded to 64: eight frames take 512.
        ok(&chain(8, 64));
        assert_eq!(stack_depth(&chain(2, 100)), vec![104, 104]);
        // max_stack_depth: the deepest chain, each function's rounded to 16.
        let max = |p: &[Insn]| verify(p, Options::default()).unwrap().max_stack_depth;
        assert_eq!(max(&chain(2, 100)), 224);
        assert_eq!(max(&[i(0x72, 10, 0, -3, 0), mov(0, 0), exit()]), 16);
        assert_eq!(
            max(&[
                call_by(3),
                call_by(5),
                mov(0, 0),
                exit(),
                i(0x72, 10, 0, -100, 0),
                mov(0, 0),
                exit(),
                mov(0, 0),
                exit(),
            ]),
            112
        );
        // 104 rounds to 112: five frames take 560.
        assert_eq!(
            refused(&chain(5, 100)),
            (
                EACCES,
                "combined stack size of 5 calls is 560. Too large".into()
            )
        );
        ok(&chain(4, 100));
        // 8 bytes round to 16 for the JIT.
        assert_eq!(
            refused(&[
                i(0x72, 10, 0, -504, 0),
                call_by(2),
                mov(0, 0),
                exit(),
                i(0x72, 10, 0, -1, 0),
                mov(0, 0),
                exit(),
            ]),
            (
                EACCES,
                "combined stack size of 2 calls is 528. Too large".into()
            )
        );
        // A function the walk never enters uses no stack.
        assert_eq!(
            stack_depth(&[
                i(0x72, 10, 0, -512, 0),
                mov(0, 0),
                i(0x15, 0, 0, 1, 0),
                call_by(2),
                mov(0, 0),
                exit(),
                i(0x72, 10, 0, -1, 0),
                mov(0, 0),
                exit(),
            ]),
            vec![512, 0]
        );
    }

    #[test]
    fn the_socket_filter_helpers_check_their_arguments() {
        // The helpers of no arguments.
        ok(&[
            call(5),
            call(7),
            call(8),
            call(14),
            call(15),
            call(42),
            call(125),
            call(160),
            call(208),
            exit(),
        ]);
        ok(&[mov_reg(6, 1), call(46), mov_reg(1, 6), call(47), exit()]);
        ok(&[call(122), mov(1, 0), call(122), exit()]);
        assert_eq!(
            refused(&[mov(1, 0), call(46), exit()]),
            (EACCES, "R1 type=scalar expected=ctx".into())
        );
        assert_eq!(
            refused(&[i(0x07, 1, 0, 0, 8), call(46), exit()]),
            (
                EACCES,
                "dereference of modified ctx ptr R1 off=8 disallowed".into()
            )
        );
        assert_eq!(
            refused(&[call(9), exit()]),
            (
                Errno::EINVAL,
                "program of this type cannot use helper bpf_skb_store_bytes#9".into()
            )
        );
        assert_eq!(
            refused(&[call(212), exit()]),
            (Errno::EINVAL, "invalid func unknown#212".into())
        );
        assert_eq!(
            refused(&[call(-1), exit()]),
            (Errno::EINVAL, "invalid func unknown#-1".into())
        );
        // bpf_skb_load_bytes(ctx, offset, to, len).
        let load = |to: &[Insn], len: Insn| {
            let mut p = vec![mov(2, 0)];
            p.extend_from_slice(to);
            p.extend([len, call(26), ldx(size::DW, 0, 10, -16), exit()]);
            p
        };
        let fp = |off| [mov_reg(3, 10), i(0x07, 3, 0, 0, off)];
        ok(&load(&fp(-16), mov(4, 16)));
        ok(&load(&fp(-512), mov(4, 512)));
        assert_eq!(
            refused(&load(&fp(-8), mov(4, 16))),
            (
                Errno::EINVAL,
                "invalid write to stack R3 off=-8 size=16".into()
            )
        );
        assert_eq!(
            refused(&load(&fp(-520), mov(4, 8))),
            (EACCES, "invalid write to stack R3 off=-520 size=8".into())
        );
        assert_eq!(
            refused(&load(&fp(-16), mov(4, 0))),
            (EACCES, "R4 invalid zero-sized read: u64=[0,0]".into())
        );
        assert_eq!(
            refused(&load(&fp(-16), mov(4, -1))),
            (
                EACCES,
                "R4 min value is negative, either use unsigned or 'var &= const'".into()
            )
        );
        assert_eq!(
            refused(&load(&fp(-16), mov(4, 1 << 29))),
            (
                EACCES,
                "R4 unbounded memory access, use 'var &= const' or 'if (var < const)'".into()
            )
        );
        assert_eq!(
            refused(&load(&fp(-16), mov_reg(4, 10))),
            (EACCES, "R4 type=fp expected=scalar".into())
        );
        assert_eq!(
            refused(&load(&[mov(3, 8)], mov(4, 8))),
            (
                EACCES,
                "R3 type=scalar expected=fp, pkt, pkt_meta, map_key, map_value, mem, ringbuf_mem, buf, trusted_ptr_".into()
            )
        );
        // A map's key may not be the context either.
        let mut p = ld_map(1, 4).to_vec();
        p.extend([mov_reg(2, 1), call(1), mov(0, 0), exit()]);
        let mut q = vec![mov_reg(6, 1)];
        q.extend(p);
        q[3] = mov_reg(2, 6);
        assert_eq!(
            refused(&q),
            (
                EACCES,
                "R2 type=ctx expected=fp, pkt, pkt_meta, map_key, map_value, mem, ringbuf_mem, buf, trusted_ptr_".into()
            )
        );
        // Into a value, which must be writable; the relative form takes a
        // fifth argument.
        let mut p = vec![mov_reg(6, 1), i(0x62, 10, 0, -4, 0)];
        p.extend(ld_map(1, 5));
        p.extend([
            mov_reg(2, 10),
            i(0x07, 2, 0, 0, -4),
            call(1),
            i(0x15, 0, 0, 5, 0),
            mov_reg(3, 0),
            mov_reg(1, 6),
            mov(2, 0),
            mov(4, 8),
            call(26),
            mov(0, 0),
            exit(),
        ]);
        assert_eq!(
            refused(&p),
            (
                EACCES,
                "write into map forbidden, value_size=8 off=0 size=8".into()
            )
        );
        p[2] = i(0x18, 1, 1, 0, 3);
        ok(&p);
        assert_eq!(
            refused(&[
                mov(2, 0),
                mov_reg(3, 10),
                i(0x07, 3, 0, 0, -8),
                mov(4, 8),
                call(68),
                exit(),
            ]),
            (EACCES, "R5 !read_ok".into())
        );
    }
}
