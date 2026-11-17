//! `bpf`, for its maps, as Linux's `kernel/bpf/syscall.c`, `arraymap.c`,
//! `hashtab.c`, `bpf_lru_list.c` and `queue_stack_maps.c` have them:
//! `BPF_MAP_CREATE` of `BPF_MAP_TYPE_ARRAY`, `BPF_MAP_TYPE_HASH`,
//! `BPF_MAP_TYPE_LRU_HASH`, `BPF_MAP_TYPE_QUEUE` and `BPF_MAP_TYPE_STACK`,
//! their elements (`LOOKUP`, `UPDATE`, `DELETE`,
//! `GET_NEXT_KEY`, `LOOKUP_AND_DELETE`), `BPF_MAP_FREEZE`, the batch
//! commands, `BPF_OBJ_GET_INFO_BY_FD`, the map IDs (`BPF_MAP_GET_NEXT_ID`,
//! `BPF_MAP_GET_FD_BY_ID`) and the descriptor's fdinfo, with the checks
//! every command makes first (`bpf_check_uarg_tail_zero`, `CHECK_ATTR`)
//! and the machine's `kernel.unprivileged_bpf_disabled`, which starts at
//! Linux's default 2 and root may write ([`crate::sysctl::Machine`]).
//!
//! The checks and their order follow Linux master, where the x86-64 test
//! machines' kernel (Ubuntu's Linux 7.0) differs too: a hash's key and
//! value limit, and where `BPF_F_RDONLY` with `BPF_F_WRONLY` is refused.
//! Only what the differential tests compare with that kernel keeps its
//! values until it catches up with master: the memory a map takes
//! (fdinfo's `memlock`, and the `ENOMEM` of one larger than the machine's
//! memory), counted with its x86-64 structure sizes; see [`ARRAY_HEADER`]
//! and [`HASH_HEADER`] for where they part from upstream v7.0 and master.
//!
//! `BPF_PROG_LOAD` checks its arguments as Linux does and then refuses every
//! program ([`crate::bpf_prog`]). A command Linux has that is not here
//! (the other program commands, BTF, links, pins and the rest) is
//! `ENOSYS`; one Linux does not have is `EINVAL`, as there. Map
//! types Linux has that are not here are `EINVAL`, as on a kernel built
//! without them (`bpf_map_types` holds no ops for them).
use crate::syscalls::{Context, Outcome};
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr, PAGE_SIZE};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

/// `sizeof(union bpf_attr)` in Linux master.
const ATTR_SIZE: usize = 168;
/// `kernel.unprivileged_bpf_disabled`: Linux's default with
/// `CONFIG_BPF_UNPRIV_DEFAULT_OFF`, which is on by default, and what the
/// machine's starts with ([`crate::sysctl::Machine`]).
pub(crate) const UNPRIVILEGED_DISABLED: i32 = 2;

const CAP_SYS_ADMIN: u64 = 1 << 21;
const CAP_BPF: u64 = 1 << 39;
const E2BIG: Errno = Errno(7);
const ENOMEM: Errno = Errno(12);
const EBUSY: Errno = Errno(16);
const ENOSPC: Errno = Errno(28);
const EBADFD: Errno = Errno(77);
/// The kernel's own `ENOTSUPP`, which reaches user space as it is.
const ENOTSUPP: Errno = Errno(524);
const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;

mod cmd {
    pub const MAP_CREATE: u32 = 0;
    pub const MAP_LOOKUP_ELEM: u32 = 1;
    pub const MAP_UPDATE_ELEM: u32 = 2;
    pub const MAP_DELETE_ELEM: u32 = 3;
    pub const MAP_GET_NEXT_KEY: u32 = 4;
    pub const PROG_LOAD: u32 = 5;
    pub const MAP_GET_NEXT_ID: u32 = 12;
    pub const MAP_GET_FD_BY_ID: u32 = 14;
    pub const OBJ_GET_INFO_BY_FD: u32 = 15;
    pub const MAP_LOOKUP_AND_DELETE_ELEM: u32 = 21;
    pub const MAP_FREEZE: u32 = 22;
    pub const MAP_LOOKUP_BATCH: u32 = 24;
    pub const MAP_LOOKUP_AND_DELETE_BATCH: u32 = 25;
    pub const MAP_UPDATE_BATCH: u32 = 26;
    pub const MAP_DELETE_BATCH: u32 = 27;
    /// `__MAX_BPF_CMD` in Linux master.
    pub const MAX: u32 = 39;
}

const TYPE_HASH: u32 = 1;
const TYPE_ARRAY: u32 = 2;
const TYPE_LRU_HASH: u32 = 9;
const TYPE_QUEUE: u32 = 22;
const TYPE_STACK: u32 = 23;
/// `__MAX_BPF_MAP_TYPE` in Linux master.
const TYPE_MAX: u32 = 39;
/// `BPF_MAP_TYPE_STRUCT_OPS`, the one `btf_vmlinux_value_type_id` is for.
const TYPE_STRUCT_OPS: u32 = 26;
/// The types `map_extra` is for: bloom filters, arenas and resizable hashes.
const TYPES_WITH_EXTRA: [u32; 3] = [30, 33, 37];

mod flag {
    pub const NO_PREALLOC: u32 = 1 << 0;
    pub const NO_COMMON_LRU: u32 = 1 << 1;
    pub const NUMA_NODE: u32 = 1 << 2;
    pub const RDONLY: u32 = 1 << 3;
    pub const WRONLY: u32 = 1 << 4;
    pub const ZERO_SEED: u32 = 1 << 6;
    pub const RDONLY_PROG: u32 = 1 << 7;
    pub const WRONLY_PROG: u32 = 1 << 8;
    pub const MMAPABLE: u32 = 1 << 10;
    pub const PRESERVE_ELEMS: u32 = 1 << 11;
    pub const INNER_MAP: u32 = 1 << 12;
    pub const TOKEN_FD: u32 = 1 << 16;
    pub const ACCESS: u32 = RDONLY | RDONLY_PROG | WRONLY | WRONLY_PROG;
    pub const ARRAY: u32 = NUMA_NODE | MMAPABLE | ACCESS | PRESERVE_ELEMS | INNER_MAP;
    pub const HASH: u32 = NO_PREALLOC | NO_COMMON_LRU | NUMA_NODE | ACCESS | ZERO_SEED;
    pub const QUEUE_STACK: u32 = NUMA_NODE | ACCESS;
}

/// The element flags: `BPF_ANY`, `BPF_NOEXIST`, `BPF_EXIST`, `BPF_F_LOCK`,
/// `BPF_F_CPU` and `BPF_F_ALL_CPUS`.
const NOEXIST: u64 = 1;
const EXIST: u64 = 2;
const F_LOCK: u64 = 4;
const F_CPU: u64 = 8;
const F_ALL_CPUS: u64 = 16;

fn word(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}
fn half(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `bpf_capable`: `CAP_BPF` or `CAP_SYS_ADMIN`.
fn bpf_capable(c: &Context<'_>) -> bool {
    let credentials = &c.process.credentials;
    credentials.capable(CAP_BPF) || credentials.capable(CAP_SYS_ADMIN)
}

/// The elements of a map.
enum Elements {
    /// An array's, by index: those never written are zeros.
    Array(BTreeMap<u32, Vec<u8>>),
    /// A hash's, by key.
    Hash(BTreeMap<Vec<u8>, Vec<u8>>),
    /// An LRU hash's, with the lists that choose which goes when it is
    /// full.
    Lru(Box<Lru>),
    /// A queue's or a stack's, oldest first.
    Queue(std::collections::VecDeque<Vec<u8>>),
}

/// A key and its value.
type Pair = (Vec<u8>, Vec<u8>);

/// A map: Linux's `struct bpf_map`.
pub(crate) struct Map {
    kind: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    flags: u32,
    name: [u8; 16],
    id: u32,
    /// The table that holds the ID, which gives it back when the map goes.
    ids: Arc<Ids>,
    /// `num_possible_cpus()`, which a hash's spare elements count.
    cpus: u64,
    frozen: AtomicBool,
    elements: Mutex<Elements>,
}

/// The machine's maps by ID: Linux's `map_idr`.
#[derive(Default)]
pub(crate) struct Ids {
    table: Mutex<IdTable>,
}

#[derive(Default)]
struct IdTable {
    /// Where the next search starts (`idr_next`).
    next: u32,
    maps: BTreeMap<u32, Weak<Map>>,
}

/// The IDs `bpf_map_alloc_id` hands out: 1 up to `INT_MAX`, less 1.
const LAST_ID: u32 = i32::MAX as u32 - 1;

impl Ids {
    /// `bpf_map_alloc_id`: `idr_alloc_cyclic` from 1 to `INT_MAX`, the
    /// first free ID from where the last search ended, around to 1
    /// (`ENOSPC` with none free); the map made with it is published.
    fn publish(self: &Arc<Self>, make: impl FnOnce(u32) -> Map) -> Result<Arc<Map>, Errno> {
        let mut table = lock(&self.table);
        // Past the last ID the search starts again at 1.
        let start = table.next.max(1);
        let id = (start..=LAST_ID)
            .chain(1..start)
            .find(|id| !table.maps.contains_key(id))
            .ok_or(ENOSPC)?;
        let map = Arc::new(make(id));
        table.maps.insert(id, Arc::downgrade(&map));
        table.next = id + 1;
        Ok(map)
    }

    /// `idr_get_next`: the first ID from `id` on.
    fn next_from(&self, id: u32) -> Option<u32> {
        lock(&self.table).maps.range(id..).next().map(|(&id, _)| id)
    }

    /// `idr_find` and `__bpf_map_inc_not_zero`: the map of `id`, while it
    /// is there.
    fn find(&self, id: u32) -> Option<Arc<Map>> {
        lock(&self.table).maps.get(&id).and_then(Weak::upgrade)
    }
}

impl Drop for Map {
    /// `bpf_map_free_id`, as the last reference goes.
    fn drop(&mut self) {
        let mut table = lock(&self.ids.table);
        if table
            .maps
            .get(&self.id)
            .is_some_and(|map| map.strong_count() == 0)
        {
            table.maps.remove(&self.id);
        }
    }
}

/// The open file: Linux's `bpf-map`.
pub(crate) struct MapFile {
    map: Arc<Map>,
    /// `O_RDONLY`, `O_WRONLY` or `O_RDWR`, from `BPF_F_RDONLY` and
    /// `BPF_F_WRONLY`.
    access: u32,
}

fn of(file: &Arc<dyn FileHandle>) -> Option<&MapFile> {
    file.as_any()?.downcast_ref::<MapFile>()
}

pub(crate) fn sys_bpf(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    Outcome::Return(
        dispatch(c, a[0] as u32, a[1], a[2] as u32).unwrap_or_else(Errno::to_syscall_return),
    )
}

/// Linux's `__sys_bpf`: the size (`bpf_check_uarg_tail_zero`: more than a
/// page, or bytes past the union that are not 0, `E2BIG`), the copy
/// (`EFAULT`), then the command.
fn dispatch(c: &mut Context<'_>, command: u32, at: u64, size: u32) -> Result<u64, Errno> {
    let size = size as usize;
    if size > PAGE_SIZE as usize {
        return Err(E2BIG);
    }
    if size > ATTR_SIZE {
        let mut tail = vec![0; size - ATTR_SIZE];
        c.mem
            .read(GuestAddr(at.wrapping_add(ATTR_SIZE as u64)), &mut tail)
            .map_err(|_| Errno::EFAULT)?;
        if tail.iter().any(|&b| b != 0) {
            return Err(E2BIG);
        }
    }
    let mut attr = [0; ATTR_SIZE];
    let size = size.min(ATTR_SIZE);
    c.mem
        .read(GuestAddr(at), &mut attr[..size])
        .map_err(|_| Errno::EFAULT)?;
    match command {
        cmd::MAP_CREATE => create(c, &attr),
        cmd::MAP_LOOKUP_ELEM => lookup(c, &attr),
        cmd::MAP_UPDATE_ELEM => update(c, &attr),
        cmd::MAP_DELETE_ELEM => delete(c, &attr),
        cmd::MAP_GET_NEXT_KEY => next_key(c, &attr),
        cmd::PROG_LOAD => crate::bpf_prog::load(c, &attr),
        cmd::MAP_LOOKUP_AND_DELETE_ELEM => lookup_and_delete(c, &attr),
        cmd::MAP_FREEZE => freeze(c, &attr),
        cmd::MAP_LOOKUP_BATCH
        | cmd::MAP_LOOKUP_AND_DELETE_BATCH
        | cmd::MAP_UPDATE_BATCH
        | cmd::MAP_DELETE_BATCH => batch(c, &attr, at, command),
        cmd::MAP_GET_NEXT_ID => next_id(c, &attr, at),
        cmd::MAP_GET_FD_BY_ID => fd_by_id(c, &attr),
        cmd::OBJ_GET_INFO_BY_FD => info(c, &attr, at),
        command if command < cmd::MAX => Err(Errno::ENOSYS),
        _ => Err(Errno::EINVAL),
    }
}

/// `CHECK_ATTR`: the bytes past the command's last field are 0.
pub(crate) fn check_attr(attr: &[u8], end: usize) -> Result<(), Errno> {
    if attr[end..].iter().any(|&b| b != 0) {
        Err(Errno::EINVAL)
    } else {
        Ok(())
    }
}

/// `bpf_obj_name_cpy`: letters, digits, `_` and `.`, ending in a NUL
/// within the field (`EINVAL`).
fn name(field: &[u8]) -> Result<[u8; 16], Errno> {
    let mut name = [0; 16];
    let end = field.iter().position(|&b| b == 0).ok_or(Errno::EINVAL)?;
    if !field[..end]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
    {
        return Err(Errno::EINVAL);
    }
    name[..end].copy_from_slice(&field[..end]);
    Ok(name)
}

/// What a descriptor that must be one kind of BPF object is, for one that
/// is not: `EBADF` for no descriptor, `EINVAL` for another file
/// (`bpf_token_get_from_fd`, `btf_get_by_fd`).
fn not_an_object(c: &Context<'_>, fd: u32) -> Errno {
    match c.files.descriptor(u64::from(fd)) {
        Ok(_) => Errno::EINVAL,
        Err(e) => e,
    }
}

/// `BPF_MAP_CREATE`, in the order of Linux's `map_create_alloc` and
/// `map_create`.
fn create(c: &mut Context<'_>, attr: &[u8]) -> Result<u64, Errno> {
    let kind = half(attr, 0);
    let key_size = half(attr, 4);
    let value_size = half(attr, 8);
    let max_entries = half(attr, 12);
    let mut flags = half(attr, 16);
    let numa_node = half(attr, 24);
    let map_ifindex = half(attr, 44);
    let btf_fd = half(attr, 48);
    let btf_key = half(attr, 52);
    let btf_value = half(attr, 56);
    let btf_vmlinux_value = half(attr, 60);
    let map_extra = word(attr, 64);
    let token_fd = half(attr, 76);
    let excl_hash = word(attr, 80);
    let excl_hash_size = half(attr, 88);
    // BPF_MAP_CREATE_LAST_FIELD is excl_prog_hash_size.
    check_attr(attr, 92)?;
    let token = flags & flag::TOKEN_FD != 0;
    flags &= !flag::TOKEN_FD;
    if btf_vmlinux_value != 0 {
        if kind != TYPE_STRUCT_OPS || btf_key != 0 || btf_value != 0 {
            return Err(Errno::EINVAL);
        }
    } else if btf_key != 0 && btf_value == 0 {
        return Err(Errno::EINVAL);
    }
    if !TYPES_WITH_EXTRA.contains(&kind) && map_extra != 0 {
        return Err(Errno::EINVAL);
    }
    // One NUMA node, 0.
    if flags & flag::NUMA_NODE != 0 && numa_node != 0 {
        return Err(Errno::EINVAL);
    }
    if kind >= TYPE_MAX {
        return Err(Errno::EINVAL);
    }
    // The map type's `map_alloc_check`.
    let access_ok =
        flags & (flag::RDONLY_PROG | flag::WRONLY_PROG) != flag::RDONLY_PROG | flag::WRONLY_PROG;
    match kind {
        TYPE_ARRAY => {
            if max_entries == 0
                || key_size != 4
                || value_size == 0
                || flags & !flag::ARRAY != 0
                || !access_ok
            {
                return Err(Errno::EINVAL);
            }
            if flags & flag::PRESERVE_ELEMS != 0 {
                return Err(Errno::EINVAL);
            }
            if value_size > i32::MAX as u32 {
                return Err(E2BIG);
            }
        }
        TYPE_HASH | TYPE_LRU_HASH => {
            let lru = kind == TYPE_LRU_HASH;
            if flags & flag::ZERO_SEED != 0 && !c.process.credentials.capable(CAP_SYS_ADMIN) {
                return Err(Errno::EPERM);
            }
            if flags & !flag::HASH != 0 || !access_ok {
                return Err(Errno::EINVAL);
            }
            // BPF_F_NO_COMMON_LRU is for LRU maps only.
            if !lru && flags & flag::NO_COMMON_LRU != 0 {
                return Err(Errno::EINVAL);
            }
            // An LRU hash is always preallocated.
            if lru && flags & flag::NO_PREALLOC != 0 {
                return Err(ENOTSUPP);
            }
            // Lists of their own for each CPU are on no one NUMA node.
            if flags & flag::NO_COMMON_LRU != 0 && flags & flag::NUMA_NODE != 0 {
                return Err(Errno::EINVAL);
            }
            if max_entries == 0 || key_size == 0 || value_size == 0 {
                return Err(Errno::EINVAL);
            }
            // KMALLOC_MAX_SIZE, 4 MiB with SLUB on x86-64, less the LRU
            // element's header (64 bytes), as Linux master has it; the test
            // machines' Linux 7.0 takes 16 bytes more (less 48, the size of
            // its `struct htab_elem`).
            if u64::from(key_size) + u64::from(value_size) >= (1 << 22) - 64 {
                return Err(E2BIG);
            }
        }
        // queue_stack_map_alloc_check, as Linux master has it, with its
        // check that the elements fit in 32 bits (7.0 does not check it).
        TYPE_QUEUE | TYPE_STACK => {
            if max_entries == 0
                || key_size != 0
                || value_size == 0
                || flags & !flag::QUEUE_STACK != 0
                || !access_ok
            {
                return Err(Errno::EINVAL);
            }
            if value_size > 1 << 22 || max_entries >= u32::MAX / value_size {
                return Err(E2BIG);
            }
        }
        // No ops for it here.
        _ => return Err(Errno::EINVAL),
    }
    // An offloaded map needs a device that offloads it: none does.
    if map_ifindex != 0 {
        return Err(Errno::EINVAL);
    }
    if token {
        // No file is a BPF token.
        return Err(not_an_object(c, token_fd));
    }
    if c.processes.sysctls.unprivileged_bpf_disabled() != 0 && !bpf_capable(c) {
        return Err(Errno::EPERM);
    }
    // The privileged map types, which need CAP_BPF even where any user
    // may make maps.
    if matches!(kind, TYPE_LRU_HASH | TYPE_QUEUE | TYPE_STACK) && !bpf_capable(c) {
        return Err(Errno::EPERM);
    }
    // array_map_alloc: without `bpf_bypass_spec_v1` (CAP_PERFMON) the
    // array is rounded up to a power of two, which may overflow.
    let bypass_spec = {
        let credentials = &c.process.credentials;
        credentials.capable(1 << 38) || credentials.capable(CAP_SYS_ADMIN)
    };
    if kind == TYPE_ARRAY && !bypass_spec && max_entries.checked_next_power_of_two().is_none() {
        return Err(E2BIG);
    }
    let cpus = c.host.cpu_count().clamp(1, 8192) as u64;
    let max_entries = entries(kind, max_entries, flags, cpus);
    allocate(
        kind,
        value_size,
        key_size,
        max_entries,
        flags,
        bypass_spec,
        cpus,
    )?;
    let name = name(&attr[28..44])?;
    if btf_key != 0 || btf_value != 0 || btf_vmlinux_value != 0 {
        // No file is BTF.
        return Err(not_an_object(c, btf_fd));
    }
    if excl_hash != 0 {
        if excl_hash_size != 32 {
            return Err(Errno::EINVAL);
        }
        let mut hash = [0; 32];
        c.mem
            .read(GuestAddr(excl_hash), &mut hash)
            .map_err(|_| Errno::EFAULT)?;
    } else if excl_hash_size != 0 {
        return Err(Errno::EINVAL);
    }
    // As Linux master's `map_create`, once the map is made; the test
    // machines' Linux 7.0 refuses both flags before the NUMA node and the
    // type.
    let access = file_access(flags)?;
    let ids = &c.processes.bpf_maps;
    let map = ids.publish(|id| Map {
        kind,
        key_size,
        value_size,
        max_entries,
        flags,
        name,
        id,
        ids: Arc::clone(ids),
        cpus,
        frozen: AtomicBool::new(false),
        elements: Mutex::new(elements(kind, max_entries, flags, cpus)),
    })?;
    new_fd(c, map, access)
}

/// A new map's elements: none.
fn elements(kind: u32, max_entries: u32, flags: u32, cpus: u64) -> Elements {
    match kind {
        TYPE_ARRAY => Elements::Array(BTreeMap::new()),
        TYPE_QUEUE | TYPE_STACK => Elements::Queue(std::collections::VecDeque::new()),
        TYPE_LRU_HASH => Elements::Lru(Box::new(Lru::new(
            max_entries,
            cpus,
            flags & flag::NO_COMMON_LRU != 0,
        ))),
        _ => Elements::Hash(BTreeMap::new()),
    }
}

/// The entries a map has: an LRU hash with lists for each CPU gives each
/// as many, rounded up to a multiple of the CPUs (down where that would
/// not fit), as `htab_map_alloc` makes it.
fn entries(kind: u32, max_entries: u32, flags: u32, cpus: u64) -> u32 {
    if kind != TYPE_LRU_HASH || flags & flag::NO_COMMON_LRU == 0 {
        return max_entries;
    }
    let cpus = cpus as u32;
    match max_entries.checked_next_multiple_of(cpus) {
        Some(up) => up,
        None => max_entries - max_entries % cpus,
    }
}

/// `bpf_map_new_fd`: a descriptor of the map, close-on-exec.
fn new_fd(c: &mut Context<'_>, map: Arc<Map>, access: u32) -> Result<u64, Errno> {
    c.files
        .install(Arc::new(MapFile { map, access }), true, c.group.nofile())
        .map(u64::from)
}

/// `sizeof(struct bpf_array)` before the values on x86-64, 312 bytes on the
/// test machines' kernel (`Ubuntu-azure-7.0.0-1019.20`, Ubuntu-7.0.0-44.44
/// too): Ubuntu carries `u32 excl` after `struct bpf_map`'s `sha`, from
/// Linux 7.2's 0fb6c9ed6493 ("libbpf: Reject non-exclusive metadata maps
/// in the signed loader"), which Linux 7.3 removed again (a2d784869a0f).
/// Upstream v7.0 and its stable releases have 304. Linux master has 312
/// as well, by another field: `unsigned long user` (a04286f6d828, "bpf:
/// Recognize pointers to functions in read-only maps", in 7.4-rc1).
const ARRAY_HEADER: u64 = 312;
/// `sizeof(struct bpf_htab)`, `sizeof(struct htab_elem)` before the key,
/// and `sizeof(struct bucket)` on x86-64, as Linux 7.0 has them (the test
/// machines' 8 more bytes of `struct bpf_map` vanish in `bpf_htab`'s
/// 64-byte alignment). Linux master's differ: its `bpf_htab` is 832 bytes
/// without the per-CPU counter (1cd28b5354ab) and its elements smaller
/// (26c9dc906692, 0d0421c96f67), so these stay the test machines'.
const HASH_HEADER: u64 = 896;
const HASH_ELEMENT: u64 = 48;
const BUCKET: u64 = 16;
/// `sizeof(struct llist_node)` and `sizeof(struct htab_elem *)`.
const POINTER: u64 = 8;
/// `totalram_pages()`: the memory `sysinfo` reports, in pages.
const RAM_PAGES: u64 = crate::syscalls::SYSINFO_RAM / PAGE_SIZE;

/// `sizeof(struct bpf_queue_stack)` on x86-64, on the test machines'
/// kernel: their 296-byte `struct bpf_map` (as [`ARRAY_HEADER`] says), its
/// lock, `head`, `tail` and `size`. Linux master's is the same size.
const QUEUE_HEADER: u64 = 312;

/// A queue's or stack's header and its `max_entries + 1` slots, as
/// `queue_stack_map_alloc` makes them and `queue_stack_map_mem_usage`
/// counts them.
fn queue_size(max_entries: u32, value_size: u32) -> u64 {
    QUEUE_HEADER + (u64::from(max_entries) + 1) * u64::from(value_size)
}

/// `bpf_map_area_alloc`: `vmalloc` takes no more pages than the machine
/// has (`ENOMEM`). The memory is not taken here until it is written.
fn area(size: u64) -> Result<(), Errno> {
    if size / PAGE_SIZE > RAM_PAGES {
        Err(ENOMEM)
    } else {
        Ok(())
    }
}

/// `round_up(size, 8)`, the room a key or value takes.
fn round8(size: u32) -> u64 {
    u64::from(size).next_multiple_of(8)
}

/// A hash's buckets: `roundup_pow_of_two(max_entries)`.
fn buckets(max_entries: u32) -> u64 {
    u64::from(max_entries).next_power_of_two()
}

/// `htab->elem_size`.
fn hash_element(key_size: u32, value_size: u32) -> u64 {
    HASH_ELEMENT + round8(key_size) + round8(value_size)
}

/// An array's header and values, as `array_map_alloc` sizes them and
/// `array_map_mem_usage` counts them: a mappable one page-aligned.
fn array_size(entries: u64, value_size: u32, flags: u32) -> u64 {
    let values = entries * round8(value_size);
    if flags & flag::MMAPABLE != 0 {
        ARRAY_HEADER.next_multiple_of(PAGE_SIZE) + values.next_multiple_of(PAGE_SIZE)
    } else {
        ARRAY_HEADER + values
    }
}

/// The map type's `map_alloc`, for what it takes from the machine's memory:
/// an array all its values (rounded up to a power of two of them without
/// `bpf_bypass_spec_v1`), a hash its buckets (more than 2^31 entries, or
/// buckets past `U32_MAX` bytes, `E2BIG`) and, preallocated, every element
/// and one spare a CPU (an LRU hash none).
fn allocate(
    kind: u32,
    value_size: u32,
    key_size: u32,
    max_entries: u32,
    flags: u32,
    bypass_spec: bool,
    cpus: u64,
) -> Result<(), Errno> {
    if matches!(kind, TYPE_QUEUE | TYPE_STACK) {
        return area(queue_size(max_entries, value_size));
    }
    if kind == TYPE_ARRAY {
        let entries = if bypass_spec {
            u64::from(max_entries)
        } else {
            buckets(max_entries)
        };
        return area(array_size(entries, value_size, flags));
    }
    if max_entries > 1 << 31 {
        return Err(E2BIG);
    }
    let buckets = buckets(max_entries);
    if buckets > u64::from(u32::MAX) / BUCKET {
        return Err(E2BIG);
    }
    area(buckets * BUCKET)?;
    if flags & flag::NO_PREALLOC == 0 {
        // An LRU hash has no spare elements.
        let spares = if kind == TYPE_LRU_HASH { 0 } else { cpus };
        area(hash_element(key_size, value_size) * (u64::from(max_entries) + spares))?;
    }
    Ok(())
}

/// `BPF_MAP_GET_NEXT_ID`: the first map ID past `start_id`
/// (`bpf_obj_get_next_id`), for `CAP_SYS_ADMIN` alone.
fn next_id(c: &mut Context<'_>, attr: &[u8], at: u64) -> Result<u64, Errno> {
    let start = half(attr, 0);
    // BPF_OBJ_GET_NEXT_ID_LAST_FIELD is next_id.
    check_attr(attr, 8)?;
    if start >= i32::MAX as u32 {
        return Err(Errno::EINVAL);
    }
    if !c.process.credentials.capable(CAP_SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let next = c
        .processes
        .bpf_maps
        .next_from(start + 1)
        .ok_or(Errno::ENOENT)?;
    write(c, at.wrapping_add(4), &next.to_le_bytes())?;
    Ok(0)
}

/// `BPF_MAP_GET_FD_BY_ID`: a new descriptor of the map with `map_id`, open
/// as `open_flags` asks (`bpf_map_get_fd_by_id`), for `CAP_SYS_ADMIN`
/// alone.
fn fd_by_id(c: &mut Context<'_>, attr: &[u8]) -> Result<u64, Errno> {
    let (id, open_flags) = (half(attr, 0), half(attr, 8));
    // BPF_MAP_GET_FD_BY_ID_LAST_FIELD is open_flags.
    check_attr(attr, 12)?;
    if open_flags & !(flag::RDONLY | flag::WRONLY) != 0 {
        return Err(Errno::EINVAL);
    }
    if !c.process.credentials.capable(CAP_SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let access = file_access(open_flags)?;
    let map = c.processes.bpf_maps.find(id).ok_or(Errno::ENOENT)?;
    new_fd(c, map, access)
}

/// `bpf_get_file_flag`: the access `BPF_F_RDONLY` and `BPF_F_WRONLY` ask
/// for, not both (`EINVAL`).
fn file_access(flags: u32) -> Result<u32, Errno> {
    match (flags & flag::RDONLY != 0, flags & flag::WRONLY != 0) {
        (true, true) => Err(Errno::EINVAL),
        (true, false) => Ok(O_RDONLY),
        (false, true) => Ok(O_WRONLY),
        (false, false) => Ok(O_RDWR),
    }
}

/// `__bpf_map_get`: `EBADF` for no descriptor, `EINVAL` for one that is
/// no map; with whether it may be read and written (`map_get_sys_perms`:
/// a frozen map is not written through any).
fn map_of(c: &Context<'_>, fd: u32) -> Result<(Arc<Map>, bool, bool), Errno> {
    let file = c.files.descriptor(u64::from(fd))?.file;
    let map_file = of(&file).ok_or(Errno::EINVAL)?;
    let map = Arc::clone(&map_file.map);
    let readable = map_file.access != O_WRONLY;
    let writable = map_file.access != O_RDONLY && !map.frozen.load(Ordering::SeqCst);
    Ok((map, readable, writable))
}

/// `bpf_map_check_op_flags`: flags in the low half past `allowed`, a lock
/// no map here has, a high half without `BPF_F_CPU`, and the CPU flags of
/// a map that is not per CPU are `EINVAL`.
fn check_op_flags(flags: u64, allowed: u64) -> Result<(), Errno> {
    if flags as u32 as u64 & !allowed != 0
        || flags & F_LOCK != 0
        || flags & F_CPU == 0 && flags >> 32 != 0
        || flags & (F_CPU | F_ALL_CPUS) != 0
    {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// The address of element `i` of `size` bytes from `base`, wrapping as a
/// guest's pointer may: an address that wraps is not mapped, so its copy is
/// `EFAULT`.
fn element(base: u64, i: u64, size: u64) -> u64 {
    base.wrapping_add(i.wrapping_mul(size))
}

/// `len` bytes of the caller's memory at `at`, `EFAULT` for any that cannot
/// be read; the range is checked before anything is allocated for it, so
/// that a large size with no memory behind it costs nothing.
fn read_bytes(c: &Context<'_>, at: u64, len: u32) -> Result<Vec<u8>, Errno> {
    let len = len as usize;
    c.mem
        .check_read(GuestAddr(at), len)
        .map_err(|_| Errno::EFAULT)?;
    let mut bytes = vec![0; len];
    c.mem
        .read(GuestAddr(at), &mut bytes)
        .map_err(|_| Errno::EFAULT)?;
    Ok(bytes)
}

/// `__bpf_copy_key`'s copy of a key (`EFAULT` for one that cannot be
/// read); a caller that takes no key for a null pointer checks for it. A
/// map without keys (a queue's or stack's) takes only a null one
/// (`EINVAL`).
fn read_key(c: &Context<'_>, map: &Map, at: u64) -> Result<Vec<u8>, Errno> {
    if map.key_size == 0 {
        return if at == 0 {
            Ok(Vec::new())
        } else {
            Err(Errno::EINVAL)
        };
    }
    read_bytes(c, at, map.key_size)
}

fn read_value(c: &Context<'_>, map: &Map, at: u64) -> Result<Vec<u8>, Errno> {
    read_bytes(c, at, map.value_size)
}

fn index(key: &[u8]) -> u32 {
    u32::from_le_bytes(key[..4].try_into().unwrap_or([0; 4]))
}

impl Map {
    fn elements(&self) -> MutexGuard<'_, Elements> {
        lock(&self.elements)
    }
    /// A hash or an LRU hash, which share their batch and delete commands.
    fn hashed(&self) -> bool {
        matches!(self.kind, TYPE_HASH | TYPE_LRU_HASH)
    }
    /// Whether it holds `key`: `ENOENT` for an index past an array's end
    /// and a key a hash does not hold.
    fn holds(&self, key: &[u8]) -> Result<(), Errno> {
        let held = match &*self.elements() {
            Elements::Array(_) => index(key) < self.max_entries,
            Elements::Hash(values) => values.contains_key(key),
            Elements::Lru(lru) => lru.table.contains_key(key),
            Elements::Queue(values) => !values.is_empty(),
        };
        if held { Ok(()) } else { Err(Errno::ENOENT) }
    }
    /// `map_lookup_elem` of the map's type: `ENOENT` for none.
    fn get(&self, key: &[u8]) -> Result<Vec<u8>, Errno> {
        match &*self.elements() {
            Elements::Array(values) => {
                let i = index(key);
                if i >= self.max_entries {
                    return Err(Errno::ENOENT);
                }
                Ok(values
                    .get(&i)
                    .cloned()
                    .unwrap_or_else(|| vec![0; self.value_size as usize]))
            }
            Elements::Hash(values) => values.get(key).cloned().ok_or(Errno::ENOENT),
            // As `htab_lru_map_lookup_elem_sys`, which leaves the
            // reference alone.
            Elements::Lru(lru) => lru.get(key).cloned().ok_or(Errno::ENOENT),
            // `map_peek_elem`: a queue's oldest, a stack's newest.
            Elements::Queue(values) => if self.kind == TYPE_QUEUE {
                values.front()
            } else {
                values.back()
            }
            .cloned()
            .ok_or(Errno::ENOENT),
        }
    }
    /// `map_pop_elem`: a queue's oldest or a stack's newest, taken out.
    fn pop(&self) -> Result<Vec<u8>, Errno> {
        let mut elements = self.elements();
        let Elements::Queue(values) = &mut *elements else {
            return Err(ENOTSUPP);
        };
        if self.kind == TYPE_QUEUE {
            values.pop_front()
        } else {
            values.pop_back()
        }
        .ok_or(Errno::ENOENT)
    }
    /// `map_update_elem` of the map's type.
    fn set(&self, key: &[u8], value: Vec<u8>, flags: u64) -> Result<(), Errno> {
        let mode = flags & !F_LOCK;
        if mode > EXIST {
            return Err(Errno::EINVAL);
        }
        match &mut *self.elements() {
            Elements::Array(values) => {
                let i = index(key);
                if i >= self.max_entries {
                    return Err(E2BIG);
                }
                if mode == NOEXIST {
                    return Err(Errno::EEXIST);
                }
                values.insert(i, value);
            }
            Elements::Hash(values) => {
                let present = values.contains_key(key);
                if present && mode == NOEXIST {
                    return Err(Errno::EEXIST);
                }
                if !present && mode == EXIST {
                    return Err(Errno::ENOENT);
                }
                if !present && values.len() >= self.max_entries as usize {
                    return Err(E2BIG);
                }
                values.insert(key.to_vec(), value);
            }
            Elements::Lru(lru) => lru.update(key, value, mode)?,
            // `queue_stack_map_push_elem`: `BPF_EXIST` makes room in a full
            // one by giving up the oldest; `BPF_NOEXIST` is not for it.
            Elements::Queue(values) => {
                if mode == NOEXIST {
                    return Err(Errno::EINVAL);
                }
                if values.len() >= self.max_entries as usize {
                    if mode != EXIST {
                        return Err(E2BIG);
                    }
                    values.pop_front();
                }
                values.push_back(value);
            }
        }
        Ok(())
    }
    /// `map_delete_elem`: an array's elements cannot be (`EINVAL`).
    fn remove(&self, key: &[u8]) -> Result<Vec<u8>, Errno> {
        match &mut *self.elements() {
            Elements::Array(_) => Err(Errno::EINVAL),
            Elements::Hash(values) => values.remove(key).ok_or(Errno::ENOENT),
            Elements::Lru(lru) => lru.delete(key),
            Elements::Queue(_) => Err(Errno::EINVAL),
        }
    }
    /// `map_get_next_key`: the first key after `key`, or the first of all
    /// for none, or (in a hash) for a key it does not hold; `ENOENT` past
    /// the last.
    fn next(&self, key: Option<&[u8]>) -> Result<Vec<u8>, Errno> {
        match &*self.elements() {
            Elements::Array(_) => {
                let i = key.map_or(u32::MAX, index);
                if i >= self.max_entries {
                    return Ok(0u32.to_le_bytes().to_vec());
                }
                if i == self.max_entries - 1 {
                    return Err(Errno::ENOENT);
                }
                Ok((i + 1).to_le_bytes().to_vec())
            }
            Elements::Lru(lru) => next_in(&lru.table, key),
            Elements::Hash(values) => next_in(values, key),
            Elements::Queue(_) => Err(Errno::EINVAL),
        }
    }
    /// The keys and values it holds, by key: a hash's and an LRU hash's.
    #[cfg(test)]
    fn held(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        match &*self.elements() {
            Elements::Hash(values) => values.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            Elements::Lru(lru) => lru
                .table
                .iter()
                .map(|(k, &i)| (k.clone(), lru.values[i].clone()))
                .collect(),
            Elements::Array(_) | Elements::Queue(_) => Vec::new(),
        }
    }
    /// The elements from the `start`th, up to `max` of them, by key, taken
    /// out with `delete`, and how many are left: all under one lock, as
    /// Linux deletes them under the bucket's, so that no other thread takes
    /// one between.
    fn take(&self, start: usize, max: usize, delete: bool) -> (Vec<Pair>, usize) {
        let mut elements = self.elements();
        let chosen: Vec<Vec<u8>> = match &*elements {
            Elements::Hash(values) => values.keys().skip(start).take(max).cloned().collect(),
            Elements::Lru(lru) => lru.table.keys().skip(start).take(max).cloned().collect(),
            Elements::Array(_) | Elements::Queue(_) => Vec::new(),
        };
        let mut taken = Vec::with_capacity(chosen.len());
        for key in chosen {
            let value = match &mut *elements {
                Elements::Hash(values) if delete => values.remove(&key),
                Elements::Hash(values) => values.get(&key).cloned(),
                Elements::Lru(lru) if delete => lru.delete(&key).ok(),
                Elements::Lru(lru) => lru.get(&key).cloned(),
                Elements::Array(_) | Elements::Queue(_) => None,
            };
            if let Some(value) = value {
                taken.push((key, value));
            }
        }
        let left = match &*elements {
            Elements::Hash(values) => values.len(),
            Elements::Lru(lru) => lru.table.len(),
            Elements::Array(_) | Elements::Queue(_) => 0,
        };
        (taken, left)
    }
    /// How many keys it holds.
    fn len(&self) -> usize {
        match &*self.elements() {
            Elements::Hash(values) => values.len(),
            Elements::Lru(lru) => lru.table.len(),
            Elements::Array(_) | Elements::Queue(_) => 0,
        }
    }
    /// The memory it takes, as `bpf_map_memory_usage` counts it: an array's
    /// header and values, a hash's header, buckets and elements, all of
    /// them and one spare a CPU with a pointer to it when preallocated (an
    /// LRU hash's all of them alone), or those it holds with a list node
    /// each when not.
    fn memory(&self) -> u64 {
        if self.kind == TYPE_ARRAY {
            return array_size(u64::from(self.max_entries), self.value_size, self.flags);
        }
        if matches!(self.kind, TYPE_QUEUE | TYPE_STACK) {
            return queue_size(self.max_entries, self.value_size);
        }
        let element = hash_element(self.key_size, self.value_size);
        let table = HASH_HEADER + BUCKET * buckets(self.max_entries);
        if self.kind == TYPE_LRU_HASH {
            table + element * u64::from(self.max_entries)
        } else if self.flags & flag::NO_PREALLOC == 0 {
            table + element * (u64::from(self.max_entries) + self.cpus) + POINTER * self.cpus
        } else {
            table + (element + POINTER) * self.len() as u64
        }
    }
}

/// `htab_map_get_next_key`, in the order of the keys: the first after
/// `key`, or the first of all for none or a key it does not hold; `ENOENT`
/// past the last.
fn next_in<V>(table: &BTreeMap<Vec<u8>, V>, key: Option<&[u8]>) -> Result<Vec<u8>, Errno> {
    let next = match key.filter(|key| table.contains_key(*key)) {
        Some(key) => table
            .range::<[u8], _>((std::ops::Bound::Excluded(key), std::ops::Bound::Unbounded))
            .next(),
        None => table.iter().next(),
    };
    next.map(|(key, _)| key.clone()).ok_or(Errno::ENOENT)
}

fn write(c: &Context<'_>, at: u64, bytes: &[u8]) -> Result<(), Errno> {
    c.mem.write(GuestAddr(at), bytes).map_err(|_| Errno::EFAULT)
}

/// `BPF_MAP_LOOKUP_ELEM`, as Linux's `map_lookup_elem`.
fn lookup(c: &mut Context<'_>, attr: &[u8]) -> Result<u64, Errno> {
    check_attr(attr, 32)?;
    let (map, readable, _) = map_of(c, half(attr, 0))?;
    if !readable {
        return Err(Errno::EPERM);
    }
    check_op_flags(word(attr, 24), F_LOCK | F_CPU)?;
    let key = read_key(c, &map, word(attr, 8))?;
    copy_value(c, &map, &key, word(attr, 16))?;
    Ok(0)
}

/// Writes the value `key` holds at `at`: `ENOENT` for none, then `EFAULT`
/// where it cannot go, which is checked before the value is made, so that a
/// large array element that was never written costs nothing to refuse.
fn copy_value(c: &Context<'_>, map: &Map, key: &[u8], at: u64) -> Result<(), Errno> {
    map.holds(key)?;
    c.mem
        .check_write(GuestAddr(at), map.value_size as usize)
        .map_err(|_| Errno::EFAULT)?;
    let value = map.get(key)?;
    write(c, at, &value)
}

/// `BPF_MAP_UPDATE_ELEM`, as Linux's `map_update_elem`.
fn update(c: &mut Context<'_>, attr: &[u8]) -> Result<u64, Errno> {
    check_attr(attr, 32)?;
    let (map, _, writable) = map_of(c, half(attr, 0))?;
    if !writable {
        return Err(Errno::EPERM);
    }
    let flags = word(attr, 24);
    check_op_flags(flags, !0)?;
    let key = read_key(c, &map, word(attr, 8))?;
    let value = read_value(c, &map, word(attr, 16))?;
    map.set(&key, value, flags)?;
    Ok(0)
}

/// `BPF_MAP_DELETE_ELEM`, as Linux's `map_delete_elem`.
fn delete(c: &mut Context<'_>, attr: &[u8]) -> Result<u64, Errno> {
    check_attr(attr, 16)?;
    let (map, _, writable) = map_of(c, half(attr, 0))?;
    if !writable {
        return Err(Errno::EPERM);
    }
    let key = read_key(c, &map, word(attr, 8))?;
    map.remove(&key).map(|_| 0)
}

/// `BPF_MAP_GET_NEXT_KEY`, as Linux's `map_get_next_key`.
fn next_key(c: &mut Context<'_>, attr: &[u8]) -> Result<u64, Errno> {
    check_attr(attr, 24)?;
    let (map, readable, _) = map_of(c, half(attr, 0))?;
    if !readable {
        return Err(Errno::EPERM);
    }
    let key = match word(attr, 8) {
        0 => None,
        at => Some(read_key(c, &map, at)?),
    };
    let next = map.next(key.as_deref())?;
    write(c, word(attr, 16), &next)?;
    Ok(0)
}

/// `BPF_MAP_LOOKUP_AND_DELETE_ELEM`, as Linux's
/// `map_lookup_and_delete_elem`: an array has no such operation
/// (`ENOTSUPP`).
fn lookup_and_delete(c: &mut Context<'_>, attr: &[u8]) -> Result<u64, Errno> {
    check_attr(attr, 32)?;
    let flags = word(attr, 24);
    if flags & !F_LOCK != 0 {
        return Err(Errno::EINVAL);
    }
    let (map, readable, writable) = map_of(c, half(attr, 0))?;
    if !readable || !writable {
        return Err(Errno::EPERM);
    }
    if flags & F_LOCK != 0 {
        return Err(Errno::EINVAL);
    }
    let key = read_key(c, &map, word(attr, 8))?;
    let value = if matches!(map.kind, TYPE_QUEUE | TYPE_STACK) {
        map.pop()?
    } else if map.hashed() {
        map.remove(&key)?
    } else {
        return Err(ENOTSUPP);
    };
    write(c, word(attr, 16), &value)?;
    Ok(0)
}

/// `BPF_MAP_FREEZE`, as Linux's `map_freeze`: a frozen map is not written
/// through any descriptor, so a second freeze is `EPERM`; `EBUSY` is for
/// one that finds it frozen after that check.
fn freeze(c: &mut Context<'_>, attr: &[u8]) -> Result<u64, Errno> {
    check_attr(attr, 4)?;
    let (map, _, writable) = map_of(c, half(attr, 0))?;
    if !writable {
        return Err(Errno::EPERM);
    }
    if map.frozen.swap(true, Ordering::SeqCst) {
        return Err(EBUSY);
    }
    Ok(0)
}

/// The batch commands, as Linux's `bpf_map_do_batch`: the access they
/// need, then the map type's operation (`ENOTSUPP` for one it lacks: an
/// array deletes nothing).
fn batch(c: &mut Context<'_>, attr: &[u8], at: u64, command: u32) -> Result<u64, Errno> {
    check_attr(attr, 56)?;
    let reads = matches!(
        command,
        cmd::MAP_LOOKUP_BATCH | cmd::MAP_LOOKUP_AND_DELETE_BATCH
    );
    let writes = command != cmd::MAP_LOOKUP_BATCH;
    let (map, readable, writable) = map_of(c, half(attr, 36))?;
    if reads && !readable || writes && !writable {
        return Err(Errno::EPERM);
    }
    let hash = map.hashed();
    // A queue and a stack have no batch operations.
    if matches!(map.kind, TYPE_QUEUE | TYPE_STACK) {
        return Err(ENOTSUPP);
    }
    match command {
        cmd::MAP_LOOKUP_BATCH if hash => hash_lookup_batch(c, &map, attr, at, false),
        cmd::MAP_LOOKUP_AND_DELETE_BATCH if hash => hash_lookup_batch(c, &map, attr, at, true),
        cmd::MAP_LOOKUP_BATCH => array_lookup_batch(c, &map, attr, at),
        cmd::MAP_UPDATE_BATCH => update_batch(c, &map, attr, at),
        cmd::MAP_DELETE_BATCH if hash => delete_batch(c, &map, attr, at),
        _ => Err(ENOTSUPP),
    }
}

/// Where a batch's count is: what it did goes back there.
const COUNT: u64 = 32;

fn put_count(c: &Context<'_>, at: u64, count: u32) -> Result<(), Errno> {
    write(c, at.wrapping_add(COUNT), &count.to_le_bytes())
}

/// `generic_map_update_batch`.
fn update_batch(c: &Context<'_>, map: &Map, attr: &[u8], at: u64) -> Result<u64, Errno> {
    let flags = word(attr, 40);
    check_op_flags(flags, F_LOCK | F_CPU | F_ALL_CPUS)?;
    let max = half(attr, 32);
    if max == 0 {
        return Ok(0);
    }
    put_count(c, at, 0)?;
    let (keys, values) = (word(attr, 16), word(attr, 24));
    let (key_size, value_size) = (u64::from(map.key_size), u64::from(map.value_size));
    let mut done = 0;
    let mut result = Ok(0);
    while done < max {
        let i = u64::from(done);
        let step = read_key(c, map, element(keys, i, key_size))
            .and_then(|key| Ok((key, read_value(c, map, element(values, i, value_size))?)))
            .and_then(|(key, value)| map.set(&key, value, flags));
        if let Err(e) = step {
            result = Err(e);
            break;
        }
        done += 1;
    }
    put_count(c, at, done)?;
    result
}

/// `generic_map_delete_batch`.
fn delete_batch(c: &Context<'_>, map: &Map, attr: &[u8], at: u64) -> Result<u64, Errno> {
    let flags = word(attr, 40);
    if flags & !F_LOCK != 0 || flags & F_LOCK != 0 {
        return Err(Errno::EINVAL);
    }
    let max = half(attr, 32);
    if max == 0 {
        return Ok(0);
    }
    put_count(c, at, 0)?;
    let keys = word(attr, 16);
    let mut done = 0;
    let mut result = Ok(0);
    while done < max {
        let step = read_key(
            c,
            map,
            element(keys, u64::from(done), u64::from(map.key_size)),
        )
        .and_then(|key| map.remove(&key));
        if let Err(e) = step {
            result = Err(e);
            break;
        }
        done += 1;
    }
    put_count(c, at, done)?;
    result
}

/// `generic_map_lookup_batch`, an array's: the elements after the key at
/// `in_batch` (from the first for none), and the last key given back at
/// `out_batch`; `ENOENT` once they run out.
fn array_lookup_batch(c: &Context<'_>, map: &Map, attr: &[u8], at: u64) -> Result<u64, Errno> {
    check_op_flags(word(attr, 40), F_LOCK | F_CPU)?;
    let max = half(attr, 32);
    if max == 0 {
        return Ok(0);
    }
    put_count(c, at, 0)?;
    let (in_batch, out_batch, keys, values) =
        (word(attr, 0), word(attr, 8), word(attr, 16), word(attr, 24));
    let mut previous = match in_batch {
        0 => None,
        at => Some(read_key(c, map, at)?),
    };
    let (key_size, value_size) = (u64::from(map.key_size), u64::from(map.value_size));
    let mut done = 0;
    let mut result = Ok(0);
    while done < max {
        let key = match map.next(previous.as_deref()) {
            Ok(key) => key,
            Err(e) => {
                result = Err(e);
                break;
            }
        };
        write(c, element(keys, u64::from(done), key_size), &key)?;
        copy_value(c, map, &key, element(values, u64::from(done), value_size))?;
        done += 1;
        previous = Some(key);
    }
    put_count(c, at, done)?;
    if done > 0
        && let Some(last) = &previous
    {
        write(c, out_batch, last)?;
    }
    result
}

/// `__htab_map_lookup_and_delete_batch`, of a hash whose every element is
/// a bucket of its own, in the order of its keys: `in_batch` and
/// `out_batch` hold where the batch starts as a `u32`, and one at or past
/// `roundup_pow_of_two(max_entries)` buckets, or a batch that finds no
/// element left, is `ENOENT`.
fn hash_lookup_batch(
    c: &Context<'_>,
    map: &Map,
    attr: &[u8],
    at: u64,
    delete: bool,
) -> Result<u64, Errno> {
    check_op_flags(word(attr, 40), F_LOCK)?;
    if word(attr, 48) != 0 {
        return Err(Errno::EINVAL);
    }
    let max = half(attr, 32);
    if max == 0 {
        return Ok(0);
    }
    put_count(c, at, 0)?;
    let (in_batch, out_batch, keys, values) =
        (word(attr, 0), word(attr, 8), word(attr, 16), word(attr, 24));
    let mut start = 0u32;
    if in_batch != 0 {
        let mut b = [0; 4];
        c.mem
            .read(GuestAddr(in_batch), &mut b)
            .map_err(|_| Errno::EFAULT)?;
        start = u32::from_le_bytes(b);
    }
    let buckets = map
        .max_entries
        .checked_next_power_of_two()
        .unwrap_or(u32::MAX);
    if start >= buckets {
        return Err(Errno::ENOENT);
    }
    let (taken, left) = map.take(start as usize, max as usize, delete);
    let (key_size, value_size) = (u64::from(map.key_size), u64::from(map.value_size));
    for (i, (key, value)) in taken.iter().enumerate() {
        write(c, element(keys, i as u64, key_size), key)?;
        write(c, element(values, i as u64, value_size), value)?;
    }
    let done = taken.len() as u32;
    let next = if delete {
        start
    } else {
        start.saturating_add(done)
    };
    let remaining = left as u32 > next;
    put_count(c, at, done)?;
    write(c, out_batch, &next.to_le_bytes())?;
    if done == 0 || !remaining && done < max {
        return Err(Errno::ENOENT);
    }
    Ok(0)
}

/// `BPF_OBJ_GET_INFO_BY_FD` of a map, as Linux's `bpf_map_get_info_by_fd`:
/// no descriptor is `EBADFD`, one of no map `EINVAL`; bytes past
/// `struct bpf_map_info` that are not 0, or more than a page, are `E2BIG`;
/// the structure, up to the length asked for, and that length go back.
fn info(c: &mut Context<'_>, attr: &[u8], at: u64) -> Result<u64, Errno> {
    /// `offsetofend(struct bpf_map_info, hash_size)`, and its size.
    const KNOWN: usize = 100;
    const SIZE: usize = 104;
    check_attr(attr, 16)?;
    let file = c
        .files
        .descriptor(u64::from(half(attr, 0)))
        .map_err(|_| EBADFD)?
        .file;
    let map = Arc::clone(&of(&file).ok_or(Errno::EINVAL)?.map);
    let (len, uinfo) = (half(attr, 4) as usize, word(attr, 8));
    if len > PAGE_SIZE as usize {
        return Err(E2BIG);
    }
    if len > KNOWN {
        let mut tail = vec![0; len - KNOWN];
        c.mem
            .read(GuestAddr(uinfo.wrapping_add(KNOWN as u64)), &mut tail)
            .map_err(|_| Errno::EFAULT)?;
        if tail.iter().any(|&b| b != 0) {
            return Err(E2BIG);
        }
    }
    let len = len.min(SIZE);
    let mut info = [0u8; SIZE];
    if len >= 96 {
        c.mem
            .read(GuestAddr(uinfo.wrapping_add(88)), &mut info[88..96])
            .map_err(|_| Errno::EFAULT)?;
    }
    if len >= KNOWN {
        c.mem
            .read(GuestAddr(uinfo.wrapping_add(96)), &mut info[96..100])
            .map_err(|_| Errno::EFAULT)?;
    }
    let (hash, hash_size) = (word(&info, 88), half(&info, 96));
    info.fill(0);
    let fields = [
        map.kind,
        map.id,
        map.key_size,
        map.value_size,
        map.max_entries,
        map.flags,
    ];
    for (i, field) in fields.iter().enumerate() {
        info[i * 4..i * 4 + 4].copy_from_slice(&field.to_le_bytes());
    }
    info[24..40].copy_from_slice(&map.name);
    // A map's SHA-256 (`map_get_hash`) is not made here.
    if hash != 0 || hash_size != 0 {
        return Err(Errno::EINVAL);
    }
    write(c, uinfo, &info[..len])?;
    write(c, at.wrapping_add(4), &(len as u32).to_le_bytes())?;
    Ok(0)
}

/// What `/proc/self/fdinfo` adds for a map, as Linux's
/// `bpf_map_show_fdinfo`. The kernel's `%#x` writes 0 as `0x0`, unlike C's.
pub(crate) fn fdinfo(file: &Arc<dyn FileHandle>) -> Option<Vec<u8>> {
    let map = &of(file)?.map;
    Some(
        format!(
            "map_type:\t{}\nkey_size:\t{}\nvalue_size:\t{}\nmax_entries:\t{}\nmap_flags:\t{:#x}\nmap_extra:\t0x0\nmemlock:\t{}\nmap_id:\t{}\nfrozen:\t{}\n",
            map.kind,
            map.key_size,
            map.value_size,
            map.max_entries,
            map.flags,
            map.memory(),
            map.id,
            u8::from(map.frozen.load(Ordering::SeqCst))
        )
        .into_bytes(),
    )
}

impl FileHandle for MapFile {
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
        Ok(FileStat {
            mode: 0o600,
            links: 1,
            ..FileStat::default()
        })
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn flags(&self) -> u32 {
        self.access
    }
    fn set_flags(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
}

/// What an LRU hash's element is on: Linux's `enum bpf_lru_list_type`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Place {
    Active,
    Inactive,
    Free,
    LocalFree,
    LocalPending,
}

/// The lists of an LRU hash, as Linux's `bpf_lru_list.c` keeps them for the
/// one CPU every command here runs on (a test on Linux pins itself to one):
/// the active, inactive and free lists, and for a common LRU that CPU's
/// local free and pending lists. Elements, as `bpf_lru_node`s, are linked
/// in rings with a head each, so that each list's order, and so which key
/// goes when the map is full, is the one Linux's gives.
struct Lru {
    /// Each element's links, then each list head's.
    next: Vec<usize>,
    prev: Vec<usize>,
    place: Vec<Place>,
    /// `bpf_lru_node.ref`, which only replacing a key sets from user space.
    referenced: Vec<bool>,
    keys: Vec<Vec<u8>>,
    values: Vec<Vec<u8>>,
    /// The hash table: which element holds each key.
    table: BTreeMap<Vec<u8>, usize>,
    /// How many are active and inactive (`counts`).
    active: usize,
    inactive: usize,
    /// `next_inactive_rotation`: an element, or the inactive list's head.
    rotation: usize,
    /// `target_free` (a common LRU) and `nr_scans`.
    target_free: usize,
    scans: usize,
    /// `BPF_F_NO_COMMON_LRU`: the CPU's own lists, without local ones.
    per_cpu: bool,
}

/// `LOCAL_FREE_TARGET`, `PERCPU_FREE_TARGET`: also each kind's `nr_scans`.
const LOCAL_FREE_TARGET: usize = 128;
const PERCPU_FREE_TARGET: usize = 4;

impl Lru {
    /// `bpf_lru_init` and `bpf_lru_populate`: every element on the free list,
    /// each put at its head. A common LRU has them all, with a target of
    /// half a CPU's share between 1 and 128; one per CPU has this CPU's
    /// share.
    fn new(max_entries: u32, cpus: u64, per_cpu: bool) -> Lru {
        let share = (u64::from(max_entries) / cpus.max(1)) as usize;
        let elements = if per_cpu { share } else { max_entries as usize };
        let heads = elements + 5;
        let mut lru = Lru {
            next: (0..heads).collect(),
            prev: (0..heads).collect(),
            place: vec![Place::Free; elements],
            referenced: vec![false; elements],
            keys: vec![Vec::new(); elements],
            values: vec![Vec::new(); elements],
            table: BTreeMap::new(),
            active: 0,
            inactive: 0,
            rotation: elements + 1,
            target_free: (share / 2).clamp(1, LOCAL_FREE_TARGET),
            scans: if per_cpu {
                PERCPU_FREE_TARGET
            } else {
                LOCAL_FREE_TARGET
            },
            per_cpu,
        };
        for i in 0..elements {
            lru.add(i, lru.head(Place::Free));
        }
        lru
    }
    /// The head of a list, past the elements.
    fn head(&self, place: Place) -> usize {
        self.place.len()
            + match place {
                Place::Active => 0,
                Place::Inactive => 1,
                Place::Free => 2,
                Place::LocalFree => 3,
                Place::LocalPending => 4,
            }
    }
    fn unlink(&mut self, i: usize) {
        let (p, n) = (self.prev[i], self.next[i]);
        self.next[p] = n;
        self.prev[n] = p;
    }
    /// `list_add`: at the head.
    fn add(&mut self, i: usize, head: usize) {
        let first = self.next[head];
        self.next[i] = first;
        self.prev[i] = head;
        self.prev[first] = i;
        self.next[head] = i;
    }
    /// `list_move`: to the head of another list, or its own.
    fn relink(&mut self, i: usize, head: usize) {
        self.unlink(i);
        self.add(i, head);
    }
    fn first(&self, place: Place) -> Option<usize> {
        let head = self.head(place);
        (self.next[head] != head).then_some(self.next[head])
    }
    fn count(&mut self, place: Place, by: isize) {
        match place {
            Place::Active => self.active = self.active.wrapping_add_signed(by),
            Place::Inactive => self.inactive = self.inactive.wrapping_add_signed(by),
            _ => {}
        }
    }
    /// `__bpf_lru_node_move_to_free`.
    fn move_to_free(&mut self, i: usize, head: usize, place: Place) {
        if i == self.rotation {
            self.rotation = self.prev[self.rotation];
        }
        self.count(self.place[i], -1);
        self.place[i] = place;
        self.relink(i, head);
    }
    /// `__bpf_lru_node_move_in`, from a local list.
    fn move_in(&mut self, i: usize, place: Place) {
        self.count(place, 1);
        self.place[i] = place;
        self.referenced[i] = false;
        self.relink(i, self.head(place));
    }
    /// `__bpf_lru_node_move`, between the active, inactive and free lists.
    fn shift(&mut self, i: usize, place: Place) {
        if self.place[i] != place {
            self.count(self.place[i], -1);
            self.count(place, 1);
            self.place[i] = place;
        }
        self.referenced[i] = false;
        if i == self.rotation {
            self.rotation = self.prev[self.rotation];
        }
        self.relink(i, self.head(place));
    }
    /// `htab_lru_map_delete_node`: takes the element's key out of the table
    /// if it is still there.
    fn take_out(&mut self, i: usize) -> bool {
        if self.table.get(&self.keys[i]) == Some(&i) {
            self.table.remove(&self.keys[i]);
            true
        } else {
            false
        }
    }
    /// `__bpf_lru_list_rotate_active`: from the tail, up to `nr_scans`
    /// elements back to the first, a referenced one to the active list's
    /// head and the rest to the inactive list's.
    fn rotate_active(&mut self) {
        let head = self.head(Place::Active);
        let first = self.next[head];
        let mut i = self.prev[head];
        let mut scanned = 0;
        while i != head {
            let before = self.prev[i];
            let to = if self.referenced[i] {
                Place::Active
            } else {
                Place::Inactive
            };
            self.shift(i, to);
            scanned += 1;
            if scanned == self.scans || i == first {
                break;
            }
            i = before;
        }
    }
    /// `__bpf_lru_list_rotate_inactive`: from `next_inactive_rotation`
    /// towards the head, up to `nr_scans` elements, a referenced one to the
    /// active list; where it stops is where the next starts.
    fn rotate_inactive(&mut self) {
        let head = self.head(Place::Inactive);
        if self.next[head] == head {
            return;
        }
        let mut last = self.next[self.rotation];
        if last == head {
            last = self.next[last];
        }
        let (mut current, mut next) = (self.rotation, head);
        let mut scanned = 0;
        while scanned < self.scans {
            if current == head {
                current = self.prev[current];
                continue;
            }
            next = self.prev[current];
            if self.referenced[current] {
                self.shift(current, Place::Active);
            }
            if current == last {
                break;
            }
            current = next;
            scanned += 1;
        }
        self.rotation = next;
    }
    /// `__bpf_lru_list_rotate`: the active list when the inactive one has
    /// fewer, then the inactive list.
    fn rotate(&mut self) {
        if self.inactive < self.active {
            self.rotate_active();
        }
        self.rotate_inactive();
    }
    /// `__bpf_lru_list_shrink`: up to `target` unreferenced elements from the
    /// inactive list's tail onto a free list, within `nr_scans`; failing
    /// that, the last of the inactive list, or else of the active one,
    /// whatever its reference.
    fn shrink(&mut self, target: usize, free: usize, place: Place) {
        let head = self.head(Place::Inactive);
        let (mut i, mut scanned, mut shrunk) = (self.prev[head], 0, 0);
        while i != head {
            let before = self.prev[i];
            if self.referenced[i] {
                self.shift(i, Place::Active);
            } else if self.take_out(i) {
                self.move_to_free(i, free, place);
                shrunk += 1;
                if shrunk == target {
                    break;
                }
            }
            scanned += 1;
            if scanned == self.scans {
                break;
            }
            i = before;
        }
        if shrunk > 0 {
            return;
        }
        let forced = if self.next[head] != head {
            head
        } else {
            self.head(Place::Active)
        };
        let mut i = self.prev[forced];
        while i != forced {
            let before = self.prev[i];
            if self.take_out(i) {
                self.move_to_free(i, free, place);
                return;
            }
            i = before;
        }
    }
    /// `bpf_lru_list_pop_free_to_local`: the pending elements into the
    /// lists, a rotation, then up to `target_free` free ones to the local
    /// free list, and what is missing shrunk onto it.
    fn pop_free_to_local(&mut self) {
        let pending = self.head(Place::LocalPending);
        let mut i = self.prev[pending];
        while i != pending {
            let before = self.prev[i];
            let to = if self.referenced[i] {
                Place::Active
            } else {
                Place::Inactive
            };
            self.move_in(i, to);
            i = before;
        }
        self.rotate();
        let (free, local) = (self.head(Place::Free), self.head(Place::LocalFree));
        let mut moved = 0;
        let mut i = self.next[free];
        while i != free {
            let after = self.next[i];
            self.move_to_free(i, local, Place::LocalFree);
            moved += 1;
            if moved == self.target_free {
                break;
            }
            i = after;
        }
        if moved < self.target_free {
            self.shrink(self.target_free - moved, local, Place::LocalFree);
        }
    }
    /// `__local_list_pop_pending`: the oldest pending element whose key can
    /// be taken out, unreferenced first.
    fn pop_pending(&mut self) -> Option<usize> {
        let pending = self.head(Place::LocalPending);
        for force in [false, true] {
            let mut i = self.prev[pending];
            while i != pending {
                if (!self.referenced[i] || force) && self.take_out(i) {
                    self.unlink(i);
                    return Some(i);
                }
                i = self.prev[i];
            }
        }
        None
    }
    /// `bpf_lru_pop_free`: an element for a new key, which may take another
    /// key out of the table.
    fn pop_free(&mut self) -> Option<usize> {
        if self.per_cpu {
            self.rotate();
            let free = self.head(Place::Free);
            if self.next[free] == free {
                self.shrink(PERCPU_FREE_TARGET, free, Place::Free);
            }
            let i = self.first(Place::Free)?;
            self.referenced[i] = false;
            self.shift(i, Place::Inactive);
            return Some(i);
        }
        let mut i = self.first(Place::LocalFree);
        if i.is_none() {
            self.pop_free_to_local();
            i = self.first(Place::LocalFree);
        }
        let i = match i {
            Some(i) => {
                self.unlink(i);
                i
            }
            // Stolen back from the CPU's own pending list: every other
            // CPU's local lists are empty.
            None => self.pop_pending()?,
        };
        self.place[i] = Place::LocalPending;
        self.referenced[i] = false;
        self.add(i, self.head(Place::LocalPending));
        Some(i)
    }
    /// `bpf_lru_push_free`: a pending element back to the local free list,
    /// any other to the free list.
    fn push_free(&mut self, i: usize) {
        if !self.per_cpu && self.place[i] == Place::LocalPending {
            self.place[i] = Place::LocalFree;
            self.referenced[i] = false;
            self.relink(i, self.head(Place::LocalFree));
        } else {
            self.shift(i, Place::Free);
        }
    }
    /// `htab_lru_map_update_elem`: an element is taken first, then the flags
    /// are checked; a key replaced is referenced in its new element.
    fn update(&mut self, key: &[u8], value: Vec<u8>, mode: u64) -> Result<(), Errno> {
        let i = self.pop_free().ok_or(ENOMEM)?;
        self.keys[i] = key.to_vec();
        self.values[i] = value;
        let old = self.table.get(key).copied();
        let refused = match (old, mode) {
            (Some(_), NOEXIST) => Some(Errno::EEXIST),
            (None, EXIST) => Some(Errno::ENOENT),
            _ => None,
        };
        if let Some(e) = refused {
            self.push_free(i);
            return Err(e);
        }
        self.table.insert(key.to_vec(), i);
        if let Some(old) = old {
            self.referenced[i] = true;
            self.push_free(old);
        }
        Ok(())
    }
    /// `htab_lru_map_delete_elem`.
    fn delete(&mut self, key: &[u8]) -> Result<Vec<u8>, Errno> {
        let i = self.table.remove(key).ok_or(Errno::ENOENT)?;
        let value = std::mem::take(&mut self.values[i]);
        self.push_free(i);
        Ok(value)
    }
    fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        self.table.get(key).map(|&i| &self.values[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(kind: u32, max_entries: u32) -> Map {
        shaped(kind, max_entries, 8, 0, &Arc::default(), 1)
    }

    fn shaped(
        kind: u32,
        max_entries: u32,
        value_size: u32,
        flags: u32,
        ids: &Arc<Ids>,
        id: u32,
    ) -> Map {
        Map {
            kind,
            key_size: 4,
            value_size,
            max_entries,
            flags,
            name: [0; 16],
            id,
            ids: Arc::clone(ids),
            cpus: 2,
            frozen: AtomicBool::new(false),
            elements: Mutex::new(elements(kind, max_entries, flags, 2)),
        }
    }

    #[test]
    fn an_arrays_elements_are_there_from_the_start() {
        let m = map(TYPE_ARRAY, 3);
        assert_eq!(m.get(&1u32.to_le_bytes()), Ok(vec![0; 8]));
        assert_eq!(m.get(&3u32.to_le_bytes()), Err(Errno::ENOENT));
        assert_eq!(m.set(&3u32.to_le_bytes(), vec![1; 8], 0), Err(E2BIG));
        assert_eq!(
            m.set(&1u32.to_le_bytes(), vec![1; 8], NOEXIST),
            Err(Errno::EEXIST)
        );
        assert_eq!(
            m.set(&1u32.to_le_bytes(), vec![1; 8], 3),
            Err(Errno::EINVAL)
        );
        m.set(&1u32.to_le_bytes(), vec![1; 8], EXIST).unwrap();
        assert_eq!(m.get(&1u32.to_le_bytes()), Ok(vec![1; 8]));
        assert_eq!(m.remove(&1u32.to_le_bytes()), Err(Errno::EINVAL));
        assert_eq!(m.next(None), Ok(0u32.to_le_bytes().to_vec()));
        assert_eq!(
            m.next(Some(&7u32.to_le_bytes())),
            Ok(0u32.to_le_bytes().to_vec())
        );
        assert_eq!(
            m.next(Some(&1u32.to_le_bytes())),
            Ok(2u32.to_le_bytes().to_vec())
        );
        assert_eq!(m.next(Some(&2u32.to_le_bytes())), Err(Errno::ENOENT));
    }

    #[test]
    fn a_hash_holds_what_was_put_in_up_to_its_size() {
        let m = map(TYPE_HASH, 2);
        let k = |i: u32| i.to_le_bytes();
        assert_eq!(m.get(&k(1)), Err(Errno::ENOENT));
        assert_eq!(m.set(&k(1), vec![1; 8], EXIST), Err(Errno::ENOENT));
        m.set(&k(1), vec![1; 8], NOEXIST).unwrap();
        assert_eq!(m.set(&k(1), vec![2; 8], NOEXIST), Err(Errno::EEXIST));
        m.set(&k(2), vec![2; 8], 0).unwrap();
        assert_eq!(m.set(&k(3), vec![3; 8], 0), Err(E2BIG));
        // Replacing one needs no room.
        m.set(&k(2), vec![4; 8], 0).unwrap();
        assert_eq!(m.next(None), Ok(k(1).to_vec()));
        assert_eq!(m.next(Some(&k(9))), Ok(k(1).to_vec()));
        assert_eq!(m.next(Some(&k(1))), Ok(k(2).to_vec()));
        assert_eq!(m.next(Some(&k(2))), Err(Errno::ENOENT));
        assert_eq!(m.remove(&k(1)), Ok(vec![1; 8]));
        assert_eq!(m.remove(&k(1)), Err(Errno::ENOENT));
    }

    #[test]
    fn ids_go_round_from_where_the_last_ended_and_come_back_as_maps_go() {
        let ids = Arc::new(Ids::default());
        let make = |id| shaped(TYPE_ARRAY, 1, 8, 0, &ids, id);
        let first = ids.publish(make).unwrap();
        let second = ids.publish(make).unwrap();
        assert_eq!((first.id, second.id), (1, 2));
        assert_eq!(ids.next_from(0), Some(1));
        assert_eq!(ids.next_from(2), Some(2));
        assert_eq!(ids.next_from(3), None);
        drop(first);
        assert!(ids.find(1).is_none());
        assert_eq!(ids.next_from(0), Some(2));
        // An ID is not taken again until they have gone round.
        assert_eq!(ids.publish(make).unwrap().id, 3);
        lock(&ids.table).next = LAST_ID;
        let last = ids.publish(make).unwrap();
        assert_eq!(last.id, LAST_ID);
        // The last one freed is not taken again before the others.
        drop(last);
        assert_eq!(ids.publish(make).unwrap().id, 1);
        assert!(Arc::ptr_eq(&ids.find(2).unwrap(), &second));
    }

    #[test]
    fn memory_is_what_linux_7_0_counts_on_x86_64() {
        let ids = Arc::default();
        let array = |entries, value, flags| shaped(TYPE_ARRAY, entries, value, flags, &ids, 1);
        assert_eq!(array(1, 8, 0).memory(), 320);
        assert_eq!(array(10, 3, 0).memory(), 312 + 80);
        assert_eq!(array(10, 24, flag::MMAPABLE).memory(), 8192);
        let hash = |entries, flags| shaped(TYPE_HASH, entries, 8, flags, &ids, 1);
        // 3 entries take 4 buckets; elements are 48 + 8 + 8 bytes.
        assert_eq!(hash(3, 0).memory(), 896 + 64 + 64 * 5 + 16);
        let sparse = hash(3, flag::NO_PREALLOC);
        assert_eq!(sparse.memory(), 896 + 64);
        sparse.set(&1u32.to_le_bytes(), vec![0; 8], 0).unwrap();
        assert_eq!(sparse.memory(), 896 + 64 + 72);
    }

    #[test]
    fn maps_larger_than_the_machine_are_enomem() {
        assert_eq!(
            allocate(TYPE_ARRAY, 1 << 30, 4, 1 << 20, 0, true, 2),
            Err(ENOMEM)
        );
        assert_eq!(allocate(TYPE_ARRAY, 8, 4, 1 << 20, 0, true, 2), Ok(()));
        // Without bypass_spec_v1 the entries are rounded up first.
        assert_eq!(
            allocate(TYPE_ARRAY, 1 << 10, 4, (1 << 22) + 1, 0, true, 2),
            Ok(())
        );
        assert_eq!(
            allocate(TYPE_ARRAY, 1 << 10, 4, (1 << 22) + 1, 0, false, 2),
            Err(ENOMEM)
        );
        assert_eq!(
            allocate(TYPE_HASH, 1 << 21, 4, 1 << 20, 0, true, 2),
            Err(ENOMEM)
        );
        assert_eq!(
            allocate(TYPE_HASH, 1 << 21, 4, 1 << 20, flag::NO_PREALLOC, true, 2),
            Ok(())
        );
        assert_eq!(
            allocate(TYPE_HASH, 8, 4, (1 << 27) + 1, 0, true, 2),
            Err(E2BIG)
        );
        assert_eq!(allocate(TYPE_HASH, 8, 4, u32::MAX, 0, true, 2), Err(E2BIG));
    }

    fn held_keys(m: &Map) -> Vec<u32> {
        m.held().iter().map(|(k, _)| index(k)).collect()
    }

    #[test]
    fn a_full_lru_hash_gives_up_its_oldest_key() {
        // Two CPUs: a target of one free element at a time.
        let m = map(TYPE_LRU_HASH, 4);
        let k = |i: u32| i.to_le_bytes();
        for i in 1..=5 {
            m.set(&k(i), vec![i as u8; 8], 0).unwrap();
        }
        assert_eq!(held_keys(&m), [2, 3, 4, 5]);
        // The oldest is taken out for the new element before a key is
        // replaced, even the very key replaced.
        m.set(&k(2), vec![9; 8], 0).unwrap();
        assert_eq!(held_keys(&m), [2, 3, 4, 5]);
        m.set(&k(6), vec![6; 8], 0).unwrap();
        assert_eq!(held_keys(&m), [2, 4, 5, 6]);
        // A refused update still takes an element, and so the oldest key.
        assert_eq!(m.set(&k(6), vec![0; 8], NOEXIST), Err(Errno::EEXIST));
        assert_eq!(held_keys(&m), [2, 5, 6]);
        assert_eq!(m.set(&k(9), vec![0; 8], EXIST), Err(Errno::ENOENT));
        assert_eq!(m.get(&k(6)), Ok(vec![6; 8]));
        // What is deleted is free again, and nothing else goes.
        assert_eq!(m.remove(&k(5)), Ok(vec![5; 8]));
        assert_eq!(m.remove(&k(5)), Err(Errno::ENOENT));
        m.set(&k(7), vec![7; 8], 0).unwrap();
        m.set(&k(8), vec![8; 8], 0).unwrap();
        assert_eq!(m.len(), 4);
        assert_eq!(m.next(None), Ok(k(held_keys(&m)[0]).to_vec()));
    }

    #[test]
    fn a_replaced_key_is_referenced_and_outlives_older_ones() {
        let m = map(TYPE_LRU_HASH, 4);
        let k = |i: u32| i.to_le_bytes();
        for i in 1..=4 {
            m.set(&k(i), vec![0; 8], 0).unwrap();
        }
        // Replacing 4 takes 1 out and references 4's new element.
        m.set(&k(4), vec![1; 8], 0).unwrap();
        assert_eq!(held_keys(&m), [2, 3, 4]);
        for i in 5..=7 {
            m.set(&k(i), vec![0; 8], 0).unwrap();
        }
        assert!(held_keys(&m).contains(&4), "{:?}", held_keys(&m));
    }

    #[test]
    fn lists_of_each_cpus_own_hold_its_share() {
        // Two CPUs, so 3 entries are 4, two for this CPU.
        assert_eq!(entries(TYPE_LRU_HASH, 3, flag::NO_COMMON_LRU, 2), 4);
        assert_eq!(
            entries(TYPE_LRU_HASH, u32::MAX, flag::NO_COMMON_LRU, 2),
            u32::MAX - 1
        );
        assert_eq!(entries(TYPE_LRU_HASH, 3, 0, 2), 3);
        let m = shaped(TYPE_LRU_HASH, 4, 8, flag::NO_COMMON_LRU, &Arc::default(), 1);
        let k = |i: u32| i.to_le_bytes();
        // Full, it frees up to four at once: both of its own go.
        m.set(&k(1), vec![0; 8], 0).unwrap();
        m.set(&k(2), vec![0; 8], 0).unwrap();
        assert_eq!(held_keys(&m), [1, 2]);
        m.set(&k(3), vec![0; 8], 0).unwrap();
        assert_eq!(held_keys(&m), [3]);
    }

    #[test]
    fn an_lru_hash_counts_its_elements_without_spares() {
        let ids = Arc::default();
        let m = shaped(TYPE_LRU_HASH, 3, 8, 0, &ids, 1);
        assert_eq!(m.memory(), 896 + 64 + 64 * 3);
        assert_eq!(allocate(TYPE_LRU_HASH, 8, 4, 3, 0, true, 2), Ok(()));
        assert_eq!(
            allocate(TYPE_LRU_HASH, 1 << 21, 4, 1 << 20, 0, true, 2),
            Err(ENOMEM)
        );
    }

    fn queue(kind: u32, max_entries: u32) -> Map {
        let mut m = shaped(kind, max_entries, 8, 0, &Arc::default(), 1);
        m.key_size = 0;
        m
    }

    #[test]
    fn a_queue_gives_its_oldest_and_a_stack_its_newest() {
        for (kind, first) in [(TYPE_QUEUE, 1u8), (TYPE_STACK, 2)] {
            let m = queue(kind, 2);
            assert_eq!(m.get(&[]), Err(Errno::ENOENT));
            assert_eq!(m.pop(), Err(Errno::ENOENT));
            m.set(&[], vec![1; 8], 0).unwrap();
            m.set(&[], vec![2; 8], 0).unwrap();
            assert_eq!(m.set(&[], vec![3; 8], 0), Err(E2BIG));
            assert_eq!(m.set(&[], vec![3; 8], NOEXIST), Err(Errno::EINVAL));
            assert_eq!(m.get(&[]), Ok(vec![first; 8]));
            assert_eq!(m.pop(), Ok(vec![first; 8]));
            assert_eq!(m.remove(&[]), Err(Errno::EINVAL));
            assert_eq!(m.next(None), Err(Errno::EINVAL));
        }
        // BPF_EXIST makes room by giving up the oldest, for a stack too.
        let m = queue(TYPE_STACK, 2);
        for i in 1..=3 {
            m.set(&[], vec![i; 8], EXIST).unwrap();
        }
        assert_eq!(m.pop(), Ok(vec![3; 8]));
        assert_eq!(m.pop(), Ok(vec![2; 8]));
        assert_eq!(m.pop(), Err(Errno::ENOENT));
    }

    #[test]
    fn a_queue_takes_its_header_and_one_slot_more_than_its_entries() {
        assert_eq!(queue(TYPE_QUEUE, 3).memory(), 312 + 4 * 8);
        assert_eq!(
            allocate(TYPE_QUEUE, 1 << 22, 0, 1 << 11, 0, true, 2),
            Err(ENOMEM)
        );
        assert_eq!(allocate(TYPE_STACK, 8, 0, 1 << 20, 0, true, 2), Ok(()));
    }

    #[test]
    fn names_take_letters_digits_underscores_and_dots() {
        assert!(name(b"map_1.x\0\0\0\0\0\0\0\0\0").is_ok());
        assert_eq!(name(b"map-1\0\0\0\0\0\0\0\0\0\0\0"), Err(Errno::EINVAL));
        assert_eq!(name(b"0123456789abcdef"), Err(Errno::EINVAL));
    }
}
