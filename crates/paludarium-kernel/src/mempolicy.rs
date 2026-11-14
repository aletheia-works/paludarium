//! NUMA memory policies (`set_mempolicy`, `get_mempolicy`, `mbind`), as
//! Linux's `mm/mempolicy.c` keeps them on a machine with one node, node 0,
//! which is what the emulator shows (`getcpu`, `/sys`): every policy places
//! memory on node 0, so only the policies themselves are kept, for
//! `get_mempolicy` to report.
use crate::syscalls::{Context, Outcome, err, ok};
use paludarium_mmu::{AddressSpace, MemoryView, PageState, Prot};
use paludarium_types::{Errno, GuestAddr};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

/// Linux x86-64's `MAX_NUMNODES` (`CONFIG_NODES_SHIFT=10`, as in Debian's
/// and Ubuntu's kernels), the bits a node mask holds.
const MAX_NUMNODES: u64 = 1024;
const WORDS: usize = (MAX_NUMNODES / 64) as usize;
/// The nodes that have memory and that the thread may use: node 0.
const NODES: u64 = 1;
/// `nr_node_ids`, one more than the highest possible node.
const NODE_IDS: u64 = 1;

const MPOL_DEFAULT: u32 = 0;
const MPOL_PREFERRED: u32 = 1;
const MPOL_BIND: u32 = 2;
const MPOL_INTERLEAVE: u32 = 3;
const MPOL_LOCAL: u32 = 4;
const MPOL_PREFERRED_MANY: u32 = 5;
const MPOL_WEIGHTED_INTERLEAVE: u32 = 6;
const MPOL_MAX: u32 = 7;
const MPOL_F_STATIC_NODES: u32 = 1 << 15;
const MPOL_F_RELATIVE_NODES: u32 = 1 << 14;
const MPOL_F_NUMA_BALANCING: u32 = 1 << 13;
const MPOL_MODE_FLAGS: u32 = MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES | MPOL_F_NUMA_BALANCING;

const MPOL_F_NODE: u64 = 1;
const MPOL_F_ADDR: u64 = 2;
const MPOL_F_MEMS_ALLOWED: u64 = 4;

const MPOL_MF_STRICT: u64 = 1;
const MPOL_MF_MOVE: u64 = 2;
const MPOL_MF_MOVE_ALL: u64 = 4;

pub(crate) type NodeMask = [u64; WORDS];

/// A policy other than the default (Linux's `struct mempolicy`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MemPolicy {
    /// The mode, `MPOL_LOCAL` for `MPOL_PREFERRED` with no nodes.
    mode: u32,
    /// The mode flags it was given.
    flags: u32,
    /// The nodes it places memory on.
    nodes: u64,
    /// The node mask the caller gave, which `get_mempolicy` reports for
    /// `MPOL_F_STATIC_NODES` and `MPOL_F_RELATIVE_NODES`.
    user: NodeMask,
}

/// The policies of a thread group's threads, and of ranges of its address
/// space (Linux keeps the latter on the VMAs; clone with `CLONE_VM` shares
/// them).
#[derive(Default)]
pub(crate) struct Numa {
    tasks: Mutex<BTreeMap<u32, MemPolicy>>,
    ranges: Mutex<Arc<Mutex<Ranges>>>,
}

/// Address ranges with a policy: start to (end, policy), not overlapping.
#[derive(Clone, Default)]
struct Ranges(BTreeMap<u64, (u64, MemPolicy)>);

impl Ranges {
    /// Gives `[start, end)` `policy`, or none, splitting the ranges it cuts.
    fn set(&mut self, start: u64, end: u64, policy: Option<MemPolicy>) {
        let cut: Vec<u64> = self
            .0
            .range(..end)
            .filter(|(_, (e, _))| *e > start)
            .map(|(s, _)| *s)
            .collect();
        for s in cut {
            let (e, p) = self.0.remove(&s).unwrap_or_else(|| unreachable!());
            if s < start {
                self.0.insert(s, (start, p.clone()));
            }
            if e > end {
                self.0.insert(end, (e, p));
            }
        }
        if let Some(p) = policy {
            self.0.insert(start, (end, p));
        }
    }
    fn at(&self, addr: u64) -> Option<MemPolicy> {
        self.0
            .range(..=addr)
            .next_back()
            .filter(|(_, (end, _))| addr < *end)
            .map(|(_, (_, p))| p.clone())
    }
    /// The ranges within `[start, end)`, cut to it.
    fn within(&self, start: u64, end: u64) -> Vec<(u64, u64, MemPolicy)> {
        self.0
            .range(..end)
            .filter(|(_, (e, _))| *e > start)
            .map(|(s, (e, p))| ((*s).max(start), (*e).min(end), p.clone()))
            .collect()
    }
}

impl Numa {
    fn ranges(&self) -> Arc<Mutex<Ranges>> {
        self.ranges
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    fn task(&self, tid: u32) -> Option<MemPolicy> {
        self.tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&tid)
            .cloned()
    }
    fn set_task(&self, tid: u32, policy: Option<MemPolicy>) {
        let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        match policy {
            Some(p) => tasks.insert(tid, p),
            None => tasks.remove(&tid),
        };
    }
    /// A new thread `tid` takes its creator's policy, as Linux's
    /// `dup_task_struct` copies it.
    pub(crate) fn new_thread(&self, parent: u32, tid: u32) {
        let policy = self.task(parent);
        self.set_task(tid, policy);
    }
    /// A new process: its first thread `pid` takes the creating thread's
    /// policy, and its address space the parent's range policies, shared
    /// with `CLONE_VM` and copied otherwise (`dup_mmap`).
    pub(crate) fn new_process(&self, child: &Numa, parent: u32, pid: u32, shares_memory: bool) {
        child.set_task(pid, self.task(parent));
        let ranges = self.ranges();
        let ranges = if shares_memory {
            ranges
        } else {
            let copy = ranges
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            Arc::new(Mutex::new(copy))
        };
        *child.ranges.lock().unwrap_or_else(PoisonError::into_inner) = ranges;
    }
    /// `execve` by `old_tid`, now `pid`: its policy stays and the other
    /// threads' are gone; the new address space has no range policies.
    pub(crate) fn exec(&self, old_tid: u32, pid: u32) {
        let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        let kept = tasks.remove(&old_tid);
        tasks.clear();
        if let Some(p) = kept {
            tasks.insert(pid, p);
        }
        drop(tasks);
        *self.ranges.lock().unwrap_or_else(PoisonError::into_inner) = Arc::default();
    }
    /// `[start, start + len)` was unmapped or mapped anew, which ends the
    /// policies of the VMAs there.
    pub(crate) fn forget(&self, start: u64, len: u64) {
        let end = start.saturating_add(len.saturating_add(4095) & !4095);
        if end > start {
            self.ranges()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .set(start, end, None);
        }
    }
    /// `mremap` moved `[old, old + old_len)` to `new`, `new_len` long: the
    /// VMA takes its policy along, a grown one over its new pages too. With
    /// `keep_old` (`MREMAP_DONTUNMAP`) the old range keeps a VMA, which
    /// keeps the policy.
    pub(crate) fn moved(&self, old: u64, old_len: u64, new: u64, new_len: u64, keep_old: bool) {
        let page = |n: u64| n.saturating_add(4095) & !4095;
        let (old_len, new_len) = (page(old_len), page(new_len));
        let ranges = self.ranges();
        let mut ranges = ranges.lock().unwrap_or_else(PoisonError::into_inner);
        let old_end = old.saturating_add(old_len);
        let kept = ranges.within(old, old_end);
        let last = ranges.at(old_end.saturating_sub(1));
        if new != old && !keep_old {
            ranges.set(old, old_end, None);
        }
        if new_len < old_len && new == old {
            ranges.set(old + new_len, old_end, None);
            return;
        }
        let new_end = new.saturating_add(new_len);
        ranges.set(new, new_end, None);
        for (s, e, p) in kept {
            let (s, e) = (s - old + new, (e - old + new).min(new_end));
            if s < e {
                ranges.set(s, e, Some(p));
            }
        }
        if new_len > old_len
            && let Some(p) = last
        {
            ranges.set(new + old_len, new_end, Some(p));
        }
    }
}

/// `sanitize_mpol_flags`: the mode and its flags from `mode`.
fn sanitize(mode: u64) -> Result<(u32, u32), Errno> {
    let mode = mode as u32;
    let flags = mode & MPOL_MODE_FLAGS;
    let mode = mode & !MPOL_MODE_FLAGS;
    if mode >= MPOL_MAX {
        return Err(Errno::EINVAL);
    }
    if flags & MPOL_F_STATIC_NODES != 0 && flags & MPOL_F_RELATIVE_NODES != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & MPOL_F_NUMA_BALANCING != 0 && mode != MPOL_BIND && mode != MPOL_PREFERRED_MANY {
        return Err(Errno::EINVAL);
    }
    Ok((mode, flags))
}

/// `get_bitmap`: `bits` bits of a node mask at `at`.
fn bitmap(mem: &AddressSpace, at: u64, bits: u64, out: &mut [u64]) -> Result<(), Errno> {
    let words = bits.div_ceil(64) as usize;
    let mut bytes = vec![0u8; words * 8];
    mem.read(GuestAddr(at), &mut bytes)
        .map_err(|_| Errno::EFAULT)?;
    for (i, word) in bytes.as_chunks::<8>().0.iter().enumerate() {
        out[i] = u64::from_le_bytes(*word);
    }
    if !bits.is_multiple_of(64) {
        out[words - 1] &= (1u64 << (bits % 64)) - 1;
    }
    Ok(())
}

/// `get_nodes`: the node mask of `maxnode - 1` bits at `at`. Bits past
/// `MAX_NUMNODES` must be clear, read a word at a time from the end.
fn nodes(mem: &AddressSpace, at: u64, maxnode: u64) -> Result<NodeMask, Errno> {
    let mut mask = [0u64; WORDS];
    let mut maxnode = maxnode.wrapping_sub(1);
    if maxnode == 0 || at == 0 {
        return Ok(mask);
    }
    if maxnode > 4096 * 8 {
        return Err(Errno::EINVAL);
    }
    while maxnode > MAX_NUMNODES {
        let bits = maxnode.min(64);
        let mut word = [0u64; 1];
        // A user pointer's sum, which wraps and then faults (EFAULT).
        bitmap(
            mem,
            at.wrapping_add((maxnode - 1) / 64 * 8),
            bits,
            &mut word,
        )?;
        let mut t = word[0];
        if maxnode - bits >= MAX_NUMNODES {
            maxnode -= bits;
        } else {
            maxnode = MAX_NUMNODES;
            t &= !((1u64 << (MAX_NUMNODES % 64)).wrapping_sub(1));
        }
        if t != 0 {
            return Err(Errno::EINVAL);
        }
    }
    bitmap(mem, at, maxnode, &mut mask)?;
    Ok(mask)
}

/// `mpol_new` and `mpol_set_nodemask`: the policy for `mode` over `nodes`,
/// `None` for `MPOL_DEFAULT`.
fn policy(mode: u32, flags: u32, nodes: &NodeMask) -> Result<Option<MemPolicy>, Errno> {
    let empty = nodes.iter().all(|w| *w == 0);
    let mut mode = mode;
    match mode {
        MPOL_DEFAULT => return if empty { Ok(None) } else { Err(Errno::EINVAL) },
        MPOL_PREFERRED if empty => {
            if flags & (MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES) != 0 {
                return Err(Errno::EINVAL);
            }
            mode = MPOL_LOCAL;
        }
        MPOL_LOCAL => {
            if !empty || flags & (MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES) != 0 {
                return Err(Errno::EINVAL);
            }
        }
        _ if empty => return Err(Errno::EINVAL),
        _ => {}
    }
    let user = if flags & (MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES) != 0 {
        *nodes
    } else {
        [0; WORDS]
    };
    if mode == MPOL_LOCAL {
        return Ok(Some(MemPolicy {
            mode,
            flags,
            nodes: 0,
            user,
        }));
    }
    // The nodes the thread may use: relative ones fold onto them, the
    // others are cut to them.
    let usable = if flags & MPOL_F_RELATIVE_NODES != 0 {
        if empty { 0 } else { NODES }
    } else {
        nodes[0] & NODES
    };
    if usable == 0 {
        return Err(Errno::EINVAL);
    }
    // MPOL_PREFERRED keeps the first of them; the others keep them all.
    let nodes = if mode == MPOL_PREFERRED {
        1 << usable.trailing_zeros()
    } else {
        usable
    };
    Ok(Some(MemPolicy {
        mode,
        flags,
        nodes,
        user,
    }))
}

/// `set_mempolicy(mode, nodemask, maxnode)`: the calling thread's policy.
pub(crate) fn sys_set_mempolicy(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let result = sanitize(a[0])
        .and_then(|(mode, flags)| Ok((mode, flags, nodes(c.mem, a[1], a[2])?)))
        .and_then(|(mode, flags, nodes)| policy(mode, flags, &nodes));
    match result {
        Ok(policy) => {
            c.group.numa().set_task(c.tid, policy);
            ok(0)
        }
        Err(e) => err(e),
    }
}

/// `get_mempolicy(mode, nodemask, maxnode, addr, flags)`, as Linux's
/// `kernel_get_mempolicy` and `do_get_mempolicy`.
pub(crate) fn sys_get_mempolicy(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (mode_at, mask_at, maxnode, addr, flags) = (a[0], a[1], a[2], a[3], a[4]);
    if mask_at != 0 && maxnode < NODE_IDS {
        return err(Errno::EINVAL);
    }
    if flags & !(MPOL_F_NODE | MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED) != 0 {
        return err(Errno::EINVAL);
    }
    let (mode, nodes) = if flags & MPOL_F_MEMS_ALLOWED != 0 {
        if flags & (MPOL_F_NODE | MPOL_F_ADDR) != 0 {
            return err(Errno::EINVAL);
        }
        (0, NODES)
    } else {
        let task = c.group.numa().task(c.tid);
        let policy = if flags & MPOL_F_ADDR != 0 {
            let Some(mapping) = c
                .mem
                .mappings()
                .find(|m| m.start.0 <= addr && addr < m.end())
            else {
                return err(Errno::EFAULT);
            };
            let policy = c
                .group
                .numa()
                .ranges()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .at(addr);
            // The node of the page, which is brought in: one that cannot
            // be is EFAULT.
            if flags & MPOL_F_NODE != 0 && mapping.prot == Prot::NONE {
                return err(Errno::EFAULT);
            }
            policy
        } else if addr != 0 {
            return err(Errno::EINVAL);
        } else {
            task.clone()
        };
        let mode = if flags & MPOL_F_NODE != 0 {
            let interleaved = flags & MPOL_F_ADDR == 0
                && task.is_some()
                && matches!(
                    policy.as_ref().map(|p| p.mode),
                    Some(MPOL_INTERLEAVE | MPOL_WEIGHTED_INTERLEAVE)
                );
            if flags & MPOL_F_ADDR == 0 && !interleaved {
                return err(Errno::EINVAL);
            }
            // Every page and every next interleaved one is on node 0.
            0
        } else {
            policy
                .as_ref()
                .map_or(MPOL_DEFAULT, |p| p.mode | p.flags & MPOL_MODE_FLAGS)
        };
        let nodes = match &policy {
            Some(p) if p.flags & (MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES) != 0 => p.user[0],
            Some(p) => p.nodes,
            None => 0,
        };
        (mode, nodes)
    };
    if mode_at != 0
        && c.mem
            .write(GuestAddr(mode_at), &mode.to_le_bytes())
            .is_err()
    {
        return err(Errno::EFAULT);
    }
    if mask_at != 0 {
        // copy_nodes_to_user: the bits asked for, up to the word of
        // nr_node_ids, and zeros up to a page past it.
        let mut copy = (maxnode.wrapping_sub(1)).next_multiple_of(64) / 8;
        let bytes = NODE_IDS.div_ceil(64) * 8;
        if copy > bytes {
            if copy > 4096 {
                return err(Errno::EINVAL);
            }
            let zeros = vec![0u8; (copy - bytes) as usize];
            if c.mem
                .write(GuestAddr(mask_at.wrapping_add(bytes)), &zeros)
                .is_err()
            {
                return err(Errno::EFAULT);
            }
            copy = bytes;
        }
        let word = nodes.to_le_bytes();
        if c.mem
            .write(GuestAddr(mask_at), &word[..copy as usize])
            .is_err()
        {
            return err(Errno::EFAULT);
        }
    }
    ok(0)
}

/// `mbind(addr, len, mode, nodemask, maxnode, flags)`, as Linux's `do_mbind`:
/// the policy of the mapped pages of `[addr, addr + len)`. With every page
/// on node 0 none needs moving, so `MPOL_MF_STRICT` and `MPOL_MF_MOVE` find
/// nothing to report.
pub(crate) fn sys_mbind(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (start, len, flags) = (a[0], a[1], a[5]);
    let (mode, mode_flags) = match sanitize(a[2]) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    let mask = match nodes(c.mem, a[3], a[4]) {
        Ok(m) => m,
        Err(e) => return err(e),
    };
    if flags & !(MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_MOVE_ALL) != 0 {
        return err(Errno::EINVAL);
    }
    // MPOL_MF_MOVE_ALL needs CAP_SYS_NICE.
    if flags & MPOL_MF_MOVE_ALL != 0 && !c.process.credentials.capable(1 << 23) {
        return err(Errno::EPERM);
    }
    if start & 4095 != 0 {
        return err(Errno::EINVAL);
    }
    let len = len.wrapping_add(4095) & !4095;
    let Some(end) = start.checked_add(len) else {
        return err(Errno::EINVAL);
    };
    if end == start {
        return ok(0);
    }
    let policy = match policy(mode, mode_flags, &mask) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    // queue_pages_range: a hole is EFAULT, except for the default policy,
    // which only needs some mapping in the range.
    let mut mappings: Vec<_> = c
        .mem
        .mappings()
        .filter(|m| m.start.0 < end && m.end() > start)
        .map(|m| (m.start.0, m.end()))
        .collect();
    mappings.sort_unstable();
    if mappings.is_empty() {
        return err(Errno::EFAULT);
    }
    if policy.is_some() {
        let mut covered = start;
        for (s, e) in &mappings {
            if *s > covered {
                return err(Errno::EFAULT);
            }
            covered = covered.max(*e);
        }
        if covered < end {
            return err(Errno::EFAULT);
        }
    }
    let ranges = c.group.numa().ranges();
    let mut ranges = ranges.lock().unwrap_or_else(PoisonError::into_inner);
    for (s, e) in mappings {
        ranges.set(s.max(start), e.min(end), policy.clone());
    }
    ok(0)
}

/// `set_mempolicy_home_node(start, len, home_node, flags)`, as Linux's: a
/// misaligned start, any flag, or a node that is not online (only node 0
/// is) is `EINVAL`, and so is a range that wraps; an empty one does
/// nothing. Then each VMA of the range with a policy of its own takes the
/// home node, which must be one of `MPOL_BIND` or `MPOL_PREFERRED_MANY`
/// (`EOPNOTSUPP`, which stops there); with none such it is `ENOENT`. Every
/// page is on node 0 whatever the home node, and `get_mempolicy` does not
/// report it, so it is not kept.
pub(crate) fn sys_set_mempolicy_home_node(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let (start, len, home, flags) = (a[0], a[1], a[2], a[3]);
    if start & 4095 != 0 || flags != 0 || home >= NODE_IDS {
        return err(Errno::EINVAL);
    }
    let end = start.wrapping_add(len.wrapping_add(4095) & !4095);
    if end < start {
        return err(Errno::EINVAL);
    }
    if end == start {
        return ok(0);
    }
    // The policies are kept only where something is mapped, a VMA's
    // whole and cut at its ends, as Linux's VMAs are by their policies.
    let ranges = c.group.numa().ranges();
    let ranges = ranges.lock().unwrap_or_else(PoisonError::into_inner);
    let mut found = false;
    for (_, _, policy) in ranges.within(start, end) {
        if policy.mode != MPOL_BIND && policy.mode != MPOL_PREFERRED_MANY {
            return err(Errno::EOPNOTSUPP);
        }
        found = true;
    }
    if found { ok(0) } else { err(Errno::ENOENT) }
}

/// `migrate_pages`'s two node masks, `old` and `new`, each of `maxnode`
/// bits, read as `kernel_migrate_pages` reads them before it looks for the
/// task.
pub(crate) fn migration_masks(
    mem: &AddressSpace,
    old: u64,
    new: u64,
    maxnode: u64,
) -> Result<(NodeMask, NodeMask), Errno> {
    Ok((nodes(mem, old, maxnode)?, nodes(mem, new, maxnode)?))
}

/// The rest of `kernel_migrate_pages` once the caller may read the task:
/// nodes in `new` that the task may not use (only node 0 is) need
/// `CAP_SYS_NICE` (`nice`, `EPERM`), and with none the caller may use it
/// is `EINVAL`. No page needs moving off node 0, so none is left behind.
pub(crate) fn migration_targets(new: &NodeMask, nice: bool) -> Result<(), Errno> {
    let outside = new[0] & !NODES != 0 || new[1..].iter().any(|word| *word != 0);
    if outside && !nice {
        return Err(Errno::EPERM);
    }
    if new[0] & NODES == 0 {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// `move_pages`'s status for the page at `addr` of `target`, as Linux's
/// `do_pages_stat_array` and `add_folio_for_migration` give it, the page
/// being on node 0 already: `EFAULT` where no VMA is or for the zero page,
/// `ENOENT` for no page, else node 0.
fn page_status(target: &MemoryView, addr: u64) -> i32 {
    match target.page_state(addr) {
        None | Some(PageState::Zero) => -14,
        Some(PageState::Absent) => -2,
        Some(PageState::Present) => 0,
    }
}

/// `move_pages(pid, count, pages, nodes, status, flags)` once the task's
/// memory `target` is found, as Linux's `do_pages_move` and
/// `do_pages_stat`; `mem` holds the arrays. Without `nodes` the status of
/// each page is reported, `DO_PAGES_STAT_CHUNK_NR` (16) at a time: a chunk
/// of addresses that cannot be read or of statuses that cannot be written
/// ends the call with `EFAULT`, after the chunks before it. With `nodes`
/// each page's address and node are read in turn (`EFAULT`); a node out of
/// range or without memory (any but node 0) ends the call with `ENODEV`,
/// after the statuses stored before it. Every page is on node 0 already,
/// so none moves and each status is the page's ([`page_status`]).
pub(crate) fn move_pages(
    mem: &AddressSpace,
    target: &MemoryView,
    count: u64,
    pages: u64,
    nodes: u64,
    status: u64,
) -> Result<u64, Errno> {
    const CHUNK: u64 = 16;
    let store = |index: u64, value: i32| {
        mem.write(
            GuestAddr(status.wrapping_add(index * 4)),
            &value.to_le_bytes(),
        )
        .map_err(|_| Errno::EFAULT)
    };
    if nodes == 0 {
        let mut done = 0;
        while done < count {
            let n = (count - done).min(CHUNK);
            let mut addresses = vec![0u8; (n * 8) as usize];
            mem.read(GuestAddr(pages.wrapping_add(done * 8)), &mut addresses)
                .map_err(|_| Errno::EFAULT)?;
            let statuses: Vec<u8> = addresses
                .as_chunks::<8>()
                .0
                .iter()
                .flat_map(|addr| page_status(target, u64::from_le_bytes(*addr)).to_le_bytes())
                .collect();
            mem.write(GuestAddr(status.wrapping_add(done * 4)), &statuses)
                .map_err(|_| Errno::EFAULT)?;
            done += n;
        }
        return Ok(0);
    }
    for index in 0..count {
        let addr = mem
            .read_u64(GuestAddr(pages.wrapping_add(index * 8)))
            .map_err(|_| Errno::EFAULT)?;
        let mut node = [0u8; 4];
        mem.read(GuestAddr(nodes.wrapping_add(index * 4)), &mut node)
            .map_err(|_| Errno::EFAULT)?;
        if i32::from_le_bytes(node) != 0 {
            return Err(Errno::ENODEV);
        }
        store(index, page_status(target, addr))?;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bind(nodes: u64) -> MemPolicy {
        policy(
            MPOL_BIND,
            0,
            &[nodes, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn a_mask_at_the_top_of_the_address_space_faults() {
        let mem = AddressSpace::new();
        // Past MAX_NUMNODES the last word is read first, at a sum that
        // wraps around.
        assert_eq!(nodes(&mem, u64::MAX - 7, 2000), Err(Errno::EFAULT));
        assert_eq!(nodes(&mem, u64::MAX - 7, 200), Err(Errno::EFAULT));
    }

    #[test]
    fn policies_keep_node_zero() {
        let mut m = [0u64; WORDS];
        assert_eq!(policy(MPOL_DEFAULT, 0, &m), Ok(None));
        assert_eq!(policy(MPOL_BIND, 0, &m), Err(Errno::EINVAL));
        assert_eq!(
            policy(MPOL_PREFERRED, 0, &m).unwrap().unwrap().mode,
            MPOL_LOCAL
        );
        assert_eq!(
            policy(MPOL_PREFERRED, MPOL_F_STATIC_NODES, &m),
            Err(Errno::EINVAL)
        );
        m[0] = 0b10;
        assert_eq!(policy(MPOL_BIND, 0, &m), Err(Errno::EINVAL));
        assert_eq!(policy(MPOL_DEFAULT, 0, &m), Err(Errno::EINVAL));
        let relative = policy(MPOL_INTERLEAVE, MPOL_F_RELATIVE_NODES, &m)
            .unwrap()
            .unwrap();
        assert_eq!((relative.nodes, relative.user[0]), (1, 0b10));
        m[0] = 0b11;
        assert_eq!(bind(0b11).nodes, 1);
        assert_eq!(policy(MPOL_LOCAL, 0, &m), Err(Errno::EINVAL));
    }

    #[test]
    fn sanitize_checks_modes_and_flags() {
        assert_eq!(sanitize(7), Err(Errno::EINVAL));
        assert_eq!(
            sanitize(u64::from(MPOL_BIND | MPOL_F_NUMA_BALANCING)),
            Ok((MPOL_BIND, MPOL_F_NUMA_BALANCING))
        );
        assert_eq!(
            sanitize(u64::from(MPOL_INTERLEAVE | MPOL_F_NUMA_BALANCING)),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            sanitize(u64::from(
                MPOL_BIND | MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES
            )),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn ranges_split_and_move() {
        let mut r = Ranges::default();
        r.set(0x1000, 0x5000, Some(bind(1)));
        r.set(0x2000, 0x3000, None);
        assert!(r.at(0x1fff).is_some() && r.at(0x2000).is_none() && r.at(0x3000).is_some());
        assert!(r.at(0x5000).is_none());
        let numa = Numa::default();
        *numa.ranges.lock().unwrap() = Arc::new(Mutex::new(r));
        numa.moved(0x3000, 0x2000, 0x10000, 0x3000, false);
        let ranges = numa.ranges();
        let r = ranges.lock().unwrap();
        assert!(r.at(0x3000).is_none() && r.at(0x10000).is_some() && r.at(0x12fff).is_some());
        assert!(r.at(0x13000).is_none() && r.at(0x1000).is_some());
    }
}
