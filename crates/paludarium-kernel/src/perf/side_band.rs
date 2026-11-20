//! The side-band records, as Linux's `kernel/events/core.c` writes them
//! to the buffers of the events that ask for them: `PERF_RECORD_MMAP` and
//! `MMAP2` of a mapping (`perf_event_mmap`), `COMM` of a new name
//! (`perf_event_comm`), and `FORK` and `EXIT` of a task
//! (`perf_event_task`). Each goes to the enabled events that count the
//! thread that writes it (`perf_iterate_sb`), through the buffer that
//! event writes to, with the `sample_id` of that thread.

use super::sample::{Who, header, put};
use super::{Event, Events, bit, lock};
use crate::ThreadGroup;
use paludarium_mmu::{AddressSpace, Vma, vm};
use std::sync::Arc;
use std::sync::atomic::Ordering;

const RECORD_MMAP: u32 = 1;
const RECORD_COMM: u32 = 3;
const RECORD_EXIT: u32 = 4;
const RECORD_FORK: u32 = 7;
const RECORD_MMAP2: u32 = 10;

const MISC_USER: u16 = 2;
const MISC_COMM_EXEC: u16 = 1 << 13;
const MISC_MMAP_DATA: u16 = 1 << 13;

const PROT_READ: u32 = 1;
const PROT_WRITE: u32 = 2;
const PROT_EXEC: u32 = 4;
const MAP_SHARED: u32 = 1;
const MAP_PRIVATE: u32 = 2;
const MAP_LOCKED: u32 = 0x2000;

/// Whether `attr` asks for any side-band record
/// (`account_pmu_sb_event`'s and `perf_event_task_match`'s bits).
pub(super) fn asks(attr: &super::Attr) -> bool {
    [bit::MMAP, bit::COMM, bit::TASK, bit::MMAP_DATA, bit::MMAP2]
        .iter()
        .any(|&b| attr.flag(b))
}

/// Whether an event that asks for side-band records has been opened, so
/// that the hooks look for receivers only then (Linux's
/// `nr_mmap_events`, `nr_comm_events` and `nr_task_events`).
pub(crate) fn wanted(events: &Events) -> bool {
    events.side_band.load(Ordering::Relaxed)
}

/// The enabled events that count thread `tid` of `group` and that `wants`
/// picks, on the CPU of `who` (`perf_iterate_ctx`'s state and
/// `event_filter_match`).
fn receivers(
    events: &Events,
    group: &ThreadGroup,
    tid: u32,
    who: &Who,
    wants: impl Fn(&super::Attr) -> bool,
) -> Vec<Arc<Event>> {
    if !wanted(events) {
        return Vec::new();
    }
    lock(&events.lists)
        .counting
        .iter()
        .filter_map(super::event)
        .filter(|event| {
            wants(&event.attr)
                && event.counts(group, tid)
                && (event.cpu < 0 || event.cpu as u32 == who.cpu)
                && {
                    let state = lock(&event.state);
                    state.enabled && !state.removed
                }
        })
        .collect()
}

impl Event {
    /// Writes a record of `kind` and `misc` with `body` after its header
    /// and the `sample_id` of `who` after that, to the buffer the event
    /// writes to; a wakeup it makes signals for `O_ASYNC` as one of a
    /// sample does (`perf_output_wakeup`'s `pending_kill`).
    fn side_band(self: &Arc<Self>, kind: u32, misc: u16, body: &[u8], who: &Who) {
        let Some(top) = self.top() else {
            return;
        };
        let Some(rb) = lock(&top.rb).clone() else {
            return;
        };
        let trailer = self.id_sample_of(who);
        let size = 8 + body.len() + trailer.len();
        let mut record = Vec::with_capacity(size);
        header(&mut record, kind, misc, size);
        record.extend_from_slice(body);
        record.extend_from_slice(&trailer);
        if rb.output(&top, &record, &[], 1, &trailer, 0) {
            top.signal_owner(0, false, true);
        }
    }
}

/// A name as `perf_event_comm_event` and `perf_event_mmap_event` copy it:
/// up to its NUL, with a NUL after it and up to the next 8 bytes.
fn padded(name: &[u8]) -> Vec<u8> {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let mut out = name[..end].to_vec();
    out.push(0);
    out.resize(out.len().next_multiple_of(8), 0);
    out
}

/// `perf_event_comm`: thread `tid` of process `pid` is named `name`, by
/// thread `who` of `group` (itself, or a writer of its `comm`), and for
/// `exec` by an `execve` (`PERF_RECORD_MISC_COMM_EXEC`).
pub(crate) fn comm(
    events: &Events,
    group: &ThreadGroup,
    who: &Who,
    (pid, tid): (u32, u32),
    name: &[u8],
    exec: bool,
) {
    comm_from(events, group, who.tid, who, (pid, tid), name, exec);
}

/// The same, to the events that count thread `counted` of `group`.
fn comm_from(
    events: &Events,
    group: &ThreadGroup,
    counted: u32,
    who: &Who,
    (pid, tid): (u32, u32),
    name: &[u8],
    exec: bool,
) {
    let name = padded(&name[..name.len().min(15)]);
    let misc = if exec { MISC_COMM_EXEC } else { 0 };
    for event in receivers(events, group, counted, who, |attr| attr.flag(bit::COMM)) {
        let mut body = event.pid_tid_of(pid, tid).to_vec();
        body.extend_from_slice(&name);
        event.side_band(RECORD_COMM, misc, &body, who);
    }
}

/// `perf_event_fork`: thread `who` of `group` made thread `child_tid` of
/// process `child_pid`.
pub(super) fn fork(
    events: &Events,
    group: &ThreadGroup,
    who: &Who,
    child_pid: u32,
    child_tid: u32,
) {
    for event in receivers(events, group, who.tid, who, asks) {
        // `pid`, `ppid`, `tid`, `ptid`.
        let mut body = event.pid_tid_of(child_pid, who.pid).to_vec();
        body.extend_from_slice(&event.pid_tid_of(child_tid, who.tid));
        put(&mut body, event.clock_now());
        event.side_band(RECORD_FORK, 0, &body, who);
    }
}

/// `perf_event_exit_task`'s `PERF_RECORD_EXIT`: thread `who` of `group`
/// ends, a thread of the process whose parent is `ppid`, which the record
/// gives as both the parent process and thread (`real_parent`).
pub(super) fn exit(events: &Events, group: &ThreadGroup, who: &Who, ppid: u32) {
    for event in receivers(events, group, who.tid, who, asks) {
        // `pid`, `ppid`, `tid`, `ptid`.
        let mut body = event.pid_tid_of(who.pid, ppid).to_vec();
        body.extend_from_slice(&event.pid_tid_of(who.tid, ppid));
        put(&mut body, event.clock_now());
        event.side_band(RECORD_EXIT, 0, &body, who);
    }
}

/// What a VMA's records say of it: `perf_event_mmap_event`'s.
struct Mapping {
    start: u64,
    len: u64,
    pgoff: u64,
    exec: bool,
    major: u32,
    minor: u32,
    inode: u64,
    prot: u32,
    flags: u32,
    name: Vec<u8>,
}

impl Mapping {
    /// `vma` of an address space whose stack starts at `start_stack`,
    /// its file named as `d_path` gives it from `root`, and named the heap
    /// for `heap` (`vma_is_initial_heap`).
    fn of(vma: &Vma, start_stack: u64, root: &[u8], heap: bool) -> Self {
        let (device, inode) = vma.identity;
        // `MAJOR` and `MINOR` of the device `stat` encodes, as glibc's
        // `major` and `minor` take them apart.
        let major = (((device >> 8) & 0xfff) | ((device >> 32) & 0xffff_f000)) as u32;
        let mut minor = ((device & 0xff) | ((device >> 12) & 0xffff_ff00)) as u32;
        let name: Vec<u8> = match &vma.file {
            Some(file) if file.source => {
                let name = file.name.as_deref().unwrap_or_default();
                crate::files::seen_from(root, name).unwrap_or_else(|| name.to_vec())
            }
            Some(_) => {
                // Shared anonymous memory's file, on Linux's first device.
                minor = 1;
                b"/dev/zero (deleted)".to_vec()
            }
            None if heap => b"[heap]".to_vec(),
            None if vma.start <= start_stack && vma.end >= start_stack => b"[stack]".to_vec(),
            None => b"//anon".to_vec(),
        };
        let flag = |f: u64, p: u32| if vma.flags & f != 0 { p } else { 0 };
        let mut flags = if vma.flags & vm::MAYSHARE != 0 {
            MAP_SHARED
        } else {
            MAP_PRIVATE
        };
        flags |= flag(vm::LOCKED, MAP_LOCKED);
        Self {
            start: vma.start,
            len: vma.end - vma.start,
            // `vm_pgoff`: a file's offset, and for private anonymous
            // memory its address.
            pgoff: if vma.file.is_some() {
                vma.offset
            } else {
                vma.start
            },
            exec: vma.flags & vm::EXEC != 0,
            major,
            minor,
            inode,
            prot: flag(vm::READ, PROT_READ)
                | flag(vm::WRITE, PROT_WRITE)
                | flag(vm::EXEC, PROT_EXEC),
            flags,
            name: padded(&name),
        }
    }
    /// `perf_event_mmap_match`.
    fn wanted_by(&self, attr: &super::Attr) -> bool {
        if self.exec {
            attr.flag(bit::MMAP) || attr.flag(bit::MMAP2)
        } else {
            attr.flag(bit::MMAP_DATA)
        }
    }
    /// `perf_event_mmap_output` for `event`, by thread `who`: a build ID
    /// is never given (`PERF_RECORD_MISC_MMAP_BUILD_ID`), as if none were
    /// found, and the inode's generation is 0.
    fn write(&self, event: &Arc<Event>, who: &Who) {
        let mut body = event.pid_tid_of(who.pid, who.tid).to_vec();
        put(&mut body, self.start);
        put(&mut body, self.len);
        put(&mut body, self.pgoff);
        let mut misc = MISC_USER;
        if !self.exec {
            misc |= MISC_MMAP_DATA;
        }
        let kind = if event.attr.flag(bit::MMAP2) {
            body.extend(self.major.to_le_bytes());
            body.extend(self.minor.to_le_bytes());
            put(&mut body, self.inode);
            put(&mut body, 0);
            body.extend(self.prot.to_le_bytes());
            body.extend(self.flags.to_le_bytes());
            RECORD_MMAP2
        } else {
            RECORD_MMAP
        };
        body.extend_from_slice(&self.name);
        event.side_band(kind, misc, &body, who);
    }
}

/// Where a thread's records of its mappings come from: its address space,
/// its group's stack and its process's root.
pub(crate) struct Space<'a> {
    pub(crate) group: &'a ThreadGroup,
    pub(crate) who: Who,
    pub(crate) mem: &'a AddressSpace,
    pub(crate) root: &'a [u8],
}

impl Space<'_> {
    /// The enabled events that count the thread and want some record of a
    /// mapping, `None` for none.
    fn receivers(&self, events: &Events) -> Option<Vec<Arc<Event>>> {
        let wants = |attr: &super::Attr| {
            attr.flag(bit::MMAP) || attr.flag(bit::MMAP2) || attr.flag(bit::MMAP_DATA)
        };
        let events = receivers(events, self.group, self.who.tid, &self.who, wants);
        (!events.is_empty()).then_some(events)
    }
    /// The records of `vmas` to `events`, each to those that want it; with
    /// `old_break`, the break was there when they were written, as `brk`
    /// sets the new one only after `do_brk_flags`.
    fn write(
        &self,
        events: &[Arc<Event>],
        vmas: impl IntoIterator<Item = Vma>,
        old_break: Option<u64>,
    ) {
        let start_stack = self.group.start_stack();
        for vma in vmas {
            let heap = vma.heap && old_break.is_none_or(|old| vma.start < old);
            let mapping = Mapping::of(&vma, start_stack, self.root, heap);
            Self::write_one(events, &mapping, &self.who);
        }
    }
    fn write_one(events: &[Arc<Event>], mapping: &Mapping, who: &Who) {
        for event in events.iter().filter(|event| mapping.wanted_by(&event.attr)) {
            mapping.write(event, who);
        }
    }
    /// The VMAs that cover any of `start..end`, in order.
    fn vmas(&self, start: u64, end: u64) -> Vec<Vma> {
        let view = self.mem.view();
        let mut out = Vec::new();
        let mut at = start;
        while at < end {
            let Some(vma) = view.vma_from(at) else {
                break;
            };
            if vma.start >= end {
                break;
            }
            at = vma.end;
            out.push(vma);
        }
        out
    }
}

/// `perf_event_mmap` of the VMA that now holds `addr`, as `mmap`, `brk`'s
/// growth (from `old_break`), `shmat` and `remap_file_pages` make it: the
/// whole VMA, as it merged with its neighbours.
pub(crate) fn mapped(events: &Events, space: &Space<'_>, addr: u64, old_break: Option<u64>) {
    let Some(receivers) = space.receivers(events) else {
        return;
    };
    let vma = space
        .mem
        .view()
        .vma_from(addr)
        .filter(|vma| vma.start <= addr);
    space.write(&receivers, vma, old_break);
}

/// The protections of the VMAs over `start..end` before `mprotect`
/// changes them, for [`reprotected`]; `None` when no event wants them.
pub(crate) fn protections(
    events: &Events,
    space: &Space<'_>,
    start: u64,
    end: u64,
) -> Option<Vec<(u64, u64, u64)>> {
    space.receivers(events)?;
    Some(
        space
            .vmas(start, end)
            .into_iter()
            .map(|vma| {
                (
                    vma.start.max(start),
                    vma.end.min(end),
                    vma.flags & PROTECTION,
                )
            })
            .collect(),
    )
}

/// `vm_flags`' protection bits.
const PROTECTION: u64 = vm::READ | vm::WRITE | vm::EXEC;

/// `mprotect_fixup`'s `perf_event_mmap`: each VMA over `start..end` whose
/// protection the call changed, as it now is, merged with its neighbours.
pub(crate) fn reprotected(
    events: &Events,
    space: &Space<'_>,
    start: u64,
    end: u64,
    before: Option<Vec<(u64, u64, u64)>>,
) {
    let Some(before) = before else {
        return;
    };
    let Some(receivers) = space.receivers(events) else {
        return;
    };
    let changed = space.vmas(start, end).into_iter().filter(|vma| {
        before.iter().any(|&(from, to, flags)| {
            from < vma.end && to > vma.start && flags != vma.flags & PROTECTION
        })
    });
    space.write(&receivers, changed, None);
}

/// What an `execve` writes once it has loaded the program: `COMM` of the
/// program's name, and then the new address space's mappings. First come
/// the stack's two of `setup_arg_pages`: its `mprotect_fixup` of the
/// temporary stack, at the top of user space and holding the arguments,
/// before the stack has a name (`//anon`), and its growth to where it is
/// (`[stack]`). The loader's mappings follow in the order of their
/// addresses.
pub(super) fn exec(events: &Events, space: &Space<'_>, counted: u32, name: &[u8]) {
    let who = space.who;
    comm_from(
        events,
        space.group,
        counted,
        &who,
        (who.pid, who.tid),
        name,
        true,
    );
    let wants = |attr: &super::Attr| {
        attr.flag(bit::MMAP) || attr.flag(bit::MMAP2) || attr.flag(bit::MMAP_DATA)
    };
    let receivers = receivers(events, space.group, counted, &who, wants);
    if receivers.is_empty() {
        return;
    }
    let start_stack = space.group.start_stack();
    let (stack, rest): (Vec<Vma>, Vec<Vma>) = space
        .vmas(0, u64::MAX)
        .into_iter()
        .partition(|vma| vma.file.is_none() && vma.start <= start_stack && vma.end >= start_stack);
    for vma in &stack {
        // Linux's `STACK_TOP_MAX` with 4-level page tables.
        const TOP: u64 = 0x7fff_ffff_f000;
        let len = vma
            .end
            .saturating_sub(start_stack & !0xfff)
            .clamp(4096, TOP);
        let temporary = Vma {
            start: TOP - len,
            end: TOP,
            ..vma.clone()
        };
        let mapping = Mapping::of(&temporary, 0, space.root, false);
        Space::write_one(&receivers, &mapping, &who);
    }
    space.write(&receivers, stack.into_iter().chain(rest), None);
}

#[cfg(test)]
mod tests {
    use super::*;
    use paludarium_mmu::{MappedFile, Prot};

    fn vma(start: u64, end: u64, flags: u64, file: Option<MappedFile>) -> Vma {
        Vma {
            start,
            end,
            prot: Prot::READ,
            shared: flags & vm::MAYSHARE != 0,
            offset: file.as_ref().map_or(0, |file| file.offset),
            file,
            identity: (0x803, 42),
            heap: false,
            flags,
        }
    }

    #[test]
    fn a_name_ends_with_a_nul_and_fills_its_last_8_bytes() {
        assert_eq!(padded(b"abc"), b"abc\0\0\0\0\0");
        assert_eq!(padded(b"1234567"), b"1234567\0");
        assert_eq!(padded(b"12345678"), b"12345678\0\0\0\0\0\0\0\0");
        assert_eq!(padded(b"ab\0cd"), b"ab\0\0\0\0\0\0");
    }

    #[test]
    fn private_anonymous_memory_is_at_its_own_address_and_named_anon() {
        let m = Mapping::of(
            &vma(0x10000, 0x13000, vm::READ | vm::WRITE, None),
            0,
            b"/",
            false,
        );
        assert_eq!((m.start, m.len, m.pgoff), (0x10000, 0x3000, 0x10000));
        assert_eq!(
            (m.prot, m.flags, m.exec),
            (PROT_READ | PROT_WRITE, MAP_PRIVATE, false)
        );
        assert_eq!(m.name, padded(b"//anon"));
        let stack = Mapping::of(&vma(0x10000, 0x13000, vm::READ, None), 0x12000, b"/", false);
        assert_eq!(stack.name, padded(b"[stack]"));
    }

    #[test]
    fn a_file_has_its_offset_device_inode_and_path_from_the_root() {
        let file = MappedFile {
            name: Some(b"/jail/lib/x".to_vec()),
            source: true,
            offset: 0x2000,
        };
        let flags = vm::READ | vm::EXEC | vm::MAYSHARE | vm::LOCKED;
        let m = Mapping::of(
            &vma(0x40_0000, 0x40_1000, flags, Some(file)),
            0,
            b"/jail",
            false,
        );
        assert_eq!(m.pgoff, 0x2000);
        assert_eq!((m.major, m.minor, m.inode), (8, 3, 42));
        let big = Vma {
            identity: (0x0000_1234_5678_9abc, 1),
            ..vma(0, 0x1000, vm::READ, None)
        };
        let wide = Mapping::of(&big, 0, b"/", false);
        // glibc's `major` (bits 8 to 19 and 44 up) and `minor` (bits 0 to 7
        // and 20 to 43).
        assert_eq!((wide.major, wide.minor), (0x189a, 0x2345_67bc));
        assert_eq!(
            (m.prot, m.flags, m.exec),
            (PROT_READ | PROT_EXEC, MAP_SHARED | MAP_LOCKED, true)
        );
        assert_eq!(m.name, padded(b"/lib/x"));
        let shared = MappedFile {
            name: None,
            source: false,
            offset: 0,
        };
        let m = Mapping::of(
            &vma(0, 0x1000, vm::READ | vm::MAYSHARE, Some(shared)),
            0,
            b"/",
            false,
        );
        assert_eq!(
            (m.minor, &m.name[..]),
            (1, &padded(b"/dev/zero (deleted)")[..])
        );
    }
}
