//! The only /proc files paludarium has, generated when opened: the mount
//! table (`/proc/self/mountinfo`, `/proc/mounts`) from the filesystem's
//! mounts, and this process's directory with its `status`, its `fd`
//! directory of links to the open descriptors, and its `maps`, which alone
//! is generated as it is read.
use paludarium_host::{FileHandle, FileStat};
use paludarium_mmu::{MemoryView, Prot, Vma};
use paludarium_types::Errno;
use paludarium_vfs::MountPoint;
use std::sync::{Mutex, PoisonError};

/// What `stat` reports for one of these files: a regular 0444 file. Linux's
/// /proc reports size 0; this reports the real length, because reads of a
/// regular file stop at its size.
pub(crate) fn stat(length: usize) -> FileStat {
    FileStat {
        size: length as u64,
        mode: 0o100_444,
        links: 1,
        ..FileStat::default()
    }
}
/// The paths served, and whether each one is the mountinfo format.
pub(crate) fn mount_table(path: &[u8]) -> Option<bool> {
    match path {
        b"/proc/self/mountinfo" => Some(true),
        b"/proc/self/mounts" | b"/proc/mounts" => Some(false),
        _ => None,
    }
}

/// This process's own /proc entries, under `/proc/self` or `/proc/<pid>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnEntry {
    Directory,
    Status,
    Maps,
    /// `fd`, and one of its links by descriptor number.
    Descriptors,
    Descriptor(u32),
}
pub(crate) fn own_entry(path: &[u8], pid: u32) -> Option<OwnEntry> {
    let rest = path.strip_prefix(b"/proc/")?;
    let (head, tail) = rest
        .iter()
        .position(|&b| b == b'/')
        .map_or((rest, &b""[..]), |at| (&rest[..at], &rest[at..]));
    if head != b"self" && head != pid.to_string().as_bytes() {
        return None;
    }
    match tail {
        b"" | b"/" => Some(OwnEntry::Directory),
        b"/status" => Some(OwnEntry::Status),
        b"/maps" => Some(OwnEntry::Maps),
        b"/fd" | b"/fd/" => Some(OwnEntry::Descriptors),
        _ => descriptor_number(tail.strip_prefix(b"/fd/")?).map(OwnEntry::Descriptor),
    }
}
/// A descriptor's name in `fd`: decimal digits without a leading zero (but
/// "0"), within `u32`, as Linux's name_to_int reads them; a trailing slash
/// is allowed.
fn descriptor_number(name: &[u8]) -> Option<u32> {
    let name = name.strip_suffix(b"/").unwrap_or(name);
    if name.is_empty() || name.len() > 1 && name[0] == b'0' || !name.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    std::str::from_utf8(name).ok()?.parse().ok()
}
/// The `fd` directory's `stat`: 0500 and owned, as Linux shows it.
pub(crate) fn descriptors_stat() -> FileStat {
    FileStat {
        mode: 0o040_500,
        links: 2,
        ..FileStat::default()
    }
}
/// The `lstat` of a link in `fd`: user permissions for the descriptor's
/// access (read gives r-x, write -wx), and size 64, as Linux shows them.
pub(crate) fn link_stat(access: u32) -> FileStat {
    let mut mode = 0o120_000;
    if access != 1 {
        mode |= 0o500;
    }
    if access != 0 {
        mode |= 0o300;
    }
    FileStat {
        mode,
        links: 1,
        size: 64,
        ..FileStat::default()
    }
}
/// `/proc/self` not followed: a symbolic link (0777) to this process's
/// directory, as Linux's `proc_self_get_link` makes it, of size 0.
pub(crate) fn self_link_stat() -> FileStat {
    FileStat {
        mode: 0o120_777,
        links: 1,
        ..FileStat::default()
    }
}
/// The directory's `stat`: 0555, as Linux shows it.
pub(crate) fn directory_stat() -> FileStat {
    FileStat {
        mode: 0o040_555,
        links: 2,
        ..FileStat::default()
    }
}

/// What `/proc/self/status` reports.
pub(crate) struct Status<'a> {
    pub name: &'a [u8],
    pub umask: u32,
    pub pid: u32,
    pub parent: u32,
    pub descriptors: usize,
    pub threads: usize,
    pub queued: usize,
    pub queue_limit: u64,
    pub pending: u64,
    pub blocked: u64,
    pub ignored: u64,
    pub caught: u64,
    pub no_new_privs: bool,
    pub credentials: &'a crate::credentials::Credentials,
}
/// `/proc/<pid>/status` in Linux's field order. The memory and CPU fields
/// are left out, as nothing measures them; parsers treat them as optional.
pub(crate) fn render_status(s: &Status<'_>) -> Vec<u8> {
    let mut name = String::new();
    for &b in s.name.iter().take_while(|&&b| b != 0) {
        match b {
            b'\\' => name.push_str("\\\\"),
            b'\n' => name.push_str("\\n"),
            _ => name.push(char::from(b)),
        }
    }
    // Linux sizes the descriptor table in powers of two from 64.
    let fd_size = s.descriptors.next_power_of_two().max(64);
    let pid = s.pid;
    let c = s.credentials;
    // Each group, then a space Linux has always written after them.
    let groups: Vec<String> = c.groups.iter().map(u32::to_string).collect();
    let groups = groups.join(" ");
    let bounding = crate::credentials::ALL_CAPABILITIES;
    format!(
        "Name:\t{name}\nUmask:\t{:04o}\nState:\tR (running)\nTgid:\t{pid}\nNgid:\t0\n\
         Pid:\t{pid}\nPPid:\t{}\nTracerPid:\t0\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\n\
         FDSize:\t{fd_size}\nGroups:\t{groups} \nThreads:\t{}\nSigQ:\t{}/{}\n\
         SigPnd:\t{:016x}\nShdPnd:\t{:016x}\nSigBlk:\t{:016x}\nSigIgn:\t{:016x}\n\
         SigCgt:\t{:016x}\nCapInh:\t{:016x}\nCapPrm:\t{:016x}\n\
         CapEff:\t{:016x}\nCapBnd:\t{bounding:016x}\nCapAmb:\t{:016x}\n\
         NoNewPrivs:\t{}\nSeccomp:\t0\nSeccomp_filters:\t0\n\
         voluntary_ctxt_switches:\t0\nnonvoluntary_ctxt_switches:\t0\n",
        s.umask & 0o777,
        s.parent,
        c.uid,
        c.euid,
        c.suid,
        c.fsuid,
        c.gid,
        c.egid,
        c.sgid,
        c.fsgid,
        s.threads,
        s.queued,
        s.queue_limit,
        s.pending,
        0,
        s.blocked,
        s.ignored,
        s.caught,
        c.inheritable,
        c.permitted,
        c.effective,
        0,
        u8::from(s.no_new_privs),
    )
    .into_bytes()
}

/// One of this process's generated directories (`/proc/self`, whose entries
/// procfs readers open relative to it, and its `fd`), with its `stat` and
/// the position `getdents` has reached in it.
pub(crate) struct OwnDirectory {
    stat: FileStat,
    position: Mutex<u64>,
}
impl OwnDirectory {
    pub(crate) fn new(stat: FileStat) -> Self {
        Self {
            stat,
            position: Mutex::new(0),
        }
    }
}
impl FileHandle for OwnDirectory {
    fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EISDIR)
    }
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EBADF)
    }
    /// From the start or the current entry; a directory has no end to seek
    /// from.
    fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno> {
        let mut position = self.position.lock().unwrap_or_else(PoisonError::into_inner);
        let base = match whence {
            0 => 0,
            1 => *position,
            _ => return Err(Errno::EINVAL),
        };
        *position = base.checked_add_signed(offset).ok_or(Errno::EINVAL)?;
        Ok(*position)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(self.stat)
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EISDIR)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        0o200000
    }
    fn set_flags(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
}

/// A mount path as /proc writes it: space, tab, newline and backslash octal.
fn escape(path: &[u8]) -> String {
    let mut out = String::new();
    for &b in path {
        match b {
            b' ' | b'\t' | b'\n' | b'\\' => out.push_str(&format!("\\{b:03o}")),
            _ => out.push(char::from(b)),
        }
    }
    out
}

/// `mountinfo` or `mounts` lines for `mounts`; each filesystem type is also
/// its source, so host paths are not shown.
pub(crate) fn render(mounts: &[MountPoint], mountinfo: bool) -> Vec<u8> {
    let mut out = String::new();
    for (i, mount) in mounts.iter().enumerate() {
        let path = escape(&mount.path);
        if mountinfo {
            let (id, parent) = (21 + i, if i == 0 { 1 } else { 21 });
            out.push_str(&format!(
                "{id} {parent} 0:{} / {path} rw,relatime - {kind} {kind} rw\n",
                i + 1,
                kind = mount.kind
            ));
        } else {
            out.push_str(&format!(
                "{kind} {path} {kind} rw,relatime 0 0\n",
                kind = mount.kind
            ));
        }
    }
    out.into_bytes()
}

/// A file whose contents were fixed when it was opened.
pub(crate) struct GeneratedFile {
    content: Vec<u8>,
    position: Mutex<usize>,
    writable: bool,
}
impl GeneratedFile {
    /// The files are 0444, but the guest is root, which may open them for
    /// writing anyway; the write itself then fails, as on Linux.
    pub(crate) fn open(content: Vec<u8>, flags: u32) -> Self {
        Self {
            content,
            position: Mutex::new(0),
            writable: flags & 3 != 0,
        }
    }
}
impl FileHandle for GeneratedFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let mut position = self.position.lock().unwrap_or_else(PoisonError::into_inner);
        let rest = self.content.get(*position..).unwrap_or(&[]);
        let count = buf.len().min(rest.len());
        buf[..count].copy_from_slice(&rest[..count]);
        *position += count;
        Ok(count)
    }
    /// These files have no write operation: EINVAL, or EBADF on a
    /// descriptor opened read-only.
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(if self.writable {
            Errno::EINVAL
        } else {
            Errno::EBADF
        })
    }
    fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno> {
        let mut position = self.position.lock().unwrap_or_else(PoisonError::into_inner);
        let base = match whence {
            0 => 0,
            1 => *position as i64,
            2 => self.content.len() as i64,
            _ => return Err(Errno::EINVAL),
        };
        let target = base
            .checked_add(offset)
            .filter(|t| *t >= 0)
            .ok_or(Errno::EINVAL)?;
        *position = usize::try_from(target).map_err(|_| Errno::EINVAL)?;
        Ok(target as u64)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(stat(self.content.len()))
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        0
    }
    fn set_flags(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
}

/// One line of `maps`, as Linux's `show_map_vma` writes it: the header with
/// a space after the inode, then, for a VMA with a name, spaces up to column
/// 72 and one more before it. A newline in a path is octal.
fn map_line(vma: &Vma, start_stack: u64) -> Vec<u8> {
    let flag = |prot: Prot, letter: char| {
        if vma.prot.contains(prot) { letter } else { '-' }
    };
    let (device, inode) = vma.identity;
    let (major, minor) = (
        (device >> 8) & 0xfff,
        (device & 0xff) | ((device >> 12) & !0xff),
    );
    // Shared anonymous memory's file lies on Linux's first device.
    let minor = match &vma.file {
        Some(file) if !file.source => 1,
        _ => minor,
    };
    let mut line = format!(
        "{:08x}-{:08x} {}{}{}{} {:08x} {major:02x}:{minor:02x} {inode} ",
        vma.start,
        vma.end,
        flag(Prot::READ, 'r'),
        flag(Prot::WRITE, 'w'),
        flag(Prot::EXEC, 'x'),
        if vma.shared { 's' } else { 'p' },
        vma.offset,
    )
    .into_bytes();
    let name: &[u8] = match &vma.file {
        Some(file) if file.source => file.name.as_deref().unwrap_or_default(),
        Some(_) => b"/dev/zero (deleted)",
        None if vma.heap => b"[heap]",
        None if vma.start <= start_stack && vma.end >= start_stack => b"[stack]",
        None => b"",
    };
    if !name.is_empty() {
        line.resize(line.len().max(MAPS_NAME_COLUMN), b' ');
        line.push(b' ');
        for &b in name {
            if b == b'\n' {
                line.extend_from_slice(b"\\012");
            } else {
                line.push(b);
            }
        }
    }
    line.push(b'\n');
    line
}
/// Where `maps` pads a line to before its name (Linux's width of
/// `25 + sizeof(void *) * 6 - 1`).
const MAPS_NAME_COLUMN: usize = 72;
/// How much a `read` of `maps` gathers: Linux's `seq_file` buffer, one page
/// until a single line needs more.
const MAPS_BUFFER: usize = 4096;
/// Past the last VMA, as Linux's `m_start` is told by its sentinel.
const MAPS_END: u64 = u64::MAX;

/// Where a reader of `maps` has got to, as Linux's `seq_file` keeps it.
struct MapsPosition {
    /// The bytes gathered but not yet read.
    pending: Vec<u8>,
    /// How far into `pending` the reader is.
    from: usize,
    /// The start of the next VMA to gather.
    next: u64,
    /// The file position.
    position: u64,
    /// The size of the buffer, which a long line doubles.
    buffer: usize,
}

/// `/proc/<pid>/maps`, generated as it is read from the VMAs of the address
/// space it was opened on: a read sees the mappings of that moment, from the
/// address it had reached, whatever they were when it was opened.
pub(crate) struct MapsFile {
    memory: MemoryView,
    start_stack: u64,
    writable: bool,
    position: Mutex<MapsPosition>,
}
impl MapsFile {
    pub(crate) fn open(memory: MemoryView, start_stack: u64, flags: u32) -> Self {
        Self {
            memory,
            start_stack,
            writable: flags & 3 != 0,
            position: Mutex::new(MapsPosition {
                pending: Vec::new(),
                from: 0,
                next: 0,
                position: 0,
                buffer: MAPS_BUFFER,
            }),
        }
    }
    /// The line of the VMA at `next` or after it, and where the next starts.
    fn take_line(&self, next: u64) -> Option<(Vec<u8>, u64)> {
        if next == MAPS_END {
            return None;
        }
        let vma = self.memory.vma_from(next)?;
        let after = self.memory.vma_from(vma.end).map_or(MAPS_END, |v| v.start);
        Some((map_line(&vma, self.start_stack), after))
    }
    /// Gathers whole lines until `wanted` bytes are there or one more would
    /// fill the buffer, as `seq_read` does; the first always goes in.
    fn gather(&self, state: &mut MapsPosition, wanted: usize) {
        state.pending.clear();
        state.from = 0;
        while let Some((line, after)) = self.take_line(state.next) {
            if state.pending.is_empty() {
                while line.len() >= state.buffer {
                    state.buffer *= 2;
                }
            } else if state.pending.len() + line.len() >= state.buffer {
                break;
            }
            state.pending.extend_from_slice(&line);
            state.next = after;
            if state.pending.len() >= wanted {
                break;
            }
        }
    }
    /// Starts over and walks to `offset`, as Linux's `traverse`: one past
    /// the end only reads nothing.
    fn walk_to(&self, state: &mut MapsPosition, offset: u64) {
        state.pending.clear();
        state.from = 0;
        state.next = 0;
        if offset == 0 {
            return;
        }
        let mut reached = 0;
        while let Some((line, after)) = self.take_line(state.next) {
            state.next = after;
            let length = line.len() as u64;
            if reached + length > offset {
                state.from = (offset - reached) as usize;
                state.pending = line;
                return;
            }
            reached += length;
            if reached == offset {
                return;
            }
        }
    }
}
impl FileHandle for MapsFile {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let mut state = self.position.lock().unwrap_or_else(PoisonError::into_inner);
        let state = &mut *state;
        let mut copied = 0;
        let waiting = &state.pending[state.from..];
        if !waiting.is_empty() {
            copied = buf.len().min(waiting.len());
            buf[..copied].copy_from_slice(&waiting[..copied]);
            state.from += copied;
            if state.from < state.pending.len() {
                state.position += copied as u64;
                return Ok(copied);
            }
        }
        if copied < buf.len() {
            self.gather(state, buf.len() - copied);
            let count = (buf.len() - copied).min(state.pending.len());
            buf[copied..copied + count].copy_from_slice(&state.pending[..count]);
            state.from = count;
            copied += count;
        }
        state.position += copied as u64;
        Ok(copied)
    }
    /// It has no write operation: EINVAL, or EBADF on a descriptor opened
    /// read-only.
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(if self.writable {
            Errno::EINVAL
        } else {
            Errno::EBADF
        })
    }
    /// As Linux's `seq_lseek`: from the start or the current position, never
    /// the end, which it does not know.
    fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno> {
        let mut state = self.position.lock().unwrap_or_else(PoisonError::into_inner);
        let base = match whence {
            0 => 0,
            1 => state.position,
            _ => return Err(Errno::EINVAL),
        };
        let target = base.checked_add_signed(offset).ok_or(Errno::EINVAL)?;
        if i64::try_from(target).is_err() {
            return Err(Errno::EINVAL);
        }
        if target != state.position {
            self.walk_to(&mut state, target);
            state.position = target;
        }
        Ok(target)
    }
    /// Size 0, as Linux's /proc: a reader goes by what `read` gives.
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(stat(0))
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        0
    }
    fn set_flags(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paludarium_mmu::{AddressSpace, MappingKind};
    use paludarium_types::GuestAddr;

    fn read_all(file: &MapsFile, piece: usize) -> Vec<u8> {
        let mut all = Vec::new();
        let mut buf = vec![0; piece];
        loop {
            let count = file.read(&mut buf).unwrap();
            if count == 0 {
                return all;
            }
            all.extend_from_slice(&buf[..count]);
        }
    }

    #[test]
    fn maps_lines_read_as_linux_writes_them() {
        let mut mem = AddressSpace::new();
        let at = |a: u64| Some(GuestAddr(a));
        mem.map(at(0x1000), 0x1000, Prot::READ, MappingKind::ElfSegment)
            .unwrap();
        mem.map(at(0x5000), 0x2000, Prot::READ_WRITE, MappingKind::Anonymous)
            .unwrap();
        mem.map(at(0x7fff0000), 0x1000, Prot::READ_WRITE, MappingKind::Stack)
            .unwrap();
        let file = MapsFile::open(mem.view(), 0x7fff0800, 0);
        assert_eq!(
            String::from_utf8(read_all(&file, 4096)).unwrap(),
            format!(
                "00001000-00002000 r--p 00000000 00:00 0 \n\
                 00005000-00007000 rw-p 00000000 00:00 0 \n\
                 7fff0000-7fff1000 rw-p 00000000 00:00 0 {}[stack]\n",
                " ".repeat(MAPS_NAME_COLUMN - 40 + 1)
            )
        );
    }

    #[test]
    fn maps_shows_the_break_as_the_heap_once_it_has_grown() {
        let mut mem = AddressSpace::new();
        mem.set_initial_break(GuestAddr(0x10000));
        let view = mem.view();
        assert_eq!(view.vma_from(0), None);
        mem.set_break(GuestAddr(0x11000));
        let vma = view.vma_from(0).unwrap();
        assert!(vma.heap);
        assert!(map_line(&vma, 0).ends_with(b" [heap]\n"));
    }

    #[test]
    fn maps_escapes_only_a_newline_in_a_name() {
        let vma = Vma {
            start: 0x1000,
            end: 0x2000,
            prot: Prot::READ,
            shared: false,
            offset: 0x3000,
            file: Some(paludarium_mmu::MappedFile {
                name: Some(b"/a b\\c\nd".to_vec()),
                source: true,
                offset: 0x3000,
            }),
            identity: (0x0812, 9),
            heap: false,
        };
        let line = map_line(&vma, 0);
        let text = std::str::from_utf8(&line).unwrap();
        assert!(text.starts_with("00001000-00002000 r--p 00003000 08:12 9 "));
        assert_eq!(text.find('/'), Some(MAPS_NAME_COLUMN + 1));
        assert!(text.ends_with("/a b\\c\\012d\n"));
    }

    #[test]
    fn maps_names_shared_anonymous_memory_as_linux_does() {
        let mem = AddressSpace::new();
        let at = mem
            .map_shared(None, 0x1000, Prot::READ_WRITE, MappingKind::Anonymous)
            .unwrap();
        mem.mark_shared(at, 0x1000).unwrap();
        let vma = mem.view().vma_from(0).unwrap();
        let line = String::from_utf8(map_line(&vma, 0)).unwrap();
        assert!(line.contains(" rw-s 00000000 00:01 "), "{line}");
        assert!(line.ends_with(" /dev/zero (deleted)\n"), "{line}");
        assert_ne!(vma.identity.1, 0);
    }

    #[test]
    fn maps_is_generated_as_it_is_read() {
        let mem = AddressSpace::new();
        let map = |at: u64| {
            mem.map_shared(
                Some(GuestAddr(at)),
                0x1000,
                Prot::READ,
                MappingKind::Anonymous,
            )
            .unwrap();
        };
        map(0x10000);
        map(0x30000);
        let file = MapsFile::open(mem.view(), 0, 0);
        let mut buf = [0; 10];
        assert_eq!(file.read(&mut buf).unwrap(), 10);
        // The reader goes on from the VMA it found next, as Linux's does:
        // one made before that is passed by, and one after it is seen.
        map(0x20000);
        map(0x40000);
        let lines = String::from_utf8(read_all(&file, 7)).unwrap();
        let starts: Vec<&str> = lines.lines().map(|line| &line[..8]).collect();
        assert_eq!(starts[1..], ["00030000", "00040000"], "{lines}");
        // Going back reads them all.
        assert_eq!(file.seek(0, 0).unwrap(), 0);
        let all = read_all(&file, 4096);
        assert_eq!(String::from_utf8_lossy(&all).lines().count(), 4);
        assert_eq!(&all[..10], &buf);
    }

    #[test]
    fn maps_reads_whole_lines_up_to_a_page_and_seeks_within_them() {
        let mem = AddressSpace::new();
        for i in 0..200u64 {
            mem.map_shared(
                Some(GuestAddr(0x100000 + i * 0x2000)),
                0x1000,
                Prot::READ,
                MappingKind::Anonymous,
            )
            .unwrap();
        }
        let file = MapsFile::open(mem.view(), 0, 0);
        let whole = read_all(&file, 1 << 16);
        assert_eq!(whole.len(), 200 * 41);
        file.seek(0, 0).unwrap();
        let mut big = vec![0; 1 << 16];
        let first = file.read(&mut big).unwrap();
        assert!((MAPS_BUFFER - 41..MAPS_BUFFER).contains(&first), "{first}");
        assert_eq!(big[first - 1], b'\n');
        // Going forward lands within a line, and past the end reads nothing.
        assert_eq!(file.seek(45, 0).unwrap(), 45);
        assert_eq!(read_all(&file, 100), &whole[45..]);
        assert_eq!(file.seek(-5, 1).unwrap(), whole.len() as u64 - 5);
        assert_eq!(read_all(&file, 100), &whole[whole.len() - 5..]);
        assert_eq!(file.seek(1 << 20, 0).unwrap(), 1 << 20);
        assert_eq!(file.read(&mut big).unwrap(), 0);
        assert_eq!(file.seek(0, 2), Err(Errno::EINVAL));
        assert_eq!(file.seek(-1, 0), Err(Errno::EINVAL));
        assert_eq!(file.stat().unwrap().size, 0);
        assert_eq!(file.write(b"x"), Err(Errno::EBADF));
        assert_eq!(
            MapsFile::open(mem.view(), 0, 2).write(b"x"),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn maps_reads_nothing_once_its_space_is_gone() {
        let mem = AddressSpace::new();
        mem.map_shared(None, 0x1000, Prot::READ, MappingKind::Anonymous)
            .unwrap();
        let file = MapsFile::open(mem.view(), 0, 0);
        drop(mem);
        assert_eq!(file.read(&mut [0; 16]).unwrap(), 0);
    }

    #[test]
    fn own_entries_are_this_process_only() {
        assert_eq!(own_entry(b"/proc/self", 7), Some(OwnEntry::Directory));
        assert_eq!(own_entry(b"/proc/7/", 7), Some(OwnEntry::Directory));
        assert_eq!(own_entry(b"/proc/self/status", 7), Some(OwnEntry::Status));
        assert_eq!(own_entry(b"/proc/7/status", 7), Some(OwnEntry::Status));
        assert_eq!(own_entry(b"/proc/self/maps", 7), Some(OwnEntry::Maps));
        assert_eq!(own_entry(b"/proc/7/maps", 7), Some(OwnEntry::Maps));
        assert_eq!(own_entry(b"/proc/8/maps", 7), None);
        assert_eq!(own_entry(b"/proc/8/status", 7), None);
        assert_eq!(own_entry(b"/proc/self/stat", 7), None);
        assert_eq!(own_entry(b"/proc/selfish", 7), None);
    }
    #[test]
    fn status_has_the_fields_parsers_require() {
        let text = String::from_utf8(render_status(&Status {
            name: b"a\\b\nc\0\0",
            umask: 0o22,
            pid: 3,
            parent: 1,
            descriptors: 70,
            threads: 2,
            queued: 1,
            queue_limit: 4096,
            pending: 1 << 9,
            blocked: 1 << 9,
            ignored: 1 << 12,
            caught: 1,
            no_new_privs: true,
            credentials: &crate::credentials::Credentials {
                uid: 1,
                euid: 2,
                suid: 3,
                fsuid: 4,
                groups: vec![5, 6],
                effective: 0,
                inheritable: 0x42,
                ..crate::credentials::Credentials::default()
            },
        }))
        .unwrap();
        for line in [
            "Name:\ta\\\\b\\nc\n",
            "Umask:\t0022\n",
            "Tgid:\t3\n",
            "PPid:\t1\n",
            "FDSize:\t128\n",
            "Threads:\t2\n",
            "SigQ:\t1/4096\n",
            "SigPnd:\t0000000000000200\n",
            "SigIgn:\t0000000000001000\n",
            "Uid:\t1\t2\t3\t4\n",
            "Gid:\t0\t0\t0\t0\n",
            "Groups:\t5 6 \n",
            "CapInh:\t0000000000000042\n",
            "CapPrm:\t000001ffffffffff\n",
            "CapEff:\t0000000000000000\n",
            "CapBnd:\t000001ffffffffff\n",
            "NoNewPrivs:\t1\n",
        ] {
            assert!(text.contains(line), "{line:?} in {text}");
        }
        assert!(text.starts_with("Name:"));
    }
    #[test]
    fn mount_table_lines_escape_paths() {
        let mounts = [
            MountPoint {
                path: b"/".to_vec(),
                kind: "tmpfs",
            },
            MountPoint {
                path: b"/my dir".to_vec(),
                kind: "hostfs",
            },
        ];
        assert_eq!(
            String::from_utf8(render(&mounts, true)).unwrap(),
            "21 1 0:1 / / rw,relatime - tmpfs tmpfs rw\n\
             22 21 0:2 / /my\\040dir rw,relatime - hostfs hostfs rw\n"
        );
        assert_eq!(
            String::from_utf8(render(&mounts, false)).unwrap(),
            "tmpfs / tmpfs rw,relatime 0 0\nhostfs /my\\040dir hostfs rw,relatime 0 0\n"
        );
        let file = GeneratedFile::open(b"abc".to_vec(), 0);
        let mut buf = [0; 2];
        assert_eq!(file.read(&mut buf), Ok(2));
        assert_eq!(file.read(&mut buf), Ok(1));
        assert_eq!(file.seek(0, 0), Ok(0));
        assert_eq!(file.read(&mut buf), Ok(2));
        assert_eq!(file.write(b"x"), Err(Errno::EBADF));
        assert_eq!(
            GeneratedFile::open(Vec::new(), 1).write(b"x"),
            Err(Errno::EINVAL)
        );
    }
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;
    #[test]
    fn descriptor_names_are_read_as_linux_reads_them() {
        let entry = |path: &[u8]| own_entry(path, 7);
        assert_eq!(entry(b"/proc/self/fd"), Some(OwnEntry::Descriptors));
        assert_eq!(entry(b"/proc/7/fd/"), Some(OwnEntry::Descriptors));
        assert_eq!(entry(b"/proc/self/fd/0"), Some(OwnEntry::Descriptor(0)));
        assert_eq!(entry(b"/proc/7/fd/12/"), Some(OwnEntry::Descriptor(12)));
        for bad in [
            &b"/proc/self/fd/03"[..],
            b"/proc/self/fd/1a",
            b"/proc/self/fd/4294967296",
            b"/proc/8/fd/1",
        ] {
            assert_eq!(entry(bad), None);
        }
        assert_eq!(link_stat(0).mode, 0o120_500);
        assert_eq!(link_stat(2).mode, 0o120_700);
    }
}
