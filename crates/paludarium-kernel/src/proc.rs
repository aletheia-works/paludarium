//! The only /proc files paludarium has, generated when opened: the mount
//! table (`/proc/self/mountinfo`, `/proc/mounts`) from the filesystem's
//! mounts, and this process's directory with its `status`.
use paludarium_host::{FileHandle, FileStat};
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
        _ => None,
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
}
/// The guest is root with every capability (CAP_LAST_CAP is 40).
const CAPABILITIES: u64 = (1 << 41) - 1;
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
    format!(
        "Name:\t{name}\nUmask:\t{:04o}\nState:\tR (running)\nTgid:\t{pid}\nNgid:\t0\n\
         Pid:\t{pid}\nPPid:\t{}\nTracerPid:\t0\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n\
         FDSize:\t{fd_size}\nGroups:\t\nThreads:\t{}\nSigQ:\t{}/{}\n\
         SigPnd:\t{:016x}\nShdPnd:\t{:016x}\nSigBlk:\t{:016x}\nSigIgn:\t{:016x}\n\
         SigCgt:\t{:016x}\nCapInh:\t{:016x}\nCapPrm:\t{CAPABILITIES:016x}\n\
         CapEff:\t{CAPABILITIES:016x}\nCapBnd:\t{CAPABILITIES:016x}\nCapAmb:\t{:016x}\n\
         NoNewPrivs:\t{}\nSeccomp:\t0\nSeccomp_filters:\t0\n\
         voluntary_ctxt_switches:\t0\nnonvoluntary_ctxt_switches:\t0\n",
        s.umask & 0o777,
        s.parent,
        s.threads,
        s.queued,
        s.queue_limit,
        s.pending,
        0,
        s.blocked,
        s.ignored,
        s.caught,
        0,
        0,
        u8::from(s.no_new_privs),
    )
    .into_bytes()
}

/// The `/proc/self` directory: opened with O_PATH or O_DIRECTORY so its
/// entries can be opened relative to it, as procfs readers do.
pub(crate) struct OwnDirectory;
impl FileHandle for OwnDirectory {
    fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EISDIR)
    }
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EBADF)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Ok(0)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(directory_stat())
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn own_entries_are_this_process_only() {
        assert_eq!(own_entry(b"/proc/self", 7), Some(OwnEntry::Directory));
        assert_eq!(own_entry(b"/proc/7/", 7), Some(OwnEntry::Directory));
        assert_eq!(own_entry(b"/proc/self/status", 7), Some(OwnEntry::Status));
        assert_eq!(own_entry(b"/proc/7/status", 7), Some(OwnEntry::Status));
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
            "CapEff:\t000001ffffffffff\n",
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
