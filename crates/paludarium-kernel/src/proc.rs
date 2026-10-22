//! The only /proc files paludarium has: the mount table, generated from the
//! filesystem's mounts when opened (`/proc/self/mountinfo`, `/proc/mounts`).
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
