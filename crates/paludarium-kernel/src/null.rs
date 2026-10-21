//! Kernel-owned /dev/null used by static-musl Command's redirected stdin.
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::Errno;
use std::sync::atomic::{AtomicU32, Ordering};
pub(crate) struct NullFile(AtomicU32);
impl NullFile {
    pub(crate) fn new(flags: u32) -> Self {
        Self(AtomicU32::new(flags & !0x80000))
    }
}
impl FileHandle for NullFile {
    fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
        if self.flags() & 3 == 1 {
            Err(Errno::EBADF)
        } else {
            Ok(0)
        }
    }
    fn write(&self, bytes: &[u8]) -> Result<usize, Errno> {
        if self.flags() & 3 == 0 {
            Err(Errno::EBADF)
        } else {
            Ok(bytes.len())
        }
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Ok(0)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(FileStat {
            mode: 0o020666,
            links: 1,
            ..FileStat::default()
        })
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        self.0.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.0.store(
            (self.flags() & 3) | (flags & !3 & !0x80000),
            Ordering::SeqCst,
        );
        Ok(())
    }
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        Ok((crate::events::IN | crate::events::OUT, 1, 1))
    }
}
#[cfg(test)]
mod processes_tests {
    use super::*;
    #[test]
    fn read_eof() {
        assert_eq!(NullFile::new(0).read(&mut [0; 8]), Ok(0));
    }
    #[test]
    fn write_consumes() {
        assert_eq!(NullFile::new(1).write(b"abc"), Ok(3));
    }
    #[test]
    fn access_mode() {
        assert_eq!(NullFile::new(1).read(&mut [0]), Err(Errno::EBADF));
        assert_eq!(NullFile::new(0).write(b"x"), Err(Errno::EBADF));
    }
    #[test]
    fn read_write_mode() {
        let file = NullFile::new(2);
        assert_eq!(file.read(&mut [0]), Ok(0));
        assert_eq!(file.write(b"x"), Ok(1));
    }
    #[test]
    fn character_stat_and_seek() {
        let file = NullFile::new(0);
        assert_eq!(file.stat().unwrap().mode & 0o170000, 0o020000);
        assert_eq!(file.seek(100, 0), Ok(0));
        assert_eq!(file.truncate(0), Err(Errno::EINVAL));
    }
    #[test]
    fn flags_preserve_access_mode() {
        let file = NullFile::new(0x80002);
        assert_eq!(file.flags(), 2);
        file.set_flags(0x800).unwrap();
        assert_eq!(file.flags(), 0x802);
    }
    #[test]
    fn readiness_and_empty_write() {
        let file = NullFile::new(2);
        assert_eq!(file.readiness().unwrap().0, 5);
        assert_eq!(file.write(b""), Ok(0));
    }
}
