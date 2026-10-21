//! Linux x86-64 file ABI and descriptor table. All guest memory is checked.
use crate::syscalls::{Context, Outcome};
use paludarium_host::{ClockId, FileHandle, FileStat};
use paludarium_types::{Errno, GuestAddr};
use paludarium_vfs::{FileSystem, HostFs, MemFs};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
pub const NUMBERS: &[u64] = &[
    0, 2, 3, 4, 5, 6, 8, 20, 22, 32, 33, 72, 73, 76, 77, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
    89, 217, 257, 258, 262, 263, 264, 265, 266, 267, 292, 293,
];
#[derive(Clone)]
pub(crate) struct Descriptor {
    pub(crate) file: Arc<dyn FileHandle>,
    path: Vec<u8>,
    cloexec: bool,
}
#[derive(Clone)]
pub struct Files {
    pub(crate) readiness: Arc<crate::events::ReadinessHub>,
    pub terminal_size: Option<(u16, u16)>,
    pub fs: Arc<dyn FileSystem>,
    fds: Arc<Mutex<BTreeMap<u32, Descriptor>>>,
    cwd: Arc<Mutex<Vec<u8>>>,
    umask: u32,
}
impl Default for Files {
    fn default() -> Self {
        let fs = MemFs::new();
        let _ = fs.mkdir(b"/tmp", 0o1777);
        Self {
            readiness: Arc::default(),
            terminal_size: None,
            fs: Arc::new(fs),
            fds: Arc::new(Mutex::new(BTreeMap::new())),
            cwd: Arc::new(Mutex::new(b"/".to_vec())),
            umask: 0o022,
        }
    }
}
impl Files {
    pub(crate) fn set_current_directory(&mut self, path: &[u8]) -> Result<(), Errno> {
        let path = paludarium_vfs::normalize_path(path)?;
        if self.fs.metadata(&path, true)?.mode & 0o170000 != 0o040000 {
            return Err(Errno::ENOTDIR);
        }
        *self.cwd.lock().unwrap_or_else(PoisonError::into_inner) = path;
        Ok(())
    }
    pub(crate) fn release_descriptors(&mut self) {
        // Detach this worker's table reference without closing a table still
        // shared by live CLONE_FILES siblings.
        self.fds = Arc::new(Mutex::new(BTreeMap::new()));
    }
    pub(crate) fn exec_path(&self, path: Vec<u8>) -> Result<Vec<u8>, Errno> {
        self.path((-100i32) as u64, path)
    }
    pub(crate) fn for_exec(&self) -> Self {
        let child = self.for_clone(false, false);
        child
            .fds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, descriptor| !descriptor.cloexec);
        child
    }
    pub(crate) fn install(
        &mut self,
        file: Arc<dyn FileHandle>,
        cloexec: bool,
    ) -> Result<u32, Errno> {
        self.allocate(
            Descriptor {
                file,
                path: Vec::new(),
                cloexec,
            },
            0,
        )
    }
    pub fn with_host(host: Arc<dyn paludarium_host::Host>) -> Self {
        let files = Self::default();
        for channel in 0..3 {
            files
                .fds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(
                    channel,
                    Descriptor {
                        file: Arc::new(StandardFile {
                            host: Arc::clone(&host),
                            channel,
                        }),
                        path: Vec::new(),
                        cloexec: false,
                    },
                );
        }
        files
    }
    pub(crate) fn stdio_channel(&self, fd: u64) -> Result<Option<u32>, Errno> {
        Ok(self.descriptor(fd)?.file.stdio_channel())
    }
    pub fn uses_original_stdio(&self, fd: u64) -> bool {
        self.descriptor(fd)
            .ok()
            .and_then(|d| d.file.stdio_channel())
            == u32::try_from(fd).ok()
    }
    fn allocate(&mut self, d: Descriptor, min: u32) -> Result<u32, Errno> {
        let mut fds = self.fds.lock().unwrap_or_else(PoisonError::into_inner);
        let mut n = min;
        while fds.contains_key(&n) {
            n = n.checked_add(1).ok_or(Errno(24))?
        }
        fds.insert(n, d);
        Ok(n)
    }
    pub(crate) fn descriptor(&self, fd: u64) -> Result<Descriptor, Errno> {
        self.fds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&u32::try_from(fd).map_err(|_| Errno::EBADF)?)
            .cloned()
            .ok_or(Errno::EBADF)
    }
    fn path(&self, dir: u64, p: Vec<u8>) -> Result<Vec<u8>, Errno> {
        if p.is_empty() {
            return Err(Errno::ENOENT);
        }
        if p.first() == Some(&b'/') {
            return Ok(p);
        }
        let mut base = if dir as i32 == -100 {
            self.cwd
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        } else {
            let d = self.descriptor(dir)?;
            if d.file.stat()?.mode & 0o170000 != 0o040000 {
                return Err(Errno::ENOTDIR);
            }
            d.file.guest_path_hint().unwrap_or(d.path)
        };
        if base.last() != Some(&b'/') {
            base.push(b'/')
        }
        base.extend_from_slice(&p);
        Ok(base)
    }
    pub(crate) fn for_clone(&self, share_files: bool, share_fs: bool) -> Self {
        let mut child = self.clone();
        if !share_files {
            child.fds = Arc::new(Mutex::new(
                self.fds
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone(),
            ));
        }
        if !share_fs {
            child.cwd = Arc::new(Mutex::new(
                self.cwd
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone(),
            ));
        }
        child
    }
}
fn path(c: &Context<'_>, addr: u64) -> Result<Vec<u8>, Errno> {
    if addr == 0 {
        return Err(Errno::EFAULT);
    }
    let mut b = Vec::new();
    for i in 0..4096 {
        let mut v = [0];
        c.mem
            .read(GuestAddr(addr.checked_add(i).ok_or(Errno::EFAULT)?), &mut v)
            .map_err(|_| Errno::EFAULT)?;
        if v[0] == 0 {
            return Ok(b);
        }
        b.push(v[0]);
    }
    Err(Errno::ENAMETOOLONG)
}
fn at(c: &Context<'_>, dir: u64, ptr: u64) -> Result<Vec<u8>, Errno> {
    c.files.path(dir, path(c, ptr)?)
}
fn output(c: &Context<'_>, addr: u64, b: &[u8]) -> Result<(), Errno> {
    c.mem.write(GuestAddr(addr), b).map_err(|_| Errno::EFAULT)
}
fn stat(c: &Context<'_>, addr: u64, s: FileStat) -> Result<u64, Errno> {
    output(c, addr, &encode_stat(s)?)?;
    Ok(0)
}
fn encode_stat(s: FileStat) -> Result<[u8; 144], Errno> {
    let (seconds, nanos) = linux_mtime(s.mtime_ns)?;
    let mut b = [0; 144];
    b[8..16].copy_from_slice(&s.inode.to_le_bytes());
    b[16..24].copy_from_slice(&s.links.to_le_bytes());
    b[24..28].copy_from_slice(&s.mode.to_le_bytes());
    b[48..56].copy_from_slice(&s.size.to_le_bytes());
    b[56..64].copy_from_slice(&4096u64.to_le_bytes());
    b[64..72].copy_from_slice(&s.size.div_ceil(512).to_le_bytes());
    b[88..96].copy_from_slice(&seconds.to_le_bytes());
    b[96..104].copy_from_slice(&nanos.to_le_bytes());
    Ok(b)
}
fn linux_mtime(ns: i128) -> Result<(i64, u64), Errno> {
    let seconds = i64::try_from(ns.div_euclid(1_000_000_000)).map_err(|_| Errno(75))?;
    let nanos = u64::try_from(ns.rem_euclid(1_000_000_000)).map_err(|_| Errno(75))?;
    Ok((seconds, nanos))
}
#[cfg(test)]
mod mtime_tests {
    use super::*;
    #[test]
    fn u7_mtime_stat_codec_signed_boundaries() {
        for (ns, seconds, nanos) in [
            (-1_000_000_000, -1i64, 0u64),
            (-500_000_000, -1, 500_000_000),
            (-1, -1, 999_999_999),
            (0, 0, 0),
            (1, 0, 1),
            (1_500_000_000, 1, 500_000_000),
            (i128::from(u64::MAX), 18_446_744_073, 709_551_615),
        ] {
            let bytes = encode_stat(FileStat {
                mtime_ns: ns,
                ..FileStat::default()
            })
            .unwrap();
            assert_eq!(&bytes[88..96], &seconds.to_le_bytes());
            assert_eq!(&bytes[96..104], &nanos.to_le_bytes());
        }
    }
    #[test]
    fn u7_mtime_stat_codec_checked_seconds_overflow() {
        for ns in [
            i128::MIN,
            i128::MAX,
            (i128::from(i64::MAX) + 1) * 1_000_000_000,
            i128::from(i64::MIN) * 1_000_000_000 - 1,
        ] {
            assert_eq!(
                encode_stat(FileStat {
                    mtime_ns: ns,
                    ..FileStat::default()
                }),
                Err(Errno(75))
            );
        }
        assert_eq!(
            linux_mtime(i128::from(i64::MIN) * 1_000_000_000),
            Ok((i64::MIN, 0))
        );
        assert_eq!(
            linux_mtime(i128::from(i64::MAX) * 1_000_000_000 + 999_999_999),
            Ok((i64::MAX, 999_999_999))
        );
    }
}
pub(crate) fn dispatch(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let n = c.cpu.gpr[paludarium_cpu::reg::RAX];
    match run(c, n, a) {
        Ok(v) => Outcome::Return(v),
        Err(e) => Outcome::Return(e.to_syscall_return()),
    }
}
pub(crate) fn run(c: &mut Context<'_>, n: u64, a: [u64; 6]) -> Result<u64, Errno> {
    match n {
        22 | 293 => {
            let flags = if n == 22 {
                0
            } else {
                u32::try_from(a[1]).map_err(|_| Errno::EINVAL)?
            };
            if flags & !(crate::events::NONBLOCK | crate::events::CLOEXEC) != 0 {
                return Err(Errno::EINVAL);
            }
            c.mem
                .check_write(GuestAddr(a[0]), 8)
                .map_err(|_| Errno::EFAULT)?;
            let [reader, writer] =
                crate::sockets::PipeEnd::pair(flags, Arc::clone(&c.files.readiness))?;
            let first = c
                .files
                .install(reader, flags & crate::events::CLOEXEC != 0)?;
            let second = c
                .files
                .install(writer, flags & crate::events::CLOEXEC != 0)?;
            let mut bytes = [0; 8];
            bytes[..4].copy_from_slice(&first.to_le_bytes());
            bytes[4..].copy_from_slice(&second.to_le_bytes());
            output(c, a[0], &bytes)?;
            Ok(0)
        }
        20 => {
            if a[2] > 1024 {
                return Err(Errno::EINVAL);
            }
            let descriptor = c.files.descriptor(a[0])?;
            let mut bytes = Vec::new();
            for index in 0..a[2] {
                let addr = a[1].checked_add(index * 16).ok_or(Errno::EFAULT)?;
                let base = c.mem.read_u64(GuestAddr(addr)).map_err(|_| Errno::EFAULT)?;
                let length = c
                    .mem
                    .read_u64(GuestAddr(addr + 8))
                    .map_err(|_| Errno::EFAULT)?;
                let length = usize::try_from(length).map_err(|_| Errno::EINVAL)?;
                let total = bytes
                    .len()
                    .checked_add(length)
                    .filter(|v| *v <= 0x7fff_f000)
                    .ok_or(Errno::EINVAL)?;
                c.mem
                    .check_read(GuestAddr(base), length)
                    .map_err(|_| Errno::EFAULT)?;
                bytes.try_reserve(length).map_err(|_| Errno::ENOMEM)?;
                let start = bytes.len();
                bytes.resize(total, 0);
                c.mem
                    .read(GuestAddr(base), &mut bytes[start..])
                    .map_err(|_| Errno::EFAULT)?;
            }
            write_io(c, &descriptor.file, &bytes, false)
        }
        0 | 1 => {
            let requested = usize::try_from(a[2].min(0x7fff_f000)).map_err(|_| Errno::EINVAL)?;
            let d = Some(c.files.descriptor(a[0])?);
            let len = if n == 0 {
                if let Some(d) = &d {
                    let metadata = d.file.stat()?;
                    if metadata.mode & 0o170000 != 0o100000 {
                        requested
                    } else {
                        let size = metadata.size;
                        let pos = d.file.seek(0, 1)?;
                        requested.min(size.saturating_sub(pos) as usize)
                    }
                } else {
                    requested
                }
            } else {
                requested
            };
            if n == 1 {
                c.mem
                    .check_read(GuestAddr(a[1]), len)
                    .map_err(|_| Errno::EFAULT)?;
            } else {
                c.mem
                    .check_write(GuestAddr(a[1]), len)
                    .map_err(|_| Errno::EFAULT)?;
            }
            let mut b = Vec::new();
            b.try_reserve(len).map_err(|_| Errno::ENOMEM)?;
            b.resize(len, 0);
            if n == 1 {
                c.mem
                    .read(GuestAddr(a[1]), &mut b)
                    .map_err(|_| Errno::EFAULT)?;
                return write_io(c, &d.ok_or(Errno::EBADF)?.file, &b, false);
            }
            let count = if let Some(d) = d {
                loop {
                    let ticket = c.files.readiness.token.value();
                    match d.file.read(&mut b) {
                        Err(e)
                            if e == Errno::EAGAIN
                                && d.file.readiness().is_ok()
                                && d.file.flags() & crate::events::NONBLOCK == 0 =>
                        {
                            crate::events::wait(c, ticket, None)?
                        }
                        result => break result?,
                    }
                }
            } else if a[0] == 0 {
                c.host.read_stdin(&mut b)?
            } else {
                return Err(Errno::EBADF);
            };
            output(c, a[1], &b[..count])?;
            Ok(count as u64)
        }
        2 | 85 | 257 => {
            let (p, flags, mode) = match n {
                2 => (at(c, (-100i32) as u64, a[0])?, a[1], a[2]),
                85 => (at(c, (-100i32) as u64, a[0])?, 577, a[1]),
                _ => (at(c, a[0], a[1])?, a[2], a[3]),
            };
            let flags = u32::try_from(flags).map_err(|_| Errno::EINVAL)?;
            if flags & 3 == 3 {
                return Err(Errno::EINVAL);
            }
            let f: Arc<dyn FileHandle> = if p == b"/dev/null" {
                Arc::new(crate::null::NullFile::new(flags))
            } else {
                c.files.fs.open(&p, flags, (mode as u32) & !c.files.umask)?
            };
            c.files
                .allocate(
                    Descriptor {
                        file: f,
                        path: p,
                        cloexec: flags & 0x80000 != 0,
                    },
                    0,
                )
                .map(u64::from)
        }
        3 => {
            c.files
                .fds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&(a[0] as u32))
                .ok_or(Errno::EBADF)?;
            Ok(0)
        }
        4 | 6 | 262 => {
            let (p, out, follow) = if n == 262 {
                if a[3] & !0x1100 != 0 {
                    return Err(Errno::EINVAL);
                }
                let raw = path(c, a[1])?;
                if raw.is_empty() && a[3] & 0x1000 != 0 {
                    return stat(c, a[2], c.files.descriptor(a[0])?.file.stat()?);
                }
                (c.files.path(a[0], raw)?, a[2], a[3] & 0x100 == 0)
            } else {
                (at(c, (-100i32) as u64, a[0])?, a[1], n == 4)
            };
            stat(c, out, c.files.fs.metadata(&p, follow)?)
        }
        5 => stat(c, a[1], c.files.descriptor(a[0])?.file.stat()?),
        8 => c
            .files
            .descriptor(a[0])?
            .file
            .seek(a[1] as i64, a[2] as u32),
        32 | 33 | 292 => {
            let mut d = c.files.descriptor(a[0])?;
            d.cloexec = n == 292 && a[2] & 0x80000 != 0;
            if n == 32 {
                return c.files.allocate(d, 0).map(u64::from);
            }
            if a[1] > i32::MAX as u64 || n == 292 && (a[2] & !0x80000 != 0 || a[0] == a[1]) {
                return Err(Errno::EINVAL);
            }
            c.files
                .fds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(a[1] as u32, d);
            Ok(a[1])
        }
        72 => {
            let mut d = c.files.descriptor(a[0])?;
            match a[1] {
                0 | 1030 => {
                    d.cloexec = a[1] == 1030;
                    c.files
                        .allocate(d, u32::try_from(a[2]).map_err(|_| Errno::EINVAL)?)
                        .map(u64::from)
                }
                1 => Ok(u64::from(d.cloexec)),
                2 => {
                    d.cloexec = a[2] & 1 != 0;
                    c.files
                        .fds
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(a[0] as u32, d);
                    Ok(0)
                }
                3 => Ok(d.file.flags() as u64),
                4 => {
                    d.file.set_flags(a[2] as u32)?;
                    Ok(0)
                }
                _ => Err(Errno::EINVAL),
            }
        }
        73 => {
            let d = c.files.descriptor(a[0])?;
            loop {
                match d.file.flock(a[1] as u32) {
                    Ok(()) => return Ok(0),
                    Err(e) if e == Errno::EAGAIN && a[1] & 4 == 0 => {
                        let timer_generation = c.group.timer_generation();
                        let receipt = c.inbox.drain(c.process);
                        c.group.drain_process(c.process);
                        let now = c.host.clock(ClockId::Monotonic)?;
                        c.group.expire_timer(c.process, now);
                        if c.group.status().is_some()
                            || crate::signals::next_pending(c.process, true).is_some()
                            || receipt.interrupted
                        {
                            return Err(Errno(4));
                        }
                        if !c.inbox.owns_wake(c.cancellation)
                            && c.cancellation.load(std::sync::atomic::Ordering::SeqCst)
                        {
                            return Err(Errno(4));
                        }
                        let outcome = c.host.wait_until(
                            ClockId::Monotonic,
                            now.saturating_add(10_000_000),
                            c.cancellation,
                        )?;
                        let receipt = c.inbox.drain(c.process);
                        c.group.drain_process(c.process);
                        if c.group.status().is_some()
                            || crate::signals::next_pending(c.process, true).is_some()
                            || receipt.interrupted
                            || (outcome == paludarium_host::WaitOutcome::Interrupted
                                && !receipt.timer_changed
                                && !receipt.signals
                                && c.group.timer_generation() == timer_generation)
                        {
                            return Err(Errno(4));
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        76 | 77 => {
            let f = if n == 77 {
                c.files.descriptor(a[0])?.file
            } else {
                c.files.fs.open(&at(c, (-100i32) as u64, a[0])?, 1, 0)?
            };
            if a[1] > i64::MAX as u64 {
                return Err(Errno::EINVAL);
            }
            f.truncate(a[1])?;
            Ok(0)
        }
        79 => {
            let mut p = c
                .files
                .cwd
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            p.push(0);
            if a[1] < p.len() as u64 {
                return Err(Errno::ERANGE);
            }
            output(c, a[0], &p)?;
            Ok(p.len() as u64)
        }
        80 | 81 => {
            let p = if n == 80 {
                at(c, (-100i32) as u64, a[0])?
            } else {
                c.files.descriptor(a[0])?.path
            };
            if c.files.fs.metadata(&p, true)?.mode & 0o170000 != 0o040000 {
                return Err(Errno::ENOTDIR);
            }
            *c.files.cwd.lock().unwrap_or_else(PoisonError::into_inner) = p;
            Ok(0)
        }
        82 | 264 => {
            let (old, new) = if n == 82 {
                (
                    at(c, (-100i32) as u64, a[0])?,
                    at(c, (-100i32) as u64, a[1])?,
                )
            } else {
                (at(c, a[0], a[1])?, at(c, a[2], a[3])?)
            };
            c.files.fs.rename(&old, &new)?;
            for d in c
                .files
                .fds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .values_mut()
            {
                if d.path == old || d.path.starts_with(&old) && d.path.get(old.len()) == Some(&b'/')
                {
                    let mut p = new.clone();
                    p.extend_from_slice(&d.path[old.len()..]);
                    d.path = p;
                }
            }
            let mut cwd = c.files.cwd.lock().unwrap_or_else(PoisonError::into_inner);
            if *cwd == old || cwd.starts_with(&old) && cwd.get(old.len()) == Some(&b'/') {
                let mut p = new.clone();
                p.extend_from_slice(&cwd[old.len()..]);
                *cwd = p;
            }
            Ok(0)
        }
        83 | 258 => {
            let (p, mode) = if n == 83 {
                (at(c, (-100i32) as u64, a[0])?, a[1])
            } else {
                (at(c, a[0], a[1])?, a[2])
            };
            c.files.fs.mkdir(&p, (mode as u32) & !c.files.umask)?;
            Ok(0)
        }
        84 | 87 | 263 => {
            let (p, dir) = if n == 263 {
                if a[2] & !512 != 0 {
                    return Err(Errno::EINVAL);
                }
                (at(c, a[0], a[1])?, a[2] & 512 != 0)
            } else {
                (at(c, (-100i32) as u64, a[0])?, n == 84)
            };
            c.files.fs.unlink(&p, dir)?;
            Ok(0)
        }
        86 | 265 => {
            let (old, new) = if n == 86 {
                (
                    at(c, (-100i32) as u64, a[0])?,
                    at(c, (-100i32) as u64, a[1])?,
                )
            } else {
                if a[4] != 0 {
                    return Err(Errno::EINVAL);
                }
                (at(c, a[0], a[1])?, at(c, a[2], a[3])?)
            };
            c.files.fs.link(&old, &new)?;
            Ok(0)
        }
        88 | 266 => {
            let target = path(c, a[0])?;
            let p = if n == 88 {
                at(c, (-100i32) as u64, a[1])?
            } else {
                at(c, a[1], a[2])?
            };
            c.files.fs.symlink(&target, &p)?;
            Ok(0)
        }
        89 | 267 => {
            let (p, buf, len) = if n == 89 {
                (at(c, (-100i32) as u64, a[0])?, a[1], a[2])
            } else {
                (at(c, a[0], a[1])?, a[2], a[3])
            };
            if len == 0 {
                return Err(Errno::EINVAL);
            }
            let b = c.files.fs.readlink(&p)?;
            let count = b
                .len()
                .min(usize::try_from(len).map_err(|_| Errno::EINVAL)?);
            output(c, buf, &b[..count])?;
            Ok(count as u64)
        }
        217 => {
            let d = c.files.descriptor(a[0])?;
            if d.file.stat()?.mode & 0o170000 != 0o040000 {
                return Err(Errno::ENOTDIR);
            }
            let entries = c.files.fs.read_dir(&d.path)?;
            let position = d.file.seek(0, 1)? as usize;
            let mut bytes = Vec::new();
            let mut count = 0;
            for (i, e) in entries.iter().enumerate().skip(position) {
                let size = (19 + e.name.len() + 1).div_ceil(8) * 8;
                if bytes.len() + size > a[2] as usize {
                    if bytes.is_empty() {
                        return Err(Errno::EINVAL);
                    }
                    break;
                }
                let pos = bytes.len();
                bytes.resize(pos + size, 0);
                bytes[pos..pos + 8].copy_from_slice(&e.inode.to_le_bytes());
                bytes[pos + 8..pos + 16].copy_from_slice(&((i + 1) as u64).to_le_bytes());
                bytes[pos + 16..pos + 18].copy_from_slice(&(size as u16).to_le_bytes());
                bytes[pos + 18] = e.kind;
                bytes[pos + 19..pos + 19 + e.name.len()].copy_from_slice(&e.name);
                count += 1;
            }
            output(c, a[1], &bytes)?;
            d.file.seek(count, 1)?;
            Ok(bytes.len() as u64)
        }
        _ => Err(Errno::ENOSYS),
    }
}
/// Blocking stream writes preserve partial progress across readiness retries.
/// No descriptor-table, stream-state or guest-memory lock spans a Host wait.
pub(crate) fn write_io(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    bytes: &[u8],
    nosignal: bool,
) -> Result<u64, Errno> {
    let stream = file
        .as_any()
        .is_some_and(|a| a.is::<crate::sockets::SocketPairEnd>());
    let mut done = 0;
    loop {
        let ticket = c.files.readiness.token.value();
        let nonblocking = file.flags() & crate::events::NONBLOCK != 0;
        match file.write(&bytes[done..]) {
            Ok(count) => {
                done += count;
                if count == 0 || done == bytes.len() || nonblocking || !stream {
                    return Ok(done as u64);
                }
            }
            Err(e) if e == Errno::EAGAIN && file.readiness().is_ok() && !nonblocking => {
                if let Err(e) = crate::events::wait(c, ticket, None) {
                    return if done != 0 { Ok(done as u64) } else { Err(e) };
                }
            }
            Err(e) => {
                if done != 0 {
                    return Ok(done as u64);
                }
                if e == Errno(32) && !nosignal {
                    crate::signals::queue(c.process, crate::signals::PendingSignal::user(13, 0));
                }
                return Err(e);
            }
        }
    }
}
struct StandardFile {
    host: Arc<dyn paludarium_host::Host>,
    channel: u32,
}
impl FileHandle for StandardFile {
    fn stdio_channel(&self) -> Option<u32> {
        Some(self.channel)
    }
    fn read(&self, b: &mut [u8]) -> Result<usize, Errno> {
        if self.channel == 0 {
            self.host.read_stdin(b)
        } else {
            Err(Errno::EBADF)
        }
    }
    fn write(&self, b: &[u8]) -> Result<usize, Errno> {
        match self.channel {
            1 => self.host.write_stdout(b),
            2 => self.host.write_stderr(b),
            _ => Err(Errno::EBADF),
        }
    }
    fn seek(&self, _o: i64, _w: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(FileStat {
            inode: self.channel as u64,
            size: 0,
            mode: 0o010666,
            links: 1,
            mtime_ns: 0,
        })
    }
    fn truncate(&self, _n: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _o: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn flags(&self) -> u32 {
        u32::from(self.channel != 0)
    }
    fn set_flags(&self, _f: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
}
#[cfg(test)]
mod files_tests {
    use super::*;
    fn d(fs: &MemFs, p: &[u8]) -> Descriptor {
        Descriptor {
            file: fs.open(p, 66, 0o600).unwrap(),
            path: p.to_vec(),
            cloexec: false,
        }
    }
    #[test]
    fn u7_fd_allocate() {
        let fs = MemFs::new();
        let mut f = Files::default();
        assert_eq!(f.allocate(d(&fs, b"/a"), 3), Ok(3));
        assert_eq!(f.allocate(d(&fs, b"/b"), 3), Ok(4));
    }
    #[test]
    fn u7_fd_minimum() {
        let fs = MemFs::new();
        assert_eq!(Files::default().allocate(d(&fs, b"/a"), 20), Ok(20));
    }
    #[test]
    fn u7_fd_bad() {
        assert!(matches!(
            Files::default().descriptor(100),
            Err(Errno::EBADF)
        ));
    }
    #[test]
    fn u7_fd_relative() {
        assert_eq!(
            Files::default().path((-100i32) as u64, b"a".to_vec()),
            Ok(b"/a".to_vec())
        );
    }
    #[test]
    fn u7_fd_absolute_ignores_bad_dir() {
        assert_eq!(
            Files::default().path(999, b"/a".to_vec()),
            Ok(b"/a".to_vec())
        );
    }
    #[test]
    fn u7_fd_empty() {
        assert_eq!(
            Files::default().path((-100i32) as u64, vec![]),
            Err(Errno::ENOENT)
        );
    }
    #[test]
    fn u7_fd_directory_type() {
        let fs = MemFs::new();
        let mut f = Files::default();
        f.allocate(d(&fs, b"/a"), 3).unwrap();
        assert_eq!(f.path(3, b"b".to_vec()), Err(Errno::ENOTDIR));
    }
    #[test]
    fn u7_fd_shared_offset() {
        let fs = MemFs::new();
        let x = d(&fs, b"/a");
        x.file.write(b"abc").unwrap();
        let y = x.clone();
        y.file.seek(0, 0).unwrap();
        let mut b = [0];
        x.file.read(&mut b).unwrap();
        assert_eq!(y.file.seek(0, 1), Ok(1));
    }
}
