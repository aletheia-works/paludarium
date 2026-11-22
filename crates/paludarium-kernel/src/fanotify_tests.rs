//! The fanotify calls ([`crate::fanotify`]) through the kernel's dispatch.
use super::*;
use paludarium_host::testing::RecordingHost;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::{Errno, GuestAddr};

const DATA: u64 = 0x10_0000;
const BUF: u64 = DATA + 0x8000;
const INIT: u64 = 300;
const MARK: u64 = 301;

const ACCESS: u64 = 0x1;
const MODIFY: u64 = 0x2;
const ATTRIB: u64 = 0x4;
const CLOSE_WRITE: u64 = 0x8;
const CLOSE_NOWRITE: u64 = 0x10;
const OPEN: u64 = 0x20;
const MOVED_FROM: u64 = 0x40;
const MOVED_TO: u64 = 0x80;
const CREATE: u64 = 0x100;
const DELETE: u64 = 0x200;
const DELETE_SELF: u64 = 0x400;
const MOVE_SELF: u64 = 0x800;
const Q_OVERFLOW: u64 = 0x4000;
const OPEN_PERM: u64 = 0x1_0000;
const EVENT_ON_CHILD: u64 = 0x800_0000;
const RENAME: u64 = 0x1000_0000;
const ONDIR: u64 = 0x4000_0000;

const NONBLOCK: u64 = 0x2;
const CLASS_CONTENT: u64 = 0x4;
const REPORT_PIDFD: u64 = 0x80;
const REPORT_TID: u64 = 0x100;
const REPORT_FID: u64 = 0x200;
const REPORT_DIR_FID: u64 = 0x400;
const REPORT_NAME: u64 = 0x800;
const REPORT_TARGET_FID: u64 = 0x1000;
const REPORT_FD_ERROR: u64 = 0x2000;

const ADD: u64 = 0x1;
const REMOVE: u64 = 0x2;
const ONLYDIR: u64 = 0x8;
const MOUNT: u64 = 0x10;
const IGNORED_MASK: u64 = 0x20;
const SURV_MODIFY: u64 = 0x40;
const FLUSH: u64 = 0x80;
const FILESYSTEM: u64 = 0x100;
const EVICTABLE: u64 = 0x200;
const IGNORE: u64 = 0x400;

const AT_FDCWD: u64 = -100i64 as u64;

struct Fixture {
    kernel: Kernel,
    thread: Thread,
    mem: AddressSpace,
    next: u64,
}

fn fixture() -> Fixture {
    let host = Arc::new(RecordingHost::new());
    let kernel = Kernel::new(host);
    let mut mem = AddressSpace::new();
    mem.map(
        Some(GuestAddr(DATA)),
        0x10000,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    mem.set_initial_break(GuestAddr(0x20_0000));
    let thread = Thread {
        tid: 1,
        state: ThreadState {
            pid: 1,
            ..ThreadState::default()
        },
        cpu: CpuState::default(),
    };
    Fixture {
        kernel,
        thread,
        mem,
        next: DATA,
    }
}

fn errno(e: Errno) -> u64 {
    e.to_syscall_return()
}

/// An event a read gives: its mask, descriptor and pid, and its info
/// records by type.
#[derive(Debug)]
struct Seen {
    mask: u64,
    fd: i32,
    pid: i32,
    records: Vec<(u8, Vec<u8>)>,
}

impl Fixture {
    fn ret(&mut self, number: u64, args: &[u64]) -> u64 {
        self.thread.cpu.gpr[reg::RAX] = number;
        let regs = [reg::RDI, reg::RSI, reg::RDX, reg::R10, reg::R8, reg::R9];
        for (r, v) in regs.iter().zip(args) {
            self.thread.cpu.gpr[*r] = *v;
        }
        let reason = ExitReason::Syscall {
            rip: GuestAddr(0x1000),
        };
        assert_eq!(
            self.kernel.handle(&mut self.thread, &self.mem, reason),
            Next::Resume
        );
        self.thread.cpu.gpr[reg::RAX]
    }
    fn put(&mut self, bytes: &[u8]) -> u64 {
        let at = self.next;
        self.mem.write(GuestAddr(at), bytes).unwrap();
        self.mem
            .write(GuestAddr(at + bytes.len() as u64), &[0])
            .unwrap();
        self.next = (at + bytes.len() as u64 + 16) & !7;
        at
    }
    fn init(&mut self, flags: u64, event_flags: u64) -> u64 {
        self.ret(INIT, &[flags, event_flags])
    }
    fn mark(&mut self, fan: u64, flags: u64, mask: u64, path: &str) -> u64 {
        let path = self.put(path.as_bytes());
        self.ret(MARK, &[fan, flags, mask, AT_FDCWD, path])
    }
    fn open(&mut self, path: &str, flags: u64) -> u64 {
        let path = self.put(path.as_bytes());
        self.ret(2, &[path, flags, 0o644])
    }
    fn close(&mut self, fd: u64) {
        assert_eq!(self.ret(3, &[fd]), 0);
    }
    fn touch(&mut self, path: &str) {
        let fd = self.open(path, 0o101);
        self.close(fd);
    }
    fn mkdir(&mut self, path: &str) {
        let path = self.put(path.as_bytes());
        assert_eq!(self.ret(83, &[path, 0o755]), 0);
    }
    /// One read of `fan` into a buffer of `len` bytes.
    fn read(&mut self, fan: u64, len: u64) -> Result<Vec<Seen>, u64> {
        let n = self.ret(0, &[fan, BUF, len]);
        if (n as i64) < 0 {
            return Err(n);
        }
        let mut bytes = vec![0; n as usize];
        self.mem.read(GuestAddr(BUF), &mut bytes).unwrap();
        let mut seen = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let event = &bytes[at..];
            let len = u32::from_le_bytes(event[..4].try_into().unwrap()) as usize;
            assert_eq!((event[4], event[6]), (3, 24));
            let mut records = Vec::new();
            let mut r = 24;
            while r < len {
                let size = u16::from_le_bytes([event[r + 2], event[r + 3]]) as usize;
                records.push((event[r], event[r + 4..r + size].to_vec()));
                r += size;
            }
            seen.push(Seen {
                mask: u64::from_le_bytes(event[8..16].try_into().unwrap()),
                fd: i32::from_le_bytes(event[16..20].try_into().unwrap()),
                pid: i32::from_le_bytes(event[20..24].try_into().unwrap()),
                records,
            });
            at += len;
        }
        Ok(seen)
    }
    fn fdinfo(&mut self, fd: u64) -> String {
        let path = format!("/proc/self/fdinfo/{fd}");
        let file = self.open(&path, 0);
        let n = self.ret(0, &[file, BUF, 4096]);
        self.close(file);
        let mut bytes = vec![0; n as usize];
        self.mem.read(GuestAddr(BUF), &mut bytes).unwrap();
        String::from_utf8(bytes).unwrap()
    }
    fn link(&mut self, fd: u64) -> String {
        let path = self.put(format!("/proc/self/fd/{fd}").as_bytes());
        let n = self.ret(89, &[path, BUF, 256]);
        let mut bytes = vec![0; n as usize];
        self.mem.read(GuestAddr(BUF), &mut bytes).unwrap();
        String::from_utf8(bytes).unwrap()
    }
}

#[test]
fn init_checks_its_flags_in_linuxs_order() {
    let mut f = fixture();
    let einval = errno(Errno::EINVAL);
    assert_eq!(f.init(0x10000, 0), einval);
    assert_eq!(f.init(0, 0o1000), einval);
    assert_eq!(f.init(0, 3), einval);
    assert_eq!(f.init(CLASS_CONTENT | 8, 0), einval);
    assert_eq!(f.init(REPORT_FID | CLASS_CONTENT, 0), einval);
    assert_eq!(f.init(REPORT_NAME, 0), einval);
    assert_eq!(
        f.init(REPORT_TARGET_FID | REPORT_DIR_FID | REPORT_NAME, 0),
        einval
    );
    assert_eq!(f.init(0x4000 | CLASS_CONTENT, 0), einval);
    assert_eq!(f.init(0x4000 | REPORT_FID, 0), einval);
    let fan = f.init(0x1 | NONBLOCK | REPORT_FID, 0);
    assert!((fan as i64) >= 0);
    assert_eq!(f.link(fan), "anon_inode:[fanotify]");
    assert!(
        f.fdinfo(fan)
            .contains("fanotify flags:203 event-flags:8000\n")
    );
    assert_eq!(f.read(fan, 64).unwrap_err(), errno(Errno::EAGAIN));
    // An unprivileged caller may only report by handle.
    assert_eq!(f.ret(117, &[1000, 1000, 1000]), 0);
    assert_eq!(f.init(0, 0), errno(Errno::EPERM));
    assert_eq!(f.init(REPORT_FID | REPORT_TID, 0), errno(Errno::EPERM));
    let unpriv = f.init(REPORT_FID, 0);
    assert!((unpriv as i64) >= 0);
    f.touch("/tmp/u");
    assert_eq!(
        f.mark(unpriv, ADD | MOUNT, OPEN, "/tmp"),
        errno(Errno::EPERM)
    );
    assert_eq!(f.mark(unpriv, ADD, OPEN, "/tmp/u"), 0);
}

#[test]
fn mark_checks_and_fdinfo() {
    let mut f = fixture();
    let einval = errno(Errno::EINVAL);
    f.mkdir("/tmp/d");
    f.touch("/tmp/f");
    let fan = f.init(0, 0);
    let dfid = f.init(REPORT_DIR_FID | REPORT_NAME, 0);
    let content = f.init(CLASS_CONTENT, 0);
    assert_eq!(f.mark(fan, ADD, 1 << 32, "/tmp/f"), einval);
    assert_eq!(f.mark(fan, ADD | 0x800, OPEN, "/tmp/f"), einval);
    assert_eq!(f.mark(fan, 0, OPEN, "/tmp/f"), einval);
    assert_eq!(f.mark(fan, ADD, 0, "/tmp/f"), einval);
    assert_eq!(f.mark(fan, FLUSH | 4, 0, "/tmp/f"), einval);
    assert_eq!(f.mark(fan, ADD, 0x2000, "/tmp/f"), einval);
    assert_eq!(
        f.mark(fan, ADD | IGNORE | IGNORED_MASK, OPEN, "/tmp/f"),
        einval
    );
    assert_eq!(f.mark(99, ADD, OPEN, "/tmp/f"), errno(Errno::EBADF));
    assert_eq!(f.mark(1, ADD, OPEN, "/tmp/f"), einval);
    assert_eq!(f.mark(fan, ADD, OPEN_PERM, "/tmp/f"), einval);
    assert_eq!(f.mark(content, ADD, OPEN_PERM, "/tmp/f"), 0);
    assert_eq!(f.mark(content, ADD, 0x10_0000, "/tmp/f"), einval);
    assert_eq!(f.mark(content, ADD, OPEN_PERM, "/proc/self/status"), einval);
    // An open of the file would now wait for the group's answer.
    assert_eq!(f.mark(content, REMOVE, OPEN_PERM, "/tmp/f"), 0);
    assert_eq!(f.mark(fan, ADD | MOUNT | EVICTABLE, OPEN, "/tmp"), einval);
    assert_eq!(f.mark(fan, ADD, CREATE, "/tmp/d"), einval);
    assert_eq!(f.mark(dfid, ADD | MOUNT, CREATE, "/tmp"), einval);
    assert_eq!(f.mark(fan, ADD, 0x8000, "/tmp/f"), einval);
    let fid = f.init(REPORT_FID, 0);
    assert_eq!(f.mark(fid, ADD, RENAME, "/tmp/d"), einval);
    assert_eq!(f.mark(fan, ADD, OPEN, "/tmp/missing"), errno(Errno::ENOENT));
    assert_eq!(
        f.mark(fan, ADD | ONLYDIR, OPEN, "/tmp/f"),
        errno(Errno::ENOTDIR)
    );
    assert_eq!(f.mark(dfid, ADD, RENAME, "/tmp/f"), errno(Errno::ENOTDIR));
    assert_eq!(
        f.mark(fan, ADD | IGNORE, OPEN, "/tmp/d"),
        errno(Errno::EISDIR)
    );
    assert_eq!(f.mark(fan, ADD | IGNORE | MOUNT, OPEN, "/tmp"), einval);
    assert_eq!(f.mark(fan, REMOVE, OPEN, "/tmp/d"), errno(Errno::ENOENT));
    assert_eq!(
        f.mark(dfid, ADD | FILESYSTEM, OPEN, "/proc/self/status"),
        errno(Errno::EOPNOTSUPP)
    );
    // A descriptor itself, by no path.
    let fd = f.open("/tmp/f", 0);
    assert_eq!(f.ret(MARK, &[fan, ADD, OPEN, fd, 0]), 0);
    assert_eq!(
        f.ret(MARK, &[fan, ADD | ONLYDIR, OPEN, fd, 0]),
        errno(Errno::ENOTDIR)
    );
    assert_eq!(f.ret(MARK, &[fan, ADD, OPEN, 77, 0]), errno(Errno::EBADF));
    f.close(fd);
    // What fdinfo shows, the newest mark first.
    assert_eq!(
        f.mark(dfid, ADD, CREATE | ONDIR | EVENT_ON_CHILD, "/tmp/d"),
        0
    );
    assert_eq!(f.mark(dfid, ADD, OPEN, "/tmp/f"), 0);
    assert_eq!(
        f.mark(dfid, ADD | IGNORED_MASK, CLOSE_WRITE | ONDIR, "/tmp/f"),
        0
    );
    assert_eq!(
        f.mark(dfid, ADD | IGNORED_MASK | SURV_MODIFY, ACCESS, "/tmp/f"),
        0
    );
    assert_eq!(
        f.mark(dfid, ADD | IGNORE, ACCESS, "/tmp/f"),
        errno(Errno::EEXIST)
    );
    assert_eq!(
        f.mark(dfid, ADD | IGNORE | SURV_MODIFY, ACCESS | ONDIR, "/tmp/d"),
        0
    );
    assert_eq!(
        f.mark(dfid, ADD | IGNORED_MASK, ACCESS, "/tmp/d"),
        errno(Errno::EEXIST)
    );
    assert_eq!(
        f.mark(dfid, ADD | EVICTABLE, OPEN, "/tmp/d"),
        errno(Errno::EEXIST)
    );
    assert_eq!(f.mark(dfid, ADD | FILESYSTEM, ATTRIB, "/tmp"), 0);
    assert_eq!(f.mark(dfid, ADD | MOUNT, CLOSE_WRITE, "/tmp"), 0);
    let info = f.fdinfo(dfid);
    let lines: Vec<&str> = info
        .lines()
        .filter(|l| l.starts_with("fanotify "))
        .collect();
    assert_eq!(lines[0], "fanotify flags:c00 event-flags:8000");
    assert!(lines[1].starts_with("fanotify mnt_id:"), "{info}");
    assert!(
        lines[1].ends_with("mflags:0 mask:8000008 ignored_mask:0"),
        "{info}"
    );
    assert!(lines[2].starts_with("fanotify sdev:"), "{info}");
    assert!(
        lines[2].ends_with("mflags:0 mask:8000004 ignored_mask:0"),
        "{info}"
    );
    // The file's mark, its own mask with its ignore mask.
    assert!(
        lines[3].contains("mflags:40 mask:8000020 ignored_mask:9"),
        "{info}"
    );
    assert!(
        lines[3].contains("fhandle-bytes:c fhandle-type:1 f_handle:"),
        "{info}"
    );
    // The directory's one mark, its events and what it ignores.
    assert!(
        lines[4].contains("mflags:440 mask:48000100 ignored_mask:40000001"),
        "{info}"
    );
    assert_eq!(lines.len(), 5, "{info}");
    assert_eq!(
        f.mark(dfid, REMOVE, CREATE | ONDIR | EVENT_ON_CHILD, "/tmp/d"),
        0
    );
    assert_eq!(
        f.mark(dfid, REMOVE | IGNORED_MASK, CLOSE_WRITE, "/tmp/f"),
        0
    );
    let info = f.fdinfo(dfid);
    assert!(info.contains("mask:8000020 ignored_mask:1 "), "{info}");
    // The directory's mark keeps what it ignores.
    assert!(
        info.contains("mflags:440 mask:0 ignored_mask:40000001"),
        "{info}"
    );
    assert_eq!(f.ret(MARK, &[dfid, FLUSH, 0, AT_FDCWD, 0]), 0);
    let info = f.fdinfo(dfid);
    assert_eq!(info.matches("fanotify ").count(), 3, "{info}");
    assert_eq!(f.ret(MARK, &[dfid, FLUSH | FILESYSTEM, 0, AT_FDCWD, 0]), 0);
    assert_eq!(f.ret(MARK, &[dfid, FLUSH | MOUNT, 0, AT_FDCWD, 0]), 0);
    assert_eq!(f.fdinfo(dfid).matches("fanotify ").count(), 1);
}

#[test]
fn path_events_give_descriptors_and_merge() {
    let mut f = fixture();
    f.mkdir("/tmp/d");
    f.touch("/tmp/d/g");
    f.touch("/tmp/f");
    let fan = f.init(NONBLOCK, 0o2_000_000);
    assert_eq!(
        f.mark(
            fan,
            ADD,
            OPEN | ACCESS | MODIFY | CLOSE_WRITE | CLOSE_NOWRITE,
            "/tmp/f"
        ),
        0
    );
    let fd = f.open("/tmp/f", 2);
    let x = f.put(b"x");
    assert_eq!(f.ret(1, &[fd, x, 1]), 1);
    assert_eq!(f.ret(8, &[fd, 0, 0]), 0);
    assert_eq!(f.ret(0, &[fd, BUF, 1]), 1);
    f.close(fd);
    let seen = f.read(fan, 4096).unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].mask, OPEN | MODIFY | ACCESS | CLOSE_WRITE);
    assert_eq!(seen[0].pid, 1);
    let event_fd = seen[0].fd as u64;
    assert_eq!(f.link(event_fd), "/tmp/f");
    // Close-on-exec, as the flags asked, which `F_GETFL` keeps; read only.
    assert_eq!(f.ret(72, &[event_fd, 1]), 1);
    assert_eq!(f.ret(72, &[event_fd, 3]) & 0o2_000_003, 0o2_000_000);
    // Reading the descriptor tells no one.
    assert_eq!(f.ret(0, &[event_fd, BUF, 1]), 1);
    f.close(event_fd);
    assert_eq!(f.read(fan, 4096).unwrap_err(), errno(Errno::EAGAIN));
    // A buffer too small for the first.
    let fd = f.open("/tmp/f", 0);
    f.close(fd);
    let n = f.put(&[0; 4]);
    assert_eq!(f.ret(16, &[fan, 0x541b, n]), 0);
    let mut queued = [0; 4];
    f.mem.read(GuestAddr(n), &mut queued).unwrap();
    assert_eq!(i32::from_le_bytes(queued), 24);
    assert_eq!(f.read(fan, 10).unwrap_err(), errno(Errno::EINVAL));
    assert_eq!(f.read(fan, 4096).unwrap()[0].mask, OPEN | CLOSE_NOWRITE);
    // Children of a directory that watches them, and the directory itself.
    assert_eq!(f.mark(fan, ADD, OPEN | EVENT_ON_CHILD | ONDIR, "/tmp/d"), 0);
    let fd = f.open("/tmp/d/g", 0);
    f.close(fd);
    let dir = f.open("/tmp/d", 0o200_000);
    f.close(dir);
    let seen = f.read(fan, 4096).unwrap();
    assert_eq!(
        seen.iter().map(|s| s.mask).collect::<Vec<_>>(),
        [OPEN, OPEN]
    );
    for s in &seen {
        f.close(s.fd as u64);
    }
    // An ignore mask, which a modification ends.
    assert_eq!(f.mark(fan, ADD | IGNORED_MASK, OPEN, "/tmp/d/g"), 0);
    let fd = f.open("/tmp/d/g", 0);
    f.close(fd);
    assert_eq!(f.read(fan, 4096).unwrap_err(), errno(Errno::EAGAIN));
    let fd = f.open("/tmp/d/g", 1);
    assert_eq!(f.ret(1, &[fd, x, 1]), 1);
    f.close(fd);
    let _ = f.read(fan, 4096);
    let fd = f.open("/tmp/d/g", 0);
    f.close(fd);
    let seen = f.read(fan, 4096).unwrap();
    assert_eq!(seen[0].mask, OPEN);
    f.close(seen[0].fd as u64);
    // A descriptor that cannot be opened: the error, or the read's.
    let err = f.init(NONBLOCK | REPORT_FD_ERROR, 2);
    assert_eq!(f.mark(err, ADD, OPEN | ONDIR, "/tmp/d"), 0);
    let plain = f.init(NONBLOCK, 2);
    assert_eq!(f.mark(plain, ADD, OPEN | ONDIR, "/tmp/d"), 0);
    let dir = f.open("/tmp/d", 0o200_000);
    f.close(dir);
    // A directory opens for writing too, as `dentry_open` checks nothing.
    let seen = f.read(err, 4096).unwrap();
    assert!(seen[0].fd >= 0);
    assert_eq!(f.ret(72, &[seen[0].fd as u64, 3]) & 3, 2);
    assert_eq!(f.read(plain, 4096).unwrap().len(), 1);
    assert_eq!(f.read(plain, 4096).unwrap_err(), errno(Errno::EAGAIN));
    // Both groups' reads give descriptors; a full table gives the error.
    let nofile = f.put(&[1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
    let dir = f.open("/tmp/d", 0o200_000);
    f.close(dir);
    assert_eq!(f.ret(160, &[7, nofile]), 0);
    assert_eq!(f.read(err, 4096).unwrap()[0].fd, -24);
    assert_eq!(f.read(plain, 4096).unwrap_err(), errno(Errno::EMFILE));
    let _ = f.read(fan, 4096);
    // Truncation by path is no path event.
    let path = f.put(b"/tmp/f");
    assert_eq!(f.ret(76, &[path, 0]), 0);
    assert_eq!(f.read(fan, 4096).unwrap_err(), errno(Errno::EAGAIN));
}

#[test]
fn fid_modes_report_handles_and_names() {
    let mut f = fixture();
    f.mkdir("/tmp/d");
    f.touch("/tmp/f");
    let fid = f.init(NONBLOCK | REPORT_FID, 0);
    let dfid = f.init(NONBLOCK | REPORT_DIR_FID | REPORT_NAME, 0);
    let target = f.init(
        NONBLOCK | REPORT_DIR_FID | REPORT_NAME | REPORT_FID | REPORT_TARGET_FID,
        0,
    );
    let dir_only = f.init(NONBLOCK | REPORT_DIR_FID, 0);
    let all = CREATE | DELETE | MOVED_FROM | MOVED_TO | ATTRIB | ONDIR;
    assert_eq!(
        f.mark(fid, ADD, all | EVENT_ON_CHILD | DELETE_SELF, "/tmp"),
        0
    );
    assert_eq!(f.mark(fid, ADD, DELETE_SELF | MOVE_SELF, "/tmp/f"), 0);
    assert_eq!(
        f.mark(
            dfid,
            ADD | FILESYSTEM,
            all | RENAME | DELETE_SELF | MOVE_SELF | OPEN,
            "/tmp"
        ),
        0
    );
    assert_eq!(
        f.mark(target, ADD, all | RENAME | EVENT_ON_CHILD, "/tmp"),
        0
    );
    assert_eq!(
        f.mark(
            dir_only,
            ADD,
            CREATE | ATTRIB | EVENT_ON_CHILD | ONDIR,
            "/tmp"
        ),
        0
    );
    f.touch("/tmp/h");
    let d = f.put(b"/tmp/d/x");
    assert_eq!(f.ret(83, &[d, 0o755]), 0);
    let (old, new) = (f.put(b"/tmp/h"), f.put(b"/tmp/d/h"));
    assert_eq!(f.ret(82, &[old, new]), 0);
    let fp = f.put(b"/tmp/f");
    assert_eq!(f.ret(90, &[fp, 0o600]), 0);
    assert_eq!(f.ret(87, &[fp]), 0);
    let types = |seen: &[Seen]| -> Vec<(u64, Vec<u8>)> {
        seen.iter()
            .map(|s| (s.mask, s.records.iter().map(|r| r.0).collect()))
            .collect()
    };
    // The directory's entries are events of the directory's handle, which
    // merge; so are the file's.
    let seen = f.read(fid, 4096).unwrap();
    assert_eq!(
        types(&seen),
        [
            (CREATE | MOVED_FROM | DELETE, vec![1]),
            (ATTRIB | DELETE_SELF, vec![1]),
        ],
        "{seen:?}"
    );
    assert!(seen.iter().all(|s| s.fd == -1 && s.pid == 1));
    let seen = f.read(dfid, 4096).unwrap();
    // Each directory and name is one event: h's creation, open and move
    // away merge; f's change of mode and removal do. A file's own events
    // with no directory (its move, its end) are not reported.
    assert_eq!(
        types(&seen),
        [
            (CREATE | OPEN | MOVED_FROM, vec![2]),
            (CREATE | ONDIR, vec![2]),
            (RENAME, vec![10, 12]),
            (MOVED_TO, vec![2]),
            (ATTRIB | DELETE, vec![2]),
        ],
        "{seen:?}"
    );
    // The name follows the directory's handle, NUL-terminated.
    let record = &seen[0].records[0].1;
    let bytes = u32::from_le_bytes(record[8..12].try_into().unwrap()) as usize;
    assert_eq!(&record[16 + bytes..16 + bytes + 2], b"h\0");
    let seen = f.read(target, 4096).unwrap();
    assert_eq!(
        types(&seen),
        [
            (CREATE | MOVED_FROM, vec![2, 1]),
            (RENAME, vec![10, 1]),
            (ATTRIB | DELETE, vec![2, 1]),
        ],
        "{seen:?}"
    );
    let seen = f.read(dir_only, 4096).unwrap();
    // Only the directory's handle, so one event.
    assert_eq!(types(&seen), [(CREATE | ATTRIB, vec![3])], "{seen:?}");
    // A directory's own event, with its name as ".".
    let dot = f.init(NONBLOCK | REPORT_DIR_FID | REPORT_NAME, 0);
    assert_eq!(f.mark(dot, ADD, OPEN | ONDIR, "/tmp/d"), 0);
    let dir = f.open("/tmp/d", 0o200_000);
    f.close(dir);
    let seen = f.read(dot, 4096).unwrap();
    assert_eq!(types(&seen), [(OPEN | ONDIR, vec![2])]);
    let record = &seen[0].records[0].1;
    let bytes = u32::from_le_bytes(record[8..12].try_into().unwrap()) as usize;
    assert_eq!(&record[16 + bytes..16 + bytes + 2], b".\0");
}

#[test]
fn pidfds_overflow_and_responses() {
    let mut f = fixture();
    f.touch("/tmp/f");
    assert_eq!(f.init(REPORT_PIDFD | REPORT_TID, 0), errno(Errno::EINVAL));
    let fan = f.init(NONBLOCK | REPORT_FID | REPORT_PIDFD, 0);
    assert_eq!(f.mark(fan, ADD, OPEN, "/tmp/f"), 0);
    let fd = f.open("/tmp/f", 0);
    f.close(fd);
    let seen = f.read(fan, 4096).unwrap();
    assert_eq!(
        seen[0].records.iter().map(|r| r.0).collect::<Vec<_>>(),
        [1, 4]
    );
    let pidfd = i32::from_le_bytes(seen[0].records[1].1[..4].try_into().unwrap());
    assert!(pidfd >= 0);
    assert!(f.link(pidfd as u64).contains("pidfd"));
    // Past the limit only the overflow event, once.
    f.kernel
        .files
        .caches
        .notify
        .fan
        .limits
        .events
        .store(2, std::sync::atomic::Ordering::SeqCst);
    let small = f.init(NONBLOCK | REPORT_DIR_FID | REPORT_NAME | REPORT_TID, 0);
    assert_eq!(
        f.mark(small, ADD | FILESYSTEM, CREATE | EVENT_ON_CHILD, "/tmp"),
        0
    );
    for name in ["/tmp/a", "/tmp/b", "/tmp/c", "/tmp/e"] {
        f.touch(name);
    }
    let seen = f.read(small, 4096).unwrap();
    assert_eq!(
        seen.iter().map(|s| s.mask).collect::<Vec<_>>(),
        [CREATE, CREATE, Q_OVERFLOW]
    );
    assert_eq!((seen[2].fd, seen[2].pid, seen[2].records.len()), (-1, 0, 0));
    // Responses are checked, then name no event.
    let write = |f: &mut Fixture, fan: u64, fd: i32, response: u32, extra: &[u8]| {
        let mut bytes = fd.to_le_bytes().to_vec();
        bytes.extend_from_slice(&response.to_le_bytes());
        bytes.extend_from_slice(extra);
        let at = f.put(&bytes);
        f.ret(1, &[fan, at, bytes.len() as u64])
    };
    let einval = errno(Errno::EINVAL);
    assert_eq!(write(&mut f, fan, 5, 1, &[]), errno(Errno::ENOENT));
    let at = f.put(&[0; 4]);
    assert_eq!(f.ret(1, &[fan, at, 4]), einval);
    assert_eq!(write(&mut f, fan, 5, 3, &[]), einval);
    assert_eq!(write(&mut f, fan, 5, 1 | 5 << 24, &[]), einval);
    assert_eq!(write(&mut f, fan, 5, 2 | 5 << 24, &[]), einval);
    assert_eq!(write(&mut f, fan, 5, 0x11, &[]), einval);
    assert_eq!(write(&mut f, fan, -5, 1, &[]), einval);
    let rule = [1, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(write(&mut f, fan, -1, 0x21, &rule), 20);
    assert_eq!(write(&mut f, fan, 5, 0x21, &rule[..8]), einval);
    assert_eq!(
        write(&mut f, fan, 5, 0x21, &[2, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        einval
    );
    assert_eq!(write(&mut f, fan, 5, 0x21, &rule), errno(Errno::ENOENT));
    // Its ioctls.
    assert_eq!(f.ret(16, &[fan, 0x5401, at]), errno(Errno::ENOTTY));
    // A file's end takes its marks.
    let marks = f.kernel.files.caches.notify.fan.marks_count();
    let p = f.put(b"/tmp/f");
    assert_eq!(f.ret(87, &[p]), 0);
    assert_eq!(f.kernel.files.caches.notify.fan.marks_count(), marks - 1);
    f.close(small);
    assert_eq!(f.kernel.files.caches.notify.fan.marks_count(), marks - 2);
}

#[test]
fn a_mount_namespace_mark_hears_mounts_come_go_and_move() {
    const REPORT_MNT: u64 = 0x4000;
    const MNTNS: u64 = 0x110;
    const ATTACH: u64 = 0x100_0000;
    const DETACH: u64 = 0x200_0000;
    let mut f = fixture();
    // A namespace's file is nsfs's, by its path or a descriptor, which a
    // mount namespace mark needs.
    let ns = f.put(b"/proc/self/ns/mnt");
    assert_eq!(f.ret(137, &[ns, BUF]), 0);
    let mut kind = [0; 8];
    f.mem.read(GuestAddr(BUF), &mut kind).unwrap();
    assert_eq!(u64::from_le_bytes(kind), 0x6e73_6673);
    let fd = f.open("/proc/self/ns/mnt", 0);
    assert_eq!(f.ret(138, &[fd, BUF]), 0);
    f.mem.read(GuestAddr(BUF), &mut kind).unwrap();
    assert_eq!(u64::from_le_bytes(kind), 0x6e73_6673);
    f.close(fd);
    let fan = f.init(REPORT_MNT | NONBLOCK, 0);
    let pidfd = f.init(REPORT_MNT | REPORT_PIDFD | NONBLOCK, 0);
    let detach = f.init(REPORT_MNT | NONBLOCK, 0);
    for (group, mask) in [(fan, ATTACH | DETACH), (pidfd, ATTACH), (detach, DETACH)] {
        assert_eq!(f.mark(group, ADD | MNTNS, mask, "/proc/self/ns/mnt"), 0);
    }
    f.mkdir("/tmp/m");
    f.mkdir("/tmp/n");
    let unique = |f: &mut Fixture, path: &str| {
        let path = f.put(path.as_bytes());
        assert_eq!(f.ret(332, &[AT_FDCWD, path, 0, 0x4000, BUF]), 0);
        let mut id = [0; 8];
        f.mem.read(GuestAddr(BUF + 144), &mut id).unwrap();
        id.to_vec()
    };
    let mount = |f: &mut Fixture, source: &str, target: &str, kind: &str, flags: u64| {
        let (source, target) = (f.put(source.as_bytes()), f.put(target.as_bytes()));
        let kind = if kind.is_empty() {
            0
        } else {
            f.put(kind.as_bytes())
        };
        f.ret(165, &[source, target, kind, flags, 0])
    };
    type Events = Vec<(u64, i32, i32, Vec<(u8, Vec<u8>)>)>;
    let events = |f: &mut Fixture, group: u64| -> Events {
        match f.read(group, 4096) {
            Ok(seen) => seen
                .into_iter()
                .map(|s| (s.mask, s.fd, s.pid, s.records))
                .collect(),
            Err(e) => {
                assert_eq!(e, errno(Errno::EAGAIN));
                Vec::new()
            }
        }
    };
    let record = |id: &[u8]| (7u8, [&[0; 4][..], id].concat());
    assert_eq!(mount(&mut f, "none", "/tmp/m", "tmpfs", 0), 0);
    let m = unique(&mut f, "/tmp/m");
    assert_eq!(events(&mut f, fan), [(ATTACH, -1, 1, vec![record(&m)])]);
    // The pidfd record comes before the mount's.
    let seen = events(&mut f, pidfd);
    assert_eq!(seen.len(), 1);
    assert_eq!((seen[0].0, seen[0].3.len()), (ATTACH, 2));
    assert_eq!((seen[0].3[0].0, &seen[0].3[1]), (4, &record(&m)));
    assert!(events(&mut f, detach).is_empty());
    // A move is both events, each group taking those it asked for.
    assert_eq!(mount(&mut f, "/tmp/m", "/tmp/n", "", 0x2000), 0);
    assert_eq!(
        events(&mut f, fan),
        [(ATTACH | DETACH, -1, 1, vec![record(&m)])]
    );
    assert_eq!(events(&mut f, pidfd).len(), 1);
    assert_eq!(events(&mut f, detach), [(DETACH, -1, 1, vec![record(&m)])]);
    let path = f.put(b"/tmp/n");
    assert_eq!(f.ret(166, &[path, 2]), 0);
    assert_eq!(events(&mut f, fan), [(DETACH, -1, 1, vec![record(&m)])]);
    assert!(events(&mut f, pidfd).is_empty());
    assert_eq!(events(&mut f, detach).len(), 1);
    // Once the mark goes, nothing more is told.
    assert_eq!(
        f.mark(fan, REMOVE | MNTNS, ATTACH | DETACH, "/proc/self/ns/mnt"),
        0
    );
    assert_eq!(mount(&mut f, "none", "/tmp/m", "tmpfs", 0), 0);
    assert!(events(&mut f, fan).is_empty());
    assert_eq!(events(&mut f, pidfd).len(), 1);
    // The first namespace goes on when its table is replaced: the old
    // table's mounts are not told as gone, and the marks stay.
    let fs = paludarium_vfs::MemFs::new();
    let _ = <paludarium_vfs::MemFs as paludarium_vfs::HostFs>::mkdir(&fs, b"/tmp", 0o1777);
    f.kernel.files.set_file_system(Arc::new(fs));
    assert!(events(&mut f, detach).is_empty());
    f.mkdir("/tmp/m");
    assert_eq!(mount(&mut f, "none", "/tmp/m", "tmpfs", 0), 0);
    assert_eq!(events(&mut f, pidfd).len(), 1);
    assert!(events(&mut f, detach).is_empty());
}

#[test]
fn a_mount_namespace_that_ends_takes_out_each_mount_and_its_marks() {
    const REPORT_MNT: u64 = 0x4000;
    const MNTNS: u64 = 0x110;
    const ATTACH: u64 = 0x100_0000;
    const DETACH: u64 = 0x200_0000;
    let mut f = fixture();
    let fan = f.init(REPORT_MNT | NONBLOCK, 0);
    // Only a mount namespace's file takes the mark (`mnt_ns_from_dentry`).
    for other in [
        "/proc/self/ns/net",
        "/proc/self/ns/uts",
        "/proc/self/ns/user",
    ] {
        assert_eq!(
            f.mark(fan, ADD | MNTNS, ATTACH, other),
            errno(Errno::EINVAL)
        );
    }
    f.mkdir("/tmp/m");
    let target = f.put(b"none");
    let path = f.put(b"/tmp/m");
    let kind = f.put(b"tmpfs");
    assert_eq!(f.ret(165, &[target, path, kind, 0, 0]), 0);
    // A namespace of the tree at /tmp/m, marked by its descriptor's link.
    let ns = f.ret(428, &[AT_FDCWD, path, 2 | 0x8000]);
    assert!((ns as i64) >= 0, "{ns}");
    let link = format!("/proc/self/fd/{ns}");
    assert_eq!(f.mark(fan, ADD | MNTNS, ATTACH | DETACH, &link), 0);
    assert!(f.fdinfo(fan).contains("fanotify mnt_ns:"));
    assert_eq!(f.read(fan, 4096).unwrap_err(), errno(Errno::EAGAIN));
    f.close(ns);
    // Each mount goes, the one below its root first, then the mark with the
    // namespace.
    let seen = f.read(fan, 4096).unwrap();
    assert_eq!(seen.len(), 2, "{seen:?}");
    for event in &seen {
        assert_eq!((event.mask, event.fd, event.records.len()), (DETACH, -1, 1));
        assert_eq!(event.records[0].0, 7);
    }
    assert!(!f.fdinfo(fan).contains("fanotify mnt_ns:"));
    assert_eq!(
        f.mark(fan, ADD | MNTNS, ATTACH, &link),
        errno(Errno::ENOENT)
    );
}

/// The names a read's events give, with their masks, from the first
/// record of each (a directory and name).
fn named(seen: &[Seen]) -> Vec<(u64, String)> {
    seen.iter()
        .map(|s| {
            let record = &s.records[0].1;
            let bytes = u32::from_le_bytes(record[8..12].try_into().unwrap()) as usize;
            let name = &record[16 + bytes..];
            let end = name.iter().position(|&b| b == 0).unwrap();
            (s.mask, String::from_utf8(name[..end].to_vec()).unwrap())
        })
        .collect()
}

#[test]
fn an_event_merges_only_into_the_newest_128_of_its_bucket() {
    let mut f = fixture();
    let bucket =
        |name: &str| crate::fanotify::full_name_hash(name.len() as u64, name.as_bytes()) % 128;
    let first = "n00000";
    // Names whose events in one directory by one task share the first's
    // bucket, as on Linux, and some that do not.
    let names: Vec<String> = (1..20_000).map(|i| format!("n{i:05}")).collect();
    let alike: Vec<&String> = names
        .iter()
        .filter(|n| bucket(n) == bucket(first))
        .take(128)
        .collect();
    let other: Vec<&String> = names
        .iter()
        .filter(|n| bucket(n) != bucket(first))
        .take(40)
        .collect();
    assert_eq!(alike.len(), 128);
    let fan = f.init(NONBLOCK | REPORT_DIR_FID | REPORT_NAME, 0);
    for (dir, before) in [("/tmp/d", 127), ("/tmp/e", 128)] {
        f.next = DATA;
        f.mkdir(dir);
        assert_eq!(f.mark(fan, ADD, CREATE | DELETE, dir), 0);
        f.touch(&format!("{dir}/{first}"));
        for (i, name) in alike.iter().take(before).enumerate() {
            f.next = DATA + 0x100;
            f.touch(&format!("{dir}/{name}"));
            if let Some(name) = other.get(i) {
                f.touch(&format!("{dir}/{name}"));
            }
        }
        let path = f.put(format!("{dir}/{first}").as_bytes());
        assert_eq!(f.ret(87, &[path]), 0);
        let mut seen = Vec::new();
        while let Ok(more) = f.read(fan, 0x7000) {
            seen.extend(named(&more));
        }
        let of_first: Vec<u64> = seen
            .iter()
            .filter(|(_, n)| n == first)
            .map(|(m, _)| *m)
            .collect();
        if before == 127 {
            // The removal is the same event as the creation, 127 events of
            // its bucket later.
            assert_eq!(of_first, [CREATE | DELETE]);
        } else {
            // With 128 between them, the creation is past the window.
            assert_eq!(of_first, [CREATE, DELETE]);
        }
        assert_eq!(
            seen.len(),
            1 + before + other.len().min(before) + usize::from(before == 128)
        );
    }
}

#[test]
fn a_superblock_that_goes_takes_the_marks_on_it_and_its_files() {
    let mut f = fixture();
    f.mkdir("/tmp/m");
    let (source, target, kind) = (f.put(b"none"), f.put(b"/tmp/m"), f.put(b"tmpfs"));
    assert_eq!(f.ret(165, &[source, target, kind, 0, 0]), 0);
    f.touch("/tmp/m/f");
    let fan = f.init(NONBLOCK, 0);
    assert_eq!(f.mark(fan, ADD, OPEN, "/tmp/m/f"), 0);
    assert_eq!(f.mark(fan, ADD | FILESYSTEM, OPEN, "/tmp/m"), 0);
    assert_eq!(f.mark(fan, ADD, OPEN, "/tmp"), 0);
    let marks = |f: &mut Fixture| {
        f.fdinfo(fan)
            .lines()
            .filter(|l| l.starts_with("fanotify ") && !l.starts_with("fanotify flags:"))
            .count()
    };
    assert_eq!(marks(&mut f), 3);
    let target = f.put(b"/tmp/m");
    assert_eq!(f.ret(166, &[target, 0]), 0);
    // fsnotify_sb_delete: the file's and the file system's marks go; the
    // other file system's stays.
    assert_eq!(marks(&mut f), 1);
    // A tmpfs that takes the device next hears nothing of them.
    let (source, target, kind) = (f.put(b"none"), f.put(b"/tmp/m"), f.put(b"tmpfs"));
    assert_eq!(f.ret(165, &[source, target, kind, 0, 0]), 0);
    f.touch("/tmp/m/f");
    assert_eq!(f.read(fan, 4096).unwrap_err(), errno(Errno::EAGAIN));
    assert_eq!(f.kernel.files.caches.notify.fan.marks_count(), 1);
}
