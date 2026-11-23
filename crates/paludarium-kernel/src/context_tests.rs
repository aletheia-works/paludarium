//! File system contexts through the system call interface: `fsopen`'s
//! checks, the arguments, descriptors and parameters `fsconfig` refuses and
//! the messages they log, `fsmount` of the superblock it made, its
//! reconfiguration, and `fspick` of a mounted tmpfs and of the root, in a
//! mount namespace of a user namespace of the caller's own; then the
//! context descriptor's file operations (`F_SETFL` keeping the access
//! mode, as a namespace file keeps its flags), a full log, the values other
//! than flags and strings, `fsmount`'s other checks and a reconfiguration
//! that fails. The calls are those of the contexts case of
//! `tests/guests/processes/process.c`, made in the same order by a user of
//! ID 1000, as the forked child there makes them; the parent's lines (the
//! child's status and the clean-up) are left out. The expected lines are
//! what that case prints on native x86-64 Linux in the differential tests,
//! which compare it with Linux on every run: up to the second `m` line as
//! printed in the CI run of main at ade0d242, the rest as the case printed
//! when it gained them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::GuestAddr;

const DATA: u64 = 0x60_0000;
const SIZE: u64 = 0x1_0000;
/// Where the strings the calls name go, one after another.
const STRINGS: u64 = DATA;
/// The buffer `read`, `readlink`, `statfs` and `stat` fill.
const BUF: u64 = DATA + 0x8000;
const BUF_SIZE: u64 = 0x8000;

const READ: u64 = 0;
const WRITE: u64 = 1;
const OPEN: u64 = 2;
const CLOSE: u64 = 3;
const STAT: u64 = 4;
const LSEEK: u64 = 8;
const FCNTL: u64 = 72;
const FLOCK: u64 = 73;
const FTRUNCATE: u64 = 77;
const MKDIR: u64 = 83;
const READLINK: u64 = 89;
const SETRESUID: u64 = 117;
const SETRESGID: u64 = 119;
const STATFS: u64 = 137;
const PRCTL: u64 = 157;
const MOUNT: u64 = 165;
const UNSHARE: u64 = 272;
const MOVE_MOUNT: u64 = 429;
const FSOPEN: u64 = 430;
const FSCONFIG: u64 = 431;
const FSMOUNT: u64 = 432;
const FSPICK: u64 = 433;

const AT_FDCWD: u64 = (-100i64) as u64;
const CLONE_NEWNS: u64 = 0x0002_0000;
const CLONE_NEWUSER: u64 = 0x1000_0000;
const MS_REC: u64 = 0x4000;
const MS_PRIVATE: u64 = 1 << 18;
const PR_SET_DUMPABLE: u64 = 4;
const O_WRONLY: u64 = 1;
const O_NONBLOCK: u64 = 0x800;
const F_GETFD: u64 = 1;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const LOCK_EX: u64 = 2;
const BASE: &str = "/tmp/paludarium-contexts-x";
const M: &str = "/tmp/paludarium-contexts-x/m";

/// What the case's child printed on native Linux.
const EXPECTED: &str = r#"maps=0 0 0
private=0
fsopen bad=22 nope=19 null=14 link=anon_inode:[fscontext]
fsconfig negative=22 cmd=95 flag-value=22 string-none=22 create-key=22 badf=9 not-context=22 size-flag=22 size-bad=22 inode32-value=22 bogus=22 source-flag=22 source=0 source-again=22 size=0 mode=0 ro=0 rw=0
messages "e tmpfs: Bad value for 'size'" "e tmpfs: Bad value for 'size'" "e tmpfs: Unexpected value for 'inode32'" "e tmpfs: Unknown parameter 'bogus'" "e Non-string source" "e Multiple sources" end=61
fsmount before=22 reconfigure=16 create=0 again=16 param=16 flags=22 attrs=22 badf=9 mounted=1 twice=16 move=0
m rw,nosuid,noatime tmpfs src rw,size=1024k,mode=700,inode64
blocks=256 mode=700
reconfigure size=0 noswap=22 apply=0 blocks=1024
messages "e tmpfs: Turning off swap in unprivileged tmpfs mounts unsupported" end=61
fspick bad=22 not-root=22 missing=2 ro=0 create=16 apply=0 root=1 root-apply=1 root-again=16
m rw,nosuid,noatime tmpfs src ro,size=4096k,mode=700,inode64
descriptor write=22 seek=29 truncate=22 flock=0 getfl=0x2 setfl=0 now=0x802 ns=0x8000 ns-setfl=0 ns-now=0x8800 size-flag=22 small=90
messages "e tmpfs: Unknown parameter 'b1'" "e tmpfs: Unknown parameter 'b2'" "e tmpfs: Unknown parameter 'b3'" "e tmpfs: Unknown parameter 'b4'" "e tmpfs: Unknown parameter 'b5'" "e tmpfs: Unknown parameter 'b6'" "e tmpfs: Unknown parameter 'b7'" "e tmpfs: Unknown parameter 'b8'" end=61
values blob-none=22 blob-big=22 blob-fault=14 blob=22 path-dfd=22 path-none=2 path=22 path-empty=22 fd-bad=9 fd=22
messages "e tmpfs: Bad value for 'size'" "e Non-string source" "e Non-string source" "e Non-string source" end=61
mount create=0 not-context=22 attr-bad=22 two-atimes=22 mounted=1 cloexec=1
repick rw=0 apply=0 dirsync=0 refused=22 failed=16 failed-apply=16
messages end=61
m rw,nosuid,noatime tmpfs src rw,size=4096k,mode=700,inode64
"#;

/// A process's thread and what it prints.
struct Env {
    k: Box<Kernel>,
    t: Thread,
    m: Arc<AddressSpace>,
    /// Where the next string goes.
    next: u64,
    out: String,
}

impl Env {
    fn new() -> Self {
        let k = Box::new(Kernel::new(Arc::new(
            paludarium_host::testing::RecordingHost::new(),
        )));
        k.enter_thread(1);
        let t = Thread::new(
            1,
            CpuState::new(GuestAddr(0x40_0000), GuestAddr(DATA + SIZE)),
        );
        let m = Arc::new(AddressSpace::new());
        m.map_shared(
            Some(GuestAddr(DATA)),
            SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        Self {
            k,
            t,
            m,
            next: STRINGS,
            out: String::new(),
        }
    }

    /// A call's result, or `-errno`.
    fn call(&mut self, n: u64, a: [u64; 6]) -> i64 {
        let t = &mut self.t;
        t.cpu.gpr[reg::RAX] = n;
        t.cpu.gpr[reg::RDI] = a[0];
        t.cpu.gpr[reg::RSI] = a[1];
        t.cpu.gpr[reg::RDX] = a[2];
        t.cpu.gpr[reg::R10] = a[3];
        t.cpu.gpr[reg::R8] = a[4];
        t.cpu.gpr[reg::R9] = a[5];
        self.k
            .handle(t, &self.m, ExitReason::Syscall { rip: t.cpu.rip });
        t.cpu.gpr[reg::RAX] as i64
    }

    /// `n` bytes at `at`.
    fn bytes(&self, at: u64, n: usize) -> Vec<u8> {
        let mut out = vec![0; n];
        self.m.read(GuestAddr(at), &mut out).unwrap();
        out
    }

    /// `text` with its 0, in guest memory.
    fn put(&mut self, text: &str) -> u64 {
        let at = self.next;
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        self.m.write(GuestAddr(at), &bytes).unwrap();
        self.next += (bytes.len() as u64).next_multiple_of(16);
        assert!(self.next <= BUF, "out of string space");
        at
    }

    fn print(&mut self, text: &str) {
        self.out.push_str(text);
    }

    /// The guest's `RM`: ` name=` and `mt_result` (0, or the errno).
    fn rm(&mut self, name: &str, r: i64) {
        assert!(r <= 0, "{name}: {r}");
        self.out.push_str(&format!(" {name}={}", -r));
    }

    fn fsconfig(&mut self, fd: i64, cmd: u64, key: Option<&str>, value: Option<&str>) -> i64 {
        self.fsconfig_aux(fd, cmd, key, value, 0)
    }

    fn fsconfig_aux(
        &mut self,
        fd: i64,
        cmd: u64,
        key: Option<&str>,
        value: Option<&str>,
        aux: i64,
    ) -> i64 {
        let key = key.map_or(0, |k| self.put(k));
        let value = value.map_or(0, |v| self.put(v));
        self.call(FSCONFIG, [fd as u64, cmd, key, value, aux as u64, 0])
    }

    fn fsmount(&mut self, fd: i64, flags: u64, attrs: u64) -> i64 {
        self.call(FSMOUNT, [fd as u64, flags, attrs, 0, 0, 0])
    }

    fn fspick(&mut self, path: &str, flags: u64) -> i64 {
        let path = self.put(path);
        self.call(FSPICK, [AT_FDCWD, path, flags, 0, 0, 0])
    }

    fn close(&mut self, fd: i64) {
        assert_eq!(self.call(CLOSE, [fd as u64, 0, 0, 0, 0, 0]), 0);
    }

    /// The guest's `mt_write`: 0, or the errno of the open or the write.
    fn write_file(&mut self, path: &str, text: &str) -> i64 {
        let path = self.put(path);
        let fd = self.call(OPEN, [path, O_WRONLY, 0, 0, 0, 0]);
        if fd < 0 {
            return -fd;
        }
        let len = text.len() as u64;
        let text = self.put(text);
        let r = self.call(WRITE, [fd as u64, text, len, 0, 0, 0]);
        self.close(fd);
        if r == len as i64 { 0 } else { -r }
    }

    /// The whole file at `path`.
    fn whole(&mut self, path: &str) -> String {
        let path = self.put(path);
        let fd = self.call(OPEN, [path, 0, 0, 0, 0, 0]);
        assert!(fd >= 0, "{fd}");
        let mut all = Vec::new();
        loop {
            let n = self.call(READ, [fd as u64, BUF, BUF_SIZE, 0, 0, 0]);
            assert!(n >= 0, "{n}");
            if n == 0 {
                break;
            }
            all.extend(self.bytes(BUF, n as usize));
        }
        self.close(fd);
        String::from_utf8(all).unwrap()
    }

    /// The guest's `fc_messages`: each message in quotes, then `end=` and
    /// the errno of the read after the last.
    fn messages(&mut self, fd: i64) {
        let end = loop {
            let n = self.call(READ, [fd as u64, BUF, 299, 0, 0, 0]);
            if n <= 0 {
                break -n;
            }
            let bytes = self.bytes(BUF, n as usize);
            let text = String::from_utf8(bytes).unwrap();
            self.out.push_str(&format!(
                " \"{}\"",
                text.strip_suffix('\n').unwrap_or(&text)
            ));
        };
        self.out.push_str(&format!(" end={end}\n"));
    }

    /// The guest's `fc_info`: the mount's options, the type, the source and
    /// the superblock's options up to `nr_inodes`, without the owner, of
    /// the last mountinfo line at `point`.
    fn info(&mut self, label: &str, point: &str) {
        let mut shown = "none".to_string();
        for line in self.whole("/proc/self/mountinfo").lines() {
            let fields: Vec<&str> = line.split(' ').collect();
            if fields.get(4) != Some(&point) {
                continue;
            }
            let after = line.split_once(" - ").map_or("", |(_, rest)| rest);
            let mut rest = after.split(' ');
            let (kind, source) = (rest.next().unwrap_or(""), rest.next().unwrap_or(""));
            let mut sb = rest.next().unwrap_or("").to_string();
            if let Some(cut) = sb.find(",nr_inodes") {
                sb.truncate(cut);
            }
            for id in [",uid=", ",gid="] {
                if let Some(at) = sb.find(id) {
                    let end = sb[at + 1..].find(',').map_or(sb.len(), |e| at + 1 + e);
                    sb.replace_range(at..end, "");
                }
            }
            shown = format!("{} {kind} {source} {sb}", fields[5]);
        }
        self.out.push_str(&format!("{label} {shown}\n"));
    }

    /// `statfs`'s `f_blocks` of `path`.
    fn blocks(&mut self, path: &str) -> u64 {
        let path = self.put(path);
        assert_eq!(self.call(STATFS, [path, BUF, 0, 0, 0, 0]), 0);
        self.m.read_u64(GuestAddr(BUF + 16)).unwrap()
    }
}

/// The contexts case's child: a user of ID 1000 in a user and mount
/// namespace of its own, which maps it to 0, makes, mounts, reconfigures
/// and picks a tmpfs as on native Linux.
#[test]
fn file_system_contexts_as_linux() {
    let mut e = Env::new();
    // The case's directories, made by the user, then the user alone.
    for dir in [BASE, M] {
        let dir = e.put(dir);
        assert_eq!(e.call(MKDIR, [dir, 0o755, 0, 0, 0, 0]), 0);
    }
    assert_eq!(e.call(SETRESGID, [1000, 1000, 1000, 0, 0, 0]), 0);
    assert_eq!(e.call(SETRESUID, [1000, 1000, 1000, 0, 0, 0]), 0);
    assert_eq!(e.call(PRCTL, [PR_SET_DUMPABLE, 1, 0, 0, 0, 0]), 0);
    assert_eq!(
        e.call(UNSHARE, [CLONE_NEWUSER | CLONE_NEWNS, 0, 0, 0, 0, 0]),
        0
    );
    let setgroups = e.write_file("/proc/self/setgroups", "deny");
    let uids = e.write_file("/proc/self/uid_map", "0 1000 1");
    let gids = e.write_file("/proc/self/gid_map", "0 1000 1");
    e.print(&format!("maps={setgroups} {uids} {gids}\n"));
    let root = e.put("/");
    let r = e.call(MOUNT, [0, root, 0, MS_REC | MS_PRIVATE, 0, 0]);
    e.print(&format!("private={}\n", -r));

    e.print("fsopen");
    let (tmpfs, nope) = (e.put("tmpfs"), e.put("nope"));
    let r = e.call(FSOPEN, [tmpfs, 2, 0, 0, 0, 0]);
    e.rm("bad", r);
    let r = e.call(FSOPEN, [nope, 0, 0, 0, 0, 0]);
    e.rm("nope", r);
    let r = e.call(FSOPEN, [0, 0, 0, 0, 0, 0]);
    e.rm("null", r);
    let fd = e.call(FSOPEN, [tmpfs, 0, 0, 0, 0, 0]);
    assert!(fd >= 0, "{fd}");
    let path = e.put(&format!("/proc/self/fd/{fd}"));
    let n = e.call(READLINK, [path, BUF, 63, 0, 0, 0]);
    let link = String::from_utf8(e.bytes(BUF, n.max(0) as usize)).unwrap();
    e.print(&format!(" link={link}\n"));

    e.print("fsconfig");
    let r = e.fsconfig(-1, 0, Some("size"), None);
    e.rm("negative", r);
    let r = e.fsconfig(fd, 99, None, None);
    e.rm("cmd", r);
    let r = e.fsconfig(fd, 0, Some("size"), Some("1m"));
    e.rm("flag-value", r);
    let r = e.fsconfig(fd, 1, Some("size"), None);
    e.rm("string-none", r);
    let r = e.fsconfig(fd, 6, Some("size"), None);
    e.rm("create-key", r);
    let r = e.fsconfig(99, 0, Some("ro"), None);
    e.rm("badf", r);
    let r = e.fsconfig(1, 0, Some("ro"), None);
    e.rm("not-context", r);
    for (name, cmd, key, value) in [
        ("size-flag", 0, "size", None),
        ("size-bad", 1, "size", Some("1q")),
        ("inode32-value", 1, "inode32", Some("x")),
        ("bogus", 0, "bogus", None),
        ("source-flag", 0, "source", None),
        ("source", 1, "source", Some("src")),
        ("source-again", 1, "source", Some("src")),
        ("size", 1, "size", Some("1m")),
        ("mode", 1, "mode", Some("700")),
        ("ro", 0, "ro", None),
        ("rw", 0, "rw", None),
    ] {
        let r = e.fsconfig(fd, cmd, Some(key), value);
        e.rm(name, r);
    }
    e.print("\nmessages");
    e.messages(fd);

    e.print("fsmount");
    let r = e.fsmount(fd, 0, 0);
    e.rm("before", r);
    let r = e.fsconfig(fd, 7, None, None);
    e.rm("reconfigure", r);
    let r = e.fsconfig(fd, 6, None, None);
    e.rm("create", r);
    let r = e.fsconfig(fd, 6, None, None);
    e.rm("again", r);
    let r = e.fsconfig(fd, 1, Some("size"), Some("2m"));
    e.rm("param", r);
    let r = e.fsmount(fd, 4, 0);
    e.rm("flags", r);
    let r = e.fsmount(fd, 0, 0x40);
    e.rm("attrs", r);
    let r = e.fsmount(99, 0, 0);
    e.rm("badf", r);
    let mfd = e.fsmount(fd, 0, 0x10 | 0x02);
    e.print(&format!(" mounted={}", u8::from(mfd >= 0)));
    let r = e.fsmount(fd, 0, 0);
    e.rm("twice", r);
    let (empty, m) = (e.put(""), e.put(M));
    let r = e.call(MOVE_MOUNT, [mfd as u64, empty, AT_FDCWD, m, 4, 0]);
    e.rm("move", r);
    e.close(mfd);
    e.print("\n");
    e.info("m", M);
    let blocks = e.blocks(M);
    assert_eq!(e.call(STAT, [m, BUF, 0, 0, 0, 0]), 0);
    let mode = e.m.read_u64(GuestAddr(BUF + 24)).unwrap() as u32 & 0o7777;
    e.print(&format!("blocks={blocks} mode={mode:o}\n"));

    e.print("reconfigure");
    let r = e.fsconfig(fd, 1, Some("size"), Some("4m"));
    e.rm("size", r);
    let r = e.fsconfig(fd, 0, Some("noswap"), None);
    e.rm("noswap", r);
    let r = e.fsconfig(fd, 7, None, None);
    e.rm("apply", r);
    let blocks = e.blocks(M);
    e.print(&format!(" blocks={blocks}"));
    e.print("\nmessages");
    e.messages(fd);
    e.close(fd);

    e.print("fspick");
    let r = e.fspick(M, 16);
    e.rm("bad", r);
    let r = e.fspick(BASE, 0);
    e.rm("not-root", r);
    let r = e.fspick(&format!("{BASE}/missing"), 0);
    e.rm("missing", r);
    let picked = e.fspick(M, 0);
    assert!(picked >= 0, "{picked}");
    let r = e.fsconfig(picked, 0, Some("ro"), None);
    e.rm("ro", r);
    let r = e.fsconfig(picked, 6, None, None);
    e.rm("create", r);
    let r = e.fsconfig(picked, 7, None, None);
    e.rm("apply", r);
    e.close(picked);
    let root_fd = e.fspick("/", 0);
    e.print(&format!(" root={}", u8::from(root_fd >= 0)));
    let r = e.fsconfig(root_fd, 7, None, None);
    e.rm("root-apply", r);
    let r = e.fsconfig(root_fd, 7, None, None);
    e.rm("root-again", r);
    e.close(root_fd);
    e.print("\n");
    e.info("m", M);

    // The descriptor's own file operations, a message longer than the
    // buffer, and a log that drops its oldest once it holds 8.
    let fd2 = e.call(FSOPEN, [tmpfs, 0, 0, 0, 0, 0]);
    assert!(fd2 >= 0, "{fd2}");
    let x = e.put("x");
    e.print("descriptor");
    let r = e.call(WRITE, [fd2 as u64, x, 1, 0, 0, 0]);
    e.rm("write", r);
    let r = e.call(LSEEK, [fd2 as u64, 0, 0, 0, 0, 0]);
    e.rm("seek", r);
    let r = e.call(FTRUNCATE, [fd2 as u64, 0, 0, 0, 0, 0]);
    e.rm("truncate", r);
    let r = e.call(FLOCK, [fd2 as u64, LOCK_EX, 0, 0, 0, 0]);
    e.rm("flock", r);
    let flags = e.call(FCNTL, [fd2 as u64, F_GETFL, 0, 0, 0, 0]);
    e.print(&format!(" getfl={flags:#x}"));
    let r = e.call(FCNTL, [fd2 as u64, F_SETFL, O_NONBLOCK, 0, 0, 0]);
    e.rm("setfl", r);
    let flags = e.call(FCNTL, [fd2 as u64, F_GETFL, 0, 0, 0, 0]);
    e.print(&format!(" now={flags:#x}"));
    // F_SETFL keeps a namespace file's open flags too.
    let path = e.put("/proc/self/ns/mnt");
    let ns = e.call(OPEN, [path, 0, 0, 0, 0, 0]);
    assert!(ns >= 0, "{ns}");
    let flags = e.call(FCNTL, [ns as u64, F_GETFL, 0, 0, 0, 0]);
    e.print(&format!(" ns={flags:#x}"));
    let r = e.call(FCNTL, [ns as u64, F_SETFL, O_NONBLOCK, 0, 0, 0]);
    e.rm("ns-setfl", r);
    let flags = e.call(FCNTL, [ns as u64, F_GETFL, 0, 0, 0, 0]);
    e.print(&format!(" ns-now={flags:#x}"));
    e.close(ns);
    let r = e.fsconfig(fd2, 0, Some("size"), None);
    e.rm("size-flag", r);
    let r = e.call(READ, [fd2 as u64, BUF, 4, 0, 0, 0]);
    e.rm("small", r);
    for i in 0..9 {
        e.fsconfig(fd2, 0, Some(&format!("b{i}")), None);
    }
    e.print("\nmessages");
    e.messages(fd2);
    // The values other than flags and strings.
    e.print("values");
    for (name, cmd, key, value, aux) in [
        ("blob-none", 2, "size", Some("1m"), 0),
        ("blob-big", 2, "size", Some("1m"), (1 << 20) + 1),
    ] {
        let r = e.fsconfig_aux(fd2, cmd, Some(key), value, aux);
        e.rm(name, r);
    }
    let size = e.put("size");
    let r = e.call(FSCONFIG, [fd2 as u64, 2, size, 8, 2, 0]);
    e.rm("blob-fault", r);
    for (name, cmd, key, value, aux) in [
        ("blob", 2, "size", Some("1m"), 2),
        ("path-dfd", 3, "source", Some("/"), -5),
        ("path-none", 3, "source", Some(""), -100),
        ("path", 3, "source", Some("/"), -100),
        ("path-empty", 4, "source", Some(""), -100),
        ("fd-bad", 5, "source", None, 99),
        ("fd", 5, "source", None, 0),
    ] {
        let r = e.fsconfig_aux(fd2, cmd, Some(key), value, aux);
        e.rm(name, r);
    }
    e.print("\nmessages");
    e.messages(fd2);
    // fsmount's other checks, and a mount with its descriptor closed on
    // exec and strict access times.
    e.print("mount");
    let r = e.fsconfig(fd2, 6, None, None);
    e.rm("create", r);
    let r = e.fsmount(1, 0, 0);
    e.rm("not-context", r);
    let r = e.fsmount(fd2, 0, 0x100);
    e.rm("attr-bad", r);
    let r = e.fsmount(fd2, 0, 0x30);
    e.rm("two-atimes", r);
    let m2 = e.fsmount(fd2, 1, 0x20);
    let cloexec = e.call(FCNTL, [m2 as u64, F_GETFD, 0, 0, 0, 0]);
    e.print(&format!(
        " mounted={} cloexec={cloexec}\n",
        u8::from(m2 >= 0)
    ));
    e.close(m2);
    e.close(fd2);
    // A picked superblock gathers again after a reconfiguration, and one
    // that fails fails the context.
    e.print("repick");
    let again = e.fspick(M, 0);
    assert!(again >= 0, "{again}");
    for (name, cmd, key) in [
        ("rw", 0, Some("rw")),
        ("apply", 7, None),
        ("dirsync", 0, Some("dirsync")),
        ("refused", 7, None),
        ("failed", 0, Some("ro")),
        ("failed-apply", 7, None),
    ] {
        let r = e.fsconfig(again, cmd, key, None);
        e.rm(name, r);
    }
    e.print("\nmessages");
    e.messages(again);
    e.close(again);
    e.info("m", M);

    let got: Vec<&str> = e.out.lines().collect();
    let want: Vec<&str> = EXPECTED.lines().collect();
    assert_eq!(got, want);
}
