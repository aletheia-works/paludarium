//! The key calls ([`crate::keys`]) through the kernel's dispatch.
use super::*;
use paludarium_host::testing::RecordingHost;
use paludarium_host::{ClockId, Host};
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::{Errno, GuestAddr};

const DATA: u64 = 0x10_0000;
const ADD_KEY: u64 = 248;
const REQUEST_KEY: u64 = 249;
const KEYCTL: u64 = 250;
/// Where the cases put strings and read results.
const STRINGS: u64 = DATA;
const BUF: u64 = DATA + 0x4000;

const THREAD: u64 = -1i64 as u64;
const PROCESS: u64 = -2i64 as u64;
const SESSION: u64 = -3i64 as u64;
const USER: u64 = -4i64 as u64;
const USER_SESSION: u64 = -5i64 as u64;

const ENOKEY: Errno = Errno(126);
const EKEYEXPIRED: Errno = Errno(127);
const EKEYREVOKED: Errno = Errno(128);
const EDQUOT: Errno = Errno(122);
const EDEADLK: Errno = Errno(35);

struct Fixture {
    host: Arc<RecordingHost>,
    kernel: Kernel,
    thread: Thread,
    mem: AddressSpace,
    /// The next free byte at `STRINGS`.
    next: u64,
}

fn fixture() -> Fixture {
    let host = Arc::new(RecordingHost::new());
    let kernel = Kernel::new(host.clone());
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
        host,
        kernel,
        thread,
        mem,
        next: STRINGS,
    }
}

fn errno(e: Errno) -> u64 {
    e.to_syscall_return()
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

    /// `bytes`, NUL-terminated, in guest memory.
    fn put(&mut self, bytes: &[u8]) -> u64 {
        let at = self.next;
        self.mem.write(GuestAddr(at), bytes).unwrap();
        self.mem
            .write(GuestAddr(at + bytes.len() as u64), &[0])
            .unwrap();
        self.next = (at + bytes.len() as u64 + 16) & !7;
        at
    }

    fn add(&mut self, kind: &str, description: &str, payload: &[u8], keyring: u64) -> u64 {
        let kind = self.put(kind.as_bytes());
        let description = self.put(description.as_bytes());
        let len = payload.len() as u64;
        let payload = self.put(payload);
        self.ret(ADD_KEY, &[kind, description, payload, len, keyring])
    }

    fn keyctl(&mut self, args: &[u64]) -> u64 {
        self.ret(KEYCTL, args)
    }

    fn join(&mut self, name: Option<&str>) -> u64 {
        let name = name.map_or(0, |n| self.put(n.as_bytes()));
        self.keyctl(&[1, name])
    }

    fn describe(&mut self, id: u64) -> String {
        let len = self.keyctl(&[6, id, BUF, 512]);
        assert!(len < 512, "describe {id:#x}: {len:#x}");
        let mut text = vec![0; len as usize - 1];
        self.mem.read(GuestAddr(BUF), &mut text).unwrap();
        String::from_utf8(text).unwrap()
    }

    fn read(&mut self, id: u64) -> Vec<u8> {
        let len = self.keyctl(&[11, id, BUF, 4096]);
        assert!(len <= 4096, "read {id:#x}: {len:#x}");
        let mut data = vec![0; len as usize];
        self.mem.read(GuestAddr(BUF), &mut data).unwrap();
        data
    }

    /// The serials keyring `id` links.
    fn links(&mut self, id: u64) -> Vec<u64> {
        self.read(id)
            .chunks(4)
            .map(|c| u64::from(u32::from_le_bytes(c.try_into().unwrap())))
            .collect()
    }

    fn search(&mut self, keyring: u64, kind: &str, description: &str, dest: u64) -> u64 {
        let kind = self.put(kind.as_bytes());
        let description = self.put(description.as_bytes());
        self.keyctl(&[10, keyring, kind, description, dest])
    }

    fn request(&mut self, kind: &str, description: &str, callout: Option<&str>, dest: u64) -> u64 {
        let kind = self.put(kind.as_bytes());
        let description = self.put(description.as_bytes());
        let callout = callout.map_or(0, |c| self.put(c.as_bytes()));
        self.ret(REQUEST_KEY, &[kind, description, callout, dest])
    }

    fn become_user(&mut self, uid: u64) {
        // setresgid, then setresuid.
        assert_eq!(self.ret(119, &[uid, uid, uid]), 0);
        assert_eq!(self.ret(117, &[uid, uid, uid]), 0);
    }

    /// Moves the kernel's clock on by `seconds`.
    fn advance(&mut self, seconds: i64) {
        let now = self.host.clock(ClockId::Realtime).unwrap();
        let step = u64::try_from(seconds).unwrap() * 1_000_000_000;
        self.host.set_clock(ClockId::Realtime, now + step);
    }
}

fn serial(r: u64) -> bool {
    (r as i64) > 0
}

#[test]
fn user_keys_add_read_update_and_describe() {
    let mut f = fixture();
    let session = f.join(None);
    assert!(serial(session));
    assert_eq!(f.describe(session), "keyring;0;0;3f030000;_ses");
    let k = f.add("user", "k1", b"hello", SESSION);
    assert!(serial(k));
    assert_eq!(f.describe(k), "user;0;0;3f010000;k1");
    assert_eq!(f.read(k), b"hello");
    assert_eq!(f.keyctl(&[11, k, 0, 0]), 5);
    // A short buffer gets nothing, but the length.
    assert_eq!(f.keyctl(&[11, k, BUF, 2]), 5);
    // Adding again updates the same key.
    assert_eq!(f.add("user", "k1", b"world!", SESSION), k);
    assert_eq!(f.read(k), b"world!");
    let abc = f.put(b"abc");
    assert_eq!(f.keyctl(&[2, k, abc, 3]), 0);
    assert_eq!(f.read(k), b"abc");
    assert_eq!(f.keyctl(&[2, k, 0, 0]), errno(Errno::EINVAL));
    assert_eq!(f.keyctl(&[2, k, abc, 32768]), errno(Errno::EINVAL));
    assert_eq!(f.keyctl(&[2, session, abc, 1]), errno(Errno::EOPNOTSUPP));
    assert_eq!(f.links(session), [k]);
    // A logon key cannot be read; its description needs a prefix.
    assert_eq!(
        f.add("logon", "nocolon", b"x", SESSION),
        errno(Errno::EINVAL)
    );
    let logon = f.add("logon", "svc:name", b"secret", SESSION);
    assert!(serial(logon));
    assert_eq!(f.keyctl(&[11, logon, BUF, 100]), errno(Errno::EOPNOTSUPP));
    // Errors in the arguments.
    assert_eq!(f.add("nope", "x", b"x", SESSION), errno(Errno::ENODEV));
    assert_eq!(f.add(".x", "x", b"x", SESSION), errno(Errno::EPERM));
    assert_eq!(f.add("user", "", b"x", SESSION), errno(Errno::EINVAL));
    assert_eq!(f.add("user", "x", b"", SESSION), errno(Errno::EINVAL));
    assert_eq!(f.add("keyring", "r", b"x", SESSION), errno(Errno::EINVAL));
    assert_eq!(f.add("user", "x", b"x", 0), errno(Errno::EINVAL));
    assert_eq!(f.add("user", "x", b"x", -6i64 as u64), errno(Errno::EINVAL));
    assert_eq!(f.add("user", "x", b"x", -7i64 as u64), errno(ENOKEY));
    assert_eq!(f.add("user", "x", b"x", 12345), errno(ENOKEY));
    assert_eq!(f.add("user", "x", b"x", k), errno(Errno::ENOTDIR));
    assert_eq!(f.ret(ADD_KEY, &[0, 0, 0, 0, SESSION]), errno(Errno::EFAULT));
    // Unknown options.
    assert_eq!(f.keyctl(&[99]), errno(Errno::EOPNOTSUPP));
    for option in [23, 25, 26, 27, 28, 32] {
        assert_eq!(f.keyctl(&[option, k, 0, 0, 0]), errno(Errno::EOPNOTSUPP));
    }
    assert_eq!(f.keyctl(&[24, k, 1, 0, 0]), errno(Errno::EINVAL));
    let mut caps = [9u8; 4];
    assert_eq!(f.keyctl(&[31, BUF, 4]), 2);
    f.mem.read(GuestAddr(BUF), &mut caps).unwrap();
    // The rest of the buffer is cleared.
    assert_eq!(caps, [0xe3, 0x03, 0, 0]);
    assert_eq!(f.keyctl(&[31, 0, 0]), 2);
}

#[test]
fn revoke_clear_invalidate_and_unlink() {
    let mut f = fixture();
    let session = f.join(None);
    let k1 = f.add("user", "k1", b"1", SESSION);
    let k2 = f.add("user", "k2", b"2", SESSION);
    let ring = f.add("keyring", "ring", b"", SESSION);
    assert!(serial(ring));
    assert_eq!(f.links(ring), Vec::<u64>::new());
    // Link k1 into ring as well, then unlink it from the session.
    assert_eq!(f.keyctl(&[8, k1, ring]), 0);
    assert_eq!(f.keyctl(&[8, k1, ring]), 0);
    assert_eq!(f.links(ring), [k1]);
    assert_eq!(f.keyctl(&[9, k1, SESSION]), 0);
    assert_eq!(f.keyctl(&[9, k1, SESSION]), errno(Errno::ENOENT));
    assert_eq!(f.search(SESSION, "user", "k1", 0), k1);
    // A cycle is refused.
    assert_eq!(f.keyctl(&[8, session, ring]), errno(EDEADLK));
    assert_eq!(f.keyctl(&[8, k1, k2]), errno(Errno::ENOTDIR));
    // Revoked keys are found but cannot be read.
    assert_eq!(f.keyctl(&[3, k2]), 0);
    assert_eq!(f.keyctl(&[11, k2, BUF, 10]), errno(EKEYREVOKED));
    assert_eq!(f.search(SESSION, "user", "k2", 0), errno(EKEYREVOKED));
    assert_eq!(f.keyctl(&[3, k2]), errno(EKEYREVOKED));
    // Clearing a keyring drops its links.
    assert_eq!(f.keyctl(&[7, ring]), 0);
    assert_eq!(f.links(ring), Vec::<u64>::new());
    assert_eq!(f.keyctl(&[7, k1]), errno(ENOKEY));
    assert_eq!(f.keyctl(&[11, k1, BUF, 10]), errno(ENOKEY));
    // An invalidated key goes at once.
    let k3 = f.add("user", "k3", b"3", SESSION);
    assert_eq!(f.keyctl(&[21, k3]), 0);
    assert_eq!(f.keyctl(&[11, k3, BUF, 10]), errno(ENOKEY));
    assert_eq!(f.search(SESSION, "user", "k3", 0), errno(ENOKEY));
    // Its number is not given again, though the host's bytes never change.
    let k4 = f.add("user", "k4", b"4", SESSION);
    assert!(serial(k4) && k4 != k3);
    assert_eq!(f.keyctl(&[11, k3, BUF, 10]), errno(ENOKEY));
}

#[test]
fn timeouts_expire_keys_and_garbage_collect_them() {
    let mut f = fixture();
    f.join(None);
    let k = f.add("user", "k", b"x", SESSION);
    assert_eq!(f.keyctl(&[15, k, 10]), 0);
    assert_eq!(f.read(k), b"x");
    f.advance(11);
    assert_eq!(f.keyctl(&[11, k, BUF, 10]), errno(EKEYEXPIRED));
    assert_eq!(f.search(SESSION, "user", "k", 0), errno(EKEYEXPIRED));
    assert_eq!(f.keyctl(&[15, k, 0]), errno(EKEYEXPIRED));
    f.advance(300);
    assert_eq!(f.keyctl(&[11, k, BUF, 10]), errno(ENOKEY));
    // Adding one again after expiry makes a new key.
    let again = f.add("user", "k", b"y", SESSION);
    assert!(serial(again));
    // A zero timeout clears the expiry.
    assert_eq!(f.keyctl(&[15, again, 5]), 0);
    assert_eq!(f.keyctl(&[15, again, 0]), 0);
    f.advance(100);
    assert_eq!(f.read(again), b"y");
}

#[test]
fn setperm_and_chown_check_the_owner() {
    let mut f = fixture();
    f.join(None);
    let k = f.add("user", "k", b"x", SESSION);
    assert_eq!(f.keyctl(&[5, k, 0x3f00_0000]), 0);
    assert_eq!(f.describe(k), "user;0;0;3f000000;k");
    assert_eq!(f.keyctl(&[5, k, 0x4000_0000]), errno(Errno::EINVAL));
    // Possession still gives what the possessor bits say.
    assert_eq!(f.read(k), b"x");
    assert_eq!(f.keyctl(&[5, k, 0x0100_0000]), 0);
    assert_eq!(f.keyctl(&[11, k, BUF, 10]), errno(Errno::EACCES));
    assert_eq!(f.keyctl(&[5, k, 0x3f00_0000]), errno(Errno::EACCES));
    let k2 = f.add("user", "k2", b"x", SESSION);
    assert_eq!(f.keyctl(&[4, k2, 1000, 1000]), 0);
    assert_eq!(f.describe(k2), "user;1000;1000;3f010000;k2");
    assert_eq!(f.keyctl(&[4, k2, u64::from(u32::MAX), 5]), 0);
    assert_eq!(f.describe(k2), "user;1000;5;3f010000;k2");
    // A key of another user's is not readable without possession.
    let ring = f.add("keyring", "r", b"", SESSION);
    assert_eq!(f.keyctl(&[4, ring, 1000, 1000]), 0);
    f.become_user(1000);
    assert_eq!(f.keyctl(&[4, k2, 0, 0]), errno(Errno::EACCES));
    assert_eq!(f.keyctl(&[4, k2, 1000, 1000]), 0);
}

#[test]
fn search_and_request_key_find_keys_in_nested_keyrings() {
    let mut f = fixture();
    f.join(None);
    let ring = f.add("keyring", "ring", b"", SESSION);
    let inner = f.add("keyring", "inner", b"", ring);
    let k = f.add("user", "deep", b"d", inner);
    assert_eq!(f.search(SESSION, "user", "deep", 0), k);
    assert_eq!(f.search(ring, "user", "deep", 0), k);
    assert_eq!(f.search(SESSION, "keyring", "inner", 0), inner);
    assert_eq!(f.search(SESSION, "user", "none", 0), errno(ENOKEY));
    assert_eq!(f.search(SESSION, "nope", "x", 0), errno(ENOKEY));
    assert_eq!(f.search(k, "user", "x", 0), errno(Errno::ENOTDIR));
    // The search links what it finds into the destination.
    let dest = f.add("keyring", "dest", b"", SESSION);
    assert_eq!(f.search(SESSION, "user", "deep", dest), k);
    assert_eq!(f.links(dest), [k]);
    assert_eq!(f.request("user", "deep", None, 0), k);
    assert_eq!(f.request("user", "none", None, 0), errno(ENOKEY));
    assert_eq!(f.request("keyring", "dest", None, 0), dest);
    // With a callout and no helper, a negative key is left behind.
    assert_eq!(
        f.request("user", "made", Some("info"), dest),
        errno(Errno::ENOENT)
    );
    assert_eq!(f.request("user", "made", None, 0), errno(ENOKEY));
    assert_eq!(f.links(dest).len(), 2);
    // Once it expires, the search skips it.
    f.advance(61);
    assert_eq!(f.request("user", "made", None, 0), errno(ENOKEY));
    // Instantiating needs authority the thread never holds.
    let x = f.put(b"x");
    assert_eq!(f.keyctl(&[12, k, x, 1, 0]), errno(Errno::EPERM));
    assert_eq!(f.keyctl(&[13, k, 10, 0]), errno(Errno::EPERM));
    assert_eq!(f.keyctl(&[19, k, 10, 128, 0]), errno(Errno::EPERM));
    assert_eq!(f.keyctl(&[20, k, BUF, 0, 0]), errno(Errno::EPERM));
    assert_eq!(f.keyctl(&[16, 0]), 0);
    assert_eq!(f.keyctl(&[16, k]), errno(ENOKEY));
    assert_eq!(
        f.request(".request_key_auth", "x", None, 0),
        errno(Errno::EPERM)
    );
}

#[test]
fn special_keyrings_are_made_when_asked() {
    let mut f = fixture();
    // Without a session keyring the user session keyring stands in.
    let user = f.keyctl(&[0, USER, 1]);
    let user_session = f.keyctl(&[0, USER_SESSION, 1]);
    assert!(serial(user) && serial(user_session) && user != user_session);
    assert_eq!(f.describe(user), "keyring;0;65534;1f3f0000;_uid.0");
    assert_eq!(
        f.describe(user_session),
        "keyring;0;65534;1f3f0000;_uid_ses.0"
    );
    assert_eq!(f.keyctl(&[0, SESSION, 0]), user_session);
    assert_eq!(f.keyctl(&[0, THREAD, 0]), errno(ENOKEY));
    assert_eq!(f.keyctl(&[0, PROCESS, 0]), errno(ENOKEY));
    let thread = f.keyctl(&[0, THREAD, 1]);
    let process = f.keyctl(&[0, PROCESS, 1]);
    assert!(serial(thread) && serial(process) && thread != process);
    assert_eq!(f.keyctl(&[0, THREAD, 1]), thread);
    assert_eq!(f.describe(thread), "keyring;0;0;3f010000;_tid");
    assert_eq!(f.describe(process), "keyring;0;0;3f010000;_pid");
    // Creating a session keyring replaces the user session one.
    let session = f.keyctl(&[0, SESSION, 1]);
    assert!(serial(session) && session != user_session);
    assert_eq!(f.keyctl(&[0, -6i64 as u64, 0]), errno(Errno::EINVAL));
    for id in -11..=-7 {
        assert_eq!(f.keyctl(&[0, id as u64, 0]), errno(ENOKEY));
    }
    // A named session keyring its user cannot search is not found by its
    // name, so joining the name again makes another.
    let unsearchable = f.join(Some("named"));
    assert!(serial(unsearchable));
    let named = f.join(Some("named"));
    assert!(serial(named) && named != unsearchable);
    assert_eq!(f.keyctl(&[5, named, 0x3f1b_0000]), 0);
    // Joining the session keyring the thread has gives 0.
    assert_eq!(f.join(Some("named")), 0);
    // Found again by name while something holds it; once nothing does, it
    // is gone and the name makes another.
    assert_eq!(f.keyctl(&[8, named, PROCESS]), 0);
    f.join(None);
    assert_eq!(f.join(Some("named")), named);
    assert_eq!(f.keyctl(&[9, named, PROCESS]), 0);
    f.join(None);
    let again = f.join(Some("named"));
    assert!(serial(again) && again != named);
    assert_eq!(f.join(Some("")), errno(Errno::EINVAL));
    // The default keyring for request_key.
    assert_eq!(f.keyctl(&[14, -1i64 as u64]), 0);
    for (default, old) in [(1, 0), (2, 1), (3, 2), (4, 3), (5, 4), (7, 5), (0, 7)] {
        assert_eq!(f.keyctl(&[14, default]), old);
    }
    for bad in [6, 8] {
        assert_eq!(f.keyctl(&[14, bad]), errno(Errno::EINVAL));
    }
    assert_eq!(f.keyctl(&[14, 1]), 0);
    assert_eq!(f.keyctl(&[14, -1i64 as u64]), 1);
    let k = f.request("user", "made", Some("x"), 0);
    assert_eq!(k, errno(Errno::ENOENT));
    assert_eq!(f.search(THREAD, "user", "made", 0), errno(ENOKEY));
    // The persistent keyring, linked into the destination.
    let persistent = f.keyctl(&[22, u64::from(u32::MAX), SESSION]);
    assert!(serial(persistent));
    assert_eq!(
        f.describe(persistent),
        "keyring;0;65534;1f030000;_persistent.0"
    );
    assert_eq!(f.keyctl(&[22, u64::from(u32::MAX), SESSION]), persistent);
    assert!(serial(f.keyctl(&[22, 1234, SESSION])));
    let u = f.add("user", "u", b"x", SESSION);
    assert_eq!(
        f.keyctl(&[22, u64::from(u32::MAX), u]),
        errno(Errno::ENOTDIR)
    );
    // A security label, empty without an LSM.
    let now = f.keyctl(&[0, SESSION, 0]);
    assert_eq!(f.keyctl(&[17, now, BUF, 10]), 1);
    // The first session keyring went when it was replaced.
    assert_eq!(f.keyctl(&[17, session, BUF, 10]), errno(ENOKEY));
    // A session for the parent, which the first process has none of.
    assert_eq!(f.keyctl(&[18]), errno(Errno::EPERM));
}

#[test]
fn restrict_and_move() {
    let mut f = fixture();
    f.join(None);
    let a = f.add("keyring", "a", b"", SESSION);
    let b = f.add("keyring", "b", b"", SESSION);
    let k = f.add("user", "k", b"x", a);
    assert_eq!(f.keyctl(&[30, k, a, b, 2]), errno(Errno::EINVAL));
    assert_eq!(f.keyctl(&[30, k, a, a, 0]), 0);
    assert_eq!(f.keyctl(&[30, k, a, b, 0]), 0);
    assert_eq!(f.links(a), Vec::<u64>::new());
    assert_eq!(f.links(b), [k]);
    assert_eq!(f.keyctl(&[30, k, a, b, 0]), errno(Errno::ENOENT));
    // An exclusive move refuses to displace a key of the same name.
    let k2 = f.add("user", "k", b"y", a);
    assert_eq!(f.keyctl(&[30, k2, a, b, 1]), errno(Errno::EEXIST));
    assert_eq!(f.keyctl(&[30, k2, a, b, 0]), 0);
    assert_eq!(f.links(b), [k2]);
    assert_eq!(f.keyctl(&[30, a, SESSION, a, 0]), errno(EDEADLK));
    // A restricted keyring takes no new links.
    assert_eq!(f.keyctl(&[29, b, 0, 0]), 0);
    assert_eq!(f.keyctl(&[29, b, 0, 0]), errno(Errno::EEXIST));
    assert_eq!(f.add("user", "n", b"x", b), errno(Errno::EPERM));
    let user = f.put(b"user");
    let zzz = f.put(b"zzz");
    let x = f.put(b"x");
    // The user type has no restrictions to look up.
    assert_eq!(f.keyctl(&[29, a, user, x]), errno(Errno::ENOENT));
    assert_eq!(f.keyctl(&[29, a, zzz, x]), errno(ENOKEY));
    assert_eq!(f.keyctl(&[29, a, user, 0]), errno(Errno::EINVAL));
    assert_eq!(f.keyctl(&[29, k2, 0, 0]), errno(Errno::ENOTDIR));
}

#[test]
fn quotas_stop_an_ordinary_user() {
    let mut f = fixture();
    f.join(None);
    f.become_user(1000);
    f.join(None);
    let mut count = 0;
    let result = loop {
        let r = f.add("user", &format!("q{count}"), b"x", SESSION);
        if !serial(r) {
            break r;
        }
        count += 1;
        assert!(count < 1000);
    };
    assert_eq!(result, errno(EDQUOT));
    assert!(count > 100);
    // Big payloads run into the byte limit sooner.
    let mut g = fixture();
    g.become_user(1001);
    g.join(None);
    let big = vec![b'b'; 4000];
    let mut bytes = 0;
    let result = loop {
        let r = g.add("user", &format!("b{bytes}"), &big, SESSION);
        if !serial(r) {
            break r;
        }
        bytes += 1;
        assert!(bytes < 10);
    };
    assert_eq!(result, errno(EDQUOT));
    assert_eq!(bytes, 4);
    // An ordinary user cannot see another's persistent keyring.
    assert_eq!(g.keyctl(&[22, 0, SESSION]), errno(Errno::EPERM));
    assert!(serial(g.keyctl(&[22, 1001, SESSION])));
    // Nor change a key's owner.
    let k = g.search(SESSION, "user", "b0", 0);
    assert_eq!(
        g.keyctl(&[4, k, 0, u64::from(u32::MAX)]),
        errno(Errno::EACCES)
    );
}
