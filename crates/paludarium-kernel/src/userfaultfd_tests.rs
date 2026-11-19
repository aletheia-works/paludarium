//! The userfaultfd calls ([`crate::userfaultfd`]) through the kernel's
//! dispatch.
use super::*;
use paludarium_host::testing::RecordingHost;
use paludarium_mmu::{MappingKind, Prot, Userfault, UserfaultReason};
use paludarium_types::{Errno, GuestAddr};

const DATA: u64 = 0x10_0000;
const ARG: u64 = DATA + 0x8000;
const SRC: u64 = DATA + 0x9000;
const AREA: u64 = 0x40_0000;
const PAGE: u64 = 4096;
const USERFAULTFD: u64 = 323;

const API: u64 = 0xc018_aa3f;
const REGISTER: u64 = 0xc020_aa00;
const UNREGISTER: u64 = 0x8010_aa01;
const WAKE: u64 = 0x8010_aa02;
const COPY: u64 = 0xc028_aa03;
const ZEROPAGE: u64 = 0xc020_aa04;
const WRITEPROTECT: u64 = 0xc018_aa06;
const POISON: u64 = 0xc020_aa08;
const MOVE: u64 = 0xc028_aa05;
const CONTINUE: u64 = 0xc020_aa07;

const NONBLOCK: u64 = 0o4000;
const SIGBUS: u64 = 1 << 7;
const THREAD_ID: u64 = 1 << 8;
const EXACT_ADDRESS: u64 = 1 << 11;
const FEATURE_POISON: u64 = 1 << 14;
const WP_UNPOPULATED: u64 = 1 << 13;
const WP_ASYNC: u64 = 1 << 15;
const EVENT_FORK: u64 = 1 << 1;
const EVENT_REMAP: u64 = 1 << 2;
const EVENT_REMOVE: u64 = 1 << 3;
const EVENT_UNMAP: u64 = 1 << 6;

struct Fixture {
    kernel: Kernel,
    thread: Thread,
    mem: AddressSpace,
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
    mem.map(
        Some(GuestAddr(AREA)),
        8 * PAGE,
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
    /// An ioctl of `fd` with the words `words` at [`ARG`]; the words after.
    fn ioctl(&mut self, fd: u64, cmd: u64, words: &[u64]) -> (u64, Vec<u64>) {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        self.mem.write(GuestAddr(ARG), &bytes).unwrap();
        let ret = self.ret(16, &[fd, cmd, ARG]);
        let mut out = vec![0; bytes.len()];
        self.mem.read(GuestAddr(ARG), &mut out).unwrap();
        (
            ret,
            out.as_chunks::<8>()
                .0
                .iter()
                .map(|c| u64::from_le_bytes(*c))
                .collect(),
        )
    }
    /// A userfaultfd that took `features`.
    fn ready(&mut self, flags: u64, features: u64) -> u64 {
        let fd = self.ret(USERFAULTFD, &[flags]);
        assert!((fd as i64) >= 0, "{fd:#x}");
        assert_eq!(self.ioctl(fd, API, &[0xaa, features, 0]).0, 0);
        fd
    }
    fn register(&mut self, fd: u64, start: u64, len: u64) -> u64 {
        self.ioctl(fd, REGISTER, &[start, len, 1, 0]).0
    }
    fn userfault(&self, addr: u64) -> Option<Userfault> {
        self.mem
            .mappings()
            .find(|m| m.start.0 <= addr && addr < m.end())
            .and_then(|m| m.userfault)
    }
    fn fault(&mut self, addr: u64, write: bool) -> Next {
        let reason = ExitReason::PageFault {
            rip: GuestAddr(0x1234),
            addr: GuestAddr(addr),
            write,
            fetch: false,
            mapped: true,
            present: false,
        };
        self.kernel.handle(&mut self.thread, &self.mem, reason)
    }
    fn fdinfo(&mut self, fd: u64) -> String {
        let path = format!("/proc/self/fdinfo/{fd}\0");
        self.mem.write(GuestAddr(DATA), path.as_bytes()).unwrap();
        let file = self.ret(2, &[DATA, 0, 0]);
        let n = self.ret(0, &[file, DATA + 0x100, 0x400]);
        assert_eq!(self.ret(3, &[file]), 0);
        let mut bytes = vec![0; n as usize];
        self.mem.read(GuestAddr(DATA + 0x100), &mut bytes).unwrap();
        String::from_utf8(bytes).unwrap()
    }
}

#[test]
fn userfaultfd_checks_its_flags_and_who_asks() {
    let mut f = fixture();
    assert_eq!(f.ret(USERFAULTFD, &[0x10]), errno(Errno::EINVAL));
    let fd = f.ret(USERFAULTFD, &[0o2000000 | NONBLOCK]);
    assert!((fd as i64) >= 0);
    assert_eq!(f.ret(72, &[fd, 3]), NONBLOCK);
    assert_eq!(f.ret(72, &[fd, 1]), 1);
    // Without CAP_SYS_PTRACE only a userfaultfd of user faults is made,
    // whose flags are checked after.
    assert_eq!(f.ret(117, &[1000, 1000, 1000]), 0);
    assert_eq!(f.ret(USERFAULTFD, &[0x10]), errno(Errno::EPERM));
    assert_eq!(f.ret(USERFAULTFD, &[1 | 0x10]), errno(Errno::EINVAL));
    let user = f.ret(USERFAULTFD, &[1]);
    assert!((user as i64) >= 0);
    // UFFD_FEATURE_EVENT_FORK needs CAP_SYS_PTRACE too.
    assert_eq!(
        f.ioctl(user, API, &[0xaa, 1 << 1, 0]),
        (errno(Errno::EPERM), vec![0, 0, 0])
    );
}

#[test]
fn uffdio_api_takes_the_features_once() {
    let mut f = fixture();
    let fd = f.ret(USERFAULTFD, &[NONBLOCK]);
    // Nothing but UFFDIO_API before it.
    assert_eq!(f.register(fd, AREA, PAGE), errno(Errno::EINVAL));
    assert_eq!(f.ret(0, &[fd, ARG, 32]), errno(Errno::EINVAL));
    assert_eq!(
        f.ioctl(fd, API, &[0xab, 0, 7]),
        (errno(Errno::EINVAL), vec![0, 0, 0])
    );
    assert_eq!(
        f.ioctl(fd, API, &[0xaa, 1 << 30, 7]),
        (errno(Errno::EINVAL), vec![0, 0, 0])
    );
    assert_eq!(f.ret(16, &[fd, API, 0]), errno(Errno::EFAULT));
    let (ret, out) = f.ioctl(fd, API, &[0xaa, SIGBUS | THREAD_ID, 0]);
    assert_eq!(ret, 0);
    assert_eq!(out, vec![0xaa, 0x1_ffff, 1 << 63 | 3]);
    assert_eq!(
        f.ioctl(fd, API, &[0xaa, 0, 0]),
        (errno(Errno::EINVAL), vec![0, 0, 0])
    );
    assert_eq!(f.ioctl(fd, 0xc018_aa3e, &[0, 0, 0]).0, errno(Errno::EINVAL));
    assert!(
        f.fdinfo(fd)
            .ends_with("pending:\t0\ntotal:\t0\nAPI:\taa:80000180:80000000000001ff\n")
    );
    // Read, write and seek of the file.
    assert_eq!(f.ret(0, &[fd, ARG, 32]), errno(Errno::EAGAIN));
    assert_eq!(f.ret(0, &[fd, ARG, 31]), errno(Errno::EINVAL));
    assert_eq!(f.ret(1, &[fd, ARG, 32]), errno(Errno::EBADF));
    assert_eq!(f.ret(8, &[fd, 10, 0]), 0);
    let link = format!("/proc/self/fd/{fd}\0");
    f.mem.write(GuestAddr(DATA), link.as_bytes()).unwrap();
    let n = f.ret(89, &[DATA, DATA + 0x100, 64]);
    let mut target = vec![0; n as usize];
    f.mem.read(GuestAddr(DATA + 0x100), &mut target).unwrap();
    assert_eq!(target, b"anon_inode:[userfaultfd]");
}

#[test]
fn uffdio_register_checks_the_range_and_its_vmas() {
    let mut f = fixture();
    let fd = f.ready(0, 0);
    let einval = errno(Errno::EINVAL);
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, PAGE, 0, 0]).0, einval);
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, PAGE, 8, 0]).0, einval);
    // The minor mode is not offered.
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, PAGE, 4, 0]).0, einval);
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA + 1, PAGE, 1, 0]).0, einval);
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, PAGE + 1, 1, 0]).0, einval);
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, 0, 1, 0]).0, einval);
    assert_eq!(f.ioctl(fd, REGISTER, &[0x1000, PAGE, 1, 0]).0, einval);
    assert_eq!(f.ioctl(fd, REGISTER, &[1 << 47, PAGE, 1, 0]).0, einval);
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, !0xfff, 1, 0]).0, einval);
    assert_eq!(f.ioctl(fd, REGISTER, &[0x4000_0000, PAGE, 1, 0]).0, einval);
    assert_eq!(f.ret(16, &[fd, REGISTER, 0]), errno(Errno::EFAULT));
    let (ret, out) = f.ioctl(fd, REGISTER, &[AREA + PAGE, 2 * PAGE, 1, 0]);
    assert_eq!((ret, out[3]), (0, 0x13c));
    assert!(f.userfault(AREA).is_none());
    assert_eq!(f.userfault(AREA + PAGE).map(|u| u.modes), Some(1));
    assert!(f.userfault(AREA + 3 * PAGE).is_none());
    // `um` in smaps, and a VMA of its own.
    let view = f.mem.view();
    let vma = view.vma_from(AREA + PAGE).unwrap();
    assert_eq!((vma.start, vma.end), (AREA + PAGE, AREA + 3 * PAGE));
    assert_ne!(vma.flags & paludarium_mmu::vm::UFFD_MISSING, 0);
    assert_eq!(f.register(fd, AREA + PAGE, 2 * PAGE), 0);
    // Another userfaultfd's range is busy, and not its to unregister.
    let other = f.ready(0, 0);
    assert_eq!(f.register(other, AREA, 2 * PAGE), errno(Errno(16)));
    assert_eq!(f.ioctl(other, UNREGISTER, &[AREA + PAGE, PAGE]).0, einval);
    assert_eq!(f.register(other, AREA + 4 * PAGE, PAGE), 0);
    assert!(f.userfault(AREA + 4 * PAGE).is_some());
    // Closing it takes its registration away.
    assert_eq!(f.ret(3, &[other]), 0);
    assert!(f.userfault(AREA + 4 * PAGE).is_none());
    assert_eq!(f.ioctl(fd, UNREGISTER, &[AREA + 1, PAGE]).0, einval);
    assert_eq!(f.ioctl(fd, UNREGISTER, &[0x4000_0000, PAGE]).0, einval);
    assert_eq!(f.ret(16, &[fd, UNREGISTER, 0]), errno(Errno::EFAULT));
    assert_eq!(f.ioctl(fd, UNREGISTER, &[AREA, 8 * PAGE]).0, 0);
    assert!(f.userfault(AREA + PAGE).is_none());
    let vma = view.vma_from(AREA).unwrap();
    assert_eq!((vma.start, vma.end), (AREA, AREA + 8 * PAGE));
}

#[test]
fn uffdio_copy_and_zeropage_fill_missing_pages() {
    let mut f = fixture();
    let fd = f.ready(0, 0);
    assert_eq!(f.register(fd, AREA + PAGE, 3 * PAGE), 0);
    f.mem.write(GuestAddr(SRC), &[b'c'; PAGE as usize]).unwrap();
    let einval = errno(Errno::EINVAL);
    assert_eq!(f.ioctl(fd, COPY, &[AREA + PAGE, SRC, PAGE, 4, 0]).0, einval);
    assert_eq!(
        f.ioctl(fd, COPY, &[AREA + PAGE + 8, SRC, PAGE, 0, 0]).0,
        einval
    );
    assert_eq!(
        f.ioctl(fd, COPY, &[AREA + PAGE, SRC, PAGE + 1, 0, 0]).0,
        einval
    );
    assert_eq!(f.ret(16, &[fd, COPY, 0]), errno(Errno::EFAULT));
    // UFFDIO_COPY_MODE_WP needs a range registered for it.
    assert_eq!(
        f.ioctl(fd, COPY, &[AREA + PAGE, SRC, PAGE, 2, 0]),
        (einval, vec![AREA + PAGE, SRC, PAGE, 2, einval])
    );
    let enoent = errno(Errno::ENOENT);
    assert_eq!(f.ioctl(fd, COPY, &[AREA, SRC, PAGE, 0, 0]).0, enoent);
    assert_eq!(
        f.ioctl(fd, COPY, &[AREA + 3 * PAGE, SRC, 2 * PAGE, 0, 0]).1[4],
        enoent
    );
    assert_eq!(
        f.ioctl(fd, COPY, &[AREA + PAGE, 0x4000_0000, PAGE, 0, 0]).1[4],
        errno(Errno::EFAULT)
    );
    assert_eq!(
        f.ioctl(fd, COPY, &[AREA + PAGE, SRC + 1, PAGE, 0, 0]),
        (0, vec![AREA + PAGE, SRC + 1, PAGE, 0, PAGE])
    );
    let mut byte = [0];
    f.mem.read(GuestAddr(AREA + PAGE), &mut byte).unwrap();
    assert_eq!(byte, [b'c']);
    let eexist = errno(Errno::EEXIST);
    assert_eq!(
        f.ioctl(fd, COPY, &[AREA + PAGE, SRC, PAGE, 0, 0]).1[4],
        eexist
    );
    assert_eq!(f.ioctl(fd, ZEROPAGE, &[AREA + PAGE, PAGE, 2, 0]).0, einval);
    assert_eq!(f.ret(16, &[fd, ZEROPAGE, 0]), errno(Errno::EFAULT));
    assert_eq!(
        f.ioctl(fd, ZEROPAGE, &[AREA + 3 * PAGE, PAGE, 0, 0]),
        (0, vec![AREA + 3 * PAGE, PAGE, 0, PAGE])
    );
    assert_eq!(
        f.mem.page_state(GuestAddr(AREA + 3 * PAGE)),
        Some(paludarium_mmu::PageState::Zero)
    );
    // Stopped short: EAGAIN, with what it filled.
    assert_eq!(
        f.ioctl(fd, COPY, &[AREA + 2 * PAGE, SRC, 2 * PAGE, 1, 0]),
        (
            errno(Errno::EAGAIN),
            vec![AREA + 2 * PAGE, SRC, 2 * PAGE, 1, PAGE]
        )
    );
    assert_eq!(
        f.ioctl(fd, ZEROPAGE, &[AREA + PAGE, PAGE, 0, 0]).1[3],
        eexist
    );
    assert_eq!(f.ioctl(fd, WAKE, &[AREA, 0]).0, einval);
    assert_eq!(f.ioctl(fd, WAKE, &[AREA, PAGE]).0, 0);
    assert_eq!(f.ret(16, &[fd, WAKE, 0]), errno(Errno::EFAULT));
}

#[test]
fn a_fault_on_a_missing_page_waits_or_raises_sigbus() {
    let mut f = fixture();
    let fd = f.ready(NONBLOCK, SIGBUS | EXACT_ADDRESS);
    assert_eq!(f.register(fd, AREA, PAGE), 0);
    assert_eq!(
        f.mem.userfault_at(GuestAddr(AREA + 5)),
        f.userfault(AREA).map(|u| u.context)
    );
    // A system call's copy there is EFAULT.
    assert_eq!(f.ret(0, &[fd, AREA, 32]), errno(Errno::EAGAIN));
    assert_eq!(f.ret(1, &[1, AREA, 1]), errno(Errno::EFAULT));
    assert_eq!(
        f.fault(AREA + 5, true),
        Next::Exit(ExitStatus::Signaled(signal::SIGBUS))
    );
    // A write the protection refuses is SIGSEGV, not a wait.
    let mut f = fixture();
    let fd = f.ready(0, 0);
    assert_eq!(f.register(fd, AREA, PAGE), 0);
    assert_eq!(f.ret(10, &[AREA, PAGE, 1]), 0);
    assert_eq!(
        f.fault(AREA, true),
        Next::Exit(ExitStatus::Signaled(signal::SIGSEGV))
    );
    // A pending signal ends the wait at once, and takes its fault away;
    // the signal is delivered, here its default action.
    let mut f = fixture();
    let fd = f.ready(NONBLOCK, THREAD_ID);
    assert_eq!(f.register(fd, AREA, 2 * PAGE), 0);
    let context = crate::userfaultfd::find(f.userfault(AREA).unwrap().context).unwrap();
    crate::signals::queue(
        &mut f.thread.state,
        crate::signals::PendingSignal::user(10, 0),
    );
    assert_eq!(
        f.fault(AREA + PAGE + 9, false),
        Next::Exit(ExitStatus::Signaled(10))
    );
    assert_eq!(crate::userfaultfd::tests::counts(&context), (0, 0));
    // Closing the file takes the registration away.
    let mut f = fixture();
    let fd = f.ready(0, 0);
    assert_eq!(f.register(fd, AREA, 2 * PAGE), 0);
    assert!(f.mem.userfault_at(GuestAddr(AREA + PAGE)).is_some());
    assert_eq!(f.ret(3, &[fd]), 0);
    assert!(f.mem.userfault_at(GuestAddr(AREA + PAGE)).is_none());
}

fn readiness(f: &Fixture, fd: u64) -> u32 {
    f.kernel
        .files
        .descriptor(fd)
        .unwrap()
        .file
        .readiness()
        .unwrap()
        .0
}

#[test]
fn a_read_takes_the_faults_in_turn() {
    let mut f = fixture();
    let fd = f.ready(NONBLOCK, THREAD_ID);
    assert_eq!(f.register(fd, AREA, 4 * PAGE), 0);
    let id = f.userfault(AREA).unwrap().context;
    let context = crate::userfaultfd::find(id).unwrap();
    for (n, address) in [(0, AREA), (1, AREA + PAGE), (0, AREA + 2 * PAGE)] {
        crate::userfaultfd::tests::queue(&context, address, n, 7);
    }
    assert_ne!(readiness(&f, fd) & 1, 0);
    assert!(f.fdinfo(fd).contains("pending:\t3\ntotal:\t3\n"));
    // A read of more than one message takes both, a short one none.
    assert_eq!(f.ret(0, &[fd, ARG, 40]), 32);
    let mut message = [0u8; 32];
    f.mem.read(GuestAddr(ARG), &mut message).unwrap();
    assert_eq!(message[0], 0x12);
    assert_eq!(
        u64::from_le_bytes(message[16..24].try_into().unwrap()),
        AREA
    );
    assert_eq!(u32::from_le_bytes(message[24..28].try_into().unwrap()), 7);
    assert!(f.fdinfo(fd).contains("pending:\t2\ntotal:\t3\n"));
    // One that cannot be copied out is lost.
    assert_eq!(f.ret(0, &[fd, 0x4000_0000, 32]), errno(Errno::EFAULT));
    assert!(f.fdinfo(fd).contains("pending:\t1\ntotal:\t3\n"));
    // readv takes them as read does.
    let iov = [ARG + 0x100, 64u64];
    let bytes: Vec<u8> = iov.iter().flat_map(|w| w.to_le_bytes()).collect();
    f.mem.write(GuestAddr(ARG + 0x80), &bytes).unwrap();
    assert_eq!(f.ret(19, &[fd, ARG + 0x80, 1]), 32);
    assert!(f.fdinfo(fd).contains("pending:\t0\ntotal:\t3\n"));
    assert_eq!(readiness(&f, fd) & 1, 0);
    assert_eq!(f.ret(19, &[fd, ARG + 0x80, 1]), errno(Errno::EAGAIN));
    // UFFDIO_UNREGISTER ends the waits of the range.
    assert_eq!(f.ioctl(fd, UNREGISTER, &[AREA + PAGE, PAGE]).0, 0);
    assert!(f.fdinfo(fd).contains("pending:\t0\ntotal:\t2\n"));
    assert_eq!(f.ioctl(fd, WAKE, &[AREA, PAGE]).0, 0);
    assert!(f.fdinfo(fd).contains("pending:\t0\ntotal:\t1\n"));
    // A file that blocks polls POLLERR, as one before UFFDIO_API.
    assert_eq!(f.ret(72, &[fd, 4, 0]), 0);
    assert_eq!(readiness(&f, fd), 8);
    // Closing it ends the last.
    assert_eq!(f.ret(3, &[fd]), 0);
    assert_eq!(crate::userfaultfd::tests::counts(&context), (0, 0));
}

#[test]
fn a_child_and_a_moved_mapping_leave_the_registration() {
    let mut f = fixture();
    let fd = f.ready(0, 0);
    assert_eq!(f.register(fd, AREA, 2 * PAGE), 0);
    let child = f.mem.fork();
    assert!(child.userfault_at(GuestAddr(AREA)).is_none());
    assert!(f.mem.userfault_at(GuestAddr(AREA)).is_some());
    // mremap moves it without its registration (MREMAP_MAYMOVE).
    assert_eq!(f.ret(25, &[AREA, 2 * PAGE, 4 * PAGE, 1, 0]) & 0xfff, 0);
    assert!(f.mem.mappings().all(|m| m.userfault.is_none()));
    // Nor the write protection of its pages, which a child does not get
    // either.
    let mut f = fixture();
    let fd = f.ready(0, 0);
    f.mem.write(GuestAddr(AREA), b"a").unwrap();
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, 2 * PAGE, 2, 0]).0, 0);
    assert_eq!(f.ioctl(fd, WRITEPROTECT, &[AREA, PAGE, 1]).0, 0);
    let child = f.mem.fork();
    child.write(GuestAddr(AREA), b"b").unwrap();
    assert!(f.mem.write(GuestAddr(AREA), b"b").is_err());
    let moved = f.ret(25, &[AREA, 2 * PAGE, 4 * PAGE, 1, 0]);
    assert_ne!(moved, AREA);
    f.mem.write(GuestAddr(moved), b"c").unwrap();
}

#[test]
fn a_write_to_a_write_protected_page_faults_until_the_protection_ends() {
    let mut f = fixture();
    let fd = f.ready(NONBLOCK, 0);
    // The minor mode is refused, the write-protect mode reports
    // UFFDIO_WRITEPROTECT.
    assert_eq!(
        f.ioctl(fd, REGISTER, &[AREA, PAGE, 4, 0]).0,
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ioctl(fd, WRITEPROTECT, &[AREA, PAGE, 1]).0,
        errno(Errno::ENOENT)
    );
    f.mem.write(GuestAddr(AREA), b"a").unwrap();
    let (ret, out) = f.ioctl(fd, REGISTER, &[AREA, 2 * PAGE, 3, 0]);
    assert_eq!((ret, out[3]), (0, 0x17c));
    assert_eq!(
        f.userfault(AREA).map(|u| u.modes),
        Some(Userfault::MISSING | Userfault::WP)
    );
    // The modes and the range are checked, and protecting does not take
    // DONTWAKE.
    for (words, error) in [
        ([AREA, PAGE, 4], Errno::EINVAL),
        ([AREA, PAGE, 3], Errno::EINVAL),
        ([AREA + 1, PAGE, 1], Errno::EINVAL),
        ([AREA, 0, 1], Errno::EINVAL),
        ([AREA, 3 * PAGE, 1], Errno::ENOENT),
    ] {
        assert_eq!(f.ioctl(fd, WRITEPROTECT, &words).0, errno(error));
    }
    assert_eq!(f.ioctl(fd, WRITEPROTECT, &[AREA, 2 * PAGE, 1]).0, 0);
    // A system call's write there is EFAULT, its read is not.
    assert_eq!(f.ret(1, &[1, AREA, 1]), 1);
    assert_eq!(f.ret(0, &[fd, AREA, 32]), errno(Errno::EAGAIN));
    // A write faults with the WP flag; the message waits for a read, which
    // a signal does not take away here, as the wait ends at once.
    let id = f.userfault(AREA).unwrap().context;
    let context = crate::userfaultfd::find(id).unwrap();
    crate::signals::queue(
        &mut f.thread.state,
        crate::signals::PendingSignal::user(10, 0),
    );
    let reason = ExitReason::PageFault {
        rip: GuestAddr(0x1234),
        addr: GuestAddr(AREA + 9),
        write: true,
        fetch: false,
        mapped: true,
        present: true,
    };
    assert_eq!(
        f.kernel.handle(&mut f.thread, &f.mem, reason),
        Next::Exit(ExitStatus::Signaled(10))
    );
    assert_eq!(crate::userfaultfd::tests::counts(&context), (0, 0));
    // UFFDIO_WRITEPROTECT that ends the protection wakes the range, unless
    // DONTWAKE.
    let mut f = fixture();
    let fd = f.ready(NONBLOCK, 0);
    f.mem.write(GuestAddr(AREA), b"a").unwrap();
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, PAGE, 2, 0]).0, 0);
    assert_eq!(f.ioctl(fd, WRITEPROTECT, &[AREA, PAGE, 1]).0, 0);
    let context = crate::userfaultfd::find(f.userfault(AREA).unwrap().context).unwrap();
    crate::userfaultfd::tests::queue(&context, AREA, 3, 0);
    assert_eq!(f.ioctl(fd, WRITEPROTECT, &[AREA, PAGE, 2]).0, 0);
    assert_eq!(crate::userfaultfd::tests::counts(&context), (1, 1));
    f.mem.write(GuestAddr(AREA), b"b").unwrap();
    assert_eq!(f.ioctl(fd, WRITEPROTECT, &[AREA, PAGE, 0]).0, 0);
    assert_eq!(crate::userfaultfd::tests::counts(&context), (0, 0));
    // A copy may protect the page it fills; with SIGBUS the write raises it.
    let mut f = fixture();
    let fd = f.ready(0, SIGBUS);
    assert_eq!(
        f.ioctl(fd, COPY, &[AREA, SRC, PAGE, 2, 0]).0,
        errno(Errno::ENOENT)
    );
    assert_eq!(f.register(fd, AREA, PAGE), 0);
    assert_eq!(
        f.ioctl(fd, COPY, &[AREA, SRC, PAGE, 2, 0]).0,
        errno(Errno::EINVAL)
    );
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, PAGE, 3, 0]).0, 0);
    assert_eq!(
        f.ioctl(fd, COPY, &[AREA, SRC, PAGE, 2, 0]),
        (0, vec![AREA, SRC, PAGE, 2, PAGE])
    );
    let mut byte = [0];
    f.mem.read(GuestAddr(AREA), &mut byte).unwrap();
    assert!(f.mem.write(GuestAddr(AREA), b"c").is_err());
    let reason = ExitReason::PageFault {
        rip: GuestAddr(0x1234),
        addr: GuestAddr(AREA),
        write: true,
        fetch: false,
        mapped: true,
        present: true,
    };
    assert_eq!(
        f.kernel.handle(&mut f.thread, &f.mem, reason),
        Next::Exit(ExitStatus::Signaled(signal::SIGBUS))
    );
    // Unregistering ends the protection.
    let mut f = fixture();
    let fd = f.ready(0, 0);
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, PAGE, 2, 0]).0, 0);
    f.mem.write(GuestAddr(AREA), b"d").unwrap();
    assert_eq!(f.ioctl(fd, WRITEPROTECT, &[AREA, PAGE, 1]).0, 0);
    assert!(f.mem.write(GuestAddr(AREA), b"e").is_err());
    assert_eq!(f.ioctl(fd, UNREGISTER, &[AREA, PAGE]).0, 0);
    f.mem.write(GuestAddr(AREA), b"e").unwrap();
}

#[test]
fn uffdio_poison_poisons_pages_that_have_none() {
    let mut f = fixture();
    let fd = f.ready(0, FEATURE_POISON);
    // A range no userfaultfd registered.
    assert_eq!(
        f.ioctl(fd, POISON, &[AREA, PAGE, 0, 0]),
        (
            errno(Errno::ENOENT),
            vec![AREA, PAGE, 0, errno(Errno::ENOENT)]
        )
    );
    f.mem.write(GuestAddr(AREA + PAGE), b"x").unwrap();
    assert_eq!(f.register(fd, AREA, 2 * PAGE), 0);
    // DONTWAKE is the only mode, and the range is whole pages.
    assert_eq!(
        f.ioctl(fd, POISON, &[AREA, PAGE, 2, 0]).0,
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ioctl(fd, POISON, &[AREA + 1, PAGE, 0, 0]).0,
        errno(Errno::EINVAL)
    );
    // It stops at a page that has an entry, short of the range.
    assert_eq!(
        f.ioctl(fd, POISON, &[AREA, 2 * PAGE, 0, 0]),
        (errno(Errno::EAGAIN), vec![AREA, 2 * PAGE, 0, PAGE])
    );
    // A zero page does not replace the poison.
    assert_eq!(
        f.ioctl(fd, ZEROPAGE, &[AREA, PAGE, 0, 0]).1[3],
        errno(Errno::EEXIST)
    );
    // A system call's copy is EFAULT, MADV_POPULATE_READ EHWPOISON.
    assert_eq!(f.ret(1, &[1, AREA, 1]), errno(Errno::EFAULT));
    assert_eq!(f.ret(28, &[AREA, PAGE, 22]), errno(Errno(133)));
    // An access raises SIGBUS with BUS_MCEERR_AR and the page's shift.
    let act = DATA + 0x200;
    let words: Vec<u8> = [0x5000u64, 0x0400_0004, 0x5100, 0]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    f.mem.write(GuestAddr(act), &words).unwrap();
    assert_eq!(f.ret(13, &[7, act, 0, 8]), 0);
    f.thread.cpu.gpr[reg::RSP] = DATA + 0x6000;
    let reason = ExitReason::BusError {
        rip: GuestAddr(0x1234),
        addr: GuestAddr(AREA + 5),
        write: false,
        fetch: false,
        present: false,
        poison: true,
    };
    assert_eq!(f.kernel.handle(&mut f.thread, &f.mem, reason), Next::Resume);
    let mut info = [0u8; 32];
    f.mem
        .read(GuestAddr(f.thread.cpu.gpr[reg::RSI]), &mut info)
        .unwrap();
    assert_eq!(info[0..4], 7u32.to_le_bytes());
    assert_eq!(info[8..12], 4u32.to_le_bytes());
    assert_eq!(info[16..24], (AREA + 5).to_le_bytes());
    assert_eq!(info[24..26], 12u16.to_le_bytes());
    // The poison outlasts the registration; MADV_DONTNEED ends it.
    assert_eq!(f.ioctl(fd, UNREGISTER, &[AREA, 2 * PAGE]).0, 0);
    assert!(f.mem.read(GuestAddr(AREA), &mut [0]).unwrap_err().poison);
    assert_eq!(f.ret(28, &[AREA, PAGE, 4]), 0);
    f.mem.read(GuestAddr(AREA), &mut [0]).unwrap();
    // A copy replaces the poison (the read left a page to discard first).
    assert_eq!(f.ret(28, &[AREA, PAGE, 4]), 0);
    assert_eq!(f.register(fd, AREA, PAGE), 0);
    assert_eq!(f.ioctl(fd, POISON, &[AREA, PAGE, 0, 0]).0, 0);
    f.mem.write(GuestAddr(SRC), b"q").unwrap();
    assert_eq!(f.ioctl(fd, COPY, &[AREA, SRC, PAGE, 0, 0]).1[4], PAGE);
    let mut byte = [0];
    f.mem.read(GuestAddr(AREA), &mut byte).unwrap();
    assert_eq!(byte, *b"q");
}

#[test]
fn uffdio_move_moves_private_anonymous_pages_into_a_registered_range() {
    let mut f = fixture();
    let fd = f.ready(0, 0);
    assert_eq!(f.register(fd, AREA, 4 * PAGE), 0);
    let src = AREA + 4 * PAGE;
    f.mem.write(GuestAddr(src), b"x").unwrap();
    f.mem.write(GuestAddr(src + PAGE), b"y").unwrap();
    let einval = errno(Errno::EINVAL);
    // Modes it knows, and whole pages.
    assert_eq!(f.ioctl(fd, MOVE, &[AREA, src, PAGE, 4, 0]).0, einval);
    assert_eq!(f.ioctl(fd, MOVE, &[AREA, src + 1, PAGE, 0, 0]).0, einval);
    assert_eq!(f.ioctl(fd, MOVE, &[AREA, src, 0, 0, 0]).0, einval);
    // A start in no VMA is ENOENT; a destination not registered EINVAL.
    assert_eq!(
        f.ioctl(fd, MOVE, &[AREA, 0x30_0000, PAGE, 0, 0]).1[4],
        errno(Errno::ENOENT)
    );
    assert_eq!(
        f.ioctl(fd, MOVE, &[src + 2 * PAGE, src, PAGE, 0, 0]).1[4],
        einval
    );
    // A page moves, with its contents, and the source has none.
    assert_eq!(
        f.ioctl(fd, MOVE, &[AREA, src, PAGE, 0, 0]),
        (0, vec![AREA, src, PAGE, 0, PAGE])
    );
    let mut byte = [0];
    f.mem.read(GuestAddr(AREA), &mut byte).unwrap();
    assert_eq!(byte, *b"x");
    // A destination page that has one is EEXIST, a source page with none
    // ENOENT, unless holes are allowed, which count as moved.
    assert_eq!(
        f.ioctl(fd, MOVE, &[AREA, src + PAGE, PAGE, 0, 0]).1[4],
        errno(Errno::EEXIST)
    );
    assert_eq!(
        f.ioctl(fd, MOVE, &[AREA + PAGE, src, PAGE, 0, 0]).1[4],
        errno(Errno::ENOENT)
    );
    assert_eq!(
        f.ioctl(fd, MOVE, &[AREA + PAGE, src, 2 * PAGE, 2, 0]),
        (0, vec![AREA + PAGE, src, 2 * PAGE, 2, 2 * PAGE])
    );
    f.mem.read(GuestAddr(AREA + 2 * PAGE), &mut byte).unwrap();
    assert_eq!(byte, *b"y");
    // A range past its VMA is EINVAL, written back as well.
    f.mem.write(GuestAddr(src + 2 * PAGE), b"z").unwrap();
    assert_eq!(
        f.ioctl(fd, MOVE, &[AREA + 3 * PAGE, src + 2 * PAGE, 2 * PAGE, 0, 0]),
        (
            einval,
            vec![AREA + 3 * PAGE, src + 2 * PAGE, 2 * PAGE, 0, einval]
        )
    );
    // A move that stops short is EAGAIN, with the bytes it moved.
    f.mem.write(GuestAddr(src), b"v").unwrap();
    f.mem.write(GuestAddr(src + PAGE), b"w").unwrap();
    assert_eq!(
        f.ioctl(fd, MOVE, &[AREA + PAGE, src, 2 * PAGE, 1, 0]),
        (
            errno(Errno::EAGAIN),
            vec![AREA + PAGE, src, 2 * PAGE, 1, PAGE]
        )
    );
    f.mem.read(GuestAddr(AREA + PAGE), &mut byte).unwrap();
    assert_eq!(byte, *b"v");
    // Both VMAs need the same protection.
    f.mem
        .protect(GuestAddr(src + 2 * PAGE), PAGE, Prot::READ)
        .unwrap();
    assert_eq!(
        f.ioctl(fd, MOVE, &[AREA + 3 * PAGE, src + 2 * PAGE, PAGE, 0, 0])
            .1[4],
        einval
    );
}

#[test]
fn uffdio_continue_maps_a_memfd_page_registered_for_minor_faults() {
    let mut f = fixture();
    let fd = f.ready(0, 0);
    // A memfd of two pages, the second written, mapped shared.
    f.mem.write(GuestAddr(DATA), b"uffd\0").unwrap();
    let file = f.ret(319, &[DATA, 0]);
    assert!((file as i64) >= 0, "{file:#x}");
    assert_eq!(f.ret(77, &[file, 2 * PAGE]), 0);
    f.mem.write(GuestAddr(SRC), b"m").unwrap();
    assert_eq!(f.ret(18, &[file, SRC, 1, PAGE]), 1);
    let at = f.ret(9, &[0, 3 * PAGE, 3, 1, file, 0]);
    assert!((at as i64) > 0, "{at:#x}");
    // The minor mode, which adds UFFDIO_CONTINUE to the ioctls.
    let (ret, out) = f.ioctl(fd, REGISTER, &[at, 3 * PAGE, 4, 0]);
    assert_eq!((ret, out[3]), (0, 0x1bc));
    let einval = errno(Errno::EINVAL);
    assert_eq!(f.ioctl(fd, CONTINUE, &[at, PAGE, 4, 0]).0, einval);
    // A write-protecting continue needs the range registered for it.
    assert_eq!(f.ioctl(fd, CONTINUE, &[at + PAGE, PAGE, 2, 0]).1[3], einval);
    // A hole is EFAULT, a page past the file's end EINVAL.
    assert_eq!(
        f.ioctl(fd, CONTINUE, &[at, PAGE, 0, 0]).1[3],
        errno(Errno::EFAULT)
    );
    assert_eq!(
        f.ioctl(fd, CONTINUE, &[at + 2 * PAGE, PAGE, 0, 0]).1[3],
        einval
    );
    assert_eq!(
        f.ioctl(fd, CONTINUE, &[at + PAGE, PAGE, 0, 0]),
        (0, vec![at + PAGE, PAGE, 0, PAGE])
    );
    let mut byte = [0];
    f.mem.read(GuestAddr(at + PAGE), &mut byte).unwrap();
    assert_eq!(byte, *b"m");
    assert_eq!(
        f.ioctl(fd, CONTINUE, &[at + PAGE, PAGE, 0, 0]).1[3],
        errno(Errno::EEXIST)
    );
}

#[test]
fn wp_unpopulated_protects_the_pages_that_have_none() {
    let mut f = fixture();
    let protected = |f: &Fixture, addr: u64| {
        f.mem
            .userfault_for(GuestAddr(addr), true, false)
            .map(|(_, reason)| reason)
    };
    // Without the feature, a page with no entry is not protected.
    let fd = f.ready(NONBLOCK, 0);
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, 2 * PAGE, 2, 0]).0, 0);
    assert_eq!(f.userfault(AREA).map(|u| u.modes), Some(Userfault::WP));
    assert_eq!(f.ioctl(fd, WRITEPROTECT, &[AREA, 2 * PAGE, 1]).0, 0);
    assert_eq!(protected(&f, AREA), None);
    assert_eq!(f.ret(3, &[fd]), 0);
    // With it, the registration has it, and the protection marks them.
    let fd = f.ready(NONBLOCK, WP_UNPOPULATED);
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, 2 * PAGE, 2, 0]).0, 0);
    assert_eq!(
        f.userfault(AREA).map(|u| u.modes),
        Some(Userfault::WP | Userfault::WP_UNPOPULATED)
    );
    assert_eq!(f.ioctl(fd, WRITEPROTECT, &[AREA, 2 * PAGE, 1]).0, 0);
    assert_eq!(protected(&f, AREA + PAGE), Some(UserfaultReason::Protected));
    assert!(f.mem.write(GuestAddr(AREA + PAGE), b"a").is_err());
    assert_eq!(f.ioctl(fd, WRITEPROTECT, &[AREA, 2 * PAGE, 0]).0, 0);
    f.mem.write(GuestAddr(AREA), b"a").unwrap();
}

#[test]
fn wp_async_clears_the_protection_a_write_meets() {
    let mut f = fixture();
    // It brings WP_UNPOPULATED, which the context then has.
    let fd = f.ready(NONBLOCK, WP_ASYNC);
    assert!(
        f.fdinfo(fd)
            .ends_with("API:\taa:8000a000:80000000000001ff\n")
    );
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, 2 * PAGE, 2, 0]).0, 0);
    assert_eq!(
        f.userfault(AREA).map(|u| u.modes),
        Some(Userfault::WP | Userfault::WP_UNPOPULATED | Userfault::WP_ASYNC)
    );
    f.mem.write(GuestAddr(AREA), b"a").unwrap();
    assert_eq!(f.ioctl(fd, WRITEPROTECT, &[AREA, 2 * PAGE, 1]).0, 0);
    assert!(f.mem.check_write(GuestAddr(AREA), 1).is_ok());
    // A write to the page with an entry, and to the one with a marker,
    // goes on, and nothing waits.
    f.mem.write(GuestAddr(AREA), b"b").unwrap();
    f.mem.write(GuestAddr(AREA + PAGE), b"c").unwrap();
    assert_eq!(f.mem.userfault_for(GuestAddr(AREA), true, false), None);
    assert_eq!(f.ret(0, &[fd, ARG, 32]), errno(Errno::EAGAIN));
    let mut bytes = [0; 1];
    f.mem.read(GuestAddr(AREA + PAGE), &mut bytes).unwrap();
    assert_eq!(bytes, *b"c");
    // The missing mode with it takes private anonymous memory as before.
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, 2 * PAGE, 3, 0]).0, 0);
}

/// The event, first word and second word of a message.
fn event_of(message: &[u8; 32]) -> (u8, u64, u64, u64) {
    let word = |at: usize| u64::from_le_bytes(message[at..at + 8].try_into().unwrap());
    (message[0], word(8), word(16), word(24))
}

#[test]
fn an_event_is_read_after_the_faults_and_holds_the_changes_back() {
    use crate::userfaultfd::tests::{changing, queue, queue_events, unmap_events};
    let mut f = fixture();
    let fd = f.ready(NONBLOCK, EVENT_UNMAP | EVENT_REMOVE | EVENT_REMAP);
    assert!(f.fdinfo(fd).contains("API:\taa:8000004c:"));
    // Two ranges of one context make one event of the whole unmap.
    assert_eq!(f.register(fd, AREA, PAGE), 0);
    assert_eq!(f.register(fd, AREA + 2 * PAGE, PAGE), 0);
    let context = crate::userfaultfd::find(f.userfault(AREA).unwrap().context).unwrap();
    let (events, messages) = unmap_events(&f.mem.view(), AREA, AREA + 4 * PAGE);
    assert_eq!(messages.len(), 1);
    assert_eq!(event_of(&messages[0]), (0x16, AREA, AREA + 4 * PAGE, 0));
    assert!(changing(&context));
    // Dropped undelivered, as when the unmap fails, it counts no more.
    drop(events);
    assert!(!changing(&context));
    let (events, _) = unmap_events(&f.mem.view(), AREA, AREA + PAGE);
    let queued = queue_events(events);
    queue(&context, AREA + PAGE, 0, 0);
    assert_ne!(readiness(&f, fd) & 1, 0);
    // Until it is read, the fills, moves and changes of protection are
    // EAGAIN, which the fills and moves write to their last field.
    let again = errno(Errno::EAGAIN);
    let (ret, out) = f.ioctl(fd, COPY, &[AREA, SRC, PAGE, 0, 0]);
    assert_eq!((ret, out[4]), (again, again));
    for cmd in [ZEROPAGE, POISON, CONTINUE] {
        let (ret, out) = f.ioctl(fd, cmd, &[AREA, PAGE, 0, 0]);
        assert_eq!((ret, out[3]), (again, again), "{cmd:#x}");
    }
    let (ret, out) = f.ioctl(fd, MOVE, &[AREA, SRC, PAGE, 0, 0]);
    assert_eq!((ret, out[4]), (again, again));
    assert_eq!(f.ioctl(fd, WRITEPROTECT, &[AREA, PAGE, 0]).0, again);
    // A read takes the fault first, then the event, whose thread goes on.
    assert_eq!(f.ret(0, &[fd, ARG, 64]), 64);
    let mut bytes = [0u8; 64];
    f.mem.read(GuestAddr(ARG), &mut bytes).unwrap();
    let (first, second) = bytes.split_at(32);
    assert_eq!(event_of(first.try_into().unwrap()).0, 0x12);
    assert_eq!(
        event_of(second.try_into().unwrap()),
        (0x16, AREA, AREA + PAGE, 0)
    );
    assert!(queued[0].read());
    assert_eq!(readiness(&f, fd) & 1, 0);
    for queued in queued {
        queued.finish();
    }
    let (ret, out) = f.ioctl(fd, COPY, &[AREA, SRC, PAGE, 0, 0]);
    assert_eq!((ret, out[4]), (0, PAGE));
    // A context without the feature is told nothing.
    let other = f.ready(NONBLOCK, 0);
    assert_eq!(f.register(other, AREA + 4 * PAGE, PAGE), 0);
    let (_, messages) = unmap_events(&f.mem.view(), AREA + 4 * PAGE, AREA + 5 * PAGE);
    assert!(messages.is_empty());
}

#[test]
fn the_changes_wait_until_their_events_are_read() {
    use crate::userfaultfd::tests::{changing, reader};
    let mut f = fixture();
    let fd = f.ready(NONBLOCK, EVENT_UNMAP | EVENT_REMOVE | EVENT_REMAP);
    assert_eq!(f.register(fd, AREA, 4 * PAGE), 0);
    let id = f.userfault(AREA).unwrap().context;
    let context = crate::userfaultfd::find(id).unwrap();
    // A move keeps the registration, and tells of the move, then of the
    // range it left.
    const TO: u64 = 0x60_0000;
    let handler = reader(Arc::clone(&context), 2);
    assert_eq!(f.ret(25, &[AREA, 2 * PAGE, 2 * PAGE, 3, TO]), TO);
    let messages = handler.join().unwrap();
    assert_eq!(event_of(&messages[0]), (0x14, AREA, TO, 2 * PAGE));
    assert_eq!(event_of(&messages[1]), (0x16, AREA, AREA + 2 * PAGE, 0));
    assert_eq!(f.userfault(TO).map(|u| u.context), Some(id));
    assert!(!changing(&context));
    // A discard tells of the range before it drops the pages.
    let handler = reader(Arc::clone(&context), 1);
    assert_eq!(f.ret(28, &[TO, 2 * PAGE, 4]), 0);
    assert_eq!(
        event_of(&handler.join().unwrap()[0]),
        (0x15, TO, TO + 2 * PAGE, 0)
    );
    // A fixed mapping over it unmaps it.
    let handler = reader(Arc::clone(&context), 1);
    assert_eq!(f.ret(9, &[TO, PAGE, 3, 0x32, u64::MAX, 0]), TO);
    assert_eq!(
        event_of(&handler.join().unwrap()[0]),
        (0x16, TO, TO + PAGE, 0)
    );
    // So does munmap, of the whole range it was given.
    let handler = reader(Arc::clone(&context), 1);
    assert_eq!(f.ret(11, &[AREA + PAGE, 4 * PAGE]), 0);
    assert_eq!(
        event_of(&handler.join().unwrap()[0]),
        (0x16, AREA + PAGE, AREA + 5 * PAGE, 0)
    );
    assert!(!changing(&context));
}

#[test]
fn a_fork_hands_the_child_a_context_of_its_own() {
    use crate::userfaultfd::tests::{children, queue_events, reader};
    let mut f = fixture();
    let fd = f.ready(NONBLOCK, EVENT_FORK);
    let other = f.ready(NONBLOCK, 0);
    assert_eq!(f.register(fd, AREA, 2 * PAGE), 0);
    assert_eq!(f.register(other, AREA + 4 * PAGE, PAGE), 0);
    let id = f.userfault(AREA).unwrap().context;
    let context = crate::userfaultfd::find(id).unwrap();
    // fork waits for the event, whose new context the child's
    // registrations moved to; the other context's go.
    let handler = reader(Arc::clone(&context), 1);
    let pid = f.ret(57, &[]);
    assert!((pid as i64) > 0, "{pid:#x}");
    let message = handler.join().unwrap()[0];
    let (event, new, _, _) = event_of(&message);
    assert_eq!(event, 0x13);
    assert_ne!(new, id);
    let child = f.kernel.pending_child.take().unwrap().0;
    let memory = child.spawn_memory.clone().unwrap();
    let registered = |addr: u64| {
        memory
            .mappings()
            .find(|m| m.start.0 <= addr && addr < m.end())
            .and_then(|m| m.userfault)
            .map(|u| u.context)
    };
    assert_eq!(registered(AREA), Some(new));
    assert_eq!(registered(AREA + 4 * PAGE), None);
    assert_eq!(f.userfault(AREA).map(|u| u.context), Some(id));
    // A read hands the child's context over as a file of its own, with the
    // features of the old, whose close takes the child's mappings out.
    let copy = f.mem.fork();
    let mut events = crate::userfaultfd::Events::default();
    crate::userfaultfd::fork(&copy.view(), &mut events);
    let made = children(&events);
    assert_eq!(made.len(), 1);
    let queued = queue_events(events);
    assert_eq!(f.ret(0, &[fd, ARG, 32]), 32);
    let mut bytes = [0u8; 32];
    f.mem.read(GuestAddr(ARG), &mut bytes).unwrap();
    assert_eq!(bytes[0], 0x13);
    let handed = u64::from(u32::from_le_bytes(bytes[8..12].try_into().unwrap()));
    assert!(queued[0].read());
    assert!(f.fdinfo(handed).contains("API:\taa:80000002:"));
    let in_copy = |addr: u64| {
        copy.mappings()
            .find(|m| m.start.0 <= addr && addr < m.end())
            .and_then(|m| m.userfault)
            .map(|u| u.context)
    };
    assert_eq!(in_copy(AREA), Some(made[0]));
    assert_eq!(f.ret(3, &[handed]), 0);
    assert_eq!(in_copy(AREA), None);
    for queued in queued {
        queued.finish();
    }
}

const PAGEMAP_SCAN: u64 = 0xc060_6610;
const VEC: u64 = DATA + 0x1000;
const IS_WRITTEN: u64 = 1 << 1;
const IS_PRESENT: u64 = 1 << 3;
const IS_ACCESSED: u64 = 1 << 9;

impl Fixture {
    /// `/proc/self/pagemap`, opened for reading.
    fn pagemap(&mut self) -> u64 {
        self.mem
            .write(GuestAddr(DATA), b"/proc/self/pagemap\0")
            .unwrap();
        let fd = self.ret(2, &[DATA, 0, 0]);
        assert!((fd as i64) >= 0, "{fd:#x}");
        fd
    }
    /// `PAGEMAP_SCAN` of the 8 pages at [`AREA`] for 4 regions at [`VEC`]
    /// with `flags` and the masks; its result, `walk_end` and the regions.
    fn scan(&mut self, fd: u64, flags: u64, required: u64, returned: u64) -> (u64, u64, Vec<u64>) {
        let words = [
            96,
            flags,
            AREA,
            AREA + 8 * PAGE,
            0,
            VEC,
            4,
            0,
            0,
            required,
            0,
            returned,
        ];
        let (ret, out) = self.ioctl(fd, PAGEMAP_SCAN, &words);
        let mut regions = vec![0; 4 * 24];
        self.mem.read(GuestAddr(VEC), &mut regions).unwrap();
        self.mem.write(GuestAddr(VEC), &[0; 4 * 24]).unwrap();
        let regions = regions
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_le_bytes(*c))
            .take(ret.min(4) as usize * 3)
            .collect();
        (ret, out[4], regions)
    }
}

#[test]
fn pagemap_scan_checks_its_request_and_reports_regions() {
    let mut f = fixture();
    let pm = f.pagemap();
    f.mem.write(GuestAddr(AREA), b"a").unwrap();
    let end = AREA + 8 * PAGE;
    // Linux master takes `PAGE_IS_ACCESSED`, which no page has here.
    assert_eq!(
        f.scan(pm, 0, IS_PRESENT, IS_PRESENT | IS_ACCESSED),
        (1, end, vec![AREA, AREA + PAGE, IS_PRESENT])
    );
    let einval = errno(Errno::EINVAL);
    assert_eq!(f.scan(pm, 4, 0, 0).0, einval);
    assert_eq!(f.scan(pm, 0, 1 << 10, 0).0, einval);
    let base = [96, 0, AREA, end, 0, VEC, 4, 0, 0, 0, 0, 0];
    let with = |i: usize, value: u64| {
        let mut words = base;
        words[i] = value;
        words
    };
    assert_eq!(f.ioctl(pm, PAGEMAP_SCAN, &with(0, 88)).0, einval);
    assert_eq!(f.ioctl(pm, PAGEMAP_SCAN, &with(2, AREA + 1)).0, einval);
    assert_eq!(f.ioctl(pm, PAGEMAP_SCAN, &with(5, 0)).0, einval);
    let efault = errno(Errno::EFAULT);
    assert_eq!(f.ioctl(pm, PAGEMAP_SCAN, &with(3, AREA - PAGE)).0, efault);
    assert_eq!(
        f.ioctl(pm, PAGEMAP_SCAN, &with(5, 0u64.wrapping_sub(4096)))
            .0,
        efault
    );
    // As Linux master's `-ENOIOCTLCMD`, any other request is `ENOTTY`.
    assert_eq!(f.ioctl(pm, PAGEMAP_SCAN + 1, &base).0, errno(Errno::ENOTTY));
    // A pagemap of a space that is gone is `ESRCH`, as master's
    // `mmget_not_zero` fails.
    let gone = AddressSpace::new();
    let file = Arc::new(crate::proc::PagemapFile::open(
        gone.view(),
        0,
        Arc::default(),
    ));
    drop(gone);
    let fd = u64::from(f.kernel.files.install(file, false, 1024).unwrap());
    assert_eq!(f.ioctl(fd, PAGEMAP_SCAN, &base).0, errno(Errno(3)));

    // With WP_ASYNC, the written pages, which it can protect.
    let ufd = f.ready(NONBLOCK, WP_ASYNC | WP_UNPOPULATED);
    assert_eq!(f.ioctl(ufd, REGISTER, &[AREA, 8 * PAGE, 2, 0]).0, 0);
    assert_eq!(f.ioctl(ufd, WRITEPROTECT, &[AREA, 8 * PAGE, 1]).0, 0);
    assert_eq!(f.scan(pm, 0, IS_WRITTEN, IS_WRITTEN), (0, end, vec![]));
    f.mem.write(GuestAddr(AREA + 2 * PAGE), b"b").unwrap();
    f.mem.write(GuestAddr(AREA + 5 * PAGE), b"c").unwrap();
    let written = vec![
        AREA + 2 * PAGE,
        AREA + 3 * PAGE,
        IS_WRITTEN,
        AREA + 5 * PAGE,
        AREA + 6 * PAGE,
        IS_WRITTEN,
    ];
    assert_eq!(f.scan(pm, 3, IS_WRITTEN, IS_WRITTEN), (2, end, written));
    assert_eq!(f.scan(pm, 0, IS_WRITTEN, IS_WRITTEN), (0, end, vec![]));
    // A VMA it may not protect stops `PM_SCAN_CHECK_WPASYNC`.
    assert_eq!(f.ioctl(ufd, UNREGISTER, &[AREA + 4 * PAGE, PAGE]).0, 0);
    assert_eq!(f.scan(pm, 2, IS_WRITTEN, IS_WRITTEN).0, errno(Errno::EPERM));
}
