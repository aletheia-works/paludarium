//! The userfaultfd calls ([`crate::userfaultfd`]) through the kernel's
//! dispatch.
use super::*;
use paludarium_host::testing::RecordingHost;
use paludarium_mmu::{MappingKind, Prot, Userfault};
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

const NONBLOCK: u64 = 0o4000;
const SIGBUS: u64 = 1 << 7;
const THREAD_ID: u64 = 1 << 8;
const EXACT_ADDRESS: u64 = 1 << 11;

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
    // UFFD_FEATURE_WP_ASYNC brings UFFD_FEATURE_WP_UNPOPULATED, neither
    // offered.
    assert_eq!(
        f.ioctl(fd, API, &[0xaa, 1 << 15, 0]).0,
        errno(Errno::EINVAL)
    );
    assert_eq!(f.ret(16, &[fd, API, 0]), errno(Errno::EFAULT));
    let (ret, out) = f.ioctl(fd, API, &[0xaa, SIGBUS | THREAD_ID, 0]);
    assert_eq!(ret, 0);
    assert_eq!(out, vec![0xaa, 0x9b0, 1 << 63 | 3]);
    assert_eq!(
        f.ioctl(fd, API, &[0xaa, 0, 0]),
        (errno(Errno::EINVAL), vec![0, 0, 0])
    );
    assert_eq!(f.ioctl(fd, 0xc018_aa3e, &[0, 0, 0]).0, errno(Errno::EINVAL));
    assert!(
        f.fdinfo(fd)
            .ends_with("pending:\t0\ntotal:\t0\nAPI:\taa:80000180:800000000000001f\n")
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
    // The write-protect and minor modes are not offered.
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, PAGE, 2, 0]).0, einval);
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA + 1, PAGE, 1, 0]).0, einval);
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, PAGE + 1, 1, 0]).0, einval);
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, 0, 1, 0]).0, einval);
    assert_eq!(f.ioctl(fd, REGISTER, &[0x1000, PAGE, 1, 0]).0, einval);
    assert_eq!(f.ioctl(fd, REGISTER, &[1 << 47, PAGE, 1, 0]).0, einval);
    assert_eq!(f.ioctl(fd, REGISTER, &[AREA, !0xfff, 1, 0]).0, einval);
    assert_eq!(f.ioctl(fd, REGISTER, &[0x4000_0000, PAGE, 1, 0]).0, einval);
    assert_eq!(f.ret(16, &[fd, REGISTER, 0]), errno(Errno::EFAULT));
    let (ret, out) = f.ioctl(fd, REGISTER, &[AREA + PAGE, 2 * PAGE, 1, 0]);
    assert_eq!((ret, out[3]), (0, 0x1c));
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
}
