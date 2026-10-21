use super::*;
use paludarium_cpu::{CpuState, reg};
use paludarium_host::testing::RecordingHost;
use paludarium_mmu::{AddressSpace, MappingKind, Prot};
use paludarium_types::ExitReason;
const DATA: u64 = 0x10_0000;
struct Fixture {
    host: Arc<RecordingHost>,
    kernel: Kernel,
    thread: Thread,
    mem: AddressSpace,
}
fn fixture() -> Fixture {
    let host = Arc::new(RecordingHost::new());
    let kernel = Kernel::new(host.clone());
    let mut mem = AddressSpace::new();
    mem.map(
        Some(GuestAddr(DATA)),
        0x2000,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    Fixture {
        host,
        kernel,
        thread: Thread {
            tid: 1,
            state: ThreadState {
                pid: 1,
                ..ThreadState::default()
            },
            cpu: CpuState::default(),
        },
        mem,
    }
}
impl Fixture {
    fn ret(&mut self, n: u64, args: &[u64]) -> u64 {
        self.thread.cpu.gpr[reg::RAX] = n;
        for (r, v) in [reg::RDI, reg::RSI, reg::RDX, reg::R10, reg::R8, reg::R9]
            .iter()
            .zip(args)
        {
            self.thread.cpu.gpr[*r] = *v;
        }
        assert_eq!(
            self.kernel.handle(
                &mut self.thread,
                &self.mem,
                ExitReason::Syscall {
                    rip: GuestAddr(0x1000)
                }
            ),
            Next::Resume
        );
        self.thread.cpu.gpr[reg::RAX]
    }
}
use paludarium_host::{StreamId, TerminalInfo};
use paludarium_types::{Errno, GuestAddr};
fn tty() -> TerminalInfo {
    TerminalInfo::new(Default::default(), 101, 37, 7, 9)
}
#[test]
fn u9_winsize_guest_layout() {
    let mut f = fixture();
    f.host.set_terminal_info(StreamId::Stdin, Some(tty()));
    assert_eq!(f.ret(16, &[0, 0x5413, DATA]), 0);
    let mut b = [0; 8];
    f.mem.read(GuestAddr(DATA), &mut b).unwrap();
    assert_eq!(b, [37, 0, 101, 0, 7, 0, 9, 0]);
}
#[test]
fn u9_tcgets_guest_layout() {
    let mut f = fixture();
    let mut info = tty();
    info.attributes.input_flags = 0x12345678;
    info.attributes.control_chars[18] = 91;
    f.host.set_terminal_info(StreamId::Stderr, Some(info));
    assert_eq!(f.ret(16, &[2, 0x5401, DATA]), 0);
    let mut b = [0; 37];
    f.mem.read(GuestAddr(DATA), &mut b).unwrap();
    assert_eq!(&b[..4], &[0x78, 0x56, 0x34, 0x12]);
    assert_eq!(&b[17..36], &info.attributes.control_chars);
    assert_eq!(b[36], 0);
}
#[test]
fn u9_unknown_request_and_nonterminal_precede_pointer() {
    let mut f = fixture();
    assert_eq!(
        f.ret(16, &[0, 0x5413, 1]),
        Errno::ENOTTY.to_syscall_return()
    );
    f.host.set_terminal_info(StreamId::Stdin, Some(tty()));
    assert_eq!(
        f.ret(16, &[0, 0xdeadbeef, 1]),
        Errno::ENOTTY.to_syscall_return()
    );
}
#[test]
fn u9_invalid_and_closed_fd() {
    let mut f = fixture();
    assert_eq!(
        f.ret(16, &[999, 0x5413, DATA]),
        Errno::EBADF.to_syscall_return()
    );
    assert_eq!(f.ret(3, &[0]), 0);
    assert_eq!(
        f.ret(16, &[0, 0x5413, DATA]),
        Errno::EBADF.to_syscall_return()
    );
}
#[test]
fn u9_bad_pointer_and_boundary() {
    let mut f = fixture();
    f.host.set_terminal_info(StreamId::Stdin, Some(tty()));
    assert_eq!(
        f.ret(16, &[0, 0x5401, 1]),
        Errno::EFAULT.to_syscall_return()
    );
    assert_eq!(
        f.ret(16, &[0, 0x5413, DATA + 0x2000 - 7]),
        Errno::EFAULT.to_syscall_return()
    );
}
#[test]
fn u9_duplicate_resolves_original_stream() {
    let mut f = fixture();
    f.host.set_terminal_info(StreamId::Stdin, Some(tty()));
    let dup = f.ret(32, &[0]);
    assert_eq!(dup, 3);
    assert_eq!(f.ret(16, &[dup, 0x5413, DATA]), 0);
    assert_eq!(
        f.ret(16, &[1, 0x5413, DATA]),
        Errno::ENOTTY.to_syscall_return()
    );
}
#[test]
fn u9_regular_file_is_not_terminal() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA), b"/regular\0").unwrap();
    let fd = f.ret(2, &[DATA, 66, 0o600]);
    assert_eq!(fd, 3);
    f.kernel = f.kernel.with_terminal_size(80, 24);
    assert_eq!(
        f.ret(16, &[fd, 0x5401, DATA]),
        Errno::ENOTTY.to_syscall_return()
    );
}
#[test]
fn u9_explicit_size_overrides_host() {
    let mut f = fixture();
    f.host.set_terminal_info(StreamId::Stdin, Some(tty()));
    f.kernel = f.kernel.with_terminal_size(120, 40);
    assert_eq!(f.ret(16, &[0, 0x5413, DATA]), 0);
    let mut b = [0; 8];
    f.mem.read(GuestAddr(DATA), &mut b).unwrap();
    assert_eq!(b, [40, 0, 120, 0, 7, 0, 9, 0]);
    assert_eq!(f.ret(16, &[1, 0x5401, DATA]), 0);
}
