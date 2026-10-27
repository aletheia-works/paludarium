use super::*;
use paludarium_host::{ClockId, WaitOutcome, WaitToken};
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::{Errno, GuestAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
const DATA: u64 = 0x600000;
#[test]
fn et_unread_write_during_host_wait() {
    for socket in [false, true] {
        let mut f = Fixture::new();
        let (fd, writer) = if socket {
            let [a, b] =
                crate::sockets::SocketPairEnd::pair(0x801, Arc::clone(&f.kernel.files.readiness))
                    .unwrap();
            let fd = f.kernel.files.install(b, false, 1024).unwrap();
            (u64::from(fd), a as Arc<dyn paludarium_host::FileHandle>)
        } else {
            let fd = f.event(0);
            (fd, f.kernel.files.descriptor(fd).unwrap().file)
        };
        let bytes = if socket {
            vec![1]
        } else {
            1u64.to_le_bytes().to_vec()
        };
        writer.write(&bytes).unwrap();
        let e = f.epoll();
        f.add(e, fd, 1 | (1 << 31), 99);
        assert_eq!(f.poll(e, 0), 1);
        assert_eq!(f.poll(e, 0), 0);
        *f.host.action.lock().unwrap() = Some(Box::new(move || {
            writer.write(&bytes).unwrap();
        }));
        assert_eq!(f.poll(e, 20), 1);
        assert_eq!(f.host.now.load(Ordering::SeqCst), 0);
        assert_eq!(f.poll(e, 0), 0);
    }
}
#[test]
fn pwait_handler_uses_temporary_mask_and_returns_original() {
    for nodefer in [false, true] {
        let mut f = Fixture::new();
        let e = f.epoll();
        let original = (1 << 13) | (1 << 9);
        let action_mask = 1 << 11;
        f.thread.state.signal_mask = original;
        f.thread.cpu.gpr[reg::RSP] = DATA + 0x4000;
        f.thread.state.signal_actions.insert(
            14,
            SignalAction {
                handler: DATA + 0x1000,
                restorer: DATA + 0x1010,
                flags: 0x4000000 | if nodefer { signals::SA_NODEFER } else { 0 },
                mask: action_mask,
            },
        );
        f.kernel.group.set_timer(signals::RealTimer {
            deadline: Some(5_000_000),
            interval: 0,
        });
        f.mem.write_u64(GuestAddr(DATA + 128), 0).unwrap();
        assert_eq!(
            f.ret(281, [e, DATA + 64, 1, 20, DATA + 128, 8]),
            Errno(4).to_syscall_return()
        );
        assert_eq!(f.thread.cpu.rip, GuestAddr(DATA + 0x1000));
        assert_eq!(f.thread.state.frames.len(), 1);
        assert_eq!(f.thread.state.wait_restore_mask, None);
        assert_eq!(
            f.thread.state.signal_mask,
            action_mask | if nodefer { 0 } else { 1 << 13 }
        );
        let frame = f.thread.cpu.gpr[reg::RSP];
        assert_eq!(f.mem.read_u64(GuestAddr(frame + 304)).unwrap(), original);
        f.thread.cpu.gpr[reg::RSP] += 8;
        f.ret(15, [0; 6]);
        assert_eq!(f.thread.state.signal_mask, original);
        assert!(f.thread.state.frames.is_empty());
        assert!(f.thread.state.pending.is_empty());
    }
}
#[test]
fn sigsuspend_and_pause_wait_for_a_handler() {
    for suspend in [true, false] {
        let mut f = Fixture::new();
        // SIGALRM is blocked; rt_sigsuspend's mask (0) lets it in, pause's does
        // not change the mask, so pause runs with it unblocked here.
        let original = if suspend {
            (1 << 13) | (1 << 9)
        } else {
            1 << 9
        };
        f.thread.state.signal_mask = original;
        f.thread.cpu.gpr[reg::RSP] = DATA + 0x4000;
        f.thread.state.signal_actions.insert(
            14,
            SignalAction {
                handler: DATA + 0x1000,
                restorer: DATA + 0x1010,
                flags: 0x4000000,
                mask: 1 << 11,
            },
        );
        f.kernel.group.set_timer(signals::RealTimer {
            deadline: Some(5_000_000),
            interval: 0,
        });
        f.mem.write_u64(GuestAddr(DATA + 128), 0).unwrap();
        let result = if suspend {
            f.ret(130, [DATA + 128, 8, 0, 0, 0, 0])
        } else {
            f.ret(34, [0; 6])
        };
        assert_eq!(result, Errno(4).to_syscall_return());
        assert_eq!(f.thread.cpu.rip, GuestAddr(DATA + 0x1000));
        assert_eq!(f.thread.state.wait_restore_mask, None);
        // The handler runs with the suspend mask (or the mask), its sa_mask
        // and the signal itself; sigreturn brings the original mask back.
        let during = if suspend { 0 } else { original };
        assert_eq!(f.thread.state.signal_mask, during | (1 << 11) | (1 << 13));
        let frame = f.thread.cpu.gpr[reg::RSP];
        assert_eq!(f.mem.read_u64(GuestAddr(frame + 304)).unwrap(), original);
        f.thread.cpu.gpr[reg::RSP] += 8;
        f.ret(15, [0; 6]);
        assert_eq!(f.thread.state.signal_mask, original);
    }
}

#[test]
fn sigsuspend_stopped_restores_the_mask_and_restarts() {
    let mut f = Fixture::new();
    let original = (1 << 13) | (1 << 9);
    f.thread.state.signal_mask = original;
    f.mem.write_u64(GuestAddr(DATA + 128), 1 << 3).unwrap();
    f.kernel.queue_signal(&mut f.thread, 19).unwrap();
    f.thread.cpu.rip = GuestAddr(0x40_1002);
    // Stopped inside rt_sigsuspend: the original mask is back, and the call
    // is rewound to run again with its own mask after the continue.
    f.thread.cpu.gpr[reg::RAX] = 130;
    f.thread.cpu.gpr[reg::RDI] = DATA + 128;
    f.thread.cpu.gpr[reg::RSI] = 8;
    let next = f.kernel.handle(
        &mut f.thread,
        &f.mem,
        ExitReason::Syscall {
            rip: GuestAddr(0x40_1002),
        },
    );
    assert_eq!(next, Next::Stopped);
    assert_eq!(f.thread.cpu.gpr[reg::RAX], 130);
    assert_eq!(f.thread.cpu.rip, GuestAddr(0x40_1000));
    assert!(f.thread.state.stopped);
    assert_eq!(f.thread.state.signal_mask, original);
    assert_eq!(f.thread.state.wait_restore_mask, None);
}

#[test]
fn sigsuspend_argument_errors() {
    let mut f = Fixture::new();
    let original = 1 << 9;
    f.thread.state.signal_mask = original;
    assert_eq!(
        f.ret(130, [DATA, 7, 0, 0, 0, 0]),
        Errno::EINVAL.to_syscall_return()
    );
    assert_eq!(
        f.ret(130, [0x10, 8, 0, 0, 0, 0]),
        Errno::EFAULT.to_syscall_return()
    );
    assert_eq!(f.thread.state.signal_mask, original);
}

#[test]
fn pwait_mask_restores_without_handler_for_masked_ignored_metadata() {
    for mode in 0..3 {
        let mut f = Fixture::new();
        let e = f.epoll();
        let original = 1 << 13;
        f.thread.state.signal_mask = original;
        f.thread.state.signal_actions.insert(
            14,
            SignalAction {
                handler: if mode == 1 { 1 } else { DATA + 0x1000 },
                ..SignalAction::default()
            },
        );
        let inbox = Arc::new(SignalInbox::default());
        f.kernel = f.kernel.with_signal_inbox(Arc::clone(&inbox));
        *f.host.action.lock().unwrap() = Some(Box::new(move || {
            if mode == 2 {
                inbox.timer_changed();
            } else {
                inbox.send(14).unwrap();
            }
        }));
        f.mem
            .write_u64(GuestAddr(DATA + 128), if mode == 0 { original } else { 0 })
            .unwrap();
        assert_eq!(f.ret(281, [e, DATA + 64, 1, 20, DATA + 128, 8]), 0);
        assert_eq!(f.thread.state.signal_mask, original);
        assert_eq!(f.thread.state.wait_restore_mask, None);
        assert!(f.thread.state.frames.is_empty());
    }
}
#[test]
fn tokio_musl_clone_accepts_ignored_detached_bit() {
    let mut f = Fixture::new();
    let flags = 0x100
        | 0x200
        | 0x400
        | 0x800
        | 0x10000
        | 0x40000
        | 0x80000
        | 0x100000
        | 0x200000
        | 0x400000;
    let tid = f.ret(
        56,
        [flags, DATA + 0x2000, DATA + 32, DATA + 40, DATA + 64, 0],
    );
    assert!((2..i32::MAX as u64).contains(&tid));
    assert_eq!(f.mem.read_u64(GuestAddr(DATA + 32)).unwrap(), tid);
    let (_, child) = f.kernel.pending_child.take().unwrap();
    assert_eq!(child.cpu.fs_base, DATA + 64);
    assert_eq!(child.state.clear_child_tid, DATA + 40);
}
#[test]
fn blocking_socket_write_retries_after_host_entry_and_metadata() {
    use paludarium_host::FileHandle;
    for metadata in [false, true] {
        let mut f = Fixture::new();
        let inbox = Arc::new(SignalInbox::default());
        f.kernel = f.kernel.with_signal_inbox(Arc::clone(&inbox));
        let [a, b] =
            crate::sockets::SocketPairEnd::pair(1, Arc::clone(&f.kernel.files.readiness)).unwrap();
        a.write(&vec![0; crate::sockets::SEND_WINDOW]).unwrap();
        let fd = f.kernel.files.install(a, false, 1024).unwrap();
        f.kernel.files.install(b.clone(), false, 1024).unwrap();
        let entered = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&entered);
        *f.host.action.lock().unwrap() = Some(Box::new(move || {
            observed.store(true, Ordering::SeqCst);
            if metadata {
                inbox.timer_changed();
            }
            assert_eq!(b.read(&mut [0; 128]), Ok(128));
        }));
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let result = f.ret(1, [u64::from(fd), DATA, 128, 0, 0, 0]);
            tx.send(result).unwrap();
        });
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(3)).unwrap(),
            128
        );
        assert!(entered.load(Ordering::SeqCst));
        worker.join().unwrap();
    }
}
#[test]
fn tokio_getrandom_checked_host_boundary() {
    let mut f = Fixture::new();
    assert_eq!(f.ret(318, [DATA, 16, 4, 0, 0, 0]), 16);
    let mut bytes = [1; 16];
    f.mem.read(GuestAddr(DATA), &mut bytes).unwrap();
    assert_eq!(bytes, [0; 16]);
    assert_eq!(
        f.ret(318, [1, 16, 4, 0, 0, 0]),
        Errno::EFAULT.to_syscall_return()
    );
}
type Action = Box<dyn FnOnce() + Send>;
#[derive(Default)]
struct TestHost {
    now: AtomicU64,
    action: Mutex<Option<Action>>,
}
impl Host for TestHost {
    fn read_stdin(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Ok(0)
    }
    fn write_stdout(&self, b: &[u8]) -> Result<usize, Errno> {
        Ok(b.len())
    }
    fn write_stderr(&self, b: &[u8]) -> Result<usize, Errno> {
        Ok(b.len())
    }
    fn random_bytes(&self, b: &mut [u8]) -> Result<(), paludarium_types::Error> {
        b.fill(0);
        Ok(())
    }
    fn clock(&self, _: ClockId) -> Result<u64, Errno> {
        Ok(self.now.load(Ordering::SeqCst))
    }
    fn wait_on(
        &self,
        token: &WaitToken,
        expected: u32,
        deadline: Option<(ClockId, u64)>,
        cancel: &AtomicBool,
    ) -> Result<WaitOutcome, Errno> {
        let action = self
            .action
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(action) = action {
            action();
        }
        if token.value() != expected {
            return Ok(WaitOutcome::Complete);
        }
        if cancel.load(Ordering::SeqCst) {
            return Ok(WaitOutcome::Interrupted);
        }
        self.now
            .store(deadline.expect("bounded kernel wait").1, Ordering::SeqCst);
        Ok(WaitOutcome::Complete)
    }
}
struct Fixture {
    host: Arc<TestHost>,
    kernel: Kernel,
    thread: Thread,
    mem: AddressSpace,
}
impl Fixture {
    fn new() -> Self {
        let host = Arc::new(TestHost::default());
        let mut mem = AddressSpace::new();
        mem.map(
            Some(GuestAddr(DATA)),
            0x4000,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        Self {
            host: Arc::clone(&host),
            kernel: Kernel::new(host),
            thread: Thread::new(1, Default::default()),
            mem,
        }
    }
    fn ret(&mut self, n: u64, args: [u64; 6]) -> u64 {
        self.thread.cpu.gpr[reg::RAX] = n;
        for (r, v) in [reg::RDI, reg::RSI, reg::RDX, reg::R10, reg::R8, reg::R9]
            .into_iter()
            .zip(args)
        {
            self.thread.cpu.gpr[r] = v;
        }
        let next = self.kernel.handle(
            &mut self.thread,
            &self.mem,
            ExitReason::Syscall {
                rip: GuestAddr(DATA + 0x3000),
            },
        );
        assert_eq!(next, Next::Resume);
        self.thread.cpu.gpr[reg::RAX]
    }
    fn event(&mut self, value: u32) -> u64 {
        self.ret(290, [value as u64, 0x800, 0, 0, 0, 0])
    }
    fn epoll(&mut self) -> u64 {
        self.ret(291, [0; 6])
    }
    fn add(&mut self, e: u64, fd: u64, mask: u32, data: u64) -> u64 {
        let mut bytes = mask.to_le_bytes().to_vec();
        bytes.extend_from_slice(&data.to_le_bytes());
        self.mem.write(GuestAddr(DATA), &bytes).unwrap();
        self.ret(233, [e, 1, fd, DATA, 0, 0])
    }
    fn put(&mut self, fd: u64, value: u64) -> u64 {
        self.mem.write_u64(GuestAddr(DATA + 32), value).unwrap();
        self.ret(1, [fd, DATA + 32, 8, 0, 0, 0])
    }
    fn poll(&mut self, e: u64, timeout: i32) -> u64 {
        self.ret(232, [e, DATA + 64, 4, timeout as u64, 0, 0])
    }
    fn data(&self) -> u64 {
        self.mem.read_u64(GuestAddr(DATA + 68)).unwrap()
    }
}

#[test]
fn ofd_dup_keeps_interest() {
    let mut f = Fixture::new();
    let fd = f.event(0);
    let dup = f.ret(32, [fd, 0, 0, 0, 0, 0]);
    let e = f.epoll();
    assert_eq!(f.add(e, fd, 1, 11), 0);
    f.ret(3, [fd, 0, 0, 0, 0, 0]);
    f.put(dup, 1);
    assert_eq!(f.poll(e, 0), 1);
    assert_eq!(f.data(), 11);
}
#[test]
fn ofd_last_close_removes_interest() {
    let mut f = Fixture::new();
    let fd = f.event(1);
    let e = f.epoll();
    f.add(e, fd, 1, 11);
    f.ret(3, [fd, 0, 0, 0, 0, 0]);
    assert_eq!(f.poll(e, 0), 0);
}
#[test]
fn ofd_reuse_is_new_description() {
    let mut f = Fixture::new();
    let fd = f.event(1);
    let e = f.epoll();
    f.add(e, fd, 1, 11);
    f.ret(3, [fd, 0, 0, 0, 0, 0]);
    let other = f.event(1);
    assert_eq!(other, fd);
    assert_eq!(f.poll(e, 0), 0);
    assert_eq!(f.add(e, other, 1, 22), 0);
    assert_eq!(f.poll(e, 0), 1);
    assert_eq!(f.data(), 22);
}
#[test]
fn ofd_duplicates_register_separately() {
    let mut f = Fixture::new();
    let fd = f.event(1);
    let dup = f.ret(32, [fd, 0, 0, 0, 0, 0]);
    let e = f.epoll();
    f.add(e, fd, 1, 11);
    f.add(e, dup, 1, 22);
    assert_eq!(f.poll(e, 0), 2);
}
#[test]
fn ofd_status_flags_are_shared() {
    let mut f = Fixture::new();
    let fd = f.event(0);
    let dup = f.ret(32, [fd, 0, 0, 0, 0, 0]);
    f.ret(72, [dup, 4, 0, 0, 0, 0]);
    assert_eq!(f.ret(72, [fd, 3, 0, 0, 0, 0]), 2);
}
#[test]
fn ofd_cloexec_is_per_descriptor() {
    let mut f = Fixture::new();
    let fd = f.ret(290, [0, 0x80800, 0, 0, 0, 0]);
    let dup = f.ret(32, [fd, 0, 0, 0, 0, 0]);
    assert_eq!(f.ret(72, [fd, 1, 0, 0, 0, 0]), 1);
    assert_eq!(f.ret(72, [dup, 1, 0, 0, 0, 0]), 0);
}
#[test]
fn ofd_clone_shared_table() {
    let mut f = Fixture::new();
    let fd = f.event(1);
    let child = f.kernel.files.for_clone(true, false);
    assert!(Arc::ptr_eq(
        &f.kernel.files.descriptor(fd).unwrap().file,
        &child.descriptor(fd).unwrap().file
    ));
    f.ret(3, [fd, 0, 0, 0, 0, 0]);
    assert!(child.descriptor(fd).is_err());
}
#[test]
fn ofd_clone_copied_table_keeps_description() {
    let mut f = Fixture::new();
    let fd = f.event(1);
    let child = f.kernel.files.for_clone(false, false);
    f.ret(3, [fd, 0, 0, 0, 0, 0]);
    let mut bytes = [0; 8];
    assert_eq!(child.descriptor(fd).unwrap().file.read(&mut bytes), Ok(8));
    assert_eq!(u64::from_le_bytes(bytes), 1);
}

#[test]
fn integration_nested_epoll() {
    let mut f = Fixture::new();
    let fd = f.event(1);
    let child = f.epoll();
    let parent = f.epoll();
    f.add(child, fd, 1, 11);
    f.add(parent, child, 1, 32);
    assert_eq!(f.poll(parent, 0), 1);
    assert_eq!(f.data(), 32);
}
#[test]
fn integration_guest_pointer_errors() {
    let mut f = Fixture::new();
    let fd = f.event(1);
    assert_eq!(
        f.ret(0, [fd, 1, 8, 0, 0, 0]),
        Errno::EFAULT.to_syscall_return()
    );
    assert_eq!(
        f.ret(1, [fd, 1, 8, 0, 0, 0]),
        Errno::EFAULT.to_syscall_return()
    );
    assert_eq!(
        f.ret(53, [1, 1, 0, 1, 0, 0]),
        Errno::EFAULT.to_syscall_return()
    );
}
#[test]
fn integration_epoll_timeout() {
    let mut f = Fixture::new();
    let e = f.epoll();
    assert_eq!(f.poll(e, 20), 0);
    assert_eq!(f.host.now.load(Ordering::SeqCst), 20_000_000);
}
#[test]
fn integration_timer_metadata_before_wait() {
    let mut f = Fixture::new();
    let inbox = Arc::new(SignalInbox::default());
    f.kernel = f.kernel.with_signal_inbox(Arc::clone(&inbox));
    let e = f.epoll();
    inbox.timer_changed();
    assert_eq!(f.poll(e, 20), 0);
    assert_eq!(f.host.now.load(Ordering::SeqCst), 20_000_000);
}
#[test]
fn integration_metadata_during_wait() {
    let mut f = Fixture::new();
    let inbox = Arc::new(SignalInbox::default());
    f.kernel = f.kernel.with_signal_inbox(Arc::clone(&inbox));
    let e = f.epoll();
    *f.host.action.lock().unwrap() = Some(Box::new(move || inbox.timer_changed()));
    assert_eq!(f.poll(e, 20), 0);
    assert_eq!(f.host.now.load(Ordering::SeqCst), 20_000_000);
}
#[test]
fn integration_ready_before_host_registration() {
    let mut f = Fixture::new();
    let fd = f.event(0);
    let e = f.epoll();
    f.add(e, fd, 1, 12);
    let file = f.kernel.files.descriptor(fd).unwrap().file;
    *f.host.action.lock().unwrap() = Some(Box::new(move || {
        file.write(&1u64.to_le_bytes()).unwrap();
    }));
    assert_eq!(f.poll(e, 20), 1);
    assert_eq!(f.host.now.load(Ordering::SeqCst), 0);
    assert_eq!(f.data(), 12);
}
#[test]
fn integration_timer_signal_interrupts_wait() {
    let mut f = Fixture::new();
    let e = f.epoll();
    f.thread.cpu.gpr[reg::RSP] = DATA + 0x4000;
    f.thread.state.signal_actions.insert(
        14,
        SignalAction {
            handler: DATA + 0x1000,
            flags: 0x4000000,
            restorer: DATA + 0x1010,
            mask: 0,
        },
    );
    f.kernel.group.set_timer(signals::RealTimer {
        deadline: Some(5_000_000),
        interval: 0,
    });
    assert_eq!(f.poll(e, 20), Errno(4).to_syscall_return());
    assert_eq!(f.host.now.load(Ordering::SeqCst), 5_000_000);
}
#[test]
fn integration_policy_and_socket_transfer() {
    let mut f = Fixture::new();
    for domain in [2, 10] {
        assert_eq!(
            f.ret(41, [domain, 1, 0, 0, 0, 0]),
            Errno(97).to_syscall_return()
        );
    }
    assert_eq!(f.ret(53, [1, 0x80801, 0, DATA, 0, 0]), 0);
    let mut bytes = [0; 8];
    f.mem.read(GuestAddr(DATA), &mut bytes).unwrap();
    let a = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64;
    let b = u32::from_le_bytes(bytes[4..].try_into().unwrap()) as u64;
    f.mem.write(GuestAddr(DATA + 32), b"hi").unwrap();
    assert_eq!(f.ret(44, [a, DATA + 32, 2, 0x4000, 0, 0]), 2);
    assert_eq!(f.ret(45, [b, DATA + 64, 2, 0, 0, 0]), 2);
    let mut received = [0; 2];
    f.mem.read(GuestAddr(DATA + 64), &mut received).unwrap();
    assert_eq!(&received, b"hi");
}
/// Writes a `msghdr` at `at`: name, iovecs `(base, len)` at `at + 0x40`,
/// and control.
fn message(f: &Fixture, at: u64, name: (u64, u32), iov: &[(u64, u64)], control: (u64, u64)) {
    let mut header = [0; 56];
    header[..8].copy_from_slice(&name.0.to_le_bytes());
    header[8..12].copy_from_slice(&name.1.to_le_bytes());
    header[16..24].copy_from_slice(&(at + 0x40).to_le_bytes());
    header[24..32].copy_from_slice(&(iov.len() as u64).to_le_bytes());
    header[32..40].copy_from_slice(&control.0.to_le_bytes());
    header[40..48].copy_from_slice(&control.1.to_le_bytes());
    f.mem.write(GuestAddr(at), &header).unwrap();
    for (i, (base, len)) in iov.iter().enumerate() {
        let entry = at + 0x40 + 16 * i as u64;
        f.mem.write(GuestAddr(entry), &base.to_le_bytes()).unwrap();
        f.mem
            .write(GuestAddr(entry + 8), &len.to_le_bytes())
            .unwrap();
    }
}
/// Writes one control message at `at` and returns its length.
fn control(f: &Fixture, at: u64, level: u32, kind: u32, fds: &[u32]) -> u64 {
    let len = 16 + 4 * fds.len() as u64;
    f.mem.write(GuestAddr(at), &len.to_le_bytes()).unwrap();
    f.mem
        .write(GuestAddr(at + 8), &level.to_le_bytes())
        .unwrap();
    f.mem
        .write(GuestAddr(at + 12), &kind.to_le_bytes())
        .unwrap();
    for (i, fd) in fds.iter().enumerate() {
        f.mem
            .write(GuestAddr(at + 16 + 4 * i as u64), &fd.to_le_bytes())
            .unwrap();
    }
    len
}
fn read_u32(f: &Fixture, at: u64) -> u32 {
    let mut bytes = [0; 4];
    f.mem.read(GuestAddr(at), &mut bytes).unwrap();
    u32::from_le_bytes(bytes)
}
fn read_u64(f: &Fixture, at: u64) -> u64 {
    f.mem.read_u64(GuestAddr(at)).unwrap()
}
/// A pair of nonblocking descriptors made by `number` (socketpair or pipe2).
fn pair(f: &mut Fixture, number: u64, args: [u64; 6]) -> (u64, u64) {
    assert_eq!(f.ret(number, args), 0);
    let at = if number == 53 { args[3] } else { args[0] };
    (u64::from(read_u32(f, at)), u64::from(read_u32(f, at + 4)))
}
const SEND: u64 = DATA + 0x100;
const RECEIVE: u64 = DATA + 0x200;
const BYTES: u64 = DATA + 0x400;
const CONTROL: u64 = DATA + 0x500;
const NAME: u64 = DATA + 0x600;
const IN: u64 = DATA + 0x800;
const RECEIVED: u64 = DATA + 0x900;
/// recvmsg into 64 bytes at IN with `room` control bytes at RECEIVED (none
/// when 0), and a name buffer.
fn receive(f: &mut Fixture, fd: u64, len: u64, room: u64, flags: u64) -> u64 {
    let control = if room == 0 { 0 } else { RECEIVED };
    message(f, RECEIVE, (NAME, 128), &[(IN, len)], (control, room));
    f.ret(47, [fd, RECEIVE, flags, 0, 0, 0])
}
#[test]
fn scm_rights_passes_descriptors_over_a_stream() {
    let mut f = Fixture::new();
    let (a, b) = pair(&mut f, 53, [1, 0x801, 0, DATA, 0, 0]);
    let (r, w) = pair(&mut f, 293, [DATA + 8, 0x800, 0, 0, 0, 0]);
    f.mem.write(GuestAddr(BYTES), b"abcdef").unwrap();
    assert_eq!(f.ret(1, [a, BYTES, 2, 0, 0, 0]), 2);
    let len = control(&f, CONTROL, 1, 1, &[r as u32, w as u32]);
    message(&f, SEND, (0, 0), &[(BYTES + 2, 2)], (CONTROL, len));
    assert_eq!(f.ret(46, [a, SEND, 0, 0, 0, 0]), 2);
    assert_eq!(f.ret(1, [a, BYTES + 4, 2, 0, 0, 0]), 2);
    // The read goes on into the write that passed them, and ends there.
    assert_eq!(receive(&mut f, b, 64, 64, 0x4000_0000), 4);
    let mut bytes = [0; 4];
    f.mem.read(GuestAddr(IN), &mut bytes).unwrap();
    assert_eq!(&bytes, b"abcd");
    assert_eq!(read_u32(&f, RECEIVE + 8), 0);
    assert_eq!(read_u64(&f, RECEIVE + 40), 24);
    assert_eq!(read_u32(&f, RECEIVE + 48), 0x4000_0000);
    assert_eq!(read_u64(&f, RECEIVED), 24);
    assert_eq!(read_u32(&f, RECEIVED + 8), 1);
    assert_eq!(read_u32(&f, RECEIVED + 12), 1);
    let (x, y) = (
        u64::from(read_u32(&f, RECEIVED + 16)),
        u64::from(read_u32(&f, RECEIVED + 20)),
    );
    assert_eq!((x, y), (w + 1, w + 2));
    assert_eq!(f.ret(72, [x, 1, 0, 0, 0, 0]), 1);
    // The received write end is the same pipe.
    assert_eq!(f.ret(1, [y, BYTES, 1, 0, 0, 0]), 1);
    assert_eq!(f.ret(0, [r, IN, 8, 0, 0, 0]), 1);
    assert_eq!(receive(&mut f, b, 64, 64, 0), 2);
    assert_eq!(read_u64(&f, RECEIVE + 40), 0);
    assert_eq!(read_u32(&f, RECEIVE + 48), 0);
    // A control buffer with room for one: the other is closed, MSG_CTRUNC.
    assert_eq!(f.ret(46, [a, SEND, 0, 0, 0, 0]), 2);
    assert_eq!(receive(&mut f, b, 1, 20, 0), 1);
    assert_eq!(read_u64(&f, RECEIVE + 40), 20);
    assert_eq!(read_u32(&f, RECEIVE + 48), 8);
    assert_eq!(read_u64(&f, RECEIVED), 20);
    assert_eq!(u64::from(read_u32(&f, RECEIVED + 16)), y + 1);
    // The rest of that write comes without them.
    assert_eq!(receive(&mut f, b, 64, 64, 0), 1);
    assert_eq!(read_u64(&f, RECEIVE + 40), 0);
    // No control buffer: both are closed.
    assert_eq!(f.ret(46, [a, SEND, 0, 0, 0, 0]), 2);
    assert_eq!(receive(&mut f, b, 64, 0, 0), 2);
    assert_eq!(read_u32(&f, RECEIVE + 48), 8);
    // A stream write of no bytes passes nothing; an empty read still takes them.
    message(&f, SEND, (0, 0), &[(BYTES, 0)], (CONTROL, len));
    assert_eq!(f.ret(46, [a, SEND, 0, 0, 0, 0]), 0);
    message(&f, SEND, (0, 0), &[(BYTES, 1)], (CONTROL, len));
    assert_eq!(f.ret(46, [a, SEND, 0, 0, 0, 0]), 1);
    assert_eq!(receive(&mut f, b, 0, 64, 0), 0);
    assert_eq!(read_u64(&f, RECEIVE + 40), 24);
    assert_eq!(receive(&mut f, b, 64, 64, 0), 1);
    assert_eq!(read_u64(&f, RECEIVE + 40), 0);
    assert_eq!(
        receive(&mut f, b, 64, 64, 0x40),
        Errno::EAGAIN.to_syscall_return()
    );
}
#[test]
fn scm_rights_checks_like_linux() {
    let mut f = Fixture::new();
    let (a, _b) = pair(&mut f, 53, [1, 0x801, 0, DATA, 0, 0]);
    let (r, w) = pair(&mut f, 293, [DATA + 8, 0x800, 0, 0, 0, 0]);
    let send = |f: &mut Fixture, name: (u64, u32), control: (u64, u64), flags: u64| {
        message(f, SEND, name, &[(BYTES, 1)], control);
        f.ret(46, [a, SEND, flags, 0, 0, 0])
    };
    let fail = |e: i32| Errno(e).to_syscall_return();
    let len = control(&f, CONTROL, 1, 1, &[99]);
    assert_eq!(send(&mut f, (0, 0), (CONTROL, len), 0), fail(9));
    let len = control(&f, CONTROL, 1, 2, &[r as u32, 0, 0]);
    assert_eq!(send(&mut f, (0, 0), (CONTROL, len), 0), fail(22));
    // Another level is skipped.
    let len = control(&f, CONTROL, 6, 2, &[]);
    assert_eq!(send(&mut f, (0, 0), (CONTROL, len), 0), 1);
    // A header longer than the buffer, or shorter than itself.
    assert_eq!(send(&mut f, (0, 0), (CONTROL, 12), 0), 1);
    f.mem
        .write(GuestAddr(CONTROL), &40u64.to_le_bytes())
        .unwrap();
    assert_eq!(send(&mut f, (0, 0), (CONTROL, 32), 0), fail(22));
    f.mem
        .write(GuestAddr(CONTROL), &8u64.to_le_bytes())
        .unwrap();
    assert_eq!(send(&mut f, (0, 0), (CONTROL, 32), 0), fail(22));
    assert_eq!(send(&mut f, (0, 0), (0, 1 << 31), 0), fail(105));
    assert_eq!(send(&mut f, (0, 0), (0, 0), 1), fail(95));
    assert_eq!(send(&mut f, (NAME, 4), (0, 0), 0), fail(106));
    assert_eq!(send(&mut f, (NAME, u32::MAX), (0, 0), 0), fail(22));
    // A name of length 0 is no name.
    assert_eq!(send(&mut f, (NAME, 0), (0, 0), 0), 1);
    message(&f, SEND, (0, 0), &[(BYTES, 1)], (0, 0));
    f.mem
        .write(GuestAddr(SEND + 24), &1025u64.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(46, [a, SEND, 0, 0, 0, 0]), fail(90));
    assert_eq!(f.ret(46, [w, SEND, 0, 0, 0, 0]), fail(88));
    assert_eq!(f.ret(47, [r, SEND, 0, 0, 0, 0]), fail(88));
    assert_eq!(f.ret(46, [99, SEND, 0, 0, 0, 0]), fail(9));
}
#[test]
fn scm_rights_on_messages_and_queued_descriptors_close_with_the_socket() {
    let mut f = Fixture::new();
    let (a, b) = pair(&mut f, 53, [1, 0x802, 0, DATA, 0, 0]);
    let (r, w) = pair(&mut f, 293, [DATA + 8, 0x800, 0, 0, 0, 0]);
    f.mem.write(GuestAddr(BYTES), b"hello").unwrap();
    let len = control(&f, CONTROL, 1, 1, &[w as u32]);
    message(&f, SEND, (0, 0), &[(BYTES, 5)], (CONTROL, len));
    assert_eq!(f.ret(46, [a, SEND, 0, 0, 0, 0]), 5);
    assert_eq!(f.ret(46, [a, SEND, 0, 0, 0, 0]), 5);
    // A short buffer truncates the message, which keeps its descriptor.
    assert_eq!(receive(&mut f, b, 2, 64, 0), 2);
    assert_eq!(read_u32(&f, RECEIVE + 48), 0x20);
    assert_eq!(read_u64(&f, RECEIVE + 40), 24);
    let copy = u64::from(read_u32(&f, RECEIVED + 16));
    assert_eq!(f.ret(3, [copy, 0, 0, 0, 0, 0]), 0);
    // recvmsg with no buffer discards a whole message.
    assert_eq!(receive(&mut f, b, 0, 64, 0), 0);
    assert_eq!(read_u32(&f, RECEIVE + 48), 0x20);
    let copy = u64::from(read_u32(&f, RECEIVED + 16));
    assert_eq!(f.ret(3, [copy, 0, 0, 0, 0, 0]), 0);
    assert_eq!(
        receive(&mut f, b, 64, 64, 0),
        Errno::EAGAIN.to_syscall_return()
    );
    // Addresses: not AF_UNIX, abstract, a missing path, an existing one.
    let fail = |e: i32| Errno(e).to_syscall_return();
    for (address, error) in [
        (&b"\x02\x00abc"[..], 22),
        (b"\x01\x00\x00abc", 111),
        (b"\x01\x00/missing\x00", 2),
        (b"\x01\x00/tmp", 111),
    ] {
        f.mem.write(GuestAddr(NAME), address).unwrap();
        message(
            &f,
            SEND,
            (NAME, address.len() as u32),
            &[(BYTES, 1)],
            (0, 0),
        );
        assert_eq!(f.ret(46, [a, SEND, 0, 0, 0, 0]), fail(error));
    }
    // A descriptor still queued closes with the receiving socket.
    let len = control(&f, CONTROL, 1, 1, &[w as u32]);
    message(&f, SEND, (0, 0), &[(BYTES, 1)], (CONTROL, len));
    assert_eq!(f.ret(46, [a, SEND, 0, 0, 0, 0]), 1);
    assert_eq!(f.ret(3, [w, 0, 0, 0, 0, 0]), 0);
    assert_eq!(
        f.ret(0, [r, IN, 8, 0, 0, 0]),
        Errno::EAGAIN.to_syscall_return()
    );
    assert_eq!(f.ret(3, [b, 0, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(0, [r, IN, 8, 0, 0, 0]), 0);
}
#[test]
fn recvfrom_peeks_waits_for_all_and_gives_whole_message_lengths() {
    let mut f = Fixture::new();
    let fail = |e: i32| Errno(e).to_syscall_return();
    let (a, b) = pair(&mut f, 53, [1, 0x801, 0, DATA, 0, 0]);
    let (c, d) = pair(&mut f, 53, [1, 1, 0, DATA, 0, 0]);
    let (p, q) = pair(&mut f, 53, [1, 0x802, 0, DATA, 0, 0]);
    let bytes = |f: &Fixture, len: usize| {
        let mut buf = vec![0; len];
        f.mem.read(GuestAddr(IN), &mut buf).unwrap();
        buf
    };
    f.mem.write(GuestAddr(BYTES), b"abcdef").unwrap();
    // MSG_PEEK leaves a stream's data; a read then takes it.
    assert_eq!(f.ret(44, [a, BYTES, 4, 0, 0, 0]), 4);
    assert_eq!(f.ret(45, [b, IN, 2, 2, 0, 0]), 2);
    assert_eq!(bytes(&f, 2), b"ab");
    assert_eq!(f.ret(45, [b, IN, 8, 0, 0, 0]), 4);
    assert_eq!(bytes(&f, 4), b"abcd");
    // MSG_WAITALL does not wait on a nonblocking socket, and ends with the
    // stream on a blocking one.
    assert_eq!(f.ret(44, [a, BYTES, 2, 0x80, 0, 0]), 2);
    assert_eq!(f.ret(45, [b, IN, 8, 0x100, 0, 0]), 2);
    assert_eq!(f.ret(44, [c, BYTES, 2, 0, 0, 0]), 2);
    assert_eq!(f.ret(48, [c, 1, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(45, [d, IN, 8, 0x100, 0, 0]), 2);
    // MSG_TRUNC gives a message's whole length, peeked or taken.
    assert_eq!(f.ret(44, [p, BYTES, 6, 0x8080, 0, 0]), 6);
    assert_eq!(f.ret(45, [q, IN, 2, 0x22, 0, 0]), 6);
    assert_eq!(f.ret(45, [q, IN, 2, 0x20, 0, 0]), 6);
    assert_eq!(bytes(&f, 2), b"ab");
    assert_eq!(f.ret(45, [q, IN, 2, 0x40, 0, 0]), fail(11));
    // A datagram socket has no out-of-band data at all.
    assert_eq!(f.ret(45, [q, IN, 2, 1, 0, 0]), fail(95));
    assert_eq!(f.ret(44, [p, BYTES, 1, 1, 0, 0]), fail(95));
    // The address is read first; a datagram socket refuses MSG_OOB before
    // it checks the address, and a stream after.
    assert_eq!(f.ret(44, [p, BYTES, 1, 1, NAME, 129]), fail(22));
    assert_eq!(f.ret(44, [p, BYTES, 1, 1, 8, 16]), fail(14));
    assert_eq!(f.ret(44, [p, BYTES, 1, 1, NAME, 16]), fail(95));
    assert_eq!(f.ret(44, [a, BYTES, 1, 1, NAME, 16]), fail(106));
}
#[test]
fn sendto_and_recvfrom_take_addresses_and_flags_like_sendmsg() {
    let mut f = Fixture::new();
    let fail = |e: i32| Errno(e).to_syscall_return();
    let (a, b) = pair(&mut f, 53, [1, 0x801, 0, DATA, 0, 0]);
    let (p, q) = pair(&mut f, 53, [1, 0x805, 0, DATA, 0, 0]);
    let (d, e) = pair(&mut f, 53, [1, 0x802, 0, DATA, 0, 0]);
    f.mem.write(GuestAddr(BYTES), b"abcd").unwrap();
    f.mem
        .write(GuestAddr(NAME), &[1, 0, b'/', b't', b'm', b'p', 0])
        .unwrap();
    // A stream takes no address, and one of no bytes is none.
    assert_eq!(f.ret(44, [a, BYTES, 1, 0, NAME, 16]), fail(106));
    assert_eq!(f.ret(44, [a, BYTES, 1, 0, NAME, 0]), 1);
    assert_eq!(f.ret(44, [a, BYTES, 1, 0, NAME, 129]), fail(22));
    assert_eq!(f.ret(44, [a, BYTES, 1, 0, NAME, u64::MAX]), fail(22));
    assert_eq!(f.ret(44, [a, BYTES, 1, 0, 8, 16]), fail(14));
    assert_eq!(f.ret(44, [a, BYTES, 1, 1, 0, 0]), fail(95));
    assert_eq!(f.ret(44, [a, BYTES + 1, 1, 0x4040, 0, 0]), 1);
    // recvfrom writes the peer's address length, 0.
    let len = NAME + 0x80;
    f.mem.write(GuestAddr(len), &77u32.to_le_bytes()).unwrap();
    assert_eq!(f.ret(45, [b, IN, 16, 0, NAME, len]), 2);
    assert_eq!(read_u32(&f, len), 0);
    assert_eq!(f.ret(45, [b, IN, 16, 0x40, 0, 0]), fail(11));
    // A stream has no out-of-band data to read.
    assert_eq!(f.ret(45, [b, IN, 16, 1, 0, 0]), fail(22));
    // A negative length or none is an error after the data is taken.
    assert_eq!(f.ret(44, [a, BYTES, 2, 0, 0, 0]), 2);
    f.mem.write(GuestAddr(len), &(-1i32).to_le_bytes()).unwrap();
    assert_eq!(f.ret(45, [b, IN, 1, 0, NAME, len]), fail(22));
    assert_eq!(read_u32(&f, len), u32::MAX);
    assert_eq!(f.ret(45, [b, IN, 1, 0, NAME, 0]), fail(14));
    assert_eq!(f.ret(45, [b, IN, 16, 0x40, 0, 0]), fail(11));
    // A packet ignores the address, and an empty buffer takes the message.
    assert_eq!(f.ret(44, [p, BYTES, 2, 0, NAME, 16]), 2);
    assert_eq!(f.ret(44, [p, BYTES + 2, 2, 0, 0, 0]), 2);
    assert_eq!(f.ret(45, [q, IN, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(45, [q, IN, 1, 0, 0, 0]), 1);
    let mut byte = [0];
    f.mem.read(GuestAddr(IN), &mut byte).unwrap();
    assert_eq!(&byte, b"c");
    assert_eq!(f.ret(45, [q, IN, 16, 0x40, 0, 0]), fail(11));
    // A datagram's address names no socket.
    assert_eq!(f.ret(44, [d, BYTES, 1, 0, NAME, 2]), fail(22));
    assert_eq!(f.ret(44, [d, BYTES, 1, 0, NAME, 7]), fail(111));
    // Descriptors that come to recvfrom close.
    let (r, w) = pair(&mut f, 293, [DATA + 8, 0x800, 0, 0, 0, 0]);
    let clen = control(&f, CONTROL, 1, 1, &[w as u32]);
    message(&f, SEND, (0, 0), &[(BYTES, 1)], (CONTROL, clen));
    assert_eq!(f.ret(46, [d, SEND, 0, 0, 0, 0]), 1);
    assert_eq!(f.ret(3, [w, 0, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(45, [e, IN, 16, 0, 0, 0]), 1);
    assert_eq!(f.ret(0, [r, IN, 1, 0, 0, 0]), 0);
    assert_eq!(f.ret(44, [r, BYTES, 1, 0, 0, 0]), fail(88));
    assert_eq!(f.ret(45, [r, IN, 1, 0, 0, 0]), fail(88));
    // A buffer past the user half is EFAULT before the descriptor and the
    // address are checked; an unmapped one only when it is copied.
    let high = 0x7fff_ffff_f000;
    assert_eq!(f.ret(44, [r, high, 1, 0, 0, 0]), fail(14));
    assert_eq!(f.ret(45, [999, high - 1, 2, 0, 0, 0]), fail(14));
    assert_eq!(f.ret(44, [a, high, 1, 0, NAME, 129]), fail(14));
    assert_eq!(f.ret(44, [a, high - 1, 1, 0, NAME, 129]), fail(22));
    assert_eq!(f.ret(44, [r, 0xffff_8000_0000_0000, 1, 0, 0, 0]), fail(14));
    // A stream's address and a datagram's form and size are checked before
    // the data is copied, and a datagram's peer is looked up after.
    assert_eq!(f.ret(44, [a, 8, 1, 0, NAME, 16]), fail(106));
    assert_eq!(f.ret(44, [d, 8, 1, 0, NAME, 2]), fail(22));
    assert_eq!(f.ret(44, [d, 8, 1 << 20, 0, NAME, 7]), fail(90));
    assert_eq!(f.ret(44, [d, 8, 1, 0, NAME, 7]), fail(14));
    message(&f, SEND, (NAME, 7), &[(8, 1)], (0, 0));
    assert_eq!(f.ret(46, [d, SEND, 0, 0, 0, 0]), fail(14));
    message(&f, SEND, (NAME, 16), &[(8, 1)], (0, 0));
    assert_eq!(f.ret(46, [a, SEND, 0, 0, 0, 0]), fail(106));
}
#[test]
fn fchmod_and_fchown_change_pipes_and_sockets() {
    let mut f = Fixture::new();
    let (r, w) = pair(&mut f, 293, [DATA + 8, 0, 0, 0, 0, 0]);
    let (a, b) = pair(&mut f, 53, [1, 1, 0, DATA, 0, 0]);
    let stat = |f: &mut Fixture, fd: u64| {
        assert_eq!(f.ret(5, [fd, DATA + 0x100, 0, 0, 0, 0]), 0);
        (
            read_u32(f, DATA + 0x100 + 24),
            read_u32(f, DATA + 0x100 + 28),
            read_u32(f, DATA + 0x100 + 32),
        )
    };
    assert_eq!(stat(&mut f, w), (0o010_600, 0, 0));
    // Both ends of a pipe are one inode.
    assert_eq!(f.ret(91, [r, 0o4640, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(93, [w, 1000, 100, 0, 0, 0]), 0);
    assert_eq!(stat(&mut f, r), (0o010_640, 1000, 100));
    assert_eq!(stat(&mut f, w), (0o010_640, 1000, 100));
    // Each end of a socket pair is its own.
    assert_eq!(f.ret(91, [a, 0o600, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(93, [a, u32::MAX as u64, 7, 0, 0, 0]), 0);
    assert_eq!(stat(&mut f, a), (0o140_600, 0, 7));
    assert_eq!(stat(&mut f, b), (0o140_777, 0, 0));
}
