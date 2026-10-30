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
    /// The connections and lookups the guest started, for a test to drive.
    streams: Mutex<Vec<Arc<paludarium_host::net::Stream>>>,
    lookups: Mutex<Vec<(String, Arc<paludarium_host::net::Lookup>)>>,
}
impl Host for TestHost {
    fn connect(
        &self,
        address: core::net::SocketAddr,
    ) -> Result<Arc<paludarium_host::net::Stream>, Errno> {
        let stream = paludarium_host::net::Stream::new(address);
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(&stream));
        Ok(stream)
    }
    fn resolve(&self, name: &str) -> Result<Arc<paludarium_host::net::Lookup>, Errno> {
        let lookup = paludarium_host::net::Lookup::new();
        self.lookups
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((name.to_owned(), Arc::clone(&lookup)));
        Ok(lookup)
    }
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
#[test]
fn fionread_and_siocoutq_count_what_waits() {
    let mut f = Fixture::new();
    let pair = |f: &mut Fixture, call: u64, args: [u64; 6]| {
        assert_eq!(f.ret(call, args), 0);
        let mut bytes = [0; 8];
        f.mem.read(GuestAddr(DATA), &mut bytes).unwrap();
        (
            u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64,
            u32::from_le_bytes(bytes[4..].try_into().unwrap()) as u64,
        )
    };
    let count = |f: &mut Fixture, fd: u64, request: u64| {
        f.mem
            .write(GuestAddr(DATA + 16), &(-7i32).to_le_bytes())
            .unwrap();
        let r = f.ret(16, [fd, request, DATA + 16, 0, 0, 0]);
        let mut bytes = [0; 4];
        f.mem.read(GuestAddr(DATA + 16), &mut bytes).unwrap();
        (r, i32::from_le_bytes(bytes))
    };
    f.mem.write(GuestAddr(DATA + 32), b"abcde").unwrap();
    // A stream counts its unread bytes; SIOCOUTQ, at the sender, the same.
    let (a, b) = pair(&mut f, 53, [1, 1, 0, DATA, 0, 0]);
    assert_eq!(f.ret(44, [a, DATA + 32, 3, 0, 0, 0]), 3);
    assert_eq!(f.ret(44, [a, DATA + 35, 2, 0, 0, 0]), 2);
    assert_eq!(count(&mut f, b, 0x541b), (0, 5));
    assert_eq!(count(&mut f, a, 0x5411), (0, 5));
    assert_eq!(count(&mut f, a, 0x541b), (0, 0));
    // A datagram socket counts its first datagram.
    let (c, d) = pair(&mut f, 53, [1, 2, 0, DATA, 0, 0]);
    assert_eq!(f.ret(44, [c, DATA + 32, 3, 0, 0, 0]), 3);
    assert_eq!(f.ret(44, [c, DATA + 35, 2, 0, 0, 0]), 2);
    assert_eq!(count(&mut f, d, 0x541b), (0, 3));
    assert_eq!(count(&mut f, c, 0x5411), (0, 5));
    // A pipe counts at either end and has no SIOCOUTQ.
    let (r, w) = pair(&mut f, 293, [DATA, 0, 0, 0, 0, 0]);
    assert_eq!(f.ret(1, [w, DATA + 32, 4, 0, 0, 0]), 4);
    assert_eq!(count(&mut f, r, 0x541b), (0, 4));
    assert_eq!(count(&mut f, w, 0x541b), (0, 4));
    assert_eq!(
        count(&mut f, r, 0x5411),
        (Errno::ENOTTY.to_syscall_return(), -7)
    );
    assert_eq!(
        f.ret(16, [r, 0x541b, 8, 0, 0, 0]),
        Errno::EFAULT.to_syscall_return()
    );
}
#[test]
fn generic_ioctls_answer_for_every_file() {
    let mut f = Fixture::new();
    let fcntl = |f: &mut Fixture, fd: u64, command: u64| f.ret(72, [fd, command, 0, 0, 0, 0]);
    let ioctl_int = |f: &mut Fixture, fd: u64, request: u64, value: i32| {
        f.mem
            .write(GuestAddr(DATA + 16), &value.to_le_bytes())
            .unwrap();
        f.ret(16, [fd, request, DATA + 16, 0, 0, 0])
    };
    assert_eq!(f.ret(293, [DATA, 0, 0, 0, 0, 0]), 0);
    let mut bytes = [0; 4];
    f.mem.read(GuestAddr(DATA), &mut bytes).unwrap();
    let r = u64::from(u32::from_le_bytes(bytes));
    // FIOCLEX and FIONCLEX set and clear FD_CLOEXEC.
    assert_eq!(f.ret(16, [r, 0x5451, 0, 0, 0, 0]), 0);
    assert_eq!(fcntl(&mut f, r, 1), 1);
    assert_eq!(f.ret(16, [r, 0x5450, 0, 0, 0, 0]), 0);
    assert_eq!(fcntl(&mut f, r, 1), 0);
    // FIOASYNC turns O_ASYNC of a pipe on and off.
    assert_eq!(ioctl_int(&mut f, r, 0x5452, 2), 0);
    assert_eq!(fcntl(&mut f, r, 3) & 0o20000, 0o20000);
    assert_eq!(ioctl_int(&mut f, r, 0x5452, 0), 0);
    assert_eq!(fcntl(&mut f, r, 3) & 0o20000, 0);
    assert_eq!(
        f.ret(16, [r, 0x5452, 8, 0, 0, 0]),
        Errno::EFAULT.to_syscall_return()
    );
    // A file without `fasync` refuses only a change.
    let event = f.ret(290, [0, 0, 0, 0, 0, 0]);
    assert_eq!(ioctl_int(&mut f, event, 0x5452, 0), 0);
    assert_eq!(
        ioctl_int(&mut f, event, 0x5452, 1),
        Errno::ENOTTY.to_syscall_return()
    );
    // FIOQSIZE gives the bytes a regular file takes, as a loff_t.
    f.mem.write(GuestAddr(DATA + 32), b"q\0abcde").unwrap();
    let memfd = f.ret(319, [DATA + 32, 0, 0, 0, 0, 0]);
    assert_eq!(f.ret(1, [memfd, DATA + 34, 5, 0, 0, 0]), 5);
    f.mem.write(GuestAddr(DATA + 16), &[0xff; 8]).unwrap();
    assert_eq!(f.ret(16, [memfd, 0x5460, DATA + 16, 0, 0, 0]), 0);
    let mut size = [0; 8];
    f.mem.read(GuestAddr(DATA + 16), &mut size).unwrap();
    assert_eq!(u64::from_le_bytes(size), 4096);
    assert_eq!(
        f.ret(16, [r, 0x5460, DATA + 16, 0, 0, 0]),
        Errno::ENOTTY.to_syscall_return()
    );
    // FIGETBSZ gives the block size stat gives, of any file, as an int.
    for fd in [r, event, memfd] {
        f.mem.write(GuestAddr(DATA + 16), &[0xff; 8]).unwrap();
        assert_eq!(f.ret(16, [fd, 0x2, DATA + 16, 0, 0, 0]), 0);
        f.mem.read(GuestAddr(DATA + 16), &mut size).unwrap();
        assert_eq!(u64::from_le_bytes(size), 0xffff_ffff_0000_1000);
    }
    assert_eq!(
        f.ret(16, [r, 0x2, 8, 0, 0, 0]),
        Errno::EFAULT.to_syscall_return()
    );
    // An O_PATH descriptor answers none.
    f.mem.write(GuestAddr(DATA + 48), b"/\0").unwrap();
    let path = f.ret(257, [-100i64 as u64, DATA + 48, 0o10000000, 0, 0, 0]);
    assert!((path as i64) >= 0, "{}", path as i64);
    assert_eq!(
        f.ret(16, [path, 0x5451, 0, 0, 0, 0]),
        Errno::EBADF.to_syscall_return()
    );
    assert_eq!(
        f.ret(16, [path, 0x2, DATA + 16, 0, 0, 0]),
        Errno::EBADF.to_syscall_return()
    );
}
/// A `sockaddr_in` for `ip` and `port` at `at`.
fn inet_address(f: &Fixture, at: u64, ip: [u8; 4], port: u16) {
    let mut raw = [0; 16];
    raw[0] = 2;
    raw[2..4].copy_from_slice(&port.to_be_bytes());
    raw[4..8].copy_from_slice(&ip);
    f.mem.write(GuestAddr(at), &raw).unwrap();
}
fn network_fixture(allow: &[&str]) -> Fixture {
    let mut f = Fixture::new();
    let policy = allow
        .iter()
        .fold(crate::NetworkPolicy::new(), |policy, entry| {
            policy.allow(entry).unwrap()
        });
    let kernel = std::mem::replace(&mut f.kernel, Kernel::new(f.host.clone()));
    f.kernel = kernel.with_network(policy);
    f
}
fn int_option(f: &mut Fixture, fd: u64, level: u64, name: u64) -> (u64, i32) {
    f.mem
        .write(GuestAddr(DATA + 0x200), &4u32.to_le_bytes())
        .unwrap();
    let r = f.ret(55, [fd, level, name, DATA + 0x204, DATA + 0x200, 0]);
    let mut raw = [0; 4];
    f.mem.read(GuestAddr(DATA + 0x204), &mut raw).unwrap();
    (r, i32::from_le_bytes(raw))
}
#[test]
fn inet_sockets_need_a_network() {
    let mut f = Fixture::new();
    assert_eq!(f.ret(41, [2, 1, 0, 0, 0, 0]), Errno(97).to_syscall_return());
    let mut f = network_fixture(&["127.0.0.1:80"]);
    assert_eq!(f.ret(41, [1, 1, 0, 0, 0, 0]), Errno(97).to_syscall_return());
    assert_eq!(
        f.ret(41, [2, 1 | 0x100000, 0, 0, 0, 0]),
        Errno::EINVAL.to_syscall_return()
    );
    assert_eq!(
        f.ret(41, [2, 1, 17, 0, 0, 0]),
        Errno(93).to_syscall_return()
    );
    assert_eq!(f.ret(41, [2, 5, 0, 0, 0, 0]), Errno(94).to_syscall_return());
    assert_eq!(f.ret(41, [2, 3, 1, 0, 0, 0]), Errno(1).to_syscall_return());
    assert_eq!(
        f.ret(41, [10, 2, 58, 0, 0, 0]),
        Errno(13).to_syscall_return()
    );
}
#[test]
fn a_tcp_socket_connects_through_the_host() {
    let mut f = network_fixture(&["127.0.0.1:80"]);
    let fd = f.ret(41, [2, 1 | 0x800, 0, 0, 0, 0]);
    assert!((fd as i64) >= 0);
    // A socket never connected.
    assert_eq!(
        f.ret(45, [fd, DATA, 8, 0, 0, 0]),
        Errno(107).to_syscall_return()
    );
    assert_eq!(
        f.ret(44, [fd, DATA, 1, 0x4000, 0, 0]),
        Errno::EPIPE.to_syscall_return()
    );
    // An address the policy does not name; on the loopback, a port no guest
    // socket listens on is refused instead (see `loopback_*`).
    inet_address(&f, DATA + 0x100, [192, 0, 2, 1], 81);
    assert_eq!(
        f.ret(42, [fd, DATA + 0x100, 16, 0, 0, 0]),
        Errno(101).to_syscall_return()
    );
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], 80);
    assert_eq!(
        f.ret(42, [fd, DATA + 0x100, 16, 0, 0, 0]),
        Errno(115).to_syscall_return()
    );
    assert_eq!(
        f.ret(42, [fd, DATA + 0x100, 16, 0, 0, 0]),
        Errno(114).to_syscall_return()
    );
    assert_eq!(int_option(&mut f, fd, 1, 4), (0, 0));
    assert_eq!(
        f.ret(44, [fd, DATA, 1, 0, 0, 0]),
        Errno::EAGAIN.to_syscall_return()
    );
    let stream = f.host.streams.lock().unwrap()[0].clone();
    assert_eq!(stream.peer(), "127.0.0.1:80".parse().unwrap());
    stream.connected(Some("127.0.0.1:40000".parse().unwrap()));
    assert_eq!(f.ret(42, [fd, DATA + 0x100, 16, 0, 0, 0]), 0);
    assert_eq!(
        f.ret(42, [fd, DATA + 0x100, 16, 0, 0, 0]),
        Errno(106).to_syscall_return()
    );
    // Addresses.
    f.mem
        .write(GuestAddr(DATA + 0x80), &16u32.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(51, [fd, DATA + 0x84, DATA + 0x80, 0, 0, 0]), 0);
    let mut name = [0; 16];
    f.mem.read(GuestAddr(DATA + 0x84), &mut name).unwrap();
    assert_eq!(&name[..8], &[2, 0, 0x9c, 0x40, 127, 0, 0, 1]);
    assert_eq!(f.ret(52, [fd, DATA + 0x84, DATA + 0x80, 0, 0, 0]), 0);
    f.mem.read(GuestAddr(DATA + 0x84), &mut name).unwrap();
    assert_eq!(&name[..4], &[2, 0, 0, 80]);
    // Bytes both ways.
    f.mem.write(GuestAddr(DATA), b"hello").unwrap();
    assert_eq!(f.ret(1, [fd, DATA, 5, 0, 0, 0]), 5);
    assert_eq!(stream.take(10), b"hello");
    stream.receive(b"world");
    assert_eq!(
        crate::sockets::queued(&f.kernel.files.descriptor(fd).unwrap().file, false),
        Some(Ok(5))
    );
    assert_eq!(f.ret(45, [fd, DATA, 3, 2, 0, 0]), 3);
    assert_eq!(f.ret(0, [fd, DATA, 16, 0, 0, 0]), 5);
    let mut got = [0; 5];
    f.mem.read(GuestAddr(DATA), &mut got).unwrap();
    assert_eq!(&got, b"world");
    assert_eq!(
        f.ret(0, [fd, DATA, 16, 0, 0, 0]),
        Errno::EAGAIN.to_syscall_return()
    );
    // TCP_NODELAY and the keepalive range.
    f.mem
        .write(GuestAddr(DATA + 0x300), &1i32.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(54, [fd, 6, 1, DATA + 0x300, 4, 0]), 0);
    assert_eq!(int_option(&mut f, fd, 6, 1), (0, 1));
    f.mem
        .write(GuestAddr(DATA + 0x300), &0i32.to_le_bytes())
        .unwrap();
    assert_eq!(
        f.ret(54, [fd, 6, 4, DATA + 0x300, 4, 0]),
        Errno::EINVAL.to_syscall_return()
    );
    assert_eq!(int_option(&mut f, fd, 6, 4), (0, 7200));
    assert_eq!(int_option(&mut f, fd, 1, 3), (0, 1));
    assert_eq!(
        int_option(&mut f, fd, 1, 9999).0,
        Errno(92).to_syscall_return()
    );
    // The end of input, then shutdown.
    stream.end();
    assert_eq!(f.ret(0, [fd, DATA, 16, 0, 0, 0]), 0);
    assert_eq!(f.ret(48, [fd, 1, 0, 0, 0, 0]), 0);
    assert_eq!(stream.finished(), (true, false));
    assert_eq!(
        f.ret(44, [fd, DATA, 1, 0x4000, 0, 0]),
        Errno::EPIPE.to_syscall_return()
    );
    assert_eq!(f.ret(3, [fd, 0, 0, 0, 0, 0]), 0);
    assert_eq!(stream.finished(), (true, true));
}
/// The 16 bytes of `getsockname` (51) or `getpeername` (52) of `fd`.
fn name_of(f: &mut Fixture, call: u64, fd: u64) -> [u8; 16] {
    f.mem
        .write(GuestAddr(DATA + 0x80), &16u32.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(call, [fd, DATA + 0x84, DATA + 0x80, 0, 0, 0]), 0);
    let mut name = [0; 16];
    f.mem.read(GuestAddr(DATA + 0x84), &mut name).unwrap();
    name
}
/// A TCP socket listening on 127.0.0.1 with `backlog`, and its port.
const SECOND: u64 = 1_000_000_000;
fn loopback_listener(f: &mut Fixture, backlog: u64) -> (u64, u16) {
    let fd = f.ret(41, [2, 1, 0, 0, 0, 0]);
    inet_address(f, DATA + 0x100, [127, 0, 0, 1], 0);
    assert_eq!(f.ret(49, [fd, DATA + 0x100, 16, 0, 0, 0]), 0);
    assert_eq!(f.ret(50, [fd, backlog, 0, 0, 0, 0]), 0);
    let name = name_of(f, 51, fd);
    (fd, u16::from_be_bytes([name[2], name[3]]))
}
/// A TCP socket connected to `port` on 127.0.0.1, blocking.
fn loopback_client(f: &mut Fixture, port: u16) -> u64 {
    let fd = f.ret(41, [2, 1, 0, 0, 0, 0]);
    inet_address(f, DATA + 0x100, [127, 0, 0, 1], port);
    assert_eq!(f.ret(42, [fd, DATA + 0x100, 16, 0, 0, 0]), 0);
    fd
}
fn readable(f: &mut Fixture, fd: u64) -> u32 {
    paludarium_host::FileHandle::readiness(&*f.kernel.files.descriptor(fd).unwrap().file)
        .unwrap()
        .0
}
#[test]
fn loopback_servers_listen_and_accept() {
    // No policy entry: the guest's own loopback needs none.
    let mut f = network_fixture(&[]);
    let (listener, port) = loopback_listener(&mut f, 8);
    assert!(port >= 32768);
    assert_eq!(int_option(&mut f, listener, 1, 30), (0, 1));
    assert_eq!(readable(&mut f, listener), 0);
    // Nothing waits: a nonblocking listener's accept is EAGAIN (accept4's
    // SOCK_NONBLOCK is the new socket's).
    assert_eq!(f.ret(72, [listener, 4, 0x800, 0, 0, 0]), 0);
    assert_eq!(
        f.ret(288, [listener, 0, 0, 0x800, 0, 0]),
        Errno::EAGAIN.to_syscall_return()
    );
    let client = loopback_client(&mut f, port);
    assert_eq!(readable(&mut f, listener), 1);
    f.mem
        .write(GuestAddr(DATA + 0x40), &16u32.to_le_bytes())
        .unwrap();
    let server = f.ret(288, [listener, DATA + 0x44, DATA + 0x40, 0x80000, 0, 0]);
    assert!((server as i64) >= 0, "{}", server as i64);
    let mut peer = [0; 16];
    f.mem.read(GuestAddr(DATA + 0x44), &mut peer).unwrap();
    assert_eq!(peer, name_of(&mut f, 51, client));
    assert_eq!(name_of(&mut f, 52, server), peer);
    assert_eq!(name_of(&mut f, 51, server), name_of(&mut f, 52, client));
    assert_eq!(
        &name_of(&mut f, 51, server)[..8],
        &[2, 0, (port >> 8) as u8, port as u8, 127, 0, 0, 1]
    );
    assert_eq!(int_option(&mut f, server, 1, 30), (0, 0));
    assert_eq!(readable(&mut f, listener), 0);
    // Bytes both ways, and the end.
    f.mem.write(GuestAddr(DATA), b"ping").unwrap();
    assert_eq!(f.ret(1, [client, DATA, 4, 0, 0, 0]), 4);
    assert_eq!(f.ret(0, [server, DATA + 8, 16, 0, 0, 0]), 4);
    let mut got = [0; 4];
    f.mem.read(GuestAddr(DATA + 8), &mut got).unwrap();
    assert_eq!(&got, b"ping");
    assert_eq!(f.ret(1, [server, DATA, 2, 0, 0, 0]), 2);
    assert_eq!(f.ret(0, [client, DATA + 8, 16, 0, 0, 0]), 2);
    assert_eq!(f.ret(48, [client, 1, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(0, [server, DATA + 8, 16, 0, 0, 0]), 0);
    assert_eq!(f.ret(3, [server, 0, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(0, [client, DATA + 8, 16, 0, 0, 0]), 0);
    // Listener calls that do not apply.
    assert_eq!(
        f.ret(42, [listener, DATA + 0x100, 16, 0, 0, 0]),
        Errno(106).to_syscall_return()
    );
    assert_eq!(
        crate::sockets::queued(&f.kernel.files.descriptor(listener).unwrap().file, false),
        Some(Err(Errno::EINVAL))
    );
    assert_eq!(
        f.ret(288, [listener, 0, 0, 1, 0, 0]),
        Errno::EINVAL.to_syscall_return()
    );
    // SHUT_RD stops it: accept is EINVAL, a connection refused.
    assert_eq!(f.ret(48, [listener, 0, 0, 0, 0, 0]), 0);
    assert_eq!(
        f.ret(43, [listener, 0, 0, 0, 0, 0]),
        Errno::EINVAL.to_syscall_return()
    );
    let late = f.ret(41, [2, 1, 0, 0, 0, 0]);
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], port);
    assert_eq!(
        f.ret(42, [late, DATA + 0x100, 16, 0, 0, 0]),
        Errno(111).to_syscall_return()
    );
}
#[test]
fn loopback_binds_check_as_linux() {
    let mut f = network_fixture(&[]);
    let (listener, port) = loopback_listener(&mut f, 1);
    let tcp = |f: &mut Fixture| f.ret(41, [2, 1, 0, 0, 0, 0]);
    let bind = |f: &mut Fixture, fd: u64, ip: [u8; 4], port: u16| {
        inet_address(f, DATA + 0x100, ip, port);
        f.ret(49, [fd, DATA + 0x100, 16, 0, 0, 0])
    };
    // Bound already, not the guest's address, in use, too short.
    assert_eq!(
        bind(&mut f, listener, [127, 0, 0, 1], 0),
        Errno::EINVAL.to_syscall_return()
    );
    let other = tcp(&mut f);
    assert_eq!(
        bind(&mut f, other, [192, 0, 2, 1], 0),
        Errno(99).to_syscall_return()
    );
    assert_eq!(
        bind(&mut f, other, [127, 0, 0, 1], port),
        Errno(98).to_syscall_return()
    );
    assert_eq!(
        bind(&mut f, other, [0, 0, 0, 0], port),
        Errno(98).to_syscall_return()
    );
    assert_eq!(
        f.ret(49, [other, DATA + 0x100, 8, 0, 0, 0]),
        Errno::EINVAL.to_syscall_return()
    );
    // SO_REUSEADDR does not share a listener's port...
    f.mem
        .write(GuestAddr(DATA + 0x300), &1i32.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(54, [other, 1, 2, DATA + 0x300, 4, 0]), 0);
    assert_eq!(
        bind(&mut f, other, [127, 0, 0, 1], port),
        Errno(98).to_syscall_return()
    );
    // ...but one of two sockets that do not listen.
    let a = tcp(&mut f);
    assert_eq!(f.ret(54, [a, 1, 2, DATA + 0x300, 4, 0]), 0);
    assert_eq!(bind(&mut f, a, [127, 0, 0, 2], 4000), 0);
    assert_eq!(bind(&mut f, other, [127, 0, 0, 2], 4000), 0);
    assert_eq!(f.ret(50, [a, 1, 0, 0, 0, 0]), 0);
    assert_eq!(
        f.ret(50, [other, 1, 0, 0, 0, 0]),
        Errno(98).to_syscall_return()
    );
    // Another address on the same port is free; a closed socket's port too.
    let b = tcp(&mut f);
    assert_eq!(bind(&mut f, b, [127, 0, 0, 3], 4000), 0);
    assert_eq!(f.ret(3, [b, 0, 0, 0, 0, 0]), 0);
    let c = tcp(&mut f);
    assert_eq!(bind(&mut f, c, [127, 0, 0, 3], 4000), 0);
    // UDP has ports of its own (TCP's 4000 is free to it), and does not
    // listen or accept.
    let udp = f.ret(41, [2, 2, 0, 0, 0, 0]);
    assert_eq!(bind(&mut f, udp, [127, 0, 0, 3], 4000), 0);
    assert_eq!(
        f.ret(50, [udp, 1, 0, 0, 0, 0]),
        Errno(95).to_syscall_return()
    );
    assert_eq!(
        f.ret(43, [udp, 0, 0, 0, 0, 0]),
        Errno(95).to_syscall_return()
    );
    // A socket never listening does not accept.
    assert_eq!(
        f.ret(43, [c, 0, 0, 0, 0, 0]),
        Errno::EINVAL.to_syscall_return()
    );
    // listen binds an unbound socket to every address.
    let d = tcp(&mut f);
    assert_eq!(f.ret(50, [d, 1, 0, 0, 0, 0]), 0);
    let name = name_of(&mut f, 51, d);
    assert_eq!(&name[4..8], &[0, 0, 0, 0]);
    assert!(u16::from_be_bytes([name[2], name[3]]) >= 32768);
}
#[test]
fn loopback_connections_in_progress_and_refused() {
    let mut f = network_fixture(&[]);
    let (listener, port) = loopback_listener(&mut f, 0);
    // A nonblocking connect is in progress even when taken at once.
    let quick = f.ret(41, [2, 1 | 0x800, 0, 0, 0, 0]);
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], port);
    assert_eq!(
        f.ret(42, [quick, DATA + 0x100, 16, 0, 0, 0]),
        Errno(115).to_syscall_return()
    );
    assert_eq!(readable(&mut f, quick) & 4, 4);
    assert_eq!(int_option(&mut f, quick, 1, 4), (0, 0));
    assert_eq!(f.ret(42, [quick, DATA + 0x100, 16, 0, 0, 0]), 0);
    assert_eq!(
        f.ret(42, [quick, DATA + 0x100, 16, 0, 0, 0]),
        Errno(106).to_syscall_return()
    );
    // The queue (backlog 0) is full: the handshake is dropped, and the
    // client tries again 1 second later, once accept has made room.
    let waiting = f.ret(41, [2, 1 | 0x800, 0, 0, 0, 0]);
    assert_eq!(
        f.ret(42, [waiting, DATA + 0x100, 16, 0, 0, 0]),
        Errno(115).to_syscall_return()
    );
    assert_eq!(readable(&mut f, waiting), 0);
    assert_eq!(
        f.ret(42, [waiting, DATA + 0x100, 16, 0, 0, 0]),
        Errno(114).to_syscall_return()
    );
    let first = f.ret(43, [listener, 0, 0, 0, 0, 0]);
    assert!((first as i64) >= 0);
    assert_eq!(readable(&mut f, waiting), 0);
    f.host.now.store(SECOND - 1, Ordering::SeqCst);
    assert_eq!(readable(&mut f, waiting), 0);
    f.host.now.store(SECOND, Ordering::SeqCst);
    assert_eq!(f.ret(42, [waiting, DATA + 0x100, 16, 0, 0, 0]), 0);
    assert_eq!(readable(&mut f, listener), 1);
    // A port no guest socket listens on: a reset.
    let nobody = f.ret(41, [2, 1 | 0x800, 0, 0, 0, 0]);
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], 9);
    assert_eq!(
        f.ret(42, [nobody, DATA + 0x100, 16, 0, 0, 0]),
        Errno(115).to_syscall_return()
    );
    assert_eq!(readable(&mut f, nobody) & 8, 8);
    assert_eq!(int_option(&mut f, nobody, 1, 4), (0, 111));
    let blocking = f.ret(41, [2, 1, 0, 0, 0, 0]);
    assert_eq!(
        f.ret(42, [blocking, DATA + 0x100, 16, 0, 0, 0]),
        Errno(111).to_syscall_return()
    );
}
#[test]
fn a_dropped_handshake_is_tried_again_until_it_times_out() {
    let mut f = network_fixture(&[]);
    let at = |f: &mut Fixture, seconds: u64| f.host.now.store(seconds * SECOND, Ordering::SeqCst);
    let nonblocking = |f: &mut Fixture, port: u16| {
        let fd = f.ret(41, [2, 1 | 0x800, 0, 0, 0, 0]);
        inet_address(f, DATA + 0x100, [127, 0, 0, 1], port);
        assert_eq!(
            f.ret(42, [fd, DATA + 0x100, 16, 0, 0, 0]),
            Errno(115).to_syscall_return()
        );
        fd
    };
    // Backlog 0 holds one: the next is dropped and tried again at 1, 2, 3,
    // 4, 5, 7, 11… seconds; room made at 5.5 seconds takes it at 7.
    let (listener, port) = loopback_listener(&mut f, 0);
    let _held = loopback_client(&mut f, port);
    let late = nonblocking(&mut f, port);
    at(&mut f, 5);
    assert_eq!(readable(&mut f, late), 0);
    f.host.now.store(5 * SECOND + SECOND / 2, Ordering::SeqCst);
    let taken = f.ret(43, [listener, 0, 0, 0, 0, 0]);
    assert!((taken as i64) >= 0);
    assert_eq!(readable(&mut f, late) & 4, 0);
    at(&mut f, 7);
    assert_eq!(readable(&mut f, late) & 4, 4);
    assert_eq!(int_option(&mut f, late, 1, 4), (0, 0));
    // One whose client closes is forgotten at the next look, not kept to
    // its next try.
    let syns = |f: &Fixture| f.kernel.files.network.as_ref().unwrap().syns();
    let closed = nonblocking(&mut f, port);
    assert_eq!(syns(&f), 1);
    assert_eq!(f.ret(3, [closed, 0, 0, 0, 0, 0]), 0);
    assert_eq!(readable(&mut f, listener), 1);
    assert_eq!(syns(&f), 0);
    // Never given room, it gives up at 131 seconds with ETIMEDOUT.
    let given_up = nonblocking(&mut f, port);
    at(&mut f, 7 + 130);
    assert_eq!(readable(&mut f, given_up) & 8, 0);
    at(&mut f, 7 + 131);
    assert_eq!(readable(&mut f, given_up) & 8, 8);
    assert_eq!(int_option(&mut f, given_up, 1, 4), (0, 110));
    // Its listener gone, the next try is refused; another listening on the
    // port by then takes it instead.
    let refused = nonblocking(&mut f, port);
    let moved = {
        let (other, other_port) = loopback_listener(&mut f, 0);
        let _filler = loopback_client(&mut f, other_port);
        (other, other_port, nonblocking(&mut f, other_port))
    };
    assert_eq!(f.ret(3, [listener, 0, 0, 0, 0, 0]), 0);
    assert_eq!(readable(&mut f, refused) & 8, 0);
    at(&mut f, 7 + 132);
    assert_eq!(readable(&mut f, refused) & 8, 8);
    assert_eq!(int_option(&mut f, refused, 1, 4), (0, 111));
    let (other, other_port, waiting) = moved;
    assert_eq!(f.ret(3, [other, 0, 0, 0, 0, 0]), 0);
    // Another socket listens on that port before the next try.
    let again = f.ret(41, [2, 1, 0, 0, 0, 0]);
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], other_port);
    assert_eq!(f.ret(49, [again, DATA + 0x100, 16, 0, 0, 0]), 0);
    assert_eq!(f.ret(50, [again, 4, 0, 0, 0, 0]), 0);
    at(&mut f, 7 + 133);
    assert_eq!(readable(&mut f, waiting) & 4, 4);
    assert_eq!(int_option(&mut f, waiting, 1, 4), (0, 0));
}
#[test]
fn loopback_closes_reset_what_is_left() {
    let mut f = network_fixture(&[]);
    let (listener, port) = loopback_listener(&mut f, 8);
    // Closed with unread input: the peer reads what it had, then the reset.
    let client = loopback_client(&mut f, port);
    let server = f.ret(43, [listener, 0, 0, 0, 0, 0]);
    f.mem.write(GuestAddr(DATA), b"abc").unwrap();
    assert_eq!(f.ret(1, [server, DATA, 3, 0, 0, 0]), 3);
    assert_eq!(f.ret(1, [client, DATA, 3, 0, 0, 0]), 3);
    assert_eq!(f.ret(3, [server, 0, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(0, [client, DATA + 8, 16, 0, 0, 0]), 3);
    assert_eq!(
        f.ret(0, [client, DATA + 8, 16, 0, 0, 0]),
        Errno(104).to_syscall_return()
    );
    assert_eq!(f.ret(0, [client, DATA + 8, 16, 0, 0, 0]), 0);
    // Closed cleanly: the peer's end, then a write answered with a reset.
    let client = loopback_client(&mut f, port);
    let server = f.ret(43, [listener, 0, 0, 0, 0, 0]);
    assert_eq!(f.ret(3, [server, 0, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(0, [client, DATA + 8, 16, 0, 0, 0]), 0);
    assert_eq!(f.ret(44, [client, DATA, 3, 0x4000, 0, 0]), 3);
    assert_eq!(
        f.ret(44, [client, DATA, 3, 0x4000, 0, 0]),
        Errno::EPIPE.to_syscall_return()
    );
    // A listener that closes resets what it had not handed out.
    let _kept_client = loopback_client(&mut f, port);
    let kept = f.ret(43, [listener, 0, 0, 0, 0, 0]);
    let queued = loopback_client(&mut f, port);
    assert_eq!(f.ret(3, [listener, 0, 0, 0, 0, 0]), 0);
    assert_eq!(
        f.ret(0, [queued, DATA + 8, 16, 0, 0, 0]),
        Errno(104).to_syscall_return()
    );
    // The port is held while a connection it accepted lives.
    let again = f.ret(41, [2, 1, 0, 0, 0, 0]);
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], port);
    assert_eq!(
        f.ret(49, [again, DATA + 0x100, 16, 0, 0, 0]),
        Errno(98).to_syscall_return()
    );
    // Closed first, that connection keeps it in `TIME_WAIT` for 60 seconds.
    assert_eq!(f.ret(3, [kept, 0, 0, 0, 0, 0]), 0);
    assert_eq!(
        f.ret(49, [again, DATA + 0x100, 16, 0, 0, 0]),
        Errno(98).to_syscall_return()
    );
    f.host
        .now
        .store(crate::loopback::TIME_WAIT, Ordering::SeqCst);
    assert_eq!(f.ret(49, [again, DATA + 0x100, 16, 0, 0, 0]), 0);
    assert_eq!(f.ret(3, [client, 0, 0, 0, 0, 0]), 0);
}
#[test]
fn loopback_time_wait_holds_the_port_closed_first() {
    let mut f = network_fixture(&[]);
    let bind_on = |f: &mut Fixture, port: u16, reuse: bool| {
        let fd = f.ret(41, [2, 1, 0, 0, 0, 0]);
        if reuse {
            f.mem
                .write(GuestAddr(DATA + 0x200), &1u32.to_le_bytes())
                .unwrap();
            assert_eq!(f.ret(54, [fd, 1, 2, DATA + 0x200, 4, 0]), 0);
        }
        inet_address(f, DATA + 0x100, [127, 0, 0, 1], port);
        let r = f.ret(49, [fd, DATA + 0x100, 16, 0, 0, 0]);
        assert_eq!(f.ret(3, [fd, 0, 0, 0, 0, 0]), 0);
        r
    };
    let port_of = |f: &mut Fixture, fd: u64| {
        let name = name_of(f, 51, fd);
        u16::from_be_bytes([name[2], name[3]])
    };
    let in_use = Errno(98).to_syscall_return();
    let (listener, port) = loopback_listener(&mut f, 8);
    // The client closes first: its port is held, even for SO_REUSEADDR, as
    // the closed socket had none; the server's, which closed second, is not.
    let client = loopback_client(&mut f, port);
    let server = f.ret(43, [listener, 0, 0, 0, 0, 0]);
    let client_port = port_of(&mut f, client);
    assert_eq!(f.ret(3, [client, 0, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(0, [server, DATA + 8, 16, 0, 0, 0]), 0);
    assert_eq!(f.ret(3, [server, 0, 0, 0, 0, 0]), 0);
    assert_eq!(bind_on(&mut f, client_port, false), in_use);
    assert_eq!(bind_on(&mut f, client_port, true), in_use);
    // Until 60 seconds have passed.
    f.host
        .now
        .store(crate::loopback::TIME_WAIT - 1, Ordering::SeqCst);
    assert_eq!(bind_on(&mut f, client_port, false), in_use);
    f.host
        .now
        .store(crate::loopback::TIME_WAIT, Ordering::SeqCst);
    assert_eq!(bind_on(&mut f, client_port, false), 0);
    // Held while its peer stays open too; a send to the closed side is
    // answered with a reset, which ends it.
    let client = loopback_client(&mut f, port);
    let server = f.ret(43, [listener, 0, 0, 0, 0, 0]);
    let open_port = port_of(&mut f, client);
    assert_eq!(f.ret(3, [client, 0, 0, 0, 0, 0]), 0);
    assert_eq!(bind_on(&mut f, open_port, false), in_use);
    f.mem.write(GuestAddr(DATA), b"x").unwrap();
    assert_eq!(f.ret(1, [server, DATA, 1, 0, 0, 0]), 1);
    assert_eq!(bind_on(&mut f, open_port, false), 0);
    assert_eq!(f.ret(3, [server, 0, 0, 0, 0, 0]), 0);
    // Closed with bytes the peer has no room for yet: held while they go
    // (Linux's `FIN_WAIT1`), then in `TIME_WAIT` once its end has reached
    // the peer first; a reset, as the peer closes with them unread, ends it.
    for drained in [true, false] {
        let client = loopback_client(&mut f, port);
        let server = f.ret(43, [listener, 0, 0, 0, 0, 0]);
        let full_port = port_of(&mut f, client);
        while f.ret(44, [client, DATA + 0x400, 0x1000, 0x40, 0, 0]) == 0x1000 {}
        assert_eq!(f.ret(3, [client, 0, 0, 0, 0, 0]), 0);
        assert_eq!(bind_on(&mut f, full_port, false), in_use);
        if drained {
            while f.ret(0, [server, DATA + 0x400, 0x1000, 0, 0, 0]) > 0 {}
        }
        assert_eq!(f.ret(3, [server, 0, 0, 0, 0, 0]), 0);
        let expected = if drained { in_use } else { 0 };
        assert_eq!(bind_on(&mut f, full_port, false), expected);
    }
    // A close with unread input resets: nothing is held.
    let client = loopback_client(&mut f, port);
    let server = f.ret(43, [listener, 0, 0, 0, 0, 0]);
    let reset_port = port_of(&mut f, client);
    assert_eq!(f.ret(1, [server, DATA, 1, 0, 0, 0]), 1);
    assert_eq!(f.ret(3, [client, 0, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(3, [server, 0, 0, 0, 0, 0]), 0);
    assert_eq!(bind_on(&mut f, reset_port, false), 0);
    assert_eq!(f.ret(3, [listener, 0, 0, 0, 0, 0]), 0);
    // A server that closes first holds the listener's port, which a new
    // socket with SO_REUSEADDR shares when the closed one had it too.
    let reusing = f.ret(41, [2, 1, 0, 0, 0, 0]);
    f.mem
        .write(GuestAddr(DATA + 0x200), &1u32.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(54, [reusing, 1, 2, DATA + 0x200, 4, 0]), 0);
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], 0);
    assert_eq!(f.ret(49, [reusing, DATA + 0x100, 16, 0, 0, 0]), 0);
    assert_eq!(f.ret(50, [reusing, 8, 0, 0, 0, 0]), 0);
    let shared = port_of(&mut f, reusing);
    let client = loopback_client(&mut f, shared);
    let server = f.ret(43, [reusing, 0, 0, 0, 0, 0]);
    assert_eq!(f.ret(3, [server, 0, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(3, [client, 0, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(3, [reusing, 0, 0, 0, 0, 0]), 0);
    assert_eq!(bind_on(&mut f, shared, false), in_use);
    assert_eq!(bind_on(&mut f, shared, true), 0);
}
#[test]
fn sockets_sharing_a_port_share_its_connections_and_datagrams() {
    let mut f = network_fixture(&[]);
    f.mem
        .write(GuestAddr(DATA + 0x300), &1i32.to_le_bytes())
        .unwrap();
    // Two of a group, bound to 127.0.0.1 on one port with SO_REUSEPORT.
    let shared = |f: &mut Fixture, kind: u64, port: u16| {
        let fd = f.ret(41, [2, kind | 0x800, 0, 0, 0, 0]);
        assert_eq!(f.ret(54, [fd, 1, 15, DATA + 0x300, 4, 0]), 0);
        inet_address(f, DATA + 0x100, [127, 0, 0, 1], port);
        assert_eq!(f.ret(49, [fd, DATA + 0x100, 16, 0, 0, 0]), 0);
        let name = name_of(f, 51, fd);
        (fd, u16::from_be_bytes([name[2], name[3]]))
    };
    let accepted = |f: &mut Fixture, fd: u64| {
        let mut count = 0;
        while (f.ret(288, [fd, 0, 0, 0, 0, 0]) as i64) >= 0 {
            count += 1;
        }
        count
    };
    let (a, port) = shared(&mut f, 1, 0);
    let (b, _) = shared(&mut f, 1, port);
    assert_eq!(f.ret(50, [a, 64, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(50, [b, 64, 0, 0, 0, 0]), 0);
    for _ in 0..32 {
        loopback_client(&mut f, port);
    }
    let (to_a, to_b) = (accepted(&mut f, a), accepted(&mut f, b));
    assert_eq!(to_a + to_b, 32);
    assert!(to_a > 0 && to_b > 0, "{to_a} {to_b}");
    // A listener that leaves the group takes no more.
    assert_eq!(f.ret(3, [a, 0, 0, 0, 0, 0]), 0);
    for _ in 0..8 {
        loopback_client(&mut f, port);
    }
    assert_eq!(accepted(&mut f, b), 8);

    let (c, port) = shared(&mut f, 2, 0);
    let (d, _) = shared(&mut f, 2, port);
    let received = |f: &mut Fixture, fd: u64| {
        let mut count = 0;
        while (f.ret(45, [fd, DATA + 8, 16, 0, 0, 0]) as i64) >= 0 {
            count += 1;
        }
        count
    };
    let send = |f: &mut Fixture| {
        let sender = f.ret(41, [2, 2, 0, 0, 0, 0]);
        inet_address(f, DATA + 0x100, [127, 0, 0, 1], port);
        assert_eq!(f.ret(44, [sender, DATA, 1, 0, DATA + 0x100, 16]), 1);
        sender
    };
    for _ in 0..32 {
        send(&mut f);
    }
    let (to_c, to_d) = (received(&mut f, c), received(&mut f, d));
    assert_eq!(to_c + to_d, 32);
    assert!(to_c > 0 && to_d > 0, "{to_c} {to_d}");
    // A connected one takes only its peer's; the rest go to the other.
    let peer = send(&mut f);
    assert_eq!(received(&mut f, c) + received(&mut f, d), 1);
    let name = name_of(&mut f, 51, peer);
    inet_address(
        &f,
        DATA + 0x100,
        [127, 0, 0, 1],
        u16::from_be_bytes([name[2], name[3]]),
    );
    assert_eq!(f.ret(42, [c, DATA + 0x100, 16, 0, 0, 0]), 0);
    for _ in 0..8 {
        send(&mut f);
    }
    assert_eq!(received(&mut f, d), 8);
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], port);
    assert_eq!(f.ret(44, [peer, DATA, 1, 0, DATA + 0x100, 16]), 1);
    assert_eq!(received(&mut f, c), 1);
}
#[test]
fn a_udp_shutdown_ends_reads_and_refuses_sends() {
    let mut f = network_fixture(&[]);
    let a = f.ret(41, [2, 2, 0, 0, 0, 0]);
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], 0);
    assert_eq!(f.ret(49, [a, DATA + 0x100, 16, 0, 0, 0]), 0);
    let name = name_of(&mut f, 51, a);
    let port = u16::from_be_bytes([name[2], name[3]]);
    // Not connected: ENOTCONN, but the socket is shut all the same.
    assert_eq!(
        f.ret(48, [a, 0, 0, 0, 0, 0]),
        Errno(107).to_syscall_return()
    );
    assert_eq!(readable(&mut f, a), 4 | 1 | 0x2000);
    // A read that would wait ends with 0; one that would not is EAGAIN.
    assert_eq!(f.ret(0, [a, DATA + 8, 16, 0, 0, 0]), 0);
    assert_eq!(
        f.ret(45, [a, DATA + 8, 16, 0x40, 0, 0]),
        Errno::EAGAIN.to_syscall_return()
    );
    // Datagrams still come, and are read.
    let b = f.ret(41, [2, 2, 0, 0, 0, 0]);
    f.mem.write(GuestAddr(DATA), b"hi").unwrap();
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], port);
    assert_eq!(f.ret(44, [b, DATA, 2, 0, DATA + 0x100, 16]), 2);
    assert_eq!(f.ret(0, [a, DATA + 8, 16, 0, 0, 0]), 2);
    // Shut for sending too: hung up, and a send is EPIPE with no SIGPIPE.
    assert_eq!(
        f.ret(48, [a, 1, 0, 0, 0, 0]),
        Errno(107).to_syscall_return()
    );
    assert_eq!(readable(&mut f, a) & 0x10, 0x10);
    assert_eq!(
        f.ret(44, [a, DATA, 2, 0, DATA + 0x100, 16]),
        Errno::EPIPE.to_syscall_return()
    );
    assert_eq!(f.ret(127, [DATA + 0x300, 8, 0, 0, 0, 0]), 0);
    let mut pending = [0; 8];
    f.mem.read(GuestAddr(DATA + 0x300), &mut pending).unwrap();
    assert_eq!(u64::from_le_bytes(pending) & (1 << 12), 0);
    // A connected socket's shutdown is 0.
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], port);
    assert_eq!(f.ret(42, [b, DATA + 0x100, 16, 0, 0, 0]), 0);
    assert_eq!(f.ret(48, [b, 2, 0, 0, 0, 0]), 0);
    assert_eq!(
        f.ret(48, [b, 3, 0, 0, 0, 0]),
        Errno::EINVAL.to_syscall_return()
    );
}
#[test]
fn loopback_udp_datagrams() {
    let mut f = network_fixture(&[]);
    let udp = |f: &mut Fixture| f.ret(41, [2, 2 | 0x800, 0, 0, 0, 0]);
    let port_of = |f: &mut Fixture, fd: u64| {
        let name = name_of(f, 51, fd);
        u16::from_be_bytes([name[2], name[3]])
    };
    let send_to = |f: &mut Fixture, fd: u64, bytes: &[u8], port: u16| {
        f.mem.write(GuestAddr(DATA), bytes).unwrap();
        inet_address(f, DATA + 0x100, [127, 0, 0, 1], port);
        f.ret(44, [fd, DATA, bytes.len() as u64, 0, DATA + 0x100, 16])
    };
    let a = udp(&mut f);
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], 0);
    assert_eq!(f.ret(49, [a, DATA + 0x100, 16, 0, 0, 0]), 0);
    let port = port_of(&mut f, a);
    assert_eq!(readable(&mut f, a) & 1, 0);
    // An unbound sender takes a port on every address.
    let b = udp(&mut f);
    assert_eq!(send_to(&mut f, b, b"one", port), 3);
    let name = name_of(&mut f, 51, b);
    assert_eq!(&name[4..8], &[0, 0, 0, 0]);
    let b_port = u16::from_be_bytes([name[2], name[3]]);
    assert!(b_port >= 32768);
    assert_eq!(readable(&mut f, a) & 1, 1);
    assert_eq!(send_to(&mut f, b, b"three", port), 5);
    assert_eq!(
        crate::sockets::queued(&f.kernel.files.descriptor(a).unwrap().file, false),
        Some(Ok(3))
    );
    // recvfrom gives each datagram, cut to the buffer, and its sender.
    f.mem
        .write(GuestAddr(DATA + 0x40), &16u32.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(45, [a, DATA + 8, 16, 0, DATA + 0x44, DATA + 0x40]), 3);
    let mut from = [0; 8];
    f.mem.read(GuestAddr(DATA + 0x44), &mut from).unwrap();
    assert_eq!(
        from,
        [2, 0, (b_port >> 8) as u8, b_port as u8, 127, 0, 0, 1]
    );
    assert_eq!(f.ret(45, [a, DATA + 8, 2, 0x20, 0, 0]), 5);
    assert_eq!(
        f.ret(45, [a, DATA + 8, 16, 0, 0, 0]),
        Errno::EAGAIN.to_syscall_return()
    );
    // A connected socket takes datagrams only from its peer.
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], b_port);
    assert_eq!(f.ret(42, [a, DATA + 0x100, 16, 0, 0, 0]), 0);
    let c = udp(&mut f);
    assert_eq!(send_to(&mut f, c, b"x", port), 1);
    assert_eq!(readable(&mut f, a) & 1, 0);
    assert_eq!(send_to(&mut f, b, b"y", port), 1);
    assert_eq!(f.ret(0, [a, DATA + 8, 16, 0, 0, 0]), 1);
    // A send without an address goes to the peer; an unconnected one has
    // no peer.
    f.mem.write(GuestAddr(DATA), b"back").unwrap();
    assert_eq!(f.ret(1, [a, DATA, 4, 0, 0, 0]), 4);
    assert_eq!(f.ret(0, [b, DATA + 8, 16, 0, 0, 0]), 4);
    assert_eq!(
        f.ret(1, [c, DATA, 4, 0, 0, 0]),
        Errno(89).to_syscall_return()
    );
    // Connected to a port nothing takes: the next call gives the
    // loopback's ICMP answer once.
    let d = udp(&mut f);
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], 9);
    assert_eq!(f.ret(42, [d, DATA + 0x100, 16, 0, 0, 0]), 0);
    assert_eq!(&name_of(&mut f, 51, d)[4..8], &[127, 0, 0, 1]);
    assert_eq!(f.ret(1, [d, DATA, 4, 0, 0, 0]), 4);
    assert_eq!(readable(&mut f, d) & 8, 8);
    assert_eq!(
        f.ret(1, [d, DATA, 4, 0, 0, 0]),
        Errno(111).to_syscall_return()
    );
    assert_eq!(f.ret(1, [d, DATA, 4, 0, 0, 0]), 4);
    assert_eq!(int_option(&mut f, d, 1, 4), (0, 111));
    assert_eq!(int_option(&mut f, d, 1, 4), (0, 0));
    // Unconnected, nothing is told.
    assert_eq!(send_to(&mut f, c, b"x", 9), 1);
    assert_eq!(int_option(&mut f, c, 1, 4), (0, 0));
    // A port another UDP socket holds; Linux's buffer defaults.
    let e = udp(&mut f);
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], port);
    assert_eq!(
        f.ret(49, [e, DATA + 0x100, 16, 0, 0, 0]),
        Errno(98).to_syscall_return()
    );
    assert_eq!(int_option(&mut f, e, 1, 8), (0, 212_992));
    // A non-loopback address is outside the guest.
    f.mem.write(GuestAddr(DATA), b"z").unwrap();
    inet_address(&f, DATA + 0x100, [192, 0, 2, 1], port);
    assert_eq!(
        f.ret(44, [e, DATA, 1, 0, DATA + 0x100, 16]),
        Errno(101).to_syscall_return()
    );
}
#[test]
fn a_udp_connect_off_the_loopback_takes_a_port() {
    let mut f = network_fixture(&[]);
    let udp = |f: &mut Fixture, family: u64| f.ret(41, [family, 2 | 0x800, 0, 0, 0, 0]);
    // Connected elsewhere, the socket takes a port on every address, as
    // the guest has no address of its own there.
    let u = udp(&mut f, 2);
    inet_address(&f, DATA + 0x100, [192, 0, 2, 1], 9);
    assert_eq!(f.ret(42, [u, DATA + 0x100, 16, 0, 0, 0]), 0);
    let name = name_of(&mut f, 51, u);
    assert_eq!(&name[..2], &[2, 0]);
    assert_eq!(&name[4..8], &[0, 0, 0, 0]);
    let port = u16::from_be_bytes([name[2], name[3]]);
    assert!(port >= 32768);
    assert_eq!(&name_of(&mut f, 52, u)[..8], &[2, 0, 0, 9, 192, 0, 2, 1]);
    // It takes no datagram from the loopback, and holds its port.
    let other = udp(&mut f, 2);
    f.mem.write(GuestAddr(DATA), b"x").unwrap();
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], port);
    assert_eq!(f.ret(44, [other, DATA, 1, 0, DATA + 0x100, 16]), 1);
    assert_eq!(readable(&mut f, u) & 1, 0);
    let taker = udp(&mut f, 2);
    inet_address(&f, DATA + 0x100, [0, 0, 0, 0], port);
    assert_eq!(
        f.ret(49, [taker, DATA + 0x100, 16, 0, 0, 0]),
        Errno(98).to_syscall_return()
    );
    // AF_UNSPEC gives the port back, as the guest did not name it.
    f.mem.write(GuestAddr(DATA + 0x100), &[0u8; 16]).unwrap();
    assert_eq!(f.ret(42, [u, DATA + 0x100, 16, 0, 0, 0]), 0);
    assert_eq!(name_of(&mut f, 51, u)[..8], [2, 0, 0, 0, 0, 0, 0, 0]);
    inet_address(&f, DATA + 0x100, [0, 0, 0, 0], port);
    assert_eq!(f.ret(49, [taker, DATA + 0x100, 16, 0, 0, 0]), 0);
    // An IPv6-only socket has no route to an IPv4-mapped address.
    let v6 = udp(&mut f, 10);
    f.mem
        .write(GuestAddr(DATA + 0x200), &1u32.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(54, [v6, 41, 26, DATA + 0x200, 4, 0]), 0);
    let mut mapped = [0u8; 28];
    mapped[0] = 10;
    mapped[3] = 9;
    mapped[18..20].copy_from_slice(&[0xff, 0xff]);
    mapped[20..24].copy_from_slice(&[192, 0, 2, 1]);
    f.mem.write(GuestAddr(DATA + 0x100), &mapped).unwrap();
    assert_eq!(
        f.ret(42, [v6, DATA + 0x100, 28, 0, 0, 0]),
        Errno(101).to_syscall_return()
    );
    // It took its port all the same, as Linux binds one first.
    f.mem
        .write(GuestAddr(DATA + 0x80), &28u32.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(51, [v6, DATA + 0x84, DATA + 0x80, 0, 0, 0]), 0);
    let mut name = [0u8; 4];
    f.mem.read(GuestAddr(DATA + 0x84), &mut name).unwrap();
    assert!(u16::from_be_bytes([name[2], name[3]]) >= 32768);
}
#[test]
fn a_failed_connection_reports_its_error_once() {
    let mut f = network_fixture(&["127.0.0.1"]);
    let fd = f.ret(41, [2, 1 | 0x800, 0, 0, 0, 0]);
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], 9);
    assert_eq!(
        f.ret(42, [fd, DATA + 0x100, 16, 0, 0, 0]),
        Errno(115).to_syscall_return()
    );
    f.host.streams.lock().unwrap()[0].fail(Errno(111));
    assert_eq!(int_option(&mut f, fd, 1, 4), (0, 111));
    assert_eq!(int_option(&mut f, fd, 1, 4), (0, 0));
    assert_eq!(
        f.ret(42, [fd, DATA + 0x100, 16, 0, 0, 0]),
        Errno(103).to_syscall_return()
    );
    // Linux disconnected it: as a socket never connected.
    assert_eq!(
        f.ret(0, [fd, DATA, 4, 0, 0, 0]),
        Errno(107).to_syscall_return()
    );
    assert_eq!(
        f.ret(44, [fd, DATA, 1, 0x4000, 0, 0]),
        Errno::EPIPE.to_syscall_return()
    );
    // A blocking connect that fails gives the error itself.
    let blocking = f.ret(41, [2, 1, 0, 0, 0, 0]);
    let host = f.host.clone();
    *f.host.action.lock().unwrap() = Some(Box::new(move || {
        host.streams.lock().unwrap()[1].fail(Errno(111));
    }));
    assert_eq!(
        f.ret(42, [blocking, DATA + 0x100, 16, 0, 0, 0]),
        Errno(111).to_syscall_return()
    );
    assert_eq!(int_option(&mut f, blocking, 1, 4), (0, 0));
}
#[test]
fn a_socket_pair_is_unnamed_and_never_listens() {
    let mut f = Fixture::new();
    let pair = |f: &mut Fixture, kind: u64| {
        assert_eq!(f.ret(53, [1, kind, 0, DATA, 0, 0]), 0);
        let mut raw = [0; 4];
        f.mem.read(GuestAddr(DATA), &mut raw).unwrap();
        u64::from(u32::from_le_bytes(raw))
    };
    let stream = pair(&mut f, 1);
    f.mem
        .write(GuestAddr(DATA + 0x80), &16u32.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(51, [stream, DATA + 0x84, DATA + 0x80, 0, 0, 0]), 0);
    let mut name = [0; 6];
    f.mem.read(GuestAddr(DATA + 0x80), &mut name).unwrap();
    assert_eq!(name, [2, 0, 0, 0, 1, 0]);
    assert_eq!(f.ret(52, [stream, DATA + 0x84, DATA + 0x80, 0, 0, 0]), 0);
    assert_eq!(
        f.ret(50, [stream, 1, 0, 0, 0, 0]),
        Errno::EINVAL.to_syscall_return()
    );
    assert_eq!(
        f.ret(43, [stream, 0, 0, 0, 0, 0]),
        Errno::EINVAL.to_syscall_return()
    );
    assert_eq!(
        f.ret(42, [stream, DATA, 2, 0, 0, 0]),
        Errno::ENOSYS.to_syscall_return()
    );
    let datagram = pair(&mut f, 2);
    assert_eq!(
        f.ret(288, [datagram, 0, 0, 0, 0, 0]),
        Errno(95).to_syscall_return()
    );
    let event = f.event(0);
    assert_eq!(
        f.ret(49, [event, DATA, 2, 0, 0, 0]),
        Errno(88).to_syscall_return()
    );
    assert_eq!(
        f.ret(51, [99, DATA, DATA + 0x80, 0, 0, 0]),
        Errno::EBADF.to_syscall_return()
    );
}
#[test]
fn an_async_tcp_socket_signals_its_owner() {
    let mut f = network_fixture(&["127.0.0.1"]);
    // Blocked, the signals stay pending to be looked at.
    f.thread.state.signal_mask = 1 << 39;
    let taken = |f: &Fixture| -> Vec<(i32, i64)> {
        std::iter::from_fn(|| f.kernel.group.take_process_signal(1 << 39))
            .filter_map(|signal| signal.queued)
            .map(|info| {
                (
                    i32::from_le_bytes(info[8..12].try_into().unwrap()),
                    i64::from_le_bytes(info[16..24].try_into().unwrap()),
                )
            })
            .collect()
    };
    let fd = f.ret(41, [2, 1 | 0x800, 0, 0, 0, 0]);
    assert_eq!(f.ret(72, [fd, 8, 1, 0, 0, 0]), 0);
    assert_eq!(f.ret(72, [fd, 9, 0, 0, 0, 0]), 1);
    assert_eq!(f.ret(72, [fd, 10, 40, 0, 0, 0]), 0);
    assert_eq!(f.ret(72, [fd, 4, 0o20000 | 0x800, 0, 0, 0]), 0);
    assert_eq!(f.ret(72, [fd, 3, 0, 0, 0, 0]) & 0o20000, 0o20000);
    inet_address(&f, DATA + 0x100, [127, 0, 0, 1], 80);
    assert_eq!(
        f.ret(42, [fd, DATA + 0x100, 16, 0, 0, 0]),
        Errno(115).to_syscall_return()
    );
    let stream = f.host.streams.lock().unwrap()[0].clone();
    // The connection opening is POLL_OUT, data POLL_IN, the peer's end
    // POLL_IN, and the end once this side has shut down too POLL_HUP.
    stream.connected(None);
    assert_eq!(taken(&f), [(2, 0x304)]);
    stream.receive(b"abc");
    assert_eq!(taken(&f), [(1, 0x41)]);
    // A full buffer found by a write makes room signal POLL_OUT, once.
    let big = vec![0; paludarium_host::net::BUFFER];
    f.mem.write(GuestAddr(DATA + 0x400), &big[..4096]).unwrap();
    while f.ret(44, [fd, DATA + 0x400, 4096, 0x40, 0, 0]) == 4096 {}
    stream.take(10);
    stream.take(10);
    assert_eq!(taken(&f), [(2, 0x304)]);
    assert_eq!(f.ret(48, [fd, 1, 0, 0, 0, 0]), 0);
    stream.end();
    assert_eq!(taken(&f), [(6, 0x18), (1, 0x41)]);
    // A connection that fails is POLL_ERR.
    let other = f.ret(41, [2, 1 | 0x800, 0, 0, 0, 0]);
    assert_eq!(f.ret(72, [other, 8, 1, 0, 0, 0]), 0);
    assert_eq!(f.ret(72, [other, 10, 40, 0, 0, 0]), 0);
    // FIOASYNC turns it on as F_SETFL does.
    f.mem
        .write(GuestAddr(DATA + 0x300), &1i32.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(16, [other, 0x5452, DATA + 0x300, 0, 0, 0]), 0);
    assert_eq!(
        f.ret(42, [other, DATA + 0x100, 16, 0, 0, 0]),
        Errno(115).to_syscall_return()
    );
    f.host.streams.lock().unwrap()[1].fail(Errno(111));
    assert_eq!(taken(&f), [(4, 0x8)]);
    // Without O_ASYNC nothing comes.
    assert_eq!(f.ret(72, [fd, 4, 0x800, 0, 0, 0]), 0);
    stream.receive(b"d");
    assert!(taken(&f).is_empty());
}
/// A DNS query for `name` of type `kind` at `at`; returns its length.
fn dns_query(f: &Fixture, at: u64, name: &str, kind: u16) -> u64 {
    let mut bytes = vec![0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.extend_from_slice(&[0]);
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&[0, 1]);
    f.mem.write(GuestAddr(at), &bytes).unwrap();
    bytes.len() as u64
}
#[test]
fn the_dns_stub_answers_over_tcp_too() {
    let mut f = network_fixture(&["example.com:443"]);
    let tcp = f.ret(41, [2, 1 | 0x800, 0, 0, 0, 0]);
    // Port 53 is the stub at any address, whatever the policy allows.
    inet_address(&f, DATA + 0x100, [10, 0, 0, 1], 53);
    assert_eq!(f.ret(42, [tcp, DATA + 0x100, 16, 0, 0, 0]), 0);
    assert!(f.host.streams.lock().unwrap().is_empty());
    // A query framed with its length, split across two writes.
    let len = dns_query(&f, DATA + 2, "example.com", 1);
    f.mem
        .write(GuestAddr(DATA), &(len as u16).to_be_bytes())
        .unwrap();
    assert_eq!(f.ret(1, [tcp, DATA, 5, 0, 0, 0]), 5);
    assert_eq!(f.ret(1, [tcp, DATA + 5, len - 3, 0, 0, 0]), len - 3);
    assert_eq!(
        f.ret(0, [tcp, DATA + 0x400, 512, 0, 0, 0]),
        Errno::EAGAIN.to_syscall_return()
    );
    let (name, lookup) = f.host.lookups.lock().unwrap()[0].clone();
    assert_eq!(name, "example.com");
    lookup.finish(Ok(vec!["192.0.2.5".parse().unwrap()]));
    let n = f.ret(0, [tcp, DATA + 0x400, 512, 0, 0, 0]);
    let mut answer = vec![0; n as usize];
    f.mem.read(GuestAddr(DATA + 0x400), &mut answer).unwrap();
    assert_eq!(
        usize::from(u16::from_be_bytes([answer[0], answer[1]])),
        answer.len() - 2
    );
    assert_eq!(&answer[2..6], &[0xab, 0xcd, 0x81, 0x80]);
    assert_eq!(&answer[answer.len() - 4..], &[192, 0, 2, 5]);
    // Another name, answered at once; then the end once this side shuts down.
    let len = dns_query(&f, DATA + 2, "other.org", 1);
    f.mem
        .write(GuestAddr(DATA), &(len as u16).to_be_bytes())
        .unwrap();
    assert_eq!(f.ret(1, [tcp, DATA, len + 2, 0, 0, 0]), len + 2);
    assert_eq!(f.ret(48, [tcp, 1, 0, 0, 0, 0]), 0);
    let n = f.ret(0, [tcp, DATA + 0x400, 512, 0, 0, 0]);
    let mut answer = vec![0; n as usize];
    f.mem.read(GuestAddr(DATA + 0x400), &mut answer).unwrap();
    assert_eq!(answer[5] & 0xf, 3, "NXDOMAIN");
    assert_eq!(f.ret(0, [tcp, DATA + 0x400, 512, 0, 0, 0]), 0);
}
#[test]
fn a_long_tcp_answer_comes_whole_in_small_reads() {
    let mut f = network_fixture(&["example.com"]);
    let tcp = f.ret(41, [2, 1 | 0x800, 0, 0, 0, 0]);
    inet_address(&f, DATA + 0x100, [127, 0, 0, 53], 53);
    assert_eq!(f.ret(42, [tcp, DATA + 0x100, 16, 0, 0, 0]), 0);
    // Two queries, the first answered after the second is queued, so that
    // their answers go out together.
    let mut framed = Vec::new();
    for _ in 0..2 {
        let len = dns_query(&f, DATA + 2, "example.com", 1);
        let mut query = vec![0; len as usize];
        f.mem.read(GuestAddr(DATA + 2), &mut query).unwrap();
        framed.extend_from_slice(&(len as u16).to_be_bytes());
        framed.extend_from_slice(&query);
    }
    f.mem.write(GuestAddr(DATA), &framed).unwrap();
    assert_eq!(
        f.ret(1, [tcp, DATA, framed.len() as u64, 0, 0, 0]),
        framed.len() as u64
    );
    let many: Vec<core::net::IpAddr> = (0..200u8)
        .map(|i| core::net::IpAddr::V4(core::net::Ipv4Addr::new(8, 8, i, 1)))
        .collect();
    let (_, lookup) = f.host.lookups.lock().unwrap()[0].clone();
    lookup.finish(Ok(many));
    assert_eq!(f.ret(48, [tcp, 1, 0, 0, 0, 0]), 0);
    let mut got = Vec::new();
    loop {
        let n = f.ret(0, [tcp, DATA + 0x400, 7, 0, 0, 0]);
        assert!((n as i64) >= 0, "{}", n as i64);
        if n == 0 {
            break;
        }
        let mut piece = vec![0; n as usize];
        f.mem.read(GuestAddr(DATA + 0x400), &mut piece).unwrap();
        got.extend(piece);
    }
    // Each answer holds all 200 records, each 16 bytes, after the 12-byte
    // header and the 17-byte question.
    let one = 2 + 12 + 17 + 200 * 16;
    assert_eq!(got.len(), 2 * one);
    for answer in got.chunks(one) {
        assert_eq!(
            usize::from(u16::from_be_bytes([answer[0], answer[1]])),
            one - 2
        );
        assert_eq!(&answer[8..10], &200u16.to_be_bytes());
    }
}
#[test]
fn tcp_answers_past_the_stream_buffer_come_as_reads_free_it() {
    let mut f = network_fixture(&["example.com"]);
    let tcp = f.ret(41, [2, 1 | 0x800, 0, 0, 0, 0]);
    inet_address(&f, DATA + 0x100, [127, 0, 0, 53], 53);
    assert_eq!(f.ret(42, [tcp, DATA + 0x100, 16, 0, 0, 0]), 0);
    // Five queries whose answers of 4000 records, about 64 KiB each, pass
    // the stream's 256 KiB: the rest waits until reads free room.
    let mut framed = Vec::new();
    for _ in 0..5 {
        let len = dns_query(&f, DATA + 2, "example.com", 1);
        let mut query = vec![0; len as usize];
        f.mem.read(GuestAddr(DATA + 2), &mut query).unwrap();
        framed.extend_from_slice(&(len as u16).to_be_bytes());
        framed.extend_from_slice(&query);
    }
    f.mem.write(GuestAddr(DATA), &framed).unwrap();
    assert_eq!(
        f.ret(1, [tcp, DATA, framed.len() as u64, 0, 0, 0]),
        framed.len() as u64
    );
    let many: Vec<core::net::IpAddr> = (0..4000u32)
        .map(|i| core::net::IpAddr::V4(core::net::Ipv4Addr::from(0x0808_0000 + i)))
        .collect();
    f.host.lookups.lock().unwrap()[0].1.finish(Ok(many));
    let full = crate::sockets::queued(&f.kernel.files.descriptor(tcp).unwrap().file, false);
    assert_eq!(full, Some(Ok(paludarium_host::net::BUFFER)));
    assert_eq!(f.ret(48, [tcp, 1, 0, 0, 0, 0]), 0);
    let mut total = 0u64;
    loop {
        let n = f.ret(0, [tcp, DATA + 0x400, 4096, 0, 0, 0]);
        assert!((n as i64) >= 0, "{}", n as i64);
        if n == 0 {
            break;
        }
        total += n;
    }
    // 2 + 12 + 17 + 4000 * 16 bytes each.
    assert_eq!(total, 5 * (2 + 12 + 17 + 4000 * 16));
}
#[test]
fn the_dns_stub_answers_allowed_names_from_the_host() {
    let mut f = network_fixture(&["example.com:443"]);
    let udp = f.ret(41, [2, 2 | 0x800, 0, 0, 0, 0]);
    inet_address(&f, DATA + 0x100, [0, 0, 0, 0], 0);
    assert_eq!(f.ret(49, [udp, DATA + 0x100, 16, 0, 0, 0]), 0);
    inet_address(&f, DATA + 0x100, [10, 0, 0, 1], 53);
    let len = dns_query(&f, DATA, "Example.com", 1);
    assert_eq!(f.ret(44, [udp, DATA, len, 0, DATA + 0x100, 16]), len);
    // The answer waits for the host.
    assert_eq!(
        f.ret(45, [udp, DATA + 0x400, 512, 0, 0, 0]),
        Errno::EAGAIN.to_syscall_return()
    );
    let (name, lookup) = f.host.lookups.lock().unwrap()[0].clone();
    assert_eq!(name, "example.com");
    lookup.finish(Ok(vec!["192.0.2.5".parse().unwrap()]));
    f.mem
        .write(GuestAddr(DATA + 0x80), &16u32.to_le_bytes())
        .unwrap();
    let n = f.ret(45, [udp, DATA + 0x400, 512, 0, DATA + 0x84, DATA + 0x80]);
    let mut answer = vec![0; n as usize];
    f.mem.read(GuestAddr(DATA + 0x400), &mut answer).unwrap();
    assert_eq!(&answer[..4], &[0xab, 0xcd, 0x81, 0x80]);
    assert_eq!(&answer[answer.len() - 4..], &[192, 0, 2, 5]);
    let mut from = [0; 8];
    f.mem.read(GuestAddr(DATA + 0x84), &mut from).unwrap();
    assert_eq!(from, [2, 0, 0, 53, 10, 0, 0, 1]);
    // The address it gave can be reached on the allowed port only.
    let tcp = f.ret(41, [2, 1 | 0x800, 0, 0, 0, 0]);
    inet_address(&f, DATA + 0x100, [192, 0, 2, 5], 80);
    assert_eq!(
        f.ret(42, [tcp, DATA + 0x100, 16, 0, 0, 0]),
        Errno(101).to_syscall_return()
    );
    inet_address(&f, DATA + 0x100, [192, 0, 2, 5], 443);
    assert_eq!(
        f.ret(42, [tcp, DATA + 0x100, 16, 0, 0, 0]),
        Errno(115).to_syscall_return()
    );
    // Another name is NXDOMAIN at once, without the host.
    inet_address(&f, DATA + 0x100, [10, 0, 0, 1], 53);
    let len = dns_query(&f, DATA, "other.org", 28);
    assert_eq!(f.ret(44, [udp, DATA, len, 0, DATA + 0x100, 16]), len);
    let n = f.ret(45, [udp, DATA + 0x400, 512, 0, 0, 0]);
    let mut answer = vec![0; n as usize];
    f.mem.read(GuestAddr(DATA + 0x400), &mut answer).unwrap();
    assert_eq!(answer[3] & 0xf, 3);
    assert_eq!(f.host.lookups.lock().unwrap().len(), 1);
    // Another UDP port is unreachable.
    inet_address(&f, DATA + 0x100, [10, 0, 0, 1], 54);
    assert_eq!(
        f.ret(44, [udp, DATA, len, 0, DATA + 0x100, 16]),
        Errno(101).to_syscall_return()
    );
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
    // SOL_SOCKET takes SCM_RIGHTS and SCM_CREDENTIALS only.
    let len = control(&f, CONTROL, 1, 3, &[r as u32, 0, 0]);
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
    // A stream sends its byte out of band.
    assert_eq!(send(&mut f, (0, 0), (0, 0), 1), 1);
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
fn socket_timeouts_end_blocking_calls_with_eagain() {
    let mut f = Fixture::new();
    let fail = |e: i32| Errno(e).to_syscall_return();
    let (a, b) = pair(&mut f, 53, [1, 1, 0, DATA, 0, 0]);
    let (value, len) = (NAME, NAME + 0x20);
    let set = |f: &mut Fixture, fd: u64, name: u64, seconds: i64, micros: i64| {
        f.mem
            .write(GuestAddr(value), &seconds.to_le_bytes())
            .unwrap();
        f.mem
            .write(GuestAddr(value + 8), &micros.to_le_bytes())
            .unwrap();
        f.ret(54, [fd, 1, name, value, 16, 0])
    };
    let get = |f: &mut Fixture, fd: u64, name: u64| {
        f.mem.write(GuestAddr(len), &16u32.to_le_bytes()).unwrap();
        assert_eq!(f.ret(55, [fd, 1, name, value, len, 0]), 0);
        let mut raw = [0; 16];
        f.mem.read(GuestAddr(value), &mut raw).unwrap();
        (
            i64::from_le_bytes(raw[..8].try_into().unwrap()),
            i64::from_le_bytes(raw[8..].try_into().unwrap()),
        )
    };
    // Kept in ticks, rounded up; microseconds outside a second are EDOM.
    assert_eq!(set(&mut f, b, 20, 1, 234_567), 0);
    assert_eq!(get(&mut f, b, 20), (1, 235_000));
    assert_eq!(set(&mut f, b, 20, 0, 1_000_000), fail(33));
    // Too long a timeout waits for ever, as MAX_SCHEDULE_TIMEOUT does.
    let most = i64::MAX / 1000 - 1;
    assert_eq!(set(&mut f, b, 20, most - 1, 0), 0);
    assert_eq!(get(&mut f, b, 20), (most - 1, 0));
    assert_eq!(set(&mut f, b, 20, most, 0), 0);
    assert_eq!(get(&mut f, b, 20), (0, 0));
    // A blocking read waits no longer than the timeout, and so does a
    // write into a full buffer, which gives what it sent.
    assert_eq!(set(&mut f, b, 20, 0, 200_000), 0);
    assert_eq!(f.ret(45, [b, IN, 8, 0, 0, 0]), fail(11));
    assert_eq!(f.ret(0, [b, IN, 8, 0, 0, 0]), fail(11));
    assert_eq!(set(&mut f, a, 21, 0, 200_000), 0);
    assert_eq!(get(&mut f, a, 21), (0, 200_000));
    // A negative timeout does not wait, and a zero one waits for ever.
    assert_eq!(set(&mut f, b, 66, -1, 0), 0);
    assert_eq!(get(&mut f, b, 66), (0, 0));
    assert_eq!(f.ret(45, [b, IN, 8, 0, 0, 0]), fail(11));
}
#[test]
fn socket_options_are_kept_as_linux_keeps_them() {
    let mut f = Fixture::new();
    let fail = |e: i32| Errno(e).to_syscall_return();
    let (a, b) = pair(&mut f, 53, [1, 0x801, 0, DATA, 0, 0]);
    let (value, len) = (NAME, NAME + 8);
    let set = |f: &mut Fixture, name: u64, v: i32, size: u64| {
        f.mem.write(GuestAddr(value), &v.to_le_bytes()).unwrap();
        f.ret(54, [a, 1, name, value, size, 0])
    };
    let get = |f: &mut Fixture, name: u64| {
        f.mem.write(GuestAddr(len), &4u32.to_le_bytes()).unwrap();
        let r = f.ret(55, [a, 1, name, value, len, 0]);
        (r, read_u32(f, value) as i32)
    };
    assert_eq!(get(&mut f, 3), (0, 1)); // SO_TYPE
    // SO_OOBINLINE takes any non-zero value as on.
    assert_eq!(set(&mut f, 10, 5, 4), 0);
    assert_eq!(get(&mut f, 10), (0, 1));
    // SO_SNDBUF doubles what it is given, and keeps a floor.
    assert_eq!(set(&mut f, 7, 50_000, 4), 0);
    assert_eq!(get(&mut f, 7), (0, 100_000));
    assert_eq!(set(&mut f, 7, 1, 4), 0);
    assert_eq!(get(&mut f, 7), (0, 4608));
    // SO_RCVLOWAT takes 0 as 1 and a negative value as INT_MAX, and
    // SO_PEEK_OFF any value.
    assert_eq!(set(&mut f, 18, 0, 4), 0);
    assert_eq!(get(&mut f, 18), (0, 1));
    assert_eq!(set(&mut f, 18, -5, 4), 0);
    assert_eq!(get(&mut f, 18), (0, i32::MAX));
    assert_eq!(get(&mut f, 42), (0, -1));
    assert_eq!(set(&mut f, 42, -2, 4), 0);
    assert_eq!(get(&mut f, 42), (0, -2));
    // Too short a value, another level, an option whose effect is not
    // modelled here, and an unknown one.
    assert_eq!(set(&mut f, 9, 1, 2), fail(22));
    assert_eq!(f.ret(54, [a, 6, 1, value, 4, 0]), fail(95));
    assert_eq!(set(&mut f, 34, 1, 4), fail(92));
    assert_eq!(set(&mut f, 999, 1, 4), fail(92));
    assert_eq!(get(&mut f, 999).0, fail(92));
    // F_SETOWN names a live process or group; F_GETOWN gives it back.
    assert_eq!(f.ret(72, [b, 9, 0, 0, 0, 0]), 0);
    assert_eq!(f.ret(72, [b, 8, 999_999, 0, 0, 0]), fail(3));
    let pid = u64::from(f.thread.state.pid);
    assert_eq!(f.ret(72, [b, 8, pid, 0, 0, 0]), 0);
    assert_eq!(f.ret(72, [b, 9, 0, 0, 0, 0]), pid);
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
    // Out of band, a stream sends a byte, and nothing is no byte to send.
    assert_eq!(f.ret(44, [a, BYTES, 0, 1, 0, 0]), fail(95));
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
