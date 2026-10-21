//! The fuzz test Host must bound legitimate blocking pipe reads as well as sleeps.
#[path = "../../../fuzz/fuzz_targets/support/syscall_host.rs"]
mod syscall_host;
use paludarium_cpu::{CpuState, reg};
use paludarium_host::{ClockId, Host, WaitOutcome, WaitToken};
use paludarium_kernel::{Kernel, Thread};
use paludarium_mmu::{AddressSpace, MappingKind, Prot};
use paludarium_types::{Errno, ExitReason, GuestAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[test]
fn empty_pipe_read_consumes_fuzz_wait_quota() {
    let host = Arc::new(syscall_host::BoundedHost::new());
    let cancel = Arc::new(AtomicBool::new(false));
    let mut kernel = Kernel::new(host.clone()).with_cancellation(cancel.clone());
    let mut mem = AddressSpace::new();
    mem.map(
        Some(GuestAddr(0x100000)),
        0x4000,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    let mut thread = Thread::new(1, CpuState::default());
    thread.cpu.gpr[reg::RAX] = 22;
    thread.cpu.gpr[reg::RDI] = 0x100000;
    kernel.handle(
        &mut thread,
        &mem,
        ExitReason::Syscall {
            rip: GuestAddr(0x1000),
        },
    );
    let mut descriptors = [0; 8];
    mem.read(GuestAddr(0x100000), &mut descriptors).unwrap();
    let reader = u32::from_le_bytes(descriptors[..4].try_into().unwrap());
    // A safety watchdog makes the old quota bypass fail quickly without leaving
    // a blocked test thread. Correct harness behavior finishes by virtual quota.
    let (finished, completion) = std::sync::mpsc::channel();
    let watchdog = std::thread::spawn(move || {
        if completion
            .recv_timeout(std::time::Duration::from_secs(1))
            .is_err()
        {
            cancel.store(true, Ordering::SeqCst);
        }
    });
    thread.cpu.gpr[reg::RAX] = 0;
    thread.cpu.gpr[reg::RDI] = u64::from(reader);
    thread.cpu.gpr[reg::RSI] = 0x100100;
    thread.cpu.gpr[reg::RDX] = 1;
    kernel.handle(
        &mut thread,
        &mem,
        ExitReason::Syscall {
            rip: GuestAddr(0x1000),
        },
    );
    finished.send(()).unwrap();
    watchdog.join().unwrap();
    assert_eq!(thread.cpu.gpr[reg::RAX], Errno(4).to_syscall_return());
    assert_eq!(
        host.wait_count(),
        65,
        "blocking ticket waits must use the fuzz quota"
    );
    assert_eq!(host.clock(ClockId::Monotonic), Ok(640_000_000));
}

#[test]
fn ticket_wait_advances_virtual_deadline() {
    let h = syscall_host::BoundedHost::new();
    assert_eq!(
        h.wait_on(
            &WaitToken::default(),
            0,
            Some((ClockId::Monotonic, 7)),
            &AtomicBool::new(false)
        ),
        Ok(WaitOutcome::Complete)
    );
    assert_eq!(h.clock(ClockId::Monotonic), Ok(7));
    assert_eq!(h.wait_count(), 1);
}
#[test]
fn ticket_wait_without_deadline_is_finite() {
    let h = syscall_host::BoundedHost::new();
    assert_eq!(
        h.wait_on(&WaitToken::default(), 0, None, &AtomicBool::new(false)),
        Ok(WaitOutcome::Complete)
    );
    assert_eq!(h.clock(ClockId::Monotonic), Ok(10_000_000));
}
#[test]
fn wake_before_wait_retains_ticket_without_quota() {
    let h = syscall_host::BoundedHost::new();
    let token = WaitToken::default();
    h.wake(&token);
    assert_eq!(
        h.wait_on(&token, 0, None, &AtomicBool::new(false)),
        Ok(WaitOutcome::Complete)
    );
    assert_eq!(h.wait_count(), 0);
}
#[test]
fn notification_is_visible_to_every_sampled_waiter() {
    let h = syscall_host::BoundedHost::new();
    let token = WaitToken::default();
    let first = token.value();
    let second = token.value();
    h.wake(&token);
    for expected in [first, second] {
        assert_eq!(
            h.wait_on(&token, expected, None, &AtomicBool::new(false)),
            Ok(WaitOutcome::Complete)
        );
    }
    assert_eq!(h.wait_count(), 0);
}
#[test]
fn cancellation_interrupts_before_virtual_wait() {
    let h = syscall_host::BoundedHost::new();
    assert_eq!(
        h.wait_on(&WaitToken::default(), 0, None, &AtomicBool::new(true)),
        Ok(WaitOutcome::Interrupted)
    );
    assert_eq!(h.wait_count(), 0);
}
#[test]
fn sleeps_and_ticket_waits_share_one_quota() {
    let h = syscall_host::BoundedHost::new();
    let cancel = AtomicBool::new(false);
    for _ in 0..32 {
        assert_eq!(
            h.wait_until(ClockId::Monotonic, 1, &cancel),
            Ok(WaitOutcome::Complete)
        );
        assert_eq!(
            h.wait_on(&WaitToken::default(), 0, None, &cancel),
            Ok(WaitOutcome::Complete)
        );
    }
    assert_eq!(
        h.wait_on(&WaitToken::default(), 0, None, &cancel),
        Ok(WaitOutcome::Interrupted)
    );
    assert_eq!(h.wait_count(), 65);
}
