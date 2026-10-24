#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::{Errno, GuestAddr, PAGE_SIZE};
const DATA: u64 = 0x600000;
mod fd {
    use super::*;
    #[test]
    fn pipe_pointer_fault() {
        let (mut k, mut t, m) = setup();
        m.write(GuestAddr(DATA), b"/dev/null\0").unwrap();
        let fd = syscall(&mut k, &mut t, &m, 2, [DATA, 0x80000, 0, 0, 0, 0]);
        assert!(fd < 1024);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 0, [fd, DATA + 64, 8, 0, 0, 0]),
            0
        );
        assert!(k.files.for_exec().descriptor(fd).is_err());
        assert_eq!(
            syscall(&mut k, &mut t, &m, 293, [1, 0, 0, 0, 0, 0]),
            Errno::EFAULT.to_syscall_return()
        );
    }
    #[test]
    fn pipe_invalid_flags() {
        let (mut k, mut t, m) = setup();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 293, [DATA, 1, 0, 0, 0, 0]),
            Errno::EINVAL.to_syscall_return()
        );
    }
    #[test]
    fn pipe_cloexec() {
        let (mut k, mut t, m) = setup();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 293, [DATA, 0x80000, 0, 0, 0, 0]),
            0
        );
        let fd = m.read_u64(GuestAddr(DATA)).unwrap() as u32;
        assert_eq!(
            syscall(&mut k, &mut t, &m, 72, [fd as u64, 1, 0, 0, 0, 0]),
            1
        );
        assert!(k.files.for_exec().descriptor(fd as u64).is_err());
        m.write(GuestAddr(DATA + 64), &1i32.to_le_bytes()).unwrap();
        assert_eq!(
            syscall(
                &mut k,
                &mut t,
                &m,
                16,
                [fd as u64, 0x5421, DATA + 64, 0, 0, 0]
            ),
            0
        );
        assert_eq!(
            k.files.descriptor(fd as u64).unwrap().file.flags() & 0x800,
            0x800
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 16, [fd as u64, 0x5421, 1, 0, 0, 0]),
            Errno::EFAULT.to_syscall_return()
        );
    }
    #[test]
    fn vector_table_fault() {
        let (mut k, mut t, m) = setup();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 20, [1, 1, 1, 0, 0, 0]),
            Errno::EFAULT.to_syscall_return()
        );
    }
    #[test]
    fn vector_count_and_total_limit() {
        let (mut k, mut t, m) = setup();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 20, [1, DATA, 1025, 0, 0, 0]),
            Errno::EINVAL.to_syscall_return()
        );
        m.write_u64(GuestAddr(DATA), DATA).unwrap();
        m.write_u64(GuestAddr(DATA + 8), 0x80000000).unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 20, [1, DATA, 1, 0, 0, 0]),
            Errno::EINVAL.to_syscall_return()
        );
    }
    #[test]
    fn vector_payload_fault() {
        let (mut k, mut t, m) = setup();
        m.write_u64(GuestAddr(DATA), 1).unwrap();
        m.write_u64(GuestAddr(DATA + 8), 1).unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 20, [1, DATA, 1, 0, 0, 0]),
            Errno::EFAULT.to_syscall_return()
        );
    }
    #[test]
    fn vector_concatenation() {
        let (mut k, mut t, m) = setup();
        m.write(GuestAddr(DATA + 64), b"abc").unwrap();
        for (offset, base, len) in [(0, DATA + 64, 1), (16, DATA + 65, 2)] {
            m.write_u64(GuestAddr(DATA + offset), base).unwrap();
            m.write_u64(GuestAddr(DATA + offset + 8), len).unwrap();
        }
        assert_eq!(syscall(&mut k, &mut t, &m, 20, [1, DATA, 2, 0, 0, 0]), 3);
    }
}
fn setup() -> (Kernel, Thread, AddressSpace) {
    let kernel = Kernel::new(Arc::new(paludarium_host::testing::RecordingHost::new()));
    let thread = Thread::new(
        1,
        CpuState::new(GuestAddr(0x400000), GuestAddr(DATA + PAGE_SIZE)),
    );
    let mem = AddressSpace::new();
    mem.map_shared(
        Some(GuestAddr(DATA)),
        PAGE_SIZE,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    (kernel, thread, mem)
}
fn syscall(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, n: u64, a: [u64; 6]) -> u64 {
    t.cpu.gpr[reg::RAX] = n;
    t.cpu.gpr[reg::RDI] = a[0];
    t.cpu.gpr[reg::RSI] = a[1];
    t.cpu.gpr[reg::RDX] = a[2];
    t.cpu.gpr[reg::R10] = a[3];
    t.cpu.gpr[reg::R8] = a[4];
    t.cpu.gpr[reg::R9] = a[5];
    k.handle(t, m, ExitReason::Syscall { rip: t.cpu.rip });
    t.cpu.gpr[reg::RAX]
}
fn fork(
    k: &mut Kernel,
    t: &mut Thread,
    m: &AddressSpace,
) -> (Box<Kernel>, Thread, Arc<AddressSpace>) {
    let pid = syscall(k, t, m, 57, [0; 6]);
    let (mut child, thread) = k.take_child().unwrap();
    assert_eq!(pid, u64::from(thread.tid));
    let memory = child.take_spawn_memory().unwrap();
    (child, thread, memory)
}
fn finish(k: &mut Kernel, t: &Thread, m: &AddressSpace, status: ExitStatus) {
    k.finish_thread(t, m);
    k.complete_process(status);
}
mod process {
    use super::*;
    #[test]
    fn unique_pid_tid() {
        let (mut k, mut t, m) = setup();
        let (_, a, _) = fork(&mut k, &mut t, &m);
        let (_, b, _) = fork(&mut k, &mut t, &m);
        assert_ne!(a.tid, b.tid);
        let id = syscall(&mut k, &mut t, &m, 56, [0x10900, 0, 0, 0, 0, 0]);
        assert_ne!(id, u64::from(a.tid));
        assert_ne!(id, u64::from(b.tid));
    }
    #[test]
    fn sessions_follow_setsid_and_bound_setpgid() {
        let (mut k, mut t, m) = setup();
        let eperm = Errno::EPERM.to_syscall_return();
        // The first process leads its group, in a session from outside.
        assert_eq!(syscall(&mut k, &mut t, &m, 124, [0; 6]), 0); // getsid
        assert_eq!(syscall(&mut k, &mut t, &m, 112, [0; 6]), eperm);
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let child = u64::from(ct.tid);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 124, [0; 6]), 0);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 112, [0; 6]), child);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 111, [0; 6]), child);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 124, [child, 0, 0, 0, 0, 0]),
            child
        );
        // A session leader stays in its group, and a group of another
        // session cannot be joined.
        assert_eq!(syscall(&mut c, &mut ct, &cm, 109, [0; 6]), eperm);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 109, [child, 1, 0, 0, 0, 0]),
            eperm
        );
        let (_, gt, _) = fork(&mut c, &mut ct, &cm);
        let member = u64::from(gt.tid);
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 124, [member, 0, 0, 0, 0, 0]),
            child
        );
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 109, [member, 1, 0, 0, 0, 0]),
            eperm
        );
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 109, [member, member, 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 109, [member, child, 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 124, [99, 0, 0, 0, 0, 0]),
            Errno(3).to_syscall_return()
        );
    }
    #[test]
    fn parent_registration() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 110, [0; 6]), 1);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [u64::MAX, 0, 1, 0, 0, 0]),
            0
        );
    }
    /// Sets `sig`'s handler through rt_sigaction and returns the old one.
    fn handler(
        k: &mut Kernel,
        t: &mut Thread,
        m: &AddressSpace,
        sig: u64,
        new: Option<u64>,
    ) -> u64 {
        let act = new.map_or(0, |handler| {
            m.write(GuestAddr(DATA + 64), &[0; 32]).unwrap();
            m.write_u64(GuestAddr(DATA + 64), handler).unwrap();
            DATA + 64
        });
        assert_eq!(syscall(k, t, m, 13, [sig, act, DATA + 128, 8, 0, 0]), 0);
        m.read_u64(GuestAddr(DATA + 128)).unwrap()
    }
    #[test]
    fn clone_sighand_shares_dispositions() {
        let (mut k, mut t, m) = setup();
        // CLONE_VM | CLONE_SIGHAND | SIGCHLD, without CLONE_THREAD.
        syscall(&mut k, &mut t, &m, 56, [0x900 | 17, 0, 0, 0, 0, 0]);
        let (mut c, mut ct) = k.take_child().unwrap();
        assert_ne!(c.process.pid, k.process.pid);
        assert_eq!(handler(&mut c, &mut ct, &m, 10, Some(0x1234)), 0);
        assert_eq!(handler(&mut k, &mut t, &m, 10, Some(0x5678)), 0x1234);
        assert_eq!(handler(&mut c, &mut ct, &m, 10, None), 0x5678);
        // A plain CLONE_VM child gets a copy.
        syscall(&mut k, &mut t, &m, 56, [0x100 | 17, 0, 0, 0, 0, 0]);
        let (mut d, mut dt) = k.take_child().unwrap();
        assert_eq!(handler(&mut d, &mut dt, &m, 10, Some(0x9abc)), 0x5678);
        assert_eq!(handler(&mut k, &mut t, &m, 10, None), 0x5678);
    }
    #[test]
    fn clone_ignores_the_high_flag_bits() {
        let (mut k, mut t, m) = setup();
        assert_eq!(handler(&mut k, &mut t, &m, 10, Some(0x1234)), 0);
        // Bit 33 is no clone flag, and bit 32 (CLONE_CLEAR_SIGHAND) only
        // exists for clone3.
        for flags in [1 << 33 | 17, 1 << 32 | 17] {
            let pid = syscall(&mut k, &mut t, &m, 56, [flags, 0, 0, 0, 0, 0]);
            let (mut c, mut ct) = k.take_child().unwrap();
            assert_eq!(pid, u64::from(ct.tid));
            let cm = c.take_spawn_memory().unwrap();
            assert_eq!(handler(&mut c, &mut ct, &cm, 10, None), 0x1234);
        }
        // A thread too: CLONE_VM | CLONE_SIGHAND | CLONE_THREAD.
        let tid = syscall(&mut k, &mut t, &m, 56, [1 << 40 | 0x10900, 0, 0, 0, 0, 0]);
        assert!(tid < 1 << 32, "{tid:#x}");
    }
    #[test]
    fn fork_inherits_the_descriptor_limit() {
        let (mut k, mut t, m) = setup();
        m.write_u64(GuestAddr(DATA), 3).unwrap();
        m.write_u64(GuestAddr(DATA + 8), 4096).unwrap();
        assert_eq!(syscall(&mut k, &mut t, &m, 160, [7, DATA, 0, 0, 0, 0]), 0);
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 32, [0; 6]),
            Errno::EMFILE.to_syscall_return()
        );
    }
    #[test]
    fn exit_group_isolated() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        syscall(&mut c, &mut ct, &cm, 231, [7, 0, 0, 0, 0, 0]);
        assert_eq!(k.group.status(), None);
        assert_eq!(c.group.status(), Some(ExitStatus::Exited(7)));
    }
    #[test]
    fn zombie_reaped_once() {
        let (mut k, mut t, m) = setup();
        let (mut c, ct, cm) = fork(&mut k, &mut t, &m);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(7));
        assert_eq!(
            syscall(
                &mut k,
                &mut t,
                &m,
                61,
                [u64::from(ct.tid), DATA, 0, 0, 0, 0]
            ),
            u64::from(ct.tid)
        );
        let mut status = [0; 4];
        m.read(GuestAddr(DATA), &mut status).unwrap();
        assert_eq!(i32::from_le_bytes(status), 7 << 8);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [u64::from(ct.tid), 0, 0, 0, 0, 0]),
            Errno(10).to_syscall_return()
        );
    }
    #[test]
    fn all_threads_before_zombie() {
        let (mut k, mut t, m) = setup();
        let (mut c, ct, cm) = fork(&mut k, &mut t, &m);
        c.group.register(42, Arc::new(SignalInbox::default()));
        finish(&mut c, &ct, &cm, ExitStatus::Exited(3));
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [u64::from(ct.tid), 0, 1, 0, 0, 0]),
            0
        );
        c.abandon_thread(42);
        c.complete_process(ExitStatus::Exited(3));
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [u64::from(ct.tid), 0, 1, 0, 0, 0]),
            u64::from(ct.tid)
        );
    }
    #[test]
    fn efault_consumes_and_invalid_options() {
        let (mut k, mut t, m) = setup();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [u64::MAX, 0, 16, 0, 0, 0]),
            Errno::EINVAL.to_syscall_return()
        );
        let (mut c, ct, cm) = fork(&mut k, &mut t, &m);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [u64::from(ct.tid), 1, 0, 0, 0, 0]),
            Errno::EFAULT.to_syscall_return()
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [u64::from(ct.tid), 0, 0, 0, 0, 0]),
            Errno(10).to_syscall_return()
        );
    }
    const EXITS: crate::processes::WaitFor = crate::processes::WaitFor {
        keep: false,
        exits: true,
        stops: false,
        continues: false,
    };
    /// Takes a pending SIGCHLD with rt_sigtimedwait (no wait) and returns
    /// its si_code, si_pid and si_status.
    fn take_sigchld(k: &mut Kernel, t: &mut Thread, m: &AddressSpace) -> (u64, [u32; 3]) {
        m.write(
            GuestAddr(DATA),
            &[1u64 << 16, 0, 0].map(u64::to_le_bytes).concat(),
        )
        .unwrap();
        let number = syscall(k, t, m, 128, [DATA, DATA + 64, DATA + 8, 8, 0, 0]);
        let word = |at: u64| m.read_u64(GuestAddr(DATA + 64 + at)).unwrap() as u32;
        (number, [word(8), word(16), word(24)])
    }
    #[test]
    fn sigchld_carries_the_child() {
        let (mut k, mut t, m) = setup();
        // Blocked, so a syscall's return does not discard it (SIG_DFL).
        m.write_u64(GuestAddr(DATA), 1 << 16).unwrap();
        syscall(&mut k, &mut t, &m, 14, [0, DATA, 0, 8, 0, 0]);
        let (mut c, ct, cm) = fork(&mut k, &mut t, &m);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(261));
        assert_eq!(take_sigchld(&mut k, &mut t, &m), (17, [1, ct.tid, 5]));
        let (mut c, ct, cm) = fork(&mut k, &mut t, &m);
        finish(&mut c, &ct, &cm, ExitStatus::Signaled(9));
        assert_eq!(take_sigchld(&mut k, &mut t, &m), (17, [2, ct.tid, 9]));
        // A stop and a continue, each with its CLD_* code.
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        syscall(&mut c, &mut ct, &cm, 62, [0, 19, 0, 0, 0, 0]);
        assert_eq!(take_sigchld(&mut k, &mut t, &m), (17, [5, ct.tid, 19]));
        syscall(&mut k, &mut t, &m, 62, [u64::from(ct.tid), 18, 0, 0, 0, 0]);
        assert_eq!(take_sigchld(&mut k, &mut t, &m), (17, [6, ct.tid, 18]));
        let none = Errno::EAGAIN.to_syscall_return();
        assert_eq!(take_sigchld(&mut k, &mut t, &m).0, none);
        // SA_NOCLDSTOP: a stop and a continue send none, an exit still does.
        m.write(
            GuestAddr(DATA + 256),
            &[0u64, 1, 0, 0].map(u64::to_le_bytes).concat(),
        )
        .unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 13, [17, DATA + 256, 0, 8, 0, 0]),
            0
        );
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        syscall(&mut c, &mut ct, &cm, 62, [0, 19, 0, 0, 0, 0]);
        assert_eq!(take_sigchld(&mut k, &mut t, &m).0, none);
        syscall(&mut k, &mut t, &m, 62, [u64::from(ct.tid), 18, 0, 0, 0, 0]);
        assert_eq!(take_sigchld(&mut k, &mut t, &m).0, none);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        assert_eq!(take_sigchld(&mut k, &mut t, &m), (17, [1, ct.tid, 0]));
    }
    #[test]
    fn stop_resumes_a_timed_futex_wait() {
        for changed in [false, true] {
            let (mut k, mut t, m) = setup();
            let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
            let pid = u64::from(ct.tid);
            cm.write_u64(GuestAddr(DATA), 7).unwrap();
            cm.write(
                GuestAddr(DATA + 64),
                &[1u64, 0].map(u64::to_le_bytes).concat(),
            )
            .unwrap();
            // FUTEX_WAIT_PRIVATE for 1 s, interrupted by a stop: rewound to
            // restart_syscall with the futex's deadline kept.
            assert_eq!(syscall(&mut k, &mut t, &m, 62, [pid, 19, 0, 0, 0, 0]), 0);
            ct.cpu.rip = GuestAddr(0x40_1002);
            assert_eq!(
                syscall(&mut c, &mut ct, &cm, 202, [DATA, 128, 7, DATA + 64, 0, 0]),
                219
            );
            assert_eq!(ct.cpu.rip, GuestAddr(0x40_1000));
            assert!(matches!(
                ct.state.restart_block,
                Some(crate::signals::RestartBlock::Futex { value: 7, .. })
            ));
            assert_eq!(syscall(&mut k, &mut t, &m, 62, [pid, 18, 0, 0, 0, 0]), 0);
            assert_eq!(c.checkpoint(&mut ct, &cm), Next::Resume);
            // Resumed, it rechecks the word (EAGAIN once it changed) and then
            // waits out the same deadline (ETIMEDOUT, nobody wakes it).
            if changed {
                cm.write_u64(GuestAddr(DATA), 8).unwrap();
            }
            let expected = if changed { Errno::EAGAIN } else { Errno(110) };
            assert_eq!(
                syscall(&mut c, &mut ct, &cm, 219, [0; 6]),
                expected.to_syscall_return()
            );
            assert!(ct.state.restart_block.is_none());
        }
    }
    #[test]
    fn stop_resumes_a_realtime_futex_bitset_wait() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let pid = u64::from(ct.tid);
        cm.write_u64(GuestAddr(DATA), 7).unwrap();
        // FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME until a second from
        // now on CLOCK_REALTIME: the block keeps that clock and deadline.
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 228, [0, DATA + 64, 0, 0, 0, 0]),
            0
        );
        let now = cm.read_u64(GuestAddr(DATA + 64)).unwrap();
        cm.write_u64(GuestAddr(DATA + 64), now + 1).unwrap();
        assert_eq!(syscall(&mut k, &mut t, &m, 62, [pid, 19, 0, 0, 0, 0]), 0);
        ct.cpu.rip = GuestAddr(0x40_1002);
        assert_eq!(
            syscall(
                &mut c,
                &mut ct,
                &cm,
                202,
                [DATA, 9 | 128 | 256, 7, DATA + 64, 0, u64::from(u32::MAX)]
            ),
            219
        );
        assert!(matches!(
            ct.state.restart_block,
            Some(crate::signals::RestartBlock::Futex {
                clock: paludarium_host::ClockId::Realtime,
                mask: u32::MAX,
                ..
            })
        ));
        assert_eq!(syscall(&mut k, &mut t, &m, 62, [pid, 18, 0, 0, 0, 0]), 0);
        assert_eq!(c.checkpoint(&mut ct, &cm), Next::Resume);
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 219, [0; 6]),
            Errno(110).to_syscall_return()
        );
    }
    #[test]
    fn stop_restarts_a_blocking_read() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 293, [DATA, 0, 0, 0, 0, 0]), 0);
        let fd = cm.read_u64(GuestAddr(DATA)).unwrap() & 0xffff_ffff;
        let pid = u64::from(ct.tid);
        // A read interrupted by a stop runs again after the continue: the
        // syscall instruction is re-executed with its number in rax.
        assert_eq!(syscall(&mut k, &mut t, &m, 62, [pid, 19, 0, 0, 0, 0]), 0);
        ct.cpu.rip = GuestAddr(0x40_1002);
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 0, [fd, DATA + 64, 1, 0, 0, 0]),
            0
        );
        assert_eq!(ct.cpu.rip, GuestAddr(0x40_1000));
        assert!(c.group.is_stopped());
        // A sleep resumes through restart_syscall with the deadline it had,
        // as Linux's restart block does: rewound with 219 in rax.
        assert_eq!(syscall(&mut k, &mut t, &m, 62, [pid, 18, 0, 0, 0, 0]), 0);
        assert_eq!(syscall(&mut k, &mut t, &m, 62, [pid, 19, 0, 0, 0, 0]), 0);
        cm.write(
            GuestAddr(DATA + 128),
            &[1u64, 0].map(u64::to_le_bytes).concat(),
        )
        .unwrap();
        ct.cpu.rip = GuestAddr(0x40_1002);
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 35, [DATA + 128, 0, 0, 0, 0, 0]),
            219
        );
        assert_eq!(ct.cpu.rip, GuestAddr(0x40_1000));
        assert!(ct.state.restart_block.is_some());
        // After the continue (whose checkpoint keeps the restart block) the
        // restarted call sleeps out the rest and ends.
        assert_eq!(syscall(&mut k, &mut t, &m, 62, [pid, 18, 0, 0, 0, 0]), 0);
        assert_eq!(c.checkpoint(&mut ct, &cm), Next::Resume);
        assert!(ct.state.restart_block.is_some());
        assert_eq!(syscall(&mut c, &mut ct, &cm, 219, [0; 6]), 0);
        assert!(ct.state.restart_block.is_none());
        // With no restart block left, restart_syscall is EINTR.
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 219, [0; 6]),
            Errno(4).to_syscall_return()
        );
    }
    #[test]
    fn stop_and_continue_reports() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let pid = u64::from(ct.tid);
        // The child stops itself; only WUNTRACED sees it, once.
        syscall(&mut c, &mut ct, &cm, 62, [0, 19, 0, 0, 0, 0]);
        assert!(c.group.is_stopped());
        assert_eq!(syscall(&mut k, &mut t, &m, 61, [pid, DATA, 1, 0, 0, 0]), 0);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [pid, DATA, 3, 0, 0, 0]),
            pid
        );
        assert_eq!(m.read_u64(GuestAddr(DATA)).unwrap() as u32, 0x137f);
        assert_eq!(syscall(&mut k, &mut t, &m, 61, [pid, DATA, 3, 0, 0, 0]), 0);
        // SIGCONT records a continue: WNOWAIT leaves it, CLD_CONTINUED.
        assert_eq!(syscall(&mut k, &mut t, &m, 62, [pid, 18, 0, 0, 0, 0]), 0);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 247, [1, pid, DATA, 0x0100_0009, 0, 0]),
            0
        );
        assert_eq!(m.read_u64(GuestAddr(DATA + 8)).unwrap() as u32, 6);
        assert_eq!(m.read_u64(GuestAddr(DATA + 24)).unwrap() as u32, 18);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [pid, DATA, 9, 0, 0, 0]),
            pid
        );
        assert_eq!(m.read_u64(GuestAddr(DATA)).unwrap() as u32, 0xffff);
        assert_eq!(syscall(&mut k, &mut t, &m, 61, [pid, DATA, 9, 0, 0, 0]), 0);
        // A continue of a running child is no event.
        assert_eq!(syscall(&mut k, &mut t, &m, 62, [pid, 18, 0, 0, 0, 0]), 0);
        assert_eq!(syscall(&mut k, &mut t, &m, 61, [pid, DATA, 9, 0, 0, 0]), 0);
    }
    #[test]
    fn racing_reapers() {
        let (mut k, mut t, m) = setup();
        let (mut c, ct, cm) = fork(&mut k, &mut t, &m);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        let processes = k.processes();
        let ids = std::thread::scope(|scope| {
            let a = processes.clone();
            let b = processes.clone();
            let first = scope.spawn(move || a.reap(1, crate::processes::Wanted::Any, EXITS));
            let second = scope.spawn(move || b.reap(1, crate::processes::Wanted::Any, EXITS));
            [first.join().unwrap(), second.join().unwrap()]
        });
        assert_eq!(
            ids.iter()
                .filter(|result| matches!(result, Ok(Some(_))))
                .count(),
            1
        );
        assert_eq!(
            ids.iter()
                .filter(|result| **result == Err(Errno(10)))
                .count(),
            1
        );
    }
}
fn exec_setup() -> (Kernel, Thread, AddressSpace) {
    let (mut k, t, m) = setup();
    let mut fs = paludarium_vfs::MemFs::new();
    fs.add_file(paludarium_vfs::GuestFile::new(
        "/child",
        paludarium_loader::testing::tiny_exec(&[0x90], b""),
    ))
    .unwrap();
    fs.add_file(paludarium_vfs::GuestFile::new("/bad", b"bad".to_vec()))
        .unwrap();
    k = k.with_file_system(Arc::new(fs));
    m.write(GuestAddr(DATA), b"/child\0").unwrap();
    (k, t, m)
}
mod exec {
    use super::*;
    #[test]
    fn argv_env_loaded() {
        let (mut k, mut t, m) = exec_setup();
        m.write(GuestAddr(DATA + 32), b"arg\0K=V\0").unwrap();
        m.write_u64(GuestAddr(DATA + 64), DATA + 32).unwrap();
        m.write_u64(GuestAddr(DATA + 80), DATA + 36).unwrap();
        assert_eq!(
            syscall(
                &mut k,
                &mut t,
                &m,
                59,
                [DATA, DATA + 64, DATA + 80, 0, 0, 0]
            ),
            0
        );
        let replacement = k.take_exec_memory().unwrap();
        assert_eq!(replacement.read_u64(GuestAddr(t.cpu.gpr[reg::RSP])), Ok(1));
    }
    #[test]
    fn missing_executable() {
        let (mut k, mut t, m) = exec_setup();
        m.write(GuestAddr(DATA), b"/absent\0").unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 59, [DATA, 0, 0, 0, 0, 0]),
            Errno::ENOENT.to_syscall_return()
        );
        assert!(k.take_exec_memory().is_none());
    }
    #[test]
    fn fault_vectors() {
        let (mut k, mut t, m) = exec_setup();
        for a in [
            [1, 0, 0, 0, 0, 0],
            [DATA, 1, 0, 0, 0, 0],
            [DATA, 0, 1, 0, 0, 0],
        ] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, 59, a),
                Errno::EFAULT.to_syscall_return()
            );
        }
    }
    #[test]
    fn invalid_elf() {
        let (mut k, mut t, m) = exec_setup();
        m.write(GuestAddr(DATA), b"/bad\0").unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 59, [DATA, 0, 0, 0, 0, 0]),
            Errno(8).to_syscall_return()
        );
        assert!(k.take_exec_memory().is_none());
    }
    #[test]
    fn closes_only_cloexec() {
        let (mut k, mut t, m) = exec_setup();
        assert_eq!(syscall(&mut k, &mut t, &m, 72, [1, 2, 1, 0, 0, 0]), 0);
        syscall(&mut k, &mut t, &m, 59, [DATA, 0, 0, 0, 0, 0]);
        assert!(k.files.descriptor(1).is_err());
        assert!(k.files.descriptor(2).is_ok());
    }
    #[test]
    fn failed_exec_preserves_state_and_fds() {
        let (mut k, mut t, m) = exec_setup();
        t.cpu.fs_base = 123;
        t.state.alt_stack.sp = 42;
        m.write(GuestAddr(DATA), b"/absent\0").unwrap();
        syscall(&mut k, &mut t, &m, 59, [DATA, 0, 0, 0, 0, 0]);
        assert_eq!(t.cpu.fs_base, 123);
        assert_eq!(t.state.alt_stack.sp, 42);
        assert!(k.files.descriptor(1).is_ok());
    }
    #[test]
    fn exec_unshares_clone_sighand_dispositions() {
        let (mut k, mut t, m) = exec_setup();
        let act = |handler: u64| {
            m.write(GuestAddr(DATA + 64), &[0; 32]).unwrap();
            m.write_u64(GuestAddr(DATA + 64), handler).unwrap();
        };
        act(0x1234);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 13, [10, DATA + 64, 0, 8, 0, 0]),
            0
        );
        act(1);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 13, [12, DATA + 64, 0, 8, 0, 0]),
            0
        );
        syscall(&mut k, &mut t, &m, 56, [0x900 | 17, 0, 0, 0, 0, 0]);
        let (mut c, mut ct) = k.take_child().unwrap();
        assert_eq!(syscall(&mut c, &mut ct, &m, 59, [DATA, 0, 0, 0, 0, 0]), 0);
        // The parent keeps its handler; the new image has the default, and
        // the ignored signal stays ignored.
        assert_eq!(
            k.group.shared_actions().lock().unwrap()[&10].handler,
            0x1234
        );
        assert!(!ct.state.signal_actions.contains_key(&10));
        assert_eq!(ct.state.signal_actions[&12].handler, 1);
        // Nor does the parent's change reach it any more.
        act(0x5678);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 13, [14, DATA + 64, 0, 8, 0, 0]),
            0
        );
        c.sync_actions(&mut ct);
        assert!(!ct.state.signal_actions.contains_key(&10));
        assert!(!ct.state.signal_actions.contains_key(&14));
    }
    #[test]
    fn tls_signals_reset_preserves_mask() {
        let (mut k, mut t, m) = exec_setup();
        t.cpu.fs_base = 123;
        t.state.signal_mask = 8;
        t.state.signal_actions.insert(
            10,
            SignalAction {
                handler: 123,
                ..SignalAction::default()
            },
        );
        t.state.signal_actions.insert(
            12,
            SignalAction {
                handler: 1,
                ..SignalAction::default()
            },
        );
        syscall(&mut k, &mut t, &m, 59, [DATA, 0, 0, 0, 0, 0]);
        assert_eq!(t.cpu.fs_base, 0);
        assert_eq!(t.state.signal_mask, 8);
        assert!(!t.state.signal_actions.contains_key(&10));
        assert_eq!(t.state.signal_actions[&12].handler, 1);
    }
}
