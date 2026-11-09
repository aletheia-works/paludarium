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
        // The first process's group and session are outside the emulator.
        assert_eq!(syscall(&mut k, &mut t, &m, 124, [0; 6]), 0); // getsid
        assert_eq!(syscall(&mut k, &mut t, &m, 111, [0; 6]), 0); // getpgrp
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
    fn nice_values_are_per_thread_and_inherited() {
        let (mut k, mut t, m) = setup();
        let get = |k: &mut Kernel, t: &mut Thread, which: u64, who: u64| {
            syscall(k, t, &m, 140, [which, who, 0, 0, 0, 0])
        };
        assert_eq!(get(&mut k, &mut t, 0, 0), 20);
        // The guest is root, so it may also lower its nice value.
        assert_eq!(
            syscall(&mut k, &mut t, &m, 141, [0, 0, (-5i64) as u64, 0, 0, 0]),
            0
        );
        assert_eq!(get(&mut k, &mut t, 0, 0), 25);
        let tid = syscall(&mut k, &mut t, &m, 56, [0x10900, 0, 0, 0, 0, 0]);
        let (mut thread_kernel, thread) = k.take_child().unwrap();
        assert_eq!(get(&mut k, &mut t, 0, tid), 25);
        assert_eq!(syscall(&mut k, &mut t, &m, 141, [0, tid, 7, 0, 0, 0]), 0);
        assert_eq!(
            (get(&mut k, &mut t, 0, tid), get(&mut k, &mut t, 0, 0)),
            (13, 25)
        );
        assert_eq!(get(&mut k, &mut t, 2, 0), 25); // PRIO_USER: the highest
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 140, [0; 6]), 25);
        // The thread's own value goes with it.
        thread_kernel.finish_thread(&thread, &m);
        assert_eq!(get(&mut k, &mut t, 0, tid), Errno(3).to_syscall_return());
        assert_eq!(syscall(&mut k, &mut t, &m, 141, [0, 0, 100, 0, 0, 0]), 0);
        assert_eq!(get(&mut k, &mut t, 0, 0), 1); // cut to 19
        assert_eq!(get(&mut k, &mut t, 3, 0), Errno::EINVAL.to_syscall_return());
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
        let own = u64::from(ct.tid);
        syscall(&mut c, &mut ct, &cm, 62, [own, 19, 0, 0, 0, 0]);
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
        let own = u64::from(ct.tid);
        syscall(&mut c, &mut ct, &cm, 62, [own, 19, 0, 0, 0, 0]);
        assert_eq!(take_sigchld(&mut k, &mut t, &m).0, none);
        syscall(&mut k, &mut t, &m, 62, [u64::from(ct.tid), 18, 0, 0, 0, 0]);
        assert_eq!(take_sigchld(&mut k, &mut t, &m).0, none);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        assert_eq!(take_sigchld(&mut k, &mut t, &m), (17, [1, ct.tid, 0]));
    }
    #[test]
    fn ignored_sigchld_reaps_children_at_once() {
        let (k, mut t, m) = setup();
        let mut k = k.with_task_limit(3);
        let none = Errno::EAGAIN.to_syscall_return();
        let echild = Errno(10).to_syscall_return();
        m.write_u64(GuestAddr(DATA), 1 << 16).unwrap();
        syscall(&mut k, &mut t, &m, 14, [0, DATA, 0, 8, 0, 0]);
        let action = |k: &mut Kernel, t: &mut Thread, handler: u64, flags: u64| {
            let bytes = [handler, flags, 0, 0].map(u64::to_le_bytes).concat();
            m.write(GuestAddr(DATA + 256), &bytes).unwrap();
            assert_eq!(syscall(k, t, &m, 13, [17, DATA + 256, 0, 8, 0, 0]), 0);
        };
        // A zombie from before SIGCHLD is ignored stays for a wait.
        let (mut z, zt, zm) = fork(&mut k, &mut t, &m);
        finish(&mut z, &zt, &zm, ExitStatus::Exited(5));
        assert_eq!(take_sigchld(&mut k, &mut t, &m).0, 17);
        action(&mut k, &mut t, 1, 0);
        // Ignored: the child is gone at its exit, with no SIGCHLD even while
        // blocked, and gives its task back.
        let (mut c, ct, cm) = fork(&mut k, &mut t, &m);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(3));
        assert_eq!(take_sigchld(&mut k, &mut t, &m).0, none);
        let child = u64::from(ct.tid);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [child, 0, 0, 0, 0, 0]),
            echild
        );
        let (mut c, ct, cm) = fork(&mut k, &mut t, &m);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(3));
        let zombie = u64::from(zt.tid);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [zombie, 0, 0, 0, 0, 0]),
            zombie
        );
        // SA_NOCLDWAIT with a handler: reaped as well, but SIGCHLD comes.
        action(&mut k, &mut t, 0x401000, 2);
        let (mut c, ct, cm) = fork(&mut k, &mut t, &m);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(4));
        assert_eq!(take_sigchld(&mut k, &mut t, &m), (17, [1, ct.tid, 4]));
        let child = u64::from(ct.tid);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [child, 0, 0, 0, 0, 0]),
            echild
        );
        // A child whose exit signal is not SIGCHLD is not reaped.
        action(&mut k, &mut t, 1, 0);
        let pid = syscall(&mut k, &mut t, &m, 56, [0; 6]);
        let (mut c, ct) = k.take_child().unwrap();
        let cm = c.take_spawn_memory().unwrap();
        finish(&mut c, &ct, &cm, ExitStatus::Exited(6));
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [pid, 0, 0x4000_0000, 0, 0, 0]),
            pid
        );
    }
    #[test]
    fn clone3_with_clone_newtime_keeps_the_exit_signal() {
        // CLONE_NEWTIME (0x80) is a bit of the exit signal in clone's
        // flags: the child of clone3 still has SIGCHLD, so a wait without
        // __WCLONE finds it.
        let (mut k, mut t, m) = setup();
        let words = [0x80u64, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0];
        m.write(GuestAddr(DATA + 512), &words.map(u64::to_le_bytes).concat())
            .unwrap();
        let pid = syscall(&mut k, &mut t, &m, 435, [DATA + 512, 88, 0, 0, 0, 0]);
        assert!(pid < 1 << 20, "{}", pid as i64);
        let (mut c, ct) = k.take_child().unwrap();
        let cm = c.take_spawn_memory().unwrap();
        finish(&mut c, &ct, &cm, ExitStatus::Exited(6));
        assert_eq!(syscall(&mut k, &mut t, &m, 61, [pid, 0, 0, 0, 0, 0]), pid);
    }
    #[test]
    fn orphans_go_to_the_first_process_or_the_nearest_subreaper() {
        let (mut k, mut t, m) = setup();
        let getppid =
            |k: &mut Kernel, t: &mut Thread, m: &AddressSpace| syscall(k, t, m, 110, [0; 6]);
        // Without a subreaper the first process adopts a grandchild.
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let (mut g, mut gt, gm) = fork(&mut c, &mut ct, &cm);
        assert_eq!(getppid(&mut g, &mut gt, &gm), u64::from(ct.tid));
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        assert_eq!(getppid(&mut g, &mut gt, &gm), 1);
        finish(&mut g, &gt, &gm, ExitStatus::Exited(7));
        let grandchild = u64::from(gt.tid);
        m.write_u64(GuestAddr(DATA + 8), 0).unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [grandchild, DATA + 8, 0, 0, 0, 0]),
            grandchild
        );
        assert_eq!(m.read_u64(GuestAddr(DATA + 8)).unwrap() >> 8 & 0xff, 7);
        // A subreaper adopts its descendants; its children do not inherit it.
        let (mut s, mut st, sm) = fork(&mut k, &mut t, &m);
        assert_eq!(syscall(&mut s, &mut st, &sm, 157, [36, 1, 0, 0, 0, 0]), 0);
        assert_eq!(
            syscall(&mut s, &mut st, &sm, 157, [37, DATA + 16, 0, 0, 0, 0]),
            0
        );
        assert_eq!(sm.read_u64(GuestAddr(DATA + 16)).unwrap() as u32, 1);
        let (mut c, mut ct, cm) = fork(&mut s, &mut st, &sm);
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 157, [37, DATA + 16, 0, 0, 0, 0]),
            0
        );
        assert_eq!(cm.read_u64(GuestAddr(DATA + 16)).unwrap() as u32, 0);
        let (mut g, mut gt, gm) = fork(&mut c, &mut ct, &cm);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        assert_eq!(getppid(&mut g, &mut gt, &gm), u64::from(st.tid));
        // An unset subreaper adopts nothing more.
        assert_eq!(syscall(&mut s, &mut st, &sm, 157, [36, 0, 0, 0, 0, 0]), 0);
        let (mut c, mut ct, cm) = fork(&mut s, &mut st, &sm);
        let (mut h, mut ht, hm) = fork(&mut c, &mut ct, &cm);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        assert_eq!(getppid(&mut h, &mut ht, &hm), 1);
    }
    #[test]
    fn an_orphaned_zombie_is_reported_to_its_new_parent() {
        let (mut k, mut t, m) = setup();
        m.write_u64(GuestAddr(DATA), 1 << 16).unwrap();
        syscall(&mut k, &mut t, &m, 14, [0, DATA, 0, 8, 0, 0]);
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let (mut g, gt, gm) = fork(&mut c, &mut ct, &cm);
        finish(&mut g, &gt, &gm, ExitStatus::Exited(9));
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        // SIGCHLD for the child, then for the zombie it left: one is kept
        // while the other is pending, so take them as they come.
        assert_eq!(take_sigchld(&mut k, &mut t, &m).0, 17);
        let grandchild = u64::from(gt.tid);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [grandchild, 0, 0, 0, 0, 0]),
            grandchild
        );
        // With SIGCHLD ignored the adopted zombie is reaped at once, and a
        // child created with another exit signal gets SIGCHLD on adoption.
        let bytes = [1u64, 0, 0, 0].map(u64::to_le_bytes).concat();
        m.write(GuestAddr(DATA + 256), &bytes).unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 13, [17, DATA + 256, 0, 8, 0, 0]),
            0
        );
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let (mut g, gt, gm) = fork(&mut c, &mut ct, &cm);
        let other = syscall(&mut c, &mut ct, &cm, 56, [0; 6]);
        let (mut o, ot) = c.take_child().unwrap();
        let om = o.take_spawn_memory().unwrap();
        finish(&mut g, &gt, &gm, ExitStatus::Exited(9));
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        let echild = Errno(10).to_syscall_return();
        let grandchild = u64::from(gt.tid);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [grandchild, 0, 0, 0, 0, 0]),
            echild
        );
        finish(&mut o, &ot, &om, ExitStatus::Exited(0));
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [other, 0, 0x4000_0000, 0, 0, 0]),
            echild
        );
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
    fn sa_restart_handler_restarts_only_errestartsys_calls() {
        // A handler with SA_RESTART leaves a frame that runs read and recv
        // again (rax back to the number, rip at the syscall instruction),
        // as Linux restarts ERESTARTSYS; pause (ERESTARTNOHAND) and a call
        // whose handler lacks SA_RESTART return EINTR.
        for (number, restart, restarted) in [
            (0, true, true),
            (45, true, true),
            (0, false, false),
            (34, true, false),
        ] {
            let (mut k, mut t, m) = setup();
            let pair = if number == 45 { 53 } else { 293 };
            let args = if number == 45 {
                [1, 1, 0, DATA, 0, 0]
            } else {
                [DATA, 0, 0, 0, 0, 0]
            };
            assert_eq!(syscall(&mut k, &mut t, &m, pair, args), 0);
            let fd = m.read_u64(GuestAddr(DATA)).unwrap() & 0xffff_ffff;
            t.state.signal_actions.insert(
                10,
                crate::SignalAction {
                    handler: 0x40_2000,
                    flags: 0x0400_0000 | if restart { 0x1000_0000 } else { 0 },
                    restorer: 0x40_3000,
                    mask: 0,
                },
            );
            k.queue_signal(&mut t, 10).unwrap();
            t.cpu.rip = GuestAddr(0x40_1002);
            syscall(&mut k, &mut t, &m, number, [fd, DATA + 64, 1, 0, 0, 0]);
            assert_eq!(t.cpu.rip, GuestAddr(0x40_2000));
            let saved = &t.state.frames.last().unwrap().cpu;
            assert_eq!(
                (saved.rip, saved.gpr[reg::RAX]),
                if restarted {
                    (GuestAddr(0x40_1000), number)
                } else {
                    (GuestAddr(0x40_1002), Errno(4).to_syscall_return())
                },
                "{number} {restart}"
            );
        }
    }
    #[test]
    fn stop_and_continue_reports() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let pid = u64::from(ct.tid);
        // The child stops itself; only WUNTRACED sees it, once.
        syscall(&mut c, &mut ct, &cm, 62, [pid, 19, 0, 0, 0, 0]);
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
    fn child_changes_wake_the_waits_for_a_child() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let pid = u64::from(ct.tid);
        let processes = k.processes();
        let mut ticket = processes.changed().value();
        // A stop, a continue, any other signal sent with kill (which may
        // interrupt a wait) and the exit each notify the waits.
        for signal in [19, 18, 17] {
            syscall(&mut c, &mut ct, &cm, 62, [pid, signal, 0, 0, 0, 0]);
            assert_ne!(processes.changed().value(), ticket, "signal {signal}");
            ticket = processes.changed().value();
        }
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        assert_ne!(processes.changed().value(), ticket);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [pid, DATA, 0, 0, 0, 0]),
            pid
        );
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
mod limit_permissions {
    use super::*;
    fn become_user(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, uid: u64) {
        assert_eq!(syscall(k, t, m, 117, [uid, uid, uid, 0, 0, 0]), 0);
    }
    /// `prlimit64(pid, RLIMIT_NOFILE, {soft, hard}, NULL)`.
    fn set_limit(
        k: &mut Kernel,
        t: &mut Thread,
        m: &AddressSpace,
        pid: u64,
        limit: [u64; 2],
    ) -> u64 {
        m.write_u64(GuestAddr(DATA), limit[0]).unwrap();
        m.write_u64(GuestAddr(DATA + 8), limit[1]).unwrap();
        syscall(k, t, m, 302, [pid, 7, DATA, 0, 0, 0])
    }
    fn set_nice(
        k: &mut Kernel,
        t: &mut Thread,
        m: &AddressSpace,
        which: u64,
        who: u64,
        nice: i64,
    ) -> u64 {
        syscall(k, t, m, 141, [which, who, nice as u64, 0, 0, 0])
    }
    #[test]
    fn a_hard_limit_goes_up_only_with_cap_sys_resource() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        become_user(&mut c, &mut ct, &cm, 2000);
        let eperm = Errno::EPERM.to_syscall_return();
        assert_eq!(set_limit(&mut c, &mut ct, &cm, 0, [512, 2048]), 0);
        assert_eq!(set_limit(&mut c, &mut ct, &cm, 0, [2048, 2048]), 0);
        assert_eq!(set_limit(&mut c, &mut ct, &cm, 0, [1024, 2049]), eperm);
        // A soft limit above the hard one is refused for that first.
        assert_eq!(
            set_limit(&mut c, &mut ct, &cm, 0, [2050, 2049]),
            Errno::EINVAL.to_syscall_return()
        );
        assert_eq!(set_limit(&mut k, &mut t, &m, 0, [1024, 8192]), 0);
    }
    #[test]
    fn another_process_limits_need_its_ids_before_anything_else() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let target = u64::from(ct.tid);
        become_user(&mut c, &mut ct, &cm, 3000);
        let (mut s, mut st, sm) = fork(&mut k, &mut t, &m);
        become_user(&mut s, &mut st, &sm, 2000);
        let eperm = Errno::EPERM.to_syscall_return();
        assert_eq!(set_limit(&mut s, &mut st, &sm, target, [256, 1024]), eperm);
        assert_eq!(
            syscall(&mut s, &mut st, &sm, 302, [target, 7, 0, DATA, 0, 0]),
            eperm
        );
        assert_eq!(
            syscall(&mut s, &mut st, &sm, 302, [target, 99, 0, DATA, 0, 0]),
            eperm
        );
        assert_eq!(
            syscall(&mut s, &mut st, &sm, 302, [0, 99, 0, DATA, 0, 0]),
            Errno::EINVAL.to_syscall_return()
        );
        assert_eq!(set_limit(&mut k, &mut t, &m, target, [256, 1024]), 0);
    }
    #[test]
    fn a_thread_id_names_its_process_and_its_own_ids() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let leader = u64::from(ct.tid);
        let tid = syscall(&mut c, &mut ct, &cm, 56, [0x10900, 0, 0, 0, 0, 0]);
        let (mut w, mut wt) = c.take_child().unwrap();
        become_user(&mut w, &mut wt, &cm, 2000);
        let (mut s, mut st, sm) = fork(&mut k, &mut t, &m);
        become_user(&mut s, &mut st, &sm, 2000);
        let eperm = Errno::EPERM.to_syscall_return();
        assert_eq!(
            syscall(&mut s, &mut st, &sm, 302, [tid, 7, 0, DATA, 0, 0]),
            0
        );
        assert_eq!(
            syscall(&mut s, &mut st, &sm, 302, [leader, 7, 0, DATA, 0, 0]),
            eperm
        );
        // The thread by its own ID is itself; by the leader's it is not.
        assert_eq!(
            syscall(&mut w, &mut wt, &cm, 302, [tid, 7, 0, DATA, 0, 0]),
            0
        );
        assert_eq!(
            syscall(&mut w, &mut wt, &cm, 302, [leader, 7, 0, DATA, 0, 0]),
            eperm
        );
        assert_eq!(set_nice(&mut s, &mut st, &sm, 0, tid, 3), 0);
        assert_eq!(set_nice(&mut s, &mut st, &sm, 0, leader, 3), eperm);
    }
    #[test]
    fn lowering_nice_needs_room_in_the_targets_limit_or_cap_sys_nice() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let target = u64::from(ct.tid);
        become_user(&mut c, &mut ct, &cm, 2000);
        let (mut s, mut st, sm) = fork(&mut k, &mut t, &m);
        become_user(&mut s, &mut st, &sm, 2000);
        let eacces = Errno::EACCES.to_syscall_return();
        assert_eq!(set_nice(&mut s, &mut st, &sm, 0, target, 5), 0);
        assert_eq!(set_nice(&mut s, &mut st, &sm, 0, target, 5), 0);
        assert_eq!(set_nice(&mut s, &mut st, &sm, 0, target, 4), eacces);
        // RLIMIT_NICE 30 of the target allows nice -10, whatever the sender's.
        m.write_u64(GuestAddr(DATA), 30).unwrap();
        m.write_u64(GuestAddr(DATA + 8), 30).unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 302, [target, 13, DATA, 0, 0, 0]),
            0
        );
        assert_eq!(set_nice(&mut s, &mut st, &sm, 0, target, -10), 0);
        assert_eq!(set_nice(&mut s, &mut st, &sm, 0, target, -11), eacces);
        assert_eq!(set_nice(&mut k, &mut t, &m, 0, target, -20), 0);
    }
    #[test]
    fn prio_user_finds_the_real_user_id_and_a_refusal_wins() {
        let (mut k, mut t, m) = setup();
        let (mut a, mut at, am) = fork(&mut k, &mut t, &m);
        become_user(&mut a, &mut at, &am, 2000);
        let (mut b, mut bt, bm) = fork(&mut k, &mut t, &m);
        // Effective 2000, real 3000: not user 2000.
        assert_eq!(
            syscall(&mut b, &mut bt, &bm, 117, [3000, 2000, 3000, 0, 0, 0]),
            0
        );
        let (a_id, b_id) = (u64::from(at.tid), u64::from(bt.tid));
        assert_eq!(set_nice(&mut k, &mut t, &m, 2, 2000, 5), 0);
        assert_eq!(syscall(&mut k, &mut t, &m, 140, [0, a_id, 0, 0, 0, 0]), 15);
        assert_eq!(syscall(&mut k, &mut t, &m, 140, [0, b_id, 0, 0, 0, 0]), 20);
        assert_eq!(
            set_nice(&mut k, &mut t, &m, 2, 4000, 5),
            Errno(3).to_syscall_return()
        );
        // Who 0 is the caller's real user ID.
        assert_eq!(syscall(&mut a, &mut at, &am, 140, [2, 0, 0, 0, 0, 0]), 15);
        // In one group, the thread it may change changes though another refuses.
        let (mut o, mut ot, om) = fork(&mut k, &mut t, &m);
        become_user(&mut o, &mut ot, &om, 4000);
        let other = u64::from(ot.tid);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 109, [a_id, a_id, 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 109, [other, a_id, 0, 0, 0, 0]),
            0
        );
        let (mut s, mut st, sm) = fork(&mut k, &mut t, &m);
        become_user(&mut s, &mut st, &sm, 2000);
        assert_eq!(
            set_nice(&mut s, &mut st, &sm, 1, a_id, 7),
            Errno::EPERM.to_syscall_return()
        );
        assert_eq!(syscall(&mut k, &mut t, &m, 140, [0, a_id, 0, 0, 0, 0]), 13);
        assert_eq!(syscall(&mut k, &mut t, &m, 140, [0, other, 0, 0, 0, 0]), 20);
        // The refusal stands though a later thread changes.
        assert_eq!(
            set_nice(&mut o, &mut ot, &om, 1, a_id, 9),
            Errno::EPERM.to_syscall_return()
        );
        assert_eq!(syscall(&mut k, &mut t, &m, 140, [0, other, 0, 0, 0, 0]), 11);
    }
}
mod signal_permissions {
    use super::*;
    /// `setresuid` for thread `t`.
    fn become_user(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, uid: u64) {
        assert_eq!(syscall(k, t, m, 117, [uid, uid, uid, 0, 0, 0]), 0);
    }
    #[test]
    fn a_process_of_another_user_refuses_its_signal() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let child = u64::from(ct.tid);
        become_user(&mut c, &mut ct, &cm, 3000);
        let (mut s, mut st, sm) = fork(&mut k, &mut t, &m);
        become_user(&mut s, &mut st, &sm, 2000);
        let eperm = Errno::EPERM.to_syscall_return();
        assert_eq!(
            syscall(&mut s, &mut st, &sm, 62, [child, 0, 0, 0, 0, 0]),
            eperm
        );
        // An invalid signal is refused for that first.
        assert_eq!(
            syscall(&mut s, &mut st, &sm, 62, [child, 65, 0, 0, 0, 0]),
            Errno::EINVAL.to_syscall_return()
        );
        // Its session lets SIGCONT through, and root may send anything.
        assert_eq!(
            syscall(&mut s, &mut st, &sm, 62, [child, 18, 0, 0, 0, 0]),
            0
        );
        assert_eq!(syscall(&mut k, &mut t, &m, 62, [child, 0, 0, 0, 0, 0]), 0);
        // A process of the same user may, through an ID `setresuid` recorded
        // and a `fork` passed on.
        let (mut o, mut ot, om) = fork(&mut c, &mut ct, &cm);
        assert_eq!(syscall(&mut o, &mut ot, &om, 62, [child, 0, 0, 0, 0, 0]), 0);
        let forked = u64::from(ot.tid);
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 62, [forked, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            syscall(&mut s, &mut st, &sm, 62, [forked, 0, 0, 0, 0, 0]),
            eperm
        );
        // Its own process, whoever that is.
        let own = u64::from(st.tid);
        assert_eq!(syscall(&mut s, &mut st, &sm, 62, [own, 0, 0, 0, 0, 0]), 0);
    }
    #[test]
    fn exec_records_the_ids_it_gives() {
        let (mut k, mut t, m) = exec_setup();
        k.files
            .fs
            .set_owner(b"/child", true, Some(3000), None)
            .unwrap();
        k.files.fs.set_mode(b"/child", 0o4755).unwrap();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let child = u64::from(ct.tid);
        become_user(&mut c, &mut ct, &cm, 2000);
        let (mut s, mut st, sm) = fork(&mut k, &mut t, &m);
        become_user(&mut s, &mut st, &sm, 3000);
        let eperm = Errno::EPERM.to_syscall_return();
        assert_eq!(
            syscall(&mut s, &mut st, &sm, 62, [child, 0, 0, 0, 0, 0]),
            eperm
        );
        // The set-user-ID program's owner is now the saved ID.
        cm.write(GuestAddr(DATA), b"/child\0").unwrap();
        assert_eq!(syscall(&mut c, &mut ct, &cm, 59, [DATA, 0, 0, 0, 0, 0]), 0);
        assert_eq!(syscall(&mut s, &mut st, &sm, 62, [child, 0, 0, 0, 0, 0]), 0);
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
    fn exec_applies_the_layout_flags_of_the_personality() {
        // ADDR_COMPAT_LAYOUT: mappings go up from TASK_UNMAPPED_BASE.
        let (mut k, mut t, m) = exec_setup();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 135, [0x20_0000, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(syscall(&mut k, &mut t, &m, 59, [DATA, 0, 0, 0, 0, 0]), 0);
        let em = k.take_exec_memory().unwrap();
        assert_eq!(em.bottom_up(), Some(0x2aaa_aaaa_b000));
        let first = syscall(&mut k, &mut t, &em, 9, [0, 4096, 3, 0x22, u64::MAX, 0]);
        let second = syscall(&mut k, &mut t, &em, 9, [0, 4096, 3, 0x22, u64::MAX, 0]);
        assert_eq!((first, second), (0x2aaa_aaaa_b000, 0x2aaa_aaaa_c000));
        // The flag stays for the next exec; without it, top-down again.
        assert_eq!(
            syscall(&mut k, &mut t, &em, 135, [0, 0, 0, 0, 0, 0]),
            0x20_0000
        );
        em.map_shared(
            Some(GuestAddr(DATA)),
            PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        em.write(GuestAddr(DATA), b"/child\0").unwrap();
        assert_eq!(syscall(&mut k, &mut t, &em, 59, [DATA, 0, 0, 0, 0, 0]), 0);
        assert_eq!(k.take_exec_memory().unwrap().bottom_up(), None);
        // MMAP_PAGE_ZERO: page 0, read and execute, for root.
        let (mut k, mut t, m) = exec_setup();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 135, [0x10_0000, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(syscall(&mut k, &mut t, &m, 59, [DATA, 0, 0, 0, 0, 0]), 0);
        let em = k.take_exec_memory().unwrap();
        let zero = em.mappings().find(|mapping| mapping.start.0 == 0).unwrap();
        assert_eq!(
            (zero.length, zero.prot),
            (4096, Prot::READ.union(Prot::EXEC))
        );
        // A user without CAP_SYS_RAWIO gets none.
        let (mut k, mut t, m) = exec_setup();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 117, [1000, 1000, 1000, 0, 0, 0]),
            0
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 135, [0x10_0000, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(syscall(&mut k, &mut t, &m, 59, [DATA, 0, 0, 0, 0, 0]), 0);
        let em = k.take_exec_memory().unwrap();
        assert!(em.mappings().all(|mapping| mapping.start.0 != 0));
    }
    #[test]
    fn scheduling_attributes_pass_to_children_as_sched_fork_has_them() {
        let (mut k, mut t, m) = setup();
        k.group.register(1, Arc::new(SignalInbox::default()));
        let attributes = |k: &mut Kernel, t: &mut Thread, m: &AddressSpace| {
            let policy = syscall(k, t, m, 145, [0; 6]);
            assert_eq!(syscall(k, t, m, 143, [0, DATA, 0, 0, 0, 0]), 0);
            (
                policy,
                m.read_value(GuestAddr(DATA), 4).unwrap(),
                syscall(k, t, m, 140, [0; 6]),
            )
        };
        // SCHED_FIFO 5 and nice -5 pass on.
        m.write(GuestAddr(DATA + 0x80), &5u32.to_le_bytes())
            .unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 141, [0, 0, (-5i64) as u64, 0, 0, 0]),
            0
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 144, [0, 1, DATA + 0x80, 0, 0, 0]),
            0
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 251, [1, 0, 3 << 13, 0, 0, 0]),
            0
        );
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        assert_eq!(attributes(&mut c, &mut ct, &cm), (1, 5, 25));
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 252, [1, 0, 0, 0, 0, 0]),
            3 << 13
        );
        // With SCHED_RESET_ON_FORK the child is a normal task with nice 0,
        // and the flag is gone.
        assert_eq!(
            syscall(
                &mut k,
                &mut t,
                &m,
                144,
                [0, 0x4000_0001, DATA + 0x80, 0, 0, 0]
            ),
            0
        );
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        assert_eq!(attributes(&mut c, &mut ct, &cm), (0, 0, 20));
        assert_eq!(attributes(&mut k, &mut t, &m), (0x4000_0001, 5, 25));
        // A priority of the class none does not pass on.
        assert_eq!(syscall(&mut k, &mut t, &m, 251, [1, 0, 0, 0, 0, 0]), 0);
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 252, [1, 0, 0, 0, 0, 0]), 0);
        assert_eq!(syscall(&mut k, &mut t, &m, 252, [1, 0, 0, 0, 0, 0]), 0);
    }
    /// `load_script`'s view of a first line.
    fn parsed(line: &[u8]) -> Result<Option<crate::processes::Script>, Errno> {
        let mut head = [0; 256];
        head[..line.len()].copy_from_slice(line);
        crate::processes::script_interpreter(&head)
    }
    #[test]
    fn a_first_line_names_an_interpreter_and_one_argument() {
        const ENOEXEC: Errno = Errno(8);
        let some = |name: &[u8], argument: Option<&[u8]>| {
            Ok(Some((name.to_vec(), argument.map(<[u8]>::to_vec))))
        };
        assert_eq!(parsed(b"#!/i\nrest"), some(b"/i", None));
        assert_eq!(parsed(b"#! \t/i\t a  b \t\n"), some(b"/i", Some(b"a  b")));
        assert_eq!(parsed(b"#!/i"), some(b"/i", None));
        assert_eq!(parsed(b"#!/i a"), some(b"/i", Some(b"a")));
        // Past the blanks a line with no newline has the rest of the buffer.
        assert_eq!(parsed(b"#!/i  "), some(b"/i", Some(b"")));
        assert_eq!(parsed(b"#!/i\0 a\n"), some(b"/i", None));
        assert_eq!(parsed(b"#!/i a\0b\n"), some(b"/i", Some(b"a")));
        assert_eq!(parsed(b"#!/i\r\n"), some(b"/i\r", None));
        // No name, or none it can tell is whole.
        assert_eq!(parsed(b"#!\n"), Err(ENOEXEC));
        assert_eq!(parsed(b"#!  \t\n"), Err(ENOEXEC));
        assert_eq!(parsed(b"#!"), some(b"", None));
        assert_eq!(parsed(&[b' '; 256][..]), Ok(None));
        let mut blanks = [b' '; 256];
        blanks[..2].copy_from_slice(b"#!");
        assert_eq!(parsed(&blanks), Err(ENOEXEC));
        let mut name = [b'x'; 256];
        name[..2].copy_from_slice(b"#!");
        assert_eq!(parsed(&name), Err(ENOEXEC));
        // The last byte of the buffer does not count, even a newline there.
        let mut cut = [b'x'; 256];
        cut[..5].copy_from_slice(b"#!/i ");
        cut[255] = b'\n';
        let (_, argument) = parsed(&cut).unwrap().unwrap();
        assert_eq!(argument.unwrap().len(), 250);
        // ... nor a terminator there.
        let mut last = [b'x'; 256];
        last[..2].copy_from_slice(b"#!");
        last[255] = b' ';
        assert_eq!(parsed(&last), Err(ENOEXEC));
        // Anything else is no script.
        assert_eq!(parsed(b"#"), Ok(None));
        assert_eq!(parsed(b""), Ok(None));
        assert_eq!(parsed(b"!#/i\n"), Ok(None));
    }
    /// `exec_setup` with these files, executable.
    fn with_scripts(files: &[(&str, &[u8])]) -> (Kernel, Thread, AddressSpace) {
        let (mut k, t, m) = setup();
        let mut fs = paludarium_vfs::MemFs::new();
        fs.add_file(paludarium_vfs::GuestFile::new(
            "/child",
            paludarium_loader::testing::tiny_exec(&[0x90], b""),
        ))
        .unwrap();
        for (name, bytes) in files {
            fs.add_file(paludarium_vfs::GuestFile::new(*name, bytes.to_vec()))
                .unwrap();
        }
        k = k.with_file_system(Arc::new(fs));
        (k, t, m)
    }
    fn run(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, path: &[u8]) -> u64 {
        let mut name = path.to_vec();
        name.push(0);
        m.write(GuestAddr(DATA), &name).unwrap();
        syscall(k, t, m, 59, [DATA, 0, 0, 0, 0, 0])
    }
    /// Reads the strings of the new image's stack: argc, then argv.
    fn arguments(k: &mut Kernel) -> Vec<Vec<u8>> {
        let memory = k.take_exec_memory().expect("an image");
        let sp = k.group.start_stack();
        let argc = memory.read_u64(GuestAddr(sp)).unwrap();
        (0..argc)
            .map(|i| {
                let mut at = memory.read_u64(GuestAddr(sp + 8 + 8 * i)).unwrap();
                let mut string = Vec::new();
                loop {
                    let mut byte = [0];
                    memory.read(GuestAddr(at), &mut byte).unwrap();
                    if byte[0] == 0 {
                        return string;
                    }
                    string.push(byte[0]);
                    at += 1;
                }
            })
            .collect()
    }
    /// A program that asks for the interpreter `path`.
    fn asks_for(path: &[u8]) -> Vec<u8> {
        let mut image = paludarium_loader::testing::tiny_exec(&[0x90], b"");
        // Turn its data segment's header into a PT_INTERP that names `path`,
        // at the end of the file.
        let offset = image.len() as u64;
        image.extend_from_slice(path);
        let header = 64 + 56;
        image[header..header + 4].copy_from_slice(&3u32.to_le_bytes());
        image[header + 8..header + 16].copy_from_slice(&offset.to_le_bytes());
        let size = (path.len() as u64).to_le_bytes();
        image[header + 32..header + 40].copy_from_slice(&size);
        image[header + 40..header + 48].copy_from_slice(&size);
        image
    }
    /// Opens `path` with `flags` in `k`, as `open(2)` does.
    fn open(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, path: &[u8], flags: u64) -> u64 {
        let mut name = path.to_vec();
        name.push(0);
        m.write(GuestAddr(DATA + 0x200), &name).unwrap();
        syscall(k, t, m, 2, [DATA + 0x200, flags, 0o755, 0, 0, 0])
    }
    #[test]
    fn exec_and_writers_refuse_each_other_with_etxtbsy() {
        let mut linker = paludarium_loader::testing::tiny_exec(&[0x90], b"");
        linker[16] = 3;
        let via_ld = asks_for(b"/ld\0");
        let (mut k, mut t, m) = with_scripts(&[
            ("/ok", &via_ld),
            ("/ld", &linker),
            ("/script", b"#!/child\n"),
        ]);
        let busy = Errno(26).to_syscall_return();
        let close = |k: &mut Kernel, t: &mut Thread, fd: u64| {
            assert_eq!(syscall(k, t, &m, 3, [fd, 0, 0, 0, 0, 0]), 0);
        };
        // A description open for writing refuses the exec of its file, of a
        // script whose interpreter it is, and of a program whose ELF
        // interpreter it is (`do_open_execat`, `open_exec`).
        for (written, runs) in [
            (&b"/child"[..], &b"/child"[..]),
            (b"/child", b"/script"),
            (b"/script", b"/script"),
            (b"/ld", b"/ok"),
        ] {
            let fd = open(&mut k, &mut t, &m, written, 2);
            assert!(fd < 1024, "{fd:#x}");
            assert_eq!(run(&mut k, &mut t, &m, runs), busy);
            close(&mut k, &mut t, fd);
        }
        // A running program's file is not opened for writing, truncated by
        // an open, or by `truncate`; read, it is.
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        assert_eq!(run(&mut c, &mut ct, &cm, b"/child"), 0);
        assert_eq!(open(&mut k, &mut t, &m, b"/child", 1), busy);
        assert_eq!(open(&mut k, &mut t, &m, b"/child", 0o1000), busy);
        m.write(GuestAddr(DATA + 0x200), b"/child\0").unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 76, [DATA + 0x200, 0, 0, 0, 0, 0]),
            busy
        );
        let fd = open(&mut k, &mut t, &m, b"/child", 0);
        assert!(fd < 1024, "{fd:#x}");
        close(&mut k, &mut t, fd);
        // An ELF interpreter and a script are given back once loaded.
        let (mut l, mut lt, lm) = fork(&mut k, &mut t, &m);
        assert_eq!(run(&mut l, &mut lt, &lm, b"/ok"), 0);
        assert_eq!(open(&mut k, &mut t, &m, b"/ok", 1), busy);
        let (mut s, mut st, sm) = fork(&mut k, &mut t, &m);
        assert_eq!(run(&mut s, &mut st, &sm, b"/script"), 0);
        for path in [&b"/ld"[..], b"/script"] {
            let fd = open(&mut k, &mut t, &m, path, 1);
            assert!(fd < 1024, "{fd:#x}");
            close(&mut k, &mut t, fd);
        }
        // A fork runs the program too, until the last of them ends.
        let (mut g, gt, gm) = fork(&mut c, &mut ct, &cm);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        finish(&mut s, &st, &sm, ExitStatus::Exited(0));
        assert_eq!(open(&mut k, &mut t, &m, b"/child", 1), busy);
        finish(&mut g, &gt, &gm, ExitStatus::Exited(0));
        let fd = open(&mut k, &mut t, &m, b"/child", 1);
        assert!(fd < 1024, "{fd:#x}");
        close(&mut k, &mut t, fd);
        finish(&mut l, &lt, &lm, ExitStatus::Exited(0));
    }
    #[test]
    fn a_memfds_own_descriptor_is_no_writer_but_one_opened_again_is() {
        let (mut k, mut t, m) = exec_setup();
        let image = paludarium_loader::testing::tiny_exec(&[0x90], b"");
        m.write(GuestAddr(DATA + 0x100), b"m\0").unwrap();
        let fd = syscall(&mut k, &mut t, &m, 319, [DATA + 0x100, 0, 0, 0, 0, 0]);
        assert!(fd < 1024, "{fd:#x}");
        let len = image.len() as u64;
        let buffer = DATA + 16 * PAGE_SIZE;
        m.map_shared(
            Some(GuestAddr(buffer)),
            len.next_multiple_of(PAGE_SIZE),
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        m.write(GuestAddr(buffer), &image).unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 1, [fd, buffer, len, 0, 0, 0]),
            len
        );
        // `memfd_create`'s descriptor is open for writing, yet runs.
        m.write(GuestAddr(DATA + 0x100), b"\0").unwrap();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let at = [fd, DATA + 0x100, 0, 0, 0x1000, 0];
        assert_eq!(syscall(&mut c, &mut ct, &cm, 322, at), 0);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        // Opened again for writing, it is a writer (`do_dentry_open`).
        let again = open(
            &mut k,
            &mut t,
            &m,
            format!("/proc/self/fd/{fd}").as_bytes(),
            2,
        );
        assert!(again < 1024, "{again:#x}");
        m.write(GuestAddr(DATA + 0x100), b"\0").unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 322, at),
            Errno(26).to_syscall_return()
        );
        assert_eq!(syscall(&mut k, &mut t, &m, 3, [again, 0, 0, 0, 0, 0]), 0);
        assert_eq!(syscall(&mut k, &mut t, &m, 322, at), 0);
    }
    #[test]
    fn exec_checks_the_interpreter_with_the_callers_permissions() {
        // Position independent, so it does not collide with the program.
        let mut linker = paludarium_loader::testing::tiny_exec(&[0x90], b"");
        linker[16] = 3;
        let (via_child, via_none, via_empty, via_dir) = (
            asks_for(b"/ld\0"),
            asks_for(b"/absent\0"),
            asks_for(b"\0\0"),
            asks_for(b"/\0"),
        );
        let (mut k, mut t, m) = with_scripts(&[
            ("/ok", &via_child),
            ("/none", &via_none),
            ("/empty", &via_empty),
            ("/dir", &via_dir),
            ("/ld", &linker),
        ]);
        let fail = |e: i32| Errno(e).to_syscall_return();
        assert_eq!(run(&mut k, &mut t, &m, b"/none"), fail(2));
        assert_eq!(run(&mut k, &mut t, &m, b"/empty"), fail(13));
        assert_eq!(run(&mut k, &mut t, &m, b"/dir"), fail(13));
        // Not executable, even for root.
        k.files.fs.set_mode(b"/ld", 0o644).unwrap();
        assert_eq!(run(&mut k, &mut t, &m, b"/ok"), fail(13));
        // Executable but not readable: it runs, undumpable.
        k.files.fs.set_mode(b"/ld", 0o111).unwrap();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let user = [2000, 2000, 2000, 0, 0, 0];
        assert_eq!(syscall(&mut c, &mut ct, &cm, 117, user), 0);
        assert_eq!(run(&mut c, &mut ct, &cm, b"/ok"), 0);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 157, [3, 0, 0, 0, 0, 0]), 0);
        // Readable: dumpable, and its set-ID bits do not count.
        k.files
            .fs
            .set_owner(b"/ld", true, Some(3000), None)
            .unwrap();
        k.files.fs.set_mode(b"/ld", 0o4755).unwrap();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 117, user), 0);
        assert_eq!(run(&mut c, &mut ct, &cm, b"/ok"), 0);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 157, [3, 0, 0, 0, 0, 0]), 1);
        assert_eq!(ct.state.credentials.euid, 2000);
    }
    #[test]
    fn a_script_runs_its_interpreter_with_its_path_in_place_of_argv_0() {
        let (mut k, mut t, m) = with_scripts(&[("/s", b"#!/child one two\n")]);
        m.write(GuestAddr(DATA), b"/s\0").unwrap();
        m.write(GuestAddr(DATA + 0x10), b"zero\0a\0").unwrap();
        let pointers = [DATA + 0x10, DATA + 0x15, 0].map(u64::to_le_bytes).concat();
        m.write(GuestAddr(DATA + 0x20), &pointers).unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 59, [DATA, DATA + 0x20, 0, 0, 0, 0]),
            0
        );
        assert_eq!(arguments(&mut k), [&b"/child"[..], b"one two", b"/s", b"a"]);
    }
    #[test]
    fn a_script_of_scripts_goes_five_levels_down() {
        let files: Vec<(String, Vec<u8>)> = (1..=7)
            .map(|i| {
                let target = if i == 1 {
                    "/child".to_owned()
                } else {
                    format!("/s{}", i - 1)
                };
                (format!("/s{i}"), format!("#!{target}\n").into_bytes())
            })
            .collect();
        let refs: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
            .collect();
        let (mut k, mut t, m) = with_scripts(&refs);
        assert_eq!(
            run(&mut k, &mut t, &m, b"/s6"),
            Errno(40).to_syscall_return()
        );
        assert_eq!(
            run(&mut k, &mut t, &m, b"/s7"),
            Errno(40).to_syscall_return()
        );
        assert_eq!(run(&mut k, &mut t, &m, b"/s5"), 0);
        assert_eq!(arguments(&mut k).len(), 6);
    }
    #[test]
    fn an_interpreter_must_be_there_and_runnable() {
        let (mut k, mut t, m) = with_scripts(&[
            ("/none", b"#!/absent\n"),
            ("/empty", b"#!"),
            ("/text", b"#!/bad\n"),
            ("/bad", b"bad"),
            ("/line", b"#!\n"),
            ("/below", b"#!/child/x\n"),
        ]);
        let fail = |e: i32| Errno(e).to_syscall_return();
        assert_eq!(run(&mut k, &mut t, &m, b"/none"), fail(2));
        assert_eq!(run(&mut k, &mut t, &m, b"/empty"), fail(13));
        assert_eq!(run(&mut k, &mut t, &m, b"/text"), fail(8));
        assert_eq!(run(&mut k, &mut t, &m, b"/line"), fail(8));
        assert_eq!(run(&mut k, &mut t, &m, b"/below"), fail(20));
        assert_eq!(run(&mut k, &mut t, &m, b"/child/x"), fail(20));
        assert!(k.take_exec_memory().is_none());
    }
    #[test]
    fn the_interpreters_set_id_bits_count_not_the_scripts() {
        let (mut k, mut t, m) = with_scripts(&[("/s", b"#!/child\n")]);
        k.files.fs.set_owner(b"/s", true, Some(3000), None).unwrap();
        k.files.fs.set_mode(b"/s", 0o4755).unwrap();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let user = [2000, 2000, 2000, 0, 0, 0];
        assert_eq!(syscall(&mut c, &mut ct, &cm, 117, user), 0);
        assert_eq!(run(&mut c, &mut ct, &cm, b"/s"), 0);
        assert_eq!(ct.state.credentials.euid, 2000);
        k.files
            .fs
            .set_owner(b"/child", true, Some(3000), None)
            .unwrap();
        k.files.fs.set_mode(b"/child", 0o4755).unwrap();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let user = [2000, 2000, 2000, 0, 0, 0];
        assert_eq!(syscall(&mut c, &mut ct, &cm, 117, user), 0);
        assert_eq!(run(&mut c, &mut ct, &cm, b"/s"), 0);
        assert_eq!(ct.state.credentials.euid, 3000);
    }
    #[test]
    fn executed_child_keeps_its_group_and_zombies_hold_theirs() {
        let (mut k, mut t, m) = exec_setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let child = u64::from(ct.tid);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 59, [DATA, 0, 0, 0, 0, 0]), 0);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 109, [child, child, 0, 0, 0, 0]),
            Errno::EACCES.to_syscall_return()
        );
        // The exec'd process can still change its own group.
        assert_eq!(syscall(&mut c, &mut ct, &cm, 109, [0; 6]), 0);
        // A group whose only member has exited, unreaped, can be joined.
        let (mut z, zt, zm) = fork(&mut k, &mut t, &m);
        let zombie = u64::from(zt.tid);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 109, [zombie, zombie, 0, 0, 0, 0]),
            0
        );
        finish(&mut z, &zt, &zm, ExitStatus::Exited(0));
        let (_, mt, _) = fork(&mut k, &mut t, &m);
        let member = u64::from(mt.tid);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 109, [member, zombie, 0, 0, 0, 0]),
            0
        );
    }
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
    fn a_set_user_id_program_runs_as_its_owner_undumpable_on_a_lower_stack_limit() {
        let (mut k, mut t, m) = exec_setup();
        k.files
            .fs
            .set_owner(b"/child", true, Some(1001), None)
            .unwrap();
        k.files.fs.set_mode(b"/child", 0o4755).unwrap();
        // RLIMIT_STACK up to infinity, then a user other than root.
        m.write_u64(GuestAddr(DATA + 64), u64::MAX).unwrap();
        m.write_u64(GuestAddr(DATA + 72), u64::MAX).unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 160, [3, DATA + 64, 0, 0, 0, 0]),
            0
        );
        t.state.credentials = t.state.credentials.setresuid(1000, 1000, 1000).unwrap();
        assert_eq!(syscall(&mut k, &mut t, &m, 59, [DATA, 0, 0, 0, 0, 0]), 0);
        let c = &t.state.credentials;
        assert_eq!([c.uid, c.euid, c.suid, c.fsuid], [1000, 1001, 1001, 1001]);
        assert_eq!(syscall(&mut k, &mut t, &m, 157, [3, 0, 0, 0, 0, 0]), 0);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 97, [3, DATA + 64, 0, 0, 0, 0]),
            0
        );
        assert_eq!(m.read_u64(GuestAddr(DATA + 64)), Ok(8 << 20));
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
mod limits {
    use super::*;
    const THREAD: u64 = 0x10900;
    #[test]
    fn tasks_count_threads_and_unreaped_processes() {
        let (k, mut t, m) = setup();
        let mut k = k.with_task_limit(3);
        let eagain = Errno::EAGAIN.to_syscall_return();
        // The first process, a thread and a child fill the limit.
        let tid = syscall(&mut k, &mut t, &m, 56, [THREAD, 0, 0, 0, 0, 0]);
        let (mut thread_kernel, thread) = k.take_child().unwrap();
        assert_eq!(u64::from(thread.tid), tid);
        let (mut c, ct, cm) = fork(&mut k, &mut t, &m);
        assert_eq!(syscall(&mut k, &mut t, &m, 57, [0; 6]), eagain);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 56, [THREAD, 0, 0, 0, 0, 0]),
            eagain
        );
        assert!(k.take_child().is_none());
        // A thread gives its task back when it ends.
        thread_kernel.finish_thread(&thread, &m);
        drop(thread_kernel);
        let (_d, dt, _dm) = fork(&mut k, &mut t, &m);
        // An exited child keeps its task until it is reaped.
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        drop(c);
        assert_eq!(syscall(&mut k, &mut t, &m, 57, [0; 6]), eagain);
        let child = u64::from(ct.tid);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [child, 0, 0, 0, 0, 0]),
            child
        );
        let (_e, et, _em) = fork(&mut k, &mut t, &m);
        assert_ne!(et.tid, dt.tid);
    }
    #[test]
    fn exec_from_a_thread_keeps_one_task() {
        let (k, mut t, m) = exec_setup();
        let mut k = k.with_task_limit(2);
        syscall(&mut k, &mut t, &m, 56, [THREAD, 0, 0, 0, 0, 0]);
        let (mut e, mut et) = k.take_child().unwrap();
        // The leader ends first, so execve need not wait for it.
        k.finish_thread(&t, &m);
        assert_eq!(syscall(&mut e, &mut et, &m, 59, [DATA, 0, 0, 0, 0, 0]), 0);
        drop(k);
        // The thread now leads the process, which counts as one task.
        let em = e.take_exec_memory().unwrap();
        let (_c, _ct, _cm) = fork(&mut e, &mut et, &em);
        assert_eq!(
            syscall(&mut e, &mut et, &em, 57, [0; 6]),
            Errno::EAGAIN.to_syscall_return()
        );
    }
    #[test]
    fn open_files_are_capped_as_by_nr_open() {
        let (k, mut t, m) = setup();
        let mut k = k.with_open_file_limit(4);
        let get = |k: &mut Kernel, t: &mut Thread, m: &AddressSpace| {
            assert_eq!(syscall(k, t, m, 302, [0, 7, 0, DATA, 0, 0]), 0);
            (
                m.read_u64(GuestAddr(DATA)).unwrap(),
                m.read_u64(GuestAddr(DATA + 8)).unwrap(),
            )
        };
        assert_eq!(get(&mut k, &mut t, &m), (4, 4));
        let set = |k: &mut Kernel, t: &mut Thread, m: &AddressSpace, soft: u64, hard: u64| {
            m.write_u64(GuestAddr(DATA + 16), soft).unwrap();
            m.write_u64(GuestAddr(DATA + 24), hard).unwrap();
            syscall(k, t, m, 302, [0, 7, DATA + 16, 0, 0, 0])
        };
        let eperm = Errno::EPERM.to_syscall_return();
        assert_eq!(set(&mut k, &mut t, &m, 4, 5), eperm);
        assert_eq!(set(&mut k, &mut t, &m, 2, 4), 0);
        assert_eq!(set(&mut k, &mut t, &m, 4, 4), 0);
        // Descriptors beyond the soft limit cannot be opened.
        m.write(GuestAddr(DATA + 64), b"/dev/null\0").unwrap();
        let emfile = Errno::EMFILE.to_syscall_return();
        let opened: Vec<u64> = (0..8)
            .map(|_| syscall(&mut k, &mut t, &m, 2, [DATA + 64, 0, 0, 0, 0, 0]))
            .collect();
        assert!(opened.contains(&emfile), "{opened:?}");
        assert!(
            opened.iter().all(|&fd| fd < 4 || fd == emfile),
            "{opened:?}"
        );
        // A child inherits the cap.
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        assert_eq!(get(&mut c, &mut ct, &cm), (4, 4));
        assert_eq!(set(&mut c, &mut ct, &cm, 4, 5), eperm);
    }
}
mod ignored_pending {
    use super::*;
    const USR1: u64 = 1 << 9;
    const CHLD: u64 = 1 << 16;
    fn pending(k: &mut Kernel, t: &mut Thread, m: &AddressSpace) -> u64 {
        assert_eq!(syscall(k, t, m, 127, [DATA + 128, 8, 0, 0, 0, 0]), 0);
        m.read_u64(GuestAddr(DATA + 128)).unwrap()
    }
    fn action(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, signal: u64, handler: u64) {
        let bytes = [handler, 0, 0, 0].map(u64::to_le_bytes).concat();
        m.write(GuestAddr(DATA + 256), &bytes).unwrap();
        assert_eq!(syscall(k, t, m, 13, [signal, DATA + 256, 0, 8, 0, 0]), 0);
    }
    fn block(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, set: u64) {
        m.write_u64(GuestAddr(DATA), set).unwrap();
        assert_eq!(syscall(k, t, m, 14, [0, DATA, 0, 8, 0, 0]), 0);
    }
    #[test]
    fn ignoring_discards_what_is_pending_but_not_what_comes_later() {
        let (mut k, mut t, m) = setup();
        block(&mut k, &mut t, &m, USR1 | CHLD);
        syscall(&mut k, &mut t, &m, 62, [1, 10, 0, 0, 0, 0]);
        assert_eq!(pending(&mut k, &mut t, &m), USR1);
        action(&mut k, &mut t, &m, 10, 1);
        assert_eq!(pending(&mut k, &mut t, &m), 0);
        // Blocked, a signal sent while ignored stays pending.
        syscall(&mut k, &mut t, &m, 62, [1, 10, 0, 0, 0, 0]);
        assert_eq!(pending(&mut k, &mut t, &m), USR1);
        // SIG_DFL discards only a signal whose default is to ignore it.
        action(&mut k, &mut t, &m, 10, 0);
        assert_eq!(pending(&mut k, &mut t, &m), USR1);
        let (mut c, ct, cm) = fork(&mut k, &mut t, &m);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        assert_eq!(pending(&mut k, &mut t, &m), USR1 | CHLD);
        action(&mut k, &mut t, &m, 17, 0);
        assert_eq!(pending(&mut k, &mut t, &m), USR1);
    }
    #[test]
    fn other_threads_drop_what_they_took_in() {
        let (mut k, mut t, m) = setup();
        block(&mut k, &mut t, &m, USR1);
        let tid = syscall(&mut k, &mut t, &m, 56, [0x10900, 0, 0, 0, 0, 0]);
        let (mut e, mut et) = k.take_child().unwrap();
        syscall(&mut k, &mut t, &m, 234, [1, tid, 10, 0, 0, 0]);
        // The thread takes its signal in, then another thread ignores it.
        assert_eq!(pending(&mut e, &mut et, &m), USR1);
        action(&mut k, &mut t, &m, 10, 1);
        assert_eq!(pending(&mut e, &mut et, &m), 0);
        syscall(&mut k, &mut t, &m, 234, [1, tid, 10, 0, 0, 0]);
        assert_eq!(pending(&mut e, &mut et, &m), USR1);
    }
    #[test]
    fn a_signal_sent_after_the_discard_stays_however_it_is_queued() {
        // A thread that never took a signal in queues one to itself after
        // another thread made it ignored.
        let (mut k, mut t, m) = setup();
        block(&mut k, &mut t, &m, USR1);
        let tid = syscall(&mut k, &mut t, &m, 56, [0x10900, 0, 0, 0, 0, 0]);
        let (mut e, mut et) = k.take_child().unwrap();
        action(&mut k, &mut t, &m, 10, 1);
        assert_eq!(syscall(&mut e, &mut et, &m, 234, [1, tid, 10, 0, 0, 0]), 0);
        assert_eq!(pending(&mut e, &mut et, &m), USR1);
        // After an execve, which starts the thread's state afresh.
        let (mut k, mut t, m) = exec_setup();
        block(&mut k, &mut t, &m, USR1);
        action(&mut k, &mut t, &m, 10, 1);
        m.write(GuestAddr(DATA), b"/child\0").unwrap();
        assert_eq!(syscall(&mut k, &mut t, &m, 59, [DATA, 0, 0, 0, 0, 0]), 0);
        let em = k.take_exec_memory().unwrap();
        em.map_shared(
            Some(GuestAddr(DATA)),
            PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        assert_eq!(syscall(&mut k, &mut t, &em, 234, [1, 1, 10, 0, 0, 0]), 0);
        assert_eq!(pending(&mut k, &mut t, &em), USR1);
    }
}
mod namespaces {
    use super::*;
    const NEWNS: u64 = 0x2_0000;
    const NEWCGROUP: u64 = 0x200_0000;
    const NEWUTS: u64 = 0x400_0000;
    const NEWIPC: u64 = 0x800_0000;
    const NEWUSER: u64 = 0x1000_0000;
    const NEWPID: u64 = 0x2000_0000;
    const NEWNET: u64 = 0x4000_0000;
    const NEWTIME: u64 = 0x80;
    /// The host and domain names `uname` reports.
    fn names(k: &mut Kernel, t: &mut Thread, m: &AddressSpace) -> (Vec<u8>, Vec<u8>) {
        assert_eq!(syscall(k, t, m, 63, [DATA + 1024, 0, 0, 0, 0, 0]), 0);
        let mut bytes = [0; 65 * 6];
        m.read(GuestAddr(DATA + 1024), &mut bytes).unwrap();
        let field = |i: usize| {
            let field = &bytes[i * 65..(i + 1) * 65];
            field[..field.iter().position(|&b| b == 0).unwrap()].to_vec()
        };
        (field(1), field(5))
    }
    /// What the link at `path` reads.
    fn link(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, path: &str) -> Vec<u8> {
        m.write(GuestAddr(DATA), format!("{path}\0").as_bytes())
            .unwrap();
        let count = syscall(k, t, m, 89, [DATA, DATA + 512, 256, 0, 0, 0]);
        assert!(count < 256, "{path}: {}", count as i64);
        let mut bytes = vec![0; count as usize];
        m.read(GuestAddr(DATA + 512), &mut bytes).unwrap();
        bytes
    }
    fn set_name(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, n: u64, name: &[u8]) -> u64 {
        m.write(GuestAddr(DATA + 2048), name).unwrap();
        syscall(k, t, m, n, [DATA + 2048, name.len() as u64, 0, 0, 0, 0])
    }
    #[test]
    fn sethostname_and_setdomainname_change_what_uname_reports() {
        let (mut k, mut t, m) = setup();
        assert_eq!(
            names(&mut k, &mut t, &m),
            (b"paludarium".to_vec(), b"(none)".to_vec())
        );
        assert_eq!(set_name(&mut k, &mut t, &m, 170, b"box"), 0);
        assert_eq!(set_name(&mut k, &mut t, &m, 171, b"example.org"), 0);
        assert_eq!(
            names(&mut k, &mut t, &m),
            (b"box".to_vec(), b"example.org".to_vec())
        );
        // 64 bytes fill the field; 65 or a negative length are EINVAL.
        assert_eq!(set_name(&mut k, &mut t, &m, 170, &[b'a'; 64]), 0);
        assert_eq!(names(&mut k, &mut t, &m).0, vec![b'a'; 64]);
        let einval = Errno::EINVAL.to_syscall_return();
        assert_eq!(set_name(&mut k, &mut t, &m, 170, &[b'a'; 65]), einval);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 171, [DATA, u64::MAX, 0, 0, 0, 0]),
            einval
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 170, [1, 4, 0, 0, 0, 0]),
            Errno::EFAULT.to_syscall_return()
        );
        // An empty name, from any address.
        assert_eq!(syscall(&mut k, &mut t, &m, 171, [1, 0, 0, 0, 0, 0]), 0);
        assert_eq!(names(&mut k, &mut t, &m).1, b"");
        // Without CAP_SYS_ADMIN, EPERM before the length is looked at.
        t.state.credentials = t.state.credentials.setresuid(1000, 1000, 1000).unwrap();
        assert_eq!(
            set_name(&mut k, &mut t, &m, 170, &[b'a'; 65]),
            Errno::EPERM.to_syscall_return()
        );
    }
    #[test]
    fn unshare_gives_new_namespaces_and_refuses_the_others() {
        let (mut k, mut t, m) = setup();
        let einval = Errno::EINVAL.to_syscall_return();
        // Nothing to unshare: one thread, its own dispositions and memory.
        for flags in [0, 0x100, 0x200, 0x400, 0x800, 0x1_0000, 0x4_0000, 0x4_0f00] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, 272, [flags, 0, 0, 0, 0, 0]),
                0,
                "{flags:#x}"
            );
        }
        // Unknown flags, and the upper half of the register.
        for flags in [0x8, 0x1000, 0x1_0000_0000] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, 272, [flags, 0, 0, 0, 0, 0]),
                einval
            );
        }
        let before = [
            "uts",
            "ipc",
            "mnt",
            "cgroup",
            "time",
            "time_for_children",
            "net",
        ]
        .map(|name| link(&mut k, &mut t, &m, &format!("/proc/self/ns/{name}")));
        assert_eq!(before[0], b"uts:[4026531838]");
        for flags in [NEWUTS, NEWIPC, NEWNS, NEWCGROUP, NEWTIME] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, 272, [flags, 0, 0, 0, 0, 0]),
                0,
                "{flags:#x}"
            );
        }
        let after = [
            "uts",
            "ipc",
            "mnt",
            "cgroup",
            "time",
            "time_for_children",
            "net",
        ]
        .map(|name| link(&mut k, &mut t, &m, &format!("/proc/self/ns/{name}")));
        // New ones of each, but the time namespace, which is the children's.
        for i in [0, 1, 2, 3, 5] {
            assert_ne!(before[i], after[i], "{i}");
            assert_eq!(before[i][..4], after[i][..4]);
        }
        assert_eq!(before[4], after[4]);
        assert_eq!(before[6], after[6]);
        assert_eq!(&after[5][..5], b"time:");
        // No new user, PID or network namespace; with a supported flag too.
        for flags in [NEWUSER, NEWPID, NEWNET, NEWPID | NEWUTS] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, 272, [flags, 0, 0, 0, 0, 0]),
                einval
            );
        }
        // Without CAP_SYS_ADMIN, EPERM, but EINVAL for a user namespace.
        t.state.credentials = t.state.credentials.setresuid(1000, 1000, 1000).unwrap();
        for flags in [NEWUTS, NEWIPC, NEWNS, NEWCGROUP, NEWTIME, NEWPID, NEWNET] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, 272, [flags, 0, 0, 0, 0, 0]),
                Errno::EPERM.to_syscall_return()
            );
        }
        assert_eq!(
            syscall(&mut k, &mut t, &m, 272, [NEWUSER, 0, 0, 0, 0, 0]),
            einval
        );
    }
    #[test]
    fn a_uts_namespace_keeps_its_names_from_others() {
        let (mut k, mut t, m) = setup();
        k.group.register(1, Arc::new(SignalInbox::default()));
        let pid = syscall(&mut k, &mut t, &m, 56, [17, 0, 0, 0, 0, 0]);
        assert!(pid < 1 << 20);
        let (mut child, mut ct) = k.take_child().unwrap();
        assert_eq!(syscall(&mut k, &mut t, &m, 272, [NEWUTS, 0, 0, 0, 0, 0]), 0);
        assert_eq!(set_name(&mut k, &mut t, &m, 170, b"inside"), 0);
        assert_eq!(names(&mut k, &mut t, &m).0, b"inside");
        assert_eq!(names(&mut child, &mut ct, &m).0, b"paludarium");
        // A child of the process starts in its new namespace.
        let pid = syscall(&mut k, &mut t, &m, 56, [17, 0, 0, 0, 0, 0]);
        assert!(pid < 1 << 20);
        let (mut second, mut st) = k.take_child().unwrap();
        assert_eq!(names(&mut second, &mut st, &m).0, b"inside");
        // A clone with CLONE_NEWUTS gives the child a new one of its own.
        let pid = syscall(&mut k, &mut t, &m, 56, [NEWUTS | 17, 0, 0, 0, 0, 0]);
        assert!(pid < 1 << 20);
        let (mut third, mut tt) = k.take_child().unwrap();
        assert_eq!(set_name(&mut third, &mut tt, &m, 170, b"third"), 0);
        assert_eq!(names(&mut k, &mut t, &m).0, b"inside");
        assert_ne!(
            link(&mut k, &mut t, &m, "/proc/self/ns/uts"),
            link(&mut third, &mut tt, &m, "/proc/self/ns/uts")
        );
    }
    #[test]
    fn clone_checks_namespace_flags_as_linux_does() {
        let (mut k, mut t, m) = setup();
        k.group.register(1, Arc::new(SignalInbox::default()));
        let einval = Errno::EINVAL.to_syscall_return();
        // CLONE_FS with a new mount or user namespace; CLONE_SYSVSEM with a
        // new IPC namespace; and the namespaces paludarium has no new ones
        // of: no child.
        for flags in [
            NEWNS | 0x200,
            NEWUSER | 0x200,
            NEWIPC | 0x4_0000,
            NEWUSER,
            NEWPID,
            NEWNET,
            NEWNET | NEWUTS,
        ] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, 56, [flags | 17, 0, 0, 0, 0, 0]),
                einval,
                "{flags:#x}"
            );
            assert!(k.take_child().is_none());
        }
        // A thread may not have a new user or PID namespace; the others
        // need CAP_SYS_ADMIN.
        for flags in [NEWUSER, NEWPID] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, 56, [flags | 0x1_0900, 0, 0, 0, 0, 0]),
                einval
            );
        }
        let user = t.state.credentials.setresuid(1000, 1000, 1000).unwrap();
        let root = std::mem::replace(&mut t.state.credentials, user);
        for flags in [NEWUTS, NEWIPC, NEWNS, NEWCGROUP, NEWPID] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, 56, [flags | 17, 0, 0, 0, 0, 0]),
                Errno::EPERM.to_syscall_return()
            );
            assert!(k.take_child().is_none());
        }
        t.state.credentials = root;
        // A thread with a new UTS namespace has its own names.
        let tid = syscall(&mut k, &mut t, &m, 56, [NEWUTS | 0x1_0b00, 0, 0, 0, 0, 0]);
        assert!(tid < 1 << 20, "{}", tid as i64);
        let (mut thread, mut tt) = k.take_child().unwrap();
        assert_eq!(set_name(&mut thread, &mut tt, &m, 170, b"thread"), 0);
        assert_eq!(names(&mut k, &mut t, &m).0, b"paludarium");
    }
    #[test]
    fn a_new_time_namespace_is_entered_by_children_and_exec() {
        let (mut k, mut t, m) = setup();
        k.group.register(1, Arc::new(SignalInbox::default()));
        assert_eq!(
            syscall(&mut k, &mut t, &m, 272, [NEWTIME, 0, 0, 0, 0, 0]),
            0
        );
        let children = link(&mut k, &mut t, &m, "/proc/self/ns/time_for_children");
        assert_ne!(link(&mut k, &mut t, &m, "/proc/self/ns/time"), children);
        // A fork is in it; a vfork-like child sharing the memory is not.
        let pid = syscall(&mut k, &mut t, &m, 56, [17, 0, 0, 0, 0, 0]);
        assert!(pid < 1 << 20);
        let (mut child, mut ct) = k.take_child().unwrap();
        assert_eq!(
            link(&mut child, &mut ct, &m, "/proc/self/ns/time"),
            children
        );
        let pid = syscall(&mut k, &mut t, &m, 56, [0x100 | 17, 0, 0, 0, 0, 0]);
        assert!(pid < 1 << 20);
        let (mut shared, mut st) = k.take_child().unwrap();
        assert_ne!(
            link(&mut shared, &mut st, &m, "/proc/self/ns/time"),
            children
        );
        // clone3's CLONE_NEWTIME gives the child a new one, which it enters
        // as a fork enters its children's (`timens_on_fork`).
        m.write(GuestAddr(DATA + 3072), &[0; 88]).unwrap();
        m.write_u64(GuestAddr(DATA + 3072), NEWTIME).unwrap();
        m.write_u64(GuestAddr(DATA + 3072 + 32), 17).unwrap();
        let pid = syscall(&mut k, &mut t, &m, 435, [DATA + 3072, 88, 0, 0, 0, 0]);
        assert!(pid < 1 << 20, "{}", pid as i64);
        let (mut third, mut tt) = k.take_child().unwrap();
        let own = link(&mut third, &mut tt, &m, "/proc/self/ns/time");
        assert_ne!(own, children);
        assert_eq!(
            link(&mut third, &mut tt, &m, "/proc/self/ns/time_for_children"),
            own
        );
    }
    #[test]
    fn setns_enters_the_namespaces_of_a_file_or_a_process() {
        let (mut k, mut t, m) = setup();
        k.group.register(1, Arc::new(SignalInbox::default()));
        let pid = syscall(
            &mut k,
            &mut t,
            &m,
            56,
            [NEWUTS | NEWIPC | 17, 0, 0, 0, 0, 0],
        );
        assert!(pid < 1 << 20);
        let (mut child, mut ct) = k.take_child().unwrap();
        assert_eq!(set_name(&mut child, &mut ct, &m, 170, b"child"), 0);
        let theirs = link(&mut k, &mut t, &m, &format!("/proc/{pid}/ns/uts"));
        assert_eq!(theirs, link(&mut child, &mut ct, &m, "/proc/self/ns/uts"));
        m.write(GuestAddr(DATA), format!("/proc/{pid}/ns/uts\0").as_bytes())
            .unwrap();
        let fd = syscall(&mut k, &mut t, &m, 2, [DATA, 0, 0, 0, 0, 0]);
        assert!(fd < 1024, "{}", fd as i64);
        // A namespace file is only a handle: reading it is EINVAL, and its
        // descriptor's link names the namespace.
        assert_eq!(
            syscall(&mut k, &mut t, &m, 0, [fd, DATA + 512, 8, 0, 0, 0]),
            einval()
        );
        assert_eq!(
            link(&mut k, &mut t, &m, &format!("/proc/self/fd/{fd}")),
            theirs
        );
        // The wrong kind, then the right one or none.
        assert_eq!(
            syscall(&mut k, &mut t, &m, 308, [fd, NEWIPC, 0, 0, 0, 0]),
            einval()
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 308, [fd, NEWUTS, 0, 0, 0, 0]),
            0
        );
        assert_eq!(names(&mut k, &mut t, &m).0, b"child");
        assert_eq!(link(&mut k, &mut t, &m, "/proc/self/ns/uts"), theirs);
        // A pidfd and the namespaces to enter: none or an unknown flag is
        // EINVAL; a user namespace is the thread's own (EINVAL).
        let pidfd = syscall(&mut k, &mut t, &m, 434, [pid, 0, 0, 0, 0, 0]);
        assert!(pidfd < 1024);
        for flags in [0, 0x100, NEWUSER | NEWIPC] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, 308, [pidfd, flags, 0, 0, 0, 0]),
                einval()
            );
        }
        assert_eq!(
            syscall(&mut k, &mut t, &m, 308, [pidfd, NEWIPC, 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            link(&mut k, &mut t, &m, "/proc/self/ns/ipc"),
            link(&mut child, &mut ct, &m, "/proc/self/ns/ipc")
        );
        // Neither a namespace file nor a pidfd.
        assert_eq!(
            syscall(&mut k, &mut t, &m, 308, [0, 0, 0, 0, 0, 0]),
            einval()
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 308, [999, 0, 0, 0, 0, 0]),
            Errno::EBADF.to_syscall_return()
        );
        // Without CAP_SYS_ADMIN, EPERM.
        t.state.credentials = t.state.credentials.setresuid(1000, 1000, 1000).unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 308, [fd, 0, 0, 0, 0, 0]),
            Errno::EPERM.to_syscall_return()
        );
    }
    #[test]
    fn setns_into_a_mount_namespace_moves_to_its_root() {
        let (mut k, mut t, m) = setup();
        m.write(GuestAddr(DATA), b"/proc/self/ns/mnt\0").unwrap();
        let fd = syscall(&mut k, &mut t, &m, 2, [DATA, 0, 0, 0, 0, 0]);
        assert!(fd < 1024);
        m.write(GuestAddr(DATA), b"/namespaces\0").unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 83, [DATA, 0o755, 0, 0, 0, 0]),
            0
        );
        assert_eq!(syscall(&mut k, &mut t, &m, 80, [DATA, 0, 0, 0, 0, 0]), 0);
        // A working directory another thread shares: EINVAL.
        let shared = k.files.for_clone(true, true);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 308, [fd, 0, 0, 0, 0, 0]),
            einval()
        );
        drop(shared);
        assert_eq!(syscall(&mut k, &mut t, &m, 308, [fd, 0, 0, 0, 0, 0]), 0);
        assert_eq!(syscall(&mut k, &mut t, &m, 79, [DATA, 64, 0, 0, 0, 0]), 2);
        let mut cwd = [0; 2];
        m.read(GuestAddr(DATA), &mut cwd).unwrap();
        assert_eq!(&cwd, b"/\0");
        // A time namespace needs the thread alone (EUSERS).
        m.write(GuestAddr(DATA), b"/proc/self/ns/time\0").unwrap();
        let time = syscall(&mut k, &mut t, &m, 2, [DATA, 0, 0, 0, 0, 0]);
        k.group.register(1, Arc::new(SignalInbox::default()));
        k.group.register(2, Arc::new(SignalInbox::default()));
        assert_eq!(
            syscall(&mut k, &mut t, &m, 308, [time, 0, 0, 0, 0, 0]),
            Errno(87).to_syscall_return()
        );
    }
    #[test]
    fn clone_ignores_the_upper_half_of_its_flags() {
        // sys_clone keeps the low 32 bits: the bit clone3's CLONE_NEWTIME
        // travels in is a plain fork from clone, as are CLONE_CLEAR_SIGHAND's,
        // with or without CAP_SYS_ADMIN, and the child stays in the time
        // namespace.
        let (mut k, mut t, m) = setup();
        k.group.register(1, Arc::new(SignalInbox::default()));
        let time = link(&mut k, &mut t, &m, "/proc/self/ns/time");
        t.state.credentials = t.state.credentials.setresuid(1000, 1000, 1000).unwrap();
        for high in [
            crate::namespaces::CLONE3_NEWTIME,
            crate::processes::CLONE_CLEAR_SIGHAND,
        ] {
            let pid = syscall(&mut k, &mut t, &m, 56, [high | 17, 0, 0, 0, 0, 0]);
            assert!(pid < 1 << 20, "{high:#x}: {}", pid as i64);
            let (mut child, mut ct) = k.take_child().unwrap();
            assert_eq!(link(&mut child, &mut ct, &m, "/proc/self/ns/time"), time);
            assert_eq!(
                link(&mut child, &mut ct, &m, "/proc/self/ns/time_for_children"),
                time
            );
        }
    }
    #[test]
    fn setns_into_a_time_namespace_enters_it_and_gives_it_to_children() {
        let (mut k, mut t, m) = setup();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 272, [NEWTIME, 0, 0, 0, 0, 0]),
            0
        );
        let theirs = link(&mut k, &mut t, &m, "/proc/self/ns/time_for_children");
        assert_ne!(link(&mut k, &mut t, &m, "/proc/self/ns/time"), theirs);
        m.write(GuestAddr(DATA), b"/proc/self/ns/time_for_children\0")
            .unwrap();
        let fd = syscall(&mut k, &mut t, &m, 2, [DATA, 0, 0, 0, 0, 0]);
        assert_eq!(syscall(&mut k, &mut t, &m, 308, [fd, 0, 0, 0, 0, 0]), 0);
        assert_eq!(link(&mut k, &mut t, &m, "/proc/self/ns/time"), theirs);
        assert_eq!(
            link(&mut k, &mut t, &m, "/proc/self/ns/time_for_children"),
            theirs
        );
    }
    fn einval() -> u64 {
        Errno::EINVAL.to_syscall_return()
    }
    #[test]
    fn proc_lists_and_stats_the_namespace_links() {
        let (mut k, mut t, m) = setup();
        m.write(GuestAddr(DATA), b"/proc/self/ns\0").unwrap();
        let fd = syscall(&mut k, &mut t, &m, 2, [DATA, 0o200000, 0, 0, 0, 0]);
        assert!(fd < 1024, "{}", fd as i64);
        let count = syscall(&mut k, &mut t, &m, 217, [fd, DATA + 512, 1024, 0, 0, 0]);
        assert!(count < 1024);
        let mut bytes = vec![0; count as usize];
        m.read(GuestAddr(DATA + 512), &mut bytes).unwrap();
        let mut names = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let length = u16::from_le_bytes([bytes[at + 16], bytes[at + 17]]) as usize;
            let name = &bytes[at + 19..at + length];
            names.push(
                String::from_utf8_lossy(&name[..name.iter().position(|&b| b == 0).unwrap()])
                    .into_owned(),
            );
            at += length;
        }
        assert_eq!(
            names,
            [
                ".",
                "..",
                "net",
                "uts",
                "ipc",
                "pid",
                "pid_for_children",
                "user",
                "mnt",
                "cgroup",
                "time",
                "time_for_children"
            ]
        );
        // The link itself, and the namespace's file it leads to.
        m.write(GuestAddr(DATA), b"/proc/self/ns/uts\0").unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 6, [DATA, DATA + 512, 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            m.read_u64(GuestAddr(DATA + 512 + 24)).unwrap() as u32,
            0o120_777
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 4, [DATA, DATA + 512, 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            m.read_u64(GuestAddr(DATA + 512 + 24)).unwrap() as u32,
            0o100_444
        );
        assert_eq!(
            m.read_u64(GuestAddr(DATA + 512 + 8)).unwrap(),
            4_026_531_838
        );
        m.write(GuestAddr(DATA), b"/proc/self/ns/nope\0").unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 4, [DATA, DATA + 512, 0, 0, 0, 0]),
            Errno::ENOENT.to_syscall_return()
        );
    }
    #[test]
    fn unshare_files_and_fs_give_the_thread_its_own() {
        let (mut k, mut t, m) = setup();
        let shared = k.files.for_clone(true, true);
        assert_eq!(syscall(&mut k, &mut t, &m, 272, [0x400, 0, 0, 0, 0, 0]), 0);
        // The identity is the working directory, the umask and the table.
        let (own, other) = (k.files.identity(), shared.identity());
        assert_eq!((own[..2] == other[..2], own[2] == other[2]), (true, false));
        assert_eq!(syscall(&mut k, &mut t, &m, 272, [0x200, 0, 0, 0, 0, 0]), 0);
        let own = k.files.identity();
        assert_eq!((own[0] == other[0], own[1] == other[1]), (false, false));
    }
    #[test]
    fn unshare_refuses_a_shared_thread_group_dispositions_or_memory() {
        let einval = Errno::EINVAL.to_syscall_return();
        // A second thread: CLONE_THREAD, CLONE_SIGHAND and CLONE_VM.
        let (mut k, mut t, m) = setup();
        k.group.register(2, Arc::new(SignalInbox::default()));
        for flags in [0x100, 0x800, 0x1_0000] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, 272, [flags, 0, 0, 0, 0, 0]),
                einval
            );
        }
        assert_eq!(syscall(&mut k, &mut t, &m, 272, [0x400, 0, 0, 0, 0, 0]), 0);
        // Dispositions shared with a CLONE_VM | CLONE_SIGHAND child.
        let (mut k, mut t, m) = setup();
        k.group.register(1, Arc::new(SignalInbox::default()));
        assert_ne!(
            syscall(&mut k, &mut t, &m, 56, [0x900 | 17, 0, 0, 0, 0, 0]) as i64,
            -1
        );
        let (mut child, mut ct) = k.take_child().unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 272, [0x800, 0, 0, 0, 0, 0]),
            einval
        );
        assert_eq!(
            syscall(&mut child, &mut ct, &m, 272, [0x100, 0, 0, 0, 0, 0]),
            einval
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 272, [0x1_0000, 0, 0, 0, 0, 0]),
            0
        );
        // Memory shared with a CLONE_VM child, which has its own dispositions.
        let (mut k, mut t, m) = setup();
        k.group.register(1, Arc::new(SignalInbox::default()));
        k.publish(1, &t.state, &m);
        assert_ne!(
            syscall(&mut k, &mut t, &m, 56, [0x100 | 17, 0, 0, 0, 0, 0]) as i64,
            -1
        );
        let (mut child, mut ct) = k.take_child().unwrap();
        assert_eq!(
            syscall(&mut child, &mut ct, &m, 272, [0x800, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            syscall(&mut child, &mut ct, &m, 272, [0x100, 0, 0, 0, 0, 0]),
            einval
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 272, [0x100, 0, 0, 0, 0, 0]),
            einval
        );
    }
    #[test]
    fn ioprio_get_reports_the_default_of_the_threads_found() {
        let (mut k, mut t, m) = setup();
        let ret = |k: &mut Kernel, t: &mut Thread, which: u64, who: u64| {
            syscall(k, t, &m, 252, [which, who, 0, 0, 0, 0])
        };
        let esrch = Errno(3).to_syscall_return();
        for which in 1..=3 {
            assert_eq!(ret(&mut k, &mut t, which, 0), 0, "{which}");
        }
        assert_eq!(ret(&mut k, &mut t, 1, 1), 0);
        assert_eq!(ret(&mut k, &mut t, 1, 99), esrch);
        assert_eq!(ret(&mut k, &mut t, 1, u64::MAX), esrch);
        assert_eq!(ret(&mut k, &mut t, 2, 99), esrch);
        assert_eq!(ret(&mut k, &mut t, 3, 4242), esrch);
        for which in [0, 4, u64::MAX] {
            assert_eq!(
                ret(&mut k, &mut t, which, 0),
                Errno::EINVAL.to_syscall_return()
            );
        }
        // Several threads: ioprio_best counts each as best-effort level 4.
        k.group.register(2, Arc::new(SignalInbox::default()));
        k.group.set_nice(2, 0);
        assert_eq!(ret(&mut k, &mut t, 1, 0), 0);
        assert_eq!(ret(&mut k, &mut t, 2, 0), 2 << 13 | 4);
        // The upper halves are not read.
        assert_eq!(
            ret(&mut k, &mut t, 0xffff_ffff_0000_0001, 0xffff_ffff_0000_0000),
            0
        );
    }
}
mod orphaned_groups {
    use super::*;
    const SIGHUP: u64 = 1 << 0;
    const SIGCONT: u64 = 1 << 17;
    /// The parent makes itself a subreaper, a child `m` starts a session, and
    /// its child `c` leads a group of that session with SIGHUP and SIGCONT
    /// blocked, so that they stay pending where the test can see them.
    fn session_with_group(
        k: &mut Kernel,
        t: &mut Thread,
        m: &AddressSpace,
    ) -> [(Box<Kernel>, Thread, Arc<AddressSpace>); 2] {
        assert_eq!(syscall(k, t, m, 157, [36, 1, 0, 0, 0, 0]), 0);
        let (mut s, mut st, sm) = fork(k, t, m);
        assert_eq!(
            syscall(&mut s, &mut st, &sm, 112, [0; 6]),
            u64::from(st.tid)
        );
        let (mut c, mut ct, cm) = fork(&mut s, &mut st, &sm);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 109, [0; 6]), 0);
        cm.write_u64(GuestAddr(DATA + 512), SIGHUP | SIGCONT)
            .unwrap();
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 14, [0, DATA + 512, 0, 8, 0, 0]),
            0
        );
        [(s, st, sm), (c, ct, cm)]
    }
    fn pending(c: &mut Kernel, ct: &mut Thread, cm: &AddressSpace) -> u64 {
        assert_eq!(syscall(c, ct, cm, 127, [DATA + 520, 8, 0, 0, 0, 0]), 0);
        cm.read_u64(GuestAddr(DATA + 520)).unwrap()
    }
    #[test]
    fn a_stopped_group_orphaned_by_an_exit_gets_sighup_and_sigcont() {
        let (mut k, mut t, m) = setup();
        let [(mut s, st, sm), (mut c, mut ct, cm)] = session_with_group(&mut k, &mut t, &m);
        syscall(&mut c, &mut ct, &cm, 62, [0, 19, 0, 0, 0, 0]);
        assert!(c.group.is_stopped());
        // The session leader linked the group to its session; its exit
        // leaves the group with a parent in another session.
        finish(&mut s, &st, &sm, ExitStatus::Exited(0));
        assert!(!c.group.is_stopped());
        assert_eq!(pending(&mut c, &mut ct, &cm), SIGHUP | SIGCONT);
        // From the kernel: si_code SI_KERNEL, and no sender.
        cm.write(
            GuestAddr(DATA + 528),
            &[SIGHUP, 0, 0].map(u64::to_le_bytes).concat(),
        )
        .unwrap();
        assert_eq!(
            syscall(
                &mut c,
                &mut ct,
                &cm,
                128,
                [DATA + 528, DATA + 640, DATA + 536, 8, 0, 0]
            ),
            1
        );
        let word = |at: u64| cm.read_u64(GuestAddr(DATA + 640 + at)).unwrap() as u32;
        assert_eq!((word(8), word(16)), (0x80, 0));
    }
    #[test]
    fn a_group_without_a_stopped_member_gets_nothing() {
        let (mut k, mut t, m) = setup();
        let [(mut s, st, sm), (mut c, mut ct, cm)] = session_with_group(&mut k, &mut t, &m);
        finish(&mut s, &st, &sm, ExitStatus::Exited(0));
        assert_eq!(pending(&mut c, &mut ct, &cm), 0);
    }
    #[test]
    fn a_group_still_linked_to_its_session_is_not_orphaned() {
        // Without the new session, the subreaper that adopts the child is in
        // another group of the same session and keeps the group linked.
        let (mut k, mut t, m) = setup();
        assert_eq!(syscall(&mut k, &mut t, &m, 157, [36, 1, 0, 0, 0, 0]), 0);
        let (mut s, mut st, sm) = fork(&mut k, &mut t, &m);
        let (mut c, mut ct, cm) = fork(&mut s, &mut st, &sm);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 109, [0; 6]), 0);
        cm.write_u64(GuestAddr(DATA + 512), SIGHUP | SIGCONT)
            .unwrap();
        syscall(&mut c, &mut ct, &cm, 14, [0, DATA + 512, 0, 8, 0, 0]);
        syscall(&mut c, &mut ct, &cm, 62, [0, 19, 0, 0, 0, 0]);
        finish(&mut s, &st, &sm, ExitStatus::Exited(0));
        assert!(c.group.is_stopped());
        assert_eq!(pending(&mut c, &mut ct, &cm), 0);
    }
    #[test]
    fn a_zombie_leader_reaped_on_adoption_still_has_its_group_told() {
        // The leader `z` of a group exits and stays a zombie; `g`, another
        // child of the session leader `s`, keeps the group linked and stops.
        // When `s` exits, the subreaper, which ignores SIGCHLD, adopts and
        // reaps `z` at once, and the group, now orphaned, is told.
        let (mut k, mut t, m) = setup();
        assert_eq!(syscall(&mut k, &mut t, &m, 157, [36, 1, 0, 0, 0, 0]), 0);
        let (mut s, mut st, sm) = fork(&mut k, &mut t, &m);
        syscall(&mut s, &mut st, &sm, 112, [0; 6]);
        let (mut z, mut zt, zm) = fork(&mut s, &mut st, &sm);
        assert_eq!(syscall(&mut z, &mut zt, &zm, 109, [0; 6]), 0);
        let (mut g, mut gt, gm) = fork(&mut s, &mut st, &sm);
        let (leader, member) = (u64::from(zt.tid), u64::from(gt.tid));
        assert_eq!(
            syscall(&mut s, &mut st, &sm, 109, [member, leader, 0, 0, 0, 0]),
            0
        );
        gm.write_u64(GuestAddr(DATA + 512), SIGHUP | SIGCONT)
            .unwrap();
        syscall(&mut g, &mut gt, &gm, 14, [0, DATA + 512, 0, 8, 0, 0]);
        let own = u64::from(gt.tid);
        syscall(&mut g, &mut gt, &gm, 62, [own, 19, 0, 0, 0, 0]);
        finish(&mut z, &zt, &zm, ExitStatus::Exited(0));
        assert!(g.group.is_stopped());
        let ignore = [1u64, 0, 0, 0].map(u64::to_le_bytes).concat();
        m.write(GuestAddr(DATA + 256), &ignore).unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 13, [17, DATA + 256, 0, 8, 0, 0]),
            0
        );
        finish(&mut s, &st, &sm, ExitStatus::Exited(0));
        let echild = Errno(10).to_syscall_return();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [leader, 0, 1, 0, 0, 0]),
            echild
        );
        assert!(!g.group.is_stopped());
        assert_eq!(pending(&mut g, &mut gt, &gm), SIGHUP | SIGCONT);
    }
    #[test]
    fn the_exit_of_the_member_that_linked_its_own_group_orphans_it() {
        // `e` leads a group of the session and links it to its parent's
        // group; its child `g` stays in the group and stops.
        let (mut k, mut t, m) = setup();
        let [_, (mut e, mut et, em)] = session_with_group(&mut k, &mut t, &m);
        let (mut g, mut gt, gm) = fork(&mut e, &mut et, &em);
        let own = u64::from(gt.tid);
        syscall(&mut g, &mut gt, &gm, 62, [own, 19, 0, 0, 0, 0]);
        finish(&mut e, &et, &em, ExitStatus::Exited(0));
        assert!(!g.group.is_stopped());
        assert_eq!(pending(&mut g, &mut gt, &gm), SIGHUP | SIGCONT);
    }
}
mod kill_targets {
    use super::*;
    const USR1: u64 = 1 << 9;
    fn block(k: &mut Kernel, t: &mut Thread, m: &AddressSpace) {
        m.write_u64(GuestAddr(DATA + 512), USR1).unwrap();
        assert_eq!(syscall(k, t, m, 14, [0, DATA + 512, 0, 8, 0, 0]), 0);
    }
    fn pending(k: &mut Kernel, t: &mut Thread, m: &AddressSpace) -> u64 {
        assert_eq!(syscall(k, t, m, 127, [DATA + 520, 8, 0, 0, 0, 0]), 0);
        m.read_u64(GuestAddr(DATA + 520)).unwrap()
    }
    fn kill(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, target: i32, number: u64) -> u64 {
        syscall(k, t, m, 62, [i64::from(target) as u64, number, 0, 0, 0, 0])
    }
    fn esrch() -> u64 {
        Errno(3).to_syscall_return()
    }
    /// The first process with SIGUSR1 blocked, a child `c` in its group and
    /// a child `o` that leads a group of its own; both inherit the mask.
    fn family() -> [(Box<Kernel>, Thread, Arc<AddressSpace>); 3] {
        let (mut k, mut t, m) = setup();
        block(&mut k, &mut t, &m);
        let (c, ct, cm) = fork(&mut k, &mut t, &m);
        let (mut o, mut ot, om) = fork(&mut k, &mut t, &m);
        assert_eq!(syscall(&mut o, &mut ot, &om, 109, [0; 6]), 0);
        [(Box::new(k), t, Arc::new(m)), (c, ct, cm), (o, ot, om)]
    }
    #[test]
    fn zero_signals_the_whole_group_of_the_caller() {
        let [(mut k, mut t, m), (mut c, mut ct, cm), (mut o, mut ot, om)] = family();
        assert_eq!(kill(&mut c, &mut ct, &cm, 0, 10), 0);
        assert_eq!(pending(&mut k, &mut t, &m), USR1);
        assert_eq!(pending(&mut c, &mut ct, &cm), USR1);
        assert_eq!(pending(&mut o, &mut ot, &om), 0);
    }
    #[test]
    fn a_negative_target_names_a_group() {
        let [(mut k, mut t, m), (mut c, mut ct, cm), (mut o, mut ot, om)] = family();
        let group = -(ot.tid as i32);
        assert_eq!(kill(&mut k, &mut t, &m, group, 0), 0);
        assert_eq!(kill(&mut k, &mut t, &m, group, 10), 0);
        assert_eq!(pending(&mut o, &mut ot, &om), USR1);
        assert_eq!(pending(&mut k, &mut t, &m), 0);
        assert_eq!(pending(&mut c, &mut ct, &cm), 0);
        // A process that leads no group names none, whatever the signal.
        let none = -(ct.tid as i32);
        assert_eq!(kill(&mut k, &mut t, &m, none, 10), esrch());
        assert_eq!(kill(&mut k, &mut t, &m, none, 65), esrch());
        assert_eq!(
            kill(&mut k, &mut t, &m, group, 65),
            Errno::EINVAL.to_syscall_return()
        );
        assert_eq!(kill(&mut k, &mut t, &m, i32::MIN, 0), esrch());
    }
    #[test]
    fn minus_one_signals_all_but_the_first_process_and_the_caller() {
        let [(mut k, mut t, m), (mut c, mut ct, cm), (mut o, mut ot, om)] = family();
        assert_eq!(kill(&mut c, &mut ct, &cm, -1, 10), 0);
        assert_eq!(pending(&mut o, &mut ot, &om), USR1);
        assert_eq!(pending(&mut k, &mut t, &m), 0);
        assert_eq!(pending(&mut c, &mut ct, &cm), 0);
        assert_eq!(kill(&mut k, &mut t, &m, -1, 10), 0);
        assert_eq!(pending(&mut c, &mut ct, &cm), USR1);
        assert_eq!(pending(&mut k, &mut t, &m), 0);
        // With nobody else, there is no process to send to.
        let (mut k, mut t, m) = setup();
        assert_eq!(kill(&mut k, &mut t, &m, -1, 0), esrch());
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        assert_eq!(kill(&mut c, &mut ct, &cm, -1, 0), esrch());
    }
    #[test]
    fn a_missing_process_is_esrch_before_an_invalid_signal() {
        let (mut k, mut t, m) = setup();
        assert_eq!(kill(&mut k, &mut t, &m, 99, 65), esrch());
        // A signal that is negative as an int is as invalid as one past 64.
        for number in [65, u64::from(u32::MAX), u64::MAX] {
            assert_eq!(
                kill(&mut k, &mut t, &m, 1, number),
                Errno::EINVAL.to_syscall_return()
            );
        }
    }
    #[test]
    fn the_target_and_the_signal_are_32_bit() {
        let (mut k, mut t, m) = setup();
        block(&mut k, &mut t, &m);
        assert_eq!(
            syscall(
                &mut k,
                &mut t,
                &m,
                62,
                [0xffff_ffff_0000_0001, 1 << 32 | 10, 0, 0, 0, 0]
            ),
            0
        );
        assert_eq!(pending(&mut k, &mut t, &m), USR1);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 62, [0xffff_fffe, 0, 0, 0, 0, 0]),
            esrch()
        );
    }
    #[test]
    fn a_thread_id_names_its_process() {
        let (mut k, mut t, m) = setup();
        block(&mut k, &mut t, &m);
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        // CLONE_VM | CLONE_SIGHAND | CLONE_THREAD.
        let tid = syscall(&mut k, &mut t, &m, 56, [0x10900, 0, 0, 0, 0, 0]);
        assert!(tid > u64::from(ct.tid), "{tid:#x}");
        assert_eq!(kill(&mut c, &mut ct, &cm, tid as i32, 10), 0);
        assert_eq!(pending(&mut k, &mut t, &m), USR1);
    }
    #[test]
    fn a_zombie_still_counts() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 109, [0; 6]), 0);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        let pid = ct.tid as i32;
        assert_eq!(kill(&mut k, &mut t, &m, pid, 10), 0);
        assert_eq!(kill(&mut k, &mut t, &m, -pid, 10), 0);
        assert_eq!(kill(&mut k, &mut t, &m, -1, 10), 0);
    }
}
mod signal_senders {
    use super::*;
    const USR1: u64 = 1 << 9;
    /// Blocks SIGUSR1, so that it stays pending where the test can see it.
    fn block(k: &mut Kernel, t: &mut Thread, m: &AddressSpace) {
        m.write_u64(GuestAddr(DATA + 512), USR1).unwrap();
        assert_eq!(syscall(k, t, m, 14, [0, DATA + 512, 0, 8, 0, 0]), 0);
    }
    /// Takes the pending SIGUSR1 with rt_sigtimedwait (no wait) and returns
    /// its si_code and si_pid.
    fn take(k: &mut Kernel, t: &mut Thread, m: &AddressSpace) -> (i32, u32) {
        m.write(
            GuestAddr(DATA),
            &[USR1, 0, 0].map(u64::to_le_bytes).concat(),
        )
        .unwrap();
        assert_eq!(
            syscall(k, t, m, 128, [DATA, DATA + 64, DATA + 8, 8, 0, 0]),
            10
        );
        let word = |at: u64| m.read_u64(GuestAddr(DATA + 64 + at)).unwrap() as u32;
        (word(8) as i32, word(16))
    }
    #[test]
    fn kill_reports_the_sender() {
        let (mut k, mut t, m) = setup();
        block(&mut k, &mut t, &m);
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 62, [1, 10, 0, 0, 0, 0]), 0);
        assert_eq!(take(&mut k, &mut t, &m), (0, ct.tid));
        // Sent to its own group, the parent hears from the child as well.
        assert_eq!(syscall(&mut c, &mut ct, &cm, 62, [0, 10, 0, 0, 0, 0]), 0);
        assert_eq!(take(&mut k, &mut t, &m), (0, ct.tid));
        assert_eq!(take(&mut c, &mut ct, &cm), (0, ct.tid));
        // To itself, the sender is the receiver.
        assert_eq!(syscall(&mut k, &mut t, &m, 62, [1, 10, 0, 0, 0, 0]), 0);
        assert_eq!(take(&mut k, &mut t, &m), (0, 1));
    }
    #[test]
    fn pidfd_send_signal_reports_the_sender() {
        let (mut k, mut t, m) = setup();
        block(&mut k, &mut t, &m);
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let pidfd = syscall(&mut c, &mut ct, &cm, 434, [1, 0, 0, 0, 0, 0]);
        assert!(pidfd < 1024, "{pidfd:#x}");
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 424, [pidfd, 10, 0, 0, 0, 0]),
            0
        );
        assert_eq!(take(&mut k, &mut t, &m), (0, ct.tid));
    }
    #[test]
    fn the_parent_death_signal_comes_from_the_parent() {
        let (mut k, mut t, m) = setup();
        let (mut p, mut pt, pm) = fork(&mut k, &mut t, &m);
        let (mut c, mut ct, cm) = fork(&mut p, &mut pt, &pm);
        block(&mut c, &mut ct, &cm);
        // PR_SET_PDEATHSIG, SIGUSR1.
        assert_eq!(syscall(&mut c, &mut ct, &cm, 157, [1, 10, 0, 0, 0, 0]), 0);
        finish(&mut p, &pt, &pm, ExitStatus::Exited(0));
        assert_eq!(take(&mut c, &mut ct, &cm), (0, pt.tid));
    }
}
mod first_process_exit {
    use super::*;
    #[test]
    fn the_exit_of_the_first_process_kills_every_other() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let (mut g, mut gt, gm) = fork(&mut c, &mut ct, &cm);
        // One of them is stopped by job control; SIGKILL ends it all the same.
        let own = u64::from(gt.tid);
        assert_eq!(syscall(&mut g, &mut gt, &gm, 62, [own, 19, 0, 0, 0, 0]), 0);
        assert!(g.group.is_stopped());
        finish(&mut k, &t, &m, ExitStatus::Exited(0));
        assert_eq!(
            c.checkpoint(&mut ct, &cm),
            Next::Exit(ExitStatus::Signaled(9))
        );
        assert_eq!(
            g.checkpoint(&mut gt, &gm),
            Next::Exit(ExitStatus::Signaled(9))
        );
    }
    #[test]
    fn the_exit_of_another_process_kills_nobody() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let (mut g, mut gt, gm) = fork(&mut c, &mut ct, &cm);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        assert_eq!(g.checkpoint(&mut gt, &gm), Next::Resume);
        assert_eq!(k.checkpoint(&mut t, &m), Next::Resume);
    }
}
#[test]
fn capget_reads_another_process_and_capabilities_decide() {
    let (mut k, mut t, m) = setup();
    let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
    // The child keeps CAP_KILL out of its effective set.
    let v3 = [0x2008_0522u32.to_le_bytes(), 0u32.to_le_bytes()].concat();
    cm.write(GuestAddr(DATA), &v3).unwrap();
    let sets = [0xffff_ffdfu32, u32::MAX, 0x3, 0x1ff, 0x1ff, 0]
        .map(u32::to_le_bytes)
        .concat();
    cm.write(GuestAddr(DATA + 0x100), &sets).unwrap();
    let args = [DATA, DATA + 0x100, 0, 0, 0, 0];
    assert_eq!(syscall(&mut c, &mut ct, &cm, 126, args), 0);
    // Its parent reads them by its ID.
    let named = [0x2008_0522u32.to_le_bytes(), ct.tid.to_le_bytes()].concat();
    m.write(GuestAddr(DATA), &named).unwrap();
    assert_eq!(syscall(&mut k, &mut t, &m, 125, args), 0);
    let mut raw = [0; 12];
    m.read(GuestAddr(DATA + 0x100), &mut raw).unwrap();
    assert_eq!(&raw[..4], &0xffff_ffdfu32.to_le_bytes());
    assert_eq!(&raw[8..12], &0x3u32.to_le_bytes());
    // Without CAP_KILL root cannot signal another user's process.
    let other = crate::credentials::Credentials::default()
        .setresuid(2000, 2000, 2000)
        .unwrap()
        .task_ids();
    let without = crate::credentials::Credentials::default()
        .capset(
            !(1 << 5) & crate::credentials::ALL_CAPABILITIES,
            crate::credentials::ALL_CAPABILITIES,
            0,
        )
        .unwrap()
        .task_ids();
    assert!(!without.may_signal(&other));
    assert!(
        crate::credentials::Credentials::default()
            .task_ids()
            .may_signal(&other)
    );
}
mod core_dumps {
    use super::*;
    const MAGIC: u64 = 0x1122_3344_5566_7788;
    /// Sets the RLIMIT_CORE soft limit, with no hard limit.
    fn core_limit(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, soft: u64) {
        m.write(
            GuestAddr(DATA + 512),
            &[soft, u64::MAX].map(u64::to_le_bytes).concat(),
        )
        .unwrap();
        assert_eq!(syscall(k, t, m, 160, [4, DATA + 512, 0, 0, 0, 0]), 0);
    }
    /// The child sends itself `signal`, ends by it and finishes.
    fn end_by(c: &mut Kernel, ct: &mut Thread, cm: &AddressSpace, signal: u64) {
        let own = u64::from(ct.tid);
        assert_eq!(syscall(c, ct, cm, 62, [own, signal, 0, 0, 0, 0]), 0);
        let status = ExitStatus::Signaled(signal as i32);
        assert_eq!(c.checkpoint(ct, cm), Next::Exit(status));
        finish(c, ct, cm, status);
    }
    /// The raw wait status of `pid`, reaped by the parent.
    fn wait_status(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, pid: u32) -> u32 {
        let pid = u64::from(pid);
        assert_eq!(syscall(k, t, m, 61, [pid, DATA, 0, 0, 0, 0]), pid);
        m.read_u64(GuestAddr(DATA)).unwrap() as u32
    }
    fn core(k: &Kernel) -> Option<Vec<u8>> {
        let file = k.files.fs.open(b"/core", 0, 0).ok()?;
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            match file.read(&mut buffer).unwrap() {
                0 => return Some(bytes),
                n => bytes.extend_from_slice(&buffer[..n]),
            }
        }
    }
    fn u16_at(b: &[u8], at: usize) -> u16 {
        u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
    }
    fn u32_at(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }
    fn u64_at(b: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
    }
    /// The program headers of a core: (type, offset, address, file size).
    fn segments(core: &[u8]) -> Vec<(u32, usize, u64, usize)> {
        (0..usize::from(u16_at(core, 56)))
            .map(|i| {
                let p = 64 + 56 * i;
                let size = u64_at(core, p + 32) as usize;
                (
                    u32_at(core, p),
                    u64_at(core, p + 8) as usize,
                    u64_at(core, p + 16),
                    size,
                )
            })
            .collect()
    }
    #[test]
    fn a_core_signal_writes_a_core_and_wait_reports_it() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        cm.write_u64(GuestAddr(DATA + 256), MAGIC).unwrap();
        core_limit(&mut c, &mut ct, &cm, u64::MAX);
        end_by(&mut c, &mut ct, &cm, 11);
        // WNOWAIT first: waitid reports CLD_DUMPED.
        assert_eq!(
            syscall(
                &mut k,
                &mut t,
                &m,
                247,
                [1, u64::from(ct.tid), DATA + 64, 4 | 0x0100_0000, 0, 0]
            ),
            0
        );
        assert_eq!(m.read_u64(GuestAddr(DATA + 72)).unwrap() as u32, 3);
        // SIGSEGV with WCOREDUMP.
        assert_eq!(wait_status(&mut k, &mut t, &m, ct.tid), 11 | 0x80);
        let core = core(&k).expect("a core file");
        assert_eq!(core[..4], *b"\x7fELF");
        assert_eq!(u16_at(&core, 16), 4); // ET_CORE
        assert_eq!(u16_at(&core, 18), 62); // EM_X86_64
        assert_eq!(
            k.files.fs.metadata(b"/core", false).unwrap().mode & 0o777,
            0o600
        );
        let segments = segments(&core);
        // The notes come first; the first is the thread's NT_PRSTATUS.
        let (kind, notes, _, _) = segments[0];
        assert_eq!(kind, 4);
        assert_eq!(u32_at(&core, notes + 8), 1);
        let status = notes + 20;
        assert_eq!(u16_at(&core, status + 12), 11); // pr_cursig
        assert_eq!(u32_at(&core, status + 32), ct.tid); // pr_pid
        assert_eq!(u32_at(&core, status + 36), 1); // pr_ppid
        // The memory holds what the child wrote.
        let &(_, offset, _, size) = segments
            .iter()
            .find(|&&(kind, _, address, _)| kind == 1 && address == DATA)
            .expect("the data mapping");
        assert_eq!(size, PAGE_SIZE as usize);
        assert_eq!(u64_at(&core, offset + 256), MAGIC);
    }
    /// The child takes other IDs, stays dumpable and ends by SIGSEGV.
    fn end_as_user(k: &mut Kernel, t: &mut Thread, m: &AddressSpace) -> u32 {
        let (mut c, mut ct, cm) = fork(k, t, m);
        core_limit(&mut c, &mut ct, &cm, u64::MAX);
        let (groups, users) = ([1100, 2100, 3100, 0, 0, 0], [1000, 2000, 3000, 0, 0, 0]);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 119, groups), 0);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 117, users), 0);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 157, [4, 1, 0, 0, 0, 0]), 0);
        end_by(&mut c, &mut ct, &cm, 11);
        ct.tid
    }
    #[test]
    fn a_core_belongs_to_the_filesystem_ids_and_names_the_real_ones() {
        let (mut k, mut t, m) = setup();
        k.files.fs.set_mode(b"/", 0o777).unwrap();
        let pid = end_as_user(&mut k, &mut t, &m);
        assert_eq!(wait_status(&mut k, &mut t, &m, pid), 11 | 0x80);
        let stat = k.files.fs.metadata(b"/core", false).unwrap();
        assert_eq!([stat.uid, stat.gid], [2000, 2100]);
        let core = core(&k).expect("a core");
        let (_, offset, _, size) = segments(&core)
            .into_iter()
            .find(|segment| segment.0 == 4)
            .expect("notes");
        let mut at = offset;
        let info = loop {
            assert!(at < offset + size, "no NT_PRPSINFO");
            let name = (u32_at(&core, at) as usize).next_multiple_of(4);
            let description = u32_at(&core, at + 4) as usize;
            if u32_at(&core, at + 8) == 3 {
                break at + 12 + name;
            }
            at += 12 + name + description.next_multiple_of(4);
        };
        assert_eq!(
            [u32_at(&core, info + 16), u32_at(&core, info + 20)],
            [1000, 1100]
        );
    }
    #[test]
    fn no_core_where_its_user_may_not_write_or_replace_it() {
        // A directory it may not write.
        let (mut k, mut t, m) = setup();
        k.files.fs.set_mode(b"/", 0o755).unwrap();
        let pid = end_as_user(&mut k, &mut t, &m);
        assert_eq!(wait_status(&mut k, &mut t, &m, pid), 11);
        assert!(core(&k).is_none());
        // Root's old core in a sticky directory stays.
        let (mut k, mut t, m) = setup();
        k.files.fs.set_mode(b"/", 0o1777).unwrap();
        k.files.fs.open(b"/core", 0o101, 0o644).unwrap();
        let pid = end_as_user(&mut k, &mut t, &m);
        assert_eq!(wait_status(&mut k, &mut t, &m, pid), 11);
        assert_eq!(core(&k).as_deref(), Some(&[][..]));
    }
    #[test]
    fn no_core_under_the_default_limit_a_page_or_without_dumpable() {
        for (limit, dumpable) in [(None, true), (Some(4095), true), (Some(u64::MAX), false)] {
            let (mut k, mut t, m) = setup();
            let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
            if let Some(limit) = limit {
                core_limit(&mut c, &mut ct, &cm, limit);
            }
            if !dumpable {
                assert_eq!(syscall(&mut c, &mut ct, &cm, 157, [4, 0, 0, 0, 0, 0]), 0);
            }
            end_by(&mut c, &mut ct, &cm, 11);
            assert_eq!(wait_status(&mut k, &mut t, &m, ct.tid), 11);
            assert!(core(&k).is_none(), "{limit:?} {dumpable}");
        }
    }
    #[test]
    fn a_core_past_the_limit_is_cut_and_still_reported() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        core_limit(&mut c, &mut ct, &cm, 4096);
        end_by(&mut c, &mut ct, &cm, 6);
        assert_eq!(wait_status(&mut k, &mut t, &m, ct.tid), 6 | 0x80);
        let core = core(&k).expect("a cut core");
        assert!(
            core.len() <= 4096 && core.starts_with(b"\x7fELF"),
            "{}",
            core.len()
        );
    }
    #[test]
    fn a_signal_that_dumps_no_core_writes_none() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        core_limit(&mut c, &mut ct, &cm, u64::MAX);
        end_by(&mut c, &mut ct, &cm, 15);
        assert_eq!(wait_status(&mut k, &mut t, &m, ct.tid), 15);
        assert!(core(&k).is_none());
    }
    #[test]
    fn an_old_core_is_replaced() {
        let (mut k, mut t, m) = setup();
        let old = k.files.fs.open(b"/core", 0o101, 0o644).unwrap();
        assert_eq!(old.write(b"old").unwrap(), 3);
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        core_limit(&mut c, &mut ct, &cm, u64::MAX);
        end_by(&mut c, &mut ct, &cm, 11);
        assert_eq!(wait_status(&mut k, &mut t, &m, ct.tid), 11 | 0x80);
        assert!(core(&k).unwrap().starts_with(b"\x7fELF"));
        assert_eq!(
            k.files.fs.metadata(b"/core", false).unwrap().mode & 0o777,
            0o600
        );
    }
}
mod queued_signals {
    use super::*;
    const USR1: u64 = 1 << 9;
    const RT: u64 = 1 << 33; // signal 34
    fn block(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, set: u64) {
        m.write_u64(GuestAddr(DATA + 512), set).unwrap();
        assert_eq!(syscall(k, t, m, 14, [0, DATA + 512, 0, 8, 0, 0]), 0);
    }
    /// A siginfo at DATA + 256: `code`, `si_pid` 99 and `si_value`, with
    /// `tail` written past the first 48 bytes.
    fn info(m: &AddressSpace, code: i32, value: u64, tail: u8) {
        let mut b = [0u8; 128];
        b[0..4].copy_from_slice(&77i32.to_le_bytes()); // replaced by the signal
        b[8..12].copy_from_slice(&code.to_le_bytes());
        b[16..20].copy_from_slice(&99u32.to_le_bytes());
        b[24..32].copy_from_slice(&value.to_le_bytes());
        b[100] = tail;
        m.write(GuestAddr(DATA + 256), &b).unwrap();
    }
    /// Takes a pending signal of `set` with rt_sigtimedwait (no wait) and
    /// returns its number and siginfo.
    fn take(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, set: u64) -> (u64, [u8; 128]) {
        m.write(GuestAddr(DATA), &[set, 0, 0].map(u64::to_le_bytes).concat())
            .unwrap();
        let number = syscall(k, t, m, 128, [DATA, DATA + 64, DATA + 8, 8, 0, 0]);
        let mut info = [0u8; 128];
        m.read(GuestAddr(DATA + 64), &mut info).unwrap();
        (number, info)
    }
    fn word(info: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(info[at..at + 8].try_into().unwrap())
    }
    #[test]
    fn the_siginfo_arrives_as_given() {
        let (mut k, mut t, m) = setup();
        block(&mut k, &mut t, &m, USR1);
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        // SI_QUEUE (-1) from the child, with its own si_pid and a value.
        info(&cm, -1, 0x1234, 0);
        assert_eq!(
            syscall(&mut c, &mut ct, &cm, 129, [1, 10, DATA + 256, 0, 0, 0]),
            0
        );
        let (number, got) = take(&mut k, &mut t, &m, USR1);
        assert_eq!(number, 10);
        assert_eq!(i32::from_le_bytes(got[0..4].try_into().unwrap()), 10);
        assert_eq!(i32::from_le_bytes(got[8..12].try_into().unwrap()), -1);
        assert_eq!(u32::from_le_bytes(got[16..20].try_into().unwrap()), 99);
        assert_eq!(word(&got, 24), 0x1234);
        // Only the first 48 bytes are taken.
        assert!(got[48..].iter().all(|&b| b == 0));
    }
    #[test]
    fn realtime_signals_queue_each_value() {
        let (mut k, mut t, m) = setup();
        block(&mut k, &mut t, &m, RT);
        for value in [1, 2] {
            info(&m, -1, value, 0);
            assert_eq!(
                syscall(&mut k, &mut t, &m, 129, [1, 34, DATA + 256, 0, 0, 0]),
                0
            );
        }
        assert_eq!(word(&take(&mut k, &mut t, &m, RT).1, 24), 1);
        assert_eq!(word(&take(&mut k, &mut t, &m, RT).1, 24), 2);
    }
    #[test]
    fn only_the_caller_itself_may_give_a_kernel_or_kill_code() {
        let (mut k, mut t, m) = setup();
        block(&mut k, &mut t, &m, USR1);
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        let eperm = Errno(1).to_syscall_return();
        for code in [0, 0x80, 1, -6] {
            info(&cm, code, 0, 0);
            assert_eq!(
                syscall(&mut c, &mut ct, &cm, 129, [1, 10, DATA + 256, 0, 0, 0]),
                eperm
            );
            // Even to a process that does not exist.
            assert_eq!(
                syscall(&mut c, &mut ct, &cm, 129, [999, 10, DATA + 256, 0, 0, 0]),
                eperm
            );
        }
        info(&m, 0, 0, 0);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 129, [1, 10, DATA + 256, 0, 0, 0]),
            0
        );
        assert_eq!(take(&mut k, &mut t, &m, USR1).0, 10);
    }
    #[test]
    fn errors_come_in_linuxs_order() {
        let (mut k, mut t, m) = setup();
        // A layout Linux does not know must leave the tail zero: below
        // SI_DETHREAD, or past the signal's codes, SI_KERNEL aside.
        for code in [-8, 0x81, 7] {
            info(&m, code, 0, 1);
            assert_eq!(
                syscall(&mut k, &mut t, &m, 129, [1, 10, DATA + 256, 0, 0, 0]),
                Errno(7).to_syscall_return(),
                "{code}"
            );
        }
        info(&m, -1, 0, 1);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 129, [1, 0, DATA + 256, 0, 0, 0]),
            0
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 129, [1, 10, 8, 0, 0, 0]),
            Errno::EFAULT.to_syscall_return()
        );
        for (pid, signal, error) in [
            (999, 10, Errno(3)),
            (0, 10, Errno(3)),
            (1, 65, Errno::EINVAL),
        ] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, 129, [pid, signal, DATA + 256, 0, 0, 0]),
                error.to_syscall_return()
            );
        }
    }
    #[test]
    fn process_signals_keep_their_order_across_a_checkpoint() {
        let (k, mut t, m) = setup();
        // As the runtime sets it up: the leader's inbox is the process's.
        let mut k = k.with_signal_inbox(Arc::new(SignalInbox::default()));
        block(&mut k, &mut t, &m, USR1 | RT);
        // SIGUSR1 reaches the shared queue at a checkpoint, and a realtime
        // signal comes before the leader drains its own inbox, which is
        // also the process's: it must not overtake SIGUSR1.
        k.group.send_process_from(10, 2, 0).unwrap();
        k.group.drain_process(&mut t.state);
        k.group.send_process_from(34, 2, 0).unwrap();
        k.inbox.drain(&mut t.state);
        assert_eq!(take(&mut k, &mut t, &m, USR1 | RT).0, 10);
        assert_eq!(take(&mut k, &mut t, &m, USR1 | RT).0, 34);
    }
    #[test]
    fn rt_tgsigqueueinfo_reaches_one_thread() {
        let (mut k, mut t, m) = setup();
        block(&mut k, &mut t, &m, USR1);
        info(&m, -1, 7, 0);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 297, [1, 1, 10, DATA + 256, 0, 0]),
            0
        );
        let (number, got) = take(&mut k, &mut t, &m, USR1);
        assert_eq!((number, word(&got, 24)), (10, 7));
        for (tgid, tid, error) in [
            (0, 1, Errno::EINVAL),
            (1, 0, Errno::EINVAL),
            (2, 1, Errno(3)),
            (1, 2, Errno(3)),
        ] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, 297, [tgid, tid, 10, DATA + 256, 0, 0]),
                error.to_syscall_return()
            );
        }
    }
}
mod signal_driven_io {
    use super::*;
    const O_ASYNC: u64 = 0o20000;
    fn fcntl(
        k: &mut Kernel,
        t: &mut Thread,
        m: &AddressSpace,
        fd: u64,
        command: u64,
        arg: u64,
    ) -> u64 {
        syscall(k, t, m, 72, [fd, command, arg, 0, 0, 0])
    }
    /// Takes the process's pending signals `number`, which stay with the
    /// thread group while blocked.
    fn taken(k: &Kernel, number: i32) -> Vec<signals::PendingSignal> {
        std::iter::from_fn(|| k.group.take_process_signal(1 << (number - 1))).collect()
    }
    #[test]
    fn an_async_pipe_sends_its_owner_the_setsig_signal() {
        let (mut k, mut t, m) = setup();
        assert_eq!(syscall(&mut k, &mut t, &m, 293, [DATA, 0, 0, 0, 0, 0]), 0);
        let fds = m.read_u64(GuestAddr(DATA)).unwrap();
        let (reader, writer) = (fds & 0xffff_ffff, fds >> 32);
        // Blocked, the signals stay pending to be looked at.
        t.state.signal_mask = 1 << 39;
        assert_eq!(fcntl(&mut k, &mut t, &m, reader, 8, 1), 0);
        assert_eq!(fcntl(&mut k, &mut t, &m, reader, 10, 40), 0);
        assert_eq!(fcntl(&mut k, &mut t, &m, reader, 4, O_ASYNC), 0);
        assert_eq!(fcntl(&mut k, &mut t, &m, reader, 3, 0) & O_ASYNC, O_ASYNC);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 1, [writer, DATA + 64, 1, 0, 0, 0]),
            1
        );
        let info: Vec<_> = taken(&k, 40).iter().filter_map(|s| s.queued).collect();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0][8..12], 1i32.to_le_bytes(), "POLL_IN");
        assert_eq!(info[0][16..24], 0x41i64.to_le_bytes(), "band");
        assert_eq!(info[0][24..28], (reader as i32).to_le_bytes(), "fd");
        // The last writer's close tells the reader too.
        assert_eq!(syscall(&mut k, &mut t, &m, 3, [writer, 0, 0, 0, 0, 0]), 0);
        assert_eq!(taken(&k, 40).len(), 1);
        // Without O_ASYNC nothing more comes.
        assert_eq!(fcntl(&mut k, &mut t, &m, reader, 4, 0), 0);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 0, [reader, DATA + 64, 1, 0, 0, 0]),
            1
        );
        assert!(taken(&k, 40).is_empty());
    }
    #[test]
    fn any_file_keeps_an_owner_but_only_pipes_and_sockets_keep_o_async() {
        let (mut k, mut t, m) = setup();
        let event = syscall(&mut k, &mut t, &m, 290, [0; 6]);
        assert_eq!(fcntl(&mut k, &mut t, &m, event, 4, O_ASYNC), 0);
        assert_eq!(fcntl(&mut k, &mut t, &m, event, 3, 0) & O_ASYNC, 0);
        assert_eq!(fcntl(&mut k, &mut t, &m, event, 8, 1), 0);
        assert_eq!(fcntl(&mut k, &mut t, &m, event, 9, 0), 1);
        // A missing owner is ESRCH and keeps the one there was.
        assert_eq!(
            fcntl(&mut k, &mut t, &m, event, 8, 999_999),
            Errno(3).to_syscall_return()
        );
        assert_eq!(fcntl(&mut k, &mut t, &m, event, 9, 0), 1);
        // F_SETOWN_EX with F_OWNER_TID, read back by F_GETOWN_EX.
        m.write(GuestAddr(DATA), &[0, 0, 0, 0, 1, 0, 0, 0]).unwrap();
        assert_eq!(fcntl(&mut k, &mut t, &m, event, 15, DATA), 0);
        assert_eq!(fcntl(&mut k, &mut t, &m, event, 16, DATA + 8), 0);
        assert_eq!(m.read_u64(GuestAddr(DATA + 8)).unwrap(), 1 << 32);
        m.write(GuestAddr(DATA), &[3, 0, 0, 0, 1, 0, 0, 0]).unwrap();
        assert_eq!(
            fcntl(&mut k, &mut t, &m, event, 15, DATA),
            Errno::EINVAL.to_syscall_return()
        );
        assert_eq!(
            fcntl(&mut k, &mut t, &m, event, 10, 65),
            Errno::EINVAL.to_syscall_return()
        );
        assert_eq!(fcntl(&mut k, &mut t, &m, event, 10, 64), 0);
        assert_eq!(fcntl(&mut k, &mut t, &m, event, 11, 0), 64);
    }
    #[test]
    fn a_closed_stream_peer_hangs_up_with_sigio() {
        let (mut k, mut t, m) = setup();
        assert_eq!(syscall(&mut k, &mut t, &m, 53, [1, 1, 0, DATA, 0, 0]), 0);
        let fds = m.read_u64(GuestAddr(DATA)).unwrap();
        let (a, b) = (fds & 0xffff_ffff, fds >> 32);
        t.state.signal_mask = 1 << 28;
        assert_eq!(fcntl(&mut k, &mut t, &m, b, 8, 1), 0);
        assert_eq!(fcntl(&mut k, &mut t, &m, b, 4, O_ASYNC), 0);
        assert_eq!(syscall(&mut k, &mut t, &m, 3, [a, 0, 0, 0, 0, 0]), 0);
        let io = taken(&k, 29);
        assert_eq!(io.len(), 1);
        assert_eq!(io[0].code, signals::SI_KERNEL);
    }
    /// A socket pair of `kind` with end `b` owned by process 1 with signal
    /// 40 (blocked) and O_ASYNC on both ends.
    fn async_pair(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, kind: u64) -> (u64, u64) {
        assert_eq!(syscall(k, t, m, 53, [1, kind, 0, DATA, 0, 0]), 0);
        let fds = m.read_u64(GuestAddr(DATA)).unwrap();
        let (a, b) = (fds & 0xffff_ffff, fds >> 32);
        t.state.signal_mask = 1 << 39 | 1 << 28 | 1 << 22;
        for fd in [a, b] {
            assert_eq!(fcntl(k, t, m, fd, 8, 1), 0);
            assert_eq!(fcntl(k, t, m, fd, 10, 40), 0);
            let flags = fcntl(k, t, m, fd, 3, 0);
            assert_eq!(fcntl(k, t, m, fd, 4, flags | O_ASYNC), 0);
        }
        (a, b)
    }
    /// The `si_code` and `si_fd` of each taken signal 40, oldest first.
    fn codes(k: &Kernel) -> Vec<(i32, i32)> {
        taken(k, 40)
            .iter()
            .filter_map(|signal| signal.queued)
            .map(|info| {
                let word = |at: usize| i32::from_le_bytes(info[at..at + 4].try_into().unwrap());
                (word(8), word(24))
            })
            .collect()
    }
    #[test]
    fn an_out_of_band_byte_sends_pollpri_then_pollin_and_sigurg() {
        let (mut k, mut t, m) = setup();
        let (a, b) = async_pair(&mut k, &mut t, &m, 1);
        m.write(GuestAddr(DATA + 64), b"z").unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 44, [a, DATA + 64, 1, 1, 0, 0]),
            1
        );
        let b = b as i32;
        assert_eq!(codes(&k), [(5, b), (1, b)]);
        assert_eq!(taken(&k, 23).len(), 1);
        // Without F_SETSIG, SIGURG stands for POLL_PRI and SIGIO for the data.
        assert_eq!(fcntl(&mut k, &mut t, &m, b as u64, 10, 0), 0);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 44, [a, DATA + 64, 1, 1, 0, 0]),
            1
        );
        assert!(codes(&k).is_empty());
        assert_eq!(taken(&k, 23).len(), 1);
        assert_eq!(taken(&k, 29).len(), 1);
    }
    #[test]
    fn a_full_socket_signals_its_writer_once_three_quarters_are_free() {
        let (mut k, mut t, m) = setup();
        let (a, b) = async_pair(&mut k, &mut t, &m, 1 | 0o4000);
        let full = loop {
            let sent = syscall(&mut k, &mut t, &m, 1, [a, DATA, 4096, 0, 0, 0]);
            if sent == Errno::EAGAIN.to_syscall_return() {
                break sent;
            }
        };
        assert_eq!(full, Errno::EAGAIN.to_syscall_return());
        // Every send told the reader; the writer has had nothing yet.
        assert!(
            codes(&k)
                .iter()
                .all(|&(code, fd)| (code, fd) == (1, b as i32))
        );
        // Room alone does not signal: only once the writer is writable to
        // poll, a quarter of its send buffer holding what waits, as
        // unix_write_space checks unix_writable.
        let writer = k.files.descriptor(a).unwrap().file;
        let writable = |writer: &Arc<dyn paludarium_host::FileHandle>| {
            writer.readiness().unwrap().0 & crate::events::OUT != 0
        };
        while !writable(&writer) {
            assert!(codes(&k).is_empty());
            assert_eq!(
                syscall(&mut k, &mut t, &m, 0, [b, DATA, 4096, 0, 0, 0]),
                4096
            );
        }
        assert_eq!(codes(&k), [(2, a as i32)]);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 0, [b, DATA, 4096, 0, 0, 0]),
            4096
        );
        assert!(codes(&k).is_empty());
    }
    #[test]
    fn a_waiting_stream_reader_gets_no_signal_for_what_ends_its_wait() {
        let (mut k, mut t, m) = setup();
        let (a, b) = async_pair(&mut k, &mut t, &m, 1);
        let reader = k.files.descriptor(b).unwrap().file;
        let b = b as i32;
        m.write(GuestAddr(DATA + 64), b"xy").unwrap();
        // Only the first part of a send ends the wait.
        crate::sockets::wait_data(&reader, true);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 1, [a, DATA + 64, 1, 0, 0, 0]),
            1
        );
        assert!(codes(&k).is_empty());
        assert_eq!(
            syscall(&mut k, &mut t, &m, 1, [a, DATA + 64, 1, 0, 0, 0]),
            1
        );
        assert_eq!(codes(&k), [(1, b)]);
        // An out-of-band byte still signals POLL_PRI, a shutdown nothing.
        crate::sockets::wait_data(&reader, true);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 44, [a, DATA + 64, 1, 1, 0, 0]),
            1
        );
        assert_eq!(codes(&k), [(5, b)]);
        assert_eq!(taken(&k, 23).len(), 1);
        crate::sockets::wait_data(&reader, true);
        assert_eq!(syscall(&mut k, &mut t, &m, 48, [a, 1, 0, 0, 0, 0]), 0);
        assert!(codes(&k).is_empty());
        // A wait that ended otherwise holds nothing back.
        crate::sockets::wait_data(&reader, true);
        crate::sockets::wait_data(&reader, false);
        assert_eq!(syscall(&mut k, &mut t, &m, 3, [a, 0, 0, 0, 0, 0]), 0);
        assert_eq!(codes(&k), [(6, b)]);
    }
    #[test]
    fn a_datagram_reader_that_waits_still_gets_its_signal() {
        let (mut k, mut t, m) = setup();
        let (a, b) = async_pair(&mut k, &mut t, &m, 2);
        let reader = k.files.descriptor(b).unwrap().file;
        crate::sockets::wait_data(&reader, true);
        assert_eq!(syscall(&mut k, &mut t, &m, 1, [a, DATA, 1, 0, 0, 0]), 1);
        assert_eq!(codes(&k), [(1, b as i32)]);
    }
    #[test]
    fn shutdowns_signal_a_stream_peer_but_not_a_datagram_one() {
        let (mut k, mut t, m) = setup();
        let (a, b) = async_pair(&mut k, &mut t, &m, 1);
        assert_eq!(syscall(&mut k, &mut t, &m, 48, [a, 0, 0, 0, 0, 0]), 0);
        assert!(codes(&k).is_empty());
        assert_eq!(syscall(&mut k, &mut t, &m, 48, [a, 1, 0, 0, 0, 0]), 0);
        assert_eq!(codes(&k), [(1, b as i32)]);
        assert_eq!(syscall(&mut k, &mut t, &m, 48, [b, 2, 0, 0, 0, 0]), 0);
        assert_eq!(codes(&k), [(6, a as i32)]);
        let (c, d) = async_pair(&mut k, &mut t, &m, 2);
        assert_eq!(syscall(&mut k, &mut t, &m, 48, [c, 2, 0, 0, 0, 0]), 0);
        assert_eq!(syscall(&mut k, &mut t, &m, 3, [c, 0, 0, 0, 0, 0]), 0);
        assert!(codes(&k).is_empty());
        // A send to the closed peer is refused and signals nothing.
        assert_eq!(
            syscall(&mut k, &mut t, &m, 44, [d, DATA, 0, 0, 0, 0]),
            Errno(111).to_syscall_return()
        );
        assert!(codes(&k).is_empty());
    }
    #[test]
    fn a_pipe_that_finds_nothing_or_no_room_still_signals() {
        let (mut k, mut t, m) = setup();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 293, [DATA, 0o4000, 0, 0, 0, 0]),
            0
        );
        let fds = m.read_u64(GuestAddr(DATA)).unwrap();
        let (reader, writer) = (fds & 0xffff_ffff, fds >> 32);
        t.state.signal_mask = 1 << 39;
        for fd in [reader, writer] {
            assert_eq!(fcntl(&mut k, &mut t, &m, fd, 8, 1), 0);
            assert_eq!(fcntl(&mut k, &mut t, &m, fd, 10, 40), 0);
            assert_eq!(fcntl(&mut k, &mut t, &m, fd, 4, O_ASYNC | 0o4000), 0);
        }
        assert_eq!(
            syscall(&mut k, &mut t, &m, 0, [reader, DATA, 1, 0, 0, 0]),
            Errno::EAGAIN.to_syscall_return()
        );
        assert_eq!(codes(&k), [(2, writer as i32)]);
        // An empty read signals nothing.
        assert_eq!(
            syscall(&mut k, &mut t, &m, 0, [reader, DATA, 0, 0, 0, 0]),
            0
        );
        assert!(codes(&k).is_empty());
        while syscall(&mut k, &mut t, &m, 1, [writer, DATA, 4096, 0, 0, 0]) == 4096 {}
        assert!(codes(&k).iter().all(|&code| code == (1, reader as i32)));
        assert_eq!(
            syscall(&mut k, &mut t, &m, 1, [writer, DATA, 1, 0, 0, 0]),
            Errno::EAGAIN.to_syscall_return()
        );
        assert_eq!(codes(&k), [(1, reader as i32)]);
        // The last reader's close tells the writer.
        assert_eq!(syscall(&mut k, &mut t, &m, 3, [reader, 0, 0, 0, 0, 0]), 0);
        assert_eq!(codes(&k), [(2, writer as i32)]);
    }
    #[test]
    fn a_thread_owner_gets_a_signal_directed_at_it() {
        let (mut k, mut t, m) = setup();
        assert_eq!(syscall(&mut k, &mut t, &m, 293, [DATA, 0, 0, 0, 0, 0]), 0);
        let fds = m.read_u64(GuestAddr(DATA)).unwrap();
        let (reader, writer) = (fds & 0xffff_ffff, fds >> 32);
        t.state.signal_mask = 1 << 39;
        m.write(GuestAddr(DATA + 16), &[0, 0, 0, 0, 1, 0, 0, 0])
            .unwrap();
        assert_eq!(fcntl(&mut k, &mut t, &m, reader, 15, DATA + 16), 0);
        assert_eq!(fcntl(&mut k, &mut t, &m, reader, 9, 0), 1);
        assert_eq!(fcntl(&mut k, &mut t, &m, reader, 10, 40), 0);
        assert_eq!(fcntl(&mut k, &mut t, &m, reader, 4, O_ASYNC), 0);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 1, [writer, DATA, 1, 0, 0, 0]),
            1
        );
        let directed: Vec<_> = t.state.pending.iter().filter(|s| s.number == 40).collect();
        assert_eq!(directed.len(), 1);
        assert_eq!(directed[0].target, signals::PendingTarget::Thread);
        assert!(taken(&k, 40).is_empty());
    }
    #[test]
    fn owner_errors_and_a_group_owner_read_back_as_linux_gives_them() {
        let (mut k, mut t, m) = setup();
        let event = syscall(&mut k, &mut t, &m, 290, [0; 6]);
        let fault = Errno::EFAULT.to_syscall_return();
        assert_eq!(fcntl(&mut k, &mut t, &m, event, 15, 8), fault);
        assert_eq!(fcntl(&mut k, &mut t, &m, event, 16, 8), fault);
        assert_eq!(
            fcntl(&mut k, &mut t, &m, event, 8, i32::MIN as u32 as u64),
            Errno::EINVAL.to_syscall_return()
        );
        m.write(GuestAddr(DATA), &[1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff])
            .unwrap();
        assert_eq!(
            fcntl(&mut k, &mut t, &m, event, 15, DATA),
            Errno(3).to_syscall_return()
        );
        // F_SETOWN names group 1 negative: no group has the ID, but the
        // first process does, and Linux finds the ID, not a group. Reading
        // the owner back gives 0 while no process is in the group.
        assert_eq!(
            fcntl(&mut k, &mut t, &m, event, 8, (-1i32) as u32 as u64),
            0
        );
        assert_eq!(fcntl(&mut k, &mut t, &m, event, 9, 0), 0);
        assert_eq!(fcntl(&mut k, &mut t, &m, event, 16, DATA + 8), 0);
        assert_eq!(m.read_u64(GuestAddr(DATA + 8)).unwrap(), 2);
        // Once the first process leads group 1, the group is read back.
        assert_eq!(syscall(&mut k, &mut t, &m, 109, [0; 6]), 0);
        assert_eq!(fcntl(&mut k, &mut t, &m, event, 9, 0) as i64, -1);
        assert_eq!(fcntl(&mut k, &mut t, &m, event, 16, DATA + 8), 0);
        assert_eq!(m.read_u64(GuestAddr(DATA + 8)).unwrap(), 1 << 32 | 2);
    }
}
mod socket_credentials {
    use super::*;
    const MESSAGE: u64 = DATA + 256;
    const CONTROL: u64 = DATA + 512;
    /// A socket pair of `kind` whose second end passes credentials.
    fn pair(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, kind: u64) -> (u64, u64) {
        assert_eq!(syscall(k, t, m, 53, [1, kind, 0, DATA, 0, 0]), 0);
        let fds = m.read_u64(GuestAddr(DATA)).unwrap();
        let (a, b) = (fds & 0xffff_ffff, fds >> 32);
        m.write(GuestAddr(DATA + 16), &1i32.to_le_bytes()).unwrap();
        assert_eq!(syscall(k, t, m, 54, [b, 1, 16, DATA + 16, 4, 0]), 0);
        (a, b)
    }
    /// A msghdr of one byte at DATA + 64 and `control_len` control bytes.
    fn message(m: &AddressSpace, control_len: u64) {
        m.write_u64(GuestAddr(DATA + 128), DATA + 64).unwrap();
        m.write_u64(GuestAddr(DATA + 136), 1).unwrap();
        m.write(GuestAddr(MESSAGE), &[0; 56]).unwrap();
        m.write_u64(GuestAddr(MESSAGE + 16), DATA + 128).unwrap();
        m.write_u64(GuestAddr(MESSAGE + 24), 1).unwrap();
        m.write_u64(GuestAddr(MESSAGE + 32), CONTROL).unwrap();
        m.write_u64(GuestAddr(MESSAGE + 40), control_len).unwrap();
    }
    fn send(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, fd: u64, ids: [u32; 3]) -> u64 {
        m.write_u64(GuestAddr(CONTROL), 28).unwrap();
        m.write(GuestAddr(CONTROL + 8), &1u32.to_le_bytes())
            .unwrap();
        m.write(GuestAddr(CONTROL + 12), &2u32.to_le_bytes())
            .unwrap();
        for (i, id) in ids.into_iter().enumerate() {
            m.write(GuestAddr(CONTROL + 16 + 4 * i as u64), &id.to_le_bytes())
                .unwrap();
        }
        message(m, 32);
        syscall(k, t, m, 46, [fd, MESSAGE, 0, 0, 0, 0])
    }
    /// recvmsg's result and the credentials it gives.
    fn receive(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, fd: u64) -> (u64, [u32; 3]) {
        m.write(GuestAddr(CONTROL), &[0; 64]).unwrap();
        message(m, 64);
        let n = syscall(k, t, m, 47, [fd, MESSAGE, 0x40, 0, 0, 0]);
        let mut raw = [0; 12];
        m.read(GuestAddr(CONTROL + 16), &mut raw).unwrap();
        let ids = [0, 4, 8].map(|i| u32::from_le_bytes(raw[i..i + 4].try_into().unwrap()));
        (n, ids)
    }
    #[test]
    fn root_sends_the_credentials_of_any_process_and_ids() {
        let (mut k, mut t, m) = setup();
        let (_, child, _) = fork(&mut k, &mut t, &m);
        let (a, b) = pair(&mut k, &mut t, &m, 2);
        let child = child.tid;
        assert_eq!(send(&mut k, &mut t, &m, a, [child, 1234, 5678]), 1);
        assert_eq!(receive(&mut k, &mut t, &m, b), (1, [child, 1234, 5678]));
        // A process ID must name one, and neither ID be -1.
        let esrch = Errno(3).to_syscall_return();
        assert_eq!(send(&mut k, &mut t, &m, a, [999_999, 0, 0]), esrch);
        assert_eq!(send(&mut k, &mut t, &m, a, [0, 0, 0]), esrch);
        assert_eq!(send(&mut k, &mut t, &m, a, [u32::MAX, 0, 0]), esrch);
        let einval = Errno::EINVAL.to_syscall_return();
        assert_eq!(send(&mut k, &mut t, &m, a, [child, u32::MAX, 0]), einval);
        assert_eq!(send(&mut k, &mut t, &m, a, [child, 0, u32::MAX]), einval);
        // The IDs are checked before the process is looked up.
        assert_eq!(send(&mut k, &mut t, &m, a, [999_999, u32::MAX, 0]), einval);
        assert_eq!(
            receive(&mut k, &mut t, &m, b).0,
            Errno::EAGAIN.to_syscall_return()
        );
    }
    #[test]
    fn a_stream_does_not_read_writes_of_other_credentials_together() {
        let (mut k, mut t, m) = setup();
        let (_, child, _) = fork(&mut k, &mut t, &m);
        let pid = syscall(&mut k, &mut t, &m, 39, [0; 6]) as u32;
        let (a, b) = pair(&mut k, &mut t, &m, 1);
        assert_eq!(send(&mut k, &mut t, &m, a, [child.tid, 0, 0]), 1);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 1, [a, DATA + 64, 1, 0, 0, 0]),
            1
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 1, [a, DATA + 64, 1, 0, 0, 0]),
            1
        );
        // A peek stops where a read would.
        let peek = syscall(&mut k, &mut t, &m, 45, [b, DATA + 300, 8, 0x42, 0, 0]);
        assert_eq!(peek, 1);
        assert_eq!(receive(&mut k, &mut t, &m, b), (1, [child.tid, 0, 0]));
        // MSG_WAITALL stops there too, without waiting.
        let all = syscall(&mut k, &mut t, &m, 45, [b, DATA + 300, 2, 0x100, 0, 0]);
        assert_eq!(all, 2);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 1, [a, DATA + 64, 1, 0, 0, 0]),
            1
        );
        assert_eq!(send(&mut k, &mut t, &m, a, [child.tid, 0, 0]), 1);
        let all = syscall(&mut k, &mut t, &m, 45, [b, DATA + 300, 8, 0x102, 0, 0]);
        assert_eq!(all, 1);
        assert_eq!(receive(&mut k, &mut t, &m, b), (1, [pid, 0, 0]));
        assert_eq!(receive(&mut k, &mut t, &m, b), (1, [child.tid, 0, 0]));
        // Without SO_PASSCRED they are read together.
        m.write(GuestAddr(DATA + 16), &0i32.to_le_bytes()).unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 54, [b, 1, 16, DATA + 16, 4, 0]),
            0
        );
        assert_eq!(send(&mut k, &mut t, &m, a, [child.tid, 0, 0]), 1);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 1, [a, DATA + 64, 1, 0, 0, 0]),
            1
        );
        assert_eq!(
            syscall(&mut k, &mut t, &m, 0, [b, DATA + 300, 8, 0, 0, 0]),
            2
        );
    }
}
