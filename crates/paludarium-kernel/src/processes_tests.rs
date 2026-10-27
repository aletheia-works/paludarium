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
    fn clone3_with_clone_newtime_creates_no_child() {
        // clone3 joins CLONE_NEWTIME (0x80) to the exit signal's bits, so
        // the clone sees 0x91 there and refuses it: no child is left whose
        // exit signal is not SIGCHLD. Time namespaces are not supported.
        let (mut k, mut t, m) = setup();
        let words = [0x80u64, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0];
        m.write(GuestAddr(DATA + 512), &words.map(u64::to_le_bytes).concat())
            .unwrap();
        assert_eq!(
            syscall(&mut k, &mut t, &m, 435, [DATA + 512, 88, 0, 0, 0, 0]),
            Errno::EINVAL.to_syscall_return()
        );
        assert!(k.take_child().is_none());
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
    #[test]
    fn namespace_flags_and_calls_are_refused() {
        let (mut k, mut t, m) = setup();
        // CLONE_NEWNS, CLONE_NEWCGROUP, CLONE_NEWUTS, CLONE_NEWIPC,
        // CLONE_NEWUSER, CLONE_NEWPID and CLONE_NEWNET, which root may use
        // on Linux: no namespace is created, and neither is a child.
        for flag in [
            0x2_0000,
            0x200_0000,
            0x400_0000,
            0x800_0000,
            0x1000_0000,
            0x2000_0000,
            0x4000_0000,
        ] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, 56, [flag | 17, 0, 0, 0, 0, 0]),
                Errno::EINVAL.to_syscall_return(),
                "{flag:#x}"
            );
            assert!(k.take_child().is_none());
        }
        // unshare and setns are not implemented.
        for number in [272, 308] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, number, [0; 6]),
                Errno::ENOSYS.to_syscall_return()
            );
        }
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
        k.group.send_process_from(10, 2).unwrap();
        k.group.drain_process(&mut t.state);
        k.group.send_process_from(34, 2).unwrap();
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
