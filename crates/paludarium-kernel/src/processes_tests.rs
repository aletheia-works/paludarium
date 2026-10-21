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
    fn parent_registration() {
        let (mut k, mut t, m) = setup();
        let (mut c, mut ct, cm) = fork(&mut k, &mut t, &m);
        assert_eq!(syscall(&mut c, &mut ct, &cm, 110, [0; 6]), 1);
        assert_eq!(
            syscall(&mut k, &mut t, &m, 61, [u64::MAX, 0, 1, 0, 0, 0]),
            0
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
    #[test]
    fn racing_reapers() {
        let (mut k, mut t, m) = setup();
        let (mut c, ct, cm) = fork(&mut k, &mut t, &m);
        finish(&mut c, &ct, &cm, ExitStatus::Exited(0));
        let processes = k.processes();
        let ids = std::thread::scope(|scope| {
            let a = processes.clone();
            let b = processes.clone();
            let first = scope.spawn(move || a.reap(1, -1));
            let second = scope.spawn(move || b.reap(1, -1));
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
