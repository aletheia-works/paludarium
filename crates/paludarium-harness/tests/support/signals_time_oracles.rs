//! Native-only infrastructure observes blocking writes and job control; the
//! checked Kernel interface is compared without implementing guest fork/pipe.
use super::*;
use paludarium_cpu::{CpuState, reg};
use paludarium_host::{Host, testing::RecordingHost};
use paludarium_kernel::{Kernel, Next, Thread, nr};
use paludarium_mmu::{AddressSpace, MappingKind, Prot};
use paludarium_types::{Errno, Error, ExitReason, ExitStatus, GuestAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
const DATA: u64 = 0x100000;
struct WriteHost(AtomicBool);
impl Host for WriteHost {
    fn read_stdin(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Ok(0)
    }
    fn write_stdout(&self, b: &[u8]) -> Result<usize, Errno> {
        if !self.0.swap(true, Ordering::SeqCst) {
            Err(Errno(4))
        } else {
            Ok(b.len())
        }
    }
    fn write_stderr(&self, b: &[u8]) -> Result<usize, Errno> {
        self.write_stdout(b)
    }
    fn random_bytes(&self, b: &mut [u8]) -> Result<(), Error> {
        b.fill(0);
        Ok(())
    }
}
fn setup(host: Arc<dyn Host>) -> (Kernel, Thread, AddressSpace) {
    let kernel = Kernel::new(host);
    let mut cpu = CpuState::new(GuestAddr(0x400002), GuestAddr(DATA + 8192));
    cpu.rflags = 0x202;
    let mut memory = AddressSpace::new();
    memory
        .map(
            Some(GuestAddr(DATA)),
            8192,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    (kernel, Thread::new(1, cpu), memory)
}
fn call(k: &mut Kernel, t: &mut Thread, m: &mut AddressSpace, number: u64, args: &[u64]) -> Next {
    t.cpu.gpr[reg::RAX] = number;
    for (r, a) in [reg::RDI, reg::RSI, reg::RDX, reg::R10, reg::R8, reg::R9]
        .iter()
        .zip(args)
    {
        t.cpu.gpr[*r] = *a;
    }
    k.handle(t, m, ExitReason::Syscall { rip: t.cpu.rip })
}
fn native(binary: &str, mode: usize) -> String {
    let out = run_native(&build_u4().join(binary), binary, &[mode.to_string()]).unwrap();
    assert_eq!(out.status, ExitStatus::Exited(0));
    assert!(out.stderr.is_empty());
    String::from_utf8(out.stdout).unwrap()
}
#[test]
fn u4_write_restart_native_oracle() {
    build_u4();
    support::bounded("oracles::u4_write_restart_native_oracle", || {
        for restart in 0..=1 {
            let expected = native("write-restart-oracle", restart);
            let (mut k, mut t, mut m) = setup(Arc::new(WriteHost(AtomicBool::new(false))));
            for (i, value) in [
                0x400100,
                if restart == 1 { 0x10000000 } else { 0 },
                0x400200,
                0,
            ]
            .iter()
            .enumerate()
            {
                m.write_u64(GuestAddr(DATA + i as u64 * 8), *value).unwrap();
            }
            assert_eq!(
                call(&mut k, &mut t, &mut m, nr::RT_SIGACTION, &[10, DATA, 0, 8]),
                Next::Resume
            );
            k.queue_signal(&mut t, 10).unwrap();
            assert_eq!(
                call(&mut k, &mut t, &mut m, nr::WRITE, &[1, DATA + 64, 1]),
                Next::Resume
            );
            let base = t.cpu.gpr[reg::RSP];
            let frame_rax = m.read_u64(GuestAddr(base + 48 + 13 * 8)).unwrap() as i64;
            let frame_rip = m.read_u64(GuestAddr(base + 48 + 16 * 8)).unwrap();
            let site = match frame_rip {
                0x400000 => 0,
                0x400002 => 1,
                _ => 2,
            };
            t.cpu.gpr[reg::RSP] += 8;
            assert_eq!(
                call(&mut k, &mut t, &mut m, nr::RT_SIGRETURN, &[]),
                Next::Resume
            );
            if t.cpu.rip == GuestAddr(0x400000) {
                t.cpu.rip = GuestAddr(0x400002);
                assert_eq!(
                    call(&mut k, &mut t, &mut m, nr::WRITE, &[1, DATA + 64, 1]),
                    Next::Resume
                );
            }
            let actual = format!(
                "restart={restart} frame_rax={frame_rax} frame_site={site} result={}\n",
                t.cpu.gpr[reg::RAX] as i64
            );
            println!("native={expected:?}; kernel={actual:?}");
            assert_eq!(actual, expected);
        }
    });
}
#[test]
fn u4_stop_continue_native_oracle() {
    build_u4();
    support::bounded("oracles::u4_stop_continue_native_oracle", || {
        for mode in 0..7 {
            let expected = native("stop-continue-oracle", mode);
            let (mut k, mut t, mut m) = setup(Arc::new(RecordingHost::new()));
            if mode == 2 || mode == 4 {
                let mask = if mode == 2 { 1 << 17 } else { 1 << 19 };
                m.write_u64(GuestAddr(DATA), mask).unwrap();
                assert_eq!(
                    call(&mut k, &mut t, &mut m, nr::RT_SIGPROCMASK, &[2, DATA, 0, 8]),
                    Next::Resume
                );
            }
            let before = t.cpu.clone();
            let stop = if mode == 1 || mode == 4 { 20 } else { 19 };
            k.queue_signal(&mut t, stop).unwrap();
            let decision = k.checkpoint(&mut t, &m);
            assert_eq!(t.cpu, before);
            let stopped = if decision == Next::Stopped {
                stop
            } else {
                assert_eq!(decision, Next::Resume);
                0
            };
            let (exit, signal) = if mode == 3 || mode >= 5 {
                if mode >= 5 {
                    for _ in 0..2048 {
                        k.queue_signal(&mut t, 34).unwrap();
                    }
                }
                k.queue_signal(&mut t, 9).unwrap();
                if mode == 6 {
                    k.queue_signal(&mut t, 18).unwrap();
                }
                match k.checkpoint(&mut t, &m) {
                    Next::Exit(ExitStatus::Signaled(s)) => (-1, s),
                    other => panic!("kill decision {other:?}"),
                }
            } else {
                k.queue_signal(&mut t, 18).unwrap();
                assert_eq!(k.checkpoint(&mut t, &m), Next::Resume);
                assert_eq!(t.cpu, before);
                match call(&mut k, &mut t, &mut m, nr::EXIT_GROUP, &[7]) {
                    Next::Exit(ExitStatus::Exited(code)) => (code, 0),
                    other => panic!("resumed exit decision {other:?}"),
                }
            };
            let actual = format!("stopped={stopped} exit={exit} signal={signal}\n");
            println!("native={expected:?}; kernel={actual:?}");
            assert_eq!(actual, expected);
        }
    });
}

#[test]
fn u4_realtime_order_native_oracle() {
    build_u4();
    support::bounded("oracles::u4_realtime_order_native_oracle", || {
        let mut mismatches = Vec::new();
        println!(
            "native_same_process_queue_fifo={:?}",
            native("realtime-order-oracle", 2)
        );
        println!(
            "native_same_thread_queue_fifo={:?}",
            native("realtime-order-oracle", 8)
        );
        for mode in [0, 1, 3, 4, 5, 6, 7] {
            let expected = native("realtime-order-oracle", mode);
            let (mut k, mut t, mut m) = setup(Arc::new(RecordingHost::new()));
            let mask = (1u64 << 9) | (1u64 << 34) | (1u64 << 35);
            if mode != 0 {
                for (i, value) in [0x400100, 4, 0x400200, mask].iter().enumerate() {
                    m.write_u64(GuestAddr(DATA + i as u64 * 8), *value).unwrap();
                }
                for number in [10, 35, 36] {
                    assert_eq!(
                        call(
                            &mut k,
                            &mut t,
                            &mut m,
                            nr::RT_SIGACTION,
                            &[number, DATA, 0, 8]
                        ),
                        Next::Resume
                    );
                }
            }
            m.write_u64(GuestAddr(DATA + 64), mask).unwrap();
            assert_eq!(
                call(
                    &mut k,
                    &mut t,
                    &mut m,
                    nr::RT_SIGPROCMASK,
                    &[2, DATA + 64, 0, 8]
                ),
                Next::Resume
            );
            match mode {
                0 | 1 => {
                    k.queue_signal(&mut t, 36).unwrap();
                    k.queue_signal(&mut t, 35).unwrap();
                }
                3 => {
                    k.queue_signal(&mut t, 35).unwrap();
                    k.queue_signal(&mut t, 10).unwrap();
                }
                4..=7 => {
                    let process_number = if mode == 7 { 10 } else { 35 };
                    let thread_number = if mode == 7 {
                        10
                    } else if mode == 6 {
                        35
                    } else {
                        36
                    };
                    let repetitions = if mode == 7 { 2 } else { 1 };
                    for _ in 0..repetitions {
                        assert_eq!(
                            call(&mut k, &mut t, &mut m, nr::KILL, &[1, process_number]),
                            Next::Resume
                        );
                    }
                    for _ in 0..repetitions {
                        let next = if mode == 5 {
                            call(&mut k, &mut t, &mut m, nr::TGKILL, &[1, 1, thread_number])
                        } else {
                            call(&mut k, &mut t, &mut m, nr::TKILL, &[1, thread_number])
                        };
                        assert_eq!(next, Next::Resume);
                    }
                }
                _ => unreachable!(),
            }
            m.write_u64(GuestAddr(DATA + 64), 0).unwrap();
            let next = call(
                &mut k,
                &mut t,
                &mut m,
                nr::RT_SIGPROCMASK,
                &[2, DATA + 64, 0, 8],
            );
            let actual = if mode == 0 {
                match next {
                    Next::Exit(ExitStatus::Signaled(number)) => {
                        format!("default_signal={number}\n")
                    }
                    other => panic!("default signal decision {other:?}"),
                }
            } else {
                assert_eq!(next, Next::Resume);
                let mut order = Vec::new();
                while t.cpu.rip == GuestAddr(0x400100) {
                    assert!(order.len() < 4, "fixture delivery budget exceeded");
                    let entry = (
                        t.cpu.gpr[reg::RDI],
                        m.read_u64(GuestAddr(t.cpu.gpr[reg::RSP] + 312 + 8))
                            .unwrap() as i32,
                    );
                    order.push(format!("{}:{}", entry.0, entry.1));
                    t.cpu.gpr[reg::RSP] += 8;
                    assert_eq!(
                        call(&mut k, &mut t, &mut m, nr::RT_SIGRETURN, &[]),
                        Next::Resume
                    );
                }
                format!("order={}\n", order.join(","))
            };
            println!("mode={mode} native={expected:?}; kernel={actual:?}");
            if actual != expected {
                mismatches.push((mode, actual, expected));
            }
        }
        assert!(
            mismatches.is_empty(),
            "pending order mismatches: {mismatches:?}"
        );
    });
}
