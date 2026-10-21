//! Runner bootstrap: independent host workers run real differential guests.
//! Shared-address-space atomic cases are added after the MMU implementation.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/instructions.rs"]
mod support;
use paludarium_mmu::{AddressSpace, AtomicOp, AtomicWidth, MappingKind, Prot};
use paludarium_types::GuestAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

fn memory() -> Arc<AddressSpace> {
    let m = Arc::new(AddressSpace::new());
    m.map_shared(
        Some(GuestAddr(0x10000)),
        8192,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    m
}
fn workers<T: Send + 'static>(operation: impl Fn() -> T + Send + Sync + 'static) -> Vec<T> {
    let start = Arc::new(Barrier::new(4));
    let operation = Arc::new(operation);
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let start = start.clone();
            let operation = operation.clone();
            std::thread::spawn(move || {
                start.wait();
                operation()
            })
        })
        .collect();
    threads.into_iter().map(|t| t.join().unwrap()).collect()
}
#[test]
fn atomic_add_parallel_native() {
    support::bounded("atomic_add_parallel_native", || {
        let native = Arc::new(AtomicU64::new(0));
        let n = native.clone();
        let mut expected: Vec<_> = workers(move || {
            (0..256)
                .map(|_| n.fetch_add(1, Ordering::SeqCst))
                .collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect();
        let m = memory();
        let data = m.clone();
        let mut actual: Vec<_> = workers(move || {
            (0..256)
                .map(|_| {
                    data.atomic(GuestAddr(0x10000), AtomicWidth::W64, AtomicOp::Add(1))
                        .unwrap()
                        .old as u64
                })
                .collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect();
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(actual, expected);
        assert_eq!(
            m.read_u64(GuestAddr(0x10000)).unwrap(),
            native.load(Ordering::SeqCst)
        );
    });
}
#[test]
fn cpu_lock_xadd_parallel_native() {
    support::bounded("cpu_lock_xadd_parallel_native", || {
        let native = Arc::new(AtomicU64::new(0));
        let n = native.clone();
        let mut expected: Vec<_> = workers(move || {
            (0..256)
                .map(|_| n.fetch_add(1, Ordering::SeqCst))
                .collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect();
        let m = memory();
        m.map_shared(
            Some(GuestAddr(0x30000)),
            4096,
            Prot::READ_EXEC,
            MappingKind::Anonymous,
        )
        .unwrap();
        m.write_initial(GuestAddr(0x30000), &[0xf0, 0x48, 0x0f, 0xc1, 0x07])
            .unwrap();
        let shared = m.clone();
        let mut actual: Vec<_> = workers(move || {
            (0..256)
                .map(|_| {
                    let mut state = paludarium_cpu::CpuState::new(GuestAddr(0x30000), GuestAddr(0));
                    state.gpr[paludarium_cpu::reg::RAX] = 1;
                    state.gpr[paludarium_cpu::reg::RDI] = 0x10000;
                    paludarium_cpu::step(&mut state, &shared).unwrap();
                    state.gpr[paludarium_cpu::reg::RAX]
                })
                .collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect();
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(actual, expected);
        assert_eq!(
            m.read_u64(GuestAddr(0x10000)).unwrap(),
            native.load(Ordering::SeqCst)
        );
    });
}
#[test]
fn compare_exchange_parallel_native() {
    support::bounded("compare_exchange_parallel_native", || {
        let n = Arc::new(AtomicU64::new(0));
        let mut expected =
            workers(
                move || match n.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst) {
                    Ok(old) => (old, true),
                    Err(old) => (old, false),
                },
            );
        let m = memory();
        let mut actual = workers(move || {
            let r = m
                .atomic(
                    GuestAddr(0x10000),
                    AtomicWidth::W64,
                    AtomicOp::CompareExchange {
                        expected: 0,
                        replacement: 1,
                    },
                )
                .unwrap();
            (r.old as u64, r.exchanged)
        });
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(actual, expected);
    });
}
#[test]
fn atomic_exchange_reads_no_tearing() {
    support::bounded("atomic_exchange_reads_no_tearing", || {
        let m = memory();
        workers(move || {
            for j in 0..512 {
                let value = if j % 2 == 0 { u128::MAX } else { 0 };
                let old = m
                    .atomic(
                        GuestAddr(0x10000),
                        AtomicWidth::W128,
                        AtomicOp::Exchange(value),
                    )
                    .unwrap()
                    .old;
                assert!(old == 0 || old == u128::MAX);
                let mut b = [0; 16];
                m.read(GuestAddr(0x10000), &mut b).unwrap();
                assert!(b == [0; 16] || b == [255; 16]);
            }
        });
    });
}
#[test]
fn atomic_vs_normal_writes_no_tearing() {
    support::bounded("atomic_vs_normal_writes_no_tearing", || {
        let m = memory();
        workers(move || {
            for j in 0..512 {
                m.write_u64(GuestAddr(0x10000), if j % 2 == 0 { u64::MAX } else { 0 })
                    .unwrap();
                let old = m
                    .atomic(GuestAddr(0x10000), AtomicWidth::W64, AtomicOp::Exchange(0))
                    .unwrap()
                    .old;
                assert!(old == 0 || old == u128::from(u64::MAX));
            }
        });
    });
}
#[test]
fn mapping_protect_competes_with_atomic() {
    support::bounded("mapping_protect_competes_with_atomic", || {
        let m = memory();
        workers(move || {
            for j in 0..128 {
                m.protect_shared(
                    GuestAddr(0x10000),
                    4096,
                    if j % 2 == 0 {
                        Prot::READ
                    } else {
                        Prot::READ_WRITE
                    },
                )
                .unwrap();
                if let Err(f) = m.atomic(GuestAddr(0x10000), AtomicWidth::W64, AtomicOp::Add(1)) {
                    assert!(f.write);
                    assert_eq!(f.addr, GuestAddr(0x10000));
                }
            }
        });
    });
}
#[test]
fn mapping_unmap_remap_competes() {
    support::bounded("mapping_unmap_remap_competes", || {
        let m = memory();
        workers(move || {
            for _ in 0..128 {
                m.unmap_shared(GuestAddr(0x10000), 4096).unwrap();
                let _ = m.map_shared(
                    Some(GuestAddr(0x10000)),
                    4096,
                    Prot::READ_WRITE,
                    MappingKind::Anonymous,
                );
                if let Err(f) = m.atomic(GuestAddr(0x10000), AtomicWidth::W64, AtomicOp::Add(1)) {
                    assert_eq!(f.addr, GuestAddr(0x10000));
                }
            }
        });
    });
}
#[test]
fn unaligned_cross_page_parallel() {
    support::bounded("unaligned_cross_page_parallel", || {
        let native = Arc::new(AtomicU64::new(0));
        let n = native.clone();
        let mut expected: Vec<_> = workers(move || {
            (0..128)
                .map(|_| n.fetch_add(1, Ordering::SeqCst))
                .collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect();
        let m = memory();
        let data = m.clone();
        let mut actual: Vec<_> = workers(move || {
            (0..128)
                .map(|_| {
                    data.atomic(GuestAddr(0x10ffd), AtomicWidth::W64, AtomicOp::Add(1))
                        .unwrap()
                        .old as u64
                })
                .collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect();
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(actual, expected);
        assert_eq!(
            m.read_u64(GuestAddr(0x10ffd)).unwrap(),
            native.load(Ordering::SeqCst)
        );
    });
}
#[test]
fn readonly_failed_cmpxchg_parallel() {
    support::bounded("readonly_failed_cmpxchg_parallel", || {
        let m = memory();
        m.write_u64(GuestAddr(0x10000), 7).unwrap();
        m.protect_shared(GuestAddr(0x10000), 4096, Prot::READ)
            .unwrap();
        let data = m.clone();
        workers(move || {
            for _ in 0..128 {
                assert!(
                    data.atomic(
                        GuestAddr(0x10000),
                        AtomicWidth::W64,
                        AtomicOp::CompareExchange {
                            expected: 0,
                            replacement: 9
                        }
                    )
                    .is_err()
                );
            }
        });
        assert_eq!(m.read_u64(GuestAddr(0x10000)).unwrap(), 7);
    });
}
#[test]
fn parallel_runner_bootstrap() {
    // Build fixtures before the execution watchdog, as in diff_instructions. The isolated
    // child inherits their directory, but not ensure_guests_built's OnceLock.
    if std::env::var("PALUDARIUM_U2_CHILD").is_err() {
        paludarium_harness::ensure_guests_built().expect("build native guests");
    }
    support::bounded("parallel_runner_bootstrap", || {
        let workers: Vec<_> = ["insn-alu", "insn-atomic"]
            .into_iter()
            .map(|binary| {
                std::thread::spawn(move || {
                    let program = paludarium_harness::guest_dir().join(binary);
                    let native = paludarium_harness::run_native(&program, binary, &[])
                        .expect("native execution");
                    let (emulated, stop) = paludarium_harness::run_emulated(&program, binary, &[])
                        .expect("emulator execution");
                    paludarium_harness::compare(&native, &emulated).unwrap_or_else(|error| {
                        panic!("{binary}: {error}; emulator stop: {stop:?}")
                    });
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("differential worker");
        }
    });
}
