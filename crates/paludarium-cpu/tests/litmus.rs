//! Litmus tests of the order in which a guest's threads see each other's
//! memory: only the outcomes x86 allows (TSO) may occur. Each thread runs a
//! few real instructions (`MOV`, `MFENCE`, `XCHG`, `LOCK OR`) through
//! [`paludarium_cpu::step`], on one address space, for many rounds.
//!
//! On an x86-64 host the host's own order is TSO already, so these say the
//! most on an Arm host (CI's macOS runner), where the MMU's acquire loads,
//! release stores and fences are what keep it. A pass shows only that no
//! forbidden outcome came up in the rounds run: a reordering the host allows
//! may still be too rare to show.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use paludarium_cpu::{CpuState, reg, step};
use paludarium_mmu::{AddressSpace, MappingKind, Prot};
use paludarium_types::GuestAddr;

/// The two locations, on pages of their own, in `RDI` and `RSI`.
const X: u64 = 0x10000;
const Y: u64 = 0x11000;
/// A location of each thread's own, in `RDX`.
const OWN: u64 = 0x12000;
/// Where thread `t`'s code starts: `CODE + 0x100 * t`.
const CODE: u64 = 0x30000;

const ROUNDS: u64 = 50_000;

// The instructions, by what they do with the registers above.
const STORE_X_RAX: &[u8] = &[0x48, 0x89, 0x07]; // mov [rdi], rax
const STORE_Y_RAX: &[u8] = &[0x48, 0x89, 0x06]; // mov [rsi], rax
const STORE_X_RBX: &[u8] = &[0x48, 0x89, 0x1f]; // mov [rdi], rbx
const STORE_Y_RBX: &[u8] = &[0x48, 0x89, 0x1e]; // mov [rsi], rbx
const LOAD_RCX_X: &[u8] = &[0x48, 0x8b, 0x0f]; // mov rcx, [rdi]
const LOAD_RCX_Y: &[u8] = &[0x48, 0x8b, 0x0e]; // mov rcx, [rsi]
const LOAD_R8_X: &[u8] = &[0x4c, 0x8b, 0x07]; // mov r8, [rdi]
const LOAD_R8_Y: &[u8] = &[0x4c, 0x8b, 0x06]; // mov r8, [rsi]
const MFENCE: &[u8] = &[0x0f, 0xae, 0xf0];
const XCHG_X_RAX: &[u8] = &[0x48, 0x87, 0x07]; // xchg [rdi], rax
const XCHG_Y_RAX: &[u8] = &[0x48, 0x87, 0x06]; // xchg [rsi], rax
const LOCK_OR_OWN: &[u8] = &[0xf0, 0x48, 0x83, 0x0a, 0x00]; // lock or qword [rdx], 0

/// One thread of a test: its instructions, and the values of `RAX` and
/// `RBX` it stores in round `r`, which no other round stores.
struct Thread {
    code: &'static [&'static [u8]],
    values: fn(u64) -> (u64, u64),
}

/// What a thread loaded in a round: `RCX` and `R8`.
type Loaded = [u64; 2];

fn memory(threads: &[Thread]) -> Arc<AddressSpace> {
    let m = AddressSpace::new();
    m.map_shared(
        Some(GuestAddr(X)),
        0x3000,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    m.map_shared(
        Some(GuestAddr(CODE)),
        0x1000,
        Prot::READ_EXEC,
        MappingKind::Anonymous,
    )
    .unwrap();
    for (t, thread) in threads.iter().enumerate() {
        let code: Vec<u8> = thread.code.concat();
        m.write_initial(GuestAddr(CODE + 0x100 * t as u64), &code)
            .unwrap();
    }
    for at in [X, Y] {
        m.write_u64(GuestAddr(at), 0).unwrap();
    }
    Arc::new(m)
}

/// Waits until every thread has arrived `round + 1` times, spinning so that
/// the threads leave as close together as they can; `false` when a thread
/// panicked instead, which then never arrives.
fn arrive(arrived: &AtomicU64, aborted: &AtomicBool, threads: u64, round: u64) -> bool {
    arrived.fetch_add(1, Ordering::SeqCst);
    let mut spins = 0u32;
    while arrived.load(Ordering::SeqCst) < threads * (round + 1) {
        if aborted.load(Ordering::SeqCst) {
            return false;
        }
        spins += 1;
        if spins < 1 << 12 {
            std::hint::spin_loop();
        } else {
            std::thread::yield_now();
        }
    }
    true
}

/// Says the threads of a test are to stop if its thread panics, so that a
/// failure in one shows as a failure, not as the others waiting forever.
struct AbortOnPanic(Arc<AtomicBool>);

impl Drop for AbortOnPanic {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.store(true, Ordering::SeqCst);
        }
    }
}

/// How many spins thread `t` waits before round `round`: up to 63, in an
/// order of its own, so that the threads' accesses meet at every offset.
fn jitter(t: u64, round: u64) -> u64 {
    (round
        .wrapping_mul(2 * t + 1)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        >> 58)
        & 63
}

/// Runs thread `t`'s instructions once for round `r`.
fn run(m: &AddressSpace, t: usize, thread: &Thread, r: u64) -> Loaded {
    let mut state = CpuState::new(GuestAddr(CODE + 0x100 * t as u64), GuestAddr(0));
    let (rax, rbx) = (thread.values)(r);
    state.gpr[reg::RAX] = rax;
    state.gpr[reg::RBX] = rbx;
    state.gpr[reg::RDI] = X;
    state.gpr[reg::RSI] = Y;
    state.gpr[reg::RDX] = OWN + 8 * t as u64;
    for _ in thread.code {
        step(&mut state, m).unwrap();
    }
    [state.gpr[reg::RCX], state.gpr[8]]
}

/// Runs the threads for `ROUNDS` rounds. Once all have run round `r`,
/// `allowed(m, r, loaded)` says whether the outcome is one x86 allows; it
/// may read the final values of `X` and `Y` too.
fn litmus(name: &str, threads: Vec<Thread>, allowed: fn(&AddressSpace, u64, &[Loaded]) -> bool) {
    let m = memory(&threads);
    let n = threads.len() as u64;
    let arrived = Arc::new(AtomicU64::new(0));
    let aborted = Arc::new(AtomicBool::new(false));
    let loaded: Arc<Vec<[AtomicU64; 2]>> = Arc::new(
        (0..n)
            .map(|_| [AtomicU64::new(0), AtomicU64::new(0)])
            .collect(),
    );
    let handles: Vec<_> = threads
        .into_iter()
        .enumerate()
        .map(|(t, thread)| {
            let (m, arrived, loaded) = (Arc::clone(&m), Arc::clone(&arrived), Arc::clone(&loaded));
            let aborted = Arc::clone(&aborted);
            let name = name.to_owned();
            std::thread::spawn(move || {
                let _abort = AbortOnPanic(Arc::clone(&aborted));
                // Use the pages first, so that the accesses take the paths
                // without a lock where those exist.
                for _ in 0..2 {
                    for at in [X, Y, OWN] {
                        m.read_u64(GuestAddr(at)).unwrap();
                    }
                }
                let mut forbidden = 0u64;
                for round in 0..ROUNDS {
                    if !arrive(&arrived, &aborted, n, 2 * round) {
                        break;
                    }
                    for _ in 0..jitter(t as u64, round) {
                        std::hint::spin_loop();
                    }
                    let values = run(&m, t, &thread, round + 1);
                    loaded[t][0].store(values[0], Ordering::SeqCst);
                    loaded[t][1].store(values[1], Ordering::SeqCst);
                    if !arrive(&arrived, &aborted, n, 2 * round + 1) {
                        break;
                    }
                    if t == 0 {
                        let all: Vec<Loaded> = loaded
                            .iter()
                            .map(|l| [l[0].load(Ordering::SeqCst), l[1].load(Ordering::SeqCst)])
                            .collect();
                        if !allowed(&m, round + 1, &all) {
                            forbidden += 1;
                            if forbidden <= 5 {
                                eprintln!("{name}: round {} loaded {all:?}", round + 1);
                            }
                        }
                    }
                }
                forbidden
            })
        })
        .collect();
    let forbidden: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(
        forbidden, 0,
        "{name}: {forbidden} of {ROUNDS} rounds gave an outcome x86 forbids"
    );
}

fn load(m: &AddressSpace, at: u64) -> u64 {
    m.read_u64(GuestAddr(at)).unwrap()
}

/// The values of round `r`: `RAX = r`.
fn round(r: u64) -> (u64, u64) {
    (r, 0)
}

/// MP: stores stay in order, and so do loads. A thread that sees the
/// second store sees the first.
#[test]
fn message_passing() {
    litmus(
        "MP",
        vec![
            Thread {
                code: &[STORE_X_RAX, STORE_Y_RAX],
                values: round,
            },
            Thread {
                code: &[LOAD_RCX_Y, LOAD_R8_X],
                values: round,
            },
        ],
        |_, r, loaded| !(loaded[1][0] == r && loaded[1][1] < r),
    );
}

/// LB: a load is never passed by a later store, so the two loads do not
/// both see the other thread's store.
#[test]
fn load_buffering() {
    litmus(
        "LB",
        vec![
            Thread {
                code: &[LOAD_RCX_X, STORE_Y_RAX],
                values: round,
            },
            Thread {
                code: &[LOAD_RCX_Y, STORE_X_RAX],
                values: round,
            },
        ],
        |_, r, loaded| !(loaded[0][0] == r && loaded[1][0] == r),
    );
}

/// The outcome of SB that x86 allows only without a fence: neither load
/// sees the other thread's store.
fn store_buffered(_: &AddressSpace, r: u64, loaded: &[Loaded]) -> bool {
    !(loaded[0][0] < r && loaded[1][0] < r)
}

/// SB with `MFENCE` between each store and load: at least one load sees the
/// other thread's store.
#[test]
fn store_buffering_with_mfence() {
    litmus(
        "SB+mfence",
        vec![
            Thread {
                code: &[STORE_X_RAX, MFENCE, LOAD_RCX_Y],
                values: round,
            },
            Thread {
                code: &[STORE_Y_RAX, MFENCE, LOAD_RCX_X],
                values: round,
            },
        ],
        store_buffered,
    );
}

/// SB with the stores as `XCHG`, which is always locked and so a full fence:
/// Go's scheduler, among others, depends on it.
#[test]
fn store_buffering_with_xchg() {
    litmus(
        "SB+xchg",
        vec![
            Thread {
                code: &[XCHG_X_RAX, LOAD_RCX_Y],
                values: round,
            },
            Thread {
                code: &[XCHG_Y_RAX, LOAD_RCX_X],
                values: round,
            },
        ],
        store_buffered,
    );
}

/// SB with `LOCK OR` of a location of each thread's own between the store
/// and the load, as compilers emit for a fence.
#[test]
fn store_buffering_with_lock_or() {
    litmus(
        "SB+lock-or",
        vec![
            Thread {
                code: &[STORE_X_RAX, LOCK_OR_OWN, LOAD_RCX_Y],
                values: round,
            },
            Thread {
                code: &[STORE_Y_RAX, LOCK_OR_OWN, LOAD_RCX_X],
                values: round,
            },
        ],
        store_buffered,
    );
}

/// 2+2W: each thread's stores stay in order, so `X` and `Y` do not both end
/// with a thread's first store.
#[test]
fn two_plus_two_writes() {
    litmus(
        "2+2W",
        vec![
            Thread {
                code: &[STORE_X_RAX, STORE_Y_RBX],
                values: |r| (2 * r - 1, 2 * r),
            },
            Thread {
                code: &[STORE_Y_RAX, STORE_X_RBX],
                values: |r| (2 * r - 1, 2 * r),
            },
        ],
        |m, r, _| !(load(m, X) == 2 * r - 1 && load(m, Y) == 2 * r - 1),
    );
}

/// S: when the second thread sees the first's second store, its own store
/// to `X` comes after the first's, so `X` ends with it.
#[test]
fn store_store_against_load_store() {
    litmus(
        "S",
        vec![
            Thread {
                code: &[STORE_X_RAX, STORE_Y_RBX],
                values: |r| (2 * r, r),
            },
            Thread {
                code: &[LOAD_RCX_Y, STORE_X_RBX],
                values: |r| (0, 2 * r - 1),
            },
        ],
        |m, r, loaded| !(loaded[1][0] == r && load(m, X) == 2 * r),
    );
}

/// IRIW: all threads see the stores in one order, so two readers do not see
/// two independent stores in opposite orders.
#[test]
fn independent_reads_of_independent_writes() {
    litmus(
        "IRIW",
        vec![
            Thread {
                code: &[STORE_X_RAX],
                values: round,
            },
            Thread {
                code: &[STORE_Y_RAX],
                values: round,
            },
            Thread {
                code: &[LOAD_RCX_X, LOAD_R8_Y],
                values: round,
            },
            Thread {
                code: &[LOAD_RCX_Y, LOAD_R8_X],
                values: round,
            },
        ],
        |_, r, loaded| {
            !(loaded[2][0] == r && loaded[2][1] < r && loaded[3][0] == r && loaded[3][1] < r)
        },
    );
}
