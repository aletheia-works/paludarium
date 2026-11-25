//! A thread's CPU time as other threads look at it ([`Usage::sample`]).

use crate::{CpuClock, ThreadGroup, ThreadState, Usage, account_cpu, proc::CpuTimes};
use paludarium_host::{ClockId::Monotonic, ThreadCpuClock, testing::RecordingHost};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering::SeqCst},
};

const MS: u64 = 1_000_000;

/// A clock the test sets, which fails at `u64::MAX`, as one of a thread
/// that ended does.
#[derive(Clone, Default)]
struct Stepped(Arc<AtomicU64>);
impl ThreadCpuClock for Stepped {
    fn read(&self) -> Option<u64> {
        Some(self.0.load(SeqCst)).filter(|&now| now != u64::MAX)
    }
}

/// Thread 5, which has the clock `clock` and another host thread runs, and
/// the host whose clock its own accounts read.
struct Fixture {
    host: RecordingHost,
    group: ThreadGroup,
    state: ThreadState,
    clock: Stepped,
}
impl Fixture {
    fn new() -> Self {
        let mut f = Self {
            host: RecordingHost::default(),
            group: ThreadGroup::default(),
            state: ThreadState::default(),
            clock: Stepped::default(),
        };
        f.host.set_clock(Monotonic, 1_000);
        f.clock.0.store(1_000, SeqCst);
        f.account();
        let owner = std::thread::spawn(|| std::thread::current().id());
        *f.used().clock.lock().unwrap() = Some(CpuClock {
            clock: Arc::new(f.clock.clone()),
            base: 1_000,
            owner: owner.join().unwrap(),
        });
        f
    }
    fn used(&self) -> Arc<Usage> {
        Arc::clone(&self.state.cpu.used)
    }
    /// The thread's own account of its time.
    fn account(&mut self) -> u64 {
        account_cpu(&self.host, &self.group, &mut self.state, 5)
    }
    /// Both show `ns` since the thread's start.
    fn at(&self, ns: u64) {
        self.host.set_clock(Monotonic, 1_000 + ns);
        self.clock.0.store(1_000 + ns, SeqCst);
    }
    fn times(&self) -> Vec<u64> {
        let mut times = CpuTimes::default();
        self.group.add_cpu_times(&mut times);
        times.per_cpu
    }
}

#[test]
fn a_thread_that_makes_no_system_call_has_its_time_seen() {
    let f = Fixture::new();
    f.at(30 * MS);
    // What looks at every system call sees the last account.
    assert_eq!(f.used().cpu_time(), 0);
    assert_eq!(f.group.process_cpu(), 30 * MS);
    f.at(50 * MS);
    assert_eq!(f.group.last_thread_cpu(5), Some(50 * MS));
    f.at(60 * MS);
    assert_eq!(f.times(), [60 * MS]);
}

#[test]
fn a_thread_s_time_never_goes_back_and_counts_once() {
    let mut f = Fixture::new();
    // Another thread's look is ahead of the thread's own by what the two
    // round.
    f.clock.0.store(1_000 + 10 * MS + 700, SeqCst);
    assert_eq!(f.group.process_cpu(), 10 * MS + 700);
    f.host.set_clock(Monotonic, 1_000 + 10 * MS);
    assert_eq!(f.account(), 10 * MS + 700);
    f.clock.0.store(1_000 + 10 * MS + 200, SeqCst);
    assert_eq!(f.group.process_cpu(), 10 * MS + 700);
    f.at(20 * MS);
    assert_eq!(f.account(), 20 * MS);
    assert_eq!(f.group.process_cpu(), 20 * MS);
    assert_eq!(f.times(), [20 * MS]);
    // Looks and accounts from several threads at once add up to its time.
    let used = f.used();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for _ in 0..1000 {
                    let before = used.cpu_time();
                    f.clock.0.fetch_add(MS, SeqCst);
                    used.sample();
                    assert!(used.cpu_time() >= before + MS);
                }
            });
        }
    });
    assert_eq!(f.group.process_cpu(), 4020 * MS);
    assert_eq!(f.times(), [4020 * MS]);
}

#[test]
fn a_thread_another_moves_runs_on_the_new_cpu_at_once() {
    let mut f = Fixture::new();
    f.at(50 * MS);
    f.group.set_affinity(5, vec![0b100]);
    f.at(80 * MS);
    assert_eq!(f.times(), [50 * MS, 0, 30 * MS]);
    assert_eq!(f.used().time_on(0), (80 * MS, 50 * MS));
    assert_eq!(f.account(), 80 * MS);
    assert_eq!(f.used().migrations.load(SeqCst), 1);
    f.at(100 * MS);
    f.account();
    assert_eq!(f.times(), [50 * MS, 0, 50 * MS]);
}

#[test]
fn a_thread_that_ended_keeps_its_last_time() {
    let f = Fixture::new();
    f.at(70 * MS);
    f.used().retire();
    assert_eq!(f.group.process_cpu(), 70 * MS);
    // Its clock is not looked at any more, whatever it would show.
    assert_eq!(Arc::strong_count(&f.clock.0), 1);
    f.at(90 * MS);
    assert_eq!(f.group.process_cpu(), 70 * MS);
    f.used().retire();
    assert_eq!(f.group.last_thread_cpu(5), Some(70 * MS));
}

#[test]
fn a_clock_that_fails_leaves_the_last_time() {
    let f = Fixture::new();
    f.at(10 * MS);
    assert_eq!(f.group.process_cpu(), 10 * MS);
    f.clock.0.store(u64::MAX, SeqCst);
    assert_eq!(f.group.process_cpu(), 10 * MS);
    f.used().retire();
    assert_eq!(f.group.process_cpu(), 10 * MS);
}

/// What a thread ran before its first account is its first CPU's.
#[test]
fn time_before_the_first_account_counts_to_the_first_cpu() {
    let used = Usage::default();
    used.ran(30 * MS);
    let mut times = Vec::new();
    used.add_times(&mut times);
    assert!(times.is_empty());
    used.time().arrive(1);
    used.ran(40 * MS);
    used.add_times(&mut times);
    assert_eq!(times, [0, 40 * MS]);
}

/// The clock of a thread where the host measures CPU time only as wall
/// time, and the one the host has.
#[test]
fn a_thread_s_clock_starts_with_it_and_ends_with_it() {
    for cpu_time in [false, true] {
        let host = Arc::new(RecordingHost::default());
        if cpu_time {
            host.measure_cpu_time();
        }
        host.set_clock(Monotonic, 5 * MS);
        let kernel = crate::Kernel::new(Arc::clone(&host) as _);
        let mut thread = crate::Thread::new(1, paludarium_cpu::CpuState::default());
        let clock = kernel.start_thread(&mut thread);
        let used = Arc::clone(&thread.state.cpu.used);
        // Its own looks read nothing: it accounts its time itself.
        assert!(!used.sample());
        assert!(used.clock.lock().unwrap().is_some());
        if !cpu_time {
            host.set_clock(Monotonic, 8 * MS);
            std::thread::scope(|s| assert!(s.spawn(|| used.sample()).join().unwrap()));
            assert_eq!(used.cpu_time(), 3 * MS);
            // Asleep in a wait, its time stands still for the others.
            kernel.inbox.blocked_flag().store(true, SeqCst);
            host.set_clock(Monotonic, 20 * MS);
            std::thread::scope(|s| assert!(!s.spawn(|| used.sample()).join().unwrap()));
            assert_eq!(used.cpu_time(), 3 * MS);
            kernel.inbox.blocked_flag().store(false, SeqCst);
            std::thread::scope(|s| assert!(s.spawn(|| used.sample()).join().unwrap()));
            assert_eq!(used.cpu_time(), 15 * MS);
        }
        drop(clock);
        assert!(used.clock.lock().unwrap().is_none());
        assert!(std::thread::scope(|s| !s
            .spawn(|| used.sample())
            .join()
            .unwrap()));
    }
}
