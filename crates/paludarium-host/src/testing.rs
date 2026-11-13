//! A deterministic [`Host`] for tests and the differential harness:
//! records standard output and error, returns fixed "random" bytes and reads
//! standard input from a preset buffer.

use std::sync::{Mutex, PoisonError};

use paludarium_types::{Errno, Error};

use crate::{ClockId, Host, StdinState, StreamId, TerminalInfo, WaitOutcome};

struct Streams {
    terminals: [Option<TerminalInfo>; 3],
    monotonic: u64,
    realtime: u64,
    interrupt_wait: bool,
    stdin: Vec<u8>,
    stdin_pos: usize,
    /// Whether more input may still come, as on a terminal, and whether it
    /// was ever opened that way.
    stdin_open: bool,
    stdin_live: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    /// Whether standard output and standard error are full, as a pipe whose
    /// reader is slow ([`RecordingHost::set_output_full`]).
    output_full: [bool; 2],
    network: bool,
    /// Whether a thread's CPU time is the host thread's, not the virtual
    /// monotonic clock ([`RecordingHost::measure_cpu_time`]).
    cpu_time: bool,
}

impl Default for Streams {
    fn default() -> Self {
        Self {
            terminals: [None; 3],
            monotonic: 0,
            realtime: 1_700_000_000_000_000_000,
            interrupt_wait: false,
            stdin: Vec::new(),
            stdin_pos: 0,
            stdin_open: false,
            stdin_live: false,
            stdout: Vec::new(),
            stderr: Vec::new(),
            output_full: [false; 2],
            network: false,
            cpu_time: false,
        }
    }
}
impl Streams {
    fn now(&self, clock: ClockId) -> u64 {
        match clock {
            ClockId::Monotonic => self.monotonic,
            ClockId::Realtime => self.realtime,
        }
    }
}
/// The real time, in nanoseconds, a wait on the virtual clock gives other
/// threads to wake it before it jumps to its deadline.
const GRACE: u64 = 10_000_000;
/// Whether `cancel` is set within `nanos` of real time.
#[cfg(not(target_arch = "wasm32"))]
fn cancelled_within(cancel: &std::sync::atomic::AtomicBool, nanos: u64) -> bool {
    use std::time::{Duration, Instant};
    let end = Instant::now() + Duration::from_nanos(nanos);
    loop {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return true;
        }
        let now = Instant::now();
        if now >= end {
            return false;
        }
        std::thread::sleep((end - now).min(Duration::from_micros(100)));
    }
}
/// Records guest output in memory.
#[derive(Default)]
pub struct RecordingHost {
    streams: Mutex<Streams>,
}

impl RecordingHost {
    /// Sets terminal state for a single stream without affecting the others.
    pub fn set_terminal_info(&self, stream: StreamId, info: Option<TerminalInfo>) {
        self.lock().terminals[stream.index()] = info;
    }

    /// Sets a deterministic clock in nanoseconds.
    pub fn set_clock(&self, clock: ClockId, value: u64) {
        let mut s = self.lock();
        match clock {
            ClockId::Monotonic => s.monotonic = value,
            ClockId::Realtime => s.realtime = value,
        }
    }
    /// Interrupts the next wait without consulting the host clock.
    pub fn interrupt_next_wait(&self) {
        self.lock().interrupt_wait = true;
    }
    /// The value every "random" byte has.
    pub const RANDOM_BYTE: u8 = 0xa5;

    /// A host with empty standard input.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A host whose standard input yields `input`.
    #[must_use]
    pub fn with_stdin(input: &[u8]) -> Self {
        let host = Self::default();
        host.lock().stdin = input.to_vec();
        host
    }

    /// Keeps standard input open past its bytes, as a terminal stays open:
    /// [`Host::stdin_state`] then reports it readable only with bytes to
    /// read, and ended after [`Self::close_stdin`]. Reading past them still
    /// returns 0.
    pub fn open_stdin(&self) {
        let mut s = self.lock();
        s.stdin_open = true;
        s.stdin_live = true;
    }
    /// Adds bytes to standard input.
    pub fn push_stdin(&self, bytes: &[u8]) {
        self.lock().stdin.extend_from_slice(bytes);
    }
    /// Connects and resolves through the native host's network, for the
    /// differential tests of guests that use one.
    pub fn enable_network(&self) {
        self.lock().network = true;
    }
    /// Measures each thread's CPU time on the native host, for the
    /// differential tests of guests that wait for CPU time to pass, which
    /// the virtual clock alone does not make pass.
    pub fn measure_cpu_time(&self) {
        self.lock().cpu_time = true;
    }
    /// Makes standard output (`channel` 1) or standard error (2) full, or
    /// gives it room again, for [`Host::output_writable`]; writes still go.
    pub fn set_output_full(&self, channel: u32, full: bool) {
        let Some(index) = (channel as usize).checked_sub(1) else {
            return;
        };
        if let Some(full_now) = self.lock().output_full.get_mut(index) {
            *full_now = full;
        }
    }
    /// Ends standard input, which is then readable at its end.
    pub fn close_stdin(&self) {
        self.lock().stdin_open = false;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Streams> {
        self.streams.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// Ends a wait at `deadline` on the virtual clock at once, unless it is
    /// cancelled or interrupted first.
    fn jump(
        &self,
        clock: ClockId,
        deadline: u64,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<WaitOutcome, Errno> {
        let mut s = self.lock();
        if cancel.load(std::sync::atomic::Ordering::SeqCst) || s.interrupt_wait {
            s.interrupt_wait = false;
            return Ok(WaitOutcome::Interrupted);
        }
        let elapsed = deadline.saturating_sub(s.now(clock));
        s.monotonic = s.monotonic.saturating_add(elapsed);
        s.realtime = s.realtime.saturating_add(elapsed);
        Ok(WaitOutcome::Complete)
    }

    /// Everything written to standard output so far.
    #[must_use]
    pub fn stdout(&self) -> Vec<u8> {
        self.lock().stdout.clone()
    }

    /// Everything written to standard error so far.
    #[must_use]
    pub fn stderr(&self) -> Vec<u8> {
        self.lock().stderr.clone()
    }
}

impl Host for RecordingHost {
    fn terminal_info(&self, stream: StreamId) -> Result<Option<TerminalInfo>, Errno> {
        Ok(self.lock().terminals[stream.index()])
    }

    fn clock(&self, clock: ClockId) -> Result<u64, Errno> {
        Ok(self.lock().now(clock))
    }
    fn thread_cpu_time(&self) -> Result<u64, Errno> {
        // WebAssembly has no thread CPU time to measure.
        #[cfg(not(target_arch = "wasm32"))]
        if self.lock().cpu_time {
            return crate::clock::native_thread_cpu_time();
        }
        Err(Errno::ENOSYS)
    }
    /// Gives other threads the wait's time, up to [`GRACE`], of real time
    /// to cancel it, then reaches its deadline at once on the virtual clock.
    /// A signal another process sends while this one sleeps still comes
    /// before the sleep ends, as it does on Linux, where the sleep lasts: a
    /// clock that jumped at once would let a long sleep end, and the
    /// sleeper exit, before a kill sent just as it started could land.
    fn wait_until(
        &self,
        clock: ClockId,
        deadline: u64,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<WaitOutcome, Errno> {
        let remaining = {
            let mut s = self.lock();
            if s.interrupt_wait {
                s.interrupt_wait = false;
                return Ok(WaitOutcome::Interrupted);
            }
            deadline.saturating_sub(s.now(clock))
        };
        #[cfg(not(target_arch = "wasm32"))]
        if cancelled_within(cancel, remaining.min(GRACE)) {
            return Ok(WaitOutcome::Interrupted);
        }
        #[cfg(target_arch = "wasm32")]
        let _ = remaining;
        self.jump(clock, deadline, cancel)
    }
    /// A bounded wait gives other threads [`GRACE`] of real time to change
    /// the token, then reaches its deadline at once on the virtual clock, as
    /// [`Host::wait_until`] does here; an unbounded one waits in real time.
    fn wait_on(
        &self,
        token: &crate::WaitToken,
        expected: u32,
        deadline: Option<(ClockId, u64)>,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<WaitOutcome, Errno> {
        let Some((clock, end)) = deadline else {
            return crate::threads::wait(self, token, expected, None, cancel);
        };
        if token.value() == expected && !cancel.load(std::sync::atomic::Ordering::SeqCst) {
            crate::threads::wait_briefly(token, expected, GRACE);
        }
        if token.value() != expected {
            return Ok(WaitOutcome::Complete);
        }
        self.jump(clock, end, cancel)
    }
    /// Only once [`RecordingHost::open_stdin`] made it a live stream: bytes
    /// to read, nothing yet, or its end after [`RecordingHost::close_stdin`].
    /// A preset buffer stays always readable, as before.
    fn stdin_state(&self) -> Option<StdinState> {
        let s = self.lock();
        if s.stdin_pos < s.stdin.len() {
            Some(StdinState::Readable)
        } else if s.stdin_live {
            Some(if s.stdin_open {
                StdinState::Waiting
            } else {
                StdinState::Ended
            })
        } else {
            None
        }
    }
    /// A live standard input ([`RecordingHost::open_stdin`]) stands for a
    /// pipe or terminal, which Linux signals with `O_ASYNC`.
    fn stdin_signals(&self) -> bool {
        self.lock().stdin_live
    }
    /// The recorded output streams stand for the pipes a test reads them
    /// through.
    fn output_signals(&self, channel: u32) -> bool {
        matches!(channel, 1 | 2)
    }
    fn output_writable(&self, channel: u32) -> Option<bool> {
        let index = (channel as usize).checked_sub(1)?;
        self.lock().output_full.get(index).map(|full| !full)
    }
    fn read_stdin(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let mut s = self.lock();
        let start = s.stdin_pos.min(s.stdin.len());
        let n = buf.len().min(s.stdin.len() - start);
        buf[..n].copy_from_slice(&s.stdin[start..start + n]);
        s.stdin_pos = start + n;
        Ok(n)
    }

    fn write_stdout(&self, buf: &[u8]) -> Result<usize, Errno> {
        self.lock().stdout.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn write_stderr(&self, buf: &[u8]) -> Result<usize, Errno> {
        self.lock().stderr.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), Error> {
        buf.fill(Self::RANDOM_BYTE);
        Ok(())
    }
    /// The machine's own, as [`Host::cpu_count`] is: the differential
    /// harness runs the guest on the machine it compares with.
    fn scheduler_slice(&self) -> Option<crate::SchedulerSlice> {
        #[cfg(not(target_arch = "wasm32"))]
        return crate::clock::native_scheduler_slice();
        #[cfg(target_arch = "wasm32")]
        None
    }
    fn connect(
        &self,
        address: core::net::SocketAddr,
    ) -> Result<std::sync::Arc<crate::net::Stream>, Errno> {
        #[cfg(not(target_arch = "wasm32"))]
        if self.lock().network {
            return crate::native_net::connect(address);
        }
        let _ = address;
        Err(crate::net::UNREACHABLE)
    }
    fn resolve(&self, name: &str) -> Result<std::sync::Arc<crate::net::Lookup>, Errno> {
        #[cfg(not(target_arch = "wasm32"))]
        if self.lock().network {
            return crate::native_net::resolve(name);
        }
        let _ = name;
        Err(crate::net::UNREACHABLE)
    }
    fn route_source(
        &self,
        address: core::net::SocketAddr,
    ) -> Result<Option<core::net::IpAddr>, Errno> {
        #[cfg(not(target_arch = "wasm32"))]
        if self.lock().network {
            return crate::native_net::route_source(address).map(Some);
        }
        let _ = address;
        Ok(None)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::{Duration, Instant};

    /// A long sleep on the virtual clock still takes real time, its grace,
    /// before it reaches its deadline, and then moves both clocks by it.
    #[test]
    fn a_long_wait_takes_its_grace_of_real_time_before_it_jumps() {
        let host = RecordingHost::new();
        let start = Instant::now();
        let outcome = host.wait_until(
            ClockId::Monotonic,
            10_101_000_000_000,
            &AtomicBool::new(false),
        );
        assert_eq!(outcome, Ok(WaitOutcome::Complete));
        assert!(start.elapsed() >= Duration::from_nanos(GRACE));
        assert_eq!(host.clock(ClockId::Monotonic), Ok(10_101_000_000_000));
        assert_eq!(
            host.clock(ClockId::Realtime),
            Ok(1_700_000_000_000_000_000 + 10_101_000_000_000)
        );
    }

    /// A wake another thread gives once the sleep has started ends it,
    /// without moving the clock: the kill-before-sleep case's parent kills
    /// a child that has just started a 10101 s nanosleep. Without the grace
    /// the sleep ended first, and the child exited before the kill.
    #[test]
    fn a_wake_after_a_long_wait_starts_interrupts_it() {
        let host = Arc::new(RecordingHost::new());
        let cancel = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(false));
        let waiter = {
            let (host, cancel, started) = (host.clone(), cancel.clone(), started.clone());
            std::thread::spawn(move || {
                started.store(true, Ordering::SeqCst);
                host.wait_until(ClockId::Monotonic, 10_101_000_000_000, &cancel)
            })
        };
        while !started.load(Ordering::SeqCst) {
            std::hint::spin_loop();
        }
        // Well after the waiter reached its wait, well within the grace.
        let late = Instant::now() + Duration::from_millis(1);
        while Instant::now() < late {
            std::hint::spin_loop();
        }
        cancel.store(true, Ordering::SeqCst);
        assert_eq!(waiter.join().unwrap(), Ok(WaitOutcome::Interrupted));
        assert_eq!(host.clock(ClockId::Monotonic), Ok(0));
    }

    /// A wait already cancelled is interrupted, and one at its deadline
    /// completes, both without moving the clock. (No bound on the real time
    /// they take: a loaded machine can stall any thread.)
    #[test]
    fn a_cancelled_or_due_wait_ends_without_moving_the_clock() {
        let host = RecordingHost::new();
        assert_eq!(
            host.wait_until(
                ClockId::Monotonic,
                10_101_000_000_000,
                &AtomicBool::new(true)
            ),
            Ok(WaitOutcome::Interrupted)
        );
        assert_eq!(
            host.wait_until(ClockId::Monotonic, 0, &AtomicBool::new(false)),
            Ok(WaitOutcome::Complete)
        );
        assert_eq!(host.clock(ClockId::Monotonic), Ok(0));
    }
}
