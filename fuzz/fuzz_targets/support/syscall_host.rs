//! Deterministic, finite Host for the syscall-argument fuzz harness only.
use paludarium_host::{ClockId, Host, WaitOutcome, WaitToken, testing::RecordingHost};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub struct BoundedHost {
    inner: RecordingHost,
    waits: AtomicUsize,
}
impl BoundedHost {
    pub fn new() -> Self {
        Self {
            inner: RecordingHost::new(),
            waits: AtomicUsize::new(0),
        }
    }
    #[cfg(test)]
    pub fn wait_count(&self) -> usize {
        self.waits.load(Ordering::Relaxed)
    }
}
impl Host for BoundedHost {
    fn wait_on(
        &self,
        token: &WaitToken,
        expected: u32,
        deadline: Option<(ClockId, u64)>,
        cancel: &AtomicBool,
    ) -> Result<WaitOutcome, paludarium_types::Errno> {
        if token.value() != expected {
            return Ok(WaitOutcome::Complete);
        }
        if cancel.load(Ordering::SeqCst) {
            return Ok(WaitOutcome::Interrupted);
        }
        // The single-thread harness has no asynchronous writer. Advance the
        // deterministic clock instead of entering a real condvar wait against
        // a clock that only wait_until can advance. Retain wake-before-wait.
        let (clock, end) = match deadline {
            Some(value) => value,
            None => (
                ClockId::Monotonic,
                self.clock(ClockId::Monotonic)?.saturating_add(10_000_000),
            ),
        };
        self.wait_until(clock, end, cancel)
    }
    fn read_stdin(&self, b: &mut [u8]) -> Result<usize, paludarium_types::Errno> {
        self.inner.read_stdin(b)
    }
    fn write_stdout(&self, b: &[u8]) -> Result<usize, paludarium_types::Errno> {
        self.inner.write_stdout(b)
    }
    fn write_stderr(&self, b: &[u8]) -> Result<usize, paludarium_types::Errno> {
        self.inner.write_stderr(b)
    }
    fn random_bytes(&self, b: &mut [u8]) -> Result<(), paludarium_types::Error> {
        self.inner.random_bytes(b)
    }
    fn clock(&self, c: ClockId) -> Result<u64, paludarium_types::Errno> {
        self.inner.clock(c)
    }
    fn wait_until(
        &self,
        c: ClockId,
        d: u64,
        a: &AtomicBool,
    ) -> Result<WaitOutcome, paludarium_types::Errno> {
        if self.waits.fetch_add(1, Ordering::Relaxed) >= 64 {
            return Ok(WaitOutcome::Interrupted);
        }
        if a.load(Ordering::SeqCst) {
            return Ok(WaitOutcome::Interrupted);
        }
        // Reach the deadline at once on the virtual clocks. RecordingHost's
        // own wait first gives other threads up to 10 ms of real time to end
        // it; nothing here can, so the 64 waits of one blocking syscall would
        // spend 640 ms of real time for nothing. RecordingHost's
        // interrupt_next_wait is not honoured here, and the two clocks are
        // read and set apart; nothing in the fuzz harness interrupts a wait
        // or waits from a second thread.
        let elapsed = d.saturating_sub(self.clock(c)?);
        for clock in [ClockId::Monotonic, ClockId::Realtime] {
            let now = self.clock(clock)?;
            self.inner.set_clock(clock, now.saturating_add(elapsed));
        }
        Ok(WaitOutcome::Complete)
    }
}
