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
    network: bool,
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
            network: false,
        }
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
    /// Ends standard input, which is then readable at its end.
    pub fn close_stdin(&self) {
        self.lock().stdin_open = false;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Streams> {
        self.streams.lock().unwrap_or_else(PoisonError::into_inner)
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
        let s = self.lock();
        Ok(match clock {
            ClockId::Monotonic => s.monotonic,
            ClockId::Realtime => s.realtime,
        })
    }
    fn wait_until(
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
        let current = match clock {
            ClockId::Monotonic => s.monotonic,
            ClockId::Realtime => s.realtime,
        };
        let elapsed = deadline.saturating_sub(current);
        s.monotonic = s.monotonic.saturating_add(elapsed);
        s.realtime = s.realtime.saturating_add(elapsed);
        Ok(WaitOutcome::Complete)
    }
    /// A bounded wait gives other threads 10 ms of real time to change the
    /// token, then reaches its deadline at once on the virtual clock, as
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
            crate::threads::wait_briefly(token, expected, 10_000_000);
        }
        if token.value() != expected {
            return Ok(WaitOutcome::Complete);
        }
        self.wait_until(clock, end, cancel)
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
