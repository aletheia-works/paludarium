//! Worker host facilities; imports never receive guest pointers.
use crate::{ClockId, Host, ThreadHandle, WaitOutcome};
use paludarium_types::{Errno, Error, ErrorKind};
use std::sync::{
    Mutex, PoisonError,
    atomic::{AtomicBool, Ordering},
};
#[link(wasm_import_module = "paludarium")]
unsafe extern "C" {
    fn random_fill(ptr: *mut u8, len: usize) -> i32;
    fn clock_ms(kind: i32) -> f64;
    fn sleep_ms(ms: f64);
    fn spawn_task(handle: u32) -> i32;
}
#[derive(Default)]
struct Streams {
    stdin: Vec<u8>,
    position: usize,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    closed: bool,
}
/// In-memory standard streams with secure randomness and Worker clocks.
#[derive(Default)]
pub struct WasmHost {
    streams: Mutex<Streams>,
}
impl WasmHost {
    pub fn new(stdin: Vec<u8>) -> Self {
        Self {
            streams: Mutex::new(Streams {
                stdin,
                closed: true,
                ..Streams::default()
            }),
        }
    }
    pub fn streaming(stdin: Vec<u8>) -> Self {
        Self {
            streams: Mutex::new(Streams {
                stdin,
                ..Streams::default()
            }),
        }
    }
    pub fn append_stdin(&self, bytes: &[u8]) -> Result<(), Errno> {
        let mut s = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
        if s.closed || s.stdin.len().saturating_add(bytes.len()) > 64 * 1024 * 1024 {
            return Err(Errno::EIO);
        }
        s.stdin.extend_from_slice(bytes);
        Ok(())
    }
    pub fn close_stdin(&self) {
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .closed = true;
    }
    pub fn stdout(&self) -> Vec<u8> {
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .stdout
            .clone()
    }
    pub fn stderr(&self) -> Vec<u8> {
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .stderr
            .clone()
    }
}
impl Host for WasmHost {
    fn spawn_thread(&self, task: Box<dyn FnOnce() + Send>) -> Result<Box<dyn ThreadHandle>, Errno> {
        let id = crate::wasm_tasks::register(task)?;
        // The handle retains the closure before notification. Worker creation
        // is owned by JS; its failures discard the complete shared runtime.
        // SAFETY: only a validated scalar closure handle crosses the import.
        if unsafe { spawn_task(id) } != 0 {
            crate::wasm_tasks::unregister(id);
            return Err(Errno::EAGAIN);
        }
        Ok(Box::new(crate::wasm_tasks::WasmThread::new(
            id,
            std::sync::Arc::new(Self::default()),
        )?))
    }
    fn read_stdin(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let mut s = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
            let n = buf.len().min(s.stdin.len().saturating_sub(s.position));
            if n > 0 || s.closed {
                buf[..n].copy_from_slice(&s.stdin[s.position..s.position + n]);
                s.position += n;
                return Ok(n);
            }
            drop(s);
            // SAFETY: bounded scalar wait outside all locks. Another Worker can append input or close it on kill.
            unsafe { sleep_ms(10.0) };
        }
    }
    fn stdin_state(&self) -> Option<crate::StdinState> {
        let s = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
        Some(if s.position < s.stdin.len() {
            crate::StdinState::Readable
        } else if s.closed {
            crate::StdinState::Ended
        } else {
            crate::StdinState::Waiting
        })
    }
    fn write_stdout(&self, buf: &[u8]) -> Result<usize, Errno> {
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .stdout
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn write_stderr(&self, buf: &[u8]) -> Result<usize, Errno> {
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .stderr
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), Error> {
        // SAFETY: synchronous import writes only into this live, exclusively borrowed host buffer.
        if unsafe { random_fill(buf.as_mut_ptr(), buf.len()) } == 0 {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Host, "Worker randomness unavailable"))
        }
    }
    fn clock(&self, clock: ClockId) -> Result<u64, Errno> {
        // SAFETY: scalar import, no guest pointer, JS returns milliseconds.
        let value = unsafe { clock_ms(if clock == ClockId::Realtime { 0 } else { 1 }) };
        if !value.is_finite() || value < 0.0 {
            return Err(Errno::EIO);
        }
        Ok((value * 1_000_000.0) as u64)
    }
    fn wait_until(
        &self,
        clock: ClockId,
        deadline: u64,
        cancel: &AtomicBool,
    ) -> Result<WaitOutcome, Errno> {
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Ok(WaitOutcome::Interrupted);
            }
            let now = self.clock(clock)?;
            if now >= deadline {
                return Ok(WaitOutcome::Complete);
            }
            // SAFETY: bounded scalar sleep outside every Rust/guest memory lock. Cancellation polled at most every 10ms.
            unsafe { sleep_ms(((deadline - now).min(10_000_000) as f64) / 1_000_000.0) };
        }
    }
}
