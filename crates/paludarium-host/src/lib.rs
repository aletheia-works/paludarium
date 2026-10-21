//! Host abstraction for paludarium (contract C2).
//!
//! Every host facility the emulator uses goes through the [`Host`] trait
//! (ADR-007), so that the native and wasm implementations differ only here.
//! The core emulator needs standard I/O and randomness (for `AT_RANDOM`);
//! threads, time and host files are added on top.
//!
//! This is the only crate where `unsafe` is permitted. The core
//! implementation does not need any.

#![cfg_attr(windows, feature(windows_by_handle))]
#![cfg_attr(target_arch = "wasm32", feature(stdarch_wasm_atomic_wait))]

use std::io;
#[cfg(not(target_arch = "wasm32"))]
use std::io::{Read, Write};
use std::path::Path;

use paludarium_types::{Errno, Error, ErrorKind};

mod clock;
#[cfg(target_os = "macos")]
mod macos;
mod threads;
#[cfg(any(target_arch = "wasm32", test))]
mod wasm_tasks;
#[cfg(windows)]
mod windows;
pub use threads::{ThreadHandle, WaitToken};
#[cfg(target_arch = "wasm32")]
pub use wasm_tasks::run_task;
pub mod fs;
#[cfg(not(target_arch = "wasm32"))]
mod native_fs;
pub use fs::{DirectoryEntry, FileHandle, FileStat, HostFs};
#[cfg(not(target_arch = "wasm32"))]
pub use native_fs::NativeFs;
#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub use wasm::WasmHost;
pub mod testing;
pub use clock::{ClockId, WaitOutcome};

/// Standard stream identity remains attached to duplicated guest descriptors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamId {
    Stdin,
    Stdout,
    Stderr,
}
impl StreamId {
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Stdin => 0,
            Self::Stdout => 1,
            Self::Stderr => 2,
        }
    }
}
/// Linux guest terminal attributes, independent of the host's libc layout.
///
/// External callers construct this extensible type with [`Self::new`].
/// ```compile_fail
/// use paludarium_host::TerminalAttributes;
/// let _ = TerminalAttributes { input_flags: 0, output_flags: 0,
///     control_flags: 0, local_flags: 0, line: 0, control_chars: [0; 19] };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TerminalAttributes {
    pub input_flags: u32,
    pub output_flags: u32,
    pub control_flags: u32,
    pub local_flags: u32,
    pub line: u8,
    pub control_chars: [u8; 19],
}
impl TerminalAttributes {
    /// Preserves every Linux guest attribute exactly as supplied.
    #[must_use]
    pub const fn new(
        input_flags: u32,
        output_flags: u32,
        control_flags: u32,
        local_flags: u32,
        line: u8,
        control_chars: [u8; 19],
    ) -> Self {
        Self {
            input_flags,
            output_flags,
            control_flags,
            local_flags,
            line,
            control_chars,
        }
    }
}
impl Default for TerminalAttributes {
    fn default() -> Self {
        Self {
            input_flags: 0x500,
            output_flags: 5,
            control_flags: 0xbf,
            local_flags: 0x8a3b,
            line: 0,
            control_chars: [
                3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0,
            ],
        }
    }
}
/// `None` from Host means a non-terminal; a zero size is still a terminal.
/// ```compile_fail
/// use paludarium_host::{TerminalAttributes, TerminalInfo};
/// let _ = TerminalInfo { attributes: TerminalAttributes::default(),
///     columns: 0, rows: 0, x_pixels: 0, y_pixels: 0 };
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TerminalInfo {
    pub attributes: TerminalAttributes,
    pub columns: u16,
    pub rows: u16,
    pub x_pixels: u16,
    pub y_pixels: u16,
}
impl TerminalInfo {
    /// Creates terminal information without changing zero sizes or attributes.
    #[must_use]
    pub const fn new(
        attributes: TerminalAttributes,
        columns: u16,
        rows: u16,
        x_pixels: u16,
        y_pixels: u16,
    ) -> Self {
        Self {
            attributes,
            columns,
            rows,
            x_pixels,
            y_pixels,
        }
    }
}

/// Facilities the emulator needs from its host.
pub trait Host: Send + Sync {
    /// Starts one native execution worker; wasm guest Workers are connected by the wasm host.
    fn spawn_thread(&self, task: Box<dyn FnOnce() + Send>) -> Result<Box<dyn ThreadHandle>, Errno> {
        threads::spawn(task)
    }
    /// Compare-and-wait on a ticket, never on guest memory. Wake-before-wait is retained.
    fn wait_on(
        &self,
        token: &WaitToken,
        expected: u32,
        deadline: Option<(ClockId, u64)>,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<WaitOutcome, Errno> {
        threads::wait(self, token, expected, deadline, cancel)
    }
    fn wake(&self, token: &WaitToken) {
        token.notify();
    }
    /// Queries one standard stream; guest ioctl numbers never cross this boundary.
    fn terminal_info(&self, _stream: StreamId) -> Result<Option<TerminalInfo>, Errno> {
        Ok(None)
    }

    fn mount_fs(&self, _root: &Path) -> Result<std::sync::Arc<dyn HostFs>, Errno> {
        Err(Errno::ENOSYS)
    }
    /// Reads from the host's standard input; `Ok(0)` at end of input.
    fn read_stdin(&self, buf: &mut [u8]) -> Result<usize, Errno>;
    /// Writes to the host's standard output; returns the bytes written.
    fn write_stdout(&self, buf: &[u8]) -> Result<usize, Errno>;
    /// Writes to the host's standard error; returns the bytes written.
    fn write_stderr(&self, buf: &[u8]) -> Result<usize, Errno>;
    /// Fills `buf` with cryptographically secure random bytes.
    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), Error>;
    /// Nanoseconds since the selected clock's epoch.
    fn clock(&self, _clock: ClockId) -> Result<u64, Errno> {
        Err(Errno::ENOSYS)
    }
    /// Waits until a deadline while polling cancellation outside guest memory locks.
    fn wait_until(
        &self,
        _clock: ClockId,
        _deadline: u64,
        _cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<WaitOutcome, Errno> {
        Err(Errno::ENOSYS)
    }
}

/// Maps a host I/O error to the errno the guest sees.
#[must_use]
pub fn errno_from_io(err: &io::Error) -> Errno {
    match err.kind() {
        io::ErrorKind::BrokenPipe => Errno::EPIPE,
        io::ErrorKind::WouldBlock => Errno::EAGAIN,
        io::ErrorKind::InvalidInput => Errno::EINVAL,
        _ => Errno::EIO,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn write_through(out: &mut dyn Write, buf: &[u8]) -> Result<usize, Errno> {
    out.write_all(buf).map_err(|e| errno_from_io(&e))?;
    out.flush().map_err(|e| errno_from_io(&e))?;
    Ok(buf.len())
}

/// The native host (Linux, and the portable parts for macOS and Windows).
/// Writes are unbuffered from the guest's point of view: every guest
/// `write` is flushed before it returns.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeHost;

impl NativeHost {
    /// Creates the native host.
    #[must_use]
    pub fn new() -> Self {
        NativeHost
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Host for NativeHost {
    fn terminal_info(&self, stream: StreamId) -> Result<Option<TerminalInfo>, Errno> {
        native_terminal_info(stream)
    }

    fn mount_fs(&self, root: &Path) -> Result<std::sync::Arc<dyn HostFs>, Errno> {
        Ok(std::sync::Arc::new(NativeFs::new(root)?))
    }
    fn clock(&self, clock: ClockId) -> Result<u64, Errno> {
        clock::native_clock(clock)
    }
    fn wait_until(
        &self,
        clock: ClockId,
        deadline: u64,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<WaitOutcome, Errno> {
        clock::native_wait(clock, deadline, cancel)
    }
    fn read_stdin(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        io::stdin().lock().read(buf).map_err(|e| errno_from_io(&e))
    }

    fn write_stdout(&self, buf: &[u8]) -> Result<usize, Errno> {
        write_through(&mut io::stdout().lock(), buf)
    }

    fn write_stderr(&self, buf: &[u8]) -> Result<usize, Errno> {
        write_through(&mut io::stderr().lock(), buf)
    }

    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(buf)
            .map_err(|_| Error::new(ErrorKind::Host, "host randomness is unavailable"))
    }
}

/// Reads a program file from the host file system for the command line.
/// Kept here so that no other crate touches `std::fs`.
pub fn read_program_file(path: &Path) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|_| Error::new(ErrorKind::Host, "cannot read the program file"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_random_bytes_fill_the_buffer() {
        let host = NativeHost::new();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        host.random_bytes(&mut a).unwrap();
        host.random_bytes(&mut b).unwrap();
        // Two 256-bit draws are equal with negligible probability.
        assert_ne!(a, b);
    }

    #[test]
    fn write_through_reports_full_length() {
        let mut sink = Vec::new();
        assert_eq!(write_through(&mut sink, b"abc"), Ok(3));
        assert_eq!(sink, b"abc");
    }

    #[test]
    fn io_errors_map_to_errno() {
        let pipe = io::Error::from(io::ErrorKind::BrokenPipe);
        assert_eq!(errno_from_io(&pipe), Errno::EPIPE);
        let other = io::Error::other("x");
        assert_eq!(errno_from_io(&other), Errno::EIO);
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(write_through(&mut Broken, b"x"), Err(Errno::EPIPE));
    }

    #[test]
    fn missing_program_file_is_a_host_error_without_path() {
        let dir = std::env::temp_dir().join("paludarium-host-test-missing-file");
        let err = read_program_file(&dir).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Host);
        assert!(!err.to_string().contains("paludarium-host-test"));
    }

    #[test]
    fn program_file_is_read_whole() {
        let path =
            std::env::temp_dir().join(format!("paludarium-host-test-{}", std::process::id()));
        std::fs::write(&path, b"\x7fELF-test").unwrap();
        let content = read_program_file(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(content, b"\x7fELF-test");
    }

    #[test]
    fn recording_host_captures_streams() {
        let host = testing::RecordingHost::new();
        host.write_stdout(b"out").unwrap();
        host.write_stderr(b"err").unwrap();
        let mut r = [0u8; 4];
        host.random_bytes(&mut r).unwrap();
        assert_eq!(host.stdout(), b"out");
        assert_eq!(host.stderr(), b"err");
        assert_eq!(r, [testing::RecordingHost::RANDOM_BYTE; 4]);
        let mut buf = [0u8; 4];
        assert_eq!(host.read_stdin(&mut buf), Ok(0));
    }
}

#[cfg(test)]
mod signals_time_tests;

// Linux x86-64 kernel ABI, not libc's larger `struct termios`.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn native_terminal_info(stream: StreamId) -> Result<Option<TerminalInfo>, Errno> {
    unsafe extern "C" {
        fn ioctl(fd: i32, request: usize, ...) -> i32;
    }
    let fd = stream.index() as i32;
    let mut attributes = [0u8; 36];
    // SAFETY: TCGETS writes exactly the 36-byte Linux x86-64 kernel termios
    // into this live buffer. fd is one of the host's standard descriptors;
    // no guest pointer or request number is forwarded.
    let result = unsafe { ioctl(fd, 0x5401, attributes.as_mut_ptr()) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(25) {
            return Ok(None);
        }
        return Err(Errno(error.raw_os_error().unwrap_or(5)));
    }
    let mut size = [0u8; 8];
    // SAFETY: TIOCGWINSZ writes the 8-byte Linux winsize into this live buffer.
    let result = unsafe { ioctl(fd, 0x5413, size.as_mut_ptr()) };
    if result < 0 {
        return Err(Errno(
            io::Error::last_os_error().raw_os_error().unwrap_or(5),
        ));
    }
    let flag = |i| {
        u32::from_ne_bytes([
            attributes[i],
            attributes[i + 1],
            attributes[i + 2],
            attributes[i + 3],
        ])
    };
    let mut control_chars = [0; 19];
    control_chars.copy_from_slice(&attributes[17..36]);
    Ok(Some(TerminalInfo {
        attributes: TerminalAttributes {
            input_flags: flag(0),
            output_flags: flag(4),
            control_flags: flag(8),
            local_flags: flag(12),
            line: attributes[16],
            control_chars,
        },
        rows: u16::from_ne_bytes([size[0], size[1]]),
        columns: u16::from_ne_bytes([size[2], size[3]]),
        x_pixels: u16::from_ne_bytes([size[4], size[5]]),
        y_pixels: u16::from_ne_bytes([size[6], size[7]]),
    }))
}
#[cfg(all(
    not(target_arch = "wasm32"),
    not(target_os = "macos"),
    not(windows),
    not(all(target_os = "linux", target_arch = "x86_64"))
))]
fn native_terminal_info(_stream: StreamId) -> Result<Option<TerminalInfo>, Errno> {
    Ok(None)
}

#[cfg(target_os = "macos")]
fn native_terminal_info(stream: StreamId) -> Result<Option<TerminalInfo>, Errno> {
    macos::terminal_info(stream.index() as i32)
}

#[cfg(windows)]
fn native_terminal_info(stream: StreamId) -> Result<Option<TerminalInfo>, Errno> {
    windows::terminal_info(stream)
}

#[cfg(test)]
mod terminal_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod macos_tests;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod threads_tests;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod windows_tests;
