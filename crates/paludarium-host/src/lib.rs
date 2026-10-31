//! Host abstraction for paludarium.
//!
//! Every host facility the emulator uses goes through the [`Host`] trait,
//! so that the native and wasm implementations differ only here.
//! The core emulator needs standard I/O and randomness (for `AT_RANDOM`);
//! threads, time and host files are added on top.
//!
//! This is the only crate where `unsafe` is permitted. The core
//! implementation does not need any.

#![cfg_attr(windows, feature(windows_by_handle))]
#![cfg_attr(target_arch = "wasm32", feature(stdarch_wasm_atomic_wait))]

use std::io;
#[cfg(all(not(target_arch = "wasm32"), not(unix)))]
use std::io::Read;
#[cfg(not(target_arch = "wasm32"))]
use std::io::Write;
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
#[cfg(not(target_arch = "wasm32"))]
mod native_net;
pub mod net;
pub use fs::{DirectoryEntry, FileHandle, FileStat, FsStats, HostFs};
#[cfg(not(target_arch = "wasm32"))]
pub use native_fs::NativeFs;
#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub use wasm::WasmHost;
pub mod testing;
#[cfg(target_arch = "wasm32")]
pub mod wasm_net;
pub use clock::{ClockId, WaitOutcome};

/// What reading the host's standard input would find now
/// ([`Host::stdin_state`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdinState {
    /// Nothing yet: a read would wait.
    Waiting,
    /// Bytes wait to be read.
    Readable,
    /// The input has ended: a read returns 0.
    Ended,
}
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
    /// What reading the host's standard input would find now. `None` where
    /// the host cannot tell; the guest then sees the stream as always
    /// readable, as before.
    fn stdin_state(&self) -> Option<StdinState> {
        None
    }
    /// Whether the host's standard input is a pipe, a socket or a terminal,
    /// the files Linux signals with `O_ASYNC` (those with `fasync`); not one
    /// where the host cannot tell.
    fn stdin_signals(&self) -> bool {
        false
    }
    /// Whether the host's standard output (`channel` 1) or standard error
    /// (2) is a pipe, a socket or a terminal, which Linux signals with
    /// `O_ASYNC`; not one where the host cannot tell.
    fn output_signals(&self, _channel: u32) -> bool {
        false
    }
    /// Whether a write to the host's standard output (`channel` 1) or
    /// standard error (2) would find room now; `None` where the host cannot
    /// tell.
    fn output_writable(&self, _channel: u32) -> Option<bool> {
        None
    }
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
    /// CPU time the calling host thread has used, in nanoseconds; `ENOSYS`
    /// where the host cannot measure it, and the kernel then counts wall time.
    fn thread_cpu_time(&self) -> Result<u64, Errno> {
        Err(Errno::ENOSYS)
    }
    /// How many CPUs the guest may run on: the host's available parallelism,
    /// or 1 where it is unknown (WebAssembly).
    fn cpu_count(&self) -> usize {
        std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
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
    /// Starts a TCP connection to `address`, which the kernel's policy
    /// allowed; `ENETUNREACH` where the host has no network.
    fn connect(
        &self,
        _address: core::net::SocketAddr,
    ) -> Result<std::sync::Arc<net::Stream>, Errno> {
        Err(net::UNREACHABLE)
    }
    /// Starts resolving `name`, which the kernel's policy allowed.
    fn resolve(&self, _name: &str) -> Result<std::sync::Arc<net::Lookup>, Errno> {
        Err(net::UNREACHABLE)
    }
    /// The host's address a datagram to `address` would leave from, as its
    /// routes pick it, without sending anything; `None` where the host
    /// cannot tell, and the error of an address it has no route to.
    fn route_source(
        &self,
        _address: core::net::SocketAddr,
    ) -> Result<Option<core::net::IpAddr>, Errno> {
        Ok(None)
    }
}

/// Whether `stream` is a pipe, a socket or a terminal: the files Linux has
/// `fasync` for.
#[cfg(unix)]
fn signals(stream: &(impl rustix::fd::AsFd + std::io::IsTerminal)) -> bool {
    stream.is_terminal()
        || rustix::fs::fstat(stream).is_ok_and(|stat| {
            matches!(
                rustix::fs::FileType::from_raw_mode(stat.st_mode),
                rustix::fs::FileType::Fifo | rustix::fs::FileType::Socket
            )
        })
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
    fn thread_cpu_time(&self) -> Result<u64, Errno> {
        clock::native_thread_cpu_time()
    }
    fn wait_until(
        &self,
        clock: ClockId,
        deadline: u64,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<WaitOutcome, Errno> {
        clock::native_wait(clock, deadline, cancel)
    }
    /// On a Unix host the descriptor is read directly, past `std`'s buffer,
    /// so that [`Host::stdin_state`] sees every byte not yet read. A closed
    /// standard input (`EBADF`) reads as its end, as `std`'s `Stdin` has it.
    fn read_stdin(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        #[cfg(unix)]
        {
            match rustix::io::read(io::stdin(), buf) {
                Err(rustix::io::Errno::BADF) => Ok(0),
                result => result.map_err(|e| errno_from_io(&e.into())),
            }
        }
        #[cfg(not(unix))]
        {
            io::stdin().lock().read(buf).map_err(|e| errno_from_io(&e))
        }
    }
    /// A poll of the standard input that does not wait, on a Unix host:
    /// input to read, or else a hang-up or a closed descriptor as its end.
    fn stdin_state(&self) -> Option<StdinState> {
        #[cfg(unix)]
        {
            use rustix::event::{PollFd, PollFlags, Timespec};
            let stdin = io::stdin();
            let mut fds = [PollFd::new(&stdin, PollFlags::IN)];
            let now = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            rustix::event::poll(&mut fds, Some(&now)).ok()?;
            let revents = fds[0].revents();
            Some(if revents.contains(PollFlags::IN) {
                StdinState::Readable
            } else if revents.is_empty() {
                StdinState::Waiting
            } else {
                StdinState::Ended
            })
        }
        #[cfg(not(unix))]
        {
            None
        }
    }
    fn stdin_signals(&self) -> bool {
        #[cfg(unix)]
        {
            signals(&io::stdin())
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
    fn output_signals(&self, channel: u32) -> bool {
        #[cfg(unix)]
        {
            match channel {
                1 => signals(&io::stdout()),
                2 => signals(&io::stderr()),
                _ => false,
            }
        }
        #[cfg(not(unix))]
        {
            let _ = channel;
            false
        }
    }
    /// A poll for `POLLOUT` that does not wait, on a Unix host.
    fn output_writable(&self, channel: u32) -> Option<bool> {
        #[cfg(unix)]
        {
            use rustix::event::{PollFd, PollFlags, Timespec};
            let now = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let writable = |fd: &dyn rustix::fd::AsFd| {
                let mut fds = [PollFd::new(&fd, PollFlags::OUT)];
                rustix::event::poll(&mut fds, Some(&now)).ok()?;
                Some(fds[0].revents().contains(PollFlags::OUT))
            };
            match channel {
                1 => writable(&io::stdout()),
                2 => writable(&io::stderr()),
                _ => None,
            }
        }
        #[cfg(not(unix))]
        {
            let _ = channel;
            None
        }
    }

    fn write_stdout(&self, buf: &[u8]) -> Result<usize, Errno> {
        write_through(&mut io::stdout().lock(), buf)
    }
    fn connect(
        &self,
        address: core::net::SocketAddr,
    ) -> Result<std::sync::Arc<net::Stream>, Errno> {
        native_net::connect(address)
    }
    fn resolve(&self, name: &str) -> Result<std::sync::Arc<net::Lookup>, Errno> {
        native_net::resolve(name)
    }
    fn route_source(
        &self,
        address: core::net::SocketAddr,
    ) -> Result<Option<core::net::IpAddr>, Errno> {
        native_net::route_source(address).map(Some)
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
        for (kind, errno) in [
            (io::ErrorKind::BrokenPipe, Errno::EPIPE),
            (io::ErrorKind::WouldBlock, Errno::EAGAIN),
            (io::ErrorKind::InvalidInput, Errno::EINVAL),
        ] {
            assert_eq!(errno_from_io(&io::Error::from(kind)), errno);
        }
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
        assert!(Broken.flush().is_ok());
        // A write that lands but whose flush fails reports the flush.
        struct Unflushed;
        impl Write for Unflushed {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
        }
        assert_eq!(write_through(&mut Unflushed, b"x"), Err(Errno::EAGAIN));
    }

    /// A host with only the methods it must have.
    struct Bare;
    impl Host for Bare {
        fn read_stdin(&self, _: &mut [u8]) -> Result<usize, Errno> {
            Ok(0)
        }
        fn write_stdout(&self, buf: &[u8]) -> Result<usize, Errno> {
            Ok(buf.len())
        }
        fn write_stderr(&self, buf: &[u8]) -> Result<usize, Errno> {
            Ok(buf.len())
        }
        fn random_bytes(&self, buf: &mut [u8]) -> Result<(), Error> {
            buf.fill(0);
            Ok(())
        }
    }

    #[test]
    fn a_host_without_the_optional_facilities_refuses_them() {
        let host = Bare;
        let mut buf = [1];
        assert_eq!(
            (host.read_stdin(&mut buf), host.write_stdout(b"x")),
            (Ok(0), Ok(1))
        );
        assert_eq!(host.write_stderr(b"x"), Ok(1));
        assert!(host.random_bytes(&mut buf).is_ok());
        assert_eq!(host.terminal_info(StreamId::Stdout), Ok(None));
        assert!(matches!(host.mount_fs(Path::new("/")), Err(Errno::ENOSYS)));
        assert_eq!(host.clock(ClockId::Monotonic), Err(Errno::ENOSYS));
        assert_eq!(host.thread_cpu_time(), Err(Errno::ENOSYS));
        assert!(host.cpu_count() >= 1);
        let cancel = std::sync::atomic::AtomicBool::new(false);
        assert_eq!(
            host.wait_until(ClockId::Monotonic, 0, &cancel),
            Err(Errno::ENOSYS)
        );
        assert!(
            host.connect("127.0.0.1:1".parse().unwrap())
                .is_err_and(|e| e == net::UNREACHABLE)
        );
        assert!(
            host.resolve("localhost")
                .is_err_and(|e| e == net::UNREACHABLE)
        );
    }

    #[test]
    fn native_host_passes_its_facilities_through() {
        let host = NativeHost::new();
        // Whether a stream is a terminal depends on how the tests run.
        assert!(host.terminal_info(StreamId::Stdout).is_ok());
        let root = std::env::temp_dir();
        assert!(host.mount_fs(&root).is_ok());
        assert!(host.thread_cpu_time().is_ok());
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
