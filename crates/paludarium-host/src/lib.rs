//! Host abstraction for paludarium.
//!
//! Every host facility the emulator uses goes through the [`Host`] trait,
//! so that the native and wasm implementations differ only here.
//! The core emulator needs standard I/O and randomness (for `AT_RANDOM`);
//! threads, time and host files are added on top.
//!
//! This is the only crate where `unsafe` is permitted. The core
//! implementation does not need any.

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
pub use fs::{DirectoryEntry, FileHandle, FileStat, FsStats, HostFs, Xattrs};
#[cfg(not(target_arch = "wasm32"))]
pub use native_fs::NativeFs;
#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub use wasm::WasmHost;
pub mod testing;
#[cfg(target_arch = "wasm32")]
pub mod wasm_net;
pub use clock::{ClockId, ThreadCpuClock, WaitOutcome};

/// Whether the guest thread a host thread runs is blocked in a wait of the
/// host ([`Host::wait_on`], [`Host::wait_until`]): what `/proc` shows as
/// sleeping, as Linux shows a task that is not running. While the kernel
/// handles a stop of a guest thread, it gives the host thread that thread's
/// flag ([`blocked::attach`]), and a wait sets it from the moment it goes
/// to sleep until it ends ([`blocked::Waiting`]). A wait outside that
/// (a worker's, or the runtime's) sets nothing.
pub mod blocked {
    use core::cell::{Cell, RefCell};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    std::thread_local! {
        static FLAG: RefCell<Option<Arc<AtomicBool>>> = const { RefCell::new(None) };
        static ACTIVE: Cell<bool> = const { Cell::new(false) };
    }

    /// Makes `flag` the one this host thread's waits set until the guard
    /// it returns is dropped. The flag stays cached after that, unmarked by
    /// any wait, so attaching it again costs no reference count.
    pub fn attach(flag: &Arc<AtomicBool>) -> Attached {
        let replaced = FLAG.with(|current| {
            let mut current = current.borrow_mut();
            if current.as_ref().is_some_and(|f| Arc::ptr_eq(f, flag)) {
                None
            } else {
                current.replace(Arc::clone(flag))
            }
        });
        Attached {
            active: ACTIVE.with(|active| active.replace(true)),
            replaced,
        }
    }

    /// The time a flag is attached ([`attach`]). Within another attachment,
    /// it gives the outer one back its flag and its state as it ends.
    #[must_use]
    pub struct Attached {
        active: bool,
        replaced: Option<Arc<AtomicBool>>,
    }
    impl Drop for Attached {
        fn drop(&mut self) {
            if let Some(outer) = self.replaced.take() {
                FLAG.with(|current| *current.borrow_mut() = Some(outer));
            }
            ACTIVE.with(|active| active.set(self.active));
        }
    }

    /// A wait of the host: from [`Self::sleep`] the attached flag is set,
    /// and once it ends it is back as it was, so a wait within another
    /// keeps it set.
    #[must_use]
    #[derive(Default)]
    pub struct Waiting(Option<(Arc<AtomicBool>, bool)>);
    impl Waiting {
        /// A wait that has not gone to sleep yet.
        pub fn new() -> Self {
            Self::default()
        }
        /// The wait goes to sleep, as it is about to block.
        pub fn sleep(&mut self) {
            if self.0.is_some() || !ACTIVE.with(Cell::get) {
                return;
            }
            self.0 = FLAG.with(|current| {
                let flag = current.borrow().clone()?;
                let was = flag.swap(true, Ordering::SeqCst);
                Some((flag, was))
            });
        }
    }
    impl Drop for Waiting {
        fn drop(&mut self) {
            if let Some((flag, was)) = &self.0 {
                flag.store(*was, Ordering::SeqCst);
            }
        }
    }
}

/// The times the calling host thread went to sleep in a wait of the host
/// ([`Host::wait_on`], [`Host::wait_until`]), each wait once however often
/// it wakes to look at its cancellation: what the kernel adds to its guest
/// thread's context switches (`perf`'s `context-switches`), as Linux counts
/// one each time the thread is scheduled out to sleep.
pub mod switches {
    use core::cell::Cell;

    std::thread_local! {
        static TAKEN: Cell<u64> = const { Cell::new(0) };
    }

    /// The thread goes to sleep; `slept` says whether this wait has already
    /// counted.
    pub fn sleep(slept: &mut bool) {
        if !core::mem::replace(slept, true) {
            TAKEN.with(|taken| taken.set(taken.get().wrapping_add(1)));
        }
    }

    /// Whether this host thread has slept since the last [`take`].
    #[must_use]
    pub fn pending() -> bool {
        TAKEN.with(|taken| taken.get() != 0)
    }

    /// The sleeps since the last call, on this host thread.
    #[must_use]
    pub fn take() -> u64 {
        TAKEN.with(|taken| taken.replace(0))
    }
}

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
    /// The signals the emulator itself started with ignored, as Linux
    /// numbers (bit `n - 1` for signal `n`): what the guest's first program
    /// keeps ignored, as Linux's `execve` keeps `SIG_IGN`
    /// (`flush_signal_handlers`). None where the host cannot tell.
    fn ignored_signals(&self) -> u64 {
        0
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
    /// A clock of the calling host thread's CPU time, as
    /// [`Self::thread_cpu_time`] counts it, that any thread may read;
    /// `None` where the host has none.
    fn thread_cpu_clock(&self) -> Option<std::sync::Arc<dyn ThreadCpuClock>> {
        None
    }
    /// How many CPUs the guest may run on: the host's available parallelism,
    /// or 1 where it is unknown (WebAssembly).
    fn cpu_count(&self) -> usize {
        std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
    }
    /// The time slice the host's scheduler gives a thread of the normal
    /// policy, and its tick, as Linux reports them; `None` where the host
    /// does not tell.
    fn scheduler_slice(&self) -> Option<SchedulerSlice> {
        None
    }
    /// The NTP state of the host's real-time clock, as a read-only
    /// `adjtimex` gives it; `None` where the host does not tell, and the
    /// kernel then gives the state Linux starts with.
    fn ntp_state(&self) -> Option<NtpState> {
        None
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

/// Maps a host I/O error to the errno the guest sees. A descriptor or
/// handle that is not open, such as a standard stream the command was
/// started without, is `EBADF`, as the guest's own call is on Linux when
/// it has no such descriptor.
#[must_use]
pub fn errno_from_io(err: &io::Error) -> Errno {
    if bad_descriptor(err) {
        return Errno::EBADF;
    }
    match err.kind() {
        io::ErrorKind::BrokenPipe => Errno::EPIPE,
        io::ErrorKind::WouldBlock => Errno::EAGAIN,
        io::ErrorKind::InvalidInput => Errno::EINVAL,
        _ => Errno::EIO,
    }
}

/// `EBADF` on a Unix host, `ERROR_INVALID_HANDLE` on Windows: what `std`
/// itself takes for a closed standard stream.
fn bad_descriptor(err: &io::Error) -> bool {
    #[cfg(unix)]
    {
        err.raw_os_error() == Some(rustix::io::Errno::BADF.raw_os_error())
    }
    #[cfg(windows)]
    {
        const ERROR_INVALID_HANDLE: i32 = 6;
        err.raw_os_error() == Some(ERROR_INVALID_HANDLE)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = err;
        false
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn write_through(out: &mut dyn Write, buf: &[u8]) -> Result<usize, Errno> {
    out.write_all(buf).map_err(|e| errno_from_io(&e))?;
    out.flush().map_err(|e| errno_from_io(&e))?;
    Ok(buf.len())
}

/// The time slice of a thread under Linux's normal policy (`se.slice`, the
/// `sched_runtime` that `sched_getattr` reports) and the scheduler's tick
/// (the resolution of `CLOCK_MONOTONIC_COARSE`), both in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulerSlice {
    pub slice: u64,
    pub tick: u64,
}

/// The NTP state of a real-time clock, as Linux's `adjtimex` reports it in
/// `struct __kernel_timex` (without its `modes` and `time`), and the call's
/// result (the clock's state, `TIME_OK` to `TIME_ERROR`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NtpState {
    pub result: i32,
    pub offset: i64,
    pub freq: i64,
    pub maxerror: i64,
    pub esterror: i64,
    pub status: i32,
    pub constant: i64,
    pub precision: i64,
    pub tolerance: i64,
    pub tick: i64,
    pub ppsfreq: i64,
    pub jitter: i64,
    pub shift: i32,
    pub stabil: i64,
    pub jitcnt: i64,
    pub calcnt: i64,
    pub errcnt: i64,
    pub stbcnt: i64,
    pub tai: i32,
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
    fn thread_cpu_clock(&self) -> Option<std::sync::Arc<dyn ThreadCpuClock>> {
        clock::native_thread_cpu_clock()
    }
    /// On Linux, the guest's threads are the host's, so the host's time
    /// slice for this thread is the guest thread's.
    fn scheduler_slice(&self) -> Option<SchedulerSlice> {
        clock::native_scheduler_slice()
    }
    /// On Linux, the guest's real-time clock is the host's, so its NTP
    /// state is the host's too.
    fn ntp_state(&self) -> Option<NtpState> {
        clock::native_ntp_state()
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
    /// standard input (`EBADF`, `ERROR_INVALID_HANDLE` on Windows) reads as
    /// its end on every host, as `std`'s `Stdin` read it until Rust's
    /// nightly of 2026-11-19 (rust-lang/rust e60e0731bd).
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
            match io::stdin().lock().read(buf) {
                Err(e) if bad_descriptor(&e) => Ok(0),
                result => result.map_err(|e| errno_from_io(&e)),
            }
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
    fn ignored_signals(&self) -> u64 {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            native_ignored_signals()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            0
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
        // A closed descriptor or handle, which `std` no longer turns into
        // success for the standard streams.
        #[cfg(unix)]
        let closed = io::Error::from_raw_os_error(9);
        #[cfg(windows)]
        let closed = io::Error::from_raw_os_error(6);
        #[cfg(any(unix, windows))]
        assert_eq!(errno_from_io(&closed), Errno::EBADF);
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
        assert!(host.thread_cpu_clock().is_none());
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
        assert_eq!(
            host.thread_cpu_clock().is_some(),
            cfg!(any(target_os = "linux", target_os = "macos", windows))
        );
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

/// The host's signals and the Linux numbers they stand for, those a process
/// can inherit ignored (not `SIGKILL` or `SIGSTOP`). `SIGPIPE` is not
/// among them: Rust's runtime ignores it before `main` in every program, so
/// whether the emulator was started with it ignored cannot be told.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const INHERITABLE: [(libc::c_int, u32); 26] = [
    (libc::SIGHUP, 1),
    (libc::SIGINT, 2),
    (libc::SIGQUIT, 3),
    (libc::SIGILL, 4),
    (libc::SIGTRAP, 5),
    (libc::SIGABRT, 6),
    (libc::SIGBUS, 7),
    (libc::SIGFPE, 8),
    (libc::SIGUSR1, 10),
    (libc::SIGSEGV, 11),
    (libc::SIGUSR2, 12),
    (libc::SIGALRM, 14),
    (libc::SIGTERM, 15),
    (libc::SIGCHLD, 17),
    (libc::SIGCONT, 18),
    (libc::SIGTSTP, 20),
    (libc::SIGTTIN, 21),
    (libc::SIGTTOU, 22),
    (libc::SIGURG, 23),
    (libc::SIGXCPU, 24),
    (libc::SIGXFSZ, 25),
    (libc::SIGVTALRM, 26),
    (libc::SIGPROF, 27),
    (libc::SIGWINCH, 28),
    (libc::SIGIO, 29),
    (libc::SIGSYS, 31),
];

/// Which of [`INHERITABLE`] this process has ignored now, as Linux numbers.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn native_ignored_signals() -> u64 {
    let mut ignored = 0;
    // Linux's real-time signals, past the two its C library keeps.
    #[cfg(target_os = "linux")]
    let real_time = (libc::SIGRTMIN()..=libc::SIGRTMAX())
        .filter_map(|n| u32::try_from(n).ok().map(|linux| (n, linux)));
    #[cfg(target_os = "macos")]
    let real_time = std::iter::empty();
    for (host, linux) in INHERITABLE.into_iter().chain(real_time) {
        // SAFETY: a query of the action alone, into a zeroed struct.
        let handler = unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(host, std::ptr::null(), &mut old) != 0 {
                continue;
            }
            old.sa_sigaction
        };
        if handler == libc::SIG_IGN {
            ignored |= 1u64 << (linux - 1);
        }
    }
    ignored
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod ignored_tests {
    /// SIGURG, whose default is to discard it, so ignoring it a moment
    /// changes nothing else the tests do.
    #[test]
    fn the_signals_ignored_now_are_given_by_linux_number() {
        assert_eq!(super::native_ignored_signals() & 1 << (23 - 1), 0);
        // SAFETY: SIG_IGN on SIGURG, then its old action back.
        let old = unsafe { libc::signal(libc::SIGURG, libc::SIG_IGN) };
        let ignored = super::native_ignored_signals();
        // SAFETY: as above.
        unsafe { libc::signal(libc::SIGURG, old) };
        assert_ne!(ignored & 1 << (23 - 1), 0);
        // Rust's runtime ignores SIGPIPE, which is not reported.
        assert_eq!(ignored & 1 << (13 - 1), 0);
    }
}
