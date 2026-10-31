//! Outbound TCP streams and name lookups that a host drives for the guest.
//!
//! The kernel never waits on the host network. It reads, writes and polls
//! a [`Stream`], whose buffers a host driver fills and drains on its own
//! (threads natively, the JavaScript event loop in WebAssembly), and asks a
//! [`Lookup`] whether its answer has come. Both call the kernel's waker
//! whenever the driver changes them.
use core::net::{IpAddr, SocketAddr};
use paludarium_types::Errno;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The most bytes a stream holds in each direction before reads wait for
/// the guest (receiving) or writes wait for the host (sending), unless the
/// kernel sets other limits ([`Stream::set_limits`]).
pub const BUFFER: usize = 256 * 1024;

/// `ENETUNREACH`: what a host without a network answers.
pub const UNREACHABLE: Errno = Errno(101);

/// What the kernel asks of the driver of a [`Stream`].
pub trait Driver: Send + Sync {
    /// The kernel changed the stream: bytes to send, room to receive, a
    /// shutdown or the close.
    fn kick(&self);
    /// `TCP_NODELAY` turned on or off.
    fn set_nodelay(&self, _on: bool) {}
}

/// Where a stream's connection stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Connecting,
    Open,
    /// The connection could not be made, or broke, with this error.
    Failed(Errno),
}

/// What a driver changed in a [`Stream`], as its waker is told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The connection opened.
    Connected,
    /// The connection could not be made, or broke.
    Failed,
    /// Bytes arrived.
    Received,
    /// The peer ended its side.
    Ended,
    /// Queued bytes left for the host, freeing room.
    Sent,
}

/// What [`Stream::readiness`] finds: what a read or write would do now and
/// how often bytes have arrived and left, for edge-triggered waits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Readiness {
    /// A read would not wait: bytes, the end of input or an error.
    pub readable: bool,
    /// A write would not wait: room, or an error.
    pub writable: bool,
    /// The peer has ended its side, or the connection failed.
    pub read_closed: bool,
    /// The guest has shut its sending down or closed the stream.
    pub write_closed: bool,
    /// The connection failed.
    pub failed: bool,
    pub arrivals: u64,
    pub departures: u64,
}

struct State {
    phase: Phase,
    local: Option<SocketAddr>,
    received: VecDeque<u8>,
    received_end: bool,
    sending: VecDeque<u8>,
    /// The most bytes `received` and `sending` hold.
    receive_limit: usize,
    send_limit: usize,
    send_shut: bool,
    closed: bool,
    arrivals: u64,
    departures: u64,
}

type Waker = Arc<dyn Fn() + Send + Sync>;
type StreamWaker = Arc<dyn Fn(Event) + Send + Sync>;

/// A TCP connection the guest opened: its phase, addresses and buffers.
pub struct Stream {
    peer: SocketAddr,
    state: Mutex<State>,
    waker: Mutex<Option<StreamWaker>>,
    driver: Mutex<Option<Arc<dyn Driver>>>,
    /// Native drivers wait on this with the state lock.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) signal: std::sync::Condvar,
}

impl Stream {
    /// A stream connecting to `peer`, for a driver to take.
    #[must_use]
    pub fn new(peer: SocketAddr) -> Arc<Self> {
        Arc::new(Self {
            peer,
            state: Mutex::new(State {
                phase: Phase::Connecting,
                local: None,
                received: VecDeque::new(),
                received_end: false,
                sending: VecDeque::new(),
                receive_limit: BUFFER,
                send_limit: BUFFER,
                send_shut: false,
                closed: false,
                arrivals: 0,
                departures: 0,
            }),
            waker: Mutex::new(None),
            driver: Mutex::new(None),
            #[cfg(not(target_arch = "wasm32"))]
            signal: std::sync::Condvar::new(),
        })
    }
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// The most bytes the stream holds to send and received, [`BUFFER`]
    /// each until set. A larger limit lets the guest write or the driver
    /// deliver more at once.
    pub fn set_limits(&self, send: usize, receive: usize) {
        {
            let mut s = self.lock();
            s.send_limit = send;
            s.receive_limit = receive;
        }
        self.kick();
    }
    /// The driver the kernel tells of its changes.
    pub fn set_driver(&self, driver: Arc<dyn Driver>) {
        *self.driver.lock().unwrap_or_else(PoisonError::into_inner) = Some(driver);
    }
    /// What the driver calls after each change it makes, with the change.
    pub fn set_waker(&self, waker: Arc<dyn Fn(Event) + Send + Sync>) {
        *self.waker.lock().unwrap_or_else(PoisonError::into_inner) = Some(waker);
    }
    fn wake(&self, event: Event) {
        #[cfg(not(target_arch = "wasm32"))]
        self.signal.notify_all();
        let waker = self
            .waker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(waker) = waker {
            waker(event);
        }
    }
    fn kick(&self) {
        #[cfg(not(target_arch = "wasm32"))]
        self.signal.notify_all();
        let driver = self
            .driver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(driver) = driver {
            driver.kick();
        }
    }

    // The kernel's side.

    #[must_use]
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }
    #[must_use]
    pub fn phase(&self) -> Phase {
        self.lock().phase
    }
    /// The host's address of the connection, once it is open.
    #[must_use]
    pub fn local(&self) -> Option<SocketAddr> {
        self.lock().local
    }
    /// Reads received bytes, keeping them with `peek`. `EAGAIN` while none
    /// have come; 0 at the end of input; the error of a failed connection.
    pub fn read(&self, buf: &mut [u8], peek: bool) -> Result<usize, Errno> {
        let mut s = self.lock();
        if !s.received.is_empty() {
            let n = buf.len().min(s.received.len());
            for (to, from) in buf.iter_mut().zip(s.received.iter()) {
                *to = *from;
            }
            if !peek {
                let was_full = s.received.len() >= s.receive_limit;
                s.received.drain(..n);
                drop(s);
                if was_full {
                    self.kick();
                }
            }
            return Ok(n);
        }
        match s.phase {
            Phase::Failed(e) => Err(e),
            _ if s.received_end => Ok(0),
            _ => Err(Errno::EAGAIN),
        }
    }
    /// Queues bytes to send: `EAGAIN` while connecting or full, `EPIPE`
    /// once this side is shut down, the error of a failed connection.
    pub fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        let mut s = self.lock();
        if let Phase::Failed(e) = s.phase {
            return Err(e);
        }
        if s.send_shut || s.closed {
            return Err(Errno::EPIPE);
        }
        let room = s.send_limit.saturating_sub(s.sending.len());
        if s.phase == Phase::Connecting || room == 0 {
            return Err(Errno::EAGAIN);
        }
        let n = buf.len().min(room);
        s.sending.extend(&buf[..n]);
        drop(s);
        self.kick();
        Ok(n)
    }
    /// Ends this side's sending once what is queued has gone.
    pub fn shutdown_write(&self) {
        self.lock().send_shut = true;
        self.kick();
    }
    /// Ends the guest's use of the stream; the driver sends what is queued
    /// and then closes the connection.
    pub fn close(&self) {
        self.lock().closed = true;
        self.kick();
    }
    #[must_use]
    pub fn readiness(&self) -> Readiness {
        let s = self.lock();
        let failed = matches!(s.phase, Phase::Failed(_));
        let open = s.phase == Phase::Open;
        Readiness {
            readable: !s.received.is_empty() || s.received_end || failed,
            writable: failed || (open && (s.send_shut || s.sending.len() < s.send_limit)),
            read_closed: s.received_end || failed,
            write_closed: s.send_shut || s.closed,
            failed,
            arrivals: s.arrivals,
            departures: s.departures,
        }
    }
    /// The bytes waiting to be read and waiting to be sent.
    #[must_use]
    pub fn queued(&self) -> (usize, usize) {
        let s = self.lock();
        (s.received.len(), s.sending.len())
    }
    /// Passes `TCP_NODELAY` to the driver.
    pub fn set_nodelay(&self, on: bool) {
        let driver = self
            .driver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(driver) = driver {
            driver.set_nodelay(on);
        }
    }

    // The driver's side.

    /// The connection is open, from the host's address `local`.
    pub fn connected(&self, local: Option<SocketAddr>) {
        {
            let mut s = self.lock();
            if s.phase != Phase::Connecting {
                return;
            }
            s.phase = Phase::Open;
            s.local = local;
            s.departures += 1;
        }
        self.wake(Event::Connected);
    }
    /// The connection could not be made, or broke.
    pub fn fail(&self, error: Errno) {
        {
            let mut s = self.lock();
            if matches!(s.phase, Phase::Failed(_)) {
                return;
            }
            s.phase = Phase::Failed(error);
            s.sending.clear();
            s.arrivals += 1;
            s.departures += 1;
        }
        self.wake(Event::Failed);
    }
    /// How many more received bytes the stream takes now.
    #[must_use]
    pub fn room(&self) -> usize {
        let s = self.lock();
        s.receive_limit.saturating_sub(s.received.len())
    }
    /// Adds received bytes; returns how many fitted.
    pub fn receive(&self, bytes: &[u8]) -> usize {
        let n = {
            let mut s = self.lock();
            let n = bytes
                .len()
                .min(s.receive_limit.saturating_sub(s.received.len()));
            s.received.extend(&bytes[..n]);
            if n > 0 {
                s.arrivals += 1;
            }
            n
        };
        if n > 0 {
            self.wake(Event::Received);
        }
        n
    }
    /// The peer ended its side.
    pub fn end(&self) {
        {
            let mut s = self.lock();
            s.received_end = true;
            s.arrivals += 1;
        }
        self.wake(Event::Ended);
    }
    /// Takes up to `max` queued bytes to send.
    pub fn take(&self, max: usize) -> Vec<u8> {
        let taken: Vec<u8> = {
            let mut s = self.lock();
            let n = max.min(s.sending.len());
            let taken = s.sending.drain(..n).collect();
            if n > 0 {
                s.departures += 1;
            }
            taken
        };
        if !taken.is_empty() {
            self.wake(Event::Sent);
        }
        taken
    }
    /// Whether nothing is queued and the guest has shut its sending down,
    /// and whether it has closed the stream.
    #[must_use]
    pub fn finished(&self) -> (bool, bool) {
        let s = self.lock();
        (s.sending.is_empty() && s.send_shut, s.closed)
    }

    /// For a native driver's sender: waits for bytes to send, for the
    /// shutdown (unless `shut` says it was seen) or for the close, once
    /// what is queued has gone.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn wait_to_send(&self, shut: bool) -> Sending {
        let mut s = self.lock();
        loop {
            if matches!(s.phase, Phase::Failed(_)) {
                return Sending::Closed;
            }
            if !s.sending.is_empty() {
                let n = s.sending.len().min(64 * 1024);
                let bytes = s.sending.drain(..n).collect();
                s.departures += 1;
                drop(s);
                self.wake(Event::Sent);
                return Sending::Bytes(bytes);
            }
            if s.closed {
                return Sending::Closed;
            }
            if s.send_shut && !shut {
                return Sending::Shut;
            }
            s = self.signal.wait(s).unwrap_or_else(PoisonError::into_inner);
        }
    }
    /// For a native driver's receiver: waits for room for received bytes;
    /// `None` once the guest has closed the stream or it failed.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn wait_for_room(&self) -> Option<usize> {
        let mut s = self.lock();
        loop {
            if s.closed || matches!(s.phase, Phase::Failed(_)) {
                return None;
            }
            let room = s.receive_limit.saturating_sub(s.received.len());
            if room > 0 {
                return Some(room);
            }
            s = self.signal.wait(s).unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// What a native driver's sender is to do next.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) enum Sending {
    Bytes(Vec<u8>),
    Shut,
    Closed,
}

/// A name lookup the host answers in its own time.
pub struct Lookup {
    state: Mutex<LookupState>,
}
#[derive(Default)]
struct LookupState {
    result: Option<Result<Vec<IpAddr>, Errno>>,
    wakers: Vec<Waker>,
}
impl Lookup {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::default(),
        })
    }
    /// Adds what is called once the host has the answer; `false`, and
    /// nothing added, when it has it already.
    pub fn add_waker(&self, waker: Arc<dyn Fn() + Send + Sync>) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.result.is_some() {
            return false;
        }
        state.wakers.push(waker);
        true
    }
    /// The answer: the addresses (none for a name that does not exist), or
    /// the error that kept the host from finding them.
    pub fn finish(&self, result: Result<Vec<IpAddr>, Errno>) {
        let wakers = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.result = Some(result);
            std::mem::take(&mut state.wakers)
        };
        for waker in wakers {
            waker();
        }
    }
    /// The answer, once it has come.
    #[must_use]
    pub fn result(&self) -> Option<Result<Vec<IpAddr>, Errno>> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .result
            .clone()
    }
}

/// The errno of a host network error, as Linux numbers it.
#[must_use]
pub fn errno_from_net(error: &std::io::Error) -> Errno {
    use std::io::ErrorKind as K;
    Errno(match error.kind() {
        K::ConnectionRefused => 111,
        K::ConnectionReset => 104,
        K::ConnectionAborted => 103,
        K::NotConnected => 107,
        K::AddrInUse => 98,
        K::AddrNotAvailable => 99,
        K::TimedOut => 110,
        K::HostUnreachable => 113,
        K::NetworkUnreachable => 101,
        K::NetworkDown => 100,
        K::BrokenPipe => 32,
        K::PermissionDenied => 13,
        _ => 5,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn counted(stream: &Stream) -> Arc<AtomicUsize> {
        let wakes = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&wakes);
        stream.set_waker(Arc::new(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
        }));
        wakes
    }

    #[test]
    fn a_stream_waits_to_connect_then_carries_bytes_both_ways() {
        let stream = Stream::new("127.0.0.1:80".parse().unwrap());
        let wakes = counted(&stream);
        assert_eq!(stream.write(b"x"), Err(Errno::EAGAIN));
        assert_eq!(stream.read(&mut [0; 4], false), Err(Errno::EAGAIN));
        assert!(!stream.readiness().writable);
        stream.connected(Some("127.0.0.1:5000".parse().unwrap()));
        assert_eq!(stream.phase(), Phase::Open);
        assert_eq!(stream.local(), Some("127.0.0.1:5000".parse().unwrap()));
        assert!(stream.readiness().writable);
        assert_eq!(stream.write(b"hello"), Ok(5));
        assert_eq!(stream.queued(), (0, 5));
        assert_eq!(stream.take(3), b"hel");
        assert_eq!(stream.take(9), b"lo");
        assert_eq!(stream.receive(b"abc"), 3);
        let mut buf = [0; 2];
        assert_eq!(stream.read(&mut buf, true), Ok(2));
        assert_eq!(stream.read(&mut buf, false), Ok(2));
        assert_eq!(&buf, b"ab");
        assert_eq!(stream.read(&mut buf, false), Ok(1));
        assert_eq!(stream.read(&mut buf, false), Err(Errno::EAGAIN));
        stream.end();
        assert!(stream.readiness().read_closed);
        assert_eq!(stream.read(&mut buf, false), Ok(0));
        assert!(wakes.load(Ordering::SeqCst) >= 5);
    }

    #[test]
    fn buffers_hold_at_most_their_size() {
        let stream = Stream::new("127.0.0.1:80".parse().unwrap());
        stream.connected(None);
        let big = vec![7; BUFFER + 10];
        assert_eq!(stream.write(&big), Ok(BUFFER));
        assert_eq!(stream.write(b"x"), Err(Errno::EAGAIN));
        assert!(!stream.readiness().writable);
        assert_eq!(stream.receive(&big), BUFFER);
        assert_eq!(stream.room(), 0);
        assert_eq!(stream.receive(b"x"), 0);
    }

    #[test]
    fn shutdown_close_and_failure() {
        let stream = Stream::new("[::1]:80".parse().unwrap());
        stream.connected(None);
        stream.write(b"ab").unwrap();
        stream.shutdown_write();
        assert_eq!(stream.write(b"c"), Err(Errno::EPIPE));
        assert_eq!(stream.finished(), (false, false));
        stream.take(2);
        assert_eq!(stream.finished(), (true, false));
        stream.close();
        assert_eq!(stream.finished(), (true, true));
        stream.fail(Errno(104));
        assert_eq!(stream.read(&mut [0], false), Err(Errno(104)));
        assert_eq!(stream.write(b"x"), Err(Errno(104)));
        let ready = stream.readiness();
        assert!(ready.readable && ready.writable && ready.failed && ready.read_closed);
    }

    #[test]
    fn a_lookup_answers_once_the_host_has() {
        let lookup = Lookup::new();
        let wakes = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&wakes);
        for _ in 0..2 {
            let seen = Arc::clone(&seen);
            assert!(lookup.add_waker(Arc::new(move || {
                seen.fetch_add(1, Ordering::SeqCst);
            })));
        }
        assert_eq!(lookup.result(), None);
        lookup.finish(Ok(vec!["192.0.2.1".parse().unwrap()]));
        assert!(!lookup.add_waker(Arc::new(|| {})));
        assert_eq!(
            lookup.result(),
            Some(Ok(vec!["192.0.2.1".parse().unwrap()]))
        );
        assert_eq!(wakes.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn host_network_errors_take_linux_numbers() {
        use std::io::{Error, ErrorKind};
        for (kind, errno) in [
            (ErrorKind::ConnectionRefused, 111),
            (ErrorKind::ConnectionReset, 104),
            (ErrorKind::TimedOut, 110),
            (ErrorKind::Other, 5),
        ] {
            assert_eq!(errno_from_net(&Error::from(kind)), Errno(errno));
        }
    }
}
