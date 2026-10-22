//! AF_UNIX stream endpoints. Buffers and peer lifetime belong to the Kernel.
use crate::events::{CLOEXEC, IN, NONBLOCK, OUT, ReadinessHub};
use crate::syscalls::{Context, Outcome};
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::Errno;
use paludarium_types::GuestAddr;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

// Per-stream flow-control window, not a per-guest memory/fd quota. Native
// queue capacity and packet accounting depend on the host; the oracle compares
// saturation, partial success and readiness transitions instead of byte counts.
pub(crate) const SEND_WINDOW: usize = 212_992;

/// Unidirectional anonymous pipe using the same buffered readiness transport.
pub(crate) struct PipeEnd {
    endpoint: Arc<SocketPairEnd>,
    reader: bool,
}
#[cfg(test)]
mod pipe_tests {
    use super::*;
    fn pair() -> [Arc<PipeEnd>; 2] {
        PipeEnd::pair(0, Arc::default()).unwrap()
    }
    #[test]
    fn transfer() {
        let [r, w] = pair();
        w.write(b"abc").unwrap();
        let mut b = [0; 3];
        assert_eq!(r.read(&mut b), Ok(3));
        assert_eq!(&b, b"abc");
    }
    #[test]
    fn eof_after_last_writer() {
        let [r, w] = pair();
        let copy = Arc::clone(&w);
        drop(w);
        assert_eq!(r.read(&mut [0]), Err(Errno::EAGAIN));
        drop(copy);
        assert_eq!(r.read(&mut [0]), Ok(0));
    }
    #[test]
    fn broken_pipe_after_reader() {
        let [r, w] = pair();
        drop(r);
        assert_eq!(w.write(b"x"), Err(Errno(32)));
    }
    #[test]
    fn direction_is_enforced() {
        let [r, w] = pair();
        assert_eq!(r.write(b"x"), Err(Errno::EBADF));
        assert_eq!(w.read(&mut [0]), Err(Errno::EBADF));
    }
    #[test]
    fn flags_and_seek() {
        let [r, w] = PipeEnd::pair(NONBLOCK | CLOEXEC, Arc::default()).unwrap();
        assert_eq!(r.flags(), NONBLOCK);
        assert_eq!(w.flags(), NONBLOCK | 1);
        r.set_flags(0).unwrap();
        assert_eq!(r.flags(), 0);
        assert_eq!(r.seek(0, 0), Err(Errno::ESPIPE));
    }
    #[test]
    fn readiness_transition() {
        let [r, w] = pair();
        assert_eq!(r.readiness().unwrap().0, 0);
        assert_eq!(w.readiness().unwrap().0, OUT);
        w.write(b"x").unwrap();
        assert_eq!(r.readiness().unwrap().0, IN);
        drop(w);
        assert_eq!(r.readiness().unwrap().0, IN | 0x10);
    }
    #[test]
    fn buffered_bytes_before_eof() {
        let [r, w] = pair();
        w.write(b"ab").unwrap();
        drop(w);
        assert_eq!(r.read(&mut [0]), Ok(1));
        assert_eq!(r.read(&mut [0]), Ok(1));
        assert_eq!(r.read(&mut [0]), Ok(0));
    }
}
impl PipeEnd {
    pub(crate) fn pair(flags: u32, hub: Arc<ReadinessHub>) -> Result<[Arc<Self>; 2], Errno> {
        let [reader, writer] = SocketPairEnd::pair(1 | flags, hub)?;
        reader.shutdown(1)?;
        writer.shutdown(0)?;
        Ok([
            Arc::new(Self {
                endpoint: reader,
                reader: true,
            }),
            Arc::new(Self {
                endpoint: writer,
                reader: false,
            }),
        ])
    }
}
impl FileHandle for PipeEnd {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, bytes: &mut [u8]) -> Result<usize, Errno> {
        if self.reader {
            self.endpoint.read(bytes)
        } else {
            Err(Errno::EBADF)
        }
    }
    fn write(&self, bytes: &[u8]) -> Result<usize, Errno> {
        if self.reader {
            Err(Errno::EBADF)
        } else {
            self.endpoint.write(bytes)
        }
    }
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let (mask, input, output) = self.endpoint.readiness()?;
        Ok((
            mask & if self.reader { IN | 0x10 } else { OUT | 8 },
            input,
            output,
        ))
    }
    fn flags(&self) -> u32 {
        u32::from(!self.reader) | (self.endpoint.flags() & NONBLOCK)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.endpoint.set_flags(flags)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(FileStat {
            mode: 0o010600,
            links: 1,
            ..FileStat::default()
        })
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
}

pub(crate) fn dispatch(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let result = (|| match c.cpu.gpr[paludarium_cpu::reg::RAX] {
        41 => Err(Errno(97)),
        53 => {
            if a[0] != 1 {
                return Err(Errno(97));
            }
            if a[2] != 0 {
                return Err(Errno(93));
            }
            c.mem
                .check_write(GuestAddr(a[3]), 8)
                .map_err(|_| Errno::EFAULT)?;
            let kind = u32::try_from(a[1]).map_err(|_| Errno::EINVAL)?;
            let [first, second] = SocketPairEnd::pair(kind, Arc::clone(&c.files.readiness))?;
            let fd0 = c.files.install(first, kind & CLOEXEC != 0)?;
            let fd1 = c.files.install(second, kind & CLOEXEC != 0)?;
            let mut bytes = [0; 8];
            bytes[..4].copy_from_slice(&fd0.to_le_bytes());
            bytes[4..].copy_from_slice(&fd1.to_le_bytes());
            c.mem
                .write(GuestAddr(a[3]), &bytes)
                .map_err(|_| Errno::EFAULT)?;
            Ok(0)
        }
        48 => {
            let d = c.files.descriptor(a[0])?;
            let socket = d
                .file
                .as_any()
                .and_then(|v| v.downcast_ref::<SocketPairEnd>())
                .ok_or(Errno(88))?;
            socket.shutdown(a[1])?;
            Ok(0)
        }
        45 => {
            let d = c.files.descriptor(a[0])?;
            if !d.file.as_any().is_some_and(|v| v.is::<SocketPairEnd>()) {
                return Err(Errno(88));
            }
            if a[3] != 0 {
                return Err(Errno(95));
            }
            crate::files::run(c, 0, a)
        }
        44 => {
            let d = c.files.descriptor(a[0])?;
            if !d.file.as_any().is_some_and(|v| v.is::<SocketPairEnd>()) {
                return Err(Errno(88));
            }
            if a[3] & !0x4000 != 0 || a[4] != 0 || a[5] != 0 {
                return Err(Errno(95));
            }
            let len = usize::try_from(a[2].min(0x7fff_f000)).map_err(|_| Errno::EINVAL)?;
            c.mem
                .check_read(GuestAddr(a[1]), len)
                .map_err(|_| Errno::EFAULT)?;
            let mut bytes = Vec::new();
            bytes.try_reserve(len).map_err(|_| Errno::ENOMEM)?;
            bytes.resize(len, 0);
            c.mem
                .read(GuestAddr(a[1]), &mut bytes)
                .map_err(|_| Errno::EFAULT)?;
            crate::files::write_io(c, &d.file, &bytes, a[3] & 0x4000 != 0)
        }
        _ => Err(Errno::ENOSYS),
    })();
    Outcome::Return(result.unwrap_or_else(Errno::to_syscall_return))
}

#[derive(Default)]
struct Side {
    bytes: VecDeque<u8>,
    /// Remaining bytes per successful write, to retain poll callbacks when
    /// a peer consumes one write while later writes remain unread.
    writes: VecDeque<usize>,
    closed: bool,
    read_shutdown: bool,
    write_shutdown: bool,
    input_epoch: u64,
    output_epoch: u64,
}
struct Pair {
    sides: Mutex<[Side; 2]>,
    hub: Arc<ReadinessHub>,
    /// SOCK_SEQPACKET: each write is one message, and each read returns one
    /// whole message, truncated to the buffer, as on Linux.
    seqpacket: bool,
}
const SOCK_STREAM: u32 = 1;
const SOCK_SEQPACKET: u32 = 5;
/// Linux refuses a message longer than the send buffer less 32 bytes.
const MAX_MESSAGE: usize = SEND_WINDOW - 32;
pub(crate) struct SocketPairEnd {
    pair: Arc<Pair>,
    side: usize,
    flags: AtomicU32,
}
impl SocketPairEnd {
    pub fn pair(kind: u32, hub: Arc<ReadinessHub>) -> Result<[Arc<Self>; 2], Errno> {
        if kind & !(NONBLOCK | CLOEXEC | 0xf) != 0 {
            return Err(Errno::EINVAL);
        }
        let seqpacket = match kind & 0xf {
            SOCK_STREAM => false,
            SOCK_SEQPACKET => true,
            _ => return Err(Errno(94)), // ESOCKTNOSUPPORT
        };
        let pair = Arc::new(Pair {
            seqpacket,
            sides: Mutex::new(std::array::from_fn(|_| Side {
                output_epoch: 1,
                ..Side::default()
            })),
            hub,
        });
        Ok(std::array::from_fn(|side| {
            Arc::new(Self {
                pair: Arc::clone(&pair),
                side,
                flags: AtomicU32::new(2 | kind & NONBLOCK),
            })
        }))
    }
    pub fn shutdown(&self, how: u64) -> Result<(), Errno> {
        if how > 2 {
            return Err(Errno::EINVAL);
        }
        let mut sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if how == 0 || how == 2 {
            sides[self.side].read_shutdown = true;
            sides[self.side].input_epoch = sides[self.side].input_epoch.wrapping_add(1);
        }
        if how == 1 || how == 2 {
            sides[self.side].write_shutdown = true;
            sides[1 - self.side].input_epoch = sides[1 - self.side].input_epoch.wrapping_add(1);
        }
        self.pair.hub.changed();
        Ok(())
    }
}
impl SocketPairEnd {
    /// SOCK_SEQPACKET read: the next whole message, truncated to `buf`. An
    /// empty buffer reads nothing and leaves the message, as Linux's read
    /// does on a socket (recv with no buffer would discard it).
    fn read_message(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let eof = sides[self.side].read_shutdown
            || sides[1 - self.side].closed
            || sides[1 - self.side].write_shutdown;
        let own = &mut sides[self.side];
        if own.read_shutdown {
            return Ok(0);
        }
        let Some(length) = own.writes.pop_front() else {
            return if eof { Ok(0) } else { Err(Errno::EAGAIN) };
        };
        let count = buf.len().min(length);
        for (i, byte) in own.bytes.drain(..length).enumerate() {
            if i < count {
                buf[i] = byte;
            }
        }
        sides[1 - self.side].output_epoch = sides[1 - self.side].output_epoch.wrapping_add(1);
        self.pair.hub.changed();
        Ok(count)
    }
}
impl Drop for SocketPairEnd {
    fn drop(&mut self) {
        let mut sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        sides[self.side].closed = true;
        sides[1 - self.side].input_epoch = sides[1 - self.side].input_epoch.wrapping_add(1);
        self.pair.hub.changed();
    }
}
impl FileHandle for SocketPairEnd {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let own = &sides[self.side];
        let peer = &sides[1 - self.side];
        let eof = own.read_shutdown || peer.closed || peer.write_shutdown;
        // An empty message is readable too.
        let readable = !own.bytes.is_empty() || self.pair.seqpacket && !own.writes.is_empty();
        let mask = (u32::from(peer.bytes.len() < SEND_WINDOW || peer.closed) * OUT)
            | (u32::from(readable || eof) * IN)
            | if peer.closed {
                0x2010
            } else if peer.write_shutdown {
                0x2000
            } else {
                0
            };
        Ok((mask, own.input_epoch, own.output_epoch))
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if self.pair.seqpacket {
            return self.read_message(buf);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let mut sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let eof = sides[self.side].read_shutdown
            || sides[1 - self.side].closed
            || sides[1 - self.side].write_shutdown;
        let full = sides[self.side].bytes.len() == SEND_WINDOW;
        let own = &mut sides[self.side];
        if own.read_shutdown {
            return Ok(0);
        }
        if own.bytes.is_empty() {
            return if eof { Ok(0) } else { Err(Errno::EAGAIN) };
        }
        let count = buf.len().min(own.bytes.len());
        for byte in &mut buf[..count] {
            *byte = own.bytes.pop_front().ok_or(Errno::EIO)?;
        }
        let mut remaining = count;
        let mut consumed_write = false;
        while remaining != 0 {
            let front = own.writes.front_mut().ok_or(Errno::EIO)?;
            let consumed = remaining.min(*front);
            *front -= consumed;
            remaining -= consumed;
            if *front == 0 {
                own.writes.pop_front();
                consumed_write = true;
            }
        }
        if full || consumed_write {
            sides[1 - self.side].output_epoch = sides[1 - self.side].output_epoch.wrapping_add(1);
        }
        self.pair.hub.changed();
        Ok(count)
    }
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        let mut sides = self
            .pair
            .sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if sides[self.side].write_shutdown
            || sides[1 - self.side].closed
            || sides[1 - self.side].read_shutdown
        {
            return Err(Errno(32));
        }
        let peer = &mut sides[1 - self.side];
        if self.pair.seqpacket {
            // A message goes whole or not at all; one that can never fit is
            // EMSGSIZE, and an empty one is a message too.
            if buf.len() > MAX_MESSAGE {
                return Err(Errno(90));
            }
            if SEND_WINDOW - peer.bytes.len() < buf.len() {
                return Err(Errno::EAGAIN);
            }
            peer.bytes
                .try_reserve(buf.len())
                .map_err(|_| Errno::ENOMEM)?;
            peer.writes.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
            peer.input_epoch = peer.input_epoch.wrapping_add(1);
            peer.bytes.extend(buf.iter().copied());
            peer.writes.push_back(buf.len());
            self.pair.hub.changed();
            return Ok(buf.len());
        }
        let count = buf.len().min(SEND_WINDOW.saturating_sub(peer.bytes.len()));
        if count == 0 && !buf.is_empty() {
            return Err(Errno::EAGAIN);
        }
        peer.bytes.try_reserve(count).map_err(|_| Errno::ENOMEM)?;
        if count != 0 {
            peer.writes.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        }
        // Additional bytes wake a readable peer's poll callback as well.
        if count != 0 {
            peer.input_epoch = peer.input_epoch.wrapping_add(1);
        }
        peer.bytes.extend(buf[..count].iter().copied());
        if count != 0 {
            peer.writes.push_back(count);
        }
        self.pair.hub.changed();
        Ok(count)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(FileStat {
            mode: 0o140777,
            links: 1,
            ..FileStat::default()
        })
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.flags.store(2 | flags & NONBLOCK, Ordering::SeqCst);
        Ok(())
    }
}
#[cfg(test)]
mod events_tests {
    use super::*;
    fn pair() -> [Arc<SocketPairEnd>; 2] {
        SocketPairEnd::pair(1, Arc::default()).unwrap()
    }
    #[test]
    fn socket_backpressure_partial_write_and_out_edge() {
        let [a, b] = pair();
        let bytes = vec![7; SEND_WINDOW + 1];
        assert_eq!(a.write(&bytes), Ok(SEND_WINDOW));
        assert_eq!(a.write(&[1]), Err(Errno::EAGAIN));
        let full = a.readiness().unwrap();
        assert_eq!(full.0 & OUT, 0);
        assert_eq!(b.read(&mut [0; 1]), Ok(1));
        let ready = a.readiness().unwrap();
        assert_ne!(ready.0 & OUT, 0);
        assert_eq!(ready.2, full.2 + 1);
        assert_eq!(a.write(&[1]), Ok(1));
    }
    fn seqpacket() -> [Arc<SocketPairEnd>; 2] {
        SocketPairEnd::pair(SOCK_SEQPACKET, Arc::default()).unwrap()
    }
    #[test]
    fn seqpacket_keeps_message_boundaries_and_truncates() {
        let [a, b] = seqpacket();
        assert_eq!(a.write(b"first"), Ok(5));
        assert_eq!(a.write(b""), Ok(0));
        assert_eq!(a.write(b"second"), Ok(6));
        let mut bytes = [0; 3];
        // A short buffer gets the start of one message; the rest is gone.
        assert_eq!(b.read(&mut bytes), Ok(3));
        assert_eq!(&bytes, b"fir");
        // An empty read leaves the next message, an empty one, in place.
        assert_eq!(b.read(&mut []), Ok(0));
        assert_ne!(b.readiness().unwrap().0 & IN, 0);
        assert_eq!(b.read(&mut [0; 8]), Ok(0));
        let mut bytes = [0; 16];
        assert_eq!(b.read(&mut bytes), Ok(6));
        assert_eq!(&bytes[..6], b"second");
        assert_eq!(b.read(&mut bytes), Err(Errno::EAGAIN));
        assert_eq!(b.readiness().unwrap().0 & IN, 0);
        drop(a);
        assert_eq!(b.read(&mut bytes), Ok(0));
    }
    #[test]
    fn seqpacket_writes_whole_messages_or_none() {
        let [a, b] = seqpacket();
        assert_eq!(a.write(&vec![0; MAX_MESSAGE + 1]), Err(Errno(90)));
        assert_eq!(a.write(&vec![1; MAX_MESSAGE]), Ok(MAX_MESSAGE));
        assert_eq!(a.write(&[2; 33]), Err(Errno::EAGAIN));
        assert_eq!(a.write(&[2; 32]), Ok(32));
        assert_eq!(b.read(&mut [0; 1]), Ok(1));
        assert_eq!(a.write(&[3; 3]), Ok(3));
        let mut bytes = [0; 40];
        assert_eq!(b.read(&mut bytes), Ok(32));
        assert_eq!(b.read(&mut bytes), Ok(3));
        assert_eq!(&bytes[..3], &[3; 3]);
        assert!(SocketPairEnd::pair(2, Arc::default()).is_err_and(|e| e == Errno(94)));
    }
    #[test]
    fn events_socket_empty() {
        assert_eq!(pair()[0].read(&mut [0]), Err(Errno::EAGAIN));
    }
    #[test]
    fn events_socket_transfer() {
        let [a, b] = pair();
        a.write(b"hi").unwrap();
        let mut bytes = [0; 2];
        assert_eq!(b.read(&mut bytes), Ok(2));
        assert_eq!(&bytes, b"hi");
    }
    #[test]
    fn events_socket_bidirectional() {
        let [a, b] = pair();
        a.write(b"a").unwrap();
        b.write(b"b").unwrap();
        let mut byte = [0];
        a.read(&mut byte).unwrap();
        assert_eq!(byte, [b'b']);
        b.read(&mut byte).unwrap();
        assert_eq!(byte, [b'a']);
    }
    #[test]
    fn events_socket_partial() {
        let [a, b] = pair();
        a.write(b"abc").unwrap();
        assert_eq!(b.read(&mut [0; 2]), Ok(2));
        assert_eq!(b.read(&mut [0; 2]), Ok(1));
    }
    #[test]
    fn socket_peer_lifetime() {
        let [a, b] = pair();
        let copy = Arc::clone(&a);
        drop(a);
        assert_eq!(b.read(&mut [0]), Err(Errno::EAGAIN));
        drop(copy);
        assert_eq!(b.read(&mut [0]), Ok(0));
        assert_eq!(b.write(b"x"), Err(Errno(32)));
    }
    #[test]
    fn events_socket_shutdown() {
        let [a, b] = pair();
        a.shutdown(1).unwrap();
        assert_eq!(b.read(&mut [0]), Ok(0));
        assert_eq!(a.write(b"x"), Err(Errno(32)));
        assert_eq!(a.shutdown(3), Err(Errno::EINVAL));
    }
    #[test]
    fn socket_edges() {
        let [a, b] = pair();
        a.write(b"abc").unwrap();
        let e = b.readiness().unwrap().1;
        b.read(&mut [0]).unwrap();
        assert_eq!(b.readiness().unwrap().1, e);
        b.read(&mut [0; 2]).unwrap();
        a.write(b"d").unwrap();
        assert_eq!(b.readiness().unwrap().1, e + 1);
    }
    #[test]
    fn events_socket_flags() {
        let [a, _b] = SocketPairEnd::pair(1 | NONBLOCK | CLOEXEC, Arc::default()).unwrap();
        assert_eq!(a.flags(), 2 | NONBLOCK);
        a.set_flags(0).unwrap();
        assert_eq!(a.flags(), 2);
        assert!(SocketPairEnd::pair(1 | 0x4000, Arc::default()).is_err());
    }
}
