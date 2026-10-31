//! The native network driver: each stream connects, receives and sends on
//! threads of its own with `std::net`, and each lookup resolves on one.
use crate::net::{Driver, Lookup, Sending, Stream, errno_from_net};
use core::net::{IpAddr, SocketAddr};
use paludarium_types::Errno;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};

/// Holds the connected socket for `TCP_NODELAY`.
#[derive(Default)]
struct Native {
    socket: OnceLock<TcpStream>,
    nodelay: std::sync::atomic::AtomicBool,
}
impl Driver for Native {
    /// The threads wait on the stream's own signal, which the kernel's
    /// changes already notify.
    fn kick(&self) {}
    fn set_nodelay(&self, on: bool) {
        self.nodelay.store(on, std::sync::atomic::Ordering::SeqCst);
        if let Some(socket) = self.socket.get() {
            let _ = socket.set_nodelay(on);
        }
    }
}

fn spawn(name: &str, task: impl FnOnce() + Send + 'static) -> Result<(), Errno> {
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(task)
        .map(drop)
        .map_err(|_| Errno::EAGAIN)
}

/// Starts connecting to `address`.
pub(crate) fn connect(address: SocketAddr) -> Result<Arc<Stream>, Errno> {
    let stream = Stream::new(address);
    let native = Arc::new(Native::default());
    stream.set_driver(Arc::clone(&native) as Arc<dyn Driver>);
    let driven = Arc::clone(&stream);
    spawn("paludarium-connect", move || {
        let socket = match TcpStream::connect(address) {
            Ok(socket) => socket,
            Err(e) => return driven.fail(errno_from_net(&e)),
        };
        let _ = socket.set_nodelay(native.nodelay.load(std::sync::atomic::Ordering::SeqCst));
        let reader = match socket.try_clone() {
            Ok(reader) => reader,
            Err(e) => return driven.fail(errno_from_net(&e)),
        };
        if let Ok(held) = socket.try_clone() {
            let _ = native.socket.set(held);
        }
        driven.connected(socket.local_addr().ok());
        let receiving = Arc::clone(&driven);
        if spawn("paludarium-receive", move || receive(&receiving, reader)).is_err() {
            return driven.fail(Errno::EAGAIN);
        }
        send(&driven, socket);
    })?;
    Ok(stream)
}

/// Reads while the stream has room, until the end, an error or the close.
fn receive(stream: &Stream, mut socket: TcpStream) {
    let mut buf = vec![0; 64 * 1024];
    while let Some(room) = stream.wait_for_room() {
        match socket.read(&mut buf[..room.min(64 * 1024)]) {
            Ok(0) => return stream.end(),
            Ok(n) => {
                stream.receive(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                if stream.finished().1 {
                    return;
                }
                return stream.fail(errno_from_net(&e));
            }
        }
    }
}

/// Writes what the guest queues; shuts the sending down when the guest
/// does, and closes the connection after the guest closes the stream.
fn send(stream: &Stream, mut socket: TcpStream) {
    let mut shut = false;
    loop {
        match stream.wait_to_send(shut) {
            Sending::Bytes(bytes) => {
                if let Err(e) = socket.write_all(&bytes) {
                    stream.fail(errno_from_net(&e));
                    let _ = socket.shutdown(Shutdown::Both);
                    return;
                }
            }
            Sending::Shut => {
                shut = true;
                let _ = socket.shutdown(Shutdown::Write);
            }
            Sending::Closed => {
                // Waking the receiver, which reads no more.
                let _ = socket.shutdown(Shutdown::Both);
                return;
            }
        }
    }
}

/// The host's address a datagram to `address` leaves from: a UDP socket
/// connected there takes it from the host's routes, sending nothing.
pub(crate) fn route_source(address: SocketAddr) -> Result<IpAddr, Errno> {
    let any: SocketAddr = if address.is_ipv4() {
        (core::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (core::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    // The port plays no part in the route, and some hosts refuse port 0.
    let to = SocketAddr::new(address.ip(), address.port().max(1));
    let socket = std::net::UdpSocket::bind(any).map_err(|e| errno_from_net(&e))?;
    socket.connect(to).map_err(|e| errno_from_net(&e))?;
    Ok(socket.local_addr().map_err(|e| errno_from_net(&e))?.ip())
}

/// Starts resolving `name` with the host's resolver.
pub(crate) fn resolve(name: &str) -> Result<Arc<Lookup>, Errno> {
    let lookup = Lookup::new();
    let answered = Arc::clone(&lookup);
    let name = name.to_owned();
    spawn("paludarium-resolve", move || {
        answered.finish(match (name.as_str(), 0).to_socket_addrs() {
            Ok(found) => {
                let mut addresses: Vec<IpAddr> = Vec::new();
                for address in found {
                    if !addresses.contains(&address.ip()) {
                        addresses.push(address.ip());
                    }
                }
                Ok(addresses)
            }
            Err(e) => Err(errno_from_net(&e)),
        });
    })?;
    Ok(lookup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Phase;
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    fn until(what: impl Fn() -> bool) {
        let start = Instant::now();
        while !what() {
            assert!(start.elapsed() < Duration::from_secs(10), "timed out");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn a_stream_talks_to_a_local_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            let mut buf = [0; 5];
            peer.read_exact(&mut buf).unwrap();
            peer.write_all(&buf).unwrap();
            let mut rest = Vec::new();
            peer.read_to_end(&mut rest).unwrap();
            rest
        });
        let stream = connect(address).unwrap();
        stream.set_nodelay(true);
        until(|| stream.phase() == Phase::Open);
        assert_eq!(stream.local().map(|a| a.ip()), Some(address.ip()));
        assert_eq!(stream.write(b"hello"), Ok(5));
        until(|| stream.queued().0 == 5);
        let mut buf = [0; 5];
        assert_eq!(stream.read(&mut buf, false), Ok(5));
        assert_eq!(&buf, b"hello");
        stream.write(b"bye").unwrap();
        stream.shutdown_write();
        assert_eq!(server.join().unwrap(), b"bye");
        until(|| stream.readiness().read_closed);
        assert_eq!(stream.read(&mut buf, false), Ok(0));
        stream.close();
    }

    #[test]
    fn a_refused_connection_fails() {
        let address = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let stream = connect(address).unwrap();
        until(|| stream.phase() != Phase::Connecting);
        assert_eq!(stream.phase(), Phase::Failed(Errno(111)));
    }

    #[test]
    fn localhost_resolves() {
        let lookup = resolve("localhost").unwrap();
        until(|| lookup.result().is_some());
        let found = lookup.result().unwrap().unwrap();
        assert!(found.iter().all(IpAddr::is_loopback), "{found:?}");
    }
}
