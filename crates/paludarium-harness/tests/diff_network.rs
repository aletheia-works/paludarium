//! TCP client sockets against native Linux. The test serves the guest on
//! 127.0.0.1 itself (see `tests/guests/network/network.c`), and the
//! emulator connects through the native host's network, allowed only to
//! that port.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use paludarium::{Config, NetworkPolicy, Session, testing::RecordingHost};
    use paludarium_harness::{Outcome, compare, run_native, workspace_root};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Instant;

    /// Serves one connection as its first byte says.
    fn serve(mut peer: TcpStream) {
        let mut command = [0];
        if peer.read(&mut command).unwrap_or(0) == 0 {
            return;
        }
        match command[0] {
            b'e' => {
                let mut buf = [0; 65536];
                while let Ok(n) = peer.read(&mut buf) {
                    if n == 0 || peer.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
            b'b' => {
                let data: Vec<u8> = (0..1 << 20).map(|i: u32| (i * 7 + 3) as u8).collect();
                let _ = peer.write_all(&data);
            }
            b'w' => {
                let mut rest = Vec::new();
                let _ = peer.read_to_end(&mut rest);
                let _ = peer.write_all(b"bye");
            }
            _ => {}
        }
    }

    /// The server's port, and a port nothing listens on.
    fn ports() -> (u16, u16) {
        static PORTS: OnceLock<(u16, u16)> = OnceLock::new();
        *PORTS.get_or_init(|| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let open = listener.local_addr().unwrap().port();
            std::thread::spawn(move || {
                for peer in listener.incoming().flatten() {
                    std::thread::spawn(move || serve(peer));
                }
            });
            let closed = TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            (open, closed)
        })
    }

    fn guest() -> PathBuf {
        let dir = workspace_root().join("target/guests/network");
        static BUILT: OnceLock<()> = OnceLock::new();
        BUILT.get_or_init(|| {
            assert!(
                std::process::Command::new("bash")
                    .arg(workspace_root().join("tests/guests/network/build.sh"))
                    .arg(&dir)
                    .status()
                    .unwrap()
                    .success()
            );
        });
        dir.join("network")
    }

    fn emulated(mode: &str, policy: NetworkPolicy) -> Outcome {
        let (open, closed) = ports();
        let bytes = std::fs::read(guest()).unwrap();
        let args = ["network", mode, &open.to_string(), &closed.to_string()];
        let config = Config::new(
            "/network",
            args.iter().map(|a| a.as_bytes().to_vec()).collect(),
        )
        .with_file("/network", bytes)
        .with_network(policy);
        let host = Arc::new(RecordingHost::new());
        host.enable_network();
        let session = Session::new(config, host.clone()).unwrap();
        let start = Instant::now();
        let status = session.run().unwrap();
        Outcome {
            stdout: host.stdout(),
            stderr: host.stderr(),
            status,
            elapsed: start.elapsed(),
        }
    }

    fn case(mode: &str) {
        // One case at a time: each uses the same server.
        static ONE: Mutex<()> = Mutex::new(());
        let _one = ONE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (open, closed) = ports();
        let args = [mode.to_owned(), open.to_string(), closed.to_string()];
        let native = run_native(&guest(), "network", &args).unwrap();
        // The server's port, and the one nothing listens on, which the
        // refused cases need to try.
        let policy = NetworkPolicy::new()
            .allow(&format!("127.0.0.1:{open}"))
            .and_then(|policy| policy.allow(&format!("127.0.0.1:{closed}")))
            .unwrap();
        let emulated = emulated(mode, policy);
        println!(
            "{mode}: native {:?}\n{}\nemulated {:?}\n{}",
            native.status,
            String::from_utf8_lossy(&native.stdout),
            emulated.status,
            String::from_utf8_lossy(&emulated.stdout)
        );
        compare(&native, &emulated).unwrap();
    }

    #[test]
    fn network_unconnected() {
        case("unconnected");
    }
    #[test]
    fn network_stream() {
        case("stream");
    }
    #[test]
    fn network_nonblocking() {
        case("nonblocking");
    }
    #[test]
    fn network_refused() {
        case("refused");
    }
    #[test]
    fn network_bulk() {
        case("bulk");
    }
    #[test]
    fn network_half() {
        case("half");
    }
    #[test]
    fn network_mapped() {
        case("mapped");
    }

    /// Name resolution has no native counterpart here: the guest's resolver
    /// would read the runner's own files and servers. Under the emulator,
    /// with only `localhost` on the server's port allowed, the stub answers
    /// it from the host, refuses another name and the policy another port.
    #[test]
    fn network_resolve_under_the_emulator() {
        let (open, _) = ports();
        let policy = NetworkPolicy::new()
            .allow(&format!("localhost:{open}"))
            .unwrap();
        let outcome = emulated("resolve", policy);
        let stdout = String::from_utf8_lossy(&outcome.stdout);
        assert_eq!(
            stdout,
            "  localhost=0\n  addr=0x7f000001 port-ok=1\n  connect=0 errno=0\n  echo=2 \"ok\"\n  blocked=1\n  connect-other-port=-1 errno=101\n",
            "{outcome:?}"
        );
    }

    /// Without a policy the guest has no network, as before.
    #[test]
    fn network_off_without_a_policy() {
        let (open, closed) = ports();
        let bytes = std::fs::read(guest()).unwrap();
        let args = ["network", "stream", &open.to_string(), &closed.to_string()];
        let config = Config::new(
            "/network",
            args.iter().map(|a| a.as_bytes().to_vec()).collect(),
        )
        .with_file("/network", bytes);
        let host = Arc::new(RecordingHost::new());
        host.enable_network();
        let session = Session::new(config, host.clone()).unwrap();
        session.run().unwrap();
        assert_eq!(host.stdout(), b"socket failed errno=97\n");
    }
}
