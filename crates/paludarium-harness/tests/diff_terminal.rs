//! Native x86-64 oracle first; emulator comparison follows captured expectations.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use paludarium_harness::workspace_root;
use std::process::Command;
#[path = "support/terminal.rs"]
mod support;
use paludarium::{Config, Session};
use paludarium_host::{StreamId, TerminalAttributes, TerminalInfo, testing::RecordingHost};
use std::sync::Arc;
fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
fn case(name: &'static str, id: usize) {
    static BUILT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    let root = workspace_root();
    let out = root.join("target/guests/terminal");
    if std::env::var_os("PALUDARIUM_TERMINAL_CHILD").is_none() {
        BUILT.get_or_init(|| {
            assert!(
                Command::new("bash")
                    .arg(root.join("tests/guests/terminal/build.sh"))
                    .arg(&out)
                    .status()
                    .unwrap()
                    .success()
            );
        });
    }
    support::bounded(name, || {
        let native = Command::new("python3")
            .arg(root.join("tests/guests/terminal/oracle.py"))
            .arg(&out)
            .arg(id.to_string())
            .output()
            .unwrap();
        assert!(native.status.success(), "{:?}", native);
        let text = String::from_utf8(native.stdout).unwrap();
        let row: Vec<_> = text.trim().split('|').collect();
        assert_eq!(row.len(), 4);
        assert_eq!(row[0], id.to_string());
        let native_code: i32 = row[1].parse().unwrap();
        let host = Arc::new(RecordingHost::with_stdin(if id == 1 {
            b"abc"
        } else {
            b""
        }));
        if matches!(id, 6 | 7 | 8 | 9 | 10 | 13) {
            // The PTY setup in oracle.py defines these inputs; expected output
            // is still obtained anew from its native guest on every run.
            let mut control_chars = [0; 19];
            control_chars[6] = 1;
            host.set_terminal_info(
                StreamId::Stdin,
                Some(TerminalInfo::new(
                    TerminalAttributes::new(0, 0, 0xbf, 0, 0, control_chars),
                    101,
                    37,
                    0,
                    0,
                )),
            );
        }
        let binary = std::fs::read(out.join(format!("io-{id}"))).unwrap();
        let args = vec![
            b"u9".to_vec(),
            if id == 11 {
                b"/regular".to_vec()
            } else {
                Vec::new()
            },
            b"two words".to_vec(),
        ];
        let config = Config::new("/prog", args)
            .with_env("TERMINAL_TEST", "value with spaces")
            .with_file("/prog", binary)
            .with_file("/regular", b"fixture".to_vec());
        let session = Session::new(config, host.clone()).unwrap();
        let status = session.run().unwrap();
        println!(
            "u9 {id}: native={text:?}, emulated={status:?}/{:02x?}/{:02x?}, stop={:?}",
            host.stdout(),
            host.stderr(),
            session.termination_detail()
        );
        assert_eq!(status, paludarium_types::ExitStatus::Exited(native_code));
        assert_eq!(host.stdout(), decode_hex(row[2]));
        assert_eq!(host.stderr(), decode_hex(row[3]));
    });
}

macro_rules! cases {($($name:ident=>$id:literal),* $(,)?)=>{$(#[test] fn $name(){case(stringify!($name),$id);})*};}
cases!(args_env=>0,stdin_short_eof=>1,terminal_streams=>2,pipe_tcgets=>3,pipe_winsize=>4,bad_fd=>5,tty_tcgets=>6,tty_winsize=>7,tty_bad_pointer=>8,tty_unknown=>9,tty_dup=>10,regular_file=>11,closed_fd=>12,stream_identity=>13);
