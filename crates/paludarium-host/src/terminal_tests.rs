use super::*;
use testing::RecordingHost;
#[test]
fn u9_default_is_nonterminal() {
    let host = RecordingHost::new();
    for stream in [StreamId::Stdin, StreamId::Stdout, StreamId::Stderr] {
        assert_eq!(host.terminal_info(stream), Ok(None));
    }
}
#[test]
fn u9_terminal_streams_are_independent() {
    let host = RecordingHost::new();
    let tty = TerminalInfo {
        columns: 101,
        rows: 37,
        ..TerminalInfo::default()
    };
    host.set_terminal_info(StreamId::Stdin, Some(tty));
    assert_eq!(host.terminal_info(StreamId::Stdin), Ok(Some(tty)));
    assert_eq!(host.terminal_info(StreamId::Stdout), Ok(None));
    assert_eq!(host.terminal_info(StreamId::Stderr), Ok(None));
}
#[test]
fn u9_terminal_can_be_removed() {
    let host = RecordingHost::new();
    host.set_terminal_info(StreamId::Stderr, Some(TerminalInfo::default()));
    host.set_terminal_info(StreamId::Stderr, None);
    assert_eq!(host.terminal_info(StreamId::Stderr), Ok(None));
}
#[test]
fn u9_zero_dimensions_remain_terminal() {
    let host = RecordingHost::new();
    host.set_terminal_info(StreamId::Stdout, Some(TerminalInfo::default()));
    let info = host.terminal_info(StreamId::Stdout).unwrap().unwrap();
    assert_eq!((info.columns, info.rows), (0, 0));
}
#[test]
fn u9_attributes_preserve_control_characters() {
    let host = RecordingHost::new();
    let mut info = TerminalInfo::default();
    info.attributes.control_chars[18] = 91;
    info.attributes.line = 7;
    host.set_terminal_info(StreamId::Stdin, Some(info));
    assert_eq!(host.terminal_info(StreamId::Stdin), Ok(Some(info)));
}
#[test]
fn u9_short_stdin_and_eof() {
    let host = RecordingHost::with_stdin(b"abc");
    let mut b = [0; 8];
    assert_eq!(host.read_stdin(&mut b), Ok(3));
    assert_eq!(&b[..3], b"abc");
    assert_eq!(host.read_stdin(&mut b), Ok(0));
    assert_eq!(host.read_stdin(&mut []), Ok(0));
}
#[test]
fn u9_stdout_stderr_remain_separate() {
    let host = RecordingHost::new();
    assert_eq!(host.write_stdout(b"out"), Ok(3));
    assert_eq!(host.write_stderr(b"err"), Ok(3));
    assert_eq!(host.stdout(), b"out");
    assert_eq!(host.stderr(), b"err");
}
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn u9_native_managed_pty() {
    if std::env::var_os("PALUDARIUM_U9_HOST_CHILD").is_some() {
        let info = NativeHost.terminal_info(StreamId::Stdin).unwrap().unwrap();
        assert_eq!((info.rows, info.columns), (37, 101));
        assert_eq!(info.attributes.control_flags, 0xbf);
        assert_eq!(info.attributes.input_flags, 0);
        assert_eq!(info.attributes.local_flags, 0);
        assert_eq!(info.attributes.control_chars[6], 1);
        assert_eq!(NativeHost.terminal_info(StreamId::Stdout), Ok(None));
        return;
    }
    let helper =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/guests/u9/host-pty.py");
    assert!(
        std::process::Command::new("python3")
            .arg(helper)
            .arg(std::env::current_exe().unwrap())
            .status()
            .unwrap()
            .success()
    );
}
