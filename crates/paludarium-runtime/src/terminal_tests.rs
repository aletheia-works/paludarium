use super::*;
use paludarium_host::testing::RecordingHost;
use paludarium_host::{StreamId, TerminalInfo as HostTerminal};
use paludarium_loader::testing::tiny_exec;
const DATA: u32 = 0x402000;
fn mov(code: &mut Vec<u8>, opcode: u8, value: u32) {
    code.push(opcode);
    code.extend_from_slice(&value.to_le_bytes());
}
fn query(host: Arc<RecordingHost>, tty: Option<TerminalInfo>, request: u32) -> Vec<u8> {
    let mut code = Vec::new();
    mov(&mut code, 0xb8, 16);
    mov(&mut code, 0xbf, 0);
    mov(&mut code, 0xbe, request);
    mov(&mut code, 0xba, DATA);
    code.extend([0x0f, 0x05]);
    // Write the syscall return into DATA+64, then output return plus queried bytes.
    code.extend([0x48, 0xa3]);
    code.extend_from_slice(&(u64::from(DATA) + 64).to_le_bytes());
    mov(&mut code, 0xb8, 1);
    mov(&mut code, 0xbf, 1);
    mov(&mut code, 0xbe, DATA + 64);
    mov(&mut code, 0xba, 8);
    code.extend([0x0f, 0x05]);
    mov(&mut code, 0xb8, 1);
    mov(&mut code, 0xbf, 1);
    mov(&mut code, 0xbe, DATA);
    mov(&mut code, 0xba, if request == 0x5401 { 36 } else { 8 });
    code.extend([0x0f, 0x05]);
    mov(&mut code, 0xb8, 60);
    mov(&mut code, 0xbf, 0);
    code.extend([0x0f, 0x05]);
    let mut config =
        Config::new("/prog", vec![b"u9".to_vec()]).with_file("/prog", tiny_exec(&code, &[0; 128]));
    config.tty = tty;
    assert_eq!(
        Session::new(config, host.clone()).unwrap().run(),
        Ok(ExitStatus::Exited(0))
    );
    host.stdout()
}
fn terminal() -> HostTerminal {
    HostTerminal::new(Default::default(), 101, 37, 0, 0)
}
#[test]
fn u9_runtime_uses_host_size() {
    let host = Arc::new(RecordingHost::new());
    host.set_terminal_info(StreamId::Stdin, Some(terminal()));
    assert_eq!(
        query(host, None, 0x5413),
        [0, 0, 0, 0, 0, 0, 0, 0, 37, 0, 101, 0, 0, 0, 0, 0]
    );
}
#[test]
fn u9_runtime_explicit_size_precedes_host() {
    let host = Arc::new(RecordingHost::new());
    host.set_terminal_info(StreamId::Stdin, Some(terminal()));
    let out = query(
        host,
        Some(TerminalInfo {
            columns: 120,
            rows: 40,
        }),
        0x5413,
    );
    assert_eq!(&out[8..], [40, 0, 120, 0, 0, 0, 0, 0]);
}
#[test]
fn u9_runtime_virtual_terminal_without_native_tty() {
    let out = query(
        Arc::new(RecordingHost::new()),
        Some(TerminalInfo {
            columns: 80,
            rows: 24,
        }),
        0x5413,
    );
    assert_eq!(&out[8..], [24, 0, 80, 0, 0, 0, 0, 0]);
}
#[test]
fn u9_runtime_none_remains_nonterminal() {
    let out = query(Arc::new(RecordingHost::new()), None, 0x5413);
    assert_eq!(&out[..8], &(-25i64).to_le_bytes());
}
#[test]
fn u9_runtime_override_preserves_attributes() {
    let host = Arc::new(RecordingHost::new());
    let mut info = terminal();
    info.attributes.input_flags = 0x12345678;
    host.set_terminal_info(StreamId::Stdin, Some(info));
    let out = query(
        host,
        Some(TerminalInfo {
            columns: 80,
            rows: 24,
        }),
        0x5401,
    );
    assert_eq!(&out[8..12], &0x12345678u32.to_le_bytes());
}
#[test]
fn u9_runtime_stdout_stderr_are_distinct() {
    let host = Arc::new(RecordingHost::new());
    let mut code = Vec::new();
    for fd in [1, 2] {
        mov(&mut code, 0xb8, 1);
        mov(&mut code, 0xbf, fd);
        mov(&mut code, 0xbe, DATA);
        mov(&mut code, 0xba, 3);
        code.extend([0x0f, 0x05]);
    }
    mov(&mut code, 0xb8, 60);
    mov(&mut code, 0xbf, 0);
    code.extend([0x0f, 0x05]);
    let config =
        Config::new("/prog", vec![b"u9".to_vec()]).with_file("/prog", tiny_exec(&code, b"abc"));
    assert_eq!(
        Session::new(config, host.clone()).unwrap().run(),
        Ok(ExitStatus::Exited(0))
    );
    assert_eq!(host.stdout(), b"abc");
    assert_eq!(host.stderr(), b"abc");
}
#[test]
fn u9_runtime_empty_argument_reaches_stack() {
    let host = Arc::new(RecordingHost::new());
    // argv[1] starts with NUL; output that byte, preserving the empty argument.
    let mut code = vec![0x48, 0x8b, 0x74, 0x24, 0x10];
    mov(&mut code, 0xb8, 1);
    mov(&mut code, 0xbf, 1);
    mov(&mut code, 0xba, 1);
    code.extend([0x0f, 0x05]);
    mov(&mut code, 0xb8, 60);
    mov(&mut code, 0xbf, 0);
    code.extend([0x0f, 0x05]);
    let config = Config::new("/prog", vec![b"u9".to_vec(), vec![], b"two words".to_vec()])
        .with_file("/prog", tiny_exec(&code, b""));
    assert_eq!(
        Session::new(config, host.clone()).unwrap().run(),
        Ok(ExitStatus::Exited(0))
    );
    assert_eq!(host.stdout(), [0]);
}
#[test]
fn u9_runtime_environment_reaches_stack() {
    let host = Arc::new(RecordingHost::new());
    // argc=1: envp[0] is the pointer at rsp+24 after argv[0] and its NULL.
    let mut code = vec![0x48, 0x8b, 0x74, 0x24, 0x18];
    mov(&mut code, 0xb8, 1);
    mov(&mut code, 0xbf, 1);
    mov(&mut code, 0xba, 7);
    code.extend([0x0f, 0x05]);
    mov(&mut code, 0xb8, 60);
    mov(&mut code, 0xbf, 0);
    code.extend([0x0f, 0x05]);
    let config = Config::new("/prog", vec![b"u9".to_vec()])
        .with_env("U9", "test")
        .with_file("/prog", tiny_exec(&code, b""));
    assert_eq!(
        Session::new(config, host.clone()).unwrap().run(),
        Ok(ExitStatus::Exited(0))
    );
    assert_eq!(host.stdout(), b"U9=test");
}
