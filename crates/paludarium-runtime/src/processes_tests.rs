#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_host::testing::RecordingHost;
use paludarium_loader::testing::tiny_exec;
const EXIT0: &[u8] = &[0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05];
const EXIT3: &[u8] = &[0xb8, 60, 0, 0, 0, 0xbf, 3, 0, 0, 0, 0x0f, 0x05];
const WAIT: &[u8] = &[
    0x48, 0x89, 0xc7, 0xb8, 61, 0, 0, 0, 0x31, 0xf6, 0x31, 0xd2, 0x45, 0x31, 0xd2, 0x0f, 0x05,
];
fn fork_code(n: u8, parent: &[u8], child: &[u8]) -> Vec<u8> {
    let mut code = vec![
        0xb8,
        n,
        0,
        0,
        0,
        0x0f,
        0x05,
        0x48,
        0x85,
        0xc0,
        0x74,
        u8::try_from(parent.len()).unwrap(),
    ];
    code.extend_from_slice(parent);
    code.extend_from_slice(child);
    code
}
fn run(code: &[u8], extra: Option<Vec<u8>>) -> (ExitStatus, Vec<u8>) {
    let host = Arc::new(RecordingHost::new());
    let mut config = Config::new("/p", vec![]).with_file("/p", tiny_exec(code, b"/child\0"));
    if let Some(extra) = extra {
        config = config.with_file("/child", extra);
    }
    let session = Session::new(config, host.clone()).unwrap().with_budget(100);
    let (tx, rx) = std::sync::mpsc::channel();
    let h = std::thread::spawn(move || tx.send(session.run()).unwrap());
    let status = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap()
        .unwrap();
    h.join().unwrap();
    (status, host.stdout())
}
fn waited() -> Vec<u8> {
    let mut parent = WAIT.to_vec();
    parent.extend_from_slice(EXIT0);
    parent
}
#[test]
fn fork_resume() {
    assert_eq!(
        run(&fork_code(57, &waited(), EXIT3), None).0,
        ExitStatus::Exited(0)
    );
}
#[test]
fn vfork_exit_releases() {
    assert_eq!(
        run(&fork_code(58, &waited(), EXIT3), None).0,
        ExitStatus::Exited(0)
    );
}
#[test]
fn vfork_exec_releases() {
    let mut exec = vec![
        0xb8, 59, 0, 0, 0, 0xbf, 0, 0x20, 0x40, 0, 0x31, 0xf6, 0x31, 0xd2, 0x0f, 0x05,
    ];
    exec.extend_from_slice(EXIT3);
    assert_eq!(
        run(
            &fork_code(58, &waited(), &exec),
            Some(tiny_exec(EXIT3, b""))
        )
        .0,
        ExitStatus::Exited(0)
    );
}
#[test]
fn multiple_children() {
    let second = fork_code(57, &waited(), EXIT3);
    let mut parent = WAIT.to_vec();
    parent.extend_from_slice(&second);
    assert_eq!(
        run(&fork_code(57, &parent, EXIT3), None).0,
        ExitStatus::Exited(0)
    );
}
#[test]
fn child_fault_does_not_kill_parent() {
    assert_eq!(
        run(&fork_code(57, &waited(), &[0x0f, 0x0b]), None).0,
        ExitStatus::Exited(0)
    );
}
#[test]
fn kill_wakes_waiting_parent_and_child() {
    let host = Arc::new(RecordingHost::new());
    let session = Arc::new(
        Session::new(
            Config::new("/p", vec![]).with_file(
                "/p",
                tiny_exec(&fork_code(57, &waited(), &[0xeb, 0xfe]), b""),
            ),
            host,
        )
        .unwrap()
        .with_budget(10),
    );
    let runner = session.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || tx.send(runner.run()).unwrap());
    std::thread::sleep(std::time::Duration::from_millis(20));
    session.kill();
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(),
        Ok(ExitStatus::Signaled(9))
    );
    handle.join().unwrap();
}
#[test]
fn session_waits_for_unreaped_child() {
    let mut child = vec![
        0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0xbe, 0, 0x20, 0x40, 0, 0xba, 1, 0, 0, 0, 0x0f, 0x05,
    ];
    child.extend_from_slice(EXIT3);
    let (status, stdout) = run(&fork_code(57, EXIT0, &child), None);
    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(stdout, b"/");
}
