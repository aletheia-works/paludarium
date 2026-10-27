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
fn a_waited_child_writes_before_the_run_ends() {
    let mut child = vec![
        0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0xbe, 0, 0x20, 0x40, 0, 0xba, 1, 0, 0, 0, 0x0f, 0x05,
    ];
    child.extend_from_slice(EXIT3);
    let (status, stdout) = run(&fork_code(57, &waited(), &child), None);
    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(stdout, b"/");
}
#[test]
fn the_first_process_exit_ends_a_running_child() {
    // The child spins forever; the first process's exit kills it, as the
    // exit of a PID namespace's init does, and the run ends.
    assert_eq!(
        run(&fork_code(57, EXIT0, &[0xeb, 0xfe]), None).0,
        ExitStatus::Exited(0)
    );
}
#[test]
fn task_limit_fails_fork_with_eagain() {
    // fork, then exit with the negated result: 11 for EAGAIN.
    let code = [
        0xb8, 57, 0, 0, 0, 0x0f, 0x05, 0xf7, 0xd8, 0x89, 0xc7, 0xb8, 60, 0, 0, 0, 0x0f, 0x05,
    ];
    let host = Arc::new(RecordingHost::new());
    let mut config = Config::new("/p", vec![]).with_file("/p", tiny_exec(&code, b""));
    config.limits = Limits::default().with_tasks(1);
    let session = Session::new(config, host).unwrap().with_budget(100);
    assert_eq!(session.run().unwrap(), ExitStatus::Exited(11));
}
#[test]
fn ended_threads_give_their_tasks_back() {
    // Under two tasks, create a thread twice: each clone that fails with
    // EAGAIN yields and retries (up to a million times) until the previous
    // thread, which only exits, has given its task back. The process exits
    // 0 once both threads were created and 1 if a retry runs out.
    let code = [
        0x41, 0xbc, 0x02, 0x00, 0x00, 0x00, 0x41, 0xbd, 0x40, 0x42, 0x0f, 0x00, 0xbf, 0x00, 0x09,
        0x01, 0x00, 0x31, 0xf6, 0x31, 0xd2, 0x45, 0x31, 0xd2, 0x45, 0x31, 0xc0, 0xb8, 0x38, 0x00,
        0x00, 0x00, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x74, 0x23, 0x79, 0x13, 0xb8, 0x18, 0x00, 0x00,
        0x00, 0x0f, 0x05, 0x41, 0xff, 0xcd, 0x75, 0xd7, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xeb, 0x07,
        0x41, 0xff, 0xcc, 0x75, 0xc5, 0x31, 0xff, 0xb8, 0xe7, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8,
        0x3c, 0x00, 0x00, 0x00, 0x31, 0xff, 0x0f, 0x05,
    ];
    let host = Arc::new(RecordingHost::new());
    let mut config = Config::new("/p", vec![]).with_file("/p", tiny_exec(&code, b""));
    config.limits = Limits::default().with_tasks(2);
    let session = Session::new(config, host).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let h = std::thread::spawn(move || tx.send(session.run()).unwrap());
    let status = rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .unwrap()
        .unwrap();
    h.join().unwrap();
    assert_eq!(status, ExitStatus::Exited(0));
}
#[test]
fn limits_out_of_range_are_rejected() {
    for limits in [
        Limits::default().with_tasks(0),
        Limits::default().with_open_files((1 << 20) + 1),
    ] {
        let mut config = Config::new("/p", vec![]);
        config.limits = limits;
        let error = Session::new(config, Arc::new(RecordingHost::new()))
            .err()
            .unwrap();
        assert_eq!(error.kind, paludarium_types::ErrorKind::InvalidProgram);
    }
}
/// Maps 1 MiB, writes a byte to each of its first `pages` pages, then runs
/// `tail` with `rax` at the next page.
fn touching(pages: u32, tail: &[u8]) -> Vec<u8> {
    let mut code = vec![
        0x31, 0xff, 0xbe, 0x00, 0x00, 0x10, 0x00, 0xba, 0x03, 0x00, 0x00, 0x00, 0x41, 0xba, 0x22,
        0x00, 0x00, 0x00, 0x49, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x45, 0x31, 0xc9, 0xb8, 0x09,
        0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0xc3, 0xb9,
    ];
    code.extend_from_slice(&pages.to_le_bytes());
    code.extend_from_slice(&[
        0x85, 0xc9, 0x74, 0x0d, 0xc6, 0x00, 0x01, 0x48, 0x05, 0x00, 0x10, 0x00, 0x00, 0xff, 0xc9,
        0xeb, 0xef,
    ]);
    code.extend_from_slice(tail);
    code
}
/// Exits with the negated result of the system call before it.
const EXIT_NEGATED: &[u8] = &[0xf7, 0xd8, 0x89, 0xc7, 0xb8, 60, 0, 0, 0, 0x0f, 0x05];
fn run_with_memory(code: &[u8], memory: Option<u64>) -> Result<ExitStatus, Error> {
    let mut config = Config::new("/p", vec![])
        .with_file("/p", tiny_exec(code, b""))
        .with_file("/child", tiny_exec(EXIT0, b""));
    if let Some(max) = memory {
        config.limits = Limits::default().with_memory(max);
    }
    Session::new(config, Arc::new(RecordingHost::new()))?
        .with_budget(100)
        .run()
}
/// The pages loading `/p` takes: below them the program does not start.
fn loaded_pages(code: &[u8]) -> u64 {
    (0..64)
        .find(|&pages| run_with_memory(code, Some(pages * 4096)).is_ok())
        .unwrap()
}
#[test]
fn a_program_that_does_not_fit_the_memory_limit_does_not_start() {
    let error = run_with_memory(EXIT0, Some(0)).unwrap_err();
    assert_eq!(error.kind, paludarium_types::ErrorKind::InvalidProgram);
}
#[test]
fn writes_beyond_the_memory_limit_end_the_process_with_sigkill() {
    let exit = [0x31, 0xff, 0xb8, 60, 0, 0, 0, 0x0f, 0x05];
    let code = touching(64, &exit);
    let loaded = loaded_pages(&code);
    // Exactly the pages it writes fit; one fewer does not.
    assert_eq!(
        run_with_memory(&code, Some((loaded + 64) * 4096)).unwrap(),
        ExitStatus::Exited(0)
    );
    assert_eq!(
        run_with_memory(&code, Some((loaded + 63) * 4096)).unwrap(),
        ExitStatus::Signaled(signal::SIGKILL)
    );
    // A system call writing to a page that does not fit ends it the same
    // way, where it would otherwise see EFAULT: getrandom into the next page.
    let mut getrandom = vec![
        0x48, 0x89, 0xc7, 0xbe, 0x00, 0x10, 0x00, 0x00, 0x31, 0xd2, 0xb8, 0x3e, 0x01, 0x00, 0x00,
        0x0f, 0x05,
    ];
    getrandom.extend_from_slice(EXIT_NEGATED);
    let code = touching(0, &getrandom);
    let loaded = loaded_pages(&code);
    assert_eq!(
        run_with_memory(&code, Some(loaded * 4096)).unwrap(),
        ExitStatus::Signaled(signal::SIGKILL)
    );
    assert_eq!(run_with_memory(&code, None).unwrap(), ExitStatus::Exited(0));
}
#[test]
fn a_fork_shares_its_pages_and_an_execve_that_does_not_fit_fails_with_enomem() {
    // fork shares the 16 written pages and the loaded ones, so it succeeds
    // although copies would not fit in the 8 pages left, as on Linux: the
    // parent exits with its child's PID (2) negated.
    let mut fork = vec![0xb8, 57, 0, 0, 0, 0x0f, 0x05];
    fork.extend_from_slice(EXIT_NEGATED);
    let code = touching(16, &fork);
    let loaded = loaded_pages(&code);
    assert_eq!(
        run_with_memory(&code, Some((loaded + 24) * 4096)).unwrap(),
        ExitStatus::Exited(254)
    );
    // With the limit full, execve has no room for the new image.
    let mut exec = vec![
        0x48, 0x8d, 0x3d, 0x16, 0x00, 0x00, 0x00, 0x31, 0xf6, 0x31, 0xd2, 0xb8, 0x3b, 0x00, 0x00,
        0x00, 0x0f, 0x05,
    ];
    exec.extend_from_slice(EXIT_NEGATED);
    exec.extend_from_slice(b"/child\0");
    let code = touching(16, &exec);
    let loaded = loaded_pages(&code);
    assert_eq!(
        run_with_memory(&code, Some((loaded + 16) * 4096)).unwrap(),
        ExitStatus::Exited(12)
    );
    assert_eq!(run_with_memory(&code, None).unwrap(), ExitStatus::Exited(0));
}
