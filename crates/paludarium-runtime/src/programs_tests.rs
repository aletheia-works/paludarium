//! Initial mode boundaries observed by the native Linux metadata oracle.
use super::*;
use paludarium_host::testing::RecordingHost;

fn configured(config: Config) -> Session {
    Session::new(config, Arc::new(RecordingHost::new())).unwrap()
}

fn config() -> Config {
    Config::new("/program", vec![])
}

#[test]
fn existing_with_file_keeps_0755() {
    let session = configured(config().with_file("/data", b"contents".to_vec()));
    assert_eq!(
        session
            .file_system()
            .unwrap()
            .metadata(b"/data", true)
            .unwrap()
            .mode,
        0o100755
    );
    assert!(session.config.file_modes.is_empty());
}

#[test]
fn explicit_0644_keeps_contents_and_links() {
    let session = configured(config().with_file_mode("/data", b"contents".to_vec(), 0o644));
    let fs = session.file_system().unwrap();
    let metadata = fs.metadata(b"/data", true).unwrap();
    assert_eq!(
        (metadata.mode, metadata.size, metadata.links),
        (0o100644, 8, 1)
    );
    let file = fs.open(b"/data", 0, 0).unwrap();
    let mut bytes = [0; 8];
    assert_eq!(file.read(&mut bytes), Ok(8));
    assert_eq!(&bytes, b"contents");
}

#[test]
fn mode_zero_keeps_regular_file_type() {
    let session = configured(config().with_file_mode("/data", Vec::new(), 0));
    assert_eq!(
        session
            .file_system()
            .unwrap()
            .metadata(b"/data", true)
            .unwrap()
            .mode,
        0o100000
    );
}

#[test]
fn permissions_preserve_type_and_normalized_path() {
    let session = configured(config().with_file_mode("/directory/../data", Vec::new(), 0o6755));
    assert_eq!(
        session
            .file_system()
            .unwrap()
            .metadata(b"/data", true)
            .unwrap()
            .mode,
        0o106755
    );
}

#[test]
fn invalid_permission_bits_rejected_before_run() {
    for mode in [0o100644, 0o10000, u32::MAX] {
        let error = Session::new(
            config().with_file_mode("/data", Vec::new(), mode),
            Arc::new(RecordingHost::new()),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind, ErrorKind::InvalidProgram);
    }
}

#[test]
fn invalid_or_missing_override_path_rejected() {
    for path in [
        b"".to_vec(),
        b"relative".to_vec(),
        b"/".to_vec(),
        b"/bad\0path".to_vec(),
        vec![b'/'; 4096],
    ] {
        let error = Session::new(
            config().with_file_mode(path, Vec::new(), 0o644),
            Arc::new(RecordingHost::new()),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind, ErrorKind::InvalidProgram);
    }
    let mut unmatched = config().with_file("/data", Vec::new());
    unmatched.file_modes.push((b"/missing".to_vec(), 0o644));
    assert_eq!(
        Session::new(unmatched, Arc::new(RecordingHost::new()))
            .err()
            .unwrap()
            .kind,
        ErrorKind::InvalidProgram
    );
}

#[test]
fn duplicate_normalized_override_rejected() {
    let mut duplicate = config().with_file_mode("/data", Vec::new(), 0o644);
    duplicate
        .file_modes
        .push((b"/directory/../data".to_vec(), 0o755));
    assert_eq!(
        Session::new(duplicate, Arc::new(RecordingHost::new()))
            .err()
            .unwrap()
            .kind,
        ErrorKind::InvalidProgram
    );
}

/// Writes `length` bytes from `argv[1]` on, then where `/proc/self/exe` leads.
fn interpreter(length: u8) -> Vec<u8> {
    #[rustfmt::skip]
    let code = [
        0x48, 0x8b, 0x74, 0x24, 0x10, // mov rsi, [rsp + 16]
        0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0xba, length, 0, 0, 0, 0x0f, 0x05, // write
        0xb8, 89, 0, 0, 0, 0xbf, 0x00, 0x20, 0x40, 0x00, // readlink(data,
        0xbe, 0x20, 0x20, 0x40, 0x00, 0xba, 64, 0, 0, 0, 0x0f, 0x05, // data + 32, 64)
        0x89, 0xc2, 0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x0f, 0x05, // write
        0xb8, 231, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05, // exit_group(0)
    ];
    let mut data = b"/proc/self/exe".to_vec();
    data.resize(32 + 64, 0);
    paludarium_loader::testing::tiny_exec(&code, &data)
}

fn run_script(config: Config) -> Result<Vec<u8>, Error> {
    let host = Arc::new(RecordingHost::new());
    let session = Session::new(config, host.clone())?;
    assert_eq!(session.run()?, ExitStatus::Exited(0));
    Ok(host.stdout())
}

#[test]
fn first_program_script_runs_its_interpreter() {
    let config = Config::new("/script", vec![b"script".to_vec(), b"extra".to_vec()])
        .with_file("/bin/interp", interpreter(16))
        .with_file("/script", b"#!/bin/interp -x\nignored\n".to_vec());
    assert_eq!(
        run_script(config).unwrap(),
        b"-x\0/script\0extra/bin/interp"
    );
}

#[test]
fn first_program_script_of_a_script() {
    // The inner script's path takes the place of the outer one's name.
    let config = Config::new("/outer", vec![b"outer".to_vec()])
        .with_file("/bin/interp", interpreter(21))
        .with_file("/bin/inner", b"#!/bin/interp\n".to_vec())
        .with_file("/outer", b"#! /bin/inner  a b \n".to_vec());
    assert_eq!(
        run_script(config).unwrap(),
        b"/bin/inner\0a b\0/outer/bin/interp"
    );
}

#[test]
fn first_program_script_errors() {
    let error = |script: &[u8]| {
        let config = Config::new("/script", vec![b"script".to_vec()])
            .with_file("/bin/interp", interpreter(0))
            .with_file("/script", script.to_vec());
        run_script(config).unwrap_err().message
    };
    assert_eq!(
        error(b"#!/missing\n"),
        "the script's interpreter was not found"
    );
    assert_eq!(error(b"#!\n"), "invalid #! line");
    assert_eq!(
        error(b"#!/tmp\n"),
        "the script's interpreter may not be run"
    );
    assert_eq!(
        error(b"#!/script\n"),
        "too many levels of script interpreters"
    );
    assert_eq!(error(b"not a script\n"), "not an ELF file");
}
