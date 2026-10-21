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
fn u10_existing_with_file_keeps_0755() {
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
fn u10_explicit_0644_keeps_contents_and_links() {
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
fn u10_mode_zero_keeps_regular_file_type() {
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
fn u10_permissions_preserve_type_and_normalized_path() {
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
fn u10_invalid_permission_bits_rejected_before_run() {
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
fn u10_invalid_or_missing_override_path_rejected() {
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
fn u10_duplicate_normalized_override_rejected() {
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
