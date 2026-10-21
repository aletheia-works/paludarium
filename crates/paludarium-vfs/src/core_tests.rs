mod tests {
    use crate::*;

    #[test]
    fn placed_file_is_readable_by_path() {
        let mut fs = MemFs::new();
        fs.add_file(GuestFile::new("/hello", b"\x7fELF".to_vec()))
            .unwrap();
        assert_eq!(&*fs.read_file(b"/hello").unwrap(), b"\x7fELF");
        assert_eq!(
            fs.stat(b"/hello").unwrap(),
            Stat {
                size: 4,
                mode: 0o755
            }
        );
    }

    #[test]
    fn missing_file_is_enoent() {
        let fs = MemFs::new();
        assert_eq!(fs.read_file(b"/nope").unwrap_err(), Errno::ENOENT);
        assert_eq!(fs.read_file(b"relative").unwrap_err(), Errno::ENOENT);
        assert_eq!(fs.read_file(b"").unwrap_err(), Errno::ENOENT);
        assert_eq!(fs.read_file(b"/").unwrap_err(), Errno::EISDIR);
    }

    #[test]
    fn dot_dot_cannot_escape_the_root() {
        assert_eq!(
            normalize_path(b"/../../etc/./passwd").unwrap(),
            b"/etc/passwd"
        );
        assert_eq!(normalize_path(b"//a/b/../c/").unwrap(), b"/a/c");
        assert_eq!(normalize_path(b"/..").unwrap(), b"/");
        let mut fs = MemFs::new();
        fs.add_file(GuestFile::new("/bin/../prog", b"x".to_vec()))
            .unwrap();
        assert!(fs.read_file(b"/../../prog").is_ok());
    }

    #[test]
    fn invalid_paths_are_rejected() {
        assert_eq!(normalize_path(b"/a\0b").unwrap_err(), Errno::EINVAL);
        assert_eq!(
            normalize_path(&[b'a'; PATH_MAX]).unwrap_err(),
            Errno::ENAMETOOLONG
        );
        let mut long = b"/".to_vec();
        long.extend(std::iter::repeat_n(b'x', NAME_MAX + 1));
        assert_eq!(normalize_path(&long).unwrap_err(), Errno::ENAMETOOLONG);
    }

    #[test]
    fn duplicate_or_root_placement_fails() {
        let mut fs = MemFs::new();
        fs.add_file(GuestFile::new("/p", b"1".to_vec())).unwrap();
        assert_eq!(
            fs.add_file(GuestFile::new("/./p", b"2".to_vec())),
            Err(Errno::EEXIST)
        );
        assert_eq!(
            fs.add_file(GuestFile::new("/", b"2".to_vec())),
            Err(Errno::EISDIR)
        );
        assert_eq!(&*fs.read_file(b"/p").unwrap(), b"1");
    }
}
