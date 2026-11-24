//! The name of a running program's file, as Linux's `d_path` of the
//! program's `exe_file` and of its segments' `vm_file` gives it when
//! `/proc/<pid>/exe`, `/proc/<pid>/maps` or a core's `NT_FILE` note asks:
//! the path with its symbolic links resolved, marked ` (deleted)` once
//! nothing links the file.

use paludarium_host::FileHandle;
use std::sync::Arc;

/// The path of a program's file, with an open of the file that tells
/// whether anything still links it.
#[derive(Clone, Default)]
pub(crate) struct ProgramName {
    path: Vec<u8>,
    file: Option<Arc<dyn FileHandle>>,
}

impl std::fmt::Debug for ProgramName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgramName")
            .field("path", &String::from_utf8_lossy(&self.path))
            .finish_non_exhaustive()
    }
}

impl ProgramName {
    /// A name that does not change: a memfd's link, or a removed file's
    /// path already marked.
    pub(crate) fn fixed(path: Vec<u8>) -> Self {
        Self { path, file: None }
    }
    /// The program at `path`, resolved, as exec opened it: opened again
    /// read-only on the host, with nothing told of the open, to see its
    /// links. A path that does not open keeps its name unmarked.
    pub(crate) fn of(files: &crate::files::Files, path: &[u8]) -> Self {
        let path = crate::files::resolved(files, path).unwrap_or_else(|| path.to_vec());
        let fs = files.fs();
        let file =
            crate::inotify::unnoticed(|| crate::page_cache::nonotify(0, || fs.open(&path, 0, 0)))
                .ok();
        Self { path, file }
    }
    /// The name as Linux's `d_path` gives it now.
    pub(crate) fn get(&self) -> Vec<u8> {
        let unlinked = self
            .file
            .as_ref()
            .and_then(|file| file.stat().ok())
            .is_some_and(|stat| stat.links == 0);
        if unlinked {
            [&self.path[..], b" (deleted)"].concat()
        } else {
            self.path.clone()
        }
    }
    /// What the program's segments keep while they last, naming them as
    /// this does, with `keep` besides ([`paludarium_loader::Named`]).
    pub(crate) fn keep(&self, keep: Option<paludarium_loader::Keep>) -> paludarium_loader::Keep {
        let name = self.clone();
        Arc::new(paludarium_loader::Named {
            name: Arc::new(move || Some(name.get())),
            keep,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[test]
    fn a_program_is_named_by_its_resolved_path_and_marked_once_removed() {
        let kernel = crate::Kernel::new(Arc::new(paludarium_host::testing::RecordingHost::new()));
        let files = &kernel.files;
        let fs = files.fs();
        // O_WRONLY | O_CREAT.
        fs.open(b"/prog", 0o101, 0o755)
            .unwrap()
            .write(b"\x7fELF")
            .unwrap();
        fs.symlink(b"prog", b"/link").unwrap();
        let direct = super::ProgramName::of(files, b"/prog");
        let through = super::ProgramName::of(files, b"/link");
        assert_eq!(direct.get(), b"/prog");
        assert_eq!(through.get(), b"/prog");
        // Its open sees the last link go, as `d_path` marks the dentry.
        fs.unlink(b"/prog", false).unwrap();
        assert_eq!(direct.get(), b"/prog (deleted)");
        assert_eq!(through.get(), b"/prog (deleted)");
        // A fixed name stays as it is.
        let fixed = super::ProgramName::fixed(b"/memfd:x (deleted)".to_vec());
        assert_eq!(fixed.get(), b"/memfd:x (deleted)");
    }
}
