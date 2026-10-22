//! Session and execution loop for paludarium.
//!
//! A [`Session`] places the configured files in the virtual file system,
//! loads the program, and runs the thread loop (W2, W3): the CPU runs for a
//! budget of instructions, the kernel handles each stop, and between budget
//! slices the loop checks whether [`Session::kill`] was requested.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

mod workers;
use paludarium_host::Host;
use paludarium_jit::{CodeCache, NoopCodeCache};
use paludarium_kernel::{Kernel, SignalInbox};
use paludarium_loader::{StartInfo, load};
use paludarium_mmu::AddressSpace;
#[cfg(test)]
use paludarium_types::signal;
use paludarium_types::{Error, ErrorKind, ExitReason, ExitStatus};
use paludarium_vfs::{GuestFile, HostFs, MemFs, MountedFs};
use workers::Execution;

/// Instructions run between two checks of the kill request
/// (internal, default 100000).
pub const DEFAULT_BUDGET: u64 = 100_000;

/// A host directory shown to the guest (`--mount`). Implemented by the files
/// support; the core emulator accepts only an empty list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    pub host: PathBuf,
    pub guest: Vec<u8>,
}

/// Terminal size given to the guest. Used by the terminal support.
/// ```compile_fail
/// use paludarium_runtime::TerminalInfo;
/// let _ = TerminalInfo { columns: 80, rows: 24 };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TerminalInfo {
    pub columns: u16,
    pub rows: u16,
}
impl TerminalInfo {
    /// Creates the explicit guest terminal size, including zero dimensions.
    #[must_use]
    pub const fn new(columns: u16, rows: u16) -> Self {
        Self { columns, rows }
    }
}

/// Configuration of one run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Config {
    /// Absolute guest path of the program.
    pub program: Vec<u8>,
    /// Optional absolute initial working directory; omitted means `/`.
    pub cwd: Option<Vec<u8>>,
    /// argv, including `argv[0]`.
    pub args: Vec<Vec<u8>>,
    pub env: Vec<(Vec<u8>, Vec<u8>)>,
    /// Files placed in the virtual file system before start: (path, content).
    pub files: Vec<(Vec<u8>, Vec<u8>)>,
    /// Optional initial permission overrides. Entries must name configured
    /// files once each and contain only Linux permission bits (0o7777).
    pub file_modes: Vec<(Vec<u8>, u32)>,
    pub mounts: Vec<Mount>,
    pub tty: Option<TerminalInfo>,
    /// Only meaningful in wasm; the native build has no JIT.
    pub jit: bool,
}

impl Config {
    /// A configuration running `program` with `args` (`argv[0]` included).
    #[must_use]
    pub fn new(program: impl Into<Vec<u8>>, args: Vec<Vec<u8>>) -> Self {
        Config {
            program: program.into(),
            args,
            ..Config::default()
        }
    }

    /// Adds an environment variable.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Adds a file to place before start.
    #[must_use]
    pub fn with_file(mut self, path: impl Into<Vec<u8>>, content: impl Into<Vec<u8>>) -> Self {
        self.files.push((path.into(), content.into()));
        self
    }

    /// Adds a file with explicit initial permissions. Existing `with_file`
    /// callers retain the default 0o755 mode. Invalid overrides are rejected
    /// by [`Session::new`], before any guest executes.
    #[must_use]
    pub fn with_file_mode(
        mut self,
        path: impl Into<Vec<u8>>,
        content: impl Into<Vec<u8>>,
        mode: u32,
    ) -> Self {
        let path = path.into();
        self.files.push((path.clone(), content.into()));
        self.file_modes.push((path, mode));
        self
    }
}

/// One guest run.
pub struct Session {
    config: Config,
    file_modes: BTreeMap<Vec<u8>, u32>,
    mounts: Vec<(Vec<u8>, Arc<dyn HostFs>)>,
    host: Arc<dyn Host>,
    code_cache: Arc<dyn CodeCache>,
    accelerated: bool,
    budget: u64,
    kill_requested: Arc<AtomicBool>,
    signal_inbox: Arc<SignalInbox>,
    stopped: Arc<AtomicBool>,
    last_stop: Arc<Mutex<Option<ExitReason>>>,
    unimplemented: Arc<Mutex<BTreeSet<u64>>>,
}

impl Session {
    /// Selects a synchronous execution cache supplied by the wasm launcher.
    /// Native/default sessions retain the interpreter-only cache.
    #[must_use]
    pub fn with_code_cache(mut self, cache: Arc<dyn CodeCache>) -> Self {
        self.code_cache = cache;
        self.accelerated = true;
        self
    }
    /// Validates the configuration. Mounts are not implemented in the core emulator.
    pub fn new(config: Config, host: Arc<dyn Host>) -> Result<Self, Error> {
        if let Some(cwd) = &config.cwd
            && (!cwd.starts_with(b"/") || paludarium_vfs::normalize_path(cwd).is_err())
        {
            return Err(Error::new(
                ErrorKind::InvalidProgram,
                "invalid current directory",
            ));
        }
        if config.program.is_empty() {
            return Err(Error::new(ErrorKind::InvalidProgram, "no program given"));
        }
        let mut file_modes = BTreeMap::new();
        for (path, mode) in &config.file_modes {
            let path = paludarium_vfs::normalize_path(path)
                .map_err(|_| Error::new(ErrorKind::InvalidProgram, "invalid file mode path"))?;
            if path == b"/" || mode & !0o7777 != 0 {
                return Err(Error::new(
                    ErrorKind::InvalidProgram,
                    "invalid file mode override",
                ));
            }
            if !config.files.iter().any(|(configured, _)| {
                paludarium_vfs::normalize_path(configured).as_ref() == Ok(&path)
            }) {
                return Err(Error::new(
                    ErrorKind::InvalidProgram,
                    "file mode path has no configured file",
                ));
            }
            if file_modes.insert(path, *mode).is_some() {
                return Err(Error::new(
                    ErrorKind::InvalidProgram,
                    "duplicate file mode override",
                ));
            }
        }
        let mut mounts = Vec::new();
        let mut validate = MountedFs::new(MemFs::new());
        for mount in &config.mounts {
            let capability = host
                .mount_fs(&mount.host)
                .map_err(|_| Error::new(ErrorKind::Host, "cannot acquire mount root"))?;
            validate
                .mount(mount.guest.clone(), Arc::clone(&capability))
                .map_err(|_| Error::new(ErrorKind::InvalidProgram, "invalid guest mount"))?;
            mounts.push((mount.guest.clone(), capability));
        }
        Ok(Session {
            mounts,
            config,
            file_modes,
            host,
            code_cache: Arc::new(NoopCodeCache),
            accelerated: false,
            budget: DEFAULT_BUDGET,
            kill_requested: Arc::new(AtomicBool::new(false)),
            signal_inbox: Arc::new(SignalInbox::default()),
            stopped: Arc::new(AtomicBool::new(false)),
            last_stop: Arc::new(Mutex::new(None)),
            unimplemented: Arc::default(),
        })
    }

    /// Sets the number of instructions between kill checks (tests).
    #[must_use]
    pub fn with_budget(mut self, budget: u64) -> Self {
        self.budget = budget.max(1);
        self
    }

    /// Requests the guest to stop; it ends with SIGKILL at the next budget boundary.
    pub fn kill(&self) {
        self.kill_requested.store(true, Ordering::SeqCst);
        self.signal_inbox.interrupt();
    }

    /// Sends a Linux signal to the single guest process.
    pub fn signal(&self, number: i32) -> Result<(), paludarium_types::Errno> {
        self.signal_inbox.send(number)
    }

    /// Whether the execution loop has observed a job-control stop.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// The CPU stop that ended the guest, if it ended by a guest exception
    /// (for diagnostics; not part of the guest-visible result).
    #[must_use]
    pub fn termination_detail(&self) -> Option<ExitReason> {
        *self
            .last_stop
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The system-call numbers the guest called that paludarium does not
    /// implement (they returned `ENOSYS`), in ascending order. For
    /// diagnostics; not part of the guest-visible result.
    #[must_use]
    pub fn unimplemented_syscalls(&self) -> Vec<u64> {
        self.unimplemented
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .copied()
            .collect()
    }

    fn file_system(&self) -> Result<MountedFs, Error> {
        let host = self.host.clone();
        let mut fs = MemFs::with_clock(Arc::new(move || {
            host.clock(paludarium_host::ClockId::Realtime)
        }));
        fs.mkdir(b"/tmp", 0o1777)
            .map_err(|_| Error::new(ErrorKind::Internal, "temporary directory"))?;
        for (path, content) in &self.config.files {
            let mut file = GuestFile::new(path.clone(), content.clone());
            let normalized = paludarium_vfs::normalize_path(path)
                .map_err(|_| Error::new(ErrorKind::InvalidProgram, "invalid file placement"))?;
            if let Some(mode) = self.file_modes.get(&normalized) {
                file.mode = *mode;
            }
            fs.add_file(file)
                .map_err(|_| Error::new(ErrorKind::InvalidProgram, "invalid file placement"))?;
        }
        let mut mounted = MountedFs::new(fs);
        for (path, capability) in &self.mounts {
            mounted
                .mount(path.clone(), Arc::clone(capability))
                .map_err(|_| Error::new(ErrorKind::InvalidProgram, "invalid guest mount"))?;
        }
        Ok(mounted)
    }

    /// Runs the guest to completion (W2–W4).
    pub fn run(&self) -> Result<ExitStatus, Error> {
        self.run_with_file_system(self.initial_file_system()?)
    }

    /// Creates the validated initial filesystem without executing the guest.
    /// Callers may retain it for explicitly shared, sequential guest runs.
    pub fn initial_file_system(&self) -> Result<Arc<dyn paludarium_vfs::FileSystem>, Error> {
        Ok(Arc::new(self.file_system()?))
    }

    /// Runs using an explicitly supplied filesystem. Initial `files`, mode
    /// overrides and mounts are applied by `initial_file_system`, not again
    /// here. The caller owns synchronization and its filesystem's lifetime.
    /// Ordinary `run()` continues to create an independent filesystem.
    pub fn run_with_file_system(
        &self,
        fs: Arc<dyn paludarium_vfs::FileSystem>,
    ) -> Result<ExitStatus, Error> {
        let mut random = [0u8; 16];
        self.host.random_bytes(&mut random)?;
        let envp: Vec<Vec<u8>> = self
            .config
            .env
            .iter()
            .map(|(k, v)| {
                let mut s = k.clone();
                s.push(b'=');
                s.extend_from_slice(v);
                s
            })
            .collect();
        let start = StartInfo {
            argv: &self.config.args,
            envp: &envp,
            execfn: &self.config.program,
            random,
        };
        let mut mem = AddressSpace::new();
        let image = load(&*fs, &self.config.program, &start, &mut mem)?;
        let mut kernel = Kernel::new(Arc::clone(&self.host))
            .with_file_system(fs)
            .with_signal_inbox(Arc::clone(&self.signal_inbox))
            .with_unimplemented_log(Arc::clone(&self.unimplemented));
        if let Some(tty) = self.config.tty {
            kernel = kernel.with_terminal_size(tty.columns, tty.rows);
        }
        if let Some(cwd) = &self.config.cwd {
            kernel = kernel.with_current_directory(cwd).map_err(|_| {
                Error::new(ErrorKind::InvalidProgram, "current directory unavailable")
            })?;
        }
        let mut thread = kernel.spawn_initial(&image);
        thread.state.name_after(&self.config.program);
        let execution = Arc::new(Execution::new(
            Arc::clone(&self.host),
            Arc::new(mem),
            kernel.thread_group(),
            kernel.processes(),
            Arc::clone(&self.kill_requested),
            Arc::clone(&self.signal_inbox),
            Arc::clone(&self.stopped),
            Arc::clone(&self.last_stop),
            Arc::clone(&self.code_cache),
            self.accelerated,
            self.budget,
        ));
        execution.execute(kernel, thread);
        execution.finish()
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod terminal_tests;

#[cfg(test)]
mod programs_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod threads_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod processes_tests;
