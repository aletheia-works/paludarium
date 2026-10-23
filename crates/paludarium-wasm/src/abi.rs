//! Internal scalar/handle ABI used by the Worker launcher.
//!
//! Guest data is copied through bounded buffers; it is never dereferenced as a
//! host pointer. JS stack/TLS regions are trusted launcher resources and must
//! stay owned until their Worker is terminated.
use crate::filesystem::{Lease, PrivateFs};
use paludarium_host::WasmHost;
use paludarium_runtime::{Config, Session, TerminalInfo};
use paludarium_types::{Error, ErrorKind, ExitStatus};
use paludarium_vfs::{EntryKind, GuestEntry};
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::sync::{
    Arc, Mutex, OnceLock, PoisonError,
    atomic::{AtomicU32, Ordering},
};

type Table<T> = OnceLock<Mutex<BTreeMap<u32, T>>>;
static NEXT: AtomicU32 = AtomicU32::new(1);
static BUFFERS: Table<Vec<u8>> = OnceLock::new();
static CONFIGS: Table<Config> = OnceLock::new();
static RUNS: Table<Arc<Run>> = OnceLock::new();
static REGIONS: Table<Box<[u128]>> = OnceLock::new();
static FILESYSTEMS: Table<Arc<PrivateFs>> = OnceLock::new();
#[cfg(feature = "cost-profile")]
static MICRO: Table<paludarium_jit::microbench::DiagnosticBench> = OnceLock::new();
#[cfg(feature = "cost-profile")]
static LENGTH: Table<paludarium_jit::microbench::LengthBench> = OnceLock::new();
struct Run {
    session: Option<Arc<Session>>,
    host: Arc<WasmHost>,
    error: Mutex<Option<Error>>,
    filesystem: Option<Lease>,
    jit: Option<Arc<paludarium_jit::WasmCodeCache>>,
}

#[link(wasm_import_module = "paludarium")]
unsafe extern "C" {
    fn jit_prepare(module: u32, code: *const u8, length: usize) -> i32;
    fn jit_execute(
        module: u32,
        code: *const u8,
        length: usize,
        state: *mut u64,
        state_length: usize,
    ) -> i32;
}
struct WorkerJit;
impl paludarium_jit::ExecutionBridge for WorkerJit {
    #[cfg(feature = "cost-profile")]
    fn diagnostic_prepared(&self, module: u32, wasm: &[u8]) -> Option<bool> {
        paludarium_jit::jit_cost::add(paludarium_jit::jit_cost::Counter::JsTransitions, 1);
        // SAFETY: immutable live Rust code; length0/null state is a diagnostic
        // no-touch query accepted only by the cost-enabled launcher import.
        match unsafe { jit_execute(module, wasm.as_ptr(), wasm.len(), std::ptr::null_mut(), 0) } {
            0 => Some(true),
            -2 => Some(false),
            _ => None,
        }
    }
    fn execute_ready(
        &self,
        module: u32,
        wasm: &[u8],
        state: &mut paludarium_jit::JitState,
    ) -> Option<bool> {
        #[cfg(feature = "cost-profile")]
        {
            use paludarium_jit::jit_cost::{self, Counter};
            jit_cost::add(Counter::JsTransitions, 1);
            jit_cost::add(Counter::ExecuteCalls, 1);
        }
        // SAFETY: live immutable code and exclusively borrowed Rust scratch of
        // exactly STATE_BYTES (GPR, RFLAGS, RIP and XMM0..15); the import
        // cannot compile and reports missing Worker-local entries.
        match unsafe {
            jit_execute(
                module,
                wasm.as_ptr(),
                wasm.len(),
                state.as_mut_ptr(),
                paludarium_jit::STATE_BYTES,
            )
        } {
            -2 => None,
            result => Some(result == 0),
        }
    }
    fn prepare(&self, module: u32, wasm: &[u8]) -> bool {
        #[cfg(feature = "cost-profile")]
        paludarium_jit::jit_cost::add(paludarium_jit::jit_cost::Counter::JsTransitions, 1);
        // SAFETY: immutable Rust code bytes stay live for the synchronous import.
        unsafe { jit_prepare(module, wasm.as_ptr(), wasm.len()) == 0 }
    }
    fn execute(&self, module: u32, wasm: &[u8], state: &mut paludarium_jit::JitState) -> bool {
        #[cfg(feature = "cost-profile")]
        paludarium_jit::jit_cost::add(paludarium_jit::jit_cost::Counter::JsTransitions, 1);
        // SAFETY: both buffers belong to Rust, are live for this synchronous
        // import, and state is exclusively borrowed scratch of exactly
        // STATE_BYTES, never guest memory.
        unsafe {
            jit_execute(
                module,
                wasm.as_ptr(),
                wasm.len(),
                state.as_mut_ptr(),
                paludarium_jit::STATE_BYTES,
            ) == 0
        }
    }
}
fn table<T>(t: &Table<T>) -> &Mutex<BTreeMap<u32, T>> {
    t.get_or_init(Default::default)
}
fn insert<T>(t: &Table<T>, value: T) -> u32 {
    let Ok(id) = NEXT.try_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1)) else {
        return 0;
    };
    table(t)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(id, value);
    id
}
fn bytes(id: u32) -> Option<Vec<u8>> {
    table(&BUFFERS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .cloned()
}
fn run(id: u32) -> Option<Arc<Run>> {
    table(&RUNS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .cloned()
}

/// The largest buffer the launcher can pass in: one file (or other value) of
/// up to 128 MiB. A file is copied a few times on its way into the guest
/// filesystem, all within the module's 1 GiB of memory.
pub(crate) const MAX_BUFFER_BYTES: u32 = 128 << 20;

// SAFETY: exported entrypoints take scalars and validated handles only. They
// neither dereference caller-provided pointers nor export guest syscall numbers.
#[unsafe(no_mangle)]
pub extern "C" fn buffer_new(len: u32) -> u32 {
    if len > MAX_BUFFER_BYTES {
        return 0;
    }
    insert(&BUFFERS, vec![0; len as usize])
}
#[unsafe(no_mangle)]
pub extern "C" fn buffer_set(id: u32, index: u32, value: u32) -> i32 {
    let mut b = table(&BUFFERS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if value > 255 {
        return -1;
    }
    if let Some(v) = b.get_mut(&id).and_then(|b| b.get_mut(index as usize)) {
        *v = value as u8;
        0
    } else {
        -1
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn buffer_len(id: u32) -> i32 {
    table(&BUFFERS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .map_or(-1, |b| b.len() as i32)
}
/// Trusted launcher bulk-copy address, never a guest memory address. The
/// caller owns the validated buffer handle until its synchronous copy ends.
#[unsafe(no_mangle)]
pub extern "C" fn buffer_pointer(id: u32) -> u32 {
    table(&BUFFERS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .and_then(|buffer| u32::try_from(buffer.as_ptr() as usize).ok())
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn host_task_run(id: u32) -> i32 {
    paludarium_host::run_task(id).map_or(-1, |()| 0)
}
#[unsafe(no_mangle)]
pub extern "C" fn buffer_get(id: u32, index: u32) -> i32 {
    table(&BUFFERS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .and_then(|b| b.get(index as usize))
        .map_or(-1, |b| i32::from(*b))
}
#[unsafe(no_mangle)]
pub extern "C" fn buffer_drop(id: u32) {
    table(&BUFFERS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&id);
}
#[unsafe(no_mangle)]
pub extern "C" fn config_new(program: u32) -> u32 {
    let Some(program) = bytes(program) else {
        return 0;
    };
    insert(&CONFIGS, Config::new(program, Vec::new()))
}
#[unsafe(no_mangle)]
pub extern "C" fn config_jit(id: u32, enabled: u32) -> i32 {
    if enabled > 1 {
        return -1;
    }
    let mut configs = table(&CONFIGS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(config) = configs.get_mut(&id) else {
        return -1;
    };
    config.jit = enabled == 1;
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn session_jit_stat(id: u32, field: u32) -> u64 {
    let Some(run) = run(id) else {
        return 0;
    };
    let Some(cache) = &run.jit else {
        return 0;
    };
    let stats = cache.statistics();
    match field {
        0 => stats.translated_blocks,
        1 => stats.executed_blocks,
        2 => stats.executed_instructions,
        3 => stats.fallbacks,
        _ => 0,
    }
}
// Diagnostic-only ABI. None of these exports or collector operations is
// present in the ordinary acceptance module. The fresh coordinator resets
// before spawning Workers; all reads/additions are lock-free counters.
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn cost_version() -> u32 {
    3
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn cost_measurement(enabled: u32) -> i32 {
    if enabled > 1 {
        return -1;
    }
    i32::from(paludarium_jit::jit_cost::set_measurement_enabled(
        enabled == 1,
    ))
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn cost_site_count() -> u32 {
    paludarium_jit::jit_cost::site_count() as u32
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn cost_site_stat(index: u32, field: u32) -> u64 {
    paludarium_jit::jit_cost::site_field(index as usize, field as usize).unwrap_or(0)
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn cost_fields() -> u32 {
    paludarium_jit::jit_cost::FIELD_COUNT as u32
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn cost_stat(field: u32) -> u64 {
    paludarium_jit::jit_cost::get(field as usize).unwrap_or(0)
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn cost_overflow() -> u32 {
    u32::from(paludarium_jit::jit_cost::overflowed())
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn cost_add(field: u32, value: u64) -> i32 {
    if paludarium_jit::jit_cost::add_field(field as usize, value) {
        0
    } else {
        -1
    }
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn cost_reset() {
    paludarium_jit::jit_cost::reset();
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn micro_new(kind: u32, maximum: u32, observe: u32) -> u32 {
    if maximum > 1 || observe > 1 {
        return 0;
    }
    paludarium_jit::microbench::DiagnosticBench::new(
        kind,
        maximum == 1,
        observe == 1,
        Arc::new(WorkerJit),
    )
    .map_or(0, |bench| insert(&MICRO, bench))
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn micro_chunk(id: u32, count: u32) -> u64 {
    table(&MICRO)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get_mut(&id)
        .and_then(|bench| bench.chunk(count))
        .unwrap_or(u64::MAX)
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn micro_operations(id: u32) -> u64 {
    table(&MICRO)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .map_or(u64::MAX, |bench| bench.operations())
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn micro_drop(id: u32) {
    table(&MICRO)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&id);
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn length_new(kind: u32, length: u32, observe: u32) -> u32 {
    if observe > 1 {
        return 0;
    }
    paludarium_jit::microbench::LengthBench::new(kind, length, observe == 1, Arc::new(WorkerJit))
        .map_or(0, |bench| insert(&LENGTH, bench))
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn length_chunk(id: u32, count: u32) -> u64 {
    table(&LENGTH)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get_mut(&id)
        .and_then(|bench| bench.chunk(count))
        .unwrap_or(u64::MAX)
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn length_stat(id: u32, field: u32) -> u64 {
    table(&LENGTH)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .and_then(|bench| match field {
            0 => Some(bench.operations()),
            1 => Some(bench.warmups()),
            _ => None,
        })
        .unwrap_or(u64::MAX)
}
#[cfg(feature = "cost-profile")]
#[unsafe(no_mangle)]
pub extern "C" fn length_drop(id: u32) {
    table(&LENGTH)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&id);
}
#[unsafe(no_mangle)]
pub extern "C" fn config_arg(id: u32, arg: u32) -> i32 {
    let Some(arg) = bytes(arg) else { return -1 };
    let mut t = table(&CONFIGS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(c) = t.get_mut(&id) else { return -1 };
    c.args.push(arg);
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn config_env(id: u32, key: u32, value: u32) -> i32 {
    let (Some(key), Some(value)) = (bytes(key), bytes(value)) else {
        return -1;
    };
    let mut t = table(&CONFIGS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(c) = t.get_mut(&id) else { return -1 };
    c.env.push((key, value));
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn config_file(id: u32, path: u32, content: u32) -> i32 {
    let (Some(path), Some(content)) = (bytes(path), bytes(content)) else {
        return -1;
    };
    let mut t = table(&CONFIGS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(c) = t.get_mut(&id) else { return -1 };
    c.files.push((path, content));
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn config_drop(id: u32) {
    table(&CONFIGS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&id);
}
#[unsafe(no_mangle)]
pub extern "C" fn config_file_mode(id: u32, path: u32, content: u32, mode: u32) -> i32 {
    let (Some(path), Some(content)) = (bytes(path), bytes(content)) else {
        return -1;
    };
    if mode > 0o7777 {
        return -1;
    }
    let mut configs = table(&CONFIGS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(config) = configs.get_mut(&id) else {
        return -1;
    };
    config.files.push((path.clone(), content));
    config.file_modes.push((path, mode));
    0
}
/// One entry of a tree to place: the kind comes from the type bits of
/// `mode` (file, directory or symlink); `content` is the file bytes or the
/// symlink target. The time is the signed nanoseconds split in two halves.
#[unsafe(no_mangle)]
pub extern "C" fn config_entry(
    id: u32,
    path: u32,
    content: u32,
    mode: u32,
    mtime_low: u64,
    mtime_high: i64,
) -> i32 {
    let (Some(path), Some(content)) = (bytes(path), bytes(content)) else {
        return -1;
    };
    let kind = match mode & !0o7777 {
        0o100000 => EntryKind::File(content),
        0o040000 if content.is_empty() => EntryKind::Directory,
        0o120000 => EntryKind::Symlink(content),
        _ => return -1,
    };
    let entry = GuestEntry {
        path,
        kind,
        mode: mode & 0o7777,
        mtime_ns: (i128::from(mtime_high) << 64) | i128::from(mtime_low),
    };
    let mut configs = table(&CONFIGS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(config) = configs.get_mut(&id) else {
        return -1;
    };
    config.entries.push(entry);
    0
}
/// Another name, `path`, for the file or symlink entry at `existing`.
#[unsafe(no_mangle)]
pub extern "C" fn config_link(id: u32, path: u32, existing: u32) -> i32 {
    let (Some(path), Some(existing)) = (bytes(path), bytes(existing)) else {
        return -1;
    };
    let mut configs = table(&CONFIGS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(config) = configs.get_mut(&id) else {
        return -1;
    };
    config.entries.push(GuestEntry {
        path,
        kind: EntryKind::HardLink(existing),
        mode: 0,
        mtime_ns: 0,
    });
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn config_terminal(id: u32, columns: u32, rows: u32) -> i32 {
    let (Ok(columns), Ok(rows)) = (u16::try_from(columns), u16::try_from(rows)) else {
        return -1;
    };
    let mut configs = table(&CONFIGS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(config) = configs.get_mut(&id) else {
        return -1;
    };
    config.tty = Some(TerminalInfo::new(columns, rows));
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn config_cwd(id: u32, path: u32) -> i32 {
    let Some(path) = bytes(path) else {
        return -1;
    };
    let mut configs = table(&CONFIGS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(config) = configs.get_mut(&id) else {
        return -1;
    };
    config.cwd = Some(path);
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn session_error_presence(id: u32) -> u32 {
    run(id)
        .and_then(|r| {
            r.error
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        })
        .map_or(0, |error| {
            u32::from(error.rip.is_some())
                | (u32::from(error.bytes.is_some()) << 1)
                | (u32::from(error.syscall.is_some()) << 2)
        })
}
#[unsafe(no_mangle)]
pub extern "C" fn session_error_rip(id: u32) -> u64 {
    run(id)
        .and_then(|r| {
            r.error
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .and_then(|error| error.rip)
        })
        .map_or(0, |addr| addr.0)
}
#[unsafe(no_mangle)]
pub extern "C" fn session_error_syscall(id: u32) -> u64 {
    run(id)
        .and_then(|r| {
            r.error
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .and_then(|error| error.syscall)
        })
        .unwrap_or(0)
}
#[unsafe(no_mangle)]
pub extern "C" fn session_error_bytes(id: u32) -> u32 {
    run(id)
        .and_then(|r| {
            r.error
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .and_then(|error| error.bytes.clone())
        })
        .map_or(0, |bytes| insert(&BUFFERS, bytes))
}
#[unsafe(no_mangle)]
pub extern "C" fn filesystem_new(id: u32) -> u32 {
    let config = table(&CONFIGS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .cloned();
    let Some(config) = config else {
        return 0;
    };
    PrivateFs::new(config, Arc::new(WasmHost::default())).map_or(0, |fs| insert(&FILESYSTEMS, fs))
}
#[unsafe(no_mangle)]
pub extern "C" fn filesystem_drop(id: u32) -> i32 {
    let mut filesystems = table(&FILESYSTEMS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(fs) = filesystems.get(&id) else {
        return -1;
    };
    if fs.close().is_err() {
        return -1;
    }
    filesystems.remove(&id);
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn filesystem_remove(id: u32, path: u32, recursive: u32) -> i32 {
    let Some(path) = bytes(path) else {
        return -1;
    };
    if recursive > 1 {
        return -1;
    }
    let fs = table(&FILESYSTEMS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .cloned();
    fs.map_or(-1, |fs| fs.remove(&path, recursive == 1).map_or(-1, |()| 0))
}
#[unsafe(no_mangle)]
pub extern "C" fn filesystem_snapshot(id: u32) -> u32 {
    let fs = table(&FILESYSTEMS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .cloned();
    let Some(fs) = fs else {
        return 0;
    };
    let Ok(entries) = fs.snapshot() else {
        return 0;
    };
    let Some(data) = crate::filesystem::snapshot_bytes(&entries) else {
        return 0;
    };
    insert(&BUFFERS, data)
}
#[unsafe(no_mangle)]
pub extern "C" fn session_from_config(id: u32, stdin: u32) -> u32 {
    session_from_config_fs(id, stdin, 0)
}
#[unsafe(no_mangle)]
pub extern "C" fn session_from_config_fs(id: u32, stdin: u32, filesystem: u32) -> u32 {
    let filesystem = if filesystem == 0 {
        None
    } else {
        let fs = table(&FILESYSTEMS)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&filesystem)
            .cloned();
        let Some(fs) = fs else {
            return 0;
        };
        let Ok(lease) = fs.acquire() else {
            return 0;
        };
        Some(lease)
    };
    let Some(config) = table(&CONFIGS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .cloned()
    else {
        return 0;
    };
    let host = Arc::new(WasmHost::streaming(bytes(stdin).unwrap_or_default()));
    // The measured two-instruction warm bridge cannot amortize its cost.
    // This excludes that case; it does not assert profitability of all >=3.
    const MINIMUM_WASM_JIT_BLOCK: usize = 3;
    let jit = config.jit.then(|| {
        Arc::new(
            paludarium_jit::WasmCodeCache::new(Arc::new(WorkerJit))
                .with_minimum_block(MINIMUM_WASM_JIT_BLOCK),
        )
    });
    let (session, error) = match Session::new(config, host.clone()) {
        Ok(s) => (
            Some(Arc::new(if let Some(cache) = &jit {
                s.with_code_cache(cache.clone())
            } else {
                s
            })),
            None,
        ),
        Err(e) => (None, Some(e)),
    };
    insert(
        &RUNS,
        Arc::new(Run {
            session,
            host,
            error: Mutex::new(error),
            filesystem,
            jit,
        }),
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn session_run(id: u32) -> i32 {
    let Some(r) = run(id) else { return -1 };
    let Some(s) = &r.session else { return -2 };
    let result = match &r.filesystem {
        Some(lease) => s.run_with_file_system(lease.filesystem()),
        None => s.run(),
    };
    match result {
        Ok(ExitStatus::Exited(code)) => code,
        Ok(ExitStatus::Signaled(signal)) => 256 + signal,
        Err(e) => {
            *r.error.lock().unwrap_or_else(PoisonError::into_inner) = Some(e);
            -2
        }
        Ok(_) => {
            *r.error.lock().unwrap_or_else(PoisonError::into_inner) =
                Some(Error::new(ErrorKind::Internal, "unknown guest status"));
            -2
        }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn session_kill(id: u32) -> i32 {
    let Some(r) = run(id) else { return -1 };
    r.host.close_stdin();
    if let Some(s) = &r.session {
        s.kill();
    }
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn session_stdin_write(id: u32, buffer: u32) -> i32 {
    let (Some(r), Some(b)) = (run(id), bytes(buffer)) else {
        return -1;
    };
    r.host.append_stdin(&b).map_or(-1, |()| 0)
}
#[unsafe(no_mangle)]
pub extern "C" fn session_stdin_close(id: u32) -> i32 {
    let Some(r) = run(id) else { return -1 };
    r.host.close_stdin();
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn session_output(id: u32, stream: u32) -> u32 {
    let Some(r) = run(id) else { return 0 };
    let data = match stream {
        1 => r.host.stdout(),
        2 => r.host.stderr(),
        _ => return 0,
    };
    insert(&BUFFERS, data)
}
#[unsafe(no_mangle)]
pub extern "C" fn session_error_kind(id: u32) -> i32 {
    let Some(r) = run(id) else { return -1 };
    r.error
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .map_or(0, |e| match e.kind {
            ErrorKind::Unimplemented => 1,
            ErrorKind::Internal => 2,
            ErrorKind::InvalidProgram => 3,
            ErrorKind::Host => 4,
            _ => 2,
        })
}
#[unsafe(no_mangle)]
pub extern "C" fn session_error_message(id: u32) -> u32 {
    let Some(r) = run(id) else { return 0 };
    let message = r
        .error
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .map_or_else(String::new, ToString::to_string);
    insert(&BUFFERS, message.into_bytes())
}
#[unsafe(no_mangle)]
pub extern "C" fn session_drop(id: u32) {
    table(&RUNS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&id);
}

#[unsafe(no_mangle)]
pub extern "C" fn region_new(len: u32) -> u32 {
    if !(4096..=16 * 1024 * 1024).contains(&len) {
        return 0;
    }
    insert(
        &REGIONS,
        vec![0u128; (len as usize).div_ceil(16)].into_boxed_slice(),
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn region_pointer(id: u32) -> u32 {
    table(&REGIONS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .map_or(0, |b| b.as_ptr() as usize as u32)
}
#[unsafe(no_mangle)]
pub extern "C" fn region_drop(id: u32) {
    table(&REGIONS)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&id);
}
#[unsafe(no_mangle)]
pub extern "C" fn thread_token() -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    std::thread::current().id().hash(&mut h);
    h.finish()
}

struct SharedSpace {
    memory: paludarium_mmu::AddressSpace,
    wake: AtomicU32,
}
static SPACES: Table<Arc<SharedSpace>> = OnceLock::new();
fn space(id: u32) -> Option<Arc<SharedSpace>> {
    table(&SPACES)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .cloned()
}
#[unsafe(no_mangle)]
pub extern "C" fn shared_space_new() -> u32 {
    let memory = paludarium_mmu::AddressSpace::new();
    if memory
        .map_shared(
            Some(paludarium_types::GuestAddr(0x1000)),
            4096,
            paludarium_mmu::Prot::READ_WRITE,
            paludarium_mmu::MappingKind::Anonymous,
        )
        .is_err()
    {
        return 0;
    }
    insert(
        &SPACES,
        Arc::new(SharedSpace {
            memory,
            wake: AtomicU32::new(0),
        }),
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn shared_space_add(id: u32, iterations: u32) -> i32 {
    let Some(s) = space(id) else { return -1 };
    if iterations > 1_000_000 {
        return -1;
    }
    for _ in 0..iterations {
        if s.memory
            .atomic(
                paludarium_types::GuestAddr(0x1000),
                paludarium_mmu::AtomicWidth::W64,
                paludarium_mmu::AtomicOp::Add(1),
            )
            .is_err()
        {
            return -1;
        }
    }
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn shared_space_value(id: u32) -> i64 {
    space(id)
        .and_then(|s| s.memory.read_u64(paludarium_types::GuestAddr(0x1000)).ok())
        .map_or(-1, |v| v as i64)
}
#[unsafe(no_mangle)]
pub extern "C" fn shared_space_drop(id: u32) {
    table(&SPACES)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&id);
}
#[unsafe(no_mangle)]
pub extern "C" fn shared_wait_word(id: u32, value: u32) -> i32 {
    let Some(s) = space(id) else { return -1 };
    s.wake.store(value, Ordering::SeqCst);
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn shared_wait(id: u32, expected: u32, timeout_ms: u32) -> i32 {
    let Some(s) = space(id) else { return -1 };
    if timeout_ms > 30_000 {
        return -1;
    }
    // SAFETY: retained Arc owns an aligned AtomicU32 for the whole bounded wait;
    // no Rust lock is held. Only atomics access this memory, in Workers.
    unsafe {
        core::arch::wasm32::memory_atomic_wait32(
            s.wake.as_ptr().cast(),
            expected as i32,
            i64::from(timeout_ms) * 1_000_000,
        )
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn shared_notify(id: u32, count: u32) -> i32 {
    let Some(s) = space(id) else { return -1 };
    // SAFETY: Arc pins the aligned AtomicU32; notify cannot outlive this call.
    unsafe { core::arch::wasm32::memory_atomic_notify(s.wake.as_ptr().cast(), count) as i32 }
}
