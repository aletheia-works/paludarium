//! Retained closure tickets for real wasm execution Workers.
use crate::{Host, ThreadHandle, WaitToken};
use paludarium_types::Errno;
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex, OnceLock, PoisonError,
    atomic::{AtomicBool, AtomicU32, Ordering},
};

type Entry = Box<dyn FnOnce() + Send>;
struct Task {
    entry: Mutex<Option<Entry>>,
    started: AtomicBool,
    result: Mutex<Option<Result<(), Errno>>>,
    done: WaitToken,
}
static NEXT: AtomicU32 = AtomicU32::new(1);
static TASKS: OnceLock<Mutex<BTreeMap<u32, Arc<Task>>>> = OnceLock::new();
fn tasks() -> &'static Mutex<BTreeMap<u32, Arc<Task>>> {
    TASKS.get_or_init(Default::default)
}
fn task(id: u32) -> Option<Arc<Task>> {
    tasks()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .cloned()
}
pub(crate) fn register(entry: Entry) -> Result<u32, Errno> {
    let id = NEXT
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
            value.checked_add(1)
        })
        .map_err(|_| Errno::EAGAIN)?;
    let value = Arc::new(Task {
        entry: Mutex::new(Some(entry)),
        started: AtomicBool::new(false),
        result: Mutex::new(None),
        done: WaitToken::default(),
    });
    tasks()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(id, value);
    Ok(id)
}
pub(crate) fn unregister(id: u32) {
    tasks()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&id);
}
/// Called once by a launcher Worker after it owns an independent stack/TLS.
/// The closure retains its Kernel/Thread and shared Arc resources until return.
pub fn run_task(id: u32) -> Result<(), Errno> {
    let value = task(id).ok_or(Errno::EINVAL)?;
    if value.started.swap(true, Ordering::SeqCst) {
        return Err(Errno::EINVAL);
    }
    let entry = value
        .entry
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .ok_or(Errno::EINVAL)?;
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(entry)).map_err(|_| Errno::EIO);
    *value.result.lock().unwrap_or_else(PoisonError::into_inner) = Some(result);
    value.done.notify();
    result
}
pub(crate) struct WasmThread {
    id: u32,
    task: Arc<Task>,
    host: Arc<dyn Host>,
}
impl WasmThread {
    pub(crate) fn new(id: u32, host: Arc<dyn Host>) -> Result<Self, Errno> {
        Ok(Self {
            id,
            task: task(id).ok_or(Errno::EINVAL)?,
            host,
        })
    }
}
impl ThreadHandle for WasmThread {
    fn join(self: Box<Self>) -> Result<(), Errno> {
        let cancel = AtomicBool::new(false);
        loop {
            let expected = self.task.done.value();
            if let Some(result) = *self
                .task
                .result
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
            {
                unregister(self.id);
                return result;
            }
            self.host
                .wait_on(&self.task.done, expected, None, &cancel)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::RecordingHost;
    #[test]
    fn task_executes_once() {
        let value = Arc::new(AtomicU32::new(0));
        let copy = value.clone();
        let id = register(Box::new(move || {
            copy.fetch_add(1, Ordering::SeqCst);
        }))
        .unwrap();
        assert_eq!(run_task(id), Ok(()));
        assert_eq!(run_task(id), Err(Errno::EINVAL));
        assert_eq!(value.load(Ordering::SeqCst), 1);
        unregister(id);
    }
    #[test]
    fn task_bad_handle() {
        assert_eq!(run_task(0), Err(Errno::EINVAL));
    }
    #[test]
    fn task_join_reclaims_registration() {
        let id = register(Box::new(|| {})).unwrap();
        let handle = WasmThread::new(id, Arc::new(RecordingHost::default())).unwrap();
        assert_eq!(run_task(id), Ok(()));
        assert_eq!(Box::new(handle).join(), Ok(()));
        assert!(task(id).is_none());
    }
    #[test]
    fn task_panic_is_host_failure() {
        let id = register(Box::new(|| panic!("test-only task panic"))).unwrap();
        assert_eq!(run_task(id), Err(Errno::EIO));
        let handle = WasmThread::new(id, Arc::new(RecordingHost::default())).unwrap();
        assert_eq!(Box::new(handle).join(), Err(Errno::EIO));
    }
    #[test]
    fn task_start_failure_releases_closure() {
        let value = Arc::new(());
        let retained = value.clone();
        let id = register(Box::new(move || drop(retained))).unwrap();
        assert_eq!(Arc::strong_count(&value), 2);
        unregister(id);
        assert_eq!(Arc::strong_count(&value), 1);
    }
    #[test]
    fn task_handle_after_unregister_rejected() {
        let id = register(Box::new(|| {})).unwrap();
        unregister(id);
        assert!(matches!(
            WasmThread::new(id, Arc::new(RecordingHost::default())),
            Err(Errno::EINVAL)
        ));
    }
    #[test]
    fn task_registrations_are_independent() {
        let first = register(Box::new(|| {})).unwrap();
        let second = register(Box::new(|| {})).unwrap();
        assert_ne!(first, second);
        assert_eq!(run_task(first), Ok(()));
        assert!(task(second).unwrap().result.lock().unwrap().is_none());
        unregister(first);
        unregister(second);
    }
}
