//! Emulated process registry; no lock spans Host waits or guest execution.
use crate::{Kernel, Next, SignalInbox, Thread, ThreadGroup, ThreadState, signals};
use paludarium_cpu::{CpuState, reg};
use paludarium_host::ClockId;
use paludarium_loader::{LoadError, StartInfo};
use paludarium_mmu::AddressSpace;
use paludarium_types::{Errno, ExitStatus, GuestAddr};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

struct Entry {
    parent: u32,
    group: Arc<ThreadGroup>,
    status: Option<ExitStatus>,
}
pub struct Processes {
    next: AtomicU32,
    entries: Mutex<BTreeMap<u32, Entry>>,
}
impl Processes {
    pub(crate) fn new(group: Arc<ThreadGroup>) -> Self {
        Self {
            next: AtomicU32::new(2),
            entries: Mutex::new(BTreeMap::from([(
                1,
                Entry {
                    parent: 0,
                    group,
                    status: None,
                },
            )])),
        }
    }
    pub(crate) fn allocate(&self) -> Result<u32, Errno> {
        self.next
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                (value < i32::MAX as u32).then_some(value + 1)
            })
            .map_err(|_| Errno::EAGAIN)
    }
    pub(crate) fn insert(&self, pid: u32, parent: u32, group: Arc<ThreadGroup>) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                pid,
                Entry {
                    parent,
                    group,
                    status: None,
                },
            );
    }
    fn parent(&self, pid: u32) -> u32 {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&pid)
            .map_or(0, |entry| entry.parent)
    }
    pub(crate) fn remove(&self, pid: u32) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&pid);
    }
    pub(crate) fn finish(&self, pid: u32, status: ExitStatus) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let parent = if let Some(entry) = entries.get_mut(&pid) {
            if entry.group.active_threads() != 0 {
                return;
            }
            entry.status = Some(entry.group.status().unwrap_or(status));
            entry.parent
        } else {
            return;
        };
        if let Some(parent) = entries.get(&parent) {
            parent.group.notify_child();
        }
    }
    pub fn active_threads(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .map(|entry| entry.group.active_threads())
            .sum()
    }
    pub fn stop_all(&self, status: ExitStatus) {
        for entry in self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            entry.group.stop(status);
        }
    }
    pub(crate) fn reap(
        &self,
        parent: u32,
        wanted: i64,
    ) -> Result<Option<(u32, ExitStatus)>, Errno> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let matching = |pid: u32, entry: &Entry| {
            entry.parent == parent && (wanted == -1 || wanted == 0 || wanted == i64::from(pid))
        };
        if !entries.iter().any(|(&pid, entry)| matching(pid, entry)) {
            return Err(Errno(10));
        }
        let ready = entries.iter().find_map(|(&pid, entry)| {
            (matching(pid, entry))
                .then_some(entry.status)
                .flatten()
                .map(|status| (pid, status))
        });
        if let Some((pid, _)) = ready {
            entries.remove(&pid);
        }
        Ok(ready)
    }
    fn signal(&self, pid: u32, number: i32) -> Result<(), Errno> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get(&pid).ok_or(Errno(3))?;
        if number == 0 {
            Ok(())
        } else {
            entry.group.send_process(number)
        }
    }
}

impl Kernel {
    #[must_use]
    pub fn processes(&self) -> Arc<Processes> {
        self.processes.clone()
    }
    pub fn take_spawn_memory(&mut self) -> Option<Arc<AddressSpace>> {
        self.spawn_memory.take()
    }
    pub fn take_exec_memory(&mut self) -> Option<Arc<AddressSpace>> {
        self.exec_memory.take()
    }
    pub fn complete_process(&self, status: ExitStatus) {
        self.processes.finish(self.process.pid, status);
        if self.group.active_threads() == 0 {
            self.release_vfork();
        }
    }
    fn release_vfork(&self) {
        if let Some(release) = &self.vfork_release {
            release.store(true, Ordering::SeqCst);
        }
    }
    pub fn abandon_child(&mut self, pid: u32, tid: u32) {
        if pid == self.process.pid {
            self.abandon_thread(tid);
        } else {
            self.processes.remove(pid);
        }
        if let Some(release) = self.vfork_wait.take() {
            release.store(true, Ordering::SeqCst);
        }
    }
    pub fn wait_vfork(&mut self, kill: &AtomicBool) -> Result<(), Errno> {
        let Some(release) = self.vfork_wait.take() else {
            return Ok(());
        };
        while !release.load(Ordering::SeqCst) && self.group.status().is_none() {
            if kill.load(Ordering::SeqCst) {
                self.processes.stop_all(ExitStatus::Signaled(9));
                return Err(Errno(4));
            }
            let now = self.host.clock(ClockId::Monotonic)?;
            self.host.wait_until(
                ClockId::Monotonic,
                now.saturating_add(10_000_000),
                &self.cancellation,
            )?;
        }
        Ok(())
    }
    pub(crate) fn process_syscall(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        n: u64,
        a: [u64; 6],
    ) -> Option<Next> {
        let result = match n {
            56 if a[0] & 0x10000 == 0 => self.clone_process(thread, mem, a),
            57 => self.clone_process(thread, mem, [17, 0, 0, 0, 0, 0]),
            58 => self.clone_process(thread, mem, [0x4111, 0, 0, 0, 0, 0]),
            59 => match self.exec(thread, mem, a) {
                Ok(()) => return Some(Next::Resume),
                Err(error) => Err(error),
            },
            61 => self.wait4(thread, mem, a),
            110 => Ok(u64::from(self.processes.parent(self.process.pid))),
            62 => {
                if a[1] > 64 {
                    Err(Errno::EINVAL)
                } else {
                    let pid = if a[0] == 0 {
                        self.process.pid
                    } else {
                        match u32::try_from(a[0]) {
                            Ok(pid) => pid,
                            Err(_) => return Some(self.return_process_error(thread, Errno(3))),
                        }
                    };
                    self.processes.signal(pid, a[1] as i32).map(|()| 0)
                }
            }
            _ => return None,
        };
        thread.cpu.gpr[reg::RAX] = result.unwrap_or_else(Errno::to_syscall_return);
        if n == 61
            && result == Err(Errno(4))
            && signals::next_pending(&thread.state, true)
                .and_then(|index| {
                    thread
                        .state
                        .signal_actions
                        .get(&thread.state.pending[index].number)
                })
                .is_some_and(|action| action.handler > 1 && action.flags & 0x10000000 != 0)
            && let Some(rip) = thread.cpu.rip.0.checked_sub(2)
        {
            thread.cpu.rip = GuestAddr(rip);
            thread.cpu.gpr[reg::RAX] = n;
        }
        Some(self.checkpoint(thread, mem))
    }
    fn return_process_error(&self, thread: &mut Thread, error: Errno) -> Next {
        thread.cpu.gpr[reg::RAX] = error.to_syscall_return();
        Next::Resume
    }
    fn clone_process(
        &mut self,
        parent: &Thread,
        mem: &AddressSpace,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        let flags = a[0];
        let known = 0xff
            | 0x100
            | 0x200
            | 0x400
            | 0x800
            | 0x4000
            | 0x40000
            | 0x80000
            | 0x100000
            | 0x200000
            | 0x400000
            | 0x1000000;
        if flags & 0x800 != 0 && flags & 0x100 == 0 || flags & 0xff > 64 {
            return Err(Errno::EINVAL);
        }
        if flags & !known != 0 {
            return Err(Errno::EINVAL);
        }
        if flags & 0x800 != 0 {
            return Err(Errno::ENOSYS);
        } // Shared dispositions require their own ownership model.
        if a[1] >= paludarium_types::USER_ADDRESS_LIMIT
            || flags & 0x80000 != 0 && a[4] >= paludarium_types::USER_ADDRESS_LIMIT
        {
            return Err(Errno::EPERM);
        }
        let pid = self.processes.allocate()?;
        let group = Arc::new(self.group.fork());
        let inbox = Arc::new(SignalInbox::default());
        group.set_process_inbox(inbox.clone());
        group.register(pid, inbox.clone());
        let mut state = parent.state.clone();
        state.pid = pid;
        state.pending.clear();
        state.frames.clear();
        state.exit_status = None;
        state.timer = signals::RealTimer::default();
        state.clear_child_tid = if flags & 0x200000 != 0 { a[3] } else { 0 };
        if flags & 0x100 != 0 {
            state.alt_stack = crate::AltStack::default();
        }
        let mut cpu = parent.cpu.clone();
        cpu.gpr[reg::RAX] = 0;
        if a[1] != 0 {
            cpu.gpr[reg::RSP] = a[1];
        }
        if flags & 0x80000 != 0 {
            cpu.fs_base = a[4];
        }
        let child_mem = (flags & 0x100 == 0).then(|| Arc::new(mem.fork()));
        if flags & 0x100000 != 0 {
            let _ = mem.write(GuestAddr(a[2]), &pid.to_le_bytes());
        }
        if flags & 0x1000000 != 0 {
            let _ = child_mem
                .as_deref()
                .unwrap_or(mem)
                .write(GuestAddr(a[3]), &pid.to_le_bytes());
        }
        let release = (flags & 0x4000 != 0).then(|| Arc::new(AtomicBool::new(false)));
        self.processes.insert(pid, self.process.pid, group.clone());
        let child = Kernel {
            host: self.host.clone(),
            process: crate::Process { pid },
            table: crate::SyscallTable::u1(),
            files: self.files.for_clone(flags & 0x400 != 0, flags & 0x200 != 0),
            cancellation: inbox.wake_token(),
            inbox,
            group,
            processes: self.processes.clone(),
            pending_child: None,
            spawn_memory: child_mem,
            exec_memory: None,
            vfork_release: release.clone(),
            vfork_wait: None,
            unimplemented: self.unimplemented.clone(),
        };
        self.vfork_wait = release;
        self.pending_child = Some((
            Box::new(child),
            Thread {
                tid: pid,
                cpu,
                state,
            },
        ));
        Ok(u64::from(pid))
    }
    fn wait4(&self, thread: &mut Thread, mem: &AddressSpace, a: [u64; 6]) -> Result<u64, Errno> {
        if a[2] & !(1 | 2 | 8 | 0xe0000000) != 0 {
            return Err(Errno::EINVAL);
        }
        loop {
            if let Some((pid, status)) = self.processes.reap(self.process.pid, a[0] as i64)? {
                let raw = match status {
                    ExitStatus::Exited(code) => (code & 255) << 8,
                    ExitStatus::Signaled(signal) => signal & 127,
                    _ => return Err(Errno::EINVAL),
                };
                // Native wait-fault oracle: Linux consumes the zombie before copyout.
                if a[1] != 0 {
                    mem.write(GuestAddr(a[1]), &raw.to_le_bytes())
                        .map_err(|_| Errno::EFAULT)?;
                }
                if a[3] != 0 {
                    mem.write(GuestAddr(a[3]), &[0; 144])
                        .map_err(|_| Errno::EFAULT)?;
                }
                return Ok(u64::from(pid));
            }
            if a[2] & 1 != 0 {
                return Ok(0);
            }
            self.group.drain_process(&mut thread.state);
            let receipt = self.inbox.drain(&mut thread.state);
            if receipt.interrupted
                || self.group.status().is_some()
                || signals::next_pending(&thread.state, true).is_some()
            {
                return Err(Errno(4));
            }
            let now = self.host.clock(ClockId::Monotonic)?;
            self.host.wait_until(
                ClockId::Monotonic,
                now.saturating_add(10_000_000),
                &self.cancellation,
            )?;
        }
    }
    fn exec(&mut self, thread: &mut Thread, mem: &AddressSpace, a: [u64; 6]) -> Result<(), Errno> {
        let path = read_string(mem, a[0], 4096, Errno::ENAMETOOLONG)?;
        let path = self.files.exec_path(path)?;
        let mut budget = paludarium_loader::MAX_ARG_BYTES as usize;
        let argv = read_vector(mem, a[1], &mut budget)?;
        let envp = read_vector(mem, a[2], &mut budget)?;
        let mut random = [0; 16];
        self.host
            .random_bytes(&mut random)
            .map_err(|_| Errno::EIO)?;
        let start = StartInfo {
            argv: &argv,
            envp: &envp,
            execfn: &path,
            random,
        };
        let mut memory = AddressSpace::new();
        let image = paludarium_loader::load(&*self.files.fs, &path, &start, &mut memory).map_err(
            |error| match error {
                LoadError::NotFound => Errno::ENOENT,
                LoadError::TooLarge => Errno(7),
                LoadError::Errno(error) => error,
                _ => Errno(8),
            },
        )?;
        // All validation precedes retirement. Old siblings must stop touching
        // their image and shared descriptors before the replacement is visible.
        self.group.begin_exec(thread.tid)?;
        while self.group.active_threads() > 1 {
            if self.group.status().is_some() {
                return Err(Errno(4));
            }
            let now = self.host.clock(ClockId::Monotonic)?;
            self.host.wait_until(
                ClockId::Monotonic,
                now.saturating_add(10_000_000),
                &self.cancellation,
            )?;
        }
        self.group
            .end_exec(thread.tid, self.process.pid, Arc::clone(&self.inbox));
        thread.tid = self.process.pid;
        self.files = self.files.for_exec();
        self.group.exec_actions();
        thread.cpu = CpuState::new(image.entry_point, image.initial_stack_pointer);
        let ignored = thread
            .state
            .signal_actions
            .iter()
            .filter(|(_, action)| action.handler == 1)
            .map(|(&number, &action)| (number, action))
            .collect();
        thread.state = ThreadState {
            pid: self.process.pid,
            signal_mask: thread.state.signal_mask,
            signal_actions: ignored,
            ..ThreadState::default()
        };
        self.exec_memory = Some(Arc::new(memory));
        self.release_vfork();
        Ok(())
    }
}
fn read_string(
    mem: &AddressSpace,
    address: u64,
    limit: usize,
    long: Errno,
) -> Result<Vec<u8>, Errno> {
    let mut bytes = Vec::new();
    for offset in 0..limit {
        let mut byte = [0];
        mem.read(
            GuestAddr(address.checked_add(offset as u64).ok_or(Errno::EFAULT)?),
            &mut byte,
        )
        .map_err(|_| Errno::EFAULT)?;
        if byte[0] == 0 {
            return Ok(bytes);
        }
        bytes.push(byte[0]);
    }
    Err(long)
}
fn read_vector(
    mem: &AddressSpace,
    address: u64,
    budget: &mut usize,
) -> Result<Vec<Vec<u8>>, Errno> {
    let mut strings = Vec::new();
    if address == 0 {
        return Ok(strings);
    }
    for index in 0..paludarium_loader::MAX_ARG_BYTES / 8 {
        let pointer = mem
            .read_u64(GuestAddr(
                address.checked_add(index * 8).ok_or(Errno::EFAULT)?,
            ))
            .map_err(|_| Errno::EFAULT)?;
        if pointer == 0 {
            return Ok(strings);
        }
        let value = read_string(mem, pointer, (*budget).min(131072), Errno(7))?;
        *budget = budget.checked_sub(value.len() + 1 + 8).ok_or(Errno(7))?;
        strings.push(value);
    }
    Err(Errno(7))
}
