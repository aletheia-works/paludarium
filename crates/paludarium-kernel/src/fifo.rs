//! FIFOs (named pipes), as Linux's `fifo_open` opens them: every open of one
//! node, in any process, joins the same pipe while some description of it is
//! open, and a new pipe starts once none is. An open for reading waits for a
//! writer and one for writing waits for a reader, unless it is nonblocking
//! (a writer then gets `ENXIO` when there is no reader) or opens both ends.
use crate::sockets::PipeEnd;
use crate::syscalls::Context;
use paludarium_host::{FileHandle, FileStat};
use paludarium_types::Errno;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};

const NONBLOCK: u32 = 0o4000;
const ENXIO: Errno = Errno(6);

/// The FIFOs of the machine, by the device and inode of their node.
#[derive(Default)]
pub(crate) struct Fifos(Mutex<HashMap<(u64, u64), Fifo>>);

#[derive(Default)]
struct Fifo {
    /// The open descriptions of the FIFO's pipe.
    descriptions: Vec<Weak<PipeEnd>>,
    /// How many times it was opened for reading and for writing, which an
    /// open waiting for the other end watches (Linux's `r_counter` and
    /// `w_counter`): an end that opened and closed again still ends the wait.
    readers: u64,
    writers: u64,
}
impl Fifo {
    fn live(&mut self) -> Vec<Arc<PipeEnd>> {
        self.descriptions.retain(|d| d.strong_count() != 0);
        self.descriptions.iter().filter_map(Weak::upgrade).collect()
    }
    /// Whether an open description reads (`reading`) or writes it.
    fn has(&mut self, reading: bool) -> bool {
        self.live().iter().any(|d| match d.flags() & 3 {
            0 => reading,
            1 => !reading,
            _ => true,
        })
    }
}

impl Fifos {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(u64, u64), Fifo>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Opens the FIFO at `path`, whose node, `key` on its device, has the
/// status `node`, with the access and `O_NONBLOCK` of `flags`. Its inotify
/// watches hear of the open once it is done, and later of its close.
pub(crate) fn open(
    c: &mut Context<'_>,
    path: &[u8],
    key: (u64, u64),
    node: &FileStat,
    flags: u32,
) -> Result<Arc<dyn FileHandle>, Errno> {
    let description = join(c, key, node, flags)?;
    if let Some(closing) = crate::inotify::Closing::opened(
        &c.files.caches.notify,
        &c.files.fs,
        path,
        key.0,
        node,
        flags,
    ) {
        description.notify_close(closing);
    }
    Ok(description)
}
/// The description [`open`] makes, once the other end is there.
fn join(
    c: &mut Context<'_>,
    key: (u64, u64),
    node: &FileStat,
    flags: u32,
) -> Result<Arc<PipeEnd>, Errno> {
    let access = flags & 3;
    if access == 3 {
        return Err(Errno::EINVAL);
    }
    let nonblocking = flags & NONBLOCK != 0;
    let fifos = c.processes.fifos();
    let (description, waiting_for) = {
        let mut table = fifos.lock();
        // Forget the FIFOs nothing has open, but this one.
        table.retain(|k, fifo| *k == key || !fifo.live().is_empty());
        let fifo = table.entry(key).or_default();
        // A writer that would wait for a reader that is not there: ENXIO.
        if access == 1 && nonblocking && !fifo.has(true) {
            return Err(ENXIO);
        }
        let description = match fifo.live().first() {
            Some(open) => open.open_again(flags)?,
            None => {
                let [reader, _] = PipeEnd::fifo(node, Arc::clone(&c.files.readiness))?;
                reader.open_again(flags)?
            }
        };
        if access != 1 {
            fifo.readers += 1;
        }
        if access != 0 {
            fifo.writers += 1;
        }
        fifo.descriptions.push(Arc::downgrade(&description));
        // Reading waits for a writer, and writing for a reader, unless the
        // other end is open now or the open does not block.
        let waiting_for = match access {
            0 if !nonblocking && !fifo.has(false) => Some((false, fifo.writers)),
            1 if !fifo.has(true) => Some((true, fifo.readers)),
            _ => None,
        };
        (description, waiting_for)
    };
    let Some((reader, seen)) = waiting_for else {
        return Ok(description);
    };
    loop {
        {
            let mut table = fifos.lock();
            let fifo = table.entry(key).or_default();
            let count = if reader { fifo.readers } else { fifo.writers };
            if count != seen || fifo.has(reader) {
                return Ok(description);
            }
        }
        // A signal ends the wait, and the description with it.
        crate::files::pause_for_lock(c)?;
    }
}
