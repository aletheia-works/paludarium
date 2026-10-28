//! The WebAssembly network driver: the launcher's coordinator owns the real
//! sockets (Node.js `net` and `dns`) and drives each stream and lookup
//! through the module's exports, by the handle it was given. The imports
//! here only tell it, by handle and with bytes copied out of host buffers,
//! what the kernel asked for.
use crate::net::{Driver, Lookup, Stream, UNREACHABLE};
use core::net::SocketAddr;
use paludarium_types::Errno;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

#[link(wasm_import_module = "paludarium")]
unsafe extern "C" {
    fn net_open(id: u32, address: *const u8, length: usize) -> i32;
    fn net_resolve(id: u32, name: *const u8, length: usize) -> i32;
    fn net_kick(id: u32);
    fn net_nodelay(id: u32, on: u32);
}

enum Entry {
    Stream(Arc<Stream>),
    Lookup(Arc<Lookup>),
}
static NEXT: AtomicU32 = AtomicU32::new(1);
static ENTRIES: Mutex<BTreeMap<u32, Entry>> = Mutex::new(BTreeMap::new());

fn register(entry: Entry) -> Result<u32, Errno> {
    let id = NEXT
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
        .map_err(|_| Errno::EAGAIN)?;
    ENTRIES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(id, entry);
    Ok(id)
}
/// The stream of handle `id`, while the coordinator holds it.
#[must_use]
pub fn stream(id: u32) -> Option<Arc<Stream>> {
    match ENTRIES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
    {
        Some(Entry::Stream(stream)) => Some(Arc::clone(stream)),
        _ => None,
    }
}
/// The lookup of handle `id`, until it is answered.
#[must_use]
pub fn lookup(id: u32) -> Option<Arc<Lookup>> {
    match ENTRIES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
    {
        Some(Entry::Lookup(lookup)) => Some(Arc::clone(lookup)),
        _ => None,
    }
}
/// Forgets handle `id`: the coordinator is done with its socket or lookup.
pub fn release(id: u32) {
    ENTRIES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&id);
}

struct Coordinated(u32);
impl Driver for Coordinated {
    fn kick(&self) {
        // SAFETY: a scalar handle only; the coordinator reads the stream
        // through the exports.
        unsafe { net_kick(self.0) }
    }
    fn set_nodelay(&self, on: bool) {
        // SAFETY: scalars only.
        unsafe { net_nodelay(self.0, u32::from(on)) }
    }
}

pub(crate) fn connect(address: SocketAddr) -> Result<Arc<Stream>, Errno> {
    let stream = Stream::new(address);
    let id = register(Entry::Stream(Arc::clone(&stream)))?;
    stream.set_driver(Arc::new(Coordinated(id)));
    let text = address.to_string();
    // SAFETY: the import copies `text`, a live host string, before it returns.
    if unsafe { net_open(id, text.as_ptr(), text.len()) } != 0 {
        release(id);
        return Err(UNREACHABLE);
    }
    Ok(stream)
}

pub(crate) fn resolve(name: &str) -> Result<Arc<Lookup>, Errno> {
    let lookup = Lookup::new();
    let id = register(Entry::Lookup(Arc::clone(&lookup)))?;
    // SAFETY: as in `connect`, the import copies the live host string.
    if unsafe { net_resolve(id, name.as_ptr(), name.len()) } != 0 {
        release(id);
        return Err(UNREACHABLE);
    }
    Ok(lookup)
}
