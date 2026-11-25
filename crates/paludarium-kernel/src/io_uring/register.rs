//! io_uring's disabled rings (`IORING_SETUP_R_DISABLED`), restrictions and
//! personalities, as Linux's `io_uring/register.c` has them.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, MutexGuard, PoisonError};

use paludarium_types::{Errno, GuestAddr};

use super::{EBUSY, OP_LAST, REGISTER_LAST, Ring, SETUP_SINGLE_ISSUER};
use crate::credentials::Credentials;
use crate::syscalls::Context;

pub(super) const REGISTER_PERSONALITY: u64 = 9;
pub(super) const UNREGISTER_PERSONALITY: u64 = 10;
pub(super) const REGISTER_RESTRICTIONS: u64 = 11;
pub(super) const REGISTER_ENABLE_RINGS: u64 = 12;

const RESTRICTION_REGISTER_OP: u16 = 0;
const RESTRICTION_SQE_OP: u16 = 1;
const RESTRICTION_SQE_FLAGS_ALLOWED: u16 = 2;
const RESTRICTION_SQE_FLAGS_REQUIRED: u16 = 3;
/// `IORING_MAX_RESTRICTIONS`.
const MAX_RESTRICTIONS: u32 = 4 + REGISTER_LAST as u32 + OP_LAST as u32;

/// The file descriptor is in a bad state.
pub(super) const EBADFD: Errno = Errno(77);
/// The last ID a personality may have.
const PERSONALITY_MAX: u32 = u16::MAX as u32;

/// `struct io_restriction`: each half only once it is registered.
#[derive(Default)]
pub(super) struct Restrictions {
    /// The registrations allowed, a bit each.
    register: Option<u64>,
    requests: Option<Requests>,
}

/// The requests allowed.
#[derive(Clone, Copy, Default)]
struct Requests {
    /// Their operations, a bit each.
    ops: u64,
    flags_allowed: u8,
    flags_required: u8,
}

/// A personality, whose trait keeps the proof that a request is `Send` from
/// going through all its credentials, past the recursion limit of the crates
/// that make a kernel.
pub(super) trait Personality: Send + Sync {
    fn credentials(&self) -> &Credentials;
}
impl Personality for Credentials {
    fn credentials(&self) -> &Credentials {
        self
    }
}

/// `ctx->personalities`, an `xarray` that gives IDs from 1 in turn
/// (`xa_alloc_cyclic`).
#[derive(Default)]
pub(super) struct Personalities {
    credentials: BTreeMap<u32, Arc<dyn Personality>>,
    next: u32,
}

impl Ring {
    fn restrictions(&self) -> MutexGuard<'_, Restrictions> {
        self.restrictions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn personalities(&self) -> MutexGuard<'_, Personalities> {
        self.personalities
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// `IORING_SETUP_R_DISABLED`, until the ring is enabled.
    pub(super) fn disabled(&self) -> bool {
        self.disabled.load(Ordering::SeqCst)
    }

    /// Whether `tid` is not the ring's only submitter (`ctx->submitter_task`).
    pub(super) fn others(&self, tid: u32) -> bool {
        self.submitter.get().is_some_and(|only| *only != tid)
    }

    /// Whether the ring's restrictions allow a registration
    /// (`__io_uring_register`), which they do of a disabled ring.
    pub(super) fn allows_registration(&self, opcode: u64) -> bool {
        self.disabled()
            || self
                .restrictions()
                .register
                .is_none_or(|allowed| allowed & 1 << opcode != 0)
    }

    /// `io_check_restriction`: whether they allow a request.
    pub(super) fn allows_request(&self, opcode: u8, flags: u8) -> bool {
        self.restrictions().requests.is_none_or(|allowed| {
            allowed.ops & 1 << opcode != 0
                && flags & allowed.flags_required == allowed.flags_required
                && flags & !(allowed.flags_allowed | allowed.flags_required) == 0
        })
    }

    /// The credentials of personality `id` (`xa_load`).
    pub(super) fn personality(&self, id: u16) -> Option<Arc<dyn Personality>> {
        self.personalities()
            .credentials
            .get(&u32::from(id))
            .map(Arc::clone)
    }
}

/// `io_register_personality`: the thread's credentials, whose ID it gives.
pub(super) fn register_personality(c: &Context<'_>, ring: &Ring) -> Result<u64, Errno> {
    let mut personalities = ring.personalities();
    let free =
        |from: u32| (from..=PERSONALITY_MAX).find(|id| !personalities.credentials.contains_key(id));
    let id = free(personalities.next.max(1))
        .or_else(|| free(1))
        .ok_or(EBUSY)?;
    personalities.next = id + 1;
    personalities
        .credentials
        .insert(id, Arc::new(c.process.credentials.clone()));
    Ok(u64::from(id))
}

/// `io_unregister_personality`: the requests that have it keep it.
pub(super) fn unregister_personality(ring: &Ring, id: u32) -> Result<u64, Errno> {
    let gone = ring.personalities().credentials.remove(&id);
    gone.map(|_| 0).ok_or(Errno::EINVAL)
}

/// `io_register_enable_rings`: the ring must be disabled (`EBADFD`), and
/// the thread is its only submitter from now on with
/// `IORING_SETUP_SINGLE_ISSUER`.
pub(super) fn enable_rings(c: &Context<'_>, ring: &Ring) -> Result<u64, Errno> {
    if !ring.disabled() {
        return Err(EBADFD);
    }
    if ring.flags & SETUP_SINGLE_ISSUER != 0 {
        let _ = ring.submitter.set(c.tid);
    }
    ring.disabled.store(false, Ordering::SeqCst);
    Ok(0)
}

/// `io_register_restrictions`: the ring must be disabled (`EBADFD`) and have
/// none yet (`EBUSY`), then as `io_parse_restrictions`: an argument and at
/// most `IORING_MAX_RESTRICTIONS` of them (`EINVAL`), which are read
/// (`EFAULT`) before any is looked at (`EINVAL` for one unknown). None at
/// all allows nothing. A failure leaves the ring without any.
pub(super) fn register_restrictions(
    c: &Context<'_>,
    ring: &Ring,
    arg: u64,
    count: u32,
) -> Result<u64, Errno> {
    if !ring.disabled() {
        return Err(EBADFD);
    }
    let mut registered = ring.restrictions();
    if registered.register.is_some() || registered.requests.is_some() {
        return Err(EBUSY);
    }
    if arg == 0 || count > MAX_RESTRICTIONS {
        return Err(Errno::EINVAL);
    }
    let mut entries = vec![0; 16 * count as usize];
    c.mem
        .read(GuestAddr(arg), &mut entries)
        .map_err(|_| Errno::EFAULT)?;
    let mut new = Restrictions::default();
    for entry in entries.as_chunks::<16>().0 {
        let value = entry[2];
        match u16::from_le_bytes([entry[0], entry[1]]) {
            RESTRICTION_REGISTER_OP if u64::from(value) < REGISTER_LAST => {
                *new.register.get_or_insert_default() |= 1 << value;
            }
            RESTRICTION_SQE_OP if value < OP_LAST => {
                new.requests.get_or_insert_default().ops |= 1 << value;
            }
            RESTRICTION_SQE_FLAGS_ALLOWED => {
                new.requests.get_or_insert_default().flags_allowed = value;
            }
            RESTRICTION_SQE_FLAGS_REQUIRED => {
                new.requests.get_or_insert_default().flags_required = value;
            }
            _ => return Err(Errno::EINVAL),
        }
    }
    if count == 0 {
        new.register = Some(0);
        new.requests = Some(Requests::default());
    }
    *registered = new;
    Ok(0)
}
