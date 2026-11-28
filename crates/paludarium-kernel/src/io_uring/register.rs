//! io_uring's disabled rings (`IORING_SETUP_R_DISABLED`), restrictions,
//! a ring's and a task's, and personalities, as Linux's
//! `io_uring/register.c` has them.

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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Restrictions {
    /// The registrations allowed, a bit each.
    register: Option<u64>,
    requests: Option<Requests>,
}

/// The requests allowed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Requests {
    /// Their operations, a bit each.
    ops: u128,
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
    /// (`__io_uring_register`), which they do of a disabled ring, unless it
    /// has them from its task (Linux master's 6da8f402e362, which the test
    /// runners' kernel has).
    pub(super) fn allows_registration(&self, opcode: u64) -> bool {
        self.disabled() && !self.inherited
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
/// none yet (`EBUSY`), which a ring set up with its task's has, then the
/// restrictions as [`parse`] reads them. A failure leaves the ring without
/// any.
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
    *registered = parse(c, arg, count)?;
    Ok(0)
}

/// `io_register_restrictions_task`, `io_uring_register` with descriptor -1:
/// restrictions the thread's rings set up from now on start with, which a
/// new thread or process copies (`io_uring_fork`) and exec keeps. A thread
/// that has them already may not change them (`EPERM`), and one needs
/// `no_new_privs` or `CAP_SYS_ADMIN` (`EACCES`), as for a seccomp filter.
/// Then there must be one argument (`EINVAL`), a `struct
/// io_uring_task_restriction` that is read (`EFAULT`), without flags or
/// reserved bits (`EINVAL`), whose restrictions follow it ([`parse`]).
pub(super) fn register_task_restrictions(
    c: &mut Context<'_>,
    arg: u64,
    count: u32,
) -> Result<u64, Errno> {
    if c.process.io_uring_restrictions.is_some() {
        return Err(Errno::EPERM);
    }
    let no_new_privs = c.processes.status_of(c.process.pid).2;
    if !no_new_privs && c.process.credentials.effective & crate::credentials::CAP_SYS_ADMIN == 0 {
        return Err(Errno::EACCES);
    }
    if count != 1 {
        return Err(Errno::EINVAL);
    }
    let mut head = [0; 16];
    c.mem
        .read(GuestAddr(arg), &mut head)
        .map_err(|_| Errno::EFAULT)?;
    if head[..2] != [0, 0] || head[4..].iter().any(|&b| b != 0) {
        return Err(Errno::EINVAL);
    }
    let entries = u32::from(u16::from_le_bytes([head[2], head[3]]));
    let restrictions = parse(c, arg.wrapping_add(16), entries)?;
    c.process.io_uring_restrictions = Some(Arc::new(restrictions));
    Ok(0)
}

impl Restrictions {
    /// Whether they say which registrations are allowed.
    pub(super) fn restricts_registrations(&self) -> bool {
        self.register.is_some()
    }
}

/// The restrictions a ring the thread sets up starts with: its task's, if
/// it has any (`io_ctx_restriction_clone`).
pub(super) fn of_task(c: &Context<'_>) -> Restrictions {
    c.process
        .io_uring_restrictions
        .as_deref()
        .cloned()
        .unwrap_or_default()
}

/// `io_parse_restrictions`: an argument and at most
/// `IORING_MAX_RESTRICTIONS` of them (`EINVAL`), which are read (`EFAULT`)
/// before any is looked at (`EINVAL` for one unknown). None at all allows
/// nothing.
fn parse(c: &Context<'_>, arg: u64, count: u32) -> Result<Restrictions, Errno> {
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
                new.requests.get_or_insert_default().ops |= 1u128 << value;
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
    Ok(new)
}
