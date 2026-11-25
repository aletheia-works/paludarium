//! io_uring's polls, as Linux master's `io_uring/poll.c` has them:
//! `IORING_OP_POLL_ADD` and `_POLL_REMOVE`.
//!
//! A poll that waits is looked at with the requests that wait for their
//! files ([`super::complete_ready`]). Its file's generations stand for the
//! wake-ups Linux gives it ([`FileHandle::readiness`]), and what it reports
//! of one is the wake-up's key ([`crate::aio::woken`]).

use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};

use paludarium_host::FileHandle;
use paludarium_types::Errno;

use super::{
    Armed, Deferred, Done, EALREADY, ECANCELED, IOSQE_CQE_SKIP_SUCCESS, Node, Polls, Request, Ring,
    Work, add_work, fail_request, file_of, finish, flush_batch, issue_link, ready, u16_at, u32_at,
    u64_at, wake,
};
use crate::aio;
use crate::syscalls::Context;

pub(super) const OP_POLL_ADD: u8 = 6;
pub(super) const OP_POLL_REMOVE: u8 = 7;

/// `IORING_POLL_*`, in `len`.
const ADD_MULTI: u32 = 1 << 0;
const UPDATE_EVENTS: u32 = 1 << 1;
const UPDATE_USER_DATA: u32 = 1 << 2;

/// `IORING_CQE_F_MORE`: the request posts more completions.
const CQE_F_MORE: u32 = 1 << 1;

const POLLIN: u32 = 0x1;
const POLLOUT: u32 = 0x4;
/// The events a wake-up for input or output tells of.
const INPUT: u32 = POLLIN | 0x2 | 0x40 | 0x80;
const OUTPUT: u32 = POLLOUT | 0x100 | 0x200;
/// `POLLERR | POLLHUP | POLLNVAL | POLLRDHUP`, whose wake-ups carry no key.
const ENDS: u32 = 0x8 | 0x10 | 0x20 | POLLRDHUP;
const POLLRDHUP: u32 = 0x2000;
/// The events `demangle_poll` knows.
const KNOWN: u32 = 0x27ff;
const EPOLLEXCLUSIVE: u32 = 1 << 28;
const EPOLLONESHOT: u32 = 1 << 30;
const EPOLLET: u32 = 1 << 31;

/// An `IORING_OP_POLL_ADD` (`struct io_poll`): its descriptor, its events
/// with `EPOLLONESHOT` unless it is multishot, and the file it found.
pub(super) struct Poll {
    fd: i32,
    fixed: bool,
    events: u32,
    found: Option<crate::files::Descriptor>,
}

impl Poll {
    fn mask(&self) -> u32 {
        self.events & KNOWN
    }
}

/// An `IORING_OP_POLL_REMOVE` (`struct io_poll_update`).
pub(super) struct Remove {
    old: u64,
    events: Option<u32>,
    user_data: Option<u64>,
}

/// How a poll waits (`Armed`): whether it is multishot, and for one that
/// is, its file's generations and events when it last looked, and what a
/// wake-up since gave that its task work has not seen: the events of the
/// first, or 0 after more, which has it look again (`io_poll_check_events`).
pub(super) struct Watch {
    multi: bool,
    seen: (u64, u64),
    previous: u32,
    woken: Option<u32>,
}

impl Watch {
    /// Its task work is queued, which a cancellation leaves it to
    /// (`io_poll_get_ownership`).
    pub(super) fn queued(&self) -> bool {
        self.woken.is_some()
    }
}

/// What a look at a request that waits found ([`look`]).
pub(super) enum Look {
    /// It waits on.
    Waits,
    /// It goes on as this task work, and waits no more.
    Goes,
    /// A multishot poll has events: its task work, and it waits on.
    More,
}

/// `io_poll_unmask`: the events that end any poll. A peer that stopped
/// sending is one for a reader.
fn unmask(events: u32) -> u32 {
    if events & (POLLIN | 0x40 | 0x80) != 0 {
        ENDS
    } else {
        ENDS & !POLLRDHUP
    }
}

/// `io_poll_parse_events`.
fn parse_events(sqe: &[u8], flags: u32) -> u32 {
    let mut events = u32_at(sqe, 28) | EPOLLET;
    if flags & ADD_MULTI == 0 {
        events |= EPOLLONESHOT;
    }
    events & (KNOWN | EPOLLEXCLUSIVE | EPOLLONESHOT | EPOLLET)
}

/// `io_poll_add_prep` and `io_poll_remove_prep`.
pub(super) fn prepare(opcode: u8, sqe_flags: u8, fixed: bool, sqe: &[u8]) -> Result<Work, Errno> {
    let flags = u32_at(sqe, 24);
    let (off, addr) = (u64_at(sqe, 8), u64_at(sqe, 16));
    if u16_at(sqe, 40) != 0 {
        return Err(Errno::EINVAL);
    }
    if opcode == OP_POLL_ADD {
        if off != 0
            || addr != 0
            || flags & !ADD_MULTI != 0
            || flags & ADD_MULTI != 0 && sqe_flags & IOSQE_CQE_SKIP_SUCCESS != 0
        {
            return Err(Errno::EINVAL);
        }
        return Ok(Work::Poll(Box::new(Poll {
            fd: u32_at(sqe, 4) as i32,
            fixed,
            events: {
                let events = parse_events(sqe, flags);
                events | unmask(events)
            },
            found: None,
        })));
    }
    if u32_at(sqe, 44) != 0
        || flags & !(UPDATE_EVENTS | UPDATE_USER_DATA | ADD_MULTI) != 0
        || flags == ADD_MULTI
        || flags & UPDATE_USER_DATA == 0 && off != 0
        || flags & UPDATE_EVENTS == 0 && u32_at(sqe, 28) != 0
    {
        return Err(Errno::EINVAL);
    }
    Ok(Work::PollRemove(Box::new(Remove {
        old: addr,
        events: (flags & UPDATE_EVENTS != 0).then(|| parse_events(sqe, flags)),
        user_data: (flags & UPDATE_USER_DATA != 0).then_some(off),
    })))
}

/// `io_poll_add`: the first request of `chain` polls its file, and
/// completes, or waits for it. `held` is what it held as it waited before.
pub(super) fn add(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    ring: &Ring,
    mut chain: Vec<Request>,
    held: Vec<Arc<Node>>,
) {
    let mark = {
        let mut state = ring.state();
        let mark = state.held.len();
        state.held.extend(held);
        mark
    };
    let Work::Poll(poll) = &mut chain[0].work else {
        return;
    };
    let found = match &poll.found {
        Some(found) => Ok(found.clone()),
        None => file_of(c, ring, poll.fd, poll.fixed),
    };
    let found = match found {
        Ok(found) => found,
        Err(e) => {
            fail_request(ring, chain, e);
            return;
        }
    };
    poll.found = Some(found.clone());
    let mask = poll.mask();
    let held = {
        let mut state = ring.state();
        let at = mark.min(state.held.len());
        state.held.split_off(at)
    };
    let armed = Armed {
        id: 0,
        ring: Arc::downgrade(file),
        inbox: Arc::clone(c.inbox),
        hub: Arc::clone(&c.files.readiness),
        polled: found.file,
        mask,
        chain,
        held,
        watch: None,
    };
    if let Err((res, armed)) = start(c, file, ring, armed) {
        ring.state().held.extend(armed.held);
        match res {
            Ok(events) => complete(ring, armed.chain, events, 0),
            Err(e) => fail_request(ring, armed.chain, e),
        }
    }
}

/// `__io_arm_poll_handler`: a poll of a file that has events already
/// completes with them unless it is multishot, and one of a file without
/// `poll` does either way (`EINVAL` without any). Else it waits, a multishot
/// one with its first events as task work.
#[allow(clippy::result_large_err, clippy::type_complexity)]
fn start(
    c: &Context<'_>,
    file: &Arc<dyn FileHandle>,
    ring: &Ring,
    mut armed: Armed,
) -> Result<(), (Result<u32, Errno>, Armed)> {
    let Some(Work::Poll(poll)) = armed.chain.first().map(|r| &r.work) else {
        return Ok(());
    };
    let multi = poll.events & EPOLLONESHOT == 0;
    let seen = generations(&armed.polled);
    let (events, queues) = aio::polled(&armed.polled);
    let found = events & armed.mask;
    if queues == 0 {
        let res = if found != 0 {
            Ok(found)
        } else {
            Err(Errno::EINVAL)
        };
        return Err((res, armed));
    }
    if found != 0 && !multi {
        return Err((Ok(found), armed));
    }
    let polls = &c.processes.io_uring;
    let id = ring.hash(&armed.chain[0], &armed.polled, &armed.inbox);
    armed.id = id;
    armed.watch = Some(Watch {
        multi,
        seen,
        previous: events,
        woken: (found != 0).then_some(found),
    });
    let (inbox, hub) = (Arc::clone(&armed.inbox), Arc::clone(&armed.hub));
    let (polled, mask) = (Arc::clone(&armed.polled), armed.mask);
    polls
        .armed
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(armed);
    polls.count.fetch_add(1, Ordering::SeqCst);
    if found != 0 {
        let other = !Arc::ptr_eq(&inbox, c.inbox);
        add_work(
            polls,
            file,
            ring,
            &inbox,
            other.then_some(&*hub),
            Deferred::PollMore { id },
        );
    }
    // What became ready in between, as for `arm`.
    if multi && generations(&polled) != seen || !multi && ready(&polled, mask) {
        wake(polls);
    }
    Ok(())
}

fn generations(file: &Arc<dyn FileHandle>) -> (u64, u64) {
    file.readiness()
        .map_or((0, 0), |(_, input, output)| (input, output))
}

/// `io_poll_wake`: whether a wake-up came for the request `armed`, and its
/// task work.
pub(super) fn look(armed: &mut Armed) -> Look {
    let Some(watch) = &mut armed.watch else {
        return if ready(&armed.polled, armed.mask) {
            Look::Goes
        } else {
            Look::Waits
        };
    };
    if !watch.multi {
        let found = aio::polled(&armed.polled).0 & armed.mask;
        if found == 0 {
            return Look::Waits;
        }
        watch.woken = Some(if found & ENDS != 0 {
            0
        } else {
            aio::woken(&armed.polled, found, armed.mask) & armed.mask
        });
        return Look::Goes;
    }
    let now = generations(&armed.polled);
    if armed.polled.keyed_wakeups() && !crate::syscalls::woke(armed.mask, watch.seen, now) {
        watch.seen = now;
        return Look::Waits;
    }
    let events = aio::polled(&armed.polled).0;
    let found = events & armed.mask;
    let rose = found & !watch.previous;
    let input = found & INPUT != 0 && (now.0 != watch.seen.0 || rose & INPUT != 0);
    let output = found & OUTPUT != 0 && (now.1 != watch.seen.1 || rose & OUTPUT != 0);
    watch.seen = now;
    watch.previous = events;
    let key = if rose & ENDS != 0 || input && output {
        found
    } else if input {
        aio::woken(&armed.polled, found & !OUTPUT, armed.mask) & armed.mask
    } else if output {
        aio::woken(&armed.polled, found & !INPUT, armed.mask) & armed.mask
    } else {
        return Look::Waits;
    };
    // A poll of a ring that its own completions may wake reports once
    // (`EPOLL_URING_WAKE`).
    if armed.polled.as_any().is_some_and(|any| any.is::<Ring>()) && watch.woken.is_none() {
        watch.woken = Some(key);
        return Look::Goes;
    }
    if watch.woken.is_some() {
        watch.woken = Some(0);
        return Look::Waits;
    }
    watch.woken = Some(key);
    Look::More
}

/// `io_poll_task_func` for a poll that waits no more: it was cancelled, or
/// completes with the events of its wake-up, those its file has now if that
/// carried no key, or waits again with none.
pub(super) fn finished(c: &mut Context<'_>, file: &Arc<dyn FileHandle>, ring: &Ring, armed: Armed) {
    if ring.unhash(armed.id) {
        cancelled(ring, armed);
        return;
    }
    let woken = armed.watch.and_then(|watch| watch.woken).unwrap_or(0);
    let events = if woken != 0 {
        woken
    } else {
        aio::polled(&armed.polled).0 & armed.mask
    };
    if events == 0 {
        issue_link(c, file, ring, armed.chain, armed.held);
        return;
    }
    ring.state().held.extend(armed.held);
    complete(ring, armed.chain, events, 0);
}

/// `io_poll_task_func` for a multishot poll that waits on: it posts the
/// events of its wake-ups (`IORING_CQE_F_MORE`), and completes with them if
/// the queue has no room, or with `ECANCELED` if it was cancelled.
pub(super) fn more(c: &mut Context<'_>, file: &Arc<dyn FileHandle>, ring: &Ring, id: u64) {
    if ring.is_cancelled(id) {
        end(&c.processes.io_uring, ring, id);
        return;
    }
    let (woken, polled, mask, user_data) = {
        let mut armed = armed(&c.processes.io_uring);
        let Some(armed) = armed.iter_mut().find(|a| a.is(ring, id)) else {
            return;
        };
        let woken = armed.watch.as_mut().and_then(|w| w.woken.take());
        (
            woken.unwrap_or(0),
            Arc::clone(&armed.polled),
            armed.mask,
            armed.chain[0].user_data,
        )
    };
    let events = if woken != 0 {
        woken
    } else {
        aio::polled(&polled).0 & mask
    };
    if events == 0 {
        return;
    }
    // The completions of the batch go first (`io_req_post_cqe`).
    flush_batch(c, file, ring);
    ring.begin();
    if ring.post_aux(user_data, events as i32, CQE_F_MORE) {
        return;
    }
    if let Some(armed) = take(&c.processes.io_uring, ring, id) {
        ring.unhash(id);
        ring.state().held.extend(armed.held);
        complete(ring, armed.chain, events, 0);
    }
}

/// A multishot poll whose task work was queued ends with `ECANCELED`.
pub(super) fn end(polls: &Polls, ring: &Ring, id: u64) {
    if let Some(armed) = take(polls, ring, id) {
        ring.unhash(id);
        cancelled(ring, armed);
    }
}

pub(super) fn cancelled(ring: &Ring, armed: Armed) {
    ring.state().held.extend(armed.held);
    fail_request(ring, armed.chain, ECANCELED);
}

fn complete(ring: &Ring, mut chain: Vec<Request>, events: u32, flags: u32) {
    let request = chain.remove(0);
    ring.complete(finish(
        Done {
            user_data: request.user_data,
            res: events as i32,
            flags,
            post: true,
            ltimeout: request.ltimeout,
            next: Vec::new(),
        },
        request.flags,
        false,
        chain,
    ));
}

fn armed(polls: &Polls) -> std::sync::MutexGuard<'_, Vec<Armed>> {
    polls.armed.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Takes a request from those that wait.
fn take(polls: &Polls, ring: &Ring, id: u64) -> Option<Armed> {
    let mut armed = armed(polls);
    let at = armed.iter().position(|a| a.is(ring, id))?;
    let found = armed.remove(at);
    polls.count.store(armed.len(), Ordering::SeqCst);
    Some(found)
}

/// `io_poll_remove`: the latest poll of `user_data` that waits stops and
/// completes with `ECANCELED`, or polls again with its new events and
/// `user_data`: `ENOENT` for none, `EALREADY` for one whose task work is
/// queued.
pub(super) fn remove(
    c: &Context<'_>,
    file: &Arc<dyn FileHandle>,
    ring: &Ring,
    remove: &Remove,
) -> Result<u64, Errno> {
    let polls = &c.processes.io_uring;
    let id = ring.find_poll(remove.old).ok_or(Errno::ENOENT)?;
    if armed(polls)
        .iter()
        .find(|a| a.is(ring, id))
        .is_none_or(|a| a.watch.as_ref().is_none_or(Watch::queued))
    {
        return Err(EALREADY);
    }
    let mut found = take(polls, ring, id).ok_or(EALREADY)?;
    ring.unhash(id);
    let (inbox, hub) = (Arc::clone(&found.inbox), Arc::clone(&found.hub));
    let mut res = Err(ECANCELED);
    if remove.events.is_some() || remove.user_data.is_some() {
        if let Some(data) = remove.user_data {
            found.chain[0].user_data = data;
        }
        if let (Some(events), Work::Poll(poll)) = (remove.events, &mut found.chain[0].work) {
            // Its behaviour flags stay.
            poll.events = poll.events & !0xffff | events & 0xffff;
            poll.events |= unmask(poll.events);
            found.mask = poll.mask();
        }
        match start(c, file, ring, found) {
            Ok(()) => return Ok(0),
            Err((again, armed)) => {
                found = armed;
                res = again.map_err(|_| ECANCELED);
            }
        }
    }
    let request = found.chain.remove(0);
    let other = !Arc::ptr_eq(&inbox, c.inbox);
    add_work(
        polls,
        file,
        ring,
        &inbox,
        other.then_some(&*hub),
        Deferred::Complete {
            done: Done {
                user_data: request.user_data,
                res: res.map_or_else(|e| -e.0, |events| events as i32),
                flags: 0,
                post: true,
                ltimeout: request.ltimeout,
                next: Vec::new(),
            },
            held: found.held,
            rest: found.chain,
            flags: request.flags,
            failed: res.is_err(),
        },
    );
    Ok(0)
}
