//! io_uring's timeouts, as Linux master's `io_uring/timeout.c` has them:
//! `IORING_OP_TIMEOUT`, `_TIMEOUT_REMOVE` and `_LINK_TIMEOUT`.
//!
//! A timer expires at the checkpoints that let the requests that wait for
//! their files go on ([`super::complete_ready`]), as task work of the
//! thread that submitted it, as Linux's timer does from its interrupt.

use std::cmp::Reverse;
use std::sync::atomic::Ordering;
use std::sync::{Arc, MutexGuard, PoisonError};

use paludarium_host::{ClockId, FileHandle, Host};
use paludarium_types::{Errno, GuestAddr};

use super::{
    CANCEL_FD, CQE_F_MORE, CancelKey, Deferred, Done, ECANCELED, ETIME, Hashed, Polls, Request,
    Ring, Work, add_work, cancel, cancel_matches, downcast, finish, int_at, live_rings, u16_at,
    u32_at, u64_at,
};
use crate::syscalls::Context;

pub(super) const OP_TIMEOUT: u8 = 11;
pub(super) const OP_TIMEOUT_REMOVE: u8 = 12;
pub(super) const OP_LINK_TIMEOUT: u8 = 15;

/// `IORING_TIMEOUT_*`, the flags in `timeout_flags`.
const ABS: u32 = 1 << 0;
const UPDATE: u32 = 1 << 1;
const BOOTTIME: u32 = 1 << 2;
const REALTIME: u32 = 1 << 3;
const LINK_UPDATE: u32 = 1 << 4;
const ETIME_SUCCESS: u32 = 1 << 5;
const MULTISHOT: u32 = 1 << 6;
const IMMEDIATE_ARG: u32 = 1 << 7;
const CLOCK_MASK: u32 = BOOTTIME | REALTIME;
const UPDATE_MASK: u32 = UPDATE | LINK_UPDATE;

const KTIME_MAX: u64 = i64::MAX as u64;

/// An `IORING_OP_TIMEOUT` or `_LINK_TIMEOUT` (`struct io_timeout` and
/// `io_timeout_data`): where its time is, or the time itself with
/// `IORING_TIMEOUT_IMMEDIATE_ARG`, then the time, its flags, the
/// completions it waits for, and how often a multishot one still expires.
pub(super) struct Timeout {
    arg: u64,
    time: u64,
    flags: u32,
    off: u32,
    repeats: u32,
}

impl Timeout {
    /// `io_is_timeout_noseq`: it waits for no number of completions.
    fn noseq(&self) -> bool {
        self.off == 0 || self.flags & MULTISHOT != 0
    }

    /// `io_timeout_finish`: whether this expiry is its last.
    fn finishes(&mut self) -> bool {
        if self.flags & MULTISHOT == 0 {
            return true;
        }
        if self.off == 0 {
            return false;
        }
        if self.repeats != 0 {
            self.repeats -= 1;
            return self.repeats == 0;
        }
        true
    }
}

/// An `IORING_OP_TIMEOUT_REMOVE`: the `user_data` it looks for, and with an
/// update where its new time is, and the time.
pub(super) struct Remove {
    user_data: u64,
    flags: u32,
    arg: u64,
    time: u64,
}

/// When an armed timer expires, on its clock.
#[derive(Clone, Copy)]
struct Expiry {
    clock: ClockId,
    at: u64,
}

impl Expiry {
    /// `hrtimer_start`: a relative time is from now, on the monotonic clock
    /// whichever the timer's is (`__hrtimer_setup`), and an absolute one on
    /// the timer's. The machine is never suspended, so `CLOCK_BOOTTIME` is
    /// `CLOCK_MONOTONIC`.
    fn new(host: &dyn Host, timer_flags: u32, abs: bool, time: u64) -> Self {
        if abs {
            let clock = if timer_flags & REALTIME != 0 {
                ClockId::Realtime
            } else {
                ClockId::Monotonic
            };
            return Self { clock, at: time };
        }
        let now = host.clock(ClockId::Monotonic).unwrap_or(0);
        Self {
            clock: ClockId::Monotonic,
            at: now.saturating_add(time).min(KTIME_MAX),
        }
    }
}

/// The clocks at one time.
struct Now {
    monotonic: u64,
    realtime: u64,
}

impl Now {
    fn of(host: &dyn Host) -> Self {
        Self {
            monotonic: host.clock(ClockId::Monotonic).unwrap_or(0),
            realtime: host.clock(ClockId::Realtime).unwrap_or(0),
        }
    }

    /// How long ago `expiry` was, if it was.
    fn late(&self, expiry: Expiry) -> Option<u64> {
        let now = match expiry.clock {
            ClockId::Realtime => self.realtime,
            ClockId::Monotonic => self.monotonic,
        };
        now.checked_sub(expiry.at)
    }

    /// `expiry` on the monotonic clock.
    fn monotonic(&self, expiry: Expiry) -> u64 {
        match expiry.clock {
            ClockId::Realtime => self
                .monotonic
                .saturating_add(expiry.at.saturating_sub(self.realtime)),
            ClockId::Monotonic => expiry.at,
        }
    }
}

/// A ring's timeouts (`ctx->timeout_list`, `ctx->ltimeout_list`,
/// `ctx->cq_timeouts`, `ctx->cq_last_tm_flush`, `ctx->off_timeout_used`).
#[derive(Default)]
pub(super) struct Timeouts {
    list: Vec<Armed>,
    links: Vec<Link>,
    expired: u32,
    last_flush: u32,
    off_used: bool,
    next: u64,
}

/// An armed `IORING_OP_TIMEOUT`, the first of `chain`.
struct Armed {
    expiry: Expiry,
    target: u32,
    inbox: Arc<crate::SignalInbox>,
    hub: Arc<crate::events::ReadinessHub>,
    chain: Vec<Request>,
}

impl Armed {
    fn timeout(&self) -> Option<&Timeout> {
        match self.chain.first().map(|r| &r.work) {
            Some(Work::Timeout(timeout)) => Some(timeout),
            _ => None,
        }
    }

    fn noseq(&self) -> bool {
        self.timeout().is_none_or(Timeout::noseq)
    }
}

/// An armed `IORING_OP_LINK_TIMEOUT`, and the `user_data` of the request it
/// is for (`timeout->head`), which holds its `id` ([`Request::ltimeout`]).
struct Link {
    id: u64,
    expiry: Expiry,
    inbox: Arc<crate::SignalInbox>,
    hub: Arc<crate::events::ReadinessHub>,
    request: Request,
    head: u64,
}

impl Ring {
    fn timeouts(&self) -> MutexGuard<'_, Timeouts> {
        self.timeouts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The completions posted, but for those of timeouts
    /// (`cached_cq_tail - cq_timeouts`).
    fn sequence(&self, timeouts: &Timeouts) -> u32 {
        self.state().cq_tail.wrapping_sub(timeouts.expired)
    }
}

/// How many of the ring's timeouts expired, came to their number of
/// completions or were cancelled (`ctx->cq_timeouts`), a change of which
/// ends a wait for completions.
pub(super) fn done(ring: &Ring) -> u32 {
    ring.timeouts().expired
}

/// `io_timeout_prep`, `io_link_timeout_prep` and `io_timeout_remove_prep`,
/// but for the time they read ([`prepare_memory`]).
pub(super) fn prepare(opcode: u8, fixed: bool, sqe: &[u8]) -> Result<Work, Errno> {
    let remove = opcode == OP_TIMEOUT_REMOVE;
    if remove && fixed {
        return Err(Errno::EINVAL);
    }
    if u64_at(sqe, 48) != 0 || u64_at(sqe, 56) != 0 {
        return Err(Errno::EINVAL);
    }
    let len = u32_at(sqe, 24);
    if u16_at(sqe, 40) != 0 || len != u32::from(!remove) || int_at(sqe, 44) != 0 {
        return Err(Errno::EINVAL);
    }
    let flags = u32_at(sqe, 28);
    let clocks = flags & CLOCK_MASK;
    if remove {
        if flags & UPDATE_MASK != 0 {
            if clocks == CLOCK_MASK || flags & !(UPDATE_MASK | ABS | IMMEDIATE_ARG) != 0 {
                return Err(Errno::EINVAL);
            }
        } else if flags != 0 {
            return Err(Errno::EINVAL);
        }
        return Ok(Work::TimeoutRemove(Box::new(Remove {
            user_data: u64_at(sqe, 16),
            flags,
            arg: u64_at(sqe, 8),
            time: 0,
        })));
    }
    let off = u32_at(sqe, 8);
    if off != 0 && opcode == OP_LINK_TIMEOUT {
        return Err(Errno::EINVAL);
    }
    if flags & !(ABS | CLOCK_MASK | ETIME_SUCCESS | MULTISHOT | IMMEDIATE_ARG) != 0
        || clocks == CLOCK_MASK
        || flags & (MULTISHOT | ABS) == MULTISHOT | ABS
    {
        return Err(Errno::EINVAL);
    }
    Ok(Work::Timeout(Box::new(Timeout {
        arg: u64_at(sqe, 16),
        time: 0,
        flags,
        off,
        repeats: if flags & MULTISHOT != 0 { off } else { 0 },
    })))
}

/// `io_parse_user_time`: the time at `arg` (`EFAULT`), or `arg` itself in
/// nanoseconds with `IORING_TIMEOUT_IMMEDIATE_ARG`, neither negative
/// (`EINVAL`). No time namespace has an offset.
fn parse_time(c: &Context<'_>, arg: u64, flags: u32) -> Result<u64, Errno> {
    if flags & IMMEDIATE_ARG != 0 {
        return if (arg as i64) < 0 {
            Err(Errno::EINVAL)
        } else {
            Ok(arg)
        };
    }
    let mut bytes = [0; 16];
    c.mem
        .read(GuestAddr(arg), &mut bytes)
        .map_err(|_| Errno::EFAULT)?;
    let (seconds, nanos) = (u64_at(&bytes, 0), u64_at(&bytes, 8));
    if (seconds as i64) < 0 || (nanos as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    Ok(seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(nanos)
        .min(KTIME_MAX))
}

/// What the preparation reads of the program's memory.
pub(super) fn prepare_memory(
    c: &Context<'_>,
    ring: &Ring,
    timeout: &mut Timeout,
) -> Result<(), Errno> {
    if timeout.off != 0 {
        ring.timeouts().off_used = true;
    }
    timeout.time = parse_time(c, timeout.arg, timeout.flags)?;
    Ok(())
}

/// As [`prepare_memory`], of an update.
pub(super) fn prepare_update(c: &Context<'_>, remove: &mut Remove) -> Result<(), Errno> {
    if remove.flags & UPDATE_MASK != 0 {
        remove.time = parse_time(c, remove.arg, remove.flags)?;
    }
    Ok(())
}

/// `io_timeout`: the timeout, the first of `chain`, waits for its time or
/// for the number of completions it asked for, the list kept in the order
/// those are due.
pub(super) fn arm(c: &Context<'_>, ring: &Ring, chain: Vec<Request>) {
    let Some(Work::Timeout(timeout)) = chain.first().map(|r| &r.work) else {
        return;
    };
    let expiry = Expiry::new(
        c.host,
        timeout.flags,
        timeout.flags & ABS != 0,
        timeout.time,
    );
    let (noseq, off) = (timeout.noseq(), timeout.off);
    let mut armed = Armed {
        expiry,
        target: 0,
        inbox: Arc::clone(c.inbox),
        hub: Arc::clone(&c.files.readiness),
        chain,
    };
    {
        let mut timeouts = ring.timeouts();
        if noseq {
            timeouts.list.push(armed);
        } else {
            let mut tail = ring.sequence(&timeouts);
            if timeouts.list.first().is_none_or(Armed::noseq) {
                timeouts.last_flush = tail;
            }
            let base = timeouts.last_flush;
            if (tail.wrapping_sub(base) as i32) < 0 {
                tail = base;
            }
            armed.target = tail.wrapping_add(off);
            let due = armed.target.wrapping_sub(base);
            let at = timeouts
                .list
                .iter()
                .rposition(|next| !next.noseq() && due >= next.target.wrapping_sub(base))
                .map_or(0, |at| at + 1);
            timeouts.list.insert(at, armed);
        }
    }
    started(&c.processes.io_uring);
}

/// Notes that a timer is armed.
fn started(polls: &Polls) {
    polls.timers.store(true, Ordering::SeqCst);
}

/// `io_queue_linked_timeout`: the timer of `request`, linked to a request of
/// `user_data` `head`, starts, and gives its ID, which that request holds.
pub(super) fn arm_link(c: &Context<'_>, ring: &Ring, request: Request, head: u64) -> Option<u64> {
    let Work::Timeout(timeout) = &request.work else {
        return None;
    };
    let expiry = Expiry::new(
        c.host,
        timeout.flags,
        timeout.flags & ABS != 0,
        timeout.time,
    );
    let id = {
        let mut timeouts = ring.timeouts();
        let id = timeouts.next;
        timeouts.next += 1;
        timeouts.links.push(Link {
            id,
            expiry,
            inbox: Arc::clone(c.inbox),
            hub: Arc::clone(&c.files.readiness),
            request,
            head,
        });
        id
    };
    started(&c.processes.io_uring);
    Some(id)
}

/// `__io_disarm_linked_timeout`: the request of linked timeout `id` is done,
/// so its timer stops and it completes with `ECANCELED`; nothing for one
/// that expired.
pub(super) fn disarm(ring: &Ring, id: u64) -> Option<Deferred> {
    let mut timeouts = ring.timeouts();
    let at = timeouts.links.iter().position(|l| l.id == id)?;
    let link = timeouts.links.remove(at);
    drop(timeouts);
    Some(canceled(link.request))
}

/// A linked timeout whose request was done first: it completes with
/// `ECANCELED`, without failing (`io_req_queue_tw_complete`).
pub(super) fn canceled(request: Request) -> Deferred {
    complete(vec![request], -ECANCELED.0, false)
}

/// Task work that completes the first of `chain`.
fn complete(mut chain: Vec<Request>, res: i32, failed: bool) -> Deferred {
    let request = chain.remove(0);
    Deferred::Complete {
        done: Done {
            user_data: request.user_data,
            res,
            flags: 0,
            post: true,
            ltimeout: request.ltimeout,
            next: Vec::new(),
        },
        held: Vec::new(),
        rest: chain,
        flags: request.flags,
        failed,
    }
}

/// `io_flush_timeouts`, as completions went in: the timeouts whose number
/// of completions came complete with 0.
pub(super) fn flush(
    polls: &Polls,
    file: &Arc<dyn FileHandle>,
    ring: &Ring,
    current: Option<&Arc<crate::SignalInbox>>,
) {
    let due: Vec<Armed> = {
        let mut timeouts = ring.timeouts();
        if !timeouts.off_used {
            return;
        }
        let mut seq = ring.sequence(&timeouts);
        if (seq.wrapping_sub(timeouts.last_flush) as i32) < 0 {
            seq = timeouts.last_flush;
        }
        let base = timeouts.last_flush;
        let got = seq.wrapping_sub(base);
        let count = timeouts
            .list
            .iter()
            .take_while(|armed| !armed.noseq() && got >= armed.target.wrapping_sub(base))
            .count();
        timeouts.expired = timeouts.expired.wrapping_add(count as u32);
        timeouts.last_flush = seq;
        timeouts.list.drain(..count).collect()
    };
    for armed in due {
        let other = current.is_none_or(|inbox| !Arc::ptr_eq(inbox, &armed.inbox));
        add_work(
            polls,
            file,
            ring,
            &armed.inbox,
            other.then_some(&*armed.hub),
            complete(armed.chain, 0, false),
        );
    }
}

/// The timers that are due expire, the earliest first (`io_timeout_fn`,
/// `io_link_timeout_fn`).
pub(super) fn expire(polls: &Polls, host: &dyn Host) {
    enum Due {
        Timeout(Armed),
        Link(Link),
    }
    if !polls.timers.swap(false, Ordering::SeqCst) {
        return;
    }
    let now = Now::of(host);
    for file in live_rings(polls) {
        let Ok(ring) = downcast(&file) else {
            continue;
        };
        let mut due: Vec<(u64, Due)> = Vec::new();
        {
            let mut timeouts = ring.timeouts();
            let mut at = 0;
            while at < timeouts.list.len() {
                if let Some(late) = now.late(timeouts.list[at].expiry) {
                    let armed = timeouts.list.remove(at);
                    timeouts.expired = timeouts.expired.wrapping_add(1);
                    due.push((late, Due::Timeout(armed)));
                } else {
                    at += 1;
                }
            }
            let mut at = 0;
            while at < timeouts.links.len() {
                if let Some(late) = now.late(timeouts.links[at].expiry) {
                    due.push((late, Due::Link(timeouts.links.remove(at))));
                } else {
                    at += 1;
                }
            }
            if !timeouts.list.is_empty() || !timeouts.links.is_empty() {
                started(polls);
            }
        }
        due.sort_by_key(|(late, _)| Reverse(*late));
        for (_, due) in due {
            let (inbox, hub, work) = match due {
                Due::Timeout(armed) => (armed.inbox, armed.hub, Deferred::Timeout(armed.chain)),
                Due::Link(link) => (
                    link.inbox,
                    link.hub,
                    Deferred::LinkTimeout {
                        request: link.request,
                        head: link.head,
                    },
                ),
            };
            add_work(polls, &file, ring, &inbox, Some(&hub), work);
        }
    }
}

/// When the next timer expires, on the monotonic clock.
pub(super) fn next_deadline(polls: &Polls, host: &dyn Host) -> Option<u64> {
    if !polls.timers.load(Ordering::SeqCst) {
        return None;
    }
    let now = Now::of(host);
    live_rings(polls)
        .iter()
        .filter_map(|file| {
            let ring = downcast(file).ok()?;
            let timeouts = ring.timeouts();
            let list = timeouts.list.iter().map(|armed| armed.expiry);
            let links = timeouts.links.iter().map(|link| link.expiry);
            list.chain(links).map(|e| now.monotonic(e)).min()
        })
        .min()
}

/// `io_timeout_complete`: a multishot timeout posts a completion and waits
/// again, unless this was its last expiry, or the completion found no room;
/// else the timeout completes, failing but with
/// `IORING_TIMEOUT_ETIME_SUCCESS`.
pub(super) fn run_expired(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    ring: &Ring,
    mut chain: Vec<Request>,
) {
    let user_data = chain[0].user_data;
    if let Work::Timeout(timeout) = &mut chain[0].work
        && !timeout.finishes()
    {
        // The completions of the batch go first (`io_req_post_cqe`).
        super::flush_batch(c, file, ring);
        ring.begin();
        if ring.post_aux(user_data, -ETIME.0, CQE_F_MORE) {
            arm_again(c, ring, chain);
            return;
        }
    }
    complete_expired(ring, chain);
}

/// Starts a multishot timeout again, last in the list.
fn arm_again(c: &Context<'_>, ring: &Ring, chain: Vec<Request>) {
    let Some(Work::Timeout(timeout)) = chain.first().map(|r| &r.work) else {
        return;
    };
    let expiry = Expiry::new(
        c.host,
        timeout.flags,
        timeout.flags & ABS != 0,
        timeout.time,
    );
    ring.timeouts().list.push(Armed {
        expiry,
        target: 0,
        inbox: Arc::clone(c.inbox),
        hub: Arc::clone(&c.files.readiness),
        chain,
    });
    started(&c.processes.io_uring);
}

/// A timeout completes with `ETIME`.
pub(super) fn complete_expired(ring: &Ring, mut chain: Vec<Request>) {
    let request = chain.remove(0);
    let failed =
        !matches!(&request.work, Work::Timeout(timeout) if timeout.flags & ETIME_SUCCESS != 0);
    ring.complete(finish(
        Done {
            user_data: request.user_data,
            res: -ETIME.0,
            flags: 0,
            post: true,
            ltimeout: request.ltimeout,
            next: Vec::new(),
        },
        request.flags,
        failed,
        chain,
    ));
}

/// `io_req_task_link_timeout`: the request it is linked to is cancelled by
/// its `user_data`, and the linked timeout gives `ETIME`, or what the
/// cancellation did not find; nothing is cancelled for a thread that exits
/// (`c` is none).
pub(super) fn run_link(c: Option<&mut Context<'_>>, ring: &Ring, request: &Request, head: u64) {
    let res = match c {
        Some(c) => {
            let key = CancelKey {
                user_data: head,
                flags: 0,
                fd: 0,
                opcode: 0,
            };
            cancel(c, ring, &key, None).map_or_else(|e| -e.0, |_| -ETIME.0)
        }
        None => -ECANCELED.0,
    };
    ring.complete(finish(
        Done {
            user_data: request.user_data,
            res,
            flags: 0,
            post: true,
            ltimeout: None,
            next: Vec::new(),
        },
        request.flags,
        false,
        Vec::new(),
    ));
}

/// `io_timeout_cancel`: the first timeout that matches `key` fails with
/// `ECANCELED`, or `ENOENT` for none. A linked one is not looked for.
pub(super) fn cancel_one(
    c: &Context<'_>,
    ring: &Ring,
    key: &CancelKey,
    seq: u32,
) -> Result<u64, Errno> {
    if key.flags & CANCEL_FD != 0 {
        return Err(Errno::ENOENT);
    }
    let armed = {
        let mut timeouts = ring.timeouts();
        let at = timeouts
            .list
            .iter()
            .position(|armed| matches(armed, key, seq))
            .ok_or(Errno::ENOENT)?;
        timeouts.expired = timeouts.expired.wrapping_add(1);
        timeouts.list.remove(at)
    };
    fail(c, ring, armed)
}

/// `io_cancel_req_match`, of a timeout, which has no file.
fn matches(armed: &Armed, key: &CancelKey, seq: u32) -> bool {
    armed.chain.first().is_some_and(|request| {
        let mut hashed = Hashed {
            id: 0,
            inbox: 0,
            user_data: request.user_data,
            opcode: request.opcode,
            file: 0,
            cancelled: false,
            seq: None,
        };
        cancel_matches(&mut hashed, key, None, seq)
    })
}

/// Adds the task work that fails a timeout with `ECANCELED`
/// (`io_req_task_queue_fail`).
fn fail(c: &Context<'_>, ring: &Ring, armed: Armed) -> Result<u64, Errno> {
    let polls = &c.processes.io_uring;
    let file = live_rings(polls)
        .into_iter()
        .find(|file| downcast(file).is_ok_and(|r| std::ptr::eq(r, ring)))
        .ok_or(Errno::ENOENT)?;
    let other = !Arc::ptr_eq(c.inbox, &armed.inbox);
    add_work(
        polls,
        &file,
        ring,
        &armed.inbox,
        other.then_some(&*armed.hub),
        complete(armed.chain, -ECANCELED.0, true),
    );
    Ok(0)
}

/// `io_timeout_remove`: cancels the timeout of a `user_data`, or with
/// `IORING_TIMEOUT_UPDATE` starts it, or a linked one
/// (`IORING_LINK_TIMEOUT_UPDATE`), again with a new time: one that is
/// multishot takes no absolute time (`EINVAL`), and another no longer waits
/// for a number of completions.
pub(super) fn remove(c: &Context<'_>, ring: &Ring, remove: &Remove) -> Result<u64, Errno> {
    let key = CancelKey {
        user_data: remove.user_data,
        flags: 0,
        fd: 0,
        opcode: 0,
    };
    if remove.flags & UPDATE == 0 {
        return cancel_one(c, ring, &key, 0);
    }
    let abs = remove.flags & ABS != 0;
    let mut timeouts = ring.timeouts();
    if remove.flags & LINK_UPDATE != 0 {
        let link = timeouts
            .links
            .iter_mut()
            .find(|link| link.request.user_data == remove.user_data)
            .ok_or(Errno::ENOENT)?;
        let Work::Timeout(timeout) = &link.request.work else {
            return Err(Errno::ENOENT);
        };
        link.expiry = Expiry::new(c.host, timeout.flags, abs, remove.time);
        return Ok(0);
    }
    let at = timeouts
        .list
        .iter()
        .position(|armed| matches(armed, &key, 0))
        .ok_or(Errno::ENOENT)?;
    if abs
        && timeouts.list[at]
            .timeout()
            .is_some_and(|t| t.flags & MULTISHOT != 0)
    {
        return Err(Errno::EINVAL);
    }
    let mut armed = timeouts.list.remove(at);
    if let Some(Work::Timeout(timeout)) = armed.chain.first_mut().map(|r| &mut r.work) {
        if timeout.flags & MULTISHOT == 0 {
            timeout.off = 0;
        }
        timeout.time = remove.time;
        armed.expiry = Expiry::new(c.host, timeout.flags, abs, remove.time);
    }
    timeouts.list.push(armed);
    Ok(0)
}

/// `io_kill_timeouts`, as the thread of `inbox` calls `execve` or its
/// process exits: its timeouts fail with `ECANCELED`.
pub(super) fn kill(polls: &Polls, inbox: &Arc<crate::SignalInbox>) {
    for file in live_rings(polls) {
        let Ok(ring) = downcast(&file) else {
            continue;
        };
        let killed: Vec<Armed> = {
            let mut timeouts = ring.timeouts();
            let (killed, kept): (Vec<Armed>, Vec<Armed>) = std::mem::take(&mut timeouts.list)
                .into_iter()
                .partition(|armed| Arc::ptr_eq(&armed.inbox, inbox));
            timeouts.list = kept;
            timeouts.expired = timeouts.expired.wrapping_add(killed.len() as u32);
            killed
        };
        for armed in killed {
            add_work(
                polls,
                &file,
                ring,
                inbox,
                None,
                complete(armed.chain, -ECANCELED.0, true),
            );
        }
    }
}
