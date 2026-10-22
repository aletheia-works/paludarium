//! Checked Linux x86-64 signal frame codec. Offsets are observed by signals-14.
use crate::{AltStack, SS_DISABLE, SignalAction, ThreadState};
use paludarium_cpu::{CpuState, flag, reg};
use paludarium_mmu::AddressSpace;
use paludarium_types::{GuestAddr, USER_ADDRESS_LIMIT};

pub(crate) const SA_ONSTACK: u64 = 0x0800_0000;
pub(crate) const SA_NODEFER: u64 = 0x4000_0000;
pub(crate) const SA_RESETHAND: u64 = 0x8000_0000;
const FRAME_SIZE: usize = 1024;
const UC: usize = 8;
const SC: usize = UC + 40;
const MASK: usize = UC + 296;
const INFO: usize = UC + 304;
const REGS: [usize; 16] = [
    reg::R8,
    reg::R9,
    reg::R10,
    reg::R11,
    reg::R12,
    reg::R13,
    reg::R14,
    reg::R15,
    reg::RDI,
    reg::RSI,
    reg::RBP,
    reg::RBX,
    reg::RDX,
    reg::RAX,
    reg::RCX,
    reg::RSP,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendingTarget {
    Process,
    Thread,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingSignal {
    pub target: PendingTarget,
    pub number: i32,
    pub code: i32,
    pub addr: u64,
    pub trap: u64,
    pub error: u64,
    pub synchronous: bool,
    /// The POSIX timer that queued this signal (SI_TIMER).
    pub timer: Option<TimerSignal>,
}
/// `si_timerid`, `si_overrun` and `si_value` of a timer's signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TimerSignal {
    pub id: i32,
    pub overrun: i32,
    pub value: u64,
}
/// `si_code` of a signal from a POSIX timer.
pub(crate) const SI_TIMER: i32 = -2;
/// The 128-byte `siginfo_t` of `signal`, as Linux fills it for the frame and
/// for `rt_sigtimedwait`.
pub(crate) fn siginfo(process: &ThreadState, signal: &PendingSignal) -> [u8; 128] {
    let mut info = [0u8; 128];
    info[0..4].copy_from_slice(&signal.number.to_le_bytes());
    info[8..12].copy_from_slice(&signal.code.to_le_bytes());
    if let Some(timer) = signal.timer {
        info[16..20].copy_from_slice(&timer.id.to_le_bytes());
        info[20..24].copy_from_slice(&timer.overrun.to_le_bytes());
        info[24..32].copy_from_slice(&timer.value.to_le_bytes());
    } else if signal.synchronous {
        info[16..24].copy_from_slice(&signal.addr.to_le_bytes());
    } else {
        info[16..20].copy_from_slice(&process.pid.to_le_bytes());
    }
    info
}
impl PendingSignal {
    pub fn user(number: i32, code: i32) -> Self {
        Self {
            target: PendingTarget::Process,
            number,
            code,
            addr: 0,
            trap: 0,
            error: 0,
            synchronous: false,
            timer: None,
        }
    }
    pub fn thread(number: i32, code: i32) -> Self {
        Self {
            target: PendingTarget::Thread,
            ..Self::user(number, code)
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SavedFrame {
    pub base: u64,
    pub cpu: CpuState,
    pub alt_stack: AltStack,
}
fn put(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn get(b: &[u8], at: usize) -> u64 {
    let mut v = [0; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}
pub(crate) fn unblockable() -> u64 {
    (1 << 8) | (1 << 18)
}
pub(crate) fn on_altstack(cpu: &CpuState, stack: AltStack) -> bool {
    stack.flags & SS_DISABLE == 0
        && cpu.gpr[reg::RSP] >= stack.sp
        && cpu.gpr[reg::RSP]
            .checked_sub(stack.sp)
            .is_some_and(|offset| offset < stack.size)
}
pub(crate) fn queue(process: &mut ThreadState, signal: PendingSignal) {
    if signal.number == 18 {
        process.stopped = false;
        process.pending.retain(|s| !matches!(s.number, 19..=22));
    } else if matches!(signal.number, 19..=22) {
        process.pending.retain(|s| s.number != 18);
    }
    // Standard signals coalesce; each real-time number retains FIFO order.
    if signal.number < 32
        && process
            .pending
            .iter()
            .any(|p| p.number == signal.number && p.target == signal.target)
    {
        return;
    }
    process.pending.push(signal);
}

/// Shared selection for delivery and syscall-restart preview. SIGKILL wins,
/// then the thread-pending queue before the process-pending queue. Each queue
/// selects eligible standard signals before the lowest real-time number. Queue
/// position breaks ties, preserving FIFO within the same real-time number.
pub(crate) fn next_pending(process: &ThreadState, skip_ignored: bool) -> Option<usize> {
    process
        .pending
        .iter()
        .enumerate()
        .filter(|(_, signal)| {
            let eligible = (signal.synchronous
                || matches!(signal.number, 9 | 19)
                || process.signal_mask & (1u64 << (signal.number - 1)) == 0)
                && (!process.stopped || matches!(signal.number, 9 | 18));
            let action = process
                .signal_actions
                .get(&signal.number)
                .copied()
                .unwrap_or_default();
            let ignored = !signal.synchronous
                && (action.handler == 1
                    || action.handler == 0 && matches!(signal.number, 17 | 18 | 23 | 28));
            eligible && (!skip_ignored || !ignored)
        })
        .min_by_key(|(index, signal)| {
            (
                if signal.number == 9 {
                    0
                } else if signal.target == PendingTarget::Thread {
                    1
                } else {
                    2
                },
                if signal.number == 9 {
                    0
                } else if signal.number < 32 {
                    1
                } else {
                    2
                },
                if signal.number >= 32 {
                    signal.number
                } else {
                    0
                },
                *index,
            )
        })
        .map(|(index, _)| index)
}
pub(crate) fn install(
    process: &mut ThreadState,
    cpu: &mut CpuState,
    mem: &AddressSpace,
    signal: PendingSignal,
    action: SignalAction,
) -> Result<(), ()> {
    let old_stack = process.alt_stack;
    let already_on = on_altstack(cpu, old_stack);
    let top = if action.flags & SA_ONSTACK != 0 && !already_on && old_stack.flags & SS_DISABLE == 0
    {
        old_stack.sp.checked_add(old_stack.size).ok_or(())?
    } else {
        cpu.gpr[reg::RSP].checked_sub(128).ok_or(())?
    };
    let base = (top.checked_sub(FRAME_SIZE as u64).ok_or(())? & !15)
        .checked_sub(8)
        .ok_or(())?;
    if base
        .checked_add(FRAME_SIZE as u64)
        .is_none_or(|end| end > USER_ADDRESS_LIMIT)
        || action.handler >= USER_ADDRESS_LIMIT
        || action.restorer >= USER_ADDRESS_LIMIT
    {
        return Err(());
    }
    let mut b = [0u8; FRAME_SIZE];
    let fp = usize::try_from(((base + 440 + 63) & !63) - base).map_err(|_| ())?;
    put(&mut b, 0, action.restorer);
    put(&mut b, UC, 0);
    put(&mut b, UC + 16, old_stack.sp);
    put(
        &mut b,
        UC + 24,
        u64::from(old_stack.flags | u32::from(already_on)),
    );
    put(&mut b, UC + 32, old_stack.size);
    for (slot, reg) in REGS.iter().enumerate() {
        put(&mut b, SC + slot * 8, cpu.gpr[*reg]);
    }
    put(&mut b, SC + 128, cpu.rip.0);
    put(&mut b, SC + 136, cpu.rflags);
    put(&mut b, SC + 144, 0x002b_0000_0000_0033);
    put(&mut b, SC + 152, signal.error);
    put(&mut b, SC + 160, signal.trap);
    put(&mut b, SC + 168, process.signal_mask);
    put(
        &mut b,
        SC + 176,
        if signal.trap == 14 { signal.addr } else { 0 },
    );
    put(&mut b, SC + 184, base + fp as u64);
    put(&mut b, MASK, process.signal_mask);
    b[INFO..INFO + 128].copy_from_slice(&siginfo(process, &signal));
    b[fp..fp + 2].copy_from_slice(&0x37fu16.to_le_bytes());
    b[fp + 24..fp + 28].copy_from_slice(&cpu.mxcsr.to_le_bytes());
    b[fp + 28..fp + 32].copy_from_slice(&0xffffu32.to_le_bytes());
    for (i, xmm) in cpu.xmm.iter().enumerate() {
        b[fp + 160 + i * 16..fp + 176 + i * 16].copy_from_slice(&xmm.to_le_bytes());
    }
    mem.write(GuestAddr(base), &b).map_err(|_| ())?;
    process.frames.push(SavedFrame {
        base,
        cpu: cpu.clone(),
        alt_stack: old_stack,
    });
    if action.flags & SA_RESETHAND != 0 {
        process
            .signal_actions
            .insert(signal.number, SignalAction::default());
    }
    process.signal_mask |= action.mask;
    if action.flags & SA_NODEFER == 0 {
        process.signal_mask |= 1u64 << (signal.number - 1)
    }
    process.signal_mask &= !unblockable();
    if old_stack.flags & (1 << 31) != 0
        && on_altstack(
            &CpuState {
                gpr: {
                    let mut g = cpu.gpr;
                    g[reg::RSP] = base;
                    g
                },
                ..cpu.clone()
            },
            old_stack,
        )
    {
        process.alt_stack = AltStack::default();
    }
    cpu.rip = GuestAddr(action.handler);
    cpu.gpr[reg::RSP] = base;
    cpu.gpr[reg::RDI] = signal.number as u64;
    cpu.gpr[reg::RSI] = base + INFO as u64;
    cpu.gpr[reg::RDX] = base + UC as u64;
    cpu.rflags &= !(flag::DF | flag::TF | flag::RF);
    cpu.repeat_continuation = None;
    Ok(())
}
pub(crate) fn restore(
    process: &mut ThreadState,
    cpu: &mut CpuState,
    mem: &AddressSpace,
) -> Result<(), ()> {
    // The restorer was reached through ret, so RSP points immediately after pretcode.
    let base = cpu.gpr[reg::RSP].checked_sub(8).ok_or(())?;
    let saved = process.frames.last().cloned();
    let mut b = [0u8; 312];
    mem.read(GuestAddr(base), &mut b).map_err(|_| ())?;
    let mut restored = saved
        .as_ref()
        .map_or_else(|| cpu.clone(), |s| s.cpu.clone());
    for (slot, reg) in REGS.iter().enumerate() {
        restored.gpr[*reg] = get(&b, SC + slot * 8);
    }
    restored.rip = GuestAddr(get(&b, SC + 128));
    if restored.rip.0 >= USER_ADDRESS_LIMIT || restored.gpr[reg::RSP] >= USER_ADDRESS_LIMIT {
        return Err(());
    }
    let selectors = get(&b, SC + 144);
    if selectors & 0xffff != 0x33 || selectors >> 48 != 0x2b {
        return Err(());
    }
    restored.rflags = (cpu.rflags & !flag::USER_WRITABLE)
        | (get(&b, SC + 136) & flag::USER_WRITABLE)
        | flag::RESERVED1;
    // FS/GS bases are thread state, not members of Linux sigcontext.
    restored.fs_base = cpu.fs_base;
    restored.gs_base = cpu.gs_base;
    let fp = get(&b, SC + 184);
    if fp != 0 {
        if fp & 15 != 0 {
            return Err(());
        }
        let mut f = [0u8; 512];
        mem.read(GuestAddr(fp), &mut f).map_err(|_| ())?;
        restored.mxcsr = u32::from_le_bytes(f[24..28].try_into().map_err(|_| ())?);
        if restored.mxcsr & !0xffff != 0 {
            return Err(());
        }
        for (i, xmm) in restored.xmm.iter_mut().enumerate() {
            *xmm = u128::from_le_bytes(f[160 + i * 16..176 + i * 16].try_into().map_err(|_| ())?);
        }
    }
    if saved.as_ref().is_none_or(|saved| {
        restored.rip != saved.cpu.rip
            || restored.rflags != saved.cpu.rflags
            || restored.gpr[reg::RCX] != saved.cpu.gpr[reg::RCX]
            || restored.gpr[reg::RSI] != saved.cpu.gpr[reg::RSI]
            || restored.gpr[reg::RDI] != saved.cpu.gpr[reg::RDI]
    }) {
        restored.repeat_continuation = None
    }
    let alt = AltStack {
        sp: get(&b, UC + 16),
        flags: get(&b, UC + 24) as u32 & !1,
        size: get(&b, UC + 32),
    };
    if alt.flags & !(SS_DISABLE | (1 << 31)) != 0
        || alt
            .sp
            .checked_add(alt.size)
            .is_none_or(|end| end > USER_ADDRESS_LIMIT)
    {
        return Err(());
    }
    process.signal_mask = get(&b, MASK) & !unblockable();
    process.alt_stack = alt;
    process.frames.pop();
    *cpu = restored;
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RealTimer {
    pub deadline: Option<u64>,
    pub interval: u64,
}
/// The index of the lowest-numbered signal in `set` (bit n-1 for signal n).
pub(crate) fn lowest_in(pending: &[PendingSignal], set: u64) -> Option<usize> {
    pending
        .iter()
        .enumerate()
        .filter(|(_, s)| (1..=64).contains(&s.number) && set >> (s.number - 1) & 1 != 0)
        .min_by_key(|(index, s)| (s.number, *index))
        .map(|(index, _)| index)
}
/// The earliest deadline of the interval timer and the POSIX timers.
pub(crate) fn next_deadline(process: &ThreadState) -> Option<u64> {
    match (process.timer.deadline, process.posix_deadline) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
pub(crate) fn expire_timer(process: &mut ThreadState, now: u64) {
    if let Some(deadline) = process.timer.deadline
        && now >= deadline
    {
        let interval = process.timer.interval;
        process.timer.deadline = if interval == 0 {
            None
        } else {
            (now - deadline)
                .checked_div(interval)
                .and_then(|n| n.checked_add(1))
                .and_then(|n| n.checked_mul(interval))
                .and_then(|delta| deadline.checked_add(delta))
        };
        queue(process, PendingSignal::user(14, 128));
    }
}
