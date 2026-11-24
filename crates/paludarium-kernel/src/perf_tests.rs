//! `perf_event_open(2)` through the system call interface: what a read of
//! a counting event gives for each read format, its ioctls, and what the
//! other file operations do on its descriptor. The expected values are
//! Linux's (`perf_event_open(2)`, `kernel/events/core.c`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::{Errno, GuestAddr, PAGE_SIZE};

const DATA: u64 = 0x600000;
/// Where the tests put a `struct perf_event_attr`.
const ATTR: u64 = DATA;
/// Where a read or an ioctl puts what it gives.
const OUT: u64 = DATA + 0x400;

const PERF_EVENT_OPEN: u64 = 298;
const READ: u64 = 0;
const WRITE: u64 = 1;
const CLOSE: u64 = 3;
const LSEEK: u64 = 8;
const IOCTL: u64 = 16;
const FCNTL: u64 = 72;
const FTRUNCATE: u64 = 77;

const PERF_TYPE_SOFTWARE: u32 = 1;
const PERF_COUNT_SW_DUMMY: u64 = 9;
const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;
const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1;
const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 2;
const PERF_FORMAT_ID: u64 = 4;
const PERF_FORMAT_GROUP: u64 = 8;
const PERF_FORMAT_LOST: u64 = 16;
/// `disabled`, `freq` and `exclude_kernel` of the attribute's bit field.
const DISABLED: u64 = 1;
const INHERIT: u64 = 1 << 1;
const FREQ: u64 = 1 << 10;
const EXCLUDE_KERNEL: u64 = 1 << 5;

const PERF_EVENT_IOC_ENABLE: u64 = 0x2400;
const PERF_EVENT_IOC_DISABLE: u64 = 0x2401;
const PERF_EVENT_IOC_REFRESH: u64 = 0x2402;
const PERF_EVENT_IOC_RESET: u64 = 0x2403;
const PERF_EVENT_IOC_PERIOD: u64 = 0x4008_2404;
const PERF_EVENT_IOC_ID: u64 = 0x8008_2407;
const PERF_IOC_FLAG_GROUP: u64 = 1;

/// An address no mapping covers.
const UNMAPPED: u64 = 0x10;

fn setup() -> (Kernel, Thread, AddressSpace) {
    let kernel = Kernel::new(Arc::new(paludarium_host::testing::RecordingHost::new()));
    let thread = Thread::new(
        1,
        CpuState::new(GuestAddr(0x400000), GuestAddr(DATA + PAGE_SIZE)),
    );
    let mem = AddressSpace::new();
    mem.map_shared(
        Some(GuestAddr(DATA)),
        PAGE_SIZE,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    (kernel, thread, mem)
}

fn syscall(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, n: u64, a: [u64; 6]) -> u64 {
    t.cpu.gpr[reg::RAX] = n;
    t.cpu.gpr[reg::RDI] = a[0];
    t.cpu.gpr[reg::RSI] = a[1];
    t.cpu.gpr[reg::RDX] = a[2];
    t.cpu.gpr[reg::R10] = a[3];
    t.cpu.gpr[reg::R8] = a[4];
    t.cpu.gpr[reg::R9] = a[5];
    k.handle(t, m, ExitReason::Syscall { rip: t.cpu.rip });
    t.cpu.gpr[reg::RAX]
}

fn errno(e: Errno) -> u64 {
    e.to_syscall_return()
}

/// A software event of `config` with `read_format`, `flags` (to which
/// `exclude_kernel` is added, so that `perf_event_paranoid` 2 takes it) and
/// `period`, written at `ATTR` with the size of `PERF_ATTR_SIZE_VER0`.
struct Spec {
    config: u64,
    read_format: u64,
    flags: u64,
    period: u64,
}

impl Default for Spec {
    fn default() -> Self {
        Spec {
            config: PERF_COUNT_SW_DUMMY,
            read_format: 0,
            flags: 0,
            period: 0,
        }
    }
}

/// `perf_event_open(&attr, 0, -1, group_fd, 0)`: the calling thread on any
/// CPU.
fn open(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, spec: &Spec, group_fd: i32) -> u64 {
    let mut attr = [0u8; 64];
    attr[0..4].copy_from_slice(&PERF_TYPE_SOFTWARE.to_le_bytes());
    attr[4..8].copy_from_slice(&64u32.to_le_bytes());
    attr[8..16].copy_from_slice(&spec.config.to_le_bytes());
    attr[16..24].copy_from_slice(&spec.period.to_le_bytes());
    attr[32..40].copy_from_slice(&spec.read_format.to_le_bytes());
    attr[40..48].copy_from_slice(&(spec.flags | EXCLUDE_KERNEL).to_le_bytes());
    m.write(GuestAddr(ATTR), &attr).unwrap();
    syscall(
        k,
        t,
        m,
        PERF_EVENT_OPEN,
        [ATTR, 0, u64::MAX, group_fd as i64 as u64, 0, 0],
    )
}

/// The words a read of `len` bytes from `fd` gave, or its error.
fn read(
    k: &mut Kernel,
    t: &mut Thread,
    m: &AddressSpace,
    fd: u64,
    len: u64,
) -> Result<Vec<u64>, u64> {
    let got = syscall(k, t, m, READ, [fd, OUT, len, 0, 0, 0]);
    if got > len {
        return Err(got);
    }
    let mut bytes = vec![0; got as usize];
    m.read(GuestAddr(OUT), &mut bytes).unwrap();
    Ok(bytes
        .chunks(8)
        .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
        .collect())
}

fn id(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, fd: u64) -> u64 {
    assert_eq!(
        syscall(k, t, m, IOCTL, [fd, PERF_EVENT_IOC_ID, OUT, 0, 0, 0]),
        0
    );
    let mut word = [0; 8];
    m.read(GuestAddr(OUT), &mut word).unwrap();
    u64::from_le_bytes(word)
}

#[test]
fn a_read_gives_the_count_then_the_times_id_and_lost_its_format_asks_for() {
    let (mut k, mut t, m) = setup();
    let plain = open(&mut k, &mut t, &m, &Spec::default(), -1);
    assert!(plain < 1024, "{plain:#x}");
    // `perf_read_one`: the value alone; a dummy event counts nothing.
    assert_eq!(read(&mut k, &mut t, &m, plain, 64), Ok(vec![0]));
    // `__perf_read`: a buffer smaller than `perf_event__read_size` gives
    // ENOSPC.
    assert_eq!(
        read(&mut k, &mut t, &m, plain, 7),
        Err(errno(Errno::ENOSPC))
    );

    let all = PERF_FORMAT_TOTAL_TIME_ENABLED
        | PERF_FORMAT_TOTAL_TIME_RUNNING
        | PERF_FORMAT_ID
        | PERF_FORMAT_LOST;
    let disabled = Spec {
        read_format: all,
        flags: DISABLED,
        ..Spec::default()
    };
    let fd = open(&mut k, &mut t, &m, &disabled, -1);
    assert!(fd < 1024, "{fd:#x}");
    let event_id = id(&mut k, &mut t, &m, fd);
    assert_ne!(event_id, id(&mut k, &mut t, &m, plain));
    // value, time_enabled, time_running, id, lost: an event that was never
    // enabled has run for no time, and a counting event loses nothing.
    assert_eq!(
        read(&mut k, &mut t, &m, fd, 40),
        Ok(vec![0, 0, 0, event_id, 0])
    );
    assert_eq!(read(&mut k, &mut t, &m, fd, 39), Err(errno(Errno::ENOSPC)));
}

#[test]
fn a_group_read_gives_the_members_after_their_number_and_the_leader_s_times() {
    let (mut k, mut t, m) = setup();
    let format = PERF_FORMAT_GROUP | PERF_FORMAT_ID | PERF_FORMAT_TOTAL_TIME_ENABLED;
    let spec = Spec {
        read_format: format,
        flags: DISABLED,
        ..Spec::default()
    };
    let leader = open(&mut k, &mut t, &m, &spec, -1);
    assert!(leader < 1024, "{leader:#x}");
    let member = open(&mut k, &mut t, &m, &spec, leader as i32);
    assert!(member < 1024, "{member:#x}");
    let (leader_id, member_id) = (
        id(&mut k, &mut t, &m, leader),
        id(&mut k, &mut t, &m, member),
    );
    // `perf_read_group`: nr, time_enabled, then { value, id } of the leader
    // and each sibling.
    let group = vec![2, 0, 0, leader_id, 0, member_id];
    assert_eq!(read(&mut k, &mut t, &m, leader, 48), Ok(group.clone()));
    // A sibling's read gives the whole group too.
    assert_eq!(read(&mut k, &mut t, &m, member, 48), Ok(group));
    assert_eq!(
        read(&mut k, &mut t, &m, leader, 47),
        Err(errno(Errno::ENOSPC))
    );
}

#[test]
fn enable_disable_and_reset_take_the_event_or_with_the_group_flag_its_group() {
    let (mut k, mut t, m) = setup();
    let spec = Spec {
        config: PERF_COUNT_SW_CPU_CLOCK,
        read_format: PERF_FORMAT_TOTAL_TIME_ENABLED,
        flags: DISABLED,
        ..Spec::default()
    };
    let leader = open(&mut k, &mut t, &m, &spec, -1);
    let member = open(&mut k, &mut t, &m, &spec, leader as i32);
    for request in [
        PERF_EVENT_IOC_ENABLE,
        PERF_EVENT_IOC_DISABLE,
        PERF_EVENT_IOC_RESET,
    ] {
        for flag in [0, PERF_IOC_FLAG_GROUP] {
            assert_eq!(
                syscall(&mut k, &mut t, &m, IOCTL, [leader, request, flag, 0, 0, 0]),
                0,
                "{request:#x} {flag}"
            );
        }
    }
    // Reset last: a disabled event's count is 0 again.
    assert_eq!(read(&mut k, &mut t, &m, leader, 16).map(|v| v[0]), Ok(0));
    assert_eq!(read(&mut k, &mut t, &m, member, 16).map(|v| v[0]), Ok(0));
    // A disabled event does not count: two reads give the same.
    let first = read(&mut k, &mut t, &m, member, 16);
    assert_eq!(read(&mut k, &mut t, &m, member, 16), first);
}

#[test]
fn period_takes_only_a_sampling_event_and_refresh_no_counting_one() {
    let (mut k, mut t, m) = setup();
    let counting = open(&mut k, &mut t, &m, &Spec::default(), -1);
    let period = |k: &mut Kernel, t: &mut Thread, fd: u64, value: Option<u64>| {
        let at = match value {
            Some(value) => {
                m.write(GuestAddr(OUT), &value.to_le_bytes()).unwrap();
                OUT
            }
            None => UNMAPPED,
        };
        syscall(k, t, &m, IOCTL, [fd, PERF_EVENT_IOC_PERIOD, at, 0, 0, 0])
    };
    // `perf_ioctl` copies the value in before `perf_event_period` looks at
    // the event.
    assert_eq!(period(&mut k, &mut t, counting, None), errno(Errno::EFAULT));
    assert_eq!(
        period(&mut k, &mut t, counting, Some(1000)),
        errno(Errno::EINVAL)
    );
    // `_perf_event_refresh`: EINVAL for an event that does not sample.
    assert_eq!(
        syscall(
            &mut k,
            &mut t,
            &m,
            IOCTL,
            [counting, PERF_EVENT_IOC_REFRESH, 1, 0, 0, 0]
        ),
        errno(Errno::EINVAL)
    );

    let sampling = open(
        &mut k,
        &mut t,
        &m,
        &Spec {
            period: 100_000,
            flags: DISABLED,
            ..Spec::default()
        },
        -1,
    );
    assert!(sampling < 1024, "{sampling:#x}");
    // A sampling event takes a refresh, which enables it; one with
    // `inherit` does not.
    assert_eq!(
        syscall(
            &mut k,
            &mut t,
            &m,
            IOCTL,
            [sampling, PERF_EVENT_IOC_REFRESH, 2, 0, 0, 0]
        ),
        0
    );
    let inherited = open(
        &mut k,
        &mut t,
        &m,
        &Spec {
            period: 100_000,
            flags: DISABLED | INHERIT,
            ..Spec::default()
        },
        -1,
    );
    assert!(inherited < 1024, "{inherited:#x}");
    assert_eq!(
        syscall(
            &mut k,
            &mut t,
            &m,
            IOCTL,
            [inherited, PERF_EVENT_IOC_REFRESH, 1, 0, 0, 0]
        ),
        errno(Errno::EINVAL)
    );
    assert_eq!(period(&mut k, &mut t, sampling, Some(5000)), 0);
    assert_eq!(
        period(&mut k, &mut t, sampling, Some(0)),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        period(&mut k, &mut t, sampling, Some(1 << 63)),
        errno(Errno::EINVAL)
    );

    // With `freq`, the value is a frequency, which may not pass
    // `perf_event_max_sample_rate` (100000 by default).
    let frequency = open(
        &mut k,
        &mut t,
        &m,
        &Spec {
            period: 1000,
            flags: DISABLED | FREQ,
            ..Spec::default()
        },
        -1,
    );
    assert!(frequency < 1024, "{frequency:#x}");
    assert_eq!(period(&mut k, &mut t, frequency, Some(100_000)), 0);
    assert_eq!(
        period(&mut k, &mut t, frequency, Some(100_001)),
        errno(Errno::EINVAL)
    );
}

#[test]
fn id_needs_a_writable_address_and_other_requests_are_enotty() {
    let (mut k, mut t, m) = setup();
    let fd = open(&mut k, &mut t, &m, &Spec::default(), -1);
    assert_eq!(
        syscall(
            &mut k,
            &mut t,
            &m,
            IOCTL,
            [fd, PERF_EVENT_IOC_ID, UNMAPPED, 0, 0, 0]
        ),
        errno(Errno::EFAULT)
    );
    // `TCGETS` is not one of perf's.
    assert_eq!(
        syscall(&mut k, &mut t, &m, IOCTL, [fd, 0x5401, OUT, 0, 0, 0]),
        errno(Errno::ENOTTY)
    );
}

#[test]
fn the_descriptor_takes_no_write_seek_or_truncate() {
    let (mut k, mut t, m) = setup();
    let fd = open(&mut k, &mut t, &m, &Spec::default(), -1);
    // `perf_fops` has no `write` (`vfs_write`'s EINVAL) and `no_llseek`.
    assert_eq!(
        syscall(&mut k, &mut t, &m, WRITE, [fd, OUT, 8, 0, 0, 0]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        syscall(&mut k, &mut t, &m, LSEEK, [fd, 0, 0, 0, 0, 0]),
        errno(Errno::ESPIPE)
    );
    // `do_ftruncate`: EINVAL for what is not a regular file.
    assert_eq!(
        syscall(&mut k, &mut t, &m, FTRUNCATE, [fd, 0, 0, 0, 0, 0]),
        errno(Errno::EINVAL)
    );
    // `anon_inode_getfile` with `O_RDWR`.
    assert_eq!(syscall(&mut k, &mut t, &m, FCNTL, [fd, 3, 0, 0, 0, 0]), 2);
    assert_eq!(syscall(&mut k, &mut t, &m, CLOSE, [fd, 0, 0, 0, 0, 0]), 0);
}

#[test]
fn a_pid_no_task_has_is_esrch() {
    let (mut k, mut t, m) = setup();
    let mut attr = [0u8; 64];
    attr[0..4].copy_from_slice(&PERF_TYPE_SOFTWARE.to_le_bytes());
    attr[4..8].copy_from_slice(&64u32.to_le_bytes());
    attr[8..16].copy_from_slice(&PERF_COUNT_SW_DUMMY.to_le_bytes());
    attr[40..48].copy_from_slice(&EXCLUDE_KERNEL.to_le_bytes());
    m.write(GuestAddr(ATTR), &attr).unwrap();
    // `find_lively_task_by_vpid`: no task has the number, nor a negative
    // one other than -1.
    for pid in [99_999u64, (-2i64) as u64] {
        assert_eq!(
            syscall(
                &mut k,
                &mut t,
                &m,
                PERF_EVENT_OPEN,
                [ATTR, pid, u64::MAX, u64::MAX, 0, 0]
            ),
            // ESRCH.
            errno(Errno(3)),
            "{pid}"
        );
    }
    // The caller's own thread by its number, as pid 0.
    let own = u64::from(t.tid);
    let fd = syscall(
        &mut k,
        &mut t,
        &m,
        PERF_EVENT_OPEN,
        [ATTR, own, u64::MAX, u64::MAX, 0, 0],
    );
    assert!(fd < 1024, "{fd:#x}");
}

/// A ring buffer's mapping keeps Linux's rules for a `VM_PFNMAP` one
/// (`perf_mmap_vmops`): a write to a data page is a bus error, no part of
/// it changes on its own, and as core mm does not back it, it takes no
/// `MADV_DOFORK` or `MADV_DODUMP`, gives `MADV_DONTNEED` no pages and
/// stays unlocked.
#[test]
fn a_ring_buffer_is_changed_whole_or_not_at_all() {
    const MMAP: u64 = 9;
    const MPROTECT: u64 = 10;
    const MUNMAP: u64 = 11;
    const MREMAP: u64 = 25;
    const MADVISE: u64 = 28;
    const MLOCK: u64 = 149;
    const MSEAL: u64 = 462;
    let (mut k, mut t, m) = setup();
    let fd = open(&mut k, &mut t, &m, &Spec::default(), -1);
    let len = 9 * PAGE_SIZE;
    let at = syscall(&mut k, &mut t, &m, MMAP, [0, len, 3, 1, fd, 0]);
    assert!(at < u64::MAX - 4095, "{at:#x}");
    let data = at + PAGE_SIZE;
    // The user page takes a write; a data page's is a bus error.
    m.write(GuestAddr(at + 8), &[0]).unwrap();
    assert!(m.write(GuestAddr(data), &[0]).unwrap_err().bus);
    let einval = errno(Errno::EINVAL);
    let calls: [(u64, [u64; 6]); 12] = [
        (MUNMAP, [at, PAGE_SIZE, 0, 0, 0, 0]),
        // MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED over a data page.
        (MMAP, [data, PAGE_SIZE, 1, 0x32, u64::MAX, 0]),
        (MPROTECT, [at, PAGE_SIZE, 1, 0, 0, 0]),
        (MREMAP, [at, len, PAGE_SIZE, 0, 0, 0]),
        // MREMAP_MAYMOVE | MREMAP_FIXED of a data page.
        (
            MREMAP,
            [data, PAGE_SIZE, PAGE_SIZE, 3, at + 64 * PAGE_SIZE, 0],
        ),
        // MADV_RANDOM of a part.
        (MADVISE, [at, PAGE_SIZE, 1, 0, 0, 0]),
        // MADV_DOFORK, MADV_DODUMP, MADV_DONTNEED and MADV_DONTNEED_LOCKED.
        (MADVISE, [at, len, 11, 0, 0, 0]),
        (MADVISE, [at, len, 17, 0, 0, 0]),
        (MADVISE, [at, len, 4, 0, 0, 0]),
        (MADVISE, [at, len, 24, 0, 0, 0]),
        (MSEAL, [at, PAGE_SIZE, 0, 0, 0, 0]),
        (MUNMAP, [at + 8 * PAGE_SIZE, PAGE_SIZE, 0, 0, 0, 0]),
    ];
    for (n, a) in calls {
        assert_eq!(syscall(&mut k, &mut t, &m, n, a), einval, "{n} {a:x?}");
    }
    // What would not change a part takes the call: the same protection,
    // and MADV_DONTDUMP, which the buffer has.
    assert_eq!(
        syscall(&mut k, &mut t, &m, MPROTECT, [at, PAGE_SIZE, 3, 0, 0, 0]),
        0
    );
    assert_eq!(
        syscall(&mut k, &mut t, &m, MADVISE, [at, PAGE_SIZE, 16, 0, 0, 0]),
        0
    );
    // mlock takes it and leaves it unlocked.
    assert_eq!(syscall(&mut k, &mut t, &m, MLOCK, [at, len, 0, 0, 0, 0]), 0);
    assert_eq!(m.locked_pages(), 0);
    // The whole takes a change.
    assert_eq!(
        syscall(&mut k, &mut t, &m, MPROTECT, [at, len, 1, 0, 0, 0]),
        0
    );
    assert_eq!(
        syscall(&mut k, &mut t, &m, MUNMAP, [at, len, 0, 0, 0, 0]),
        0
    );
}

/// A ring is `VM_IO | VM_PFNMAP`, which `get_user_pages` refuses
/// (`check_vma_flags`): `process_vm_readv` and `process_vm_writev` pin
/// nothing of it (`EFAULT`), and `MADV_POPULATE_READ` is `EINVAL`
/// (`FOLL_MADV_POPULATE`), while the task's own reads see it.
#[test]
fn get_user_pages_refuses_a_ring() {
    let (mut k, mut t, m) = setup();
    let fd = open(&mut k, &mut t, &m, &Spec::default(), -1);
    assert!(fd < 1024, "{fd}");
    // mmap(NULL, 2 pages, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0).
    let ring = syscall(&mut k, &mut t, &m, 9, [0, 2 * PAGE_SIZE, 3, 1, fd, 0]);
    assert!(ring < 1 << 47, "{ring:#x}");
    let mut version = [0u8; 4];
    m.read(GuestAddr(ring), &mut version).unwrap();
    let pid = syscall(&mut k, &mut t, &m, 39, [0; 6]);
    let (local, lvec, rvec) = (DATA + 0xa00, DATA + 0x800, DATA + 0x900);
    for (at, base) in [(lvec, local), (rvec, ring)] {
        m.write_u64(GuestAddr(at), base).unwrap();
        m.write_u64(GuestAddr(at + 8), 16).unwrap();
    }
    for call in [310, 311] {
        assert_eq!(
            syscall(&mut k, &mut t, &m, call, [pid, lvec, 1, rvec, 1, 0]),
            errno(Errno::EFAULT),
            "{call}"
        );
    }
    // madvise(ring, 1 page, MADV_POPULATE_READ).
    assert_eq!(
        syscall(&mut k, &mut t, &m, 28, [ring, PAGE_SIZE, 22, 0, 0, 0]),
        errno(Errno::EINVAL)
    );
}
