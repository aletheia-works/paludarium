//! The aio calls ([`crate::aio`]) through the kernel's dispatch.
use super::*;
use paludarium_host::Host;
use paludarium_host::testing::RecordingHost;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::{Errno, GuestAddr};

const DATA: u64 = 0x10_0000;
const SETUP: u64 = 206;
const DESTROY: u64 = 207;
const GETEVENTS: u64 = 208;
const SUBMIT: u64 = 209;
const CANCEL: u64 = 210;
const PGETEVENTS: u64 = 333;
/// Where the cases keep a context ID, `iocb`s, their pointers, buffers
/// and events.
const CTX: u64 = DATA;
const IOCBS: u64 = DATA + 0x1000;
const POINTERS: u64 = DATA + 0x2000;
const BUFFERS: u64 = DATA + 0x3000;
const EVENTS: u64 = DATA + 0x8000;

struct Fixture {
    host: Arc<RecordingHost>,
    kernel: Kernel,
    thread: Thread,
    mem: AddressSpace,
}

fn fixture() -> Fixture {
    let host = Arc::new(RecordingHost::new());
    let kernel = Kernel::new(host.clone());
    let mut mem = AddressSpace::new();
    mem.map(
        Some(GuestAddr(DATA)),
        0x10000,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    mem.set_initial_break(GuestAddr(0x20_0000));
    let thread = Thread {
        tid: 1,
        state: ThreadState {
            pid: 1,
            ..ThreadState::default()
        },
        cpu: CpuState::default(),
    };
    Fixture {
        host,
        kernel,
        thread,
        mem,
    }
}

fn errno(e: Errno) -> u64 {
    e.to_syscall_return()
}

/// `struct iocb`.
#[derive(Clone, Copy, Default)]
struct Iocb {
    data: u64,
    key: u32,
    rw_flags: u32,
    opcode: u16,
    reqprio: u16,
    fildes: u32,
    buf: u64,
    nbytes: u64,
    offset: u64,
    reserved2: u64,
    flags: u32,
    resfd: u32,
}

impl Fixture {
    fn ret(&mut self, number: u64, args: &[u64]) -> u64 {
        self.thread.cpu.gpr[reg::RAX] = number;
        let regs = [reg::RDI, reg::RSI, reg::RDX, reg::R10, reg::R8, reg::R9];
        for (r, v) in regs.iter().zip(args) {
            self.thread.cpu.gpr[*r] = *v;
        }
        let reason = ExitReason::Syscall {
            rip: GuestAddr(0x1000),
        };
        assert_eq!(
            self.kernel.handle(&mut self.thread, &self.mem, reason),
            Next::Resume
        );
        self.thread.cpu.gpr[reg::RAX]
    }
    fn u32_at(&self, at: u64) -> u32 {
        let mut b = [0; 4];
        self.mem.read(GuestAddr(at), &mut b).unwrap();
        u32::from_le_bytes(b)
    }
    fn u64_at(&self, at: u64) -> u64 {
        self.mem.read_u64(GuestAddr(at)).unwrap()
    }
    /// A context of `nr` events, whose ID it gives.
    fn setup(&mut self, nr: u64) -> u64 {
        self.mem.write(GuestAddr(CTX), &[0; 8]).unwrap();
        assert_eq!(self.ret(SETUP, &[nr, CTX]), 0);
        self.u64_at(CTX)
    }
    /// Puts `iocb` in place `index`, and its address among the pointers.
    fn iocb(&self, index: u64, iocb: Iocb) -> u64 {
        let at = IOCBS + 64 * index;
        let mut b = [0; 64];
        b[..8].copy_from_slice(&iocb.data.to_le_bytes());
        b[8..12].copy_from_slice(&iocb.key.to_le_bytes());
        b[12..16].copy_from_slice(&iocb.rw_flags.to_le_bytes());
        b[16..18].copy_from_slice(&iocb.opcode.to_le_bytes());
        b[18..20].copy_from_slice(&iocb.reqprio.to_le_bytes());
        b[20..24].copy_from_slice(&iocb.fildes.to_le_bytes());
        b[24..32].copy_from_slice(&iocb.buf.to_le_bytes());
        b[32..40].copy_from_slice(&iocb.nbytes.to_le_bytes());
        b[40..48].copy_from_slice(&iocb.offset.to_le_bytes());
        b[48..56].copy_from_slice(&iocb.reserved2.to_le_bytes());
        b[56..60].copy_from_slice(&iocb.flags.to_le_bytes());
        b[60..64].copy_from_slice(&iocb.resfd.to_le_bytes());
        self.mem.write(GuestAddr(at), &b).unwrap();
        self.mem
            .write(GuestAddr(POINTERS + 8 * index), &at.to_le_bytes())
            .unwrap();
        at
    }
    /// Submits the one `iocb`.
    fn submit(&mut self, ctx: u64, iocb: Iocb) -> u64 {
        self.iocb(0, iocb);
        self.ret(SUBMIT, &[ctx, 1, POINTERS])
    }
    /// The events `io_getevents` takes, without waiting: (data, obj, res).
    fn reap(&mut self, ctx: u64) -> Vec<(u64, u64, i64)> {
        self.mem.write(GuestAddr(DATA + 0xf00), &[0; 16]).unwrap();
        let got = self.ret(GETEVENTS, &[ctx, 0, 64, EVENTS, DATA + 0xf00]);
        (0..got)
            .map(|i| {
                let at = EVENTS + 32 * i;
                (
                    self.u64_at(at),
                    self.u64_at(at + 8),
                    self.u64_at(at + 16) as i64,
                )
            })
            .collect()
    }
    /// A file `/<name>` holding `contents`, open to read and write.
    fn file(&mut self, name: &str, contents: &[u8]) -> u64 {
        let path = format!("/{name}\0");
        self.mem
            .write(GuestAddr(DATA + 0xe00), path.as_bytes())
            .unwrap();
        let fd = self.ret(2, &[DATA + 0xe00, 0o102, 0o600]);
        assert!(fd < 1024, "{fd:#x}");
        self.mem.write(GuestAddr(BUFFERS), contents).unwrap();
        assert_eq!(
            self.ret(1, &[fd, BUFFERS, contents.len() as u64]),
            contents.len() as u64
        );
        fd
    }
    /// A pipe's read and write ends.
    fn pipe(&mut self) -> (u64, u64) {
        assert_eq!(self.ret(22, &[DATA + 0xd00]), 0);
        (
            u64::from(self.u32_at(DATA + 0xd00)),
            u64::from(self.u32_at(DATA + 0xd04)),
        )
    }
    fn aio_nr(&self) -> u64 {
        self.kernel.processes.aio.nr()
    }
}

/// The events a context of `nr` has: twice at least four for each CPU,
/// and two, made as many as fill its pages.
fn ring_events(host: &RecordingHost, nr: u32) -> u32 {
    let cpus = host.cpu_count().clamp(1, 8192) as u32;
    let events = nr.max(cpus * 4) * 2 + 2;
    let pages = (32 + 32 * u64::from(events)).div_ceil(4096);
    ((pages * 4096 - 32) / 32) as u32
}

#[test]
fn setup_maps_a_ring_and_destroy_ends_it() {
    let mut f = fixture();
    // *ctxp is read first, and must be 0, and nr_events not.
    assert_eq!(f.ret(SETUP, &[1, 0x5000_0000]), errno(Errno::EFAULT));
    f.mem.write(GuestAddr(CTX), &1u64.to_le_bytes()).unwrap();
    assert_eq!(f.ret(SETUP, &[1, CTX]), errno(Errno::EINVAL));
    f.mem.write(GuestAddr(CTX), &[0; 8]).unwrap();
    assert_eq!(f.ret(SETUP, &[0, CTX]), errno(Errno::EINVAL));
    // Too many events is EINVAL, before the limit's EAGAIN.
    assert_eq!(f.ret(SETUP, &[0x40_0001, CTX]), errno(Errno::EINVAL));
    assert_eq!(f.ret(SETUP, &[0x1_0001, CTX]), errno(Errno::EAGAIN));
    assert_eq!(f.u64_at(CTX), 0);
    let ctx = f.setup(10);
    assert_ne!(ctx, 0);
    assert_eq!(ctx % 4096, 0);
    // The header: index, events, head, tail, magic, features, its size.
    let header: Vec<u32> = (0..8).map(|i| f.u32_at(ctx + 4 * i)).collect();
    assert_eq!(
        header,
        [0, ring_events(&f.host, 10), 0, 0, 0xa10a_10a1, 1, 0, 32]
    );
    assert_eq!(f.aio_nr(), 10);
    // The next has the next index; the machine's count adds up.
    let second = f.setup(20);
    assert_eq!(f.u32_at(second), 1);
    assert_eq!(f.aio_nr(), 30);
    // Past the machine's limit with the others.
    f.mem.write(GuestAddr(CTX), &[0; 8]).unwrap();
    assert_eq!(f.ret(SETUP, &[0x1_0000 - 29, CTX]), errno(Errno::EAGAIN));
    // Destroying unmaps the ring, and frees its index and events.
    assert_eq!(f.ret(DESTROY, &[ctx]), 0);
    assert!(f.mem.read_u64(GuestAddr(ctx)).is_err());
    assert_eq!(f.ret(DESTROY, &[ctx]), errno(Errno::EINVAL));
    assert_eq!(f.aio_nr(), 20);
    let third = f.setup(1);
    assert_eq!(f.u32_at(third), 0);
    // An ID whose header names another context, or none, is none.
    f.mem.write(GuestAddr(third), &1u32.to_le_bytes()).unwrap();
    assert_eq!(f.ret(DESTROY, &[third]), errno(Errno::EINVAL));
    f.mem.write(GuestAddr(third), &0u32.to_le_bytes()).unwrap();
    assert_eq!(f.ret(DESTROY, &[DATA]), errno(Errno::EINVAL));
    assert_eq!(f.ret(DESTROY, &[0]), errno(Errno::EINVAL));
    // The end of the address space ends them all.
    f.kernel.group.aio().release();
    assert_eq!(f.aio_nr(), 0);
    assert_eq!(f.ret(DESTROY, &[second]), errno(Errno::EINVAL));
}

#[test]
fn mremap_moves_a_ring_only_whole() {
    let mut f = fixture();
    let ctx = f.setup(1000);
    let size = 32 + 32 * u64::from(f.u32_at(ctx + 4));
    assert!(size > 4096, "{size}");
    // Part of it does not move (`aio_ring_mremap`), and stays where it is.
    let to = 0x4000_0000;
    assert_eq!(
        f.ret(25, &[ctx, 4096, 4096, 1 | 2, to]),
        errno(Errno::EINVAL)
    );
    assert_eq!(f.u32_at(ctx + 16), 0xa10a_10a1);
    assert!(f.mem.read_u64(GuestAddr(to)).is_err());
    // A fixed mapping neither grows nor stays behind a move.
    assert_eq!(
        f.ret(25, &[ctx, size, size + 4096, 1]),
        errno(Errno::EFAULT)
    );
    assert_eq!(f.ret(25, &[ctx, size, size, 1 | 4]), errno(Errno::EINVAL));
    // Whole, it moves, and its context goes with it.
    assert_eq!(f.ret(25, &[ctx, size, size, 1 | 2, to]), to);
    assert!(f.mem.read_u64(GuestAddr(ctx)).is_err());
    assert_eq!(f.ret(DESTROY, &[to]), 0);
}

#[test]
fn reads_and_writes_complete_before_submit_returns() {
    let mut f = fixture();
    let fd = f.file("a", b"hello world");
    let ctx = f.setup(8);
    let write = f.iocb(
        0,
        Iocb {
            data: 7,
            key: 0xdead,
            opcode: 1,
            fildes: fd as u32,
            buf: BUFFERS + 0x100,
            nbytes: 2,
            offset: 2,
            ..Iocb::default()
        },
    );
    f.mem.write(GuestAddr(BUFFERS + 0x100), b"XY").unwrap();
    let read = f.iocb(
        1,
        Iocb {
            data: 8,
            opcode: 0,
            fildes: fd as u32,
            buf: BUFFERS + 0x200,
            nbytes: 64,
            offset: 0,
            ..Iocb::default()
        },
    );
    assert_eq!(f.ret(SUBMIT, &[ctx, 2, POINTERS]), 2);
    // The key is cleared, and both events are in the ring already.
    assert_eq!(f.u32_at(write + 8), 0);
    assert_eq!(f.u32_at(ctx + 12), 2);
    assert_eq!(f.reap(ctx), [(7, write, 2), (8, read, 11)]);
    assert_eq!((f.u32_at(ctx + 8), f.u32_at(ctx + 12)), (2, 2));
    let mut got = [0; 11];
    f.mem.read(GuestAddr(BUFFERS + 0x200), &mut got).unwrap();
    assert_eq!(&got, b"heXYo world");
    // The file's position stays.
    assert_eq!(f.ret(8, &[fd, 0, 1]), 11);
    // Vectors: two buffers read from offset 6, and a write of them back.
    let iov = BUFFERS + 0x300;
    for (i, (base, len)) in [(BUFFERS + 0x400, 2u64), (BUFFERS + 0x500, 3)]
        .iter()
        .enumerate()
    {
        f.mem
            .write(GuestAddr(iov + 16 * i as u64), &base.to_le_bytes())
            .unwrap();
        f.mem
            .write(GuestAddr(iov + 16 * i as u64 + 8), &len.to_le_bytes())
            .unwrap();
    }
    let readv = Iocb {
        data: 9,
        opcode: 7,
        fildes: fd as u32,
        buf: iov,
        nbytes: 2,
        offset: 6,
        ..Iocb::default()
    };
    assert_eq!(f.submit(ctx, readv), 1);
    let mut first = [0; 2];
    let mut second = [0; 3];
    f.mem.read(GuestAddr(BUFFERS + 0x400), &mut first).unwrap();
    f.mem.read(GuestAddr(BUFFERS + 0x500), &mut second).unwrap();
    assert_eq!((&first, &second), (b"wo", b"rld"));
    let writev = Iocb {
        opcode: 8,
        offset: 11,
        ..readv
    };
    assert_eq!(f.submit(ctx, writev), 1);
    assert_eq!(f.reap(ctx), [(9, IOCBS, 5), (9, IOCBS, 5)]);
    assert_eq!(f.ret(8, &[fd, 0, 2]), 16);
    // Only the low 32 bits of a vector's count are read, as `import_iovec`
    // takes an `unsigned` on the kernels CI runs: two buffers, then none.
    let wide = Iocb {
        data: 13,
        nbytes: 0x1_0000_0002,
        ..readv
    };
    assert_eq!(f.submit(ctx, wide), 1);
    let empty = Iocb {
        data: 14,
        nbytes: 1 << 32,
        ..readv
    };
    assert_eq!(f.submit(ctx, empty), 1);
    assert_eq!(f.reap(ctx), [(13, IOCBS, 5), (14, IOCBS, 0)]);
    // A sync, and a read past the end, which reads nothing.
    let sync = Iocb {
        data: 10,
        opcode: 2,
        fildes: fd as u32,
        ..Iocb::default()
    };
    assert_eq!(f.submit(ctx, sync), 1);
    let past = Iocb {
        data: 11,
        fildes: fd as u32,
        buf: BUFFERS,
        nbytes: 4,
        offset: 100,
        ..Iocb::default()
    };
    assert_eq!(f.submit(ctx, past), 1);
    // A buffer that cannot be written fails the read, not the submission.
    let unmapped = Iocb {
        data: 12,
        buf: 0x4000_0000,
        offset: 0,
        ..past
    };
    assert_eq!(f.submit(ctx, unmapped), 1);
    assert_eq!(
        f.reap(ctx),
        [
            (10, IOCBS, 0),
            (11, IOCBS, 0),
            (12, IOCBS, -i64::from(Errno::EFAULT.0))
        ]
    );
}

#[test]
fn noappend_writes_an_appending_file_at_aio_offset() {
    let mut f = fixture();
    f.mem.write(GuestAddr(DATA + 0xe00), b"/a\0").unwrap();
    let fd = f.ret(2, &[DATA + 0xe00, 0o2102, 0o600]);
    f.mem.write(GuestAddr(BUFFERS), b"abcdef").unwrap();
    assert_eq!(f.ret(1, &[fd, BUFFERS, 6]), 6);
    let ctx = f.setup(8);
    f.mem.write(GuestAddr(BUFFERS + 0x100), b"XY").unwrap();
    let write = Iocb {
        data: 1,
        opcode: 1,
        fildes: fd as u32,
        buf: BUFFERS + 0x100,
        nbytes: 2,
        offset: 1,
        ..Iocb::default()
    };
    assert_eq!(
        f.submit(
            ctx,
            Iocb {
                rw_flags: 0x20,
                ..write
            }
        ),
        1
    );
    // With RWF_APPEND too it is no request (EINVAL), as kiocb_set_rw_flags
    // refuses the pair before either is applied.
    assert_eq!(
        f.submit(
            ctx,
            Iocb {
                rw_flags: 0x30,
                ..write
            }
        ),
        errno(Errno::EINVAL)
    );
    // Without it, the write appends.
    assert_eq!(f.submit(ctx, Iocb { data: 2, ..write }), 1);
    assert_eq!(f.reap(ctx), [(1, IOCBS, 2), (2, IOCBS, 2)]);
    let mut got = [0; 8];
    assert_eq!(f.ret(17, &[fd, BUFFERS + 0x200, 8, 0]), 8);
    f.mem.read(GuestAddr(BUFFERS + 0x200), &mut got).unwrap();
    assert_eq!(&got, b"aXYdefXY");
}

#[test]
fn submit_checks_each_request_in_linux_order() {
    let mut f = fixture();
    let fd = f.file("a", b"abc");
    let (reader, writer) = f.pipe();
    let ctx = f.setup(8);
    let read = Iocb {
        fildes: fd as u32,
        buf: BUFFERS,
        nbytes: 1,
        ..Iocb::default()
    };
    let fail = |f: &mut Fixture, iocb: Iocb| f.submit(ctx, iocb);
    assert_eq!(
        f.ret(SUBMIT, &[ctx, -1i64 as u64, POINTERS]),
        errno(Errno::EINVAL)
    );
    assert_eq!(f.ret(SUBMIT, &[DATA, 1, POINTERS]), errno(Errno::EINVAL));
    assert_eq!(f.ret(SUBMIT, &[ctx, 0, 0]), 0);
    assert_eq!(f.ret(SUBMIT, &[ctx, 1, 0x4000_0000]), errno(Errno::EFAULT));
    // The iocb itself, then its fields.
    f.mem
        .write(GuestAddr(POINTERS), &0x4000_0000u64.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(SUBMIT, &[ctx, 1, POINTERS]), errno(Errno::EFAULT));
    let cases = [
        (
            Iocb {
                reserved2: 1,
                fildes: u32::MAX,
                ..read
            },
            Errno::EINVAL,
        ),
        (
            Iocb {
                nbytes: 1 << 63,
                fildes: u32::MAX,
                ..read
            },
            Errno::EINVAL,
        ),
        (Iocb { fildes: 99, ..read }, Errno::EBADF),
        (
            Iocb {
                flags: 1,
                resfd: 99,
                ..read
            },
            Errno::EBADF,
        ),
        (
            Iocb {
                flags: 1,
                resfd: fd as u32,
                ..read
            },
            Errno::EINVAL,
        ),
        // IOCB_CMD_NOOP, and a number Linux does not have.
        (Iocb { opcode: 6, ..read }, Errno::EINVAL),
        (Iocb { opcode: 4, ..read }, Errno::EINVAL),
        // An I/O priority of no class with a level.
        (
            Iocb {
                flags: 2,
                reqprio: 1,
                ..read
            },
            Errno::EINVAL,
        ),
        (
            Iocb {
                rw_flags: 0x8000,
                ..read
            },
            Errno::EOPNOTSUPP,
        ),
        (
            Iocb {
                rw_flags: 0x30,
                ..read
            },
            Errno::EINVAL,
        ),
        (
            Iocb {
                fildes: writer as u32,
                ..read
            },
            Errno::EBADF,
        ),
        (
            Iocb {
                opcode: 1,
                fildes: reader as u32,
                ..read
            },
            Errno::EBADF,
        ),
        (
            Iocb {
                offset: -1i64 as u64,
                ..read
            },
            Errno::EINVAL,
        ),
        (
            Iocb {
                offset: i64::MAX as u64,
                ..read
            },
            Errno::EINVAL,
        ),
        (
            Iocb {
                buf: 1 << 47,
                ..read
            },
            Errno::EFAULT,
        ),
        (
            Iocb {
                opcode: 7,
                nbytes: 1025,
                ..read
            },
            Errno::EINVAL,
        ),
        (
            Iocb {
                opcode: 2,
                nbytes: 1,
                ..read
            },
            Errno::EINVAL,
        ),
        (
            Iocb {
                opcode: 2,
                fildes: reader as u32,
                buf: 0,
                nbytes: 0,
                ..read
            },
            Errno::EINVAL,
        ),
        (
            Iocb {
                opcode: 5,
                buf: 0x1_0000,
                nbytes: 0,
                ..read
            },
            Errno::EINVAL,
        ),
        // A regular file is never ready for POLLPRI, and its poll waits on
        // nothing.
        (
            Iocb {
                opcode: 5,
                buf: 2,
                nbytes: 0,
                ..read
            },
            Errno::EINVAL,
        ),
    ];
    for (i, (iocb, error)) in cases.into_iter().enumerate() {
        assert_eq!(fail(&mut f, iocb), errno(error), "case {i}");
    }
    // A directory has no read_iter.
    f.mem.write(GuestAddr(DATA + 0xe00), b"/\0").unwrap();
    let dir = f.ret(2, &[DATA + 0xe00, 0o200000, 0]);
    assert_eq!(
        fail(
            &mut f,
            Iocb {
                fildes: dir as u32,
                ..read
            }
        ),
        errno(Errno::EINVAL)
    );
    // Nothing failed took a place or left an event.
    assert_eq!(f.reap(ctx), []);
    // A failure after the first stops there: the count of those before.
    f.iocb(0, read);
    f.iocb(1, Iocb { fildes: 99, ..read });
    f.iocb(2, read);
    assert_eq!(f.ret(SUBMIT, &[ctx, 3, POINTERS]), 1);
    // An iocb whose key cannot be written.
    let page = f.ret(9, &[0, 4096, 3, 0x22, -1i64 as u64, 0]);
    let mut b = [0; 64];
    b[20..24].copy_from_slice(&(fd as u32).to_le_bytes());
    f.mem.write(GuestAddr(page), &b).unwrap();
    assert_eq!(f.ret(10, &[page, 4096, 1]), 0);
    f.mem
        .write(GuestAddr(POINTERS), &page.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(SUBMIT, &[ctx, 1, POINTERS]), errno(Errno::EFAULT));
    assert_eq!(f.reap(ctx).len(), 1);
}

#[test]
fn the_ring_holds_one_less_than_its_events() {
    let mut f = fixture();
    let fd = f.file("a", b"abc");
    let ctx = f.setup(1);
    let events = u64::from(f.u32_at(ctx + 4));
    let read = Iocb {
        fildes: fd as u32,
        buf: BUFFERS,
        nbytes: 1,
        ..Iocb::default()
    };
    for i in 0..events {
        f.mem
            .write(GuestAddr(POINTERS + 8 * i), &IOCBS.to_le_bytes())
            .unwrap();
    }
    f.iocb(0, read);
    // At most the ring's events are taken in one call, and they stop at
    // the place left for the tail.
    assert_eq!(f.ret(SUBMIT, &[ctx, events + 10, POINTERS]), events - 1);
    assert_eq!(f.ret(SUBMIT, &[ctx, 1, POINTERS]), errno(Errno::EAGAIN));
    // Moving the head makes room again, and the tail wraps.
    let head = f.u32_at(ctx + 12);
    f.mem
        .write(GuestAddr(ctx + 8), &head.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(SUBMIT, &[ctx, 3, POINTERS]), 3);
    assert_eq!(f.u32_at(ctx + 12), 2);
    assert_eq!(f.reap(ctx).len(), 3);
}

#[test]
fn polls_wait_for_their_files_and_can_be_cancelled() {
    let mut f = fixture();
    let fd = f.file("a", b"abc");
    let (reader, writer) = f.pipe();
    let eventfd = f.ret(290, &[0, 0x800]);
    let ctx = f.setup(8);
    // A regular file is ready at once.
    let poll = Iocb {
        data: 1,
        opcode: 5,
        fildes: fd as u32,
        buf: 1,
        ..Iocb::default()
    };
    assert_eq!(f.submit(ctx, poll), 1);
    assert_eq!(f.reap(ctx), [(1, IOCBS, 1)]);
    // A pipe waits until it is written, and counts on the eventfd.
    let waiting = f.iocb(
        1,
        Iocb {
            data: 2,
            fildes: reader as u32,
            flags: 1,
            resfd: eventfd as u32,
            ..poll
        },
    );
    assert_eq!(f.ret(SUBMIT, &[ctx, 1, POINTERS + 8]), 1);
    assert_eq!(f.reap(ctx), []);
    assert_eq!(f.ret(0, &[eventfd, BUFFERS, 8]), errno(Errno::EAGAIN));
    f.mem.write(GuestAddr(BUFFERS), b"x").unwrap();
    assert_eq!(f.ret(1, &[writer, BUFFERS, 1]), 1);
    // The pipe's wake-up gives its whole key, POLLIN | POLLRDNORM.
    assert_eq!(f.reap(ctx), [(2, waiting, 0x41)]);
    assert_eq!(f.ret(0, &[eventfd, BUFFERS, 8]), 8);
    assert_eq!(f.u64_at(BUFFERS), 1);
    assert_eq!(f.ret(0, &[reader, BUFFERS, 1]), 1);
    // Cancelling one that waits gives EINPROGRESS and an event of nothing;
    // one no longer waiting, or a key that is not 0, is EINVAL.
    let pending = f.iocb(
        2,
        Iocb {
            data: 3,
            fildes: reader as u32,
            ..poll
        },
    );
    assert_eq!(f.ret(SUBMIT, &[ctx, 1, POINTERS + 16]), 1);
    assert_eq!(f.ret(CANCEL, &[ctx, waiting, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(CANCEL, &[ctx, 0x4000_0000, 0]), errno(Errno::EFAULT));
    assert_eq!(f.ret(CANCEL, &[DATA, pending, 0]), errno(Errno::EINVAL));
    assert_eq!(f.ret(CANCEL, &[ctx, pending, 0]), errno(Errno(115)));
    assert_eq!(f.ret(CANCEL, &[ctx, pending, 0]), errno(Errno::EINVAL));
    assert_eq!(f.reap(ctx), [(3, pending, 0)]);
    f.mem
        .write(GuestAddr(pending + 8), &1u32.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(CANCEL, &[ctx, pending, 0]), errno(Errno::EINVAL));
    // The writer's end hangs the reader up.
    assert_eq!(f.ret(SUBMIT, &[ctx, 1, POINTERS + 16]), 1);
    assert_eq!(f.ret(3, &[writer]), 0);
    assert_eq!(f.reap(ctx), [(3, pending, 0x10)]);
    // io_destroy cancels what still waits, and counts it on its eventfd.
    let (reader, _writer) = f.pipe();
    f.iocb(
        3,
        Iocb {
            fildes: reader as u32,
            flags: 1,
            resfd: eventfd as u32,
            ..poll
        },
    );
    assert_eq!(f.ret(SUBMIT, &[ctx, 1, POINTERS + 24]), 1);
    assert_eq!(f.ret(DESTROY, &[ctx]), 0);
    assert_eq!(f.ret(0, &[eventfd, BUFFERS, 8]), 8);
    assert_eq!(f.u64_at(BUFFERS), 1);
}

#[test]
fn getevents_checks_its_arguments_and_waits_for_min_nr() {
    let mut f = fixture();
    let fd = f.file("a", b"abc");
    let ctx = f.setup(8);
    let ts = DATA + 0xf00;
    f.mem.write(GuestAddr(ts), &[0; 16]).unwrap();
    assert_eq!(
        f.ret(GETEVENTS, &[ctx, 0, 1, EVENTS, 0x4000_0000]),
        errno(Errno::EFAULT)
    );
    assert_eq!(
        f.ret(GETEVENTS, &[DATA, 0, 1, EVENTS, ts]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(GETEVENTS, &[ctx, 2, 1, EVENTS, ts]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        f.ret(GETEVENTS, &[ctx, -1i64 as u64, 1, EVENTS, ts]),
        errno(Errno::EINVAL)
    );
    assert_eq!(f.ret(GETEVENTS, &[ctx, 0, 0, EVENTS, 0]), 0);
    // A timeout of 1 ms ends a wait for an event that never comes.
    f.mem
        .write(GuestAddr(ts + 8), &1_000_000u64.to_le_bytes())
        .unwrap();
    assert_eq!(f.ret(GETEVENTS, &[ctx, 1, 1, EVENTS, ts]), 0);
    let read = Iocb {
        data: 5,
        fildes: fd as u32,
        buf: BUFFERS,
        nbytes: 1,
        ..Iocb::default()
    };
    f.iocb(0, read);
    f.iocb(1, read);
    assert_eq!(f.ret(SUBMIT, &[ctx, 2, POINTERS]), 2);
    // Events that cannot be written are EFAULT, and stay in the ring.
    assert_eq!(
        f.ret(GETEVENTS, &[ctx, 1, 2, 0x4000_0000, 0]),
        errno(Errno::EFAULT)
    );
    assert_eq!(f.u32_at(ctx + 8), 0);
    // One at a time, then the other.
    assert_eq!(f.ret(GETEVENTS, &[ctx, 1, 1, EVENTS, 0]), 1);
    assert_eq!(f.ret(GETEVENTS, &[ctx, 1, 5, EVENTS, ts]), 1);
    // Fewer than min_nr when the time is up.
    assert_eq!(f.submit(ctx, read), 1);
    assert_eq!(f.ret(GETEVENTS, &[ctx, 2, 5, EVENTS, ts]), 1);
    // io_pgetevents reads its timeout, then its {mask, size}, then the mask.
    let usig = DATA + 0xf80;
    assert_eq!(
        f.ret(PGETEVENTS, &[ctx, 0, 1, EVENTS, ts, 0x4000_0000]),
        errno(Errno::EFAULT)
    );
    f.mem
        .write(GuestAddr(usig), &(DATA + 0xfc0).to_le_bytes())
        .unwrap();
    f.mem
        .write(GuestAddr(usig + 8), &4u64.to_le_bytes())
        .unwrap();
    assert_eq!(
        f.ret(PGETEVENTS, &[ctx, 0, 1, EVENTS, ts, usig]),
        errno(Errno::EINVAL)
    );
    f.mem
        .write(GuestAddr(usig + 8), &8u64.to_le_bytes())
        .unwrap();
    f.mem.write(GuestAddr(DATA + 0xfc0), &[0; 8]).unwrap();
    assert_eq!(f.submit(ctx, read), 1);
    assert_eq!(f.ret(PGETEVENTS, &[ctx, 1, 1, EVENTS, ts, usig]), 1);
    assert_eq!(f.thread.state.signal_mask, 0);
}

#[test]
fn the_sysctls_show_and_bound_the_events() {
    let mut f = fixture();
    let read = |f: &mut Fixture, path: &str| -> Vec<u8> {
        let path = format!("{path}\0");
        f.mem
            .write(GuestAddr(DATA + 0xe00), path.as_bytes())
            .unwrap();
        let fd = f.ret(2, &[DATA + 0xe00, 0, 0]);
        let n = f.ret(0, &[fd, BUFFERS, 64]);
        assert_eq!(f.ret(3, &[fd]), 0);
        let mut b = vec![0; n as usize];
        f.mem.read(GuestAddr(BUFFERS), &mut b).unwrap();
        b
    };
    assert_eq!(read(&mut f, "/proc/sys/fs/aio-max-nr"), b"65536\n");
    assert_eq!(read(&mut f, "/proc/sys/fs/aio-nr"), b"0\n");
    let ctx = f.setup(5);
    assert_eq!(read(&mut f, "/proc/sys/fs/aio-nr"), b"5\n");
    // aio-nr cannot be written; aio-max-nr takes an unsigned long.
    f.mem
        .write(GuestAddr(DATA + 0xe00), b"/proc/sys/fs/aio-nr\0")
        .unwrap();
    assert_eq!(f.ret(2, &[DATA + 0xe00, 1, 0]), errno(Errno::EACCES));
    f.mem
        .write(GuestAddr(DATA + 0xe00), b"/proc/sys/fs/aio-max-nr\0")
        .unwrap();
    let fd = f.ret(2, &[DATA + 0xe00, 1, 0]);
    f.mem.write(GuestAddr(BUFFERS), b"-1\n").unwrap();
    assert_eq!(f.ret(1, &[fd, BUFFERS, 3]), errno(Errno::EINVAL));
    f.mem.write(GuestAddr(BUFFERS), b"9\n").unwrap();
    assert_eq!(f.ret(1, &[fd, BUFFERS, 2]), 2);
    assert_eq!(read(&mut f, "/proc/sys/fs/aio-max-nr"), b"9\n");
    f.mem.write(GuestAddr(CTX), &[0; 8]).unwrap();
    assert_eq!(f.ret(SETUP, &[5, CTX]), errno(Errno::EAGAIN));
    assert_eq!(f.ret(DESTROY, &[ctx]), 0);
    assert_ne!(f.setup(5), 0);
}
