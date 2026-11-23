//! The files of a thread's /proc directory (`/proc/self/task/<tid>`),
//! which `files/tasks.rs` makes: each of them has a size of 0 to `stat`
//! and `fstat`, as Linux's do, and a read still gives its text. The calls
//! are those of the proc-sizes case of `tests/guests/processes/process.c`
//! for its `thread` line, made in the same order as musl makes them. The
//! expected line is what that case printed on native x86-64 Linux in the
//! differential tests (the CI run of main at b1641852), which compare it
//! with Linux on every run.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::GuestAddr;

const DATA: u64 = 0x60_0000;
/// A path, a `struct stat` for `stat` and one for `fstat`, and a buffer.
const PATH: u64 = DATA;
const STAT: u64 = DATA + 0x100;
const OPEN_STAT: u64 = DATA + 0x200;
const BUFFER: u64 = DATA + 0x300;
/// The stack an exec leaves: `argc`, `argv` and an empty `envp`, which
/// `cmdline` reads, and the argument's string.
const STACK: u64 = DATA + 0x800;
const ARGUMENT: u64 = DATA + 0x900;
const SIZE: u64 = 0x1000;
/// `st_size` in `struct stat`.
const ST_SIZE: u64 = 48;

const READ: u64 = 0;
const OPEN: u64 = 2;
const CLOSE: u64 = 3;
const FSTAT: u64 = 5;
const GETTID: u64 = 186;
const NEWFSTATAT: u64 = 262;
const AT_FDCWD: u64 = -100i64 as u64;
/// musl's `open` adds `O_LARGEFILE`.
const O_RDONLY_LARGEFILE: u64 = 0o100000;

/// The case's `ps_entries`.
const ENTRIES: [&str; 19] = [
    "status",
    "stat",
    "statm",
    "limits",
    "cmdline",
    "environ",
    "comm",
    "auxv",
    "uid_map",
    "gid_map",
    "setgroups",
    "mounts",
    "mountinfo",
    "io",
    "personality",
    "wchan",
    "maps",
    "smaps",
    "fdinfo/0",
];

/// What the case printed on native Linux for the thread.
const EXPECTED: &str = "thread: status=0/0,0/0,1 stat=0/0,0/0,1 statm=0/0,0/0,1 \
limits=0/0,0/0,1 cmdline=0/0,0/0,1 environ=0/0,0/0,0 comm=0/0,0/0,1 auxv=0/0,0/0,1 \
uid_map=0/0,0/0,1 gid_map=0/0,0/0,1 setgroups=0/0,0/0,1 mounts=0/0,0/0,1 \
mountinfo=0/0,0/0,1 io=0/0,0/0,1 personality=0/0,0/0,1 wchan=0/0,0/0,1 maps=0/0,0/0,1 \
smaps=0/0,0/0,1 fdinfo/0=0/0,0/0,1";

/// A process's thread.
struct Env {
    k: Box<Kernel>,
    t: Thread,
    m: Arc<AddressSpace>,
}

impl Env {
    fn new() -> Self {
        let k = Box::new(Kernel::new(Arc::new(
            paludarium_host::testing::RecordingHost::new(),
        )));
        k.enter_thread(1);
        let t = Thread::new(
            1,
            CpuState::new(GuestAddr(0x40_0000), GuestAddr(DATA + SIZE)),
        );
        let m = Arc::new(AddressSpace::new());
        m.map_shared(
            Some(GuestAddr(DATA)),
            SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        // What an exec of `process` leaves for `cmdline` and `auxv`.
        m.write(GuestAddr(ARGUMENT), b"process\0").unwrap();
        for (i, word) in [1, ARGUMENT, 0, 0].into_iter().enumerate() {
            m.write(GuestAddr(STACK + 8 * i as u64), &u64::to_le_bytes(word))
                .unwrap();
        }
        let mut auxv = [(0, 0); paludarium_loader::AUXV_ENTRIES];
        auxv[0] = (6, 4096); // AT_PAGESZ
        k.group.set_program(&paludarium_loader::LoadedImage {
            entry_point: GuestAddr(0x40_1000),
            program_entry: GuestAddr(0x40_1000),
            interpreter_base: 0,
            program_header_address: GuestAddr(0x40_0040),
            program_header_count: 2,
            initial_stack_pointer: GuestAddr(STACK),
            initial_break: GuestAddr(0x40_4000),
            load_base: GuestAddr(0),
            auxv,
            code: (0x40_1000, 0x40_2345),
            data: (0x40_3000, 0x40_3100),
            fails: false,
        });
        Self { k, t, m }
    }

    /// A call's result, or `-errno`.
    fn call(&mut self, n: u64, a: [u64; 6]) -> i64 {
        let t = &mut self.t;
        t.cpu.gpr[reg::RAX] = n;
        t.cpu.gpr[reg::RDI] = a[0];
        t.cpu.gpr[reg::RSI] = a[1];
        t.cpu.gpr[reg::RDX] = a[2];
        t.cpu.gpr[reg::R10] = a[3];
        t.cpu.gpr[reg::R8] = a[4];
        t.cpu.gpr[reg::R9] = a[5];
        self.k
            .handle(t, &self.m, ExitReason::Syscall { rip: t.cpu.rip });
        t.cpu.gpr[reg::RAX] as i64
    }

    fn size(&self, at: u64) -> i64 {
        self.m.read_u64(GuestAddr(at + ST_SIZE)).unwrap() as i64
    }

    /// The case's `ps_show`: for each entry, `stat`'s errno and size, the
    /// open's or `fstat`'s errno and the size, and whether a read of 64
    /// bytes gave any.
    fn show(&mut self, who: &str, dir: &str) -> String {
        let mut line = format!("{who}:");
        for entry in ENTRIES {
            let mut path = format!("{dir}/{entry}").into_bytes();
            path.push(0);
            self.m.write(GuestAddr(PATH), &path).unwrap();
            self.m.write(GuestAddr(STAT), &[0; 144]).unwrap();
            self.m.write(GuestAddr(OPEN_STAT), &[0; 144]).unwrap();
            let r = self.call(NEWFSTATAT, [AT_FDCWD, PATH, STAT, 0, 0, 0]);
            let fd = self.call(OPEN, [PATH, O_RDONLY_LARGEFILE, 0, 0, 0, 0]);
            let f = if fd < 0 {
                -fd
            } else {
                -self.call(FSTAT, [fd as u64, OPEN_STAT, 0, 0, 0, 0])
            };
            let n = if fd < 0 {
                -1
            } else {
                self.call(READ, [fd as u64, BUFFER, 64, 0, 0, 0])
            };
            if fd >= 0 {
                self.call(CLOSE, [fd as u64, 0, 0, 0, 0, 0]);
            }
            line += &format!(
                " {entry}={}/{},{}/{},{}",
                -r,
                self.size(STAT),
                f,
                self.size(OPEN_STAT),
                u8::from(n > 0)
            );
        }
        line
    }
}

#[test]
fn thread_proc_files_have_no_size_as_linux() {
    let mut e = Env::new();
    let tid = e.call(GETTID, [0; 6]);
    let line = e.show("thread", &format!("/proc/self/task/{tid}"));
    assert_eq!(line, EXPECTED);
}
