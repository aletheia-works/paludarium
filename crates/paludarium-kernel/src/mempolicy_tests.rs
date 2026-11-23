//! NUMA memory policies through the system call interface: what
//! `get_mempolicy` reports for each mode and flag and the errors it checks,
//! the policies `set_mempolicy` takes and refuses, and `mbind`'s policies
//! of ranges as unmapping, `mremap`, a new mapping and the break change
//! them. The calls are those of the mempolicy case of
//! `tests/guests/processes/process.c`, made in the same order, but for the
//! thread and the two forked children, whose lines are left out (they only
//! read a policy and change none the rest reads). The expected lines are
//! what that case printed on native x86-64 Linux in the differential tests
//! (the CI run of main at b1641852), which compare it with Linux on every
//! run.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::GuestAddr;

const DATA: u64 = 0x60_0000;
/// `get_mempolicy`'s mode and two node words, `set_mempolicy`'s 32-word
/// mask, and `mbind`'s mask with node 0.
const MODE: u64 = DATA;
const NODES: u64 = DATA + 0x10;
const MASK: u64 = DATA + 0x100;
const ONE: u64 = DATA + 0x400;
const SIZE: u64 = 0x1000;
const BREAK: u64 = 0x80_0000;
const PAGE: u64 = 4096;

const MMAP: u64 = 9;
const MUNMAP: u64 = 11;
const BRK: u64 = 12;
const MREMAP: u64 = 25;
const MBIND: u64 = 237;
const SET_MEMPOLICY: u64 = 238;
const GET_MEMPOLICY: u64 = 239;

const PROT_NONE: u64 = 0;
const PROT_RW: u64 = 3;
const MAP_PRIVATE_ANONYMOUS: u64 = 0x22;
const MAP_FIXED: u64 = 0x10;
const MREMAP_MAYMOVE_FIXED: u64 = 3;

/// What the case printed on native Linux, without the thread's and the
/// children's lines.
const EXPECTED: &str = r#"default=0 errno=0 mode=0 nodes=0 next=0xffffffffffffffff
default-129=0 errno=0 mode=0 nodes=0 next=0
default-1=0 errno=0 mode=0 nodes=0xffffffffffffffff next=0xffffffffffffffff
maxnode-0=-1 errno=22 mode=-1 nodes=0xffffffffffffffff next=0xffffffffffffffff
mems-allowed=0 errno=0 mode=0 nodes=0x1 next=0xffffffffffffffff
mems-and-node=-1 errno=22 mode=-1 nodes=0xffffffffffffffff next=0xffffffffffffffff
unknown-flag=-1 errno=22 mode=-1 nodes=0xffffffffffffffff next=0xffffffffffffffff
addr-without-flag=-1 errno=22 mode=-1 nodes=0xffffffffffffffff next=0xffffffffffffffff
node-of-default=-1 errno=22 mode=-1 nodes=0xffffffffffffffff next=0xffffffffffffffff
mode-fault=-1 errno=14
mask-fault=-1 errno=14
mask-too-big=-1 errno=22
bind-0=0 errno=0
bind-0-get=0 errno=0 mode=2 nodes=0x1 next=0xffffffffffffffff
bind-01=0 errno=0
bind-01-get=0 errno=0 mode=2 nodes=0x1 next=0xffffffffffffffff
bind-1=-1 errno=22
after-bind-1=0 errno=0 mode=2 nodes=0x1 next=0xffffffffffffffff
bind-empty=-1 errno=22
bind-maxnode-1=-1 errno=22
interleave=0 errno=0
interleave-node=0 errno=0 mode=0 nodes=0x1 next=0xffffffffffffffff
weighted=0 errno=0
weighted-get=0 errno=0 mode=6 nodes=0x1 next=0xffffffffffffffff
weighted-node=0 errno=0 mode=0 nodes=0x1 next=0xffffffffffffffff
preferred-empty=0 errno=0
preferred-empty-get=0 errno=0 mode=4 nodes=0 next=0xffffffffffffffff
preferred-01=0 errno=0
preferred-01-get=0 errno=0 mode=1 nodes=0x1 next=0xffffffffffffffff
preferred-many=0 errno=0
preferred-many-get=0 errno=0 mode=5 nodes=0x1 next=0xffffffffffffffff
local=0 errno=0
local-get=0 errno=0 mode=4 nodes=0 next=0xffffffffffffffff
local-nodes=-1 errno=22
default-nodes=-1 errno=22
mode-7=-1 errno=22
static=0 errno=0
static-get=0 errno=0 mode=32770 nodes=0x3 next=0xffffffffffffffff
relative=0 errno=0
relative-get=0 errno=0 mode=16387 nodes=0x4 next=0xffffffffffffffff
static-relative=-1 errno=22
preferred-static-empty=-1 errno=22
balancing=0 errno=0
balancing-get=0 errno=0 mode=8194 nodes=0x1 next=0xffffffffffffffff
balancing-interleave=-1 errno=22
bit-1023=0 errno=0
bit-1024=-1 errno=22
too-long=-1 errno=22
nodes-fault=-1 errno=14
null-nodes=-1 errno=22
interleave-again=0 errno=0
back-to-default=0 errno=0
default-again=0 errno=0 mode=0 nodes=0 next=0xffffffffffffffff
mbind=0 errno=0
addr-bound=0 errno=0 mode=2 nodes=0x1 next=0xffffffffffffffff
addr-after=0 errno=0 mode=0 nodes=0 next=0xffffffffffffffff
addr-node=0 errno=0 mode=0 nodes=0x1 next=0xffffffffffffffff
task-unchanged=0 errno=0 mode=0 nodes=0 next=0xffffffffffffffff
mbind-unaligned=-1 errno=22
mbind-zero=0 errno=0
mbind-zero-bad-mode=-1 errno=22
mbind-empty=-1 errno=22
mbind-flag=-1 errno=22
mbind-strict=0 errno=0
mbind-move=0 errno=0
addr-interleave=0 errno=0 mode=3 nodes=0x1 next=0xffffffffffffffff
mbind-default-part=0 errno=0
addr-split-low=0 errno=0 mode=2 nodes=0x1 next=0xffffffffffffffff
addr-split-high=0 errno=0 mode=0 nodes=0 next=0xffffffffffffffff
addr-unmapped=-1 errno=14 mode=-1 nodes=0xffffffffffffffff next=0xffffffffffffffff
mbind-hole=-1 errno=14
mbind-hole-default=0 errno=0
hole-default-low=0 errno=0 mode=0 nodes=0 next=0xffffffffffffffff
mbind-all-hole=-1 errno=14
mbind-again=0 errno=0
addr-none-node=-1 errno=14 mode=-1 nodes=0xffffffffffffffff next=0xffffffffffffffff
moved=1
moved-policy=0 errno=0 mode=2 nodes=0x1 next=0xffffffffffffffff
moved-from=-1 errno=14 mode=-1 nodes=0xffffffffffffffff next=0xffffffffffffffff
fresh=1
fresh-policy=0 errno=0 mode=0 nodes=0 next=0xffffffffffffffff
grown=1
mbind-heap=0 errno=0
same-page=1
heap-kept=0 errno=0 mode=2 nodes=0x1 next=0xffffffffffffffff
shrunk=1
heap-gone=-1 errno=14 mode=-1 nodes=0xffffffffffffffff next=0xffffffffffffffff
regrown=1
heap-new=0 errno=0 mode=0 nodes=0 next=0xffffffffffffffff
"#;

/// A process's thread and the lines it prints.
struct Env {
    k: Box<Kernel>,
    t: Thread,
    m: Arc<AddressSpace>,
    lines: Vec<String>,
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
        let mut m = AddressSpace::new();
        m.set_initial_break(GuestAddr(BREAK));
        let m = Arc::new(m);
        m.map_shared(
            Some(GuestAddr(DATA)),
            SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        m.write(GuestAddr(ONE), &1u64.to_le_bytes()).unwrap();
        Self {
            k,
            t,
            m,
            lines: Vec::new(),
        }
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

    fn word(&self, at: u64) -> u64 {
        self.m.read_u64(GuestAddr(at)).unwrap()
    }

    /// The guest's `outcome`: a raw call's result and its errno.
    fn outcome(&mut self, name: &str, r: i64) {
        let line = if r < 0 {
            format!("{name}=-1 errno={}", -r)
        } else {
            format!("{name}={r} errno=0")
        };
        self.lines.push(line);
    }

    /// The guest's `result`.
    fn result(&mut self, name: &str, value: bool) {
        self.lines.push(format!("{name}={}", u8::from(value)));
    }

    /// The guest's `policy`: `get_mempolicy` into a mode of -1 and two
    /// node words of all ones.
    fn policy(&mut self, name: &str, maxnode: u64, addr: u64, flags: u64) {
        self.m
            .write(GuestAddr(MODE), &(-1i32).to_le_bytes())
            .unwrap();
        self.m.write(GuestAddr(NODES), &[0xff; 16]).unwrap();
        let r = self.call(GET_MEMPOLICY, [MODE, NODES, maxnode, addr, flags, 0]);
        let mode = self.word(MODE) as u32 as i32;
        let (nodes, next) = (self.word(NODES), self.word(NODES + 8));
        let (r, errno) = if r < 0 { (-1, -r) } else { (r, 0) };
        self.lines.push(format!(
            "{name}={r} errno={errno} mode={mode} nodes={} next={}",
            hex(nodes),
            hex(next)
        ));
    }

    /// The guest's `set_policy`: `set_mempolicy` with a 32-word mask whose
    /// first word is `nodes`.
    fn set_policy(&mut self, name: &str, mode: u64, nodes: u64, maxnode: u64) {
        let mut mask = [0u64; 32];
        mask[0] = nodes;
        self.mask(&mask);
        let r = self.call(SET_MEMPOLICY, [mode, MASK, maxnode, 0, 0, 0]);
        self.outcome(name, r);
    }

    fn mask(&self, mask: &[u64; 32]) {
        let bytes: Vec<u8> = mask.iter().flat_map(|w| w.to_le_bytes()).collect();
        self.m.write(GuestAddr(MASK), &bytes).unwrap();
    }

    /// The guest's `MBIND`: `mbind` with a maxnode of 65.
    fn mbind(&mut self, name: &str, at: u64, len: u64, mode: u64, nodes: u64, flags: u64) {
        let r = self.call(MBIND, [at, len, mode, nodes, 65, flags]);
        self.outcome(name, r);
    }

    fn mmap(&mut self, at: u64, len: u64, prot: u64, flags: u64) -> u64 {
        let r = self.call(MMAP, [at, len, prot, flags, u64::MAX, 0]);
        assert!(r > 0, "mmap {r}");
        r as u64
    }
}

/// `%#lx`: `0` for zero, as glibc and musl print it.
fn hex(v: u64) -> String {
    if v == 0 {
        "0".into()
    } else {
        format!("{v:#x}")
    }
}

#[test]
fn mempolicy_calls_as_linux() {
    let mut e = Env::new();
    e.policy("default", 65, 0, 0);
    e.policy("default-129", 129, 0, 0);
    e.policy("default-1", 1, 0, 0);
    e.policy("maxnode-0", 0, 0, 0);
    e.policy("mems-allowed", 65, 0, 4);
    e.policy("mems-and-node", 65, 0, 5);
    e.policy("unknown-flag", 65, 0, 8);
    e.policy("addr-without-flag", 65, PAGE, 0);
    e.policy("node-of-default", 65, 0, 1);
    let r = e.call(GET_MEMPOLICY, [1, 0, 0, 0, 0, 0]);
    e.outcome("mode-fault", r);
    let r = e.call(GET_MEMPOLICY, [0, 1, 65, 0, 0, 0]);
    e.outcome("mask-fault", r);
    let r = e.call(GET_MEMPOLICY, [0, 1, PAGE * 8 + 2, 0, 0, 0]);
    e.outcome("mask-too-big", r);

    e.set_policy("bind-0", 2, 1, 65);
    e.policy("bind-0-get", 65, 0, 0);
    e.set_policy("bind-01", 2, 3, 65);
    e.policy("bind-01-get", 65, 0, 0);
    e.set_policy("bind-1", 2, 2, 65);
    e.policy("after-bind-1", 65, 0, 0);
    e.set_policy("bind-empty", 2, 0, 65);
    e.set_policy("bind-maxnode-1", 2, 1, 1);
    e.set_policy("interleave", 3, 1, 65);
    e.policy("interleave-node", 65, 0, 1);
    e.set_policy("weighted", 6, 1, 65);
    e.policy("weighted-get", 65, 0, 0);
    e.policy("weighted-node", 65, 0, 1);
    e.set_policy("preferred-empty", 1, 0, 65);
    e.policy("preferred-empty-get", 65, 0, 0);
    e.set_policy("preferred-01", 1, 3, 65);
    e.policy("preferred-01-get", 65, 0, 0);
    e.set_policy("preferred-many", 5, 1, 65);
    e.policy("preferred-many-get", 65, 0, 0);
    e.set_policy("local", 4, 0, 65);
    e.policy("local-get", 65, 0, 0);
    e.set_policy("local-nodes", 4, 1, 65);
    e.set_policy("default-nodes", 0, 1, 65);
    e.set_policy("mode-7", 7, 1, 65);
    e.set_policy("static", 2 | 0x8000, 3, 65);
    e.policy("static-get", 65, 0, 0);
    e.set_policy("relative", 3 | 0x4000, 4, 65);
    e.policy("relative-get", 65, 0, 0);
    e.set_policy("static-relative", 2 | 0xc000, 1, 65);
    e.set_policy("preferred-static-empty", 1 | 0x8000, 0, 65);
    e.set_policy("balancing", 2 | 0x2000, 1, 65);
    e.policy("balancing-get", 65, 0, 0);
    e.set_policy("balancing-interleave", 3 | 0x2000, 1, 65);
    let mut mask = [0u64; 32];
    mask[0] = 1;
    mask[15] = 1 << 63;
    e.mask(&mask);
    let r = e.call(SET_MEMPOLICY, [2, MASK, 1025, 0, 0, 0]);
    e.outcome("bit-1023", r);
    mask[15] = 0;
    mask[16] = 1;
    e.mask(&mask);
    let r = e.call(SET_MEMPOLICY, [2, MASK, 2000, 0, 0, 0]);
    e.outcome("bit-1024", r);
    let r = e.call(SET_MEMPOLICY, [2, MASK, PAGE * 8 + 2, 0, 0, 0]);
    e.outcome("too-long", r);
    let r = e.call(SET_MEMPOLICY, [2, 1, 65, 0, 0, 0]);
    e.outcome("nodes-fault", r);
    let r = e.call(SET_MEMPOLICY, [2, 0, 65, 0, 0, 0]);
    e.outcome("null-nodes", r);

    // The case's thread and first child come here.
    e.set_policy("interleave-again", 3, 1, 65);
    e.set_policy("back-to-default", 0, 0, 65);
    e.policy("default-again", 65, 0, 0);

    let map = e.mmap(0, 4 * PAGE, PROT_RW, MAP_PRIVATE_ANONYMOUS);
    e.mbind("mbind", map, 2 * PAGE, 2, ONE, 0);
    e.policy("addr-bound", 65, map + PAGE + 7, 2);
    e.policy("addr-after", 65, map + 2 * PAGE, 2);
    e.policy("addr-node", 65, map, 3);
    e.policy("task-unchanged", 65, 0, 0);
    e.mbind("mbind-unaligned", map + 1, PAGE, 2, ONE, 0);
    e.mbind("mbind-zero", map, 0, 2, ONE, 0);
    e.mbind("mbind-zero-bad-mode", map, 0, 7, ONE, 0);
    e.mbind("mbind-empty", map, PAGE, 2, 0, 0);
    e.mbind("mbind-flag", map, PAGE, 2, ONE, 8);
    e.mbind("mbind-strict", map + 3 * PAGE, PAGE, 3, ONE, 1);
    e.mbind("mbind-move", map + 3 * PAGE, PAGE, 3, ONE, 2);
    e.policy("addr-interleave", 65, map + 3 * PAGE, 2);
    e.mbind("mbind-default-part", map + PAGE, PAGE, 0, 0, 0);
    e.policy("addr-split-low", 65, map, 2);
    e.policy("addr-split-high", 65, map + PAGE, 2);
    assert_eq!(e.call(MUNMAP, [map + 2 * PAGE, PAGE, 0, 0, 0, 0]), 0);
    e.policy("addr-unmapped", 65, map + 2 * PAGE, 2);
    e.mbind("mbind-hole", map, 4 * PAGE, 2, ONE, 0);
    e.mbind("mbind-hole-default", map, 4 * PAGE, 0, 0, 0);
    e.policy("hole-default-low", 65, map, 2);
    e.mbind("mbind-all-hole", map + 2 * PAGE, PAGE, 0, 0, 0);
    e.mbind("mbind-again", map, PAGE, 2, ONE, 0);

    // The second child comes here.
    let moved = e.mmap(0, 2 * PAGE, PROT_NONE, MAP_PRIVATE_ANONYMOUS);
    e.policy("addr-none-node", 65, moved, 3);
    assert_eq!(e.call(MUNMAP, [moved, 2 * PAGE, 0, 0, 0, 0]), 0);
    let to = e.call(MREMAP, [map, PAGE, PAGE, MREMAP_MAYMOVE_FIXED, moved, 0]);
    e.result("moved", to as u64 == moved);
    e.policy("moved-policy", 65, moved, 2);
    e.policy("moved-from", 65, map, 2);
    let fresh = e.mmap(moved, PAGE, PROT_RW, MAP_PRIVATE_ANONYMOUS | MAP_FIXED);
    e.result("fresh", fresh == moved);
    e.policy("fresh-policy", 65, moved, 2);

    let heap = e.call(BRK, [0; 6]) as u64;
    let top = heap + 2 * PAGE + 100;
    let r = e.call(BRK, [top, 0, 0, 0, 0, 0]) as u64;
    e.result("grown", r == top);
    let last = (top - 1) & !(PAGE - 1);
    e.mbind("mbind-heap", last, PAGE, 2, ONE, 0);
    e.call(BRK, [0; 6]);
    let r = e.call(BRK, [top + 50, 0, 0, 0, 0, 0]) as u64;
    e.result("same-page", r == top + 50);
    e.policy("heap-kept", 65, last, 2);
    let r = e.call(BRK, [last, 0, 0, 0, 0, 0]) as u64;
    e.result("shrunk", r == last);
    e.policy("heap-gone", 65, last, 2);
    let r = e.call(BRK, [top, 0, 0, 0, 0, 0]) as u64;
    e.result("regrown", r == top);
    e.policy("heap-new", 65, last, 2);

    assert_eq!(e.lines, EXPECTED.lines().collect::<Vec<_>>());
}
