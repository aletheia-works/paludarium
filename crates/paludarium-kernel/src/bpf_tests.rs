//! `bpf(2)`'s map commands through the system call interface: the checks
//! `BPF_MAP_CREATE` makes, queues, stacks and bloom filters, maps of maps,
//! map IDs, the access a descriptor gives, and `BPF_OBJ_GET_INFO_BY_FD`.
//! The expected values are Linux's (`kernel/bpf/syscall.c` and the map
//! types' files); most are cases of `tests/guests/processes/bpf.c`, which
//! the differential tests compare with Linux.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::{Errno, Error, GuestAddr, PAGE_SIZE};

const DATA: u64 = 0x600000;
/// Where the tests put a `union bpf_attr`.
const ATTR: u64 = DATA;
/// A key, and a value or what a command gives back.
const KEY: u64 = DATA + 0x200;
const VALUE: u64 = DATA + 0x300;
/// Where `BPF_OBJ_GET_INFO_BY_FD` puts a `struct bpf_map_info`.
const INFO: u64 = DATA + 0x800;
/// An address no mapping covers.
const UNMAPPED: u64 = 0x10;
/// No descriptor.
const NO_FD: u64 = 999;

const BPF: u64 = 321;
const CLOSE: u64 = 3;
const FCNTL: u64 = 72;
const FTRUNCATE: u64 = 77;
const F_SETFL: u64 = 4;
const O_NONBLOCK: u64 = 0o4000;

const MAP_CREATE: u64 = 0;
const MAP_LOOKUP_ELEM: u64 = 1;
const MAP_UPDATE_ELEM: u64 = 2;
const MAP_DELETE_ELEM: u64 = 3;
const MAP_GET_NEXT_KEY: u64 = 4;
const MAP_GET_NEXT_ID: u64 = 12;
const MAP_GET_FD_BY_ID: u64 = 14;
const OBJ_GET_INFO_BY_FD: u64 = 15;
const MAP_LOOKUP_AND_DELETE_ELEM: u64 = 21;
const MAP_FREEZE: u64 = 22;
const MAP_LOOKUP_BATCH: u64 = 24;
const MAP_LOOKUP_AND_DELETE_BATCH: u64 = 25;
const MAP_UPDATE_BATCH: u64 = 26;
const MAP_DELETE_BATCH: u64 = 27;

const HASH: u32 = 1;
const ARRAY: u32 = 2;
const ARRAY_OF_MAPS: u32 = 12;
const HASH_OF_MAPS: u32 = 13;
const LRU_HASH: u32 = 9;
const LPM_TRIE: u32 = 11;
const QUEUE: u32 = 22;
const STACK: u32 = 23;
const BLOOM_FILTER: u32 = 30;

const F_NO_PREALLOC: u32 = 1;
const F_NO_COMMON_LRU: u32 = 1 << 1;
const F_NUMA_NODE: u32 = 1 << 2;
const F_RDONLY: u32 = 1 << 3;
const F_WRONLY: u32 = 1 << 4;
const F_ZERO_SEED: u32 = 1 << 6;
const F_RDONLY_PROG: u32 = 1 << 7;
const F_WRONLY_PROG: u32 = 1 << 8;
const F_MMAPABLE: u32 = 1 << 10;
const F_PRESERVE_ELEMS: u32 = 1 << 11;
const F_TOKEN_FD: u32 = 1 << 16;
const NOEXIST: u64 = 1;
const EXIST: u64 = 2;

const E2BIG: Errno = Errno(7);
const EEXIST: Errno = Errno(17);
/// `EBADFD`, which `BPF_OBJ_GET_INFO_BY_FD` gives for no descriptor.
const EBADFD: Errno = Errno(77);
/// The kernel's own `ENOTSUPP`, which `bpf(2)` lets out.
const ENOTSUPP: Errno = Errno(524);

fn setup() -> (Kernel, Thread, AddressSpace) {
    on(Arc::new(paludarium_host::testing::RecordingHost::new()))
}

/// A host of a fixed number of CPUs, which an LRU hash's lists depend on.
struct Cpus(usize);
impl Host for Cpus {
    fn read_stdin(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Ok(0)
    }
    fn write_stdout(&self, buf: &[u8]) -> Result<usize, Errno> {
        Ok(buf.len())
    }
    fn write_stderr(&self, buf: &[u8]) -> Result<usize, Errno> {
        Ok(buf.len())
    }
    fn random_bytes(&self, _: &mut [u8]) -> Result<(), Error> {
        Ok(())
    }
    fn cpu_count(&self) -> usize {
        self.0
    }
}

fn on(host: Arc<dyn Host>) -> (Kernel, Thread, AddressSpace) {
    let kernel = Kernel::new(host);
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

/// A `union bpf_attr` of fields at their byte offsets.
#[derive(Default)]
struct Attr(Vec<(usize, Vec<u8>)>);

impl Attr {
    fn half(mut self, at: usize, v: u32) -> Self {
        self.0.push((at, v.to_le_bytes().to_vec()));
        self
    }
    fn word(mut self, at: usize, v: u64) -> Self {
        self.0.push((at, v.to_le_bytes().to_vec()));
        self
    }
    fn bytes(mut self, at: usize, v: &[u8]) -> Self {
        self.0.push((at, v.to_vec()));
        self
    }
}

/// `bpf(command, attr, sizeof(union bpf_attr))`.
fn bpf(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, command: u64, attr: &Attr) -> u64 {
    let mut b = [0u8; 168];
    for (at, v) in &attr.0 {
        b[*at..*at + v.len()].copy_from_slice(v);
    }
    m.write(GuestAddr(ATTR), &b).unwrap();
    syscall(k, t, m, BPF, [command, ATTR, b.len() as u64, 0, 0, 0])
}

/// The `BPF_MAP_CREATE` attribute of a map of `kind`.
fn map(kind: u32, key: u32, value: u32, entries: u32, flags: u32) -> Attr {
    Attr::default()
        .half(0, kind)
        .half(4, key)
        .half(8, value)
        .half(12, entries)
        .half(16, flags)
}

fn create(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, attr: Attr) -> u64 {
    bpf(k, t, m, MAP_CREATE, &attr)
}

/// The descriptor of a new map of `attr`.
fn make(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, attr: Attr) -> u64 {
    let fd = create(k, t, m, attr);
    assert!(fd < 1024, "create: {fd:#x}");
    fd
}

/// An element command with no flags; see [`elem_with`].
fn elem(
    k: &mut Kernel,
    t: &mut Thread,
    m: &AddressSpace,
    command: u64,
    fd: u64,
    key: Option<&[u8]>,
    value: Option<&[u8]>,
) -> u64 {
    elem_with(k, t, m, command, fd, (key, value), 0)
}

/// An element command on the map of `fd` with the key and value at `KEY`
/// and `VALUE` (or none where one is `None`), which are written there
/// first, and `flags`.
fn elem_with(
    k: &mut Kernel,
    t: &mut Thread,
    m: &AddressSpace,
    command: u64,
    fd: u64,
    (key, value): (Option<&[u8]>, Option<&[u8]>),
    flags: u64,
) -> u64 {
    if let Some(key) = key {
        m.write(GuestAddr(KEY), key).unwrap();
    }
    if let Some(value) = value {
        m.write(GuestAddr(VALUE), value).unwrap();
    }
    let attr = Attr::default()
        .half(0, fd as u32)
        .word(8, key.map_or(0, |_| KEY))
        .word(16, value.map_or(0, |_| VALUE))
        .word(24, flags);
    bpf(k, t, m, command, &attr)
}

/// The eight bytes of `VALUE`, where a lookup puts what it finds.
fn value(m: &AddressSpace) -> u64 {
    let mut b = [0; 8];
    m.read(GuestAddr(VALUE), &mut b).unwrap();
    u64::from_le_bytes(b)
}

/// `BPF_OBJ_GET_INFO_BY_FD`'s `struct bpf_map_info` of `fd`, of
/// `len` bytes.
fn info(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, fd: u64, len: u32) -> u64 {
    let attr = Attr::default()
        .half(0, fd as u32)
        .half(4, len)
        .word(8, INFO);
    bpf(k, t, m, OBJ_GET_INFO_BY_FD, &attr)
}

/// The map ID of `fd`, from its `struct bpf_map_info`.
fn id(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, fd: u64) -> u32 {
    assert_eq!(info(k, t, m, fd, 8), 0);
    let mut b = [0; 4];
    m.read(GuestAddr(INFO + 4), &mut b).unwrap();
    u32::from_le_bytes(b)
}

#[test]
fn a_command_with_master_s_common_attributes_is_no_command() {
    // BPF_COMMON_ATTRS (1 << 16) is master's; Linux 7.0 has no such flag,
    // so the command is a number with no command, even with a struct
    // bpf_common_attr in the fourth and fifth arguments.
    let (mut k, mut t, m) = setup();
    let einval = errno(Errno::EINVAL);
    let attr = map(ARRAY, 4, 8, 4, 0);
    assert_eq!(bpf(&mut k, &mut t, &m, MAP_CREATE | 1 << 16, &attr), einval);
    m.write(GuestAddr(ATTR), &[0; 168]).unwrap();
    assert_eq!(
        syscall(
            &mut k,
            &mut t,
            &m,
            BPF,
            [MAP_CREATE | 1 << 16, ATTR, 168, ATTR, 24, 0]
        ),
        einval
    );
    // The size and the copy still come first.
    assert_eq!(
        syscall(
            &mut k,
            &mut t,
            &m,
            BPF,
            [MAP_CREATE | 1 << 16, ATTR, 4097, 0, 0, 0]
        ),
        errno(E2BIG)
    );
    assert_eq!(
        syscall(
            &mut k,
            &mut t,
            &m,
            BPF,
            [MAP_CREATE | 1 << 16, 0, 168, 0, 0, 0]
        ),
        errno(Errno::EFAULT)
    );
    // Without the flag, the same attribute makes the map.
    assert!(create(&mut k, &mut t, &m, attr) < 1 << 31);
}

#[test]
fn map_create_refuses_each_attribute_linux_refuses() {
    let (mut k, mut t, m) = setup();
    let einval = errno(Errno::EINVAL);
    let array = || map(ARRAY, 4, 8, 4, 0);
    // The checks of map_create before the type's: map_extra for a type
    // without it, a NUMA node that is not one, and an unknown type.
    assert_eq!(create(&mut k, &mut t, &m, array().word(64, 1)), einval);
    assert_eq!(
        create(
            &mut k,
            &mut t,
            &m,
            map(ARRAY, 4, 8, 4, F_NUMA_NODE).half(24, 5000)
        ),
        einval
    );
    assert_eq!(create(&mut k, &mut t, &m, map(1000, 4, 8, 4, 0)), einval);
    // BTF: a key's type without a value's, a vmlinux value's type for a
    // map that is no struct_ops, and a descriptor that is not BTF.
    assert_eq!(create(&mut k, &mut t, &m, array().half(52, 1)), einval);
    assert_eq!(create(&mut k, &mut t, &m, array().half(60, 1)), einval);
    let other = make(&mut k, &mut t, &m, map(ARRAY, 4, 8, 4, 0));
    let btf = |fd: u64| array().half(48, fd as u32).half(52, 1).half(56, 1);
    assert_eq!(create(&mut k, &mut t, &m, btf(other)), einval);
    assert_eq!(create(&mut k, &mut t, &m, btf(NO_FD)), errno(Errno::EBADF));
    // An array's own: kept elements are a program array's, and both
    // descriptor accesses at once are neither.
    assert_eq!(
        create(&mut k, &mut t, &m, map(ARRAY, 4, 8, 4, F_PRESERVE_ELEMS)),
        einval
    );
    assert_eq!(
        create(&mut k, &mut t, &m, map(ARRAY, 4, 8, 4, F_RDONLY | F_WRONLY)),
        einval
    );
    // A token's descriptor (bpf_token_get_from_fd): none, or a file that
    // is not a token.
    let token = |fd: u64| map(ARRAY, 4, 8, 4, F_TOKEN_FD).half(76, fd as u32);
    assert_eq!(
        create(&mut k, &mut t, &m, token(NO_FD)),
        errno(Errno::EBADF)
    );
    assert_eq!(create(&mut k, &mut t, &m, token(other)), einval);
    // The name: letters, digits, `_` and `.`, with its NUL.
    assert_eq!(
        create(&mut k, &mut t, &m, array().bytes(28, b"a-b\0")),
        einval
    );
    assert_eq!(
        create(&mut k, &mut t, &m, array().bytes(28, b"0123456789abcdef")),
        einval
    );
    let named = create(&mut k, &mut t, &m, array().bytes(28, b"map_1.x\0"));
    assert!(named < 1024);
    // A map's descriptor takes no truncate, and its status flags change.
    assert_eq!(
        syscall(&mut k, &mut t, &m, FTRUNCATE, [named, 0, 0, 0, 0, 0]),
        einval
    );
    assert_eq!(
        syscall(
            &mut k,
            &mut t,
            &m,
            FCNTL,
            [named, F_SETFL, O_NONBLOCK, 0, 0, 0]
        ),
        0
    );
}

#[test]
fn a_queue_gives_its_oldest_and_a_stack_its_newest_without_keys() {
    let (mut k, mut t, m) = setup();
    let einval = errno(Errno::EINVAL);
    assert_eq!(create(&mut k, &mut t, &m, map(QUEUE, 4, 8, 4, 0)), einval);
    assert_eq!(create(&mut k, &mut t, &m, map(STACK, 4, 8, 4, 0)), einval);
    assert_eq!(create(&mut k, &mut t, &m, map(QUEUE, 0, 0, 4, 0)), einval);
    assert_eq!(
        create(&mut k, &mut t, &m, map(QUEUE, 0, 8, 4, F_MMAPABLE)),
        einval
    );
    assert_eq!(
        create(&mut k, &mut t, &m, map(QUEUE, 0, (1 << 22) + 1, 4, 0)),
        errno(E2BIG)
    );
    for (kind, first) in [(QUEUE, 1), (STACK, 3)] {
        let fd = make(&mut k, &mut t, &m, map(kind, 0, 8, 3, 0));
        let v = |x: u64| x.to_le_bytes();
        assert_eq!(
            elem(&mut k, &mut t, &m, MAP_LOOKUP_ELEM, fd, None, Some(&v(0))),
            errno(Errno::ENOENT)
        );
        for x in 1..=3 {
            assert_eq!(
                elem(&mut k, &mut t, &m, MAP_UPDATE_ELEM, fd, None, Some(&v(x))),
                0
            );
        }
        // queue_stack_map_push_elem: full, without BPF_EXIST.
        assert_eq!(
            elem(&mut k, &mut t, &m, MAP_UPDATE_ELEM, fd, None, Some(&v(4))),
            errno(E2BIG)
        );
        // A key is refused wherever one is given.
        let key = Some(&[0u8; 4][..]);
        assert_eq!(
            elem(&mut k, &mut t, &m, MAP_UPDATE_ELEM, fd, key, Some(&v(4))),
            einval
        );
        assert_eq!(
            elem(&mut k, &mut t, &m, MAP_LOOKUP_ELEM, fd, None, Some(&v(0))),
            0
        );
        assert_eq!(value(&m), first);
        // No delete or next key of its own (queue_stack_map_delete_elem,
        // queue_stack_map_get_next_key), and no batches.
        assert_eq!(
            elem(&mut k, &mut t, &m, MAP_DELETE_ELEM, fd, None, None),
            einval
        );
        assert_eq!(
            elem(&mut k, &mut t, &m, MAP_GET_NEXT_KEY, fd, None, Some(&v(0))),
            einval
        );
        let batch = Attr::default().half(32, 2).half(36, fd as u32);
        assert_eq!(
            bpf(&mut k, &mut t, &m, MAP_LOOKUP_BATCH, &batch),
            errno(ENOTSUPP)
        );
        // A pop takes what a peek gives.
        assert_eq!(
            elem(
                &mut k,
                &mut t,
                &m,
                MAP_LOOKUP_AND_DELETE_ELEM,
                fd,
                None,
                Some(&v(0))
            ),
            0
        );
        assert_eq!(value(&m), first);
        // Read only, a push and a pop are EPERM.
        let readonly = make(&mut k, &mut t, &m, map(kind, 0, 8, 3, F_RDONLY));
        assert_eq!(
            elem(
                &mut k,
                &mut t,
                &m,
                MAP_UPDATE_ELEM,
                readonly,
                None,
                Some(&v(1))
            ),
            errno(Errno::EPERM)
        );
        assert_eq!(
            elem(
                &mut k,
                &mut t,
                &m,
                MAP_LOOKUP_AND_DELETE_ELEM,
                readonly,
                None,
                Some(&v(0))
            ),
            errno(Errno::EPERM)
        );
    }
}

#[test]
fn a_bloom_filter_takes_no_key_and_finds_what_was_pushed() {
    let (mut k, mut t, m) = setup();
    let einval = errno(Errno::EINVAL);
    assert_eq!(
        create(&mut k, &mut t, &m, map(BLOOM_FILTER, 4, 4, 10, 0)),
        einval
    );
    assert_eq!(
        create(
            &mut k,
            &mut t,
            &m,
            map(BLOOM_FILTER, 0, (1 << 22) + 1, 10, 0)
        ),
        errno(E2BIG)
    );
    // map_extra's low four bits are the number of hashes, and no more.
    assert_eq!(
        create(
            &mut k,
            &mut t,
            &m,
            map(BLOOM_FILTER, 0, 4, 10, 0).word(64, 0x10)
        ),
        einval
    );
    let fd = create(
        &mut k,
        &mut t,
        &m,
        map(BLOOM_FILTER, 0, 4, 10, 0).word(64, 3),
    );
    assert!(fd < 1024);
    let pushed = 0x1234_5678u32.to_le_bytes();
    assert_eq!(
        elem(&mut k, &mut t, &m, MAP_UPDATE_ELEM, fd, None, Some(&pushed)),
        0
    );
    // A lookup reads the value it asks about.
    assert_eq!(
        elem(&mut k, &mut t, &m, MAP_LOOKUP_ELEM, fd, None, Some(&pushed)),
        0
    );
    // map_extra comes back in the map's information.
    assert_eq!(info(&mut k, &mut t, &m, fd, 88), 0);
    let mut extra = [0; 8];
    m.read(GuestAddr(INFO + 80), &mut extra).unwrap();
    assert_eq!(u64::from_le_bytes(extra), 3);
}

#[test]
fn a_map_of_maps_holds_maps_that_fit_its_template_and_gives_their_ids() {
    let (mut k, mut t, m) = setup();
    let einval = errno(Errno::EINVAL);
    let inner = make(&mut k, &mut t, &m, map(ARRAY, 4, 8, 4, 0));
    let outer = |kind: u32, value: u32, flags: u32, inner: u64| {
        map(kind, 4, value, 3, flags).half(20, inner as u32)
    };
    // A value is a descriptor, which a program neither only reads nor
    // only writes; only an array is mapped.
    assert_eq!(
        create(&mut k, &mut t, &m, outer(ARRAY_OF_MAPS, 8, 0, inner)),
        einval
    );
    assert_eq!(
        create(&mut k, &mut t, &m, outer(HASH_OF_MAPS, 8, 0, inner)),
        einval
    );
    assert_eq!(
        create(
            &mut k,
            &mut t,
            &m,
            outer(ARRAY_OF_MAPS, 4, F_RDONLY_PROG, inner)
        ),
        einval
    );
    assert_eq!(
        create(
            &mut k,
            &mut t,
            &m,
            outer(ARRAY_OF_MAPS, 4, F_MMAPABLE, inner)
        ),
        einval
    );
    // The inner map's descriptor: none is EBADF, and a map of maps is no
    // template (one level alone).
    assert_eq!(
        create(&mut k, &mut t, &m, outer(ARRAY_OF_MAPS, 4, 0, NO_FD)),
        errno(Errno::EBADF)
    );
    let array = create(&mut k, &mut t, &m, outer(ARRAY_OF_MAPS, 4, 0, inner));
    assert!(array < 1024);
    assert_eq!(
        create(&mut k, &mut t, &m, outer(HASH_OF_MAPS, 4, 0, array)),
        einval
    );
    // bpf_fd_array_map_update_elem: BPF_ANY alone, an index in range, then
    // a map that fits the template.
    let fd = |fd: u64| (fd as u32).to_le_bytes();
    let key = |i: u32| i.to_le_bytes();
    assert_eq!(
        elem_with(
            &mut k,
            &mut t,
            &m,
            MAP_UPDATE_ELEM,
            array,
            (Some(&key(0)), Some(&fd(inner))),
            NOEXIST
        ),
        einval
    );
    assert_eq!(
        elem(
            &mut k,
            &mut t,
            &m,
            MAP_UPDATE_ELEM,
            array,
            Some(&key(3)),
            Some(&fd(inner))
        ),
        errno(E2BIG)
    );
    let hash = make(&mut k, &mut t, &m, map(HASH, 4, 8, 4, 0));
    assert_eq!(
        elem(
            &mut k,
            &mut t,
            &m,
            MAP_UPDATE_ELEM,
            array,
            Some(&key(0)),
            Some(&fd(hash))
        ),
        einval
    );
    assert_eq!(
        elem(
            &mut k,
            &mut t,
            &m,
            MAP_UPDATE_ELEM,
            array,
            Some(&key(1)),
            Some(&fd(inner))
        ),
        0
    );
    // A lookup gives the ID of the map it holds.
    let inner_id = id(&mut k, &mut t, &m, inner);
    assert_eq!(
        elem(
            &mut k,
            &mut t,
            &m,
            MAP_LOOKUP_ELEM,
            array,
            Some(&key(1)),
            Some(&[0; 4])
        ),
        0
    );
    assert_eq!(value(&m) as u32, inner_id);
    // bpf_fd_htab_map_update_elem: the descriptor, then flags past
    // BPF_EXIST.
    let by_key = create(&mut k, &mut t, &m, outer(HASH_OF_MAPS, 4, 0, inner));
    assert!(by_key < 1024);
    assert_eq!(
        elem_with(
            &mut k,
            &mut t,
            &m,
            MAP_UPDATE_ELEM,
            by_key,
            (Some(&key(7)), Some(&fd(inner))),
            3
        ),
        einval
    );
    assert_eq!(
        elem(
            &mut k,
            &mut t,
            &m,
            MAP_UPDATE_ELEM,
            by_key,
            Some(&key(7)),
            Some(&fd(inner))
        ),
        0
    );
}

#[test]
fn ids_give_descriptors_with_the_access_asked_for() {
    let (mut k, mut t, m) = setup();
    let einval = errno(Errno::EINVAL);
    let eperm = errno(Errno::EPERM);
    let map = make(&mut k, &mut t, &m, map(ARRAY, 4, 8, 4, 0));
    let id = id(&mut k, &mut t, &m, map);
    let next_id = |k: &mut Kernel, t: &mut Thread, start: u32| {
        bpf(k, t, &m, MAP_GET_NEXT_ID, &Attr::default().half(0, start))
    };
    assert_eq!(next_id(&mut k, &mut t, id - 1), 0);
    let mut next = [0; 4];
    m.read(GuestAddr(ATTR + 4), &mut next).unwrap();
    assert_eq!(u32::from_le_bytes(next), id);
    assert_eq!(next_id(&mut k, &mut t, id), errno(Errno::ENOENT));
    assert_eq!(next_id(&mut k, &mut t, 0x7fff_ffff), einval);
    let by_id = |k: &mut Kernel, t: &mut Thread, id: u32, flags: u32| {
        bpf(
            k,
            t,
            &m,
            MAP_GET_FD_BY_ID,
            &Attr::default().half(0, id).half(8, flags),
        )
    };
    assert_eq!(by_id(&mut k, &mut t, id, 1), einval);
    assert_eq!(by_id(&mut k, &mut t, id, F_RDONLY | F_WRONLY), einval);
    assert_eq!(by_id(&mut k, &mut t, 0, 0), errno(Errno::ENOENT));
    // Through a read-only descriptor, nothing is written.
    let readonly = by_id(&mut k, &mut t, id, F_RDONLY);
    assert!(readonly < 1024);
    let key = Some(&[1u8, 0, 0, 0][..]);
    let v = Some(&[7u8; 8][..]);
    assert_eq!(elem(&mut k, &mut t, &m, MAP_UPDATE_ELEM, map, key, v), 0);
    assert_eq!(
        elem(
            &mut k,
            &mut t,
            &m,
            MAP_LOOKUP_ELEM,
            readonly,
            key,
            Some(&[0; 8])
        ),
        0
    );
    assert_eq!(value(&m), u64::from_le_bytes([7; 8]));
    // Each with only the fields it takes: CHECK_ATTR is EINVAL first.
    for (command, key, v) in [
        (MAP_UPDATE_ELEM, key, v),
        (MAP_DELETE_ELEM, key, None),
        (MAP_LOOKUP_AND_DELETE_ELEM, key, v),
        (MAP_FREEZE, None, None),
    ] {
        assert_eq!(elem(&mut k, &mut t, &m, command, readonly, key, v), eperm);
    }
    let batch = Attr::default().half(32, 1).half(36, readonly as u32);
    assert_eq!(bpf(&mut k, &mut t, &m, MAP_UPDATE_BATCH, &batch), eperm);
    // Through a write-only one, nothing is read.
    let writeonly = by_id(&mut k, &mut t, id, F_WRONLY);
    assert!(writeonly < 1024);
    for command in [MAP_LOOKUP_ELEM, MAP_GET_NEXT_KEY] {
        assert_eq!(elem(&mut k, &mut t, &m, command, writeonly, key, v), eperm);
    }
    // The map stays while a descriptor has it.
    assert_eq!(syscall(&mut k, &mut t, &m, CLOSE, [map, 0, 0, 0, 0, 0]), 0);
    assert_eq!(
        elem(
            &mut k,
            &mut t,
            &m,
            MAP_LOOKUP_ELEM,
            readonly,
            key,
            Some(&[0; 8])
        ),
        0
    );
}

#[test]
fn a_frozen_map_is_written_through_no_descriptor() {
    let (mut k, mut t, m) = setup();
    let fd = make(&mut k, &mut t, &m, map(HASH, 4, 8, 4, 0));
    let key = Some(&[1u8, 0, 0, 0][..]);
    let v = Some(&[5u8; 8][..]);
    assert_eq!(elem(&mut k, &mut t, &m, MAP_UPDATE_ELEM, fd, key, v), 0);
    assert_eq!(elem(&mut k, &mut t, &m, MAP_FREEZE, fd, None, None), 0);
    // map_freeze asks for a writable map, which a frozen one is not.
    assert_eq!(
        elem(&mut k, &mut t, &m, MAP_FREEZE, fd, None, None),
        errno(Errno::EPERM)
    );
    assert_eq!(
        elem(&mut k, &mut t, &m, MAP_UPDATE_ELEM, fd, key, v),
        errno(Errno::EPERM)
    );
    assert_eq!(
        elem(&mut k, &mut t, &m, MAP_DELETE_ELEM, fd, key, None),
        errno(Errno::EPERM)
    );
    assert_eq!(
        elem(&mut k, &mut t, &m, MAP_LOOKUP_ELEM, fd, key, Some(&[0; 8])),
        0
    );
    assert_eq!(value(&m), u64::from_le_bytes([5; 8]));
}

#[test]
fn map_information_is_for_a_map_descriptor_and_a_length_linux_knows() {
    let (mut k, mut t, m) = setup();
    let fd = create(
        &mut k,
        &mut t,
        &m,
        map(HASH, 4, 8, 7, 0).bytes(28, b"named\0"),
    );
    assert!(fd < 1024);
    // Up to the length asked for, which comes back.
    assert_eq!(info(&mut k, &mut t, &m, fd, 40), 0);
    let mut got = [0; 40];
    m.read(GuestAddr(INFO), &mut got).unwrap();
    let half = |at: usize| u32::from_le_bytes(got[at..at + 4].try_into().unwrap());
    assert_eq!(
        [half(0), half(8), half(12), half(16), half(20)],
        [HASH, 4, 8, 7, 0]
    );
    assert_eq!(&got[24..30], b"named\0");
    let mut len = [0; 4];
    m.read(GuestAddr(ATTR + 4), &mut len).unwrap();
    assert_eq!(u32::from_le_bytes(len), 40);
    // No descriptor is EBADFD, a file that is no map EINVAL.
    assert_eq!(info(&mut k, &mut t, &m, NO_FD, 40), errno(EBADFD));
    let file = syscall(&mut k, &mut t, &m, 293, [ATTR, 0, 0, 0, 0, 0]); // pipe2
    assert_eq!(file, 0);
    let mut pipe = [0; 4];
    m.read(GuestAddr(ATTR), &mut pipe).unwrap();
    let pipe = u64::from(u32::from_le_bytes(pipe));
    assert_eq!(info(&mut k, &mut t, &m, pipe, 40), errno(Errno::EINVAL));
    // More than a page, or bytes past what Linux knows that are not 0
    // (bpf_check_uarg_tail_zero), are E2BIG.
    assert_eq!(info(&mut k, &mut t, &m, fd, 4097), errno(E2BIG));
    m.write(GuestAddr(INFO + 150), &[1]).unwrap();
    assert_eq!(info(&mut k, &mut t, &m, fd, 200), errno(E2BIG));
    // And a structure that cannot be read for that check is EFAULT.
    let attr = Attr::default()
        .half(0, fd as u32)
        .half(4, 200)
        .word(8, UNMAPPED);
    assert_eq!(
        bpf(&mut k, &mut t, &m, OBJ_GET_INFO_BY_FD, &attr),
        errno(Errno::EFAULT)
    );
}

/// Where a batch's keys, values and `out_batch` go.
const KEYS: u64 = DATA + 0x600;
const VALUES: u64 = DATA + 0x700;
const BATCH_OUT: u64 = DATA + 0x500;
const BATCH_IN: u64 = DATA + 0x580;

/// The keys `BPF_MAP_GET_NEXT_KEY` walks to from none, of `size` bytes
/// each, and how the walk ends.
fn keys(
    k: &mut Kernel,
    t: &mut Thread,
    m: &AddressSpace,
    fd: u64,
    size: usize,
) -> (Vec<Vec<u8>>, u64) {
    let mut found = Vec::new();
    let first = Attr::default().half(0, fd as u32).word(16, VALUE);
    let mut r = bpf(k, t, m, MAP_GET_NEXT_KEY, &first);
    while r == 0 && found.len() < 32 {
        let mut key = vec![0; size];
        m.read(GuestAddr(VALUE), &mut key).unwrap();
        m.write(GuestAddr(KEY), &key).unwrap();
        found.push(key);
        let next = Attr::default()
            .half(0, fd as u32)
            .word(8, KEY)
            .word(16, VALUE);
        r = bpf(k, t, m, MAP_GET_NEXT_KEY, &next);
    }
    (found, r)
}

/// An LRU hash's keys, sorted, as `bpf.c`'s `keys` prints them.
fn lru_keys(k: &mut Kernel, t: &mut Thread, m: &AddressSpace, fd: u64) -> Vec<u32> {
    let (found, end) = keys(k, t, m, fd, 4);
    assert_eq!(end, errno(Errno::ENOENT));
    let mut keys: Vec<u32> = found
        .iter()
        .map(|key| u32::from_le_bytes(key[..4].try_into().unwrap()))
        .collect();
    keys.sort_unstable();
    keys
}

/// `BPF_MAP_UPDATE_ELEM` of a `u32` key and a `u64` value.
fn put(
    k: &mut Kernel,
    t: &mut Thread,
    m: &AddressSpace,
    fd: u64,
    key: u32,
    value: u64,
    flags: u64,
) -> u64 {
    let kv = (Some(&key.to_le_bytes()[..]), Some(&value.to_le_bytes()[..]));
    elem_with(k, t, m, MAP_UPDATE_ELEM, fd, kv, flags)
}

/// A batch's count, as the command gave it back.
fn count(m: &AddressSpace) -> u32 {
    let mut b = [0; 4];
    m.read(GuestAddr(ATTR + 32), &mut b).unwrap();
    u32::from_le_bytes(b)
}

/// `bpf.c`'s `case_lru`, on one CPU's lists as Linux's `bpf_lru_list.c`
/// keeps them: which keys a full map gives up as new ones come.
#[test]
fn a_full_lru_hash_gives_up_the_keys_linux_s_lists_give_up() {
    // Four entries take one free element at a time on any machine of two
    // CPUs or more, as the differential case says; one CPU would take two.
    for cpus in [2, 4, 8, 64] {
        lru_case(cpus);
    }
}

fn lru_case(cpus: usize) {
    let (mut k, mut t, m) = on(Arc::new(Cpus(cpus)));
    let einval = errno(Errno::EINVAL);
    let lru = |flags: u32| map(LRU_HASH, 4, 8, 4, flags);
    // An LRU hash is always preallocated (ENOTSUPP), and lists of each
    // CPU's own are on no one NUMA node.
    assert_eq!(
        create(&mut k, &mut t, &m, lru(F_NO_PREALLOC)),
        errno(ENOTSUPP)
    );
    assert_eq!(
        create(&mut k, &mut t, &m, lru(F_NO_COMMON_LRU | F_NUMA_NODE)),
        einval
    );
    assert_eq!(create(&mut k, &mut t, &m, lru(F_MMAPABLE)), einval);
    assert_eq!(
        create(&mut k, &mut t, &m, map(LRU_HASH, 0, 8, 4, 0)),
        einval
    );
    assert_eq!(
        create(&mut k, &mut t, &m, map(LRU_HASH, 4, 1 << 22, 4, 0)),
        errno(E2BIG)
    );
    let fd = make(&mut k, &mut t, &m, lru(0));
    for key in 1..=5 {
        assert_eq!(put(&mut k, &mut t, &m, fd, key, key.into(), 0), 0);
    }
    assert_eq!(lru_keys(&mut k, &mut t, &m, fd), [2, 3, 4, 5]);
    assert_eq!(put(&mut k, &mut t, &m, fd, 2, 20, 0), 0);
    assert_eq!(lru_keys(&mut k, &mut t, &m, fd), [2, 3, 4, 5]);
    // The replaced key is referenced, so the oldest other goes.
    assert_eq!(put(&mut k, &mut t, &m, fd, 6, 6, 0), 0);
    assert_eq!(lru_keys(&mut k, &mut t, &m, fd), [2, 4, 5, 6]);
    // htab_lru_map_update_elem takes an element before it checks the
    // flags: a refused update still costs a key.
    assert_eq!(put(&mut k, &mut t, &m, fd, 6, 60, NOEXIST), errno(EEXIST));
    assert_eq!(lru_keys(&mut k, &mut t, &m, fd), [2, 5, 6]);
    assert_eq!(
        put(&mut k, &mut t, &m, fd, 9, 9, EXIST),
        errno(Errno::ENOENT)
    );
    assert_eq!(lru_keys(&mut k, &mut t, &m, fd), [2, 5, 6]);
    let six = Some(&6u32.to_le_bytes()[..]);
    assert_eq!(
        elem(&mut k, &mut t, &m, MAP_LOOKUP_ELEM, fd, six, Some(&[0; 8])),
        0
    );
    assert_eq!(value(&m), 6);
    let five = Some(&5u32.to_le_bytes()[..]);
    assert_eq!(elem(&mut k, &mut t, &m, MAP_DELETE_ELEM, fd, five, None), 0);
    assert_eq!(
        elem(&mut k, &mut t, &m, MAP_DELETE_ELEM, fd, five, None),
        errno(Errno::ENOENT)
    );
    assert_eq!(lru_keys(&mut k, &mut t, &m, fd), [2, 6]);
    for key in 7..=9 {
        assert_eq!(put(&mut k, &mut t, &m, fd, key, key.into(), 0), 0);
    }
    assert_eq!(lru_keys(&mut k, &mut t, &m, fd), [6, 7, 8, 9]);
    let eight = Some(&8u32.to_le_bytes()[..]);
    assert_eq!(
        elem(
            &mut k,
            &mut t,
            &m,
            MAP_LOOKUP_AND_DELETE_ELEM,
            fd,
            eight,
            Some(&[0; 8])
        ),
        0
    );
    assert_eq!(value(&m), 8);
    assert_eq!(lru_keys(&mut k, &mut t, &m, fd), [6, 7, 9]);
    // Many more, every third replaced and so referenced: the lists rotate
    // and shrink.
    for key in 10..=30u32 {
        assert_eq!(put(&mut k, &mut t, &m, fd, key, key.into(), 0), 0);
        if key % 3 == 0 {
            assert_eq!(put(&mut k, &mut t, &m, fd, key, u64::from(key) + 100, 0), 0);
        }
    }
    assert_eq!(lru_keys(&mut k, &mut t, &m, fd), [28, 29, 30]);
    // Batches: six updated, then everything looked up and deleted.
    let batch_keys: Vec<u8> = (40u32..48).flat_map(u32::to_le_bytes).collect();
    m.write(GuestAddr(KEYS), &batch_keys).unwrap();
    m.write(GuestAddr(VALUES), &[0; 64]).unwrap();
    let update = Attr::default()
        .word(16, KEYS)
        .word(24, VALUES)
        .half(32, 6)
        .half(36, fd as u32);
    assert_eq!(bpf(&mut k, &mut t, &m, MAP_UPDATE_BATCH, &update), 0);
    assert_eq!(count(&m), 6);
    assert_eq!(lru_keys(&mut k, &mut t, &m, fd), [30, 43, 44, 45]);
    let take = Attr::default()
        .word(8, BATCH_OUT)
        .word(16, KEYS)
        .word(24, VALUES)
        .half(32, 8)
        .half(36, fd as u32);
    assert_eq!(
        bpf(&mut k, &mut t, &m, MAP_LOOKUP_AND_DELETE_BATCH, &take),
        errno(Errno::ENOENT)
    );
    assert_eq!(count(&m), 4);
    let mut taken = [0; 16];
    m.read(GuestAddr(KEYS), &mut taken).unwrap();
    let mut taken: Vec<u32> = taken
        .chunks(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect();
    taken.sort_unstable();
    assert_eq!(taken, [30, 43, 44, 45]);
    assert_eq!(lru_keys(&mut k, &mut t, &m, fd), [] as [u32; 0]);
    // Lists for each CPU: one entry is one for each, so this CPU holds
    // one key.
    let own = make(&mut k, &mut t, &m, map(LRU_HASH, 4, 8, 1, F_NO_COMMON_LRU));
    for key in 1..=3 {
        assert_eq!(put(&mut k, &mut t, &m, own, key, key.into(), 0), 0);
    }
    assert_eq!(lru_keys(&mut k, &mut t, &m, own), [3]);
}

/// An LPM trie's key: a prefix length, then an IPv4 address.
fn v4(address: [u8; 4], length: u32) -> [u8; 8] {
    let mut key = [0; 8];
    key[..4].copy_from_slice(&length.to_le_bytes());
    key[4..].copy_from_slice(&address);
    key
}

/// `bpf.c`'s `case_lpm`, of IPv4 keys: what a trie takes, the longest
/// prefix a lookup finds, the order of its next keys, and its batches.
#[test]
fn an_lpm_trie_finds_the_longest_prefix_and_walks_its_keys_in_linux_s_order() {
    let (mut k, mut t, m) = setup();
    let einval = errno(Errno::EINVAL);
    let trie =
        |key: u32, value: u32, entries: u32, flags: u32| map(LPM_TRIE, key, value, entries, flags);
    // A prefix length and 1 to 256 bytes, a value up to what one kmalloc
    // holds with the node, entries, and BPF_F_NO_PREALLOC, which it must
    // have, with its own flags alone.
    for attr in [
        trie(4, 4, 10, F_NO_PREALLOC),
        trie(261, 4, 10, F_NO_PREALLOC),
        trie(8, 0, 10, F_NO_PREALLOC),
        trie(8, (1 << 22) - 279, 10, F_NO_PREALLOC),
        trie(8, 4, 0, F_NO_PREALLOC),
        trie(8, 4, 10, 0),
        trie(8, 4, 10, F_NO_PREALLOC | F_ZERO_SEED),
        trie(8, 4, 10, F_NO_PREALLOC | F_MMAPABLE),
        trie(8, 4, 10, F_NO_PREALLOC | F_RDONLY_PROG | F_WRONLY_PROG),
    ] {
        assert_eq!(create(&mut k, &mut t, &m, attr), einval);
    }
    for key in [5, 260] {
        make(&mut k, &mut t, &m, trie(key, 4, 10, F_NO_PREALLOC));
    }
    let fd = make(&mut k, &mut t, &m, trie(8, 4, 6, F_NO_PREALLOC));
    let put = |k: &mut Kernel, t: &mut Thread, a: [u8; 4], length: u32, v: u32, flags: u64| {
        let kv = (Some(&v4(a, length)[..]), Some(&v.to_le_bytes()[..]));
        elem_with(k, t, &m, MAP_UPDATE_ELEM, fd, kv, flags)
    };
    // What a lookup finds, or its error.
    let find = |k: &mut Kernel, t: &mut Thread, a: [u8; 4], length: u32| {
        let r = elem(
            k,
            t,
            &m,
            MAP_LOOKUP_ELEM,
            fd,
            Some(&v4(a, length)),
            Some(&[0; 4]),
        );
        if r == 0 { Ok(value(&m) as u32) } else { Err(r) }
    };
    let order = |k: &mut Kernel, t: &mut Thread| {
        let (found, end) = keys(k, t, &m, fd, 8);
        assert_eq!(end, errno(Errno::ENOENT));
        found
            .iter()
            .map(|key| {
                (
                    key[4..].to_vec(),
                    u32::from_le_bytes(key[..4].try_into().unwrap()),
                )
            })
            .collect::<Vec<_>>()
    };
    let key = |a: [u8; 4], length: u32| (a.to_vec(), length);
    let enoent = Err(errno(Errno::ENOENT));
    assert_eq!(order(&mut k, &mut t), []);
    assert_eq!(put(&mut k, &mut t, [192, 168, 0, 0], 16, 1, NOEXIST), 0);
    assert_eq!(put(&mut k, &mut t, [192, 168, 0, 0], 24, 2, 0), 0);
    assert_eq!(put(&mut k, &mut t, [192, 168, 128, 0], 24, 3, 0), 0);
    assert_eq!(put(&mut k, &mut t, [192, 168, 1, 0], 24, 5, 0), 0);
    assert_eq!(find(&mut k, &mut t, [192, 168, 0, 7], 32), Ok(2));
    assert_eq!(find(&mut k, &mut t, [192, 168, 1, 7], 32), Ok(5));
    assert_eq!(find(&mut k, &mut t, [192, 168, 128, 1], 32), Ok(3));
    assert_eq!(find(&mut k, &mut t, [192, 168, 200, 1], 32), Ok(1));
    // The key's own length bounds the prefix it finds.
    assert_eq!(find(&mut k, &mut t, [192, 168, 0, 0], 23), Ok(1));
    assert_eq!(find(&mut k, &mut t, [192, 168, 0, 0], 15), enoent);
    assert_eq!(find(&mut k, &mut t, [10, 0, 0, 1], 32), enoent);
    assert_eq!(find(&mut k, &mut t, [192, 168, 0, 0], 33), enoent);
    // trie_get_next_key: the longer prefixes first, in post-order.
    let four = [
        key([192, 168, 0, 0], 24),
        key([192, 168, 1, 0], 24),
        key([192, 168, 128, 0], 24),
        key([192, 168, 0, 0], 16),
    ];
    assert_eq!(order(&mut k, &mut t), four);
    // The next key of one it does not hold, or of no prefix it could, is
    // the first.
    for (a, length) in [([192, 168, 0, 0], 23), ([0, 0, 0, 0], 40)] {
        m.write(GuestAddr(KEY), &v4(a, length)).unwrap();
        let next = Attr::default()
            .half(0, fd as u32)
            .word(8, KEY)
            .word(16, VALUE);
        assert_eq!(bpf(&mut k, &mut t, &m, MAP_GET_NEXT_KEY, &next), 0);
        let mut got = [0; 8];
        m.read(GuestAddr(VALUE), &mut got).unwrap();
        assert_eq!(got, v4([192, 168, 0, 0], 24));
    }
    assert_eq!(
        put(&mut k, &mut t, [192, 168, 0, 0], 16, 9, NOEXIST),
        errno(EEXIST)
    );
    assert_eq!(
        put(&mut k, &mut t, [192, 168, 0, 0], 23, 4, EXIST),
        errno(Errno::ENOENT)
    );
    assert_eq!(put(&mut k, &mut t, [192, 168, 0, 0], 23, 4, NOEXIST), 0);
    assert_eq!(put(&mut k, &mut t, [192, 168, 0, 0], 33, 4, 0), einval);
    // The key's bits past its prefix are kept as given.
    assert_eq!(put(&mut k, &mut t, [10, 1, 2, 3], 8, 6, 0), 0);
    // Full: a new key is ENOSPC, a key it holds is replaced.
    assert_eq!(
        put(&mut k, &mut t, [11, 0, 0, 0], 8, 7, 0),
        errno(Errno::ENOSPC)
    );
    assert_eq!(
        put(&mut k, &mut t, [11, 0, 0, 0], 8, 7, EXIST),
        errno(Errno::ENOENT)
    );
    assert_eq!(put(&mut k, &mut t, [10, 9, 9, 9], 8, 8, EXIST), 0);
    assert_eq!(
        order(&mut k, &mut t),
        [
            key([10, 9, 9, 9], 8),
            key([192, 168, 0, 0], 24),
            key([192, 168, 1, 0], 24),
            key([192, 168, 0, 0], 23),
            key([192, 168, 128, 0], 24),
            key([192, 168, 0, 0], 16),
        ]
    );
    let take = |k: &mut Kernel, t: &mut Thread, a: [u8; 4], length: u32| {
        elem(k, t, &m, MAP_DELETE_ELEM, fd, Some(&v4(a, length)), None)
    };
    assert_eq!(take(&mut k, &mut t, [192, 168, 0, 0], 23), 0);
    assert_eq!(
        take(&mut k, &mut t, [192, 168, 0, 0], 23),
        errno(Errno::ENOENT)
    );
    assert_eq!(take(&mut k, &mut t, [192, 168, 0, 0], 33), einval);
    assert_eq!(
        take(&mut k, &mut t, [192, 168, 2, 0], 24),
        errno(Errno::ENOENT)
    );
    assert_eq!(take(&mut k, &mut t, [192, 168, 0, 0], 24), 0);
    assert_eq!(take(&mut k, &mut t, [192, 168, 0, 0], 16), 0);
    assert_eq!(find(&mut k, &mut t, [192, 168, 0, 9], 32), enoent);
    assert_eq!(find(&mut k, &mut t, [192, 168, 1, 9], 32), Ok(5));
    assert_eq!(
        order(&mut k, &mut t),
        [
            key([10, 9, 9, 9], 8),
            key([192, 168, 1, 0], 24),
            key([192, 168, 128, 0], 24),
        ]
    );
    // A trie has no lookup and delete of its own.
    assert_eq!(
        elem(
            &mut k,
            &mut t,
            &m,
            MAP_LOOKUP_AND_DELETE_ELEM,
            fd,
            Some(&v4([10, 0, 0, 0], 8)),
            Some(&[0; 4])
        ),
        errno(ENOTSUPP)
    );
    // Its batches are the generic ones, which follow the next keys.
    let batch = |at: u64, count: u32| {
        Attr::default()
            .word(0, at)
            .word(8, BATCH_OUT)
            .word(16, KEYS)
            .word(24, VALUES)
            .half(32, count)
            .half(36, fd as u32)
    };
    let read = |at: u64, len: usize| {
        let mut b = vec![0; len];
        m.read(GuestAddr(at), &mut b).unwrap();
        b
    };
    assert_eq!(bpf(&mut k, &mut t, &m, MAP_LOOKUP_BATCH, &batch(0, 2)), 0);
    assert_eq!(count(&m), 2);
    assert_eq!(
        read(KEYS, 16),
        [v4([10, 9, 9, 9], 8), v4([192, 168, 1, 0], 24)].concat()
    );
    assert_eq!(
        read(VALUES, 8),
        [8u32.to_le_bytes(), 5u32.to_le_bytes()].concat()
    );
    let last = read(BATCH_OUT, 8);
    assert_eq!(last, v4([192, 168, 1, 0], 24));
    m.write(GuestAddr(BATCH_IN), &last).unwrap();
    assert_eq!(
        bpf(&mut k, &mut t, &m, MAP_LOOKUP_BATCH, &batch(BATCH_IN, 8)),
        errno(Errno::ENOENT)
    );
    assert_eq!(count(&m), 1);
    assert_eq!(read(KEYS, 8), v4([192, 168, 128, 0], 24));
    assert_eq!(read(VALUES, 4), 3u32.to_le_bytes());
    // No lookup and delete batch: the count is left as it was.
    assert_eq!(
        bpf(
            &mut k,
            &mut t,
            &m,
            MAP_LOOKUP_AND_DELETE_BATCH,
            &batch(0, 2)
        ),
        errno(ENOTSUPP)
    );
    assert_eq!(count(&m), 2);
    // An update batch stops at the key it refuses, a delete batch at the
    // one it does not hold, each with the count of those done.
    let three = [
        v4([172, 16, 0, 0], 12),
        v4([172, 16, 0, 0], 40),
        v4([172, 17, 0, 0], 16),
    ];
    m.write(GuestAddr(KEYS), &three.concat()).unwrap();
    let values: Vec<u8> = [20u32, 21, 22]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    m.write(GuestAddr(VALUES), &values).unwrap();
    assert_eq!(
        bpf(&mut k, &mut t, &m, MAP_UPDATE_BATCH, &batch(0, 3)),
        einval
    );
    assert_eq!(count(&m), 1);
    assert_eq!(find(&mut k, &mut t, [172, 16, 5, 5], 32), Ok(20));
    m.write(GuestAddr(KEYS + 8), &v4([192, 168, 1, 0], 24))
        .unwrap();
    assert_eq!(
        bpf(&mut k, &mut t, &m, MAP_DELETE_BATCH, &batch(0, 3)),
        errno(Errno::ENOENT)
    );
    assert_eq!(count(&m), 2);
    assert_eq!(
        order(&mut k, &mut t),
        [key([10, 9, 9, 9], 8), key([192, 168, 128, 0], 24)]
    );
}

const MMAP: u64 = 9;
const MPROTECT: u64 = 10;
const MUNMAP: u64 = 11;
const MAP_SHARED: u64 = 1;
const MAP_PRIVATE: u64 = 2;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;

/// `mmap` of `[fd, len, prot, flags, offset]` at an address of the
/// kernel's choice.
fn mmap(
    k: &mut Kernel,
    t: &mut Thread,
    m: &AddressSpace,
    [fd, len, prot, flags, offset]: [u64; 5],
) -> u64 {
    syscall(k, t, m, MMAP, [0, len, prot, flags, fd, offset])
}

#[test]
fn a_mappable_arrays_mapping_shows_its_values() {
    let (mut k, mut t, m) = setup();
    // A VMA's open and close reach the map only from a thread the kernel
    // runs, as Linux's `current`.
    k.enter_thread(t.tid);
    // 300 values of 12 bytes, 16 apart: two pages.
    let fd = make(&mut k, &mut t, &m, map(ARRAY, 4, 12, 300, F_MMAPABLE));
    let key = Some(&[1u8, 0, 0, 0][..]);
    assert_eq!(
        elem(&mut k, &mut t, &m, MAP_UPDATE_ELEM, fd, key, Some(&[7; 12])),
        0
    );
    let at = mmap(
        &mut k,
        &mut t,
        &m,
        [fd, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, 0],
    );
    assert!(at < u64::MAX - 4095, "mmap: {at:#x}");
    let mut seen = [0; 16];
    m.read(GuestAddr(at + 16), &mut seen).unwrap();
    assert_eq!(seen, [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 0, 0, 0]);
    // `/proc/<pid>/maps` shows the device and inode the descriptor's
    // `fstat` gives.
    let vma = m.view().vma_from(at).unwrap();
    assert_eq!(vma.start, at);
    assert_eq!(
        vma.identity,
        (crate::files::Internal::AnonInodes.device(), 0)
    );
    m.write(GuestAddr(at + 299 * 16), &[3; 8]).unwrap();
    let last = Some(&299u32.to_le_bytes()[..]);
    assert_eq!(
        elem(
            &mut k,
            &mut t,
            &m,
            MAP_LOOKUP_ELEM,
            fd,
            last,
            Some(&[0; 12])
        ),
        0
    );
    assert_eq!(value(&m), u64::from_le_bytes([3; 8]));
    // And what an update writes, the mapping shows.
    let third = Some(&3u32.to_le_bytes()[..]);
    assert_eq!(
        elem(
            &mut k,
            &mut t,
            &m,
            MAP_UPDATE_ELEM,
            fd,
            third,
            Some(&[9; 12])
        ),
        0
    );
    m.read(GuestAddr(at + 48), &mut seen).unwrap();
    assert_eq!(seen[..12], [9; 12]);
    // Nothing executes it, and it never grows.
    assert_eq!(
        syscall(
            &mut k,
            &mut t,
            &m,
            MPROTECT,
            [at, PAGE_SIZE, PROT_READ | PROT_EXEC, 0, 0, 0]
        ),
        errno(Errno::EACCES)
    );
    // A mapping that writes holds a freeze off until it goes.
    assert_eq!(
        elem(&mut k, &mut t, &m, MAP_FREEZE, fd, None, None),
        errno(Errno(16))
    );
    assert_eq!(
        syscall(
            &mut k,
            &mut t,
            &m,
            MUNMAP,
            [at + PAGE_SIZE, PAGE_SIZE, 0, 0, 0, 0]
        ),
        0
    );
    assert_eq!(
        elem(&mut k, &mut t, &m, MAP_FREEZE, fd, None, None),
        errno(Errno(16))
    );
    assert_eq!(
        syscall(&mut k, &mut t, &m, MUNMAP, [at, PAGE_SIZE, 0, 0, 0, 0]),
        0
    );
    assert_eq!(elem(&mut k, &mut t, &m, MAP_FREEZE, fd, None, None), 0);
    // A frozen map maps only to be read, and that mapping never writes.
    assert_eq!(
        mmap(
            &mut k,
            &mut t,
            &m,
            [fd, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, 0]
        ),
        errno(Errno::EPERM)
    );
    let at = mmap(
        &mut k,
        &mut t,
        &m,
        [fd, PAGE_SIZE, PROT_READ, MAP_SHARED, 0],
    );
    assert!(at < u64::MAX - 4095, "mmap: {at:#x}");
    assert_eq!(
        syscall(
            &mut k,
            &mut t,
            &m,
            MPROTECT,
            [at, PAGE_SIZE, PROT_READ | PROT_WRITE, 0, 0, 0]
        ),
        errno(Errno::EACCES)
    );
}

#[test]
fn a_map_maps_only_as_linux_s_bpf_map_mmap_lets_it() {
    let (mut k, mut t, m) = setup();
    let fd = make(&mut k, &mut t, &m, map(ARRAY, 4, 12, 300, F_MMAPABLE));
    let mut try_map = |fd, len, prot, flags, offset| {
        let r = mmap(&mut k, &mut t, &m, [fd, len, prot, flags, offset]);
        if r < u64::MAX - 4095 { 0 } else { r }
    };
    assert_eq!(try_map(fd, PAGE_SIZE, PROT_READ, MAP_SHARED, PAGE_SIZE), 0);
    assert_eq!(
        try_map(fd, PAGE_SIZE, PROT_READ, MAP_SHARED, 2 * PAGE_SIZE),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        try_map(fd, 3 * PAGE_SIZE, PROT_READ, MAP_SHARED, 0),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        try_map(fd, PAGE_SIZE, PROT_READ, MAP_PRIVATE, 0),
        errno(Errno::EINVAL)
    );
    // Its anonymous inode's file system runs nothing.
    assert_eq!(
        try_map(fd, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED, 0),
        errno(Errno::EPERM)
    );
    let plain = make(&mut k, &mut t, &m, map(ARRAY, 4, 8, 4, 0));
    let hash = make(&mut k, &mut t, &m, map(HASH, 4, 8, 4, 0));
    let read_only = make(
        &mut k,
        &mut t,
        &m,
        map(ARRAY, 4, 8, 4, F_MMAPABLE | F_RDONLY_PROG),
    );
    let mut try_map = |fd, prot| {
        let r = mmap(&mut k, &mut t, &m, [fd, PAGE_SIZE, prot, MAP_SHARED, 0]);
        if r < u64::MAX - 4095 { 0 } else { r }
    };
    assert_eq!(try_map(plain, PROT_READ), errno(Errno::EINVAL));
    assert_eq!(try_map(hash, PROT_READ), errno(ENOTSUPP));
    assert_eq!(
        try_map(read_only, PROT_READ | PROT_WRITE),
        errno(Errno::EACCES)
    );
    assert_eq!(try_map(read_only, PROT_READ), 0);
    // A descriptor open only for reading maps nothing shared, and one only
    // for writing nothing at all.
    let id = id(&mut k, &mut t, &m, fd);
    let by_id = |k: &mut Kernel, t: &mut Thread, flags| {
        bpf(
            k,
            t,
            &m,
            MAP_GET_FD_BY_ID,
            &Attr::default().half(0, id).half(8, flags),
        )
    };
    let ro = by_id(&mut k, &mut t, F_RDONLY);
    let wo = by_id(&mut k, &mut t, F_WRONLY);
    let mut try_map = |fd, prot| {
        let r = mmap(&mut k, &mut t, &m, [fd, PAGE_SIZE, prot, MAP_SHARED, 0]);
        if r < u64::MAX - 4095 { 0 } else { r }
    };
    assert_eq!(try_map(ro, PROT_READ), errno(Errno::EINVAL));
    assert_eq!(try_map(ro, PROT_READ | PROT_WRITE), errno(Errno::EACCES));
    assert_eq!(try_map(wo, PROT_READ), errno(Errno::EACCES));
}
