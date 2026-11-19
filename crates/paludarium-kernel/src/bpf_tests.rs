//! `bpf(2)`'s map commands through the system call interface: the checks
//! `BPF_MAP_CREATE` makes, queues, stacks and bloom filters, maps of maps,
//! map IDs, the access a descriptor gives, and `BPF_OBJ_GET_INFO_BY_FD`.
//! The expected values are Linux's (`kernel/bpf/syscall.c` and the map
//! types' files); most are cases of `tests/guests/processes/bpf.c`, which
//! the differential tests compare with Linux.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::{Errno, GuestAddr, PAGE_SIZE};

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
const MAP_UPDATE_BATCH: u64 = 26;

const HASH: u32 = 1;
const ARRAY: u32 = 2;
const ARRAY_OF_MAPS: u32 = 12;
const HASH_OF_MAPS: u32 = 13;
const QUEUE: u32 = 22;
const STACK: u32 = 23;
const BLOOM_FILTER: u32 = 30;

const F_NUMA_NODE: u32 = 1 << 2;
const F_RDONLY: u32 = 1 << 3;
const F_WRONLY: u32 = 1 << 4;
const F_RDONLY_PROG: u32 = 1 << 7;
const F_MMAPABLE: u32 = 1 << 10;
const F_PRESERVE_ELEMS: u32 = 1 << 11;
const F_TOKEN_FD: u32 = 1 << 16;
const NOEXIST: u64 = 1;

const E2BIG: Errno = Errno(7);
/// `EBADFD`, which `BPF_OBJ_GET_INFO_BY_FD` gives for no descriptor.
const EBADFD: Errno = Errno(77);
/// The kernel's own `ENOTSUPP`, which `bpf(2)` lets out.
const ENOTSUPP: Errno = Errno(524);

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
