use super::*;
fn memory(pages: u64) -> AddressSpace {
    let m = AddressSpace::new();
    m.map_shared(
        Some(GuestAddr(0x10000)),
        pages * PAGE_SIZE,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    m
}
#[test]
fn atomic_width_wraps_without_touching_neighbors() {
    let m = memory(1);
    m.write(GuestAddr(0x10000), &[7, 255, 9]).unwrap();
    assert_eq!(
        m.atomic(GuestAddr(0x10001), AtomicWidth::W8, AtomicOp::Add(1))
            .unwrap()
            .old,
        255
    );
    let mut b = [0; 3];
    m.read(GuestAddr(0x10000), &mut b).unwrap();
    assert_eq!(b, [7, 0, 9]);
}
#[test]
fn failed_cmpxchg_requires_write_permission() {
    let m = memory(1);
    m.write_u64(GuestAddr(0x10000), 7).unwrap();
    m.protect_shared(GuestAddr(0x10000), PAGE_SIZE, Prot::READ)
        .unwrap();
    assert_eq!(
        m.atomic(
            GuestAddr(0x10000),
            AtomicWidth::W64,
            AtomicOp::CompareExchange {
                expected: 0,
                replacement: 9
            }
        ),
        Err(Fault {
            addr: GuestAddr(0x10000),
            write: true,
            fetch: false,
            mapped: true,
            present: true,
            bus: false,
            poison: false,
        })
    );
    assert_eq!(m.read_u64(GuestAddr(0x10000)).unwrap(), 7);
}
#[test]
fn cross_page_fault_has_no_partial_write() {
    let m = memory(1);
    m.write(GuestAddr(0x10ffc), &[1, 2, 3, 4]).unwrap();
    assert_eq!(
        m.atomic(GuestAddr(0x10ffc), AtomicWidth::W64, AtomicOp::Exchange(0)),
        Err(Fault {
            addr: GuestAddr(0x11000),
            write: true,
            fetch: false,
            mapped: false,
            present: false,
            bus: false,
            poison: false,
        })
    );
    let mut b = [0; 4];
    m.read(GuestAddr(0x10ffc), &mut b).unwrap();
    assert_eq!(b, [1, 2, 3, 4]);
}
#[test]
fn unaligned_cross_page_128bit_exchange() {
    let m = memory(2);
    let address = GuestAddr(0x10ff9);
    let value = 0x112233445566778899aabbccddeeff00;
    assert_eq!(
        m.atomic(address, AtomicWidth::W128, AtomicOp::Exchange(value))
            .unwrap()
            .old,
        0
    );
    assert_eq!(
        m.atomic(address, AtomicWidth::W128, AtomicOp::Exchange(0))
            .unwrap()
            .old,
        value
    );
}
#[test]
fn compare_exchange_returns_old_and_success() {
    let m = memory(1);
    let a = GuestAddr(0x10000);
    assert_eq!(
        m.atomic(
            a,
            AtomicWidth::W32,
            AtomicOp::CompareExchange {
                expected: 0,
                replacement: 7
            }
        )
        .unwrap(),
        AtomicResult {
            old: 0,
            exchanged: true
        }
    );
    assert_eq!(
        m.atomic(
            a,
            AtomicWidth::W32,
            AtomicOp::CompareExchange {
                expected: 0,
                replacement: 9
            }
        )
        .unwrap(),
        AtomicResult {
            old: 7,
            exchanged: false
        }
    );
    assert_eq!(m.read_u64(a).unwrap(), 7);
}
#[test]
fn atomic_operations_share_normal_memory_view() {
    let m = memory(1);
    let a = GuestAddr(0x10000);
    m.write_u64(a, 0xff).unwrap();
    for op in [
        AtomicOp::And(0xf),
        AtomicOp::Or(0x10),
        AtomicOp::Xor(3),
        AtomicOp::Sub(1),
        AtomicOp::Not,
        AtomicOp::Neg,
    ] {
        m.atomic(a, AtomicWidth::W64, op).unwrap();
    }
    assert_eq!(m.read_u64(a).unwrap(), 0x1c);
}
#[test]
fn mapping_mutation_and_fetch_use_same_view() {
    let m = memory(1);
    let a = GuestAddr(0x10000);
    m.protect_shared(a, PAGE_SIZE, Prot::READ_EXEC.union(Prot::WRITE))
        .unwrap();
    m.fetch(a, &mut [0]).unwrap();
    let generation = m.code_generation();
    m.atomic(a, AtomicWidth::W8, AtomicOp::Exchange(0x90))
        .unwrap();
    assert!(m.code_generation() > generation);
    let mut b = [0];
    m.fetch(a, &mut b).unwrap();
    assert_eq!(b, [0x90]);
    m.unmap_shared(a, PAGE_SIZE).unwrap();
    assert!(m.fetch(a, &mut b).is_err());
}
#[test]
fn all_bytes_permissions_preflight_before_128_update() {
    let m = memory(2);
    let a = GuestAddr(0x10ff8);
    m.write(a, &[0xa5; 16]).unwrap();
    m.protect_shared(GuestAddr(0x11000), PAGE_SIZE, Prot::READ)
        .unwrap();
    assert!(
        m.atomic(a, AtomicWidth::W128, AtomicOp::Exchange(0))
            .is_err()
    );
    let mut b = [0; 16];
    m.read(a, &mut b).unwrap();
    assert_eq!(b, [0xa5; 16]);
}
#[test]
fn stack_write_probe_preserves_bytes_and_observes_protection() {
    let m = memory(1);
    m.write_u64(GuestAddr(0x10000), 0x123456789abcdef0).unwrap();
    m.check_write(GuestAddr(0x10000), 8).unwrap();
    assert_eq!(m.read_u64(GuestAddr(0x10000)).unwrap(), 0x123456789abcdef0);
    m.protect_shared(GuestAddr(0x10000), PAGE_SIZE, Prot::READ)
        .unwrap();
    assert!(m.check_write(GuestAddr(0x10000), 1).is_err());
    assert!(m.check_write(GuestAddr(0xffff), 1).is_err());
    assert_eq!(m.read_u64(GuestAddr(0x10000)).unwrap(), 0x123456789abcdef0);
}

#[test]
fn a_replacing_map_takes_the_place_of_what_was_mapped() {
    let m = memory(2);
    let a = GuestAddr(0x10000);
    m.write_u64(a, 7).unwrap();
    m.write_u64(GuestAddr(0x10000 + PAGE_SIZE), 8).unwrap();
    let generation = m.code_generation();
    let map =
        |at, prot, backing| m.map_backed(at, PAGE_SIZE, prot, MappingKind::Anonymous, backing);
    assert_eq!(
        map(Placement::Replacing(a), Prot::READ_EXEC, Backing::None),
        Ok(a)
    );
    // The page is new, zero and executable; the next one stays as it was.
    assert_eq!(m.read_u64(a).unwrap(), 0);
    assert!(m.write_u64(a, 1).is_err());
    m.fetch(a, &mut [0]).unwrap();
    assert_eq!(m.read_u64(GuestAddr(0x10000 + PAGE_SIZE)).unwrap(), 8);
    assert_ne!(m.code_generation(), generation);
    // Where nothing was mapped, it maps; a bad range maps nothing.
    let free = GuestAddr(0x40000);
    assert_eq!(
        map(Placement::Replacing(free), Prot::READ, Backing::None),
        Ok(free)
    );
    assert_eq!(
        map(
            Placement::Replacing(GuestAddr(0x40001)),
            Prot::READ,
            Backing::None
        ),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        map(Placement::Exactly(free), Prot::READ, Backing::None),
        Err(Errno::EEXIST)
    );
}
#[test]
fn a_backed_map_shows_its_backing_or_nothing() {
    let m = memory(1);
    let a = GuestAddr(0x10000);
    let pages = SharedPages::new();
    pages.fill(0, &[0x5a], None).unwrap();
    let backing = Backing::Shared {
        pages: &pages,
        offset: 0,
        writes: SharedWrites::Allowed,
    };
    assert_eq!(
        m.map_backed(
            Placement::Replacing(a),
            PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::File,
            backing
        ),
        Ok(a)
    );
    assert_eq!(m.read_value(a, 1), Ok(0x5a));
    // A page cache without its file cannot back a private mapping: the new
    // mapping goes, and the one it replaced stays gone.
    let cache = Backing::Cache {
        pages: &pages,
        offset: 0,
    };
    assert_eq!(
        m.map_backed(
            Placement::Replacing(a),
            PAGE_SIZE,
            Prot::READ,
            MappingKind::File,
            cache
        ),
        Err(Errno::EINVAL)
    );
    assert!(!m.read(a, &mut [0]).unwrap_err().mapped);
    // Placed anywhere, it lands where there is room.
    let anywhere = m
        .map_backed(
            Placement::Near(None),
            PAGE_SIZE,
            Prot::READ,
            MappingKind::File,
            backing,
        )
        .unwrap();
    assert_eq!(m.read_value(anywhere, 1), Ok(0x5a));
}

mod signals_time_tests {
    use super::*;
    include!("signals_time_tests.rs");
}
#[test]
fn another_task_copies_page_by_page_as_linux_pins() {
    let mut m = AddressSpace::new();
    for (at, prot) in [
        (0x10000, Prot::READ_WRITE),
        (0x11000, Prot::READ),
        (0x12000, Prot::WRITE),
    ] {
        m.map(Some(GuestAddr(at)), PAGE_SIZE, prot, MappingKind::Anonymous)
            .unwrap();
    }
    m.write(GuestAddr(0x10ffc), b"abcd").unwrap();
    let view = m.view();
    let mut buf = [0; 16];
    // Up to the write-only page, which has no VM_READ.
    assert_eq!(view.read_pages(0x10ffc, &mut buf[..8]), Some(8));
    assert_eq!(&buf[..4], b"abcd");
    assert_eq!(view.read_pages(0x11ffc, &mut buf), Some(4));
    assert_eq!(view.read_pages(0x12000, &mut buf), Some(0));
    // Up to the read-only page; the write-only one takes bytes.
    assert_eq!(view.write_pages(0x10ff8, b"12345678"), Some(8));
    assert_eq!(view.write_pages(0x10ffc, b"wxyz1234"), Some(4));
    assert_eq!(view.write_pages(0x12000, b"wo"), Some(2));
    assert_eq!(view.write_pages(0x13000, b"no"), Some(0));
    m.read(GuestAddr(0x10ff8), &mut buf[..8]).unwrap();
    assert_eq!(&buf[..8], b"1234wxyz");
    drop(m);
    assert_eq!(view.read_pages(0x10000, &mut buf), None);
    assert_eq!(view.write_pages(0x10000, b"x"), None);
}
#[test]
fn page_state_tells_untouched_read_and_written_pages_apart() {
    let mut m = AddressSpace::new();
    m.map(
        Some(GuestAddr(0x20000)),
        3 * PAGE_SIZE,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    m.map_backed(
        Placement::Exactly(GuestAddr(0x30000)),
        2 * PAGE_SIZE,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
        Backing::SharedAnonymous,
    )
    .unwrap();
    m.write(GuestAddr(0x20000), &[1]).unwrap();
    let mut byte = [0u8];
    m.read(GuestAddr(0x21000), &mut byte).unwrap();
    m.read(GuestAddr(0x30000), &mut byte).unwrap();
    let states = |space: &AddressSpace| {
        [0x20000, 0x21fff, 0x22000, 0x30000, 0x31000, 0x40000]
            .map(|addr| space.page_state(GuestAddr(addr)))
    };
    let expected = [
        Some(PageState::Present),
        Some(PageState::Zero),
        Some(PageState::Absent),
        Some(PageState::Present),
        Some(PageState::Absent),
        None,
    ];
    assert_eq!(states(&m), expected);
    assert_eq!(m.view().page_state(0x21000), Some(PageState::Zero));
    // A child of fork shares the written page and the zero page, as
    // Linux copies the page table of a VMA with an anon_vma.
    assert_eq!(states(&m.fork())[..3], expected[..3]);
    // Discarded, a written page has none again.
    m.discard_shared(GuestAddr(0x20000), PAGE_SIZE).unwrap();
    assert_eq!(m.page_state(GuestAddr(0x20000)), Some(PageState::Absent));
}

#[test]
fn vma_flags_follow_linux_vm_flags() {
    let mut m = AddressSpace::new();
    let flags = |m: &AddressSpace, at: u64| m.view().vma_from(at).unwrap().flags;
    let vmas = |m: &AddressSpace, from: u64, to: u64| {
        let mut count = 0;
        let mut at = from;
        while let Some(vma) = m.view().vma_from(at).filter(|v| v.start < to) {
            count += 1;
            at = vma.end;
        }
        count
    };
    let base = vm::MAYREAD | vm::MAYWRITE | vm::MAYEXEC | vm::SOFTDIRTY;
    let rw = vm::READ | vm::WRITE;
    // Private memory that may be written is charged.
    let at = m
        .map(
            Some(GuestAddr(0x10000)),
            3 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap()
        .0;
    assert_eq!(flags(&m, at), base | rw | vm::ACCOUNT);
    // Advice splits a VMA off and merges it again once the flags agree.
    let middle = at + PAGE_SIZE;
    let advise = |m: &AddressSpace, advice| {
        m.advise_flags(GuestAddr(middle), middle + PAGE_SIZE, advice)
            .unwrap();
    };
    advise(&m, FlagAdvice::Read(Some(ReadHint::Random)));
    assert_eq!(flags(&m, middle), base | rw | vm::ACCOUNT | vm::RAND_READ);
    assert_eq!(vmas(&m, at, at + 3 * PAGE_SIZE), 3);
    advise(&m, FlagAdvice::Read(None));
    assert_eq!(vmas(&m, at, at + 3 * PAGE_SIZE), 1);
    advise(&m, FlagAdvice::HugePages(false));
    advise(&m, FlagAdvice::Mergeable(true));
    assert_eq!(
        flags(&m, middle),
        base | rw | vm::ACCOUNT | vm::NOHUGEPAGE | vm::MERGEABLE
    );
    // Never written, anonymous memory gives its charge back as it stops
    // being writable; written, it keeps it.
    let fresh = m
        .map(
            Some(GuestAddr(0x20000)),
            PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    m.protect(fresh, PAGE_SIZE, Prot::READ).unwrap();
    assert_eq!(flags(&m, fresh.0), base | vm::READ);
    m.protect(fresh, PAGE_SIZE, Prot::READ_WRITE).unwrap();
    m.write(fresh, b"x").unwrap();
    m.protect(fresh, PAGE_SIZE, Prot::READ).unwrap();
    assert_eq!(flags(&m, fresh.0), base | vm::READ | vm::ACCOUNT);
    // MAP_NORESERVE takes it out of the charge; MAP_STACK keeps huge pages
    // away.
    let new = m
        .map(
            Some(GuestAddr(0x30000)),
            PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    m.flag_new(new, new.0 + PAGE_SIZE, true, true);
    assert_eq!(flags(&m, new.0), base | rw | vm::NORESERVE | vm::NOHUGEPAGE);
    // Shared memory is not charged, and its file decides what it may do.
    let pages = SharedPages::new();
    for (writes, extra) in [
        (SharedWrites::Allowed, vm::SHARED | vm::MAYWRITE),
        (SharedWrites::Sealed, vm::SHARED),
        (SharedWrites::ReadOnly, 0),
    ] {
        let at = m
            .map(None, PAGE_SIZE, Prot::READ, MappingKind::File)
            .unwrap();
        m.share_pages(at, PAGE_SIZE, &pages, 0, writes).unwrap();
        let expected = vm::READ | vm::MAYREAD | vm::MAYEXEC | vm::MAYSHARE | vm::SOFTDIRTY | extra;
        assert_eq!(flags(&m, at.0), expected, "{writes:?}");
        // A sealed file still lets remap_file_pages map it again.
        assert_eq!(
            m.remap_shared_pages(at, PAGE_SIZE, Ok(0)).is_ok(),
            writes != SharedWrites::ReadOnly,
            "{writes:?}"
        );
    }
    // The initial stack is not soft-dirty.
    let stack = m
        .map(
            Some(GuestAddr(0x7000_0000)),
            PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Stack,
        )
        .unwrap();
    assert_eq!(
        flags(&m, stack.0),
        base & !vm::SOFTDIRTY | rw | vm::GROWSDOWN | vm::ACCOUNT
    );
}

#[test]
fn usage_counts_pages_as_linux_smaps_does() {
    let mut m = AddressSpace::new();
    let at = m
        .map(
            Some(GuestAddr(0x10000)),
            4 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    let mut byte = [0];
    m.read(at, &mut byte).unwrap();
    m.write(GuestAddr(at.0 + PAGE_SIZE), b"x").unwrap();
    m.write(GuestAddr(at.0 + 2 * PAGE_SIZE), b"x").unwrap();
    let usage = |m: &AddressSpace| m.view().usage(at.0, at.0 + 4 * PAGE_SIZE).unwrap();
    // The page only read shows the zero page, which is not counted.
    let written = usage(&m);
    assert_eq!(
        (written.resident, written.anonymous, written.private_dirty),
        (2, 2, 2)
    );
    // After a fork the pages are shared until either writes them.
    let child = m.fork();
    let shared = usage(&child);
    assert_eq!(
        (shared.resident, shared.shared_dirty, shared.private_dirty),
        (2, 2, 0)
    );
    // Shared memory's pages are not anonymous, and dirty once written.
    let s = m
        .map(
            Some(GuestAddr(0x40000)),
            2 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    m.mark_shared(s, 2 * PAGE_SIZE).unwrap();
    m.write(s, b"x").unwrap();
    let pages = m.view().usage(s.0, s.0 + 2 * PAGE_SIZE).unwrap();
    assert_eq!(
        (pages.resident, pages.anonymous, pages.private_dirty),
        (1, 0, 1)
    );
}

#[test]
fn a_mapping_that_grows_down_grows_as_linux_expand_downwards_does() {
    let m = AddressSpace::new();
    let top = 0x4000_0000;
    let at = m
        .map_backed(
            Placement::Exactly(GuestAddr(top)),
            2 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
            Backing::None,
        )
        .unwrap();
    // Not before it is marked.
    assert!(!m.grow_down(GuestAddr(top - 1), u64::MAX, u64::MAX));
    m.grow_new_down(at, top + 2 * PAGE_SIZE);
    let start = |m: &AddressSpace| m.vma_at(GuestAddr(top)).unwrap().0.0;
    // An access anywhere below takes the pages from its own up.
    assert!(m.grow_down(GuestAddr(top - 3 * PAGE_SIZE + 5), u64::MAX, u64::MAX));
    assert_eq!(start(&m), top - 3 * PAGE_SIZE);
    m.write(GuestAddr(top - 3 * PAGE_SIZE), &[7]).unwrap();
    assert!(m.view().vma_from(top).unwrap().flags & vm::GROWSDOWN != 0);
    // Within it, nothing grows, a guard page included.
    assert!(!m.grow_down(GuestAddr(top - PAGE_SIZE), u64::MAX, u64::MAX));
    m.guard(GuestAddr(top - PAGE_SIZE), top, true).unwrap();
    assert!(!m.grow_down(GuestAddr(top - PAGE_SIZE), u64::MAX, u64::MAX));
    m.guard(GuestAddr(top - PAGE_SIZE), top, false).unwrap();
    // RLIMIT_STACK bounds the whole VMA, 5 pages here.
    let low = top - 3 * PAGE_SIZE;
    assert!(!m.grow_down(GuestAddr(low - 2 * PAGE_SIZE), 6 * PAGE_SIZE, u64::MAX));
    assert!(m.grow_down(GuestAddr(low - PAGE_SIZE), 6 * PAGE_SIZE, u64::MAX));
    let low = low - PAGE_SIZE;
    // A mapping below that can be accessed keeps the guard gap free.
    let other = low - STACK_GUARD_GAP - PAGE_SIZE;
    m.map_shared(
        Some(GuestAddr(other)),
        PAGE_SIZE,
        Prot::READ,
        MappingKind::Anonymous,
    )
    .unwrap();
    assert!(!m.grow_down(GuestAddr(low - PAGE_SIZE), u64::MAX, u64::MAX));
    m.protect_shared(GuestAddr(other), PAGE_SIZE, Prot::NONE)
        .unwrap();
    assert!(m.grow_down(GuestAddr(low - PAGE_SIZE), u64::MAX, u64::MAX));
    // A hint in the gap is not taken, and the search leaves the gap free.
    let gap_start = low - PAGE_SIZE - STACK_GUARD_GAP;
    let hinted = m
        .map_backed(
            Placement::Near(Some(GuestAddr(low - 3 * PAGE_SIZE))),
            PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
            Backing::None,
        )
        .unwrap();
    assert!(hinted.0 + PAGE_SIZE <= gap_start || hinted.0 >= top + 2 * PAGE_SIZE);
    m.unmap_shared(hinted, PAGE_SIZE).unwrap();
    m.unmap_shared(GuestAddr(other), PAGE_SIZE).unwrap();
    let mut space = AddressSpace::new();
    space.set_mmap_top(GuestAddr(top + 2 * PAGE_SIZE));
    let at = space
        .map(
            Some(GuestAddr(top)),
            2 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    space.grow_new_down(at, top + 2 * PAGE_SIZE);
    let found = space
        .map(None, PAGE_SIZE, Prot::READ_WRITE, MappingKind::Anonymous)
        .unwrap();
    assert_eq!(found.0, top - STACK_GUARD_GAP - PAGE_SIZE);
    // Nor below the lowest address a mapping may have.
    let mut low = AddressSpace::new();
    low.map(
        Some(GuestAddr(MMAP_MIN_ADDR)),
        PAGE_SIZE,
        Prot::READ_WRITE,
        MappingKind::Stack,
    )
    .unwrap();
    assert!(!low.grow_down(GuestAddr(MMAP_MIN_ADDR - 1), u64::MAX, u64::MAX));
}

#[test]
fn a_locked_mapping_grows_down_within_the_lock_limit() {
    let m = AddressSpace::new();
    let top = 0x4000_0000;
    let at = m
        .map_shared(
            Some(GuestAddr(top)),
            PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    m.grow_new_down(at, top + PAGE_SIZE);
    m.lock(at, top + PAGE_SIZE, Some(Lock::OnFault)).unwrap();
    assert!(!m.grow_down(GuestAddr(top - PAGE_SIZE), u64::MAX, 1));
    assert!(m.grow_down(GuestAddr(top - PAGE_SIZE), u64::MAX, 2));
    assert_eq!(m.locked_pages(), 2);
}

#[test]
fn a_userfaultfd_registration_faults_on_missing_pages_only() {
    let m = AddressSpace::new();
    let s = m
        .map_shared(
            Some(GuestAddr(0x40000)),
            2 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    m.mark_shared(s, 2 * PAGE_SIZE).unwrap();
    let child = m.fork();
    // A page the child's mapping of the memory has is no missing page.
    child.write(GuestAddr(s.0 + PAGE_SIZE), b"k").unwrap();
    let view = m.view();
    assert_eq!(
        view.userfault_register(s.0, s.0 + 2 * PAGE_SIZE, 7, 1),
        Ok(())
    );
    let missing = m.read(s, &mut [0]).unwrap_err();
    assert!(missing.mapped && !missing.present && !missing.write);
    assert_eq!(m.userfault_at(s), Some(7));
    assert_eq!(view.userfault_at(s.0 + 5), Some(7));
    // An access the protection refuses is the CPU's fault.
    assert_eq!(m.userfault_for(s, true, false), Some((7, false)));
    assert_eq!(m.userfault_for(s, false, true), None);
    // A guarded page is neither a fault nor a page to fill.
    m.guard(GuestAddr(s.0), s.0 + PAGE_SIZE, true).unwrap();
    assert_eq!(m.userfault_for(s, false, false), None);
    assert_eq!(
        view.userfault_fill(s.0, s.0 + PAGE_SIZE, s.0, None, false),
        Err(Errno::EEXIST)
    );
    m.guard(GuestAddr(s.0), s.0 + PAGE_SIZE, false).unwrap();
    let mut byte = [0];
    m.read(GuestAddr(s.0 + PAGE_SIZE), &mut byte).unwrap();
    assert_eq!(byte, [b'k']);
    assert_eq!(view.userfault_target(s.0, s.0 + 2 * PAGE_SIZE), Ok(1));
    assert_eq!(
        view.userfault_fill(s.0, s.0 + PAGE_SIZE, s.0 + PAGE_SIZE, None, false),
        Err(Errno::EEXIST)
    );
    assert_eq!(
        view.userfault_fill(s.0, s.0 + PAGE_SIZE, s.0, Some(b"h"), false),
        Ok(())
    );
    m.read(s, &mut byte).unwrap();
    assert_eq!(byte, [b'h']);
    // The child sees the page the fill gave the memory.
    child.read(s, &mut byte).unwrap();
    assert_eq!(byte, [b'h']);
    // The registration is the space's own, and goes with release.
    assert!(child.userfault_at(s).is_none());
    view.userfault_release(7);
    assert!(m.mappings().all(|mapping| mapping.userfault.is_none()));
    // A space that is gone takes none.
    let gone = AddressSpace::new().view();
    assert!(!gone.lives());
    assert_eq!(
        gone.userfault_register(s.0, s.0 + PAGE_SIZE, 7, 1),
        Err(Errno::ENOMEM)
    );
    assert_eq!(
        gone.userfault_unregister(s.0, s.0 + PAGE_SIZE, 7),
        Err(Errno::ENOMEM)
    );
    assert_eq!(
        gone.userfault_fill(s.0, s.0 + PAGE_SIZE, s.0, None, false),
        Err(Errno(3))
    );
    assert_eq!(gone.userfault_target(s.0, s.0 + PAGE_SIZE), Err(Errno(3)));
    assert!(gone.userfault_at(s.0).is_none());
}

#[test]
fn a_userfaultfd_write_protection_faults_on_writes_while_registered() {
    let mut m = AddressSpace::new();
    let a = m
        .map(
            Some(GuestAddr(0x80000)),
            3 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    m.write(a, b"a").unwrap();
    let view = m.view();
    // Neither minor faults nor write protection of shared memory are taken.
    assert_eq!(
        view.userfault_register(a.0, a.0 + PAGE_SIZE, 7, Userfault::MINOR),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        view.userfault_write_protect(a.0, a.0 + PAGE_SIZE, true),
        Err(Errno::ENOENT)
    );
    assert_eq!(
        view.userfault_register(a.0, a.0 + 2 * PAGE_SIZE, 7, Userfault::WP),
        Ok(())
    );
    assert_eq!(
        view.userfault_write_protect(a.0, a.0 + 3 * PAGE_SIZE, true),
        Err(Errno::ENOENT)
    );
    // The VMA before the one not registered was protected, but only its
    // page with an entry.
    let page = GuestAddr(a.0 + PAGE_SIZE);
    m.write(page, b"x").unwrap();
    assert_eq!(
        view.userfault_target(a.0, a.0 + PAGE_SIZE),
        Ok(Userfault::WP)
    );
    let mut byte = [0];
    m.read(a, &mut byte).unwrap();
    let fault = m.write(a, b"c").unwrap_err();
    assert!(fault.mapped && fault.present && fault.write);
    assert_eq!(m.userfault_for(a, true, false), Some((7, true)));
    assert_eq!(m.userfault_for(a, false, false), None);
    // Read before the write: the thread's TLB entry is read-only too.
    view.userfault_write_protect(page.0, page.0 + PAGE_SIZE, true)
        .unwrap();
    m.read(page, &mut byte).unwrap();
    assert!(m.write(page, b"y").is_err());
    // A protection that refuses writes is the CPU's fault; giving writes
    // back keeps the page protected.
    m.protect(a, PAGE_SIZE, Prot::READ).unwrap();
    assert_eq!(m.userfault_for(a, true, false), None);
    m.protect(a, PAGE_SIZE, Prot::READ_WRITE).unwrap();
    assert!(m.write(a, b"d").is_err());
    // A child's mapping is not registered, nor its pages protected.
    let child = m.fork();
    child.write(a, b"e").unwrap();
    m.read(a, &mut byte).unwrap();
    assert_eq!(byte, [b'a']);
    assert_eq!(
        view.userfault_write_protect(a.0, a.0 + PAGE_SIZE, false),
        Ok(())
    );
    m.write(a, b"f").unwrap();
    child.read(a, &mut byte).unwrap();
    assert_eq!(byte, [b'e']);
    // A fill may protect its page.
    view.userfault_prepare_fill(a.0);
    m.discard_shared(page, PAGE_SIZE).unwrap();
    assert_eq!(
        view.userfault_fill(page.0, page.0 + PAGE_SIZE, page.0, Some(b"g"), true),
        Ok(())
    );
    assert!(m.write(page, b"h").is_err());
    // Unregistering ends the protection.
    view.userfault_unregister(a.0, a.0 + 2 * PAGE_SIZE, 7)
        .unwrap();
    m.write(page, b"i").unwrap();
    assert!(m.mappings().all(|mapping| mapping.userfault.is_none()));
    // As does a registration that replaces it with one for missing pages
    // alone, though not one it has the modes of already; and the release.
    view.userfault_register(a.0, a.0 + PAGE_SIZE, 7, Userfault::WP | Userfault::MISSING)
        .unwrap();
    view.userfault_write_protect(a.0, a.0 + PAGE_SIZE, true)
        .unwrap();
    view.userfault_register(a.0, a.0 + PAGE_SIZE, 7, Userfault::MISSING)
        .unwrap();
    assert!(m.write(a, b"j").is_err());
    view.userfault_unregister(a.0, a.0 + PAGE_SIZE, 7).unwrap();
    view.userfault_register(a.0, a.0 + PAGE_SIZE, 7, Userfault::WP)
        .unwrap();
    view.userfault_write_protect(a.0, a.0 + PAGE_SIZE, true)
        .unwrap();
    view.userfault_register(a.0, a.0 + PAGE_SIZE, 7, Userfault::MISSING)
        .unwrap();
    assert!(m.write(a, b"j").is_ok());
    view.userfault_register(a.0, a.0 + PAGE_SIZE, 7, Userfault::WP)
        .unwrap();
    view.userfault_write_protect(a.0, a.0 + PAGE_SIZE, true)
        .unwrap();
    view.userfault_release(7);
    m.write(a, b"k").unwrap();
    // Shared memory takes no write protection.
    let s = m
        .map_shared(
            Some(GuestAddr(0x100000)),
            PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    m.mark_shared(s, PAGE_SIZE).unwrap();
    assert_eq!(
        view.userfault_register(s.0, s.0 + PAGE_SIZE, 7, Userfault::WP),
        Err(Errno::EINVAL)
    );
    let gone = AddressSpace::new().view();
    assert_eq!(
        gone.userfault_write_protect(a.0, a.0 + PAGE_SIZE, true),
        Err(Errno(3))
    );
}
#[test]
fn a_userfaultfd_poison_raises_a_bus_error_until_a_discard() {
    let mut m = AddressSpace::new();
    let a = m
        .map(
            Some(GuestAddr(0x90000)),
            3 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    let page = |n: u64| GuestAddr(a.0 + n * PAGE_SIZE);
    m.write(page(1), b"a").unwrap();
    let view = m.view();
    // Only a registered range is poisoned.
    assert_eq!(
        view.userfault_poison(a.0, a.0 + PAGE_SIZE, a.0),
        Err(Errno::ENOENT)
    );
    view.userfault_register(a.0, a.0 + 3 * PAGE_SIZE, 7, Userfault::MISSING)
        .unwrap();
    view.userfault_prepare_fill(a.0);
    assert_eq!(view.userfault_poison(a.0, a.0 + PAGE_SIZE, a.0), Ok(()));
    // A page with an entry or poison already is `EEXIST`, for a zero page
    // too; a copy replaces the poison.
    assert_eq!(
        view.userfault_poison(a.0, a.0 + 2 * PAGE_SIZE, page(1).0),
        Err(Errno::EEXIST)
    );
    assert_eq!(
        view.userfault_poison(a.0, a.0 + PAGE_SIZE, a.0),
        Err(Errno::EEXIST)
    );
    assert_eq!(
        view.userfault_fill(a.0, a.0 + PAGE_SIZE, a.0, None, false),
        Err(Errno::EEXIST)
    );
    assert_eq!(
        view.userfault_poison(a.0, a.0 + 3 * PAGE_SIZE, page(2).0),
        Ok(())
    );
    let copied = [b'c'; PAGE_SIZE as usize];
    assert_eq!(
        view.userfault_fill(page(2).0, page(3).0, page(2).0, Some(&copied), false),
        Ok(())
    );
    let mut byte = [0];
    m.read(GuestAddr(page(2).0 + 7), &mut byte).unwrap();
    assert_eq!(byte, [b'c']);
    assert_eq!(
        view.userfault_fill(page(2).0, page(3).0, page(2).0, Some(&copied), false),
        Err(Errno::EEXIST)
    );
    // Every access is the poison's bus error, not the userfaultfd's wait.
    for fault in [
        m.read(a, &mut [0]).unwrap_err(),
        m.write(GuestAddr(a.0 + 9), b"b").unwrap_err(),
    ] {
        assert!(fault.poison && fault.bus && fault.mapped && !fault.present);
    }
    assert_eq!(m.userfault_at(a), None);
    // An access the protection refuses is the CPU's fault before it.
    m.protect(a, PAGE_SIZE, Prot::READ).unwrap();
    let refused = m.write(a, b"c").unwrap_err();
    assert!(!refused.poison && !refused.bus);
    m.protect(a, PAGE_SIZE, Prot::READ_WRITE).unwrap();
    // The poison outlasts the registration, and a child of private memory
    // has it too.
    view.userfault_unregister(a.0, a.0 + 3 * PAGE_SIZE, 7)
        .unwrap();
    assert!(m.read(a, &mut [0]).unwrap_err().poison);
    let child = m.fork();
    assert!(child.read(a, &mut [0]).unwrap_err().poison);
    // It moves with the pages.
    let moved = m
        .remap_shared(
            a,
            2 * PAGE_SIZE,
            2 * PAGE_SIZE,
            Remap {
                may_move: true,
                fixed: true,
                keep_old: false,
                new_addr: GuestAddr(0xa0000),
            },
        )
        .unwrap();
    assert!(m.read(moved, &mut [0]).unwrap_err().poison);
    m.read(GuestAddr(moved.0 + PAGE_SIZE), &mut byte).unwrap();
    assert_eq!(byte, [b'a']);
    // A guard replaces it, and removing the guard leaves an empty page.
    m.guard(moved, moved.0 + PAGE_SIZE, true).unwrap();
    assert!(!m.read(moved, &mut [0]).unwrap_err().poison);
    m.guard(moved, moved.0 + PAGE_SIZE, false).unwrap();
    m.read(moved, &mut byte).unwrap();
    assert_eq!(byte, [0]);
    // A discard ends it, as an unmap does; so does `MADV_FREE`'s.
    assert!(child.read(a, &mut [0]).unwrap_err().poison);
    child.discard_shared(a, PAGE_SIZE).unwrap();
    child.read(a, &mut byte).unwrap();
    assert_eq!(byte, [0]);
    m.discard_shared(moved, PAGE_SIZE).unwrap();
    m.read(moved, &mut byte).unwrap();
    assert_eq!(byte, [0]);
    child.unmap_shared(a, PAGE_SIZE).unwrap();
    child
        .map_shared(Some(a), PAGE_SIZE, Prot::READ_WRITE, MappingKind::Anonymous)
        .unwrap();
    child.read(a, &mut byte).unwrap();
    assert_eq!(byte, [0]);
    // Shared memory is poisoned in this mapping only, and a child's mapping
    // of it does not have the poison.
    let s = m
        .map_shared(
            Some(GuestAddr(0xb0000)),
            PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    m.mark_shared(s, PAGE_SIZE).unwrap();
    let sharer = m.fork();
    sharer.write(s, b"s").unwrap();
    view.userfault_register(s.0, s.0 + PAGE_SIZE, 7, Userfault::MISSING)
        .unwrap();
    assert_eq!(view.userfault_poison(s.0, s.0 + PAGE_SIZE, s.0), Ok(()));
    assert!(m.read(s, &mut [0]).unwrap_err().poison);
    sharer.read(s, &mut byte).unwrap();
    assert_eq!(byte, [b's']);
    let other = m.fork();
    other.read(s, &mut byte).unwrap();
    assert_eq!(byte, [b's']);
    m.clear_poisons(s, PAGE_SIZE);
    m.read(s, &mut byte).unwrap();
    assert_eq!(byte, [b's']);
    // A space that is gone takes none.
    let gone = AddressSpace::new().view();
    assert_eq!(
        gone.userfault_poison(a.0, a.0 + PAGE_SIZE, a.0),
        Err(Errno(3))
    );
}

#[test]
fn a_userfaultfd_move_moves_exclusive_pages_and_refuses_markers() {
    let mut m = AddressSpace::new();
    let dst = m
        .map(
            Some(GuestAddr(0x90000)),
            4 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap()
        .0;
    let src = m
        .map(
            Some(GuestAddr(0xa0000)),
            4 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap()
        .0;
    let view = m.view();
    view.userfault_register(
        dst,
        dst + 4 * PAGE_SIZE,
        7,
        Userfault::MISSING | Userfault::WP,
    )
    .unwrap();
    // Another context's range is EINVAL.
    m.write(GuestAddr(src), b"s").unwrap();
    assert_eq!(
        view.userfault_move(dst, src, PAGE_SIZE, 8, false),
        (0, Some(Errno::EINVAL))
    );
    // A page `fork` shares is EBUSY until a write gives it its own.
    let child = m.fork();
    assert_eq!(
        view.userfault_move(dst, src, PAGE_SIZE, 7, false),
        (0, Some(Errno(16))) // EBUSY
    );
    m.write(GuestAddr(src + 1), b"t").unwrap();
    assert_eq!(
        view.userfault_move(dst, src, PAGE_SIZE, 7, false),
        (PAGE_SIZE, None)
    );
    let mut bytes = [0; 2];
    m.read(GuestAddr(dst), &mut bytes).unwrap();
    assert_eq!(&bytes, b"st");
    assert_eq!(m.page_state(GuestAddr(src)), Some(PageState::Absent));
    child.read(GuestAddr(src), &mut bytes).unwrap();
    assert_eq!(&bytes, b"s\0");
    // The zero page moves as the zero page.
    m.read(GuestAddr(src + PAGE_SIZE), &mut bytes).unwrap();
    assert_eq!(
        view.userfault_move(dst + PAGE_SIZE, src + PAGE_SIZE, PAGE_SIZE, 7, false),
        (PAGE_SIZE, None)
    );
    assert_eq!(
        m.page_state(GuestAddr(dst + PAGE_SIZE)),
        Some(PageState::Zero)
    );
    // A marker at the destination is EEXIST, at the source EFAULT.
    view.userfault_poison(dst, dst + 4 * PAGE_SIZE, dst + 2 * PAGE_SIZE)
        .unwrap();
    m.write(GuestAddr(src + 2 * PAGE_SIZE), b"u").unwrap();
    assert_eq!(
        view.userfault_move(
            dst + 2 * PAGE_SIZE,
            src + 2 * PAGE_SIZE,
            PAGE_SIZE,
            7,
            false
        ),
        (0, Some(Errno::EEXIST))
    );
    m.guard(GuestAddr(src + 3 * PAGE_SIZE), src + 4 * PAGE_SIZE, true)
        .unwrap();
    assert_eq!(
        view.userfault_move(dst + 3 * PAGE_SIZE, src + 3 * PAGE_SIZE, PAGE_SIZE, 7, true),
        (0, Some(Errno::EFAULT))
    );
    // A moved page is writable, and no longer write-protected.
    m.write(GuestAddr(dst), b"w").unwrap();
    view.userfault_register(src, src + 4 * PAGE_SIZE, 7, Userfault::WP)
        .unwrap();
    view.userfault_write_protect(src + 2 * PAGE_SIZE, src + 3 * PAGE_SIZE, true)
        .unwrap();
    assert_eq!(
        view.userfault_move(
            dst + 3 * PAGE_SIZE,
            src + 2 * PAGE_SIZE,
            PAGE_SIZE,
            7,
            false
        ),
        (PAGE_SIZE, None)
    );
    m.write(GuestAddr(dst + 3 * PAGE_SIZE + 1), b"v").unwrap();
    m.read(GuestAddr(dst + 3 * PAGE_SIZE), &mut bytes).unwrap();
    assert_eq!(&bytes, b"uv");
}
