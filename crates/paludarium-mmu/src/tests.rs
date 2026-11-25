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
    assert_eq!(states(&m.fork().unwrap())[..3], expected[..3]);
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
    let child = m.fork().unwrap();
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
    let child = m.fork().unwrap();
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
    assert_eq!(
        m.userfault_for(s, true, false),
        Some((7, UserfaultReason::Missing))
    );
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
    assert_eq!(
        m.userfault_for(a, true, false),
        Some((7, UserfaultReason::Protected))
    );
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
    let child = m.fork().unwrap();
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
    // Shared memory takes write protection too.
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
        Ok(())
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
    let child = m.fork().unwrap();
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
    let sharer = m.fork().unwrap();
    sharer.write(s, b"s").unwrap();
    view.userfault_register(s.0, s.0 + PAGE_SIZE, 7, Userfault::MISSING)
        .unwrap();
    assert_eq!(view.userfault_poison(s.0, s.0 + PAGE_SIZE, s.0), Ok(()));
    assert!(m.read(s, &mut [0]).unwrap_err().poison);
    sharer.read(s, &mut byte).unwrap();
    assert_eq!(byte, [b's']);
    let other = m.fork().unwrap();
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
    let child = m.fork().unwrap();
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

/// A shmem file of `size` bytes that holds the pages in `held`.
struct Shmem {
    size: u64,
    held: Vec<u64>,
    shmem: bool,
}

impl PageSource for Shmem {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let n = buf
            .len()
            .min(usize::try_from(self.size.saturating_sub(offset)).unwrap_or(0));
        buf[..n].fill(b'f');
        Ok(n)
    }
    fn size(&self) -> Option<u64> {
        Some(self.size)
    }
    fn shmem(&self) -> bool {
        self.shmem
    }
    fn holds(&self, offset: u64) -> bool {
        self.held.contains(&(offset / PAGE_SIZE))
    }
}

#[test]
fn usage_splits_pss_by_what_each_page_is_as_smaps_account_does() {
    let mut m = AddressSpace::new();
    let view = m.view();
    let pss_split = |at: u64, pages: u64| {
        let usage = view.usage(at, at + pages * PAGE_SIZE).unwrap();
        assert_eq!(usage.pss, usage.pss_anon + usage.pss_file + usage.pss_shmem);
        (usage.pss_anon, usage.pss_file, usage.pss_shmem)
    };
    let page = PAGE_SIZE << Usage::PSS_SHIFT;
    // A written page of private memory is anonymous.
    let anonymous = m
        .map(None, PAGE_SIZE, Prot::READ_WRITE, MappingKind::Anonymous)
        .unwrap();
    m.write(anonymous, b"x").unwrap();
    assert_eq!(pss_split(anonymous.0, 1), (page, 0, 0));
    // Shared memory of no file is shmem's.
    let shared = m
        .map(None, PAGE_SIZE, Prot::READ_WRITE, MappingKind::Anonymous)
        .unwrap();
    m.mark_shared(shared, PAGE_SIZE).unwrap();
    m.write(shared, b"x").unwrap();
    assert_eq!(pss_split(shared.0, 1), (0, 0, page));
    // A shared mapping of a file: shmem's for a shmem file, the file's
    // otherwise.
    for (shmem, split) in [(true, (0, 0, page)), (false, (0, page, 0))] {
        let source: Arc<dyn PageSource> = Arc::new(Shmem {
            size: PAGE_SIZE,
            held: vec![0],
            shmem,
        });
        let pages = SharedPages::new().with_source(source);
        let at = m
            .map_shared(None, PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
            .unwrap();
        m.share_pages(at, PAGE_SIZE, &pages, 0, SharedWrites::Allowed)
            .unwrap();
        m.read(at, &mut [0]).unwrap();
        assert_eq!(pss_split(at.0, 1), split, "shmem {shmem}");
    }
}

#[test]
fn a_userfaultfd_registers_shmem_files_and_waits_for_their_holes() {
    let file = |shmem| -> Arc<dyn PageSource> {
        Arc::new(Shmem {
            size: 2 * PAGE_SIZE,
            held: vec![1],
            shmem,
        })
    };
    let m = AddressSpace::new();
    let view = m.view();
    let map = |source: &Arc<dyn PageSource>| {
        let pages = SharedPages::new().with_source(Arc::clone(source));
        let at = m
            .map_shared(None, 3 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
            .unwrap();
        m.share_pages(at, 3 * PAGE_SIZE, &pages, 0, SharedWrites::Allowed)
            .unwrap();
        (at.0, pages)
    };
    // A file that is not shmem's is not registered; shmem is, for write
    // protection too.
    let (other, _) = map(&file(false));
    assert_eq!(
        view.userfault_register(other, other + PAGE_SIZE, 7, Userfault::MISSING),
        Err(Errno::EINVAL)
    );
    let (at, pages) = map(&file(true));
    assert_eq!(
        view.userfault_register(at, at + PAGE_SIZE, 7, Userfault::WP),
        Ok(())
    );
    view.userfault_register(at, at + 3 * PAGE_SIZE, 7, Userfault::MISSING)
        .unwrap();
    // A hole waits; a page the file holds does not, nor one past its end,
    // which is a bus error.
    assert_eq!(m.userfault_at(GuestAddr(at)), Some(7));
    assert_eq!(m.userfault_at(GuestAddr(at + PAGE_SIZE)), None);
    assert_eq!(m.userfault_at(GuestAddr(at + 2 * PAGE_SIZE)), None);
    assert!(
        m.read(GuestAddr(at + 2 * PAGE_SIZE), &mut [0])
            .unwrap_err()
            .bus
    );
    let bytes = [b'c'; PAGE_SIZE as usize];
    let end = at + 3 * PAGE_SIZE;
    assert_eq!(
        view.userfault_fill(at, end, at + 2 * PAGE_SIZE, Some(&bytes), false),
        Err(Errno::EFAULT)
    );
    assert_eq!(
        view.userfault_poison(at, end, at + 2 * PAGE_SIZE),
        Err(Errno::EFAULT)
    );
    assert_eq!(
        view.userfault_fill(at, end, at + PAGE_SIZE, Some(&bytes), false),
        Err(Errno::EEXIST)
    );
    // A fill of the hole is the file's, for write-back.
    assert_eq!(
        view.userfault_fill(at, end, at, Some(&bytes), false),
        Ok(())
    );
    let mut written = Vec::new();
    pages
        .write_back(|key, page| {
            written.push((key, page[0]));
            Ok(())
        })
        .unwrap();
    assert_eq!(written, [(0, b'c')]);
    // A private mapping's fill is its own: the cache keeps its hole.
    let private_pages = SharedPages::new().with_source(file(true));
    let private = m
        .map_shared(None, 2 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
        .unwrap();
    m.back_with_cache(private, 2 * PAGE_SIZE, &private_pages, 0)
        .unwrap();
    let private = private.0;
    view.userfault_register(private, private + 2 * PAGE_SIZE, 7, Userfault::MISSING)
        .unwrap();
    assert_eq!(m.userfault_at(GuestAddr(private)), Some(7));
    let end = private + 2 * PAGE_SIZE;
    assert_eq!(
        view.userfault_fill(private, end, private, None, false),
        Ok(())
    );
    assert!(!private_pages.contains(0));
    let mut b = [1];
    m.read(GuestAddr(private + 3), &mut b).unwrap();
    assert_eq!(b, [0]);
    m.read(GuestAddr(private + PAGE_SIZE), &mut b).unwrap();
    assert_eq!(b, *b"f");
}

#[test]
fn a_userfaultfd_minor_fault_waits_for_uffdio_continue() {
    let source: Arc<dyn PageSource> = Arc::new(Shmem {
        size: 3 * PAGE_SIZE,
        held: vec![1],
        shmem: true,
    });
    let m = AddressSpace::new();
    let view = m.view();
    let pages = SharedPages::new().with_source(Arc::clone(&source));
    let at = m
        .map_shared(None, 4 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
        .unwrap();
    m.share_pages(at, 4 * PAGE_SIZE, &pages, 0, SharedWrites::Allowed)
        .unwrap();
    let at = at.0;
    let anon = m
        .map_shared(None, PAGE_SIZE, Prot::READ_WRITE, MappingKind::Anonymous)
        .unwrap()
        .0;
    // Only shmem takes the minor mode, with write protection too.
    assert_eq!(
        view.userfault_register(anon, anon + PAGE_SIZE, 7, Userfault::MINOR),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        view.userfault_register(at, at + 4 * PAGE_SIZE, 7, Userfault::MINOR | Userfault::WP),
        Ok(())
    );
    view.userfault_register(at, at + 4 * PAGE_SIZE, 7, Userfault::MINOR)
        .unwrap();
    view.userfault_register(anon, anon + PAGE_SIZE, 7, Userfault::MISSING)
        .unwrap();
    // A page the file holds waits; a hole is brought in, as the mode is not
    // for missing pages.
    let page = |n: u64| at + n * PAGE_SIZE;
    assert_eq!(
        m.userfault_for(GuestAddr(page(1)), false, false),
        Some((7, UserfaultReason::Minor))
    );
    assert!(!m.read(GuestAddr(page(1)), &mut [0]).unwrap_err().present);
    assert_eq!(m.userfault_for(GuestAddr(page(2)), false, false), None);
    let end = at + 4 * PAGE_SIZE;
    // `UFFDIO_CONTINUE`: shmem only, the page within the file, in the page
    // cache, and not mapped yet.
    assert_eq!(
        view.userfault_continue(anon, anon + PAGE_SIZE, anon, false),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        view.userfault_continue(at, end, page(3), false),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        view.userfault_continue(at, end, page(2), false),
        Err(Errno::EFAULT)
    );
    assert_eq!(view.userfault_continue(at, end, page(1), false), Ok(()));
    assert_eq!(
        view.userfault_continue(at, end, page(1), false),
        Err(Errno::EEXIST)
    );
    let mut byte = [0];
    m.read(GuestAddr(page(1) + 3), &mut byte).unwrap();
    assert_eq!(byte, *b"f");
    // Once a mapping brought a hole in, the page cache has it.
    m.read(GuestAddr(page(0)), &mut byte).unwrap();
    assert_eq!(
        view.userfault_continue(at, end, page(0), false),
        Err(Errno::EEXIST)
    );
    // A discard drops the entries, and the pages wait again; a
    // `UFFDIO_CONTINUE` with the write-protect mode protects its page.
    m.discard_shared(GuestAddr(at), 4 * PAGE_SIZE).unwrap();
    assert_eq!(
        m.userfault_for(GuestAddr(page(1)), false, false),
        Some((7, UserfaultReason::Minor))
    );
    view.userfault_register(at, end, 7, Userfault::MINOR | Userfault::WP)
        .unwrap();
    assert_eq!(view.userfault_continue(at, end, page(1), true), Ok(()));
    assert!(m.write(GuestAddr(page(1)), b"g").is_err());
    assert_eq!(
        m.userfault_for(GuestAddr(page(1)), true, false),
        Some((7, UserfaultReason::Protected))
    );
    // With the missing mode too, a hole is a missing page.
    view.userfault_register(at, end, 7, Userfault::MISSING | Userfault::MINOR)
        .unwrap();
    assert_eq!(
        m.userfault_for(GuestAddr(page(2)), true, false),
        Some((7, UserfaultReason::Missing))
    );
}

#[test]
fn uffdio_writeprotect_marks_the_pages_of_shmem_that_have_no_entry() {
    let source: Arc<dyn PageSource> = Arc::new(Shmem {
        size: 4 * PAGE_SIZE,
        held: vec![],
        shmem: true,
    });
    let m = AddressSpace::new();
    let view = m.view();
    let pages = SharedPages::new().with_source(Arc::clone(&source));
    let at = m
        .map_shared(None, 4 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
        .unwrap();
    m.share_pages(at, 4 * PAGE_SIZE, &pages, 0, SharedWrites::Allowed)
        .unwrap();
    let at = at.0;
    let end = at + 4 * PAGE_SIZE;
    let page = |n: u64| GuestAddr(at + n * PAGE_SIZE);
    let state = |n: u64| {
        view.pagemap(page(n).0, 1).unwrap()[0]
            & (pagemap::PRESENT | pagemap::SWAP | pagemap::UFFD_WP)
    };
    view.userfault_register(at, end, 7, Userfault::WP).unwrap();
    m.write(page(1), b"a").unwrap();
    view.userfault_write_protect(at, end, true).unwrap();
    // A page with no entry has a marker: a write to it faults to the
    // `userfaultfd`, which makes its entry, write-protected, first.
    assert_eq!(state(0), pagemap::SWAP | pagemap::UFFD_WP);
    let fault = m.write(page(0), b"b").unwrap_err();
    assert!(fault.mapped && !fault.present && fault.write);
    assert_eq!(
        m.userfault_for(page(0), true, false),
        Some((7, UserfaultReason::Protected))
    );
    assert_eq!(state(0), pagemap::PRESENT | pagemap::UFFD_WP);
    assert!(m.write(page(0), b"b").unwrap_err().present);
    // A read makes a write-protected entry too.
    let mut b = [0];
    m.read(page(2), &mut b).unwrap();
    assert_eq!(state(2), pagemap::PRESENT | pagemap::UFFD_WP);
    assert!(m.write(page(2), b"c").is_err());
    assert_eq!(m.userfault_for(page(2), false, false), None);
    // A discard drops shmem's entries and leaves markers for the
    // protected ones; the page cache keeps the contents.
    m.discard_shared(GuestAddr(at), 4 * PAGE_SIZE).unwrap();
    assert_eq!(state(1), pagemap::SWAP | pagemap::UFFD_WP);
    m.read(page(1), &mut b).unwrap();
    assert_eq!(b, *b"a");
    assert!(m.write(page(1), b"d").is_err());
    // The end of the protection drops the markers.
    view.userfault_write_protect(at, end, false).unwrap();
    assert_eq!(state(3), 0);
    m.write(page(3), b"e").unwrap();
    m.write(page(1), b"f").unwrap();
    m.discard_shared(GuestAddr(at), 4 * PAGE_SIZE).unwrap();
    m.write(page(1), b"g").unwrap();
    // A fill takes a marker's place, protected only by its mode.
    view.userfault_write_protect(at, end, true).unwrap();
    m.discard_shared(GuestAddr(at), 4 * PAGE_SIZE).unwrap();
    assert_eq!(state(1), pagemap::SWAP | pagemap::UFFD_WP);
    assert_eq!(
        view.userfault_poison(at, end, page(1).0),
        Err(Errno::EEXIST)
    );
    // A page the page cache has is a shmem fill's `EEXIST`; a hole's
    // marker gives way.
    assert_eq!(
        view.userfault_fill(at, end, page(1).0, None, false),
        Err(Errno::EEXIST)
    );
    view.userfault_unregister(at, end, 7).unwrap();
    assert_eq!(state(1), 0);
}

#[test]
fn uffdio_writeprotect_marks_unpopulated_anonymous_pages_with_wp_unpopulated() {
    let mut m = AddressSpace::new();
    let view = m.view();
    let at = m
        .map(
            None,
            3 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap()
        .0;
    let end = at + 3 * PAGE_SIZE;
    let page = |n: u64| GuestAddr(at + n * PAGE_SIZE);
    // Without `WP_UNPOPULATED` a page with no entry is not protected.
    view.userfault_register(at, end, 7, Userfault::WP).unwrap();
    view.userfault_write_protect(at, end, true).unwrap();
    m.write(page(0), b"a").unwrap();
    view.userfault_register(at, end, 7, Userfault::WP | Userfault::WP_UNPOPULATED)
        .unwrap();
    view.userfault_write_protect(at, end, true).unwrap();
    assert!(m.write(page(0), b"b").is_err());
    assert!(m.write(page(1), b"b").is_err());
    assert_eq!(
        m.userfault_for(page(1), true, false),
        Some((7, UserfaultReason::Protected))
    );
    // A zero page or a poison does not replace a marker; a copy does.
    view.userfault_prepare_fill(at);
    assert_eq!(
        view.userfault_fill(at, end, page(2).0, None, false),
        Err(Errno::EEXIST)
    );
    assert_eq!(
        view.userfault_poison(at, end, page(2).0),
        Err(Errno::EEXIST)
    );
    assert_eq!(
        view.userfault_fill(at, end, page(2).0, Some(b"c"), false),
        Ok(())
    );
    m.write(page(2), b"d").unwrap();
    // A discard of anonymous memory drops the protection, markers too.
    m.discard_shared(page(1), 2 * PAGE_SIZE).unwrap();
    m.write(page(1), b"e").unwrap();
    m.write(page(2), b"e").unwrap();
    // A child has no markers.
    m.discard_shared(page(1), 2 * PAGE_SIZE).unwrap();
    view.userfault_write_protect(at, end, true).unwrap();
    let child = m.fork().unwrap();
    child.write(page(1), b"f").unwrap();
    assert!(m.write(page(1), b"g").is_err());
}

#[test]
fn wp_async_writes_clear_the_protection_of_any_memory() {
    let source: Arc<dyn PageSource> = Arc::new(Shmem {
        size: 4 * PAGE_SIZE,
        held: vec![],
        shmem: false,
    });
    let mut m = AddressSpace::new();
    let view = m.view();
    let at = m
        .map(None, 4 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
        .unwrap();
    m.back_with_file(at, 4 * PAGE_SIZE, source, 0).unwrap();
    let at = at.0;
    let end = at + 4 * PAGE_SIZE;
    let page = |n: u64| GuestAddr(at + n * PAGE_SIZE);
    let state = |n: u64| {
        view.pagemap(page(n).0, 1).unwrap()[0]
            & (pagemap::PRESENT | pagemap::SWAP | pagemap::UFFD_WP)
    };
    let modes = Userfault::WP | Userfault::WP_UNPOPULATED;
    // A private mapping of a file takes write protection only with
    // `WP_ASYNC`, and then no other mode.
    assert_eq!(
        view.userfault_register(at, end, 7, modes),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        view.userfault_register(at, end, 7, modes | Userfault::MISSING | Userfault::WP_ASYNC),
        Err(Errno::EINVAL)
    );
    view.userfault_register(at, end, 7, modes | Userfault::WP_ASYNC)
        .unwrap();
    let mut b = [0];
    m.read(page(0), &mut b).unwrap();
    view.userfault_write_protect(at, end, true).unwrap();
    assert_eq!(state(0), pagemap::PRESENT | pagemap::UFFD_WP);
    assert_eq!(state(1), pagemap::SWAP | pagemap::UFFD_WP);
    // A write goes on, to an entry or to a marker's page, and clears the
    // protection; nothing waits.
    m.write(page(0), b"a").unwrap();
    m.write(page(1), b"b").unwrap();
    assert_eq!(m.userfault_for(page(0), true, false), None);
    assert_eq!(state(0), pagemap::PRESENT);
    assert_eq!(state(1), pagemap::PRESENT);
    m.read(page(0), &mut b).unwrap();
    assert_eq!(b, *b"a");
    // A read keeps it.
    m.read(page(2), &mut b).unwrap();
    assert_eq!(b, *b"f");
    assert_eq!(state(2), pagemap::PRESENT | pagemap::UFFD_WP);
    // A discard drops every entry and keeps the protection of the
    // protected pages only, as markers (`zap_install_uffd_wp_if_needed`).
    // An access reads the file again.
    m.discard_shared(GuestAddr(at), 4 * PAGE_SIZE).unwrap();
    assert_eq!(state(0), 0);
    assert_eq!(state(1), 0);
    assert_eq!(state(2), pagemap::SWAP | pagemap::UFFD_WP);
    assert_eq!(state(3), pagemap::SWAP | pagemap::UFFD_WP);
    m.read(page(0), &mut b).unwrap();
    assert_eq!(b, *b"f");
    assert_eq!(state(0), pagemap::PRESENT);
    m.read(page(3), &mut b).unwrap();
    assert_eq!(state(3), pagemap::PRESENT | pagemap::UFFD_WP);
    m.write(page(2), b"c").unwrap();
    assert_eq!(state(2), pagemap::PRESENT);
    // A fill is not for a file's memory.
    assert_eq!(view.userfault_target(at, end).err(), Some(Errno::EINVAL));
    view.userfault_unregister(at, end, 7).unwrap();
    assert_eq!(state(3), pagemap::PRESENT);
}

#[test]
fn wp_async_writes_clear_the_protection_of_anonymous_memory() {
    let mut m = AddressSpace::new();
    let view = m.view();
    let at = m
        .map(
            None,
            2 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap()
        .0;
    let end = at + 2 * PAGE_SIZE;
    let page = |n: u64| GuestAddr(at + n * PAGE_SIZE);
    let state = |n: u64| {
        view.pagemap(page(n).0, 1).unwrap()[0]
            & (pagemap::PRESENT | pagemap::SWAP | pagemap::UFFD_WP)
    };
    let modes = Userfault::WP | Userfault::WP_UNPOPULATED | Userfault::WP_ASYNC;
    view.userfault_register(at, end, 7, modes).unwrap();
    m.write(page(0), b"a").unwrap();
    view.userfault_write_protect(at, end, true).unwrap();
    assert_eq!(state(0), pagemap::PRESENT | pagemap::UFFD_WP);
    assert_eq!(state(1), pagemap::SWAP | pagemap::UFFD_WP);
    m.write(page(0), b"b").unwrap();
    m.write(page(1), b"c").unwrap();
    assert_eq!(state(0), pagemap::PRESENT);
    assert_eq!(state(1), pagemap::PRESENT);
    // A discard of anonymous memory drops the markers.
    view.userfault_write_protect(at, end, true).unwrap();
    m.discard_shared(GuestAddr(at), 2 * PAGE_SIZE).unwrap();
    assert_eq!(state(0), 0);
}

#[test]
fn a_wp_async_write_with_no_room_keeps_a_markers_protection_only() {
    let meter = Arc::new(MemoryMeter::new(PAGE_SIZE));
    let mut m = AddressSpace::new().with_memory_meter(Arc::clone(&meter));
    let view = m.view();
    let at = m
        .map(
            None,
            3 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap()
        .0;
    let end = at + 3 * PAGE_SIZE;
    let page = |n: u64| GuestAddr(at + n * PAGE_SIZE);
    let wp = |n: u64| view.pagemap(page(n).0, 1).unwrap()[0] & pagemap::UFFD_WP != 0;
    let modes = Userfault::WP | Userfault::WP_UNPOPULATED | Userfault::WP_ASYNC;
    view.userfault_register(at, end, 7, modes).unwrap();
    m.write(page(0), b"a").unwrap();
    let mut b = [0];
    m.read(page(2), &mut b).unwrap();
    view.userfault_write_protect(at, end, true).unwrap();
    // The meter is full: a marker's page stays protected, as Linux makes
    // no entry; the zero page loses it, as `do_wp_page` clears it before
    // the copy fails.
    assert!(m.write(page(1), b"b").is_err());
    assert!(wp(1));
    assert!(m.write(page(2), b"c").is_err());
    assert!(!wp(2));
    m.write(page(0), b"d").unwrap();
    assert!(!wp(0));
}

/// A file whose VMAs never merge, as System V shared memory's, which counts
/// the VMAs opened and closed and who did it.
#[derive(Default)]
struct Counted {
    told: Mutex<Vec<(bool, u32)>>,
}

impl PageSource for Counted {
    fn read_at(&self, _: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        buf.fill(0);
        Ok(buf.len())
    }
    fn merges(&self) -> bool {
        false
    }
    fn opened(&self, by: &Actor) {
        self.told
            .lock()
            .unwrap()
            .push((true, *by.downcast_ref::<u32>().unwrap()));
    }
    fn closed(&self, by: &Actor) {
        self.told
            .lock()
            .unwrap()
            .push((false, *by.downcast_ref::<u32>().unwrap()));
    }
}

#[test]
fn the_vmas_of_a_file_that_never_merges_open_and_close_as_linux_s_do() {
    let file = Arc::new(Counted::default());
    let told = || std::mem::take(&mut *file.told.lock().unwrap());
    let m = AddressSpace::new();
    let pages = SharedPages::new().with_source(file.clone());
    let at = m
        .map_shared(None, 6 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
        .unwrap()
        .0;
    let page = |n: u64| GuestAddr(at + n * PAGE_SIZE);
    m.share_pages(page(0), 6 * PAGE_SIZE, &pages, 0, SharedWrites::Allowed)
        .unwrap();
    drop(pages);
    // A thread with no actor tells nothing.
    m.protect_shared(page(5), PAGE_SIZE, Prot::READ).unwrap();
    assert_eq!(told(), []);
    set_current_actor(Some(Arc::new(1u32)));
    // A split opens the new VMA; an unmap of a whole VMA closes it, and
    // one of part splits it and closes the part.
    m.protect_shared(page(4), PAGE_SIZE, Prot::READ).unwrap();
    assert_eq!(told(), [(true, 1)]);
    m.unmap_shared(page(5), PAGE_SIZE).unwrap();
    assert_eq!(told(), [(false, 1)]);
    m.unmap_shared(page(3), PAGE_SIZE).unwrap();
    assert_eq!(told(), [(true, 1), (false, 1)]);
    // mlock and madvise split where they change the flags, and not where
    // they leave them, nor at the end of a VMA.
    m.lock(page(0), page(1).0, Some(Lock::OnFault)).unwrap();
    assert_eq!(told(), [(true, 1)]);
    m.lock(page(0), page(1).0, Some(Lock::OnFault)).unwrap();
    m.advise_flags(page(1), page(3).0, FlagAdvice::DontDump)
        .unwrap();
    assert_eq!(told(), []);
    m.advise_flags(page(2), page(3).0, FlagAdvice::DoDump)
        .unwrap();
    assert_eq!(told(), [(true, 1)]);
    let pieces = |m: &AddressSpace| m.shared_fragments().len();
    assert_eq!(pieces(&m), 4);
    // A move by mremap closes the old VMA and opens its copy.
    let moved = m
        .remap_shared(
            page(4),
            PAGE_SIZE,
            PAGE_SIZE,
            Remap {
                may_move: true,
                fixed: true,
                new_addr: page(16),
                ..Remap::default()
            },
        )
        .unwrap();
    assert_eq!(moved, page(16));
    assert_eq!(told(), [(false, 1), (true, 1)]);
    // A fork opens the child's VMAs as the parent; the child's space then
    // closes them as whoever lets go of it last.
    let child = m.fork().unwrap();
    assert_eq!(told(), [(true, 1); 4]);
    set_current_actor(Some(Arc::new(2u32)));
    drop(child);
    assert_eq!(told(), [(false, 2); 4]);
    // Tasks that share one space (`CLONE_VM`) each tell as themselves, and
    // only the last of them to let go of it closes what is left
    // (`exit_mmap`).
    let m = Arc::new(m);
    let other = Arc::clone(&m);
    m.unmap_shared(page(0), PAGE_SIZE).unwrap();
    assert_eq!(told(), [(false, 2)]);
    set_current_actor(Some(Arc::new(1u32)));
    drop(m);
    assert_eq!(told(), []);
    set_current_actor(Some(Arc::new(3u32)));
    drop(other);
    assert_eq!(told(), [(false, 3); 3]);
    set_current_actor(None);
}

#[test]
fn a_fork_that_fails_closes_the_vmas_it_opened() {
    let file = Arc::new(Counted::default());
    let told = || std::mem::take(&mut *file.told.lock().unwrap());
    let meter = Arc::new(MemoryMeter::new(PAGE_SIZE));
    let mut m = AddressSpace::new().with_memory_meter(Arc::clone(&meter));
    // The private page is between three shared mappings, one of which
    // MADV_DONTFORK leaves out.
    let shared = [0x10000, 0x20000, 0x40000].map(GuestAddr);
    for at in shared {
        m.map_shared(Some(at), PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
            .unwrap();
        let pages = SharedPages::new().with_source(file.clone());
        m.share_pages(at, PAGE_SIZE, &pages, 0, SharedWrites::Allowed)
            .unwrap();
    }
    m.advise_flags(shared[0], 0x11000, FlagAdvice::DontFork)
        .unwrap();
    let at = m
        .map(
            Some(GuestAddr(0x30000)),
            PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    m.write(at, b"p").unwrap();
    set_current_actor(Some(Arc::new(1u32)));
    told();
    let pinned = m.pin(at, 1).unwrap();
    assert!(matches!(m.fork(), Err(Errno::ENOMEM)));
    // Only the mapping before the one that failed was opened (`dup_mmap`).
    assert_eq!(told(), [(true, 1), (false, 1)]);
    assert_eq!(meter.used(), PAGE_SIZE);
    drop(pinned);
    drop(m.fork().unwrap());
    assert_eq!(told(), [(true, 1), (true, 1), (false, 1), (false, 1)]);
    set_current_actor(None);
}

#[test]
fn a_fork_leaves_out_a_pinned_page_the_child_does_not_get() {
    for advice in [FlagAdvice::DontFork, FlagAdvice::WipeOnFork] {
        // Room for the one page written: `dup_mmap` copies no page of a
        // mapping the child does not get or gets empty.
        let meter = Arc::new(MemoryMeter::new(PAGE_SIZE));
        let mut m = AddressSpace::new().with_memory_meter(Arc::clone(&meter));
        let at = m
            .map(None, PAGE_SIZE, Prot::READ_WRITE, MappingKind::Anonymous)
            .unwrap();
        m.write(at, b"p").unwrap();
        m.advise_flags(at, at.0 + PAGE_SIZE, advice).unwrap();
        let pinned = m.pin(at, 1).unwrap();
        let child = m.fork().unwrap();
        assert_eq!(meter.used(), PAGE_SIZE);
        assert_eq!(child.resident_pages(), (0, 0));
        // The parent's page is still the pinned one.
        m.write(at, b"q").unwrap();
        let mut buf = [0u8; 1];
        pinned.read(0, &mut buf);
        assert_eq!(&buf, b"q");
        assert_eq!(meter.used(), PAGE_SIZE);
    }
}

#[test]
fn a_child_and_a_moved_mapping_keep_the_registrations_whose_events_they_give() {
    const WP: u64 = 1 << 57;
    let mut m = AddressSpace::new();
    let a = m
        .map(
            Some(GuestAddr(0x80000)),
            4 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    let view = m.view();
    let modes = Userfault::WP | Userfault::WP_UNPOPULATED;
    // The first two pages for a context with fork's event, the next for one
    // without; the first page has an entry, the second a marker.
    view.userfault_register(a.0, a.0 + 2 * PAGE_SIZE, 7, modes | Userfault::EVENT_FORK)
        .unwrap();
    view.userfault_register(a.0 + 2 * PAGE_SIZE, a.0 + 3 * PAGE_SIZE, 8, modes)
        .unwrap();
    m.write(a, b"a").unwrap();
    m.write(GuestAddr(a.0 + 2 * PAGE_SIZE), b"b").unwrap();
    view.userfault_write_protect(a.0, a.0 + 3 * PAGE_SIZE, true)
        .unwrap();
    assert_eq!(
        view.userfault_registrations(a.0 + PAGE_SIZE, a.0 + 4 * PAGE_SIZE)
            .iter()
            .map(|&(s, e, u)| (s - a.0, e - a.0, u.context))
            .collect::<Vec<_>>(),
        [
            (PAGE_SIZE, 2 * PAGE_SIZE, 7),
            (2 * PAGE_SIZE, 3 * PAGE_SIZE, 8)
        ]
    );
    let child = m.fork().unwrap();
    let in_child = child.view();
    let registered = |space: &AddressSpace, addr: GuestAddr| {
        space
            .mappings()
            .find(|m| m.start.0 <= addr.0 && addr.0 < m.end())
            .and_then(|m| m.userfault)
            .map(|u| u.context)
    };
    // The child keeps the one registration, its entry's protection and the
    // marker; the other's go.
    let flags = |space: &MemoryView| -> Vec<bool> {
        space
            .pagemap(a.0, 3)
            .unwrap()
            .iter()
            .map(|e| e & WP != 0)
            .collect()
    };
    assert_eq!(flags(&in_child), [true, true, false]);
    assert_eq!(flags(&view), [true, true, true]);
    assert_eq!(registered(&child, a), Some(7));
    assert_eq!(registered(&child, GuestAddr(a.0 + 2 * PAGE_SIZE)), None);
    assert_eq!(
        child.userfault_for(a, true, false),
        Some((7, UserfaultReason::Protected))
    );
    child.write(GuestAddr(a.0 + 2 * PAGE_SIZE), b"c").unwrap();
    // The kernel moves it to the child's own context.
    in_child.userfault_renumber(7, 9);
    assert_eq!(
        child.userfault_for(a, true, false),
        Some((9, UserfaultReason::Protected))
    );
    assert_eq!(registered(&m, a), Some(7));
    // A move keeps a registration with the remap event, with its pages'
    // protection and markers; one without leaves its context.
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
    assert_eq!(registered(&m, moved), None);
    let pagemap = view.pagemap(moved.0, 2).unwrap();
    assert!(pagemap.iter().all(|e| e & WP == 0));
    view.userfault_register(
        moved.0,
        moved.0 + 2 * PAGE_SIZE,
        7,
        modes | Userfault::EVENT_REMAP,
    )
    .unwrap();
    m.write(moved, b"d").unwrap();
    view.userfault_write_protect(moved.0, moved.0 + 2 * PAGE_SIZE, true)
        .unwrap();
    let back = m
        .remap_shared(
            moved,
            2 * PAGE_SIZE,
            2 * PAGE_SIZE,
            Remap {
                may_move: true,
                fixed: true,
                keep_old: false,
                new_addr: a,
            },
        )
        .unwrap();
    assert_eq!(back, a);
    assert_eq!(registered(&m, a), Some(7));
    assert_eq!(flags(&view)[..2], [true, true]);
    assert_eq!(
        m.userfault_for(a, true, false),
        Some((7, UserfaultReason::Protected))
    );
}

/// One `PAGEMAP_SCAN` walk of `[start, end)` for at most `capacity`
/// regions, with the request `ask` makes.
fn scan_walk(
    view: &MemoryView,
    start: u64,
    end: u64,
    capacity: Option<usize>,
    ask: impl FnOnce(&mut Scan),
) -> (ScanWalk, Scan) {
    let mut request = Scan {
        end,
        max_pages: u64::MAX,
        ..Scan::default()
    };
    ask(&mut request);
    let walk = view.pagemap_scan(start, &mut request, capacity).unwrap();
    (walk, request)
}

#[test]
fn pagemap_scan_reports_the_pages_of_each_category_as_regions() {
    let mut m = AddressSpace::new();
    let view = m.view();
    let at = m
        .map(
            None,
            5 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap()
        .0;
    let end = at + 5 * PAGE_SIZE;
    let page = |n: u64| at + n * PAGE_SIZE;
    m.write(GuestAddr(page(0)), b"a").unwrap();
    m.write(GuestAddr(page(1)), b"b").unwrap();
    let mut b = [0];
    m.read(GuestAddr(page(2)), &mut b).unwrap();
    m.guard(GuestAddr(page(4)), page(5), true).unwrap();
    let kinds = scan::PRESENT | scan::FILE | scan::PFNZERO | scan::SWAPPED | scan::GUARD;
    let any = |s: &mut Scan| {
        s.any_of = scan::PRESENT | scan::SWAPPED;
        s.returned = kinds;
    };
    let (walk, _) = scan_walk(&view, at, end, Some(8), any);
    assert_eq!(
        walk.regions,
        [
            [page(0), page(2), scan::PRESENT],
            [page(2), page(3), scan::PRESENT | scan::PFNZERO],
            [page(4), page(5), scan::SWAPPED | scan::GUARD],
        ]
    );
    assert_eq!(walk.stop, None);
    // Without a VMA registered for write protection nothing is written,
    // and categories it does not return join regions.
    let (walk, _) = scan_walk(&view, at, end, Some(8), |s| {
        s.returned = scan::WRITTEN | scan::PRESENT;
    });
    assert_eq!(
        walk.regions,
        [[page(0), page(3), scan::PRESENT], [page(3), page(5), 0]]
    );
    // One region of room: the walk stops where the next would start.
    let (walk, request) = scan_walk(&view, at, end, Some(1), any);
    assert_eq!(walk.regions, [[page(0), page(2), scan::PRESENT]]);
    assert_eq!(
        (walk.stop, request.walk_end),
        (Some(ScanStop::Full), page(2))
    );
    // A page limit cuts a region short, and stops at the next page that
    // matches.
    let (walk, request) = scan_walk(&view, at, end, Some(8), |s| {
        s.required = scan::PRESENT;
        s.returned = scan::PRESENT;
        s.max_pages = 1;
    });
    assert_eq!(walk.regions, [[page(0), page(1), scan::PRESENT]]);
    assert_eq!(
        (walk.stop, request.walk_end, request.found),
        (Some(ScanStop::Full), page(1), 1)
    );
    // Inverted: the pages that are not present.
    let (walk, _) = scan_walk(&view, at, end, Some(8), |s| {
        s.inverted = scan::PRESENT;
        s.required = scan::PRESENT;
        s.returned = kinds;
    });
    assert_eq!(
        walk.regions,
        [
            [page(3), page(4), 0],
            [page(4), page(5), scan::SWAPPED | scan::GUARD]
        ]
    );
    // Nothing may be write-protected: passed over, or refused.
    let (walk, _) = scan_walk(&view, at, end, Some(8), |s| s.write_protect = true);
    assert_eq!(walk, ScanWalk::default());
    let (walk, _) = scan_walk(&view, at, end, Some(8), |s| s.check_wp_async = true);
    assert_eq!(walk.stop, Some(ScanStop::Refused));
}

#[test]
fn pagemap_scan_write_protects_the_written_pages_for_wp_async() {
    let mut m = AddressSpace::new();
    let view = m.view();
    let at = m
        .map(
            None,
            4 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap()
        .0;
    let end = at + 4 * PAGE_SIZE;
    let page = |n: u64| at + n * PAGE_SIZE;
    let wp = |n: u64| view.pagemap(page(n), 1).unwrap()[0] & pagemap::UFFD_WP != 0;
    m.write(GuestAddr(page(0)), b"a").unwrap();
    // Without markers for the pages with no entry, it may not.
    view.userfault_register(at, end, 7, Userfault::WP | Userfault::WP_ASYNC)
        .unwrap();
    let (walk, _) = scan_walk(&view, at, end, Some(8), |s| s.check_wp_async = true);
    assert_eq!(walk.stop, Some(ScanStop::Refused));
    // Not write-protected, an empty page is written as well.
    let written = |s: &mut Scan| {
        s.required = scan::WRITTEN;
        s.returned = scan::WRITTEN;
    };
    let (walk, _) = scan_walk(&view, at, end, Some(8), written);
    assert_eq!(walk.regions, [[page(0), page(4), scan::WRITTEN]]);
    view.userfault_register(
        at,
        end,
        7,
        Userfault::WP | Userfault::WP_ASYNC | Userfault::WP_UNPOPULATED,
    )
    .unwrap();
    view.userfault_write_protect(at, end, true).unwrap();
    let (walk, _) = scan_walk(&view, at, end, Some(8), written);
    assert_eq!(walk, ScanWalk::default());
    m.write(GuestAddr(page(0)), b"b").unwrap();
    m.write(GuestAddr(page(2)), b"c").unwrap();
    let (walk, _) = scan_walk(&view, at, end, Some(8), |s| {
        s.returned = scan::WPALLOWED | scan::WRITTEN | scan::PRESENT | scan::SWAPPED;
    });
    let both = scan::WPALLOWED | scan::WRITTEN | scan::PRESENT;
    assert_eq!(
        walk.regions,
        [
            [page(0), page(1), both],
            [page(1), page(2), scan::WPALLOWED | scan::SWAPPED],
            [page(2), page(3), both],
            [page(3), page(4), scan::WPALLOWED | scan::SWAPPED],
        ]
    );
    // It protects what it reports, and only that.
    let (walk, _) = scan_walk(&view, at, end, Some(8), |s| {
        written(s);
        s.write_protect = true;
        s.check_wp_async = true;
    });
    assert_eq!(
        walk.regions,
        [
            [page(0), page(1), scan::WRITTEN],
            [page(2), page(3), scan::WRITTEN]
        ]
    );
    assert!(wp(0) && wp(2));
    m.write(GuestAddr(page(1)), b"d").unwrap();
    m.write(GuestAddr(page(3)), b"e").unwrap();
    let (walk, request) = scan_walk(&view, at, end, Some(1), |s| {
        written(s);
        s.write_protect = true;
    });
    assert_eq!(walk.regions, [[page(1), page(2), scan::WRITTEN]]);
    assert_eq!(request.walk_end, page(3));
    assert!(wp(1) && !wp(3));
    // Without a buffer, every page of a page table.
    m.write(GuestAddr(page(0)), b"f").unwrap();
    let (walk, _) = scan_walk(&view, at, end, None, |s| {
        s.required = scan::PRESENT | scan::FILE;
        s.write_protect = true;
    });
    assert_eq!(walk, ScanWalk::default());
    assert!((0..4).all(wp));
    // A write still clears the protection of what it protected.
    m.write(GuestAddr(page(3)), b"g").unwrap();
    assert!(!wp(3));
}

#[test]
fn a_discard_drops_the_entries_of_any_shared_mapping_and_keeps_its_pages() {
    // A shared mapping of a file that is not shmem's, as a disk file or
    // System V shared memory is.
    let source: Arc<dyn PageSource> = Arc::new(Shmem {
        size: 3 * PAGE_SIZE,
        held: vec![],
        shmem: false,
    });
    let m = AddressSpace::new();
    let view = m.view();
    let pages = SharedPages::new().with_source(Arc::clone(&source));
    let at = m
        .map_shared(None, 3 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
        .unwrap();
    m.share_pages(at, 3 * PAGE_SIZE, &pages, 0, SharedWrites::Allowed)
        .unwrap();
    let at = at.0;
    let end = at + 3 * PAGE_SIZE;
    let page = |n: u64| GuestAddr(at + n * PAGE_SIZE);
    let state = |n: u64| {
        view.pagemap(page(n).0, 1).unwrap()[0]
            & (pagemap::PRESENT | pagemap::SWAP | pagemap::UFFD_WP)
    };
    m.write(page(0), b"a").unwrap();
    m.write(page(1), b"b").unwrap();
    let mut b = [0];
    m.read(page(2), &mut b).unwrap();
    assert_eq!(state(0), pagemap::PRESENT);
    let resident = view.usage(at, end).unwrap();
    m.discard_shared(GuestAddr(at), 3 * PAGE_SIZE).unwrap();
    // The entries go, as Linux's zap clears them; the pages stay.
    assert!((0..3).all(|n| state(n) == 0));
    assert_ne!(view.usage(at, end).unwrap(), resident);
    m.read(page(0), &mut b).unwrap();
    assert_eq!(b, *b"a");
    assert_eq!(state(0), pagemap::PRESENT);
    m.read(page(1), &mut b).unwrap();
    assert_eq!(b, *b"b");
    // With write protection, a protected entry leaves a marker, which a
    // write with `WP_ASYNC` clears.
    view.userfault_register(at, end, 7, Userfault::WP | Userfault::WP_ASYNC)
        .unwrap();
    view.userfault_write_protect(at, end, true).unwrap();
    m.write(page(1), b"c").unwrap();
    m.discard_shared(GuestAddr(at), 3 * PAGE_SIZE).unwrap();
    assert_eq!(state(0), pagemap::SWAP | pagemap::UFFD_WP);
    assert_eq!(state(1), 0);
    m.write(page(0), b"d").unwrap();
    assert_eq!(state(0), pagemap::PRESENT);
    m.read(page(1), &mut b).unwrap();
    assert_eq!(b, *b"c");
}

/// A tmpfs file of `size` bytes with room for `room` pages, which takes in
/// each page an access asks it to until it is full.
struct Tmpfs {
    size: u64,
    room: usize,
    shmem: bool,
    held: Mutex<std::collections::BTreeSet<u64>>,
    asked: AtomicU64,
    fits: Mutex<Vec<crate::HugeFit>>,
}

impl Tmpfs {
    fn new(size: u64, room: usize, shmem: bool) -> Arc<Self> {
        Arc::new(Tmpfs {
            size,
            room,
            shmem,
            held: Mutex::default(),
            asked: AtomicU64::new(0),
            fits: Mutex::default(),
        })
    }
    fn held(&self) -> Vec<u64> {
        self.held.lock().unwrap().iter().copied().collect()
    }
}

impl PageSource for Tmpfs {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let n = buf
            .len()
            .min(usize::try_from(self.size.saturating_sub(offset)).unwrap_or(0));
        buf[..n].fill(0);
        Ok(n)
    }
    fn size(&self) -> Option<u64> {
        Some(self.size)
    }
    fn shmem(&self) -> bool {
        self.shmem
    }
    fn holds(&self, offset: u64) -> bool {
        self.held.lock().unwrap().contains(&(offset / PAGE_SIZE))
    }
    fn admit(&self, offset: u64, fit: crate::HugeFit) -> bool {
        self.asked.fetch_add(1, Ordering::Relaxed);
        self.fits.lock().unwrap().push(fit);
        let mut held = self.held.lock().unwrap();
        held.len() < self.room && held.insert(offset / PAGE_SIZE)
            || held.contains(&(offset / PAGE_SIZE))
    }
    fn allocate(&self, offset: u64, _len: u64) -> Result<(), Errno> {
        let mut held = self.held.lock().unwrap();
        if held.len() < self.room && held.insert(offset / PAGE_SIZE) {
            Ok(())
        } else {
            Err(Errno(28))
        }
    }
}

#[test]
fn a_fault_tells_the_file_how_its_mapping_would_hold_a_large_folio() {
    let m = AddressSpace::new();
    let mut byte = [0];
    let huge = 2 << 20;
    let file = Tmpfs::new(4 * huge, 8, true);
    let pages = SharedPages::new().with_source(file.clone());
    // 64 KiB at a 2 MiB boundary, at offset 0: a 16-page extent fits.
    let base = GuestAddr(0x4000_0000);
    let at = m
        .map_shared(Some(base), 64 << 10, Prot::READ_WRITE, MappingKind::File)
        .unwrap();
    m.share_pages(at, 64 << 10, &pages, 0, SharedWrites::Allowed)
        .unwrap();
    m.read(GuestAddr(at.0 + PAGE_SIZE), &mut byte).unwrap();
    // A page off the boundary, at offset 0: none does.
    let off = GuestAddr(base.0 + huge + PAGE_SIZE);
    m.map_shared(Some(off), huge, Prot::READ_WRITE, MappingKind::File)
        .unwrap();
    m.share_pages(off, huge, &pages, 0, SharedWrites::Allowed)
        .unwrap();
    m.read(off, &mut byte).unwrap();
    let fits = file.fits.lock().unwrap().clone();
    assert_eq!(fits.first().map(|fit| fit.order), Some(4));
    assert_eq!(fits.last().map(|fit| fit.order), Some(0));
}

#[test]
fn a_fill_of_a_shmem_page_its_file_has_no_room_for_is_enomem() {
    let m = AddressSpace::new();
    let file = Tmpfs::new(2 * PAGE_SIZE, 1, true);
    let pages = SharedPages::new().with_source(file.clone());
    let at = m
        .map_shared(None, 2 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
        .unwrap();
    m.share_pages(at, 2 * PAGE_SIZE, &pages, 0, SharedWrites::Allowed)
        .unwrap();
    let view = m.view();
    view.userfault_register(at.0, at.0 + 2 * PAGE_SIZE, 7, Userfault::MISSING)
        .unwrap();
    let end = at.0 + 2 * PAGE_SIZE;
    assert_eq!(
        view.userfault_fill(at.0, end, at.0, Some(b"a"), false),
        Ok(())
    );
    assert_eq!(
        view.userfault_fill(at.0, end, at.0 + PAGE_SIZE, Some(b"b"), false),
        Err(Errno::ENOMEM)
    );
    assert_eq!(file.held(), [0]);
}

#[test]
fn faults_bring_shmem_pages_into_their_file_or_are_bus_errors() {
    let m = AddressSpace::new();
    let mut byte = [0];
    // Shared: a read fault and a write fault each bring a page into the
    // file, and one the file has no room for is a bus error.
    let file = Tmpfs::new(4 * PAGE_SIZE, 2, true);
    let source: Arc<dyn PageSource> = file.clone();
    let pages = SharedPages::new().with_source(source);
    let at = m
        .map_shared(None, 4 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
        .unwrap();
    m.share_pages(at, 4 * PAGE_SIZE, &pages, 0, SharedWrites::Allowed)
        .unwrap();
    m.read(at, &mut byte).unwrap();
    m.write(GuestAddr(at.0 + PAGE_SIZE), &[1]).unwrap();
    assert_eq!(file.held(), [0, 1]);
    let fault = m
        .read(GuestAddr(at.0 + 2 * PAGE_SIZE), &mut byte)
        .unwrap_err();
    assert!(fault.bus);
    let fault = m.write(GuestAddr(at.0 + 3 * PAGE_SIZE), &[1]).unwrap_err();
    assert!(fault.bus);
    // Private: a read and a copy-on-write fault bring the file's page in
    // too; a page with a copy of its own asks nothing more.
    let file = Tmpfs::new(4 * PAGE_SIZE, 2, true);
    let cache = SharedPages::new().with_source(file.clone());
    let at = m
        .map_shared(None, 4 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
        .unwrap();
    m.back_with_cache(at, 4 * PAGE_SIZE, &cache, 0).unwrap();
    m.read(at, &mut byte).unwrap();
    m.write(GuestAddr(at.0 + PAGE_SIZE), &[1]).unwrap();
    assert_eq!(file.held(), [0, 1]);
    file.held.lock().unwrap().remove(&1);
    let asked = file.asked.load(Ordering::Relaxed);
    m.write(GuestAddr(at.0 + PAGE_SIZE + 1), &[2]).unwrap();
    m.read(GuestAddr(at.0 + PAGE_SIZE), &mut byte).unwrap();
    assert_eq!(byte, [1]);
    assert_eq!(file.asked.load(Ordering::Relaxed), asked);
    assert_eq!(file.held(), [0]);
    // A hole of a mapping a userfaultfd registered for minor faults comes
    // in at once, as Linux allocates it, without waiting for the page it
    // took in.
    let file = Tmpfs::new(2 * PAGE_SIZE, 2, true);
    let source: Arc<dyn PageSource> = file.clone();
    let pages = SharedPages::new().with_source(source);
    let at = m
        .map_shared(None, 2 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
        .unwrap();
    m.share_pages(at, 2 * PAGE_SIZE, &pages, 0, SharedWrites::Allowed)
        .unwrap();
    m.view()
        .userfault_register(at.0, at.0 + 2 * PAGE_SIZE, 7, Userfault::MINOR)
        .unwrap();
    m.read(GuestAddr(at.0 + PAGE_SIZE), &mut byte).unwrap();
    assert_eq!(file.held(), [1]);
    // A private mapping of a file that is not shmem's asks nothing.
    let file = Tmpfs::new(4 * PAGE_SIZE, 0, false);
    let cache = SharedPages::new().with_source(file.clone());
    let at = m
        .map_shared(None, 4 * PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
        .unwrap();
    m.back_with_cache(at, 4 * PAGE_SIZE, &cache, 0).unwrap();
    m.read(at, &mut byte).unwrap();
    m.write(GuestAddr(at.0 + PAGE_SIZE), &[1]).unwrap();
    assert_eq!(file.asked.load(Ordering::Relaxed), 0);
}

#[test]
fn collapse_takes_shmem_page_caches_an_aligned_extent_at_a_time() {
    const AT: u64 = 0x4000_0000;
    const HUGE: u64 = 2 << 20;
    let m = AddressSpace::new();
    let view = m.view();
    let shared = |at: u64, pages: &SharedPages, offset: u64| {
        let kind = if pages.source().is_some() {
            MappingKind::File
        } else {
            MappingKind::Anonymous
        };
        let _ = m.unmap_shared(GuestAddr(at), 2 * HUGE);
        m.map_shared(Some(GuestAddr(at)), 2 * HUGE, Prot::READ_WRITE, kind)
            .unwrap();
        m.share_pages(
            GuestAddr(at),
            2 * HUGE,
            pages,
            offset,
            SharedWrites::Allowed,
        )
        .unwrap();
    };
    let einval = Err(Errno::EINVAL);
    // Shared memory of no file: an extent of it nothing touched was
    // truncated, which ends the collapse; one touched becomes whole.
    let memory = SharedPages::new();
    shared(AT, &memory, 0);
    assert_eq!(m.collapse(GuestAddr(AT), AT + 2 * HUGE), einval);
    m.write(GuestAddr(AT + 3 * PAGE_SIZE), &[7]).unwrap();
    assert_eq!(m.collapse(GuestAddr(AT), AT + 2 * HUGE), einval);
    assert!((0..HUGE / PAGE_SIZE).all(|i| memory.has(i * PAGE_SIZE)));
    assert!(!memory.has(HUGE));
    assert_eq!(m.collapse(GuestAddr(AT), AT + HUGE), Ok(()));
    let mut byte = [0];
    m.read(GuestAddr(AT + 3 * PAGE_SIZE), &mut byte).unwrap();
    assert_eq!(byte, [7]);
    // A shmem file holding a page, mapped out of step with its offsets
    // and then in step; a file that is not shmem's is refused.
    let file = |shmem| -> SharedPages {
        SharedPages::new().with_source(Arc::new(Shmem {
            size: 2 * HUGE,
            held: vec![5],
            shmem,
        }))
    };
    let memfd = file(true);
    shared(AT, &memfd, PAGE_SIZE);
    assert_eq!(m.collapse(GuestAddr(AT), AT + HUGE), einval);
    shared(AT, &memfd, 0);
    assert_eq!(m.collapse(GuestAddr(AT), AT + HUGE), Ok(()));
    assert!((0..HUGE / PAGE_SIZE).all(|i| memfd.has(i * PAGE_SIZE)));
    assert_eq!(m.collapse(GuestAddr(AT + HUGE), AT + 2 * HUGE), einval);
    shared(AT, &file(false), 0);
    m.write(GuestAddr(AT), &[1]).unwrap();
    assert_eq!(m.collapse(GuestAddr(AT), AT + HUGE), einval);
    // A private mapping of the shmem file: an extent it only reads maps,
    // one with a page of its own does not.
    let cache = file(true);
    m.unmap_shared(GuestAddr(AT), 2 * HUGE).unwrap();
    m.map_shared(
        Some(GuestAddr(AT)),
        2 * HUGE,
        Prot::READ_WRITE,
        MappingKind::File,
    )
    .unwrap();
    m.back_with_cache(GuestAddr(AT), 2 * HUGE, &cache, 0)
        .unwrap();
    m.read(GuestAddr(AT), &mut byte).unwrap();
    assert_eq!(byte, [b'f']);
    assert_eq!(m.collapse(GuestAddr(AT), AT + HUGE), Ok(()));
    m.write(GuestAddr(AT + HUGE + PAGE_SIZE), &[1]).unwrap();
    assert_eq!(m.collapse(GuestAddr(AT + HUGE), AT + 2 * HUGE), einval);
    // Holes, in a VMA a userfaultfd registered for missing pages.
    let armed = SharedPages::new();
    shared(AT, &armed, 0);
    m.write(GuestAddr(AT), &[1]).unwrap();
    view.userfault_register(AT, AT + HUGE, 7, Userfault::MISSING)
        .unwrap();
    assert_eq!(m.collapse(GuestAddr(AT), AT + HUGE), Err(Errno(16)));
    assert!(!armed.has(PAGE_SIZE));
}

#[test]
fn an_aligned_placement_puts_a_mapping_at_its_offset_past_a_boundary() {
    const HUGE: u64 = 2 << 20;
    let place = |m: &AddressSpace, hint: Option<GuestAddr>, len: u64, offset: u64| {
        m.map_backed(
            Placement::Aligned {
                hint,
                size: HUGE,
                offset,
            },
            len,
            Prot::READ,
            MappingKind::Anonymous,
            Backing::None,
        )
        .unwrap()
        .0
    };
    for bottom_up in [false, true] {
        let mut m = AddressSpace::new();
        if bottom_up {
            m.set_bottom_up(Some(GuestAddr(0x1000_1000)));
        }
        // A page off a boundary first, so that the ordinary choice is not
        // aligned.
        m.map_shared(None, PAGE_SIZE, Prot::READ, MappingKind::Anonymous)
            .unwrap();
        assert_eq!(place(&m, None, 2 * HUGE, 0) % HUGE, 0, "{bottom_up}");
        assert_eq!(
            place(&m, None, 2 * HUGE, PAGE_SIZE) % HUGE,
            PAGE_SIZE,
            "{bottom_up}"
        );
        // Shorter than the size, or ending within the second at an
        // offset: where `Near` would put it.
        let near = |m: &mut AddressSpace, len: u64| {
            let at = m
                .map_backed(
                    Placement::Near(None),
                    len,
                    Prot::READ,
                    MappingKind::Anonymous,
                    Backing::None,
                )
                .unwrap();
            m.unmap(at, len).unwrap();
            at.0
        };
        let expected = near(&mut m, HUGE / 2);
        assert_eq!(place(&m, None, HUGE / 2, 0), expected, "{bottom_up}");
        let expected = near(&mut m, HUGE);
        assert_eq!(place(&m, None, HUGE, PAGE_SIZE), expected, "{bottom_up}");
        // A free hint is taken as it is.
        let hint = GuestAddr(0x2000_3000);
        assert_eq!(place(&m, Some(hint), 2 * HUGE, 0), hint.0, "{bottom_up}");
    }
}

#[test]
fn a_name_splits_its_vmas_and_keeps_their_lock_and_userfaultfd() {
    // Private anonymous memory: six pages, two of them locked and one
    // registered with a userfaultfd.
    let mut mem = AddressSpace::new();
    let base = mem
        .map(
            None,
            6 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    let page = |n: u64| base.0 + n * PAGE_SIZE;
    mem.lock(GuestAddr(page(2)), page(4), Some(Lock::Populated))
        .unwrap();
    mem.view()
        .userfault_register(page(4), page(5), 7, 1)
        .unwrap();
    mem.set_anon_name(GuestAddr(page(1)), page(5), Some(b"heap-of-x"))
        .unwrap();
    let at = |mem: &AddressSpace, n: u64| {
        mem.mappings()
            .find(|m| m.start.0 <= page(n) && page(n) < m.end())
            .unwrap()
    };
    let named = |mem: &AddressSpace, n: u64| {
        mem.view()
            .vma_from(page(n))
            .unwrap()
            .anon_name
            .map(|name| name.to_vec())
    };
    let x = Some(b"heap-of-x".to_vec());
    // Named from page 1 to 5, each piece with the state it had.
    assert_eq!(named(&mem, 0), None);
    assert_eq!((named(&mem, 1), at(&mem, 1).locked), (x.clone(), None));
    assert_eq!(
        (named(&mem, 2), at(&mem, 2).locked),
        (x.clone(), Some(Lock::Populated))
    );
    assert_eq!(at(&mem, 3).locked, Some(Lock::Populated));
    assert_eq!(named(&mem, 4), x);
    assert!(at(&mem, 4).userfault.is_some());
    assert_eq!(named(&mem, 5), None);
    // Pieces of one name hold one id.
    assert_eq!(at(&mem, 1).anon_name, at(&mem, 2).anon_name);
    // A fork keeps it; clearing it gives the VMAs back their merge.
    let child = mem.fork().unwrap();
    assert_eq!(named(&child, 1), x);
    mem.set_anon_name(GuestAddr(page(1)), page(2), None)
        .unwrap();
    assert_eq!(named(&mem, 1), None);
    assert_eq!(mem.view().vma_from(page(0)).unwrap().end, page(2));
    // A hole is ENOMEM once what is mapped is named.
    assert_eq!(
        mem.set_anon_name(GuestAddr(page(5)), page(7), Some(b"heap-of-x")),
        Err(Errno::ENOMEM)
    );
    assert_eq!(named(&mem, 5), x);
    assert_eq!(named(&child, 1), x);
}

#[test]
fn names_no_mapping_holds_are_let_go_as_the_table_grows() {
    let mut mem = AddressSpace::new();
    let at = mem
        .map(None, PAGE_SIZE, Prot::READ_WRITE, MappingKind::Anonymous)
        .unwrap();
    // A name a counter changes: each replaces the last, and the table
    // takes back the slots of those no mapping holds.
    for n in 0..1000 {
        mem.set_anon_name(at, at.0 + PAGE_SIZE, Some(format!("n{n}").as_bytes()))
            .unwrap();
    }
    assert_eq!(
        mem.view().vma_from(at.0).unwrap().anon_name.as_deref(),
        Some(&b"n999"[..])
    );
    let id = mem
        .mappings()
        .find(|m| m.start == at)
        .unwrap()
        .anon_name
        .unwrap();
    assert!(id.0 < 128, "{id:?}");
}

#[test]
fn only_anonymous_memory_takes_a_name() {
    let mut mem = AddressSpace::new();
    let file = mem
        .map(None, PAGE_SIZE, Prot::READ, MappingKind::File)
        .unwrap();
    assert_eq!(
        mem.set_anon_name(file, file.0 + PAGE_SIZE, Some(b"f")),
        Err(Errno::EBADF)
    );
    // The refused call left no name: the next one takes the first slot.
    let anon = mem
        .map(None, PAGE_SIZE, Prot::READ_WRITE, MappingKind::Anonymous)
        .unwrap();
    mem.set_anon_name(anon, anon.0 + PAGE_SIZE, Some(b"a"))
        .unwrap();
    let id = mem.mappings().find(|m| m.start == anon).unwrap().anon_name;
    assert_eq!(id, Some(AnonName(0)));
    let shared = mem
        .map_shared(None, PAGE_SIZE, Prot::READ_WRITE, MappingKind::Anonymous)
        .unwrap();
    mem.set_anon_name(shared, shared.0 + PAGE_SIZE, Some(b"s"))
        .unwrap();
    assert_eq!(
        mem.view().vma_from(shared.0).unwrap().anon_name.as_deref(),
        Some(&b"s"[..])
    );
}

/// A file of a tmpfs mount with `huge=`, whose mappings `mremap` moves to a
/// 2 MiB boundary.
struct HugeFile(u64);

impl PageSource for HugeFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let n = buf
            .len()
            .min(usize::try_from(self.0.saturating_sub(offset)).unwrap_or(0));
        buf[..n].fill(0);
        Ok(n)
    }
    fn size(&self) -> Option<u64> {
        Some(self.0)
    }
    fn huge_placement(&self) -> bool {
        true
    }
}

#[test]
fn a_moved_mapping_of_a_huge_file_goes_at_its_offset_past_a_boundary() {
    const HUGE: u64 = 2 << 20;
    let m = AddressSpace::new();
    let file: Arc<dyn PageSource> = Arc::new(HugeFile(8 * HUGE));
    let pages = SharedPages::new().with_source(file.clone());
    let cache = SharedPages::new().with_source(file);
    let moved = |at: GuestAddr, len: u64| {
        m.remap_shared(
            at,
            len,
            len,
            Remap {
                may_move: true,
                fixed: false,
                keep_old: true,
                new_addr: GuestAddr(0),
            },
        )
        .unwrap()
        .0
    };
    // Shared, at offset 0 and at one page in.
    let at = m
        .map_shared(None, 2 * HUGE, Prot::READ, MappingKind::File)
        .unwrap();
    m.share_pages(at, 2 * HUGE, &pages, 0, SharedWrites::Allowed)
        .unwrap();
    assert_eq!(moved(at, 2 * HUGE) % HUGE, 0);
    let at = m
        .map_shared(None, 2 * HUGE, Prot::READ, MappingKind::File)
        .unwrap();
    m.share_pages(at, 2 * HUGE, &pages, PAGE_SIZE, SharedWrites::Allowed)
        .unwrap();
    assert_eq!(moved(at, 2 * HUGE) % HUGE, PAGE_SIZE);
    // Private, which the file's page cache backs.
    let at = m
        .map_shared(None, 2 * HUGE, Prot::READ, MappingKind::File)
        .unwrap();
    m.back_with_cache(at, 2 * HUGE, &cache, 0).unwrap();
    assert_eq!(moved(at, 2 * HUGE) % HUGE, 0);
    // A grow that has to move, the old mapping gone.
    let at = m
        .map_shared(None, 2 * HUGE, Prot::READ, MappingKind::File)
        .unwrap();
    m.share_pages(at, 2 * HUGE, &pages, PAGE_SIZE, SharedWrites::Allowed)
        .unwrap();
    m.map_shared(
        Some(GuestAddr(at.0 + 2 * HUGE)),
        PAGE_SIZE,
        Prot::NONE,
        MappingKind::Anonymous,
    )
    .ok();
    let grown = m
        .remap_shared(
            at,
            2 * HUGE,
            3 * HUGE,
            Remap {
                may_move: true,
                fixed: false,
                keep_old: false,
                new_addr: GuestAddr(0),
            },
        )
        .unwrap();
    assert_ne!(grown, at);
    assert_eq!(grown.0 % HUGE, PAGE_SIZE);
}

#[test]
fn a_thp_placement_pads_by_2_mib_and_keeps_top_down_mappings_together() {
    const HUGE: u64 = 2 << 20;
    let place = |m: &AddressSpace, hint: Option<GuestAddr>, len: u64, offset: u64| {
        m.map_backed(
            Placement::Thp { hint, offset },
            len,
            Prot::READ,
            MappingKind::Anonymous,
            Backing::None,
        )
        .unwrap()
        .0
    };
    for bottom_up in [false, true] {
        let mut m = AddressSpace::new();
        if bottom_up {
            m.set_bottom_up(Some(GuestAddr(0x1000_1000)));
        }
        m.map_shared(None, PAGE_SIZE, Prot::READ, MappingKind::Anonymous)
            .unwrap();
        let a = place(&m, None, 2 * HUGE, 0);
        assert_eq!(a % HUGE, 0, "{bottom_up}");
        let b = place(&m, None, 2 * HUGE, 0);
        assert_eq!(b % HUGE, 0, "{bottom_up}");
        if !bottom_up {
            // The boundary above the padded area's aligned start: right
            // below the one before.
            assert_eq!(b + 2 * HUGE, a);
        }
        // An offset into the extent: that far past a boundary.
        assert_eq!(
            place(&m, None, 3 * HUGE, PAGE_SIZE) % HUGE,
            PAGE_SIZE,
            "{bottom_up}"
        );
        // Less than a whole extent past the first boundary: as `Near`.
        let short = place(&m, None, HUGE + PAGE_SIZE, PAGE_SIZE);
        assert_ne!(short, 0);
        // A hint with room for the padded area is taken.
        let hint = GuestAddr(0x2000_3000);
        assert_eq!(place(&m, Some(hint), 2 * HUGE, 0), hint.0, "{bottom_up}");
        // Not one whose padded area reaches into the guard gap below a
        // mapping that grows down, though the mapping itself would not.
        let top = 0x4000_0000;
        let stack = m
            .map_backed(
                Placement::Exactly(GuestAddr(top)),
                PAGE_SIZE,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
                Backing::None,
            )
            .unwrap();
        m.grow_new_down(stack, top + PAGE_SIZE);
        let hint = GuestAddr(top - 3 * HUGE);
        assert_ne!(place(&m, Some(hint), 2 * HUGE, 0), hint.0, "{bottom_up}");
        // With the padded area ending where the gap starts, it is taken.
        let hint = GuestAddr(top - 3 * HUGE - STACK_GUARD_GAP);
        assert_eq!(place(&m, Some(hint), 2 * HUGE, 0), hint.0, "{bottom_up}");
    }
}
