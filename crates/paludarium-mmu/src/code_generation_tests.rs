//! [`AddressSpace::code_generation_cached`]: it gives what
//! [`AddressSpace::code_generation`] gives under the locks, through every
//! change of the code, the mappings, the shared mappings and the page
//! caches, and takes no lock while none of them has been borrowed mutably.
//! Stores to shared memory count only where a space may run code from it.
use super::*;
use std::sync::mpsc;
use std::time::Duration;

const CODE: u64 = 0x10000;
const DATA: u64 = 0x20000;

fn space() -> AddressSpace {
    let space = AddressSpace::new();
    space
        .map_shared(
            Some(GuestAddr(CODE)),
            PAGE_SIZE,
            Prot::READ_WRITE.union(Prot::EXEC),
            MappingKind::Anonymous,
        )
        .unwrap();
    space
        .map_shared(
            Some(GuestAddr(DATA)),
            PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    space
}
/// The generation without the locks, checked against the one under them.
fn cached(space: &AddressSpace) -> u64 {
    let generation = space.code_generation_cached();
    assert_eq!(generation, space.code_generation());
    generation
}

#[test]
fn it_follows_code_writes_and_mapping_changes() {
    let mut space = space();
    let g0 = cached(&space);
    space.write(GuestAddr(DATA), &[1]).unwrap();
    space.write(GuestAddr(DATA), &[2]).unwrap();
    assert_eq!(cached(&space), g0, "data writes keep code");
    space.fetch(GuestAddr(CODE), &mut [0]).unwrap();
    space.write(GuestAddr(CODE), &[0x90]).unwrap();
    let g1 = cached(&space);
    assert_ne!(g1, g0);
    // A write through the TLB, to a page written before, too.
    space.write(GuestAddr(CODE + 1), &[0x90]).unwrap();
    let g2 = cached(&space);
    assert_ne!(g2, g1);
    space
        .protect(GuestAddr(DATA), PAGE_SIZE, Prot::READ_EXEC)
        .unwrap();
    assert_ne!(cached(&space), g2);
}

struct Zeros;
impl PageSource for Zeros {
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        buf.fill(0);
        Ok(buf.len())
    }
}
/// A space with an executable file mapping, and the page cache it shows.
fn with_cache() -> (AddressSpace, GuestAddr, SharedPages) {
    let space = AddressSpace::new();
    let at = space
        .map_shared(
            None,
            PAGE_SIZE,
            Prot::READ_WRITE.union(Prot::EXEC),
            MappingKind::File,
        )
        .unwrap();
    (space, at, SharedPages::new().with_source(Arc::new(Zeros)))
}

#[test]
fn it_counts_a_page_cache_added_without_a_mapping_change() {
    let (space, at, pages) = with_cache();
    cached(&space);
    // Backing the mapping with a page cache bumps no generation; the store
    // to the cache, which another process may make, must still count.
    space.back_with_cache(at, PAGE_SIZE, &pages, 0).unwrap();
    let before = cached(&space);
    pages.store(0, &[0xc3]);
    assert_ne!(cached(&space), before);
}

#[test]
fn it_tells_spaces_apart_whatever_their_layout() {
    // Two spaces changed the same way, so at the same layout, each with a
    // page cache of its own.
    let (first, first_at, first_pages) = with_cache();
    let (second, second_at, second_pages) = with_cache();
    first
        .back_with_cache(first_at, PAGE_SIZE, &first_pages, 0)
        .unwrap();
    second
        .back_with_cache(second_at, PAGE_SIZE, &second_pages, 0)
        .unwrap();
    first_pages.store(0, &[0xc3]);
    let one = cached(&first);
    let other = cached(&second);
    assert_ne!(one, other);
}

#[test]
fn it_counts_another_space_s_writes_to_shared_memory() {
    let parent = space();
    parent.mark_shared(GuestAddr(CODE), PAGE_SIZE).unwrap();
    let child = parent.fork();
    let before = cached(&parent);
    child.write(GuestAddr(CODE), &[0xc3]).unwrap();
    assert_ne!(cached(&parent), before);
}

#[test]
fn it_reads_another_space_afresh() {
    let first = space();
    first.write(GuestAddr(CODE), &[0x90]).unwrap();
    cached(&first);
    let second = first.fork();
    second.write(GuestAddr(CODE), &[0xc3]).unwrap();
    cached(&second);
    cached(&AddressSpace::new());
    cached(&first);
}

#[test]
fn it_takes_no_lock_while_the_space_is_not_borrowed_mutably() {
    let space = Arc::new(space());
    let before = cached(&space);
    let held = space.data.lock().unwrap();
    let (sent, received) = mpsc::channel();
    let reader = Arc::clone(&space);
    std::thread::spawn(move || {
        let generation = reader.code_generation_cached();
        sent.send(generation).unwrap();
    });
    assert_eq!(
        received.recv_timeout(Duration::from_secs(10)),
        Ok(before),
        "the generation was read without the lock"
    );
    drop(held);
}

#[test]
fn it_ignores_another_space_s_writes_to_shared_data() {
    let parent = space();
    parent.mark_shared(GuestAddr(DATA), PAGE_SIZE).unwrap();
    let child = parent.fork();
    let before = cached(&parent);
    // Neither space may run code from the page, so nothing decoded is stale.
    child.write(GuestAddr(DATA), &[0xc3]).unwrap();
    assert_eq!(cached(&parent), before);
}

#[test]
fn it_counts_shared_memory_made_executable_later() {
    let mut parent = space();
    parent.mark_shared(GuestAddr(DATA), PAGE_SIZE).unwrap();
    let child = parent.fork();
    cached(&parent);
    parent
        .protect(GuestAddr(DATA), PAGE_SIZE, Prot::READ_EXEC)
        .unwrap();
    let before = cached(&parent);
    child.write(GuestAddr(DATA), &[0xc3]).unwrap();
    assert_ne!(cached(&parent), before);
}

#[test]
fn it_counts_a_page_cache_store_without_the_locks() {
    let (space, at, pages) = with_cache();
    space.back_with_cache(at, PAGE_SIZE, &pages, 0).unwrap();
    let before = cached(&space);
    pages.store(0, &[0xc3]);
    // The store reached the space's own generation: the read without the
    // locks sees it.
    assert_ne!(space.code_generation_cached(), before);
}

#[test]
fn a_page_cache_outlives_the_spaces_that_watched_it() {
    let (first, first_at, pages) = with_cache();
    first
        .back_with_cache(first_at, PAGE_SIZE, &pages, 0)
        .unwrap();
    cached(&first);
    drop(first);
    pages.store(0, &[0xc3]);
    assert!(
        !pages.watchers.any.load(Ordering::SeqCst),
        "stores take no lock once no space watches"
    );
    let (second, second_at, _) = with_cache();
    second
        .back_with_cache(second_at, PAGE_SIZE, &pages, 0)
        .unwrap();
    let before = cached(&second);
    pages.store(0, &[0x90]);
    assert_ne!(cached(&second), before);
}

/// Fetches the instruction byte at `addr`, as decoding it does.
fn fetch(space: &AddressSpace, addr: u64) {
    space.fetch(GuestAddr(addr), &mut [0]).unwrap();
}

#[test]
fn a_store_to_code_nothing_fetched_keeps_decoded_instructions() {
    let space = space();
    let before = cached(&space);
    // The first under the locks, the next through the TLB, as data on an
    // executable heap (SBCL's dynamic space) is stored.
    space.write(GuestAddr(CODE), &[1]).unwrap();
    space.write(GuestAddr(CODE + 1), &[2]).unwrap();
    space.write_value(GuestAddr(CODE + 8), 8, 3).unwrap();
    space
        .atomic(GuestAddr(CODE + 16), AtomicWidth::W32, AtomicOp::Add(1))
        .unwrap();
    space.write_initial(GuestAddr(CODE + 24), &[4]).unwrap();
    assert_eq!(cached(&space), before);
}

#[test]
fn every_store_to_code_once_fetched_makes_it_stale() {
    let space = space();
    space.write(GuestAddr(CODE), &[0x90]).unwrap();
    fetch(&space, CODE);
    let stores: [&dyn Fn(&AddressSpace); 4] = [
        &|space| space.write(GuestAddr(CODE + 1), &[0xc3]).unwrap(),
        &|space| space.write_value(GuestAddr(CODE + 8), 8, 3).unwrap(),
        &|space| {
            space
                .atomic(GuestAddr(CODE + 16), AtomicWidth::W32, AtomicOp::Add(1))
                .unwrap();
        },
        &|space| space.write_initial(GuestAddr(CODE + 24), &[4]).unwrap(),
    ];
    for store in stores {
        // Twice: under the locks and through the TLB where it can.
        for _ in 0..2 {
            let before = cached(&space);
            store(&space);
            assert_ne!(cached(&space), before);
        }
    }
}

#[test]
fn a_page_fetched_before_its_first_write_keeps_its_mark() {
    // The page reads as zeros, without a frame, when it is fetched.
    let space = space();
    fetch(&space, CODE);
    let before = cached(&space);
    space.write(GuestAddr(CODE), &[0xc3]).unwrap();
    assert_ne!(cached(&space), before);
}

#[test]
fn a_copy_of_fetched_code_keeps_its_mark() {
    // A page `fork` shares, with contents and without.
    for written in [true, false] {
        let parent = space();
        if written {
            parent.write(GuestAddr(CODE), &[0x90]).unwrap();
        }
        fetch(&parent, CODE);
        let child = parent.fork();
        // A VMA never written has no `anon_vma`: the child gets none of its
        // page tables, as Linux's `vma_needs_copy`, and fetches the page
        // again before running it.
        if !written {
            assert_eq!(child.page_state(GuestAddr(CODE)), Some(PageState::Absent));
            fetch(&child, CODE);
        }
        for space in [&parent, &child] {
            let before = cached(space);
            space.write(GuestAddr(CODE), &[0xc3]).unwrap();
            assert_ne!(cached(space), before, "written first: {written}");
        }
    }
}

#[test]
fn a_fetch_reaches_a_page_another_thread_holds() {
    let space = Arc::new(space());
    let (sent, received) = mpsc::channel::<()>();
    let (stored, done) = mpsc::channel();
    let writer = Arc::clone(&space);
    let thread = std::thread::spawn(move || {
        // Twice, so that this thread's TLB holds the page.
        writer.write(GuestAddr(CODE), &[1]).unwrap();
        writer.write(GuestAddr(CODE), &[2]).unwrap();
        stored.send(()).unwrap();
        received.recv().unwrap();
        let before = writer.code_generation_cached();
        writer.write(GuestAddr(CODE + 1), &[0xc3]).unwrap();
        writer.code_generation_cached() != before
    });
    done.recv().unwrap();
    fetch(&space, CODE);
    sent.send(()).unwrap();
    assert!(thread.join().unwrap(), "the store saw the fetch's mark");
}

#[test]
fn a_fetch_sees_a_store_under_way_that_missed_its_mark() {
    let space = Arc::new(space());
    let (started, starting) = mpsc::channel();
    let writer = Arc::clone(&space);
    let thread = std::thread::spawn(move || {
        // Twice, so that this thread's TLB holds the page.
        writer.write(GuestAddr(CODE), &[0; 24]).unwrap();
        writer.write(GuestAddr(CODE), &[0; 24]).unwrap();
        // The store reads the page's mark, unset, and then writes its words
        // with a pause between each.
        WORD_STALL.set(Some(Duration::from_millis(200)));
        started.send(()).unwrap();
        writer.write(GuestAddr(CODE + 4), &[0xc3; 16]).unwrap();
    });
    starting.recv().unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let before = space.code_generation_cached();
    let mut code = [0; 16];
    space.fetch(GuestAddr(CODE + 4), &mut code).unwrap();
    thread.join().unwrap();
    // The store bumped the generation after its bytes, or the fetch waited
    // for them: no instruction stays decoded from half of them.
    assert!(
        code == [0xc3; 16] || space.code_generation_cached() != before,
        "{code:x?}"
    );
}

#[test]
fn a_first_fetch_keeps_the_pages_its_thread_holds() {
    let space = space();
    // Twice each, so that this thread's TLB holds both pages.
    for _ in 0..2 {
        space.write(GuestAddr(DATA), &[1]).unwrap();
        space.write(GuestAddr(CODE), &[0x90]).unwrap();
    }
    fetch(&space, CODE);
    let held = THREAD_TLB.with(|cell| {
        let thread = cell.borrow();
        thread.epoch == space.code.epoch.load(Ordering::SeqCst)
            && thread.tlb.get(DATA).is_some()
            && thread.tlb.get(CODE).is_some()
    });
    assert!(held, "marking a page changes no entry");
    // A store through the entry it kept sees the mark.
    let before = cached(&space);
    space.write(GuestAddr(CODE + 1), &[0xc3]).unwrap();
    assert_ne!(cached(&space), before);
}
