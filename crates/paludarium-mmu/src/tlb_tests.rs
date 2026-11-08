//! The [`Tlb`]: each test uses a page first, so that the TLB holds it, then
//! changes the mapping or the page entry some other way, and checks that the
//! next access sees the change, not the page the TLB remembered.
use super::*;

const AT: u64 = 0x10000;

fn space(pages: u64, prot: Prot) -> AddressSpace {
    let space = AddressSpace::new();
    space
        .map_shared(
            Some(GuestAddr(AT)),
            pages * PAGE_SIZE,
            prot,
            MappingKind::Anonymous,
        )
        .unwrap();
    space
}
fn byte(space: &AddressSpace, addr: u64) -> u8 {
    let mut b = [0];
    space.read(GuestAddr(addr), &mut b).unwrap();
    b[0]
}
/// Reads the byte at `addr` twice, so that the TLB holds its page.
fn used(space: &AddressSpace, addr: u64) -> u8 {
    byte(space, addr);
    byte(space, addr)
}

#[test]
fn reads_see_the_writes_made_through_it() {
    let space = space(1, Prot::READ_WRITE);
    space.write(GuestAddr(AT), &[1]).unwrap();
    assert_eq!(used(&space, AT), 1);
    for value in 2..10 {
        space.write(GuestAddr(AT + 7), &[value]).unwrap();
        assert_eq!(byte(&space, AT + 7), value);
    }
    space.write_u64(GuestAddr(AT + 8), 0x1122_3344).unwrap();
    assert_eq!(space.read_u64(GuestAddr(AT + 8)).unwrap(), 0x1122_3344);
}

#[test]
fn it_checks_the_protection_of_the_page_it_holds() {
    let space = space(1, Prot::READ);
    space.write_initial(GuestAddr(AT), &[5]).unwrap();
    assert_eq!(used(&space, AT), 5);
    let fault = space.write(GuestAddr(AT), &[6]).unwrap_err();
    assert!(fault.write && fault.present);
    assert!(space.fetch(GuestAddr(AT), &mut [0]).unwrap_err().fetch);
    assert_eq!(byte(&space, AT), 5);
}

#[test]
fn mprotect_takes_effect_on_a_page_it_holds() {
    let mut space = space(1, Prot::READ_WRITE);
    space.write(GuestAddr(AT), &[1]).unwrap();
    assert_eq!(used(&space, AT), 1);
    space
        .protect_shared(GuestAddr(AT), PAGE_SIZE, Prot::READ)
        .unwrap();
    assert!(space.write(GuestAddr(AT), &[2]).is_err());
    assert_eq!(byte(&space, AT), 1);
    space.protect(GuestAddr(AT), PAGE_SIZE, Prot::NONE).unwrap();
    assert!(space.read(GuestAddr(AT), &mut [0]).is_err());
}

#[test]
fn munmap_takes_effect_and_a_new_mapping_reads_zeros() {
    let mut space = space(2, Prot::READ_WRITE);
    space.write(GuestAddr(AT), &[1]).unwrap();
    space.write(GuestAddr(AT + PAGE_SIZE), &[2]).unwrap();
    assert_eq!(used(&space, AT), 1);
    assert_eq!(used(&space, AT + PAGE_SIZE), 2);
    space.unmap_shared(GuestAddr(AT), PAGE_SIZE).unwrap();
    assert!(!space.read(GuestAddr(AT), &mut [0]).unwrap_err().mapped);
    space.unmap(GuestAddr(AT + PAGE_SIZE), PAGE_SIZE).unwrap();
    assert!(space.write(GuestAddr(AT + PAGE_SIZE), &[3]).is_err());
    space
        .map_shared(
            Some(GuestAddr(AT)),
            2 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    assert_eq!(byte(&space, AT), 0);
    assert_eq!(byte(&space, AT + PAGE_SIZE), 0);
}

#[test]
fn madvise_dontneed_reads_zeros_again() {
    let space = space(1, Prot::READ_WRITE);
    space.write(GuestAddr(AT), &[1]).unwrap();
    assert_eq!(used(&space, AT), 1);
    space.discard_shared(GuestAddr(AT), PAGE_SIZE).unwrap();
    assert_eq!(byte(&space, AT), 0);
    space.write(GuestAddr(AT), &[4]).unwrap();
    assert_eq!(byte(&space, AT), 4);
}

#[test]
fn mremap_moves_a_page_it_holds() {
    let space = space(1, Prot::READ_WRITE);
    space.write(GuestAddr(AT), &[7]).unwrap();
    assert_eq!(used(&space, AT), 7);
    let moved = space
        .remap_shared(
            GuestAddr(AT),
            PAGE_SIZE,
            PAGE_SIZE,
            Remap {
                may_move: true,
                fixed: true,
                keep_old: false,
                new_addr: GuestAddr(0x4000_0000),
            },
        )
        .unwrap();
    assert!(space.read(GuestAddr(AT), &mut [0]).is_err());
    assert!(space.write(GuestAddr(AT), &[8]).is_err());
    assert_eq!(byte(&space, moved.0), 7);
}

#[test]
fn a_shrinking_break_takes_away_a_page_it_holds() {
    let mut space = AddressSpace::new();
    space.set_initial_break(GuestAddr(AT));
    assert_eq!(
        space.set_break_shared(GuestAddr(AT + PAGE_SIZE)),
        GuestAddr(AT + PAGE_SIZE)
    );
    space.write(GuestAddr(AT), &[3]).unwrap();
    assert_eq!(used(&space, AT), 3);
    assert_eq!(space.set_break(GuestAddr(AT)), GuestAddr(AT));
    assert!(space.read(GuestAddr(AT), &mut [0]).is_err());
}

#[test]
fn fork_keeps_the_parent_and_the_child_apart() {
    let parent = space(1, Prot::READ_WRITE);
    parent.write(GuestAddr(AT), &[1]).unwrap();
    assert_eq!(used(&parent, AT), 1);
    let child = parent.fork();
    // Writes after the fork copy the page for the space that makes them.
    parent.write(GuestAddr(AT), &[2]).unwrap();
    assert_eq!(byte(&child, AT), 1);
    assert_eq!(used(&child, AT), 1);
    child.write(GuestAddr(AT), &[3]).unwrap();
    assert_eq!(byte(&parent, AT), 2);
    assert_eq!(byte(&child, AT), 3);
    // And later ones stay in their own copies.
    parent.write(GuestAddr(AT + 1), &[4]).unwrap();
    child.write(GuestAddr(AT + 1), &[5]).unwrap();
    assert_eq!(byte(&parent, AT + 1), 4);
    assert_eq!(byte(&child, AT + 1), 5);
}

#[test]
fn a_page_shared_after_fork_is_read_through_its_copy() {
    let parent = space(1, Prot::READ_WRITE);
    parent.write(GuestAddr(AT), &[1]).unwrap();
    let child = parent.fork();
    // The child holds the frame it shares with the parent; the parent's
    // write copies it for the parent alone.
    assert_eq!(used(&child, AT), 1);
    assert_eq!(used(&parent, AT), 1);
    parent.write(GuestAddr(AT), &[2]).unwrap();
    assert_eq!(byte(&parent, AT), 2);
    assert_eq!(byte(&child, AT), 1);
}

#[test]
fn a_loader_write_across_pages_after_fork_is_read_from_the_copies() {
    let parent = space(2, Prot::READ);
    parent.write_initial(GuestAddr(AT), &[1]).unwrap();
    parent
        .write_initial(GuestAddr(AT + PAGE_SIZE), &[2])
        .unwrap();
    let child = parent.fork();
    assert_eq!(used(&parent, AT + PAGE_SIZE - 1), 0);
    assert_eq!(used(&parent, AT + PAGE_SIZE), 2);
    // A write across both pages, which copies the frames shared with the
    // child, without a mutable borrow of the space.
    parent
        .write_initial(GuestAddr(AT + PAGE_SIZE - 1), &[8, 9])
        .unwrap();
    assert_eq!(byte(&parent, AT + PAGE_SIZE - 1), 8);
    assert_eq!(byte(&parent, AT + PAGE_SIZE), 9);
    assert_eq!(byte(&child, AT + PAGE_SIZE - 1), 0);
    assert_eq!(byte(&child, AT + PAGE_SIZE), 2);
}

#[test]
fn a_mapping_made_shared_before_fork_stays_shared() {
    let parent = space(1, Prot::READ_WRITE);
    parent.write(GuestAddr(AT), &[1]).unwrap();
    assert_eq!(used(&parent, AT), 1);
    parent.mark_shared(GuestAddr(AT), PAGE_SIZE).unwrap();
    let child = parent.fork();
    assert_eq!(used(&parent, AT), 1);
    child.write(GuestAddr(AT), &[2]).unwrap();
    assert_eq!(byte(&parent, AT), 2);
    parent.write(GuestAddr(AT), &[3]).unwrap();
    assert_eq!(byte(&child, AT), 3);
}

#[test]
fn a_write_to_code_changes_the_code_generation() {
    let space = space(1, Prot::READ_WRITE.union(Prot::EXEC));
    space.write(GuestAddr(AT), &[0x90]).unwrap();
    let mut code = [0];
    space.fetch(GuestAddr(AT), &mut code).unwrap();
    space.fetch(GuestAddr(AT), &mut code).unwrap();
    let generation = space.code_generation();
    space.write(GuestAddr(AT), &[0xc3]).unwrap();
    assert_ne!(space.code_generation(), generation);
    space.fetch(GuestAddr(AT), &mut code).unwrap();
    assert_eq!(code, [0xc3]);
}

#[test]
fn the_page_cache_of_a_file_mapping_shows_through() {
    struct Zeros;
    impl PageSource for Zeros {
        fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
            buf.fill(0);
            Ok(buf.len())
        }
    }
    let pages = SharedPages::new().with_source(Arc::new(Zeros));
    let space = AddressSpace::new();
    let at = space
        .map_shared(None, PAGE_SIZE, Prot::READ_WRITE, MappingKind::File)
        .unwrap();
    space.back_with_cache(at, PAGE_SIZE, &pages, 0).unwrap();
    assert_eq!(used(&space, at.0 + 3), 0);
    // A write by the file, not by this space, shows at once.
    pages.store(3, b"f");
    assert_eq!(byte(&space, at.0 + 3), b'f');
}

/// Waiting for an access that should finish: it returns as soon as the access
/// does, so only a failure waits this long, however loaded the machine.
const SHOULD_FINISH: std::time::Duration = std::time::Duration::from_secs(60);
/// Waiting for an access that should not: a late finish still passes.
const SHOULD_WAIT: std::time::Duration = std::time::Duration::from_millis(200);

/// Which of the space's locks another thread holds while the access runs.
#[derive(Clone, Copy)]
enum Held {
    /// The session's serialization lock.
    Serialization,
    /// That and the space's own lock.
    Both,
}

/// Whether `access` finishes within `patience` while another thread holds
/// the `held` locks. The accessing thread runs `prepare` first, without them,
/// so that its own TLB can hold the page.
fn finishes_while_held(
    space: &Arc<AddressSpace>,
    held: Held,
    patience: std::time::Duration,
    prepare: impl FnOnce(&AddressSpace) + Send + 'static,
    access: impl FnOnce(&AddressSpace) + Send + 'static,
) -> bool {
    let (ready, prepared) = std::sync::mpsc::channel();
    let (go, started) = std::sync::mpsc::channel::<()>();
    let (sent, received) = std::sync::mpsc::channel();
    let accessing = Arc::clone(space);
    let thread = std::thread::spawn(move || {
        prepare(&accessing);
        ready.send(()).unwrap();
        started.recv().unwrap();
        access(&accessing);
        sent.send(()).unwrap();
    });
    prepared.recv().unwrap();
    let serialization = space.serialization.lock().unwrap();
    let data = matches!(held, Held::Both).then(|| space.data.lock().unwrap());
    go.send(()).unwrap();
    let finished = received.recv_timeout(patience).is_ok();
    drop(data);
    drop(serialization);
    thread.join().unwrap();
    finished
}

/// [`finishes_while_held`] with the serialization lock held and nothing
/// prepared.
fn finishes_under_serialization(
    space: &Arc<AddressSpace>,
    patience: std::time::Duration,
    access: impl FnOnce(&AddressSpace) + Send + 'static,
) -> bool {
    finishes_while_held(space, Held::Serialization, patience, |_| {}, access)
}

#[test]
fn an_access_it_holds_needs_no_serialization() {
    let space = Arc::new(space(1, Prot::READ_WRITE));
    space.write(GuestAddr(AT), &[1]).unwrap();
    assert_eq!(used(&space, AT), 1);
    assert!(finishes_while_held(
        &space,
        Held::Serialization,
        SHOULD_FINISH,
        |space| {
            used(space, AT);
        },
        |space| {
            assert_eq!(byte(space, AT), 1);
        }
    ));
    assert!(finishes_under_serialization(
        &space,
        SHOULD_FINISH,
        |space| {
            space.write(GuestAddr(AT), &[2]).unwrap();
        }
    ));
    assert_eq!(byte(&space, AT), 2);
}

#[test]
fn an_access_it_does_not_hold_waits_for_serialization() {
    let space = Arc::new(space(1, Prot::READ_WRITE));
    // A first read, and a first write, go through the page table.
    assert!(!finishes_under_serialization(
        &space,
        SHOULD_WAIT,
        |space| {
            assert_eq!(byte(space, AT), 0);
        }
    ));
    let shared = Arc::new(self::space(1, Prot::READ_WRITE));
    shared.mark_shared(GuestAddr(AT), PAGE_SIZE).unwrap();
    assert!(!finishes_under_serialization(
        &shared,
        SHOULD_WAIT,
        |shared| {
            shared.write(GuestAddr(AT), &[1]).unwrap();
        }
    ));
    assert_eq!(byte(&shared, AT), 1);
    // Nor does shared memory ever get in, however much it is used.
    assert_eq!(used(&shared, AT), 1);
    assert!(!finishes_under_serialization(
        &shared,
        SHOULD_WAIT,
        |shared| {
            assert_eq!(byte(shared, AT), 1);
        }
    ));
}

#[test]
fn a_load_its_thread_holds_takes_no_lock() {
    let space = Arc::new(space(1, Prot::READ_WRITE.union(Prot::EXEC)));
    space
        .write(GuestAddr(AT), &[1, 2, 3, 4, 5, 6, 7, 8])
        .unwrap();
    assert!(finishes_while_held(
        &space,
        Held::Both,
        SHOULD_FINISH,
        |space| {
            used(space, AT);
        },
        |space| {
            assert_eq!(byte(space, AT + 1), 2);
            assert_eq!(space.read_value(GuestAddr(AT), 4).unwrap(), 0x0403_0201);
            let mut code = [0; 3];
            assert_eq!(
                space.fetch_partial(GuestAddr(AT + 2), &mut code).unwrap(),
                3
            );
            assert_eq!(code, [3, 4, 5]);
        }
    ));
    // A write still takes the space's lock.
    assert!(!finishes_while_held(
        &space,
        Held::Both,
        SHOULD_WAIT,
        |space| {
            used(space, AT);
        },
        |space| {
            space.write(GuestAddr(AT), &[9]).unwrap();
        }
    ));
    assert_eq!(byte(&space, AT), 9);
}

#[test]
fn a_page_another_thread_holds_shows_what_this_one_does_to_it() {
    let space = Arc::new(space(2, Prot::READ_WRITE));
    space.write(GuestAddr(AT), &[1]).unwrap();
    space.write(GuestAddr(AT + PAGE_SIZE), &[1]).unwrap();
    let (filled, wait_filled) = std::sync::mpsc::channel();
    let (changed, wait_changed) = std::sync::mpsc::channel::<u32>();
    let (seen, wait_seen) = std::sync::mpsc::channel();
    let other = Arc::clone(&space);
    let thread = std::thread::spawn(move || {
        used(&other, AT);
        used(&other, AT + PAGE_SIZE);
        filled.send(()).unwrap();
        while let Ok(step) = wait_changed.recv() {
            let result = match step {
                0 => Ok(byte(&other, AT)),
                1 => other.read(GuestAddr(AT), &mut [0]).map(|()| 0),
                _ => other.read(GuestAddr(AT + PAGE_SIZE), &mut [0]).map(|()| 0),
            };
            seen.send(result).unwrap();
        }
    });
    wait_filled.recv().unwrap();
    // A write through the frame both TLBs show.
    space.write(GuestAddr(AT), &[2]).unwrap();
    changed.send(0).unwrap();
    assert_eq!(wait_seen.recv().unwrap().unwrap(), 2);
    // mprotect and munmap by this thread, which the other one held.
    space
        .protect_shared(GuestAddr(AT), PAGE_SIZE, Prot::NONE)
        .unwrap();
    changed.send(1).unwrap();
    let fault = wait_seen.recv().unwrap().unwrap_err();
    assert!(fault.mapped && !fault.present);
    space
        .unmap_shared(GuestAddr(AT + PAGE_SIZE), PAGE_SIZE)
        .unwrap();
    changed.send(2).unwrap();
    assert!(!wait_seen.recv().unwrap().unwrap_err().mapped);
    drop(changed);
    thread.join().unwrap();
}

#[test]
fn a_space_never_takes_the_pages_of_another_space_in_a_threads_tlb() {
    let first = space(1, Prot::READ_WRITE);
    first.write(GuestAddr(AT), &[1]).unwrap();
    assert_eq!(used(&first, AT), 1);
    drop(first);
    // Made after the first was dropped, so possibly where it was.
    let second = AddressSpace::new();
    assert!(!second.read(GuestAddr(AT), &mut [0]).unwrap_err().mapped);
    assert_ne!(second.code.epoch.load(Ordering::Acquire), 0);
}

#[test]
fn a_load_it_holds_sees_a_16_byte_exchange_whole() {
    let space = Arc::new(space(1, Prot::READ_WRITE));
    space.write(GuestAddr(AT), &[0; 16]).unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let (reader, finished) = (Arc::clone(&space), Arc::clone(&done));
    let thread = std::thread::spawn(move || {
        used(&reader, AT);
        while !finished.load(Ordering::Relaxed) {
            let mut value = [0; 16];
            reader.read(GuestAddr(AT), &mut value).unwrap();
            assert!(value == [0; 16] || value == [0xff; 16], "{value:?}");
        }
    });
    for round in 0..100_000 {
        let value = if round % 2 == 0 { u128::MAX } else { 0 };
        space
            .atomic(GuestAddr(AT), AtomicWidth::W128, AtomicOp::Exchange(value))
            .unwrap();
    }
    done.store(true, Ordering::Relaxed);
    thread.join().unwrap();
}
