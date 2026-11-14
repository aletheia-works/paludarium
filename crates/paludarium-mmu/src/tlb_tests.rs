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
fn a_page_only_read_before_fork_gets_a_frame_in_each_space() {
    // The parent reads the page, so that it has an entry but no contents.
    let parent = space(1, Prot::READ_WRITE);
    assert_eq!(used(&parent, AT), 0);
    let child = parent.fork();
    child.write(GuestAddr(AT), &[7]).unwrap();
    assert_eq!(byte(&parent, AT), 0);
    assert_eq!(used(&child, AT), 7);
    parent.write(GuestAddr(AT + 1), &[8]).unwrap();
    assert_eq!(byte(&child, AT + 1), 0);
    assert_eq!(used(&parent, AT + 1), 8);
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
    assert!(finishes_while_held(
        &space,
        Held::Serialization,
        SHOULD_FINISH,
        |space| {
            used(space, AT);
        },
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
    // Nor does a page that only another thread used: each thread has a TLB
    // of its own.
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
fn an_access_its_thread_holds_takes_no_lock() {
    let space = Arc::new(space(2, Prot::READ_WRITE.union(Prot::EXEC)));
    space
        .write(GuestAddr(AT), &[1, 2, 3, 4, 5, 6, 7, 8])
        .unwrap();
    let generation = space.code_generation();
    assert!(finishes_while_held(
        &space,
        Held::Both,
        SHOULD_FINISH,
        |space| {
            // A page is fetched from under the locks the first time.
            space.fetch(GuestAddr(AT), &mut [0]).unwrap();
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
            space.write(GuestAddr(AT), &[9]).unwrap();
            space.write_value(GuestAddr(AT + 1), 2, 0x0b0a).unwrap();
            let result = space
                .atomic(GuestAddr(AT + 4), AtomicWidth::W32, AtomicOp::Add(1))
                .unwrap();
            assert_eq!(result.old, 0x0807_0605);
        }
    ));
    let mut bytes = [0; 8];
    space.read(GuestAddr(AT), &mut bytes).unwrap();
    assert_eq!(bytes, [9, 10, 11, 4, 6, 6, 7, 8]);
    // Stores to code that was fetched still make its decoded instructions
    // stale.
    assert_ne!(space.code_generation(), generation);
    // A page it does not hold takes the locks.
    assert!(!finishes_while_held(
        &space,
        Held::Both,
        SHOULD_WAIT,
        |space| {
            used(space, AT);
        },
        |space| {
            space.write(GuestAddr(AT + PAGE_SIZE), &[9]).unwrap();
        }
    ));
    assert_eq!(byte(&space, AT + PAGE_SIZE), 9);
}

/// What one thread of a [`race`] does.
type Racer = Box<dyn FnOnce(&AddressSpace) + Send>;

/// Runs `threads` threads at once, each of which uses the page first.
fn race(space: &Arc<AddressSpace>, threads: Vec<Racer>) {
    let start = Arc::new(std::sync::Barrier::new(threads.len()));
    let handles: Vec<_> = threads
        .into_iter()
        .map(|run| {
            let (space, start) = (Arc::clone(space), Arc::clone(&start));
            std::thread::spawn(move || {
                used(&space, AT);
                start.wait();
                run(&space);
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
}

const ROUNDS: u64 = 20_000;

#[test]
fn a_locked_instruction_keeps_the_stores_to_its_word_that_take_no_lock() {
    let space = Arc::new(space(1, Prot::READ_WRITE));
    space.write(GuestAddr(AT), &[0; 8]).unwrap();
    let add = |space: &AddressSpace| {
        for _ in 0..ROUNDS {
            space
                .atomic(GuestAddr(AT), AtomicWidth::W32, AtomicOp::Add(1))
                .unwrap();
        }
    };
    race(
        &space,
        vec![
            Box::new(add),
            Box::new(add),
            Box::new(|space: &AddressSpace| {
                for round in 0..ROUNDS {
                    space.write(GuestAddr(AT + 5), &[round as u8]).unwrap();
                    space
                        .write_value(GuestAddr(AT + 6), 2, round & 0xffff)
                        .unwrap();
                }
            }),
        ],
    );
    assert_eq!(space.read_value(GuestAddr(AT), 4).unwrap(), 2 * ROUNDS);
    let last = ROUNDS - 1;
    assert_eq!(
        space.read_value(GuestAddr(AT + 5), 3).unwrap(),
        last & 0xff | (last & 0xffff) << 8
    );
}

#[test]
fn a_locked_instruction_across_words_is_whole_against_ones_within_them() {
    let space = Arc::new(space(1, Prot::READ_WRITE));
    space.write(GuestAddr(AT), &[0; 64]).unwrap();
    race(
        &space,
        vec![
            // `CMPXCHG16B`'s width, and a split lock across two words.
            Box::new(|space: &AddressSpace| {
                for _ in 0..ROUNDS {
                    space
                        .atomic(GuestAddr(AT + 16), AtomicWidth::W128, AtomicOp::Add(1))
                        .unwrap();
                    space
                        .atomic(GuestAddr(AT + 44), AtomicWidth::W64, AtomicOp::Add(1))
                        .unwrap();
                }
            }),
            Box::new(|space: &AddressSpace| {
                for _ in 0..ROUNDS {
                    space
                        .atomic(GuestAddr(AT + 16), AtomicWidth::W64, AtomicOp::Add(1))
                        .unwrap();
                    space
                        .atomic(GuestAddr(AT + 44), AtomicWidth::W32, AtomicOp::Add(1))
                        .unwrap();
                }
            }),
        ],
    );
    assert_eq!(space.read_u64(GuestAddr(AT + 16)).unwrap(), 2 * ROUNDS);
    assert_eq!(space.read_u64(GuestAddr(AT + 24)).unwrap(), 0);
    assert_eq!(space.read_u64(GuestAddr(AT + 44)).unwrap(), 2 * ROUNDS);
}

/// Stores `1, 2, …` at `AT` without a lock from another thread until one
/// faults, while `change` runs in this one; then checks that the value
/// `after` reads no longer changes. After the first stores, each one waits
/// while it is under way, so that `change` comes in the middle of one.
fn no_store_lands_after(
    change: impl FnOnce(&AddressSpace),
    after: impl Fn(&AddressSpace) -> u64,
    space: &Arc<AddressSpace>,
) {
    let storing = Arc::clone(space);
    let (started, wait_started) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        used(&storing, AT);
        let mut value = 0;
        loop {
            value += 1;
            if storing.write_u64(GuestAddr(AT), value).is_err() {
                break;
            }
            if value == 1000 {
                STORE_STALL.set(Some(std::time::Duration::from_millis(20)));
                started.send(()).unwrap();
            }
        }
    });
    wait_started.recv().unwrap();
    change(space);
    let first = after(space);
    std::thread::sleep(std::time::Duration::from_millis(60));
    assert_eq!(after(space), first);
    // Undo the change, if it was one, so that the thread stops.
    let _ = space.protect_shared(GuestAddr(AT), PAGE_SIZE, Prot::READ);
    thread.join().unwrap();
}

#[test]
fn no_store_without_a_lock_lands_after_mprotect_returns() {
    for _ in 0..3 {
        let space = Arc::new(space(1, Prot::READ_WRITE));
        no_store_lands_after(
            |space| {
                space
                    .protect_shared(GuestAddr(AT), PAGE_SIZE, Prot::READ)
                    .unwrap();
            },
            |space| space.read_u64(GuestAddr(AT)).unwrap(),
            &space,
        );
    }
}

#[test]
fn no_store_without_a_lock_lands_in_a_child_after_fork_returns() {
    for _ in 0..20 {
        let space = Arc::new(space(1, Prot::READ_WRITE));
        let child = std::sync::OnceLock::new();
        no_store_lands_after(
            |space| {
                let _ = child.set(space.fork());
            },
            |_| child.get().unwrap().read_u64(GuestAddr(AT)).unwrap(),
            &space,
        );
    }
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
fn a_barrier_waits_for_a_store_under_way_in_another_thread() {
    let space = Arc::new(space(1, Prot::READ_WRITE));
    space.write_u64(GuestAddr(AT), 1).unwrap();
    let storing = Arc::clone(&space);
    let (started, wait_started) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        used(&storing, AT);
        STORE_STALL.set(Some(std::time::Duration::from_millis(100)));
        started.send(()).unwrap();
        storing.write_u64(GuestAddr(AT), 2).unwrap();
    });
    wait_started.recv().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    space.barrier();
    assert_eq!(space.read_u64(GuestAddr(AT)).unwrap(), 2);
    thread.join().unwrap();
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

/// A file that can shrink, as the page cache counts it: each byte is its
/// offset modulo 251, and a shrink sets the size, zeros its page cache past
/// it, then counts, as the kernel's page cache does.
struct Shrinking {
    /// Its page cache, once a mapping shows it.
    cache: std::sync::OnceLock<SharedPages>,
    size: Arc<FileSize>,
    /// The smallest size it has shrunk to: past it, it reads as zeros.
    zeros_from: AtomicU64,
    shrinks: std::sync::Mutex<Vec<(u64, u64)>>,
    /// A size to shrink to as the count is next read, or 0.
    shrink_when_counted: AtomicU64,
}
impl Shrinking {
    fn new(size: u64) -> Arc<Self> {
        Arc::new(Shrinking {
            cache: std::sync::OnceLock::new(),
            size: Arc::new(FileSize::new(size)),
            zeros_from: AtomicU64::new(u64::MAX),
            shrinks: std::sync::Mutex::default(),
            shrink_when_counted: AtomicU64::new(0),
        })
    }
    fn resize(&self, size: u64) {
        let mut shrinks = self.shrinks.lock().unwrap();
        if self.size.set(size) {
            self.zeros_from.fetch_min(size, Ordering::SeqCst);
            if let Some(cache) = self.cache.get() {
                cache.zero(size, u64::MAX);
            }
            shrinks.push((self.size.count_shrink(), size));
        }
    }
}
impl PageSource for Shrinking {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let size = self.size.get();
        let n =
            usize::try_from(size.saturating_sub(offset)).map_or(buf.len(), |n| n.min(buf.len()));
        let zeros_from = self.zeros_from.load(Ordering::SeqCst);
        for (i, b) in buf[..n].iter_mut().enumerate() {
            let at = offset + i as u64;
            *b = if at < zeros_from { (at % 251) as u8 } else { 0 };
        }
        Ok(n)
    }
    fn size(&self) -> Option<u64> {
        Some(self.size.get())
    }
    fn shrinks(&self) -> u64 {
        match self.shrink_when_counted.swap(0, Ordering::SeqCst) {
            0 => {}
            size => self.resize(size),
        }
        self.size.shrinks()
    }
    fn file_size(&self) -> Option<Arc<FileSize>> {
        Some(Arc::clone(&self.size))
    }
    fn shrunk_since(&self, count: u64) -> Option<u64> {
        let shrinks = self.shrinks.lock().unwrap();
        shrinks
            .iter()
            .filter(|&&(after, _)| after > count)
            .map(|&(_, size)| size)
            .min()
    }
}

/// How a page of a private file mapping shows its file.
#[derive(Clone, Copy, Debug)]
enum FileView {
    /// A copy of its own, read from the file when first touched.
    Copy,
    /// The file's page-cache page, until a write copies it.
    Cache,
}

/// A space with `pages` pages of `file` mapped privately at `AT`, shown as
/// `view` says.
fn file_space(file: &Arc<Shrinking>, pages: u64, view: FileView) -> Arc<AddressSpace> {
    let space = AddressSpace::new();
    let len = pages * PAGE_SIZE;
    space
        .map_shared(
            Some(GuestAddr(AT)),
            len,
            Prot::READ_WRITE,
            MappingKind::File,
        )
        .unwrap();
    let source: Arc<dyn PageSource> = file.clone();
    match view {
        FileView::Copy => space.back_with_file(GuestAddr(AT), len, source, 0),
        FileView::Cache => {
            let pages = SharedPages::new().with_source(source);
            let _ = file.cache.set(pages.clone());
            space.back_with_cache(GuestAddr(AT), len, &pages, 0)
        }
    }
    .unwrap();
    Arc::new(space)
}

#[test]
fn a_file_page_its_thread_holds_takes_no_lock() {
    for view in [FileView::Copy, FileView::Cache] {
        let file = Shrinking::new(2 * PAGE_SIZE);
        let space = file_space(&file, 2, view);
        // A load of the file, and a store to a copy of its own.
        assert!(
            finishes_while_held(
                &space,
                Held::Both,
                SHOULD_FINISH,
                |space| {
                    // The first touch of a page changes the page table,
                    // which empties the TLB, so both come first.
                    byte(space, AT + 5);
                    space.write(GuestAddr(AT + PAGE_SIZE), &[1]).unwrap();
                    used(space, AT + PAGE_SIZE);
                    used(space, AT + 5);
                },
                |space| {
                    assert_eq!(byte(space, AT + 5), 5);
                    space.write(GuestAddr(AT + PAGE_SIZE + 1), &[2]).unwrap();
                    space.write_u64(GuestAddr(AT + PAGE_SIZE + 8), 3).unwrap();
                },
            ),
            "{view:?}"
        );
        assert_eq!(byte(&space, AT + PAGE_SIZE + 1), 2);
        assert_eq!(space.read_u64(GuestAddr(AT + PAGE_SIZE + 8)).unwrap(), 3);
        // A page-cache page is still copied first, under the locks.
        if let FileView::Cache = view {
            assert!(!finishes_while_held(
                &space,
                Held::Both,
                SHOULD_WAIT,
                |space| {
                    used(space, AT);
                },
                |space| {
                    space.write(GuestAddr(AT), &[9]).unwrap();
                },
            ));
            assert_eq!(byte(&space, AT), 9);
        }
    }
}

#[test]
fn a_file_page_it_holds_is_a_bus_error_once_its_file_ends_before_it() {
    for view in [FileView::Copy, FileView::Cache] {
        let file = Shrinking::new(2 * PAGE_SIZE);
        let space = file_space(&file, 2, view);
        let last = AT + PAGE_SIZE;
        // A copy, or the page-cache page, which no write copied.
        let shown = match view {
            FileView::Copy => {
                space.write(GuestAddr(last), &[7]).unwrap();
                7
            }
            FileView::Cache => pattern(PAGE_SIZE),
        };
        assert_eq!(used(&space, last), shown, "{view:?}");
        assert_eq!(used(&space, AT + 3), 3, "{view:?}");
        // Within the last page of the file, the page stays.
        file.resize(PAGE_SIZE + 1);
        assert_eq!(byte(&space, last), shown, "{view:?}");
        file.resize(PAGE_SIZE);
        let fault = space.read(GuestAddr(last), &mut [0]).unwrap_err();
        assert!(fault.bus && !fault.write, "{view:?}");
        assert!(space.write(GuestAddr(last), &[8]).unwrap_err().bus);
        assert!(space.read_u64(GuestAddr(last + 8)).unwrap_err().bus);
        assert!(space.write_u64(GuestAddr(last + 8), 1).unwrap_err().bus);
        assert_eq!(byte(&space, AT + 3), 3, "{view:?}");
    }
}

#[test]
fn a_copy_it_holds_goes_once_its_file_shrinks_past_it_even_when_it_grows_again() {
    for view in [FileView::Copy, FileView::Cache] {
        let file = Shrinking::new(2 * PAGE_SIZE);
        let space = file_space(&file, 2, view);
        let last = AT + PAGE_SIZE;
        space.write(GuestAddr(last + 1), &[0xee]).unwrap();
        assert_eq!(used(&space, last + 1), 0xee, "{view:?}");
        file.resize(PAGE_SIZE);
        file.resize(2 * PAGE_SIZE);
        // As Linux drops the copy: the file shows again, zeros where it
        // shrank.
        assert_eq!(byte(&space, last + 1), 0, "{view:?}");
        // A shrink that leaves the copy within the file keeps it.
        space.write(GuestAddr(last + 1), &[0xdd]).unwrap();
        assert_eq!(used(&space, last + 1), 0xdd, "{view:?}");
        file.resize(PAGE_SIZE + 2);
        file.resize(2 * PAGE_SIZE);
        assert_eq!(byte(&space, last + 1), 0xdd, "{view:?}");
    }
}

fn pattern(offset: u64) -> u8 {
    (offset % 251) as u8
}

/// Accesses the last page of a two-page file from another thread, without a
/// lock, until one is a bus error, while this one shrinks the file to one
/// page: no access that starts after the shrink returns may succeed, as
/// Linux's truncation unmaps the page before it returns.
fn no_access_succeeds_after_a_shrink_past_it(
    view: FileView,
    access: fn(&AddressSpace, u64) -> Result<(), Fault>,
) {
    let file = Shrinking::new(2 * PAGE_SIZE);
    let space = file_space(&file, 2, view);
    let last = AT + PAGE_SIZE;
    let shrunk = Arc::new(AtomicBool::new(false));
    let (started, wait_started) = std::sync::mpsc::channel();
    let (accessing, after) = (Arc::clone(&space), Arc::clone(&shrunk));
    let thread = std::thread::spawn(move || {
        used(&accessing, last);
        let mut value = 0u64;
        loop {
            value += 1;
            let late = after.load(Ordering::SeqCst);
            match access(&accessing, value) {
                Ok(()) => assert!(!late, "an access after the shrink succeeded"),
                Err(fault) => {
                    assert!(fault.bus);
                    break;
                }
            }
            if value == 1000 {
                started.send(()).unwrap();
            }
        }
    });
    wait_started.recv().unwrap();
    file.resize(PAGE_SIZE);
    shrunk.store(true, Ordering::SeqCst);
    thread.join().unwrap();
    // Grown again, the file shows, zeros where it shrank: whatever stores
    // came in the shrink's way went with the copy.
    file.resize(2 * PAGE_SIZE);
    assert_eq!(byte(&space, last + 8), 0, "{view:?}");
}

#[test]
fn no_load_or_store_without_a_lock_succeeds_after_a_shrink_past_it_returns() {
    for _ in 0..10 {
        for view in [FileView::Copy, FileView::Cache] {
            no_access_succeeds_after_a_shrink_past_it(view, |space, _| {
                space.read_u64(GuestAddr(AT + PAGE_SIZE + 8)).map(drop)
            });
            no_access_succeeds_after_a_shrink_past_it(view, |space, value| {
                space.write_u64(GuestAddr(AT + PAGE_SIZE + 8), value)
            });
        }
    }
}

/// A space with `pages` pages of `memory` mapped shared at `AT`, with
/// `prot`, as a `MAP_SHARED` mapping of a file or of shared memory shows it.
fn shared_space(memory: &SharedPages, pages: u64, prot: Prot) -> Arc<AddressSpace> {
    let space = AddressSpace::new();
    let len = pages * PAGE_SIZE;
    space
        .map_shared(Some(GuestAddr(AT)), len, prot, MappingKind::File)
        .unwrap();
    space
        .share_pages(GuestAddr(AT), len, memory, 0, SharedWrites::Allowed)
        .unwrap();
    Arc::new(space)
}

#[test]
fn a_shared_page_its_thread_holds_takes_no_lock() {
    let file = Shrinking::new(PAGE_SIZE);
    let source: Arc<dyn PageSource> = file;
    for (memory, file) in [
        (SharedPages::new(), false),
        (SharedPages::new().with_source(source), true),
    ] {
        let space = shared_space(&memory, 1, Prot::READ_WRITE);
        let generation = memory.generation();
        assert!(finishes_while_held(
            &space,
            Held::Both,
            SHOULD_FINISH,
            |space| {
                space.write(GuestAddr(AT), &[1]).unwrap();
                used(space, AT);
            },
            |space| {
                assert_eq!(byte(space, AT), 1);
                space.write(GuestAddr(AT + 1), &[2]).unwrap();
                space.write_u64(GuestAddr(AT + 8), 3).unwrap();
                space
                    .atomic(GuestAddr(AT + 16), AtomicWidth::W32, AtomicOp::Add(4))
                    .unwrap();
            },
        ));
        // Each store moved the memory's generation on, and the page is
        // dirty, as under the locks.
        assert_ne!(memory.generation(), generation);
        let mut pages = Vec::new();
        memory
            .write_back(|key, page| {
                pages.push((key, page[..20].to_vec()));
                Ok(())
            })
            .unwrap();
        // What the file held, or zeros, with the stores over it.
        let mut expected: Vec<u8> = (0..20)
            .map(|offset| if file { pattern(offset) } else { 0 })
            .collect();
        expected[..2].copy_from_slice(&[1, 2]);
        expected[8..16].copy_from_slice(&3u64.to_le_bytes());
        expected[16] = expected[16].wrapping_add(4);
        assert_eq!(pages, [(0, expected)]);
    }
}

#[test]
fn a_store_without_a_lock_to_shared_memory_shows_in_every_space_and_changes_its_code() {
    let memory = SharedPages::new();
    let writer = shared_space(&memory, 1, Prot::READ_WRITE);
    let runner = shared_space(&memory, 1, Prot::READ.union(Prot::EXEC));
    writer.write(GuestAddr(AT), &[1]).unwrap();
    assert_eq!(used(&writer, AT), 1);
    // The runner watches the memory it may run code from.
    let code = runner.code_generation_cached();
    assert!(finishes_while_held(
        &writer,
        Held::Both,
        SHOULD_FINISH,
        |space| {
            used(space, AT);
        },
        |space| {
            space.write(GuestAddr(AT), &[0x90]).unwrap();
        },
    ));
    assert_eq!(byte(&runner, AT), 0x90);
    assert_ne!(runner.code_generation_cached(), code);
}

#[test]
fn a_write_back_never_misses_a_store_that_takes_no_lock() {
    // Each write-back marks the page clean before it reads it, and each
    // store makes it dirty after its bytes: whatever a write-back missed,
    // the next one hands over.
    let memory = SharedPages::new();
    let space = shared_space(&memory, 1, Prot::READ_WRITE);
    space.write_u64(GuestAddr(AT), 0).unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let (storing, finished) = (Arc::clone(&space), Arc::clone(&done));
    let thread = std::thread::spawn(move || {
        used(&storing, AT);
        let mut value = 0;
        while !finished.load(Ordering::SeqCst) {
            value += 1;
            storing.write_u64(GuestAddr(AT), value).unwrap();
        }
        value
    });
    let mut seen = 0;
    let take = |seen: &mut u64| {
        memory
            .write_back(|_, page| {
                *seen = u64::from_le_bytes(page[..8].try_into().unwrap());
                Ok(())
            })
            .unwrap();
    };
    for _ in 0..10_000 {
        take(&mut seen);
    }
    done.store(true, Ordering::SeqCst);
    let last = thread.join().unwrap();
    take(&mut seen);
    assert_eq!(seen, last);
}

#[test]
fn a_thread_tlb_never_keeps_a_file_or_its_owner_alive() {
    // Holding them would keep the file open after `munmap`, and count as
    // an attachment of System V shared memory.
    let file = Shrinking::new(2 * PAGE_SIZE);
    let owner: Arc<dyn std::any::Any + Send + Sync> = Arc::new(());
    let source: Arc<dyn PageSource> = file.clone();
    let memory = SharedPages::new()
        .with_source(Arc::clone(&source))
        .with_owner(Arc::clone(&owner));
    let private = file_space(&file, 2, FileView::Copy);
    let shared = shared_space(&memory, 2, Prot::READ_WRITE);
    drop(memory);
    let (files, owners) = (Arc::strong_count(&file), Arc::strong_count(&owner));
    for space in [&private, &shared] {
        space.write(GuestAddr(AT), &[1]).unwrap();
        assert_eq!(used(space, AT), 1);
        space.write(GuestAddr(AT + 1), &[2]).unwrap();
    }
    assert_eq!(Arc::strong_count(&file), files);
    assert_eq!(Arc::strong_count(&owner), owners);
    // The pages were held, without a lock.
    assert!(finishes_while_held(
        &shared,
        Held::Both,
        SHOULD_FINISH,
        |space| {
            used(space, AT);
        },
        |space| {
            assert_eq!(byte(space, AT + 1), 2);
        },
    ));
}

#[test]
fn a_page_gone_leaves_the_meter_though_another_thread_still_holds_it() {
    // The other thread does not run again until after the check, so its TLB
    // still has the entry: only the bytes, not the charge.
    let meter = Arc::new(MemoryMeter::new(16 * PAGE_SIZE));
    let space = Arc::new(space(4, Prot::READ_WRITE).with_memory_meter(Arc::clone(&meter)));
    for page in 0..4 {
        space.write(GuestAddr(AT + page * PAGE_SIZE), &[1]).unwrap();
    }
    assert_eq!(meter.used(), 4 * PAGE_SIZE);
    let (held, wait_held) = std::sync::mpsc::channel();
    let (go, wait_go) = std::sync::mpsc::channel::<()>();
    let holding = Arc::clone(&space);
    let thread = std::thread::spawn(move || {
        for page in 0..4 {
            assert_eq!(used(&holding, AT + page * PAGE_SIZE), 1);
        }
        held.send(()).unwrap();
        wait_go.recv().unwrap();
        // Its next access sees the change.
        assert!(!holding.read(GuestAddr(AT), &mut [0]).unwrap_err().mapped);
    });
    wait_held.recv().unwrap();
    space.unmap_shared(GuestAddr(AT), 4 * PAGE_SIZE).unwrap();
    assert_eq!(meter.used(), 0);
    // So there is room for as many new frames again.
    let fresh = space
        .map_shared(
            None,
            16 * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    for page in 0..16 {
        space
            .write(GuestAddr(fresh.0 + page * PAGE_SIZE), &[2])
            .unwrap();
    }
    go.send(()).unwrap();
    thread.join().unwrap();
}

#[test]
fn a_thread_holds_a_thousand_pages_without_a_lock() {
    // The size the docs give, not `TLB_ENTRIES`, so that a smaller TLB fails.
    let pages = 1024;
    let space = Arc::new(space(pages, Prot::READ_WRITE));
    for page in 0..pages {
        space
            .write(GuestAddr(AT + page * PAGE_SIZE), &[page as u8])
            .unwrap();
    }
    assert!(finishes_while_held(
        &space,
        Held::Both,
        SHOULD_FINISH,
        move |space| {
            for page in 0..pages {
                used(space, AT + page * PAGE_SIZE);
            }
        },
        move |space| {
            for page in 0..pages {
                assert_eq!(byte(space, AT + page * PAGE_SIZE), page as u8);
            }
        },
    ));
}

#[test]
fn a_write_that_copies_a_page_as_its_file_shrinks_past_it_is_a_bus_error() {
    // The page-cache page is copied for the write under the locks, after
    // the check of the file's end, and the copy records the shrinks so far:
    // a shrink between the two would leave a copy past the end that no
    // later shrink check drops.
    let file = Shrinking::new(2 * PAGE_SIZE);
    let space = file_space(&file, 2, FileView::Cache);
    let last = AT + PAGE_SIZE;
    assert_eq!(byte(&space, last), pattern(PAGE_SIZE));
    file.shrink_when_counted.store(PAGE_SIZE, Ordering::SeqCst);
    let fault = space.write(GuestAddr(last), &[0xee]).unwrap_err();
    assert!(fault.bus && fault.write);
    // Grown again, the page reads as the page cache does after the shrink,
    // zeros, as in Linux: not the bytes from before it, which the write's
    // copy took if it copied before the shrink zeroed them.
    file.resize(2 * PAGE_SIZE);
    assert_eq!(byte(&space, last), 0);
}

#[test]
fn a_page_first_touched_after_its_file_shrank_and_grew_keeps_its_writes() {
    for view in [FileView::Copy, FileView::Cache] {
        let file = Shrinking::new(2 * PAGE_SIZE);
        let space = file_space(&file, 2, view);
        file.resize(0);
        file.resize(2 * PAGE_SIZE);
        space.write(GuestAddr(AT + PAGE_SIZE), &[0xee]).unwrap();
        assert_eq!(byte(&space, AT + PAGE_SIZE), 0xee, "{view:?}");
        assert_eq!(byte(&space, AT + PAGE_SIZE), 0xee, "{view:?}");
    }
}

#[test]
fn a_first_read_as_its_file_shrinks_past_the_page_is_a_bus_error() {
    // The page entry is made under the locks after the check of the file's
    // end, and records the shrinks so far: a shrink between the two must
    // still be a bus error, not a page of zeros.
    let file = Shrinking::new(2 * PAGE_SIZE);
    let space = file_space(&file, 2, FileView::Copy);
    file.shrink_when_counted.store(PAGE_SIZE, Ordering::SeqCst);
    let fault = space.read(GuestAddr(AT + PAGE_SIZE), &mut [0]).unwrap_err();
    assert!(fault.bus && !fault.write);
}

#[test]
fn code_a_truncation_takes_back_is_stale() {
    let file = Shrinking::new(PAGE_SIZE);
    let space = AddressSpace::new();
    space
        .map_shared(
            Some(GuestAddr(AT)),
            PAGE_SIZE,
            Prot::READ_WRITE.union(Prot::EXEC),
            MappingKind::File,
        )
        .unwrap();
    let source: Arc<dyn PageSource> = file.clone();
    space
        .back_with_file(GuestAddr(AT), PAGE_SIZE, source, 0)
        .unwrap();
    space.write(GuestAddr(AT), &[0xc3]).unwrap();
    let mut code = [0];
    space.fetch(GuestAddr(AT), &mut code).unwrap();
    assert_eq!(code, [0xc3]);
    let before = space.code_generation();
    // Shrunk past the page and grown again: the page shows the file once
    // more, not the copy the instruction was decoded from.
    file.resize(0);
    file.resize(PAGE_SIZE);
    space.fetch(GuestAddr(AT), &mut code).unwrap();
    assert_eq!(code, [0]);
    assert_ne!(space.code_generation(), before);
}
