//! [`AddressSpace::code_generation_cached`]: it gives what
//! [`AddressSpace::code_generation`] gives under the locks, through every
//! change of the code, the mappings, the shared mappings and the page
//! caches, and takes no lock while none of them has been borrowed mutably.
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
fn cached(space: &AddressSpace, sources: &mut CodeSources) -> u64 {
    let generation = space.code_generation_cached(sources);
    assert_eq!(generation, space.code_generation());
    generation
}

#[test]
fn it_follows_code_writes_and_mapping_changes() {
    let mut space = space();
    let mut sources = CodeSources::default();
    let g0 = cached(&space, &mut sources);
    space.write(GuestAddr(DATA), &[1]).unwrap();
    space.write(GuestAddr(DATA), &[2]).unwrap();
    assert_eq!(cached(&space, &mut sources), g0, "data writes keep code");
    space.write(GuestAddr(CODE), &[0x90]).unwrap();
    let g1 = cached(&space, &mut sources);
    assert_ne!(g1, g0);
    // A write through the TLB, to a page written before, too.
    space.write(GuestAddr(CODE + 1), &[0x90]).unwrap();
    let g2 = cached(&space, &mut sources);
    assert_ne!(g2, g1);
    space
        .protect(GuestAddr(DATA), PAGE_SIZE, Prot::READ_EXEC)
        .unwrap();
    assert_ne!(cached(&space, &mut sources), g2);
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
    let mut sources = CodeSources::default();
    cached(&space, &mut sources);
    // Backing the mapping with a page cache bumps no generation; the store
    // to the cache, which another process may make, must still count.
    space.back_with_cache(at, PAGE_SIZE, &pages, 0).unwrap();
    let before = cached(&space, &mut sources);
    pages.store(0, &[0xc3]);
    assert_ne!(cached(&space, &mut sources), before);
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
    let mut sources = CodeSources::default();
    let one = cached(&first, &mut sources);
    let other = cached(&second, &mut sources);
    assert_ne!(one, other);
}

#[test]
fn it_counts_another_space_s_writes_to_shared_memory() {
    let parent = space();
    parent.mark_shared(GuestAddr(CODE), PAGE_SIZE).unwrap();
    let child = parent.fork();
    let mut sources = CodeSources::default();
    let before = cached(&parent, &mut sources);
    child.write(GuestAddr(CODE), &[0xc3]).unwrap();
    assert_ne!(cached(&parent, &mut sources), before);
}

#[test]
fn it_reads_another_space_afresh() {
    let first = space();
    first.write(GuestAddr(CODE), &[0x90]).unwrap();
    let mut sources = CodeSources::default();
    cached(&first, &mut sources);
    let second = first.fork();
    second.write(GuestAddr(CODE), &[0xc3]).unwrap();
    cached(&second, &mut sources);
    cached(&AddressSpace::new(), &mut sources);
    cached(&first, &mut sources);
}

#[test]
fn it_takes_no_lock_while_the_space_is_not_borrowed_mutably() {
    let space = Arc::new(space());
    let mut sources = CodeSources::default();
    let before = cached(&space, &mut sources);
    let held = space.data.lock().unwrap();
    let (sent, received) = mpsc::channel();
    let reader = Arc::clone(&space);
    std::thread::spawn(move || {
        let generation = reader.code_generation_cached(&mut sources);
        sent.send(generation).unwrap();
    });
    assert_eq!(
        received.recv_timeout(Duration::from_secs(10)),
        Ok(before),
        "the generation was read without the lock"
    );
    drop(held);
}
