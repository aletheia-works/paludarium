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
