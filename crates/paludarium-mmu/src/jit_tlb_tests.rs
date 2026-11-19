//! The [`JitSlot`]s that compiled code reads: which pages they let it read
//! and write without calling into the MMU.
use super::*;

const AT: u64 = 0x40_0000;

fn space(prot: Prot) -> AddressSpace {
    let mut m = AddressSpace::new();
    m.map(
        Some(GuestAddr(AT)),
        2 * PAGE_SIZE,
        prot,
        MappingKind::Anonymous,
    )
    .unwrap();
    m.write_initial(GuestAddr(AT), &[1; 16]).unwrap();
    m
}

#[test]
fn a_written_private_page_fills_its_slot_for_reads_and_writes() {
    let m = space(Prot::READ_WRITE);
    m.jit_write_value(GuestAddr(AT), 8, 5).unwrap();
    assert_eq!(m.jit_slot(AT), (true, AT, AT));
    assert_eq!(m.jit_read_value(GuestAddr(AT), 8), Ok(5));
    assert_eq!(m.jit_slot(AT), (true, AT, AT));
}

#[test]
fn a_page_without_bytes_has_no_slot() {
    let m = space(Prot::READ_WRITE);
    let other = AT + PAGE_SIZE;
    assert_eq!(m.jit_read_value(GuestAddr(other), 8), Ok(0));
    let (_, read, write) = m.jit_slot(other);
    assert_eq!((read, write), (NO_PAGE, NO_PAGE));
}

#[test]
fn mprotect_empties_the_slots_and_a_read_only_page_is_only_read() {
    let mut m = space(Prot::READ_WRITE);
    m.jit_write_value(GuestAddr(AT), 8, 5).unwrap();
    m.protect(GuestAddr(AT), PAGE_SIZE, Prot::READ).unwrap();
    assert!(!m.jit_slot(AT).0);
    assert_eq!(m.jit_read_value(GuestAddr(AT), 8), Ok(5));
    assert_eq!(m.jit_slot(AT), (true, AT, NO_PAGE));
    assert!(m.jit_write_value(GuestAddr(AT), 8, 6).is_err());
    assert_eq!(m.jit_slot(AT), (true, AT, NO_PAGE));
}

#[test]
fn an_executable_page_is_never_written_through_its_slot() {
    let m = space(Prot::from_bits(7).unwrap());
    m.jit_write_value(GuestAddr(AT), 8, 5).unwrap();
    assert_eq!(m.jit_slot(AT), (true, AT, NO_PAGE));
}

#[test]
fn a_page_that_fork_shares_is_not_written_through_its_slot() {
    let m = space(Prot::READ_WRITE);
    m.jit_write_value(GuestAddr(AT), 8, 5).unwrap();
    let child = m.fork();
    assert!(!m.jit_slot(AT).0);
    assert_eq!(m.jit_read_value(GuestAddr(AT), 8), Ok(5));
    assert_eq!(m.jit_slot(AT), (true, AT, NO_PAGE));
    // The write copies the page under the locks, after which it is the
    // parent's own.
    m.jit_write_value(GuestAddr(AT), 8, 6).unwrap();
    m.jit_write_value(GuestAddr(AT), 8, 7).unwrap();
    assert_eq!(m.jit_slot(AT), (true, AT, AT));
    assert_eq!(child.read_u64(GuestAddr(AT)), Ok(5));
}

#[test]
fn clear_refs_takes_writes_back_to_the_locks_until_the_page_is_soft_dirty() {
    let m = space(Prot::READ_WRITE);
    m.jit_write_value(GuestAddr(AT), 8, 5).unwrap();
    assert!(m.view().clear_soft_dirty());
    assert_eq!(m.jit_read_value(GuestAddr(AT), 8), Ok(5));
    assert_eq!(m.jit_slot(AT), (true, AT, NO_PAGE));
    m.jit_write_value(GuestAddr(AT), 8, 6).unwrap();
    m.jit_write_value(GuestAddr(AT), 8, 7).unwrap();
    assert_eq!(m.jit_slot(AT), (true, AT, AT));
    assert_eq!(m.read_u64(GuestAddr(AT)), Ok(7));
}

#[test]
fn a_userfaultfd_write_protected_page_is_not_written_through_its_slot() {
    let m = space(Prot::READ_WRITE);
    m.jit_write_value(GuestAddr(AT), 8, 5).unwrap();
    let view = m.view();
    view.userfault_register(AT, AT + PAGE_SIZE, 7, Userfault::WP)
        .unwrap();
    view.userfault_write_protect(AT, AT + PAGE_SIZE, true)
        .unwrap();
    assert_eq!(m.jit_read_value(GuestAddr(AT), 8), Ok(5));
    assert_eq!(m.jit_slot(AT), (true, AT, NO_PAGE));
    let fault = m.jit_write_value(GuestAddr(AT), 8, 6).unwrap_err();
    assert!(fault.write);
    assert_eq!(m.jit_slot(AT), (true, AT, NO_PAGE));
    view.userfault_write_protect(AT, AT + PAGE_SIZE, false)
        .unwrap();
    m.jit_write_value(GuestAddr(AT), 8, 6).unwrap();
    m.jit_write_value(GuestAddr(AT), 8, 7).unwrap();
    assert_eq!(m.jit_slot(AT), (true, AT, AT));
}

#[test]
fn another_space_never_holds_the_slots_of_this_one() {
    let m = space(Prot::READ_WRITE);
    m.jit_write_value(GuestAddr(AT), 8, 5).unwrap();
    let other = space(Prot::READ_WRITE);
    assert!(!other.jit_slot(AT).0);
    other.jit_read_value(GuestAddr(AT), 8).unwrap();
    assert!(!m.jit_slot(AT).0);
}

#[test]
fn a_thread_whose_tlb_is_in_use_gets_slots_that_hold_nothing() {
    let m = space(Prot::READ_WRITE);
    let access = THREAD_TLB.with(|cell| {
        let _in_use = cell.borrow_mut();
        m.jit_access()
    });
    assert_eq!(access.slots, NO_JIT_SLOTS.as_ptr().addr() as u64);
    assert!(
        NO_JIT_SLOTS
            .iter()
            .all(|s| s.epoch.load(Ordering::Relaxed) == 0)
    );
    assert_eq!(m.jit_access().epoch, address_of(&m.code.epoch));
}
