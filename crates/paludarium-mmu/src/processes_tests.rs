#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
fn space() -> AddressSpace {
    let space = AddressSpace::new();
    space
        .map_shared(
            Some(GuestAddr(0x10000)),
            PAGE_SIZE * 2,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
    space
}
#[test]
fn private_copy() {
    let p = space();
    p.write_u64(GuestAddr(0x10000), 7).unwrap();
    let c = p.fork();
    assert_ne!(p.id(), c.id());
    assert_eq!(c.read_u64(GuestAddr(0x10000)), Ok(7));
    c.write_u64(GuestAddr(0x10000), 9).unwrap();
    assert_eq!(p.read_u64(GuestAddr(0x10000)), Ok(7));
}
#[test]
fn shared_lazy_pages() {
    let p = space();
    p.mark_shared(GuestAddr(0x10000), PAGE_SIZE * 2).unwrap();
    let c = p.fork();
    c.write_u64(GuestAddr(0x11000), 9).unwrap();
    assert_eq!(p.read_u64(GuestAddr(0x11000)), Ok(9));
}
#[test]
fn parent_child_writes() {
    let p = space();
    let c = p.fork();
    p.write_u64(GuestAddr(0x10000), 7).unwrap();
    assert_eq!(c.read_u64(GuestAddr(0x10000)), Ok(0));
}
#[test]
fn protections_independent() {
    let p = space();
    let c = p.fork();
    c.protect_shared(GuestAddr(0x10000), PAGE_SIZE, Prot::READ)
        .unwrap();
    assert!(c.write_u64(GuestAddr(0x10000), 1).is_err());
    assert!(p.write_u64(GuestAddr(0x10000), 1).is_ok());
}
#[test]
fn break_cloned() {
    let mut p = space();
    p.set_initial_break(GuestAddr(0x20000));
    p.set_break(GuestAddr(0x22001));
    let c = p.fork();
    assert_eq!(c.current_break(), GuestAddr(0x22001));
    c.set_break_shared(GuestAddr(0x20000));
    assert_eq!(p.current_break(), GuestAddr(0x22001));
}
#[test]
fn unmap_and_remap_detaches_shared() {
    let p = space();
    p.mark_shared(GuestAddr(0x10000), PAGE_SIZE * 2).unwrap();
    let c = p.fork();
    c.unmap_shared(GuestAddr(0x10000), PAGE_SIZE).unwrap();
    c.map_shared(
        Some(GuestAddr(0x10000)),
        PAGE_SIZE,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    c.write_u64(GuestAddr(0x10000), 5).unwrap();
    assert_eq!(p.read_u64(GuestAddr(0x10000)), Ok(0));
    c.write_u64(GuestAddr(0x11000), 8).unwrap();
    assert_eq!(p.read_u64(GuestAddr(0x11000)), Ok(8));
}
#[test]
fn faults_and_shared_atomic() {
    let p = Arc::new(space());
    assert!(p.mark_shared(GuestAddr(0x10001), PAGE_SIZE).is_err());
    p.mark_shared(GuestAddr(0x10000), PAGE_SIZE * 2).unwrap();
    let c = Arc::new(p.fork());
    assert!(c.read_u64(GuestAddr(0)).is_err());
    std::thread::scope(|scope| {
        for s in [p.clone(), c.clone()] {
            scope.spawn(move || {
                for _ in 0..1000 {
                    s.atomic(GuestAddr(0x10000), AtomicWidth::W64, AtomicOp::Add(1))
                        .unwrap();
                }
            });
        }
    });
    assert_eq!(p.read_u64(GuestAddr(0x10000)), Ok(2000));
}
