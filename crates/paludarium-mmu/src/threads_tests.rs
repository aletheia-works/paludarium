use super::*;
const DATA: GuestAddr = GuestAddr(0x600000);
fn memory() -> AddressSpace {
    let m = AddressSpace::new();
    m.map_shared(Some(DATA), 4096, Prot::READ_WRITE, MappingKind::Anonymous)
        .unwrap();
    m
}
#[test]
fn shared_break_grows() {
    let mut m = memory();
    m.set_initial_break(GuestAddr(0x700000));
    assert_eq!(m.set_break_shared(GuestAddr(0x701000)), GuestAddr(0x701000));
}
#[test]
fn shared_break_invalid_preserves() {
    let mut m = memory();
    m.set_initial_break(GuestAddr(0x700000));
    assert_eq!(m.set_break_shared(DATA), GuestAddr(0x700000));
}
#[test]
fn shared_protect_observed() {
    let m = memory();
    m.protect_shared(DATA, 4096, Prot::READ).unwrap();
    assert!(m.write(DATA, &[1]).is_err());
}
#[test]
fn shared_unmap_observed() {
    let m = memory();
    m.unmap_shared(DATA, 4096).unwrap();
    assert!(m.read(DATA, &mut [0]).is_err());
}
#[test]
fn distinct_spaces_have_distinct_keys() {
    assert_ne!(memory().id(), memory().id());
}
#[test]
fn atomics_share_normal_view() {
    let m = memory();
    m.atomic(DATA, AtomicWidth::W32, AtomicOp::Add(1)).unwrap();
    let mut b = [0; 4];
    m.read(DATA, &mut b).unwrap();
    assert_eq!(b, 1u32.to_le_bytes());
}
