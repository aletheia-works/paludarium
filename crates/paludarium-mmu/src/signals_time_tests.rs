#[test]
fn u4_memory_page_rounding() {
    let mut m = AddressSpace::new();
    m.map(
        Some(GuestAddr(0x10000)),
        4097,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    m.write(GuestAddr(0x11fff), &[42]).unwrap();
    assert!(m.write(GuestAddr(0x12000), &[1]).is_err());
}
#[test]
fn u4_memory_overflow_preserves_mapping() {
    let mut m = memory(1);
    m.write(GuestAddr(0x10000), &[41]).unwrap();
    assert!(m.unmap(GuestAddr(0x10000), u64::MAX).is_err());
    let mut b = [0];
    m.read(GuestAddr(0x10000), &mut b).unwrap();
    assert_eq!(b, [41]);
}
#[test]
fn u4_memory_protection_transition() {
    let mut m = memory(1);
    m.protect(GuestAddr(0x10000), 4096, Prot::READ).unwrap();
    assert!(m.write(GuestAddr(0x10000), &[1]).is_err());
    m.protect(GuestAddr(0x10000), 4096, Prot::READ_WRITE)
        .unwrap();
    m.write(GuestAddr(0x10000), &[1]).unwrap();
}
#[test]
fn u4_memory_unmap_holes() {
    let mut m = memory(3);
    m.unmap(GuestAddr(0x11000), 4096).unwrap();
    m.unmap(GuestAddr(0x10000), 12288).unwrap();
    assert_eq!(m.mappings().count(), 0);
}
#[test]
fn u4_memory_overlap_rejected_without_write() {
    let mut m = memory(1);
    m.write(GuestAddr(0x10000), &[41]).unwrap();
    assert_eq!(
        m.map(
            Some(GuestAddr(0x10000)),
            4096,
            Prot::READ,
            MappingKind::Anonymous
        ),
        Err(Errno::EEXIST)
    );
    let mut b = [0];
    m.read(GuestAddr(0x10000), &mut b).unwrap();
    assert_eq!(b, [41]);
}
#[test]
fn u4_memory_reused_page_zeroed() {
    let mut m = memory(1);
    m.write(GuestAddr(0x10000), &[41]).unwrap();
    m.unmap(GuestAddr(0x10000), 4096).unwrap();
    m.map(
        Some(GuestAddr(0x10000)),
        4096,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    let mut b = [99];
    m.read(GuestAddr(0x10000), &mut b).unwrap();
    assert_eq!(b, [0]);
}
#[test]
fn u4_memory_brk_shrink_and_regrow() {
    let mut m = AddressSpace::new();
    m.set_initial_break(GuestAddr(0x20000));
    assert_eq!(m.set_break(GuestAddr(0x22000)), GuestAddr(0x22000));
    m.write(GuestAddr(0x21000), &[41]).unwrap();
    assert_eq!(m.set_break(GuestAddr(0x20000)), GuestAddr(0x20000));
    assert_eq!(m.set_break(GuestAddr(0x22000)), GuestAddr(0x22000));
    let mut b = [99];
    m.read(GuestAddr(0x21000), &mut b).unwrap();
    assert_eq!(b, [0]);
}
#[test]
fn u4_memory_invalid_range_no_panic() {
    let mut m = memory(1);
    assert!(
        m.map(
            Some(GuestAddr(USER_ADDRESS_LIMIT - 4096)),
            8192,
            Prot::READ,
            MappingKind::Anonymous
        )
        .is_err()
    );
    assert!(m.unmap(GuestAddr(0x10001), 4096).is_err());
}

#[test]
fn u4_memory_partial_protect_invalidates_code_prefix() {
    let mut m = memory(3);
    m.unmap(GuestAddr(0x11000), 4096).unwrap();
    let generation = m.code_generation();
    assert_eq!(
        m.protect(GuestAddr(0x10000), 12288, Prot::NONE),
        Err(Errno::ENOMEM)
    );
    assert!(m.read(GuestAddr(0x10000), &mut [0]).is_err());
    assert!(m.read(GuestAddr(0x12000), &mut [0]).is_ok());
    assert!(m.code_generation() > generation);
}
#[test]
fn u4_memory_fault_snapshot_survives_permission_change() {
    let mut m = memory(1);
    m.protect(GuestAddr(0x10000), 4096, Prot::NONE).unwrap();
    let fault = m.write(GuestAddr(0x10000), &[1]).unwrap_err();
    m.protect(GuestAddr(0x10000), 4096, Prot::READ_WRITE)
        .unwrap();
    m.write(GuestAddr(0x10000), &[1]).unwrap();
    assert!(fault.mapped);
    assert!(!fault.present);
    assert!(!fault.fetch);
    assert!(fault.write);
}
