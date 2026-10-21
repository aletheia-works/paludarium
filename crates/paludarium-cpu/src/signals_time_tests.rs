use super::*;
#[test]
fn u4_fetch_unmapped_captures_fault_metadata() {
    let (mut s, m) = fixture(&[0x90]);
    s.rip = GuestAddr(0x70000000);
    assert!(matches!(
        step(&mut s, &m),
        Err(ExitReason::PageFault {
            fetch: true,
            mapped: false,
            present: false,
            ..
        })
    ));
}
#[test]
fn u4_fetch_nonexecute_resident_captures_present() {
    let (mut s, m) = fixture(&[0x90]);
    m.write(GuestAddr(0x40000000), &[0xc3]).unwrap();
    s.rip = GuestAddr(0x40000000);
    assert!(matches!(
        step(&mut s, &m),
        Err(ExitReason::PageFault {
            fetch: true,
            mapped: true,
            present: true,
            ..
        })
    ));
}
#[test]
fn u4_write_virgin_readonly_captures_not_present() {
    let (mut s, mut m) = fixture(&[0x88, 0x07]);
    m.protect(GuestAddr(0x40000000), 4096, Prot::READ).unwrap();
    s.gpr[reg::RDI] = 0x40000000;
    assert!(matches!(
        step(&mut s, &m),
        Err(ExitReason::PageFault {
            fetch: false,
            write: true,
            mapped: true,
            present: false,
            ..
        })
    ));
}
#[test]
fn u4_read_populates_zero_page_before_write_fault() {
    let (mut s, mut m) = fixture(&[0x88, 0x07]);
    m.read(GuestAddr(0x40000000), &mut [0]).unwrap();
    m.protect(GuestAddr(0x40000000), 4096, Prot::READ).unwrap();
    s.gpr[reg::RDI] = 0x40000000;
    assert!(matches!(
        step(&mut s, &m),
        Err(ExitReason::PageFault {
            fetch: false,
            write: true,
            mapped: true,
            present: true,
            ..
        })
    ));
}
#[test]
fn u4_partial_instruction_fetch_reports_next_page() {
    let (mut s, m) = fixture(&[0x90]);
    m.write_initial(GuestAddr(0x10fff), &[0x48]).unwrap();
    s.rip = GuestAddr(0x10fff);
    assert!(matches!(
        step(&mut s, &m),
        Err(ExitReason::PageFault {
            addr: GuestAddr(0x11000),
            fetch: true,
            mapped: false,
            present: false,
            ..
        })
    ));
}
