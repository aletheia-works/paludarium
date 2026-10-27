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
#[test]
fn the_meter_counts_written_frames_once_until_they_go() {
    let meter = Arc::new(MemoryMeter::new(PAGE_SIZE * 3));
    let p = space().with_memory_meter(Arc::clone(&meter));
    assert!(Arc::ptr_eq(&p.memory_meter().unwrap(), &meter));
    p.mark_shared(GuestAddr(0x10000), PAGE_SIZE * 2).unwrap();
    p.map_shared(
        Some(GuestAddr(0x20000)),
        PAGE_SIZE,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    // Mapping and reading take nothing; the first write to a page does.
    assert_eq!(p.read_u64(GuestAddr(0x10000)), Ok(0));
    assert_eq!(meter.used(), 0);
    p.write_u64(GuestAddr(0x10000), 7).unwrap();
    p.write_u64(GuestAddr(0x10008), 8).unwrap();
    p.write_u64(GuestAddr(0x20000), 1).unwrap();
    assert_eq!(meter.used(), PAGE_SIZE * 2);
    // fork shares both frames: each counts once for both spaces.
    let c = p.fork();
    assert_eq!(meter.used(), PAGE_SIZE * 2);
    c.write_u64(GuestAddr(0x10000), 3).unwrap();
    assert_eq!(p.read_u64(GuestAddr(0x10000)), Ok(3));
    // The first write to the private frame copies it for the writer.
    c.write_u64(GuestAddr(0x20000), 4).unwrap();
    assert_eq!(meter.used(), PAGE_SIZE * 3);
    assert_eq!(p.read_u64(GuestAddr(0x20000)), Ok(1));
    // No room is left for a new frame: the write faults and marks the
    // space that made it, once.
    assert_eq!(
        p.write_u64(GuestAddr(0x11000), 2),
        Err(Fault {
            addr: GuestAddr(0x11000),
            write: true,
            fetch: false,
            mapped: true,
            present: false,
            bus: false,
        })
    );
    assert!(p.take_out_of_memory());
    assert!(!p.take_out_of_memory());
    assert!(!c.take_out_of_memory());
    // Frames go back when the last space holding them lets them go.
    drop(c);
    assert_eq!(meter.used(), PAGE_SIZE * 2);
    p.write_u64(GuestAddr(0x11000), 2).unwrap();
    assert_eq!(meter.used(), PAGE_SIZE * 3);
    p.unmap_shared(GuestAddr(0x20000), PAGE_SIZE).unwrap();
    assert_eq!(meter.used(), PAGE_SIZE * 2);
}
#[test]
fn a_fork_shares_private_frames_until_either_space_writes() {
    let meter = Arc::new(MemoryMeter::new(PAGE_SIZE * 3));
    let p = space().with_memory_meter(Arc::clone(&meter));
    p.write_u64(GuestAddr(0x10000), 1).unwrap();
    p.write_u64(GuestAddr(0x11000), 2).unwrap();
    // The frames do not fit twice, but a fork copies none of them.
    let c = p.fork();
    assert_eq!(meter.used(), PAGE_SIZE * 2);
    assert_eq!(c.read_u64(GuestAddr(0x11000)), Ok(2));
    // A write copies the frame it changes; once the other space has its
    // own copy, the last holder writes the frame in place.
    c.write_u64(GuestAddr(0x10000), 3).unwrap();
    assert_eq!(meter.used(), PAGE_SIZE * 3);
    p.write_u64(GuestAddr(0x10000), 4).unwrap();
    assert_eq!(meter.used(), PAGE_SIZE * 3);
    assert_eq!(c.read_u64(GuestAddr(0x10000)), Ok(3));
    // Without room for a copy, the write faults; the other space can
    // still write the frame it then holds alone.
    assert!(p.write_u64(GuestAddr(0x11000), 5).is_err());
    assert!(p.take_out_of_memory());
    drop(c);
    p.write_u64(GuestAddr(0x11000), 5).unwrap();
    assert_eq!(meter.used(), PAGE_SIZE * 2);
    assert_eq!(p.read_u64(GuestAddr(0x10000)), Ok(4));
}
