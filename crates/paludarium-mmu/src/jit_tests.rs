use super::*;

fn code() -> AddressSpace {
    let mut memory = AddressSpace::new();
    memory
        .map(
            Some(GuestAddr(4096)),
            8192,
            Prot::from_bits(7).unwrap(),
            MappingKind::ElfSegment,
        )
        .unwrap();
    memory
        .write_initial(GuestAddr(4096), &[0x90, 0xc3])
        .unwrap();
    memory
}

#[test]
fn snapshot_captures_bytes_and_epoch_together() {
    let memory = code();
    let snapshot = memory.code_snapshot(GuestAddr(4096), 2).unwrap();
    assert_eq!(snapshot.bytes, [0x90, 0xc3]);
    assert_eq!(
        memory.with_code_epoch(snapshot.address_space, snapshot.generation, || 42),
        Some(42)
    );
}

#[test]
fn snapshot_allocation_is_bounded() {
    assert_eq!(
        code()
            .code_snapshot(GuestAddr(4096), usize::MAX)
            .unwrap()
            .bytes
            .len(),
        960
    );
}

#[test]
fn snapshot_fetch_requires_execute_permission() {
    let mut memory = code();
    memory
        .protect(GuestAddr(4096), 8192, Prot::READ_WRITE)
        .unwrap();
    assert!(memory.code_snapshot(GuestAddr(4096), 2).is_err());
}

#[test]
fn write_rejects_captured_epoch() {
    let memory = code();
    let snapshot = memory.code_snapshot(GuestAddr(4096), 2).unwrap();
    memory.write(GuestAddr(4096), &[0xcc]).unwrap();
    assert_eq!(
        memory.with_code_epoch(snapshot.address_space, snapshot.generation, || panic!(
            "stale execution"
        )),
        None::<()>
    );
}

#[test]
fn different_address_space_rejects_epoch() {
    let first = code();
    let snapshot = first.code_snapshot(GuestAddr(4096), 2).unwrap();
    assert_eq!(
        code().with_code_epoch(snapshot.address_space, snapshot.generation, || 42),
        None
    );
}

#[test]
fn snapshot_crosses_page_boundary() {
    let memory = code();
    memory.write(GuestAddr(8191), &[0x48, 0x89, 0xc0]).unwrap();
    assert_eq!(
        memory.code_snapshot(GuestAddr(8191), 3).unwrap().bytes,
        [0x48, 0x89, 0xc0]
    );
}

#[test]
fn private_data_write_preserves_code_epoch() {
    let mut memory = code();
    memory
        .map(
            Some(GuestAddr(16384)),
            4096,
            Prot::READ_WRITE,
            MappingKind::Stack,
        )
        .unwrap();
    let epoch = memory.code_epoch();
    memory.write(GuestAddr(16384), &[42]).unwrap();
    assert_eq!(memory.code_epoch(), epoch);
}

#[test]
fn protect_rejects_previous_execution_epoch() {
    let mut memory = code();
    let snapshot = memory.code_snapshot(GuestAddr(4096), 2).unwrap();
    memory
        .protect(GuestAddr(4096), 8192, Prot::READ_WRITE)
        .unwrap();
    assert_eq!(
        memory.with_code_epoch(snapshot.address_space, snapshot.generation, || 42),
        None
    );
    assert!(memory.code_snapshot(GuestAddr(4096), 2).is_err());
}

#[test]
fn unmap_remap_same_address_rejects_previous_execution_epoch() {
    let mut memory = code();
    let snapshot = memory.code_snapshot(GuestAddr(4096), 2).unwrap();
    memory.unmap(GuestAddr(4096), 8192).unwrap();
    memory
        .map(
            Some(GuestAddr(4096)),
            8192,
            Prot::READ_EXEC,
            MappingKind::ElfSegment,
        )
        .unwrap();
    memory.write_initial(GuestAddr(4096), &[0xcc]).unwrap();
    assert_eq!(
        memory.with_code_epoch(snapshot.address_space, snapshot.generation, || 42),
        None
    );
    assert_eq!(
        memory.code_snapshot(GuestAddr(4096), 1).unwrap().bytes,
        [0xcc]
    );
}

#[test]
fn epoch_guard_serializes_another_workers_write() {
    use std::sync::{Arc, mpsc};
    let memory = Arc::new(code());
    let snapshot = memory.code_snapshot(GuestAddr(4096), 2).unwrap();
    let (entered_send, entered_receive) = mpsc::channel();
    let (finished_send, finished_receive) = mpsc::channel();
    let worker_memory = memory.clone();
    let worker = std::thread::spawn(move || {
        entered_receive.recv().unwrap();
        worker_memory.write(GuestAddr(4096), &[0xcc]).unwrap();
        finished_send.send(()).unwrap();
    });
    memory
        .with_code_epoch(snapshot.address_space, snapshot.generation, || {
            entered_send.send(()).unwrap();
            assert!(
                finished_receive
                    .recv_timeout(std::time::Duration::from_millis(30))
                    .is_err()
            );
        })
        .unwrap();
    finished_receive
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    worker.join().unwrap();
    assert_eq!(
        memory.with_code_epoch(snapshot.address_space, snapshot.generation, || 42),
        None
    );
}
