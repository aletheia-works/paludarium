use super::*;
use paludarium_mmu::{MappingKind, Prot};
use paludarium_types::Error;

const AREA: u64 = 0x10_0000;
const DESCRIPTOR: u64 = AREA + 0x40;
const START: u64 = AREA + 0x100;
const ABORT: u64 = AREA + 0x200;
const SIGNATURE: u32 = 0x5305_3053;

struct TwoCpus;
impl Host for TwoCpus {
    fn read_stdin(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Ok(0)
    }
    fn write_stdout(&self, buf: &[u8]) -> Result<usize, Errno> {
        Ok(buf.len())
    }
    fn write_stderr(&self, buf: &[u8]) -> Result<usize, Errno> {
        Ok(buf.len())
    }
    fn random_bytes(&self, _: &mut [u8]) -> Result<(), Error> {
        Ok(())
    }
    fn cpu_count(&self) -> usize {
        2
    }
}

fn memory() -> AddressSpace {
    let mut mem = AddressSpace::new();
    mem.map(
        Some(GuestAddr(AREA)),
        0x1000,
        Prot::READ_WRITE,
        MappingKind::Anonymous,
    )
    .unwrap();
    mem
}

fn registration() -> Registration {
    Registration {
        address: AREA,
        length: 32,
        signature: SIGNATURE,
    }
}

/// A descriptor of a 0x20-byte section at [`START`] that aborts to
/// [`ABORT`], with the signature before it, named by the area.
fn describe(mem: &AddressSpace, version: u32, flags: u32, abort: u64) {
    let mut bytes = Vec::new();
    bytes.extend(version.to_le_bytes());
    bytes.extend(flags.to_le_bytes());
    bytes.extend(START.to_le_bytes());
    bytes.extend(0x20u64.to_le_bytes());
    bytes.extend(abort.to_le_bytes());
    mem.write(GuestAddr(DESCRIPTOR), &bytes).unwrap();
    mem.write(GuestAddr(ABORT - 4), &SIGNATURE.to_le_bytes())
        .unwrap();
    mem.write(GuestAddr(AREA + 8), &DESCRIPTOR.to_le_bytes())
        .unwrap();
}

fn descriptor(mem: &AddressSpace) -> u64 {
    mem.read_u64(GuestAddr(AREA + 8)).unwrap()
}

#[test]
fn a_thread_in_its_section_goes_on_at_the_abort_handler() {
    let mem = memory();
    describe(&mem, 0, 0, ABORT);
    let mut rip = START + 0x10;
    // Without a preemption, a move or a signal, it goes on where it is.
    assert_eq!(fixup(&mem, &registration(), &mut rip, false), Ok(()));
    assert_eq!((rip, descriptor(&mem)), (START + 0x10, DESCRIPTOR));
    assert_eq!(fixup(&mem, &registration(), &mut rip, true), Ok(()));
    assert_eq!((rip, descriptor(&mem)), (ABORT, 0));
    // The end is past the section, where the descriptor is only cleared.
    describe(&mem, 0, 0, ABORT);
    let mut rip = START + 0x20;
    assert_eq!(fixup(&mem, &registration(), &mut rip, true), Ok(()));
    assert_eq!((rip, descriptor(&mem)), (START + 0x20, 0));
    // With no descriptor, nothing is read.
    assert_eq!(fixup(&mem, &registration(), &mut rip, true), Ok(()));
}

#[test]
fn a_descriptor_is_refused_only_for_a_thread_inside_its_section() {
    let mem = memory();
    // An abort handler inside the section, and another signature before
    // the handler.
    let refused: [(u32, u32, u64, u32); 2] = [(0, 0, START + 4, SIGNATURE), (0, 0, ABORT, 1)];
    for (version, flags, abort, signature) in refused {
        // Outside the section, the descriptor is only cleared, as current
        // Linux reads no more of it than where the section is.
        for outside in [START - 1, START + 0x20, START + 0x40] {
            describe(&mem, version, flags, abort);
            mem.write(GuestAddr(abort - 4), &signature.to_le_bytes())
                .unwrap();
            let mut rip = outside;
            assert_eq!(fixup(&mem, &registration(), &mut rip, true), Ok(()));
            assert_eq!((rip, descriptor(&mem)), (outside, 0));
        }
        describe(&mem, version, flags, abort);
        mem.write(GuestAddr(abort - 4), &signature.to_le_bytes())
            .unwrap();
        let mut rip = START + 2;
        assert_eq!(fixup(&mem, &registration(), &mut rip, true), Err(()));
        assert_eq!(rip, START + 2);
    }
    // Neither the descriptor's version and flags nor the area's own flags
    // are read any more: the section is aborted.
    for (version, flags) in [(1, 0), (0, 1)] {
        describe(&mem, version, flags, ABORT);
        mem.write(GuestAddr(AREA + 16), &2u32.to_le_bytes())
            .unwrap();
        let mut rip = START;
        assert_eq!(fixup(&mem, &registration(), &mut rip, true), Ok(()));
        assert_eq!(rip, ABORT);
    }
}

#[test]
fn a_section_or_descriptor_past_user_space_is_refused_wherever_the_thread_is() {
    let mem = memory();
    let outside = START + 0x40;
    // A section that ends past user space, for a thread past its start.
    describe(&mem, 0, 0, ABORT);
    mem.write(
        GuestAddr(DESCRIPTOR + 16),
        &(TASK_SIZE - 0x10).to_le_bytes(),
    )
    .unwrap();
    assert_eq!(
        fixup(&mem, &registration(), &mut outside.clone(), true),
        Err(())
    );
    // One that starts there.
    describe(&mem, 0, 0, ABORT);
    mem.write(GuestAddr(DESCRIPTOR + 8), &TASK_SIZE.to_le_bytes())
        .unwrap();
    assert_eq!(
        fixup(&mem, &registration(), &mut outside.clone(), true),
        Err(())
    );
    // A descriptor there, and one it cannot read.
    for address in [TASK_SIZE, 0x40_0000] {
        mem.write(GuestAddr(AREA + 8), &address.to_le_bytes())
            .unwrap();
        assert_eq!(
            fixup(&mem, &registration(), &mut outside.clone(), true),
            Err(())
        );
    }
}

#[test]
fn the_area_shows_the_cpu_twice_node_0_and_the_concurrency_id() {
    let mem = memory();
    mem.write(GuestAddr(AREA), &[0xff; 32]).unwrap();
    let on = OnCpu {
        cpu: 3,
        cid: 1,
        runner: 9,
    };
    assert_eq!(update(&mem, &registration(), on), Ok(()));
    let mut bytes = [0; 32];
    mem.read(GuestAddr(AREA), &mut bytes).unwrap();
    assert_eq!(bytes[0..8], [3, 0, 0, 0, 3, 0, 0, 0]);
    assert_eq!(bytes[8..20], [0xff; 12]);
    assert_eq!(bytes[20..28], [0, 0, 0, 0, 1, 0, 0, 0]);
    let elsewhere = Registration {
        address: 0x40_0000,
        ..registration()
    };
    assert_eq!(update(&mem, &elsewhere, on), Err(()));
}

/// Takes a CPU as [`Kernel::take_cpu`] does without waiting: its own first.
fn take(cpus: &Cpus, runner: &Runner) -> bool {
    let me = u64::from(runner.id);
    let mine = runner.cpu.load(Ordering::SeqCst);
    let slots = cpus.slots(&TwoCpus);
    if mine != NONE
        && runner.cid.load(Ordering::SeqCst) != NONE
        && slots[mine as usize]
            .compare_exchange(me, me | RUNNING, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    {
        runner.running.store(true, Ordering::SeqCst);
        return true;
    }
    cpus.take(&TwoCpus, runner, &|_| true)
}

#[test]
fn a_cpu_runs_one_thread_and_is_taken_only_while_its_thread_does_not_run() {
    let cpus = Arc::new(Cpus::default());
    let [a, b, c] = [1, 1, 2].map(|space| cpus.runner(space));
    assert!(take(&cpus, &a) && take(&cpus, &b));
    assert_ne!(a.cpu.load(Ordering::SeqCst), b.cpu.load(Ordering::SeqCst));
    // The threads of one space have their own concurrency IDs, from 0.
    let mut cids = [a.cid.load(Ordering::SeqCst), b.cid.load(Ordering::SeqCst)];
    cids.sort_unstable();
    assert_eq!(cids, [0, 1]);
    assert!(!take(&cpus, &c));
    // A thread that stops running may lose its CPU, and its ID with it.
    a.leave();
    assert!(take(&cpus, &c));
    assert_eq!(c.cpu.load(Ordering::SeqCst), a.cpu.load(Ordering::SeqCst));
    assert_eq!(c.cid.load(Ordering::SeqCst), 0);
    assert_eq!(a.cid.load(Ordering::SeqCst), NONE);
    assert!(!take(&cpus, &a));
    // Once the CPU is left, the thread that had it gets it back, but has
    // moved: it takes it anew.
    c.leave();
    assert!(take(&cpus, &a));
    assert_eq!(a.cid.load(Ordering::SeqCst), 0);
    // Taking back its own CPU, untouched, keeps the thread's ID.
    b.leave();
    let cid = b.cid.load(Ordering::SeqCst);
    assert!(take(&cpus, &b));
    assert_eq!(b.cid.load(Ordering::SeqCst), cid);
    // A dropped runner frees its CPU and its ID.
    drop(b);
    assert!(take(&cpus, &c));
    assert_eq!(c.cid.load(Ordering::SeqCst), 0);
}

#[test]
fn no_two_threads_run_on_one_cpu_at_once() {
    let cpus = Arc::new(Cpus::default());
    let occupied: Arc<[AtomicU32; 2]> = Arc::new([AtomicU32::new(0), AtomicU32::new(0)]);
    let workers: Vec<_> = (0..6)
        .map(|_| {
            let cpus = Arc::clone(&cpus);
            let occupied = Arc::clone(&occupied);
            std::thread::spawn(move || {
                let mut runner = cpus.runner(7);
                let mut ran = 0;
                while ran < 2000 {
                    if !take(&cpus, &runner) {
                        std::thread::yield_now();
                        continue;
                    }
                    let cpu = runner.cpu.load(Ordering::SeqCst) as usize;
                    assert_eq!(occupied[cpu].fetch_add(1, Ordering::SeqCst), 0);
                    assert!(runner.cid.load(Ordering::SeqCst) < 2);
                    occupied[cpu].fetch_sub(1, Ordering::SeqCst);
                    runner.leave();
                    ran += 1;
                    // Threads come and go: a new one may take the CPU of
                    // one going away, and its ID.
                    if ran % 250 == 0 {
                        runner = cpus.runner(7);
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn membarrier_waits_for_the_running_threads_of_the_space_only() {
    let cpus = Arc::new(Cpus::default());
    let [me, other, elsewhere] = [1, 1, 2].map(|space| cpus.runner(space));
    assert!(take(&cpus, &other) && take(&cpus, &elsewhere));
    let cancel = AtomicBool::new(false);
    let leaver = {
        let other = Arc::clone(&other);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            other.leave();
        })
    };
    restart_others(&cpus, &TwoCpus, &cancel, 1, Some(me.id), None);
    assert!(!other.running.load(Ordering::SeqCst));
    leaver.join().unwrap();
    assert_eq!(other.requested.load(Ordering::SeqCst), 1);
    assert_eq!(me.requested.load(Ordering::SeqCst), 0);
    assert_eq!(elsewhere.requested.load(Ordering::SeqCst), 0);
    // A thread on another CPU than the one named is left alone.
    let cpu = elsewhere.cpu.load(Ordering::SeqCst);
    restart_others(&cpus, &TwoCpus, &cancel, 2, None, Some(cpu ^ 1));
    assert_eq!(elsewhere.requested.load(Ordering::SeqCst), 0);
}
