//! U2 native expectations are generated on every execution.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/instructions.rs"]
mod support;
use paludarium_harness::{compare, ensure_guests_built, guest_dir, run_emulated, run_native};
static GUESTS: std::sync::OnceLock<()> = std::sync::OnceLock::new();
macro_rules! cases {
    ($($name:ident => $binary:literal),* $(,)?) => {$(
        #[test]
        fn $name() {
            if std::env::var("PALUDARIUM_INSTRUCTIONS_CHILD").is_err() {
                GUESTS.get_or_init(|| { ensure_guests_built().expect("build native guests"); });
            }
            support::bounded(stringify!($name), || {
                let program=guest_dir().join($binary);
                let native=run_native(&program,$binary,&[]).expect("native execution");
                let (emulated,stop)=run_emulated(&program,$binary,&[]).expect("emulator execution");
                compare(&native,&emulated).unwrap_or_else(|error|panic!("{}: {error}; stop={stop:?}",stringify!($name)));
            });
        }
    )*};
}
cases!(
    instructions_alu => "insn-alu", instructions_cmptest => "insn-cmptest",
    instructions_incdec => "insn-incdec", instructions_shift => "insn-shift",
    instructions_muldiv => "insn-muldiv", instructions_bt => "insn-bt",
    instructions_set => "insn-cond-set", instructions_cmov => "insn-cond-cmov",
    instructions_branch => "insn-cond-jcc", instructions_move => "insn-mov",
    instructions_string => "insn-string", instructions_atomic => "insn-atomic",
    integer_forms => "insn-forms-integer",
    string_forms => "insn-forms-string",
    atomic_pairs => "insn-forms-pairs",
    control_forms => "insn-forms-control",
    bmi_forms => "insn-forms-bmi",
    frame_forms => "insn-forms-frame",
    frame_caller_boundaries => "insn-forms-frame-boundary",
    segment_atomic_forms => "insn-forms-segment-atomic",
);

fn cmps_fault(name: &'static str, completed: u64) {
    support::bounded(name, || {
        use paludarium_cpu::{CpuState, RepFaultFlags, reg};
        use paludarium_mmu::{AddressSpace, MappingKind, Prot};
        use paludarium_types::{ExitReason, GuestAddr};
        let root = paludarium_harness::workspace_root();
        let dir = paludarium_harness::guest_dir()
            .join("instructions")
            .join(name);
        let built = std::process::Command::new("bash")
            .arg(root.join("tests/guests/instructions/build.sh"))
            .arg(&dir)
            .status()
            .expect("build native fault observer");
        assert!(built.success());
        let scas = name.contains("scas");
        let scenario = match (scas, completed) {
            (false, 0) => "cmps-start",
            (false, 17) => "cmps-partial",
            (false, _) => "cmps-budget",
            (true, 0) => "scas-start",
            (true, 17) => "scas-partial",
            (true, _) => "scas-budget",
        };
        let native =
            paludarium_harness::run_native(&dir.join("observe"), "observe", &[scenario.into()])
                .expect("native signal observation");
        assert_eq!(native.status, paludarium::ExitStatus::Exited(0));
        println!("{name}: {}", String::from_utf8_lossy(&native.stderr));
        // Native expectations differ by vendor. Select an explicit guest CPU
        // model here; production execution never detects the host vendor.
        let vendor = String::from_utf8_lossy(&native.stderr);
        let policy = match vendor
            .lines()
            .find_map(|line| line.strip_prefix("cpu_vendor="))
        {
            Some("GenuineIntel") => RepFaultFlags::RestoreInitial,
            Some("AuthenticAMD") => RepFaultFlags::PreserveCompleted,
            other => panic!("unsupported native REP fault-flags baseline: {other:?}"),
        };
        let mut memory = AddressSpace::new();
        for (address, length, protection) in [
            (0x10000, 4096, Prot::READ_EXEC),
            (0x40000000, 4096, Prot::READ_WRITE),
            (0x50000000, if scas { 4096 } else { 8192 }, Prot::READ_WRITE),
        ] {
            memory
                .map(
                    Some(GuestAddr(address)),
                    length,
                    protection,
                    MappingKind::Anonymous,
                )
                .unwrap();
        }
        memory
            .write_initial(
                GuestAddr(0x10000),
                if scas { &[0xf2, 0xae] } else { &[0xf3, 0xa6] },
            )
            .unwrap();
        memory.write(GuestAddr(0x40000000), &[0x31; 4096]).unwrap();
        memory
            .write(
                GuestAddr(0x50000000),
                &vec![0x31; if scas { 4096 } else { 8192 }],
            )
            .unwrap();
        let mut state = CpuState::new(GuestAddr(0x10000), GuestAddr(0));
        state.rep_fault_flags = policy;
        state.rflags = 0x8d7;
        state.gpr[reg::RAX] = 0x32;
        state.gpr[reg::RCX] = completed + 1;
        state.gpr[reg::RSI] = 0x40001000 - completed;
        state.gpr[reg::RDI] = 0x50001000 - completed;
        if completed == 4096 {
            assert!(matches!(
                paludarium_cpu::run(&mut state, &memory, 1),
                ExitReason::BudgetExhausted { .. }
            ));
            assert_eq!(state.gpr[reg::RCX], 1);
        }
        let reason = paludarium_cpu::run(&mut state, &memory, 1);
        let (rip, address) = match reason {
            ExitReason::PageFault {
                rip,
                addr,
                write: false,
                ..
            } => (rip, addr),
            other => panic!("{name}: expected native SIGSEGV, got {other:?}"),
        };
        let actual = format!(
            "signal=11 rip_delta={} count={} src={} dst={} flags={:x} addr={:x}\n",
            rip.0 - 0x10000,
            state.gpr[reg::RCX],
            state.gpr[reg::RSI] - 0x40000000,
            state.gpr[reg::RDI] - 0x50000000,
            state.rflags & 0xcd5,
            address.0
        );
        assert_eq!(String::from_utf8(native.stdout).unwrap(), actual);
    });
}

#[test]
fn cmps_fault_start() {
    cmps_fault("cmps_fault_start", 0);
}
#[test]
fn cmps_fault_partial() {
    cmps_fault("cmps_fault_partial", 17);
}
#[test]
fn cmps_fault_budget() {
    cmps_fault("cmps_fault_budget", 4096);
}
#[test]
fn scas_fault_start() {
    cmps_fault("scas_fault_start", 0);
}
#[test]
fn scas_fault_partial() {
    cmps_fault("scas_fault_partial", 17);
}
#[test]
fn scas_fault_budget() {
    cmps_fault("scas_fault_budget", 4096);
}

fn atomic_fault(name: &'static str, scenario: &'static str, misaligned: bool, cross: bool) {
    support::bounded(name, || {
        use paludarium_cpu::{CpuState, reg};
        use paludarium_mmu::{AddressSpace, MappingKind, Prot};
        use paludarium_types::{ExitReason, GuestAddr};
        let dir = guest_dir().join("instructions").join(name);
        assert!(
            std::process::Command::new("bash")
                .arg(
                    paludarium_harness::workspace_root().join("tests/guests/instructions/build.sh")
                )
                .arg(&dir)
                .status()
                .unwrap()
                .success()
        );
        let native = run_native(&dir.join("observe"), "observe", &[scenario.into()]).unwrap();
        assert_eq!(native.status, paludarium::ExitStatus::Exited(0));
        println!("{name}: {}", String::from_utf8_lossy(&native.stderr));
        let mut memory = AddressSpace::new();
        memory
            .map(
                Some(GuestAddr(0x10000)),
                4096,
                Prot::READ_EXEC,
                MappingKind::Anonymous,
            )
            .unwrap();
        memory
            .map(
                Some(GuestAddr(0x40000000)),
                8192,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        let address = 0x40000000
            + if misaligned {
                1
            } else if cross {
                4093
            } else {
                0
            };
        let segmented = scenario.contains("gs");
        let mut code = Vec::new();
        if segmented {
            code.push(0x65);
            memory
                .map(
                    Some(GuestAddr(0x30000000)),
                    4096,
                    Prot::READ_WRITE,
                    MappingKind::Anonymous,
                )
                .unwrap();
            memory.write_u64(GuestAddr(0x30000000), 7).unwrap();
        }
        code.extend_from_slice(if misaligned {
            &[0xf0, 0x48, 0x0f, 0xc7, 0x0f]
        } else {
            &[0xf0, 0x48, 0x0f, 0xb1, 0x1f]
        });
        memory.write_initial(GuestAddr(0x10000), &code).unwrap();
        if !misaligned {
            memory.write_u64(GuestAddr(address), 7).unwrap();
            memory
                .protect(
                    GuestAddr(if cross { 0x40001000 } else { 0x40000000 }),
                    4096,
                    Prot::READ,
                )
                .unwrap();
        }
        let mut state = CpuState::new(GuestAddr(0x10000), GuestAddr(0));
        state.rflags = 0x8d7;
        state.gpr[reg::RDI] = address;
        if segmented {
            state.gpr[reg::RDI] = 0x30000000;
            state.gs_base = address - 0x30000000;
        }
        state.gpr[reg::RBX] = 9;
        state.gpr[reg::RCX] = 10;
        let before = state.clone();
        let mut bytes = [0; 8192];
        memory.read(GuestAddr(0x40000000), &mut bytes).unwrap();
        let reason = paludarium_cpu::run(&mut state, &memory, 1);
        let fault_address = match reason {
            ExitReason::GeneralProtection { .. } if misaligned => 0,
            ExitReason::PageFault {
                addr, write: true, ..
            } if !misaligned => addr.0,
            other => panic!("expected native atomic fault: {other:?}"),
        };
        assert_eq!(state, before, "fault commits no register/flags");
        let mut after = [0; 8192];
        memory.read(GuestAddr(0x40000000), &mut after).unwrap();
        assert_eq!(bytes, after);
        if segmented {
            assert_eq!(memory.read_u64(GuestAddr(0x30000000)).unwrap(), 7);
        }
        let actual = format!(
            "signal=11 rip_delta=0 rax={:x} rdx={:x} flags={:x} addr={:x}\n",
            state.gpr[reg::RAX],
            state.gpr[reg::RDX],
            state.rflags & 0xcd5,
            fault_address
        );
        assert_eq!(String::from_utf8(native.stdout).unwrap(), actual);
    });
}
#[test]
fn atomic_gs_readonly_failed_cmpxchg() {
    atomic_fault(
        "atomic_gs_readonly_failed_cmpxchg",
        "atomic-gs-readonly",
        false,
        false,
    );
}
#[test]
fn atomic_gs_misaligned_cmpxchg16b() {
    atomic_fault(
        "atomic_gs_misaligned_cmpxchg16b",
        "atomic-gs-misaligned",
        true,
        false,
    );
}
#[test]
fn atomic_readonly_failed_cmpxchg() {
    atomic_fault(
        "atomic_readonly_failed_cmpxchg",
        "atomic-readonly",
        false,
        false,
    );
}
#[test]
fn atomic_cross_page_readonly() {
    atomic_fault("atomic_cross_page_readonly", "atomic-cross", false, true);
}
#[test]
fn atomic_misaligned_cmpxchg16b() {
    atomic_fault(
        "atomic_misaligned_cmpxchg16b",
        "atomic-misaligned",
        true,
        false,
    );
}

fn divide_fault(name: &'static str, scenario: &'static str, signed: bool, overflow: bool) {
    support::bounded(name, || {
        use paludarium_cpu::{CpuState, reg};
        use paludarium_mmu::{AddressSpace, MappingKind, Prot};
        use paludarium_types::{ExitReason, GuestAddr};
        let root = paludarium_harness::workspace_root();
        let dir = paludarium_harness::guest_dir()
            .join("instructions")
            .join(name);
        assert!(
            std::process::Command::new("bash")
                .arg(root.join("tests/guests/instructions/build.sh"))
                .arg(&dir)
                .status()
                .unwrap()
                .success()
        );
        let native =
            paludarium_harness::run_native(&dir.join("observe"), "observe", &[scenario.into()])
                .unwrap();
        assert_eq!(native.status, paludarium::ExitStatus::Exited(0));
        println!("{name}: {}", String::from_utf8_lossy(&native.stderr));
        let mut memory = AddressSpace::new();
        memory
            .map(
                Some(GuestAddr(0x10000)),
                4096,
                Prot::READ_EXEC,
                MappingKind::Anonymous,
            )
            .unwrap();
        memory
            .write_initial(
                GuestAddr(0x10000),
                &[0x48, 0xf7, if signed { 0xfb } else { 0xf3 }],
            )
            .unwrap();
        let mut state = CpuState::new(GuestAddr(0x10000), GuestAddr(0));
        state.rflags = 0x8d7;
        state.gpr[reg::RAX] = if overflow {
            if signed { 1 << 63 } else { 0 }
        } else {
            123
        };
        state.gpr[reg::RDX] = if overflow {
            if signed { u64::MAX } else { 1 }
        } else {
            0
        };
        state.gpr[reg::RBX] = if overflow {
            if signed { u64::MAX } else { 1 }
        } else {
            0
        };
        let before = state.clone();
        let reason = paludarium_cpu::run(&mut state, &memory, 1);
        let rip = match reason {
            ExitReason::ArithmeticFault { rip } => rip,
            other => panic!("expected ArithmeticFault, got {other:?}"),
        };
        assert_eq!(
            state, before,
            "fault must not commit quotient/remainder/flags"
        );
        let actual = format!(
            "signal=8 rip_delta={} rax={:x} rdx={:x} flags={:x}\n",
            rip.0 - 0x10000,
            state.gpr[reg::RAX],
            state.gpr[reg::RDX],
            state.rflags & 0xcd5
        );
        assert_eq!(String::from_utf8(native.stdout).unwrap(), actual);
    });
}
#[test]
fn div_zero() {
    divide_fault("div_zero", "div-zero", false, false);
}
#[test]
fn div_overflow() {
    divide_fault("div_overflow", "div-overflow", false, true);
}
#[test]
fn idiv_zero() {
    divide_fault("idiv_zero", "idiv-zero", true, false);
}
#[test]
fn idiv_overflow() {
    divide_fault("idiv_overflow", "idiv-overflow", true, true);
}

#[test]
fn pop_fault_preserves_stack_and_flags() {
    support::bounded("pop_fault_preserves_stack_and_flags", || {
        use paludarium_cpu::{CpuState, reg};
        use paludarium_mmu::{AddressSpace, MappingKind, Prot};
        use paludarium_types::{ExitReason, GuestAddr};
        let dir = paludarium_harness::guest_dir().join("instructions/pop-fault");
        assert!(
            std::process::Command::new("bash")
                .arg(
                    paludarium_harness::workspace_root().join("tests/guests/instructions/build.sh")
                )
                .arg(&dir)
                .status()
                .unwrap()
                .success()
        );
        let native =
            paludarium_harness::run_native(&dir.join("observe"), "observe", &["pop-fault".into()])
                .unwrap();
        assert_eq!(native.status, paludarium::ExitStatus::Exited(0));
        println!("{}", String::from_utf8_lossy(&native.stderr));
        let mut memory = AddressSpace::new();
        memory
            .map(
                Some(GuestAddr(0x10000)),
                4096,
                Prot::READ_EXEC,
                MappingKind::Anonymous,
            )
            .unwrap();
        memory
            .map(
                Some(GuestAddr(0x40000000)),
                4096,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        memory
            .write_initial(GuestAddr(0x10000), &[0x8f, 0x07])
            .unwrap();
        memory.write_u64(GuestAddr(0x40000ff8), 123).unwrap();
        let mut state = CpuState::new(GuestAddr(0x10000), GuestAddr(0x40000ff8));
        state.rflags = 0x8d7;
        state.gpr[reg::RDI] = 0x50000000;
        let before = state.clone();
        let reason = paludarium_cpu::run(&mut state, &memory, 1);
        let rip = match reason {
            ExitReason::PageFault {
                rip, write: true, ..
            } => rip,
            other => panic!("{other:?}"),
        };
        let actual = format!(
            "signal=11 rip_delta={} rsp={} flags={:x}\n",
            rip.0 - 0x10000,
            state.gpr[reg::RSP] - 0x40000000,
            state.rflags & 0xcd5
        );
        assert_eq!(String::from_utf8(native.stdout).unwrap(), actual);
        assert_eq!(state, before);
        assert_eq!(memory.read_u64(GuestAddr(0x40000ff8)).unwrap(), 123);
    });
}

fn enter_fault(name: &'static str, allocation: bool) {
    support::bounded(name, || {
        use paludarium_cpu::{CpuState, reg};
        use paludarium_mmu::{AddressSpace, MappingKind, Prot};
        use paludarium_types::{ExitReason, GuestAddr};
        let dir = guest_dir().join("instructions").join(name);
        assert!(
            std::process::Command::new("bash")
                .arg(
                    paludarium_harness::workspace_root().join("tests/guests/instructions/build.sh")
                )
                .arg(&dir)
                .status()
                .unwrap()
                .success()
        );
        let scenario = if name == "enter_word_fault" {
            "enter-word"
        } else if allocation {
            "enter-allocation"
        } else {
            "enter-chain"
        };
        let native = run_native(&dir.join("observe"), "observe", &[scenario.into()]).unwrap();
        assert_eq!(native.status, paludarium::ExitStatus::Exited(0));
        println!(
            "{name}: {}{}",
            String::from_utf8_lossy(&native.stdout),
            String::from_utf8_lossy(&native.stderr)
        );
        let mut memory = AddressSpace::new();
        memory
            .map(
                Some(GuestAddr(0x10000)),
                4096,
                Prot::READ_EXEC,
                MappingKind::Anonymous,
            )
            .unwrap();
        memory
            .map(
                Some(GuestAddr(0x40000000)),
                4096,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        let bytes: &[u8] = if name == "enter_word_fault" {
            &[0x66, 0xc8, 24, 0, 6]
        } else if allocation {
            &[0xc8, 0, 0x20, 0]
        } else {
            &[0xc8, 24, 0, 3]
        };
        memory.write_initial(GuestAddr(0x10000), bytes).unwrap();
        for i in 0..512 {
            memory.write_u64(GuestAddr(0x40000000 + i * 8), 42).unwrap();
        }
        // Native pushfq/popfq before ENTER leaves the same stack bytes.
        memory.write_u64(GuestAddr(0x40000ff8), 0x8d7).unwrap();
        let mut state = CpuState::new(GuestAddr(0x10000), GuestAddr(0x40001000));
        state.gpr[reg::RBP] = 0x40000008;
        state.rflags = 0x8d7;
        let (rip, addr) = match paludarium_cpu::run(&mut state, &memory, 1) {
            ExitReason::PageFault { rip, addr, .. } => (rip, addr),
            other => panic!("{name}: expected fault, got {other:?}"),
        };
        let actual = format!(
            "signal=11 rip_delta={} rsp={} rbp={} flags={:x} addr={:x} m0={:x} m1={:x}\n",
            rip.0 - 0x10000,
            state.gpr[reg::RSP] - 0x40000000,
            state.gpr[reg::RBP] - 0x40000000,
            state.rflags & 0xcd5,
            addr.0,
            memory.read_u64(GuestAddr(0x40000ff8)).unwrap(),
            memory.read_u64(GuestAddr(0x40000ff0)).unwrap()
        );
        assert_eq!(String::from_utf8(native.stdout).unwrap(), actual);
    });
}
#[test]
fn enter_chain_fault() {
    enter_fault("enter_chain_fault", false);
}
#[test]
fn enter_allocation_fault() {
    enter_fault("enter_allocation_fault", true);
}

#[test]
fn enter_word_fault() {
    enter_fault("enter_word_fault", false);
}
