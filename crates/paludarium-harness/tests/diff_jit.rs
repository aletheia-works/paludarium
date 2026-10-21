//! Fresh x86-64 Linux instruction oracle against interpreter and real wasm JIT.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use paludarium_cpu::{CpuState, reg};
use paludarium_jit::{CodeCache, ExecutionBridge, WasmCodeCache};
use paludarium_mmu::{AddressSpace, MappingKind, Prot};
use paludarium_types::{ExitReason, GuestAddr};
use std::{
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
};

struct NodeBridge;
impl ExecutionBridge for NodeBridge {
    fn execute(&self, _: u32, code: &[u8], state: &mut paludarium_jit::JitState) -> bool {
        let script = "import{readFileSync}from'node:fs';const [code,values]=readFileSync(0,'utf8').trim().split('\\n');const memory=new WebAssembly.Memory({initial:1,maximum:65536,shared:true});const state=new BigUint64Array(memory.buffer,64,50);state.set(values.split(',').map(BigInt));const instance=new WebAssembly.Instance(new WebAssembly.Module(Buffer.from(code,'hex')),{env:{memory}});if(instance.exports.run(64)!==0)process.exit(1);console.log(Array.from(state,String).join(','));";
        let mut child =
            Command::new(std::env::var("PALUDARIUM_TEST_NODE").expect("actual Node executable"))
                .args(["--input-type=module", "-e", script])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
        let hex: String = code.iter().map(|byte| format!("{byte:02x}")).collect();
        let values = state
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        writeln!(child.stdin.take().unwrap(), "{hex}\n{values}").unwrap();
        let output = child.wait_with_output().unwrap();
        if !output.status.success() {
            return false;
        }
        let values = String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .split(',')
            .map(|value| value.parse::<u64>().unwrap())
            .collect::<Vec<_>>();
        state.copy_from_slice(&values);
        true
    }
}

fn field<'a>(row: &'a str, key: &str) -> &'a str {
    let prefix = format!("\"{key}\":\"");
    row.split_once(&prefix)
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap()
}
fn number(row: &str, key: &str) -> u64 {
    u64::from_str_radix(field(row, key), 16).unwrap()
}
/// A JSON array of hex strings, e.g. `"xmm":["..",".."]`.
fn list<'a>(row: &'a str, key: &str) -> Vec<&'a str> {
    let prefix = format!("\"{key}\":[");
    row.split_once(&prefix)
        .unwrap()
        .1
        .split(']')
        .next()
        .unwrap()
        .split(',')
        .map(|value| value.trim_matches('"'))
        .collect()
}
fn gprs(row: &str, key: &str) -> [u64; 16] {
    let values = list(row, key);
    assert_eq!(values.len(), 16, "{key}: sixteen GPRs");
    std::array::from_fn(|index| u64::from_str_radix(values[index], 16).unwrap())
}
fn xmms(row: &str, key: &str) -> [u128; 16] {
    let values = list(row, key);
    assert_eq!(values.len(), 16, "{key}: sixteen XMM registers");
    std::array::from_fn(|index| u128::from_str_radix(values[index], 16).unwrap())
}

/// Integer-SSE register forms (Loop-back 1 Step32). Inputs come from the same
/// fresh native run (`in_*`); the bytes are checked against the native row.
/// Since Step34 the JIT translates these forms, so a run where they only
/// fell back to the interpreter is rejected (see `compare_sse`).
const SSE_CASES: [(&str, &[u8]); 15] = [
    ("sse-pshufd-00", &[0x66, 0x0f, 0x70, 0xc1, 0x00, 0xc3]),
    (
        "sse-pshufd-1b",
        &[
            0x66, 0x0f, 0x70, 0xc1, 0x1b, 0x66, 0x45, 0x0f, 0x70, 0xce, 0x1b, 0xc3,
        ],
    ),
    ("sse-pshufd-b1", &[0x66, 0x0f, 0x70, 0xc1, 0xb1, 0xc3]),
    ("sse-pshufd-e4", &[0x66, 0x0f, 0x70, 0xc1, 0xe4, 0xc3]),
    ("sse-pmuludq-max", &[0x66, 0x0f, 0xf4, 0xc1, 0xc3]),
    ("sse-pmuludq-upper-ignored", &[0x66, 0x0f, 0xf4, 0xc1, 0xc3]),
    ("sse-paddd-wraparound", &[0x66, 0x0f, 0xfe, 0xc1, 0xc3]),
    ("sse-psubd-wraparound", &[0x66, 0x0f, 0xfa, 0xc1, 0xc3]),
    (
        "sse-pslld-counts",
        &[
            0x66, 0x0f, 0x72, 0xf0, 0x00, 0x66, 0x0f, 0x72, 0xf1, 0x01, 0x66, 0x0f, 0x72, 0xf2,
            0x1f, 0x66, 0x0f, 0x72, 0xf3, 0x20, 0x66, 0x0f, 0x72, 0xf4, 0xff, 0x66, 0x41, 0x0f,
            0x72, 0xf4, 0x1f, 0xc3,
        ],
    ),
    (
        "sse-psrld-counts",
        &[
            0x66, 0x0f, 0x72, 0xd0, 0x00, 0x66, 0x0f, 0x72, 0xd1, 0x01, 0x66, 0x0f, 0x72, 0xd2,
            0x1f, 0x66, 0x0f, 0x72, 0xd3, 0x20, 0x66, 0x0f, 0x72, 0xd4, 0xff, 0x66, 0x41, 0x0f,
            0x72, 0xd5, 0x01, 0xc3,
        ],
    ),
    ("sse-packuswb-saturation", &[0x66, 0x0f, 0x67, 0xc1, 0xc3]),
    ("sse-punpckldq", &[0x66, 0x0f, 0x62, 0xc1, 0xc3]),
    (
        "sse-movdqa-register",
        &[
            0x66, 0x0f, 0x6f, 0xc1, 0x66, 0x0f, 0x7f, 0xda, 0x66, 0x45, 0x0f, 0x6f, 0xce, 0xc3,
        ],
    ),
    (
        "sse-logic-register",
        &[
            0x66, 0x0f, 0xef, 0xc1, 0x66, 0x0f, 0xeb, 0xd3, 0x66, 0x0f, 0xdb, 0xe5, 0x66, 0x0f,
            0xef, 0xf6, 0x66, 0x45, 0x0f, 0xdb, 0xd7, 0xc3,
        ],
    ),
    (
        "sse-jcc-loop",
        &[
            0xb9, 4, 0, 0, 0, 0x66, 0x0f, 0xfe, 0xc1, 0x66, 0x0f, 0x70, 0xc9, 0x93, 0x66, 0x0f,
            0xf4, 0xd9, 0x66, 0x0f, 0x72, 0xd3, 0x03, 0x66, 0x0f, 0xef, 0xd0, 0x83, 0xe9, 1, 0x75,
            0xe5, 0xc3,
        ],
    ),
];

fn compare_sse(name: &str, code: &[u8], row: &str) {
    assert_eq!(field(row, "name"), name);
    let hex: String = code.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(field(row, "code"), hex, "{name}: native code bytes");
    let (in_gpr, in_xmm, in_flags) = (
        gprs(row, "in_gpr"),
        xmms(row, "in_xmm"),
        number(row, "in_flags"),
    );
    let prepare = |state: &mut CpuState| {
        for (index, value) in in_gpr.into_iter().enumerate() {
            if index != reg::RSP {
                state.gpr[index] = value;
            }
        }
        state.xmm = in_xmm;
        state.rflags = in_flags;
    };
    let address = 4096;
    let interpreter = execute(code, address, false, false, &prepare);
    let actual = execute(code, address, false, true, &prepare);
    assert_eq!(actual.0, interpreter.0, "{name}: interpreter/JIT state");
    assert_eq!((actual.2, interpreter.2), (0, 0), "{name}: no fault");
    // Require real JIT execution of the SSE forms, not a fallback-only pass.
    assert!(actual.3 > 0, "{name}: real translation execution required");
    if name == "sse-jcc-loop" {
        // Only the 32-bit SUB (not a translated form) may fall back; the
        // five SSE forms of each of the four iterations must be translated.
        assert!(
            actual.4.translated_instructions >= 20,
            "{name}: translated SSE instructions"
        );
        assert!(
            actual.4.interpreted <= 4,
            "{name}: interpreter fallbacks {}",
            actual.4.interpreted
        );
    } else {
        assert_eq!(actual.4.interpreted, 0, "{name}: no SSE fallback");
        assert_eq!(
            actual.4.translated_instructions, interpreter.4.interpreted,
            "{name}: every instruction translated"
        );
    }
    let state = &actual.0;
    for (index, value) in gprs(row, "gpr").into_iter().enumerate() {
        // RSP is an address and is not observed natively.
        if index != reg::RSP {
            assert_eq!(state.gpr[index], value, "{name}: native GPR {index}");
        }
    }
    for (index, value) in xmms(row, "xmm").into_iter().enumerate() {
        assert_eq!(state.xmm[index], value, "{name}: native XMM{index}");
    }
    assert_eq!(
        state.rip.0 - address,
        number(row, "rip"),
        "{name}: native RIP"
    );
    let mask = number(row, "flag_mask");
    assert_eq!(mask, 0x8d5, "{name}: all arithmetic flags compared");
    assert_eq!(
        state.rflags & mask,
        number(row, "flags"),
        "{name}: native flags"
    );
    if name != "sse-jcc-loop" {
        // Only the loop's SUB writes flags; the SSE forms leave them unchanged.
        assert_eq!(
            number(row, "flags"),
            in_flags & mask,
            "{name}: SSE kept flags"
        );
    }
}

fn execute(
    code: &[u8],
    address: u64,
    fault: bool,
    jit: bool,
    prepare: &dyn Fn(&mut CpuState),
) -> (CpuState, AddressSpace, i32, u64, Run) {
    let mut memory = AddressSpace::new();
    memory
        .map(
            Some(GuestAddr(4096)),
            8192,
            Prot::from_bits(7).unwrap(),
            MappingKind::Anonymous,
        )
        .unwrap();
    memory.write_initial(GuestAddr(address), code).unwrap();
    if !fault {
        memory
            .map(
                Some(GuestAddr(0x10000)),
                4096,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
    }
    let mut state = CpuState::new(GuestAddr(address), GuestAddr(0));
    state.gpr[reg::RDI] = 0x10000;
    prepare(&mut state);
    let cache = WasmCodeCache::new(Arc::new(NodeBridge));
    let mut signal = 0;
    let mut interpreted = 0;
    // Stop before RET, matching native values immediately before its return.
    for _ in 0..64 {
        let mut byte = [0];
        memory.fetch(state.rip, &mut byte).unwrap();
        if byte[0] == 0xc3 {
            break;
        }
        let reason = if jit {
            cache.try_run(&mut state, &memory).unwrap_or_else(|| {
                interpreted += 1;
                paludarium_cpu::run(&mut state, &memory, 1)
            })
        } else {
            interpreted += 1;
            paludarium_cpu::run(&mut state, &memory, 1)
        };
        match reason {
            ExitReason::BudgetExhausted { .. } => {}
            ExitReason::PageFault { .. } => {
                signal = 11;
                break;
            }
            ExitReason::ArithmeticFault { .. } => {
                signal = 8;
                break;
            }
            other => panic!("unexpected instruction exit: {other:?}"),
        }
    }
    let statistics = cache.statistics();
    (
        state,
        memory,
        signal,
        statistics.executed_blocks,
        Run {
            translated_instructions: statistics.executed_instructions,
            interpreted,
        },
    )
}

/// How one JIT-enabled run split its instructions.
struct Run {
    /// Instructions executed inside real wasm translations.
    translated_instructions: u64,
    /// Instructions that fell back to the interpreter.
    interpreted: u64,
}

#[test]
fn fresh_linux_instruction_differential() {
    if std::env::var_os("PALUDARIUM_JIT_INSTRUCTION_CHILD").is_none() {
        assert!(
            Command::new("python3")
                .arg(
                    paludarium_harness::workspace_root()
                        .join("tests/guests/jit/instruction-supervisor.py")
                )
                .arg(std::env::current_exe().unwrap())
                .status()
                .unwrap()
                .success()
        );
        return;
    }
    {
        let root = paludarium_harness::workspace_root();
        let directory = paludarium_harness::guest_dir().join("jit-instructions");
        std::fs::create_dir_all(&directory).unwrap();
        let binary = directory.join("oracle");
        assert!(
            Command::new("cc")
                .args(["-O2", "-Wall", "-Wextra", "-Werror"])
                .arg(root.join("tests/guests/jit/native.c"))
                .arg("-o")
                .arg(&binary)
                .status()
                .unwrap()
                .success()
        );
        let report = directory.join("observations.json");
        assert!(
            Command::new("python3")
                .arg(root.join("scripts/jit-native-first.py"))
                .arg("--binary")
                .arg(&binary)
                .arg("--output")
                .arg(&report)
                .status()
                .unwrap()
                .success()
        );
        // Parse only the native generator's original stdout; Python checks the
        // complete ordered schema and hashes before this comparison.
        let output = Command::new("python3")
            .args([
                "-c",
                "import json,sys;print(json.load(open(sys.argv[1]))['stdout'],end='')",
            ])
            .arg(&report)
            .output()
            .unwrap();
        assert!(output.status.success());
        let native = String::from_utf8(output.stdout).unwrap();
        let move64 = [
            0x48, 0xb8, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 1, 0xc3,
        ];
        let jne = [
            0x48, 0x83, 0xf8, 7, 0x75, 6, 0xb8, 42, 0, 0, 0, 0xc3, 0xb8, 9, 0, 0, 0, 0xc3,
        ];
        let je = [
            0x48, 0x83, 0xf8, 7, 0x74, 6, 0xb8, 42, 0, 0, 0, 0xc3, 0xb8, 9, 0, 0, 0, 0xc3,
        ];
        let cases: [(&str, &[u8], u64, bool); 13] = [
            ("move64", &move64, 0, true),
            ("add64-carry", &[0x48, 0x83, 0xc0, 1, 0xc3], u64::MAX, true),
            (
                "sub64-overflow",
                &[0x48, 0x83, 0xe8, 1, 0xc3],
                1 << 63,
                true,
            ),
            ("jne-zf1-not-taken", &jne, 7, true),
            ("jne-zf0-taken", &jne, 8, true),
            ("je-zf1-taken", &je, 7, true),
            ("je-zf0-not-taken", &je, 8, true),
            (
                "memory-read-write",
                &[0x48, 0x89, 7, 0x48, 0x83, 7, 5, 0x48, 0x8b, 7, 0xc3],
                11,
                false,
            ),
            (
                "unsupported-sse-fallback",
                &[0x66, 0x0f, 0xef, 0xc0, 0x66, 0x48, 0x0f, 0x7e, 0xc0, 0xc3],
                17,
                false,
            ),
            ("unmapped-data-fault", &[0x48, 0x8b, 7, 0xc3], 0, false),
            (
                "division-fault",
                &[0x31, 0xd2, 0x31, 0xc9, 0x48, 0xf7, 0xf1, 0xc3],
                1,
                false,
            ),
            ("self-modifying-code", &move64, 0, true),
            ("cross-page-instruction", &move64, 0, true),
        ];
        assert_eq!(native.lines().count(), cases.len() + SSE_CASES.len());
        for ((name, code, input, translated), row) in cases.into_iter().zip(native.lines()) {
            assert_eq!(field(row, "name"), name);
            let address = if name == "cross-page-instruction" {
                8189
            } else {
                4096
            };
            let prepare = |state: &mut CpuState| state.gpr[reg::RAX] = input;
            let fault = name == "unmapped-data-fault";
            let interpreter = execute(code, address, fault, false, &prepare);
            let actual = execute(code, address, fault, true, &prepare);
            assert_eq!(actual.0, interpreter.0, "{name}: interpreter/JIT state");
            assert_eq!(actual.2, interpreter.2, "{name}: interpreter/JIT fault");
            if translated {
                assert!(actual.3 > 0, "{name}: real translation execution required");
            }
            if actual.2 != 0 {
                assert!(
                    row.contains(&format!("\"signal\":{}", actual.2)),
                    "{name}: native signal"
                );
            } else {
                assert_eq!(
                    actual.0.gpr[0],
                    number(row, "first_rax"),
                    "{name}: native first RAX"
                );
                assert_eq!(
                    actual.0.rflags & number(row, "flag_mask"),
                    number(row, "flags"),
                    "{name}: native flags"
                );
                assert_eq!(
                    actual.1.read_u64(GuestAddr(0x10000)).unwrap(),
                    number(row, "memory"),
                    "{name}: native memory"
                );
                if name == "self-modifying-code" {
                    let cache = WasmCodeCache::new(Arc::new(NodeBridge));
                    let mut state = actual.0;
                    state.rip = GuestAddr(address);
                    assert!(cache.try_run(&mut state, &actual.1).is_some());
                    actual
                        .1
                        .write(GuestAddr(address + 2), &[42, 0, 0, 0, 0, 0, 0, 0])
                        .unwrap();
                    state.rip = GuestAddr(address);
                    assert!(cache.try_run(&mut state, &actual.1).is_some());
                    assert_eq!(state.gpr[0], number(row, "rax"));
                    assert_eq!(cache.statistics().translated_blocks, 2);
                }
            }
            println!("{name}: native/interpreter/real-wasm match");
        }
        for ((name, code), row) in SSE_CASES.into_iter().zip(native.lines().skip(cases.len())) {
            compare_sse(name, code, row);
            println!("{name}: native/interpreter/real-wasm match (XMM0-15, GPR, RIP, flags)");
        }
    }
}
