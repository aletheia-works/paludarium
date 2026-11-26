//! `/proc/cpuinfo`, as Linux 7.0's `show_cpuinfo` prints it for the virtual
//! CPU: what Linux would make of the CPU's `cpuid`
//! ([`paludarium_cpu::cpuid`]) when it boots on it, never the host's CPU.
//!
//! Linux reads the words of its capabilities from `cpuid` (`get_cpu_cap`),
//! then sets some of its own for the vendor and family (`init_amd`) and the
//! bugs its tables give the family (`cpu_set_bug_bits`). Those are kept
//! here for the one CPU `cpuid` describes, an AMD of family 15, model 0 and
//! stepping 0, with no machine-specific register to read: a test checks that
//! `cpuid` still says so. The "scattered" capabilities come from leaves
//! (`0x6`'s ECX, `0xf`, `0x10`, `0x8000_0007`) the CPU answers with zeros
//! or not at all, so they are none. The names are those of Linux 7.0's
//! `x86_cap_flags` and `x86_bug_flags`, from `cpufeatures.h`.
use paludarium_cpu::cpuid;

/// Words of capabilities and of bugs (`NCAPINTS`, `NBUGINTS`).
const CAP_WORDS: usize = 22;
const BUG_WORDS: usize = 2;

const EAX: usize = 0;
const EBX: usize = 1;
const ECX: usize = 2;
const EDX: usize = 3;

/// The words `get_cpu_cap` copies from `cpuid`: the word, then the leaf,
/// subleaf and register it comes from.
const CPUID_WORDS: [(usize, u32, u32, usize); 14] = [
    (0, 1, 0, EDX),
    (4, 1, 0, ECX),
    (14, 6, 0, EAX),
    (9, 7, 0, EBX),
    (16, 7, 0, ECX),
    (18, 7, 0, EDX),
    (12, 7, 1, EAX),
    (10, 0xd, 1, EAX),
    (6, 0x8000_0001, 0, ECX),
    (1, 0x8000_0001, 0, EDX),
    (13, 0x8000_0008, 0, EBX),
    (15, 0x8000_000a, 0, EDX),
    (19, 0x8000_001f, 0, EAX),
    (20, 0x8000_0021, 0, EAX),
];

/// Capabilities, as `32 * word + bit`.
const LM: u16 = 32 + 29;
const AMD_3DNOW: u16 = 32 + 31;
const REP_GOOD: u16 = 3 * 32 + 16;
const NOPL: u16 = 3 * 32 + 20;
const CPUID: u16 = 3 * 32 + 25;
const HYPERVISOR: u16 = 4 * 32 + 31;
const LAHF_LM: u16 = 6 * 32;
const PREFETCHW: u16 = 6 * 32 + 8;
const VMMCALL: u16 = 8 * 32 + 15;
const XSAVEERPTR: u16 = 13 * 32 + 2;
const NULL_SEL_CLR_BASE: u16 = 20 * 32 + 6;
/// Bugs, as `32 * word + bit` past the capabilities.
const FXSAVE_LEAK: u16 = 6;
const SYSRET_SS_ATTRS: u16 = 8;
const NULL_SEG: u16 = 10;
const SWAPGS_FENCE: u16 = 11;
const AMD_E400: u16 = 13;
const SPECTRE_V1: u16 = 15;
const SPECTRE_V2: u16 = 16;
const SPECTRE_V2_USER: u16 = 32 + 5;

/// What Linux knows of the CPU once it has identified it.
#[derive(Debug, PartialEq, Eq)]
struct Identity {
    vendor: [u8; 12],
    level: u32,
    family: u32,
    model: u32,
    stepping: u32,
    initial_apicid: u32,
    clflush: u32,
    physical_bits: u32,
    virtual_bits: u32,
    caps: [u32; CAP_WORDS],
    bugs: [u32; BUG_WORDS],
}

fn has(words: &[u32], bit: u16) -> bool {
    words[usize::from(bit / 32)] & 1 << (bit % 32) != 0
}
fn set(words: &mut [u32], bit: u16, on: bool) {
    let word = &mut words[usize::from(bit / 32)];
    if on {
        *word |= 1 << (bit % 32);
    } else {
        *word &= !(1 << (bit % 32));
    }
}

/// `cpu_detect`, `get_cpu_cap`, `get_cpu_address_sizes` and, for this
/// CPU, `early_init_amd`, `init_amd_k8`, `init_amd`, `detect_nopl` and
/// `cpu_set_bug_bits`.
fn identify() -> Identity {
    let [level, b, c, d] = cpuid(0, 0);
    let mut vendor = [0; 12];
    for (at, register) in [b, d, c].into_iter().enumerate() {
        vendor[at * 4..at * 4 + 4].copy_from_slice(&register.to_le_bytes());
    }
    let [signature, misc, _, _] = cpuid(1, 0);
    let base = signature >> 8 & 0xf;
    let family = if base == 0xf {
        base + (signature >> 20 & 0xff)
    } else {
        base
    };
    let mut model = signature >> 4 & 0xf;
    if family >= 6 {
        model += (signature >> 16 & 0xf) << 4;
    }
    let extended = match cpuid(0x8000_0000, 0)[EAX] {
        top if top & 0xffff_0000 == 0x8000_0000 => top,
        _ => 0,
    };
    let answers = |leaf: u32| {
        if leaf >= 0x8000_0000 {
            leaf <= extended
        } else {
            leaf <= level
        }
    };
    let mut caps = [0; CAP_WORDS];
    for (word, leaf, subleaf, register) in CPUID_WORDS {
        // Subleaf 1 of leaf 7 only where subleaf 0's EAX says it is there.
        let present = answers(leaf) && (leaf != 7 || subleaf == 0 || cpuid(7, 0)[EAX] >= 1);
        if present {
            caps[word] = cpuid(leaf, subleaf)[register];
        }
    }
    // Leaf 0x8000_0008's sizes, or the defaults of a 64-bit kernel, which
    // also make the CLFLUSH line 64 bytes.
    let (clflush, physical_bits, virtual_bits) = if answers(0x8000_0008) {
        let sizes = cpuid(0x8000_0008, 0)[EAX];
        let line = if has(&caps, 19) {
            (misc >> 8 & 0xff) * 8
        } else {
            0
        };
        (
            if line == 0 { 32 } else { line },
            sizes & 0xff,
            sizes >> 8 & 0xff,
        )
    } else {
        (64, 36, 48)
    };
    let mut bugs = [0; BUG_WORDS];
    // A 64-bit kernel's own, on every CPU with `cpuid`.
    set(&mut caps, CPUID, true);
    set(&mut caps, NOPL, true);
    // An AMD of family 15 (`init_amd`, `init_amd_k8`).
    if model < 0x14 && !has(&caps, HYPERVISOR) {
        set(&mut caps, LAHF_LM, false);
    }
    if (0x0f48..0x0f50).contains(&signature) || signature >= 0x0f58 {
        set(&mut caps, REP_GOOD, true);
    }
    set(&mut caps, VMMCALL, true);
    if has(&caps, AMD_3DNOW) || has(&caps, LM) {
        set(&mut caps, PREFETCHW, true);
    }
    set(&mut bugs, SWAPGS_FENCE, true);
    if model > 0x41 || model == 0x41 && signature & 0xf >= 2 {
        set(&mut bugs, AMD_E400, true);
    }
    set(&mut bugs, FXSAVE_LEAK, !has(&caps, XSAVEERPTR));
    set(&mut bugs, SYSRET_SS_ATTRS, true);
    set(&mut bugs, NULL_SEG, !has(&caps, NULL_SEL_CLR_BASE));
    // `cpu_vuln_whitelist` has family 15 of AMD with neither
    // `NO_SPECULATION` nor `NO_SPECTRE_V2`, but with `NO_SSB` and the rest:
    // no `spec_store_bypass`, and `cpu_vuln_blacklist` has no such family.
    set(&mut bugs, SPECTRE_V1, true);
    set(&mut bugs, SPECTRE_V2, true);
    set(&mut bugs, SPECTRE_V2_USER, true);
    Identity {
        vendor,
        level,
        family,
        model,
        stepping: signature & 0xf,
        initial_apicid: misc >> 24,
        clflush,
        physical_bits,
        virtual_bits,
        caps,
        bugs,
    }
}

/// `/proc/cpuinfo` for `cpus` CPUs, each online. With no topology leaf
/// and no HTT or CmpLegacy bit, Linux takes each CPU for a package of its
/// own, of one core with one thread, its APIC ID the CPU's number; the
/// initial APIC ID is the one `cpuid`'s leaf 1 gives. There is no model
/// name in `cpuid`, so `init_amd_k8` names it `Hammer`; no microcode
/// level (`MSR_AMD64_PATCH_LEVEL`), cache or TLB size (leaves 0x8000_0005
/// and 0x8000_0006), no time stamp counter in `cpuid`, so no `cpu MHz`,
/// and no power management (leaf 0x8000_0007). Nothing calibrates a delay
/// loop, so `bogomips` is 0.
pub(crate) fn render(cpus: usize) -> Vec<u8> {
    use std::fmt::Write;
    let id = identify();
    let names = |words: &[u32], names: &[(u16, &str)]| {
        names.iter().filter(|&&(bit, _)| has(words, bit)).fold(
            String::new(),
            |mut out, (_, name)| {
                out.push(' ');
                out.push_str(name);
                out
            },
        )
    };
    let flags = names(&id.caps, FLAG_NAMES);
    let bugs = names(&id.bugs, BUG_NAMES);
    let vendor = String::from_utf8_lossy(&id.vendor);
    let mut out = String::new();
    for cpu in 0..cpus {
        let _ = write!(
            out,
            "processor\t: {cpu}\nvendor_id\t: {vendor}\ncpu family\t: {}\nmodel\t\t: {}\n\
             model name\t: Hammer\nstepping\t: {}\n",
            id.family, id.model, id.stepping
        );
        let _ = write!(
            out,
            "physical id\t: {cpu}\nsiblings\t: 1\ncore id\t\t: 0\ncpu cores\t: 1\n\
             apicid\t\t: {cpu}\ninitial apicid\t: {}\n",
            id.initial_apicid
        );
        let _ = write!(
            out,
            "fpu\t\t: yes\nfpu_exception\t: yes\ncpuid level\t: {}\nwp\t\t: yes\n\
             flags\t\t:{flags}\nbugs\t\t:{bugs}\nbogomips\t: 0.00\n",
            id.level
        );
        let _ = write!(
            out,
            "clflush size\t: {}\ncache_alignment\t: {}\n\
             address sizes\t: {} bits physical, {} bits virtual\npower management:\n\n",
            id.clflush, id.clflush, id.physical_bits, id.virtual_bits
        );
    }
    out.into_bytes()
}

/// Linux 7.0's `x86_cap_flags` and `x86_bug_flags`: each named bit and its
/// name, as `mkcapflags.sh` takes them from `cpufeatures.h`.
#[rustfmt::skip]
const FLAG_NAMES: &[(u16, &str)] = &[
    (0, "fpu"), (1, "vme"), (2, "de"), (3, "pse"), (4, "tsc"), (5, "msr"), (6, "pae"), (7, "mce"),
    (8, "cx8"), (9, "apic"), (11, "sep"), (12, "mtrr"), (13, "pge"), (14, "mca"), (15, "cmov"),
    (16, "pat"), (17, "pse36"), (18, "pn"), (19, "clflush"), (21, "dts"), (22, "acpi"),
    (23, "mmx"), (24, "fxsr"), (25, "sse"), (26, "sse2"), (27, "ss"), (28, "ht"), (29, "tm"),
    (30, "ia64"), (31, "pbe"), (43, "syscall"), (51, "mp"), (52, "nx"), (54, "mmxext"),
    (57, "fxsr_opt"), (58, "pdpe1gb"), (59, "rdtscp"), (61, "lm"), (62, "3dnowext"), (63, "3dnow"),
    (64, "recovery"), (65, "longrun"), (67, "lrti"), (96, "cxmmx"), (97, "k6_mtrr"),
    (98, "cyrix_arr"), (99, "centaur_mcr"), (104, "constant_tsc"), (105, "up"), (106, "art"),
    (107, "arch_perfmon"), (108, "pebs"), (109, "bts"), (112, "rep_good"), (113, "amd_lbr_v2"),
    (115, "acc_power"), (116, "nopl"), (118, "xtopology"), (119, "tsc_reliable"),
    (120, "nonstop_tsc"), (121, "cpuid"), (122, "extd_apicid"), (123, "amd_dcm"),
    (124, "aperfmperf"), (125, "rapl"), (126, "nonstop_tsc_s3"), (127, "tsc_known_freq"),
    (128, "pni"), (129, "pclmulqdq"), (130, "dtes64"), (131, "monitor"), (132, "ds_cpl"),
    (133, "vmx"), (134, "smx"), (135, "est"), (136, "tm2"), (137, "ssse3"), (138, "cid"),
    (139, "sdbg"), (140, "fma"), (141, "cx16"), (142, "xtpr"), (143, "pdcm"), (145, "pcid"),
    (146, "dca"), (147, "sse4_1"), (148, "sse4_2"), (149, "x2apic"), (150, "movbe"),
    (151, "popcnt"), (152, "tsc_deadline_timer"), (153, "aes"), (154, "xsave"), (156, "avx"),
    (157, "f16c"), (158, "rdrand"), (159, "hypervisor"), (162, "rng"), (163, "rng_en"),
    (166, "ace"), (167, "ace_en"), (168, "ace2"), (169, "ace2_en"), (170, "phe"), (171, "phe_en"),
    (172, "pmm"), (173, "pmm_en"), (192, "lahf_lm"), (193, "cmp_legacy"), (194, "svm"),
    (195, "extapic"), (196, "cr8_legacy"), (197, "abm"), (198, "sse4a"), (199, "misalignsse"),
    (200, "3dnowprefetch"), (201, "osvw"), (202, "ibs"), (203, "xop"), (204, "skinit"),
    (205, "wdt"), (207, "lwp"), (208, "fma4"), (209, "tce"), (211, "nodeid_msr"), (213, "tbm"),
    (214, "topoext"), (215, "perfctr_core"), (216, "perfctr_nb"), (218, "bpext"), (219, "ptsc"),
    (220, "perfctr_llc"), (221, "mwaitx"), (224, "ring3mwait"), (225, "cpuid_fault"), (226, "cpb"),
    (227, "epb"), (228, "cat_l3"), (229, "cat_l2"), (230, "cdp_l3"), (231, "tdx_host_platform"),
    (232, "hw_pstate"), (233, "proc_feedback"), (235, "pti"), (238, "intel_ppin"), (239, "cdp_l2"),
    (241, "ssbd"), (242, "mba"), (244, "perfmon_v2"), (249, "ibrs"), (250, "ibpb"), (251, "stibp"),
    (254, "ibrs_enhanced"), (256, "tpr_shadow"), (257, "flexpriority"), (258, "ept"),
    (259, "vpid"), (271, "vmmcall"), (273, "ept_ad"), (278, "tdx_guest"), (288, "fsgsbase"),
    (289, "tsc_adjust"), (290, "sgx"), (291, "bmi1"), (292, "hle"), (293, "avx2"), (295, "smep"),
    (296, "bmi2"), (297, "erms"), (298, "invpcid"), (299, "rtm"), (300, "cqm"), (302, "mpx"),
    (303, "rdt_a"), (304, "avx512f"), (305, "avx512dq"), (306, "rdseed"), (307, "adx"),
    (308, "smap"), (309, "avx512ifma"), (311, "clflushopt"), (312, "clwb"), (313, "intel_pt"),
    (314, "avx512pf"), (315, "avx512er"), (316, "avx512cd"), (317, "sha_ni"), (318, "avx512bw"),
    (319, "avx512vl"), (320, "xsaveopt"), (321, "xsavec"), (322, "xgetbv1"), (323, "xsaves"),
    (352, "cqm_llc"), (353, "cqm_occup_llc"), (354, "cqm_mbm_total"), (355, "cqm_mbm_local"),
    (358, "split_lock_detect"), (375, "user_shstk"), (388, "avx_vnni"), (389, "avx512_bf16"),
    (390, "lass"), (401, "fred"), (410, "lam"), (416, "clzero"), (417, "irperf"),
    (418, "xsaveerptr"), (420, "rdpru"), (425, "wbnoinvd"), (439, "amd_ppin"), (441, "virt_ssbd"),
    (443, "cppc"), (447, "brs"), (448, "dtherm"), (449, "ida"), (450, "arat"), (452, "pln"),
    (454, "pts"), (455, "hwp"), (456, "hwp_notify"), (457, "hwp_act_window"), (458, "hwp_epp"),
    (459, "hwp_pkg_req"), (467, "hfi"), (480, "npt"), (481, "lbrv"), (482, "svm_lock"),
    (483, "nrip_save"), (484, "tsc_scale"), (485, "vmcb_clean"), (486, "flushbyasid"),
    (487, "decodeassists"), (490, "pausefilter"), (492, "pfthreshold"), (493, "avic"),
    (495, "v_vmsave_vmload"), (496, "vgif"), (498, "x2avic"), (500, "v_spec_ctrl"), (505, "vnmi"),
    (513, "avx512vbmi"), (514, "umip"), (515, "pku"), (516, "ospke"), (517, "waitpkg"),
    (518, "avx512_vbmi2"), (520, "gfni"), (521, "vaes"), (522, "vpclmulqdq"), (523, "avx512_vnni"),
    (524, "avx512_bitalg"), (525, "tme"), (526, "avx512_vpopcntdq"), (528, "la57"), (534, "rdpid"),
    (536, "bus_lock_detect"), (537, "cldemote"), (539, "movdiri"), (540, "movdir64b"),
    (541, "enqcmd"), (542, "sgx_lc"), (544, "overflow_recov"), (545, "succor"), (547, "smca"),
    (578, "avx512_4vnniw"), (579, "avx512_4fmaps"), (580, "fsrm"), (584, "avx512_vp2intersect"),
    (586, "md_clear"), (590, "serialize"), (592, "tsxldtrk"), (594, "pconfig"), (595, "arch_lbr"),
    (596, "ibt"), (598, "amx_bf16"), (599, "avx512_fp16"), (600, "amx_tile"), (601, "amx_int8"),
    (604, "flush_l1d"), (605, "arch_capabilities"), (608, "sme"), (609, "sev"), (611, "sev_es"),
    (612, "sev_snp"), (622, "debug_swap"), (636, "svsm"), (672, "amd_lbr_pmc_freeze"),
];
#[rustfmt::skip]
const BUG_NAMES: &[(u16, &str)] = &[
    (0, "f00f"), (1, "fdiv"), (2, "coma"), (3, "tlb_mmatch"), (4, "apic_c1e"), (5, "11ap"),
    (6, "fxsave_leak"), (7, "clflush_monitor"), (8, "sysret_ss_attrs"), (10, "null_seg"),
    (11, "swapgs_fence"), (12, "monitor"), (13, "amd_e400"), (14, "cpu_meltdown"),
    (15, "spectre_v1"), (16, "spectre_v2"), (17, "spec_store_bypass"), (18, "l1tf"), (19, "mds"),
    (20, "msbds_only"), (21, "swapgs"), (22, "taa"), (23, "itlb_multihit"), (24, "srbds"),
    (25, "mmio_stale_data"), (27, "retbleed"), (28, "eibrs_pbrsb"), (29, "smt_rsb"), (30, "gds"),
    (31, "tdx_pw_mce"), (32, "srso"), (33, "div0"), (34, "rfds"), (35, "bhi"), (36, "ibpb_no_ret"),
    (37, "spectre_v2_user"), (38, "old_microcode"), (39, "its"), (40, "its_native_only"),
    (41, "tsa"), (42, "vmscape"),
];

#[cfg(test)]
mod tests {
    use super::*;

    const TSC: u16 = 4;

    #[test]
    fn the_cpu_is_the_one_linux_s_amd_family_15_code_was_read_for() {
        let id = identify();
        assert_eq!(&id.vendor, b"AuthenticAMD");
        assert_eq!((id.family, id.model, id.stepping), (15, 0, 0));
        // Neither a brand string nor sizes, nor a time stamp counter.
        assert!(cpuid(0x8000_0000, 0)[EAX] < 0x8000_0004);
        assert!(!has(&id.caps, TSC));
    }

    #[test]
    fn each_cpu_has_a_record_in_linux_s_format() {
        let text = String::from_utf8(render(2)).unwrap();
        let records: Vec<&str> = text.split_terminator("\n\n").collect();
        assert_eq!(records.len(), 2);
        assert!(text.ends_with("power management:\n\n"));
        let first: Vec<&str> = records[0].lines().collect();
        assert_eq!(
            first,
            [
                "processor\t: 0",
                "vendor_id\t: AuthenticAMD",
                "cpu family\t: 15",
                "model\t\t: 0",
                "model name\t: Hammer",
                "stepping\t: 0",
                "physical id\t: 0",
                "siblings\t: 1",
                "core id\t\t: 0",
                "cpu cores\t: 1",
                "apicid\t\t: 0",
                "initial apicid\t: 0",
                "fpu\t\t: yes",
                "fpu_exception\t: yes",
                "cpuid level\t: 7",
                "wp\t\t: yes",
                "flags\t\t: fpu cx8 cmov clflush mmx fxsr sse sse2 lm nopl cpuid 3dnowprefetch vmmcall",
                "bugs\t\t: fxsave_leak sysret_ss_attrs null_seg swapgs_fence spectre_v1 spectre_v2 \
                 spectre_v2_user",
                "bogomips\t: 0.00",
                "clflush size\t: 64",
                "cache_alignment\t: 64",
                "address sizes\t: 36 bits physical, 48 bits virtual",
                "power management:",
            ]
        );
        assert!(records[1].starts_with("processor\t: 1\n"));
        assert!(records[1].contains("\napicid\t\t: 1\n"));
    }

    #[test]
    fn the_names_are_in_the_order_of_their_bits() {
        for names in [FLAG_NAMES, BUG_NAMES] {
            assert!(names.windows(2).all(|pair| pair[0].0 < pair[1].0));
        }
        assert!(
            FLAG_NAMES
                .iter()
                .all(|&(bit, _)| usize::from(bit) < 32 * CAP_WORDS)
        );
        assert!(
            BUG_NAMES
                .iter()
                .all(|&(bit, _)| usize::from(bit) < 32 * BUG_WORDS)
        );
    }
}
