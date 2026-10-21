// Test-only disposition of the six observed SHA alignment differences.
// No native identity is forwarded to the virtual CPU.
pub fn amd_profile(cpuid: &str) -> bool {
    let rows: Vec<Vec<&str>> = cpuid.lines().map(|s| s.split('|').collect()).collect();
    assert_eq!(rows.len(), 12, "missing native CPUID rows");
    let leaf = |n: &str| {
        rows.iter()
            .find(|r| r.len() == 7 && r[0] == n && r[1] == "00000000")
            .expect("missing CPUID leaf")
    };
    let zero = leaf("00000000");
    let mut vendor = Vec::new();
    for n in [3, 5, 4] {
        vendor.extend_from_slice(&(u64::from_str_radix(zero[n], 16).unwrap() as u32).to_le_bytes());
    }
    let signature = u64::from_str_radix(leaf("00000001")[2], 16).unwrap();
    assert_ne!(
        u64::from_str_radix(leaf("00000007")[3], 16).unwrap() & (1 << 29),
        0,
        "native SHA feature missing"
    );
    match (vendor.as_slice(), signature) {
        (b"AuthenticAMD", 0x00a00f11 | 0x00a10f11 | 0x00b00f21) => true,
        // 000606a6 observed on fork run 39347200422, job 118382556639 (artifact u3-intel-observation-39347200422-17).
        (b"GenuineIntel", 0x000c06f2 | 0x000a06d1 | 0x000606a6) => false,
        _ => panic!(
            "unobserved native SHA profile: {:?} signature {signature:08x}",
            String::from_utf8_lossy(&vendor)
        ),
    }
}

pub fn amd_sha_difference(fields: &[&str], amd: bool) -> bool {
    if !amd || !matches!(fields[1], "2" | "3") {
        return false;
    }
    let expected_code = match fields[0] {
        "sha256rnds2_memory" => "0f38cb4210",
        "sha256msg1_memory" => "0f38cc4210",
        "sha256msg2_memory" => "0f38cd4210",
        _ => return false,
    };
    assert_eq!(fields[8], expected_code, "unexpected SHA encoding");
    let mut input: Vec<u8> = (0..512).map(|k| (k * 17 + 3) as u8).collect();
    input[256..260].copy_from_slice(&0x1f80u32.to_le_bytes());
    let hex: String = input.iter().map(|v| format!("{v:02x}")).collect();
    assert_eq!(fields[9], hex, "unexpected SHA input");
    assert_eq!(fields[10], hex, "unexpected SHA initial memory");
    assert_eq!(fields[12], hex, "native SHA changed memory");
    if fields[1] == "2" {
        assert_eq!(&fields[2..8], &["11", "0", "2", "14", "4", "24"]);
    } else {
        assert_eq!(&fields[2..8], &["0", "0", "0", "0", "0", "0"]);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{amd_profile, amd_sha_difference};
    // CPUID leaf 0 (ebx, ecx, edx).
    const AMD: (u32, u32, u32) = (0x68747541, 0x444d4163, 0x69746e65);
    const INTEL: (u32, u32, u32) = (0x756e6547, 0x6c65746e, 0x49656e69);
    fn profile(signature: u32, sha: bool) -> String {
        vendor_profile(AMD, signature, sha)
    }
    fn vendor_profile(vendor: (u32, u32, u32), signature: u32, sha: bool) -> String {
        let mut rows = Vec::new();
        for leaf in [0, 1, 7, 0x80000000, 0x80000001, u32::MAX] {
            for sub in 0..2 {
                let (a, b, c, d) = match leaf {
                    0 => (7, vendor.0, vendor.1, vendor.2),
                    1 => (signature, 0, 0, 0),
                    7 => (0, if sha { 1 << 29 } else { 0 }, 0, 0),
                    _ => (0, 0, 0, 0),
                };
                rows.push(format!(
                    "{leaf:08x}|{sub:08x}|{a:016x}|{b:016x}|{c:016x}|{d:016x}|00000000000008d5"
                ));
            }
        }
        rows.join("\n")
    }
    #[test]
    fn known_exact_amd_profiles() {
        for signature in [0xa00f11, 0xa10f11, 0xb00f21] {
            assert!(amd_profile(&profile(signature, true)));
        }
    }
    #[test]
    fn known_exact_intel_profiles() {
        for signature in [0x0606a6, 0x0c06f2, 0x0a06d1] {
            assert!(!amd_profile(&vendor_profile(INTEL, signature, true)));
        }
    }
    #[test]
    #[should_panic(expected = "unobserved native SHA profile")]
    fn unknown_intel_profile_is_rejected() {
        amd_profile(&vendor_profile(INTEL, 0x0606a5, true));
    }
    #[test]
    #[should_panic(expected = "unobserved native SHA profile")]
    fn unknown_amd_profile_is_rejected() {
        amd_profile(&profile(0xa00f12, true));
    }
    #[test]
    #[should_panic(expected = "native SHA feature missing")]
    fn missing_sha_feature_is_rejected() {
        amd_profile(&profile(0xa00f11, false));
    }
    #[test]
    #[should_panic(expected = "missing native CPUID rows")]
    fn incomplete_observation_is_rejected() {
        amd_profile("");
    }
    #[test]
    #[should_panic(expected = "unobserved native SHA profile")]
    fn unknown_vendor_is_rejected() {
        amd_profile(&profile(0xa00f11, true).replace("0000000068747541", "0000000000000000"));
    }
    fn candidate() -> Vec<String> {
        let mut input: Vec<u8> = (0..512).map(|k| (k * 17 + 3) as u8).collect();
        input[256..260].copy_from_slice(&0x1f80u32.to_le_bytes());
        let hex: String = input.iter().map(|v| format!("{v:02x}")).collect();
        [
            "sha256msg1_memory",
            "2",
            "11",
            "0",
            "2",
            "14",
            "4",
            "24",
            "0f38cc4210",
            &hex,
            &hex,
            "",
            &hex,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    fn disposition(fields: &[String]) {
        amd_sha_difference(&fields.iter().map(String::as_str).collect::<Vec<_>>(), true);
    }
    #[test]
    #[should_panic(expected = "unexpected SHA encoding")]
    fn changed_encoding_is_rejected() {
        let mut f = candidate();
        f[8] = "0f38cc4211".into();
        disposition(&f);
    }
    #[test]
    #[should_panic(expected = "unexpected SHA input")]
    fn changed_input_is_rejected() {
        let mut f = candidate();
        f[9].replace_range(..2, "00");
        disposition(&f);
    }
    #[test]
    #[should_panic]
    fn unexpected_native_trap_is_rejected() {
        let mut f = candidate();
        f[5] = "13".into();
        disposition(&f);
    }
    #[test]
    fn unrelated_opcode_and_intel_are_never_disposed() {
        let f = candidate();
        let borrowed: Vec<_> = f.iter().map(String::as_str).collect();
        assert!(!amd_sha_difference(&borrowed, false));
        let mut f = f;
        f[0] = "aesenc_memory".into();
        assert!(!amd_sha_difference(
            &f.iter().map(String::as_str).collect::<Vec<_>>(),
            true
        ));
    }
}
