//! The core instruction list and which differential-test guest covers each
//! instruction. The list is the union of the instructions the C and Rust
//! hello worlds execute natively, found with
//! `tools/insn-trace/insn-census.sh`.
//!
//! Each entry names the guest and a fragment of its source that exercises
//! the instruction, so the record is checked against the real sources.

/// (instruction, guest source under tests/guests, evidence in that source)
pub const CORE_INSTRUCTIONS: &[(&str, &str, &str)] = &[
    ("add", "insn/alu.c", "BIN_RR(\"add64\""),
    ("and", "insn/alu.c", "BIN_RR(\"and64\""),
    ("bt", "insn/bt.c", "BIN_RR(\"bt32\""),
    ("call", "insn/mov.c", "call *%[f]"),
    ("cdqe", "insn/mov.c", "cltq"),
    ("cmova", "insn/cond-cmov.c", "CMOVCC(a)"),
    ("cmovae", "insn/cond-cmov.c", "CMOVCC(ae)"),
    ("cmove", "insn/cond-cmov.c", "CMOVCC(e)"),
    ("cmovge", "insn/cond-cmov.c", "CMOVCC(ge)"),
    ("cmovns", "insn/cond-cmov.c", "CMOVCC(ns)"),
    ("cmovs", "insn/cond-cmov.c", "CMOVCC(s)"),
    ("cmp", "insn/cmptest.c", "BIN_RR(\"cmp64\""),
    ("dec", "insn/incdec.c", "UN_R(\"dec64\""),
    ("div", "insn/muldiv.c", "div %[d]"),
    ("endbr64", "insn/mov.c", "0xf3, 0x0f, 0x1e, 0xfa"),
    ("imul", "insn/muldiv.c", "IMUL3(\"imul64i\""),
    ("inc", "insn/incdec.c", "UN_R(\"inc64\""),
    ("ja", "insn/cond-jcc.c", "JCC(a)"),
    ("jae", "insn/cond-jcc.c", "JCC(ae)"),
    ("jb", "insn/cond-jcc.c", "JCC(b)"),
    ("jbe", "insn/cond-jcc.c", "JCC(be)"),
    ("je", "insn/cond-jcc.c", "JCC(e)"),
    ("jg", "insn/cond-jcc.c", "JCC(g)"),
    ("jge", "insn/cond-jcc.c", "JCC(ge)"),
    ("jl", "insn/cond-jcc.c", "JCC(l)"),
    ("jle", "insn/cond-jcc.c", "JCC(le)"),
    ("jmp", "insn/mov.c", "jmp *%[r]"),
    ("jne", "insn/cond-jcc.c", "JCC(ne)"),
    ("jns", "insn/cond-jcc.c", "JCC(ns)"),
    ("js", "insn/cond-jcc.c", "JCC(s)"),
    ("lea", "insn/mov.c", "lea 0x10("),
    ("lock cmpxchg", "insn/atomic.c", "lock cmpxchg"),
    ("lock or", "insn/atomic.c", "lock or"),
    ("mov", "insn/mov.c", "movq %[v], %[m]"),
    ("movabs", "insn/mov.c", "movabs $"),
    ("movaps", "insn/sse.c", "movaps 16("),
    ("movq", "insn/sse.c", "movq %[low], %%xmm0"),
    ("movsx", "insn/mov.c", "movsbl"),
    ("movsxd", "insn/mov.c", "movslq"),
    ("movups", "insn/sse.c", "movups 3("),
    ("movzx", "insn/mov.c", "movzbl"),
    ("neg", "insn/incdec.c", "UN_R(\"neg64\""),
    ("nop", "insn/mov.c", "nopl 0x0(%%rax,%%rax,1)"),
    ("cs nop", "insn/mov.c", ".byte 0x2e, 0x66, 0x0f, 0x1f"),
    ("not", "insn/incdec.c", "UN_R(\"not64\""),
    ("or", "insn/alu.c", "BIN_RR(\"or64\""),
    ("pop", "insn/mov.c", "pop %[r]"),
    ("push", "insn/mov.c", "push $-3"),
    ("punpcklqdq", "insn/sse.c", "punpcklqdq %%xmm1, %%xmm0"),
    ("pxor", "insn/sse.c", "pxor %%xmm3"),
    ("rep movsq", "insn/string.c", "rep movsq"),
    ("rep stosq", "insn/string.c", "rep stosq"),
    ("ret", "insn/mov.c", "static void target(void)"),
    ("sar", "insn/shift.c", "SHIFT_CL(\"sar64cl\""),
    ("seta", "insn/cond-set.c", "SETCC(a)"),
    ("setb", "insn/cond-set.c", "SETCC(b)"),
    ("setbe", "insn/cond-set.c", "SETCC(be)"),
    ("sete", "insn/cond-set.c", "SETCC(e)"),
    ("setne", "insn/cond-set.c", "SETCC(ne)"),
    ("shl", "insn/shift.c", "SHIFT_CL(\"shl64cl\""),
    ("shr", "insn/shift.c", "SHIFT_CL(\"shr64cl\""),
    ("sub", "insn/alu.c", "BIN_RR(\"sub64\""),
    ("syscall", "insn/insn.h", "\"syscall\""),
    ("test", "insn/cmptest.c", "BIN_RR(\"test64\""),
    ("xchg", "insn/mov.c", "xchg %k[x], %k[m]"),
    ("xchg ax, ax", "insn/mov.c", ".byte 0x66, 0x90"),
    ("xor", "insn/alu.c", "BIN_RR(\"xor64\""),
    ("xorps", "insn/sse.c", "xorps %%xmm2"),
];

/// (instructions with at least one differential test, all core instructions)
pub fn instruction_coverage(guest_sources: &std::path::Path) -> (usize, usize) {
    let covered = CORE_INSTRUCTIONS
        .iter()
        .filter(|(_, file, evidence)| {
            std::fs::read_to_string(guest_sources.join(file))
                .is_ok_and(|text| text.contains(evidence))
        })
        .count();
    (covered, CORE_INSTRUCTIONS.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_core_instruction_has_a_differential_test() {
        let sources = crate::workspace_root().join("tests").join("guests");
        let (covered, total) = instruction_coverage(&sources);
        println!("Core instruction coverage by differential tests: {covered}/{total}");
        let missing: Vec<&str> = CORE_INSTRUCTIONS
            .iter()
            .filter(|(_, file, evidence)| {
                !std::fs::read_to_string(sources.join(file)).is_ok_and(|t| t.contains(evidence))
            })
            .map(|(name, _, _)| *name)
            .collect();
        assert!(
            missing.is_empty(),
            "instructions without a differential test: {missing:?}"
        );
    }

    #[test]
    fn coverage_counts_missing_sources_as_uncovered() {
        let (covered, total) = instruction_coverage(std::path::Path::new("/nonexistent"));
        assert_eq!(covered, 0);
        assert_eq!(total, CORE_INSTRUCTIONS.len());
    }
}
