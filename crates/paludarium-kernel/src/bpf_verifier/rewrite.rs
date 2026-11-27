//! How long a verified program is after Linux's rewrites, which come after
//! the walk in `bpf_check` (7.0's, which master's do as well): the
//! program's memory grows to it (`bpf_patch_insn_single` reallocates
//! `prog->pages`, which never shrink) and its socket is charged for it
//! (`sk_filter_charge`). The interpreter runs the instructions as loaded;
//! only their number is what the rewrites make it here.
//!
//! In order, each a pass over the program:
//! - `opt_hard_wire_dead_code_branches`, `opt_remove_dead_code` and
//!   `opt_remove_nops` (the loader has `CAP_BPF`): a conditional jump one
//!   of whose sides no path took becomes a `BPF_JA`, the instructions no
//!   path reached go, and then each `BPF_JA` of 0 as the pass comes to it
//!   (`remove_fastcall_spills_fills` makes none: a socket filter's
//!   `bpf_get_smp_processor_id` is `bpf_get_raw_smp_processor_id_proto`,
//!   which has no `bpf_fastcall`);
//! - `convert_ctx_accesses`: an access to the `struct __sk_buff` becomes
//!   the loads of `struct sk_buff` that `bpf_convert_ctx_access` gives;
//! - `do_misc_fixups`: a division or remainder by a register gets its
//!   checks of 0 and -1, `BPF_LD_ABS` and `BPF_LD_IND` their calls
//!   (`bpf_gen_ld_abs`), `bpf_get_smp_processor_id` is inlined as the
//!   x86-64 JIT allows, and so is a lookup of one map;
//! - `opt_subreg_zext_lo32_rnd_hi32`: on x86-64, a 32-bit
//!   `BPF_CMPXCHG` whose R0 is read as 64 bits gets a zero-extension,
//!   and with `BPF_F_TEST_RND_HI32` a 32-bit definition read as no more
//!   gets random upper bits.
//!
//! A rewrite whose jumps no longer reach in 16 bits is `ENOMEM`, with
//! the original instruction's index in the log (`bpf_patch_insn_data`).
use super::{
    Checked, F_INNER_MAP, Insn, MapShape, alu, class, def32, func, jmp, map_type, mode, size,
};
use paludarium_types::Errno;
use std::collections::BTreeMap;

/// What the walk found that the rewrites depend on.
pub(super) struct Facts<'a> {
    pub(super) insns: &'a [Insn],
    /// `seen`, per instruction.
    pub(super) seen: &'a [bool],
    /// Each load or store, and whether through the context.
    pub(super) through_ctx: &'a BTreeMap<usize, bool>,
    /// Each lookup, and its one map.
    pub(super) lookups: &'a BTreeMap<usize, Option<u8>>,
    pub(super) maps: &'a [MapShape],
    /// `zext_dst`, per instruction.
    pub(super) zext: &'a [bool],
    pub(super) rnd_hi32: bool,
}

/// `prog->len` after the rewrites.
pub(super) fn len(f: &Facts<'_>) -> Checked<usize> {
    let n = f.insns.len();
    // Where each instruction is once those no path reached are gone.
    let mut seen_before = vec![0; n + 1];
    for i in 0..n {
        seen_before[i + 1] = seen_before[i] + usize::from(f.seen[i]);
    }
    let kept: Vec<usize> = (0..n)
        .filter(|&i| f.seen[i] && !removed_nop(f, &seen_before, i))
        .collect();
    // The patches, in the passes' order: where, how many instructions
    // the one there becomes, and the jumps.
    let mut patches = Vec::new();
    let mut patched = vec![false; n];
    for pass in [ctx_access, misc_fixup] {
        for (at, &i) in kept.iter().enumerate() {
            if let Some(cnt) = pass(f, i) {
                patched[i] = true;
                patches.push((at, cnt, i));
            }
        }
    }
    for (at, &i) in kept.iter().enumerate() {
        if patched[i] {
            continue;
        }
        if let Some(cnt) = zext_patch(f, i) {
            patches.push((at, cnt, i));
        }
    }
    let len = kept.len() + patches.iter().map(|&(_, cnt, _)| cnt - 1).sum::<usize>();
    if len > i16::MAX as usize {
        check_ranges(f, &kept, &patches)?;
    }
    Ok(len)
}

/// `insn_is_cond_jump`.
fn cond_jump(insn: Insn) -> bool {
    match insn.class() {
        class::JMP32 => insn.op() != jmp::JA,
        class::JMP => !matches!(insn.op(), jmp::JA | jmp::EXIT | jmp::CALL),
        _ => false,
    }
}

/// Where a jump that remains goes once the dead code is gone, as the
/// index of the instruction it jumps to in the original program: a
/// conditional jump one of whose sides is dead goes to the other.
fn target(f: &Facts<'_>, i: usize) -> usize {
    let insn = f.insns[i];
    let taken = (i as i64 + insn.jump() + 1) as usize;
    if cond_jump(insn) && f.seen[i + 1] && !f.seen[taken] {
        i + 1
    } else {
        taken
    }
}

/// Whether `opt_remove_nops` removes the instruction at `i`, which a path
/// reached: a `BPF_JA` of 0, all its other fields 0 too, once the dead
/// code is gone. Linux compares the instruction whole with
/// `BPF_JMP_IMM(BPF_JA, 0, 0, 0)`, so a 32-bit `BPF_JA` (`gotol`) of 0
/// stays. It goes through the program once, so a jump that only a
/// later removal makes one of 0 stays.
fn removed_nop(f: &Facts<'_>, seen_before: &[usize], i: usize) -> bool {
    let insn = f.insns[i];
    let ja = insn.code == class::JMP | jmp::JA && insn.dst == 0 && insn.src == 0 && insn.imm == 0;
    // opt_hard_wire_dead_code_branches.
    let taken = (i as i64 + insn.jump() + 1) as usize;
    let wired = cond_jump(insn) && (!f.seen[i + 1] || !f.seen[taken]);
    if !ja && !wired {
        return false;
    }
    let to = target(f, i);
    to == i + 1 || seen_before[to] - seen_before[i] - 1 == 0
}

/// `convert_ctx_accesses` of the instruction at `i`, if it goes through
/// the context: what `bpf_convert_ctx_access` makes of it, with a narrow
/// load's shift and mask, and a sign extension's move.
fn ctx_access(f: &Facts<'_>, i: usize) -> Option<usize> {
    if f.through_ctx.get(&i) != Some(&true) {
        return None;
    }
    let insn = f.insns[i];
    let off = i64::from(insn.off);
    if insn.class() != class::LDX {
        // A store, which only `cb` takes: one store of `sk_buff`'s.
        return Some(1);
    }
    let bytes = match insn.size() {
        size::B => 1,
        size::H => 2,
        size::W => 4,
        _ => 8,
    };
    let sx = usize::from(insn.mode() == mode::MEMSX);
    // `cb` is read as it is, at any width.
    if (48..68).contains(&off) {
        return Some(1 + sx);
    }
    // The other fields are 4 bytes that a narrower load reads from the
    // aligned field (the x86-64 kernel's, with NET_SKBUFF_DATA_USES_OFFSET
    // and CONFIG_NET_RX_BUSY_POLL): the loads, and the bytes of the
    // field the load converts to.
    let field = off & !3;
    let (cnt, target_size) = match field {
        0 | 8 | 32 | 36 | 68 => (1, 4),
        4 => (2, 1),
        12 | 16 | 24 | 28 | 44 => (1, 2),
        20 | 40 | 84 => (3, 4),
        164 | 176 => (4, 2),
        // context_field refuses every other offset before the access is
        // recorded (the test below goes through them all).
        _ => unreachable!("the verifier takes no other field"),
    };
    let narrow = bytes < 4 && bytes < target_size;
    let extra = if narrow {
        1 + usize::from(off & 3 != 0)
    } else {
        0
    };
    Some(cnt + extra + sx)
}

/// `do_misc_fixups` of the instruction at `i`.
fn misc_fixup(f: &Facts<'_>, i: usize) -> Option<usize> {
    let insn = f.insns[i];
    let alu = matches!(insn.class(), class::ALU | class::ALU64);
    let wide = insn.class() == class::ALU64;
    let signed = insn.off == 1;
    match insn.class() {
        // A signed division or remainder by -1 is a negation or a 0.
        _ if alu && !insn.x() && matches!(insn.op(), alu::DIV | alu::MOD) => {
            (signed && insn.imm == -1).then_some(1)
        }
        _ if alu && insn.x() && insn.op() == alu::DIV => Some(if signed { 8 } else { 4 }),
        _ if alu && insn.x() && insn.op() == alu::MOD => Some(match (signed, wide) {
            (true, true) => 7,
            (true, false) => 9,
            (false, true) => 2,
            (false, false) => 4,
        }),
        class::LD if matches!(insn.mode(), mode::ABS | mode::IND) => {
            Some(if insn.mode() == mode::IND && insn.imm != 0 {
                7
            } else {
                6
            })
        }
        class::JMP if insn.op() == jmp::CALL && insn.src == 0 => match insn.imm {
            func::GET_SMP_PROCESSOR_ID => Some(3),
            func::MAP_LOOKUP_ELEM => {
                let map = &f.maps[usize::from(f.lookups.get(&i).copied().flatten()?)];
                match map.kind {
                    // array_map_gen_lookup, which an inner map has none of.
                    map_type::ARRAY if map.flags & F_INNER_MAP == 0 => {
                        Some(if map.bypass_spec { 7 } else { 8 })
                    }
                    // htab_map_gen_lookup, htab_lru_map_gen_lookup.
                    map_type::HASH => Some(3),
                    map_type::LRU_HASH => Some(6),
                    _ => None,
                }
            }
            _ => None,
        },
        _ => None,
    }
}

/// `opt_subreg_zext_lo32_rnd_hi32` of an instruction no other pass
/// patched: x86-64 needs no zero-extension but a `BPF_CMPXCHG`'s; with
/// `BPF_F_TEST_RND_HI32`, a 32-bit definition nothing reads as 64 bits
/// is followed by three instructions that set its upper half.
fn zext_patch(f: &Facts<'_>, i: usize) -> Option<usize> {
    let insn = f.insns[i];
    let (_, narrow) = def32(insn)?;
    if !narrow {
        return None;
    }
    if f.zext[i] {
        let cmpxchg = insn.class() == class::STX && insn.imm == super::atomic::CMPXCHG;
        cmpxchg.then_some(2)
    } else {
        f.rnd_hi32.then_some(4)
    }
}

/// The 16-bit jumps of a program longer than `S16_MAX` after the
/// rewrites: the first patch after which one of them no longer reaches
/// (`bpf_adj_branches` in its probing pass) is refused.
fn check_ranges(f: &Facts<'_>, kept: &[usize], patches: &[(usize, usize, usize)]) -> Checked<()> {
    let at: BTreeMap<usize, usize> = kept.iter().enumerate().map(|(k, &i)| (i, k)).collect();
    // A jump that remains, where it is and the instruction it goes to
    // among those kept (a removed one's next), both forward.
    let place = |i: usize| kept.partition_point(|&k| k < i);
    let jumps: Vec<(usize, usize)> = kept
        .iter()
        .filter(|&&i| {
            let insn = f.insns[i];
            insn.class() == class::JMP && insn.op() == jmp::JA || cond_jump(insn)
        })
        .map(|&i| (at[&i], place(target(f, i))))
        .collect();
    let overflows = |count: usize| {
        let mut grown = vec![0i64; kept.len() + 1];
        for &(p, cnt, _) in &patches[..count] {
            grown[p + 1] += cnt as i64 - 1;
        }
        for k in 0..kept.len() {
            grown[k + 1] += grown[k];
        }
        // Each jump's offset with the patches strictly between it and its
        // target.
        jumps.iter().any(|&(p, t)| {
            let between = if t > p + 1 {
                grown[t] - grown[p + 1]
            } else {
                0
            };
            (t - p - 1) as i64 + between > i64::from(i16::MAX)
        })
    };
    if !overflows(patches.len()) {
        return Ok(());
    }
    // The offsets only grow, so the first patch that makes one too far is
    // found by halves.
    let (mut lo, mut hi) = (0, patches.len());
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if overflows(mid) {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    Err((
        Errno::ENOMEM,
        format!(
            "insn {} cannot be patched due to 16-bit range",
            patches[hi - 1].2
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn i(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
        Insn {
            code,
            dst,
            src,
            off,
            imm,
        }
    }

    fn facts<'a>(
        insns: &'a [Insn],
        seen: &'a [bool],
        zext: &'a [bool],
        empty: &'a (BTreeMap<usize, bool>, BTreeMap<usize, Option<u8>>),
    ) -> Facts<'a> {
        Facts {
            insns,
            seen,
            through_ctx: &empty.0,
            lookups: &empty.1,
            maps: &[],
            zext,
            rnd_hi32: false,
        }
    }

    #[test]
    fn dead_code_and_jumps_of_0_go() {
        let exit = i(class::JMP | jmp::EXIT, 0, 0, 0, 0);
        let mov = i(class::ALU64 | alu::MOV, 0, 0, 0, 0);
        let ja = |off| i(class::JMP | jmp::JA, 0, 0, off, 0);
        let jeq = |off| i(class::JMP | jmp::JEQ, 1, 0, off, 0);
        let empty = Default::default();
        // ja +1 over a dead mov becomes ja 0 and goes, with the mov.
        let insns = [ja(1), mov, mov, exit];
        let seen = [true, false, true, true];
        let n = [false; 4];
        assert_eq!(len(&facts(&insns, &seen, &n, &empty)), Ok(2));
        // A jump over a nop that goes later stays as a jump of 0.
        let insns = [ja(1), ja(0), mov, exit];
        let seen = [true; 4];
        assert_eq!(len(&facts(&insns, &seen, &n, &empty)), Ok(3));
        // A conditional jump whose target is dead is a jump of 0, and one
        // whose fall-through is dead goes to the target.
        let insns = [jeq(1), mov, mov, exit];
        let seen = [true, true, false, true];
        assert_eq!(len(&facts(&insns, &seen, &n, &empty)), Ok(2));
        let seen = [true, false, true, true];
        assert_eq!(len(&facts(&insns, &seen, &n, &empty)), Ok(2));
        // Both sides taken: the jump stays.
        let seen = [true; 4];
        assert_eq!(len(&facts(&insns, &seen, &n, &empty)), Ok(4));
    }

    #[test]
    fn the_fixups_make_linux_s_counts() {
        let exit = i(class::JMP | jmp::EXIT, 0, 0, 0, 0);
        let x = 0x08;
        let empty = Default::default();
        let count = |insn: Insn| {
            let insns = [insn, exit];
            let seen = [true; 2];
            let n = [false; 2];
            len(&facts(&insns, &seen, &n, &empty)).unwrap() - 1
        };
        assert_eq!(count(i(class::ALU64 | alu::DIV | x, 0, 1, 1, 0)), 8);
        assert_eq!(count(i(class::ALU64 | alu::DIV | x, 0, 1, 0, 0)), 4);
        assert_eq!(count(i(class::ALU64 | alu::MOD | x, 0, 1, 1, 0)), 7);
        assert_eq!(count(i(class::ALU | alu::MOD | x, 0, 1, 1, 0)), 9);
        assert_eq!(count(i(class::ALU64 | alu::MOD | x, 0, 1, 0, 0)), 2);
        assert_eq!(count(i(class::ALU | alu::MOD | x, 0, 1, 0, 0)), 4);
        assert_eq!(count(i(class::ALU64 | alu::DIV, 0, 0, 1, -1)), 1);
        assert_eq!(count(i(class::LD | mode::ABS | size::B, 0, 0, 0, 1)), 6);
        assert_eq!(count(i(class::LD | mode::IND | size::W, 0, 2, 0, 0)), 6);
        assert_eq!(count(i(class::LD | mode::IND | size::H, 0, 2, 0, 3)), 7);
        assert_eq!(
            count(i(
                class::JMP | jmp::CALL,
                0,
                0,
                0,
                func::GET_SMP_PROCESSOR_ID
            )),
            3
        );
    }
}
