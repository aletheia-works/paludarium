"""Generate native-only SSE observers; expectations are regenerated each run."""

import sys
from pathlib import Path

output = Path(sys.argv[1])
output.mkdir(parents=True, exist_ok=True)
names = [
    "addpd",
    "addps",
    "addsd",
    "andnpd",
    "andpd",
    "andps",
    "blendvps",
    "cmpeqsd",
    "cmpltsd",
    "cmpneqsd",
    "cmpunordsd",
    "comisd",
    "cvtdq2ps",
    "cvtsi2sd",
    "cvtss2sd",
    "cvttps2dq",
    "cvttsd2si",
    "cvttss2si",
    "divpd",
    "divsd",
    "divss",
    "lddqu",
    "ldmxcsr",
    "maxsd",
    "minsd",
    "movapd",
    "movaps",
    "movd",
    "movddup",
    "movdqa",
    "movdqu",
    "movhlps",
    "movhpd",
    "movhps",
    "movlhps",
    "movlpd",
    "movlps",
    "movmskpd",
    "movmskps",
    "movq",
    "movsd",
    "movss",
    "movupd",
    "movups",
    "mulpd",
    "mulsd",
    "orpd",
    "orps",
    "packssdw",
    "packsswb",
    "packuswb",
    "paddb",
    "paddd",
    "paddq",
    "paddusw",
    "paddw",
    "palignr",
    "pand",
    "pandn",
    "pblendw",
    "pcmpeqb",
    "pcmpeqd",
    "pcmpeqw",
    "pcmpgtb",
    "pcmpgtd",
    "pcmpgtw",
    "pextrb",
    "pextrd",
    "pextrq",
    "pextrw",
    "pinsrb",
    "pinsrd",
    "pinsrq",
    "pinsrw",
    "pmaddubsw",
    "pmaddwd",
    "pmaxub",
    "pminub",
    "pmovmskb",
    "pmovzxdq",
    "pmulhuw",
    "pmulhw",
    "pmullw",
    "pmuludq",
    "por",
    "psadbw",
    "pshufb",
    "pshufd",
    "pshufhw",
    "pshuflw",
    "pslld",
    "pslldq",
    "psllq",
    "psllw",
    "psrad",
    "psraw",
    "psrld",
    "psrldq",
    "psrlq",
    "psrlw",
    "psubb",
    "psubd",
    "psubq",
    "psubusb",
    "psubusw",
    "psubw",
    "ptest",
    "punpckhbw",
    "punpckhdq",
    "punpckhqdq",
    "punpckhwd",
    "punpcklbw",
    "punpckldq",
    "punpcklqdq",
    "punpcklwd",
    "pxor",
    "shufpd",
    "shufps",
    "sqrtps",
    "sqrtsd",
    "subpd",
    "subsd",
    "ucomisd",
    "ucomiss",
    "unpckhpd",
    "unpcklpd",
    "unpcklps",
    "xorpd",
    "xorps",
]
assert len(names) == 129
cases = []
for name in names:
    insn = f"{name} xmm0, xmm1"
    if name in ("lddqu", "movhpd", "movhps", "movlpd", "movlps"):
        insn = f"{name} xmm0, [rdx+16]"
    elif name == "ldmxcsr":
        insn = "ldmxcsr [rdx+256]"
    elif name in ("movmskpd", "movmskps", "pmovmskb"):
        insn = f"{name} eax, xmm1"
    elif name in ("movd", "movq"):
        insn = f"{name} xmm0, {'eax' if name == 'movd' else 'rax'}"
    elif name.startswith("pextr"):
        insn = f"{name} {'rax' if name == 'pextrq' else 'eax'}, xmm1, 3"
    elif name.startswith("pinsr"):
        insn = f"{name} xmm0, {'rax' if name == 'pinsrq' else 'eax'}, 3"
    elif name == "cvtsi2sd":
        insn = "cvtsi2sd xmm0, rax"
    elif name in ("cvttsd2si", "cvttss2si"):
        insn = f"{name} rax, xmm1"
    elif name.startswith("cmp"):
        insn = f"cmpsd xmm0, xmm1, {dict(cmpeqsd=0, cmpltsd=1, cmpneqsd=4, cmpunordsd=3)[name]}"
    elif name in ("pslldq", "psrldq"):
        insn = f"{name} xmm0, 3"
    elif name in ("pshufd", "pshufhw", "pshuflw", "shufps"):
        insn += ", 0x1b"
    elif name == "shufpd":
        insn += ", 3"
    elif name == "palignr":
        insn += ", 17"
    elif name == "pblendw":
        insn += ", 0xa5"
    cases.append((name, insn))
cases.extend(
    (n, f"{n} xmm0, xmm1")
    for n in ["sha256rnds2", "sha256msg1", "sha256msg2", "aesenc", "aesenclast"]
)
cases.extend((f"pclmulqdq_{i:02x}", f"pclmulqdq xmm0, xmm1, {i}") for i in [0, 17, 128, 238])
# Distinct high registers, aliasing, and memory forms are native cases first.
base_cases = list(cases)
for name, insn in base_cases:
    if "xmm0" in insn:
        cases.append((name + "_high", insn.replace("xmm0", "xmm8").replace("xmm1", "xmm9")))
    if "xmm0" in insn and "xmm1" in insn:
        cases.append((name + "_alias", insn.replace("xmm1", "xmm0")))
    if "xmm1" in insn and not name.startswith(
        ("pextr", "movmsk", "pmovmskb", "movhlps", "movlhps")
    ):
        cases.append((name + "_memory", insn.replace("xmm1", "[rdx+16]")))
    if name in ("movd", "movq"):
        gpr = "eax" if name == "movd" else "rax"
        cases.append((name + "_reverse", f"{name} {gpr}, xmm1"))
        cases.append((name + "_memory_load", f"{name} xmm0, [rdx+16]"))
        cases.append((name + "_memory_store", f"{name} [rdx+16], xmm1"))
    if name in (
        "movaps",
        "movups",
        "movapd",
        "movupd",
        "movdqa",
        "movdqu",
        "movss",
        "movsd",
        "movlps",
        "movhps",
        "movlpd",
        "movhpd",
    ):
        cases.append((name + "_store", f"{name} [rdx+16], xmm0"))
    if name in ("psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq", "psraw", "psrad"):
        for amount in [0, 15, 16, 31, 32, 63, 64, 255]:
            cases.append((name + f"_imm{amount}", f"{name} xmm0, {amount}"))
cases.append(("stmxcsr", "stmxcsr [rdx+256]"))
assembly = [".intel_syntax noprefix", ".text"]
declarations = []
for i, (_name, insn) in enumerate(cases):
    label = f"u3_case_{i}"
    declarations.append(
        f"extern void {label}(void *, const void *, void *); extern unsigned char {label}_op[], {label}_end[];"
    )
    assembly += [f".global {label}, {label}_op, {label}_end", f"{label}:"]
    assembly += [f"movdqu xmm{k}, [rsi+{k * 16}]" for k in range(16)]
    assembly += [
        "ldmxcsr [rsi+256]",
        "movabs rax, 0x800000017fff0011",
        "push 0x8d7",
        "popfq",
        f"{label}_op:",
        insn,
        f"{label}_end:",
    ]
    assembly += [f"movdqu [rdi+{k * 16}], xmm{k}" for k in range(16)]
    assembly += [
        "mov [rdi+256], rax",
        "pushfq",
        "pop r10",
        "mov [rdi+264], r10",
        "stmxcsr [rdi+272]",
        "ret",
    ]
assembly += ['.section .note.GNU-stack,"",@progbits']
(output / "cases.S").write_text("\n".join(assembly) + "\n")
header = "\n".join(declarations) + "\nstatic const struct u3_case cases[] = {\n"
header += "\n".join(
    f'{{"{n}",u3_case_{i},u3_case_{i}_op,u3_case_{i}_end,{int("[rdx" in insn)}}},'
    for i, (n, insn) in enumerate(cases)
)
(output / "cases.h").write_text(header + "\n};\n")
print(f"Generated {len(cases)} native observers; expected values not yet measured.")
