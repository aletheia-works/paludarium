"""Summarize static disassembly; static presence does not prove execution."""

import collections
import json
import pathlib
import re

root = pathlib.Path("/work/target/instructions-inventory")
prefixes = {
    "lock",
    "rep",
    "repe",
    "repz",
    "repne",
    "repnz",
    "data16",
    "addr32",
    "cs",
    "ds",
    "es",
    "ss",
    "fs",
    "gs",
    "bnd",
    "xacquire",
    "xrelease",
    "{evex}",
}
registers = re.compile(
    r"\b(?:r(?:1[0-5]|[89])(?:d|w|b)?|[re]?(?:ax|bx|cx|dx|si|di|bp|sp)|[abcd][hl]|[xyz]mm\d+)\b"
)


def register_class(match):
    name = match.group(0)
    if name.startswith(("xmm", "ymm", "zmm")):
        return name[:3]
    if name in ("ah", "bh", "ch", "dh"):
        return "high8"
    if name.endswith("b") or name in ("al", "bl", "cl", "dl", "sil", "dil", "spl", "bpl"):
        return "reg8"
    if name.endswith("w") or name in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
        return "reg16"
    return "reg32" if name.startswith("e") or name.endswith("d") else "reg64"


for name in ("probe", "aube"):
    counts = collections.Counter()
    samples = {}
    mnemonics = collections.Counter()
    invalid_rows = 0
    for line in (root / (name + ".disassembly")).open():
        matched = re.match(r"\s*([0-9a-f]+):\s+(.+)", line)
        if not matched:
            continue
        asm = matched.group(2).split("#", 1)[0].strip()
        tokens = asm.split()
        index = 0
        while index < len(tokens) and (
            tokens[index] in prefixes or tokens[index].startswith("rex")
        ):
            index += 1
        if index == len(tokens):
            continue
        mnemonic = tokens[index]
        if mnemonic in ("(bad)", ".byte"):
            invalid_rows += 1
            continue
        mnemonics[mnemonic] += 1
        form = re.sub(r"<[^>]+>", "<symbol>", asm)
        form = registers.sub(register_class, form)
        form = re.sub(r"\b(?:0x[0-9a-f]+|[0-9][0-9a-f]*)\b", "IMM", form)
        counts[form] += 1
        samples.setdefault(form, {"address": matched.group(1), "asm": asm})
    result = {
        "binary": name,
        "kind": "static-presence",
        "complete_runtime_inventory": False,
        "instruction_rows": sum(mnemonics.values()),
        "invalid_disassembly_rows": invalid_rows,
        "mnemonics": dict(sorted(mnemonics.items())),
        "forms": [
            {"form": form, "count": count, "sample": samples[form]}
            for form, count in sorted(counts.items())
        ],
    }
    (root / (name + ".static.json")).write_text(json.dumps(result, indent=2))
    print(
        name, "rows", result["instruction_rows"], "mnemonics", len(mnemonics), "forms", len(counts)
    )
