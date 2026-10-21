"""Unwind membership is evidence, not a proof that an instruction executes."""

import bisect
import json
import pathlib
import re

root = pathlib.Path("/work/target/u2-inventory")
ranges = []
for line in (root / "aube.frames").open():
    match = re.search(r"pc=(?:0x)?([0-9a-f]+)\.\.(?:0x)?([0-9a-f]+)", line)
    if match:
        ranges.append((int(match[1], 16), int(match[2], 16)))
ranges.sort()
starts = [start for start, _ in ranges]
candidates = [
    "adcx",
    "adox",
    "andn",
    "bzhi",
    "enter",
    "enterw",
    "leavew",
    "popfw",
    "popf",
    "pushf",
    "movbe",
    "mulx",
    "pext",
    "rorx",
    "shlx",
    "shrx",
    "xlat",
]
results = {
    name: {
        "rows": 0,
        "inside_fde": 0,
        "outside_fde": 0,
        "inside_samples": [],
        "outside_samples": [],
    }
    for name in candidates
}
for line in (root / "aube.disassembly").open():
    match = re.match(r"\s*([0-9a-f]+):\s+(.+)", line)
    if not match:
        continue
    asm = match[2].strip()
    tokens = asm.split()
    while tokens and (
        tokens[0]
        in {
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
        or tokens[0].startswith("rex")
    ):
        tokens.pop(0)
    if not tokens:
        continue
    name = tokens[0]
    if name not in results:
        continue
    address = int(match[1], 16)
    index = bisect.bisect_right(starts, address) - 1
    inside = index >= 0 and address < ranges[index][1]
    kind = "inside" if inside else "outside"
    result = results[name]
    result["rows"] += 1
    result[kind + "_fde"] += 1
    if len(result[kind + "_samples"]) < 4:
        result[kind + "_samples"].append({"address": match[1], "asm": asm})
(root / "aube.candidate-classification.json").write_text(
    json.dumps(
        {
            "fde_ranges": len(ranges),
            "note": "Absence from FDE alone does not justify exclusion",
            "candidates": results,
        },
        indent=2,
    )
)
for name, result in results.items():
    print(
        name,
        result["rows"],
        "inside_fde",
        result["inside_fde"],
        "outside_fde",
        result["outside_fde"],
    )
