"""ab.py <times.txt>: for jit-ab.yml, the medians of each case and side
against the old commit's JIT, then for the A/A side (same-jit) and the change
(new-jit) the cases where every round is slower, or faster, than every round of
the old JIT. It fails when a program's output differed from native Linux's."""

import collections
import statistics
import sys

times = collections.defaultdict(lambda: collections.defaultdict(list))
wrong = []
with open(sys.argv[1]) as lines:
    for line in lines:
        p = line.split()
        if (len(p) == 4 and p[0] == "time") or (len(p) == 5 and p[0] == "case"):
            times[p[1]][p[2]].append(float(p[3]))
        if (len(p) == 5 and p[0] == "case" and p[4] == "False") or (p and p[0] == "DIFFERENT"):
            wrong.append(line.strip())

sides = ("old-interpreter", "old-jit", "same-jit", "new-jit")
for case, by in sorted(times.items()):
    if not by["old-jit"]:
        continue
    base = statistics.median(by["old-jit"])
    row = f"{case:24}"
    for side in sides:
        if by[side]:
            m = statistics.median(by[side])
            row += f"  {side} {m:8.3f} ({100 * (m - base) / base:+6.1f}%)"
    print(row)

for side in ("same-jit", "new-jit"):
    slower, faster, ratios = [], [], []
    for case, by in sorted(times.items()):
        old, new = by["old-jit"], by[side]
        if not old or not new:
            continue
        r = statistics.median(new) / statistics.median(old) - 1
        ratios.append(r)
        if min(new) > max(old):
            slower.append(f"{case} {r:+.1%}")
        if max(new) < min(old):
            faster.append(f"{case} {r:+.1%}")
    if not ratios:
        print(f"== {side}: no times")
        continue
    print(
        f"== {side} against old-jit: {len(ratios)} cases, median of medians "
        f"{statistics.median(ratios):+.1%}, range {min(ratios):+.1%} to {max(ratios):+.1%}"
    )
    print("strictly slower:", ", ".join(slower) or "none")
    print("strictly faster:", ", ".join(faster) or "none")

if wrong:
    print("\n".join(wrong))
    sys.exit(1)
