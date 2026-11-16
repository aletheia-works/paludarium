"""check.py <times.txt>: the medians of each case with and without the native
JIT, and a failure for every case the JIT makes slower than every round
without it (its fastest round slower than the slowest round without it)."""

import collections
import statistics
import sys

times = collections.defaultdict(list)
with open(sys.argv[1]) as lines:
    for line in lines:
        p = line.split()
        if (len(p) == 4 and p[0] == "time") or (len(p) == 5 and p[0] == "case"):
            times[(p[1], p[2])].append(float(p[3]))

slower = []
for case in sorted({c for c, _ in times}):
    off, on = times.get((case, "interpreter")), times.get((case, "jit"))
    if not off or not on:
        continue
    a, b = statistics.median(off), statistics.median(on)
    flag = ""
    if min(on) > max(off):
        slower.append(case)
        flag = "  SLOWER"
    print(f"{case:26} interpreter {a:8.3f}  jit {b:8.3f}  {100 * (b - a) / a:+6.1f}%{flag}")
if slower:
    print(f"{len(slower)} cases slower with the JIT: {' '.join(slower)}")
    sys.exit(1)
print("no case slower with the JIT")
