#!/usr/bin/env bash
# U3 guest runner bootstrap. Instruction fixtures follow native-oracle design.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:?output directory required}"
mkdir -p "$out"
cc="${MUSL_CC:-musl-gcc}"
"$cc" -static -nostdlib -fno-pie -no-pie -o "$out/runner" "$here/runner.S"
python3 "$here/generate.py" "$out"
"$cc" -static -O2 -Wall -Wextra -Werror -I "$out" "$here/observe.c" "$out/cases.S" -o "$out/observe"
"$cc" -static -O2 -Wall -Wextra -Werror "$here/cpuid-observe.c" -o "$out/cpuid-observe"
"$cc" -static -O2 -Wall -Wextra -Werror -I "$out" "$here/fault-observe.c" "$out/cases.S" -o "$out/fault-observe"
