#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/../../../target/guests/files}"
mkdir -p "$out"
for id in {0..59}; do
  musl-gcc -static -O1 -nostdlib -mgeneral-regs-only -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables -fcf-protection=none -mno-red-zone -fno-pie -no-pie -DCASE="$id" -o "$out/files-$id" "$here/files.c"
done
musl-gcc -static -O1 -nostdlib -mgeneral-regs-only -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables -fcf-protection=none -mno-red-zone -fno-pie -no-pie -o "$out/mtime" "$here/mtime.c"
# Case 60 prints with musl's printf, so it is linked with the C library.
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/files-60" "$here/arguments.c"
