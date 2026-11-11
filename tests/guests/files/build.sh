#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/../../../target/guests/files}"
mkdir -p "$out"
# 60 and 61 are arguments.c's, below.
for id in {0..59} 62 63 64 65 66 67 68 74; do
  musl-gcc -static -O1 -nostdlib -mgeneral-regs-only -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables -fcf-protection=none -mno-red-zone -fno-pie -no-pie -DCASE="$id" -o "$out/files-$id" "$here/files.c"
done
# 69 to 73 are splice.c's: splice, tee and vmsplice, and (73) a signal
# interrupting sendfile and splice.
for id in 69 70 71 72 73; do
  musl-gcc -static -O1 -nostdlib -mgeneral-regs-only -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables -fcf-protection=none -mno-red-zone -fno-pie -no-pie -DCASE="$id" -o "$out/files-$id" "$here/splice.c"
done
musl-gcc -static -O1 -nostdlib -mgeneral-regs-only -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables -fcf-protection=none -mno-red-zone -fno-pie -no-pie -o "$out/mtime" "$here/mtime.c"
# Cases 60 and 61 print with musl's printf, so they are linked with the C library.
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/files-60" "$here/arguments.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -DRESTARTS -o "$out/files-61" "$here/arguments.c"
