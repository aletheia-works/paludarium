#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/../../../target/guests/u7}"
mkdir -p "$out"
for id in {0..32}; do
  musl-gcc -static -O1 -nostdlib -mgeneral-regs-only -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables -fcf-protection=none -mno-red-zone -fno-pie -no-pie -DCASE="$id" -o "$out/files-$id" "$here/files.c"
done
musl-gcc -static -O1 -nostdlib -mgeneral-regs-only -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables -fcf-protection=none -mno-red-zone -fno-pie -no-pie -o "$out/mtime" "$here/mtime.c"




