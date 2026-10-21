#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/../../../target/guests/u9}"
mkdir -p "$out"
for id in {0..13}; do
  "${MUSL_CC:-musl-gcc}" -static -O1 -nostdlib -mgeneral-regs-only -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables -fcf-protection=none -mno-red-zone -fno-pie -no-pie -DCASE="$id" -o "$out/io-$id" "$here/io.c"
done
