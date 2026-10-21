#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/../../../target/guests/u4}"
mkdir -p "$out"
for case_id in {0..9}; do
  "${MUSL_CC:-musl-gcc}" -static -O1 -nostdlib -fno-stack-protector -fno-builtin \
    -fno-asynchronous-unwind-tables -fcf-protection=none -mno-red-zone -fno-pie -no-pie \
    -DCASE="$case_id" -o "$out/memory-$case_id" "$here/memory.c"
done

cc -O1 -fno-inline -no-pie "$here/write-restart-oracle.c" -o "$out/write-restart-oracle"
cc -O1 "$here/stop-continue-oracle.c" -o "$out/stop-continue-oracle"
cc -O1 "$here/realtime-order-oracle.c" -o "$out/realtime-order-oracle"
for case_id in {0..7}; do
  "${MUSL_CC:-musl-gcc}" -static -O1 -nostdlib -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables -fcf-protection=none -mno-red-zone -fno-pie -no-pie -DCASE="$case_id" -o "$out/time-$case_id" "$here/time.c"
done
for case_id in {0..22}; do
  "${MUSL_CC:-musl-gcc}" -static -O1 -nostdlib -mgeneral-regs-only -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables -fcf-protection=none -mno-red-zone -fno-pie -no-pie -DCASE="$case_id" -o "$out/signals-$case_id" "$here/signals.c"
done



