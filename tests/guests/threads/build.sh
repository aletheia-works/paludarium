#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/../../../target/guests/u5}"
mkdir -p "$out"
for case_id in {0..42}; do
  "${MUSL_CC:-musl-gcc}" -static -O1 -nostdlib -fno-stack-protector -fno-builtin \
    -fno-asynchronous-unwind-tables -fcf-protection=none -mno-red-zone -fno-pie -no-pie \
    -Wall -Wextra -Werror -DCASE="$case_id" -o "$out/thread-$case_id" "$here/threads.c"
done
