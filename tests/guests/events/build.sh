#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/../../../target/guests/u6}"
mkdir -p "$out"
for case_id in {0..81}; do
  "${MUSL_CC:-musl-gcc}" -static -O1 -nostdlib -fno-stack-protector -fno-builtin \
    -fno-asynchronous-unwind-tables -fcf-protection=none -mno-red-zone -fno-pie -no-pie \
    -Wall -Wextra -Werror -DCASE="$case_id" -o "$out/event-$case_id" "$here/events.c"
done
if [[ "${U6_BUILD_RUST:-1}" == 1 ]]; then
  rust_target="$here/../../../target/u6-target-guests"
  cargo build --locked --manifest-path "$here/rust/Cargo.toml" --target-dir "$rust_target" --target x86_64-unknown-linux-musl --release
  cp "$rust_target/x86_64-unknown-linux-musl/release/u6-timer" "$out/u6-timer"
  cp "$rust_target/x86_64-unknown-linux-musl/release/u6-unix" "$out/u6-unix"
fi
