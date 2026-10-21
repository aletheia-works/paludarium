#!/usr/bin/env bash
# Build the differential-test guests from source. x86-64 Linux only:
# CI's ubuntu runner, or locally inside mise-tasks/linux-dev.sh.
#
#   tests/guests/build.sh [output-dir]      (default: target/guests)
#
# Requires musl-gcc (Debian/Ubuntu: musl-tools) and the
# x86_64-unknown-linux-musl Rust target (rust-toolchain.toml installs it).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="${1:-${PALUDARIUM_GUEST_DIR:-$root/target/guests}}"
mkdir -p "$out"

cc="${MUSL_CC:-musl-gcc}"
if ! command -v "$cc" >/dev/null 2>&1; then
  echo "build.sh: $cc not found (install musl-tools)" >&2
  exit 1
fi

# C hello world: write + exit only.
"$cc" -static -O2 -o "$out/hello-c" "$here/hello-c/hello.c"

# Rust hello world (println!).
cargo build --quiet --locked --release \
  --manifest-path "$here/hello-rs/Cargo.toml" \
  --target x86_64-unknown-linux-musl \
  --target-dir "$out/hello-rs-target"
cp "$out/hello-rs-target/x86_64-unknown-linux-musl/release/hello-rs" "$out/hello-rs"

# Per-instruction guests: no libc, own _start, so the only
# instructions executed are the ones under test plus the tiny print helpers.
shopt -s nullglob
for src in "$here"/insn/*.c; do
  name="$(basename "$src" .c)"
  "$cc" -static -O1 -nostdlib -fno-stack-protector -fno-builtin \
    -fno-asynchronous-unwind-tables -fcf-protection=none -mno-red-zone \
    -fno-tree-loop-distribute-patterns -fno-pie -no-pie \
    -I "$here/insn" -o "$out/insn-$name" "$src"
done

echo "guests built in $out" >&2
