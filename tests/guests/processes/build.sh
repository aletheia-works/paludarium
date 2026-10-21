#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/../../../target/guests/u8}"
mkdir -p "$out"
musl-gcc -static -pthread -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/u8-process" "$here/process.c"
rustc --target x86_64-unknown-linux-musl -C opt-level=1 -C target-feature=+crt-static -o "$out/u8-command" "$here/command.rs"
