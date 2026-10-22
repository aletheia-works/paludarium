#!/usr/bin/env bash
# Prints the toolchain pinned in rust-toolchain.toml of the current directory
# (its channel), so CI names the pin without repeating it; scripts/bump-pins.py
# moves the pin.
#
#   bash scripts/rust-toolchain.sh   # for example nightly-2026-10-11
set -euo pipefail

channel=$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' rust-toolchain.toml | head -n 1)
if [ -z "$channel" ]; then
  echo "no channel in $PWD/rust-toolchain.toml" >&2
  exit 1
fi
printf '%s\n' "$channel"
