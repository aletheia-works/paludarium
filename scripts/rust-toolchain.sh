#!/usr/bin/env bash
# Prints the toolchain pinned in rust-toolchain.toml of the current directory
# (its channel), so CI names the pin without repeating it; scripts/bump-pins.py
# moves the pin. With --rust-version it prints the workspace's rust-version in
# Cargo.toml instead: the latest stable Rust, which bump-pins.py also moves.
#
#   bash scripts/rust-toolchain.sh                  # for example nightly-2026-10-11
#   bash scripts/rust-toolchain.sh --rust-version   # for example 1.100.0
set -euo pipefail

if [ "${1:-}" = --rust-version ]; then
  version=$(sed -n 's/^rust-version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -n 1)
  if [ -z "$version" ]; then
    echo "no rust-version in $PWD/Cargo.toml" >&2
    exit 1
  fi
  printf '%s\n' "$version"
  exit 0
fi

channel=$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' rust-toolchain.toml | head -n 1)
if [ -z "$channel" ]; then
  echo "no channel in $PWD/rust-toolchain.toml" >&2
  exit 1
fi
printf '%s\n' "$channel"
