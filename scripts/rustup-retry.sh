#!/usr/bin/env bash
# Runs `rustup "$@"`, retrying a failed attempt.
#
# CI installs toolchains from static.rust-lang.org on every job. A download
# sometimes fails, and an interrupted install can leave a partially installed
# toolchain that the next install cannot replace ("detected conflict:
# 'bin/cargo-clippy'"). Before each retry this removes rustup's temporary
# files and, for `toolchain install`, the toolchain being installed, so the
# retry starts clean. `rustup toolchain install` without a name installs the
# toolchain of rust-toolchain.toml in the current directory.
#
#   scripts/rustup-retry.sh toolchain install nightly-2026-10-11 --profile minimal
#   scripts/rustup-retry.sh toolchain install
#   scripts/rustup-retry.sh target add wasm32-unknown-unknown --toolchain nightly-2026-10-11
#
# RUSTUP_RETRY_ATTEMPTS (default 3) and RUSTUP_RETRY_DELAY (seconds, default
# 15, multiplied by the attempt number) tune the retries.
set -euo pipefail

attempts=${RUSTUP_RETRY_ATTEMPTS:-3}
delay=${RUSTUP_RETRY_DELAY:-15}
home=${RUSTUP_HOME:-$HOME/.rustup}

# The toolchain a `toolchain install` installs: its first name argument, or
# the channel of rust-toolchain.toml.
toolchain=""
if [ "${1:-}" = toolchain ] && [ "${2:-}" = install ]; then
  shift_value=false
  for arg in "${@:3}"; do
    if $shift_value; then shift_value=false; continue; fi
    case $arg in
      --profile | -c | --component | -t | --target) shift_value=true ;;
      -*) ;;
      *) toolchain=$arg; break ;;
    esac
  done
  if [ -z "$toolchain" ] && [ -f rust-toolchain.toml ]; then
    toolchain=$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' rust-toolchain.toml | head -n 1)
  fi
fi

attempt=1
while true; do
  if rustup "$@"; then
    exit 0
  fi
  if [ "$attempt" -ge "$attempts" ]; then
    echo "rustup $* failed $attempts times" >&2
    exit 1
  fi
  echo "::warning::rustup $* failed (attempt $attempt of $attempts); cleaning up and retrying"
  rm -rf "$home/tmp" "$home/downloads"
  if [ -n "$toolchain" ]; then
    rm -rf "$home/toolchains/$toolchain" "$home/toolchains/$toolchain"-* "$home/update-hashes/$toolchain" "$home/update-hashes/$toolchain"-*
  fi
  sleep $((attempt * delay))
  attempt=$((attempt + 1))
done
