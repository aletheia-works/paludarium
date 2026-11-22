#!/usr/bin/env bash
# Runs the cargo of the stable Rust that rust-version in Cargo.toml names,
# with its arguments: the toolchain of CI's "clippy (stable Rust of
# rust-version)" job. mise sets RUSTUP_TOOLCHAIN to the pinned nightly, and
# its cargo wrapper sets it back for any cargo it runs, so this resolves
# that release's own cargo from rustup and runs it with RUSTUP_TOOLCHAIN set
# to the release. The release, with clippy and the targets in
# STABLE_TARGETS (space-separated), is installed when it is missing.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version=$(sed -n 's/^rust-version = "\(.*\)"$/\1/p' "$root/Cargo.toml")
if [ -z "$version" ]; then
  echo "stable-cargo: no rust-version in $root/Cargo.toml" >&2
  exit 1
fi
if ! cargo=$(rustup which --toolchain "$version" cargo-clippy 2>/dev/null); then
  rustup toolchain install "$version" --profile minimal --component clippy
fi
cargo=$(rustup which --toolchain "$version" cargo)
installed=$(rustup target list --toolchain "$version" --installed)
for target in ${STABLE_TARGETS:-}; do
  if ! grep -qx "$target" <<<"$installed"; then
    rustup target add --toolchain "$version" "$target"
  fi
done
bin=$(dirname "$cargo")
export RUSTUP_TOOLCHAIN="$version" PATH="$bin:$PATH" RUSTC="$bin/rustc"
exec "$cargo" "$@"
