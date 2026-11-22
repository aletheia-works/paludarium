#!/usr/bin/env bash
#MISE description="cargo fmt --check + cargo clippy -D warnings, as in CI (read-only)"
set -euo pipefail
# The fuzz crate and the hello-rs guest are separate workspaces.
cargo fmt --all --check
cargo fmt --check --manifest-path fuzz/Cargo.toml
cargo fmt --check --manifest-path tests/guests/hello-rs/Cargo.toml
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
# CI's "clippy (stable Rust of rust-version)" job, whose clippy has lints the
# nightly's does not, for the targets it checks (and the fuzz crate for the
# host's), unless PALUDARIUM_SKIP_STABLE_CLIPPY=1: the workflows that run
# lint:all set it, as that job runs these.
if [ "${PALUDARIUM_SKIP_STABLE_CLIPPY:-}" != 1 ]; then
  targets="x86_64-unknown-linux-gnu aarch64-apple-darwin x86_64-pc-windows-msvc"
  for target in $targets; do
    STABLE_TARGETS="$targets" scripts/stable-cargo.sh clippy --locked --workspace --all-targets \
      --target "$target" -- -D warnings
  done
  scripts/stable-cargo.sh clippy --locked --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
fi
