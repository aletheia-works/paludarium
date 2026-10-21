#!/usr/bin/env bash
#MISE description="cargo fmt --check + cargo clippy -D warnings, as in CI (read-only)"
set -euo pipefail
# The fuzz crate and the hello-rs guest are separate workspaces.
cargo fmt --all --check
cargo fmt --check --manifest-path fuzz/Cargo.toml
cargo fmt --check --manifest-path tests/guests/hello-rs/Cargo.toml
cargo clippy --locked --workspace --all-targets -- -D warnings
