#!/usr/bin/env bash
#MISE description="cargo fmt + cargo clippy --fix (in-place)"
set -euo pipefail
cargo fmt --all
cargo fmt --manifest-path fuzz/Cargo.toml
cargo fmt --manifest-path tests/guests/hello-rs/Cargo.toml
cargo clippy --locked --workspace --all-targets --fix --allow-dirty --allow-staged
