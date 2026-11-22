#!/usr/bin/env bash
#MISE description="cargo fmt + cargo clippy --fix (in-place)"
set -euo pipefail
cargo fmt --all
cargo fmt --manifest-path fuzz/Cargo.toml
cargo fmt --manifest-path tests/guests/hello-rs/Cargo.toml
cargo clippy --locked --workspace --all-targets --fix --allow-dirty --allow-staged
cargo clippy --locked --manifest-path fuzz/Cargo.toml --all-targets --fix --allow-dirty --allow-staged
# The fixes of the stable Rust that rust-version names, for the host, unless
# PALUDARIUM_SKIP_STABLE_CLIPPY=1 (see check.sh).
if [ "${PALUDARIUM_SKIP_STABLE_CLIPPY:-}" != 1 ]; then
  scripts/stable-cargo.sh clippy --locked --workspace --all-targets --fix --allow-dirty --allow-staged
  scripts/stable-cargo.sh clippy --locked --manifest-path fuzz/Cargo.toml --all-targets --fix \
    --allow-dirty --allow-staged
fi
