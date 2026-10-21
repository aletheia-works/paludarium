#!/usr/bin/env bash
#MISE description="Build paludarium.wasm for packages/paludarium-wasm (pinned nightly, rebuilt std)"
set -euo pipefail
# Fixed toolchain; rebuild std so its allocator and locks support wasm atomics.
export RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals -C link-arg=--import-memory -C link-arg=--shared-memory -C link-arg=--max-memory=1073741824 -C link-arg=--export=__stack_pointer -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base'
cargo +nightly-2026-10-11 build --locked -Z build-std=std,panic_abort --release --target wasm32-unknown-unknown -p paludarium-wasm
cp target/wasm32-unknown-unknown/release/paludarium_wasm.wasm packages/paludarium-wasm/paludarium.wasm
