# Native x86-64 Linux environment for paludarium: builds the musl guests,
# runs them natively (differential tests), strace/objdump, coverage, fuzzing.
# Build: docker build --platform linux/amd64 -t paludarium-dev ci/linux-dev
FROM rust:1-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools binutils strace gdb \
 && rm -rf /var/lib/apt/lists/*

# Same pinned nightly as rust-toolchain.toml.
ARG TOOLCHAIN=nightly-2026-10-10
RUN rustup toolchain install "$TOOLCHAIN" --profile minimal \
      --component rustfmt,clippy,llvm-tools,rust-src \
      --target x86_64-unknown-linux-musl,wasm32-unknown-unknown \
 && rustup default "$TOOLCHAIN"

RUN cargo +"$TOOLCHAIN" install --locked cargo-llvm-cov cargo-fuzz

# llvm-symbolizer: symbolised sanitizer reports and LSan suppressions
# (fuzz/lsan.supp) for cargo-fuzz.
RUN apt-get update \
 && apt-get install -y --no-install-recommends llvm \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
