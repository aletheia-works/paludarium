# Native x86-64 Linux environment for paludarium: builds the musl guests,
# runs them natively (differential tests), strace/objdump, coverage, fuzzing.
# Build it with `mise run linux-dev`, which passes the pinned toolchain:
#   docker build --platform linux/amd64 --build-arg TOOLCHAIN="$(bash scripts/rust-toolchain.sh)" \
#     -t paludarium-dev:<toolchain> ci/linux-dev
FROM rust:1-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools binutils strace gdb \
 && rm -rf /var/lib/apt/lists/*

# The nightly pinned in rust-toolchain.toml. No default, so that an image is
# never built with an old one.
ARG TOOLCHAIN
RUN test -n "$TOOLCHAIN" || { echo "pass --build-arg TOOLCHAIN" >&2; exit 1; } \
 && rustup toolchain install "$TOOLCHAIN" --profile minimal \
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
