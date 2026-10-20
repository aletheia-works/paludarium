# Install

paludarium is published as crates on crates.io and as a package on npm.

| You want | Install |
|---|---|
| the command | `cargo install paludarium` |
| the Rust library | `cargo add paludarium` |
| the browser or Node.js | `npm install @aletheia-works/paludarium-wasm` |

## Rust

paludarium is built and tested with a pinned nightly Rust
(`nightly-2026-10-11`). The crates declare 1.101 as their MSRV (the oldest Rust
they support), so today's stable Rust cannot build them; use a nightly Rust.

```sh
rustup toolchain install nightly
cargo +nightly install paludarium
```

paludarium runs statically linked x86-64 Linux executables (`ET_EXEC` and
static-pie). Linking statically with musl produces them:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
paludarium target/x86_64-unknown-linux-musl/release/hello
```

## JavaScript

```sh
npm install @aletheia-works/paludarium-wasm
```

The package holds `paludarium.wasm`, the launcher and its Workers, and the
TypeScript types. In the browser, the page must be cross-origin isolated; see
[JavaScript and the browser](./javascript).

## Build from source

```sh
git clone https://github.com/aletheia-works/paludarium.git
cd paludarium
cargo build --release --locked       # the paludarium command
bash scripts/build-wasm.sh           # paludarium.wasm of the npm package
```

rustup installs the nightly pinned in `rust-toolchain.toml` automatically.
