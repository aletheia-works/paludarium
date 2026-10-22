# paludarium

A user-mode x86-64 Linux emulator in Rust. It runs statically linked x86-64
Linux programs unchanged on Linux, macOS and Windows, and in WebAssembly
(Node.js and browsers), with a JIT for WebAssembly.

**Documentation: <https://aletheia-works.github.io/paludarium/>**
([日本語](https://aletheia-works.github.io/paludarium/ja/)): what paludarium
is, installation, the command line, the Rust and JavaScript APIs, supported
platforms and features, limitations, architecture, verification, design
decisions, and a [live demo](https://aletheia-works.github.io/paludarium/demo)
that runs in your browser.

paludarium is a from-scratch Rust counterpart of
[jart/blink](https://github.com/jart/blink) (behaviour and design are a
reference; no code is copied). Its first user is
[formicarium](https://github.com/aletheia-works/formicarium).

| Package | Install |
|---|---|
| [`paludarium`](https://crates.io/crates/paludarium) (library and command) | `cargo +nightly install paludarium` / `cargo add paludarium` |
| [`@aletheia-works/paludarium-wasm`](https://www.npmjs.com/package/@aletheia-works/paludarium-wasm) | `npm install @aletheia-works/paludarium-wasm` |

## Development

### Requirements

- Rust: the nightly pinned in `rust-toolchain.toml` (rustup installs it).
- [mise](https://mise.jdx.dev/): `mise install` provides the other tools (bun,
  Node.js, Python, cargo-deny, cargo-llvm-cov, OpenTofu and the linters), and
  `mise tasks` lists the tasks below. mise also reads `rust-toolchain.toml`, so
  a global `rust` in mise does not override the pinned nightly here.
- Differential tests, coverage and fuzzing: x86-64 Linux (CI's Ubuntu runners,
  or the development container below) with musl-tools.

### Build and run

```sh
mise run build         # cargo build --release --locked
paludarium [--env KEY=VALUE]... [--mount HOST:GUEST]... [--no-jit] <program> [args...]
mise run wasm:build    # paludarium.wasm for packages/paludarium-wasm
```

Within mise, `target/release` is on `PATH`.

### Tests and checks

| Task | What it runs |
|---|---|
| `mise run test` | Unit tests of every crate (Linux, macOS, Windows) |
| `mise run test:diff` | Differential tests (x86-64 Linux only) |
| `mise run coverage` | Line coverage; fails under 80 % (x86-64 Linux) |
| `mise run fuzz <target> [--seconds N]` | One target in `fuzz/fuzz_targets/` with the nightly's settings (x86-64 Linux) |
| `mise run deny` | `cargo deny --locked check` |
| `mise run lint:all` | `rust:check` (rustfmt, clippy), `shell:check` (ShellCheck), `actions:check` (actionlint), `python:check` (Ruff), `toml:check` (Tombi) and `markdown:check` (rumdl) |
| `mise run ci` | `lint:all`, `build`, `test` and `deny` |

Each `<lang>:check` has a `<lang>:check:fix`, and CI runs `lint:all` on every
pull request (`test-lint-check.yml`, called by `ci.yml`). `lint-autofix.yml` runs `lint:all:fix`
there too, and aletheia-works-bot commits any fixes to the pull request branch
as a signed `style:` commit (a pull request from a fork needs "Allow edits by
maintainers"); fetch it before pushing to that branch again.

Differential tests build the guests under `tests/guests/` from source, run each
one natively and in the emulator, and compare standard output, standard error
and the exit status byte for byte (instruction guests also compare registers,
flags and memory; undefined flags are listed in
`tests/guests/insn/UNDEFINED.md`). Expected results are produced natively on
every run and never stored. Each case has a 30-second timeout.

### Linux tests from macOS or Windows

`ci/linux-dev/Dockerfile` is an x86-64 Linux environment with everything the
differential tests, coverage and fuzzing need:

```sh
mise run linux-dev -- cargo test --locked -p paludarium-harness --test diff_core -- --nocapture
```

The working tree is copied into a named volume first, so Docker Desktop does
not need to share the repository path (`PALUDARIUM_DEV_MOUNT=bind` mounts it
directly). Docker on an Arm Mac runs x86-64 under emulation, so its results
are not evidence of native Linux behaviour; CI is.

### Documentation site

```sh
mise run docs:dev      # http://localhost:5173/paludarium/
```

mise installs the site's packages (`bun install`) when you enter the directory
or run a task.

## CI

- `ci.yml` (every pull request): unit tests on three OSes, rustfmt, clippy
  (`-D warnings`), the wasm32 build, cargo-deny, differential tests, 80 %
  coverage, probe and aube differential tests, the WebAssembly acceptance
  tests, polyglot lint, the documentation build and the release package
  check. A pull request runs the jobs its changed files need
  (`scripts/ci-changes.py`); `ci-ok`, the required check, passes when every
  job passed or was not needed.
- `nightly.yml`: fuzzing of every target for 600 seconds with ASan and LSan,
  and the full quality run (macOS, Windows, Node.js, Chromium, Firefox and the
  real Safari, with and without the JIT). A failure opens an issue; the next
  passing night closes it.
- `docs.yml`: builds the documentation site (`docs-build.yml`) and deploys it
  from main.
- `release.yml`, `release-merge.yml`, `publish.yml`: releases; see
  [docs/release.md](docs/release.md).

Actions are pinned by commit SHA and the default token is read-only.

## Repository layout

| Path | Contents |
|---|---|
| `crates/paludarium-types` | Shared types (`GuestAddr`, `Errno`, `ExitReason`, `ExitStatus`, `Error`) |
| `crates/paludarium-decoder` | Decoder wrapping iced-x86 |
| `crates/paludarium-mmu` | Software MMU |
| `crates/paludarium-cpu` | Interpreter |
| `crates/paludarium-jit` | Code cache interface and the WebAssembly JIT |
| `crates/paludarium-loader` | ELF loading and the initial stack |
| `crates/paludarium-vfs` | Virtual filesystem and host directory mounts |
| `crates/paludarium-kernel` | Linux system calls |
| `crates/paludarium-host` | The `Host` trait and the native and WebAssembly hosts |
| `crates/paludarium-runtime` | `Session` and the execution loop |
| `crates/paludarium` | Public API and the command |
| `crates/paludarium-harness` | Differential tests (not published) |
| `crates/paludarium-wasm` | WebAssembly entry point (not published) |
| `packages/paludarium-wasm` | The npm package |
| `tests/guests/` | Sources of the differential test guests |
| `fuzz/` | cargo-fuzz targets |
| `docs/` | The documentation site (VitePress) and the release process |
| `infra/github/` | Repository settings (OpenTofu) |
| `spikes/wasm-threads/` | The early check that WebAssembly threads can wait and wake |

## License

[Apache License 2.0](LICENSE)
