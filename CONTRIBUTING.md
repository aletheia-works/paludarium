# Contributing to paludarium

Please discuss large changes in an issue before implementation. Keep each PR
focused on one problem and include reproducible evidence for correctness claims.
AI-assisted contributions follow the same standard; identify the tool and model
used, and verify the output before submitting it.

## Getting started

Use [README.md](README.md) for the toolchain, builds, and test commands, and
[docs/release.md](docs/release.md) for packaging and publication. Repository
settings (rulesets, labels, the `release` and `github-pages` environments) are
managed with OpenTofu in [infra/github/](infra/github/README.md); change them
there, not in the UI. The documentation site
(<https://aletheia-works.github.io/paludarium/>, sources in [docs/](docs/))
describes the supported features, the architecture, the design decisions and
how correctness is verified; read the relevant pages before changing emulator
behaviour, and update them with it. When a page disagrees with the code, trust
the code and name the mismatch in the PR.

This repository uses Jujutsu (`jj`), including for fork synchronization:

```sh
jj git fetch --all-remotes
jj new main@upstream
```

Here `origin` is your fork and `upstream` is `aletheia-works/paludarium`.
In PowerShell quote revision expressions containing `@`, such as `jj log -r '@'`.
Resolve mise-managed executables from their installation directories rather than
using `mise exec` or shims; declared tasks still use `mise run <task>`.

The Rust toolchain is the nightly pinned in `rust-toolchain.toml`; a weekly
pull request moves it to the latest nightly, so do not write its date into
workflows (use `$RUST_TOOLCHAIN`). Do not copy
code from other projects (including jart/blink); use them only as references for
behavior and design. New dependencies must come from crates.io and have
licenses compatible with Apache-2.0 (`cargo deny` checks this).

## Verification

Run checks appropriate to the affected files and record exact commands, results,
and any unverified behavior in the PR:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
PALUDARIUM_TEST_NODE=<absolute path to node> cargo test --locked --workspace
```

`mise run lint:all` runs the first two and `mise run test` the unit tests;
`mise tasks` lists the other checks (differential tests, coverage, fuzzing).
On x86-64 Linux, `mise run test:diff` needs
`sudo sysctl -w kernel.core_pattern=core kernel.core_uses_pid=0` for the
core-dump case and `sudo sysctl -w net.unix.max_dgram_qlen=10` for the
unix-datagram case, as CI sets.
A new process case is a mode of `tests/guests/processes/process.c`, listed in
`tests/guests/processes/cases.json` and in the `cases!` list of
`crates/paludarium-harness/tests/diff_processes.rs`; a test fails when the two
lists differ.
`lint:all` also checks that the system-call tables of the features pages, in
English and Japanese, list exactly the calls the kernel implements: a new
system call gets its name in `scripts/syscall-docs.py` and a place in both
tables. It also checks, through `scripts/interface-docs.py`, that the
command-line pages list exactly the options `crates/paludarium/src/cli.rs`
parses, that the JavaScript pages name everything
`packages/paludarium-wasm/index.d.ts` declares, with exactly its run options in
the table, that the Rust pages name everything the `paludarium` crate
re-exports, with the public fields and methods of the types an embedder uses
(`DETAILED` in the script; `UNDOCUMENTED` lists the items left out, with why)
and exactly the `ErrorKind` variants in the table, that every English page has a
Japanese page with the same headings, and that every link to a heading
(`page#section`) resolves. VitePress decomposes a heading's text (NFKD) into its
id, so a link to a Japanese heading with a dakuten such as プ does not match it;
give such a heading an explicit id, such as
`## 確かめたプログラム {#programs-verified}`.

The emulator is correct when it matches native x86-64 Linux. Differential tests,
line coverage (80% floor), and fuzzing only produce real evidence on x86-64
Linux, which CI runs on every pull request that changes what they cover (and on
every push to main); a macOS or Windows run is not a substitute. Nor is
`mise run linux-dev` on an Arm Mac: Docker runs the x86-64 programs there, the
native side included, under QEMU's user-mode emulation, which handles signals
itself, so even the native results can differ from Linux (a stopped and
continued child sends SIGCHLD despite `SA_NOCLDSTOP`, for one). Do not lower
coverage floors, add skips, or weaken comparison masks to make a check pass. Measure speed only with background load stopped. For
documentation or GitHub configuration changes, check syntax, referenced paths,
and the final diff; a full emulator rebuild is unnecessary.

## Pull requests

Use Conventional Commits for commit messages and PR titles, for example
`docs: clarify contribution guidelines` or `chore: add repository metadata`.
Link the relevant issue, explain the change, and highlight review risks.
Do not rewrite shared history. Sign off commits created through GitHub's web UI.
Pin every GitHub Action to a full commit SHA. Do not apply workflow labels by
judgment; labels are applied mechanically.

Contributions use [Apache-2.0](LICENSE). Follow the
[Code of Conduct](https://github.com/aletheia-works/.github/blob/main/CODE_OF_CONDUCT.md)
and use the private channel in [SECURITY.md](SECURITY.md) for vulnerabilities.
