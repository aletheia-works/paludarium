# AGENTS.md

Instructions for AI coding agents working in this repository (the
[agents.md](https://agents.md) convention). Agents follow the same rules as
people: [CONTRIBUTING.md](CONTRIBUTING.md) is the source, and this file only
lists what an agent needs first.

## Orientation

- paludarium is a user-mode x86-64 Linux emulator in Rust that also runs in
  WebAssembly ([README.md](README.md)).
- The documentation site under `docs/` (English; Japanese under `docs/ja/`)
  describes the features, architecture, design decisions and how correctness is
  verified. Read the relevant pages before changing emulator behaviour, and
  update both languages with it.
- Correct means behaving exactly like native x86-64 Linux, shown by the
  differential tests.

## Commands

`mise tasks` lists every task. The common ones:

| Task | Use |
|---|---|
| `mise run lint:all` | All formatters and linters (read-only); `lint:all:fix` applies the fixes |
| `mise run test` | Unit tests of every crate |
| `mise run build`, `mise run wasm:build` | The command, and the npm package's `paludarium.wasm` |
| `mise run test:diff`, `coverage`, `fuzz <target>` | x86-64 Linux only; elsewhere `mise run linux-dev -- <command>` |
| `mise run linux-dev-compare` | The differential tests in that container, listing only results that differ from main's (reference, not evidence) |
| `mise run deny`, `mise run release:check` | Dependency policy and release configuration |

## Rules

- Never lower coverage floors, skip tests or weaken comparison masks to make a
  check pass.
- Differential tests, coverage and fuzzing are evidence only on x86-64 Linux
  (CI). A macOS or Windows run, or Docker on an Arm Mac, is not.
- Back every correctness claim with the command and its output, and say what
  was not verified.
- When the code and a document (`docs/`, README.md, CONTRIBUTING.md, this
  file) disagree, trust the code, not the text. After the change, always tell
  the person you work for about every mismatch you found, whether you fixed it
  (in both languages) or left it. Agents that trusted a stale instruction file
  over the code have broken working systems
  ([arXiv:2605.30777](https://arxiv.org/abs/2605.30777)).
- The Rust toolchain is the nightly pinned in `rust-toolchain.toml`.
  Dependencies come from crates.io with licenses compatible with Apache-2.0
  (`mise run deny`).
- Do not copy code from other projects, including jart/blink.

## Version control and pull requests

- Use Jujutsu (`jj`): `origin` is your fork, `upstream` is
  `aletheia-works/paludarium` (see CONTRIBUTING.md).
- Commit messages and pull request titles follow Conventional Commits; the
  first line is at most 100 characters (commitlint checks every commit).
- Allow edits by maintainers on a pull request from a fork:
  aletheia-works-bot then commits lint autofixes to it. Fetch before pushing to
  that branch again.
- Pin every GitHub Action to a full commit SHA.
