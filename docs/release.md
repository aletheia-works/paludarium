# Release verification and publication

## Current status

The latest release is `v0.2.0` (2026-10-22, tag on 4125399f, publish run
39701905461). The eleven crates and `@aletheia-works/paludarium-wasm` are
published only by Trusted Publishing (OIDC) from `publish.yml`, after the
same-head evidence of the head (steps 5 and 6 below). Only the first release,
`v0.1.0` (2026-10-20, tag on 0f456d07), was published by hand with one-time
scoped tokens, because crates.io lets a Trusted Publisher be registered only
for a crate that already exists.

The eleven public crates are types, host, mmu, vfs, loader, decoder, cpu,
jit, kernel, runtime and paludarium, in the dependency order calculated from
the manifests. They share the workspace version, which Release Please sets
together with the internal dependency versions and the npm package version.
Harness, the Rust Wasm adapter and the fuzz crate have `publish = false`.

The tested toolchain is the nightly pinned in `rust-toolchain.toml`. Every
crate declares MSRV 1.101, so the current stable release (1.99.1) cannot
build them, and stable support is not claimed. The Wasm adapter
additionally needs nightly build-std and atomic-wait support.

## Non-publishing checks

Use the real executable of the latest Python release and project-local
coverage 7.16.2:

```sh
python3 -B -m unittest discover -s tests/release -p 'test_*.py' -v
python3 -B scripts/release/check.py --mode validate
python3 -B scripts/release/check.py --mode package-check
```

`package-check` creates an exclusive `target/release-evidence/package-*` directory. It
retains argv, tool SHA, stdout, stderr, real exit/timeout/reaping, source and
lock before/after hashes. The original source is never rewritten. It builds
eleven real `.crate` files, checks all members and normalized dependencies,
builds a crate-external consumer from a temporary sparse registry, probes
stable separately, and builds the production Wasm without diagnostic features.
One npm tarball is inspected and used for all seven distribution boundary
checks, including real Wasm hello, invalid guest cleanup, missing JS and a
corrupt Wasm. A mock upload test is not a registry or OIDC test.

`release-check.yml` is PR/manual/reusable and has no publication credentials.
It measures the fixed policy/package/check/acceptance file population (four
files), each at least 80%, including the actual package path (validate and
package-check are appended to the unit-test coverage data). Existing
Rust/JS/workspace/terminal floors remain unchanged. A branch-only workflow may need
a PR and owner Actions approval before GitHub allows it to run; dispatch
registration is not assumed.

## Same-head evidence map

`policy.release_gate` requires, for the exact head being released, one
official quality run for each of the eight `REQUIRED` purposes and the four
`ACCEPTANCE` conditions. `scripts/release/acceptance.py` derives both from
upstream `aletheia-works/paludarium` only. A run counts only when its
workflow file matches the table, its head and head repository are the
upstream head, its branch is `main` and its event is `push` or
`workflow_dispatch` (pull-request runs are ignored). For each workflow there
must be exactly one such run, and it must be completed and successful: none,
two or more, unfinished or failed runs stop the producer. Every listed job
must exist once and have succeeded at that head. Job names below were read
from the current workflow files and checked against saved job listings and
artifacts (JIT runs 38840433942 and 38897611874, macOS run 38996219364);
the producer re-checks them on the live run and fails loudly if GitHub
names them differently.

### Quality purposes (`REQUIRED`)

| Purpose | Workflow on main | Job(s) that must succeed |
|---|---|---|
| `three-os` | `ci.yml` (push to main) | `unit tests (ubuntu-latest)`, `unit tests (macos-latest)`, `unit tests (windows-latest)` |
| `lint` | `ci.yml` | `lint` |
| `dependencies` | `ci.yml` | `dependencies` |
| `linux-differential` | `ci.yml` | `differential tests (x86-64 Linux)`, `fixed guest programs / differential` |
| `rust-coverage` | `ci.yml` | `line coverage >= 80%` |
| `terminal-coverage` | `ci.yml` | `line coverage >= 80%` (its step `Terminal target crates line coverage >= 80%` fails under 80%) |
| `js-coverage` | `quality.yml` (dispatch on main) | `wasm-programs / differential (ubuntu-latest, node)` (its step `Fixed production JavaScript coverage` fails under 80%) |
| `package-check` | `release-check.yml` (dispatch on main) | `packages` |

### Acceptance conditions (`ACCEPTANCE`)

Each environment is compared with the fresh native x86-64 Linux oracle of its
own run, and the guest bytes (probe, aube) must equal that oracle's. Guests
are never compared across runs: aube embeds its build date, so separately
built guests differ by design.

| Source | Workflow / job | Artifact: members read |
|---|---|---|
| Linux native | `ci.yml` / `fixed guest programs / differential` | `programs-differential`: `observations.json`, `native/observations.json` |
| macOS native | `macos-quality.yml` / `macos-host` | `macos-host`: `comparison/observations.json`, `comparison-original/observations.json`; `macos-native-first`: `macos/native/observations.json`, `macos/native-original/observations.json` |
| Windows native | `quality.yml` / `windows-host` | `windows-host`: `windows/comparison/observations.json`, `windows/comparison-original/observations.json`; `windows-native-first`: `windows/native/observations.json`, `windows/native-original/observations.json` |
| Wasm Node, Chromium, Firefox, Safari | `quality.yml` / `wasm-programs / differential (ubuntu-latest, node)`, `(ubuntu-latest, chromium)`, `(ubuntu-latest, firefox)`, `(macos-latest, safari)` | `wasm-<environment>`: `observations.json`; `wasm-acceptance-inputs`: `target/wasm/native/observations.json` |
| Performance | `quality.yml` / `wasm-programs / differential (ubuntu-latest, node)` | `wasm-node`: `performance/observations.json` |

| Condition | Sources | What is checked in the artifact content |
|---|---|---|
| Probe | all native and Wasm sources (Wasm interpreter mode) | every probe row exits 0 and prints exactly its `PASS <item>` line; `probe-all` prints all eight; `probe-environment` starts with `PASS` |
| aube | same | the four aube commands have the oracle's exit codes and the same `--version` stdout; the job's own runner compares full stdout/exit and fails the job on a difference |
| Wasm modes | the four Wasm sources | `complete` and `passed`, 28 cases, both `interpreter` and `jit` modes complete and passed, every row `pass: true`, probe and aube checks above in both modes; in both modes the four aube steps rerun on rebuilt filesystems (`restored`) are all there, `pass: true`, and match the oracle's exit status and `--version` output |
| Performance | performance | `head` equals the released head, `complete`, `passed`, `warmupsPassed`, `result.pass`, `p < 0.05`, mean JIT time below mean interpreter time, 20 rows all exit 0 and passed |

Shared checks: all native documents are complete (`differential_complete`,
`native_complete`), each artifact is unexpired, belongs to the selected run
and head, and its ZIP matches the official `digest` and size. The four Wasm
environments must report one module and one oracle digest (the exact bytes of
`wasm-acceptance-inputs`), and the measurement must name the same module,
oracle and probe. `artifact_sha256` of each condition is the SHA-256 of the
sorted `[source, artifact, artifact id, official digest]` list it was checked
against; the document also keeps every member's SHA-256.

`release-evidence.json` records the four conditions as `probe`, `aube`,
`wasm-modes` and `performance`.

The performance step in `quality.yml` runs only on `workflow_dispatch` and
has `continue-on-error: true`, so a successful run does not mean the
performance condition passed: only `performance/observations.json`
decides. It is measured once per head; dispatching again to wait for a pass
is not allowed (a second run is also rejected as ambiguous). Most source artifacts are kept for 7 days
(`macos-host` and the native-first oracles for 14), so the acceptance
artifact must be produced within 7 days of the quality runs.

### Producer

`.github/workflows/release-acceptance.yml` runs only by dispatch (by a person,
or by the evidence job of `publish.yml` below), with
`contents: read` and `actions: read`, SHA-pinned actions and
`persist-credentials: false`. It runs
`python -B scripts/release/acceptance.py --output target/release-evidence/release-evidence.json`
and uploads one artifact `release-acceptance` whose only member is
`release-evidence.json` (fields `head`, `quality`, `acceptance`, plus the
checked `evidence`). The producer refuses to run outside upstream or for a
ref other than `refs/heads/main`. It has no inputs: publication is by Trusted
Publishing only, so no authentication declaration exists; the publish job's
OIDC token exchange is what proves the registry side. Unit and integration
tests replace the GitHub adapter with in-memory data: they do not prove that
any real run, artifact or registration exists.

## Release Please

`.github/workflows/release.yml` runs Release Please as in the other
aletheia-works repositories, with the `aletheia-works-bot` App token
(`vars.BOT_CLIENT_ID`, `secrets.BOT_PRIVATE_KEY`). Unlike those
repositories, a push to
main only creates or updates the release PR (`skip-github-release`): the
same-head evidence of step 5 must exist for the release PR's merge commit
before anything is published, so Release Please never tags: `publish.yml`
publishes that commit and creates the tag and the GitHub release last
(steps 5 and 6), as biome and mise do. The labels `autorelease: pending` and `autorelease: tagged` are
managed in `infra/github/main.tf`. Release Please writes no `CHANGELOG.md`
(`skip-changelog`): the release PR body holds the release notes, and the
`tag` job copies that section into the GitHub release.

`.github/workflows/release-merge.yml` enables auto-merge on the pending
release PR every Monday (00:23 UTC) or on dispatch, as in the other
aletheia-works repositories: only one open, non-draft PR from the bot on the
release-please branch with `autorelease: pending`, merged by squash at its
current head once the required checks pass.

`.github/release-please-config.json` uses the `simple` release type and
updates the workspace version, the eleven internal dependency versions, the
workspace crates' entries in `Cargo.lock` and `fuzz/Cargo.lock` (the fuzz
crate keeps `0.0.0`), and the npm package version. The first version was
fixed with `release-as: 0.1.0`, removed after `v0.1.0` was published; Release
Please now calculates each version from the Conventional Commits since the
last release.

## Release steps

A release needs a person only to merge the release PR (step 1, or Monday's
auto-merge), and once per new package (step 3); everything else runs by
itself.

1. **Merge the release PR.** When: when the version Release Please
   proposes is the one to publish, or let `release-merge.yml` merge it
   on Monday. `release.yml` (Release Please) keeps a
   release PR open from every push to main; it changes only the versions
   (`Cargo.toml`, `Cargo.lock`, `fuzz/Cargo.lock`, `package.json`) and the
   manifest; its body holds the release notes. Merging it starts the release in
   `publish.yml` (steps 5 and 6). Confirm: note
   the merge commit, the new main head SHA;
   `gh api repos/aletheia-works/paludarium/commits/<sha> --jq .commit.verification.verified`
   prints `true`, and the `CI` (`ci.yml`) push run for that SHA starts.
2. **Create the `release` environment.** When: before the first release
   (release preflight rejects a missing environment). `infra/github`
   manages environment `release` with administrator bypass off and
   deployments limited to `main`. It has no required reviewer:
   publication waits for no approval, because the same-head evidence gate
   (step 5) decides it. Confirm:
   `gh api repos/aletheia-works/paludarium/environments/release` shows
   `can_admins_bypass: false` (preflight refuses bypass `true` or unknown).
3. **New packages.** Trusted Publishing needs the package to exist, so a
   crate or npm package that is not on its registry yet is published once
   by hand (by its owner, from the release head, with a short-lived token
   that is revoked right after), and its Trusted Publisher is registered as
   in step 4 before the next release. The evidence job of `publish.yml` stops before
   any dispatch while a package is missing. crates.io also limits how many
   new crates one account can create in a short time (the first
   publication stopped after five and resumed every ten minutes). Each
   cargo and npm child of the publish job gets only an allow-list of
   variables (`CARGO_ENVIRONMENT` and `NPM_ENVIRONMENT` in
   `scripts/release/check.py`): `cargo` never receives `GH_TOKEN`,
   `GITHUB_TOKEN` or `ACTIONS_ID_TOKEN_REQUEST_*`, and `npm` receives only
   what `npm publish --provenance` needs (CI detection, the OIDC request
   variables, the GitHub context named in the provenance statement and
   setup-node's `.npmrc`). Receipts and `publication-progress.json` record
   no token value.
4. **Register the Trusted Publishers.** For each of the eleven crates on
   crates.io and for `@aletheia-works/paludarium-wasm` on npm, register
   repository `aletheia-works/paludarium`, workflow `publish.yml` and
   environment `release`. npm also requires `repository.url` in
   `package.json` to match (it does) and its supported runner and CLI (npm
   12.2.0 on Node 26.12.0 here). Revoke the one-time tokens of the first
   publication on crates.io and npm and delete their `release` environment
   secrets. Confirm: each crate's and the npm package's Trusted Publishing
   settings show exactly that repository, workflow and environment. Without
   a registered Trusted Publisher, the publish job's OIDC token exchange
   fails before any upload.
5. **Same-head evidence: automatic.**
   `.github/workflows/publish.yml` runs on every push to main. Its
   `evidence` job runs `scripts/release/evidence.py`: while tag
   `v<version>` of the workspace version does not exist and the main head
   is that push, it first requires every crate and the npm package to exist
   on its registry without this version: a missing package (step 3) or a
   version already partly on a registry (re-run the stopped jobs of the
   earlier `Publish` run instead) stops it before any dispatch. It then
   waits for the `ci.yml` push run, dispatches `macos-quality.yml`,
   `quality.yml` and `release-check.yml` once each (a run a person
   already dispatched for the head is reused, never doubled), waits for all
   of them, then dispatches `release-acceptance.yml` once and waits for it. A
   failed run is not dispatched again (performance is measured once per head);
   the head then needs a person. When the version is already tagged or the
   head is no longer main, the run does nothing.

   **By hand** (only when the automatic run stopped and the cause is
   fixed). On the release head, while it is still the main head, the
   `ci.yml` push run starts by itself; dispatch each of the others once:
   `gh workflow run macos-quality.yml --repo aletheia-works/paludarium --ref main`,
   the same for `quality.yml` and `release-check.yml`. When all four
   have succeeded (do not dispatch `quality.yml` again to wait for a
   passing performance condition; if it fails, record it and stop),
   dispatch, within 7 days,
   `gh workflow run release-acceptance.yml --repo aletheia-works/paludarium --ref main`,
   then `publish.yml` once: its evidence job reuses those runs. Confirm:
   the release-acceptance run succeeded and its artifact `release-acceptance` holds only
   `release-evidence.json`, with that head, eight `quality` rows and the
   four `acceptance` IDs all `passed: true`.
6. **Publication, then tag: automatic.** When the evidence of step 5
   succeeded, the same `Publish` run continues with `preflight` (main,
   untagged version, signed head, environment), `packages` (the package
   check of that head) and `publish` (every crate and the npm package by
   Trusted Publishing, without waiting for an approval). Only after all of
   them succeeded does its `tag` job create tag `v<version>` and the GitHub
   release (notes from the body of the merged release PR, whose merge commit
   that head must contain) on that head with the workflow's own
   token, and move the merged release PR from `autorelease: pending` to
   `autorelease: tagged`, as Release Please does when it tags. A version
   that was not published therefore never gets a tag, and no tag is ever
   deleted or moved. Confirm: the run succeeded and
   `publication-progress.json` (in the run's artifact
   `publication-progress-attempt-<n>`) lists all eleven
   crates and `@aletheia-works/paludarium-wasm`; then, independently, each crate's
   `https://crates.io/api/v1/crates/<name>/<version>` `checksum` equals the
   `.crate` SHA-256 in the `release-package` artifact, `npm view
   @aletheia-works/paludarium-wasm@<version> dist.integrity` equals the tarball's SHA-512
   integrity, and the npm provenance attestation names the upstream
   repository, `publish.yml` and that head.

The evidence document follows `policy.release_gate`: exact head/tag/repository,
official completed successful quality run identities for every required
purpose and each acceptance ID with its verified artifact digest. The
authorization step re-fetches GitHub
commit, reachability, environment and run history.
Evidence from old JIT measurements is historical unless the declared source
and build closure are independently proven equivalent. No same-binary
performance rerun is used to wait for a passing result.

## Publication and recovery

`publish.yml` publishes only on main, only an exact `vMAJOR.MINOR.PATCH`
version that has no tag yet, after Python validation; it verifies the signed
head, its reachability from main and the `release` environment before
builds, publishes without waiting for an approval, and tags last.

Only the publish job receives `id-token: write`. crates-io-auth-action
obtains a short-lived crates.io token and revokes it in its post step, only
the `cargo publish` children receive it, and npm uses Trusted Publishing
with provenance. No registry token is stored anywhere. All
third-party actions are pinned to
officially resolved commit SHAs. The fork is never substituted for upstream.

The publish job checks the previously tested eleven crate artifacts and npm
tarball. Cargo dry-run reassembly must have the approved byte digest before
upload; original source/locks must remain unchanged. Existing versions are
queried first: an equal digest is verified without re-upload, a different
digest or unknown network result stops the sequence. The same npm tarball is
uploaded. Registry checksums/integrity are checked after each upload; a
just-uploaded version that still answers 404 is asked again every 15 seconds
for up to 15 minutes (the first npm upload took about five minutes to appear).

On partial failure, preserve `publication-progress.json` (the run's artifact
`publication-progress-attempt-<n>`, uploaded even when the job stops), attempted uploads,
unverified uploads and all logs. Do not delete, replace, move a tag or retry
publication automatically. An owner must inspect registry state and propose
the remaining recovery. Re-running the stopped jobs of the same `Publish`
run (same head; nothing is tagged yet) is safe: every version already present is only verified
(it must equal the approved digest and must not be yanked), and only the
remaining ones are uploaded. The cargo and npm children
get allow-listed environments only (step 3); the allow-list for
`npm publish --provenance` follows npm's provenance generator for GitHub
Actions and is proven only by the real publication. A successful workflow alone is not
enough: registry retrieval/source/provenance verification is required.

## Official references

- [Cargo publishing](https://doc.rust-lang.org/cargo/reference/publishing.html)
- [Current crates.io Trusted Publishing implementation documentation](https://github.com/rust-lang/crates.io/blob/8b4b7af90bf73b0bbb73b47a29b9de86ed702093/svelte/src/routes/docs/trusted-publishing/%2Bpage.svelte)
- [crates.io authentication action](https://github.com/rust-lang/crates-io-auth-action)
- [npm Trusted Publishing](https://docs.npmjs.com/trusted-publishers/)
- [GitHub environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
