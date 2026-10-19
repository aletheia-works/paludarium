# Release verification and publication

## Current status

The first release version is decided as `0.1.0` (Build and Test Q7,
2026-10-18). The Cargo workspace version, the eleven internal dependency
versions and the npm package `@aletheia-works/paludarium-wasm` are all `0.1.0`;
`Cargo.lock` and `fuzz/Cargo.lock` changed only in the workspace crates'
version lines. The fuzz crate (`paludarium-fuzz`, `publish = false`) keeps its
own `0.0.0`. Nothing has been published yet: FR10.1 stays unverified until the
real publication and the registry checks below.

The eleven public crates are types, host, mmu, vfs, loader, decoder, cpu,
jit, kernel, runtime and paludarium, in the dependency order calculated from
the manifests. Harness and the Rust Wasm adapter have `publish = false`.

The tested toolchain remains `nightly-2026-10-11`. A real external consumer
using the eleven generated crates through a private loopback sparse registry
built successfully. The initial stable 1.99.0 probe failed because every
crate declares MSRV 1.101. The separately installed latest stable 1.99.1 also
failed with exit 101 for the same declared MSRV; both raw failures are retained,
never labeled stable support. The Wasm
adapter additionally needs nightly build-std and atomic-wait support.

## Non-publishing checks

Use the real Python 3.15 executable and project-local coverage 7.16.2:

```sh
python3 -B -m unittest discover -s tests/release -p 'test_*.py' -v
python3 -B scripts/release/check.py --mode validate
python3 -B scripts/release/check.py --mode package-check
```

`package-check` creates an exclusive `target/u15/package-*` directory. It
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
Rust/JS/workspace/U9 floors remain unchanged. A branch-only workflow may need
a PR and owner Actions approval before GitHub allows it to run; dispatch
registration is not assumed.

## Same-head evidence map

`policy.release_gate` requires, for the exact head being released, one
official quality run for each of the eight `REQUIRED` purposes and the five
`ACCEPTANCE` conditions. `scripts/release/acceptance.py` derives both from
upstream `aletheia-works/paludarium` only. A run counts only when its
workflow file matches the table, its head and head repository are the
upstream head, its branch is `main` and its event is `push` or
`workflow_dispatch` (pull-request runs are ignored). For each workflow there
must be exactly one such run, and it must be completed and successful: none,
two or more, unfinished or failed runs stop the producer. Every listed job
must exist once and have succeeded at that head. Job names below were read
from the current workflow files and checked against saved job listings and
artifacts (U14 runs 38840433942 and 38897611874, macOS run 38996219364);
the producer re-checks them on the live run and fails loudly if GitHub
names them differently.

### Quality purposes (`REQUIRED`)

| Purpose | Workflow on main | Job(s) that must succeed |
|---|---|---|
| `three-os` | `ci.yml` (push to main) | `unit tests (ubuntu-latest)`, `unit tests (macos-latest)`, `unit tests (windows-latest)` |
| `lint` | `ci.yml` | `lint` |
| `dependencies` | `ci.yml` | `dependencies` |
| `linux-differential` | `ci.yml` | `differential tests (x86-64 Linux)`, `U10 fixed guests and fresh native differential / differential` |
| `rust-coverage` | `ci.yml` | `line coverage >= 80%` |
| `u9-coverage` | `ci.yml` | `line coverage >= 80%` (its step `U9 target crates line coverage >= 80%` fails under 80%) |
| `js-coverage` | `u14-quality.yml` (dispatch on main) | `u11-programs / differential (ubuntu-latest, node)` (its step `Fixed production JavaScript coverage` fails under 80%) |
| `package-check` | `release-check.yml` (dispatch on main) | `packages` |

### Acceptance conditions (`ACCEPTANCE`)

Each environment is compared with the fresh native x86-64 Linux oracle of its
own run, and the guest bytes (probe, aube) must equal that oracle's. Guests
are never compared across runs: aube embeds its build date, so separately
built guests differ by design.

| Source | Workflow / job | Artifact: members read |
|---|---|---|
| Linux native | `ci.yml` / `U10 fixed guests and fresh native differential / differential` | `u10-differential`: `observations.json`, `native/observations.json` |
| macOS native | `u12-quality.yml` / `macos-host` | `u12-macos-host`: `comparison/observations.json`, `comparison-original/observations.json`; `u12-native-first`: `u12/native/observations.json`, `u12/native-original/observations.json` |
| Windows native | `u14-quality.yml` / `windows-host` | `u13-windows-host`: `windows/comparison/observations.json`, `windows/comparison-original/observations.json`; `u13-native-first`: `u13/native/observations.json`, `u13/native-original/observations.json` |
| Wasm Node, Chromium, Firefox, Safari | `u14-quality.yml` / `u11-programs / differential (ubuntu-latest, node)`, `(ubuntu-latest, chromium)`, `(ubuntu-latest, firefox)`, `(macos-latest, safari)` | `u11-<environment>`: `observations.json`; `u11-acceptance-inputs`: `target/u11/native/observations.json` |
| Performance | `u14-quality.yml` / `u11-programs / differential (ubuntu-latest, node)` | `u11-node`: `performance/observations.json` |

| Condition | Sources | What is checked in the artifact content |
|---|---|---|
| FR6.3 | all native and Wasm sources (Wasm interpreter mode) | every probe row exits 0 and prints exactly its `PASS <item>` line; `probe-all` prints all eight; `probe-environment` starts with `PASS` |
| FR7.2 | same | the four aube commands have the oracle's exit codes and the same `--version` stdout; the job's own runner compares full stdout/exit and fails the job on a difference |
| FR7.3 | same | frozen install stderr shows `+ filedep@0.0.0` and `+ linked@0.0.0`; `aube list` shows both at `0.0.0` |
| FR8.2 | the four Wasm sources | `complete` and `passed`, 28 cases, both `interpreter` and `jit` modes complete and passed, every row `pass: true`, probe and aube checks above in both modes |
| FR8.3 | performance | `head` equals the released head, `complete`, `passed`, `warmupsPassed`, `result.pass`, `p < 0.05`, mean JIT time below mean interpreter time, 20 rows all exit 0 and passed |

Shared checks: all native documents are complete (`differential_complete`,
`native_complete`), each artifact is unexpired, belongs to the selected run
and head, and its ZIP matches the official `digest` and size. The four Wasm
environments must report one module and one oracle digest (the exact bytes of
`u11-acceptance-inputs`), and the measurement must name the same module,
oracle and probe. `artifact_sha256` of each condition is the SHA-256 of the
sorted `[source, artifact, artifact id, official digest]` list it was checked
against; the document also keeps every member's SHA-256.

The FR8.3 step in `u14-quality.yml` runs only on `workflow_dispatch` and has
`continue-on-error: true`, so a successful run does not mean FR8.3 passed:
only `performance/observations.json` decides. It is measured once per head;
dispatching again to wait for a pass is not allowed (a second run is also
rejected as ambiguous). Most source artifacts are kept for 7 days
(`u12-macos-host` and the native-first oracles for 14), so the acceptance
artifact must be produced within 7 days of the quality runs.

### Producer

`.github/workflows/u15-acceptance.yml` runs only by manual dispatch, with
`contents: read` and `actions: read`, SHA-pinned actions and
`persist-credentials: false`. It runs
`python -B scripts/release/acceptance.py --output target/u15/release-evidence.json`
and uploads one artifact `u15-acceptance` whose only member is
`release-evidence.json` (fields `head`, `quality`, `acceptance`,
`trusted_publishers_registered`, plus the checked `evidence`). The producer
refuses to run outside upstream or for a ref other than `refs/heads/main`.
Its input `trusted_publishers_registered` (default `false`) is the person's
declaration that step 4 below is done; it is not checked against the
registries. Its second input `first_publication` (default `false`) declares
the one-time first publication with scoped tokens (steps 3 and 4b below).
`release_gate` accepts exactly one of the two: `trusted_publishers_registered:
true` (OIDC), or `first_publication: true` when the protected publish job's
own live query finds all eleven crate names on crates.io and
`@aletheia-works/paludarium-wasm` on npm absent, or, to resume a first publication that
stopped partway, finds every name that is present holding exactly the
release version with the approved digest (step 3). Any `registries_absent`,
`registry_presence` or `registry_resume_verified` value in the document is
discarded, and any registry answer other than 200/404 stops. Both `false`,
or both `true`, is refused. Unit and integration tests
replace the GitHub adapter with in-memory data: they do not prove that any
real run, artifact or registration exists.

## Release Please

`.github/workflows/release.yml` runs Release Please as in the other
aletheia-works repositories, with the `aletheia-works-bot` App token
(`vars.BOT_CLIENT_ID`, `secrets.BOT_PRIVATE_KEY`) and only while the
repository variable `RELEASE_AUTOMATION_ENABLED` (managed in
`infra/github/release.tf`) is `true`. Unlike those repositories, a push to
main only creates or updates the release PR (`skip-github-release`): the
same-head evidence of step 5 must exist for the release PR's merge commit
before any tag, so only a manual dispatch creates the tag and the GitHub
release. The labels `autorelease: pending` and `autorelease: tagged` are
managed in `infra/github/main.tf`.

`.github/release-please-config.json` uses the `simple` release type and
updates the workspace version, the eleven internal dependency versions, the
workspace crates' entries in `Cargo.lock` and `fuzz/Cargo.lock` (the fuzz
crate keeps `0.0.0`), and the npm package version. `release-as: 0.1.0`
fixes the first version; remove it in the first change after `v0.1.0` is
published, or the next release PR proposes `0.1.0` again.

## Owner hand-off (Step 16)

U15 does not publish. The person (and, where noted, an upstream
administrator) does these steps in order. FR10.1 stays a GAP until step 6
and its registry checks are complete.

1. **Merge the release PR.** When: when the version Release Please
   proposes is the one to publish. `release.yml` (Release Please) keeps a
   release PR open from every push to main; it changes only the versions
   (`Cargo.toml`, `Cargo.lock`, `fuzz/Cargo.lock`, `package.json`), the
   manifest and `CHANGELOG.md`. Merging it creates no tag. Confirm: note
   the merge commit, the new main head SHA;
   `gh api repos/aletheia-works/paludarium/commits/<sha> --jq .commit.verification.verified`
   prints `true`, and the `CI` (`ci.yml`) push run for that SHA starts.
2. **Create the protected `release` environment.** When: before any tag
   is pushed (release preflight rejects a missing or unprotected
   environment). An upstream administrator creates environment `release`
   with required reviewers (at least one) and administrator bypass off;
   limiting deployments to `v*.*.*` tags is recommended. "Prevent
   self-review" is optional (Step14b, Q3): the project has one maintainer,
   who both pushes the tag and approves the deployment, so `release_gate`
   no longer requires it. Turning it on is stricter and still accepted,
   but then a second reviewer is needed.
   Confirm: `gh api repos/aletheia-works/paludarium/environments/release`
   shows a `required_reviewers` rule with at least one reviewer and
   `can_admins_bypass: false` (preflight refuses a missing rule, an empty
   reviewer list, or bypass `true` or unknown).
3. **Decide name ownership and the first publication.** When: before
   step 4. Confirm that all eleven crate names and `@aletheia-works/paludarium-wasm` are
   free (not yet on crates.io or npm) or owned by the project. crates.io
   lets a Trusted Publisher be registered only for a crate that already
   exists, so the first publication cannot use OIDC. For that one release
   only, `publish.yml` can publish with short-lived, scoped tokens that the
   person creates (Step14b, Q4); it never creates a token itself:
   - crates.io: on crates.io, Account Settings, API Tokens, create a new
     token with an expiration date as short as the release needs (for
     example 1 to 7 days, long enough to cover a resumed run below), the
     endpoint scope `publish-new` only, and crate scopes listing the eleven
     names one by one (recommended). A pattern such as `paludarium*` is a
     prefix match: it covers `paludarium` and the `paludarium-*` names, but
     also any other crate name that starts with `paludarium`, so it is
     broader than the eleven crates.
   - npm: create a granular access token with the shortest expiration the
     release needs and "Read and write" permission limited to the
     `@aletheia-works` scope (organization); it must be usable from CI for
     publishing (check npm's current settings for two-factor bypass when
     creating it). A package that does not exist yet cannot be selected on
     its own, so this token also covers the organization's other packages
     (such as `@aletheia-works/terrarium`): keep its expiration short and
     revoke it right after the first publication (step 4b).
   - Store them as **environment secrets of `release`** (not repository or
     organization secrets): `U15_FIRST_CRATES_IO_TOKEN` and
     `U15_FIRST_NPM_TOKEN`. Environment secrets reach only the protected
     publish job, after the deployment approval. `publish.yml` passes them
     only to the `cargo publish` and `npm publish` child processes (dry
     runs get no token), never prints them, and receipts and
     `publication-progress.json` record no token value. Each child gets
     only an allow-list of variables (`CARGO_ENVIRONMENT` and
     `NPM_ENVIRONMENT` in `scripts/release/check.py`): `cargo` never
     receives `GH_TOKEN`, `GITHUB_TOKEN` or `ACTIONS_ID_TOKEN_REQUEST_*`,
     and `npm` receives only what `npm publish --provenance` needs (CI
     detection, the OIDC request variables, the GitHub context named in
     the provenance statement, setup-node's `.npmrc` and its token).
   - **crates.io new-crate rate limit.** crates.io limits how many new
     crates one account can create in a short time, and all eleven crates
     are new in the first publication. Before step 6, check the current
     limit on crates.io (its documentation or help@crates.io); if it is
     lower than eleven within the publish job's 30 minutes, ask crates.io
     (help@crates.io) to raise it for this account first. If it is not
     raised, expect the run to stop at the limit and resume as below.
   - **Declare the expected owners** (Step24). As **environment variables
     of `release`** (Settings, Environments, `release`, Environment
     variables; not secrets, they are not secret), set
     `U15_CRATES_IO_OWNERS` to the comma-separated crates.io owner logins
     every one of the eleven crates must have (users by login, teams as
     `github:<org>:<team>`, exactly as `https://crates.io/api/v1/crates/<name>/owners`
     lists them in `users[].login`), and `U15_NPM_MAINTAINERS` to the
     comma-separated npm maintainer names of `@aletheia-works/paludarium-wasm` (as
     `https://registry.npmjs.org/%40aletheia-works%2Fpaludarium-wasm` lists them in
     `maintainers[].name`). A resume (below) is refused when either is
     unset, or when a present name has any other owner set (an extra or
     missing owner included).
   - **Resuming a first publication that stopped partway** (rate limit,
     timeout, network error). Do not delete, yank or re-upload anything,
     and do not move the tag. Keep the artifact
     `u15-publication-progress-attempt-<n>` of the stopped run (Step24:
     `publish.yml` uploads `publication-progress.json` and the command
     receipts, which hold no token values, even when the job stops; keep
     it before its 90-day retention ends) and the job logs. After the cause is gone (for the rate limit,
     after the waiting time crates.io names), re-run the publish job of the
     same `publish.yml` run (same tag and head; it needs the `release`
     approval again; the tokens must not have expired). The publish job's
     live check then accepts `first_publication: true` only when every
     crate name and `@aletheia-works/paludarium-wasm` that is already present holds
     exactly `0.1.0` with the approved digest: the crates.io `checksum`
     equals the SHA-256 of that crate's approved `.crate`, and the npm
     `dist.integrity` equals the approved tarball's SHA-512 integrity
     (both taken from the `u15-package` artifact for the release head).
     The crates.io version must also say `yanked: false`, and the name's
     crates.io owners or npm maintainers must equal the declared ones
     above exactly (Step24, review 04 findings 3 and 4).
     Those versions are only verified; the remaining ones are uploaded in
     dependency order. If even one present name has another version, a
     different digest, a digest that cannot be read, a yanked version, or
     other or unreadable owners, the job refuses before uploading
     anything. Then the owner decides the recovery
     outside `publish.yml` (for example a new version), never by
     overwriting a published version.
   The first publication is accepted only when the acceptance document
   declares `first_publication: true` (step 5) and the publish job's live
   query finds none of the eleven crates nor `@aletheia-works/paludarium-wasm` on any
   registry, or only matching versions as in the resume above. If a
   crate's `0.1.0` is uploaded outside `publish.yml`, `publish.yml` later
   only verifies it, and stops unless the registry checksum equals the
   `.crate` digest built by `release-check.yml` for the release head.
   Confirm: before step 5, `https://crates.io/api/v1/crates/<name>` returns
   404 for each of the eleven names and
   `https://registry.npmjs.org/%40aletheia-works%2Fpaludarium-wasm` returns 404, and the
   `release` environment lists both secrets (names only).
4. **Register the Trusted Publishers.** When: for the first release,
   right after its publication (step 6) succeeded; for a later release,
   before step 5. After the first publication, also (4b) revoke both
   tokens on crates.io and npm and delete `U15_FIRST_CRATES_IO_TOKEN` and
   `U15_FIRST_NPM_TOKEN` from the `release` environment: from the second
   release on, only OIDC (Trusted Publishing) is used, and the publish job
   refuses to run in OIDC mode while either secret is still set. For each
   of the eleven crates on crates.io and for
   `@aletheia-works/paludarium-wasm` on npm, register repository
   `aletheia-works/paludarium`, workflow `publish.yml` and environment
   `release`. npm also requires `repository.url` in `package.json` to
   match (it does) and its supported runner and CLI (npm 12.2.0 on Node
   26.12.0 here). Confirm: each crate's and the npm package's Trusted
   Publishing settings show exactly that repository, workflow and
   environment.
5. **Produce same-head quality and acceptance evidence.** When: on the
   release PR's merge commit from step 1, while it is still the main head, after steps 2 and 3 (first release) or 2 to 4
   (later releases). The `ci.yml` push run
   starts by itself; dispatch each of the others once:
   `gh workflow run u12-quality.yml --repo aletheia-works/paludarium --ref main`,
   the same for `u14-quality.yml` and `release-check.yml`. When all four
   have succeeded (do not dispatch `u14-quality.yml` again to wait for a
   passing FR8.3; if FR8.3 fails, record it and stop), dispatch, within 7
   days:
   for the first release
   `gh workflow run u15-acceptance.yml --repo aletheia-works/paludarium --ref main -f first_publication=true`,
   and for later releases
   `gh workflow run u15-acceptance.yml --repo aletheia-works/paludarium --ref main -f trusted_publishers_registered=true`
   (`true` only when step 4 is complete). Never set both. Confirm: the run
   succeeded and its artifact `u15-acceptance` holds only
   `release-evidence.json`, with that head, eight `quality` rows, the five
   `acceptance` IDs all `passed: true`, and exactly one of
   `first_publication: true` or `trusted_publishers_registered: true`.
6. **Create the tag and approve the environment.** When: after step 5,
   with the person's explicit approval of the exact version, tag, head,
   registries, artifact digests, authentication and environment settings.
   Dispatch Release Please once:
   `gh workflow run release.yml --repo aletheia-works/paludarium --ref main`.
   It finds the merged release PR, creates tag `v<version>` on its merge
   commit and the GitHub release, and the tag starts `publish.yml`. If any
   commit landed on main after the merge commit, preflight still accepts
   the tag only when the merge commit is reachable from main and every
   evidence run in step 5 is for that commit. `publish.yml`
   then runs preflight and the package check and waits at the `release`
   environment; a required reviewer (the maintainer, unless self-review is
   prevented) checks the head, version and digests and approves the
   deployment. Confirm: the run
   succeeded and `publication-progress.json` (in the run's artifact
   `u15-publication-progress-attempt-<n>`) lists all eleven
   crates and `@aletheia-works/paludarium-wasm`; then, independently, each crate's
   `https://crates.io/api/v1/crates/<name>/0.1.0` `checksum` equals the
   `.crate` SHA-256 in the `u15-package` artifact, `npm view
   @aletheia-works/paludarium-wasm@0.1.0 dist.integrity` equals the tarball's SHA-512
   integrity, and the npm provenance attestation names the upstream
   repository, `publish.yml` and that head. Only then FR10.1 becomes OK.
   After the first release, do step 4 (Trusted Publishers) and 4b
   (revoke and delete both tokens) before any later tag.

The evidence document follows `policy.release_gate`: exact head/tag/repository,
official completed successful quality run identities for every required
purpose, each acceptance ID with its verified artifact digest, and either the
Trusted Publisher declaration or the first-publication declaration confirmed
by the live registry-absence check. The authorization step re-fetches GitHub
commit, reachability, environment, run and actual environment-review history.
Evidence from old U14 measurements is historical unless the declared source
and build closure are independently proven equivalent. No same-binary
performance rerun is used to wait for a passing result.

## Publication and recovery

Only after the user explicitly approves the precise version, tag/head,
registries, artifact digests, authentication and protection configuration may
the owner dispatch `release.yml` to create the version tag. No plan approval authorizes tag creation
or publication by itself. `publish.yml` accepts only an exact
`vMAJOR.MINOR.PATCH` after Python validation, verifies signed main
reachability and actual environment protection before builds, then requires
the protected human approval.

Only the publish job receives `id-token: write`. The authorize step writes the
fixed value `authentication=oidc` or `authentication=first-publication-token`
to its step output. With `oidc`, crates-io-auth-action obtains a short-lived
token and revokes it in its post step, and npm uses Trusted Publishing; the
job refuses if a first-publication secret is still set. With
`first-publication-token` (the first release only), the OIDC step is skipped
and the person's scoped, expiring tokens from the `release` environment
secrets are used; the job refuses if an OIDC token is present or either
secret is missing. npm provenance is requested in both modes. All
third-party actions are pinned to
officially resolved commit SHAs. The fork is never substituted for upstream.

The publish job checks the previously tested eleven crate artifacts and npm
tarball. Cargo dry-run reassembly must have the approved byte digest before
upload; original source/locks must remain unchanged. Existing versions are
queried first: an equal digest is verified without re-upload, a different
digest or unknown network result stops the sequence. The same npm tarball is
uploaded. Registry checksums/integrity are checked after each upload.

On partial failure, preserve `publication-progress.json` (the run's artifact
`u15-publication-progress-attempt-<n>`, uploaded even when the job stops), attempted uploads,
unverified uploads and all logs. Do not delete, replace, move a tag or retry
publication automatically. An owner must inspect registry state and propose
the remaining recovery. For a first publication, the owner may re-run the
publish job as described in step 3 ("Resuming a first publication"): it
continues only when every version already present equals the approved
artifact, and uploads only the remaining ones. The cargo and npm children
get allow-listed environments only (step 3); the allow-list for
`npm publish --provenance` follows npm's provenance generator for GitHub
Actions and is proven only by the real publication. A successful workflow alone does not establish
FR10.1: registry retrieval/source/provenance verification is required.

## Official references

- [Cargo publishing](https://doc.rust-lang.org/cargo/reference/publishing.html)
- [Current crates.io Trusted Publishing implementation documentation](https://github.com/rust-lang/crates.io/blob/8b4b7af90bf73b0bbb73b47a29b9de86ed702093/svelte/src/routes/docs/trusted-publishing/%2Bpage.svelte)
- [crates.io authentication action](https://github.com/rust-lang/crates-io-auth-action)
- [npm Trusted Publishing](https://docs.npmjs.com/trusted-publishers/)
- [GitHub environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
