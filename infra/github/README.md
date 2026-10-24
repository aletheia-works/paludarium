# `infra/github/` — GitHub Settings as Code

OpenTofu configuration that manages this repository's settings declaratively,
as in [terrarium](https://github.com/aletheia-works/terrarium/tree/main/infra/github)
and [vivarium](https://github.com/aletheia-works/vivarium/tree/main/infra/github).
Organization settings, including the allowed GitHub Actions, live in
[`aletheia-works/.github`](https://github.com/aletheia-works/.github) instead.

## Managed resources

| Resource | File |
|---|---|
| Repository (About: description, homepage and topics; merge methods, features) | `main.tf` |
| Vulnerability alerts | `main.tf` |
| Branch ruleset for `main`, with the required status checks | `main.tf` |
| Issue/PR labels | `main.tf` |
| `release` environment and its `main` branch policy | `release.tf` |

The repository and GitHub's default labels existed before this module and are
adopted by `import` blocks in `main.tf`, so the first apply starts from an
empty state without a seed.

The main ruleset requires every check of `ci.yml` and `check / Commitlint`.
Keep `local.required_checks` equal to the job check names whenever a job in
`ci.yml` is added, removed or renamed.

The `release` environment is the one `docs/release.md` (step 2) and release
preflight require: administrator bypass off and deployments limited to
`main` (publication runs on main; the tag is made after it). It has no
required reviewer: publication waits for no approval, because the same-head
evidence gate decides it. Publication is by
Trusted Publishing (OIDC) only, so it holds no registry token; the Trusted
Publisher of every crate and of the npm package names this environment.

## CI workflows

| Trigger | Workflow | Action |
|---|---|---|
| PR touching `infra/github/**` | `terraform-plan.yml` | Runs `tofu plan` and posts the diff as a PR comment |
| PR touching `infra/github/**` | `tofu-fmt-autofix.yml` | Commits `tofu fmt -recursive` fixes to the PR |
| Merge to `main` | `terraform-apply.yml` | Runs `tofu apply` |
| Weekly + post-apply | `terraform-state-backup.yml` | Renews the state artifact before it expires |

All four call the organization's reusable workflows in
[`aletheia-works/.github`](https://github.com/aletheia-works/.github) and use
the `TF_TOKEN_GITHUB` secret. Plan and apply also use the organization secret
`TF_STATE_PASSPHRASE`, which encrypts the state.

## Running locally

### 1. Create a Fine-grained PAT

Create a Fine-grained personal access token at
<https://github.com/settings/personal-access-tokens/new> with:

- **Resource owner**: the organization that owns this repository
- **Repository access**: this repository only
- **Repository permissions**: Administration (RW), Contents (RW), Metadata (R),
  Issues (RW), Pull requests (RW), Actions (RW), Workflows (RW),
  Secrets (RW), Variables (RW), Environments (RW), Webhooks (RW),
  Dependabot alerts (RW), Code scanning alerts (RW)
- **Organization permissions**: none

CI uses the same token as the repository secret `TF_TOKEN_GITHUB`.

### 2. Prepare local files

```bash
cd infra/github
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars and set github_owner

export GITHUB_TOKEN=github_pat_xxxxxxxxxxxx
```

### 3. Fetch the latest state

The canonical state lives as an artifact on the most recent successful
`terraform-apply` run, named by the repository variable `LATEST_APPLY_RUN_ID`.
Download it before running `plan`/`apply` locally:

```bash
gh run download "$(gh variable get LATEST_APPLY_RUN_ID)" --name terraform-state --dir .
```

The state is encrypted, so set `TF_ENCRYPTION` as CI does, with the same
passphrase as `TF_STATE_PASSPHRASE`. State encryption needs OpenTofu 1.7 or
later, which `versions.tf` requires; CI installs the latest release.

```bash
export TF_ENCRYPTION='
key_provider "pbkdf2" "state" { passphrase = "<TF_STATE_PASSPHRASE>" }
method "aes_gcm" "state" { keys = key_provider.pbkdf2.state }
state { method = method.aes_gcm.state }
'
```

### 4. Run tofu

```bash
tofu init
tofu plan
tofu apply
```

## State management

State is stored as a GitHub Actions artifact, encrypted with the organization
secret `TF_STATE_PASSPHRASE`, because anyone can download the artifacts of a
public repository. The backup only downloads and uploads that artifact again
to extend its retention; no state is put in a GitHub Release. An unencrypted
state can still be read, so the first apply after the change encrypts it.
Keep secrets out of the state all the same: the token is not managed as a
resource. A `concurrency` group serializes workflow runs to avoid concurrent
writes; there is no true distributed lock, so avoid running `apply` locally
while CI is running.

## File layout

```text
infra/github/
├── versions.tf                 # OpenTofu (1.7 or later) and provider versions
├── providers.tf                # GitHub provider config
├── variables.tf                # Input variables
├── main.tf                     # Repository settings, main ruleset, labels
├── release.tf                  # release environment and its branch policy
├── terraform.tfvars.example    # Template for terraform.tfvars
├── .gitignore                  # Excludes state and secrets
├── .terraform.lock.hcl         # Provider version lock (committed)
└── README.md
```
