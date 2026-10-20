# The environment of the publish job in .github/workflows/publish.yml
# (docs/release.md, step 2). It needs no reviewer: the same-head evidence gate
# decides publication. Only main deploys (publish first, tag last: the tag is
# made after publication), and release preflight refuses administrator
# bypass. The Trusted Publisher of every crate and of the npm package names
# this environment.

resource "github_repository_environment" "release" {
  repository  = github_repository.this.name
  environment = "release"

  can_admins_bypass   = false
  prevent_self_review = false

  deployment_branch_policy {
    protected_branches     = false
    custom_branch_policies = true
  }
}

resource "github_repository_environment_deployment_policy" "release_main" {
  repository     = github_repository.this.name
  environment    = github_repository_environment.release.environment
  branch_pattern = "main"
}
