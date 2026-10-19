# The protected environment of the publish job in .github/workflows/publish.yml
# (docs/release.md, step 2). Release preflight refuses an environment without
# a required reviewer or with administrator bypass on.
data "github_user" "release_reviewers" {
  for_each = toset(var.release_reviewers)
  username = each.value
}

resource "github_repository_environment" "release" {
  repository  = github_repository.this.name
  environment = "release"

  can_admins_bypass   = false
  prevent_self_review = false

  reviewers {
    users = [for user in data.github_user.release_reviewers : tonumber(user.id)]
  }

  deployment_branch_policy {
    protected_branches     = false
    custom_branch_policies = true
  }
}

resource "github_repository_environment_deployment_policy" "release_tags" {
  repository  = github_repository.this.name
  environment = github_repository_environment.release.environment
  tag_pattern = "v*.*.*"
}

# The expected owners a resumed first publication checks (docs/release.md,
# step 3). The first-publication tokens are environment secrets the person
# sets by hand; they are never managed here.
resource "github_actions_environment_variable" "crates_io_owners" {
  repository    = github_repository.this.name
  environment   = github_repository_environment.release.environment
  variable_name = "U15_CRATES_IO_OWNERS"
  value         = join(",", var.crates_io_owners)
}

resource "github_actions_environment_variable" "npm_maintainers" {
  repository    = github_repository.this.name
  environment   = github_repository_environment.release.environment
  variable_name = "U15_NPM_MAINTAINERS"
  value         = join(",", var.npm_maintainers)
}

# Release Please (.github/workflows/release.yml) runs only while this is true.
variable "release_automation_enabled" {
  description = "Enable release PR generation and, on dispatch, tag/GitHub release creation"
  type        = bool
  default     = true
}

resource "github_actions_variable" "release_automation" {
  repository    = github_repository.this.name
  variable_name = "RELEASE_AUTOMATION_ENABLED"
  value         = tostring(var.release_automation_enabled)
}
