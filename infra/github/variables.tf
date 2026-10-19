variable "github_owner" {
  description = "GitHub user or organization that owns the repository"
  type        = string
}

variable "repository_name" {
  description = "Name of the repository to manage"
  type        = string
  default     = "paludarium"
}

variable "repository_description" {
  description = "Repository description"
  type        = string
  default     = "A Rust re-implementation of the blink x86-64 Linux user-mode emulator (work in progress)"
}

variable "repository_visibility" {
  description = "Repository visibility (public or private)"
  type        = string
  default     = "public"

  validation {
    condition     = contains(["public", "private"], var.repository_visibility)
    error_message = "visibility must be either \"public\" or \"private\"."
  }
}

variable "repository_topics" {
  description = "Topics to attach to the repository"
  type        = list(string)
  default = [
    "emulator",
    "x86-64",
    "linux",
    "webassembly",
    "rust",
  ]
}

variable "release_reviewers" {
  description = "GitHub logins whose approval the release environment requires before publishing"
  type        = list(string)
  default     = ["JamBalaya56562"]
}

variable "crates_io_owners" {
  description = "crates.io owner logins every published crate must have (U15_CRATES_IO_OWNERS, see docs/release.md)"
  type        = list(string)
  default     = ["JamBalaya56562"]
}

variable "npm_maintainers" {
  description = "npm maintainer names @aletheia-works/paludarium-wasm must have (U15_NPM_MAINTAINERS, see docs/release.md)"
  type        = list(string)
  default     = ["jambalaya56562"]
}
