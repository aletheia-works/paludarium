variable "github_owner" {
  description = "GitHub user or organization that owns the repository"
  type        = string
}

variable "repository_name" {
  description = "Name of the repository to manage"
  type        = string
  default     = "paludarium"
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

