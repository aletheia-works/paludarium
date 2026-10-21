#!/usr/bin/env bash
#MISE description="actionlint — workflow syntax + ShellCheck over every run: block (read-only)"
set -euo pipefail
actionlint .github/workflows/*.yml
