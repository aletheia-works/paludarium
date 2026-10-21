#!/usr/bin/env bash
#MISE description="actionlint — workflow syntax + ShellCheck over every run: block (read-only; not yet part of lint:all)"
set -euo pipefail
actionlint .github/workflows/*.yml
