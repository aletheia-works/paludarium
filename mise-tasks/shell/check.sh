#!/usr/bin/env bash
#MISE description="ShellCheck — every shell script in the repository (read-only)"
set -euo pipefail
# find rather than globstar: macOS ships bash 3.2.
find mise-tasks scripts tests tools spikes -name '*.sh' \
  -not -path '*/target/*' -not -path '*/node_modules/*' -print0 | xargs -0 shellcheck
