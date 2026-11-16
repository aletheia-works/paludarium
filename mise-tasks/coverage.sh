#!/usr/bin/env bash
#MISE description="The core and workspace line-coverage gates, each failing under 80 %, as in CI (x86-64 Linux)"
set -euo pipefail
# The same commands as the two gates of the coverage job in ci.yml and
# quality.yml: one instrumented build and one run of each test. The core
# packages' and the harness's tests run first and the core gate reports on
# them alone; the other workspace packages' tests then add theirs and the
# workspace gate reports on all of them (docs/design/quality.md). The
# WebAssembly, terminal and encodings gates need CI's native inputs and run
# only there.
if [ -z "${CORE_PACKAGES:-}" ]; then
  # The one list, from ci.yml's env.
  CORE_PACKAGES=$(awk '/^  CORE_PACKAGES: >-$/ { list = 1; next }
    list && /^    -p / { printf "%s ", $0; next }
    list { exit }' .github/workflows/ci.yml)
fi
read -r -a packages <<< "$CORE_PACKAGES"
if [ "${#packages[@]}" -eq 0 ]; then
  echo "no CORE_PACKAGES in .github/workflows/ci.yml" >&2
  exit 1
fi
export RUST_TEST_THREADS=1

cargo llvm-cov clean --workspace
(
  # shellcheck disable=SC1090
  source <(cargo llvm-cov show-env --sh)
  cargo build --locked -p paludarium --target-dir target/llvm-cov-target
)
cargo llvm-cov --no-report --locked "${packages[@]}" -p paludarium-harness
cargo llvm-cov report "${packages[@]}" -p paludarium-harness --ignore-filename-regex 'paludarium-harness/' --fail-under-lines 80

excludes=(--exclude paludarium-harness)
for package in "${packages[@]}"; do
  if [ "$package" != -p ]; then
    excludes+=(--exclude "$package")
  fi
done
cargo llvm-cov --no-report --locked --workspace "${excludes[@]}"
cargo llvm-cov report --workspace --fail-under-lines 80
