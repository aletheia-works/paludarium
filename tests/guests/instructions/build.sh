#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/../../../target/guests/u2}"
case_id="${2:-observe}"
case "$case_id" in observe) ;; *) echo "unknown U2 case: $case_id" >&2; exit 2;; esac
mkdir -p "$out"
"${MUSL_CC:-musl-gcc}" -static -O1 -o "$out/observe" "$here/observe.c"
