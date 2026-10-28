#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/../../../target/guests/network}"
mkdir -p "$out"
"${MUSL_CC:-musl-gcc}" -static -O1 -Wall -Wextra -Werror -o "$out/network" "$here/network.c"
