#!/usr/bin/env bash
#MISE description="Fuzz one target with the nightly's settings (x86-64 Linux, ASan and LSan)"
#MISE tools={"cargo:cargo-fuzz"="latest"}
#USAGE arg "<target>" help="fuzz target in fuzz/fuzz_targets/ (e.g. decode)"
#USAGE flag "--seconds <seconds>" default="600" help="libFuzzer -max_total_time"
# shellcheck disable=SC2154  # usage_* are exported by mise from the #USAGE spec
set -euo pipefail
# The same options and per-target input limits as .github/workflows/fuzz-nightly.yml.
export ASAN_OPTIONS=detect_leaks=1
export LSAN_OPTIONS="suppressions=$PWD/fuzz/lsan.supp"
extra=()
case "$usage_target" in
  cpu_instructions) extra=(-max_len=4096) ;;
  mmu_instructions) extra=(-max_len=4608) ;;
  jit_compile) extra=(-max_len=968) ;;
  jit_cache) extra=(-max_len=2048) ;;
esac
cargo fuzz run --fuzz-dir fuzz --sanitizer address "$usage_target" -- \
  -seed=1 -max_total_time="$usage_seconds" -timeout=30 -rss_limit_mb=2048 ${extra[@]+"${extra[@]}"}
