#!/usr/bin/env bash
# Tests scripts/rustup-retry.sh with a fake rustup that fails a given number
# of times and leaves partial install state behind, as a broken download does.
set -euo pipefail

script=$(cd "$(dirname "$0")" && pwd)/rustup-retry.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/project"
cat > "$work/bin/rustup" <<'EOF'
#!/usr/bin/env bash
count=$(( $(cat "$FAKE_COUNT" 2>/dev/null || echo 0) + 1 ))
echo "$count" > "$FAKE_COUNT"
echo "$*" >> "$FAKE_CALLS"
# Each attempt finds the state the previous failure left behind.
if [ -e "$RUSTUP_HOME/toolchains/$FAKE_TOOLCHAIN-x86_64-unknown-linux-gnu/partial" ]; then
  echo "seen partial" >> "$FAKE_CALLS"
fi
if [ "$count" -le "$FAKE_FAILURES" ]; then
  mkdir -p "$RUSTUP_HOME/tmp" "$RUSTUP_HOME/toolchains/$FAKE_TOOLCHAIN-x86_64-unknown-linux-gnu" \
    "$RUSTUP_HOME/toolchains/other-x86_64-unknown-linux-gnu"
  touch "$RUSTUP_HOME/toolchains/$FAKE_TOOLCHAIN-x86_64-unknown-linux-gnu/partial"
  exit 1
fi
EOF
chmod +x "$work/bin/rustup"
export PATH="$work/bin:$PATH" RUSTUP_HOME="$work/home" RUSTUP_RETRY_DELAY=0
export FAKE_COUNT="$work/count" FAKE_CALLS="$work/calls"

run() {
  rm -rf "$RUSTUP_HOME" "$FAKE_COUNT" "$FAKE_CALLS"
  FAKE_FAILURES=$1 FAKE_TOOLCHAIN=$2 && export FAKE_FAILURES FAKE_TOOLCHAIN
  shift 2
  (cd "$work/project" && bash "$script" "$@")
}
fail() { echo "FAIL: $*" >&2; exit 1; }

# A failure is retried, and the half-installed toolchain is removed first.
run 2 nightly-2026-10-11 toolchain install nightly-2026-10-11 --profile minimal --component rust-src
[ "$(cat "$FAKE_COUNT")" = 3 ] || fail "expected 3 attempts"
! grep -q "seen partial" "$FAKE_CALLS" || fail "a retry saw the partial toolchain"
[ -d "$RUSTUP_HOME/toolchains/other-x86_64-unknown-linux-gnu" ] || fail "another toolchain was removed"
[ ! -e "$RUSTUP_HOME/tmp" ] || fail "rustup tmp was kept"

# The toolchain name is found after options that take values.
run 1 1.99.1 toolchain install --profile minimal -c clippy 1.99.1
! grep -q "seen partial" "$FAKE_CALLS" || fail "options before the name"

# Without a name, the channel of rust-toolchain.toml is cleaned up.
printf '[toolchain]\nchannel = "nightly-2026-10-11"\n' > "$work/project/rust-toolchain.toml"
run 1 nightly-2026-10-11 toolchain install
! grep -q "seen partial" "$FAKE_CALLS" || fail "toolchain from rust-toolchain.toml"
rm "$work/project/rust-toolchain.toml"

# Other subcommands are retried without removing any toolchain.
run 1 nightly-2026-10-11 target add wasm32-unknown-unknown --toolchain nightly-2026-10-11
grep -q "seen partial" "$FAKE_CALLS" || fail "target add removed the toolchain"
[ "$(cat "$FAKE_COUNT")" = 2 ] || fail "target add was not retried"

# It gives up after RUSTUP_RETRY_ATTEMPTS failures, with a failing status.
if RUSTUP_RETRY_ATTEMPTS=2 run 5 nightly-2026-10-11 toolchain install nightly-2026-10-11 2>/dev/null; then
  fail "expected a failure after the last attempt"
fi
[ "$(cat "$FAKE_COUNT")" = 2 ] || fail "expected exactly 2 attempts"

# The arguments reach rustup unchanged.
run 0 nightly-2026-10-11 component add rust-src --toolchain nightly-2026-10-11
[ "$(cat "$FAKE_CALLS")" = "component add rust-src --toolchain nightly-2026-10-11" ] || fail "arguments changed"

echo "rustup-retry: all tests passed"
