#!/bin/bash
# programs.sh <emulator> <name>: runs the probe, ripgrep and aube cases once and
# prints "time <case> <name> <seconds>" for each (jit-speed.yml, jit-ab.yml).
set -u
E=$1; N=$2; shift 2
G=$PWD/target/guests/programs
envs=(--env PATH=/no-node --env HOME=/home/guest --env TMPDIR=/tmp --env NO_COLOR=1 --env TERM=dumb --env LANG=C --env LC_ALL=C --env TZ=UTC)
t() { local tag=$1; shift; local s=$(date +%s.%N); "$@" >/dev/null 2>&1 || true; local e=$(date +%s.%N); echo "time $tag $N $(awk "BEGIN{print $e - $s}")"; }
for c in tokio-timer unix-stream-pair rayon mutex-condvar fs-basic fs-hardlink fs-symlink fs-flock; do
  t probe-$c timeout 120 "$E" "$@" "${envs[@]}" "$G/probe" "$c"
done
W=$(mktemp -d) && cp -r tests/guests/programs/fixtures/. "$W"
mapfile -t cases < <(python3 -c 'import json; [print(c["name"]) for c in json.load(open("tests/guests/programs/ripgrep-cases.json"))["cases"]]')
for c in "${cases[@]}"; do
  mapfile -t args < <(python3 -c 'import json,sys; [print(a) for c in json.load(open("tests/guests/programs/ripgrep-cases.json"))["cases"] if c["name"]==sys.argv[1] for a in c["args"]]' "$c")
  (cd "$W/app" && t ripgrep-$c timeout 120 "$E" "$@" "${envs[@]}" --mount "$W/app:/" --mount "$W/outside:/outside" "$G/ripgrep" "${args[@]}")
done
for a in version install frozen list; do
  case $a in version) x=(--version);; install) x=(install);; frozen) rm -rf "$W/app/node_modules"; x=(install --frozen-lockfile);; list) x=(list);; esac
  (cd "$W/app" && t aube-$a timeout 300 "$E" "$@" "${envs[@]}" --mount "$W/app:/" --mount "$W/outside:/outside" "$G/aube" "${x[@]}")
done
rm -rf "$W"
