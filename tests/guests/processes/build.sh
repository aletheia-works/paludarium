#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/../../../target/guests/processes}"
mkdir -p "$out"
musl-gcc -static -pthread -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/process" "$here/process.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/pty" "$here/pty.c"
musl-gcc -static -pthread -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/signalfd" "$here/signalfd.c"
musl-gcc -static -pthread -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/mqueue" "$here/mqueue.c"
# The dynamic case: its linker is the one musl-gcc names, on the host and in the
# emulator.
musl-gcc -shared -fPIC -O1 -fno-stack-protector -o "$out/dynamic-plugin.so" "$here/dynamic-plugin.c"
musl-gcc -pthread -O1 -fno-stack-protector -fcf-protection=none -pie -fPIE -o "$out/dynamic" "$here/dynamic.c"
musl-gcc -pthread -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/dynamic-no-pie" "$here/dynamic.c"
# And on glibc's, which is the host's.
gcc -shared -fPIC -O1 -fno-stack-protector -o "$out/dynamic-glibc-plugin.so" "$here/dynamic-plugin.c"
gcc -pthread -O1 -fno-stack-protector -fcf-protection=none -pie -fPIE -DPLUGIN_NAME='"dynamic-glibc-plugin.so"' -o "$out/dynamic-glibc" "$here/dynamic.c" -ldl
rustc --target x86_64-unknown-linux-musl -C opt-level=1 -C target-feature=+crt-static -o "$out/command" "$here/command.rs"
