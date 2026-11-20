#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/../../../target/guests/processes}"
mkdir -p "$out"
musl-gcc -static -pthread -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/process" "$here/process.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/pty" "$here/pty.c"
musl-gcc -static -pthread -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/signalfd" "$here/signalfd.c"
musl-gcc -static -pthread -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/mqueue" "$here/mqueue.c"
musl-gcc -static -pthread -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/keys" "$here/keys.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/inotify" "$here/inotify.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/fanotify" "$here/fanotify.c"
musl-gcc -static -pthread -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/userfaultfd" "$here/userfaultfd.c"
musl-gcc -static -pthread -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/aio" "$here/aio.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/perf" "$here/perf.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/bpf" "$here/bpf.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/bpf-prog" "$here/bpf-prog.c"
musl-gcc -static -pthread -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/ptrace" "$here/ptrace.c"
musl-gcc -static -pthread -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/ptrace-syscalls" "$here/ptrace-syscalls.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/ptrace-requests" "$here/ptrace-requests.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/single-step" "$here/single-step.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/netlink-options" "$here/netlink-options.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/veth" "$here/veth.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/veth-ipv4" "$here/veth-ipv4.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/veth-traffic" "$here/veth-traffic.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/veth-iif" "$here/veth-iif.c"
musl-gcc -static -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/x87" "$here/x87.c" -lm
# The same on musl's dynamic linker by a name exec finds in the working
# directory, where inotify-interpreter puts a copy of it.
musl-gcc -O1 -fno-stack-protector -fcf-protection=none -pie -fPIE -Wl,--dynamic-linker=inotify-ld.so -o "$out/inotify-interp" "$here/inotify.c"
# The dynamic case: its linker is the one musl-gcc names, on the host and in the
# emulator.
musl-gcc -shared -fPIC -O1 -fno-stack-protector -o "$out/dynamic-plugin.so" "$here/dynamic-plugin.c"
musl-gcc -pthread -O1 -fno-stack-protector -fcf-protection=none -pie -fPIE -o "$out/dynamic" "$here/dynamic.c"
musl-gcc -pthread -O1 -fno-stack-protector -fcf-protection=none -fno-pie -no-pie -o "$out/dynamic-no-pie" "$here/dynamic.c"
# And on glibc's, which is the host's.
gcc -shared -fPIC -O1 -fno-stack-protector -o "$out/dynamic-glibc-plugin.so" "$here/dynamic-plugin.c"
gcc -pthread -O1 -fno-stack-protector -fcf-protection=none -pie -fPIE -DPLUGIN_NAME='"dynamic-glibc-plugin.so"' -o "$out/dynamic-glibc" "$here/dynamic.c" -ldl
rustc --target x86_64-unknown-linux-musl -C opt-level=1 -C target-feature=+crt-static -o "$out/command" "$here/command.rs"
