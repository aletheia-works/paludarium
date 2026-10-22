#!/usr/bin/env bash
#MISE description="Run a command in the x86-64 Linux development container (ci/linux-dev/Dockerfile)"
# Run a command inside the native x86-64 Linux development container
# (ci/linux-dev/Dockerfile).
#
#   mise run linux-dev -- cargo test --locked -p paludarium-harness --test diff_core
#
# By default the working tree is copied (tar) into the named volume
# `paludarium-work` before every run, so it also works when Docker Desktop does
# not share the repository path with containers. Build output under
# /work/target and the cargo registry persist in volumes between runs.
# Set PALUDARIUM_DEV_MOUNT=bind to bind-mount the repository instead.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
# The image is tagged with the toolchain pinned in rust-toolchain.toml, so a
# toolchain bump builds a new image rather than reusing one with the old nightly.
toolchain="$(cd "$root" && bash scripts/rust-toolchain.sh)"
image="${PALUDARIUM_DEV_IMAGE:-paludarium-dev:$toolchain}"
docker_bin="${DOCKER:-docker}"
mode="${PALUDARIUM_DEV_MOUNT:-sync}"

host_root="$root"
if command -v cygpath >/dev/null 2>&1; then
  # Git Bash on Windows: hand Docker a Windows path and stop MSYS from
  # rewriting the container-side paths.
  host_root="$(cygpath -w "$root")"
  export MSYS_NO_PATHCONV=1
fi

if ! "$docker_bin" image inspect "$image" >/dev/null 2>&1; then
  "$docker_bin" build --platform linux/amd64 --ulimit stack=-1 \
    --build-arg TOOLCHAIN="$toolchain" -t "$image" "$host_root/ci/linux-dev"
fi

common=(--rm --platform linux/amd64
  # QEMU on Docker VMM can crash rustc with the default finite stack limit.
  # Apply the same stack setting during both image builds and test runs.
  --ulimit stack=-1
  --cap-add SYS_PTRACE --security-opt seccomp=unconfined
  -v paludarium-cargo-registry:/usr/local/cargo/registry
  -e CARGO_TERM_COLOR=never -w /work)

if [ "$mode" = bind ]; then
  exec "$docker_bin" run "${common[@]}" -v "$host_root:/work" \
    -v paludarium-target:/work/target "$image" "$@"
fi

# Copy the working tree (without build output and VCS data) into the volume,
# removing files that no longer exist locally but keeping /work/target.
tar -C "$root" \
  --exclude=./target --exclude=./.git --exclude=./.jj \
  --exclude=./.claude --exclude=./fuzz/target --exclude=./node_modules \
  --exclude='./spikes/*/target' --exclude='./spikes/*/node_modules' \
  --exclude='./tests/guests/hello-rs/target' \
  -cf - . \
  | "$docker_bin" run -i "${common[@]}" -v paludarium-work:/work "$image" \
      bash -c 'find /work -mindepth 1 -maxdepth 1 ! -name target -exec rm -rf {} + && tar -C /work -xf - && find /work -path /work/target -prune -o -name "*.sh" -exec sed -i "s/\r$//" {} +'

exec "$docker_bin" run "${common[@]}" -v paludarium-work:/work "$image" "$@"
