# Debian's own builds of the programs compare.py runs. Debian's amd64 packages
# target the x86-64 baseline, without AVX, which paludarium does not implement
# (Ubuntu 26.04's runner images take x86-64-v3 builds).
# The image and packages are not pinned: the emulator is checked against the
# programs Debian ships now, and the workflow keeps their versions with the results.
FROM debian:trixie
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    bc binutils bzip2 ca-certificates cmake coreutils curl dc file findutils g++ gawk gcc gdb git \
    gnupg jq less libc6-dev lua5.4 make mawk nodejs openssh-client openssl perl php-cli python3 \
    rsync ruby sqlite3 tar tcl vim-tiny xxd xz-utils zstd \
 && rm -rf /var/lib/apt/lists/*
