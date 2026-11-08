# Debian's own builds of the programs compare.py runs. Debian's amd64 packages
# target the x86-64 baseline, without AVX, which paludarium does not implement
# (Ubuntu 26.04's runner images take x86-64-v3 builds).
# The image and packages are not pinned: the emulator is checked against the
# programs Debian ships now, and the workflow keeps their versions with the results.
FROM debian:trixie
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    bc binutils brotli bsdextrautils bsdutils busybox bzip2 ca-certificates cmake coreutils curl dc diffutils \
    ed emacs-nox file findutils g++ gawk gcc gdb git gnupg golang-go jq less libc6-dev \
    libjson-pp-perl lua5.4 lz4 lzip make mawk mksh ninja-build nodejs openssh-client openssl \
    parallel patch perl php-cli pigz procps python3 redis-server redis-tools rsync ruby sqlite3 \
    tar tcl tzdata unzip util-linux vim-tiny xxd xz-utils zip zsh zstd \
 && rm -rf /var/lib/apt/lists/*
# Go programs are built here, natively: compiling Go's standard library under
# the emulator takes far longer than a case may (8 s natively, over 15 minutes
# emulated), and the cases check the Go runtime, not the compiler.
COPY scripts/goroutines.go /opt/go/goroutines.go
RUN cd /opt/go && GOCACHE=/tmp/go-cache CGO_ENABLED=0 go build -o /usr/local/bin/goroutines goroutines.go \
 && rm -rf /tmp/go-cache
# Language runtimes and servers the runtimes() cases run.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    graphviz guile-3.0 imagemagick luajit memcached nginx ocaml pandoc r-base-core sbcl socat \
 && rm -rf /var/lib/apt/lists/*
