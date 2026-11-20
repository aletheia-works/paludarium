# Testing and verification

paludarium is correct when it gives the same results as a real x86-64 Linux.

## Differential tests

The same guest program runs on a real x86-64 Linux and on paludarium, and the
results are compared. Expected results are not stored in the repository: every
CI run produces them afresh on an x86-64 Linux runner.

- **Per instruction**: registers, flags and memory.

- **Per program**: standard output, standard error and the exit status, byte
  for byte.

- Flags and values that x86 leaves undefined (AF after logic instructions,
  the flags after `div`, …) are skipped, following a per-instruction table.

- Where x86 only bounds a result and Intel's and AMD's CPUs differ in it
  (`RCPPS` and the like, and the last bit of x87's transcendental
  instructions), a case prints whether the result is within that bound of a
  reference, which each CPU's is, rather than its bits; it still prints every
  bit where the CPUs agree. Limitations names each such place.

- Values that change from run to run, such as pids, times, random numbers and
  addresses, are normalised or excluded before the comparison.

- New instructions and system calls get their test cases, and the result on
  real Linux, before they are implemented.

- Each case has a 30-second timeout, or a longer one for a case that waits
  out a timer of Linux's own, such as `TIME_WAIT`.

- The emulated side of the program cases runs on a virtual clock
  (`RecordingHost`): a sleep or a timed wait jumps it to its deadline after
  up to 10 ms of real time (no more than the wait itself) for a wake-up from
  another thread, so a signal another process sends just as a long sleep
  starts still comes before the sleep ends, as on Linux. The clock is
  shared by every process and thread of the guest, so one that sleeps moves
  the time another one sees. A case therefore prints no times, and compares
  how long a wait took only when no other process or thread sleeps
  meanwhile. To wait for another process, it uses a pipe or a descriptor
  to wait on without a timeout, not a sleep.

- The core-dump case needs Linux to keep the kernel's default `core_pattern`
  (`core`, with `core_uses_pid` 0). CI sets it with `sysctl`; elsewhere the
  case stops and says so, rather than compare with a core sent to a crash
  handler.

- The AF_UNIX datagram case needs the kernel's default
  `net.unix.max_dgram_qlen` of 10, which systemd raises on many hosts. CI
  sets it with `sysctl` (a container's own network namespace has it);
  elsewhere the case stops and says so.

- The `chroot` case takes `CAP_SYS_CHROOT` in a user namespace of its own,
  which Linux grants. Ubuntu's AppArmor refuses every capability there
  (the `unprivileged_userns` profile) while
  `kernel.apparmor_restrict_unprivileged_userns` is 1, so CI sets it to 0
  with `sysctl`; elsewhere the case differs from such a host's native run.

- The native side must be a real x86-64 Linux. Docker on an Arm Mac runs
  x86-64 programs under QEMU's user-mode emulation, which handles signals
  itself, so there even native results can differ from Linux: a stopped and
  continued child sends SIGCHLD to a parent that set `SA_NOCLDSTOP`, where
  Linux sends none. Such a run is not evidence, in either direction.
  On main, 27 of the process cases and 5 of the network cases fail there
  for such reasons. QEMU:
  - refuses socket options it does not know (`SO_PEEK_OFF`,
    `SO_PASSPIDFD`, `SO_PASSRIGHTS`, `SO_TIMESTAMP_NEW`, …), and gives
    `SO_TIMESTAMPING` back as an `int`;
  - leaves `MSG_CTRUNC` out of `recvmsg`'s flags;
  - handles `SA_NOCLDSTOP`, `SA_NOCLDWAIT`, `F_SETSIG`, core dumps and
    `sigqueue` itself;
  - shows its own threads and timer numbers;
  - does not pass `FIOQSIZE` on;
  - takes `socket` type flags Linux refuses with `EINVAL`.

  Docker's own kernel counts a datagram's buffer differently, and the
  slower native side can time out. The container's musl is Debian's (1.2.5
  in Debian 13), not the runner's (1.2.4), so where musl's wrapper changed
  (`accept4`) a guest checks the kernel through the system call itself.
  `mise run linux-dev-compare` runs the tests there for a checkout and for
  main, each in the image its own `ci/linux-dev/Dockerfile` makes (so a
  checkout that changes the image shows that change too), and lists only
  the cases whose result differs. A case that fails
  only on the checkout runs once more: if it passes then, it is listed as
  flaky, as some cases' timing is under QEMU; else it fails the task, as
  does a case that main ran and the checkout did not (a suite that
  stopped).

- The native results are those of the CI runner's kernel (Linux 7.0 on
  `ubuntu-26.04`, which the `differential` and `coverage` jobs of `ci.yml` and
  `quality.yml` name instead of `ubuntu-latest`; the jobs that compare fixed
  programs stay on `ubuntu-latest`). Where Linux changed between versions or
  builds, as in what a UDP datagram takes of the receive buffer, whose small
  head cache that kernel's Hyper-V networking makes 704 bytes (640 under
  Docker), the emulator follows that kernel, and a runner with another kernel
  can fail those cases. `listen` on a connected AF_UNIX socket is one: it is
  `EINVAL` as Linux's fix of 2026 makes it, where `ubuntu-24.04`'s
  7.0.0-1017-azure still succeeded when this was written.

- A test checks that `diff_processes` runs exactly the process cases that
  `tests/guests/processes/cases.json` lists, so that a case cannot be listed
  and never run.

- The network cases (`diff_network`) serve the guest from the test itself, on
  127.0.0.1, so that native Linux and the emulator talk to the same server;
  the emulator may reach only that server's port and one that nothing
  listens on. The `listen` and `udp` cases serve on the guest's own loopback, which
  both run in their own way: Linux's network stack, and the emulator's
  kernel. Name resolution on Linux depends on the runner's own files and
  servers, so it is checked under the emulator only, against `localhost`,
  over UDP through musl's resolver and over TCP with a query of its own.

- The WebAssembly package's network is checked on Node.js
  (`wasm-network.test.mjs`) and through the [relay](../guide/relay)
  (`wasm-relay.test.mjs`): freestanding guests reach a server the test runs
  on 127.0.0.1, and `localhost` is resolved. The relay's own tests cover its
  allow list and tickets, its window in both directions (with a peer that
  writes everything before it reads anything) and its parity with the
  kernel's rules. `wasm-browser-network.mjs` runs the guests through the
  relay in Chromium, Firefox, WebKit and Safari in CI.

- Every night, Debian's own dynamically linked programs run natively and
  under the emulator, once without and once with the native JIT, in a Debian
  container, and their exit status and
  standard output are compared (`tests/guests/distro/compare.py`): shells
  (fish among them), awk, Perl, Python, Ruby, PHP, Lua, LuaJIT, Tcl,
  Node.js, Go, Java, Erlang, OCaml, R, Guile, SBCL, pandoc, Emacs, BusyBox,
  SQLite, PostgreSQL, Redis, memcached, nginx, compressors, Git, OpenSSL,
  GnuPG, rsync, make, CMake, Ninja, gcc, g++ and binutils, among others, and
  cases that use signals and timers, child processes and threads, sockets on
  the loopback, netlink (iproute2's `ip` and glibc's `getifaddrs` on `lo`),
  file locks (SQLite's WAL with several writers) and `/proc`.
  Under the emulator they run with the container's root mounted, so both
  sides load the same libraries. Each case writes to its own directory, and
  none prints times, so no output is masked. Every case succeeds natively;
  one that fails there counts as a failure, since comparing two failures
  would check little. The emulator is a static musl
  build, since the container's glibc may be older than the runner's. The
  Debian image and packages are not pinned, so that the emulator is checked
  against what Debian ships now. This comparison is also part of the run
  before a release, so a Debian update that breaks a program blocks a release
  until the emulator is fixed; the versions are kept with the results.

## Fuzzing

Fourteen targets (decoding, ELF loading, system call arguments, filesystem
paths, MMU operations, the CPU, threads, futexes, events, sockets and the two
JITs)
each run for 600 seconds with AddressSanitizer and LeakSanitizer, every night.

Fuzzing for a fixed time does not prove that every input is safe, but it keeps
checking that no guest input makes the emulator panic.

A pull request also fuzzes seven of them (`vfs_paths`, `load_elf`,
`syscall_args` and the four `kernel_*`), for the same 600 seconds with the
same sanitizers, from `-seed=1` and an empty corpus. As the seed and corpus
are fixed, a target that does not link the changed code repeats main's search,
so only the targets that can see the change run. A target links the
workspace packages its source names (with the modules it includes by
`#[path]`) and their dependencies, which `scripts/ci-changes.py` reads from
`cargo metadata`; a change to one of those packages runs the target. A
change to a manifest, `Cargo.lock`, `rust-toolchain.toml`, `fuzz/`,
`fuzz-pr.yml`, the selection script or anything else the fuzz group needs,
and every push to main, run all seven. When no target can see the change,
the fuzz job is skipped; a separate job still checks that all fourteen
targets build whenever the change could affect them.

## Memory order

Litmus tests (`crates/paludarium-cpu/tests/litmus.rs`) run small programs of
`MOV`, `MFENCE`, `XCHG` and `LOCK OR` on two to four guest threads that share
memory, for many rounds, and fail on any outcome x86 forbids: MP, LB, SB with
each kind of fence, 2+2W, S and IRIW. They run on every host in CI, the Arm
one (macOS) included, where the emulator itself has to keep x86's order.

They are meant for an order the emulator breaks in its own logic, such as a
store it holds back or a value it keeps too long. A missing host fence they
mostly do not catch: an emulated instruction takes long enough that a
host's store has become visible before the next one runs, and on the Arm
machines tried, removing the fence of `MFENCE` or of a locked instruction left
every test passing.

## Coverage and static checks

- Line coverage must stay at 80 % or more. The measurement before the first
  release was about 94 % for the whole workspace. The `coverage` job of
  `ci.yml` holds five gates to that floor, each counting only its own tests:
  the whole workspace; the core packages, with the harness's tests run but
  its own files left out; the Rust crates the WebAssembly build uses; the
  crates behind the terminal; and the CPU and decoder under the encodings
  tests.
- The core and workspace gates share one instrumented build and one run of
  each test. The core packages' and the harness's tests run first and the
  core gate reports on their profiles; the other packages' tests then add
  theirs and the workspace gate reports on all of them. Cargo builds the
  same units for the two runs as for one run of the whole workspace, so both
  numbers are the ones separate runs give. The other three gates each clean
  and run their own tests, as a report counts every test binary in the
  target directory; before the terminal gate the job removes the test
  binaries of the packages outside the core gate, so it starts from what the
  core run left, as it did when that run came last. The copy of this job in
  `quality.yml` (nightly and before a release) runs the gates the same way,
  and `mise run coverage` runs the core and workspace gates so. On one
  commit, the separate runs and the shared run counted the same lines in
  every gate, and their missed lines differed only in a few lines that
  depend on thread timing.
- Each gate's printed table counts the same packages and files as the
  gate. A `cargo llvm-cov report` without `-p` counts every workspace
  member whose code the test binaries link, so the terminal and encodings
  reports used to add `paludarium-jit-native`, which the `paludarium`
  binary and the harness link, at 0%: their totals read below the
  measured rates (79.86% for 80.83%). Starting a gate from a clean target
  directory instead of the earlier steps' binaries gave the same lines
  and the same rates, but for lines that depend on thread timing.
- The terminal gate runs the libraries' unit tests, not the harness's
  differential tests. So that the system calls those check count there too,
  some kernel unit tests (`replay_tests.rs` and `ptrace_replay_tests.rs`
  in `crates/paludarium-kernel/src/`) make a differential guest's calls in
  the same order and compare its lines with what the guest prints on
  native Linux: as printed on Linux 7.0, or as printed under the emulator
  for a case whose differential test finds it equal to Linux's. The
  differential tests still compare the whole guests with Linux on every
  run.
- The coverage job's summary prints, for each gate that writes an lcov
  (WebAssembly, terminal and encodings), the lcov's hit and measured lines,
  their rate, and how many hit lines it has above the 80% floor (rounded up
  to a whole line), so a pull request sees a margin shrink before its gate
  fails. `--fail-under-lines` does not read the lcov file: cargo-llvm-cov
  compares the line totals of llvm-cov's JSON export of the same test
  binaries, profile and ignored files, which count the same lines, so the
  printed rate is the one the gate compared. The core and workspace gates
  write no lcov; they compare the totals their printed table's TOTAL line
  shows. Where a gate also prints a table (terminal and encodings), the
  summary says whether its TOTAL line counts the same hit and measured
  lines. On main (run 44284364893) both did. A TOTAL differs only when the
  `report` reads other binaries or files than the gated run, as the
  terminal and encodings tables did when they added `paludarium-jit-native`
  (above).
- `cargo fmt --check`, clippy (warnings are errors) and `cargo deny` (licences,
  sources, known vulnerabilities) run on every pull request. Clippy also runs
  with the stable Rust that `rust-version` names (the latest, moved weekly)
  for the Linux, macOS and Windows targets, so the native crates keep building
  with stable; the tests use only the pinned nightly.
- Every GitHub Actions action is pinned to a commit SHA.

## CI

| When | What |
|---|---|
| Every pull request | unit tests on Linux, macOS and Windows (when the change can reach them, below); lint; dependency checks; the WebAssembly build; differential tests on x86-64 Linux, also with the native JIT; coverage; probe, aube, ripgrep and coreutils differential tests; acceptance tests in the four WebAssembly environments (Safari when the change can reach the Wasm module, below) and in WebKit on x86-64 Linux, which include the x87 process cases compared byte for byte with x86-64 Linux; fuzzing of the seven pull-request targets the change can affect (above) |
| Every night | fuzzing of the 14 targets; differential tests on macOS and Windows; Debian's own programs on x86-64 Linux, with and without the native JIT; the four WebAssembly environments and WebKit on x86-64 Linux with and without the JIT; the performance measurement |
| Every day | every scheduled workflow is checked to have started on time; one that failed to start, did not run or was disabled opens an Issue |
| Every week | the pinned nightly Rust, the workspace's `rust-version` (the latest stable Rust) and the aube, ripgrep and coreutils guests move to their latest releases, each in a pull request that merges itself once its checks pass |
| Before a release | all of the above on the exact code being released (below) |

On a pull request and on a push to main, the expensive jobs — the
differential tests, coverage, fuzzing, the guest programs and the
WebAssembly checks — start only after the quick stage passed: lint, clippy
(also with the stable Rust), polyglot lint and the Linux unit tests, which
take two to four minutes. A head that fails them, or that a later push
supersedes in those minutes, takes no runners for the long jobs. A quick
check the change does not need is skipped (polyglot lint on a push to main,
lint and clippy when no Rust changed), and a skip would pass down to every
job that needs it, so each expensive job tests the quick stage's own result
instead. `ci-ok`, the required check, needs every job itself, so a job
skipped because the quick stage failed cannot make it pass;
`scripts/ci-changes.py --self-test` refuses a `ci.yml` where it does not.
Dependency Review runs only on pull requests that change a Cargo or npm
manifest or lockfile, a workflow or a local action.

Two kinds of job run only when the change can reach what they test, as
macOS runners can be scarce. The unit test jobs (Linux, macOS and Windows)
run when the change touches a crate they test (the harness only for its
library), a manifest, the lockfile or the toolchain, or a file outside the
crates that their sources name by a relative path (`#[path]`,
`include_str!`, a path joined to the crate's directory) or that the
harness's instruction list reads under `tests/guests`. So a new
differential guest or a script alone does not run them, and a change to
`packages/paludarium-wasm/jit-support.mjs`, which a JIT unit test reads,
does. The Safari row of the WebAssembly checks is left out when the only
crates a change reaches are ones the Wasm module (`paludarium-wasm`) does
not link, such as the harness, the command or the native JIT; the Linux
rows still run. `scripts/ci-changes.py` reads both from `cargo metadata`
and the sources, and its self-test fails on a unit test source that builds
a path at run time without saying what it reads.

GitHub cancels a job that no hosted runner acquires, as macOS arm64 runners
run short of capacity, with an annotation ("not acquired by Runner") and no
step run. `ci-ok` fails then, as those tests did not run. When such jobs
are a CI run's only failures but for `ci-ok`, `rerun-unacquired.yml`
reruns the failed jobs with `gh run rerun --failed`, at most twice per run,
and not when a later run of the branch replaced it. A job that ran a step
and failed is never rerun, and then nothing is. Its log says why each run
was or was not rerun; `scripts/ci-rerun.py --self-test` checks the decision.

So do not rerun such jobs of a `CI` run by hand: the workflow starts as soon
as the run completes. It watches only `CI`, not `Publish` or
`release-acceptance`. A hand rerun started first makes it see an attempt that is not
the latest, and it then reruns nothing. Rerun by hand only when its log says
the run was already rerun twice, or when a job that ran a step failed and
you have reason to think the failure was a flake.

Before a guest program is built, its dependencies must pass `cargo deny`
under the root policy. Only aube and coreutils have exceptions. coreutils has
one, for itself alone: the CC0-1.0 license of `notify` 8.2.2, which `uu_tail`
uses; the build keeps its full license text. aube has the licenses of two crates
and, for now, three RustSec advisories against `zstd` 0.13.3 and `zstd-safe`
7.3.0 (RUSTSEC-2026-0391, RUSTSEC-2026-0398 and RUSTSEC-2026-0403). aube gets
those versions through `decmpfs`, which pins `zstd` exactly, so aube cannot
update them. The advisory exceptions go once a `decmpfs` release takes `zstd`
0.14 ([SocketDev/decmpfs#16](https://github.com/SocketDev/decmpfs/issues/16)):
an exception that no crate matches fails the audit, so the aube bump that no
longer needs them cannot merge until they are removed.
`tests/guests/programs/evidence.py` lists every exception, and `source-lock.json`
names them with the exact crate versions.

## Acceptance before a release

Before a version is published, the exact code to be released must meet all of
these, or nothing is published ([Release process](../release)):

- The eight probe checks pass on Linux, macOS and Windows, and on Node.js,
  Chromium, Firefox and Safari.
- The four aube operations give the same standard output and exit status as
  real x86-64 Linux everywhere. In the four WebAssembly environments they
  also match when the filesystem is rebuilt from its snapshot before each
  operation, and each rebuilt filesystem has the same snapshot.
- Results with and without the JIT agree in the four WebAssembly
  environments.
- The JIT is faster, by a statistically significant margin (below).

## JIT and the interpreter

The JIT must mean exactly what the interpreter means. It has no semantics of
its own: the same differential tests run with and without it. Instructions the
JIT cannot translate run in the interpreter, and such runs do not count as JIT
successes. In the four WebAssembly environments, probe, aube and the ripgrep
searches all run in both modes, and each JIT run must execute translated code.

### The native JIT

The native JIT has no semantics of its own either. Its unit tests run every
form it compiles, and random runs of them, from random registers, flags and
memory, and compare the registers, flags and memory with the interpreter's;
a stop before an instruction must be one the interpreter faults on. On every
pull request the differential tests also run with every block compiled the
first time it runs (`PALUDARIUM_TEST_JIT=1`, the `differential-jit` job), and
the `jit_native` fuzz target compares compiled code with the interpreter for
arbitrary instruction bytes. Half of the unit tests' runs start with the slots
of the thread's TLB filled, so that compiled code loads and stores through
them, and the MMU's tests check which pages a slot lets it read and write
after `mprotect`, `fork`, `clear_refs` and `UFFDIO_WRITEPROTECT`. Stores
through a slot that a load just filled again after `mprotect` and
`UFFDIO_WRITEPROTECT` must fault, and one after `clear_refs` must set the
soft-dirty bit again.

### How speed is measured

In a Node.js Worker, the whole probe program runs ten times with and ten times
without the JIT, alternating in a fixed order. Every run uses a new Session and
includes the JIT's translation time. A one-sided exact sign-flip test over 1024
permutations must give p < 0.05, and the JIT must be faster on average. No
outliers are dropped and nothing is measured again until it passes.

Before the first release (Node.js 26.12.0), the mean was 5.75 s without the JIT
and 4.55 s with it (about 21 % faster), with p = 1/1024. No speed-up is claimed
for other CPUs or browsers.
