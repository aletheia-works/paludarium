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
- Values that change from run to run, such as pids, times, random numbers and
  addresses, are normalised or excluded before the comparison.
- New instructions and system calls get their test cases, and the result on
  real Linux, before they are implemented.
- Each case has a 30-second timeout, or a longer one for a case that waits
  out a timer of Linux's own, such as `TIME_WAIT`.
- The core-dump case needs Linux to keep the kernel's default `core_pattern`
  (`core`, with `core_uses_pid` 0). CI sets it with `sysctl`; elsewhere the
  case stops and says so, rather than compare with a core sent to a crash
  handler.
- The AF_UNIX datagram case needs the kernel's default
  `net.unix.max_dgram_qlen` of 10, which systemd raises on many hosts. CI
  sets it with `sysctl` (a container's own network namespace has it);
  elsewhere the case stops and says so.
- The native side must be a real x86-64 Linux. Docker on an Arm Mac runs
  x86-64 programs under QEMU's user-mode emulation, which handles signals
  itself, so there even native results can differ from Linux: a stopped and
  continued child sends SIGCHLD to a parent that set `SA_NOCLDSTOP`, where
  Linux sends none. Such a run is not evidence, in either direction.
- The native results are those of the CI runner's kernel (Linux 7.0 on
  `ubuntu-24.04`). Where Linux changed between versions or builds, as in
  what a UDP datagram takes of the receive buffer, whose small head cache
  that kernel's Hyper-V networking makes 704 bytes (640 under Docker), the
  emulator follows that kernel, and a runner with another kernel can fail
  those cases.
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

## Fuzzing

Thirteen targets (decoding, ELF loading, system call arguments, filesystem
paths, MMU operations, the CPU, threads, futexes, events, sockets and the JIT)
each run for 600 seconds with AddressSanitizer and LeakSanitizer, every night.

Fuzzing for a fixed time does not prove that every input is safe, but it keeps
checking that no guest input makes the emulator panic.

## Coverage and static checks

- Line coverage must stay at 80 % or more. The measurement before the first
  release was about 94 % for the whole workspace.
- `cargo fmt --check`, clippy (warnings are errors) and `cargo deny` (licences,
  sources, known vulnerabilities) run on every pull request.
- Every GitHub Actions action is pinned to a commit SHA.

## CI

| When | What |
|---|---|
| Every pull request | unit tests on Linux, macOS and Windows; lint; dependency checks; the WebAssembly build; differential tests on x86-64 Linux; coverage; probe, aube and ripgrep differential tests; acceptance tests in the four WebAssembly environments and in WebKit on x86-64 Linux; part of the fuzzing |
| Every night | fuzzing of the 13 targets; differential tests on macOS and Windows; the four WebAssembly environments and WebKit on x86-64 Linux with and without the JIT; the performance measurement |
| Every day | every scheduled workflow is checked to have started on time; one that failed to start, did not run or was disabled opens an Issue |
| Every week | the pinned nightly Rust and the aube and ripgrep guests move to their latest releases, each in a pull request that merges itself once its checks pass |
| Before a release | all of the above on the exact code being released (below) |

Before a guest program is built, its dependencies must pass `cargo deny`
under the root policy. Only aube has exceptions: the licenses of two crates
and, for now, three RustSec advisories against `zstd` 0.13.3 and `zstd-safe`
7.3.0 (RUSTSEC-2026-0391, RUSTSEC-2026-0398 and RUSTSEC-2026-0403). aube gets
those versions through `decmpfs`, which pins `zstd` exactly, so aube cannot
update them. The advisory exceptions go once a `decmpfs` release takes `zstd`
0.14 ([SocketDev/decmpfs#16](https://github.com/SocketDev/decmpfs/issues/16)):
an exception that no crate matches fails the audit, so the aube bump that no
longer needs them cannot merge until they are removed.
`tests/guests/programs/evidence.py` lists every exception.

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

### How speed is measured

In a Node.js Worker, the whole probe program runs ten times with and ten times
without the JIT, alternating in a fixed order. Every run uses a new Session and
includes the JIT's translation time. A one-sided exact sign-flip test over 1024
permutations must give p < 0.05, and the JIT must be faster on average. No
outliers are dropped and nothing is measured again until it passes.

Before the first release (Node.js 26.12.0), the mean was 5.75 s without the JIT
and 4.55 s with it (about 21 % faster), with p = 1/1024. No speed-up is claimed
for other CPUs or browsers.
