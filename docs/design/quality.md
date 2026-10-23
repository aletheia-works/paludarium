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
- Each case has a 30-second timeout.

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
| Every night | fuzzing of the 13 targets; differential tests on macOS and Windows; the four WebAssembly environments with and without the JIT; the performance measurement |
| Every day | every scheduled workflow is checked to have started on time; one that failed to start, did not run or was disabled opens an Issue |
| Every week | the pinned nightly Rust and the aube and ripgrep guests move to their latest releases, each in a pull request that merges itself once its checks pass |
| Before a release | all of the above on the exact code being released (below) |

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
