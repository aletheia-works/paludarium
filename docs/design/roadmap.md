# Roadmap

paludarium was built from the ground up in these stages.

| Stage | Goal | Status |
|---|---|---|
| 1 | A static-musl hello world runs on native Linux | Done |
| 2 | probe and aube run on native Linux | Done |
| 3 | probe and aube run in Node.js and three browsers (Chromium-based, Firefox, Safari) | Done |
| 4 | probe and aube run on macOS and Windows hosts | Done |
| 5 | A minimal WebAssembly JIT, faster than the interpreter in Node.js | Done |
| Release | Publish to crates.io and npm | Published since 0.1.0 ([releases](https://github.com/aletheia-works/paludarium/releases)) |

Each stage moved on only after differential tests showed that its programs give
the same results as a real x86-64 Linux. ripgrep has since joined probe and
aube as a verified program ([Supported features](../guide/features#programs-verified)).

## Next

Nothing here is a promise, but these are on the table:

- Two more verified programs, uutils coreutils and the brush shell, once
  their next releases pass the guest audit (the current ones are held back
  by yanked crates and security advisories in their dependencies).
- More system calls and instructions (see [Limitations](../guide/limitations)).
- x87's transcendental instructions for the `long double` math of programs on
  glibc that reach them.
- The native JIT (`--jit`, experimental on Linux x86-64): turning it on by
  default, other hosts (Arm64, macOS, Windows), and compiling more of each
  block (more instructions, blocks joined to each other, flags worked out
  only when they are read).
- Revisiting building with stable Rust.
- Revisiting how much checking a release needs.
