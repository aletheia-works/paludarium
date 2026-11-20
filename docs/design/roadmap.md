# Roadmap

paludarium was built from the ground up in these stages.

| Stage | Goal | Status |
|---|---|---|
| 1 | A static-musl hello world runs on native Linux | Done |
| 2 | probe and aube run on native Linux | Done |
| 3 | probe and aube run in Node.js and three browsers (Chromium-based, Firefox, Safari) | Done |
| 4 | probe and aube run on macOS and Windows hosts | Done |
| 5 | A minimal WebAssembly JIT, faster than the interpreter in Node.js | Done |
| Release | Publish to crates.io, npm and JSR | crates.io and npm since 0.1.0, JSR from the first release after 0.15.0 ([releases](https://github.com/aletheia-works/paludarium/releases)) |

Each stage moved on only after differential tests showed that its programs give
the same results as a real x86-64 Linux. ripgrep and uutils coreutils have
since joined probe and aube as verified programs ([Supported features](../guide/features#programs-verified)).

## Next

Nothing here is a promise, but these are on the table:

- One more verified program, the brush shell, once its next release passes
  the guest audit (the current one is held back by yanked crates and
  security advisories in its dependencies).
- More system calls and instructions (see [Limitations](../guide/limitations)).
- The native JIT (`--jit`, experimental on Linux x86-64): turning it on by
  default once the criteria in [Decisions](decisions#when-the-native-jit-is-turned-on-by-default)
  hold, other hosts (Arm64, macOS, Windows), and compiling more of each
  block (more instructions, blocks joined to each other, flags worked out
  only when they are read).
- Revisiting building with stable Rust.
- Revisiting how much checking a release needs.
