# Roadmap

paludarium was built from the ground up in these stages.

| Stage | Goal | Status |
|---|---|---|
| 1 | A static-musl hello world runs on native Linux | Done |
| 2 | probe and aube run on native Linux | Done |
| 3 | probe and aube run in Node.js and three browsers (Chromium-based, Firefox, Safari) | Done |
| 4 | probe and aube run on macOS and Windows hosts | Done |
| 5 | A minimal WebAssembly JIT, faster than the interpreter in Node.js | Done |
| Release | Publish to crates.io and npm | 0.1.x published |

Each stage moved on only after differential tests showed that its programs give
the same results as a real x86-64 Linux.

## Next

Nothing here is a promise, but these are on the table:

- More system calls and instructions (see [Limitations](../guide/limitations)).
- Considering dynamically linked programs.
- Considering a native JIT.
- Revisiting limits on memory and threads.
- Revisiting building with stable Rust.
- Revisiting how much checking a release needs.
