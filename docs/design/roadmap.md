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
- More system calls and instructions. Writable shared file mappings are the
  largest gap; others include passing descriptors over sockets
  (`SCM_RIGHTS`) and file ownership (`chown`) (both under
  [Limitations](../guide/limitations)).
- Considering dynamically linked programs.
- Considering a native JIT.
- A limit on memory; tasks and open files can already be limited.
- Revisiting building with stable Rust.
- Revisiting how much checking a release needs.
