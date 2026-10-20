# Live demo

This page runs paludarium in your browser. When you press **Run**, the page
builds a tiny static x86-64 Linux program that prints your message with the
`write` system call and ends with `exit_group`, and paludarium runs it in
WebAssembly.

<ClientOnly>
  <HelloDemo />
</ClientOnly>

## What happens

1. The page assembles an ELF executable of about 200 bytes in JavaScript: one loadable
   segment with eight instructions and your message
   ([`hello-elf.ts`](https://github.com/aletheia-works/paludarium/blob/main/docs/.vitepress/theme/hello-elf.ts)).
2. It loads [`@aletheia-works/paludarium-wasm`](https://www.npmjs.com/package/@aletheia-works/paludarium-wasm)
   and calls `run()` with the program in a private in-memory filesystem.
3. paludarium decodes and runs the x86-64 instructions, handles the two
   system calls, and returns standard output and the exit status as Web
   Streams and a promise.

The same package runs real programs such as statically linked C and Rust
binaries; see [JavaScript and the browser](./guide/javascript).

::: info Cross-origin isolation
paludarium uses `SharedArrayBuffer`, which browsers allow only on
cross-origin isolated pages. GitHub Pages cannot send the needed headers, so
this site registers
[coi-serviceworker](https://github.com/gzuidhof/coi-serviceworker) to add
them. On the first visit the page reloads once.
:::
