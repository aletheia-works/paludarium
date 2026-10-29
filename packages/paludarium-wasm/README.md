# @aletheia-works/paludarium-wasm

Runs Linux x86-64 guest programs in a shared WebAssembly memory with dedicated
execution Workers. Pass `jit: true` to `run()` to translate blocks of x86-64
register instructions into WebAssembly; it is off by default.

```js
import { createPaludarium } from "@aletheia-works/paludarium-wasm";

const launcher = await createPaludarium({ wasmUrl: "/paludarium.wasm" });
try {
  const guest = launcher.run({
    program: "/guest",
    files: { "/guest": elfBytes }, // Uint8Array, default mode 0755
    args: ["/guest"],
  });
  const output = new Response(guest.stdout).text();
  const errors = new Response(guest.stderr).text();
  await guest.stdin.getWriter().close();
  console.log(await guest.exited, await output, await errors);
} finally {
  await launcher.dispose();
}
```

Serve the page, Wasm, and ES module Workers from the same origin with
`Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: require-corp`. SharedArrayBuffer and module Workers
are required. Node.js runs the same execution modules in worker_threads.

`run()` returns Web Streams and an `exited` promise. A guest exit or signal
resolves the promise; an emulator error rejects it with `PaludariumError`.
Errors retain available `rip` (bigint), instruction `bytes`, and `syscall`
(number). Call `kill()` for a cooperative SIGKILL request. Guest execution has
no automatic deadline. Callers may set their own deadline and dispose the
launcher if the guest does not stop. Initialization, diagnostics, and disposal
have bounded host cleanup watchdogs. A Worker trap discards the entire shared
runtime because the abandoned Worker may have held a Rust lock.

Independent `run()` calls create isolated virtual filesystems. To retain state
between stopped guests, explicitly create a filesystem:

```js
const filesystem = await launcher.createFileSystem({
  files: { "/app/program": elfBytes, "/app/input": inputBytes },
  fileModes: { "/app/input": 0o644 },
});
const guest = launcher.run({ program: "/app/program", cwd: "/app", filesystem });
// Drain both output streams and close stdin as above before awaiting exit.
await guest.exited;
const entries = await filesystem.snapshot();
await filesystem.remove("/app/node_modules", { recursive: true });
await filesystem.dispose();
```

Filesystem handles belong to one launcher. A running guest holds an exclusive
lease: snapshot, remove, dispose, and a second run using that filesystem reject
while the lease is active. Disposed handles cannot be reused. Snapshots include
paths, modes, inode/link identity, nanosecond modification times, regular bytes,
and symlink target bytes. They do not follow symlinks. Initial configured files
have epoch modification times; guest-created and modified files use the Host
realtime clock. `createFileSystem({ entries: await filesystem.snapshot() })`
rebuilds a filesystem from a snapshot: directories, symlinks, hard links (entries
sharing an `inode`), modes and modification times. See the JavaScript guide for
its validation rules and limits. `cwd` defaults to `/` and must name an existing virtual
directory. `tty` optionally supplies columns and rows in the range 0–65535.
`limits: { tasks, openFiles, memory }` optionally caps the guest's tasks
(`EAGAIN` beyond it), its `RLIMIT_NOFILE` (`EMFILE`) and its memory in bytes
(`SIGKILL` beyond it, as the OOM killer); all are unlimited by default.
No host filesystem mount is exposed by this API. `network: { allow }` gives the
guest TCP clients and name resolution for what `allow` names; Node.js connects
itself, and a browser needs `relay: { url, protocols }`, a WebSocket relay that
connects for it. `relay.mjs` in this package is one
(`node relay.mjs --allow github.com:443`; see the documentation's Network relay
page).

Build the one production Wasm module from the repository root with
`mise run wasm:build`. The npm archive includes that module, the launcher
and its required Workers, TypeScript declarations, and Apache-2.0 license.
Publishing is a separate lifecycle step. Verification uses fixed probe/aube
binaries and a fresh Linux oracle for Node, Chromium, Firefox, and real Safari;
results apply to the versions and fixtures recorded in the wasm evidence.
