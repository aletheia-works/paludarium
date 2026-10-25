# JavaScript and the browser

[`@aletheia-works/paludarium-wasm`](https://www.npmjs.com/package/@aletheia-works/paludarium-wasm)
runs x86-64 Linux programs in a shared WebAssembly memory, with one Worker per
guest thread. The same modules run in browsers and in Node.js
(`worker_threads`). The [live demo](../demo) uses this package.

```sh
npm install @aletheia-works/paludarium-wasm
```

## Run a program

```js
import { createPaludarium } from "@aletheia-works/paludarium-wasm";

const launcher = await createPaludarium({ wasmUrl: "/paludarium.wasm" });
try {
  const guest = launcher.run({
    program: "/guest",
    files: { "/guest": elfBytes }, // Uint8Array; default mode 0755
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

- `createPaludarium({ wasmUrl })` loads `paludarium.wasm` (shipped in the
  package) and starts the coordinator Worker.
- `run(options)` starts one guest and returns at once. `stdin` is a
  `WritableStream`, `stdout` and `stderr` are `ReadableStream`s of `Uint8Array`,
  and `exited` resolves to `{ kind: "exited", code }` or
  `{ kind: "signaled", signal }`.
- Drain both output streams and close `stdin` before awaiting `exited`.
- `kill()` asks the guest to stop with a cooperative `SIGKILL`. Guests have no
  automatic deadline: set your own and `dispose()` the launcher if a guest does
  not stop.

### Run options

| Option | Meaning |
|---|---|
| `program` | Absolute guest path of the program to run |
| `args` | `argv`, including `argv[0]` |
| `env` | Environment variables, as an object |
| `cwd` | Initial working directory (default `/`; it must exist) |
| `files` | Files to create before the start, path → `Uint8Array` |
| `fileModes` | Permission bits for some of `files` (default `0755`) |
| `entries` | A tree to create after `files`, such as a snapshot (see below); not with `filesystem` |
| `tty` | `{ columns, rows }` (0–65535) to give the guest a terminal size |
| `filesystem` | A filesystem from `createFileSystem()` to reuse (see below) |
| `jit` | `true` to translate hot x86-64 code to WebAssembly (default `false`) |
| `limits` | `{ tasks, openFiles }` to limit the guest (default: no limit; see below) |

The package does not expose host directories or the network to the guest.

`limits.tasks` (1 to 4294967295) is the most tasks the guest may have at once:
threads, and processes until they are reaped, as a cgroup's `pids.max`. A
`clone` or `fork` beyond it fails with `EAGAIN`. `limits.openFiles` (0 to
1048576) caps `RLIMIT_NOFILE`, as Linux's `fs.nr_open`: the guest starts with
both limits at most this and cannot raise them above it (`EPERM`), so opening
more files fails with `EMFILE`. Memory has no limit yet.

## Keep files between runs

Each `run()` gets its own isolated in-memory filesystem. To keep state between
guests, create a filesystem and pass it to `run()`:

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

A running guest holds an exclusive lease on its filesystem: `snapshot()`,
`remove()`, `dispose()` and a second `run()` with the same filesystem are
rejected while it runs. A snapshot lists every path with its mode, inode, link
count, modification time in nanoseconds, and the bytes of regular files or
symlink targets; it does not follow symlinks. A snapshot holds at most
272 MiB, and `snapshot()` rejects a larger one. That can happen to a
filesystem that was created without error: the snapshot writes the content
of every hard link (creation counts a link group once) and about 44 bytes
plus the path for each entry, so many links to large files, or close to the
1,048,576 entries allowed, can go past it.

### Rebuild a filesystem from a snapshot

`createFileSystem({ entries })` creates a filesystem from a list in the shape
`snapshot()` returns, so a snapshot can be passed back as it is. A host that
starts a new launcher for each run can carry the filesystem across that way:

```js
const entries = await filesystem.snapshot();
await filesystem.dispose();
const next = await launcher.createFileSystem({ entries });
```

Each entry has a `path`, a `mode` whose type bits make it a regular file, a
directory or a symlink, and optionally `content` (the bytes of a file or the
target of a symlink), `mtimeNs` (default 0) and `inode`. Entries with the same
`inode` value become hard links to one file or symlink; the value itself is not
kept, and `links` is recalculated, so you may leave entries out of a snapshot
before passing it back. A new filesystem always has `/` and `/tmp`: entries for
them, or for a directory `files` created, set that directory's mode and time.

Rebuilding a snapshot keeps its paths, kinds, modes, file bytes, symlink
targets, modification times, link counts and which paths share an inode.
Names that are not UTF-8 are already replaced in a snapshot, and access and
change times are not kept.

The list is checked before anything is created, and a `PaludariumError` of kind
`"invalid-program"` names the first problem and its path:

- each `path` is absolute and normalized (no `.`, `..`, empty or trailing part),
  shorter than 4096 bytes with parts of at most 255 bytes, and appears once,
  also among `files`;
- the parent of each path is a directory entry, `/`, `/tmp` or a directory
  created for `files`; a symlink is never a parent;
- `mode` holds only type bits and permission bits 0o7777; a symlink's
  permissions are 0o777, and its target is 1 to 4095 bytes without NUL; a
  directory has no content;
- entries that share an `inode` are files or symlinks of one kind with the same
  mode, time and content;
- at most 1,048,576 entries, each at most 128 MiB, and 256 MiB of content in all,
  where a hard-link group counts once.

## Errors

A guest exit or signal resolves `exited`. An error of the emulator rejects it
with a `PaludariumError` whose `kind` is `"unimplemented"`, `"internal"`,
`"invalid-program"` or `"host"`, and which keeps the instruction address
(`rip`), the instruction `bytes` and the `syscall` number when they are known.
If a Worker traps, the whole shared runtime is discarded, because the
abandoned Worker may have held a lock.

## Requirements in the browser

- `SharedArrayBuffer` and module Workers.
- Serve the page, `paludarium.wasm` and the package's `.mjs` files from the
  same origin, with `Cross-Origin-Opener-Policy: same-origin` and
  `Cross-Origin-Embedder-Policy: require-corp`. On hosts that cannot send
  headers, a service worker such as
  [coi-serviceworker](https://github.com/gzuidhof/coi-serviceworker) can add
  them, as this site does.
- Serve the package files as they are: the launcher starts its Workers from
  paths relative to `index.mjs`, so bundlers must not inline or rename them.

## The JIT

With `jit: true`, paludarium translates blocks of x86-64 register instructions
into WebAssembly modules inside the guest's Worker and caches them; everything
else still runs in the interpreter, with the same results. In the measured
Node.js run, the whole probe program was about 21 % faster with the JIT. See
[Testing and verification](../design/quality#jit-and-the-interpreter).
