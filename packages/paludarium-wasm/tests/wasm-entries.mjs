// Rebuilding a filesystem from its snapshot, for Node and browser acceptance.
import { compare, observeProgram } from "./wasm-programs.mjs";
import { compareFilesystem } from "./wasm-filesystem.mjs";
const encoder = new TextEncoder();
const hex = array => Array.from(new Uint8Array(array), value => value.toString(16).padStart(2, "0")).join("");
/** What a rebuild keeps: paths, kinds and modes, contents, times, link counts
 * and which paths share an inode (named by the first such path). */
export async function comparableTree(entries) {
  const first = new Map(), rows = [];
  for (const entry of entries) {
    if (!first.has(entry.inode)) first.set(entry.inode, entry.path);
    rows.push([entry.path, entry.mode, String(entry.mtimeNs), String(entry.links), hex(await crypto.subtle.digest("SHA-256", entry.content)), first.get(entry.inode)]);
  }
  return JSON.stringify(rows);
}
export async function sameTree(expected, actual) {
  if (await comparableTree(expected) !== await comparableTree(actual)) throw new Error("rebuilt filesystem differs from its snapshot");
}
// Every kind a snapshot holds, in an order where children come before parents.
export const TREE = [
  { path: "/a/x/data", mode: 0o100644, content: encoder.encode("data"), inode: 7n, mtimeNs: -1_500_000_001n },
  { path: "/a/x", mode: 0o042775, mtimeNs: 11n },
  { path: "/a/empty", mode: 0o040700, mtimeNs: (1n << 80n) + 3n },
  { path: "/a/blank", mode: 0o100600, content: new Uint8Array(), mtimeNs: 0n },
  { path: "/a/abs", mode: 0o120777, content: encoder.encode("/a/x/data"), inode: 9n, mtimeNs: 2n },
  { path: "/a/rel", mode: 0o120777, content: encoder.encode("x/data"), mtimeNs: 3 },
  { path: "/a/dangling", mode: 0o120777, content: encoder.encode("../nowhere"), mtimeNs: 4n },
  { path: "/a", mode: 0o040755, mtimeNs: 5n },
  { path: "/b", mode: 0o040750, mtimeNs: 6n },
  { path: "/b/again", mode: 0o100644, content: encoder.encode("data"), inode: 7, mtimeNs: -1_500_000_001n },
  { path: "/a/x/third", mode: 0o100644, content: encoder.encode("data"), inode: 7n, mtimeNs: -1_500_000_001n },
  { path: "/b/abs2", mode: 0o120777, content: encoder.encode("/a/x/data"), inode: 9n, mtimeNs: 2n },
  { path: "/tmp", mode: 0o041770, mtimeNs: 8n },
  { path: "/", mode: 0o040711, mtimeNs: 1n },
];
/** Builds TREE, checks what it became, rebuilds it from its snapshot and
 * checks the two snapshots are the same. */
export async function checkEntries(launcher) {
  const built = await launcher.createFileSystem({ entries: TREE });
  const snapshot = await built.snapshot(); await built.dispose();
  const byPath = new Map(snapshot.map(entry => [entry.path, entry]));
  for (const entry of TREE) {
    const actual = byPath.get(entry.path);
    if (!actual || actual.mode !== entry.mode || actual.mtimeNs !== BigInt(entry.mtimeNs) || hex(actual.content) !== hex(entry.content ?? new Uint8Array())) throw new Error("placed entry differs: " + entry.path);
  }
  if (byPath.size !== TREE.length) throw new Error("unexpected placed paths");
  const group = paths => new Set(paths.map(path => byPath.get(path).inode)).size === 1 && paths.every(path => byPath.get(path).links === BigInt(paths.length));
  if (!group(["/a/x/data", "/b/again", "/a/x/third"]) || !group(["/a/abs", "/b/abs2"]) || byPath.get("/a/x/data").inode === byPath.get("/a/abs").inode) throw new Error("hard link groups differ");
  const rebuilt = await launcher.createFileSystem({ entries: snapshot });
  try { await sameTree(snapshot, await rebuilt.snapshot()); } finally { await rebuilt.dispose(); }
  return { entries: snapshot.length, rebuilt: true };
}
/** The aube steps again, with the filesystem copied out with snapshot() and
 * rebuilt from it before every step after the first, as a host that starts a
 * new core for each run does. Each row is compared with the same native row. */
export async function observeRestoredAube(launch, { files, fileModes, cwd, environment, steps, oracle, fixtureRoot, jit = false, onRow = () => {} }) {
  const rows = {}, launcher = await launch();
  try {
    let filesystem = await launcher.createFileSystem({ files, fileModes });
    for (const item of steps) {
      let row;
      try {
        if (item !== steps[0]) {
          const before = await filesystem.snapshot(); await filesystem.dispose();
          filesystem = await launcher.createFileSystem({ entries: before });
          await sameTree(before, await filesystem.snapshot());
        }
        if (item.before) await filesystem.remove(cwd + "/node_modules", { recursive: true });
        row = await observeProgram(launcher, { program: "/aube", cwd, args: ["/aube", ...item.args], env: environment, filesystem, jit });
        // The JIT proof of the run, as the first aube steps record it.
        if (jit) {
          try { row.jit = (await launcher.diagnostics()).workers.filter(worker => !worker.guestThread).at(-1)?.jit; }
          catch (cause) { row.jit_diagnostics_error = String(cause); }
        }
        const entries = await filesystem.snapshot();
        compare(oracle.rows[item.name], row, oracle.fixture_root, oracle.fixture_root);
        row.filesystem_comparison = await compareFilesystem(oracle.rows[item.name].filesystem_metadata, entries, fixtureRoot); row.pass = true;
      } catch (cause) { row ??= { errors: [] }; row.pass = false; row.comparison_error = String(cause); }
      rows[item.name] = row; await onRow(item.name, row, "restored");
    }
  } finally { await launcher.dispose(); }
  return rows;
}
