// Same real-program observation boundary for Node and browser acceptance.
import { WASM_DEADLINE_MS, WASM_PROBES } from "./wasm-contract.mjs";
export function normalize(text, root) {
  return text.replace(/\x1b\[[0-9;]*m/g, "").split(root).join("<FIXTURE>").replace(/(?<= in )\d+(?:\.\d+)?(?:ms|s)\b/g, "<ELAPSED>");
}
export function compare(expected, actual, nativeRoot, guestRoot = "/") {
  if (actual.timed_out || expected.timed_out) throw new Error("Guest operation timed out");
  if (actual.errors.length || actual.exit !== expected.exit) throw new Error("Guest exit/error mismatch");
  for (const key of ["stdout", "stderr"]) {
    // Only normalize the explicit oracle fixture root and elapsed/ANSI text.
    if (normalize(expected[key], nativeRoot) !== normalize(actual[key], guestRoot === "/" ? "\0" : guestRoot)) throw new Error(`${key} mismatch`);
  }
}
// Kept beside the row, never compared: the shared memory's size when a Worker trapped, and what
// that launcher's heap reserve did at its start.
function noteHostTrap(row, cause) {
  if (cause?.memoryBytes !== undefined) row.host_trap ??= { memory_bytes: cause.memoryBytes, heap_reserve: cause.heapReserve ?? null };
}
// The probe item a row trapped in: its own, or for probe-all the item after the last one it passed.
export function trappedProbe(name, stdout) {
  if (name !== "probe-all") return name.replace(/^probe-/, "");
  const passed = [...stdout.matchAll(/^PASS (\S+)$/gm)].map(match => match[1]);
  return WASM_PROBES[passed.length] ?? null;
}
export async function observeProgram(launcher, { stdin, ...options }) {
  const started = performance.now(), row = { stdout: "", stderr: "", exit: null, errors: [], timed_out: false };
  const guest = launcher.run(options);
  let timer;
  const capture = async (stream, key) => {
    const reader = stream.getReader(), decoder = new TextDecoder();
    try { for (;;) { const chunk = await reader.read(); if (chunk.done) break; row[key] += decoder.decode(chunk.value, { stream: true }); } row[key] += decoder.decode(); }
    catch (cause) { row.errors.push({ stream: key, kind: cause.kind, message: String(cause) }); noteHostTrap(row, cause); }
    finally { reader.releaseLock(); }
  };
  try {
    // A case's stdin, when it has one; otherwise stdin is empty.
    const writer = guest.stdin.getWriter(); if (stdin) await writer.write(stdin); await writer.close(); writer.releaseLock();
    const completed = Promise.all([capture(guest.stdout, "stdout"), capture(guest.stderr, "stderr"), guest.exited.then(status => { row.exit = status.kind === "exited" ? status.code : 128 + status.signal; }).catch(cause => { row.errors.push({ kind: cause.kind, message: String(cause) }); noteHostTrap(row, cause); })]);
    await Promise.race([completed, new Promise(resolve => { timer = setTimeout(() => { row.timed_out = true; guest.kill(); resolve(); }, WASM_DEADLINE_MS); })]);
    if (row.timed_out) await launcher.dispose();
  } catch (cause) { row.errors.push({ kind: cause.kind, message: String(cause) }); noteHostTrap(row, cause); }
  finally { clearTimeout(timer); }
  row.seconds = (performance.now() - started) / 1000;
  return row;
}
export function probeCases() {
  return [...WASM_PROBES, "all", "environment"].map(name => ({ name: `probe-${name}`, args: name === "all" ? [] : [name] }));
}
// ripgrep reads the fixture before aube changes it and prints only the
// relative paths it is given, so its rows must match the Linux rows exactly.
export async function observeRipgrep(launch, { ripgrep, cases, oracle, fixtures, jit = false, onRow = () => {} }) {
  const native = oracle.ripgrep, environment = oracle.guest_environment, fixtureRoot = oracle.fixture_root + "/fixture";
  if (!native || !environment) throw new Error("Fresh native ripgrep rows and environment are required");
  if (Object.keys(native.rows).join() !== cases.map(item => item.name).join()) throw new Error("Unexpected native ripgrep inventory");
  const files = { "/ripgrep": ripgrep }, fileModes = {};
  for (const [relative, data] of Object.entries(fixtures)) { const path = fixtureRoot + "/" + relative; files[path] = data; fileModes[path] = 0o644; }
  const rows = {}, launcher = await launch();
  try {
    const filesystem = await launcher.createFileSystem({ files, fileModes });
    for (const item of cases) {
      const row = await observeProgram(launcher, { program: "/ripgrep", cwd: fixtureRoot + "/app", args: ["/ripgrep", ...item.args], env: environment, filesystem, jit });
      if (jit) {
        try { row.jit = (await launcher.diagnostics()).workers.filter(worker => !worker.guestThread).at(-1)?.jit; }
        catch (cause) { row.jit_diagnostics_error = String(cause); }
      }
      const expected = native.rows[item.name];
      try {
        if (row.timed_out || expected.timed_out || row.errors.length) throw new Error("Guest operation timed out or failed");
        for (const key of ["exit", "stdout", "stderr"]) if (row[key] !== expected[key]) throw new Error(`${key} mismatch`);
        row.pass = true;
      } catch (cause) { row.pass = false; row.comparison_error = String(cause); }
      rows[item.name] = row; await onRow(item.name, row, "ripgrep");
    }
  } finally { await launcher.dispose(); }
  return rows;
}
const hex = array => Array.from(new Uint8Array(array), value => value.toString(16).padStart(2, "0")).join("");
// Each regular file under `root` by its path from there, with its bytes'
// SHA-256, as the Linux snapshot lists them: a symlink to a file is listed
// with that file's bytes, and directories and dangling symlinks are not.
export async function fileDigests(entries, root) {
  const byPath = new Map(entries.map(entry => [entry.path, entry])), result = {};
  const resolve = (path, depth = 0) => {
    const entry = byPath.get(path), kind = entry ? entry.mode & 0o170000 : 0;
    if (kind !== 0o120000 || depth > 40) return kind === 0o100000 ? entry : undefined;
    const target = new TextDecoder().decode(entry.content);
    const base = target.startsWith("/") ? [] : path.split("/").slice(0, -1);
    const parts = [...base, ...target.split("/")].reduce((done, part) => part === ".." ? done.slice(0, -1) : part === "." || part === "" ? done : [...done, part], []);
    return resolve("/" + parts.join("/"), depth + 1);
  };
  for (const entry of [...entries].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)) {
    if (!entry.path.startsWith(root + "/")) continue;
    const file = resolve(entry.path);
    if (file) result[entry.path.slice(root.length + 1)] = hex(await crypto.subtle.digest("SHA-256", file.content));
  }
  return result;
}
// coreutils' cases, each in a fresh copy of its fixture; a case marked
// writes also compares the copy's files with Linux's afterwards. The
// utilities print only the relative paths they are given, so rows match the
// Linux rows exactly.
export async function observeCoreutils(launch, { coreutils, cases, oracle, fixture, jit = false, onRow = () => {} }) {
  const native = oracle.coreutils, base = oracle.guest_environment;
  if (!native || !base) throw new Error("Fresh native coreutils rows and environment are required");
  if (Object.keys(native.rows).join() !== cases.map(item => item.name).join()) throw new Error("Unexpected native coreutils inventory");
  const rows = {}, launcher = await launch();
  try {
    for (const item of cases) {
      const root = oracle.fixture_root + "/coreutils/" + item.name;
      const files = { "/coreutils": coreutils, [base.HOME + "/.keep"]: new Uint8Array(), [base.TMPDIR + "/.keep"]: new Uint8Array() }, fileModes = {};
      for (const [relative, data] of Object.entries(fixture)) { files[root + "/" + relative] = data; fileModes[root + "/" + relative] = 0o644; }
      const filesystem = await launcher.createFileSystem({ files, fileModes });
      try {
        const stdin = item.stdin === undefined ? undefined : fixture["app/" + item.stdin];
        const row = await observeProgram(launcher, { program: "/coreutils", cwd: root + "/app", args: ["/coreutils", ...item.args], env: { ...base, ...(item.env ?? {}) }, filesystem, jit, stdin });
        if (jit) {
          try { row.jit = (await launcher.diagnostics()).workers.filter(worker => !worker.guestThread).at(-1)?.jit; }
          catch (cause) { row.jit_diagnostics_error = String(cause); }
        }
        const expected = native.rows[item.name];
        try {
          if (row.timed_out || expected.timed_out || row.errors.length) throw new Error("Guest operation timed out or failed");
          for (const key of ["exit", "stdout", "stderr"]) if (row[key] !== expected[key]) throw new Error(`${key} mismatch`);
          if (item.writes) {
            row.filesystem = await fileDigests(await filesystem.snapshot(), root);
            if (JSON.stringify(row.filesystem) !== JSON.stringify(Object.fromEntries(Object.entries(expected.filesystem).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)))) throw new Error("filesystem mismatch");
          }
          row.pass = true;
        } catch (cause) { row.pass = false; row.comparison_error = String(cause); }
        rows[item.name] = row; await onRow(item.name, row, "coreutils");
      } finally { await filesystem.dispose(); }
    }
  } finally { await launcher.dispose(); }
  return rows;
}
