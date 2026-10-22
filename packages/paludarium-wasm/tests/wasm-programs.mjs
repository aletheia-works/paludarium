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
export async function observeProgram(launcher, options) {
  const started = performance.now(), row = { stdout: "", stderr: "", exit: null, errors: [], timed_out: false };
  const guest = launcher.run(options);
  let timer;
  const capture = async (stream, key) => {
    const reader = stream.getReader(), decoder = new TextDecoder();
    try { for (;;) { const chunk = await reader.read(); if (chunk.done) break; row[key] += decoder.decode(chunk.value, { stream: true }); } row[key] += decoder.decode(); }
    catch (cause) { row.errors.push({ stream: key, kind: cause.kind, message: String(cause) }); }
    finally { reader.releaseLock(); }
  };
  try {
    const writer = guest.stdin.getWriter(); await writer.close(); writer.releaseLock();
    const completed = Promise.all([capture(guest.stdout, "stdout"), capture(guest.stderr, "stderr"), guest.exited.then(status => { row.exit = status.kind === "exited" ? status.code : 128 + status.signal; }).catch(cause => row.errors.push({ kind: cause.kind, message: String(cause) }))]);
    await Promise.race([completed, new Promise(resolve => { timer = setTimeout(() => { row.timed_out = true; guest.kill(); resolve(); }, WASM_DEADLINE_MS); })]);
    if (row.timed_out) await launcher.dispose();
  } catch (cause) { row.errors.push({ kind: cause.kind, message: String(cause) }); }
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
