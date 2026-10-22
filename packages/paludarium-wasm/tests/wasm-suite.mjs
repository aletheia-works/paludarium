import { createPaludarium } from "../index.mjs";
import { validateOracle } from "./wasm-contract.mjs";
import { compare, observeProgram, observeRipgrep, probeCases } from "./wasm-programs.mjs";
import { compareFilesystem } from "./wasm-filesystem.mjs";
import { observeRestoredAube } from "./wasm-entries.mjs";
export async function runSuite({ wasmUrl, oracle, config, probe, aube, ripgrep, ripgrepCases, fixtures, jit = false, onRow = () => {} }) {
  validateOracle(oracle);
  const rows = {}, launch = () => createPaludarium({ wasmUrl });
  for (const item of probeCases()) {
    const launcher = await launch();
    try {
      const row = await observeProgram(launcher, { program: "/probe", args: ["/probe", ...item.args], env: config.environment, files: { "/probe": probe, "/home/guest/.keep": new Uint8Array() }, jit });
      if (jit) {
        try { row.jit = (await launcher.diagnostics()).workers.filter(worker => !worker.guestThread).at(-1)?.jit; }
        catch (cause) { row.jit_diagnostics_error = String(cause); }
      }
      try { compare(oracle.rows[item.name], row, oracle.fixture_root); row.pass = true; }
      catch (cause) { row.pass = false; row.comparison_error = String(cause); }
      rows[item.name] = row; await onRow(item.name, row);
    } finally { await launcher.dispose(); }
  }
  // The ripgrep rows are optional, so the JIT suite can leave them out.
  const ripgrepRows = ripgrep ? await observeRipgrep(launch, { ripgrep, cases: ripgrepCases, oracle, fixtures, jit, onRow }) : undefined;
  const environment = oracle.guest_environment, fixtureRoot = oracle.fixture_root + "/fixture", cwd = fixtureRoot + "/app";
  if (!environment) throw new Error("Fresh native exact environment is required");
  const files = { "/aube": aube, [environment.HOME + "/.keep"]: new Uint8Array(), [environment.TMPDIR + "/.keep"]: new Uint8Array() }, fileModes = {};
  for (const [relative, data] of Object.entries(fixtures)) { const path = fixtureRoot + "/" + relative; files[path] = data; fileModes[path] = 0o644; }
  const launcher = await launch();
  try {
    const filesystem = await launcher.createFileSystem({ files, fileModes });
    for (const item of config.aube) {
      if (item.before) await filesystem.remove(cwd + "/node_modules", { recursive: true });
      const row = await observeProgram(launcher, { program: "/aube", cwd, args: ["/aube", ...item.args], env: environment, filesystem, jit });
      row.pass = false;
      rows[item.name] = row; await onRow(item.name, row);
      if (jit) {
        try { row.jit = (await launcher.diagnostics()).workers.filter(worker => !worker.guestThread).at(-1)?.jit; }
        catch (cause) { row.jit_diagnostics_error = String(cause); }
      }
      let entries;
      try { entries = await filesystem.snapshot(); }
      catch (cause) {
        row.filesystem_error = String(cause); await onRow(item.name, row); throw cause;
      }
      row.filesystem = entries.filter(entry => entry.path !== "/aube").map(entry => ({ ...entry, inode: String(entry.inode), links: String(entry.links), mtimeNs: String(entry.mtimeNs), content: btoa(Array.from(entry.content, byte => String.fromCharCode(byte)).join("")) }));
      try { compare(oracle.rows[item.name], row, oracle.fixture_root, oracle.fixture_root); row.filesystem_comparison = await compareFilesystem(oracle.rows[item.name].filesystem_metadata, entries, fixtureRoot); row.pass = true; }
      catch (cause) { row.pass = false; row.comparison_error = String(cause); }
      rows[item.name] = row; await onRow(item.name, row);
    }
  } finally { await launcher.dispose(); }
  const restored = await observeRestoredAube(launch, { files, fileModes, cwd, environment, steps: config.aube, oracle, fixtureRoot, jit, onRow });
  const ripgrepPassed = Object.values(ripgrepRows ?? {}).every(row => row.pass), restoredPassed = Object.values(restored).every(row => row.pass);
  return { rows, ripgrep: ripgrepRows, restored, complete: Object.keys(rows).length === 14 && Object.values(rows).every(row => row.pass) && ripgrepPassed && restoredPassed && Object.keys(restored).length === config.aube.length && (!ripgrep || Object.keys(ripgrepRows).length === ripgrepCases.length), passed: Object.values(rows).every(row => row.pass) && ripgrepPassed && restoredPassed };
}
