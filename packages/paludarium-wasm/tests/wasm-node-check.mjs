import { readFile, mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { createPaludarium } from "../index.mjs";
import { validateOracle } from "./wasm-contract.mjs";
import { compare, observeProgram, probeCases } from "./wasm-programs.mjs";
import { compareFilesystem } from "./wasm-filesystem.mjs";
const [modulePath, oraclePath, guestDirectory = "target/guests/programs", outputDirectory = "target/wasm/node", slice] = process.argv.slice(2);
if (!modulePath || !oraclePath) throw new Error("usage: wasm-node-check.mjs module oracle [guests] [output] [--probe-only]");
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const oracle = validateOracle(JSON.parse((await readFile(oraclePath, "utf8")).replace(/("mtime_ns"\s*:\s*)(\d+)/g, '$1"$2"')));
const probe = new Uint8Array(await readFile(resolve(guestDirectory, "probe")));
if (hash(probe) !== oracle.binary_hashes.probe) throw new Error("Probe differs from fresh native binary");
const config = oracle.case_config ?? JSON.parse(await readFile("tests/guests/programs/cases.json", "utf8"));
const report = { schema: 1, environment: "node", version: process.version, module_sha256: hash(await readFile(modulePath)),
  oracle_sha256: hash(await readFile(oraclePath)), guest_hashes: oracle.binary_hashes, slice: slice ?? "full", rows: {}, complete: false };
await mkdir(outputDirectory, { recursive: true });
const persist = () => writeFile(resolve(outputDirectory, "observations.json"), JSON.stringify(report, null, 2) + "\n");
await persist(); let failed = false;
for (const item of probeCases()) {
  const launcher = await createPaludarium({ wasmUrl: pathToFileURL(resolve(modulePath)) });
  try {
    const row = await observeProgram(launcher, { program: "/probe", args: ["/probe", ...item.args], env: config.environment, files: { "/probe": probe, "/home/guest/.keep": new Uint8Array() } });
    try { compare(oracle.rows[item.name], row, oracle.fixture_root); row.pass = true; }
    catch (cause) { row.pass = false; row.comparison_error = String(cause); failed = true; }
    report.rows[item.name] = row; await persist(); console.log(JSON.stringify({ name: item.name, exit: row.exit, pass: row.pass, timed_out: row.timed_out, errors: row.errors }));
  } finally { await launcher.dispose(); }
}
if (slice !== "--probe-only") {
  const aube = new Uint8Array(await readFile(resolve(guestDirectory, "aube")));
  if (hash(aube) !== oracle.binary_hashes.aube) throw new Error("Aube differs from fresh native binary");
  const files = { "/aube": aube }, fileModes = {};
  const environment = oracle.guest_environment ?? config.environment;
  const fixtureRoot = oracle.fixture_root + "/fixture", cwd = fixtureRoot + "/app";
  files[environment.HOME + "/.keep"] = new Uint8Array();
  files[environment.TMPDIR + "/.keep"] = new Uint8Array();
  for (const relative of ["app/package.json", "app/filedep/package.json", "outside/linked/package.json"]) {
    const path = fixtureRoot + "/" + relative;
    files[path] = new Uint8Array(await readFile("tests/guests/programs/fixtures/" + relative)); fileModes[path] = 0o644;
  }
  const launcher = await createPaludarium({ wasmUrl: pathToFileURL(resolve(modulePath)) });
  try {
    const filesystem = await launcher.createFileSystem({ files, fileModes });
    for (const item of config.aube) {
      if (item.before) await filesystem.remove(cwd + "/node_modules", { recursive: true });
      const row = await observeProgram(launcher, { program: "/aube", cwd, args: ["/aube", ...item.args], env: environment, filesystem });
      row.filesystem = (await filesystem.snapshot()).filter(entry => entry.path !== "/aube").map(entry => ({ ...entry, inode: String(entry.inode), links: String(entry.links), mtimeNs: String(entry.mtimeNs), content: Buffer.from(entry.content).toString("base64") }));
      try { compare(oracle.rows[item.name], row, oracle.fixture_root, oracle.fixture_root); row.filesystem_comparison = await compareFilesystem(oracle.rows[item.name].filesystem_metadata, row.filesystem, fixtureRoot); row.pass = true; }
      catch (cause) { row.pass = false; row.comparison_error = String(cause); failed = true; }
      report.rows[item.name] = row; await persist(); console.log(JSON.stringify({ name: item.name, exit: row.exit, pass: row.pass, timed_out: row.timed_out, errors: row.errors }));
    }
  } finally { await launcher.dispose(); }
}
report.complete = !failed && slice !== "--probe-only"; report.slice_passed = !failed; await persist();
process.exitCode = failed ? 1 : 0;
