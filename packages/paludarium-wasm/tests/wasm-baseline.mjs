// Read-only observation of the pre-U11 launcher after a fresh native oracle.
// Known missing persistence/mode/clone capabilities remain failures in evidence.
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createPaludarium } from "../index.mjs";
import { U11_DEADLINE_MS, U11_PROBES, validateOracle } from "./wasm-contract.mjs";

const [modulePath, oraclePath, guestDirectory = "target/guests/u10", outputDirectory = "target/wasm/baseline"] = process.argv.slice(2);
if (!modulePath || !oraclePath) throw new Error("usage: wasm-baseline.mjs module oracle [guests] [output]");
const oracle = validateOracle(JSON.parse(await readFile(oraclePath, "utf8")));
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const guests = {};
for (const name of ["probe", "aube"]) {
  guests[name] = new Uint8Array(await readFile(resolve(guestDirectory, name)));
  if (hash(guests[name]) !== oracle.binary_hashes[name]) throw new Error(`Guest ${name} differs from native oracle`);
}
const fixture = {};
for (const [source, path] of [["app/package.json", "/package.json"], ["app/filedep/package.json", "/filedep/package.json"], ["outside/linked/package.json", "/outside/linked/package.json"]]) fixture[path] = new Uint8Array(await readFile(resolve("tests/guests/programs/fixtures", source)));
const config = JSON.parse(await readFile("tests/guests/programs/cases.json", "utf8"));
const report = { schema: 1, baseline: true, module_sha256: hash(await readFile(modulePath)), oracle_sha256: hash(await readFile(oraclePath)), guest_hashes: oracle.binary_hashes, rows: {}, gaps: ["current config_file has no 0644 mode override", "current run has no persistent filesystem borrow", "current wasm spawn and ticket wait return ENOSYS"] };
await mkdir(outputDirectory, { recursive: true });
const persist = () => writeFile(resolve(outputDirectory, "observations.json"), JSON.stringify(report, null, 2) + "\n");
await persist();
const cases = [...[...U11_PROBES, "all", "environment"].map(name => ({ name: `probe-${name}`, guest: "probe", args: name === "all" ? [] : [name] })), ...config.aube.map(row => ({ ...row, guest: "aube" }))];
for (const item of cases) {
  const start = performance.now(), row = { stdout: "", stderr: "", exit: null, timed_out: false, errors: [] };
  let launcher, timer;
  try {
    launcher = await createPaludarium({ wasmUrl: pathToFileURL(resolve(modulePath)) });
    const guest = launcher.run({ program: `/${item.guest}`, args: [`/${item.guest}`, ...item.args], env: config.environment, files: { [`/${item.guest}`]: guests[item.guest], ...fixture, "/tmp/.keep": new Uint8Array(), "/home/u10/.keep": new Uint8Array() } });
    const capture = async (stream, key) => {
      const reader = stream.getReader(), decoder = new TextDecoder();
      try { for (;;) { const chunk = await reader.read(); if (chunk.done) break; row[key] += decoder.decode(chunk.value, { stream: true }); } row[key] += decoder.decode(); }
      catch (error) { row.errors.push({ stream: key, kind: error.kind, message: String(error) }); }
      finally { reader.releaseLock(); }
    };
    const writer = guest.stdin.getWriter(); await writer.close(); writer.releaseLock();
    const finished = Promise.all([capture(guest.stdout, "stdout"), capture(guest.stderr, "stderr"), guest.exited.then(status => { row.exit = status.kind === "exited" ? status.code : 128 + status.signal; }).catch(error => row.errors.push({ kind: error.kind, message: String(error) }))]);
    await Promise.race([finished, new Promise((_, reject) => { timer = setTimeout(() => { row.timed_out = true; guest.kill(); reject(new Error("external 30-second baseline deadline")); }, U11_DEADLINE_MS); })]);
  } catch (error) { row.errors.push({ kind: error.kind, message: String(error) }); }
  finally { clearTimeout(timer); await launcher?.dispose(); }
  row.seconds = (performance.now() - start) / 1000;
  row.native_exit = oracle.rows[item.name].exit;
  row.streams_equal_without_normalization = row.stdout === oracle.rows[item.name].stdout && row.stderr === oracle.rows[item.name].stderr;
  report.rows[item.name] = row; await persist(); console.log(JSON.stringify({ name: item.name, exit: row.exit, timed_out: row.timed_out, errors: row.errors }));
}
console.log(`Observed ${cases.length} baseline cases; this diagnostic does not claim U11 acceptance`);
