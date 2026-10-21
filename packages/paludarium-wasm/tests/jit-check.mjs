import { createServer } from "node:http";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { runBrowser } from "./wasm-browser-driver.mjs";
import { runJitSuite } from "./jit-suite.mjs";
import { createJitHandler } from "./jit-http.mjs";

const [environment, modulePath, oraclePath, guestDirectory, outputDirectory] = process.argv.slice(2);
if (!outputDirectory || !["node", "chromium", "firefox", "safari"].includes(environment)) throw new Error("usage: jit-check.mjs node|chromium|firefox|safari module oracle guests output");
const root = resolve("."), hash = bytes => createHash("sha256").update(bytes).digest("hex");
const rawOracle = await readFile(oraclePath, "utf8"), oracle = JSON.parse(rawOracle.replace(/("mtime_ns"\s*:\s*)(\d+)/g, '$1"$2"'));
const probe = await readFile(resolve(guestDirectory, "probe")), aube = await readFile(resolve(guestDirectory, "aube"));
if (hash(probe) !== oracle.binary_hashes.probe || hash(aube) !== oracle.binary_hashes.aube) throw new Error("Guest differs from fresh native binary");
const fixtures = {};
for (const name of ["app/package.json", "app/filedep/package.json", "outside/linked/package.json"]) fixtures[name] = new Uint8Array(await readFile("tests/guests/programs/fixtures/" + name));
const input = { oracle, config: oracle.case_config, probe: new Uint8Array(probe), aube: new Uint8Array(aube), fixtures };
if (!input.config) throw new Error("Exact fresh native case config missing");
const report = { schema: 1, environment, module_sha256: hash(await readFile(modulePath)), oracle_sha256: hash(rawOracle),
                 guest_hashes: oracle.binary_hashes, rows: { interpreter: {}, jit: {} }, complete: false };
await mkdir(outputDirectory, { recursive: true });
const persist = () => writeFile(resolve(outputDirectory, "observations.json"), JSON.stringify(report, null, 2) + "\n");
await persist();
const onRow = async (mode, name, row) => {
  report.rows[mode][name] = row; await persist();
  console.log(JSON.stringify({ environment, mode, name, pass: row.pass, seconds: row.seconds, jit: row.jit, error: row.comparison_error ?? row.jit_error }));
};
let server;
try {
  let result;
  if (environment === "node") {
    report.version = process.version;
    result = await runJitSuite({ ...input, wasmUrl: pathToFileURL(resolve(modulePath)), onRow });
  } else {
    const encoded = { ...input, probe: probe.toString("base64"), aube: aube.toString("base64"),
      fixtures: Object.fromEntries(Object.entries(fixtures).map(([name, bytes]) => [name, Buffer.from(bytes).toString("base64")])) };
    const page = `<!doctype html><script type="module">
import{runJitSuite}from'/packages/paludarium-wasm/tests/jit-suite.mjs';
try{if(!crossOriginIsolated)throw Error('Shared memory unavailable');const input=await(await fetch('/input.json')).json();const decode=text=>Uint8Array.from(atob(text),c=>c.charCodeAt(0));input.probe=decode(input.probe);input.aube=decode(input.aube);for(const name of Object.keys(input.fixtures))input.fixtures[name]=decode(input.fixtures[name]);window.__wasmReport=await runJitSuite({...input,wasmUrl:'/production.wasm',onRow:async(mode,name,row)=>{await fetch('/row',{method:'POST',body:JSON.stringify({mode,name,row})});}});}catch(error){window.__wasmReport={complete:false,passed:false,error:String(error)};}</script>`;
    server = createServer(createJitHandler({ root, modulePath, page, encoded, oracle, onRow }));
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    result = await runBrowser(environment, `http://127.0.0.1:${server.address().port}/`, 1200000);
  }
  Object.assign(report, result); await persist();
  if (!report.complete || !report.passed || report.caseCount !== 28) throw Error("JIT/interpreter acceptance failed");
} catch (error) { report.error = String(error); await persist(); process.exitCode = 1; }
finally { if (server) await new Promise(resolve => server.close(resolve)); }
