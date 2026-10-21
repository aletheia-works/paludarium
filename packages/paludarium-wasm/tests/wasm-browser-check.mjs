import { createServer } from "node:http";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { createHash } from "node:crypto";
import { runBrowser } from "./wasm-browser-driver.mjs";
const [browser, modulePath, oraclePath, guestDirectory, outputDirectory] = process.argv.slice(2);
if (!outputDirectory) throw new Error("usage: wasm-browser-check.mjs browser module oracle guests output");
const root = resolve("."), hash = bytes => createHash("sha256").update(bytes).digest("hex"), encode = bytes => Buffer.from(bytes).toString("base64");
const rawOracle = await readFile(oraclePath, "utf8"), oracle = JSON.parse(rawOracle.replace(/("mtime_ns"\s*:\s*)(\d+)/g, '$1"$2"'));
const probe = await readFile(resolve(guestDirectory, "probe")), aube = await readFile(resolve(guestDirectory, "aube"));
if (hash(probe) !== oracle.binary_hashes.probe || hash(aube) !== oracle.binary_hashes.aube) throw new Error("Guest hash mismatch");
const fixtures = {};
for (const path of ["app/package.json", "app/filedep/package.json", "outside/linked/package.json"]) fixtures[path] = encode(await readFile("tests/guests/programs/fixtures/" + path));
const input = { oracle, config: oracle.case_config ?? JSON.parse(await readFile("tests/guests/programs/cases.json", "utf8")), probe: encode(probe), aube: encode(aube), fixtures };
const report = { schema: 1, environment: browser, module_sha256: hash(await readFile(modulePath)), oracle_sha256: hash(rawOracle), guest_hashes: oracle.binary_hashes, rows: {}, complete: false };
await mkdir(outputDirectory, { recursive: true });
const persist = () => writeFile(resolve(outputDirectory, "observations.json"), JSON.stringify(report, null, 2) + "\n"); await persist();
const page = `<!doctype html><script type="module">
import {runSuite} from '/packages/paludarium-wasm/tests/wasm-suite.mjs';
try {
 if (!crossOriginIsolated) throw new Error('Shared memory unavailable');
 const input = await (await fetch('/input.json')).json(), decode = text => Uint8Array.from(atob(text), char => char.charCodeAt(0));
 input.probe=decode(input.probe); input.aube=decode(input.aube); for(const key of Object.keys(input.fixtures)) input.fixtures[key]=decode(input.fixtures[key]);
 window.__u11Report = await runSuite({...input,wasmUrl:'/production.wasm',onRow: async(name,row)=>{await fetch('/row',{method:'POST',body:JSON.stringify({name,row})});}});
} catch(error) {window.__u11Report={passed:false,complete:false,error:String(error)};}
</script>`;
const server = createServer(async (request, response) => {
  const headers = { "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp", "Cache-Control": "no-store" };
  try {
    if (request.url === "/") response.writeHead(200, { ...headers, "Content-Type": "text/html" }).end(page);
    else if (request.url === "/input.json") response.writeHead(200, { ...headers, "Content-Type": "application/json" }).end(JSON.stringify(input));
    else if (request.url === "/row" && request.method === "POST") {
      const chunks = []; let size = 0; for await (const chunk of request) { size += chunk.length; if (size > 16 * 1024 * 1024) throw new Error("row evidence too large"); chunks.push(chunk); }
      const { name, row } = JSON.parse(Buffer.concat(chunks)); report.rows[name] = row; await persist(); response.writeHead(200, headers).end();
    } else {
      const path = request.url === "/production.wasm" ? resolve(modulePath) : resolve(root, "." + new URL(request.url, "http://localhost").pathname);
      if (request.url !== "/production.wasm" && !path.startsWith(root + sep)) throw new Error("invalid path");
      const content = await readFile(path);
      response.writeHead(200, { ...headers, "Content-Type": path.endsWith(".wasm") ? "application/wasm" : "text/javascript" }).end(content);
    }
  } catch (cause) {
    console.error(JSON.stringify({ request: request.url, error: String(cause) }));
    if (!response.headersSent) response.writeHead(cause.code === "ENOENT" ? 404 : 500, headers).end(String(cause));
    else response.destroy(cause);
  }
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
try { const result = await runBrowser(browser, `http://127.0.0.1:${server.address().port}/`, 600000); Object.assign(report, result); await persist(); if (!report.complete || !report.passed) throw new Error("Actual browser acceptance failed"); console.log(JSON.stringify({ environment: browser, version: report.version, complete: report.complete })); }
finally { await new Promise(resolve => server.close(resolve)); }
