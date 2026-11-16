// Runs the x87 cases in Node or an actual browser and compares them with
// the x86-64 Linux results that tests/guests/wasm/x87.py wrote:
//   node wasm-x87-check.mjs <node|chromium|firefox|safari|webkit> <module> <x87 directory> <output>
import { createServer } from "node:http";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
const [environment, modulePath, x87Directory, outputDirectory] = process.argv.slice(2);
if (!outputDirectory) throw new Error("usage: wasm-x87-check.mjs environment module x87-directory output");
const native = JSON.parse(await readFile(resolve(x87Directory, "native.json"), "utf8"));
const x87 = new Uint8Array(await readFile(resolve(x87Directory, "x87")));
if (createHash("sha256").update(x87).digest("hex") !== native.binary_sha256) throw new Error("x87 differs from the native binary");
const { cases } = JSON.parse(await readFile("tests/guests/wasm/x87-cases.json", "utf8"));
const report = { schema: 1, environment, native_cpu: native.cpu, rows: {}, complete: false };
await mkdir(outputDirectory, { recursive: true });
const persist = () => writeFile(resolve(outputDirectory, "x87.json"), JSON.stringify(report, null, 2) + "\n");
const show = (name, row) => console.log(JSON.stringify({ name, exit: row.exit, pass: row.pass, seconds: Number(row.seconds.toFixed(3)), native_seconds: Number(row.native_seconds.toFixed(3)), errors: row.errors, comparison_error: row.comparison_error }));
if (environment === "node") {
  const { createPaludarium } = await import("../index.mjs");
  const { observeX87 } = await import("./wasm-x87.mjs");
  report.rows = await observeX87(() => createPaludarium({ wasmUrl: pathToFileURL(resolve(modulePath)) }), { x87, cases, native, onRow: async (name, row) => { report.rows[name] = row; await persist(); show(name, row); } });
} else {
  const { runBrowser } = await import("./wasm-browser-driver.mjs");
  const root = resolve(".");
  const page = `<!doctype html><script type="module">
import {createPaludarium} from '/packages/paludarium-wasm/index.mjs';
import {observeX87} from '/packages/paludarium-wasm/tests/wasm-x87.mjs';
try {
 if (!crossOriginIsolated) throw new Error('Shared memory unavailable');
 const input = await (await fetch('/input.json')).json();
 const x87 = Uint8Array.from(atob(input.x87), char => char.charCodeAt(0));
 const onRow = async (name, row) => { await fetch('/row', {method: 'POST', body: JSON.stringify({name, row})}); };
 const rows = await observeX87(() => createPaludarium({wasmUrl: '/production.wasm'}), {x87, cases: input.cases, native: input.native, onRow});
 window.__wasmReport = {rows, passed: Object.values(rows).every(row => row.pass), complete: true};
} catch (error) { window.__wasmReport = {passed: false, complete: false, error: String(error)}; }
</script>`;
  const input = JSON.stringify({ x87: Buffer.from(x87).toString("base64"), cases, native });
  const headers = { "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp", "Cache-Control": "no-store" };
  const server = createServer(async (request, response) => {
    try {
      if (request.url === "/") response.writeHead(200, { ...headers, "Content-Type": "text/html" }).end(page);
      else if (request.url === "/input.json") response.writeHead(200, { ...headers, "Content-Type": "application/json" }).end(input);
      else if (request.url === "/row" && request.method === "POST") {
        // Each row as it comes, so that a case that hangs leaves the ones before it.
        const chunks = []; let size = 0;
        for await (const chunk of request) { size += chunk.length; if (size > 16 * 1024 * 1024) throw new Error("row too large"); chunks.push(chunk); }
        const { name, row } = JSON.parse(Buffer.concat(chunks));
        if (cases.includes(name)) { report.rows[name] = row; await persist(); show(name, row); }
        response.writeHead(200, headers).end();
      }
      else {
        const path = request.url === "/production.wasm" ? resolve(modulePath) : resolve(root, "." + new URL(request.url, "http://localhost").pathname);
        if (request.url !== "/production.wasm" && !path.startsWith(root + sep)) throw new Error("invalid path");
        response.writeHead(200, { ...headers, "Content-Type": path.endsWith(".wasm") ? "application/wasm" : "text/javascript" }).end(await readFile(path));
      }
    } catch (cause) {
      console.error(JSON.stringify({ request: request.url, error: String(cause) }));
      if (!response.headersSent) response.writeHead(cause.code === "ENOENT" ? 404 : 500, headers).end(String(cause));
      else response.destroy(cause);
    }
  });
  await new Promise(done => server.listen(0, "127.0.0.1", done));
  try {
    const result = await runBrowser(environment, `http://127.0.0.1:${server.address().port}/`, 600000);
    if (result.error) throw new Error(result.error);
    report.version = result.version;
    report.rows = result.rows ?? report.rows;
  } finally { await new Promise(done => server.close(done)); }
}
// Safari's WebDriver returns the report without its key order.
report.complete = [...Object.keys(report.rows)].sort().join() === [...cases].sort().join() && Object.values(report.rows).every(row => row.pass);
await persist();
if (!report.complete) throw new Error("x87 cases differ from x86-64 Linux");
