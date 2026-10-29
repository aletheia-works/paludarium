// The guest's network in an actual browser: a page runs the guests of
// wasm-network-guests.mjs with `network.relay` naming relay.mjs, which reaches
// a TCP server and resolves names here. Prints the page's report, and fails
// unless every case passed.
//   node packages/paludarium-wasm/tests/wasm-browser-network.mjs chromium packages/paludarium-wasm/paludarium.wasm
import { createServer as createHttpServer } from "node:http";
import { createServer } from "node:net";
import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { runBrowser } from "./wasm-browser-driver.mjs";
import { startRelay } from "../relay.mjs";
import { WINDOW } from "../relay-protocol.mjs";

const [browser, modulePath] = process.argv.slice(2);
if (!modulePath) throw new Error("usage: wasm-browser-network.mjs browser module");
const root = resolve(".");
// Echoes what follows the first byte; a first byte of "l" asks for a long reply instead.
const reply = Uint8Array.from({ length: 4 * WINDOW + 12345 }, (_, index) => (index * 7) & 255);
const tcp = createServer(socket => {
  let first = true;
  socket.on("data", chunk => {
    if (first && chunk[0] === 0x6c) { socket.end(reply); socket.resume(); }
    else if (!socket.writableEnded) socket.write(first ? chunk.subarray(1) : chunk);
    first = false;
  });
  socket.on("end", () => socket.end());
});
await new Promise(done => tcp.listen(0, "127.0.0.1", done));
const port = tcp.address().port;
const relay = await startRelay({ host: "127.0.0.1", port: 0, allow: [`127.0.0.1:${port}`, "localhost"] });
const page = `<!doctype html><script type="module">
import { createPaludarium } from '/packages/paludarium-wasm/index.mjs';
import { DNS, TCP, data, elf, hex, query } from '/packages/paludarium-wasm/tests/wasm-network-guests.mjs';
const port = ${port}, length = ${reply.length}, relay = { url: ${JSON.stringify(relay.url)}, protocols: ['lambda-microvms', 'lambda-microvms.port.8080'] };
const cases = {}, details = {};
try {
  if (!crossOriginIsolated) throw new Error('Shared memory unavailable');
  const runtime = await createPaludarium({ wasmUrl: '/production.wasm' });
  const run = async (program, network) => {
    const guest = runtime.run({ program: '/guest', files: { '/guest': program }, network });
    const chunks = []; let size = 0;
    // Safari's ReadableStream is not async iterable.
    const reader = guest.stdout.getReader();
    for (let read = await reader.read(); !read.done; read = await reader.read()) { chunks.push(read.value); size += read.value.length; }
    const stdout = new Uint8Array(size); let at = 0;
    for (const chunk of chunks) { stdout.set(chunk, at); at += chunk.length; }
    return { status: await guest.exited, stdout };
  };
  const tcp = text => { const bytes = data(port); bytes.set(new TextEncoder().encode(text), 16); return elf(hex(TCP), bytes); };
  const allow = [\`127.0.0.1:\${port}\`, 'localhost:80'];
  const echo = await run(tcp('ehello'), { allow, relay });
  cases.echo = echo.status.code === 0 && new TextDecoder().decode(echo.stdout) === 'hello';
  const long = await run(tcp('l'), { allow, relay });
  const wrong = long.stdout.findIndex((byte, index) => byte !== ((index * 7) & 255));
  cases.long = long.status.code === 0 && long.stdout.length === length && wrong < 0;
  details.long = { status: long.status, length: long.stdout.length, wrong };
  cases.refused = (await run(tcp('ehello'), { allow: [\`127.0.0.1:\${port + 1}\`], relay })).status.code === 101;
  const ask = async name => {
    const bytes = data(53), question = query(name);
    new DataView(bytes.buffer).setUint32(0x38, question.length, true);
    bytes.set(question, 0x40);
    return (await run(elf(hex(DNS), bytes), { allow, relay })).stdout;
  };
  const answer = await ask('localhost');
  cases.resolve = answer[3] === 0x80 && answer[7] >= 1 && answer.subarray(answer.length - 4).join('.') === '127.0.0.1';
  cases.nxdomain = ((await ask('blocked.example'))[3] & 15) === 3;
  let unimplemented;
  try { runtime.run({ program: '/guest', files: { '/guest': tcp('ehello') }, network: { allow } }); } catch (error) { unimplemented = error.kind; }
  cases.unimplemented = unimplemented === 'unimplemented';
  await runtime.dispose();
  window.__wasmReport = { cases, details, passed: Object.values(cases).every(Boolean) };
} catch (error) { window.__wasmReport = { cases, details, passed: false, error: String(error) }; }
</script>`;
const server = createHttpServer(async (request, response) => {
  const headers = { "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp", "Cache-Control": "no-store" };
  try {
    if (request.url === "/") { response.writeHead(200, { ...headers, "Content-Type": "text/html" }).end(page); return; }
    const path = request.url === "/production.wasm" ? resolve(modulePath) : resolve(root, "." + new URL(request.url, "http://localhost").pathname);
    if (request.url !== "/production.wasm" && !path.startsWith(root + sep)) throw new Error("invalid path");
    const content = await readFile(path);
    response.writeHead(200, { ...headers, "Content-Type": path.endsWith(".wasm") ? "application/wasm" : "text/javascript" }).end(content);
  } catch (cause) {
    if (!response.headersSent) response.writeHead(cause.code === "ENOENT" ? 404 : 500, headers).end(String(cause));
    else response.destroy(cause);
  }
});
await new Promise(done => server.listen(0, "127.0.0.1", done));
try {
  const report = await runBrowser(browser, `http://127.0.0.1:${server.address().port}/`, 120000);
  console.log(JSON.stringify(report));
  if (!report.passed) process.exitCode = 1;
} finally {
  await new Promise(done => server.close(done));
  await relay.close();
  tcp.close();
}
