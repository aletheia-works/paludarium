// Runner readiness only; the real probe/aube acceptance suite is separate.
import { createServer } from "node:http";
import { runBrowser } from "./wasm-browser-driver.mjs";
const page = `<!doctype html><meta charset="utf-8"><script type="module">
try {
  if (!crossOriginIsolated || typeof SharedArrayBuffer !== 'function') throw new Error('COOP/COEP shared memory unavailable');
  const shared = new SharedArrayBuffer(4), word = new Int32Array(shared);
  const worker = new Worker(new URL('/worker.mjs', location.href), {type:'module'});
  try {
    await new Promise((resolve,reject) => {
      const timer = setTimeout(() => reject(new Error('readiness Worker timeout')), 5000);
      worker.onmessage = () => { clearTimeout(timer); resolve(); };
      worker.onerror = event => { clearTimeout(timer); reject(new Error(event.message)); };
      worker.postMessage(shared);
    });
    if (Atomics.load(word,0) !== 73) throw new Error('actual Worker did not share memory');
    window.__u11Report = {readiness:true, passed:true, crossOriginIsolated, sharedWorker:true};
  } finally { worker.terminate(); }
} catch(error) { window.__u11Report = {readiness:true, passed:false, error:String(error)}; }
</script>`;
const server = createServer((request, response) => {
  const headers = { "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp", "Cache-Control": "no-store" };
  if (request.url === "/") response.writeHead(200, { ...headers, "Content-Type": "text/html" }).end(page);
  else if (request.url === "/worker.mjs") response.writeHead(200, { ...headers, "Content-Type": "text/javascript" }).end("onmessage = event => { Atomics.store(new Int32Array(event.data),0,73); postMessage('ready'); };");
  else response.writeHead(404, headers).end();
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
try {
  const names = process.argv.slice(2);
  if (!names.length) throw new Error("usage: wasm-browser-ready.mjs chromium|firefox|safari ...");
  for (const name of names) {
    const report = await runBrowser(name, `http://127.0.0.1:${server.address().port}/`, 15000);
    console.log(JSON.stringify(report));
    if (!report.passed || !report.readiness) throw new Error(`${name} readiness failed`);
  }
} finally { await new Promise(resolve => server.close(resolve)); }
