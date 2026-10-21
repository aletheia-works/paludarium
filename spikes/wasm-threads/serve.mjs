// A minimal static server for the browser check. Every response carries the
// COOP/COEP headers that make the page cross-origin isolated, which
// browsers require before they expose SharedArrayBuffer.
//
//   node spikes/wasm-threads/serve.mjs [port]     (default 8787)

import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
const types = {
  ".html": "text/html; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".wasm": "application/wasm",
};

export function startServer(port = 8787) {
  const server = createServer(async (req, res) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    const relative = normalize(decodeURIComponent(path === "/" ? "/web/index.html" : path));
    const file = root + relative.replace(/^[/\\]+/, "");
    const headers = {
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
      "Cache-Control": "no-store",
    };
    // Serve only files below the spike directory.
    if (!file.startsWith(root) || relative.split(sep).includes("..")) {
      res.writeHead(403, headers).end();
      return;
    }
    try {
      const body = await readFile(file);
      res.writeHead(200, { ...headers, "Content-Type": types[extname(file)] ?? "application/octet-stream" });
      res.end(body);
    } catch {
      res.writeHead(404, headers).end();
    }
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve(server)));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const port = Number(process.argv[2] ?? 8787);
  await startServer(port);
  console.log(`serving http://127.0.0.1:${port}/ with COOP/COEP`);
}
