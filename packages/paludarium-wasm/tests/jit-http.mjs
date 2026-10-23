import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

export function createJitHandler({ root, modulePath, page, encoded, oracle, onRow, read = readFile }) {
  const headers = { "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp", "Cache-Control": "no-store" };
  return async (request, response) => {
    const send = (status, body, type) => {
      if (response.destroyed || response.writableEnded) return;
      response.writeHead(status, type ? { ...headers, "Content-Type": type } : headers);
      response.end(body);
    };
    try {
      if (request.url === "/") send(200, page, "text/html");
      else if (request.url === "/input.json") send(200, JSON.stringify(encoded), "application/json");
      else if (request.url === "/row" && request.method === "POST") {
        const chunks = []; let size = 0;
        for await (const chunk of request) {
          size += chunk.length;
          if (size > 16 * 1024 * 1024) throw Error("Evidence row too large");
          chunks.push(chunk);
        }
        const { mode, name, row, group = "rows" } = JSON.parse(Buffer.concat(chunks));
        // A restored row reruns an aube step, so it names a row of the oracle.
        const known = group === "ripgrep" ? oracle.ripgrep?.rows ?? {} : group === "rows" || group === "restored" ? oracle.rows : {};
        if (!["interpreter", "jit"].includes(mode) || !Object.hasOwn(known, name)) throw Error("Unknown evidence row");
        await onRow(mode, name, row, group);
        send(200);
      } else {
        const path = request.url === "/production.wasm" ? resolve(modulePath) : resolve(root, "." + new URL(request.url, "http://localhost").pathname);
        if (request.url !== "/production.wasm" && !path.startsWith(root + sep)) throw Error("Invalid path");
        // Finish fallible I/O before committing any response headers.
        const bytes = await read(path);
        send(200, bytes, path.endsWith(".wasm") ? "application/wasm" : "text/javascript");
      }
    } catch (error) {
      if (response.destroyed || response.writableEnded) return;
      if (response.headersSent) response.destroy(error);
      else send(500, String(error));
    }
  };
}
