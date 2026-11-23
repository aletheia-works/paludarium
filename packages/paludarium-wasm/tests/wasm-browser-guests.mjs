// The server side of the browser checks' inputs (the page side is wasm-browser-load.mjs): each guest binary as its
// own raw response at /guest/<name>, and input.json, both with Content-Length. A response that closes before it
// finished is logged with its file, its size and the bytes queued for it (Node counts bytes queued, not sent).

// The guest a request URL names, or null when it names none; a name that is not served is "" (answered with 404).
export function guestName(url, guests) {
  const match = /^\/guest\/([^/?#]+)$/.exec(url);
  if (!match) return null;
  return Object.hasOwn(guests, match[1]) ? match[1] : "";
}

export function sendBytes(response, headers, file, bytes, type) {
  const socket = response.socket, before = socket?.bytesWritten ?? 0;
  response.once("close", () => {
    if (!response.writableFinished) console.error(JSON.stringify({ response_cut: file, bytes: bytes.length, bytes_queued: (socket?.bytesWritten ?? before) - before }));
  });
  response.writeHead(200, { ...headers, "Content-Type": type, "Content-Length": bytes.length }).end(bytes);
}

// Answers /input.json and /guest/<name>; false for any other URL.
export function serveInputs(request, response, headers, input, guests) {
  if (request.url === "/input.json") { sendBytes(response, headers, "input.json", input, "application/json"); return true; }
  const name = guestName(request.url, guests);
  if (name === null) return false;
  if (name === "") { response.writeHead(404, headers).end(`no guest ${request.url}`); return true; }
  sendBytes(response, headers, request.url.slice(1), guests[name], "application/octet-stream");
  return true;
}
