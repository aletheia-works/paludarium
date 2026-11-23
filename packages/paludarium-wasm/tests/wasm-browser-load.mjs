// The page side of the browser checks' inputs: each guest binary is its own raw response at /guest/<name>, read
// through its body stream, and /input.json holds only the oracle, the configs and the small fixtures. One body of
// 100 MB and more with every guest in base64 was what Safari dropped (#936: "Load failed", 114,365,125 bytes unsent).
// Safari's TypeError says only "Load failed", so a failed load names the file, how many of its bytes came and how
// many were due (Content-Length), and when. Nothing is retried.
export async function loadBytes(path, fetchImpl = globalThis.fetch) {
  const started = performance.now();
  let received = 0, expected = null;
  const fail = (what, cause) => new Error(`${path}: ${what} after ${received} of ${expected ?? "unknown"} bytes, `
    + `${Math.round(performance.now() - started)} ms after the request (at ${Math.round(performance.now())} ms)${cause === undefined ? "" : ": " + cause}`, { cause });
  let response;
  try { response = await fetchImpl(path); } catch (error) { throw fail("request failed", error); }
  const length = Number(response.headers.get("content-length"));
  if (response.headers.has("content-length") && Number.isSafeInteger(length)) expected = length;
  if (!response.ok) throw fail(`status ${response.status}`, await response.text().catch(error => String(error)));
  const chunks = [], reader = response.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value); received += value.byteLength;
    }
  } catch (error) { throw fail("body failed", error); }
  if (expected !== null && received !== expected) throw fail("body ended early");
  const bytes = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}

export async function loadJson(path, fetchImpl) {
  const bytes = await loadBytes(path, fetchImpl);
  try { return JSON.parse(new TextDecoder().decode(bytes)); } catch (error) { throw new Error(`${path}: not JSON (${bytes.byteLength} bytes): ${error}`, { cause: error }); }
}

// The guests one at a time, so that a failure names one file and no two large bodies share the connection's time.
export async function loadGuests(names, fetchImpl) {
  const guests = {};
  for (const name of names) guests[name] = await loadBytes(`/guest/${name}`, fetchImpl);
  return guests;
}

export const decodeBase64 = text => Uint8Array.from(atob(text), char => char.charCodeAt(0));
