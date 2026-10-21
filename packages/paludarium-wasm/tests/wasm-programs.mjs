// Same real-program observation boundary for Node and browser acceptance.
import { U11_DEADLINE_MS, U11_PROBES } from "./wasm-contract.mjs";
export function normalize(text, root) {
  return text.replace(/\x1b\[[0-9;]*m/g, "").split(root).join("<FIXTURE>").replace(/(?<= in )\d+(?:\.\d+)?(?:ms|s)\b/g, "<ELAPSED>");
}
export function compare(expected, actual, nativeRoot, guestRoot = "/") {
  if (actual.timed_out || expected.timed_out) throw new Error("Guest operation timed out");
  if (actual.errors.length || actual.exit !== expected.exit) throw new Error("Guest exit/error mismatch");
  for (const key of ["stdout", "stderr"]) {
    // Only normalize the explicit oracle fixture root and elapsed/ANSI text.
    if (normalize(expected[key], nativeRoot) !== normalize(actual[key], guestRoot === "/" ? "\0" : guestRoot)) throw new Error(`${key} mismatch`);
  }
}
export async function observeProgram(launcher, options) {
  const started = performance.now(), row = { stdout: "", stderr: "", exit: null, errors: [], timed_out: false };
  const guest = launcher.run(options);
  let timer;
  const capture = async (stream, key) => {
    const reader = stream.getReader(), decoder = new TextDecoder();
    try { for (;;) { const chunk = await reader.read(); if (chunk.done) break; row[key] += decoder.decode(chunk.value, { stream: true }); } row[key] += decoder.decode(); }
    catch (cause) { row.errors.push({ stream: key, kind: cause.kind, message: String(cause) }); }
    finally { reader.releaseLock(); }
  };
  try {
    const writer = guest.stdin.getWriter(); await writer.close(); writer.releaseLock();
    const completed = Promise.all([capture(guest.stdout, "stdout"), capture(guest.stderr, "stderr"), guest.exited.then(status => { row.exit = status.kind === "exited" ? status.code : 128 + status.signal; }).catch(cause => row.errors.push({ kind: cause.kind, message: String(cause) }))]);
    await Promise.race([completed, new Promise(resolve => { timer = setTimeout(() => { row.timed_out = true; guest.kill(); resolve(); }, U11_DEADLINE_MS); })]);
    if (row.timed_out) await launcher.dispose();
  } catch (cause) { row.errors.push({ kind: cause.kind, message: String(cause) }); }
  finally { clearTimeout(timer); }
  row.seconds = (performance.now() - started) / 1000;
  return row;
}
export function probeCases() {
  return [...U11_PROBES, "all", "environment"].map(name => ({ name: `probe-${name}`, args: name === "all" ? [] : [name] }));
}
