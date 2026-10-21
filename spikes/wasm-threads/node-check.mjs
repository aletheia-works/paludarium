// Node.js runner of the wasm thread check. Prints one
// WasmThreadReport as JSON and exits 0 on pass, 1 on failure.
//
//   node spikes/wasm-threads/node-check.mjs

import { readFile } from "node:fs/promises";
import { Worker } from "node:worker_threads";

import { runCheck } from "./js/check.mjs";

const here = new URL(".", import.meta.url);
const wasmBytes = await readFile(new URL("pkg/threads.wasm", here));

function makeWorker() {
  const worker = new Worker(new URL("js/worker.mjs", here));
  return {
    post: (m) => worker.postMessage(m),
    listen: (f) => worker.on("message", f),
    terminate: () => worker.terminate(),
  };
}

const outcome = await runCheck({ wasmBytes, makeWorker });
const report = {
  environment: "nodejs",
  version: process.version,
  // Node.js has no cross-origin isolation concept; SharedArrayBuffer is
  // always available.
  crossOriginIsolated: true,
  ...outcome,
};
console.log(JSON.stringify(report));
process.exit(report.waitNotifyPassed ? 0 : 1);
