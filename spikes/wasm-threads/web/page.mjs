// Browser side of the wasm thread check. The result is shown on the
// page and stored in window.__wasmThreadReport for the automation scripts.

import { runCheck } from "/js/check.mjs";

async function main() {
  const isolated = globalThis.crossOriginIsolated === true;
  let outcome;
  if (typeof SharedArrayBuffer === "undefined") {
    outcome = { waitNotifyPassed: false, notes: "SharedArrayBuffer is not available" };
  } else {
    const wasmBytes = await (await fetch("/pkg/threads.wasm")).arrayBuffer();
    outcome = await runCheck({
      wasmBytes,
      makeWorker() {
        const worker = new Worker("/js/worker.mjs", { type: "module" });
        return {
          post: (m) => worker.postMessage(m),
          listen: (f) => worker.addEventListener("message", (e) => f(e.data)),
          terminate: () => worker.terminate(),
        };
      },
    });
  }
  const report = { userAgent: navigator.userAgent, crossOriginIsolated: isolated, ...outcome };
  window.__wasmThreadReport = report;
  document.getElementById("status").textContent = report.waitNotifyPassed ? "passed" : "failed";
  document.getElementById("report").textContent = JSON.stringify(report, null, 2);
}

main().catch((error) => {
  window.__wasmThreadReport = { crossOriginIsolated: globalThis.crossOriginIsolated === true, waitNotifyPassed: false, notes: String(error) };
});
