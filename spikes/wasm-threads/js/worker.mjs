// Worker for the wasm thread check. Runs unchanged in a Node.js
// worker_threads Worker and in a browser module Worker.
//
// Messages in:  { module, memory, role: "waiter" | "waker", timeoutMs }
//               { go: true }           (waker only: store and notify now)
// Messages out: { ready: true } | { waiting: true } | { result } | { error }

const isNode = typeof process !== "undefined" && process.versions?.node !== undefined;

let port;
if (isNode) {
  const { parentPort } = await import("node:worker_threads");
  port = {
    post: (m) => parentPort.postMessage(m),
    listen: (f) => parentPort.on("message", f),
  };
} else {
  port = {
    post: (m) => self.postMessage(m),
    listen: (f) => {
      self.onmessage = (e) => f(e.data);
    },
  };
}

let exports;

port.listen(async (message) => {
  try {
    if (message.module) {
      const instance = await WebAssembly.instantiate(message.module, {
        env: { memory: message.memory },
      });
      exports = instance.exports;
      port.post({ ready: true });
      if (message.role === "waiter") {
        port.post({ waiting: true });
        const started = performance.now();
        const timeoutNs = BigInt(message.timeoutMs) * 1000000n;
        const code = exports.wait_while_equal(0, timeoutNs);
        port.post({
          result: {
            code,
            value: exports.flag_value(),
            elapsedMs: performance.now() - started,
          },
        });
      }
    } else if (message.go) {
      const woken = exports.store_and_notify(42);
      port.post({ result: { woken } });
    }
  } catch (error) {
    port.post({ error: String(error) });
  }
});
