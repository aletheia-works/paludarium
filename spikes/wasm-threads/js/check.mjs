// The wasm thread check itself, shared by the Node.js and browser
// runners. Two Workers instantiate the same module with one shared
// WebAssembly.Memory; Worker A waits on the shared word with
// memory.atomic.wait32, Worker B stores 42 and notifies. The check passes
// when A wakes with the value 42 within 5 seconds.

export const PASS_LIMIT_MS = 5000;

// 18 pages = 1179648 bytes, the --initial-memory/--max-memory of the module.
const PAGES = 18;

function once(worker, predicate) {
  return new Promise((resolve, reject) => {
    worker.listen((m) => {
      if (m.error) reject(new Error(m.error));
      else if (predicate(m)) resolve(m);
    });
  });
}

function timeout(ms, what) {
  return new Promise((_, reject) =>
    setTimeout(() => reject(new Error(`${what} timed out after ${ms} ms`)), ms),
  );
}

/**
 * @param {{ wasmBytes: ArrayBuffer | Uint8Array,
 *           makeWorker: () => { post(m: unknown): void, listen(f: (m: any) => void): void, terminate(): void } }} options
 */
export async function runCheck({ wasmBytes, makeWorker }) {
  const memory = new WebAssembly.Memory({ initial: PAGES, maximum: PAGES, shared: true });
  const module = await WebAssembly.compile(wasmBytes);
  const waiter = makeWorker();
  const waker = makeWorker();
  const started = Date.now();
  try {
    const waiterReady = once(waiter, (m) => m.waiting);
    const waiterDone = once(waiter, (m) => m.result);
    const wakerReady = once(waker, (m) => m.ready);
    waiter.post({ module, memory, role: "waiter", timeoutMs: PASS_LIMIT_MS });
    waker.post({ module, memory, role: "waker" });
    await Promise.race([Promise.all([waiterReady, wakerReady]), timeout(PASS_LIMIT_MS, "worker start")]);
    // Give the waiter time to enter memory.atomic.wait32 before waking it.
    await new Promise((r) => setTimeout(r, 200));
    const wakerDone = once(waker, (m) => m.result);
    waker.post({ go: true });
    const [a, b] = await Promise.race([
      Promise.all([waiterDone, wakerDone]),
      timeout(PASS_LIMIT_MS + 1000, "wait/notify"),
    ]);
    const { code, value, elapsedMs } = a.result;
    const passed = code === 0 && value === 42 && elapsedMs <= PASS_LIMIT_MS;
    return {
      waitNotifyPassed: passed,
      notes: `wait result ${code} (0 = woken), value ${value}, waited ${Math.round(elapsedMs)} ms, ` +
        `notify woke ${b.result.woken}, total ${Date.now() - started} ms`,
    };
  } catch (error) {
    return { waitNotifyPassed: false, notes: String(error) };
  } finally {
    waiter.terminate();
    waker.terminate();
  }
}
