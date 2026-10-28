export const isNode = typeof process !== "undefined" && Boolean(process.versions?.node);
export async function channel() {
  if (isNode) {
    const { parentPort } = await import("node:worker_threads");
    return { send: value => parentPort.postMessage(value), listen: callback => parentPort.on("message", callback) };
  }
  return { send: value => postMessage(value), listen: callback => addEventListener("message", event => callback(event.data)) };
}
export async function spawnWorker(url) {
  const Constructor = isNode ? (await import("node:worker_threads")).Worker : globalThis.Worker;
  return new Constructor(url, { type: "module" });
}
export function listen(worker, message, error) {
  if (isNode) { worker.on("message", message); worker.on("error", error); }
  else { worker.addEventListener("message", event => message(event.data)); worker.addEventListener("error", event => error(new Error(event.message))); }
}
export async function stopWorker(worker) { await worker.terminate(); }
export function imports(memory, { spawnTask, cost, net } = {}) {
  const sleepWord = new Int32Array(new SharedArrayBuffer(4));
  const jit = jitImports(memory, cost);
  // The guest's network requests go to the coordinator, which owns the sockets; text is copied out of shared memory.
  const text = (pointer, length) => new TextDecoder().decode(new Uint8Array(memory.buffer, pointer, length).slice());
  const request = (message) => { try { if (!net || !Number.isInteger(message.id) || message.id <= 0) return -1; net(message); return 0; } catch { return -1; } };
  return {
    env: { memory },
    paludarium: {
      jit_prepare: (...arguments_) => jit.prepare(...arguments_),
      jit_execute: (...arguments_) => jit.execute(...arguments_),
      spawn_task(handle) {
        try { if (!spawnTask || !Number.isInteger(handle) || handle <= 0) return -1; spawnTask(handle); return 0; }
        catch { return -1; }
      },
      random_fill(pointer, length) {
        try {
          const buffer = new Uint8Array(memory.buffer, pointer, length);
          // WebCrypto implementations may reject views backed by SharedArrayBuffer.
          // Generate cryptographic entropy in ordinary storage, then copy into Rust memory.
          for (let offset = 0; offset < length; offset += 65536) {
            const entropy = new Uint8Array(Math.min(65536, length - offset));
            globalThis.crypto.getRandomValues(entropy);
            buffer.set(entropy, offset);
          }
          return 0;
        } catch { return -1; }
      },
      net_open(id, pointer, length) { try { return request({ op: "open", id, address: text(pointer, length) }); } catch { return -1; } },
      net_resolve(id, pointer, length) { try { return request({ op: "resolve", id, name: text(pointer, length) }); } catch { return -1; } },
      net_kick(id) { request({ op: "kick", id }); },
      net_nodelay(id, on) { request({ op: "nodelay", id, on: on !== 0 }); },
      clock_ms(kind) { return kind === 0 ? Date.now() : performance.timeOrigin + performance.now(); },
      sleep_ms(ms) { Atomics.wait(sleepWord, 0, 0, Math.max(0, Math.min(ms, 10))); },
    },
  };
}
export function putBuffer(exports, bytes, memory) {
  const id = exports.buffer_new(bytes.length);
  if (!id) throw new Error("Rust buffer allocation rejected");
  if (memory && typeof exports.buffer_pointer === "function") {
    try {
      const pointer = exports.buffer_pointer(id);
      if (!pointer) throw new Error("Rust buffer pointer rejected");
      new Uint8Array(memory.buffer, pointer, bytes.length).set(bytes);
      return id;
    } catch (error) { exports.buffer_drop(id); throw error; }
  }
  for (let index = 0; index < bytes.length; index++) {
    if (exports.buffer_set(id, index, bytes[index]) !== 0) { exports.buffer_drop(id); throw new Error("Rust buffer write rejected"); }
  }
  return id;
}
export function takeBuffer(exports, id, memory) {
  if (!id) return new Uint8Array();
  try {
    const length = exports.buffer_len(id);
    if (length < 0) throw new Error("invalid Rust buffer handle");
    if (memory && typeof exports.buffer_pointer === "function") {
      const pointer = exports.buffer_pointer(id);
      if (!pointer) throw new Error("Rust buffer pointer rejected");
      return new Uint8Array(memory.buffer, pointer, length).slice();
    }
    const bytes = new Uint8Array(length);
    for (let index = 0; index < length; index++) {
      const value = exports.buffer_get(id, index);
      if (value < 0) throw new Error("invalid Rust buffer index");
      bytes[index] = value;
    }
    return bytes;
  } finally { exports.buffer_drop(id); }
}
import { jitImports } from "./jit-support.mjs";
