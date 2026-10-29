import { channel, imports, spawnWorker, listen, stopWorker, putBuffer, takeBuffer } from "./worker-support.mjs";
import { costSnapshot } from "./jit-support.mjs";
import { VERSION, WINDOW, ENETUNREACH, ECONNRESET, canonicalIp, errnoOf, joinAddress, splitAddress } from "./relay-protocol.mjs";
const port = await channel();
const encoder = new TextEncoder(), decoder = new TextDecoder();
let module, memory, e;
const jobs = new Map();
const latestDiagnostics = [];
const childWorkers = new Set();
let abandoned = false;
const failure = (kind, message) => ({ kind, message });
function check(value, name) { if (value < 0) throw new Error(`${name} rejected`); return value; }
function jitDiagnostics(job) {
  if (job.diagnostics && typeof e.cost_version === "function") job.diagnostics.costProfile = costSnapshot(e);
  if (!job.diagnostics || typeof e.session_jit_stat !== "function") return;
  job.diagnostics.jit = {
    translatedBlocks: String(e.session_jit_stat(job.handle, 0)),
    executedBlocks: String(e.session_jit_stat(job.handle, 1)),
    executedInstructions: String(e.session_jit_stat(job.handle, 2)),
    fallbacks: String(e.session_jit_stat(job.handle, 3)),
  };
}
// The guest's network: a socket per stream handle, each fed into and drained
// from its Rust stream through the net_* exports. On Node.js it is a
// net.Socket unless the run names a relay; through a relay (a browser's only
// way) it is a WebSocket to it (docs/guide/relay.md).
const sockets = new Map();
const concat = (a, b) => { const joined = new Uint8Array(a.length + b.length); joined.set(a); joined.set(b, a.length); return joined; };
/** A WebSocket to the relay that sends `request` once open, its first message. */
function relayWebSocket(relay, request) {
  const ws = new WebSocket(relay.url, [...(relay.protocols ?? [])]);
  ws.binaryType = "arraybuffer";
  ws.addEventListener("open", () => ws.send(JSON.stringify({ v: VERSION, ...request })));
  return ws;
}
/** The addresses the relay resolved `name` to; each one's ticket is kept for the job's connections to it. */
function relayLookup(job, name) {
  return new Promise((resolve, reject) => {
    const ws = relayWebSocket(job.relay, { op: "resolve", name });
    const timer = setTimeout(() => { ws.close(); reject({ paludariumErrno: 110 }); }, 30000);
    ws.addEventListener("message", event => {
      let message;
      try { message = typeof event.data === "string" ? JSON.parse(event.data) : undefined; } catch { message = undefined; }
      clearTimeout(timer);
      if (message?.op === "resolved" && Array.isArray(message.addresses)) {
        const addresses = [];
        for (const item of message.addresses) {
          const ip = canonicalIp(item?.address);
          if (!ip || typeof item.ticket !== "string") continue;
          addresses.push(ip);
          const tickets = job.tickets.get(ip) ?? new Map();
          job.tickets.set(ip, tickets.set(name.toLowerCase().replace(/\.$/, ""), item.ticket));
        }
        resolve(addresses);
      } else reject({ paludariumErrno: message?.op === "failed" ? message.errno : 5 });
      ws.close();
    });
    ws.addEventListener("close", () => { clearTimeout(timer); reject({ paludariumErrno: ENETUNREACH }); });
  });
}
/** A connection through the relay, with the part of net.Socket's interface the coordinator uses. */
function relaySocket(job, target) {
  const listeners = new Map(), tickets = [...(job.tickets.get(target.ip) ?? [])].map(([name, ticket]) => ({ name, ticket }));
  const ws = relayWebSocket(job.relay, { op: "open", address: joinAddress(target.ip, target.port), tickets });
  let state = "connecting", failed = false, ended = false, sentEnd = false, paused = false, held = 0, unreported = 0, unacked = 0, noDelay = false, draining = false;
  const emit = (event, value) => { for (const listener of [...(listeners.get(event) ?? [])]) { if (listener.once) listeners.get(event).delete(listener); listener.callback(value); } };
  const add = (event, callback, once) => { if (!listeners.has(event)) listeners.set(event, new Set()); listeners.get(event).add({ callback, once }); return socket; };
  const send = value => { if (ws.readyState === WebSocket.OPEN) ws.send(value); };
  // The relay sends up to WINDOW bytes ahead of what the guest took: credit them back in quarters, and at once when a pause ends.
  const credit = force => { if (unreported && (force || unreported >= WINDOW / 4)) { send(JSON.stringify({ op: "credit", bytes: unreported })); unreported = 0; } };
  const fail = errno => { if (!failed) { failed = true; emit("error", { paludariumErrno: errno }); } };
  // The client closes the WebSocket, once both sides ended or the relay reported an error: the relay leaves it to the client.
  const finish = () => { if (state === "closed") return; state = "closed"; if (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN) ws.close(1000); emit("close"); };
  ws.addEventListener("message", event => {
    if (typeof event.data !== "string") {
      if (state !== "open") return;
      const bytes = new Uint8Array(event.data);
      if (paused) held += bytes.length; else { unreported += bytes.length; credit(false); }
      emit("data", bytes);
      return;
    }
    let message;
    try { message = JSON.parse(event.data); } catch { message = undefined; }
    if (message?.op === "connected" && state === "connecting") {
      const local = splitAddress(message.local);
      state = "open"; socket.localAddress = local?.ip ?? "0.0.0.0"; socket.localPort = local?.port ?? 0;
      if (noDelay) send(JSON.stringify({ op: "nodelay", on: true }));
      emit("connect");
    } else if (message?.op === "credit" && Number.isSafeInteger(message.bytes) && message.bytes >= 0) {
      unacked = Math.max(0, unacked - message.bytes);
      if (draining && unacked < WINDOW) { draining = false; emit("drain"); }
    } else if (message?.op === "end") { ended = true; emit("end"); if (sentEnd) finish(); }
    else if (message?.op === "failed") { fail(message.errno); finish(); }
  });
  // A WebSocket that closed before the client closed it is lost: unreachable before connecting, a reset after.
  ws.addEventListener("close", () => {
    if (state === "closed") return;
    if (state !== "open") fail(ENETUNREACH);
    else if (!ended) fail(ECONNRESET);
    finish();
  });
  const socket = {
    localAddress: undefined, localPort: undefined,
    on: (event, callback) => add(event, callback, false),
    once: (event, callback) => add(event, callback, true),
    // The relay credits what it wrote to the peer: no more than WINDOW goes ahead of that.
    write(bytes) {
      send(bytes); unacked += bytes.length;
      if (unacked < WINDOW) return true;
      draining = true;
      return false;
    },
    end() { if (sentEnd) return; sentEnd = true; send(JSON.stringify({ op: "end" })); if (ended) finish(); },
    destroy() { finish(); },
    pause() { paused = true; },
    resume() { if (!paused) return; paused = false; unreported += held; held = 0; credit(true); },
    setNoDelay(on) { noDelay = on; if (state === "open") send(JSON.stringify({ op: "nodelay", on })); },
  };
  return socket;
}
/** Passes received bytes on as the stream takes them; the peer's end follows the last of them. */
function deliver(entry) {
  if (!entry.pending) return;
  const accepted = withBytes(entry.pending, id => e.net_receive(entry.id, id));
  if (accepted < 0) { entry.socket.destroy(); return; }
  entry.pending = accepted < entry.pending.length ? entry.pending.subarray(accepted) : null;
  if (entry.pending) { entry.socket.pause(); return; }
  entry.socket.resume();
  if (entry.peerEnded) e.net_end(entry.id);
  settle(entry);
}
/** Moves what the guest queued to the socket, and passes on its shutdown and close. */
function pump(entry) {
  if (abandoned || entry.released) return;
  deliver(entry);
  while (entry.open && !entry.blocked) {
    const id = e.net_take(entry.id, 65536);
    if (!id) break;
    if (!entry.socket.write(takeBuffer(e, id, memory))) { entry.blocked = true; entry.socket.once("drain", () => { entry.blocked = false; pump(entry); }); }
  }
  const state = e.net_state(entry.id);
  if (state < 0 || state & 2) {
    entry.guestClosed = true; entry.pending = null;
    if (entry.open) entry.socket.end(); else entry.socket.destroy();
    settle(entry);
  } else if (state & 1 && entry.open && !entry.ended) { entry.ended = true; entry.socket.end(); }
}
/** Releases the handle once the socket is closed and nothing received waits for a guest still using it. */
function settle(entry) { if (entry.closed && (!entry.pending || entry.guestClosed)) release(entry); }
function release(entry) {
  if (entry.released) return;
  entry.released = true; sockets.delete(entry.id);
  if (!abandoned) e.net_release(entry.id);
}
async function netRequest(job, request) {
  if (abandoned) return;
  if (request.op === "kick") { const entry = sockets.get(request.id); if (entry) pump(entry); return; }
  if (request.op === "nodelay") { const entry = sockets.get(request.id); if (entry) { entry.noDelay = request.on; entry.socket.setNoDelay(request.on); } return; }
  // The kernel asks only for what its policy allows; a run without a network never gets here.
  if (request.op === "resolve") {
    if (!job?.network) { e.net_unresolved(request.id, 101); return; }
    // A lookup still pending when its job ends is released then (closeSockets), and its answer dropped.
    job.lookups.add(request.id);
    let found, failed;
    try {
      if (job.relay) found = await relayLookup(job, request.name);
      else found = (await (await import("node:dns/promises")).lookup(request.name, { all: true, verbatim: true })).map(item => item.address);
    } catch (cause) { if (cause?.code === "ENOTFOUND" || cause?.code === "ENODATA") found = []; else failed = cause; }
    if (abandoned || !job.lookups.delete(request.id)) return;
    if (found) withBytes(encoder.encode(found.join("\n")), id => e.net_resolved(request.id, id));
    else e.net_unresolved(request.id, errnoOf(failed));
    return;
  }
  if (request.op !== "open") return;
  if (!job?.network) { e.net_failed(request.id, 101); e.net_release(request.id); return; }
  const target = splitAddress(request.address);
  if (!target) { e.net_failed(request.id, 22); e.net_release(request.id); return; }
  // Half-open, as TCP: the peer's end leaves this side able to send.
  const socket = job.relay ? relaySocket(job, target) : (await import("node:net")).connect({ host: target.ip, port: target.port, allowHalfOpen: true });
  if (abandoned) { socket.destroy(); return; }
  const entry = { id: request.id, job, socket, pending: null, open: false, closed: false, blocked: false, ended: false, peerEnded: false, guestClosed: false, released: false };
  sockets.set(entry.id, entry); job.sockets.add(entry);
  socket.on("connect", () => {
    if (abandoned || entry.released) return;
    entry.open = true;
    withBytes(encoder.encode(joinAddress(socket.localAddress, socket.localPort)), id => e.net_connected(entry.id, id));
    pump(entry);
  });
  socket.on("data", chunk => {
    if (abandoned || entry.released) return;
    entry.pending = entry.pending ? concat(entry.pending, chunk) : chunk;
    deliver(entry);
  });
  socket.on("end", () => { if (abandoned || entry.released) return; entry.peerEnded = true; if (!entry.pending) e.net_end(entry.id); });
  socket.on("error", cause => { if (!abandoned && !entry.released && !entry.guestClosed) e.net_failed(entry.id, errnoOf(cause)); });
  socket.on("close", () => { entry.open = false; entry.closed = true; job.sockets.delete(entry); settle(entry); });
}
function closeSockets(job) {
  for (const entry of job.sockets) { entry.socket.destroy(); release(entry); }
  job.sockets.clear();
  for (const entry of sockets.values()) if (entry.job === job) release(entry);
  if (!abandoned) for (const id of job.lookups) e.net_release(id);
  job.lookups.clear();
}
function withBytes(bytes, callback) { const id = putBuffer(e, bytes, memory); try { return callback(id); } finally { e.buffer_drop(id); } }
function placeEntries(config, entries) {
  for (const entry of entries?.nodes ?? []) withBytes(encoder.encode(entry.path), pathId => withBytes(entry.content, dataId => check(e.config_entry(config, pathId, dataId, entry.mode, BigInt.asUintN(64, entry.mtimeNs), BigInt.asIntN(64, entry.mtimeNs >> 64n)), "filesystem entry")));
  for (const link of entries?.links ?? []) withBytes(encoder.encode(link.path), pathId => withBytes(encoder.encode(link.existing), existingId => check(e.config_link(config, pathId, existingId), "filesystem entry")));
}
function errorFor(handle) {
  const kind = e.session_error_kind(handle);
  const names = ["internal", "unimplemented", "internal", "invalid-program", "host"];
  const message = decoder.decode(takeBuffer(e, e.session_error_message(handle), memory));
  const error = failure(names[kind] ?? "internal", message || "Guest session failed"), presence = e.session_error_presence(handle);
  if (presence & 1) error.rip = e.session_error_rip(handle);
  if (presence & 2) error.bytes = takeBuffer(e, e.session_error_bytes(handle), memory);
  if (presence & 4) error.syscall = Number(e.session_error_syscall(handle));
  return error;
}
function flush(job) {
  for (const [stream, name] of [[1, "stdout"], [2, "stderr"]]) {
    const bytes = takeBuffer(e, e.session_output(job.handle, stream), memory);
    const offset = job.offsets[name];
    if (bytes.length > offset) port.send({ type: "output", id: job.id, stream: name, bytes: bytes.slice(offset) });
    job.offsets[name] = bytes.length;
  }
}
function fatal(message) {
  if (abandoned) return;
  abandoned = true;
  for (const job of jobs.values()) { clearTimeout(job.timer); clearInterval(job.poll); }
  // Termination may abandon Rust locks; no further Rust ABI calls are permitted.
  void Promise.all([...childWorkers].map(stopWorker)).finally(() => port.send({ type: "fatal", error: failure("host", message) }));
}
async function sharedProbe() {
  const space = e.shared_space_new();
  if (!space) throw new Error("shared AddressSpace creation failed");
  const children = [];
  const timer = setTimeout(() => fatal("shared probe watchdog; discard shared heap"), 30000);
  try {
    for (let index = 0; index < 2; index++) {
      const tlsSize = Number(e.__tls_size.value), align = Math.max(16, Number(e.__tls_align.value));
      const region = e.region_new(2 * 1024 * 1024 + tlsSize + align + 16);
      const pointer = e.region_pointer(region), tlsPointer = Math.ceil(pointer / align) * align;
      const stackTop = Math.ceil((tlsPointer + tlsSize) / 16) * 16 + 2 * 1024 * 1024;
      const token = putBuffer(e, new Uint8Array([73]));
      const worker = await spawnWorker(new URL("execution.mjs", import.meta.url));
      childWorkers.add(worker);
      const child = { worker, region, token, pending: new Map() };
      child.next = type => new Promise((resolve, reject) => child.pending.set(type, { resolve, reject }));
      listen(worker, report => {
        if (report.type === "failed") { fatal(report.error); for (const promise of child.pending.values()) promise.reject(new Error(report.error)); }
        else { child.pending.get(report.type)?.resolve(report); child.pending.delete(report.type); }
      }, cause => { fatal(String(cause)); for (const promise of child.pending.values()) promise.reject(cause); });
      const started = child.next("started"); children.push(child);
      worker.postMessage({ type: "execute", operation: "probe", module, memory, stackTop, tlsPointer, tokenHandle: token });
      child.diagnostics = (await started).diagnostics;
    }
    const completions = children.map(child => { const done = child.next("probe-done"); child.worker.postMessage({ type: "probe-go", space }); return done; });
    const allocations = await Promise.all(completions);
    if (abandoned) throw new Error("shared runtime abandoned");
    const value = String(e.shared_space_value(space));
    check(e.shared_wait_word(space, 0), "wait word");
    const waiter = children[0], starting = waiter.next("wait-starting"), done = waiter.next("wait-done");
    waiter.worker.postMessage({ type: "wait-go", space }); await starting;
    await new Promise(resolve => setTimeout(resolve, 50));
    check(e.shared_wait_word(space, 1), "notify word");
    const notified = e.shared_notify(space, 1), waited = (await done).result;
    if (abandoned) throw new Error("shared runtime abandoned");
    for (const child of children) { await stopWorker(child.worker); childWorkers.delete(child.worker); e.region_drop(child.region); e.buffer_drop(child.token); }
    e.shared_space_drop(space);
    return { value, allocations, notified, waited, workers: children.map(child => child.diagnostics) };
  } catch (cause) {
    // A trapped child may own a Rust lock: discard the complete runtime, never free/reuse it.
    fatal(String(cause)); throw cause;
  } finally { clearTimeout(timer); }
}
async function finish(job, result, error) {
  if (job.finished) return;
  if (abandoned) return;
  job.finished = true;
  clearTimeout(job.timer); clearInterval(job.poll);
  try { flush(job); } catch (cause) { error ??= failure("internal", String(cause)); }
  if (job.worker) await stopWorker(job.worker);
  await Promise.all([...job.tasks.values()].map(task => task.done));
  if (abandoned) return;
  childWorkers.delete(job.worker);
  // Parent owns these allocations until the child is gone; never free an active stack.
  // This path is reached only after Rust returned, including a typed guest error.
  // Traps and forced failures discard the complete runtime through fatal().
  e.region_drop(job.region); e.buffer_drop(job.token);
  closeSockets(job);
  jitDiagnostics(job);
  e.session_drop(job.handle); jobs.delete(job.id);
  if (error) port.send({ type: "failed", id: job.id, error });
  else port.send({ type: "finished", id: job.id, status: result >= 256 ? { kind: "signaled", signal: result - 256 } : { kind: "exited", code: result }, diagnostics: job.diagnostics });
}
async function launchTask(job, handle) {
  if (abandoned || job.finished || job.tasks.has(handle)) { fatal("invalid or stale guest task spawn"); return; }
  const tlsSize = Number(e.__tls_size.value), align = Math.max(16, Number(e.__tls_align.value));
  const region = e.region_new(2 * 1024 * 1024 + tlsSize + align + 16);
  if (!region) { fatal("guest Worker region allocation failed"); return; }
  const pointer = e.region_pointer(region), tlsPointer = Math.ceil(pointer / align) * align;
  const stackTop = Math.ceil((tlsPointer + tlsSize) / 16) * 16 + 2 * 1024 * 1024;
  const token = putBuffer(e, new Uint8Array([73]), memory);
  let resolveDone;
  const task = { region, token, done: new Promise(resolve => { resolveDone = resolve; }) };
  job.tasks.set(handle, task);
  try {
    const worker = await spawnWorker(new URL("execution.mjs", import.meta.url));
    task.worker = worker; childWorkers.add(worker);
    listen(worker, report => {
      if (report.type === "spawn-task") void launchTask(job, report.handle);
      else if (report.type === "net") void netRequest(job, report.request);
      else if (report.type === "started") {
        latestDiagnostics.push({ ...report.diagnostics, taskHandle: handle, guestThread: true, regionPointer: pointer,
          coordinatorTls: e.__tls_base.value, coordinatorThreadToken: String(e.thread_token()), sharedMemory: memory.buffer instanceof SharedArrayBuffer, nestedWorker: true });
      } else if (report.type === "task-finished") {
        if (report.result !== 0) { fatal("guest task execution rejected"); resolveDone(); return; }
        void stopWorker(worker).then(() => {
          childWorkers.delete(worker);
          if (!abandoned) { e.region_drop(region); e.buffer_drop(token); }
          resolveDone();
        }).catch(cause => { fatal(String(cause)); resolveDone(); });
      } else if (report.type === "failed") { fatal(report.error); resolveDone(); }
    }, cause => { fatal(String(cause)); resolveDone(); });
    worker.postMessage({ type: "execute", operation: "task", module, memory, sessionHandle: job.handle, taskHandle: handle, stackTop, tlsPointer, tokenHandle: token });
  } catch (cause) { fatal(`guest Worker start failed: ${cause}`); resolveDone(); }
}
async function launch(message) {
  const config = withBytes(encoder.encode(message.options.program), id => e.config_new(id));
  if (!config) throw new Error("invalid program configuration");
  try {
    if (message.options.cwd !== undefined) withBytes(encoder.encode(message.options.cwd), id => check(e.config_cwd(config, id), "current directory"));
    if (message.options.tty != null) check(e.config_terminal(config, message.options.tty.columns, message.options.tty.rows), "terminal");
    if (message.options.jit !== undefined) check(e.config_jit(config, message.options.jit ? 1 : 0), "JIT");
    if (message.options.limits?.tasks !== undefined) check(e.config_limit(config, 0, message.options.limits.tasks), "task limit");
    if (message.options.limits?.openFiles !== undefined) check(e.config_limit(config, 1, message.options.limits.openFiles), "open file limit");
    if (message.options.limits?.memory !== undefined) check(e.config_limit(config, 2, message.options.limits.memory), "memory limit");
    // NetworkPolicy::allow has the last word on an entry; one it refuses is the caller's error.
    for (const entry of message.options.network?.allow ?? []) {
      if (withBytes(encoder.encode(entry), id => e.config_network(config, id)) < 0) throw Object.assign(new Error(`network.allow entry ${JSON.stringify(entry)} rejected`), { kind: "invalid-program" });
    }
    for (const arg of message.options.args ?? [message.options.program]) withBytes(encoder.encode(arg), id => check(e.config_arg(config, id), "argument"));
    for (const [key, value] of Object.entries(message.options.env ?? {})) withBytes(encoder.encode(key), keyId => withBytes(encoder.encode(value), valueId => check(e.config_env(config, keyId, valueId), "environment")));
    for (const [path, bytes] of Object.entries(message.options.files ?? {})) withBytes(encoder.encode(path), pathId => withBytes(bytes, dataId => check(e.config_file_mode(config, pathId, dataId, message.options.fileModes?.[path] ?? 0o755), "file")));
    placeEntries(config, message.options.entries);
    const handle = withBytes(new Uint8Array(), id => e.session_from_config_fs(config, id, message.options.filesystemHandle ?? 0));
    if (!handle) throw new Error("session creation failed");
    const tlsSize = Number(e.__tls_size.value), tlsAlign = Math.max(16, Number(e.__tls_align.value));
    const region = e.region_new(2 * 1024 * 1024 + tlsSize + tlsAlign + 16);
    if (!region) { e.session_drop(handle); throw new Error("Worker region allocation failed"); }
    const pointer = e.region_pointer(region);
    const tlsPointer = Math.ceil(pointer / tlsAlign) * tlsAlign;
    const stackTop = Math.ceil((tlsPointer + tlsSize) / 16) * 16 + 2 * 1024 * 1024;
    const token = putBuffer(e, new Uint8Array([73]), memory);
    const job = { id: message.id, handle, region, token, offsets: { stdout: 0, stderr: 0 }, finished: false, diagnostics: null, tasks: new Map(), network: message.options.network !== undefined, relay: message.options.network?.relay, tickets: new Map(), sockets: new Set(), lookups: new Set() };
    jobs.set(message.id, job);
    port.send({ type: "accepted", id: message.id });
    job.worker = await spawnWorker(new URL("execution.mjs", import.meta.url));
    childWorkers.add(job.worker);
    listen(job.worker, report => {
      if (report.type === "started") { job.diagnostics = { ...report.diagnostics, regionPointer: pointer, coordinatorTls: e.__tls_base.value, coordinatorThreadToken: String(e.thread_token()), sharedMemory: memory.buffer instanceof SharedArrayBuffer, nestedWorker: true }; latestDiagnostics.push(job.diagnostics); }
      else if (report.type === "spawn-task") void launchTask(job, report.handle);
      else if (report.type === "net") void netRequest(job, report.request);
      else if (report.type === "finished") void finish(job, report.result, report.result < 0 ? errorFor(handle) : null);
      else if (report.type === "failed") fatal(report.error);
    }, cause => fatal(String(cause)));
    job.poll = setInterval(() => { try { flush(job); } catch (cause) { fatal(String(cause)); } }, 10);
    job.worker.postMessage({ type: "execute", module, memory, sessionHandle: handle, stackTop, tlsPointer, tokenHandle: token });
  } finally { if (typeof e.config_drop === "function") e.config_drop(config); }
}
port.listen(async message => {
  if (abandoned) return;
  try {
    if (message.type === "init") {
      module = message.module; memory = message.memory;
      // Dropping a session closes its sockets from here: their kicks come back through the same path.
      e = (await WebAssembly.instantiate(module, imports(memory, { net: request => queueMicrotask(() => void netRequest(null, request)) }))).exports;
      if (typeof e.cost_reset === "function") e.cost_reset();
      port.send({ type: "ready", exports: WebAssembly.Module.exports(module), imports: WebAssembly.Module.imports(module) });
    } else if (message.type === "filesystem-new") {
      const config = withBytes(encoder.encode("/"), id => e.config_new(id));
      try {
        for (const [path, bytes] of Object.entries(message.options.files ?? {})) withBytes(encoder.encode(path), pathId => withBytes(bytes, dataId => check(e.config_file_mode(config, pathId, dataId, message.options.fileModes?.[path] ?? 0o755), "file")));
        placeEntries(config, message.options.entries);
        const handle = e.filesystem_new(config);
        if (!handle) throw new Error("filesystem creation failed");
        port.send({ type: "control", id: message.id, value: handle });
      } finally { e.config_drop(config); }
    } else if (message.type === "filesystem-snapshot") {
      const handle = e.filesystem_snapshot(message.handle);
      if (!handle) throw new Error("filesystem snapshot rejected (active or stale handle)");
      port.send({ type: "control", id: message.id, value: takeBuffer(e, handle, memory) });
    } else if (message.type === "filesystem-remove") {
      withBytes(encoder.encode(message.path), id => check(e.filesystem_remove(message.handle, id, message.recursive ? 1 : 0), "filesystem removal"));
      port.send({ type: "control", id: message.id });
    } else if (message.type === "filesystem-drop") {
      if (e.filesystem_drop(message.handle) !== 0) throw new Error("filesystem disposal rejected (active or stale handle)");
      port.send({ type: "control", id: message.id });
    } else if (message.type === "run") await launch(message);
    else if (message.type === "diagnostics") {
      port.send({ type: "diagnostics", id: message.id, diagnostics: { workers: latestDiagnostics, sharedProbe: await sharedProbe() } });
    }
    else if (message.type === "stdin") {
      const job = jobs.get(message.id);
      if (job) withBytes(message.bytes, id => check(e.session_stdin_write(job.handle, id), "stdin"));
    } else if (message.type === "stdin-close") { const job = jobs.get(message.id); if (job) check(e.session_stdin_close(job.handle), "stdin close"); }
    else if (message.type === "kill") { const job = jobs.get(message.id); if (job) e.session_kill(job.handle); }
    else if (message.type === "dispose") {
      for (const job of jobs.values()) e.session_kill(job.handle);
      while (jobs.size) await new Promise(resolve => setTimeout(resolve, 10));
      port.send({ type: "disposed" });
    }
  } catch (cause) { port.send({ type: "failed", id: message.id, error: failure(cause?.kind ?? "internal", cause?.kind ? cause.message : String(cause)) }); }
});
