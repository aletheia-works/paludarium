import { isNode, spawnWorker, listen, stopWorker } from "./worker-support.mjs";
import { decodeSnapshot } from "./filesystem-snapshot.mjs";
export class PaludariumError extends Error {
  constructor(kind, message, details = {}) { super(message); this.name = "PaludariumError"; this.kind = kind; for (const field of ["rip", "bytes", "syscall"]) if (details[field] !== undefined) this[field] = details[field]; }
}
async function moduleBytes(url) {
  const source = new URL(url, typeof location === "undefined" ? import.meta.url : location.href);
  if (isNode && source.protocol === "file:") return (await import("node:fs/promises")).readFile(source);
  const response = await fetch(source, { signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new PaludariumError("host", `Wasm fetch returned ${response.status}`);
  return response.arrayBuffer();
}
function validate(options) {
  if (!options || typeof options.program !== "string" || !options.program.startsWith("/") || options.program.includes("\0")) throw new PaludariumError("invalid-program", "program must be an absolute guest path");
  if (options.tty != null && [options.tty.columns, options.tty.rows].some(value => !Number.isInteger(value) || value < 0 || value > 65535)) throw new PaludariumError("invalid-program", "invalid guest terminal size");
  if (options.jit !== undefined && typeof options.jit !== "boolean") throw new PaludariumError("invalid-program", "jit must be a boolean");
  if (options.limits !== undefined && (options.limits === null || typeof options.limits !== "object")) throw new PaludariumError("invalid-program", "limits must be an object");
  const { tasks, openFiles, memory } = options.limits ?? {};
  if (tasks !== undefined && (!Number.isInteger(tasks) || tasks < 1 || tasks > 0xffffffff)) throw new PaludariumError("invalid-program", "limits.tasks must be an integer from 1 to 4294967295");
  if (openFiles !== undefined && (!Number.isInteger(openFiles) || openFiles < 0 || openFiles > 1048576)) throw new PaludariumError("invalid-program", "limits.openFiles must be an integer from 0 to 1048576");
  if (memory !== undefined && (!Number.isInteger(memory) || memory < 0 || memory > 0xffffffff)) throw new PaludariumError("invalid-program", "limits.memory must be an integer from 0 to 4294967295");
  if (options.network !== undefined) {
    const allow = options.network?.allow;
    // host, host:port, *.host, IPv4, [IPv6] or [IPv6]:port, or a bare IPv6 address; the kernel parses each in full.
    const entry = /^(?:(?:\*\.)?[A-Za-z0-9_.-]+(?::\d{1,5})?|\[[0-9A-Fa-f:.]+\](?::\d{1,5})?|[0-9A-Fa-f:.]+)$/;
    if (options.network === null || typeof options.network !== "object" || !Array.isArray(allow) || allow.some(item => typeof item !== "string" || !entry.test(item))) throw new PaludariumError("invalid-program", "network.allow must be an array of host, host:port, [ipv6] or [ipv6]:port entries");
    if (!isNode) throw new PaludariumError("unimplemented", "the network is available on Node.js only");
  }
  if (options.cwd !== undefined && (typeof options.cwd !== "string" || !options.cwd.startsWith("/") || options.cwd.includes("\0"))) throw new PaludariumError("invalid-program", "invalid guest current directory");
  if (options.args && (!Array.isArray(options.args) || options.args.some(arg => typeof arg !== "string" || arg.includes("\0")))) throw new PaludariumError("invalid-program", "invalid guest arguments");
  if (Object.entries(options.env ?? {}).some(([key, value]) => !key || key.includes("=") || key.includes("\0") || typeof value !== "string" || value.includes("\0"))) throw new PaludariumError("invalid-program", "invalid guest environment");
  if (Object.entries(options.files ?? {}).some(([path, bytes]) => !path.startsWith("/") || path.includes("\0") || !(bytes instanceof Uint8Array))) throw new PaludariumError("invalid-program", "invalid guest files");
  if (Object.entries(options.fileModes ?? {}).some(([path, mode]) => !Object.hasOwn(options.files ?? {}, path) || !Number.isInteger(mode) || mode < 0 || mode > 0o7777)) throw new PaludariumError("invalid-program", "invalid guest file modes");
}
const KINDS = { [0o100000]: "file", [0o040000]: "directory", [0o120000]: "symlink" }, encoder = new TextEncoder();
const normalize = path => "/" + path.split("/").reduce((parts, part) => { if (part === "..") parts.pop(); else if (part && part !== ".") parts.push(part); return parts; }, []).join("/");
const integer = value => typeof value === "bigint" ? value : Number.isSafeInteger(value) ? BigInt(value) : undefined;
const sameBytes = (a, b) => { if (a.length !== b.length) return false; for (let index = 0; index < a.length; index++) if (a[index] !== b[index]) return false; return true; };
/** Checks a tree (a snapshot, for one) and returns what the coordinator places:
 * the first path of each inode carries the node, the others are hard links to it. */
function entryPlan({ entries, files, filesystem }) {
  if (entries === undefined) return undefined;
  const fail = (reason, path) => { throw new PaludariumError("invalid-program", `invalid guest filesystem entries: ${reason}${path === undefined ? "" : ": " + path}`); };
  if (!Array.isArray(entries)) fail("entries must be an array");
  if (filesystem !== undefined) fail("entries apply only to a new filesystem");
  if (entries.length > 1048576) fail("more than 1048576 entries");
  const kinds = new Map(), groups = new Map(), nodes = [], links = [];
  let bytes = 0;
  for (const entry of entries) {
    if (entry === null || typeof entry !== "object") fail("an entry is not an object");
    const { path, mode } = entry, content = entry.content ?? new Uint8Array();
    if (typeof path !== "string" || !path.startsWith("/") || path.includes("\0")) fail("path is not absolute", path);
    if (path !== normalize(path)) fail("path is not normalized", path);
    if (encoder.encode(path).length >= 4096 || path.split("/").some(part => encoder.encode(part).length > 255)) fail("path is too long", path);
    if (kinds.has(path)) fail("duplicate path", path);
    const kind = Number.isInteger(mode) && mode >= 0 && mode <= 0o177777 ? KINDS[mode & 0o170000] : undefined;
    if (!kind) fail("mode is not a file, directory or symlink mode", path);
    if (!(content instanceof Uint8Array)) fail("content is not a Uint8Array", path);
    if (content.length > 128 * 1024 * 1024) fail("content is larger than 128 MiB", path);
    const mtimeNs = entry.mtimeNs === undefined ? 0n : integer(entry.mtimeNs), inode = entry.inode === undefined ? undefined : integer(entry.inode);
    if (mtimeNs === undefined || mtimeNs < -(1n << 127n) || mtimeNs >= 1n << 127n) fail("invalid mtimeNs", path);
    if ((entry.inode !== undefined && inode === undefined) || (entry.links !== undefined && integer(entry.links) === undefined)) fail("invalid inode or links", path);
    if (kind === "directory" && content.length) fail("a directory has content", path);
    if (kind === "symlink" && ((mode & 0o7777) !== 0o777 || !content.length || content.length >= 4096 || content.includes(0))) fail("invalid symlink", path);
    kinds.set(path, kind);
    const first = inode === undefined ? undefined : groups.get(inode);
    if (first) {
      if (kind === "directory" || first.kind !== kind) fail("a hard link names a directory or another kind", path);
      if (first.mode !== mode || first.mtimeNs !== mtimeNs || !sameBytes(first.content, content)) fail("hard links differ in mode, mtimeNs or content", path);
      links.push({ path, existing: first.path });
    } else {
      if (inode !== undefined) groups.set(inode, { path, kind, mode, mtimeNs, content });
      nodes.push({ path, mode, content, mtimeNs }); bytes += content.length;
    }
  }
  if (bytes > 256 * 1024 * 1024) fail("more than 256 MiB of content");
  // `/`, `/tmp` and the parents of `files` are directories before entries are placed.
  const directories = new Set(["/", "/tmp"]), placed = new Set(Object.keys(files ?? {}).map(normalize));
  for (const path of placed) { const parts = path.split("/"); for (let index = 2; index < parts.length; index++) directories.add(parts.slice(0, index).join("/")); }
  for (const [path, kind] of kinds) {
    if (placed.has(path)) fail("duplicate path", path);
    if (directories.has(path) && kind !== "directory") fail("path is a directory", path);
    if (path === "/") continue;
    const parent = path.slice(0, path.lastIndexOf("/")) || "/";
    if (kinds.has(parent) ? kinds.get(parent) !== "directory" : !directories.has(parent)) fail("parent is not a directory", path);
  }
  return { nodes, links };
}
/** C12: all Rust execution and locking takes place in dedicated Workers. */
export async function createPaludarium({ wasmUrl }) {
  const module = await WebAssembly.compile(await moduleBytes(wasmUrl));
  const memory = new WebAssembly.Memory({ initial: 128, maximum: 16384, shared: true });
  const coordinator = await spawnWorker(new URL("coordinator.mjs", import.meta.url));
  const pending = new Map(); let next = 1, closed = false, failed = false, readyResolve, readyReject, disposeResolve, disposal, disposeTimer;
  const filesystems = new WeakMap();
  function control(type, values = {}) {
    if (closed) return Promise.reject(new PaludariumError("host", "Launcher is closed"));
    const id = next++;
    return new Promise((resolve, reject) => { pending.set(id, { resolve, reject }); coordinator.postMessage({ type, id, ...values }); });
  }
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const initTimer = setTimeout(() => void failAll(new PaludariumError("host", "30 second launcher initialization watchdog")), 30000);
  function rejectPending(error) {
    for (const job of pending.values()) { clearTimeout(job.timer); job.reject(error); job.stdout?.error(error); job.stderr?.error(error); job.stdin?.error(error); }
    pending.clear();
  }
  async function failAll(error) {
    if (failed) return;
    failed = true; closed = true; clearTimeout(initTimer); clearTimeout(disposeTimer); readyReject(error);
    rejectPending(error);
    await stopWorker(coordinator); disposeResolve?.();
  }
  listen(coordinator, report => {
    if (report.type === "fatal") { void failAll(new PaludariumError(report.error.kind, report.error.message)); return; }
    if (report.type === "ready") { clearTimeout(initTimer); readyResolve(report); return; }
    if (report.type === "disposed") { clearTimeout(disposeTimer); void stopWorker(coordinator).then(() => disposeResolve?.()); return; }
    const job = pending.get(report.id);
    if (!job) { if (report.type === "failed" && report.id === undefined) void failAll(new PaludariumError(report.error.kind, report.error.message)); return; }
    if (report.type === "output") job[report.stream]?.enqueue(report.bytes);
    else if (report.type === "finished" || report.type === "failed") {
      clearTimeout(job.timer); pending.delete(report.id);
      if (report.type === "failed") { const error = new PaludariumError(report.error.kind, report.error.message, report.error); job.stdout?.error(error); job.stderr?.error(error); job.reject(error); }
      else { job.stdout?.close(); job.stderr?.close(); job.resolve(report.status); }
    } else if (report.type === "diagnostics") { pending.delete(report.id); clearTimeout(job.timer); job.resolve(report.diagnostics); }
    else if (report.type === "control") { pending.delete(report.id); job.resolve(report.value); }
  }, cause => void failAll(new PaludariumError("internal", String(cause))));
  coordinator.postMessage({ type: "init", module, memory });
  await ready;
  return {
    async createFileSystem(options = {}) {
      validate({ ...options, program: "/" });
      const entries = entryPlan(options);
      const handle = await control("filesystem-new", { options: { ...options, entries } });
      let disposed = false, filesystemDisposal;
      const available = () => { if (disposed) throw new PaludariumError("host", "Filesystem is disposed"); };
      const filesystem = Object.freeze({
        async snapshot() { available(); return decodeSnapshot(await control("filesystem-snapshot", { handle })); },
        async remove(path, { recursive = false } = {}) {
          available();
          if (typeof path !== "string" || !path.startsWith("/") || path.includes("\0") || typeof recursive !== "boolean") throw new PaludariumError("invalid-program", "invalid filesystem removal");
          await control("filesystem-remove", { handle, path, recursive });
        },
        async dispose() {
          if (disposed) return;
          // A single drop owns the handle; concurrent callers share its result.
          filesystemDisposal ??= control("filesystem-drop", { handle }).then(() => {
            disposed = true; filesystems.delete(filesystem);
          }).finally(() => { filesystemDisposal = undefined; });
          await filesystemDisposal;
        },
      });
      filesystems.set(filesystem, handle); return filesystem;
    },
    run(options) {
      validate(options);
      const entries = entryPlan(options);
      if (closed) throw new PaludariumError("host", "Launcher is closed");
      const id = next++, job = {};
      const stdout = new ReadableStream({ start(controller) { job.stdout = controller; }, cancel() { job.stdout = null; } });
      const stderr = new ReadableStream({ start(controller) { job.stderr = controller; }, cancel() { job.stderr = null; } });
      const exited = new Promise((resolve, reject) => { job.resolve = resolve; job.reject = reject; });
      // Guest deadlines belong to the caller/test supervisor. kill() requests
      // a cooperative stop; dispose() retains its bounded resource cleanup.
      pending.set(id, job);
      const { filesystem, ...messageOptions } = options;
      messageOptions.entries = entries;
      if (filesystem !== undefined) {
        const handle = filesystems.get(filesystem);
        if (!handle) { pending.delete(id); throw new PaludariumError("invalid-program", "filesystem belongs to another launcher"); }
        messageOptions.filesystemHandle = handle;
      }
      coordinator.postMessage({ type: "run", id, options: messageOptions });
      const stdin = new WritableStream({
        start(controller) { job.stdin = controller; },
        write(bytes) { if (!(bytes instanceof Uint8Array)) throw new TypeError("stdin requires Uint8Array"); if (closed || !pending.has(id)) throw new PaludariumError("host", "Guest input is closed"); coordinator.postMessage({ type: "stdin", id, bytes }); },
        close() { if (!closed) coordinator.postMessage({ type: "stdin-close", id }); },
        abort() { if (!closed) coordinator.postMessage({ type: "kill", id }); },
      });
      return { stdin, stdout, stderr, exited, kill() { if (!closed) coordinator.postMessage({ type: "kill", id }); } };
    },
    diagnostics() {
      if (closed) return Promise.reject(new PaludariumError("host", "Launcher is closed"));
      const id = next++;
      return new Promise((resolve, reject) => { const timer = setTimeout(() => void failAll(new PaludariumError("host", "diagnostics watchdog")), 30000); pending.set(id, { resolve, reject, timer }); coordinator.postMessage({ type: "diagnostics", id }); });
    },
    async dispose() {
      if (disposal) return disposal;
      if (closed) return;
      closed = true;
      rejectPending(new PaludariumError("host", "Launcher disposed"));
      disposal = new Promise(resolve => {
        disposeResolve = resolve;
        coordinator.postMessage({ type: "dispose" });
        // Graceful kill gets one second; forced termination discards this entire heap.
        disposeTimer = setTimeout(() => void failAll(new PaludariumError("host", "Launcher disposal watchdog")), 1000);
      });
      return disposal;
    },
  };
}
