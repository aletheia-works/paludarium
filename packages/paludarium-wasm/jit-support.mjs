// Synchronous compiler/executor owned by one existing guest Worker. Pointers
// address trusted Rust scratch buffers, never guest virtual memory.
export const COST_FIELDS = [
  "hookAttempts", "checkpoints", "cacheHits", "negativeHits", "cacheMisses", "epochInvalidations",
  "lruUpdates", "snapshotBytes", "translatedBlocks", "executedBlocks", "executedInstructions", "fallbacks",
  "prepareCalls", "executeCalls", "compileAttempts", "compileNanoseconds", "jsTransitions",
  "comparisonBytesUpperBound", "codeBytesCopied", "stateBytesCopied", "prepareRejections", "executeRejections",
  "interpreterSteps", "budgetCharged", ...Array.from({ length: 64 }, (_, i) => `blockLength${i + 1}`),
  "observationLookups", "observationBytes", "nextPositive", "nextPrepared", "nextMissing",
  "nextNegative", "nextEpoch", "nextUnprepared", "nextUnavailable", "chainLength1", "chainLength2",
  "chainLength3", "chainLength4to7", "chainLength8plus", "stopUnsupported", "stopNegative",
  "stopFallback", "stopEpoch", "stopBudget", "stopExit", "stopKill",
  "siteObserved", "siteDropped", "decodeHintHit", "decodeSlotEmpty", "decodeSlotRipCollision",
  "decodeSlotEpochStale", "decodedHit", "coldSnapshots", "coldExtracts", "coldEmits", "warmExecutions",
];
export function costSnapshot(exports) {
  if (typeof exports.cost_version !== "function") return null;
  if (exports.cost_version() !== 3 || exports.cost_fields() !== COST_FIELDS.length
    || typeof exports.cost_site_count !== "function" || typeof exports.cost_site_stat !== "function") throw Error("Diagnostic ABI mismatch");
  const count = exports.cost_site_count();
  if (!Number.isInteger(count) || count < 0 || count > 16384) throw Error("Diagnostic site capacity mismatch");
  const rows = Array.from({length:count}, (_,i) => {
    const get = field => exports.cost_site_stat(i,field);
    const length = Number(get(5)), truncated = get(6);
    if (!Number.isInteger(length) || length < 0 || length > 256 || ![0n,1n].includes(truncated)) throw Error("Diagnostic site descriptor mismatch");
    return {space:String(get(0)),epoch:String(get(1)),rip:String(get(2)),classification:String(get(3)),count:String(get(4)),
      descriptor:String.fromCharCode(...Array.from({length},(_,j)=>Number(get(7+j)))),truncated:truncated===1n};
  });
  return { schema: 3, purpose: "cost-profile", overflow: exports.cost_overflow() !== 0,
    sites:{capacity:16384,retainedOnly:true,rows},
    counters: Object.fromEntries(COST_FIELDS.map((name, index) => [name, String(exports.cost_stat(index))])) };
}
// Rust scratch state (paludarium_jit::STATE_BYTES): GPR0..15, RFLAGS, RIP as
// u64 words (144 bytes), then XMM0..15 as 16-byte little-endian lanes.
export const JIT_STATE_BYTES = 400;
export function jitImports(memory, cost = null, now = () => performance.now()) {
  const compiled = new Map();
  const rollback = new Uint8Array(JIT_STATE_BYTES);
  const equalBytes = (stored, view) => {
    if (stored.length !== view.length) return false;
    for (let i = 0; i < view.length; i++) if (stored[i] !== view[i]) return false;
    return true;
  };
  let running = false;
  const range = (pointer, length) => Number.isInteger(pointer) && pointer > 0
    && Number.isInteger(length) && length > 0 && pointer + length <= memory.buffer.byteLength;
  return {
    prepare(key, codePointer, codeLength) {
      if (running || !Number.isInteger(key) || key <= 0 || codeLength > 65536
          || !range(codePointer, codeLength)) return -1;
      const view = new Uint8Array(memory.buffer, codePointer, codeLength);
      try {
        const entry = compiled.get(key);
        if (entry) {
          if (cost) cost(17, view.length);
          if (!equalBytes(entry.bytes, view)) return -1;
          compiled.delete(key); compiled.set(key, entry);
          return 0;
        }
        const bytes = view.slice();
        if (cost) cost(18, bytes.length);
        const started = cost ? now() : 0;
        let instance;
        try {
          const module = new WebAssembly.Module(bytes);
          instance = new WebAssembly.Instance(module, { env: { memory } });
        } finally {
          if (cost) { cost(14, 1); cost(15, Math.round(Math.max(0, now() - started) * 1e6)); }
        }
        if (typeof instance.exports.run !== "function") return -1;
        if (compiled.size >= 1024) compiled.delete(compiled.keys().next().value);
        compiled.set(key, { bytes, run: instance.exports.run });
        return 0;
      } catch { return -1; }
    },
    execute(key, codePointer, codeLength, statePointer, stateLength) {
      // Diagnostic-only query: never prepare, run, evict, touch recency, or
      // access scratch. Ordinary imports reject this sentinel below.
      if (cost && statePointer === 0 && stateLength === 0) {
        if (running || !Number.isInteger(key) || key <= 0 || codeLength > 65536
            || !range(codePointer, codeLength)) return -1;
        cost(88, 1);
        const entry = compiled.get(key);
        if (!entry) return -2;
        const bytes = new Uint8Array(memory.buffer, codePointer, codeLength);
        cost(89, bytes.length);
        return equalBytes(entry.bytes, bytes) ? 0 : -1;
      }
      if (running || !Number.isInteger(key) || key <= 0 || codeLength > 65536
          || stateLength !== JIT_STATE_BYTES || !range(codePointer, codeLength) || !range(statePointer, stateLength)) return -1;
      // A module ID is allocated in shared Rust and never reused. Each Worker
      // separately compiles it; JS objects/handles never cross Worker boundaries.
      const entry = compiled.get(key);
      if (!entry) return -2;
      const bytes = new Uint8Array(memory.buffer, codePointer, codeLength);
      if (cost) cost(17, bytes.length);
      if (!equalBytes(entry.bytes, bytes)) return -1;
      running = true;
      try {
        rollback.set(new Uint8Array(memory.buffer, statePointer, stateLength));
        if (cost) cost(19, stateLength);
        compiled.delete(key); compiled.set(key, entry);
        try {
          if (entry.run(statePointer) !== 0) throw new Error("JIT result rejected");
          return 0;
        } catch {
          new Uint8Array(memory.buffer, statePointer, stateLength).set(rollback);
          compiled.delete(key);
          return -1;
        }
      } finally { running = false; }
    },
  };
}
