// Fixed ten paired observations; no retries, exclusions, or post-hoc ordering.
import { createPaludarium } from "../index.mjs";
import { compare, observeProgram } from "./wasm-programs.mjs";
export const PERFORMANCE_SEED = 0x14c9;
export function schedule() {
  const order = [false, false, false, false, false, true, true, true, true, true];
  let state = PERFORMANCE_SEED;
  for (let i = order.length - 1; i > 0; i--) {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    const j = (state >>> 0) % (i + 1);
    [order[i], order[j]] = [order[j], order[i]];
  }
  return order.map((first, pair) => ({ pair, modes: [first, !first] }));
}
export function validateSchedule(rows) {
  const expected = schedule().flatMap(pair => pair.modes.map(jit => ({pair: pair.pair, jit})));
  if (rows.length !== expected.length || rows.some((row, i) => row.pair !== expected[i].pair || row.jit !== expected[i].jit)) {
    throw new Error("Performance execution differs from frozen schedule");
  }
}
export function evaluate(rows) {
  if (rows.length !== 20) throw new Error("Exactly twenty observations required");
  const pairs = new Map();
  for (const row of rows) {
    if (!Number.isInteger(row.pair) || row.pair < 0 || row.pair >= 10 || typeof row.jit !== "boolean"
        || !Number.isFinite(row.seconds) || row.seconds <= 0 || row.seconds > 30
        || row.pass !== true || row.timed_out !== false || row.exit !== 0 || !Array.isArray(row.errors) || row.errors.length
        || (row.jit && (!row.statistics || BigInt(row.statistics.executedBlocks) <= 0n
            || BigInt(row.statistics.executedInstructions) <= 0n))) throw new Error("Invalid performance observation");
    const pair = pairs.get(row.pair) ?? {};
    const key = row.jit ? "jit" : "interpreter";
    if (Object.hasOwn(pair, key)) throw new Error("Duplicate performance observation");
    pair[key] = row.seconds; pairs.set(row.pair, pair);
  }
  const differences = Array.from({ length: 10 }, (_, i) => {
    const pair = pairs.get(i);
    if (!pair || !Object.hasOwn(pair, "jit") || !Object.hasOwn(pair, "interpreter")) throw new Error("Missing pair");
    return pair.interpreter - pair.jit;
  });
  const observed = differences.reduce((sum, value) => sum + value, 0);
  let extreme = 0;
  for (let mask = 0; mask < 1024; mask++) {
    const permuted = differences.reduce((sum, value, i) => sum + ((mask & (1 << i)) ? value : -value), 0);
    // Include ties in the one-sided tail; zero differences yield p=1.
    if (permuted >= observed) extreme++;
  }
  const mean = jit => rows.filter(row => row.jit === jit).reduce((sum, row) => sum + row.seconds, 0) / 10;
  return { meanInterpreter: mean(false), meanJit: mean(true), differences,
    signFlips: 1024, extreme, p: extreme / 1024, pass: mean(true) < mean(false) && extreme / 1024 < 0.05 };
}
export async function measure({ wasmUrl, probe, oracle, onObservation }) {
  const rows = [], warmups = [];
  async function observe(jit, pair, warmup) {
    const prepared = performance.now();
    const launcher = await createPaludarium({ wasmUrl });
    try {
      await launcher.diagnostics();
      const preparationSeconds = (performance.now() - prepared) / 1000;
      const row = await observeProgram(launcher, { program: "/probe", args: ["/probe"],
        env: oracle.case_config.environment, files: { "/probe": probe, "/home/guest/.keep": new Uint8Array() }, jit });
      if (jit && !row.timed_out) {
        try { row.statistics = (await launcher.diagnostics()).workers.filter(worker => !worker.guestThread).at(-1)?.jit; }
        catch (error) { row.diagnostics_error = String(error); }
      }
      try { compare(oracle.rows["probe-all"], row, oracle.fixture_root); row.pass = true; }
      catch (error) { row.pass = false; row.error = String(error); }
      Object.assign(row, { pair, jit, warmup, preparationSeconds });
      (warmup ? warmups : rows).push(row);
      await onObservation?.({ rows, warmups, last: row });
    } finally { await launcher.dispose(); }
  }
  await observe(false, -1, true); await observe(true, -1, true);
  for (const pair of schedule()) for (const jit of pair.modes) await observe(jit, pair.pair, false);
  validateSchedule(rows);
  const result = evaluate(rows);
  const warmupsPassed = warmups.every(row => row.pass && row.exit === 0 && !row.timed_out
    && (!row.jit || (row.statistics && BigInt(row.statistics.executedBlocks) > 0n && BigInt(row.statistics.executedInstructions) > 0n)));
  result.pass = result.pass && warmupsPassed;
  return { seed: PERFORMANCE_SEED, schedule: schedule(), warmupPerMode: 1, rows, warmups, warmupsPassed, result };
}
