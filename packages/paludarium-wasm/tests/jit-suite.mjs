import { runSuite } from "./wasm-suite.mjs";

export function requireJitProof(row) {
  if (row.pass === true && (!row.jit || BigInt(row.jit.executedBlocks) <= 0n || BigInt(row.jit.executedInstructions) <= 0n)) {
    row.pass = false; row.jit_error = "No translated instruction execution proved";
  }
  return row;
}

// Identical 14 cases, fixture state, masks and deadline for both execution modes.
export async function runJitSuite(input) {
  const modes = {};
  for (const jit of [false, true]) {
    const mode = jit ? "jit" : "interpreter";
    const result = await runSuite({ ...input, jit, onRow: async (name, row) => {
      if (jit) requireJitProof(row);
      await input.onRow?.(mode, name, row);
    } });
    modes[mode] = result;
  }
  return { modes, complete: Object.values(modes).every(mode => mode.complete),
           passed: Object.values(modes).every(mode => mode.passed), caseCount: 28 };
}
