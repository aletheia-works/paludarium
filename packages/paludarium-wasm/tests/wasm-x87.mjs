// The x87 cases of the process tests, run in one wasm environment and
// compared byte for byte with what the same guest printed on x86-64 Linux.
import { observeProgram } from "./wasm-programs.mjs";
export async function observeX87(launch, { x87, cases, native, onRow = () => {} }) {
  if (Object.keys(native.rows).join() !== cases.join()) throw new Error("Unexpected native x87 inventory");
  const rows = {};
  for (const name of cases) {
    const launcher = await launch();
    try {
      const row = await observeProgram(launcher, { program: "/x87", args: ["/x87", name], env: {}, files: { "/x87": x87 } });
      const expected = native.rows[name];
      try {
        if (row.timed_out || row.errors.length) throw new Error("Guest operation timed out or failed");
        for (const key of ["exit", "stdout", "stderr"]) if (row[key] !== expected[key]) throw new Error(`${key} mismatch`);
        row.pass = true;
      } catch (cause) { row.pass = false; row.comparison_error = String(cause); }
      row.native_seconds = expected.seconds;
      rows[name] = row; await onRow(name, row);
    } finally { await launcher.dispose(); }
  }
  return rows;
}
