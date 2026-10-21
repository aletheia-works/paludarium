// Bounded diagnostic only; never substitutes for the 28-case acceptance suite.
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { createPaludarium } from "../index.mjs";
import { observeProgram } from "./wasm-programs.mjs";
const [module, probePath, name, output] = process.argv.slice(2);
const launcher = await createPaludarium({ wasmUrl: pathToFileURL(module).href });
const probe = new Uint8Array(await readFile(probePath));
let diagnostics;
const timer = setTimeout(async () => { try { diagnostics = await launcher.diagnostics(); } catch (error) { diagnostics = { error: String(error) }; } }, 25000);
try {
  const row = await observeProgram(launcher, { program: "/probe", args: ["/probe", name],
    env: { PATH: "/no-node", HOME: "/home/guest", TMPDIR: "/tmp", NO_COLOR: "1", TERM: "dumb", LANG: "C", LC_ALL: "C", TZ: "UTC" },
    files: { "/probe": probe, "/home/guest/.keep": new Uint8Array() }, jit: true });
  try { diagnostics = await launcher.diagnostics(); } catch (error) { row.diagnostics_error = String(error); }
  await mkdir(output, { recursive: true });
  const result = { name, row, diagnostics };
  await writeFile(output + "/observations.json", JSON.stringify(result, null, 2) + "\n");
  console.log(JSON.stringify({ name, seconds: row.seconds, timed_out: row.timed_out, exit: row.exit, errors: row.errors, workers: diagnostics?.workers }));
  if (row.timed_out || row.exit !== 0 || row.errors.length) process.exitCode = 1;
} finally { clearTimeout(timer); await launcher.dispose(); }
