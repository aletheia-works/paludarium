// U6's Node entry point shares checks.mjs with the actual Safari page.
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { runChecks } from "./checks.mjs";

const args = process.argv.slice(2);
function option(name) {
  const index = args.indexOf(name);
  if (index < 0 || !args[index + 1]) throw new Error(`missing ${name}`);
  return args[index + 1];
}
const wasmPath = option("--wasm"), nativePath = option("--native");
const watchdog = setTimeout(() => { console.error("U6 production Worker watchdog expired"); process.exit(1); }, 30000);
try {
  const native = JSON.parse(await readFile(nativePath, "utf8"));
  const u6 = native.filter(row => row.name.startsWith("u6-"));
  const expected = new Set([...Array.from({ length: 82 }, (_, n) => n).filter(n => n !== 66).map(n => `u6-${n}`), "u6-unix"]);
  if (u6.length !== 82 || u6.some(row => !expected.delete(row.name)) || expected.size !== 0) throw new Error("U6 nonthreaded catalog must contain 0..81 excluding 66 plus unix exactly once");
  const report = await runChecks({ wasmUrl: pathToFileURL(wasmPath), native, readGuest: name => readFile(new URL(`guests/${name}`, import.meta.url)) });
  if (report.caseCount !== 102 || report.results.filter(row => row.case.startsWith("u6-")).length !== 82) throw new Error("U6 production suite must contain 102 finite cases");
  console.log(JSON.stringify({ unit: "u6-events-sockets", environment: "Node Worker", version: process.version, ...report }));
} catch (error) { console.error(error); process.exitCode = 1; }
finally { clearTimeout(watchdog); }
