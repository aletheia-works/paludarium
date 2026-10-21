import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
export const population = ['index.mjs', 'coordinator.mjs', 'execution.mjs', 'worker-support.mjs', 'filesystem-snapshot.mjs', 'jit-support.mjs'];
// Conservatively count every nonempty non-comment-only line, including braces.
// V8 offsets are UTF-16 offsets, as are JavaScript string indices.
export function lines(source, scripts) {
  let offset = 0;
  let comment = false;
  return source.split('\n').flatMap((line, index) => {
    const start = offset; offset += line.length + 1;
    const trimmed = line.trim();
    let code = line;
    if (comment) {
      const end = code.indexOf('*/');
      if (end < 0) return [];
      code = code.slice(end + 2); comment = false;
    }
    while (code.includes('/*')) {
      const begin = code.indexOf('/*');
      const end = code.indexOf('*/', begin + 2);
      if (end < 0) { code = code.slice(0, begin); comment = true; break; }
      code = code.slice(0, begin) + code.slice(end + 2);
    }
    if (!code.trim() || code.trim().startsWith('//')) return [];
    const positions = [];
    for (let i = 0; i < line.length; i++) if (!/\s/.test(line[i])) positions.push(start + i);
    const hit = scripts.some(script => positions.some(position => {
      // Each function is independent; nested uncalled functions must not inherit
      // the containing module's execution count.
      const candidates = script.functions.flatMap(fn => fn.ranges)
        .filter(range => range.startOffset <= position && position < range.endOffset);
      if (!candidates.length) return false;
      const narrowest = candidates.reduce((a, b) =>
        a.endOffset - a.startOffset <= b.endOffset - b.startOffset ? a : b);
      return narrowest.count > 0;
    }));
    return [{ line: index + 1, hit }];
  });
}
export async function aggregate(rawDirectory, root) {
  const scripts = [];
  const raw_files = [];
  const digest = bytes => createHash('sha256').update(bytes).digest('hex');
  for (const name of await readdir(rawDirectory)) {
    if (!name.endsWith('.json')) continue;
    const bytes = await readFile(resolve(rawDirectory, name));
    const result = JSON.parse(bytes).result;
    if (!Array.isArray(result)) throw new Error('Malformed V8 result');
    raw_files.push({name, sha256: digest(bytes)});
    scripts.push(...result);
  }
  const files = [];
  for (const name of population) {
    const path = resolve(root, 'packages/paludarium-wasm', name);
    const matched = scripts.filter(script => script.url.startsWith('file:') && fileURLToPath(script.url) === path);
    const source = await readFile(path, 'utf8');
    const measured = lines(source, matched);
    files.push({ path: `packages/paludarium-wasm/${name}`, source_sha256: digest(source), raw_scripts: matched.length,
      lines: measured.length, hit: measured.filter(line => line.hit).length, measured });
  }
  const total = files.reduce((sum, file) => ({ lines: sum.lines + file.lines, hit: sum.hit + file.hit }), { lines: 0, hit: 0 });
  return { population, raw_files, definition: 'all nonempty non-comment-only lines, including structural lines; narrowest V8 range, merged across processes and Workers', files, total,
    passed: files.every(file => file.raw_scripts > 0 && file.lines > 0) && total.hit / total.lines >= 0.8 };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [raw, output] = process.argv.slice(2);
  const report = await aggregate(raw, process.cwd());
  await writeFile(output, JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ total: report.total, passed: report.passed }));
  if (!report.passed) process.exitCode = 1;
}
