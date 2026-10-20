/**
 * Copies the files the live demo serves as they are into public/:
 * - @aletheia-works/paludarium-wasm (its Workers are started from paths
 *   relative to its own modules, so they must not be bundled), and
 * - coi-serviceworker, which adds the COOP/COEP headers that
 *   SharedArrayBuffer needs on hosts such as GitHub Pages.
 */
import { copyFile, mkdir, readdir, rm } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const docs = join(dirname(fileURLToPath(import.meta.url)), '..')
const modules = join(docs, 'node_modules')
const wasmPackage = join(modules, '@aletheia-works/paludarium-wasm')
const target = join(docs, 'public/paludarium')

await rm(target, { recursive: true, force: true })
await mkdir(target, { recursive: true })
const files = (await readdir(wasmPackage)).filter((name) => name.endsWith('.mjs') || name === 'paludarium.wasm')
if (!files.includes('paludarium.wasm') || !files.includes('index.mjs')) {
  throw new Error(`${wasmPackage} does not hold paludarium.wasm and index.mjs`)
}
for (const name of files) await copyFile(join(wasmPackage, name), join(target, name))
await copyFile(join(modules, 'coi-serviceworker/coi-serviceworker.min.js'), join(docs, 'public/coi-serviceworker.js'))
console.log(`staged ${files.length} paludarium-wasm files and coi-serviceworker`)
