// coreutils' fixture files by their path from coreutils-fixture, as Node reads them.
import { readdir, readFile } from "node:fs/promises";

export async function readCoreutilsFixture(directory = "tests/guests/programs/coreutils-fixture") {
  const fixture = {};
  for (const entry of (await readdir(directory, { recursive: true, withFileTypes: true })).filter(entry => entry.isFile())) {
    const relative = (entry.parentPath + "/" + entry.name).slice(directory.length + 1).replaceAll("\\", "/");
    fixture[relative] = new Uint8Array(await readFile(directory + "/" + relative));
  }
  return Object.fromEntries(Object.entries(fixture).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
}
