// Browser runner of the wasm thread check. Serves the page with
// COOP/COEP, opens it in the requested browsers and prints one
// WasmThreadReport (JSON) per browser. Exits 1 if any browser fails.
//
//   node spikes/wasm-threads/browser-check.mjs chromium firefox
//   node spikes/wasm-threads/browser-check.mjs safari      (macOS)
//
// Chromium and Firefox are driven by Playwright. Safari is the real Safari,
// driven through Apple's safaridriver (WebDriver), never a WebKit build.
// Run `safaridriver --enable` once on the
// Mac (CI does this) before using it.

import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

import { startServer } from "./serve.mjs";

const PORT = Number(process.env.WASM_CHECK_PORT ?? 8787);
const URL_ = `http://127.0.0.1:${PORT}/`;
const RESULT_WAIT_MS = 15000;

async function viaPlaywright(name) {
  const playwright = await import("playwright");
  const browser = await playwright[name].launch();
  try {
    const page = await browser.newPage();
    await page.goto(URL_);
    await page.waitForFunction(() => window.__wasmThreadReport !== undefined, null, {
      timeout: RESULT_WAIT_MS,
    });
    const report = await page.evaluate(() => window.__wasmThreadReport);
    return { environment: name, version: browser.version(), ...report };
  } finally {
    await browser.close();
  }
}

async function webdriver(base, method, path, body) {
  const response = await fetch(base + path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await response.json();
  if (!response.ok) {
    throw new Error(`WebDriver ${method} ${path}: ${JSON.stringify(json)}`);
  }
  return json.value;
}

async function viaSafariDriver() {
  const port = 4444;
  const driver = spawn("safaridriver", ["--port", String(port)], { stdio: "ignore" });
  const base = `http://127.0.0.1:${port}`;
  try {
    for (let i = 0; i < 50; i++) {
      try {
        await fetch(`${base}/status`);
        break;
      } catch {
        await sleep(200);
      }
    }
    const session = await webdriver(base, "POST", "/session", {
      capabilities: { alwaysMatch: { browserName: "safari" } },
    });
    const id = session.sessionId;
    try {
      await webdriver(base, "POST", `/session/${id}/url`, { url: URL_ });
      const deadline = Date.now() + RESULT_WAIT_MS;
      while (Date.now() < deadline) {
        const report = await webdriver(base, "POST", `/session/${id}/execute/sync`, {
          script: "return window.__wasmThreadReport || null;",
          args: [],
        });
        if (report) {
          const version = session.capabilities?.browserVersion ?? "unknown";
          return { environment: "safari", version, ...report };
        }
        await sleep(250);
      }
      return { environment: "safari", version: "unknown", crossOriginIsolated: false, waitNotifyPassed: false, notes: "no result before timeout" };
    } finally {
      await webdriver(base, "DELETE", `/session/${id}`).catch(() => {});
    }
  } finally {
    driver.kill();
  }
}

const browsers = process.argv.slice(2);
if (browsers.length === 0) {
  console.error("usage: browser-check.mjs <chromium|firefox|safari>...");
  process.exit(2);
}
const server = await startServer(PORT);
let failed = false;
try {
  for (const name of browsers) {
    let report;
    try {
      report = name === "safari" ? await viaSafariDriver() : await viaPlaywright(name);
    } catch (error) {
      report = { environment: name, version: "unknown", crossOriginIsolated: false, waitNotifyPassed: false, notes: String(error) };
    }
    console.log(JSON.stringify(report));
    failed ||= !report.waitNotifyPassed;
  }
} finally {
  server.close();
}
process.exit(failed ? 1 : 0);
