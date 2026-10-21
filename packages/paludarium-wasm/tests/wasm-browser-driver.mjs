// Actual Safari uses Apple's WebDriver; Chromium/Firefox reuse pinned Playwright.
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

export async function webdriverRequest(base, method, path, body, timeoutMs = 10000) {
  const response = await fetch(base + path, { method, headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) });
  const payload = await response.json();
  if (!response.ok || !Object.hasOwn(payload, 'value') || payload.value?.error) throw new Error(`WebDriver ${method} ${path}: ${JSON.stringify(payload.value)}`);
  return payload.value;
}

async function stopDriver(driver) {
  if (driver.exitCode !== null || driver.signalCode !== null) return;
  const stopped = new Promise(resolve => driver.once("exit", resolve));
  driver.kill("SIGTERM");
  const force = setTimeout(() => driver.kill("SIGKILL"), 1000);
  try { await stopped; } finally { clearTimeout(force); }
}

// The one safaridriver failure that is retried (NFR7): on a fresh macOS runner, session creation can fail while
// safaridriver waits for its first Safari launch, e.g. run 39114110570 attempt 1:
// {"error":"session not created","message":"Could not create a session: The session timed out while connecting to a Safari instance. ..."}
export function isSafariLaunchTimeout(error) {
  const text = String(error?.cause ?? error);
  return error?.phase === "session-creation" && text.includes('"error":"session not created"')
    && text.includes("timed out while connecting to a Safari instance");
}

// Stop any Safari left by the failed attempt before the single retry: SIGTERM by exact process name, bounded to 10 s.
async function stopSafari() {
  const killer = spawn("/usr/bin/pkill", ["-x", "Safari"], { stdio: "ignore" });
  const exited = new Promise(resolve => { killer.once("exit", (code, signal) => resolve({ code, signal })); killer.once("error", error => resolve({ error: String(error) })); });
  const bound = setTimeout(() => killer.kill("SIGKILL"), 10000);
  try { return await exited; } finally { clearTimeout(bound); }
}

const RETRY_PAUSE_MS = 2000;

async function safari(url, timeout) {
  let first;
  try {
    const result = await safariAttempt(url, timeout);
    return { ...result, session_retry: { attempts: 1, retried: false, first_failure: null } };
  } catch (error) {
    if (!isSafariLaunchTimeout(error)) throw error;
    first = error;
  }
  const stopped = await stopSafari();
  // Logged, never hidden: the first failure goes to stderr (kept by the suite supervisor) and into the result.
  console.error(JSON.stringify({ safari_session_retry: { attempt: 1, failure: first.message, safari_stopped: stopped } }));
  await sleep(RETRY_PAUSE_MS);
  try {
    const result = await safariAttempt(url, timeout);
    return { ...result, session_retry: { attempts: 2, retried: true, first_failure: first.message, safari_stopped: stopped } };
  } catch (error) {
    error.message += `; first attempt (retried once): ${first.message}`;
    error.firstFailure = first;
    throw error;
  }
}

async function safariAttempt(url, timeout) {
  const port = 4455, base = `http://127.0.0.1:${port}`;
  const driver = spawn("/usr/bin/safaridriver", ["--port", String(port)], { stdio: ["ignore", "pipe", "pipe"] });
  let driverError, sessionId, log = "", phase = "driver-startup", failure;
  driver.on("error", error => { driverError = error; });
  for (const stream of [driver.stdout, driver.stderr]) stream.on("data", bytes => { log = (log + bytes.toString()).slice(-8192); });
  try {
    const startup = Date.now() + 10000;
    for (;;) {
      if (driverError) throw driverError;
      if (driver.exitCode !== null || driver.signalCode !== null) throw new Error(`Safari driver exited: ${driver.exitCode ?? driver.signalCode}; ${log}`);
      try { await webdriverRequest(base, "GET", "/status"); break; }
      catch (error) { if (Date.now() >= startup) throw error; await sleep(100); }
    }
    phase = "session-creation";
    const session = await webdriverRequest(base, "POST", "/session", { capabilities: { alwaysMatch: { browserName: "safari" } } }, 60000);
    sessionId = session.sessionId;
    if (!sessionId) throw new Error("Safari did not return a session ID");
    phase = "navigation";
    await webdriverRequest(base, "POST", `/session/${sessionId}/url`, { url });
    phase = "script-report";
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const report = await webdriverRequest(base, "POST", `/session/${sessionId}/execute/sync`, { script: "return window.__wasmReport || null;", args: [] });
      if (report) return { environment: "safari", version: session.capabilities?.browserVersion ?? "unknown", ...report };
      await sleep(100);
    }
    throw new Error("Safari page report exceeded external suite deadline");
  } catch (cause) {
    failure = new Error(`Safari ${phase}: ${cause}; driver exit=${driver.exitCode}, signal=${driver.signalCode}, log=${log}`, { cause });
    failure.phase = phase;
    throw failure;
  } finally {
    let cleanupError;
    try { if (sessionId) await webdriverRequest(base, "DELETE", `/session/${sessionId}`); }
    catch (error) { cleanupError = error; }
    await stopDriver(driver);
    if (cleanupError) {
      if (failure) failure.message += `; cleanup: ${cleanupError}`;
      else throw new Error(`Safari cleanup: ${cleanupError}`);
    }
  }
}

export async function runBrowser(name, url, timeout = 600000) {
  if (!Number.isFinite(timeout) || timeout <= 0 || timeout > 1200000) throw new Error("Invalid external browser deadline");
  if (name === "safari") return safari(url, timeout);
  if (!["chromium", "firefox"].includes(name)) throw new Error("Unsupported actual browser");
  const playwright = await import("../../../spikes/wasm-threads/node_modules/playwright/index.mjs");
  const browser = await playwright[name].launch({ timeout: 30000 });
  try {
    const page = await browser.newPage();
    await page.goto(url, { timeout: 30000 });
    await page.waitForFunction(() => window.__wasmReport !== undefined, null, { timeout });
    const report = await page.evaluate(() => window.__wasmReport);
    return { environment: name, version: browser.version(), ...report };
  } finally { await browser.close(); }
}
