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

// The safaridriver failures that are retried, both of session creation while safaridriver launches Safari on
// a fresh macOS runner: it times out waiting for that launch, e.g. run 39114110570 attempt 1:
// {"error":"session not created","message":"Could not create a session: The session timed out while connecting to a Safari instance. ..."}
// or the launched Safari never becomes ready, e.g. run 43576635510 attempt 1 (4 such runs in 2026-11-08..14):
// {"error":"session not created","message":"Could not create a session: The host application never became ready, unable to create a WebDriver session."}
const SAFARI_LAUNCH_FAILURES = ["timed out while connecting to a Safari instance", "The host application never became ready"];
export function isSafariLaunchFailure(error) {
  const text = String(error?.cause ?? error);
  return error?.phase === "session-creation" && text.includes('"error":"session not created"')
    && SAFARI_LAUNCH_FAILURES.some(failure => text.includes(failure));
}

// Stop any Safari left by the failed attempt before the single retry: SIGTERM by exact process name, bounded to 10 s.
async function stopSafari() {
  const killer = spawn("/usr/bin/pkill", ["-x", "Safari"], { stdio: "ignore" });
  const exited = new Promise(resolve => { killer.once("exit", (code, signal) => resolve({ code, signal })); killer.once("error", error => resolve({ error: String(error) })); });
  const bound = setTimeout(() => killer.kill("SIGKILL"), 10000);
  try { return await exited; } finally { clearTimeout(bound); }
}

const RETRY_PAUSE_MS = 2000;

// A Safari that was told to quit (the CI warm-up's, or an earlier session's) may still be exiting when the next
// session is asked for; safaridriver then attaches to it as it goes, which is one way its "host application never
// became ready". Before a session, wait until no Safari process is left, polled with `pgrep -x Safari` and bounded:
// past the bound the session is asked for anyway, and the log says so. The tests shorten the bound.
export const safariExit = { waitMs: 15000, pollMs: 250 };
function safariRunning() {
  const probe = spawn("/usr/bin/pgrep", ["-x", "Safari"], { stdio: "ignore" });
  return new Promise(resolve => {
    probe.once("exit", code => resolve(code === 0));
    probe.once("error", () => resolve(false));
  });
}
async function untilSafariExited() {
  const start = Date.now();
  let polls = 0;
  while (await safariRunning()) {
    polls += 1;
    const waited = Date.now() - start;
    if (waited >= safariExit.waitMs) return { exited: false, waited_ms: waited, polls };
    await sleep(safariExit.pollMs);
  }
  return { exited: true, waited_ms: Date.now() - start, polls };
}

async function safari(url, timeout) {
  let first;
  const started = Date.now();
  try {
    const result = await safariAttempt(url, timeout);
    return { ...result, session_retry: { attempts: 1, retried: false, first_failure: null } };
  } catch (error) {
    if (!isSafariLaunchFailure(error)) throw error;
    first = error;
  }
  const failedAfter = Date.now() - started;
  const stopped = await stopSafari();
  // Logged, never hidden: the first failure goes to stderr (kept by the suite supervisor) and into the result,
  // with when it came and how long the attempt took, so how often it happens can be counted from the logs.
  const retry = { attempt: 1, failure: first.message, at: new Date().toISOString(), failed_after_ms: failedAfter,
    session_requested_after_ms: first.sessionRequestedAfter ?? null, safari_exit_wait: first.safariExitWait ?? null,
    safari_stopped: stopped, pause_ms: RETRY_PAUSE_MS };
  console.error(JSON.stringify({ safari_session_retry: retry }));
  await sleep(RETRY_PAUSE_MS);
  try {
    const result = await safariAttempt(url, timeout);
    return { ...result, session_retry: { attempts: 2, retried: true, first_failure: first.message, safari_stopped: stopped,
      first_failed_after_ms: failedAfter } };
  } catch (error) {
    error.message += `; first attempt (retried once): ${first.message}`;
    error.firstFailure = first;
    throw error;
  }
}

async function safariAttempt(url, timeout) {
  const port = 4455, base = `http://127.0.0.1:${port}`;
  const driver = spawn("/usr/bin/safaridriver", ["--port", String(port)], { stdio: ["ignore", "pipe", "pipe"] });
  const started = Date.now();
  let driverError, sessionId, log = "", phase = "driver-startup", failure, exitWait = null, sessionRequestedAfter = null;
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
    phase = "safari-exit-wait";
    exitWait = await untilSafariExited();
    if (exitWait.polls > 0) console.error(JSON.stringify({ safari_exit_wait: exitWait }));
    phase = "session-creation";
    sessionRequestedAfter = Date.now() - started;
    const session = await webdriverRequest(base, "POST", "/session", { capabilities: { alwaysMatch: { browserName: "safari" } } }, 60000);
    sessionId = session.sessionId;
    if (!sessionId) throw new Error("Safari did not return a session ID");
    phase = "navigation";
    await webdriverRequest(base, "POST", `/session/${sessionId}/url`, { url });
    phase = "script-report";
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const report = await webdriverRequest(base, "POST", `/session/${sessionId}/execute/sync`, { script: "return window.__wasmReport || null;", args: [] });
      if (report) return { environment: "safari", version: session.capabilities?.browserVersion ?? "unknown", safari_exit_wait: exitWait, ...report };
      await sleep(100);
    }
    throw new Error("Safari page report exceeded external suite deadline");
  } catch (cause) {
    failure = new Error(`Safari ${phase}: ${cause}; driver exit=${driver.exitCode}, signal=${driver.signalCode}, log=${log}`, { cause });
    failure.phase = phase;
    failure.safariExitWait = exitWait;
    failure.sessionRequestedAfter = sessionRequestedAfter;
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
  // Playwright's WebKit on Linux: JavaScriptCore on x86-64, which macOS Safari
  // (arm64) does not cover.
  if (!["chromium", "firefox", "webkit"].includes(name)) throw new Error("Unsupported actual browser");
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
