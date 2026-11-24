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
// became ready", and a page load in the next session can fail (#919, #922). Before a session, the pids of one
// `pgrep -x Safari` are each waited for with `caffeinate -w <pid>`, which returns on the process's exit (an event,
// not a poll), all within one deadline. A Safari past it is logged as never exited, with its pid, and then killed
// with SIGKILL only on CI, where every Safari is the job's own; elsewhere it may be the person's own browser, so it
// is only logged. The session is asked for after that either way. The tests shorten the bounds and set `kill`.
export const safariExit = { waitMs: 15000, killWaitMs: 5000, kill: process.env.GITHUB_ACTIONS === "true" };
function safariPids() { return pgrep(["-x", "Safari"]); }
function pgrep(args) {
  const probe = spawn("/usr/bin/pgrep", args, { stdio: ["ignore", "pipe", "ignore"] });
  let out = "";
  probe.stdout.on("data", bytes => { out += bytes; });
  return new Promise(resolve => {
    probe.once("close", () => resolve(out.split(/\s+/).filter(Boolean).map(Number).filter(Number.isInteger)));
    probe.once("error", () => resolve([]));
  });
}
// Whether `pid` is still a process (signal 0 checks without sending one).
function running(pid) {
  try { process.kill(pid, 0); return true; } catch (error) { return error.code !== "ESRCH"; }
}
// Whether `pid` exited within `ms`.
function exitOf(pid, ms) {
  const waiter = spawn("/usr/bin/caffeinate", ["-w", String(pid)], { stdio: "ignore" });
  return new Promise(resolve => {
    const bound = setTimeout(() => { resolve(false); waiter.kill("SIGTERM"); }, ms);
    waiter.once("exit", () => { clearTimeout(bound); resolve(true); });
    waiter.once("error", () => { clearTimeout(bound); resolve(false); });
  });
}
async function untilSafariExited() {
  const start = Date.now(), deadline = start + safariExit.waitMs;
  const pids = await safariPids();
  const exited = await Promise.all(pids.map(pid => exitOf(pid, Math.max(0, deadline - Date.now()))));
  // A wait cut short by the deadline (0 ms for a pid reached after it) may miss an exit that came: ask once more.
  const left = pids.filter((pid, index) => !exited[index] && running(pid));
  const wait = { exited: left.length === 0, waited_ms: Date.now() - start, pids };
  if (left.length === 0) return wait;
  wait.never_exited = [];
  for (const pid of left) {
    const entry = { pid, killed: false, exited_after_kill: null };
    console.error(JSON.stringify({ safari_never_exited: { pid, waited_ms: wait.waited_ms, killing: safariExit.kill } }));
    if (safariExit.kill) {
      try { process.kill(pid, "SIGKILL"); entry.killed = true; } catch (error) { entry.kill_error = String(error); }
      entry.exited_after_kill = await exitOf(pid, safariExit.killWaitMs);
    }
    wait.never_exited.push(entry);
  }
  return wait;
}

// Ending a session (DELETE /session, or closing its last window) leaves the Safari that safaridriver launched for it
// running: it does not exit on its own, so each later session found it there (#947's runs: 14 of 14 never exited in
// the 15 s wait and were killed). After a session, or a request for one that failed (safaridriver may have launched a
// Safari by then), each Safari that the pgrep before the request did not list is asked to quit: one launched for the
// session, or one started by someone else in between, but never a Safari running already, such as the person's own. It
// is asked through
// NSRunningApplication's terminate, the same quit request as choosing Quit Safari, and its exit is awaited as an event
// within safariExit.waitMs. Nothing is killed here: a Safari that does not quit is logged with exited:false, and the
// next session's exit wait then reports it as never exited.
const QUIT_SAFARI = 'ObjC.import("AppKit"); function run(argv) { const app = $.NSRunningApplication.runningApplicationWithProcessIdentifier(Number(argv[0])); return app.isNil() ? "gone" : String(app.terminate); }';
function askToQuit(pid) {
  const asker = spawn("/usr/bin/osascript", ["-l", "JavaScript", "-e", QUIT_SAFARI, String(pid)], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  for (const stream of [asker.stdout, asker.stderr]) stream.on("data", bytes => { out += bytes; });
  return new Promise(resolve => {
    const bound = setTimeout(() => asker.kill("SIGKILL"), 10000);
    asker.once("close", (code, signal) => { clearTimeout(bound); resolve(code === 0 ? out.trim() : `osascript ${code ?? signal}: ${out.trim()}`); });
    asker.once("error", error => { clearTimeout(bound); resolve(String(error)); });
  });
}
async function quitLaunched(pids) {
  const start = Date.now();
  return Promise.all(pids.map(async pid => {
    const answer = await askToQuit(pid);
    const exited = await exitOf(pid, Math.max(0, start + safariExit.waitMs - Date.now())) || !running(pid);
    return { pid, answer, exited, waited_ms: Date.now() - start };
  }));
}

// safaridriver serves WebDriver through a helper, com.apple.WebDriver.HTTPService, which registers with the per-user
// daemon webinspectord. webinspectord shuts itself down when its last client disconnects and may take seconds to exit.
// A driver started meanwhile has its helper connect to the exiting webinspectord ("webinspectord validation failed"),
// the helper shuts down, and safaridriver exits 1 with no output (2 of 35 CI jobs after #965, once the session's Safari,
// another client, quit before the driver stopped). So after safaridriver stops, the helper and each webinspectord that
// were running before the stop are each waited for with `caffeinate -w`, all within safariExit.waitMs, and logged.
// Nothing is killed: one that stays (webinspectord serving another client) is logged, and the next driver starts anyway.
function driverHelperPids() {
  return Promise.all([pgrep(["-f", "com.apple.WebDriver.HTTPService"]), pgrep(["-x", "webinspectord"])])
    .then(([helper, webinspectord]) => ({ helper, webinspectord }));
}
async function untilDriverHelpersExited(pids) {
  const start = Date.now(), all = [...pids.helper, ...pids.webinspectord];
  const exited = await Promise.all(all.map(pid => exitOf(pid, Math.max(0, start + safariExit.waitMs - Date.now()))));
  const left = all.filter((pid, index) => !exited[index] && running(pid));
  return { ...pids, exited: left.length === 0, waited_ms: Date.now() - start, ...(left.length > 0 ? { left } : {}) };
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
    if (exitWait.pids.length > 0) console.error(JSON.stringify({ safari_exit_wait: exitWait }));
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
    if (sessionRequestedAfter !== null) {
      const launched = (await safariPids()).filter(pid => !exitWait.pids.includes(pid));
      if (launched.length > 0) console.error(JSON.stringify({ safari_quit: await quitLaunched(launched) }));
    }
    const helpers = await driverHelperPids();
    await stopDriver(driver);
    if (helpers.helper.length + helpers.webinspectord.length > 0)
      console.error(JSON.stringify({ webinspectord_exit: await untilDriverHelpersExited(helpers) }));
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
