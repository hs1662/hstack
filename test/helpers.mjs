// Shared fixtures for the domain test files (node --test runs each file in its own process).
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after, afterEach, beforeEach } from "node:test";
import { fileURLToPath } from "node:url";

import { PRE_TOOL_DENIAL_NEEDLE } from "../scripts/transcript.mjs";

const TEST_DIR = dirname(fileURLToPath(import.meta.url));
export const PLUGIN_ROOT = resolve(TEST_DIR, "..");
export const HOOK_SCRIPT = join(PLUGIN_ROOT, "scripts", "post-invocation.mjs");
export const STOP_HOOK_SCRIPT = join(PLUGIN_ROOT, "scripts", "stop.mjs");
export const PRE_TOOL_HOOK_SCRIPT = join(PLUGIN_ROOT, "scripts", "pre-tool-use.mjs");
export const RULES_PATH = join(PLUGIN_ROOT, "rules", "AGENTS.md");
export const HOOKS_JSON_PATH = join(PLUGIN_ROOT, "hooks.json");

const tempDirs = [];

after(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
  try {
    rmdirSync(SHARED_LOCK_DIR);
  } catch {
    // Another file still holds it, or it is already gone.
  }
});

export function createTempDir(prefix = "hstack-test-") {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

// node --test runs test files in parallel. Every test of every file importing this module holds the CPU lock
// shared; wall-clock perf tests and the 16-process lock stress test take it exclusive through withCpuLock, so
// a timing waits for in-flight tests to finish and no other test starts until it ends.
const CPU_LOCK_DIR = join(tmpdir(), `hstack-test-cpu-${createHash("sha1").update(PLUGIN_ROOT).digest("hex").slice(0, 12)}.lock`);
const CPU_LOCK_STALE_MS = 120_000;
const SLEEP_CELL = new Int32Array(new SharedArrayBuffer(4));
const SHARED_LOCK_DIR = `${CPU_LOCK_DIR}.shared`;
const sleep = () => Atomics.wait(SLEEP_CELL, 0, 0, 20);

function isLivePid(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === "EPERM";
  }
}

function isLiveCpuLockHolder() {
  let pid = Number.NaN;
  try {
    pid = Number(readFileSync(join(CPU_LOCK_DIR, "pid"), "utf8"));
  } catch {
    // A holder writes its pid right after mkdir; a missing pid is a holder still starting.
  }
  if (!(pid > 0)) {
    return Date.now() - statSync(CPU_LOCK_DIR).mtimeMs < 1_000;
  }
  try {
    process.kill(pid, 0);
    return Date.now() - statSync(CPU_LOCK_DIR).mtimeMs < CPU_LOCK_STALE_MS;
  } catch (err) {
    return err.code === "EPERM";
  }
}

function tryTakeCpuLock() {
  try {
    mkdirSync(CPU_LOCK_DIR);
    writeFileSync(join(CPU_LOCK_DIR, "pid"), String(process.pid));
    return true;
  } catch (err) {
    if (err.code !== "EEXIST") {
      throw err;
    }
  }
  try {
    if (!isLiveCpuLockHolder()) {
      rmSync(CPU_LOCK_DIR, { recursive: true, force: true });
    }
  } catch {
    // The holder released it between our checks.
  }
  return false;
}

// An exclusive holder in another live process, which shared holders wait out.
function otherExclusiveHolder() {
  try {
    return readFileSync(join(CPU_LOCK_DIR, "pid"), "utf8") !== String(process.pid) && isLiveCpuLockHolder();
  } catch {
    return false;
  }
}

// Shared holders in other live processes; a dead holder's entry is removed.
function otherSharedHolders() {
  let names = [];
  try {
    names = readdirSync(SHARED_LOCK_DIR);
  } catch {
    return false;
  }
  return names.some((name) => {
    if (name === String(process.pid)) {
      return false;
    }
    if (isLivePid(Number(name))) {
      return true;
    }
    rmSync(join(SHARED_LOCK_DIR, name), { force: true });
    return false;
  });
}

const sharedEntry = join(SHARED_LOCK_DIR, String(process.pid));
function takeSharedCpuLock() {
  for (;;) {
    while (otherExclusiveHolder()) {
      sleep();
    }
    mkdirSync(SHARED_LOCK_DIR, { recursive: true });
    try {
      writeFileSync(sharedEntry, "");
    } catch (err) {
      // Another file's after() removed the empty directory in between.
      if (err.code === "ENOENT") {
        continue;
      }
      throw err;
    }
    // An exclusive taker that got in between waits for this entry, so step back for it.
    if (!otherExclusiveHolder()) {
      return;
    }
    rmSync(sharedEntry, { force: true });
  }
}
const releaseSharedCpuLock = () => rmSync(sharedEntry, { force: true });
beforeEach(takeSharedCpuLock);
afterEach(releaseSharedCpuLock);

export function withCpuLock(fn) {
  // A test holds the lock shared; waiting for exclusive while holding it would deadlock two such tests.
  const wasShared = existsSync(sharedEntry);
  releaseSharedCpuLock();
  while (!tryTakeCpuLock()) {
    sleep();
  }
  while (otherSharedHolders()) {
    sleep();
  }
  const release = () => {
    rmSync(CPU_LOCK_DIR, { recursive: true, force: true });
    if (wasShared) {
      takeSharedCpuLock();
    }
  };
  let result;
  try {
    result = fn();
  } catch (err) {
    release();
    throw err;
  }
  if (result && typeof result.then === "function") {
    return result.finally(release);
  }
  release();
  return result;
}

export function makeStep(stepIndex, type, { thinking = "", content = "", toolCalls = [] } = {}) {
  return { stepIndex, type, thinking, content, toolCalls };
}

// GENERIC step the runtime records when the PreToolUse hook denies a tool call.
export function makeDenialStep(stepIndex, reason = "작업 단계 제목을 한국어로 바꿔라") {
  return { stepIndex, type: "GENERIC", thinking: "", content: `${PRE_TOOL_DENIAL_NEEDLE}: ${reason}`, error: "", toolCalls: [] };
}

export function toJsonl(records) {
  return `${records.map((record) => JSON.stringify(record)).join("\n")}\n`;
}

export function wrapAntigravityHookMessage(message, hookName = "PostInvocation") {
  return [
    "The following is a <SYSTEM_MESSAGE> not actually sent by the user. It is provided by the system as important information to pay attention to.",
    "",
    "<SYSTEM_MESSAGE>",
    `The following system message was injected by a ${hookName} hook:`,
    message,
    "</SYSTEM_MESSAGE>",
  ].join("\n");
}

export function runHookSubprocess(scriptPath, input, { nodeArgs = [], ...spawnOptions } = {}) {
  return spawnSync(process.execPath, [...nodeArgs, scriptPath], {
    cwd: PLUGIN_ROOT,
    input,
    encoding: "utf8",
    ...spawnOptions,
  });
}

// Wall time of fn() with no other test running, for timing assertions.
export function timeUnderCpuLock(fn) {
  return withCpuLock(() => {
    const t0 = performance.now();
    const result = fn();
    return { result, elapsedMs: performance.now() - t0 };
  });
}
