// Shared fixtures for the domain test files (node --test runs each file in its own process).
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after } from "node:test";
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
});

export function createTempDir(prefix = "hstack-test-") {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

// node --test runs test files in parallel. Wall-clock perf tests and the 16-process lock stress test take
// this cross-process lock, so a timing never overlaps the stress test's burst of node startups.
const CPU_LOCK_DIR = join(tmpdir(), `hstack-test-cpu-${createHash("sha1").update(PLUGIN_ROOT).digest("hex").slice(0, 12)}.lock`);
const CPU_LOCK_STALE_MS = 120_000;
const SLEEP_CELL = new Int32Array(new SharedArrayBuffer(4));

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

export function withCpuLock(fn) {
  while (!tryTakeCpuLock()) {
    Atomics.wait(SLEEP_CELL, 0, 0, 20);
  }
  const release = () => rmSync(CPU_LOCK_DIR, { recursive: true, force: true });
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
