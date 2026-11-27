// Shared fixtures for the domain test files (node --test runs each file in its own process).
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmdirSync, rmSync, statSync, writeFileSync } from "node:fs";
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

let lockOwnerSeq = 0;

function readOwnerFile(lockDir) {
  try {
    return readFileSync(join(lockDir, "pid"), "utf8").trim();
  } catch {
    return null;
  }
}

export function createCpuLockController(lockDir, { staleMs = CPU_LOCK_STALE_MS } = {}) {
  const sharedDir = `${lockDir}.shared`;
  const reclaimDir = `${lockDir}.reclaim`;
  const sharedEntry = join(sharedDir, String(process.pid));

  const safeMtimeMs = (p) => {
    try {
      return statSync(p).mtimeMs;
    } catch {
      return 0;
    }
  };

  const isLiveHolder = () => {
    const raw = readOwnerFile(lockDir);
    if (raw === null) {
      return safeMtimeMs(lockDir) > 0 && Date.now() - safeMtimeMs(lockDir) < 1_000;
    }
    const pid = Number.parseInt(raw.split(":")[0], 10);
    if (!(pid > 0)) {
      return safeMtimeMs(lockDir) > 0 && Date.now() - safeMtimeMs(lockDir) < Math.min(1_000, staleMs);
    }
    return isLivePid(pid);
  };

  const reclaimStaleLock = () => {
    try {
      mkdirSync(reclaimDir);
    } catch (err) {
      if (err.code === "EEXIST") {
        const rOwner = readOwnerFile(reclaimDir);
        const rPid = rOwner ? Number.parseInt(rOwner.split(":")[0], 10) : Number.NaN;
        const rLive = rPid > 0 ? isLivePid(rPid) : Date.now() - safeMtimeMs(reclaimDir) < 1_000;
        if (!rLive) {
          try {
            const trash = `${reclaimDir}.trash-${process.pid}-${Date.now()}-${++lockOwnerSeq}`;
            renameSync(reclaimDir, trash);
            rmSync(trash, { recursive: true, force: true });
          } catch {
          }
        }
        return false;
      }
      return false;
    }
    try {
      writeFileSync(join(reclaimDir, "pid"), `${process.pid}:${++lockOwnerSeq}`);
      if (!isLiveHolder()) {
        const trash = `${lockDir}.dead-${process.pid}-${Date.now()}-${++lockOwnerSeq}`;
        renameSync(lockDir, trash);
        rmSync(trash, { recursive: true, force: true });
        return true;
      }
      return false;
    } catch {
      return false;
    } finally {
      rmSync(reclaimDir, { recursive: true, force: true });
    }
  };

  const tryTake = () => {
    lockOwnerSeq += 1;
    const ownerToken = `${process.pid}:${lockOwnerSeq}`;
    try {
      mkdirSync(lockDir);
      writeFileSync(join(lockDir, "pid"), ownerToken);
      return ownerToken;
    } catch (err) {
      if (err.code !== "EEXIST") {
        throw err;
      }
    }
    reclaimStaleLock();
    return false;
  };

  const otherExclusiveHolder = () => {
    const owner = readOwnerFile(lockDir);
    if (!owner) {
      return false;
    }
    const pid = Number.parseInt(owner.split(":")[0], 10);
    return pid !== process.pid && isLiveHolder();
  };

  const otherSharedHolders = () => {
    let names = [];
    try {
      names = readdirSync(sharedDir);
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
      rmSync(join(sharedDir, name), { force: true });
      return false;
    });
  };

  const takeShared = () => {
    for (;;) {
      while (otherExclusiveHolder()) {
        sleep();
      }
      mkdirSync(sharedDir, { recursive: true });
      try {
        writeFileSync(sharedEntry, "");
      } catch (err) {
        if (err.code === "ENOENT") {
          continue;
        }
        throw err;
      }
      if (!otherExclusiveHolder()) {
        return;
      }
      rmSync(sharedEntry, { force: true });
    }
  };

  const releaseShared = () => rmSync(sharedEntry, { force: true });

  const releaseExclusive = (ownerToken) => {
    if (readOwnerFile(lockDir) === ownerToken) {
      try {
        const trash = `${lockDir}.rel-${process.pid}-${Date.now()}-${++lockOwnerSeq}`;
        renameSync(lockDir, trash);
        rmSync(trash, { recursive: true, force: true });
      } catch {
      }
    }
  };

  const holdReclaimLockForTest = (fn) => {
    mkdirSync(reclaimDir);
    writeFileSync(join(reclaimDir, "pid"), `${process.pid}:${++lockOwnerSeq}`);
    try {
      return fn();
    } finally {
      rmSync(reclaimDir, { recursive: true, force: true });
    }
  };

  return {
    sharedDir,
    isLiveHolder,
    tryTake,
    reclaimStaleLock,
    holdReclaimLockForTest,
    takeShared,
    releaseShared,
    otherSharedHolders,
    releaseExclusive,
  };
}

const defaultCpuLock = createCpuLockController(CPU_LOCK_DIR);
beforeEach(defaultCpuLock.takeShared);
afterEach(defaultCpuLock.releaseShared);

export function withCpuLock(fn) {
  const sharedEntry = join(defaultCpuLock.sharedDir, String(process.pid));
  const wasShared = existsSync(sharedEntry);
  defaultCpuLock.releaseShared();
  let ownerToken = false;
  while (!(ownerToken = defaultCpuLock.tryTake())) {
    sleep();
  }
  while (defaultCpuLock.otherSharedHolders()) {
    sleep();
  }
  const release = () => {
    defaultCpuLock.releaseExclusive(ownerToken);
    if (wasShared) {
      defaultCpuLock.takeShared();
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
