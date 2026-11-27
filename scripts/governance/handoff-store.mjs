import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { resolvePluginDataDir } from "../hook-io.mjs";
import { classifyCanaryTurn, createCanaryState, transitionCanary } from "./language-canary.mjs";
import {
  DEFAULT_POLLUTION_THRESHOLDS,
  HANDOFF_COPY,
  PASSING_VERDICTS,
  isExemptDocOrAssetPath,
} from "./constants.mjs";
import {
  SNAPSHOT_UNREADABLE_SIGNATURE,
  listCommittedPaths,
  normalizeWorkspacePath,
  readGitLedger,
  readNumstatSinceHead,
  resolveGitRootFast,
  snapshotWorkingTree,
  statSnapshotFile,
} from "./fact-ledger.mjs";

const MAX_SNAPSHOTS_PER_WORKSPACE = 20;
const MAX_LIST_SNAPSHOTS = 10;
const MAX_RECENT_VERIFICATIONS = 5;
const SAFE_SNAPSHOT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const SAFE_PIN_OWNER_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const LATEST_HANDOFF_FILE = "latest.json";
const HANDOFF_PINS_FILE = "pins.json";
const SAFE_SESSION_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const URL_SPAN_RE = /\b[a-z][a-z0-9+.-]*:\/\/\S+/gi;
const FILE_PATH_TOKEN_RE = /(?:^|[\s`'"(\[])([A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)+\.[A-Za-z0-9]{1,10})(?=$|[\s`'")\],:;])/g;
const PASS_CLAIM_RE = /(?:통과|성공|모두\s*통과|pass(?:ed)?)/i;
const TEST_CONTEXT_RE = /(?:테스트|검증|빌드|린트|test|vitest|jest|pytest|cargo\s+test|go\s+test)/i;
const MAX_HASH_FILE_BYTES = 256 * 1024;

function safeRealpath(rawPath) {
  if (typeof rawPath !== "string" || rawPath.trim().length === 0) {
    return "";
  }
  try {
    return realpathSync(rawPath);
  } catch {
    return resolve(rawPath);
  }
}

export function computeWorkspaceKey(cwd, gitRoot = "") {
  const base = safeRealpath(gitRoot || cwd || process.cwd());
  return createHash("sha256").update(base, "utf8").digest("hex").slice(0, 12);
}

const SESSION_LOCK_STALE_MS = 10_000;
// Critical sections last milliseconds and hooks time out after 5s; past this age a lock is stale even if its
// pid is alive (pid reuse).
const SESSION_LOCK_MAX_AGE_MS = 120_000;
const SESSION_LOCK_RETRIES = 25;
const SLEEP_BUFFER = new Int32Array(new SharedArrayBuffer(4));

function sleepMsSync(ms) {
  Atomics.wait(SLEEP_BUFFER, 0, 0, ms);
}

// A lock is stale when its recorded holder is dead, when it has no readable pid and is old, or when it is
// older than the hard cap whatever its pid.
function isSessionLockStale(lockPath) {
  let st;
  let raw;
  try {
    st = statSync(lockPath);
    raw = readFileSync(lockPath, "utf8");
  } catch {
    return false;
  }
  if (Date.now() - st.mtimeMs > SESSION_LOCK_MAX_AGE_MS) {
    return true;
  }
  let pid = null;
  try {
    const parsed = JSON.parse(raw);
    pid = Number.isInteger(parsed?.pid) && parsed.pid > 0 ? parsed.pid : null;
  } catch {
  }
  if (pid !== null) {
    try {
      process.kill(pid, 0);
      return false;
    } catch (err) {
      return err?.code === "ESRCH";
    }
  }
  return Date.now() - st.mtimeMs > SESSION_LOCK_STALE_MS;
}

// Reclaimers serialize with an OS kernel flock when available (auto-released on crash/SIGKILL),
// falling back to an inode-verified guard file on non-POSIX hosts.
function reclaimStaleSessionLock(lockPath) {
  if (process.platform !== "win32") {
    const res = spawnSync(
      "flock",
      [
        "-n",
        `${lockPath}.flock`,
        process.execPath,
        "-e",
        [
          'const fs = require("node:fs");',
          'const lockPath = process.argv[1];',
          'let st; try { st = fs.statSync(lockPath); } catch { process.exit(0); }',
          `let dead = Date.now() - st.mtimeMs > ${SESSION_LOCK_MAX_AGE_MS};`,
          'if (!dead) {',
          '  let pid = null; try { pid = JSON.parse(fs.readFileSync(lockPath, "utf8"))?.pid ?? null; } catch {}',
          '  if (typeof pid === "number" && pid > 0) { try { process.kill(pid, 0); } catch (e) { dead = e?.code === "ESRCH"; } }',
          `  else { dead = Date.now() - st.mtimeMs > ${SESSION_LOCK_STALE_MS}; }`,
          '}',
          'if (!dead) process.exit(0);',
          'try {',
          '  const st2 = fs.statSync(lockPath);',
          '  if (st2.dev === st.dev && st2.ino === st.ino) {',
          '    const stale = `${lockPath}.stale.${process.pid}.${Date.now()}`;',
          '    fs.renameSync(lockPath, stale);',
          '    fs.unlinkSync(stale);',
          '  }',
          '} catch {}',
        ].join("\n"),
        lockPath,
      ],
      { stdio: "ignore", timeout: 5000 },
    );
    if (res.error?.code !== "ENOENT") {
      return !res.error && res.status === 0;
    }
  }
  const guardPath = `${lockPath}.reclaim`;
  const guardNonce = randomBytes(8).toString("hex");
  let guard;
  try {
    guard = openSync(guardPath, "wx");
  } catch {
    try {
      const gst = lstatSync(guardPath);
      if (Date.now() - gst.mtimeMs > SESSION_LOCK_STALE_MS) {
        const trash = `${guardPath}.stale.${process.pid}.${randomBytes(4).toString("hex")}`;
        renameSync(guardPath, trash);
        unlinkSync(trash);
      }
    } catch {
    }
    return false;
  }
  let guardFstat = null;
  try {
    writeSync(guard, JSON.stringify({ pid: process.pid, nonce: guardNonce }));
    guardFstat = fstatSync(guard);
    if (isSessionLockStale(lockPath)) {
      const stalePath = `${lockPath}.stale.${process.pid}.${randomBytes(4).toString("hex")}`;
      renameSync(lockPath, stalePath);
      unlinkSync(stalePath);
    }
  } catch {
  } finally {
    closeSync(guard);
    try {
      if (guardFstat && lstatSync(guardPath).ino === guardFstat.ino) {
        unlinkSync(guardPath);
      }
    } catch {
    }
  }
  return true;
}

export function withSessionLock(filePath, fn) {
  const dir = resolve(filePath, "..");
  mkdirSync(dir, { recursive: true });
  const lockPath = `${filePath}.lock`;
  let fd = null;
  for (let attempt = 0; attempt < SESSION_LOCK_RETRIES; attempt += 1) {
    try {
      fd = openSync(lockPath, "wx");
      break;
    } catch (err) {
      if (err?.code !== "EEXIST") {
        throw err;
      }
    }
    if (isSessionLockStale(lockPath) && reclaimStaleSessionLock(lockPath)) {
      continue;
    }
    sleepMsSync(10);
  }
  if (fd === null) {
    throw new Error(`Failed to acquire session lock: ${lockPath}`);
  }
  // The nonce tells this owner's lock from one a reclaimer handed to the next owner after the age cap.
  const owner = JSON.stringify({ pid: process.pid, createdAt: Date.now(), nonce: randomBytes(8).toString("hex") });
  try {
    writeSync(fd, owner);
    return fn();
  } finally {
    try {
      closeSync(fd);
    } catch {
    }
    try {
      // shortcut: a reclaim landing between this read and the unlink still loses the new lock, which needs a 120s-old holder plus a microsecond race; upgrade to rename-then-verify if it shows up.
      if (readFileSync(lockPath, "utf8") === owner) {
        unlinkSync(lockPath);
      }
    } catch {
    }
  }
}

function atomicWriteJson(targetPath, data) {
  const dir = resolve(targetPath, "..");
  mkdirSync(dir, { recursive: true });
  const tmpPath = `${targetPath}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
  try {
    writeFileSync(tmpPath, `${JSON.stringify(data, null, 2)}\n`, "utf8");
    renameSync(tmpPath, targetPath);
  } catch (err) {
    try {
      unlinkSync(tmpPath);
    } catch {
    }
    throw err;
  }
}

function computeDirtyFingerprint(dirtyFiles, baseDir) {
  if (!Array.isArray(dirtyFiles) || dirtyFiles.length === 0 || !baseDir) {
    return "";
  }
  const hasher = createHash("sha256");
  for (const relPath of [...dirtyFiles].sort()) {
    hasher.update(relPath, "utf8");
    hasher.update("\0");
    const absPath = join(baseDir, relPath);
    try {
      const st = statSync(absPath);
      if (st.isFile()) {
        if (st.size <= MAX_HASH_FILE_BYTES) {
          hasher.update(readFileSync(absPath));
        } else {
          hasher.update(`size:${st.size}:mtime:${st.mtimeMs}`);
        }
      } else {
        hasher.update("nonfile");
      }
    } catch {
      hasher.update("missing");
    }
    hasher.update("\n");
  }
  return hasher.digest("hex").slice(0, 16);
}

function sanitizeSessionFileId(conversationId) {
  if (typeof conversationId !== "string") {
    return "";
  }
  const trimmed = conversationId.trim();
  if (trimmed.length === 0) {
    return "";
  }
  if (SAFE_SESSION_ID_RE.test(trimmed)) {
    return trimmed;
  }
  return createHash("sha256").update(trimmed, "utf8").digest("hex").slice(0, 24);
}

export function resolveSessionStatePath(conversationId, dataDir = resolvePluginDataDir()) {
  const safeId = sanitizeSessionFileId(conversationId);
  if (!safeId) {
    return "";
  }
  return join(dataDir, "sessions", `${safeId}.json`);
}

export function resolveEffectiveConversationKey(conversationId, cwd = "") {
  const trimmed = typeof conversationId === "string" ? conversationId.trim() : "";
  if (trimmed.length > 0) {
    return trimmed;
  }
  if (typeof cwd === "string" && cwd.trim().length > 0) {
    return `anon-${computeWorkspaceKey(cwd)}`;
  }
  return "anon-global";
}

export function readSessionState(conversationId, dataDir = resolvePluginDataDir()) {
  const filePath = resolveSessionStatePath(conversationId, dataDir);
  if (!filePath || !existsSync(filePath)) {
    return null;
  }
  try {
    const parsed = JSON.parse(readFileSync(filePath, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

// Lock order: session, then workspace (only on handoff). A replay or a late hook
// cannot count the same user turn twice or move the observed frontier backwards.
export function recordLanguageCanaryTurn({ conversationId, cwd, user, reply, request, ledger, config, dataDir }) {
  if (!cwd || !conversationId || !Number.isSafeInteger(user?.stepIndex) || !reply) return null;
  const classification = classifyCanaryTurn({ text: reply.content, userRequest: request }, config);
  if (!classification.applicable) return null;
  const filePath = resolveSessionStatePath(conversationId, dataDir);
  return withSessionLock(filePath, () => {
    const session = readSessionState(conversationId, dataDir) ?? {};
    if (Number.isSafeInteger(session.canaryTurn) && user.stepIndex <= session.canaryTurn) return null;
    const { state, event } = transitionCanary(session.languageCanary ?? createCanaryState(), classification, config);
    let message = null;
    let canaryHandoff = session.canaryHandoff;
    if (event === "load_failure") {
      message = "[카나리아:load_failure] 첫 유효 응답이 한국어에서 이탈했습니다. 새 세션으로 교체하기 전에 한국어 규칙이 로드됐는지 확인하세요.";
    } else if (event === "suspect") {
      message = "[카나리아:suspect] 한국어 산문 이탈이 반복됐습니다. 현재 세션의 한국어 규칙을 다시 고정하세요.";
    } else if (event === "handoff_required") {
      const pinOwner = `canary:${createHash("sha256").update(conversationId).digest("hex").slice(0, 24)}`;
      const { snapshot } = saveHandoffSnapshot({
        conversationId, cwd, ledger, dataDir, pinOwner, gitLedger: readGitLedger(cwd),
        input: {
          objective: "언어 이탈 이전 세션의 작업 상태 인계",
          remaining_tasks: ["새 세션에서 작업 목표와 미검증 항목을 재확인하세요."],
        },
      });
      canaryHandoff = { snapshotId: snapshot.snapshotId, pinOwner };
      message = `[카나리아:handoff_required] 핸드오프 ${snapshot.snapshotId}를 고정했습니다(소유자 ${pinOwner}). 새 세션에서 이 ID를 불러오세요. 완료 검증 판정과는 별개입니다.`;
    }
    atomicWriteJson(filePath, { ...session, canaryTurn: user.stepIndex, languageCanary: state, canaryHandoff });
    return message;
  });
}

export function updateSessionPollutionState({
  conversationId,
  turnStartStepIndex = null,
  inputTokens = null,
  failedExecutionsInTurn = 0,
  maxSingleFileEdits = 0,
  thresholds = DEFAULT_POLLUTION_THRESHOLDS,
  dataDir = resolvePluginDataDir(),
} = {}) {
  const filePath = resolveSessionStatePath(conversationId, dataDir);
  if (!filePath) {
    return null;
  }

  return withSessionLock(filePath, () => {
    const prev = readSessionState(conversationId, dataDir) ?? {};
    const isNewTurn =
      typeof turnStartStepIndex === "number" &&
      Number.isFinite(turnStartStepIndex) &&
      typeof prev.turnStartStepIndex === "number" &&
      prev.turnStartStepIndex !== turnStartStepIndex;

    const mergedInputTokens =
      typeof inputTokens === "number" && Number.isFinite(inputTokens)
        ? Math.max(inputTokens, Number.isFinite(prev.inputTokens) ? prev.inputTokens : 0)
        : (Number.isFinite(prev.inputTokens) ? prev.inputTokens : null);
    const nextFailed = Number.isFinite(failedExecutionsInTurn) ? failedExecutionsInTurn : 0;
    const nextEdits = Number.isFinite(maxSingleFileEdits) ? maxSingleFileEdits : 0;
    const mergedFailed = isNewTurn
      ? nextFailed
      : Math.max(nextFailed, Number.isFinite(prev.failedExecutionsInTurn) ? prev.failedExecutionsInTurn : 0);
    const mergedFileEdits = isNewTurn
      ? nextEdits
      : Math.max(nextEdits, Number.isFinite(prev.maxSingleFileEdits) ? prev.maxSingleFileEdits : 0);

    const tokenLimit = thresholds?.inputTokensWarning ?? DEFAULT_POLLUTION_THRESHOLDS.inputTokensWarning;
    const failLimit = thresholds?.failedExecutionsInTurn ?? DEFAULT_POLLUTION_THRESHOLDS.failedExecutionsInTurn;
    const churnLimit = thresholds?.repeatedFileEditChurn ?? DEFAULT_POLLUTION_THRESHOLDS.repeatedFileEditChurn;

    const pollutionAlert =
      (mergedInputTokens !== null && mergedInputTokens >= tokenLimit) ||
      mergedFailed >= failLimit ||
      mergedFileEdits >= churnLimit;

    const prevLoggedPreflightKeys = Array.isArray(prev.loggedPreflightKeys)
      ? prev.loggedPreflightKeys.filter((k) => typeof k === "string" && k.length > 0).slice(-50)
      : [];

    const state = {
      ...prev,
      conversationId,
      turnStartStepIndex:
        typeof turnStartStepIndex === "number" && Number.isFinite(turnStartStepIndex)
          ? turnStartStepIndex
          : (typeof prev.turnStartStepIndex === "number" ? prev.turnStartStepIndex : 0),
      updatedAt: new Date().toISOString(),
      inputTokens: mergedInputTokens,
      failedExecutionsInTurn: mergedFailed,
      maxSingleFileEdits: mergedFileEdits,
      pollutionAlert,
      loggedPreflightKeys: prevLoggedPreflightKeys,
    };

    try {
      atomicWriteJson(filePath, state);
    } catch {
    }
    return state;
  });
}

const ALLOWED_AUTONOMY_FLAG_NAMES = new Set([
  "circuitBreakerTurns",
  "promptRouteTurns",
  "autoHandoffTurns",
  "koreanAnchorTurns",
]);
const MAX_AUTONOMY_TURN_KEYS = 30;

export function hasAutonomyTurnFlag({
  conversationId,
  flagName,
  turnKey,
  dataDir = resolvePluginDataDir(),
} = {}) {
  if (
    !ALLOWED_AUTONOMY_FLAG_NAMES.has(flagName) ||
    typeof turnKey !== "string" ||
    turnKey.length === 0
  ) {
    return false;
  }
  const state = readSessionState(conversationId, dataDir);
  if (!state) {
    return false;
  }
  const existing = Array.isArray(state[flagName]) ? state[flagName] : [];
  return existing.includes(turnKey);
}

export function claimAutonomyTurnFlag({
  conversationId,
  flagName,
  turnKey,
  dataDir = resolvePluginDataDir(),
} = {}) {
  if (!ALLOWED_AUTONOMY_FLAG_NAMES.has(flagName) || typeof turnKey !== "string" || turnKey.length === 0) {
    return false;
  }
  const filePath = resolveSessionStatePath(conversationId, dataDir);
  if (!filePath) {
    return true;
  }
  try {
    return withSessionLock(filePath, () => {
      const prev = readSessionState(conversationId, dataDir) ?? { conversationId };
      const existing = Array.isArray(prev[flagName])
        ? prev[flagName].filter((k) => typeof k === "string" && k.length > 0)
        : [];
      if (existing.includes(turnKey)) {
        return false;
      }
      const nextList = [...existing, turnKey].slice(-MAX_AUTONOMY_TURN_KEYS);
      const nextState = {
        ...prev,
        conversationId,
        updatedAt: new Date().toISOString(),
        [flagName]: nextList,
      };
      atomicWriteJson(filePath, nextState);
      return true;
    });
  } catch {
    return null;
  }
}

// One working-tree snapshot per conversation, valid only for the turn that recorded it.
export function saveTurnSnapshot({
  conversationId,
  turnStartStepIndex,
  afterStepIndex = null,
  snapshot,
  dataDir = resolvePluginDataDir(),
} = {}) {
  const filePath = resolveSessionStatePath(conversationId, dataDir);
  const hasStep = Number.isFinite(turnStartStepIndex);
  const hasAfter = !hasStep && Number.isFinite(afterStepIndex);
  if (!filePath || !snapshot || (!hasStep && !hasAfter)) {
    return false;
  }
  try {
    return withSessionLock(filePath, () => {
      const prev = readSessionState(conversationId, dataDir) ?? { conversationId };
      atomicWriteJson(filePath, {
        ...prev,
        conversationId,
        updatedAt: new Date().toISOString(),
        turnSnapshot: {
          turnStartStepIndex: hasStep ? turnStartStepIndex : null,
          ...(hasAfter ? { afterStepIndex } : {}),
          gitRoot: snapshot.gitRoot,
          head: snapshot.head,
          files: snapshot.files,
          docFiles: snapshot.docFiles ?? null,
          docFilesTruncated: Boolean(snapshot.docFilesTruncated),
          untrackedFiles: snapshot.untrackedTruncated ? null : snapshot.untrackedFiles ?? null,
          untrackedTruncated: Boolean(snapshot.untrackedTruncated),
          capturedAtMs: Number.isFinite(snapshot.capturedAtMs) ? snapshot.capturedAtMs : Date.now(),
        },
      });
      return true;
    });
  } catch {
    return false;
  }
}

// The tree as the last passing verify_completion saw it, attached to the current turn snapshot so a new turn discards it.
export function saveGateSnapshot({ conversationId, snapshot, dataDir = resolvePluginDataDir(), gatePassCount = null } = {}) {
  const filePath = resolveSessionStatePath(conversationId, dataDir);
  if (!filePath) {
    return false;
  }
  try {
    return withSessionLock(filePath, () => {
      const prev = readSessionState(conversationId, dataDir);
      if (!prev?.turnSnapshot || typeof prev.turnSnapshot !== "object") {
        return false;
      }
      if (!snapshot || prev.turnSnapshot.gitRoot !== snapshot.gitRoot) {
        if ("gate" in prev.turnSnapshot) {
          const nextTurn = { ...prev.turnSnapshot };
          delete nextTurn.gate;
          atomicWriteJson(filePath, {
            ...prev,
            updatedAt: new Date().toISOString(),
            turnSnapshot: nextTurn,
          });
        }
        return false;
      }
      atomicWriteJson(filePath, {
        ...prev,
        updatedAt: new Date().toISOString(),
        turnSnapshot: {
          ...prev.turnSnapshot,
          gate: {
            head: snapshot.head,
            files: snapshot.files,
            docFiles: snapshot.docFiles ?? null,
            docFilesTruncated: Boolean(snapshot.docFilesTruncated),
            untrackedFiles: snapshot.untrackedTruncated ? null : snapshot.untrackedFiles ?? null,
            untrackedTruncated: Boolean(snapshot.untrackedTruncated),
            capturedAtMs: Number.isFinite(snapshot.capturedAtMs) ? snapshot.capturedAtMs : Date.now(),
            passCount: Number.isInteger(gatePassCount) && gatePassCount >= 1 ? gatePassCount : null,
          },
        },
      });
      return true;
    });
  } catch {
    return false;
  }
}

function toNullProtoRecord(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return null;
  }
  const out = Object.create(null);
  for (const [k, v] of Object.entries(raw)) {
    out[k] = v;
  }
  return out;
}

export function readTurnSnapshot({ conversationId, turnStartStepIndex, dataDir = resolvePluginDataDir() } = {}) {
  let snap = readSessionState(conversationId, dataDir)?.turnSnapshot;
  if (
    !snap ||
    typeof snap !== "object" ||
    typeof snap.gitRoot !== "string" ||
    !snap.files ||
    typeof snap.files !== "object" ||
    Array.isArray(snap.files)
  ) {
    return null;
  }
  if (snap.turnStartStepIndex !== turnStartStepIndex) {
    const canBind =
      snap.turnStartStepIndex === null &&
      Number.isFinite(snap.afterStepIndex) &&
      Number.isFinite(turnStartStepIndex) &&
      turnStartStepIndex > snap.afterStepIndex;
    if (!canBind) {
      return null;
    }
    const filePath = resolveSessionStatePath(conversationId, dataDir);
    if (filePath) {
      try {
        withSessionLock(filePath, () => {
          const prev = readSessionState(conversationId, dataDir);
          const cur = prev?.turnSnapshot;
          if (
            cur &&
            cur.turnStartStepIndex === null &&
            cur.afterStepIndex === snap.afterStepIndex &&
            cur.capturedAtMs === snap.capturedAtMs
          ) {
            const bound = { ...cur, turnStartStepIndex };
            delete bound.afterStepIndex;
            atomicWriteJson(filePath, { ...prev, turnSnapshot: bound });
            snap = bound;
          }
        });
      } catch {
      }
    }
  }

  const headOf = (raw) => (typeof raw?.head === "string" ? raw.head : null);
  const docFilesOf = (raw) => toNullProtoRecord(raw?.docFiles);
  const untrackedOf = (raw) => toNullProtoRecord(raw?.untrackedFiles);
  const capturedAtOf = (raw) => (Number.isFinite(raw?.capturedAtMs) ? raw.capturedAtMs : null);
  const gateFiles = toNullProtoRecord(snap.gate?.files);
  const gate = gateFiles
    ? {
        head: headOf(snap.gate),
        files: gateFiles,
        docFiles: docFilesOf(snap.gate),
        docFilesTruncated: Boolean(snap.gate?.docFilesTruncated),
        untrackedFiles: untrackedOf(snap.gate),
        untrackedTruncated: Boolean(snap.gate?.untrackedTruncated),
        capturedAtMs: capturedAtOf(snap.gate),
        passCount: Number.isInteger(snap.gate?.passCount) ? snap.gate.passCount : null,
      }
    : null;
  return {
    gitRoot: snap.gitRoot,
    head: headOf(snap),
    files: toNullProtoRecord(snap.files),
    docFiles: docFilesOf(snap),
    docFilesTruncated: Boolean(snap.docFilesTruncated),
    untrackedFiles: untrackedOf(snap),
    untrackedTruncated: Boolean(snap.untrackedTruncated),
    capturedAtMs: capturedAtOf(snap),
    gate,
  };
}

const statSignature = statSnapshotFile;

function sameFileSignature(a, b) {
  if (a === SNAPSHOT_UNREADABLE_SIGNATURE || b === SNAPSHOT_UNREADABLE_SIGNATURE) {
    return false;
  }
  return Array.isArray(a) && Array.isArray(b)
    ? a.length === b.length && a.every((v, i) => v === b[i])
    : a === b;
}

function isRiskyShellExec(exec) {
  return exec.kind === "other" || exec.hasPrepSideEffect === true;
}

function syncPendingAsyncAfterWrite(ledger) {
  if (Array.isArray(ledger.pendingAsyncAuditLaunchSteps)) {
    ledger.pendingAsyncAuditsAfterLastWrite = ledger.pendingAsyncAuditLaunchSteps.filter((s) => s > ledger.lastWriteStepIndex).length;
  }
  if (Array.isArray(ledger.pendingAsyncChallengeLaunchSteps)) {
    ledger.pendingAsyncChallengesAfterLastWrite = ledger.pendingAsyncChallengeLaunchSteps.filter((s) => s > ledger.lastWriteStepIndex).length;
  }
}

// Shell commands (sed -i, redirects) write files no write tool records; diff the tree against the turn-start snapshot.
// Returns true when an arbitrary shell command ran in a git tree that could not be diffed (fail closed).
export function mergeShellWrittenFiles(ledger, { conversationKey, cwd, dirtyFiles = new Set(), dirtyFilesAvailable = true, diffNumstat = null, dataDir = resolvePluginDataDir() }) {
  // run_command and mcp_agy-fast_fast_run_checks both run arbitrary shell commands.
  const shellExecs = ledger.turnExecutions;
  if (ledger.sessionRole !== "main" || shellExecs.length === 0 || !cwd) {
    return false;
  }
  const riskyShellExecs = shellExecs.filter(isRiskyShellExec);
  // Date a change at the last command that could have made it: a writer, else a read-only-looking command, else a check.
  const datingStep = (execs) =>
    (execs.findLast(isRiskyShellExec) ?? execs.findLast((exec) => exec.kind === "read_only") ?? execs.at(-1)).stepIndex;
  const riskyStep = riskyShellExecs.at(-1)?.stepIndex ?? -1;
  const record = (relPath, step) => {
    ledger.turnWrittenFiles.add(relPath);
    ledger.turnCodeWrittenFiles.add(relPath);
    ledger.lastWriteStepIndex = Math.max(ledger.lastWriteStepIndex, step);
    ledger.lastCodeWriteStepIndex = Math.max(ledger.lastCodeWriteStepIndex, step);
    syncPendingAsyncAfterWrite(ledger);
  };
  // A write tool already dated its own file; with no writer command in the turn, a check must not re-date it.
  const keepsToolDate = (relPath) => riskyStep === -1 && ledger.turnWrittenFiles.has(relPath);
  const baseline = readTurnSnapshot({ conversationId: conversationKey, turnStartStepIndex: ledger.turnStartStepIndex, dataDir });
  const current = baseline ? snapshotWorkingTree(cwd) : null;
  const passingAttempts = ledger.turnGateAttempts.filter((attempt) => PASSING_VERDICTS.has(attempt.verdict));
  const lastGateStep = passingAttempts.at(-1)?.stepIndex ?? -1;
  const activeGate =
    baseline?.gate && typeof baseline.gate.passCount === "number" && baseline.gate.passCount === passingAttempts.length
      ? baseline.gate
      : null;
  // Commits made this turn leave a clean tree, so the files they touched count as changed too.
  const committedSince = (head) =>
    head === null || head === current.head ? new Set() : listCommittedPaths(current.gitRoot, head, current.head);
  const sinceTurn = current && current.gitRoot === baseline.gitRoot ? committedSince(baseline.head) : null;
  const sinceGate = sinceTurn && activeGate ? committedSince(activeGate.head) : new Set();
  if (!sinceTurn || !sinceGate) {
    if (baseline && baseline.head !== null && (!current || current.head !== baseline.head) && (!sinceTurn || !sinceGate)) {
      ledger.commitNumstatUnavailable = true;
    }
    if (riskyShellExecs.length === 0 || !resolveGitRootFast(cwd)) {
      return false;
    }
    ledger.lastWriteStepIndex = Math.max(ledger.lastWriteStepIndex, riskyStep);
    ledger.lastCodeWriteStepIndex = Math.max(ledger.lastCodeWriteStepIndex, riskyStep);
    syncPendingAsyncAfterWrite(ledger);
    // Without a diff any dirty code file may be the shell's, so each one needs reporting and a check after it.
    for (const relPath of dirtyFiles) {
      if (!isExemptDocOrAssetPath(relPath) && !keepsToolDate(relPath)) {
        record(relPath, riskyStep);
      }
    }
    return true;
  }
  const postGateShell = activeGate ? shellExecs.filter((exec) => exec.stepIndex > lastGateStep) : [];
  const postGateWriter = postGateShell.some(isRiskyShellExec);
  const toolWroteAfterGate = (relPath) => (ledger.turnToolWriteSteps.get(relPath) ?? -1) > lastGateStep;
  const preGateShell = postGateShell.length > 0 ? shellExecs.filter((exec) => exec.stepIndex < lastGateStep) : shellExecs;
  const preGateKeepsToolDate = (relPath) => !preGateShell.some(isRiskyShellExec) && ledger.turnWrittenFiles.has(relPath);

  const statFreshnessMs = (gitRoot, relPath) => {
    try {
      const st = statSync(join(gitRoot, relPath));
      return Math.max(st.mtimeMs, st.ctimeMs);
    } catch {
      return null;
    }
  };
  let postGateDocRequiresReverify = false;
  const postGateHandledDocs = new Set();
  if (postGateShell.length > 0 && activeGate) {
    if (!(ledger.turnCommittedFiles instanceof Set)) {
      ledger.turnCommittedFiles = new Set();
    }
    const postGateStep = datingStep(postGateShell);
    const gateDocCandidates = new Set(sinceGate);
    for (const relPath of Object.keys(current.docFiles ?? {})) {
      gateDocCandidates.add(relPath);
    }
    for (const relPath of Object.keys(activeGate.docFiles ?? {})) {
      gateDocCandidates.add(relPath);
    }
    for (const relPath of dirtyFiles) {
      if (isExemptDocOrAssetPath(relPath)) {
        gateDocCandidates.add(relPath);
      }
    }
    const postGateDocTruncated = Boolean(activeGate.docFilesTruncated || current.docFilesTruncated || dirtyFilesAvailable === false);
    const gateCutoffMs = Number.isFinite(activeGate.capturedAtMs) ? activeGate.capturedAtMs - 10 : 0;
    for (const relPath of gateDocCandidates) {
      const inSinceGate = sinceGate.has(relPath);
      if (inSinceGate) {
        ledger.turnCommittedFiles.add(relPath);
      }
      if (!isExemptDocOrAssetPath(relPath)) {
        continue;
      }
      const nowDoc = current.docFiles?.[relPath] ?? statSignature(current.gitRoot, relPath);
      const gateDoc = activeGate?.docFiles?.[relPath];
      let hasDefinitePostGateDocChange =
        gateDoc !== undefined
          ? !sameFileSignature(gateDoc, nowDoc)
          : inSinceGate || (!postGateDocTruncated && nowDoc !== undefined);
      if (!hasDefinitePostGateDocChange && gateDoc === undefined && postGateDocTruncated && postGateWriter) {
        const freshMs = statFreshnessMs(current.gitRoot, relPath);
        if (freshMs !== null && freshMs >= gateCutoffMs) {
          hasDefinitePostGateDocChange = true;
        }
      }
      if (hasDefinitePostGateDocChange) {
        ledger.turnWrittenFiles.add(relPath);
        ledger.lastWriteStepIndex = Math.max(ledger.lastWriteStepIndex, postGateStep);
        postGateHandledDocs.add(relPath);
      }
    }
    if (postGateDocTruncated && postGateWriter) {
      ledger.lastWriteStepIndex = Math.max(ledger.lastWriteStepIndex, postGateStep);
      postGateDocRequiresReverify = true;
    }
  }

  const turnDocCandidates = new Set(sinceTurn);
  if (shellExecs.length > 0 && current && baseline) {
    for (const relPath of Object.keys(current.docFiles ?? {})) {
      turnDocCandidates.add(relPath);
    }
    for (const relPath of Object.keys(baseline.docFiles ?? {})) {
      turnDocCandidates.add(relPath);
    }
    for (const relPath of dirtyFiles) {
      if (isExemptDocOrAssetPath(relPath)) {
        turnDocCandidates.add(relPath);
      }
    }
  }
  if (sinceTurn.size > 0 && !(ledger.turnCommittedFiles instanceof Set)) {
    ledger.turnCommittedFiles = new Set();
  }
  const turnDocTruncated = Boolean(baseline.docFilesTruncated || current.docFilesTruncated);
  const turnCutoffMs = Number.isFinite(baseline.capturedAtMs) ? baseline.capturedAtMs - 10 : 0;
  for (const relPath of turnDocCandidates) {
    if (sinceTurn.has(relPath)) {
      ledger.turnCommittedFiles.add(relPath);
    }
    if (!isExemptDocOrAssetPath(relPath) || postGateHandledDocs.has(relPath)) {
      continue;
    }
    const beforeDoc = baseline.docFiles?.[relPath];
    const nowDoc = current.docFiles?.[relPath] ?? statSignature(current.gitRoot, relPath);
    let docChangedThisTurn = false;
    if (beforeDoc !== undefined) {
      docChangedThisTurn = !sameFileSignature(beforeDoc, nowDoc);
    } else if (sinceTurn.has(relPath)) {
      docChangedThisTurn = true;
    } else if (!turnDocTruncated) {
      docChangedThisTurn = nowDoc !== undefined;
    } else if (riskyShellExecs.length > 0) {
      const freshMs = statFreshnessMs(current.gitRoot, relPath);
      docChangedThisTurn = freshMs !== null && freshMs >= turnCutoffMs;
    }
    if (!docChangedThisTurn) {
      continue;
    }
    const alreadyTrackedByTool = preGateKeepsToolDate(relPath);
    ledger.turnWrittenFiles.add(relPath);
    if (!alreadyTrackedByTool && (preGateShell.some(isRiskyShellExec) || sinceTurn.has(relPath))) {
      const preStep = preGateShell.length > 0 ? datingStep(preGateShell) : ledger.turnStartStepIndex;
      ledger.lastWriteStepIndex = Math.max(ledger.lastWriteStepIndex, preStep);
    }
  }

  if (sinceTurn.size > 0 && diffNumstat instanceof Map && baseline.head !== null) {
    const turnNumstat = readNumstatSinceHead(current.gitRoot, baseline.head);
    if (turnNumstat === null) {
      ledger.commitNumstatUnavailable = true;
    } else {
      for (const [relPath, stat] of turnNumstat) {
        if (isExemptDocOrAssetPath(relPath)) {
          continue;
        }
        if (!sinceTurn.has(relPath) && !ledger.turnCodeWrittenFiles.has(relPath)) {
          continue;
        }
        const prev = diffNumstat.get(relPath);
        const prevSum = prev ? prev.added + prev.deleted : -1;
        if (stat.added + stat.deleted > prevSum) {
          diffNumstat.set(relPath, stat);
        }
      }
    }
  }
  const signatureIn = (snapObj, relPath) => {
    if (!snapObj) {
      return undefined;
    }
    if (Object.hasOwn(snapObj.files, relPath)) {
      return snapObj.files[relPath];
    }
    if (snapObj.untrackedFiles && Object.hasOwn(snapObj.untrackedFiles, relPath)) {
      return snapObj.untrackedFiles[relPath];
    }
    return undefined;
  };
  const changedBetween = (fromSnap, committed, relPath) => {
    const before = signatureIn(fromSnap, relPath);
    const fromCurrent = signatureIn(current, relPath);
    const now = fromCurrent !== undefined ? fromCurrent : committed.has(relPath) ? statSignature(current.gitRoot, relPath) : undefined;
    return before !== undefined ? !sameFileSignature(before, now) : now !== undefined;
  };
  const canDiffTurnUntracked = Boolean(!baseline.untrackedTruncated && !current.untrackedTruncated && baseline.untrackedFiles && current.untrackedFiles);
  const canDiffGateUntracked = Boolean(
    postGateShell.length > 0 &&
      activeGate &&
      !activeGate.untrackedTruncated &&
      !current.untrackedTruncated &&
      activeGate.untrackedFiles &&
      current.untrackedFiles,
  );

  const trackedKeySet = new Set([
    ...Object.keys(current.files),
    ...Object.keys(baseline.files),
    ...Object.keys(activeGate?.files ?? {}),
    ...sinceTurn,
    ...sinceGate,
  ]);
  const turnUntrackedKeySet = canDiffTurnUntracked
    ? new Set([...Object.keys(current.untrackedFiles), ...Object.keys(baseline.untrackedFiles)])
    : new Set();
  const gateUntrackedKeySet = canDiffGateUntracked
    ? new Set([...Object.keys(current.untrackedFiles), ...Object.keys(activeGate.untrackedFiles)])
    : new Set();
  const allDiffKeys = new Set([...trackedKeySet, ...turnUntrackedKeySet, ...gateUntrackedKeySet]);

  for (const relPath of allDiffKeys) {
    if (isExemptDocOrAssetPath(relPath)) {
      continue;
    }
    const isTrackedCandidate = trackedKeySet.has(relPath);
    const canCheckGate = postGateShell.length > 0 && activeGate && (isTrackedCandidate || gateUntrackedKeySet.has(relPath));
    if (canCheckGate && changedBetween(activeGate, sinceGate, relPath)) {
      if (postGateWriter || !toolWroteAfterGate(relPath)) {
        record(relPath, datingStep(postGateShell));
      }
      continue;
    }
    const canCheckTurn = isTrackedCandidate || turnUntrackedKeySet.has(relPath);
    if (canCheckTurn && changedBetween(baseline, sinceTurn, relPath) && !preGateKeepsToolDate(relPath)) {
      record(relPath, preGateShell.length > 0 ? datingStep(preGateShell) : ledger.turnStartStepIndex);
    }
  }

  const untrackedIncomplete = Boolean(
    current.untrackedTruncated || baseline.untrackedTruncated || (postGateShell.length > 0 && activeGate?.untrackedTruncated),
  );
  if (untrackedIncomplete && riskyShellExecs.length > 0) {
    const baseMs = postGateWriter && activeGate?.capturedAtMs ? activeGate.capturedAtMs : baseline.capturedAtMs;
    const cutoffMs = Number.isFinite(baseMs) ? baseMs - 10 : 0;
    const targetStep = postGateWriter ? datingStep(postGateShell) : riskyStep;
    const markRecentUntracked = (step) => {
      for (const relPath of dirtyFiles) {
        if (isExemptDocOrAssetPath(relPath) || Object.hasOwn(baseline.files, relPath) || Object.hasOwn(current.files, relPath)) {
          continue;
        }
        const freshMs = statFreshnessMs(current.gitRoot, relPath);
        if (freshMs !== null && freshMs >= cutoffMs && !keepsToolDate(relPath)) {
          record(relPath, step);
        }
      }
      ledger.lastWriteStepIndex = Math.max(ledger.lastWriteStepIndex, step);
      ledger.lastCodeWriteStepIndex = Math.max(ledger.lastCodeWriteStepIndex, step);
      syncPendingAsyncAfterWrite(ledger);
    };
    if (postGateWriter || lastGateStep === -1 || riskyStep > lastGateStep) {
      markRecentUntracked(targetStep);
      return true;
    }
  }
  if (lastGateStep !== -1 && !activeGate) {
    const postMissingGateExec = shellExecs.findLast((exec) => exec.stepIndex > lastGateStep && isRiskyShellExec(exec));
    if (postMissingGateExec) {
      ledger.lastWriteStepIndex = Math.max(ledger.lastWriteStepIndex, postMissingGateExec.stepIndex);
      ledger.lastCodeWriteStepIndex = Math.max(ledger.lastCodeWriteStepIndex, postMissingGateExec.stepIndex);
      syncPendingAsyncAfterWrite(ledger);
      return true;
    }
  }
  return postGateDocRequiresReverify;
}

export function markPreflightChallengeLogged({
  conversationId,
  dedupKey,
  dataDir = resolvePluginDataDir(),
} = {}) {
  const filePath = resolveSessionStatePath(conversationId, dataDir);
  if (!filePath || typeof dedupKey !== "string" || dedupKey.length === 0) {
    return false;
  }
  return withSessionLock(filePath, () => {
    const prev = readSessionState(conversationId, dataDir) ?? { conversationId };
    const existing = Array.isArray(prev.loggedPreflightKeys)
      ? prev.loggedPreflightKeys.filter((k) => typeof k === "string" && k.length > 0)
      : [];
    if (existing.includes(dedupKey)) {
      return false;
    }
    const nextKeys = [...existing, dedupKey].slice(-50);
    const nextState = {
      ...prev,
      conversationId,
      updatedAt: new Date().toISOString(),
      loggedPreflightKeys: nextKeys,
    };
    try {
      atomicWriteJson(filePath, nextState);
      return true;
    } catch {
      return false;
    }
  });
}

function summarizeDiffStat(gitLedger) {
  if (!gitLedger?.diffNumstat || !(gitLedger.diffNumstat instanceof Map) || gitLedger.diffNumstat.size === 0) {
    return "변경량 없음";
  }
  let files = 0;
  let added = 0;
  let deleted = 0;
  for (const stat of gitLedger.diffNumstat.values()) {
    files += 1;
    added += Number.isFinite(stat?.added) ? stat.added : 0;
    deleted += Number.isFinite(stat?.deleted) ? stat.deleted : 0;
  }
  return `${files}개 파일 (+${added} / -${deleted}줄)`;
}

function collectRecentVerifications(ledger) {
  const execs = Array.isArray(ledger?.turnExecutions) ? ledger.turnExecutions : [];
  const verifications = execs.filter((exec) => exec.kind === "verification" && exec.hasResult !== false);
  return verifications.slice(-MAX_RECENT_VERIFICATIONS).map((exec) => ({
    command: exec.command || "",
    passed: Boolean(exec.passed),
    stepIndex: exec.stepIndex,
  }));
}

function detectEpistemicWarnings(verifiedFacts, ledger, cwd, gitRoot) {
  const warnings = [];
  const readFiles = ledger?.sessionReadFiles instanceof Set ? ledger.sessionReadFiles : new Set();
  const verifications = Array.isArray(ledger?.turnExecutions)
    ? ledger.turnExecutions.filter((exec) => exec.kind === "verification" && exec.hasResult !== false)
    : [];
  const lastVerification = verifications.length > 0 ? verifications[verifications.length - 1] : null;
  const hasUnresolvedFailure = Boolean(lastVerification && !lastVerification.passed);

  for (const fact of verifiedFacts) {
    if (typeof fact !== "string" || fact.trim().length === 0) {
      continue;
    }
    const withoutUrls = fact.replace(URL_SPAN_RE, " ");
    const matches = withoutUrls.matchAll(FILE_PATH_TOKEN_RE);
    for (const match of matches) {
      const candidate = normalizeWorkspacePath(match[1], cwd, gitRoot);
      if (candidate && !readFiles.has(candidate)) {
        const msg = `세션 열람 기록에 없는 파일 \`${candidate}\` 이 확인된 사실에 언급되었습니다.`;
        if (!warnings.includes(msg)) {
          warnings.push(msg);
        }
      }
    }
    if (hasUnresolvedFailure && TEST_CONTEXT_RE.test(fact) && PASS_CLAIM_RE.test(fact)) {
      const msg = `최근 검증 실행(\`${lastVerification.command}\`)이 실패 상태인데 확인된 사실에서 통과를 주장했습니다.`;
      if (!warnings.includes(msg)) {
        warnings.push(msg);
      }
    }
  }
  return warnings;
}

function generateSnapshotId() {
  const iso = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  return `${iso}-${randomBytes(8).toString("hex")}`;
}

function isSnapshotId(value) {
  return typeof value === "string" && SAFE_SNAPSHOT_ID_RE.test(value)
    && !/^(?:latest|pins|con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(value);
}

export function isHandoffPinOwner(value) {
  return typeof value === "string" && SAFE_PIN_OWNER_RE.test(value);
}

function handoffWorkspaceDir(dataDir, workspaceKey) {
  if (typeof workspaceKey !== "string" || !/^[0-9a-f]{12}$/.test(workspaceKey)) {
    throw new TypeError("Invalid handoff workspace key");
  }
  const root = join(dataDir, "handoffs");
  const workspaceDir = join(root, workspaceKey);
  for (const path of [root, workspaceDir]) {
    const entry = lstatSync(path, { throwIfNoEntry: false });
    if (entry && !entry.isDirectory()) {
      throw new Error("Handoff storage path is not a directory");
    }
  }
  return workspaceDir;
}

function handoffFileStat(path) {
  const entry = lstatSync(path, { throwIfNoEntry: false });
  if (entry && !entry.isFile()) {
    throw new Error("Handoff storage entry is not a regular file");
  }
  return entry;
}

function withHandoffLock(workspaceDir, fn) {
  const latestPath = join(workspaceDir, LATEST_HANDOFF_FILE);
  handoffFileStat(`${latestPath}.lock`);
  return withSessionLock(latestPath, () => fn(latestPath));
}

function readSnapshotFile(path, workspaceKey, snapshotId = "") {
  if (!handoffFileStat(path)) return null;
  const record = JSON.parse(readFileSync(path, "utf8"));
  if (!isSnapshotId(record?.snapshotId) || record.workspaceKey !== workspaceKey
    || (snapshotId && record.snapshotId !== snapshotId)) {
    throw new Error("Invalid handoff snapshot");
  }
  return record;
}

function readPinRoots(workspaceDir) {
  const path = join(workspaceDir, HANDOFF_PINS_FILE);
  const roots = new Map();
  if (!handoffFileStat(path)) return roots;
  const record = JSON.parse(readFileSync(path, "utf8"));
  if (record?.schemaVersion !== 1 || !Array.isArray(record.pins) || Object.keys(record).length !== 2) {
    throw new Error("Invalid handoff pin metadata");
  }
  for (const item of record.pins) {
    const { snapshotId, pinOwners } = item ?? {};
    if (!isSnapshotId(snapshotId) || roots.has(snapshotId) || Object.keys(item).length !== 2
      || !Array.isArray(pinOwners) || pinOwners.length === 0 || !pinOwners.every(isHandoffPinOwner)
      || new Set(pinOwners).size !== pinOwners.length) {
      throw new Error("Invalid handoff pin root");
    }
    roots.set(snapshotId, new Set(pinOwners));
  }
  return roots;
}

function pinItems(roots) {
  return [...roots.keys()].sort().map((snapshotId) => ({
    snapshotId, pinOwners: [...roots.get(snapshotId)].sort(),
  }));
}

function writePinRoots(workspaceDir, roots) {
  atomicWriteJson(join(workspaceDir, HANDOFF_PINS_FILE), { schemaVersion: 1, pins: pinItems(roots) });
}

function snapshotEntries(workspaceDir, workspaceKey, roots = new Map()) {
  const entries = [];
  for (const file of readdirSync(workspaceDir, { withFileTypes: true })) {
    if (!file.isFile() || !file.name.endsWith(".json")) continue;
    const snapshotId = file.name.slice(0, -5);
    if (!isSnapshotId(snapshotId) || roots.has(snapshotId)) continue;
    const path = join(workspaceDir, file.name);
    try {
      const stat = handoffFileStat(path);
      const snapshot = stat && readSnapshotFile(path, workspaceKey, snapshotId);
      if (snapshot) entries.push({ path, snapshot, mtimeMs: stat.mtimeMs });
    } catch {
      // Unknown or damaged entries are not safe to remove as snapshots.
    }
  }
  return entries;
}

function newestFirst(entries, latestId) {
  return entries.sort((a, b) =>
    Number(b.snapshot.snapshotId === latestId) - Number(a.snapshot.snapshotId === latestId)
    || b.mtimeMs - a.mtimeMs || b.snapshot.snapshotId.localeCompare(a.snapshot.snapshotId));
}

function pruneOldSnapshots(workspaceDir, workspaceKey, roots, latestId) {
  try {
    const entries = newestFirst(snapshotEntries(workspaceDir, workspaceKey, roots), latestId);
    let removed = 0;
    for (const { path } of entries.slice(MAX_SNAPSHOTS_PER_WORKSPACE)) {
      try {
        unlinkSync(path);
        removed += 1;
      } catch {
        // Best-effort retention; publication is already committed.
      }
    }
    return removed;
  } catch {
    return 0;
  }
}

function changePin(workspaceKey, snapshotId, pinOwner, dataDir, adding) {
  if (!isSnapshotId(snapshotId)) throw new TypeError("Invalid handoff snapshot ID");
  if (!isHandoffPinOwner(pinOwner)) throw new TypeError("Invalid handoff pin owner");
  const workspaceDir = handoffWorkspaceDir(dataDir, workspaceKey);
  if (!existsSync(workspaceDir)) return false;
  return withHandoffLock(workspaceDir, (latestPath) => {
    const roots = readPinRoots(workspaceDir);
    const owners = roots.get(snapshotId) ?? new Set();
    if (adding) {
      if (owners.has(pinOwner)) return false;
      if (!readSnapshotFile(join(workspaceDir, `${snapshotId}.json`), workspaceKey, snapshotId)) return false;
      owners.add(pinOwner);
      roots.set(snapshotId, owners);
      writePinRoots(workspaceDir, roots);
    } else {
      if (!owners.delete(pinOwner)) return false;
      const lastOwner = owners.size === 0;
      const latestId = lastOwner ? readSnapshotFile(latestPath, workspaceKey)?.snapshotId : undefined;
      if (lastOwner) roots.delete(snapshotId);
      writePinRoots(workspaceDir, roots);
      if (lastOwner) pruneOldSnapshots(workspaceDir, workspaceKey, roots, latestId);
    }
    return true;
  });
}

// A pin is a retention root for this owner, not an authorization credential.
export function pinSnapshot(workspaceKey, snapshotId, pinOwner, dataDir = resolvePluginDataDir()) {
  return changePin(workspaceKey, snapshotId, pinOwner, dataDir, true);
}

export function unpinSnapshot(workspaceKey, snapshotId, pinOwner, dataDir = resolvePluginDataDir()) {
  return changePin(workspaceKey, snapshotId, pinOwner, dataDir, false);
}

export function listPinnedSnapshots(workspaceKey, dataDir = resolvePluginDataDir()) {
  const workspaceDir = handoffWorkspaceDir(dataDir, workspaceKey);
  if (!existsSync(workspaceDir)) return [];
  return withHandoffLock(workspaceDir, () => pinItems(readPinRoots(workspaceDir)));
}

// Clear removes only unpinned snapshots; it invalidates an unpinned latest without promoting another root.
export function clearHandoffSnapshots({ cwd = "", gitLedger = null, dataDir = resolvePluginDataDir() } = {}) {
  const workspaceKey = computeWorkspaceKey(cwd, typeof gitLedger?.gitRoot === "string" ? gitLedger.gitRoot : "");
  const workspaceDir = handoffWorkspaceDir(dataDir, workspaceKey);
  if (!existsSync(workspaceDir)) return { workspaceKey, clearedCount: 0 };
  return withHandoffLock(workspaceDir, (latestPath) => {
    const roots = readPinRoots(workspaceDir);
    const latest = readSnapshotFile(latestPath, workspaceKey);
    const entries = snapshotEntries(workspaceDir, workspaceKey, roots);
    if (latest && !roots.has(latest.snapshotId)) unlinkSync(latestPath);
    for (const { path } of entries) unlinkSync(path);
    return { workspaceKey, clearedCount: entries.length };
  });
}

function normalizeTextArray(items) {
  if (!Array.isArray(items)) {
    return [];
  }
  return items.filter((v) => typeof v === "string" && v.trim().length > 0).map((v) => v.trim());
}

export function saveHandoffSnapshot({
  input = {},
  ledger = null,
  gitLedger = null,
  cwd = "",
  conversationId = "",
  dataDir = resolvePluginDataDir(),
  pinOwner,
} = {}) {
  if (pinOwner !== undefined && !isHandoffPinOwner(pinOwner)) {
    throw new TypeError("Invalid handoff pin owner");
  }
  const gitRoot = typeof gitLedger?.gitRoot === "string" ? gitLedger.gitRoot : "";
  const workspaceKey = computeWorkspaceKey(cwd, gitRoot);
  const workspaceDir = handoffWorkspaceDir(dataDir, workspaceKey);

  const objective = typeof input.objective === "string" ? input.objective.trim() : "";
  const verifiedFacts = normalizeTextArray(input.verified_facts);
  const failedApproaches = normalizeTextArray(input.failed_approaches);
  const remainingTasks = normalizeTextArray(input.remaining_tasks);
  const openRisks = normalizeTextArray(input.open_risks);

  const unverifiedWarnings = ledger?.transcriptAvailable
    ? detectEpistemicWarnings(verifiedFacts, ledger, cwd, gitRoot)
    : [];

  let maxSingleFileEdits = Number.isFinite(ledger?.maxSingleFileEdits) ? ledger.maxSingleFileEdits : 0;
  if (maxSingleFileEdits === 0 && ledger?.fileEditCounts instanceof Map) {
    for (const count of ledger.fileEditCounts.values()) {
      if (count > maxSingleFileEdits) {
        maxSingleFileEdits = count;
      }
    }
  }

  const dirtyFilesSorted = Array.from(gitLedger?.gitDirtyFiles ?? []).sort();
  const dirtyFingerprint = computeDirtyFingerprint(dirtyFilesSorted, gitRoot || cwd);

  const draft = {
    schemaVersion: 1,
    workspaceKey,
    sourceConversationId: conversationId,
    objective,
    verifiedFacts,
    failedApproaches,
    remainingTasks,
    openRisks,
    unverifiedWarnings,
    machineEvidence: {
      gitBranch: gitLedger?.gitBranch ?? "",
      gitHead: gitLedger?.gitHead ?? "",
      dirtyFiles: dirtyFilesSorted,
      dirtyFingerprint,
      diffStatSummary: summarizeDiffStat(gitLedger),
      sessionReadFiles: Array.from(ledger?.sessionReadFiles ?? []).sort().slice(0, 40),
      turnWrittenFiles: Array.from(ledger?.turnWrittenFiles ?? []).sort(),
      recentVerifications: collectRecentVerifications(ledger),
      sourceMetrics: {
        inputTokens: ledger?.latestTokens?.inputTokens ?? null,
        failedExecutionsInTurn: ledger?.turnFailedExecutionCount ?? 0,
        maxSingleFileEdits,
      },
    },
  };

  return withHandoffLock(workspaceDir, (latestPath) => {
    const roots = readPinRoots(workspaceDir);
    handoffFileStat(latestPath);
    let snapshotId;
    let snapshotPath;
    do {
      snapshotId = generateSnapshotId();
      snapshotPath = join(workspaceDir, `${snapshotId}.json`);
    } while (roots.has(snapshotId) || lstatSync(snapshotPath, { throwIfNoEntry: false }));
    const snapshot = { ...draft, snapshotId, savedAt: new Date().toISOString() };
    atomicWriteJson(snapshotPath, snapshot);
    // Publish the root before latest and prune. An interruption cannot expose a new unpinned latest.
    if (pinOwner !== undefined) {
      roots.set(snapshotId, new Set([pinOwner]));
      writePinRoots(workspaceDir, roots);
    }
    atomicWriteJson(latestPath, snapshot);
    const prunedCount = pruneOldSnapshots(workspaceDir, workspaceKey, roots, snapshotId);
    return { snapshot, workspaceKey, prunedCount };
  });
}

function sameStringList(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

export function formatLoadedHandoffText(snapshot, { treeChanged = false } = {}) {
  const lines = [
    "[팩트 증류 인수인계서]",
    `- 스냅샷: \`${snapshot.snapshotId}\` (저장 시각: \`${snapshot.savedAt}\`)`,
    `- 목표: ${snapshot.objective || "미기재"}`,
  ];

  if (treeChanged) {
    lines.push(HANDOFF_COPY.staleTreeWarning);
  }

  const ev = snapshot.machineEvidence ?? {};
  lines.push(
    `- 작업 공간 기준: 브랜치 \`${ev.gitBranch || "미확인"}\`, 커밋 \`${ev.gitHead || "없음"}\`, 변경량 ${ev.diffStatSummary || "없음"}`,
  );

  if (Array.isArray(ev.dirtyFiles) && ev.dirtyFiles.length > 0) {
    lines.push(`- 수정 중인 파일: ${ev.dirtyFiles.slice(0, 8).map((f) => `\`${f}\``).join(", ")}`);
  }

  if (Array.isArray(snapshot.verifiedFacts) && snapshot.verifiedFacts.length > 0) {
    lines.push("확인된 사실:");
    for (const fact of snapshot.verifiedFacts.slice(0, 6)) {
      lines.push(`- ${fact}`);
    }
  }

  if (Array.isArray(snapshot.failedApproaches) && snapshot.failedApproaches.length > 0) {
    lines.push("실패하거나 폐기한 접근:");
    for (const item of snapshot.failedApproaches.slice(0, 4)) {
      lines.push(`- ${item}`);
    }
  }

  if (Array.isArray(snapshot.remainingTasks) && snapshot.remainingTasks.length > 0) {
    lines.push("남은 작업:");
    for (const task of snapshot.remainingTasks.slice(0, 6)) {
      lines.push(`- ${task}`);
    }
  }

  if (Array.isArray(snapshot.openRisks) && snapshot.openRisks.length > 0) {
    lines.push("열린 위험:");
    for (const risk of snapshot.openRisks.slice(0, 3)) {
      lines.push(`- ${risk}`);
    }
  }

  if (Array.isArray(ev.recentVerifications) && ev.recentVerifications.length > 0) {
    const summary = ev.recentVerifications
      .slice(-3)
      .map((v) => `\`${v.command}\`(${v.passed ? "통과" : "실패"})`)
      .join(", ");
    lines.push(`- 최근 검증 기록: ${summary}`);
  }

  if (Array.isArray(snapshot.unverifiedWarnings) && snapshot.unverifiedWarnings.length > 0) {
    lines.push("주의(미확인 주장):");
    for (const warn of snapshot.unverifiedWarnings.slice(0, 3)) {
      lines.push(`- ${warn}`);
    }
  }

  return lines.join("\n");
}

export function loadHandoffSnapshot({
  snapshotId = "",
  cwd = "",
  gitLedger = null,
  dataDir = resolvePluginDataDir(),
} = {}) {
  const gitRoot = typeof gitLedger?.gitRoot === "string" ? gitLedger.gitRoot : "";
  const workspaceKey = computeWorkspaceKey(cwd, gitRoot);
  const trimmedId = typeof snapshotId === "string" ? snapshotId.trim() : "";
  const concreteId = trimmedId === "latest" ? "" : trimmedId;
  if (concreteId && !isSnapshotId(concreteId)) {
    return {
      ok: false,
      error: "올바르지 않은 스냅샷 식별자 형식입니다. 경로 구분자나 특수 문자 없이 지정해 주세요.",
      workspaceKey,
    };
  }

  const targetFile = concreteId ? `${concreteId}.json` : LATEST_HANDOFF_FILE;
  let snapshot;
  try {
    const workspaceDir = handoffWorkspaceDir(dataDir, workspaceKey);
    snapshot = readSnapshotFile(join(workspaceDir, targetFile), workspaceKey, concreteId);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      return {
        ok: false,
        error: "저장된 스냅샷 파일을 읽을 수 없습니다. 파일이 손상되었는지 확인해 주세요.",
        workspaceKey,
      };
    }
  }
  if (!snapshot) {
    return {
      ok: false,
      error:
        trimmedId.length > 0
          ? `요청한 스냅샷 \`${trimmedId}\` 을 현재 작업 공간에서 찾을 수 없습니다.`
          : "현재 작업 공간에 저장된 핸드오프 스냅샷이 없습니다.",
      workspaceKey,
    };
  }

  const savedHead = snapshot?.machineEvidence?.gitHead ?? "";
  const savedDirty = Array.isArray(snapshot?.machineEvidence?.dirtyFiles)
    ? [...snapshot.machineEvidence.dirtyFiles].sort()
    : [];
  const savedFingerprint = typeof snapshot?.machineEvidence?.dirtyFingerprint === "string"
    ? snapshot.machineEvidence.dirtyFingerprint
    : "";
  const currentHead = gitLedger?.gitHead ?? "";
  const currentDirty = Array.from(gitLedger?.gitDirtyFiles ?? []).sort();
  const currentFingerprint =
    savedFingerprint.length > 0 ? computeDirtyFingerprint(currentDirty, gitRoot || cwd) : "";

  const treeChanged = Boolean(
    gitLedger?.gitAvailable &&
      (savedHead !== currentHead ||
        !sameStringList(savedDirty, currentDirty) ||
        (savedFingerprint.length > 0 && savedFingerprint !== currentFingerprint)),
  );

  return {
    ok: true,
    snapshot,
    treeChanged,
    workspaceKey,
    formattedText: formatLoadedHandoffText(snapshot, { treeChanged }),
  };
}

export function listHandoffSnapshots({ cwd = "", gitLedger = null, dataDir = resolvePluginDataDir() } = {}) {
  const gitRoot = typeof gitLedger?.gitRoot === "string" ? gitLedger.gitRoot : "";
  const workspaceKey = computeWorkspaceKey(cwd, gitRoot);
  const workspaceDir = handoffWorkspaceDir(dataDir, workspaceKey);
  if (!existsSync(workspaceDir)) {
    return { workspaceKey, items: [] };
  }

  return withHandoffLock(workspaceDir, (latestPath) => {
    let latestId;
    try {
      latestId = readSnapshotFile(latestPath, workspaceKey)?.snapshotId;
    } catch {
      // A damaged pointer does not hide individually readable snapshots.
    }
    const items = newestFirst(snapshotEntries(workspaceDir, workspaceKey), latestId)
      .slice(0, MAX_LIST_SNAPSHOTS)
      .map(({ snapshot }) => ({
        snapshotId: snapshot.snapshotId, savedAt: snapshot.savedAt || "", objective: snapshot.objective || "",
      }));
    return { workspaceKey, items };
  });
}
