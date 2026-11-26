import { posix } from "node:path";
import { resolveAutonomyThresholds } from "./config.mjs";
import { DEFAULT_AUTONOMY_THRESHOLDS, isExemptDocOrAssetPath } from "./constants.mjs";
import { normalizeWorkspacePath } from "./fact-ledger.mjs";
import { isSensitiveFilePath } from "./risk-classifier.mjs";

const TEST_FILE_PATH_RE = /(?:^|\/)(?:test|tests|__tests__)(?:\/|$)|\.(?:test|spec)\.[^/]+$/i;
const MULTI_APPLY_TOOLS = new Set(["mcp_agy-fast_fast_apply_edits", "mcp_agy-fast_apply_edits"]);

const TIMING_SAFE_EQUAL_RE = /\btimingSafeEqual\b/g;
const FILE_LOCK_OPEN_WX_RE = /\bopenSync\s*\([^()\n]{0,120}["']wx["']/g;
const FILE_LOCK_SYMBOL_RE = /\b(?:flock|acquireLock|withLock|withFileLock|withSessionLock|Mutex|renameSync)\b/g;
const AUTH_VERIFY_CALL_RE =
  /\b(?:verifyToken|verifySessionToken|authorize|checkPermission|requireAuth|verifyCsrf|csrfToken|validateCsrf)\b/gi;
const EXPIRY_CHECK_LEFT_RE = /\b(?:expiresAt|expires_at|isExpired|exp)\b[^\n;]{0,60}(?:<=?|>=?|===?|!==?)/gi;
const EXPIRY_CHECK_RIGHT_RE = /(?:Date\.now\(\)|now)\s*(?:<=?|>=?)\s*[^\n;]{0,40}\b(?:expiresAt|expires_at|exp)\b/gi;
const EMPTY_TOKEN_GUARD_RE =
  /if\s*\(\s*!(?:token|signature|sig|secret|authHeader|csrf)\b|\b(?:token|signature|secret)\.length\s*===?\s*0\b/gi;
const LEGACY_TOKEN_RE = /(?:legacy|deprecated)/i;
const BRANCH_CONTEXT_RE = /(?:\b(?:if|else|case|switch|return|fallback)\b|[?]|\|\||\?\?)/i;

function countLegacyBranchLines(text) {
  if (typeof text !== "string" || text.length === 0) {
    return 0;
  }
  let count = 0;
  for (const line of text.split(/\r?\n/)) {
    if (LEGACY_TOKEN_RE.test(line) && (BRANCH_CONTEXT_RE.test(line) || /\bfallback\b|Fallback/i.test(line))) {
      count += 1;
    }
  }
  return count;
}
const TRY_BLOCK_RE = /\btry\s*\{/g;
const CATCH_BLOCK_RE = /\}\s*catch\b/g;
const ALT_ERROR_HANDLER_RE = /\.catch\s*\(|\btry\s*\{/;

function unwrapSerialized(value, depth = 0) {
  if (typeof value !== "string" || depth >= 2) {
    return value;
  }
  const trimmed = value.trim();
  const first = trimmed.charAt(0);
  if (first !== "{" && first !== "[" && first !== '"') {
    return value;
  }
  try {
    return unwrapSerialized(JSON.parse(trimmed), depth + 1);
  } catch {
    return value;
  }
}

function asObject(value) {
  const unwrapped = unwrapSerialized(value);
  return unwrapped && typeof unwrapped === "object" && !Array.isArray(unwrapped) ? unwrapped : null;
}

function asArray(value) {
  const unwrapped = unwrapSerialized(value);
  return Array.isArray(unwrapped) ? unwrapped : null;
}

function pickStr(obj, keys) {
  for (const key of keys) {
    if (typeof obj?.[key] === "string" && obj[key].length > 0) {
      return obj[key];
    }
  }
  return "";
}

function stripCommentsAndWhitespace(text) {
  if (typeof text !== "string" || text.length === 0) {
    return "";
  }
  return text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "")
    .replace(/^\s*#[^\n]*/gm, "")
    .replace(/\s+/g, "");
}

function countLines(text) {
  if (typeof text !== "string" || text.length === 0) {
    return 0;
  }
  const normalized = text.replace(/\r\n/g, "\n");
  const lines = normalized.split("\n");
  if (lines.length > 1 && lines[lines.length - 1] === "") {
    return lines.length - 1;
  }
  return lines.length;
}

function countMatches(text, re) {
  if (typeof text !== "string" || text.length === 0) {
    return 0;
  }
  re.lastIndex = 0;
  let count = 0;
  while (re.exec(text) !== null) {
    count += 1;
  }
  return count;
}

export function isExemptDestructiveTarget(relPath) {
  if (typeof relPath !== "string" || relPath.trim().length === 0) {
    return false;
  }
  const normalized = relPath.trim().replace(/\\/g, "/").replace(/^\.\//, "");
  if (isExemptDocOrAssetPath(normalized)) {
    return true;
  }
  if (TEST_FILE_PATH_RE.test(normalized)) {
    return true;
  }
  const base = posix.basename(normalized);
  return base.startsWith(".") && base.endsWith(".md");
}

function normalizePathSafe(rawPath, cwd, gitRoot) {
  if (typeof rawPath !== "string" || rawPath.trim().length === 0) {
    return "";
  }
  return normalizeWorkspacePath(rawPath, cwd, gitRoot) || rawPath.trim().replace(/\\/g, "/");
}

/**
 * 다양한 쓰기 도구 입력 스키마를 파일 단위 편집 레코드 목록으로 정규화한다.
 */
export function normalizeWriteOperations(toolName, toolInput, cwd = "", gitRoot = "") {
  const args = asObject(toolInput);
  if (!args || typeof toolName !== "string") {
    return [];
  }

  if (toolName === "edit_file") {
    const rawPath = pickStr(args, ["Path", "path"]);
    const relPath = normalizePathSafe(rawPath, cwd, gitRoot);
    if (!relPath) return [];
    const target = typeof args.Target === "string" ? args.Target : typeof args.target === "string" ? args.target : "";
    const replacement =
      typeof args.Replacement === "string"
        ? args.Replacement
        : typeof args.replacement === "string"
          ? args.replacement
          : "";
    return [{ targetPath: relPath, rawPath, hunks: [{ oldText: target, newText: replacement }], isFullOverwrite: false }];
  }

  if (toolName === "write_file" || toolName === "write_to_file") {
    const rawPath = pickStr(args, ["Path", "path", "TargetFile", "target_file"]);
    const relPath = normalizePathSafe(rawPath, cwd, gitRoot);
    if (!relPath) return [];
    const content =
      typeof args.Content === "string"
        ? args.Content
        : typeof args.CodeContent === "string"
          ? args.CodeContent
          : typeof args.content === "string"
            ? args.content
            : "";
    const isAppend = args.Append === true || args.append === true;
    return [{ targetPath: relPath, rawPath, fullContent: content, hunks: [], isFullOverwrite: !isAppend, isAppend }];
  }

  if (toolName === "replace_file_content") {
    const rawPath = pickStr(args, ["TargetFile", "target_file", "Path", "path"]);
    const relPath = normalizePathSafe(rawPath, cwd, gitRoot);
    if (!relPath) return [];
    const oldText = typeof args.TargetContent === "string" ? args.TargetContent : "";
    const newText = typeof args.ReplacementContent === "string" ? args.ReplacementContent : "";
    return [{ targetPath: relPath, rawPath, hunks: [{ oldText, newText }], isFullOverwrite: false }];
  }

  if (toolName === "multi_replace_file_content") {
    const rawPath = pickStr(args, ["TargetFile", "target_file", "Path", "path"]);
    const relPath = normalizePathSafe(rawPath, cwd, gitRoot);
    if (!relPath) return [];
    const rawChunks = asArray(args.ReplacementChunks ?? args.replacementChunks) ?? [];
    const hunks = rawChunks
      .map(asObject)
      .filter(Boolean)
      .map((chunk) => ({
        oldText: typeof chunk.TargetContent === "string" ? chunk.TargetContent : "",
        newText: typeof chunk.ReplacementContent === "string" ? chunk.ReplacementContent : "",
      }));
    return [{ targetPath: relPath, rawPath, hunks, isFullOverwrite: false }];
  }

  if (MULTI_APPLY_TOOLS.has(toolName)) {
    const baseCwd = pickStr(args, ["cwd"]) || cwd;
    const rawEdits = asArray(args.edits) ?? [];
    const ops = [];
    for (const rawEdit of rawEdits) {
      const edit = asObject(rawEdit);
      if (!edit) continue;
      const rawPath = pickStr(edit, ["path", "Path"]);
      const relPath = normalizePathSafe(rawPath, baseCwd, gitRoot);
      if (!relPath) continue;
      if (typeof edit.create === "string") {
        ops.push({
          targetPath: relPath,
          rawPath,
          baseCwd,
          fullContent: edit.create,
          hunks: [],
          isFullOverwrite: true,
          isAppend: false,
        });
        continue;
      }
      const rawHunks = asArray(edit.hunks) ?? [];
      const hunks = rawHunks
        .map(asObject)
        .filter(Boolean)
        .map((h) => ({
          oldText: typeof h.target === "string" ? h.target : "",
          newText: typeof h.replacement === "string" ? h.replacement : "",
        }));
      ops.push({ targetPath: relPath, rawPath, baseCwd, hunks, isFullOverwrite: false, isAppend: false });
    }
    return ops;
  }

  return [];
}

function detectRemovedPrimitives(oldText, newText) {
  if (typeof oldText !== "string" || typeof newText !== "string" || oldText.length === 0) {
    return [];
  }
  const removed = [];

  if (countMatches(oldText, TIMING_SAFE_EQUAL_RE) > 0 && countMatches(newText, TIMING_SAFE_EQUAL_RE) === 0) {
    removed.push("timingSafeEqual");
  }

  const oldLockCount = countMatches(oldText, FILE_LOCK_OPEN_WX_RE) + countMatches(oldText, FILE_LOCK_SYMBOL_RE);
  const newLockCount = countMatches(newText, FILE_LOCK_OPEN_WX_RE) + countMatches(newText, FILE_LOCK_SYMBOL_RE);
  if (oldLockCount > 0 && newLockCount === 0) {
    removed.push("file_lock_or_atomic");
  }

  const oldAuthCalls = countMatches(oldText, AUTH_VERIFY_CALL_RE);
  const newAuthCalls = countMatches(newText, AUTH_VERIFY_CALL_RE);
  const oldExpiry = countMatches(oldText, EXPIRY_CHECK_LEFT_RE) + countMatches(oldText, EXPIRY_CHECK_RIGHT_RE);
  const newExpiry = countMatches(newText, EXPIRY_CHECK_LEFT_RE) + countMatches(newText, EXPIRY_CHECK_RIGHT_RE);
  const oldEmptyGuard = countMatches(oldText, EMPTY_TOKEN_GUARD_RE);
  const newEmptyGuard = countMatches(newText, EMPTY_TOKEN_GUARD_RE);
  if (
    (oldAuthCalls > 0 && newAuthCalls === 0) ||
    (oldExpiry > 0 && newExpiry === 0) ||
    (oldEmptyGuard > 0 && newEmptyGuard === 0)
  ) {
    removed.push("auth_or_expiry_guard");
  }

  if (countLegacyBranchLines(oldText) > 0 && countLegacyBranchLines(newText) === 0) {
    removed.push("legacy_compat_fallback");
  }

  const oldTryCount = countMatches(oldText, TRY_BLOCK_RE);
  const oldCatchCount = countMatches(oldText, CATCH_BLOCK_RE);
  const newCatchCount = countMatches(newText, CATCH_BLOCK_RE);
  if (oldTryCount > 0 && oldCatchCount > 0 && newCatchCount === 0 && !ALT_ERROR_HANDLER_RE.test(newText)) {
    removed.push("try_catch_removed");
  }

  return removed;
}

function evaluateSingleOperation(op, existingContent, { config, deleteLinesThreshold }) {
  if (existingContent === null || existingContent === undefined) {
    return { destructive: false, reasons: [], deletedLines: 0, removedPrimitives: [] };
  }
  if (isExemptDestructiveTarget(op.targetPath)) {
    return { destructive: false, reasons: [], deletedLines: 0, removedPrimitives: [] };
  }
  if (op.isAppend) {
    return { destructive: false, reasons: [], deletedLines: 0, removedPrimitives: [] };
  }

  let oldSample = "";
  let newSample = "";
  let netDeletedLines = 0;

  if (op.isFullOverwrite) {
    oldSample = typeof existingContent === "string" ? existingContent : "";
    newSample = typeof op.fullContent === "string" ? op.fullContent : "";
    netDeletedLines = Math.max(0, countLines(oldSample) - countLines(newSample));
  } else {
    if (!Array.isArray(op.hunks) || op.hunks.length === 0) {
      return { destructive: false, reasons: [], deletedLines: 0, removedPrimitives: [] };
    }
    const oldParts = [];
    const newParts = [];
    for (const h of op.hunks) {
      oldParts.push(h.oldText ?? "");
      newParts.push(h.newText ?? "");
    }
    oldSample = oldParts.join("\n");
    newSample = newParts.join("\n");
    netDeletedLines = Math.max(0, countLines(oldSample) - countLines(newSample));
  }

  if (stripCommentsAndWhitespace(oldSample) === stripCommentsAndWhitespace(newSample)) {
    return { destructive: false, reasons: [], deletedLines: 0, removedPrimitives: [] };
  }

  const reasons = [];
  const removedPrimitives = detectRemovedPrimitives(oldSample, newSample);
  if (removedPrimitives.length > 0) {
    reasons.push("safety_primitive_removed");
  }

  if (isSensitiveFilePath(op.targetPath, config)) {
    if (op.isFullOverwrite) {
      const oldLines = countLines(oldSample);
      const newLines = countLines(newSample);
      const shrunkByRatio = oldLines >= deleteLinesThreshold && newLines <= oldLines * 0.6;
      if (netDeletedLines >= deleteLinesThreshold || shrunkByRatio) {
        reasons.push("sensitive_mass_delete");
      }
    } else if (netDeletedLines >= deleteLinesThreshold) {
      reasons.push("sensitive_mass_delete");
    }
  }

  return {
    destructive: reasons.length > 0,
    reasons,
    deletedLines: netDeletedLines,
    removedPrimitives,
  };
}

function lookupExistingContent(op, { existingFileContent, existingContentsByPath }) {
  if (existingContentsByPath instanceof Map) {
    if (existingContentsByPath.has(op.targetPath)) {
      return existingContentsByPath.get(op.targetPath);
    }
    if (op.rawPath && existingContentsByPath.has(op.rawPath)) {
      return existingContentsByPath.get(op.rawPath);
    }
  } else if (existingContentsByPath && typeof existingContentsByPath === "object") {
    if (Object.hasOwn(existingContentsByPath, op.targetPath)) {
      return existingContentsByPath[op.targetPath];
    }
    if (op.rawPath && Object.hasOwn(existingContentsByPath, op.rawPath)) {
      return existingContentsByPath[op.rawPath];
    }
  }
  return existingFileContent;
}

/**
 * 쓰기 도구 호출이 안전장치 삭제나 민감 파일 대규모 삭제에 해당하는지 판정한다.
 */
export function detectDestructiveEdit({
  toolName,
  toolInput,
  cwd = "",
  gitRoot = "",
  existingFileContent = null,
  existingContentsByPath = null,
  config = null,
  thresholds = DEFAULT_AUTONOMY_THRESHOLDS,
} = {}) {
  const ops = normalizeWriteOperations(toolName, toolInput, cwd, gitRoot);
  if (ops.length === 0) {
    return {
      destructive: false,
      reasons: [],
      targetPath: "",
      deletedLines: 0,
      removedPrimitives: [],
    };
  }

  const resolvedThresholds = config
    ? resolveAutonomyThresholds(undefined, config)
    : {
        ...DEFAULT_AUTONOMY_THRESHOLDS,
        ...(thresholds && typeof thresholds === "object" ? thresholds : {}),
      };
  const deleteLinesThreshold = resolvedThresholds.destructiveDeleteLines;

  let firstTargetPath = "";
  let maxDeletedLines = 0;
  const allReasons = new Set();
  const allRemoved = new Set();

  for (const op of ops) {
    const content = lookupExistingContent(op, { existingFileContent, existingContentsByPath });
    const res = evaluateSingleOperation(op, content, { config, deleteLinesThreshold });
    if (res.destructive) {
      if (!firstTargetPath) {
        firstTargetPath = op.targetPath;
      }
      if (res.deletedLines > maxDeletedLines) {
        maxDeletedLines = res.deletedLines;
      }
      for (const r of res.reasons) allReasons.add(r);
      for (const p of res.removedPrimitives) allRemoved.add(p);
    }
  }

  return {
    destructive: allReasons.size > 0,
    reasons: Array.from(allReasons),
    targetPath: firstTargetPath,
    deletedLines: maxDeletedLines,
    removedPrimitives: Array.from(allRemoved),
  };
}
