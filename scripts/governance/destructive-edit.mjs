import { posix } from "node:path";
import { resolveAutonomyThresholds } from "./config.mjs";
import { DEFAULT_AUTONOMY_THRESHOLDS, isExemptDocOrAssetPath } from "./constants.mjs";
import { asArray, asObject, normalizeWorkspacePath, pickString } from "./fact-ledger.mjs";
import { isSensitiveFilePath } from "./risk-classifier.mjs";

const TEST_FILE_PATH_RE = /(?:^|\/)(?:test|tests|__tests__)(?:\/|$)|\.(?:test|spec)\.[^/]+$/i;
const MULTI_APPLY_TOOLS = new Set(["mcp_agy-fast_fast_apply_edits", "mcp_agy-fast_apply_edits"]);

const TIMING_SAFE_EQUAL_RE = /\btimingSafeEqual\b/g;
const FILE_LOCK_OPEN_WX_RE = /\bopenSync\s*\([^()\n]{0,120}["']wx["']/g;
const FILE_LOCK_SYMBOL_RE = /\b(?:flock|acquireLock|withLock|withFileLock|withSessionLock|Mutex|renameSync)\b/g;
const AUTH_VERIFY_CALL_RE =
  /\b(?:verifyToken|verifySessionToken|authorize|checkPermission|requireAuth|verifyCsrf|csrfToken|validateCsrf)\b/gi;
const EXPIRY_CHECK_LEFT_RE = /\b(?:expiresAt|expires_at|isExpired|exp)\b[ \t]*(?:<=?|>=?|===?|!==?)/gi;
const EXPIRY_CHECK_RIGHT_RE = /(?:Date\.now\(\)|now)\s*(?:<=?|>=?)\s*[^\n;]{0,40}\b(?:expiresAt|expires_at|exp)\b/gi;
const EMPTY_TOKEN_GUARD_RE =
  /if\s*\(\s*!(?:token|signature|sig|secret|authHeader|csrf)\b|\b(?:token|signature|secret)\.length\s*===?\s*0\b/gi;
const LEGACY_TOKEN_RE = /(?:legacy|deprecated)/i;
const BRANCH_CONTEXT_RE = /(?:\b(?:if|else|case|switch|return|fallback)\b|[?]|\|\||\?\?)/i;
const TRY_BLOCK_RE = /\btry\s*\{/g;
const CATCH_BLOCK_RE = /\}\s*catch\b/g;
const ALT_ERROR_HANDLER_RE = /\.catch\s*\(|\btry\s*\{/;
const PATH_ARG_KEYS = ["Path", "path", "TargetFile", "target_file", "AbsolutePath", "absolute_path", "file_path"];

function countNewlines(text, from, to) {
  let count = 0;
  for (let i = text.indexOf("\n", from); i !== -1 && i < to; i = text.indexOf("\n", i + 1)) {
    count += 1;
  }
  return count;
}

// Single O(N) pass: real comments (`//`, `/* */`, line-leading `#`) become one space plus their newlines;
// '...', "..." and `...` are copied verbatim, so `//` inside a URL string stays code.
function stripCommentsOnly(text) {
  if (typeof text !== "string" || text.length === 0) {
    return "";
  }
  const parts = [];
  let copyFrom = 0;
  let quote = "";
  let lineStart = true;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quote) {
      if (ch === "\\") {
        i += 1;
      } else if (ch === quote || (ch === "\n" && quote !== "`")) {
        quote = "";
        lineStart = ch === "\n";
      }
      continue;
    }
    const next = text[i + 1];
    let commentEnd = -1;
    if (ch === "/" && next === "*") {
      const close = text.indexOf("*/", i + 2);
      commentEnd = close === -1 ? text.length : close + 2;
    } else if ((ch === "/" && next === "/") || (ch === "#" && lineStart)) {
      const newline = text.indexOf("\n", i);
      commentEnd = newline === -1 ? text.length : newline;
    }
    if (commentEnd !== -1) {
      parts.push(text.slice(copyFrom, i), " ", "\n".repeat(countNewlines(text, i, commentEnd)));
      copyFrom = commentEnd;
      i = commentEnd - 1;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") {
      quote = ch;
    } else if (ch === "\n") {
      lineStart = true;
    } else if (ch !== " " && ch !== "\t") {
      lineStart = false;
    }
  }
  parts.push(text.slice(copyFrom));
  return parts.join("");
}

// Quote-blind strip: a regex literal such as /`/ or /'/ opens a false string in stripCommentsOnly and hides
// a real comment after it, so removal checks also run on this view.
const PLAIN_COMMENT_RE = /\/\*[\s\S]*?\*\/|\/\*[\s\S]*|\/\/[^\n]*|^[ \t]*#[^\n]*/gm;

function stripCommentsPlain(text) {
  return typeof text === "string" ? text.replace(PLAIN_COMMENT_RE, " ") : "";
}

function countLegacyBranchLines(text) {
  if (typeof text !== "string" || text.length === 0) {
    return 0;
  }
  let count = 0;
  for (const line of text.split(/\r?\n/)) {
    if (LEGACY_TOKEN_RE.test(line) && BRANCH_CONTEXT_RE.test(line)) {
      count += 1;
    }
  }
  return count;
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

export function normalizeWriteOperations(toolName, toolInput, cwd = "", gitRoot = "") {
  const args = asObject(toolInput);
  if (!args || typeof toolName !== "string") {
    return [];
  }

  if (toolName === "edit_file") {
    const rawPath = pickString(args, PATH_ARG_KEYS);
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
    const rawPath = pickString(args, PATH_ARG_KEYS);
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
    const rawPath = pickString(args, PATH_ARG_KEYS);
    const relPath = normalizePathSafe(rawPath, cwd, gitRoot);
    if (!relPath) return [];
    const oldText = typeof args.TargetContent === "string" ? args.TargetContent : "";
    const newText = typeof args.ReplacementContent === "string" ? args.ReplacementContent : "";
    return [{ targetPath: relPath, rawPath, hunks: [{ oldText, newText }], isFullOverwrite: false }];
  }

  if (toolName === "multi_replace_file_content") {
    const rawPath = pickString(args, PATH_ARG_KEYS);
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
    const baseCwd = pickString(args, ["cwd"]) || cwd;
    const rawEdits = asArray(args.edits) ?? [];
    const ops = [];
    for (const rawEdit of rawEdits) {
      const edit = asObject(rawEdit);
      if (!edit) continue;
      const rawPath = pickString(edit, PATH_ARG_KEYS);
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
  const removed = new Set([
    ...removedPrimitivesInCode(stripCommentsOnly(oldText), stripCommentsOnly(newText)),
    ...removedPrimitivesInCode(stripCommentsPlain(oldText), stripCommentsPlain(newText)),
  ]);
  return [...removed];
}

function removedPrimitivesInCode(oldCode, newCode) {
  const removed = [];

  if (countMatches(oldCode, TIMING_SAFE_EQUAL_RE) > 0 && countMatches(newCode, TIMING_SAFE_EQUAL_RE) === 0) {
    removed.push("timingSafeEqual");
  }

  const oldLockCount = countMatches(oldCode, FILE_LOCK_OPEN_WX_RE) + countMatches(oldCode, FILE_LOCK_SYMBOL_RE);
  const newLockCount = countMatches(newCode, FILE_LOCK_OPEN_WX_RE) + countMatches(newCode, FILE_LOCK_SYMBOL_RE);
  if (oldLockCount > 0 && newLockCount === 0) {
    removed.push("file_lock_or_atomic");
  }

  const oldAuthCalls = countMatches(oldCode, AUTH_VERIFY_CALL_RE);
  const newAuthCalls = countMatches(newCode, AUTH_VERIFY_CALL_RE);
  const oldExpiry = countMatches(oldCode, EXPIRY_CHECK_LEFT_RE) + countMatches(oldCode, EXPIRY_CHECK_RIGHT_RE);
  const newExpiry = countMatches(newCode, EXPIRY_CHECK_LEFT_RE) + countMatches(newCode, EXPIRY_CHECK_RIGHT_RE);
  const oldEmptyGuard = countMatches(oldCode, EMPTY_TOKEN_GUARD_RE);
  const newEmptyGuard = countMatches(newCode, EMPTY_TOKEN_GUARD_RE);
  if (
    (oldAuthCalls > 0 && newAuthCalls === 0) ||
    (oldExpiry > 0 && newExpiry === 0) ||
    (oldEmptyGuard > 0 && newEmptyGuard === 0)
  ) {
    removed.push("auth_or_expiry_guard");
  }

  if (countLegacyBranchLines(oldCode) > 0 && countLegacyBranchLines(newCode) === 0) {
    removed.push("legacy_compat_fallback");
  }

  const oldTryCount = countMatches(oldCode, TRY_BLOCK_RE);
  const oldCatchCount = countMatches(oldCode, CATCH_BLOCK_RE);
  const newCatchCount = countMatches(newCode, CATCH_BLOCK_RE);
  if (oldTryCount > 0 && oldCatchCount > 0 && newCatchCount === 0 && !ALT_ERROR_HANDLER_RE.test(newCode)) {
    removed.push("try_catch_removed");
  }

  return removed;
}

function evaluateSingleOperation(op, existingInfo, { config, deleteLinesThreshold }) {
  const existingContent =
    existingInfo && typeof existingInfo === "object" ? existingInfo.content : existingInfo;
  const effectivePath =
    existingInfo && typeof existingInfo === "object" && typeof existingInfo.effectivePath === "string" && existingInfo.effectivePath.length > 0
      ? existingInfo.effectivePath
      : op.targetPath;

  if (existingContent === null || existingContent === undefined) {
    return { destructive: false, reasons: [], deletedLines: 0, removedPrimitives: [], targetPath: effectivePath };
  }
  if (isExemptDestructiveTarget(effectivePath)) {
    return { destructive: false, reasons: [], deletedLines: 0, removedPrimitives: [], targetPath: effectivePath };
  }
  if (op.isAppend) {
    return { destructive: false, reasons: [], deletedLines: 0, removedPrimitives: [], targetPath: effectivePath };
  }

  let oldSample = "";
  let newSample = "";
  let netDeletedLines = 0;

  if (op.isFullOverwrite) {
    oldSample = typeof existingContent === "string" ? existingContent : "";
    newSample = typeof op.fullContent === "string" ? op.fullContent : "";
    const existingLineCount =
      existingInfo && typeof existingInfo === "object" && Number.isFinite(existingInfo.lineCount)
        ? existingInfo.lineCount
        : countLines(oldSample);
    netDeletedLines = Math.max(0, existingLineCount - countLines(newSample));
  } else {
    if (!Array.isArray(op.hunks) || op.hunks.length === 0) {
      return { destructive: false, reasons: [], deletedLines: 0, removedPrimitives: [], targetPath: effectivePath };
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

  const sameIgnoringComments = (strip) => strip(oldSample).replace(/\s+/g, "") === strip(newSample).replace(/\s+/g, "");
  if (sameIgnoringComments(stripCommentsOnly) && sameIgnoringComments(stripCommentsPlain)) {
    return { destructive: false, reasons: [], deletedLines: 0, removedPrimitives: [], targetPath: effectivePath };
  }

  const reasons = [];
  const removedPrimitives = detectRemovedPrimitives(oldSample, newSample);
  if (removedPrimitives.length > 0) {
    reasons.push("safety_primitive_removed");
  }

  if (isSensitiveFilePath(effectivePath, config)) {
    if (op.isFullOverwrite) {
      const oldLines =
        existingInfo && typeof existingInfo === "object" && Number.isFinite(existingInfo.lineCount)
          ? existingInfo.lineCount
          : countLines(oldSample);
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
    targetPath: effectivePath,
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
        firstTargetPath = res.targetPath || op.targetPath;
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
