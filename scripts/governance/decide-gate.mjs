import { existsSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, posix, relative, resolve, win32 } from "node:path";
import {
  ALLOWED_AUDIT_ESCALATION_MODES,
  ALLOWED_SCHEMA_REGISTERS,
  PASSING_VERDICTS,
  POLLUTION_WARNING_LINE,
  REGISTER_COPY,
  RISK_REASON_LABELS,
} from "./constants.mjs";
import { classifyCommand, extractChainPrepInfo, extractPytestCommandInfo, hasPytestNonExecFlag, normalizeWorkspacePath, readRegularFileBounded, splitShellSegments, unwrapShellBuiltin } from "./fact-ledger.mjs";
import { detectHedges } from "./hedge-detector.mjs";
import { classifyRisk } from "./risk-classifier.mjs";

const BARE_RUNTIME_LAUNCHERS = new Set([
  "node",
  "npm",
  "npx",
  "pnpx",
  "bunx",
  "pnpm",
  "yarn",
  "python",
  "python3",
  "cargo",
  "go",
  "sh",
  "bash",
  "agy",
  "bun",
  "deno",
]);

function normalizeCommandText(cmd) {
  return typeof cmd === "string" ? cmd.trim().replace(/\s+/g, " ") : "";
}

function isBareRuntimeLauncher(normCmd) {
  return !normCmd.includes(" ") && BARE_RUNTIME_LAUNCHERS.has(normCmd);
}

function isWindowsLikePath(raw) {
  return process.platform === "win32" || /^\\\\[^\\]|^\/\/[^/]|^[A-Za-z]:[\\/]/.test(raw);
}

function normalizeExecDir(dir, { preserveSpaces = false } = {}) {
  if (typeof dir !== "string" || (preserveSpaces ? dir.length === 0 : dir.trim().length === 0)) {
    return ".";
  }
  const raw = preserveSpaces ? dir : dir.trim();
  if (isWindowsLikePath(raw)) {
    const isUnc = raw.startsWith("\\\\") || raw.startsWith("//");
    const winNorm = win32.normalize(raw.replace(/\//g, "\\")).replace(/\\/g, "/");
    if (isUnc && !winNorm.startsWith("//")) {
      return `//${winNorm.replace(/^\/+/, "").replace(/\/+$/, "")}`;
    }
    if (/^[A-Za-z]:\/$/.test(winNorm)) {
      return winNorm;
    }
    return winNorm.length > 1 ? winNorm.replace(/\/+$/, "") : winNorm;
  }
  const norm = posix.normalize(raw);
  return norm.length > 1 ? norm.replace(/\/+$/, "") : norm;
}

function isWindowsAbsolutePath(raw) {
  return /^\\\\[^\\]|^\/\/[^/]|^[A-Za-z]:[\\/]/.test(raw);
}

function isAbsoluteExecDir(raw) {
  return typeof raw === "string" && (raw.startsWith("/") || isWindowsAbsolutePath(raw));
}

function resolveExecDirStep(currentDir, dirArg, { preserveSpaces = false } = {}) {
  if (isAbsoluteExecDir(dirArg)) {
    return normalizeExecDir(dirArg, { preserveSpaces });
  }
  if (typeof currentDir === "string" && currentDir.startsWith("opaque:")) {
    return `${currentDir}/${dirArg}`;
  }
  if (!currentDir || currentDir === ".") {
    return normalizeExecDir(dirArg, { preserveSpaces });
  }
  return normalizeExecDir(`${currentDir}/${dirArg}`, { preserveSpaces });
}

function advanceDir(currentDir, op, arg, opaqueSeq) {
  if (op === "popd") {
    return currentDir.stack.length > 0 ? { dir: currentDir.stack.pop(), stack: currentDir.stack } : currentDir;
  }
  if (!arg || arg === "-" || arg.startsWith("~") || /[$`]/.test(arg)) {
    const stack = op === "pushd" ? [...currentDir.stack, currentDir.dir] : currentDir.stack;
    return { dir: `opaque:${opaqueSeq}:${arg ?? ""}`, stack };
  }
  const cleanArg = arg.replace(/^['"]|['"]$/g, "");
  const nextDir = resolveExecDirStep(currentDir.dir, cleanArg);
  const stack = op === "pushd" ? [...currentDir.stack, currentDir.dir] : currentDir.stack;
  return { dir: nextDir, stack };
}

function unsetClearsVar(args, varName) {
  let varOnly = false;
  let afterDoubleDash = false;
  for (let i = 0; i < args.length; i += 1) {
    const tok = args[i];
    if (!afterDoubleDash && tok === "--") {
      afterDoubleDash = true;
      continue;
    }
    if (!afterDoubleDash && tok.startsWith("-") && tok.length > 1) {
      if (tok === "-f" || tok === "-n") {
        return false;
      }
      if (tok === "-v") {
        varOnly = true;
        continue;
      }
      if (/^-[fnv]+$/.test(tok)) {
        if (tok.includes("f") || tok.includes("n")) {
          return false;
        }
        if (tok.includes("v")) {
          varOnly = true;
        }
        continue;
      }
      return false;
    }
    if (tok === varName) {
      return true;
    }
    if (varOnly) {
      continue;
    }
  }
  return false;
}

function parseSetAllexportUpdate(segTokens) {
  if (!segTokens || segTokens.length === 0) {
    return null;
  }
  let args = null;
  if (segTokens[0] === "set") {
    args = segTokens.slice(1);
  } else if (segTokens[0] === "command") {
    let idx = 1;
    while (idx < segTokens.length && segTokens[idx] === "-p") idx += 1;
    if (segTokens[idx] === "--") idx += 1;
    if (segTokens[idx] === "set") args = segTokens.slice(idx + 1);
  }
  if (!args) {
    return null;
  }
  let updated = null;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (!/^[-+][A-Za-z]+$/.test(arg)) continue;
    const enable = arg[0] === "-";
    for (let k = 1; k < arg.length; k += 1) {
      if (arg[k] === "a") updated = enable;
      else if (arg[k] === "o" && args[i + 1] === "allexport") {
        updated = enable;
        i += 1;
        break;
      }
    }
  }
  return updated;
}

function serializeOtherEnv(exportedMap, opaque) {
  if (opaque) return "__OPAQUE__";
  if (exportedMap.size === 0) return "";
  return JSON.stringify([...exportedMap.entries()].sort((a, b) => a[0].localeCompare(b[0])));
}

function extractVerificationEntries(
  cmd,
  baseDir = ".",
  {
    initialEnvPytestAddopts = null,
    initialEnvPytestOpaque = false,
    initialEnvPytestExported = false,
    initialAllexport = false,
    initialOtherEnv = null,
    initialOtherEnvOpaque = false,
  } = {},
) {
  if (typeof cmd !== "string" || cmd.trim().length === 0) {
    return [];
  }
  const entries = [];
  let state = { dir: normalizeExecDir(baseDir, { preserveSpaces: true }), stack: [] };
  let prepPrefixes = [];
  let prepItems = [];
  let seq = 0;
  let allexport = Boolean(initialAllexport);
  let chainEnvPytestExported = Boolean(initialEnvPytestExported || initialEnvPytestAddopts !== null || initialEnvPytestOpaque);
  let chainEnvPytestAddopts = initialEnvPytestAddopts;
  let chainEnvPytestOpaque = initialEnvPytestOpaque;
  let localPytestAddopts = initialEnvPytestAddopts;
  let localPytestOpaque = initialEnvPytestOpaque;
  const exportedOtherEnv = new Map(initialOtherEnv ?? []);
  const localOtherEnv = new Map(initialOtherEnv ?? []);
  let otherEnvOpaque = Boolean(initialOtherEnvOpaque);

  for (const seg of splitShellSegments(cmd)) {
    const rawTrimmed = seg.trim();
    if (rawTrimmed.length === 0) {
      continue;
    }
    const segTokens = splitQuotedWhitespace(rawTrimmed);
    if (segTokens === null) {
      if (/\bPYTEST_ADDOPTS\b/.test(rawTrimmed)) {
        chainEnvPytestOpaque = true;
        localPytestOpaque = true;
      }
      if (/=/.test(rawTrimmed) || /\b(?:export|unset)\b/.test(rawTrimmed)) {
        otherEnvOpaque = true;
      }
    }
    if (segTokens === null && /^(?:cd|pushd|popd)(?:\s|$)/.test(rawTrimmed)) {
      seq += 1;
      state = advanceDir(state, rawTrimmed.split(/\s+/, 1)[0], "$opaque", seq);
      continue;
    }
    if (segTokens && segTokens.length > 0 && /^(?:cd|pushd|popd)$/.test(segTokens[0])) {
      seq += 1;
      const dirArg = segTokens.length === 2 && !segTokens[1].startsWith("-") ? segTokens[1] : segTokens.length === 1 ? undefined : `$${segTokens.slice(1).join(" ")}`;
      if (dirArg === undefined || dirArg === "-" || dirArg.startsWith("~") || /[$`]/.test(dirArg)) {
        state = advanceDir(state, segTokens[0], dirArg, seq);
      } else {
        const nextDir = resolveExecDirStep(state.dir, dirArg, { preserveSpaces: true });
        const stack = segTokens[0] === "pushd" ? [...state.stack, state.dir] : state.stack;
        state = { dir: nextDir, stack };
      }
      continue;
    }
    const unwrapped = unwrapShellBuiltin(segTokens);
    const nextAllexport = parseSetAllexportUpdate(segTokens);
    if (nextAllexport !== null) {
      allexport = nextAllexport;
      continue;
    }
    if (unwrapped?.builtin === "export") {
      for (const tok of unwrapped.args) {
        if (tok === "PYTEST_ADDOPTS") {
          chainEnvPytestExported = true;
          chainEnvPytestAddopts = localPytestAddopts ?? chainEnvPytestAddopts;
          chainEnvPytestOpaque = Boolean(chainEnvPytestOpaque || localPytestOpaque);
        } else if (tok.startsWith("PYTEST_ADDOPTS=")) {
          chainEnvPytestExported = true;
          chainEnvPytestAddopts = tok.slice("PYTEST_ADDOPTS=".length);
          chainEnvPytestOpaque = /[$`]/.test(rawTrimmed);
          localPytestAddopts = chainEnvPytestAddopts;
          localPytestOpaque = chainEnvPytestOpaque;
        } else if (tok.includes("=")) {
          const eq = tok.indexOf("=");
          const k = tok.slice(0, eq);
          const v = tok.slice(eq + 1);
          localOtherEnv.set(k, v);
          exportedOtherEnv.set(k, v);
          if (/[$`]/.test(v)) otherEnvOpaque = true;
        } else if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(tok)) {
          if (localOtherEnv.has(tok)) {
            exportedOtherEnv.set(tok, localOtherEnv.get(tok));
          } else {
            otherEnvOpaque = true;
          }
        }
      }
      continue;
    } else if (unwrapped?.builtin === "unset") {
      if (unsetClearsVar(unwrapped.args, "PYTEST_ADDOPTS")) {
        chainEnvPytestExported = false;
        chainEnvPytestAddopts = null;
        chainEnvPytestOpaque = false;
        localPytestAddopts = null;
        localPytestOpaque = false;
      }
      for (const tok of unwrapped.args) {
        if (!tok.startsWith("-") && /^[A-Za-z_][A-Za-z0-9_]*$/.test(tok)) {
          exportedOtherEnv.delete(tok);
          localOtherEnv.delete(tok);
        }
      }
      continue;
    } else if (segTokens && segTokens.length > 0 && segTokens.every((t) => ENV_ASSIGNMENT_RE.test(t))) {
      for (const tok of segTokens) {
        if (tok.startsWith("PYTEST_ADDOPTS=")) {
          localPytestAddopts = tok.slice("PYTEST_ADDOPTS=".length);
          localPytestOpaque = /[$`]/.test(rawTrimmed);
          if (chainEnvPytestExported || allexport) {
            chainEnvPytestExported = true;
            chainEnvPytestAddopts = localPytestAddopts;
            chainEnvPytestOpaque = localPytestOpaque;
          }
        } else {
          const eq = tok.indexOf("=");
          const k = tok.slice(0, eq);
          const v = tok.slice(eq + 1);
          localOtherEnv.set(k, v);
          if (allexport || exportedOtherEnv.has(k)) {
            exportedOtherEnv.set(k, v);
            if (/[$`]/.test(v)) otherEnvOpaque = true;
          }
        }
      }
      continue;
    }
    const norm = normalizeCommandText(seg);
    const prepInfo = extractChainPrepInfo(seg);
    if (prepInfo) {
      prepPrefixes.push(`${state.dir}::${prepInfo.sig}`);
      prepItems.push({ dir: state.dir, dirs: prepInfo.dirs, prefixTokens: prepInfo.prefixTokens, argv: prepInfo.argv, opaque: prepInfo.opaque });
      continue;
    }
    if (classifyCommand(norm) === "verification") {
      entries.push({
        seg: rawTrimmed,
        dir: state.dir,
        prepKey: prepPrefixes.join(" && "),
        prepItems: [...prepItems],
        envPytestAddopts: chainEnvPytestAddopts,
        envPytestOpaque: chainEnvPytestOpaque,
        allexport,
        otherEnvMap: new Map(exportedOtherEnv),
        otherEnvKey: serializeOtherEnv(exportedOtherEnv, otherEnvOpaque),
        otherEnvOpaque,
      });
    }
  }
  return entries;
}

function extractVerificationSegments(cmd) {
  return extractVerificationEntries(cmd).map((entry) => entry.seg);
}

// Runner prefixes whose form without file targets runs the whole suite. `go test` is absent on purpose:
// without targets it tests only the current package, so go widens only to `./...`.
const ALL_TESTS_WITHOUT_TARGETS = [
  ["node", "--test"],
  ["npm", "test"],
  ["npm", "t"],
  ["npm", "run", "test"],
  ["pnpm", "test"],
  ["pnpm", "run", "test"],
  ["yarn", "test"],
  ["yarn", "run", "test"],
  ["bun", "test"],
  ["bun", "run", "test"],
  ["vitest"],
  ["vitest", "run"],
  ["npx", "vitest"],
  ["npx", "vitest", "run"],
  ["pnpx", "vitest"],
  ["pnpx", "vitest", "run"],
  ["bunx", "vitest"],
  ["bunx", "vitest", "run"],
  ["jest"],
  ["npx", "jest"],
  ["pnpx", "jest"],
  ["bunx", "jest"],
  ["pytest"],
  ["python", "-m", "pytest"],
  ["python3", "-m", "pytest"],
];
const SHELL_OPERATOR_TOKEN_RE = /[|&;()<>`$]/;
const ENV_ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

function isPathTarget(token, runnerPrefix = []) {
  const raw = Array.isArray(runnerPrefix) && runnerPrefix.includes("pytest") ? token.split("::")[0] : token;
  return Boolean(raw) && !raw.startsWith("-") && !raw.includes("=") && (/[/\\*]/.test(raw) || /\.[A-Za-z0-9]+$/.test(raw));
}

const EXCLUDED_TEST_DIRS_RE = /(?:^|\/)(?:node_modules|\.git|\.venv|venv|__pycache__|build|dist|\.tox|\.nox|\.eggs)(?:\/|$)/;

function toPlatformPosix(rawPath) {
  if (process.platform === "win32" || /^[A-Za-z]:\\|^\\\\/.test(rawPath)) {
    return rawPath.replace(/\\/g, "/");
  }
  return rawPath;
}

function normalizeTestpathItem(raw) {
  return toPlatformPosix(raw).replace(/^\.\//, "").replace(/\/+$/, "");
}

function unwrapSingleShellQuotePair(token) {
  if (typeof token !== "string" || token.length < 2) {
    return token;
  }
  const first = token[0];
  const last = token[token.length - 1];
  if ((first === "'" || first === '"') && last === first) {
    return token.slice(1, -1);
  }
  return token;
}

const SHELL_EXPANSION_META_RE = /[*?[\]~$`{}]/;

function splitQuotedWhitespaceWithMeta(rawValue, { splitComma = false } = {}) {
  const items = [];
  let cur = "";
  let quote = null;
  let hasToken = false;
  let unquotedMetaPositions = [];
  for (let i = 0; i < rawValue.length; i += 1) {
    const ch = rawValue[i];
    if (quote) {
      if (ch === "\\" && quote === '"' && i + 1 < rawValue.length) {
        const next = rawValue[i + 1];
        if (next === '"' || next === "\\" || next === "$" || next === "`" || next === "\n") {
          i += 1;
          cur += next;
        } else {
          cur += ch;
        }
      } else if (ch === quote) {
        quote = null;
      } else {
        cur += ch;
      }
      continue;
    }
    if (ch === "\\" && i + 1 < rawValue.length) {
      i += 1;
      cur += rawValue[i];
      hasToken = true;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      hasToken = true;
      continue;
    }
    if (/\s/.test(ch) || (splitComma && ch === ",")) {
      if (hasToken) {
        items.push({ value: cur, unquotedMetaMask: unquotedMetaPositions.join(",") });
        cur = "";
        hasToken = false;
        unquotedMetaPositions = [];
      }
      continue;
    }
    if (SHELL_EXPANSION_META_RE.test(ch)) {
      unquotedMetaPositions.push(cur.length);
    }
    cur += ch;
    hasToken = true;
  }
  if (quote !== null) {
    return null;
  }
  if (hasToken) {
    items.push({ value: cur, unquotedMetaMask: unquotedMetaPositions.join(",") });
  }
  return items;
}

function splitQuotedWhitespace(rawValue, opts) {
  const meta = splitQuotedWhitespaceWithMeta(rawValue, opts);
  return meta ? meta.map((t) => t.value) : null;
}

function decodeTomlStringToken(rawBody, startIdx) {
  const quote = rawBody[startIdx];
  if (quote !== '"' && quote !== "'") {
    return null;
  }
  if (rawBody.slice(startIdx, startIdx + 3) === quote.repeat(3)) {
    return null;
  }
  let i = startIdx + 1;
  if (quote === "'") {
    while (i < rawBody.length) {
      if (rawBody[i] === "'") {
        return { value: rawBody.slice(startIdx + 1, i), nextIdx: i + 1 };
      }
      if (rawBody[i] === "\n" || rawBody[i] === "\r") {
        return null;
      }
      i += 1;
    }
    return null;
  }
  let out = "";
  while (i < rawBody.length) {
    const ch = rawBody[i];
    if (ch === '"') {
      return { value: out, nextIdx: i + 1 };
    }
    if (ch === "\n" || ch === "\r") {
      return null;
    }
    if (ch === "\\") {
      if (i + 1 >= rawBody.length) {
        return null;
      }
      const esc = rawBody[i + 1];
      if (esc === "b") { out += "\b"; i += 2; continue; }
      if (esc === "t") { out += "\t"; i += 2; continue; }
      if (esc === "n") { out += "\n"; i += 2; continue; }
      if (esc === "f") { out += "\f"; i += 2; continue; }
      if (esc === "r") { out += "\r"; i += 2; continue; }
      if (esc === '"') { out += '"'; i += 2; continue; }
      if (esc === "\\") { out += "\\"; i += 2; continue; }
      if (esc === "u" && /^[0-9A-Fa-f]{4}$/.test(rawBody.slice(i + 2, i + 6))) {
        out += String.fromCodePoint(parseInt(rawBody.slice(i + 2, i + 6), 16));
        i += 6;
        continue;
      }
      if (esc === "U" && /^[0-9A-Fa-f]{8}$/.test(rawBody.slice(i + 2, i + 10))) {
        const cp = parseInt(rawBody.slice(i + 2, i + 10), 16);
        if (cp > 0x10ffff) return null;
        out += String.fromCodePoint(cp);
        i += 10;
        continue;
      }
      return null;
    }
    out += ch;
    i += 1;
  }
  return null;
}

function parseTomlStringArrayRaw(rawArrayBody) {
  const items = [];
  let i = 0;
  while (i < rawArrayBody.length) {
    const ch = rawArrayBody[i];
    if (/\s|,/.test(ch)) {
      i += 1;
      continue;
    }
    if (ch === "#") {
      while (i < rawArrayBody.length && rawArrayBody[i] !== "\n") {
        i += 1;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      const decoded = decodeTomlStringToken(rawArrayBody, i);
      if (!decoded) {
        return null;
      }
      items.push(decoded.value);
      i = decoded.nextIdx;
      continue;
    }
    return null;
  }
  return items;
}

function parseTomlStringArray(rawArrayBody) {
  const rawItems = parseTomlStringArrayRaw(rawArrayBody);
  return rawItems ? rawItems.map(normalizeTestpathItem).filter(Boolean) : null;
}

const PYTEST_COLLECTION_OVERRIDE_KEYS = new Set([
  "python_files",
  "python_classes",
  "python_functions",
  "norecursedirs",
]);

const MAX_PYTEST_CONFIG_LINE_CHARS = 16384;

function stripIniInlineComment(raw) {
  let quote = null;
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    if (quote) {
      if (ch === "\\" && quote === '"' && i + 1 < raw.length) {
        i += 1;
        continue;
      }
      if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if ((ch === "#" || ch === ";") && (i === 0 || raw[i - 1] === " " || raw[i - 1] === "\t")) {
      return raw.slice(0, i).trim();
    }
  }
  return raw.trim();
}

function parseIniTestpaths(text, targetSections) {
  const lines = text.split(/\r?\n/);
  let inTargetSection = false;
  let sawTargetSection = false;
  let foundKey = false;
  let hasCollectionOverride = false;
  let hasDryRunAddopts = false;
  let uncertain = false;
  const collected = [];
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.length > MAX_PYTEST_CONFIG_LINE_CHARS) {
      return { restricted: true, paths: [], hasDryRunAddopts: true, uncertain: true };
    }
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";")) {
      continue;
    }
    const secMatch = /^\[([^\]]+)\]\s*$/.exec(trimmed);
    if (secMatch) {
      inTargetSection = targetSections.has(secMatch[1].trim().toLowerCase());
      sawTargetSection ||= inTargetSection;
      continue;
    }
    if (!inTargetSection) {
      continue;
    }
    const genericKeyMatch = /^([A-Za-z0-9_.-]+)\s*=/.exec(trimmed);
    if (genericKeyMatch) {
      const keyLower = genericKeyMatch[1].toLowerCase();
      if (PYTEST_COLLECTION_OVERRIDE_KEYS.has(keyLower)) {
        hasCollectionOverride = true;
      } else if (keyLower === "addopts") {
        let rawAddopts = stripIniInlineComment(trimmed.slice(trimmed.indexOf("=") + 1));
        for (let j = i + 1; j < lines.length; j += 1) {
          const nextLine = lines[j];
          const nextTrimmed = nextLine.trim();
          if (!nextTrimmed || nextTrimmed.startsWith("#") || nextTrimmed.startsWith(";")) {
            continue;
          }
          if (/^[ \t]+/.test(nextLine) && !nextTrimmed.startsWith("[")) {
            rawAddopts += ` ${stripIniInlineComment(nextTrimmed)}`;
            i = j;
          } else {
            break;
          }
        }
        const addoptsTokens = splitQuotedWhitespace(rawAddopts);
        if (!addoptsTokens) {
          hasCollectionOverride = true;
          hasDryRunAddopts = true;
          uncertain = true;
        } else {
          if (addoptsTokens.some((tok) => isPytestAddoptsUnsafeToken(tok))) {
            hasCollectionOverride = true;
          }
          if (hasPytestNonExecFlag(addoptsTokens)) {
            hasDryRunAddopts = true;
          }
        }
      }
    }
    const keyMatch = /^testpaths\s*=\s*(.*)$/i.exec(trimmed);
    if (keyMatch) {
      foundKey = true;
      const firstVal = stripIniInlineComment(keyMatch[1]);
      if (firstVal) {
        const splitFirst = shlexSplitTestpaths(firstVal);
        if (!splitFirst) return { restricted: true, paths: [], hasDryRunAddopts, uncertain: true };
        collected.push(...splitFirst);
      }
      for (let j = i + 1; j < lines.length; j += 1) {
        const nextLine = lines[j];
        const nextTrimmed = nextLine.trim();
        if (!nextTrimmed || nextTrimmed.startsWith("#") || nextTrimmed.startsWith(";")) {
          continue;
        }
        if (/^[ \t]+/.test(nextLine) && !nextTrimmed.startsWith("[") && !nextTrimmed.includes("=")) {
          const clean = stripIniInlineComment(nextTrimmed);
          const splitNext = shlexSplitTestpaths(clean);
          if (!splitNext) return { restricted: true, paths: [], hasDryRunAddopts, uncertain: true };
          collected.push(...splitNext);
          i = j;
        } else {
          break;
        }
      }
    }
  }
  if (!sawTargetSection) {
    return null;
  }
  if (hasCollectionOverride) {
    return { restricted: true, paths: [], hasDryRunAddopts, uncertain };
  }
  return foundKey
    ? { restricted: true, paths: collected, hasDryRunAddopts, uncertain }
    : { restricted: false, paths: [], hasDryRunAddopts, uncertain };
}

function shlexSplitTestpaths(rawValue) {
  const rawItems = splitQuotedWhitespace(rawValue, { splitComma: false });
  return rawItems ? rawItems.map(normalizeTestpathItem).filter(Boolean) : null;
}

function parseTomlBracketArrayContent(rawRhsTrimmed) {
  if (!rawRhsTrimmed.startsWith("[")) {
    return null;
  }
  let i = 1;
  let quote = null;
  while (i < rawRhsTrimmed.length) {
    const ch = rawRhsTrimmed[i];
    if (quote) {
      if (ch === "\\" && quote === '"' && i + 1 < rawRhsTrimmed.length) {
        i += 2;
        continue;
      }
      if (ch === quote) {
        quote = null;
      }
      i += 1;
      continue;
    }
    if (ch === "#") {
      while (i < rawRhsTrimmed.length && rawRhsTrimmed[i] !== "\n") {
        i += 1;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      i += 1;
      continue;
    }
    if (ch === "]") {
      const trailing = rawRhsTrimmed.slice(i + 1).trim();
      return trailing.length === 0 ? rawRhsTrimmed.slice(1, i) : null;
    }
    i += 1;
  }
  return null;
}

function parseTomlKeySegments(rawKeyPart) {
  const segs = [];
  let i = 0;
  while (i < rawKeyPart.length) {
    while (i < rawKeyPart.length && /[ \t.]/.test(rawKeyPart[i])) {
      i += 1;
    }
    if (i >= rawKeyPart.length) {
      break;
    }
    const ch = rawKeyPart[i];
    if (ch === '"' || ch === "'") {
      const dec = decodeTomlStringToken(rawKeyPart, i);
      if (!dec) {
        return null;
      }
      segs.push(dec.value);
      i = dec.nextIdx;
    } else {
      const m = /^[A-Za-z0-9_-]+/.exec(rawKeyPart.slice(i));
      if (!m) {
        return null;
      }
      segs.push(m[0]);
      i += m[0].length;
    }
  }
  return segs;
}

function advanceTomlLexState(rawLine, inMultilineQuote) {
  let quote = inMultilineQuote;
  let commentAt = -1;
  let bracketDepthDelta = 0;
  let sawTripleInIni = false;
  for (let i = 0; i < rawLine.length; i += 1) {
    const ch = rawLine[i];
    if (quote === '"""' || quote === "'''") {
      sawTripleInIni = true;
      if (quote === '"""' && ch === "\\") {
        i += 1;
        continue;
      }
      if (rawLine.slice(i, i + 3) === quote) {
        quote = null;
        i += 2;
      }
      continue;
    }
    if (quote === '"' || quote === "'") {
      if (quote === '"' && ch === "\\") {
        i += 1;
        continue;
      }
      if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === "#") {
      commentAt = i;
      break;
    }
    if (rawLine.slice(i, i + 3) === '"""' || rawLine.slice(i, i + 3) === "'''") {
      sawTripleInIni = true;
      quote = rawLine.slice(i, i + 3);
      i += 2;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === "[" || ch === "{") {
      bracketDepthDelta += 1;
    } else if (ch === "]" || ch === "}") {
      bracketDepthDelta -= 1;
    }
  }
  const codeOnly = commentAt === -1 ? rawLine : rawLine.slice(0, commentAt);
  const nextMultiline = quote === '"""' || quote === "'''" ? quote : null;
  return { codeOnly, nextMultiline, sawTriple: sawTripleInIni, bracketDepthDelta };
}

function arrayMatchesPrefix(arr, prefix) {
  return prefix.length <= arr.length && prefix.every((seg, idx) => arr[idx] === seg);
}

function parseTomlValueAsStringList(rawRhs) {
  const rhsTrim = rawRhs.trim();
  if (rhsTrim.startsWith("[")) {
    const arrBody = parseTomlBracketArrayContent(rhsTrim);
    if (arrBody === null) {
      return null;
    }
    return { kind: "array", items: parseTomlStringArrayRaw(arrBody) };
  }
  const dec = decodeTomlStringToken(rhsTrim, 0);
  if (!dec || rhsTrim.slice(dec.nextIdx).trim()) {
    return null;
  }
  return { kind: "string", value: dec.value };
}

function parseAddoptsValue(rawRhs) {
  const parsed = parseTomlValueAsStringList(rawRhs);
  if (!parsed) {
    return null;
  }
  if (parsed.kind === "array") {
    if (!parsed.items) {
      return null;
    }
    const tokens = [];
    for (const item of parsed.items) {
      const parts = splitQuotedWhitespace(item);
      if (!parts) {
        return null;
      }
      tokens.push(...parts);
    }
    return tokens;
  }
  return splitQuotedWhitespace(parsed.value);
}

function parseTestpathsValue(rawRhs) {
  const parsed = parseTomlValueAsStringList(rawRhs);
  if (!parsed) {
    return null;
  }
  if (parsed.kind === "array") {
    return parsed.items ? parsed.items.map(normalizeTestpathItem).filter(Boolean) : null;
  }
  return shlexSplitTestpaths(parsed.value);
}

function evaluatePytestIniEntries(entries) {
  let hasCollectionOverride = false;
  let hasDryRunAddopts = false;
  let uncertain = false;
  let testpathsCount = 0;
  let addoptsCount = 0;
  let collectedPaths = null;

  for (const entry of entries) {
    if (PYTEST_COLLECTION_OVERRIDE_KEYS.has(entry.key)) {
      hasCollectionOverride = true;
    } else if (entry.key === "addopts") {
      addoptsCount += 1;
      if (addoptsCount > 1) {
        return { restricted: true, paths: [], hasDryRunAddopts: true, uncertain: true };
      }
      const addoptsTokens = parseAddoptsValue(entry.rawValue);
      if (!addoptsTokens) {
        hasCollectionOverride = true;
        hasDryRunAddopts = true;
        uncertain = true;
      } else {
        if (addoptsTokens.some((tok) => isPytestAddoptsUnsafeToken(tok))) {
          hasCollectionOverride = true;
        }
        if (hasPytestNonExecFlag(addoptsTokens)) {
          hasDryRunAddopts = true;
        }
      }
    } else if (entry.key === "testpaths") {
      testpathsCount += 1;
      if (testpathsCount > 1) {
        return { restricted: true, paths: [], hasDryRunAddopts: true, uncertain: true };
      }
      const paths = parseTestpathsValue(entry.rawValue);
      if (!paths) {
        uncertain = true;
      } else {
        collectedPaths = paths;
      }
    }
  }

  if (uncertain) {
    return { restricted: true, paths: [], hasDryRunAddopts, uncertain: true };
  }
  if (hasCollectionOverride) {
    return { restricted: true, paths: [], hasDryRunAddopts, uncertain: false };
  }
  if (collectedPaths !== null) {
    return { restricted: true, paths: collectedPaths, hasDryRunAddopts, uncertain: false };
  }
  return { restricted: false, paths: [], hasDryRunAddopts, uncertain: false };
}

function parsePytestToml(text, targetTablePath) {
  let currentTable = [];
  let iniOptionsCount = 0;
  let inIniOptions = false;
  let inMultilineQuote = null;
  let iniBracketDepth = 0;
  let hasCollectionOverride = false;
  let hasDryRunAddopts = false;
  let pendingEntry = null;
  const iniEntries = [];
  const prefixScope = targetTablePath.slice(0, Math.max(1, targetTablePath.length - 1));
  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const { codeOnly, nextMultiline, sawTriple, bracketDepthDelta } = advanceTomlLexState(rawLine, inMultilineQuote);
    const wasInMultiline = inMultilineQuote !== null;
    inMultilineQuote = nextMultiline;
    const t = codeOnly.trim();
    if (wasInMultiline) {
      if (inIniOptions && sawTriple) {
        return { failClosed: true, iniEntries: null, hasCollectionOverride: true, hasDryRunAddopts: false };
      }
      continue;
    }
    if (inIniOptions && (sawTriple || nextMultiline !== null)) {
      return { failClosed: true, iniEntries: null, hasCollectionOverride: true, hasDryRunAddopts: false };
    }
    if (!t) {
      continue;
    }
    if (nextMultiline === null && iniBracketDepth === 0 && t.startsWith("[")) {
      if (pendingEntry) {
        return { failClosed: true, iniEntries: null, hasCollectionOverride: true, hasDryRunAddopts: false };
      }
      const closeIdx = t.startsWith("[[") ? t.indexOf("]]") : t.indexOf("]");
      if (closeIdx === -1) {
        return { failClosed: true, iniEntries: null, hasCollectionOverride: true, hasDryRunAddopts: false };
      }
      const headerBody = t.slice(t.startsWith("[[") ? 2 : 1, closeIdx).trim();
      const segs = parseTomlKeySegments(headerBody);
      if (!segs) {
        if (/pytest/i.test(headerBody)) {
          return { failClosed: true, iniEntries: null, hasCollectionOverride: true, hasDryRunAddopts: false };
        }
        currentTable = [];
        inIniOptions = false;
        continue;
      }
      currentTable = segs;
      if (segs.length === targetTablePath.length && arrayMatchesPrefix(segs, targetTablePath)) {
        iniOptionsCount += 1;
        if (iniOptionsCount > 1) {
          return { failClosed: true, iniEntries: null, hasCollectionOverride: true, hasDryRunAddopts: false };
        }
        inIniOptions = true;
      } else {
        inIniOptions = false;
        if (arrayMatchesPrefix(segs, prefixScope) && segs.includes("pytest")) {
          return { failClosed: true, iniEntries: null, hasCollectionOverride: true, hasDryRunAddopts: false };
        }
      }
      continue;
    }

    if (pendingEntry) {
      pendingEntry.rawLines.push(codeOnly);
      iniBracketDepth = Math.max(0, iniBracketDepth + bracketDepthDelta);
      if (iniBracketDepth === 0) {
        iniEntries.push({ key: pendingEntry.key, rawValue: pendingEntry.rawLines.join("\n") });
        pendingEntry = null;
      }
      continue;
    }

    if (inIniOptions) {
      iniBracketDepth = Math.max(0, iniBracketDepth + bracketDepthDelta);
    }
    const eqPos = t.indexOf("=");
    if (eqPos !== -1) {
      const keyPart = t.slice(0, eqPos).trim();
      const keySegs = parseTomlKeySegments(keyPart);
      if (!keySegs) {
        if (/pytest/i.test(keyPart)) {
          return { failClosed: true, iniEntries: null, hasCollectionOverride: true, hasDryRunAddopts: false };
        }
        continue;
      }
      const fullPath = [...currentTable, ...keySegs];
      if (arrayMatchesPrefix(fullPath, prefixScope) && fullPath.includes("pytest")) {
        const isDirectIniOption =
          currentTable.length === targetTablePath.length &&
          arrayMatchesPrefix(currentTable, targetTablePath) &&
          keySegs.length === 1;
        if (!isDirectIniOption || nextMultiline !== null) {
          return { failClosed: true, iniEntries: null, hasCollectionOverride: true, hasDryRunAddopts: false };
        }
        const optKey = keySegs[0];
        const rhsRaw = t.slice(eqPos + 1);
        if (iniBracketDepth > 0) {
          pendingEntry = { key: optKey, rawLines: [rhsRaw] };
        } else {
          iniEntries.push({ key: optKey, rawValue: rhsRaw });
        }
        if (PYTEST_COLLECTION_OVERRIDE_KEYS.has(optKey)) {
          hasCollectionOverride = true;
        }
      }
      if (fullPath.length === 1 && fullPath[0] === prefixScope[0]) {
        return { failClosed: true, iniEntries: null, hasCollectionOverride: true, hasDryRunAddopts: false };
      }
    }
  }
  if (pendingEntry || inMultilineQuote !== null) {
    return { failClosed: true, iniEntries: null, hasCollectionOverride: true, hasDryRunAddopts: false };
  }
  return {
    failClosed: false,
    iniEntries: iniOptionsCount === 1 ? iniEntries : null,
    hasCollectionOverride,
    hasDryRunAddopts,
  };
}

function readPytestTomlFile(filePath, targetTablePath, configDir) {
  const bounded = readRegularFileBounded(filePath);
  if (!bounded.ok) {
    return { restricted: true, paths: [], hasDryRunAddopts: false, uncertain: true, configDir };
  }
  try {
    const parsedToml = parsePytestToml(bounded.text, targetTablePath);
    if (parsedToml.failClosed) {
      return {
        restricted: true,
        paths: [],
        hasDryRunAddopts: false,
        uncertain: true,
        configDir,
      };
    }
    const evaluated =
      parsedToml.iniEntries !== null
        ? evaluatePytestIniEntries(parsedToml.iniEntries)
        : parsedToml.hasCollectionOverride
          ? { restricted: true, paths: [], hasDryRunAddopts: Boolean(parsedToml.hasDryRunAddopts), uncertain: false }
          : null;
    if (!evaluated) {
      return null;
    }
    if (parsedToml.hasCollectionOverride) {
      return {
        restricted: true,
        paths: [],
        hasDryRunAddopts: Boolean(evaluated.hasDryRunAddopts || parsedToml.hasDryRunAddopts),
        uncertain: Boolean(evaluated.uncertain),
        configDir,
      };
    }
    return { ...evaluated, configDir };
  } catch {
    return { restricted: true, paths: [], hasDryRunAddopts: false, uncertain: true, configDir };
  }
}

function readPytestConfigInDir(dir) {
  if (!dir || !existsSync(dir)) {
    return null;
  }
  for (const tomlName of ["pytest.toml", ".pytest.toml"]) {
    const tomlPath = join(dir, tomlName);
    if (!existsSync(tomlPath)) {
      continue;
    }
    const evaluated = readPytestTomlFile(tomlPath, ["pytest"], dir);
    return evaluated ?? { restricted: false, paths: [], hasDryRunAddopts: false, uncertain: false, configDir: dir };
  }
  for (const iniName of ["pytest.ini", ".pytest.ini"]) {
    const pytestIniPath = join(dir, iniName);
    if (!existsSync(pytestIniPath)) {
      continue;
    }
    const bounded = readRegularFileBounded(pytestIniPath);
    if (!bounded.ok) {
      return { restricted: true, paths: [], hasDryRunAddopts: false, uncertain: true, configDir: dir };
    }
    try {
      const parsed = parseIniTestpaths(bounded.text, new Set(["pytest"]));
      return parsed
        ? { ...parsed, uncertain: Boolean(parsed.uncertain), configDir: dir }
        : { restricted: false, paths: [], hasDryRunAddopts: false, uncertain: false, configDir: dir };
    } catch {
      return { restricted: true, paths: [], hasDryRunAddopts: false, uncertain: true, configDir: dir };
    }
  }
  const pyprojPath = join(dir, "pyproject.toml");
  if (existsSync(pyprojPath)) {
    const evaluated = readPytestTomlFile(pyprojPath, ["tool", "pytest", "ini_options"], dir);
    if (evaluated) {
      return evaluated;
    }
  }
  for (const [fileName, sections] of [
    ["tox.ini", new Set(["pytest"])],
    ["setup.cfg", new Set(["tool:pytest"])],
  ]) {
    const cfgPath = join(dir, fileName);
    if (!existsSync(cfgPath)) {
      continue;
    }
    const bounded = readRegularFileBounded(cfgPath);
    if (!bounded.ok) {
      return { restricted: true, paths: [], hasDryRunAddopts: false, uncertain: true, configDir: dir };
    }
    try {
      const parsed = parseIniTestpaths(bounded.text, sections);
      if (parsed) {
        return { ...parsed, uncertain: Boolean(parsed.uncertain), configDir: dir };
      }
    } catch {
      return { restricted: true, paths: [], hasDryRunAddopts: false, uncertain: true, configDir: dir };
    }
  }
  return null;
}

function readPytestConfig(execDir) {
  if (!execDir || !existsSync(execDir)) {
    return { restricted: false, paths: [], hasDryRunAddopts: false, uncertain: false, configDir: "" };
  }
  let dir = resolve(execDir);
  for (let depth = 0; depth < 64; depth += 1) {
    const found = readPytestConfigInDir(dir);
    if (found) {
      return found;
    }
    const parent = dirname(dir);
    if (parent === dir) {
      return { restricted: false, paths: [], hasDryRunAddopts: false, uncertain: false, configDir: "" };
    }
    dir = parent;
  }
  return { restricted: true, paths: [], hasDryRunAddopts: false, uncertain: true, configDir: "" };
}

function readPytestConfigFile(rawPath, execDir) {
  if (!rawPath) {
    return { restricted: true, paths: [], hasDryRunAddopts: false, uncertain: true, configDir: execDir || "" };
  }
  const resolvedPath = isAbsolute(rawPath) ? rawPath : resolve(execDir || ".", rawPath);
  const configDir = dirname(resolvedPath);
  if (!existsSync(resolvedPath)) {
    return { restricted: true, paths: [], hasDryRunAddopts: false, uncertain: true, configDir };
  }
  const exactBaseName = posix.basename(toPlatformPosix(resolvedPath));
  const lowerBaseName = exactBaseName.toLowerCase();
  if (lowerBaseName.endsWith(".toml")) {
    if (exactBaseName === "pytest.toml" || exactBaseName === ".pytest.toml") {
      const evaluated = readPytestTomlFile(resolvedPath, ["pytest"], configDir);
      return evaluated ?? { restricted: false, paths: [], hasDryRunAddopts: false, uncertain: false, configDir };
    }
    if (exactBaseName === "pyproject.toml") {
      const evaluated = readPytestTomlFile(resolvedPath, ["tool", "pytest", "ini_options"], configDir);
      return evaluated ?? { restricted: false, paths: [], hasDryRunAddopts: false, uncertain: false, configDir };
    }
    const evalTool = readPytestTomlFile(resolvedPath, ["tool", "pytest", "ini_options"], configDir);
    const evalRoot = readPytestTomlFile(resolvedPath, ["pytest"], configDir);
    if (!evalTool && !evalRoot) {
      return { restricted: true, paths: [], hasDryRunAddopts: false, uncertain: true, configDir };
    }
    if (evalTool && evalRoot) {
      return {
        restricted: Boolean(evalTool.restricted || evalRoot.restricted),
        paths: evalTool.paths?.length ? evalTool.paths : evalRoot.paths,
        hasDryRunAddopts: Boolean(evalTool.hasDryRunAddopts || evalRoot.hasDryRunAddopts),
        uncertain: Boolean(evalTool.uncertain || evalRoot.uncertain),
        configDir,
      };
    }
    return evalTool ?? evalRoot;
  }
  const bounded = readRegularFileBounded(resolvedPath);
  if (!bounded.ok) {
    return { restricted: true, paths: [], hasDryRunAddopts: false, uncertain: true, configDir };
  }
  try {
    const sections = exactBaseName === "setup.cfg" || lowerBaseName.endsWith(".cfg") ? new Set(["tool:pytest"]) : new Set(["pytest"]);
    const parsed = parseIniTestpaths(bounded.text, sections);
    return parsed
      ? { ...parsed, uncertain: Boolean(parsed.uncertain), configDir }
      : { restricted: false, paths: [], hasDryRunAddopts: false, uncertain: false, configDir };
  } catch {
    return { restricted: true, paths: [], hasDryRunAddopts: false, uncertain: true, configDir };
  }
}

const PYTEST_VALUE_FLAGS = new Set([
  "-c",
  "--config",
  "-k",
  "-m",
  "-o",
  "-p",
  "-r",
  "-W",
  "-n",
  "--rootdir",
  "--confcutdir",
  "--junitxml",
  "--maxfail",
  "--tb",
  "--ignore",
  "--deselect",
  "--basetemp",
  "--cov",
  "--cov-report",
]);
const JEST_VALUE_FLAGS = new Set([
  "-c",
  "--config",
  "-t",
  "--testNamePattern",
  "--testPathPattern",
  "--testPathIgnorePatterns",
  "--rootDir",
  "--projects",
  "--selectProjects",
  "--outputFile",
  "--reporters",
  "--setupFiles",
  "--setupFilesAfterEnv",
  "--maxWorkers",
  "--shard",
]);
const VITEST_VALUE_FLAGS = new Set([
  "-c",
  "--config",
  "-t",
  "--testNamePattern",
  "-r",
  "--reporter",
  "--root",
  "--dir",
  "--environment",
  "--mode",
  "--project",
  "--outputFile",
  "--coverage.reporter",
  "--shard",
  "--maxWorkers",
]);
const NODE_TEST_VALUE_FLAGS = new Set([
  "--test-reporter",
  "--test-reporter-destination",
  "--test-name-pattern",
  "--test-skip-pattern",
  "--test-shard",
  "--test-concurrency",
  "--test-timeout",
  "--import",
  "--require",
  "--loader",
  "--env-file",
  "--conditions",
  "-r",
  "-C",
  "--tsconfig",
]);
const GENERIC_RUNNER_VALUE_FLAGS = new Set([
  "-c",
  "--config",
  "-t",
  "--test-name-pattern",
  "--testNamePattern",
  "--filter",
  "-w",
  "--workspace",
  "--reporter",
  "-r",
]);

function runnerValueFlagsFor(runnerPrefix) {
  if (!Array.isArray(runnerPrefix)) {
    return GENERIC_RUNNER_VALUE_FLAGS;
  }
  if (runnerPrefix.includes("pytest")) return PYTEST_VALUE_FLAGS;
  if (runnerPrefix.includes("jest")) return JEST_VALUE_FLAGS;
  if (runnerPrefix.includes("vitest")) return VITEST_VALUE_FLAGS;
  if (runnerPrefix[0] === "node" && runnerPrefix[1] === "--test") return NODE_TEST_VALUE_FLAGS;
  return GENERIC_RUNNER_VALUE_FLAGS;
}

function extractPytestPositionalTargets(args) {
  const targets = [];
  let afterDoubleDash = false;
  for (let i = 0; i < args.length; i += 1) {
    const tok = args[i];
    if (afterDoubleDash) {
      targets.push(tok);
      continue;
    }
    if (tok === "--") {
      afterDoubleDash = true;
      continue;
    }
    if (tok.startsWith("-")) {
      if (PYTEST_VALUE_FLAGS.has(tok) && !tok.includes("=") && i + 1 < args.length) {
        i += 1;
      }
      continue;
    }
    targets.push(tok);
  }
  return targets;
}

function commonAncestorDir(dirs) {
  if (!dirs || dirs.length === 0) {
    return "";
  }
  let cur = resolve(dirs[0]);
  for (let i = 1; i < dirs.length; i += 1) {
    const next = resolve(dirs[i]);
    while (cur) {
      const rel = relative(cur, next);
      if (!rel.startsWith("..") && !isAbsolute(rel)) {
        break;
      }
      const parent = dirname(cur);
      if (parent === cur) {
        return cur;
      }
      cur = parent;
    }
  }
  return cur;
}

function resolveTargetLookupDir(rawTarget, execDir) {
  const nodeFile = unwrapSingleShellQuotePair(rawTarget).split("::")[0];
  if (!nodeFile || /[*?[\]]/.test(nodeFile)) {
    return { dir: execDir, uncertain: true };
  }
  const absPath = isAbsolute(nodeFile) ? nodeFile : resolve(execDir || ".", nodeFile);
  try {
    const st = statSync(absPath);
    return { dir: st.isDirectory() ? absPath : dirname(absPath), uncertain: false };
  } catch {
    const parent = dirname(absPath);
    return { dir: existsSync(parent) ? parent : execDir, uncertain: false };
  }
}

function hasAncestorSetupPy(startDir, stopDir = "") {
  if (!startDir || !existsSync(startDir)) {
    return false;
  }
  let cur = resolve(startDir);
  const resolvedStop = stopDir ? resolve(stopDir) : "";
  for (let depth = 0; depth < 64; depth += 1) {
    try {
      if (statSync(join(cur, "setup.py")).isFile()) {
        return true;
      }
    } catch {
    }
    if (resolvedStop && cur === resolvedStop) {
      return false;
    }
    const parent = dirname(cur);
    if (parent === cur) {
      return false;
    }
    cur = parent;
  }
  return false;
}

function resolvePytestConfigForCommand(args, execDir) {
  let explicitConfigPath = null;
  let explicitRootDir = null;
  let cliOverrideAddopts = null;
  for (let i = 0; i < args.length; i += 1) {
    const tok = args[i];
    if (tok === "-c" || tok === "--config" || tok === "--config-file") {
      if (i + 1 < args.length) {
        explicitConfigPath = args[i + 1];
        i += 1;
      }
    } else if (tok.startsWith("-c") && tok.length > 2) {
      explicitConfigPath = tok.slice(2);
    } else if (tok.startsWith("--config-file=")) {
      explicitConfigPath = tok.slice("--config-file=".length);
    } else if (tok.startsWith("--config=")) {
      explicitConfigPath = tok.slice("--config=".length);
    } else if (tok === "--rootdir" && i + 1 < args.length) {
      explicitRootDir = args[i + 1];
      i += 1;
    } else if (tok.startsWith("--rootdir=")) {
      explicitRootDir = tok.slice("--rootdir=".length);
    } else if (tok === "-o" || tok === "--override-ini") {
      if (i + 1 < args.length) {
        const nextVal = args[i + 1];
        if (nextVal.startsWith("addopts=")) {
          cliOverrideAddopts = nextVal.slice("addopts=".length);
        }
        i += 1;
      }
    } else if (tok.startsWith("-o") && tok.length > 2) {
      const rest = tok.slice(2);
      if (rest.startsWith("addopts=")) {
        cliOverrideAddopts = rest.slice("addopts=".length);
      }
    } else if (tok.startsWith("--override-ini=")) {
      const rest = tok.slice("--override-ini=".length);
      if (rest.startsWith("addopts=")) {
        cliOverrideAddopts = rest.slice("addopts=".length);
      }
    }
  }
  let baseConfig;
  if (explicitConfigPath) {
    baseConfig = readPytestConfigFile(explicitConfigPath, execDir);
  } else {
    const targets = extractPytestPositionalTargets(args);
    const resolvedRootDir = explicitRootDir ? (isAbsolute(explicitRootDir) ? explicitRootDir : resolve(execDir || ".", explicitRootDir)) : "";
    if (targets.length === 0) {
      baseConfig = readPytestConfig(execDir);
      if (resolvedRootDir && !baseConfig.configDir && !baseConfig.uncertain) {
        baseConfig = readPytestConfig(resolvedRootDir);
      }
    } else {
      const targetDirs = [];
      let targetUncertain = false;
      for (const rawT of targets) {
        const resolved = resolveTargetLookupDir(rawT, execDir);
        if (resolved.uncertain) {
          targetUncertain = true;
        }
        if (resolved.dir) {
          targetDirs.push(resolved.dir);
        }
      }
      const lookupRoot = targetDirs.length > 0 ? commonAncestorDir(targetDirs) : (resolvedRootDir || execDir);
      baseConfig = readPytestConfig(lookupRoot || execDir);
      if (!baseConfig.configDir && !baseConfig.uncertain && targetDirs.length > 0 && !hasAncestorSetupPy(lookupRoot || execDir)) {
        for (const tDir of targetDirs) {
          const subCfg = readPytestConfig(tDir);
          if (subCfg.configDir || subCfg.uncertain) {
            baseConfig = subCfg;
            break;
          }
        }
      }
      if (resolvedRootDir && !baseConfig.configDir && !baseConfig.uncertain) {
        baseConfig = readPytestConfig(resolvedRootDir);
      }
      if (targetUncertain) {
        baseConfig = { ...baseConfig, uncertain: true };
      }
    }
  }
  if (cliOverrideAddopts !== null) {
    const cleanedOverride = unwrapSingleShellQuotePair(cliOverrideAddopts);
    const overrideTokens = cleanedOverride === "" ? [] : splitQuotedWhitespace(cleanedOverride);
    const hasDryRunInOverride = !overrideTokens || hasPytestNonExecFlag(overrideTokens);
    const hasUnsafeInOverride = !overrideTokens || overrideTokens.some((t) => isPytestAddoptsUnsafeToken(t));
    return {
      ...baseConfig,
      restricted: Boolean(baseConfig.restricted || hasUnsafeInOverride),
      paths: hasUnsafeInOverride ? [] : baseConfig.paths,
      hasDryRunAddopts: hasDryRunInOverride,
      uncertain: Boolean(baseConfig.uncertain || !overrideTokens),
    };
  }
  return baseConfig;
}

function isDefaultDiscoverableTestTarget(target, runnerPrefix, execDir = "") {
  const rawFile = runnerPrefix.includes("pytest") ? target.split("::")[0] : target;
  const normRaw = toPlatformPosix(rawFile);
  if (normRaw.startsWith("/") || /^[A-Za-z]:\//.test(normRaw)) {
    return false;
  }
  const norm = normRaw.replace(/^\.\//, "");
  if (norm.split("/").includes("..") || EXCLUDED_TEST_DIRS_RE.test(norm)) {
    return false;
  }
  if (runnerPrefix.includes("pytest")) {
    if (!/(?:^|\/)test_[^/]*\.py$|_test\.py$/.test(norm)) {
      return false;
    }
    const tpConfig = readPytestConfig(execDir);
    if (tpConfig.restricted) {
      if (tpConfig.paths.length === 0) {
        return false;
      }
      if (tpConfig.configDir && execDir) {
        const rel = toPlatformPosix(relative(tpConfig.configDir, resolve(execDir)));
        if (rel && rel !== "." && !rel.startsWith("..") && !isAbsolute(rel)) {
          return true;
        }
      }
      return tpConfig.paths.some((tp) => tp === "." || norm === tp || norm.startsWith(`${tp}/`));
    }
    return true;
  }
  if (runnerPrefix[0] === "node" && runnerPrefix[1] === "--test") {
    return /(?:^|\/)test(?:\/|$)|(?:^|\/)test-[^/]*\.[cm]?js$|(?:^|\/)test\.[cm]?js$|[._-]test\.[cm]?js$/.test(norm);
  }
  return /(?:^|\/)(?:__tests__|tests?)(?:\/|$)|[._-](?:test|spec)\.[cm]?[jt]sx?$/i.test(norm);
}

function runnerPrefixLength(tokens) {
  let start = 0;
  while (start < tokens.length && ENV_ASSIGNMENT_RE.test(tokens[start])) {
    start += 1;
  }
  const matches = (prefix) => prefix.every((word, k) => tokens[start + k] === word);
  if (tokens[start] === "go" && tokens[start + 1] === "test") {
    return { kind: "go", prefix: ["go", "test"], end: start + 2 };
  }
  const prefix = ALL_TESTS_WITHOUT_TARGETS.filter(matches).sort((x, y) => y.length - x.length)[0];
  return prefix ? { kind: "all", prefix, end: start + prefix.length } : null;
}

const PYTEST_DISCOVERY_OVERRIDE_LONG_RE =
  /^--(?:config-file|config|override-ini|rootdir|confcutdir|pyargs|noconftest|import-mode|ignore|ignore-glob|deselect|collect-only|co|continue-on-collection-errors|doctest-modules|doctest-glob|doctest-ignore-import-errors)(?:=|$)/;
const PYTEST_SAFE_SHORT_FLAG_CLUSTER_RE = /^-[vqsxl]+$/;
const PYTEST_ADDOPTS_DISALLOWED_LONG_RE = /^--(?:k|m|p|lf|ff|nf|sw|stepwise|last-failed|failed-first|new-first|markers|fixtures|help|version)(?:=|$)/;

function isPytestDiscoveryOverrideToken(tok) {
  if (typeof tok !== "string" || !tok.startsWith("-")) {
    return false;
  }
  if (tok.startsWith("--")) {
    return PYTEST_DISCOVERY_OVERRIDE_LONG_RE.test(tok);
  }
  return !PYTEST_SAFE_SHORT_FLAG_CLUSTER_RE.test(tok);
}

function isPytestAddoptsUnsafeToken(tok) {
  return (
    typeof tok !== "string" ||
    !tok.startsWith("-") ||
    isPytestDiscoveryOverrideToken(tok) ||
    PYTEST_ADDOPTS_DISALLOWED_LONG_RE.test(tok)
  );
}

function isVerificationEntryEffective(entry, baseExecCwd, depth = 0) {
  const pytestInfo = extractPytestCommandInfo(entry.seg);
  if (!pytestInfo || pytestInfo.chdirOpaque) {
    return false;
  }
  let execDir = resolveEntryExecDir(entry.dir, baseExecCwd);
  for (const ch of pytestInfo.chdirs ?? []) {
    execDir = resolveExecDirStep(execDir, ch, { preserveSpaces: true });
  }
  const rawEnv = pytestInfo.envPytestCleared ? null : (pytestInfo.envPytestAddopts ?? entry.envPytestAddopts ?? null);
  const envOpaque = !pytestInfo.envPytestCleared && pytestInfo.envPytestAddopts === null && Boolean(entry.envPytestOpaque);
  if (pytestInfo.shellBody !== undefined) {
    if (depth >= 2) {
      return false;
    }
    const innerEntries = extractVerificationEntries(pytestInfo.shellBody, execDir, {
      initialEnvPytestAddopts: rawEnv,
      initialEnvPytestOpaque: envOpaque,
      initialEnvPytestExported: rawEnv !== null || envOpaque,
      initialAllexport: false,
      initialOtherEnv: entry.otherEnvMap,
      initialOtherEnvOpaque: Boolean(entry.otherEnvOpaque),
    });
    return innerEntries.some((subEntry) => isVerificationEntryEffective(subEntry, execDir, depth + 1));
  }
  if (!pytestInfo.isPytest) {
    return true;
  }
  if (envOpaque) {
    return false;
  }
  let envTokens = [];
  if (rawEnv !== null) {
    const parsed = splitQuotedWhitespace(unwrapSingleShellQuotePair(rawEnv));
    if (!parsed) {
      return false;
    }
    envTokens = parsed;
  }
  const effectiveArgs = [...envTokens, ...pytestInfo.args];
  if (hasPytestNonExecFlag(effectiveArgs)) {
    return false;
  }
  const cfg = resolvePytestConfigForCommand(effectiveArgs, execDir);
  if (cfg.hasDryRunAddopts || cfg.uncertain) {
    return false;
  }
  return true;
}

function isEffectiveVerificationExecution(exec, defaultCwd = ".") {
  if (!exec || exec.kind !== "verification" || exec.hasResult === false) {
    return false;
  }
  const entries = extractExecutionVerificationEntries(exec, defaultCwd);
  if (entries.length === 0) {
    return true;
  }
  const baseExecCwd = normalizeExecDir(exec?.execCwd || defaultCwd || ".", { preserveSpaces: true });
  return entries.some((entry) => isVerificationEntryEffective(entry, baseExecCwd, 0));
}

function droppedTokenIndexes(failed, passed) {
  const dropped = [];
  let j = 0;
  for (let i = 0; i < failed.length; i += 1) {
    if (j < passed.length && metaTokenEqual(failed[i], passed[j])) {
      j += 1;
    } else {
      dropped.push(i);
    }
  }
  return j === passed.length ? dropped : null;
}

const PYTEST_DISPLAY_ONLY_SHORT_RE = /^-[vqs]+$/;
const PYTEST_DISPLAY_ONLY_LONG_RE =
  /^--(?:verbose|quiet|no-header|no-summary|show-capture=(?:no|stdout|stderr|log|all)|tb=(?:auto|long|short|line|native|no)|color=(?:yes|no|auto)|code-highlight=(?:yes|no)|durations=\d+)$/;

function isSafeDisplayOnlyPytestToken(tok) {
  return typeof tok === "string" && (PYTEST_DISPLAY_ONLY_SHORT_RE.test(tok) || PYTEST_DISPLAY_ONLY_LONG_RE.test(tok));
}

function hasUnsafeOrTargetedEnvAddopts(rawEnv) {
  if (rawEnv === null || rawEnv === undefined) {
    return false;
  }
  const envToks = splitQuotedWhitespace(unwrapSingleShellQuotePair(rawEnv));
  if (!envToks) {
    return true;
  }
  return envToks.some((tok) => !isSafeDisplayOnlyPytestToken(tok));
}

// A passing command clears a failing one when it is the same command, or the same runner and flags
// with every file target removed on a runner whose target-less form runs every test. Dropping only
// some targets narrows the run. Go widens only to `./...`, over relative package targets inside it.
function segmentResolvedBy(failedSeg, passedSeg, execDir = "", { failedEntry = null, passedEntry = null, depth = 0 } = {}) {
  if (failedSeg.length === 0 || passedSeg.length === 0) {
    return false;
  }
  const failedMeta = splitQuotedWhitespaceWithMeta(failedSeg);
  const passedMeta = splitQuotedWhitespaceWithMeta(passedSeg);
  if (!failedMeta || !passedMeta) {
    return false;
  }
  if (failedEntry?.otherEnvOpaque || passedEntry?.otherEnvOpaque || (failedEntry?.otherEnvKey ?? "") !== (passedEntry?.otherEnvKey ?? "")) {
    return false;
  }
  const failedPyInfo = extractPytestCommandInfo(failedSeg);
  const passedPyInfo = extractPytestCommandInfo(passedSeg);
  if (failedPyInfo?.chdirOpaque || passedPyInfo?.chdirOpaque) {
    return false;
  }
  if (failedPyInfo?.shellBody !== undefined || passedPyInfo?.shellBody !== undefined) {
    if (failedPyInfo?.shellBody === undefined || passedPyInfo?.shellBody === undefined || depth >= 2) {
      return false;
    }
    if (failedPyInfo.bin !== passedPyInfo.bin || failedPyInfo.outerContextKey !== passedPyInfo.outerContextKey) {
      return false;
    }
    const expandShell = (info, entry) => {
      let subDir = resolveEntryExecDir(entry?.dir, execDir || ".");
      for (const ch of info.chdirs ?? []) {
        subDir = resolveExecDirStep(subDir, ch, { preserveSpaces: true });
      }
      const rawEnv = info.envPytestCleared ? null : (info.envPytestAddopts ?? entry?.envPytestAddopts ?? null);
      const envOpaque = !info.envPytestCleared && info.envPytestAddopts === null && Boolean(entry?.envPytestOpaque);
      return extractVerificationEntries(info.shellBody, subDir, {
        initialEnvPytestAddopts: rawEnv,
        initialEnvPytestOpaque: envOpaque,
        initialEnvPytestExported: rawEnv !== null || envOpaque,
        initialAllexport: false,
        initialOtherEnv: entry?.otherEnvMap,
        initialOtherEnvOpaque: Boolean(entry?.otherEnvOpaque),
      });
    };
    const failedInner = expandShell(failedPyInfo, failedEntry);
    const passedInner = expandShell(passedPyInfo, passedEntry);
    if (failedInner.length === 0 || passedInner.length === 0) {
      return false;
    }
    return failedInner.every((fSub) => passedInner.some((pSub) => entriesMatchForResolution(fSub, pSub, execDir, depth + 1)));
  }
  if (failedPyInfo?.isPytest || passedPyInfo?.isPytest) {
    const failedEnvOpaque = !failedPyInfo?.envPytestCleared && failedPyInfo?.envPytestAddopts === null && Boolean(failedEntry?.envPytestOpaque);
    const passedEnvOpaque = !passedPyInfo?.envPytestCleared && passedPyInfo?.envPytestAddopts === null && Boolean(passedEntry?.envPytestOpaque);
    if (failedEnvOpaque || passedEnvOpaque) {
      return false;
    }
    const failedEnvRaw = failedPyInfo?.envPytestCleared ? null : (failedPyInfo?.envPytestAddopts ?? failedEntry?.envPytestAddopts ?? null);
    const passedEnvRaw = passedPyInfo?.envPytestCleared ? null : (passedPyInfo?.envPytestAddopts ?? passedEntry?.envPytestAddopts ?? null);
    if (passedEnvRaw !== failedEnvRaw && (hasUnsafeOrTargetedEnvAddopts(failedEnvRaw) || hasUnsafeOrTargetedEnvAddopts(passedEnvRaw))) {
      return false;
    }
  }
  if (tokensEqualExact(failedMeta, passedMeta)) {
    return true;
  }
  const failed = failedMeta.map((t) => t.value);
  const passed = passedMeta.map((t) => t.value);
  if ([...failed, ...passed].some((token) => SHELL_OPERATOR_TOKEN_RE.test(token))) {
    return false;
  }
  const runner = runnerPrefixLength(failed);
  if (!runner || failed.slice(0, runner.end).join(" ") !== passed.slice(0, runner.end).join(" ")) {
    return false;
  }
  if (runner.kind === "go") {
    const isGoTarget = (token) => token === "." || isPathTarget(token, runner.prefix);
    const targets = (tokens) => tokens.slice(runner.end).filter(isGoTarget);
    const flags = (tokens) => tokens.slice(runner.end).filter((token) => !isGoTarget(token));
    return (
      targets(passed).join(" ") === "./..." &&
      flags(failed).join(" ") === flags(passed).join(" ") &&
      targets(failed).every((target) => target === "." || (target.startsWith("./") && !target.split("/").includes("..")))
    );
  }
  if (runner.prefix.includes("pytest")) {
    const failedPyInfo = extractPytestCommandInfo(failedSeg);
    const passedPyInfo = extractPytestCommandInfo(passedSeg);
    const failedEnvOpaque = !failedPyInfo?.envPytestCleared && failedPyInfo?.envPytestAddopts === null && Boolean(failedEntry?.envPytestOpaque);
    const passedEnvOpaque = !passedPyInfo?.envPytestCleared && passedPyInfo?.envPytestAddopts === null && Boolean(passedEntry?.envPytestOpaque);
    if (failedEnvOpaque || passedEnvOpaque) {
      return false;
    }
    const failedEnvRaw = failedPyInfo?.envPytestCleared ? null : (failedPyInfo?.envPytestAddopts ?? failedEntry?.envPytestAddopts ?? null);
    const passedEnvRaw = passedPyInfo?.envPytestCleared ? null : (passedPyInfo?.envPytestAddopts ?? passedEntry?.envPytestAddopts ?? null);
    const hasRestrictedEnvAddopts = [failedEnvRaw, passedEnvRaw].some((rawEnv) => {
      if (rawEnv === null || rawEnv === undefined) {
        return false;
      }
      const envToks = splitQuotedWhitespace(unwrapSingleShellQuotePair(rawEnv));
      return !envToks || envToks.some((tok) => isPytestAddoptsUnsafeToken(tok) || !tok.startsWith("-"));
    });
    if (
      hasRestrictedEnvAddopts ||
      [...failed.slice(runner.end), ...passed.slice(runner.end)].some((tok) => isPytestDiscoveryOverrideToken(tok))
    ) {
      return false;
    }
  }
  const dropped = droppedTokenIndexes(failedMeta, passedMeta);
  if (!dropped || dropped.length === 0 || dropped.some((index) => index < runner.end)) {
    return false;
  }
  const runnerValueFlags = runnerValueFlagsFor(runner.prefix);
  const isTarget = (tokens, index) =>
    isPathTarget(tokens[index], runner.prefix) && !(index - 1 >= runner.end && runnerValueFlags.has(tokens[index - 1]));
  const droppedOnlyTargets = dropped.every((index) =>
    failed[index] === "--"
      ? failed.slice(index + 1).every((_, k) => dropped.includes(index + 1 + k))
      : isTarget(failed, index) && isDefaultDiscoverableTestTarget(failed[index], runner.prefix, execDir),
  );
  const hasRemainingPositionalTarget = (tokens) => {
    let afterDoubleDash = false;
    for (let i = runner.end; i < tokens.length; i += 1) {
      const tok = tokens[i];
      if (afterDoubleDash) {
        return true;
      }
      if (tok === "--") {
        afterDoubleDash = true;
        continue;
      }
      if (tok.startsWith("-")) {
        if (runnerValueFlags.has(tok) && i + 1 < tokens.length) {
          i += 1;
        }
        continue;
      }
      return true;
    }
    return false;
  };
  return droppedOnlyTargets && !hasRemainingPositionalTarget(passed);
}

function resolveEntryExecDir(entryDir, baseCwd) {
  if (!entryDir || entryDir === ".") {
    return baseCwd;
  }
  return resolveExecDirStep(baseCwd || ".", entryDir, { preserveSpaces: true });
}

function strArrayEqual(a, b) {
  const arrA = Array.isArray(a) ? a : [];
  const arrB = Array.isArray(b) ? b : [];
  return arrA.length === arrB.length && arrA.every((v, idx) => v === arrB[idx]);
}

function prepItemsEqual(failedItems, passedItems) {
  if (!Array.isArray(passedItems) || failedItems.length !== passedItems.length) {
    return false;
  }
  return failedItems.every((f, i) => {
    const p = passedItems[i];
    return f.dir === p.dir && strArrayEqual(f.dirs, p.dirs) && strArrayEqual(f.prefixTokens, p.prefixTokens) && strArrayEqual(f.argv, p.argv);
  });
}

function entriesMatchForResolution(failedEntry, passedEntry, baseCwd = "", depth = 0) {
  if (failedEntry.dir !== passedEntry.dir) {
    return false;
  }
  const failedPreps = Array.isArray(failedEntry.prepItems) ? failedEntry.prepItems : [];
  const passedPreps = Array.isArray(passedEntry.prepItems) ? passedEntry.prepItems : [];
  if (failedPreps.some((p) => p.opaque) || passedPreps.some((p) => p.opaque)) {
    return false;
  }
  if (failedPreps.length > 0) {
    if (!prepItemsEqual(failedPreps, passedPreps)) {
      return false;
    }
  } else if (failedEntry.prepKey && passedEntry.prepKey !== failedEntry.prepKey) {
    return false;
  }
  return segmentResolvedBy(failedEntry.seg, passedEntry.seg, resolveEntryExecDir(failedEntry.dir, baseCwd), {
    failedEntry,
    passedEntry,
    depth,
  });
}

function isCommandResolvedBy(failedCmd, passedCmd, failedBaseDir = ".", passedBaseDir = ".") {
  const failedNorm = normalizeCommandText(failedCmd);
  const passedNorm = normalizeCommandText(passedCmd);
  if (failedNorm.length === 0 || passedNorm.length === 0) {
    return false;
  }
  const failedEntries = extractVerificationEntries(failedCmd, failedBaseDir);
  const passedEntries = extractVerificationEntries(passedCmd, passedBaseDir);
  if (failedEntries.length > 0 && passedEntries.length > 0) {
    return failedEntries.every((failedEntry) => passedEntries.some((passedEntry) => entriesMatchForResolution(failedEntry, passedEntry, failedBaseDir)));
  }
  return (
    normalizeExecDir(failedBaseDir, { preserveSpaces: true }) === normalizeExecDir(passedBaseDir, { preserveSpaces: true }) &&
    segmentResolvedBy(failedNorm, passedNorm, failedBaseDir)
  );
}

function extractExecutionVerificationEntries(exec, defaultCwd = ".") {
  const baseDir = normalizeExecDir(exec?.execCwd || defaultCwd || ".", { preserveSpaces: true });
  const candidates =
    Array.isArray(exec?.subCommands) && exec.subCommands.length > 0 ? exec.subCommands : [exec?.command ?? ""];
  const entries = [];
  for (const cmd of candidates) {
    for (const entry of extractVerificationEntries(cmd, baseDir)) {
      entries.push(entry);
    }
  }
  return entries;
}

function isExecutionResolvedBy(failedExec, passedExec, defaultCwd = ".") {
  const hasFailedSubs = Array.isArray(failedExec?.subCommands) && failedExec.subCommands.length > 0;
  const hasPassedSubs = Array.isArray(passedExec?.subCommands) && passedExec.subCommands.length > 0;
  if (!hasFailedSubs && !hasPassedSubs) {
    const failedBase = normalizeExecDir(failedExec?.execCwd || defaultCwd || ".", { preserveSpaces: true });
    const passedBase = normalizeExecDir(passedExec?.execCwd || defaultCwd || ".", { preserveSpaces: true });
    if (isCommandResolvedBy(failedExec?.command, passedExec?.command, failedBase, passedBase)) {
      return true;
    }
  }
  const failedEntries = extractExecutionVerificationEntries(failedExec, defaultCwd);
  const passedEntries = extractExecutionVerificationEntries(passedExec, defaultCwd);
  if (failedEntries.length > 0 && passedEntries.length > 0) {
    return failedEntries.every((failedEntry) => passedEntries.some((passedEntry) => entriesMatchForResolution(failedEntry, passedEntry, defaultCwd)));
  }
  return Boolean(
    !hasFailedSubs &&
      !hasPassedSubs &&
      failedExec?.toolName &&
      passedExec?.toolName &&
      failedExec.toolName === passedExec.toolName &&
      failedEntries.length === 0,
  );
}

function normalizePathList(items, cwd, gitRoot) {
  if (!Array.isArray(items)) {
    return [];
  }
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const normalized = normalizeWorkspacePath(item, cwd, gitRoot);
    if (normalized.length > 0 && !seen.has(normalized)) {
      seen.add(normalized);
      out.push(normalized);
    }
  }
  return out;
}

const FILLER_UNVERIFIED_RE =
  /^(?:없음|없습니다|없어요|해당\s*없음|해당\s*사항\s*없음|특이\s*사항\s*없음|누락\s*없음|누락된\s*항목\s*없음|제외\s*항목\s*없음|미검증\s*항목\s*없음|미검증\s*범위\s*없음|별도\s*없음|별도\s*제한\s*없음|추가\s*없음|none|n\/a|na|nil|null|nothing|no\s+gaps|no\s+issues)(?:\s*(?:\([^()]*\)|\[[^[\]]*\]))*[.!?,;:~·\s]*$/i;

export function isFillerUnverifiedEntry(entry) {
  if (typeof entry !== "string") {
    return true;
  }
  const trimmed = entry.trim();
  if (trimmed.length === 0) {
    return true;
  }
  return FILLER_UNVERIFIED_RE.test(trimmed);
}

function normalizeStringList(items) {
  if (!Array.isArray(items)) {
    return [];
  }
  return items.filter((item) => typeof item === "string" && item.trim().length > 0).map((item) => item.trim());
}

function normalizeVerificationRuns(items) {
  if (!Array.isArray(items)) {
    return [];
  }
  return items
    .filter((item) => item && typeof item === "object")
    .map((item) => ({
      command: typeof item.command === "string" ? item.command.trim() : "",
      outcome: typeof item.outcome === "string" ? item.outcome.trim() : "",
      reason_if_na: typeof item.reason_if_na === "string" ? item.reason_if_na.trim() : "",
    }));
}

function resolveCopy(register) {
  const key = ALLOWED_SCHEMA_REGISTERS.has(register) ? register : "neutral";
  return REGISTER_COPY[key];
}

function buildRuleLine(rule, details, copy) {
  const builder = copy.ruleMessages[rule];
  if (!builder) {
    return "";
  }
  if (rule === "R1_UNREAD_INSPECTED") return builder(details.unreadInspected);
  if (rule === "R2_STALE_VERIFICATION") return builder(details.maskedVerifications);
  if (rule === "R3_CONCEALED_FAILURE") return builder(details.failedVerifications);
  if (rule === "R4_UNREPORTED_MODIFIED") return builder(details.unreportedModified);
  if (rule === "R5_FABRICATED_COMMAND") return builder(details.fabricatedCommands);
  if (rule === "R6_PHANTOM_MODIFIED") return builder(details.phantomModified);
  if (rule === "R7_HEDGE_DETECTED") return builder(details.hedgeHits);
  if (rule === "R8_AUDIT_REJECTED") return builder();
  if (rule === "R8_AUDIT_ERROR") return builder();
  if (rule === "R9_PREFLIGHT_UNVOTED") return builder(details.preflightVerdict);
  return "";
}

function formatRiskSummaryLine(risk) {
  if (!risk || risk.tier !== "TIER_1") {
    return "";
  }
  const labels = (risk.reasons ?? []).map((r) => RISK_REASON_LABELS[r] ?? r);
  const parts = [];
  if (labels.length > 0) {
    parts.push(`고위험 사유: ${labels.join(", ")}`);
  }
  if (Array.isArray(risk.matchedSensitiveFiles) && risk.matchedSensitiveFiles.length > 0) {
    parts.push(`민감 파일: ${risk.matchedSensitiveFiles.map((f) => `\`${f}\``).join(", ")}`);
  }
  if (Number.isFinite(risk.changedLines) && risk.changedLines > 0) {
    parts.push(`변경 줄 수: ${risk.changedLines}줄`);
  }
  return parts.length > 0 ? `- ${parts.join(" / ")}` : "";
}

export function formatGateReceipt({
  verdict,
  blockedRules = [],
  warnedRules = [],
  details = {},
  register = "neutral",
  risk = null,
  auditPassed = false,
  pollutionAlert = false,
}) {
  const copy = resolveCopy(register);
  const header = copy.headers[verdict] ?? copy.headers.REJECT;
  const lines = [header, copy.summaries[verdict] ?? copy.summaries.REJECT];

  if (verdict === "PASS_WITH_DEGRADATION") {
    lines.push(`- ${copy.degradedNotice}`);
    for (const rule of details.degradedFromBlockedRules ?? []) {
      const msg = buildRuleLine(rule, details, copy);
      if (msg) lines.push(`- ${msg}`);
    }
  } else if (verdict === "PASS_WITH_AUDIT_DEGRADATION") {
    const notice =
      details.auditDegradationReason === "error" ? copy.auditDegradedErrorNotice : copy.auditDegradedRejectNotice;
    lines.push(`- ${notice}`);
  } else if (verdict === "ESCALATE_AUDIT_REQUIRED") {
    const riskLine = formatRiskSummaryLine(risk);
    if (riskLine) {
      lines.push(riskLine);
    }
  } else {
    for (const rule of blockedRules) {
      const msg = buildRuleLine(rule, details, copy);
      if (msg) lines.push(`- ${msg}`);
    }
  }

  if (auditPassed && (verdict === "PASS" || verdict === "PASS_WITH_WARNING")) {
    lines.push(copy.auditPassedLine);
  }

  for (const rule of warnedRules) {
    const msg = buildRuleLine(rule, details, copy);
    if (msg) lines.push(`- 주의: ${msg}`);
  }

  if (pollutionAlert) {
    lines.push(POLLUTION_WARNING_LINE);
  }

  return lines.join("\n");
}

function metaTokenEqual(a, b) {
  return a.value === b.value && a.unquotedMetaMask === b.unquotedMetaMask;
}

function tokensEqualExact(a, b) {
  return a.length === b.length && a.every((tok, idx) => metaTokenEqual(tok, b[idx]));
}

function tokensPrefixMatch(prefixTokens, fullTokens) {
  return fullTokens.length > prefixTokens.length && prefixTokens.every((tok, idx) => metaTokenEqual(tok, fullTokens[idx]));
}

function commandMatchesExecution(rawClaim, execCommand) {
  const claimText = typeof rawClaim === "string" ? rawClaim.trim() : "";
  const execText = typeof execCommand === "string" ? execCommand.trim() : "";
  if (claimText.length === 0 || execText.length === 0) {
    return false;
  }
  const claimTokens = splitQuotedWhitespaceWithMeta(claimText);
  const execTokens = splitQuotedWhitespaceWithMeta(execText);
  const allowPrefixMatch = claimTokens
    ? !(claimTokens.length === 1 && BARE_RUNTIME_LAUNCHERS.has(claimTokens[0].value))
    : !isBareRuntimeLauncher(normalizeCommandText(claimText));
  if (claimTokens && execTokens) {
    if (tokensEqualExact(claimTokens, execTokens)) {
      return true;
    }
    if (allowPrefixMatch && tokensPrefixMatch(claimTokens, execTokens)) {
      return true;
    }
  } else if (execText === claimText) {
    return true;
  }
  const execSegments = splitShellSegments(execCommand).map((s) => s.trim()).filter(Boolean);
  for (const seg of execSegments) {
    const segTokens = splitQuotedWhitespaceWithMeta(seg);
    if (claimTokens && segTokens) {
      if (tokensEqualExact(claimTokens, segTokens)) {
        return true;
      }
      if (allowPrefixMatch && tokensPrefixMatch(claimTokens, segTokens)) {
        return true;
      }
    } else if (seg === claimText) {
      return true;
    }
  }
  return false;
}

function mcpToolAliases(toolName) {
  if (typeof toolName !== "string" || toolName.length === 0) {
    return [];
  }
  const aliases = [toolName];
  if (toolName === "mcp_agy-fast_fast_run_checks") {
    aliases.push("fast_run_checks", "run_checks");
  }
  return aliases;
}

function claimMatchesExecution(normClaim, exec) {
  if (normClaim.length === 0 || !exec) {
    return false;
  }
  const hasSubCommands = Array.isArray(exec.subCommands) && exec.subCommands.length > 0;
  if (!hasSubCommands && commandMatchesExecution(normClaim, exec.command)) {
    return true;
  }
  if (hasSubCommands) {
    for (const subCmd of exec.subCommands) {
      if (commandMatchesExecution(normClaim, subCmd)) {
        return true;
      }
    }
  }
  if (typeof exec.toolName === "string" && exec.toolName.length > 0) {
    for (const alias of mcpToolAliases(exec.toolName)) {
      if (normClaim === alias) {
        return true;
      }
    }
  }
  if (Array.isArray(exec.checkLabels)) {
    for (const label of exec.checkLabels) {
      if (typeof label === "string" && normalizeCommandText(label) === normClaim) {
        return true;
      }
    }
  }
  return false;
}

export function decideGate(input = {}, context = {}) {
  const register = ALLOWED_SCHEMA_REGISTERS.has(context.register) ? context.register : "neutral";
  const cwd = typeof context.cwd === "string" ? context.cwd : "";
  const gitLedger = context.gitLedger ?? { gitAvailable: false, gitRoot: null, gitDirtyFiles: new Set() };
  const gitRoot = typeof gitLedger.gitRoot === "string" ? gitLedger.gitRoot : "";
  const testInfra = context.testInfra ?? { hasTestSuite: false, indicators: [] };

  const details = {
    unreadInspected: [],
    failedVerifications: [],
    maskedVerifications: [],
    unreportedModified: [],
    fabricatedCommands: [],
    phantomModified: [],
    hedgeHits: 0,
    hedgeMatches: [],
    degradedFromBlockedRules: [],
    auditDegradationReason: null,
    preflightVerdict: null,
  };

  const rawUnverifiedScope = normalizeStringList(input.unverified_scope);
  const effectiveUnverifiedScope = rawUnverifiedScope.filter((entry) => !isFillerUnverifiedEntry(entry));
  const fillerUnverifiedCount = rawUnverifiedScope.length - effectiveUnverifiedScope.length;
  const pollutionAlert = context.pollutionAlert === true;
  const auditEscalation = ALLOWED_AUDIT_ESCALATION_MODES.has(context.auditEscalation)
    ? context.auditEscalation
    : "auto";
  const emptyRisk = { tier: "TIER_0", reasons: [], matchedSensitiveFiles: [], changedLines: 0 };
  const emptyPreflight = { used: false, verdict: null, voted: false };

  if (context.sessionMissing) {
    const verdict = "SKIPPED_NO_SESSION";
    const receiptText = formatGateReceipt({
      verdict,
      blockedRules: [],
      warnedRules: [],
      details,
      register,
      risk: emptyRisk,
      pollutionAlert,
    });
    return {
      verdict,
      passed: PASSING_VERDICTS.has(verdict),
      blockedRules: [],
      warnedRules: [],
      details,
      risk: emptyRisk,
      auditVerdict: null,
      preflight: emptyPreflight,
      preflightMode: "none",
      receiptText,
      metrics: {
        hedgeHits: 0,
        priorRejects: 0,
        unverifiedScopeCount: effectiveUnverifiedScope.length,
        fillerUnverifiedCount,
        riskTier: emptyRisk.tier,
        changedLines: 0,
        auditRejectCount: 0,
        auditErrorCount: 0,
        pollutionAlert,
      },
    };
  }

  const ledger = context.ledger ?? {
    sessionRole: "main",
    sessionReadFiles: new Set(),
    turnWrittenFiles: new Set(),
    turnCodeWrittenFiles: new Set(),
    lastWriteStepIndex: -1,
    lastCodeWriteStepIndex: -1,
    turnExecutions: [],
    turnGateAttempts: [],
    turnSubagentAudits: [],
    turnPreflightChallenges: [],
    turnUserVotes: [],
  };

  const reportedModified = normalizePathList(input.modified_files, cwd, gitRoot);
  const reportedModifiedSet = new Set(reportedModified);
  const reportedInspected = normalizePathList(input.inspected_files, cwd, gitRoot);
  const verificationRuns = normalizeVerificationRuns(input.verification_runs);
  const selfAssessment = typeof input.self_assessment === "string" ? input.self_assessment : "";

  const blockedRules = [];
  const warnedRules = [];

  for (const file of reportedInspected) {
    if (!ledger.sessionReadFiles.has(file)) {
      details.unreadInspected.push(file);
    }
  }
  if (details.unreadInspected.length > 0) {
    blockedRules.push("R1_UNREAD_INSPECTED");
  }

  const isCompletedExec = (exec) => exec && exec.hasResult !== false;
  const hasCodeWrite = ledger.lastCodeWriteStepIndex !== -1;
  const postWriteExecutions = hasCodeWrite
    ? ledger.turnExecutions.filter((exec) => exec.stepIndex > ledger.lastCodeWriteStepIndex)
    : ledger.turnExecutions;
  const completedVerifications = hasCodeWrite
    ? postWriteExecutions.filter((exec) => exec.kind === "verification" && isCompletedExec(exec))
    : [];
  const postWriteVerifications = completedVerifications.filter((exec) => isEffectiveVerificationExecution(exec, cwd || gitRoot));

  if (hasCodeWrite && postWriteVerifications.length === 0) {
    for (const exec of postWriteExecutions) {
      if (exec.kind === "other" && extractVerificationSegments(exec.command).length > 0) {
        details.maskedVerifications.push(exec.command);
      }
    }
    const hasValidNaClaim = verificationRuns.some(
      (run) => run.outcome === "not_applicable" && run.reason_if_na.length > 0,
    );
    if (!testInfra.hasTestSuite && !testInfra.uncertain && hasValidNaClaim && effectiveUnverifiedScope.length >= 1) {
      warnedRules.push("R2_STALE_VERIFICATION");
    } else {
      blockedRules.push("R2_STALE_VERIFICATION");
    }
  }

  if (hasCodeWrite && completedVerifications.length > 0) {
    const unresolvedFailures = [];
    for (let i = 0; i < completedVerifications.length; i += 1) {
      const exec = completedVerifications[i];
      if (exec.passed) {
        continue;
      }
      const execEffective = isEffectiveVerificationExecution(exec, cwd || gitRoot);
      let resolvedByLaterPass = false;
      for (let j = i + 1; j < completedVerifications.length; j += 1) {
        const later = completedVerifications[j];
        if (!later.passed) {
          continue;
        }
        const laterEffective = isEffectiveVerificationExecution(later, cwd || gitRoot);
        if (execEffective && !laterEffective) {
          continue;
        }
        if (isExecutionResolvedBy(exec, later, cwd || gitRoot)) {
          resolvedByLaterPass = true;
          break;
        }
      }
      if (!resolvedByLaterPass) {
        unresolvedFailures.push(exec.command || "(검증 명령)");
      }
    }

    const lastVerification = completedVerifications[completedVerifications.length - 1];
    if (lastVerification && !lastVerification.passed) {
      const lastCmd = lastVerification.command || "(검증 명령)";
      if (!unresolvedFailures.includes(lastCmd)) {
        unresolvedFailures.push(lastCmd);
      }
    }

    if (unresolvedFailures.length > 0) {
      for (const cmd of unresolvedFailures) {
        if (!details.failedVerifications.includes(cmd)) {
          details.failedVerifications.push(cmd);
        }
      }
      blockedRules.push("R3_CONCEALED_FAILURE");
    }
  }

  const hasReliableGitStatus = Boolean(gitLedger.gitAvailable && gitLedger.dirtyFilesAvailable !== false);
  for (const writtenFile of ledger.turnWrittenFiles) {
    if (hasReliableGitStatus && !gitLedger.gitDirtyFiles.has(writtenFile) && !ledger.turnCommittedFiles?.has(writtenFile)) {
      continue;
    }
    if (!reportedModifiedSet.has(writtenFile)) {
      details.unreportedModified.push(writtenFile);
    }
  }
  if (details.unreportedModified.length > 0) {
    blockedRules.push("R4_UNREPORTED_MODIFIED");
  }

  for (const run of verificationRuns) {
    if (run.outcome !== "pass") {
      continue;
    }
    const rawClaim = typeof run.command === "string" ? run.command.trim() : "";
    const matchingExecs =
      rawClaim.length > 0
        ? postWriteExecutions.filter((exec) => exec.kind !== "read_only" && claimMatchesExecution(rawClaim, exec))
        : [];
    const matchedPass = matchingExecs.some((exec) => isCompletedExec(exec) && exec.passed === true);
    const coveredByR3Failure =
      hasCodeWrite &&
      blockedRules.includes("R3_CONCEALED_FAILURE") &&
      matchingExecs.some((exec) => exec.kind === "verification" && isCompletedExec(exec) && !exec.passed);
    if (!matchedPass && !coveredByR3Failure) {
      details.fabricatedCommands.push(run.command || "(비어 있는 명령)");
    }
  }
  if (details.fabricatedCommands.length > 0) {
    blockedRules.push("R5_FABRICATED_COMMAND");
  }

  for (const reportedFile of reportedModified) {
    if (!ledger.turnWrittenFiles.has(reportedFile) && !(hasReliableGitStatus && gitLedger.gitDirtyFiles.has(reportedFile))) {
      details.phantomModified.push(reportedFile);
    }
  }
  if (details.phantomModified.length > 0) {
    if (ledger.turnWrittenFiles.size === 0 && hasReliableGitStatus) {
      blockedRules.push("R6_PHANTOM_MODIFIED");
    } else {
      warnedRules.push("R6_PHANTOM_MODIFIED");
    }
  }

  const hedge = detectHedges(selfAssessment);
  details.hedgeHits = hedge.hedgeHits;
  details.hedgeMatches = hedge.matches;
  if (hedge.hedgeHits >= 2 && effectiveUnverifiedScope.length === 0) {
    warnedRules.push("R7_HEDGE_DETECTED");
  }

  const priorRejects = ledger.turnGateAttempts.filter((attempt) => attempt.verdict === "REJECT").length;
  const claimsAnyPass = verificationRuns.some((run) => run.outcome === "pass");

  const sessionRole = typeof ledger.sessionRole === "string" && ledger.sessionRole.length > 0 ? ledger.sessionRole : "main";
  const allChallenges = Array.isArray(ledger.turnPreflightChallenges) ? ledger.turnPreflightChallenges : [];
  const completedChallenges = allChallenges.filter(
    (entry) => typeof entry?.completedStepIndex === "number" && entry.completedStepIndex >= 0,
  );
  const turnUserVotes = Array.isArray(ledger.turnUserVotes) ? ledger.turnUserVotes : [];
  const hasVoteAfterChallenge = (challenge) =>
    turnUserVotes.some(
      (vote) =>
        vote &&
        vote.answered === true &&
        vote.errored !== true &&
        typeof vote.completedStepIndex === "number" &&
        vote.completedStepIndex > challenge.completedStepIndex,
    );

  const latestChallenge =
    completedChallenges.length > 0 ? completedChallenges[completedChallenges.length - 1] : null;
  const unvotedChallenges = completedChallenges.filter((ch) => !hasVoteAfterChallenge(ch));
  const unvotedRethinkChallenge =
    unvotedChallenges.findLast((ch) => ch.verdict === "RETHINK") ?? null;
  const effectiveChallenge =
    unvotedRethinkChallenge ??
    (unvotedChallenges.length > 0 ? unvotedChallenges[unvotedChallenges.length - 1] : latestChallenge);
  const hasPostChallengeVote = Boolean(
    effectiveChallenge && !unvotedRethinkChallenge && unvotedChallenges.length === 0 && hasVoteAfterChallenge(effectiveChallenge),
  );
  const preflight = {
    used: Boolean(latestChallenge),
    verdict: effectiveChallenge ? effectiveChallenge.verdict : null,
    voted: hasPostChallengeVote,
  };
  const preflightMode = effectiveChallenge
    ? effectiveChallenge.mode === "auto"
      ? "auto"
      : "manual"
    : "none";

  if (sessionRole === "main" && ledger.turnCodeWrittenFiles.size > 0 && effectiveChallenge && !hasPostChallengeVote) {
    details.preflightVerdict = effectiveChallenge.verdict;
    if (effectiveChallenge.verdict === "RETHINK") {
      blockedRules.push("R9_PREFLIGHT_UNVOTED");
    } else if (preflightMode === "auto") {
      if (effectiveChallenge.verdict === "ERROR" || effectiveChallenge.verdict === "MISSING_VERDICT") {
        warnedRules.push("R9_PREFLIGHT_UNVOTED");
      }
    } else {
      warnedRules.push("R9_PREFLIGHT_UNVOTED");
    }
  }

  const risk =
    context.risk ??
    classifyRisk({
      turnCodeWrittenFiles: ledger.turnCodeWrittenFiles,
      gitLedger,
      config: context.governanceConfig ?? null,
      numstatUnavailable: Boolean(ledger?.commitNumstatUnavailable || gitLedger?.numstatUnavailable),
    });
  const allTurnAudits = Array.isArray(ledger.turnSubagentAudits) ? ledger.turnSubagentAudits : [];
  const totalAuditRejects = allTurnAudits.filter((audit) => audit.verdict === "REJECT").length;
  const auditAnchorStep = (audit) =>
    typeof audit.launchedStepIndex === "number" ? audit.launchedStepIndex : audit.stepIndex;
  const postWriteAudits = hasCodeWrite
    ? allTurnAudits.filter((audit) => auditAnchorStep(audit) > ledger.lastCodeWriteStepIndex)
    : allTurnAudits;
  const latestPostWriteAudit = postWriteAudits.length > 0 ? postWriteAudits[postWriteAudits.length - 1] : null;
  let consecutiveTrailingAuditErrors = 0;
  for (let i = postWriteAudits.length - 1; i >= 0; i -= 1) {
    const v = postWriteAudits[i].verdict;
    if (v === "ERROR" || v === "MISSING_VERDICT") {
      consecutiveTrailingAuditErrors += 1;
    } else {
      break;
    }
  }

  let verdict;
  let finalBlockedRules = blockedRules;
  let auditPassed = false;
  let auditVerdict = latestPostWriteAudit?.verdict ?? null;

  const isOnlyPreflightUnvotedBlock =
    blockedRules.length === 1 && blockedRules[0] === "R9_PREFLIGHT_UNVOTED";
  const canDegradeStandard =
    blockedRules.length > 0 && priorRejects >= 3 && effectiveUnverifiedScope.length >= 1 && !claimsAnyPass;
  const canDegradePreflightOnly =
    isOnlyPreflightUnvotedBlock && priorRejects >= 3 && effectiveUnverifiedScope.length >= 1;
  const needsIndependentAudit =
    (hasCodeWrite || risk.reasons.includes("numstat_unavailable")) &&
    auditEscalation === "auto" &&
    risk.tier === "TIER_1" &&
    sessionRole === "main";

  if (canDegradeStandard && !isOnlyPreflightUnvotedBlock && needsIndependentAudit) {
    // TIER_1 changes never degrade past the independent audit, however many REJECTs pile up.
    verdict = latestPostWriteAudit ? "REJECT" : "ESCALATE_AUDIT_REQUIRED";
  } else if (canDegradeStandard && !isOnlyPreflightUnvotedBlock) {
    verdict = "PASS_WITH_DEGRADATION";
    details.degradedFromBlockedRules = [...blockedRules];
    finalBlockedRules = [];
  } else if (blockedRules.length > 0 && !canDegradePreflightOnly) {
    verdict = "REJECT";
  } else {
    if (canDegradePreflightOnly) {
      details.degradedFromBlockedRules = [...blockedRules];
      finalBlockedRules = [];
    }

    if (needsIndependentAudit) {
      if (!latestPostWriteAudit) {
        verdict = "ESCALATE_AUDIT_REQUIRED";
      } else if (latestPostWriteAudit.verdict === "PASS") {
        auditPassed = true;
        verdict = canDegradePreflightOnly
          ? "PASS_WITH_DEGRADATION"
          : warnedRules.length > 0
            ? "PASS_WITH_WARNING"
            : "PASS";
      } else if (latestPostWriteAudit.verdict === "REJECT") {
        if (totalAuditRejects >= 2 && effectiveUnverifiedScope.length >= 1) {
          verdict = "PASS_WITH_AUDIT_DEGRADATION";
          details.auditDegradationReason = "reject";
        } else {
          finalBlockedRules = ["R8_AUDIT_REJECTED"];
          verdict = "REJECT";
        }
      } else if (consecutiveTrailingAuditErrors >= 2 && effectiveUnverifiedScope.length >= 1) {
        verdict = "PASS_WITH_AUDIT_DEGRADATION";
        details.auditDegradationReason = "error";
      } else {
        finalBlockedRules = ["R8_AUDIT_ERROR"];
        verdict = "REJECT";
      }
    } else if (canDegradePreflightOnly) {
      verdict = "PASS_WITH_DEGRADATION";
    } else if (warnedRules.length > 0) {
      verdict = "PASS_WITH_WARNING";
    } else {
      verdict = "PASS";
    }
  }

  const receiptText = formatGateReceipt({
    verdict,
    blockedRules: finalBlockedRules,
    warnedRules,
    details,
    register,
    risk,
    auditPassed,
    pollutionAlert,
  });

  return {
    verdict,
    passed: PASSING_VERDICTS.has(verdict),
    blockedRules: finalBlockedRules,
    warnedRules,
    details,
    risk,
    auditVerdict,
    preflight,
    preflightMode,
    receiptText,
    metrics: {
      hedgeHits: hedge.hedgeHits,
      priorRejects,
      unverifiedScopeCount: effectiveUnverifiedScope.length,
      fillerUnverifiedCount,
      riskTier: risk.tier,
      changedLines: risk.changedLines,
      auditRejectCount: totalAuditRejects,
      auditErrorCount: consecutiveTrailingAuditErrors,
      pollutionAlert,
    },
  };
}
