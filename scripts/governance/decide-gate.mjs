import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join, posix } from "node:path";
import {
  ALLOWED_AUDIT_ESCALATION_MODES,
  ALLOWED_SCHEMA_REGISTERS,
  PASSING_VERDICTS,
  POLLUTION_WARNING_LINE,
  REGISTER_COPY,
  RISK_REASON_LABELS,
} from "./constants.mjs";
import { classifyCommand, extractChainPrepSignature, normalizeWorkspacePath, splitShellSegments } from "./fact-ledger.mjs";
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

function normalizeExecDir(dir, { preserveSpaces = false } = {}) {
  if (typeof dir !== "string" || (preserveSpaces ? dir.length === 0 : dir.trim().length === 0)) {
    return ".";
  }
  const raw = preserveSpaces ? dir : dir.trim();
  const norm = posix.normalize(raw.replace(/\\/g, "/"));
  return norm.length > 1 ? norm.replace(/\/+$/, "") : norm;
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
  const nextDir = cleanArg.startsWith("/")
    ? normalizeExecDir(cleanArg)
    : currentDir.dir.startsWith("opaque:")
      ? `${currentDir.dir}/${cleanArg}`
      : currentDir.dir === "."
        ? normalizeExecDir(cleanArg)
        : normalizeExecDir(`${currentDir.dir}/${cleanArg}`);
  const stack = op === "pushd" ? [...currentDir.stack, currentDir.dir] : currentDir.stack;
  return { dir: nextDir, stack };
}

function extractVerificationEntries(cmd, baseDir = ".") {
  if (typeof cmd !== "string" || cmd.trim().length === 0) {
    return [];
  }
  const entries = [];
  let state = { dir: normalizeExecDir(baseDir), stack: [] };
  let prepPrefixes = [];
  let seq = 0;
  for (const seg of splitShellSegments(cmd)) {
    const rawTrimmed = seg.trim();
    if (rawTrimmed.length === 0) {
      continue;
    }
    const segTokens = splitQuotedWhitespace(rawTrimmed);
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
        const nextDir = dirArg.startsWith("/")
          ? normalizeExecDir(dirArg, { preserveSpaces: true })
          : state.dir.startsWith("opaque:")
            ? `${state.dir}/${dirArg}`
            : state.dir === "."
              ? normalizeExecDir(dirArg, { preserveSpaces: true })
              : normalizeExecDir(`${state.dir}/${dirArg}`, { preserveSpaces: true });
        const stack = segTokens[0] === "pushd" ? [...state.stack, state.dir] : state.stack;
        state = { dir: nextDir, stack };
      }
      continue;
    }
    const norm = normalizeCommandText(seg);
    const prepSig = extractChainPrepSignature(seg);
    if (prepSig) {
      prepPrefixes.push(`${state.dir}::${prepSig}`);
      continue;
    }
    if (classifyCommand(norm) === "verification") {
      entries.push({ seg: rawTrimmed, dir: state.dir, prepKey: prepPrefixes.join(" && ") });
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

function normalizeTestpathItem(raw) {
  return raw.trim().replace(/^['"]|['"]$/g, "").replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, "");
}

const SHELL_EXPANSION_META_RE = /[*?[\]~$`{}]/;

function splitQuotedWhitespaceWithMeta(rawValue, { splitComma = false } = {}) {
  const items = [];
  let cur = "";
  let quote = null;
  let hasToken = false;
  let hadUnquotedMeta = false;
  for (let i = 0; i < rawValue.length; i += 1) {
    const ch = rawValue[i];
    if (quote) {
      if (ch === "\\" && quote === '"' && i + 1 < rawValue.length) {
        i += 1;
        cur += rawValue[i];
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
        items.push({ value: cur, hadUnquotedMeta });
        cur = "";
        hasToken = false;
        hadUnquotedMeta = false;
      }
      continue;
    }
    if (SHELL_EXPANSION_META_RE.test(ch)) {
      hadUnquotedMeta = true;
    }
    cur += ch;
    hasToken = true;
  }
  if (quote !== null) {
    return null;
  }
  if (hasToken) {
    items.push({ value: cur, hadUnquotedMeta });
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

function parseTomlStringArray(rawArrayBody) {
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
      const normalized = normalizeTestpathItem(decoded.value);
      if (normalized) {
        items.push(normalized);
      }
      i = decoded.nextIdx;
      continue;
    }
    return null;
  }
  return items;
}

function parseIniTestpaths(text, targetSections) {
  const lines = text.split(/\r?\n/);
  let inTargetSection = false;
  let sawTargetSection = false;
  let foundKey = false;
  const collected = [];
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
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
    const keyMatch = /^testpaths\s*=\s*(.*)$/i.exec(trimmed);
    if (keyMatch) {
      foundKey = true;
      const firstVal = keyMatch[1].replace(/\s+[#;].*$/, "").trim();
      if (firstVal) {
        const splitFirst = shlexSplitTestpaths(firstVal);
        if (!splitFirst) return { restricted: true, paths: [] };
        collected.push(...splitFirst);
      }
      for (let j = i + 1; j < lines.length; j += 1) {
        const nextLine = lines[j];
        const nextTrimmed = nextLine.trim();
        if (!nextTrimmed || nextTrimmed.startsWith("#") || nextTrimmed.startsWith(";")) {
          continue;
        }
        if (/^[ \t]+/.test(nextLine) && !nextTrimmed.startsWith("[") && !nextTrimmed.includes("=")) {
          const clean = nextTrimmed.replace(/\s+[#;].*$/, "").trim();
          const splitNext = shlexSplitTestpaths(clean);
          if (!splitNext) return { restricted: true, paths: [] };
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
  return foundKey ? { restricted: true, paths: collected } : { restricted: false, paths: [] };
}

function shlexSplitTestpaths(rawValue) {
  const rawItems = splitQuotedWhitespace(rawValue, { splitComma: false });
  return rawItems ? rawItems.map(normalizeTestpathItem).filter(Boolean) : null;
}

function extractBracketedTomlArray(sectionBody) {
  const startMatch = /(?:^|\n)[ \t]*(?:testpaths|"testpaths"|'testpaths')[ \t]*=[ \t]*\[/.exec(sectionBody);
  if (!startMatch) {
    return null;
  }
  let i = startMatch.index + startMatch[0].length;
  const start = i;
  let quote = null;
  while (i < sectionBody.length) {
    const ch = sectionBody[i];
    if (quote) {
      if (ch === "\\" && quote === '"' && i + 1 < sectionBody.length) {
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
      while (i < sectionBody.length && sectionBody[i] !== "\n") {
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
      return sectionBody.slice(start, i);
    }
    i += 1;
  }
  return "";
}

function sectionHasUnsupportedTestpathsKey(sectionBody) {
  for (const line of sectionBody.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#") || !t.includes("=")) {
      continue;
    }
    if (t.startsWith('"') || t.startsWith("'")) {
      const dec = decodeTomlStringToken(t, 0);
      if (!dec) {
        return true;
      }
      const after = t.slice(dec.nextIdx).trim();
      if (dec.value === "testpaths" && !after.startsWith("=")) {
        return true;
      }
      if (dec.value === "testpaths" && after.startsWith("=") && !/^["']testpaths["'][ \t]*=/.test(t)) {
        return true;
      }
    } else if (/^testpaths\s*\./.test(t)) {
      return true;
    }
  }
  return false;
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

function tomlHasOtherPytestConfig(text, hasPrimaryIniOptions) {
  let currentTable = [];
  let iniOptionsCount = 0;
  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const t = rawLine.trim();
    if (!t || t.startsWith("#")) {
      continue;
    }
    if (t.startsWith("[")) {
      const closeIdx = t.startsWith("[[") ? t.indexOf("]]") : t.indexOf("]");
      if (closeIdx === -1) {
        return true;
      }
      const headerBody = t.slice(t.startsWith("[[") ? 2 : 1, closeIdx).trim();
      const segs = parseTomlKeySegments(headerBody);
      if (!segs) {
        if (/pytest/i.test(headerBody)) {
          return true;
        }
        currentTable = [];
        continue;
      }
      currentTable = segs;
      if (segs.length === 3 && segs[0] === "tool" && segs[1] === "pytest" && segs[2] === "ini_options") {
        iniOptionsCount += 1;
        if (iniOptionsCount > 1 || !hasPrimaryIniOptions) {
          return true;
        }
      } else if (segs.length >= 2 && segs[0] === "tool" && segs[1] === "pytest") {
        return true;
      }
      continue;
    }
    const eqPos = t.indexOf("=");
    if (eqPos !== -1) {
      const keyPart = t.slice(0, eqPos).trim();
      const keySegs = parseTomlKeySegments(keyPart);
      if (!keySegs) {
        if (/pytest/i.test(keyPart)) {
          return true;
        }
        continue;
      }
      const fullPath = [...currentTable, ...keySegs];
      if (fullPath.length >= 2 && fullPath[0] === "tool" && fullPath[1] === "pytest") {
        const isDirectIniOption =
          hasPrimaryIniOptions &&
          currentTable.length === 3 &&
          currentTable[0] === "tool" &&
          currentTable[1] === "pytest" &&
          currentTable[2] === "ini_options" &&
          keySegs.length === 1;
        if (!isDirectIniOption) {
          return true;
        }
      }
    }
  }
  return false;
}

function readPytestTestpaths(execDir) {
  if (!execDir || !existsSync(execDir)) {
    return { restricted: false, paths: [] };
  }
  for (const iniName of ["pytest.ini", ".pytest.ini"]) {
    const pytestIniPath = join(execDir, iniName);
    if (!existsSync(pytestIniPath)) {
      continue;
    }
    try {
      const parsed = parseIniTestpaths(readFileSync(pytestIniPath, "utf8"), new Set(["pytest"]));
      return parsed ?? { restricted: false, paths: [] };
    } catch {
      return { restricted: true, paths: [] };
    }
  }
  const pyprojPath = join(execDir, "pyproject.toml");
  if (existsSync(pyprojPath)) {
    try {
      const text = readFileSync(pyprojPath, "utf8");
      const sect = /^\[tool\.pytest\.ini_options\][ \t]*(?:#.*)?\r?\n([\s\S]*?)(?=\r?\n\[|$)/m.exec(text);
      if (sect) {
        if (tomlHasOtherPytestConfig(text, true) || sectionHasUnsupportedTestpathsKey(sect[1])) {
          return { restricted: true, paths: [] };
        }
        if (!/(?:^|\n)[ \t]*(?:testpaths|"testpaths"|'testpaths')[ \t]*=/.test(sect[1])) {
          return { restricted: false, paths: [] };
        }
        const arrBody = extractBracketedTomlArray(sect[1]);
        if (arrBody !== null) {
          const paths = parseTomlStringArray(arrBody);
          return paths ? { restricted: true, paths } : { restricted: true, paths: [] };
        }
        const strMatch = /(?:testpaths|"testpaths"|'testpaths')[ \t]*=[ \t]*(.+)/.exec(sect[1]);
        if (strMatch) {
          const rhs = strMatch[1].trim();
          const dec = decodeTomlStringToken(rhs, 0);
          if (dec && (!rhs.slice(dec.nextIdx).trim() || rhs.slice(dec.nextIdx).trim().startsWith("#"))) {
            const split = shlexSplitTestpaths(dec.value);
            return split ? { restricted: true, paths: split } : { restricted: true, paths: [] };
          }
        }
        return { restricted: true, paths: [] };
      }
      if (/^\[(?:["']?tool["']?\s*\.\s*["']?pytest["']?\b)/m.test(text) || tomlHasOtherPytestConfig(text, false)) {
        return { restricted: true, paths: [] };
      }
    } catch {
      return { restricted: true, paths: [] };
    }
  }
  for (const [fileName, sections] of [
    ["tox.ini", new Set(["pytest"])],
    ["setup.cfg", new Set(["tool:pytest"])],
  ]) {
    const cfgPath = join(execDir, fileName);
    if (!existsSync(cfgPath)) {
      continue;
    }
    try {
      const parsed = parseIniTestpaths(readFileSync(cfgPath, "utf8"), sections);
      if (parsed) {
        return parsed;
      }
    } catch {
      return { restricted: true, paths: [] };
    }
  }
  return { restricted: false, paths: [] };
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

function isDefaultDiscoverableTestTarget(target, runnerPrefix, execDir = "") {
  const unquoted = target.replace(/^['"]|['"]$/g, "");
  const rawFile = runnerPrefix.includes("pytest") ? unquoted.split("::")[0] : unquoted;
  const normRaw = rawFile.replace(/\\/g, "/");
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
    const tpConfig = readPytestTestpaths(execDir);
    if (tpConfig.restricted) {
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

function droppedTokenIndexes(failed, passed) {
  const dropped = [];
  let j = 0;
  for (let i = 0; i < failed.length; i += 1) {
    if (j < passed.length && failed[i] === passed[j]) {
      j += 1;
    } else {
      dropped.push(i);
    }
  }
  return j === passed.length ? dropped : null;
}

// A passing command clears a failing one when it is the same command, or the same runner and flags
// with every file target removed on a runner whose target-less form runs every test. Dropping only
// some targets narrows the run. Go widens only to `./...`, over relative package targets inside it.
function segmentResolvedBy(failedSeg, passedSeg, execDir = "") {
  if (failedSeg.length === 0 || passedSeg.length === 0) {
    return false;
  }
  const failed = splitQuotedWhitespace(failedSeg);
  const passed = splitQuotedWhitespace(passedSeg);
  if (!failed || !passed) {
    return false;
  }
  if (failed.length === passed.length && failed.every((tok, idx) => tok === passed[idx])) {
    return true;
  }
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
  const dropped = droppedTokenIndexes(failed, passed);
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
  if (isAbsolute(entryDir)) {
    return entryDir;
  }
  return baseCwd ? join(baseCwd, entryDir) : entryDir;
}

function entriesMatchForResolution(failedEntry, passedEntry, baseCwd = "") {
  if (failedEntry.dir !== passedEntry.dir) {
    return false;
  }
  if (failedEntry.prepKey && passedEntry.prepKey !== failedEntry.prepKey) {
    return false;
  }
  return segmentResolvedBy(failedEntry.seg, passedEntry.seg, resolveEntryExecDir(failedEntry.dir, baseCwd));
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
  return normalizeExecDir(failedBaseDir) === normalizeExecDir(passedBaseDir) && segmentResolvedBy(failedNorm, passedNorm, failedBaseDir);
}

function extractExecutionVerificationEntries(exec, defaultCwd = ".") {
  const baseDir = normalizeExecDir(exec?.execCwd || defaultCwd || ".");
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
    const failedBase = normalizeExecDir(failedExec?.execCwd || defaultCwd || ".");
    const passedBase = normalizeExecDir(passedExec?.execCwd || defaultCwd || ".");
    if (isCommandResolvedBy(failedExec?.command, passedExec?.command, failedBase, passedBase)) {
      return true;
    }
  }
  const failedEntries = extractExecutionVerificationEntries(failedExec, defaultCwd);
  const passedEntries = extractExecutionVerificationEntries(passedExec, defaultCwd);
  if (failedEntries.length > 0 && passedEntries.length > 0) {
    return failedEntries.every((failedEntry) => passedEntries.some((passedEntry) => entriesMatchForResolution(failedEntry, passedEntry)));
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
  return a.value === b.value && a.hadUnquotedMeta === b.hadUnquotedMeta;
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
  const postWriteVerifications = hasCodeWrite
    ? postWriteExecutions.filter((exec) => exec.kind === "verification" && isCompletedExec(exec))
    : [];

  if (hasCodeWrite && postWriteVerifications.length === 0) {
    for (const exec of postWriteExecutions) {
      if (exec.kind === "other" && extractVerificationSegments(exec.command).length > 0) {
        details.maskedVerifications.push(exec.command);
      }
    }
    const hasValidNaClaim = verificationRuns.some(
      (run) => run.outcome === "not_applicable" && run.reason_if_na.length > 0,
    );
    if (!testInfra.hasTestSuite && hasValidNaClaim && effectiveUnverifiedScope.length >= 1) {
      warnedRules.push("R2_STALE_VERIFICATION");
    } else {
      blockedRules.push("R2_STALE_VERIFICATION");
    }
  }

  if (hasCodeWrite && postWriteVerifications.length > 0) {
    const unresolvedFailures = [];
    for (let i = 0; i < postWriteVerifications.length; i += 1) {
      const exec = postWriteVerifications[i];
      if (exec.passed) {
        continue;
      }
      let resolvedByLaterPass = false;
      for (let j = i + 1; j < postWriteVerifications.length; j += 1) {
        const later = postWriteVerifications[j];
        if (!later.passed) {
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

    const lastVerification = postWriteVerifications[postWriteVerifications.length - 1];
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
