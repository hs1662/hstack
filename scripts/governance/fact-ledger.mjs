import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, constants as fsConstants, existsSync, fstatSync, lstatSync, openSync, readdirSync, readFileSync, readlinkSync, readSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import {
  extractLinePrefixType,
  findLastLine,
  LINE_TOO_LONG,
  readTailTranscriptSteps,
  readTranscriptSteps,
  resolveTranscriptCandidates,
  streamTranscriptRecords,
} from "../hook-io.mjs";
import { GATE_STOP_MARKER } from "../transcript/markers.mjs";
import { getToolCalls, isPreToolDenialStep, parseRawRecord, parseStepIndex, recordToStep } from "../transcript/steps.mjs";
import {
  AUDITOR_AGENT_NAME,
  AUDITOR_SESSION_MARKER,
  AUDIT_PASS_TAG,
  AUDIT_REJECT_TAG,
  AUTO_CHALLENGER_MARKER,
  AUTO_HANDOFF_MARKER,
  CHALLENGER_AGENT_NAME,
  CHALLENGER_SESSION_MARKER,
  CREATE_AS_READ_TOOL_NAMES,
  EXEC_TOOL_NAMES,
  GATE_TOOL_NAME,
  MCP_VERIFICATION_TOOL_NAMES,
  PASSING_VERDICTS,
  PREFLIGHT_CONDITIONAL_TAG,
  PREFLIGHT_PROCEED_TAG,
  PREFLIGHT_RETHINK_TAG,
  READ_ONLY_BINARIES,
  READ_ONLY_GIT_SUBCOMMANDS,
  READ_TOOL_NAMES,
  SUBAGENT_TOOL_NAME,
  USER_VOTE_TOOL_NAMES,
  VERDICT_HEADERS,
  VERIFICATION_BINARIES,
  WORKER_AGENT_NAME,
  WORKER_SESSION_MARKER,
  WRITE_TOOL_NAMES,
  isExemptDocOrAssetPath,
} from "./constants.mjs";

const RESULT_HEAD_MAX_CHARS = 256;
const RESULT_TAIL_MAX_CHARS = 2048;
const AUDIT_TAIL_MAX_CHARS = 4096;
const GIT_TIMEOUT_MS = 1500;
const MAX_UNWRAP_DEPTH = 2;
const MAX_UNTRACKED_COUNT_BYTES = 512 * 1024;
const SUBAGENT_CONVERSATION_ID_RE = /["']?(?:conversationId|conversation_id|sender)["']?\s*[:=]\s*["']?([0-9a-f-]{8,64})/i;
const SUBAGENT_CONVERSATION_ID_GLOBAL_RE = /["']?(?:conversationId|conversation_id|sender)["']?\s*[:=]\s*["']?([0-9a-f-]{8,64})/gi;
const SUBAGENT_SENDER_MSG_RE = /sender=([0-9a-f-]{8,64})\b/i;
const SYSTEM_WRAPPER_LINE_RE = /^<\/?(?:SYSTEM_MESSAGE|USER_REQUEST|ADDITIONAL_METADATA)>$/i;
const AUDITOR_MARKER_LINE_RE = /^\[hstack:독립감사\]$/;
const CHALLENGER_MARKER_LINE_RE = /^\[hstack:사전검토\]$/;
const WORKER_MARKER_LINE_RE = /^\[hstack:격리작업\]$/;
const INJECTED_CONTEXT_LINE_RE =
  /^(?:작업 경로:|세션 기록 경로:|현재 턴 시작 스텝:|-\s*작업 디렉터리:|위 작업 경로의 실제 파일과 호출 관계를 직접 읽고)/;
const PACKAGE_EXEC_RUNNERS = new Set(["npx", "pnpx", "bunx"]);
const PACKAGE_EXEC_SAFE_FLAGS = new Set([
  "-y",
  "--yes",
  "--no",
  "--no-install",
  "-q",
  "--quiet",
  "--silent",
  "--prefer-offline",
  "--offline",
  "--bun",
]);
const PACKAGE_EXEC_VERIFICATION_TOOLS = new Set([
  "vitest",
  "jest",
  "mocha",
  "ava",
  "tap",
  "playwright",
  "cypress",
  "tsc",
  "vue-tsc",
  "eslint",
  "oxlint",
  "biome",
  "stylelint",
]);
const NPM_TEST_SUBCOMMANDS = new Set(["test", "t", "tst"]);
const PNPM_YARN_DIRECT_CHECK_SUBCOMMANDS = new Set([
  "test",
  "t",
  "tst",
  "lint",
  "typecheck",
  "check",
  "build",
  "verify",
]);
const GO_VERIFICATION_SUBCOMMANDS = new Set(["test", "vet", "build"]);
const GO_EXEC_FLAG_RE = /^--?(?:exec|toolexec|vettool)(?:=|$)/;
const CARGO_VERIFICATION_SUBCOMMANDS = new Set(["test", "check", "clippy", "build", "bench", "doc"]);
const CARGO_VALUE_FLAGS = new Set(["--manifest-path", "--target", "--target-dir", "--package", "-p", "--features", "-F", "--jobs", "-j", "--color", "--config", "-Z"]);
const DENO_VERIFICATION_SUBCOMMANDS = new Set(["test", "check", "lint", "bench", "compile"]);
const PYTEST_NON_EXEC_LONG_RE = /^--(?:collect-only|co|fixtures|fixtures-per-test|markers|setup-plan|setup-only|help|version|version-verbose|cache-show)(?:=|$)/;
const PYTEST_SHORT_VALUE_CHARS = new Set(["c", "k", "m", "o", "p", "r", "W", "n"]);
const PYTEST_LONG_VALUE_FLAGS = new Set([
  "--config",
  "--config-file",
  "--override-ini",
  "--rootdir",
  "--confcutdir",
  "--junitxml",
  "--maxfail",
  "--tb",
  "--ignore",
  "--ignore-glob",
  "--deselect",
  "--basetemp",
  "--cov",
  "--cov-report",
  "--import-mode",
  "--log-level",
  "--log-format",
  "--log-date-format",
  "--log-file",
  "--log-cli-level",
  "-c",
  "-k",
  "-m",
  "-o",
  "-p",
  "-r",
  "-W",
  "-n",
]);
export const MAX_PYTEST_CONFIG_BYTES = 262144;
export const MAX_PYTEST_CONFIG_LINES = 5000;
export const MAX_PYTEST_CONFIG_LINE_CHARS = 16384;

export function readRegularFileBounded(
  filePath,
  { maxBytes = MAX_PYTEST_CONFIG_BYTES, maxLines = MAX_PYTEST_CONFIG_LINES, maxLineChars = MAX_PYTEST_CONFIG_LINE_CHARS } = {},
) {
  let fd = -1;
  try {
    const flags = fsConstants.O_RDONLY | (fsConstants.O_NONBLOCK ?? 0) | (fsConstants.O_NOFOLLOW ?? 0);
    fd = openSync(filePath, flags);
    const stBefore = fstatSync(fd);
    if (!stBefore.isFile()) {
      return { ok: false, reason: "not_regular", text: "" };
    }
    if (stBefore.size > maxBytes) {
      return { ok: false, reason: "too_large", text: "" };
    }
    const buf = Buffer.allocUnsafe(maxBytes + 1);
    let total = 0;
    while (total <= maxBytes) {
      const n = readSync(fd, buf, total, maxBytes + 1 - total, null);
      if (n <= 0) {
        break;
      }
      total += n;
    }
    if (total > maxBytes) {
      return { ok: false, reason: "too_large", text: "" };
    }
    const stAfter = fstatSync(fd);
    if (
      !stAfter.isFile() ||
      total !== stBefore.size ||
      total !== stAfter.size ||
      stBefore.size !== stAfter.size ||
      stBefore.mtimeMs !== stAfter.mtimeMs ||
      stBefore.ctimeMs !== stAfter.ctimeMs
    ) {
      return { ok: false, reason: "changed_during_read", text: "" };
    }
    const text = buf.subarray(0, total).toString("utf8");
    const lines = text.split(/\r?\n/);
    if (lines.length > maxLines) {
      return { ok: false, reason: "line_budget", text: "" };
    }
    for (const line of lines) {
      if (line.length > maxLineChars) {
        return { ok: false, reason: "line_budget", text: "" };
      }
    }
    return { ok: true, reason: "", text };
  } catch {
    return { ok: false, reason: "read_error", text: "" };
  } finally {
    if (fd !== -1) {
      try {
        closeSync(fd);
      } catch {
      }
    }
  }
}

export function hasPytestNonExecFlag(args) {
  if (!Array.isArray(args)) {
    return false;
  }
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (typeof arg !== "string") {
      return true;
    }
    if (arg === "--") {
      return false;
    }
    if (PYTEST_NON_EXEC_LONG_RE.test(arg)) {
      return true;
    }
    if (arg.startsWith("--")) {
      if (!arg.includes("=") && PYTEST_LONG_VALUE_FLAGS.has(arg)) {
        i += 1;
      }
      continue;
    }
    if (arg.startsWith("-") && arg.length > 1) {
      for (let k = 1; k < arg.length; k += 1) {
        const ch = arg[k];
        if (ch === "h" || ch === "V") {
          return true;
        }
        if (PYTEST_SHORT_VALUE_CHARS.has(ch)) {
          if (k === arg.length - 1) {
            i += 1;
          }
          break;
        }
      }
    }
  }
  return false;
}
const JS_TEST_LIST_FLAGS = new Set(["--listTests", "--list-tests", "--list", "--showConfig", "--show-config"]);
const MAKE_DRY_RUN_LONG_FLAGS = new Set([
  "--just-print",
  "--dry-run",
  "--recon",
  "--question",
  "--touch",
  "--print-data-base",
  "--help",
  "--version",
  "--ignore-errors",
  "--assume-old",
  "--old-file",
  "--assume-new",
  "--new-file",
  "--what-if",
  "--keep-going",
]);
const MAKE_SAFE_LONG_FLAGS = new Set([
  "--always-make",
  "--silent",
  "--quiet",
  "--no-print-directory",
  "--print-directory",
  "--no-builtin-rules",
  "--no-builtin-variables",
  "--warn-undefined-variables",
  "--environment-overrides",
  "--check-symlink-times",
  "--trace",
  "--debug",
  "--jobs",
  "--load-average",
  "--max-load",
  "--directory",
  "--file",
  "--makefile",
  "--include-dir",
  "--output-sync",
  "--shuffle",
  "--stop-on-failure",
  "--stop-on-error",
]);
const MAKE_LONG_REQUIRED_VALUE_FLAGS = new Set(["--directory", "--file", "--makefile", "--include-dir"]);
const MAKE_LONG_OPTIONAL_VALUE_FLAGS = new Set(["--debug", "--output-sync", "--shuffle"]);
const MAKE_LONG_OPT_NUM_FLAGS = new Set(["--jobs", "--load-average", "--max-load"]);
const MAKE_LONG_VALUE_FLAGS = new Set([
  ...MAKE_LONG_REQUIRED_VALUE_FLAGS,
  ...MAKE_LONG_OPTIONAL_VALUE_FLAGS,
  ...MAKE_LONG_OPT_NUM_FLAGS,
]);
const MAKE_BLOCKED_VARS = new Set(["MAKEFLAGS", "GNUMAKEFLAGS", "SHELL", "MAKE", ".SHELLFLAGS", "VPATH", "PATH"]);
const MAKE_VALUE_FLAGS = new Set(["f", "C", "I", "l", "j"]);
const MAKE_NOOP_SHORT_FLAGS = new Set(["n", "q", "t", "p", "h", "v", "i", "o", "W", "k"]);
const MAKE_SAFE_SHORT_FLAGS = new Set(["B", "s", "w", "r", "R", "S", "d", "e", "L", "O"]);
const SCRIPT_RUNNER_SAFE_VALUE_FLAGS = new Set(["-w", "--workspace", "--filter", "-F"]);
const SCRIPT_RUNNER_BLOCKED_FLAG_RE =
  /^(?:--if-present|--script-shell|--userconfig|--globalconfig|--prefix|--dir|--cwd|-C|--preload|-r|--require|--import|--loader)(?:=|$)/;
const NODE_TSX_VALUE_FLAGS = new Set([
  "-r",
  "--require",
  "--import",
  "--loader",
  "--conditions",
  "-C",
  "--env-file",
  "--env-file-if-exists",
  "--tsconfig",
  "--test-reporter",
  "--test-reporter-destination",
  "--test-name-pattern",
  "--test-skip-pattern",
  "--test-shard",
  "--test-concurrency",
  "--test-timeout",
  "-e",
  "--eval",
  "-p",
  "--print",
]);
const VERIFY_SCRIPT_NAME_RE = /(?:^|[:_-])(?:test|tests|check|verify|lint|typecheck|tsc|spec|build|e2e|unit|ci)(?:$|[:_-])/i;
const WRITE_SCRIPT_NAME_RE = /(?:^|[:_-])(?:fix|format|fmt|write|mutate|clean|deploy|release|publish|start|dev)(?:$|[:_-])/i;
const BARE_SCRIPT_RUNNERS = new Set(["npm", "pnpm", "yarn", "bun"]);
const ALLOWED_SUBAGENT_SYSTEM_SOURCES = new Set(["SYSTEM"]);
const SESSION_ROLE_PRIORITY = { main: 0, worker: 1, challenger: 2, auditor: 3 };
const ASYNC_LAUNCH_ACK_HINT_RE = /\b(?:launch(?:ed)?|start(?:ed)?|spawn(?:ed)?|creat(?:ed)?|subagent|background|async)\b/i;
const MAX_ASYNC_LAUNCH_ACK_CHARS = 2048;
const VOTE_TIMESTAMP_LINE_RE = /^(?:Created|Completed)\s+At:/i;
const VOTE_ANSWER_LINE_RE = /^A\d+\s*:\s*(.*)$/;
const VOTE_ERROR_CONTENT_RE =
  /^(?:Error:|Tool error:|Failed to|Cancelled|Canceled|User cancelled|User canceled|User rejected|Rejected|Dismissed|No answer|Aborted|Timeout)/i;
const FINAL_AUDIT_VERDICTS = new Set(["PASS", "REJECT", "ERROR"]);
const FINAL_PREFLIGHT_VERDICTS = new Set(["PROCEED", "CONDITIONAL", "RETHINK", "ERROR"]);

const SHELL_WRAPPERS = new Set(["sudo", "time", "env", "command", "nohup"]);
const WRAPPER_FLAGS_WITH_ARG = {
  env: new Set(["-u", "--unset", "-C", "--chdir", "-S", "--split-string"]),
  sudo: new Set(["-u", "--user", "-g", "--group", "-C", "--close-from", "-h", "--host", "-p", "--prompt", "-r", "--role", "-t", "--type", "-D", "--chdir"]),
};
const SHELL_NEUTRAL_BUILTINS = new Set(["cd", "pushd", "popd", "export", "set", "unset", "true", "false", "sleep", "umask"]);
// Flags that make an otherwise read-only binary run commands or write files.
const READ_ONLY_BINARY_WRITER_FLAG_RE = {
  find: /^-(?:exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)$/,
  rg: /^--pre(?:=|$)/,
  tree: /^-[oR]$|^--?output(?:=|$)/,
  file: /^-C$|^--compile$/,
  git: /^--output(?:=|$)/,
};
const GIT_FLAGS_WITH_ARG = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix"]);
const ENV_ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;
const SYSTEM_PATH_ENTRY_RE = /^(?:\$PATH|\$\{PATH\}|\/usr(?:\/local)?\/s?bin|\/s?bin)$/;

const NPM_BLOCKED_CONFIG_ENV_RE =
  /^(?:npm|pnpm|yarn)_config_(?:if[-_]present|script[-_]shell|userconfig|globalconfig|prefix|dir|cwd|ignore[-_]scripts|dry[-_]run)=/i;

// Assignments that change which binary or code runs: PATH with a non-system dir, preload and startup hooks, GIT_*, and unsafe package-manager env configs.
function isExecHijackAssign(tok) {
  if (/^(?:GIT_[A-Za-z0-9_]*|LD_[A-Za-z0-9_]*|DYLD_[A-Za-z0-9_]*|NODE_OPTIONS|BASH_ENV|ENV|SHELLOPTS|BASHOPTS|MAKEFLAGS|GNUMAKEFLAGS)=/.test(tok)) {
    return true;
  }
  if (NPM_BLOCKED_CONFIG_ENV_RE.test(tok)) {
    return true;
  }
  return tok.startsWith("PATH=") && tok.slice(5).split(":").some((entry) => !SYSTEM_PATH_ENTRY_RE.test(entry));
}

const EXIT_CODE_FAIL_RE = /exit\s+code[:\s]+[1-9]\d*/i;
const TAP_FAIL_ZERO_RE = /(?:^|\n)[ \t]*(?:#|ℹ)[ \t]*fail[ \t]+0\b/m;
const TAP_FAIL_NONZERO_RE = /(?:^|\n)[ \t]*(?:#|ℹ)[ \t]*fail[ \t]+[1-9]\d*\b/m;
const RUN_CHECKS_FAIL_HEADER_RE = /^Checks:\s+\d+\/\d+\s+passed,\s+(?:[1-9]\d*\s+failed|[1-9]\d*\s+not run)\b/m;
const RUN_CHECKS_ALL_PASSED_HEADER_RE = /^Checks:\s+(\d+)\/\1\s+passed\b(?!,\s*[1-9]\d*\s+(?:failed|not run)\b)/m;
const RUN_CHECKS_FAIL_BLOCK_RE = /^##\s+\[(?:FAIL|NOT RUN)\]/m;
const PASSING_TEST_LINE_RE = /^\s*(?:ok\s+\d+|ok\b|✔|✓|#\s*Subtest:|▶)/;
const FAILURE_LINE_PATTERNS = [
  EXIT_CODE_FAIL_RE,
  /^\s*(?:Error:\s*)?Command failed\b/i,
  /^\s*(?:AssertionError\b|[\w$.]*AssertionError\b)/,
  /^\s*FAIL\b/,
  /(?:^|[ \t#ℹ])fail[ \t]+[1-9]\d*\b/i,
];

const PRE_TOOL_NOTICE_PREFIX = "A pre-tool hook changed the arguments";
const VERDICT_HEADER_ENTRIES = [
  [VERDICT_HEADERS.REJECT_NEUTRAL, "REJECT"],
  [VERDICT_HEADERS.REJECT_AUDIT, "REJECT"],
  [VERDICT_HEADERS.PASS_WITH_AUDIT_DEGRADATION, "PASS_WITH_AUDIT_DEGRADATION"],
  [VERDICT_HEADERS.PASS_WITH_DEGRADATION, "PASS_WITH_DEGRADATION"],
  [VERDICT_HEADERS.PASS_WITH_WARNING, "PASS_WITH_WARNING"],
  [VERDICT_HEADERS.PASS, "PASS"],
  [VERDICT_HEADERS.ESCALATE_AUDIT_REQUIRED, "ESCALATE_AUDIT_REQUIRED"],
  [VERDICT_HEADERS.SKIPPED_NO_SESSION, "SKIPPED_NO_SESSION"],
];

const TEST_INFRA_EXACT_FILES = ["pytest.toml", ".pytest.toml", "pytest.ini", ".pytest.ini", "pyproject.toml", "Cargo.toml", "go.mod", "Makefile"];
const TEST_INFRA_CONFIG_PREFIXES = ["vitest.config.", "jest.config."];

function toPosix(rawPath) {
  if (process.platform === "win32" || /^[A-Za-z]:\\|^\\\\/.test(rawPath)) {
    return rawPath.replace(/\\/g, "/");
  }
  return rawPath;
}

function stripTrailingSlashes(p) {
  return p.length > 1 ? p.replace(/\/+$/, "") : p;
}

function isAbsolutePosix(p) {
  return p.startsWith("/") || /^[A-Za-z]:\//.test(p);
}

// Scoped to one readFactLedger call: a scan normalizes every tool path against the same bases.
let fsMemo = null;

function memoFs(kind, path, compute) {
  if (!fsMemo) {
    return compute();
  }
  let byPath = fsMemo.get(kind);
  if (!byPath) {
    byPath = new Map();
    fsMemo.set(kind, byPath);
  }
  if (!byPath.has(path)) {
    byPath.set(path, compute());
  }
  return byPath.get(path);
}

function memoExists(path) {
  return memoFs("exists", path, () => existsSync(path));
}

function tryRealpath(rawPath) {
  if (typeof rawPath !== "string" || rawPath.trim().length === 0) {
    return null;
  }
  return memoFs("realpath", rawPath, () => {
    try {
      return realpathSync(rawPath);
    } catch {
      return null;
    }
  });
}

function collectBaseVariants(rawBase) {
  if (typeof rawBase !== "string" || rawBase.trim().length === 0) {
    return [];
  }
  return memoFs("bases", rawBase, () => {
    const real = tryRealpath(rawBase);
    return real && real !== rawBase ? [rawBase, real] : [rawBase];
  });
}

// Absolute variants of a base, normalized once per scan; drive-letter bases compare case-insensitively.
function preparedBases(rawBase) {
  return memoFs("prepared", rawBase, () =>
    collectBaseVariants(rawBase).flatMap((variant) => {
      const norm = stripTrailingSlashes(posix.normalize(toPosix(variant)));
      if (!norm || !isAbsolutePosix(norm)) {
        return [];
      }
      const caseFold = /^[A-Za-z]:\//.test(norm);
      const cmp = caseFold ? norm.toLowerCase() : norm;
      return [{ norm, cmp, prefix: `${cmp}/`, caseFold }];
    }),
  );
}

function relativizeAgainstAnyBase(normPath, bases) {
  for (const { cmp, prefix, caseFold } of bases) {
    const cmpPath = caseFold ? normPath.toLowerCase() : normPath;
    if (cmpPath === cmp) {
      return ".";
    }
    if (cmpPath.startsWith(prefix)) {
      return normPath.slice(prefix.length);
    }
  }
  return null;
}

export function normalizeWorkspacePath(rawPath, cwd = "", gitRoot = "") {
  if (typeof rawPath !== "string" || rawPath.trim().length === 0) {
    return "";
  }
  let normalized = posix.normalize(toPosix(rawPath));
  const gitBases = preparedBases(gitRoot);
  const cwdBases = preparedBases(cwd);
  if (isAbsolutePosix(normalized)) {
    const rel = relativizeAgainstAnyBase(normalized, gitBases) ?? relativizeAgainstAnyBase(normalized, cwdBases);
    if (rel !== null) {
      normalized = rel;
    }
  } else if (cwdBases.length > 0 && gitBases.length > 0) {
    let cwdRel = null;
    for (const cwdCandidate of cwdBases) {
      cwdRel = relativizeAgainstAnyBase(cwdCandidate.norm, gitBases);
      if (cwdRel !== null) {
        break;
      }
    }
    if (cwdRel && cwdRel !== ".") {
      const alreadyGitRootRelative =
        !normalized.startsWith("../") &&
        gitRoot &&
        memoExists(gitRoot) &&
        !memoExists(join(cwd, normalized)) &&
        memoExists(join(gitRoot, normalized));
      if (!alreadyGitRootRelative) {
        normalized = posix.normalize(`${cwdRel}/${normalized}`);
      }
    }
  }
  normalized = normalized.replace(/^\.\//, "");
  return stripTrailingSlashes(normalized);
}

function splitShellChain(commandLine) {
  const chain = [];
  let current = "";
  let quote = null;
  for (let i = 0; i < commandLine.length; i += 1) {
    const ch = commandLine[i];
    if (quote) {
      current += ch;
      if (ch === "\\" && quote === '"' && i + 1 < commandLine.length) {
        i += 1;
        current += commandLine[i];
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === "\\" && i + 1 < commandLine.length) {
      current += ch + commandLine[i + 1];
      i += 1;
      continue;
    }
    const next = commandLine[i + 1];
    if ((ch === "&" && next === "&") || (ch === "|" && next === "|")) {
      chain.push({ text: current, op: ch + next });
      current = "";
      i += 1;
      continue;
    }
    // A lone `&` backgrounds its segment; `>&`, `<&` and `&>` are redirections.
    const isBackground = ch === "&" && next !== ">" && !/[<>]$/.test(current);
    if (ch === ";" || ch === "|" || ch === "\n" || isBackground) {
      chain.push({ text: current, op: ch });
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.length > 0) {
    chain.push({ text: current, op: "" });
  }
  return chain;
}

export function splitShellSegments(commandLine) {
  return splitShellChain(commandLine).map((seg) => seg.text);
}

function tokenizeSegment(segment) {
  const tokens = [];
  let current = "";
  let quote = null;
  for (let i = 0; i < segment.length; i += 1) {
    const ch = segment[i];
    if (quote) {
      if (ch === "\\" && quote === '"' && i + 1 < segment.length) {
        i += 1;
        current += segment[i];
      } else if (ch === quote) {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (current.length > 0) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }
  if (current.length > 0) {
    tokens.push(current);
  }
  return tokens;
}

// A check may keep its log; any other redirect target is a write the check only disguises.
const CHECK_LOG_TARGET_RE = /^(?:\/dev\/null|[\w./-]+\.(?:log|out|txt))$/;

function hasUnquotedFileRedirection(segment) {
  let quote = null;
  for (let i = 0; i < segment.length; i += 1) {
    const ch = segment[i];
    if (quote) {
      if (ch === "\\" && quote === '"' && i + 1 < segment.length) {
        i += 1;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (ch === "\\" && i + 1 < segment.length) {
      i += 1;
      continue;
    }
    if (ch === ">") {
      let j = i + 1;
      if (segment[j] === ">") {
        j += 1;
      }
      if (segment[j] === "&") {
        let k = j + 1;
        while (k < segment.length && /\d/.test(segment[k])) {
          k += 1;
        }
        if (k > j + 1 || segment[j + 1] === "-") {
          i = k - 1;
          continue;
        }
      }
      while (j < segment.length && /\s/.test(segment[j])) {
        j += 1;
      }
      const target = /^[^\s;&|<>]*/.exec(segment.slice(j))[0];
      if (target === "/dev/null") {
        i = j + target.length - 1;
        continue;
      }
      return true;
    }
  }
  return false;
}

const SHELL_INTERPRETERS = new Set(["sh", "bash"]);
const SHELL_OPTION_FLAGS_WITH_ARG = new Set(["-o", "+o", "-O", "+O"]);
const PYTHON_FLAGS_WITH_ARG = new Set(["-W", "-X"]);
// A short-flag cluster counts with its code attached too (`-e"…"` reaches the tokenizer as `-e…`).
const INLINE_CODE_FLAG_RE = {
  node: /^(?:-[A-Za-z]*[ep]|--eval|--print)/,
  bun: /^(?:-[A-Za-z]*[ep]|--eval|--print)/,
  tsx: /^(?:-[A-Za-z]*[ep]|--eval|--print)/,
};

// The inline body of an interpreter given code on its command line, or null for a script or a plain run.
// A shell `-c` body is shell, so it is returned for classification; any other language returns "" (never verification).
function inlineInterpreterBody(bin, args) {
  if (SHELL_INTERPRETERS.has(bin)) {
    let inline = false;
    let pipefail = false;
    let noexec = false;
    for (let i = 0; i < args.length; i += 1) {
      const arg = args[i];
      if (SHELL_OPTION_FLAGS_WITH_ARG.has(arg) || /^[-+][euxvn]*o$/.test(arg)) {
        if (arg.includes("n")) {
          noexec = arg[0] === "-";
        }
        if (args[i + 1] === "pipefail") {
          pipefail = arg[0] === "-";
        } else if (args[i + 1] === "noexec") {
          noexec = arg[0] === "-";
        }
        i += 1;
      } else if (/^[-+][A-Za-z]+$/.test(arg)) {
        if (arg.includes("n")) {
          noexec = arg[0] === "-";
        }
        inline ||= arg[0] === "-" && arg.includes("c");
      } else if (/^-[A-Za-z]*c/.test(arg)) {
        const prefixFlags = arg.slice(1, arg.indexOf("c"));
        if (prefixFlags.includes("n")) {
          noexec = true;
        }
        if (noexec) {
          return "";
        }
        // Words after the body become $0, $1…, which the body may run; only a body with nothing after it counts.
        const body = i === args.length - 1 ? arg.slice(arg.indexOf("c") + 1) : "";
        return pipefail && body ? `set -o pipefail && ${body}` : body;
      } else if (!arg.startsWith("--") || arg === "--") {
        if (noexec) {
          return "";
        }
        const bodyIdx = arg === "--" ? i + 1 : i;
        const body = bodyIdx === args.length - 1 ? args[bodyIdx] : "";
        return inline ? (pipefail && body ? `set -o pipefail && ${body}` : body) : null;
      }
    }
    if (noexec) {
      return "";
    }
    return inline ? "" : null;
  }
  if (bin === "python" || bin === "python3") {
    for (let i = 0; i < args.length; i += 1) {
      const arg = args[i];
      if (!arg.startsWith("-")) {
        return null;
      }
      // The first of c/m/W/X in a short-flag cluster takes the rest of it (or the next arg) as its value.
      const flag = /^-[A-Za-z]*?([cmWX]|$)/.exec(arg)?.[1];
      if (flag === "c") {
        return "";
      }
      if (flag === "m") {
        return null;
      }
      if (PYTHON_FLAGS_WITH_ARG.has(arg)) {
        i += 1;
      }
    }
    return null;
  }
  if (bin === "deno") {
    return args.find((arg) => !arg.startsWith("-")) === "eval" ? "" : null;
  }
  const flagRe = INLINE_CODE_FLAG_RE[bin];
  if (!flagRe) {
    return null;
  }
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--") {
      break;
    }
    if (flagRe.test(arg)) {
      return "";
    }
    if (arg.startsWith("-")) {
      if (NODE_TSX_VALUE_FLAGS.has(arg)) {
        i += 1;
      }
      continue;
    }
    break;
  }
  return null;
}

function isCommandProbeInvocation(tokens) {
  let idx = 0;
  while (idx < tokens.length && (tokens[idx] === "!" || tokens[idx] === "(" || ENV_ASSIGN_RE.test(tokens[idx]))) {
    if (isExecHijackAssign(tokens[idx])) {
      return false;
    }
    idx += 1;
  }
  if (tokens[idx] !== "command") {
    return false;
  }
  idx += 1;
  let seenProbe = false;
  while (idx < tokens.length) {
    const arg = tokens[idx];
    if (arg === "--") {
      return seenProbe && idx + 1 < tokens.length;
    }
    if (!arg.startsWith("-")) {
      return seenProbe;
    }
    if (/^-[pvV]+$/.test(arg)) {
      seenProbe ||= /[vV]/.test(arg);
      idx += 1;
      continue;
    }
    return false;
  }
  return false;
}

const WRAPPER_VALUE_SHORT_CHARS = {
  env: new Set(["u", "C", "S"]),
  sudo: new Set(["u", "g", "C", "h", "p", "r", "t", "D"]),
};
const WRAPPER_NOARG_SHORT_CHARS = {
  env: new Set(["i", "0", "v"]),
  sudo: new Set(["A", "E", "H", "n", "P", "S"]),
  time: new Set(["p", "v"]),
  nohup: new Set([]),
};
const WRAPPER_SAFE_LONG_NOARG = {
  env: new Set(["--ignore-environment", "--null", "--debug"]),
  sudo: new Set(["--askpass", "--preserve-env", "--set-home", "--non-interactive", "--preserve-groups", "--stdin"]),
  time: new Set(["--portability", "--verbose"]),
  nohup: new Set([]),
};
const SUDO_NON_EXEC_SHORT_CHARS = new Set(["b", "e", "h", "i", "K", "k", "l", "s", "V", "v"]);
const SUDO_NON_EXEC_LONG_FLAGS = new Set([
  "--background",
  "--edit",
  "--help",
  "--list",
  "--login",
  "--remove-timestamp",
  "--reset-timestamp",
  "--shell",
  "--validate",
  "--version",
]);
const ENV_NON_EXEC_LONG_FLAGS = new Set(["--help", "--version"]);

// The binary index and wrapper context after leading assignments and wrappers, or binIdx: -1 on hijack/opaque prefix.
function parseCommandPrefix(tokens) {
  let idx = 0;
  let envPytestAddopts = null;
  let envPytestCleared = false;
  const chdirs = [];
  let chdirOpaque = false;
  const applyChdirVal = (dirVal) => {
    if (!dirVal || dirVal === "-" || dirVal.startsWith("~") || /[$`]/.test(dirVal)) {
      chdirOpaque = true;
    } else {
      chdirs.push(dirVal);
    }
  };
  const applyEnvUnset = (varName) => {
    if (varName === "PYTEST_ADDOPTS") {
      envPytestAddopts = null;
      envPytestCleared = true;
    }
  };
  while (idx < tokens.length) {
    const tok = tokens[idx];
    if (isExecHijackAssign(tok)) {
      return { binIdx: -1, chdirs, chdirOpaque: true, envPytestAddopts: null, envPytestCleared: false };
    }
    if (tok === "!" || tok === "(" || ENV_ASSIGN_RE.test(tok)) {
      if (tok.startsWith("PYTEST_ADDOPTS=")) {
        envPytestAddopts = tok.slice("PYTEST_ADDOPTS=".length);
        envPytestCleared = false;
      }
      idx += 1;
      continue;
    }
    if (SHELL_WRAPPERS.has(tok)) {
      const valueFlags = WRAPPER_FLAGS_WITH_ARG[tok];
      const valueChars = WRAPPER_VALUE_SHORT_CHARS[tok];
      const noargChars = WRAPPER_NOARG_SHORT_CHARS[tok];
      const safeLongNoarg = WRAPPER_SAFE_LONG_NOARG[tok];
      idx += 1;
      while (idx < tokens.length) {
        const arg = tokens[idx];
        // `env -S` splits its argument into a whole new command line.
        if (tok === "env" && (arg === "-S" || arg === "--split-string" || arg.startsWith("--split-string=") || isExecHijackAssign(arg))) {
          return { binIdx: -1, chdirs, chdirOpaque: true, envPytestAddopts: null, envPytestCleared: false };
        }
        if (tok === "env" && (arg === "-" || arg === "--ignore-environment")) {
          envPytestAddopts = null;
          envPytestCleared = true;
          idx += 1;
          continue;
        }
        if (tok === "env" && arg.startsWith("--chdir=")) {
          applyChdirVal(arg.slice("--chdir=".length));
          idx += 1;
          continue;
        }
        if (tok === "env" && arg.startsWith("--unset=")) {
          applyEnvUnset(arg.slice("--unset=".length));
          idx += 1;
          continue;
        }
        if (tok === "sudo" && arg.startsWith("--chdir=")) {
          applyChdirVal(arg.slice("--chdir=".length));
          idx += 1;
          continue;
        }
        if (tok === "sudo" && SUDO_NON_EXEC_LONG_FLAGS.has(arg)) {
          return { binIdx: -1, chdirs, chdirOpaque: true, envPytestAddopts: null, envPytestCleared: false };
        }
        if (tok === "env" && ENV_NON_EXEC_LONG_FLAGS.has(arg)) {
          return { binIdx: -1, chdirs, chdirOpaque: true, envPytestAddopts: null, envPytestCleared: false };
        }
        if (arg === "--") {
          idx += 1;
          break;
        }
        if (tok === "command") {
          if (arg === "-p") {
            idx += 1;
            continue;
          }
          if (!arg.startsWith("-")) {
            break;
          }
          return { binIdx: -1, chdirs, chdirOpaque: true, envPytestAddopts: null, envPytestCleared: false };
        }
        if (valueFlags && valueFlags.has(arg)) {
          const val = tokens[idx + 1];
          if ((tok === "env" && (arg === "-C" || arg === "--chdir")) || (tok === "sudo" && (arg === "-D" || arg === "--chdir"))) {
            applyChdirVal(val);
          } else if (tok === "env" && (arg === "-u" || arg === "--unset")) {
            applyEnvUnset(val);
          }
          idx += 2;
          continue;
        }
        if (arg.startsWith("--")) {
          if (arg.includes("=")) {
            const optName = arg.slice(0, arg.indexOf("="));
            if (tok === "sudo" && valueFlags?.has(optName)) {
              idx += 1;
              continue;
            }
            chdirOpaque = true;
            idx += 1;
            continue;
          }
          if (!safeLongNoarg?.has(arg)) {
            chdirOpaque = true;
          }
          idx += 1;
          continue;
        }
        if (arg.startsWith("-") && arg.length > 1) {
          let consumedNext = false;
          let opaqueShort = false;
          for (let k = 1; k < arg.length; k += 1) {
            const ch = arg[k];
            if (tok === "sudo" && SUDO_NON_EXEC_SHORT_CHARS.has(ch)) {
              return { binIdx: -1, chdirs, chdirOpaque: true, envPytestAddopts: null, envPytestCleared: false };
            }
            if (tok === "env" && ch === "i") {
              envPytestAddopts = null;
              envPytestCleared = true;
              continue;
            }
            if (valueChars?.has(ch)) {
              const attached = arg.slice(k + 1);
              const val = attached.length > 0 ? attached : tokens[idx + 1];
              if (!attached) {
                consumedNext = true;
              }
              if ((tok === "env" && ch === "C") || (tok === "sudo" && ch === "D")) {
                applyChdirVal(val);
              } else if (tok === "env" && ch === "u") {
                applyEnvUnset(val);
              } else if (tok === "env" && ch === "S") {
                return { binIdx: -1, chdirs, chdirOpaque: true, envPytestAddopts: null, envPytestCleared: false };
              }
              break;
            }
            if (!noargChars?.has(ch)) {
              opaqueShort = true;
            }
          }
          if (opaqueShort) {
            chdirOpaque = true;
          }
          idx += consumedNext ? 2 : 1;
          continue;
        }
        if (tok === "env" && ENV_ASSIGN_RE.test(arg)) {
          if (arg.startsWith("PYTEST_ADDOPTS=")) {
            envPytestAddopts = arg.slice("PYTEST_ADDOPTS=".length);
            envPytestCleared = false;
          }
          idx += 1;
          continue;
        }
        break;
      }
      continue;
    }
    break;
  }
  return { binIdx: idx, chdirs, chdirOpaque, envPytestAddopts, envPytestCleared };
}

function skipCommandPrefix(tokens) {
  return parseCommandPrefix(tokens).binIdx;
}

// read_only, empty or other; runners are other here, since only matchesVerificationGrammar grants verification.
function classifySingleSegment(segment) {
  const cleaned = segment.trim().replace(/^[(!\s]+/, "");
  if (cleaned.length === 0) {
    return "empty";
  }
  const hasFileRedirect = hasUnquotedFileRedirection(cleaned);
  const tokens = tokenizeSegment(cleaned);
  if (isCommandProbeInvocation(tokens)) {
    return hasFileRedirect ? "other" : "read_only";
  }
  const idx = skipCommandPrefix(tokens);
  if (idx === -1) {
    return "other";
  }
  if (idx >= tokens.length) {
    return "empty";
  }

  const rawBin = tokens[idx];
  const baseBin = posix.basename(toPosix(rawBin));
  const writerFlagRe = READ_ONLY_BINARY_WRITER_FLAG_RE[baseBin];
  if (writerFlagRe && tokens.slice(idx + 1).some((tok) => writerFlagRe.test(tok))) {
    return "other";
  }

  if (baseBin === "git") {
    let subIdx = idx + 1;
    while (subIdx < tokens.length) {
      const arg = tokens[subIdx];
      // `-c core.fsmonitor=…` and `--config-env` make even `git status` run a command.
      if (arg === "-c" || arg.startsWith("--config-env")) {
        return "other";
      }
      if (GIT_FLAGS_WITH_ARG.has(arg)) {
        subIdx += 2;
        continue;
      }
      if (arg.startsWith("-")) {
        subIdx += 1;
        continue;
      }
      break;
    }
    const subcommand = tokens[subIdx] ?? "";
    if (READ_ONLY_GIT_SUBCOMMANDS.has(subcommand) && !hasFileRedirect) {
      return "read_only";
    }
    return "other";
  }

  if (baseBin === "export" && tokens.slice(idx + 1).some((tok) => isExecHijackAssign(tok))) {
    return "other";
  }
  if (READ_ONLY_BINARIES.has(baseBin) || SHELL_NEUTRAL_BUILTINS.has(baseBin)) {
    return hasFileRedirect ? "other" : "read_only";
  }
  if (tokens.length === idx + 2 && isVersionProbe(baseBin, tokens[idx + 1])) {
    return hasFileRedirect ? "other" : "read_only";
  }
  if (BARE_SCRIPT_RUNNERS.has(baseBin)) {
    const args = tokens.slice(idx + 1).filter((tok) => !tok.startsWith("-"));
    if (args.length === 1 && (args[0] === "run" || args[0] === "run-script")) {
      return "read_only";
    }
  }
  return "other";
}

// Unquoted, these start syntax the grammar does not accept: subshells, groups, negation, expansion, `;`, `||`, `&`,
// input redirects, escapes. `$`, backticks and backslashes inside double quotes still expand, so they fail too.
const GRAMMAR_METACHARS = new Set(["(", ")", "{", "}", "!", "$", "`", "|", "&", "<", ">", "\\", ";"]);
const PIPE_FILTERS = new Set(["tail", "head", "grep"]);
const SET_FLAG_RE = /^[-+](?:[euxv]*o|[euxv]+)$/;
const SET_OPTIONS = new Set(["pipefail", "errexit", "nounset", "xtrace"]);

// Lexes `cmd [&& cmd]… [| cmd]` into { words, redirects, raw, op } commands, or null on any other syntax. A
// redirect is kept only as `2>&1`/`1>&2` or `[12]>[>] /dev/null|x.log|x.out|x.txt`; a trailing `;` or newline ends the line.
function lexVerificationChain(line) {
  const cmds = [];
  let cur = { words: [], redirects: 0, start: 0 };
  let word = null;
  const flush = () => {
    if (word !== null) {
      cur.words.push(word);
      word = null;
    }
  };
  const close = (op, end) => {
    flush();
    if (cur.words.length === 0) {
      return false;
    }
    cmds.push({ words: cur.words, redirects: cur.redirects, raw: line.slice(cur.start, end), op });
    return true;
  };
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === "'" || ch === '"') {
      let inner = "";
      let closed = false;
      for (let j = i + 1; j < line.length; j += 1) {
        const innerCh = line[j];
        if (ch === '"' && (innerCh === "$" || innerCh === "`")) {
          return null;
        }
        if (ch === '"' && innerCh === "\\") {
          const nextCh = j + 1 < line.length ? line[j + 1] : "";
          if (!nextCh || nextCh === '"' || nextCh === "\\" || nextCh === "$" || nextCh === "`" || nextCh === "\n") {
            return null;
          }
          inner += innerCh;
          continue;
        }
        if (innerCh === ch) {
          word = (word ?? "") + inner;
          i = j;
          closed = true;
          break;
        }
        inner += innerCh;
      }
      if (!closed) {
        return null;
      }
    } else if (ch === " " || ch === "\t") {
      flush();
    } else if (ch === ">" || (word === null && /[12]/.test(ch) && line[i + 1] === ">")) {
      flush();
      const m = /^[12]?>(?:&[12](?![^\s&|;])|>?[ \t]*([^\s()<>&|;'"`$\\]+))/.exec(line.slice(i));
      if (!m || (m[1] !== undefined && !CHECK_LOG_TARGET_RE.test(m[1]))) {
        return null;
      }
      cur.redirects += 1;
      i += m[0].length - 1;
    } else if (ch === "&" && line[i + 1] === "&") {
      if (!close("&&", i)) {
        return null;
      }
      i += 1;
      cur = { words: [], redirects: 0, start: i + 1 };
    } else if (ch === "|" && line[i + 1] !== "|") {
      if (!close("|", i)) {
        return null;
      }
      cur = { words: [], redirects: 0, start: i + 1 };
    } else if (ch === ";" || ch === "\n") {
      return /^[\s;]*$/.test(line.slice(i)) && close("", i) ? cmds : null;
    } else if (GRAMMAR_METACHARS.has(ch) || (ch === "#" && word === null)) {
      return null;
    } else {
      word = (word ?? "") + ch;
    }
  }
  return close("", line.length) ? cmds : null;
}

const NODE_TEST_FILE_RE = /(?:^|\/)test\/|\.(?:test|spec)\.[cm]?[jt]sx?$/;
const PYTHON_TEST_FILE_RE = /(?:^|\/)tests?\/|(?:^|\/)test_[^/]*\.py$|_test\.py$/;
const CHECK_SCRIPT_RE = /(?:^|\/)tests?\/|(?:^|\/)[^/]*(?:test|check|verify|lint|spec)[^/]*$/i;

// `--version` and friends print and exit, so they neither check nor write. pytest's `-v` is verbose, not a probe,
// and `version`/`help` are subcommands only for go and cargo (`make help` is a target, `sh help` a script).
function isVersionProbe(bin, arg) {
  if (!VERIFICATION_BINARIES.has(bin) && !PACKAGE_EXEC_VERIFICATION_TOOLS.has(bin)) {
    return false;
  }
  if (arg === "version" || arg === "help") {
    return bin === "go" || bin === "cargo";
  }
  return arg === "--version" || arg === "-V" || arg === "--help" || arg === "-h" || (arg === "-v" && bin !== "pytest");
}

// Parse `-m pytest|py.test` through Python interpreter options (`-u`, `-W arg`, `-X arg`, ...).
function parsePythonPytestArgs(args) {
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--version" || arg === "-V" || arg === "--help" || arg === "-h") {
      return null;
    }
    if (!arg.startsWith("-")) {
      return null;
    }
    const flag = /^-[A-Za-z]*?([cmWX]|$)/.exec(arg)?.[1];
    if (flag === "c") {
      return null;
    }
    if (flag === "m") {
      const attached = arg.slice(arg.indexOf("m") + 1);
      const module = attached || (args[i + 1] ?? "");
      if (module !== "pytest" && module !== "py.test") {
        return null;
      }
      return {
        module,
        modArgs: args.slice(attached ? i + 1 : i + 2),
        moduleArgConsumed: attached ? i + 1 : i + 2,
      };
    }
    if (PYTHON_FLAGS_WITH_ARG.has(arg)) {
      i += 1;
    }
  }
  return null;
}

export function extractPytestCommandInfo(segment) {
  if (typeof segment !== "string" || segment.trim().length === 0) {
    return null;
  }
  const cleaned = segment.trim().replace(/^[(!\s]+/, "");
  const lexed = lexVerificationChain(cleaned);
  let tokens = lexed && lexed.length === 1 ? lexed[0].words : tokenizeSegment(cleaned);
  if (!tokens || tokens.length === 0) {
    return null;
  }
  if (!lexed && tokens.some((tok) => /[<>]/.test(tok))) {
    return null;
  }
  const prefix = parseCommandPrefix(tokens);
  const idx = prefix.binIdx;
  if (idx === -1 || idx >= tokens.length) {
    return null;
  }
  const baseBin = posix.basename(toPosix(tokens[idx]));
  if (SHELL_INTERPRETERS.has(baseBin)) {
    const body = inlineInterpreterBody(baseBin, tokens.slice(idx + 1));
    if (body === "") {
      return null;
    }
    if (body !== null) {
      return {
        isPytest: false,
        shellBody: body,
        bin: baseBin,
        envPytestAddopts: prefix.envPytestAddopts,
        envPytestCleared: prefix.envPytestCleared,
        chdirs: prefix.chdirs,
        chdirOpaque: prefix.chdirOpaque,
      };
    }
  }
  if (baseBin === "pytest" || baseBin === "py.test") {
    return {
      isPytest: true,
      runnerKind: "pytest",
      bin: baseBin,
      args: tokens.slice(idx + 1),
      envPytestAddopts: prefix.envPytestAddopts,
      envPytestCleared: prefix.envPytestCleared,
      chdirs: prefix.chdirs,
      chdirOpaque: prefix.chdirOpaque,
      prefixEndIdx: idx + 1,
      tokens,
    };
  }
  if (baseBin === "python" || baseBin === "python3" || /^python3?\.\d+$/.test(baseBin)) {
    const pyMod = parsePythonPytestArgs(tokens.slice(idx + 1));
    if (pyMod) {
      return {
        isPytest: true,
        runnerKind: "python-pytest",
        bin: baseBin,
        args: pyMod.modArgs,
        envPytestAddopts: prefix.envPytestAddopts,
        envPytestCleared: prefix.envPytestCleared,
        chdirs: prefix.chdirs,
        chdirOpaque: prefix.chdirOpaque,
        prefixEndIdx: idx + 1 + pyMod.moduleArgConsumed,
        tokens,
      };
    }
  }
  return {
    isPytest: false,
    bin: baseBin,
    chdirs: prefix.chdirs,
    chdirOpaque: prefix.chdirOpaque,
  };
}

// python runs any program, so it counts only for `-m pytest|unittest` (with actual test execution) or a test file.
function pythonRunsTests(args) {
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--version" || arg === "-V" || arg === "--help" || arg === "-h") {
      return false;
    }
    if (!arg.startsWith("-")) {
      return PYTHON_TEST_FILE_RE.test(arg);
    }
    const flag = /^-[A-Za-z]*?([cmWX]|$)/.exec(arg)?.[1];
    if (flag === "m") {
      const attached = arg.slice(arg.indexOf("m") + 1);
      const module = attached || (args[i + 1] ?? "");
      if (module !== "pytest" && module !== "unittest") {
        return false;
      }
      const modArgs = args.slice(attached ? i + 1 : i + 2);
      const sepIdx = modArgs.indexOf("--");
      const modHead = sepIdx === -1 ? modArgs : modArgs.slice(0, sepIdx);
      if (modHead.some((a) => a === "--version" || a === "-V" || a === "--help" || a === "-h")) {
        return false;
      }
      if (module === "pytest" && hasPytestNonExecFlag(modArgs)) {
        return false;
      }
      return true;
    }
    if (PYTHON_FLAGS_WITH_ARG.has(arg)) {
      i += 1;
    }
  }
  return false;
}

// The script a shell runs from a file (`bash x.sh`), or "" when it reads stdin.
function shellScriptArg(args) {
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (SHELL_OPTION_FLAGS_WITH_ARG.has(arg)) {
      i += 1;
    } else if (arg === "--") {
      return args[i + 1] ?? "";
    } else if (!/^[-+]/.test(arg)) {
      return arg;
    }
  }
  return "";
}

function isSafeAssign(tok) {
  return ENV_ASSIGN_RE.test(tok) && !isExecHijackAssign(tok);
}

function isValidSetCommandArgs(args) {
  if (args.length === 0) {
    return false;
  }
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (!SET_FLAG_RE.test(arg)) {
      return false;
    }
    if (arg.endsWith("o")) {
      if (!SET_OPTIONS.has(args[i + 1] ?? "")) {
        return false;
      }
      i += 1;
    }
  }
  return true;
}

function extractSetCommandArgs(words) {
  if (words[0] === "set") {
    return words.slice(1);
  }
  if (words[0] !== "command") {
    return null;
  }
  let idx = 1;
  while (idx < words.length) {
    const arg = words[idx];
    if (arg === "--") {
      idx += 1;
      break;
    }
    if (arg === "-p") {
      idx += 1;
      continue;
    }
    if (arg.startsWith("-")) {
      return null;
    }
    break;
  }
  return words[idx] === "set" ? words.slice(idx + 1) : null;
}

// cd/pushd/popd, `set` with errexit/nounset/xtrace/pipefail only, safe assignments or exports, or a read-only command.
function isPrefixCommand({ words, raw }) {
  const [bin, ...args] = words;
  if (words.every(isSafeAssign) || (bin === "export" && args.length > 0 && args.every(isSafeAssign))) {
    return true;
  }
  if (bin === "cd" || bin === "pushd" || bin === "popd") {
    return args.length <= 1;
  }
  const setArgs = extractSetCommandArgs(words);
  if (setArgs !== null) {
    // `set -n` (noexec) would skip the runner and exit 0, so only these flags pass.
    return isValidSetCommandArgs(setArgs);
  }
  const innerIdx = skipCommandPrefix(words);
  if (innerIdx !== -1 && words[innerIdx] === "set") {
    return false;
  }
  return bin !== "export" && classifySingleSegment(raw) === "read_only";
}

function applyPipefailState({ words }, current) {
  const setArgs = extractSetCommandArgs(words);
  if (setArgs === null) {
    return current;
  }
  let state = current;
  for (let i = 0; i < setArgs.length; i += 1) {
    const tok = setArgs[i];
    if (SET_FLAG_RE.test(tok) && tok.endsWith("o")) {
      if (setArgs[i + 1] === "pipefail") {
        state = tok[0] === "-";
      }
      i += 1;
    }
  }
  return state;
}

function hasLeadingVersionProbe(bin, args) {
  if (!VERIFICATION_BINARIES.has(bin) && !PACKAGE_EXEC_VERIFICATION_TOOLS.has(bin)) {
    return false;
  }
  if (bin === "pytest" || bin === "py.test") {
    return hasPytestNonExecFlag(args);
  }
  const verboseDashVAllowed = bin === "go" || bin === "cargo" || bin === "ctest" || bin === "rspec";
  const sepIdx = args.indexOf("--");
  const head = sepIdx === -1 ? args : args.slice(0, sepIdx);
  for (let i = 0; i < head.length; i += 1) {
    const arg = head[i];
    if (arg === "--version" || arg === "-V" || arg === "--help" || arg === "-h" || (arg === "-v" && !verboseDashVAllowed)) {
      return true;
    }
    if ((bin === "node" || bin === "tsx") && NODE_TSX_VALUE_FLAGS.has(arg)) {
      i += 1;
    }
  }
  return false;
}

function isNodeOrTsxVerification(bin, args) {
  if (inlineInterpreterBody(bin, args) !== null) {
    return false;
  }
  let sawTestFlag = false;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--") {
      return sawTestFlag || NODE_TEST_FILE_RE.test(args[i + 1] ?? "");
    }
    if (isVersionProbe(bin, arg)) {
      return false;
    }
    if (arg === "--test") {
      sawTestFlag = true;
      continue;
    }
    if (arg.startsWith("-")) {
      if (NODE_TSX_VALUE_FLAGS.has(arg)) {
        i += 1;
      }
      continue;
    }
    return sawTestFlag || NODE_TEST_FILE_RE.test(arg);
  }
  return sawTestFlag;
}

function isTsxVerification(args) {
  return isNodeOrTsxVerification("tsx", args);
}

function isEslintSafeArgs(toolArgs) {
  return !toolArgs.some((a) => a === "--fix" || a === "--fix-dry-run" || a.startsWith("--fix-type"));
}

function isCargoVerification(args) {
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--list") {
      return false;
    }
    if (arg.startsWith("+")) {
      continue;
    }
    if (arg.startsWith("-")) {
      if (CARGO_VALUE_FLAGS.has(arg)) {
        i += 1;
      }
      continue;
    }
    return CARGO_VERIFICATION_SUBCOMMANDS.has(arg);
  }
  return false;
}

function isDenoVerification(args) {
  const sub = args.find((arg) => !arg.startsWith("-")) ?? "";
  return DENO_VERIFICATION_SUBCOMMANDS.has(sub);
}

function isJsTestToolArgsSafe(tool, toolArgs) {
  const sepIdx = toolArgs.indexOf("--");
  const head = sepIdx === -1 ? toolArgs : toolArgs.slice(0, sepIdx);
  if (head.some((a) => JS_TEST_LIST_FLAGS.has(a))) {
    return false;
  }
  const firstPos = head.find((a) => !a.startsWith("-")) ?? "";
  if (tool === "vitest" && firstPos === "list") {
    return false;
  }
  if (tool === "playwright") {
    return firstPos === "test";
  }
  if (tool === "cypress") {
    return firstPos === "run";
  }
  return true;
}

function isMakeVerification(args) {
  const sepIdx = args.indexOf("--");
  const head = sepIdx === -1 ? args : args.slice(0, sepIdx);
  const blockedArgs = (sepIdx === -1 ? head : args);
  for (let i = 0; i < blockedArgs.length; i += 1) {
    const arg = blockedArgs[i];
    if (!arg.startsWith("-") && arg.includes("=")) {
      const assignMatch = /^([A-Za-z0-9_.-]+)\s*(::::=|:::=|::=|:=|!=|\?=|\+=|=)/.exec(arg);
      if (!assignMatch || assignMatch[2] === "!=" || MAKE_BLOCKED_VARS.has(assignMatch[1])) {
        return false;
      }
      const rhs = arg.slice(assignMatch[0].length);
      if (/[`$]/.test(rhs)) {
        return false;
      }
      continue;
    }
    if (arg === "--" || !arg.startsWith("-")) {
      continue;
    }
    if (arg.startsWith("--")) {
      const eqIdx = arg.indexOf("=");
      const flagName = eqIdx === -1 ? arg : arg.slice(0, eqIdx);
      if (MAKE_DRY_RUN_LONG_FLAGS.has(flagName) || !MAKE_SAFE_LONG_FLAGS.has(flagName)) {
        return false;
      }
      if (eqIdx !== -1 && !MAKE_LONG_VALUE_FLAGS.has(flagName)) {
        return false;
      }
      if (eqIdx !== -1 && MAKE_LONG_OPT_NUM_FLAGS.has(flagName)) {
        const val = arg.slice(eqIdx + 1);
        if (!/^(?:\d+(?:\.\d*)?|\.\d+)$/.test(val)) {
          return false;
        }
      }
      if (eqIdx === -1) {
        if (MAKE_LONG_REQUIRED_VALUE_FLAGS.has(flagName)) {
          if (i + 1 < blockedArgs.length) {
            i += 1;
          }
        } else if (MAKE_LONG_OPT_NUM_FLAGS.has(flagName)) {
          if (blockedArgs[i + 1] && /^(?:\d+(?:\.\d*)?|\.\d+)$/.test(blockedArgs[i + 1])) {
            i += 1;
          }
        }
      }
      continue;
    }
    const chars = arg.slice(1);
    if (chars.length === 0) {
      return false;
    }
    for (let j = 0; j < chars.length; j += 1) {
      const ch = chars[j];
      if (MAKE_NOOP_SHORT_FLAGS.has(ch)) {
        return false;
      }
      if (ch === "O") {
        break;
      }
      if (MAKE_VALUE_FLAGS.has(ch)) {
        const rest = chars.slice(j + 1);
        if (ch === "j" || ch === "l") {
          if (rest.length > 0) {
            const numMatch = /^(?:\d+(?:\.\d*)?|\.\d+)(.*)$/.exec(rest);
            if (!numMatch) {
              return false;
            }
            const trailing = numMatch[1];
            for (const t of trailing) {
              if (MAKE_NOOP_SHORT_FLAGS.has(t) || (!MAKE_SAFE_SHORT_FLAGS.has(t) && !MAKE_VALUE_FLAGS.has(t))) {
                return false;
              }
            }
            j += numMatch[0].length - trailing.length;
            continue;
          }
          if (blockedArgs[i + 1] && /^(?:\d+(?:\.\d*)?|\.\d+)$/.test(blockedArgs[i + 1])) {
            i += 1;
          }
          break;
        }
        if (rest.length === 0 && i + 1 < blockedArgs.length) {
          i += 1;
        }
        break;
      }
      if (!MAKE_SAFE_SHORT_FLAGS.has(ch)) {
        return false;
      }
    }
  }
  return true;
}

function isVerificationScriptName(name) {
  return Boolean(name) && !/[/\\.]/.test(name) && VERIFY_SCRIPT_NAME_RE.test(name) && !WRITE_SCRIPT_NAME_RE.test(name);
}

function isPackageExecVerification(args) {
  let toolIdx = 0;
  while (toolIdx < args.length) {
    const arg = args[toolIdx];
    if (arg === "--") {
      toolIdx += 1;
      break;
    }
    if (!arg.startsWith("-")) {
      break;
    }
    if (!PACKAGE_EXEC_SAFE_FLAGS.has(arg)) {
      return false;
    }
    toolIdx += 1;
  }
  const tool = args[toolIdx];
  if (!tool || /[/\\@:]/.test(tool)) {
    return false;
  }
  const toolArgs = args.slice(toolIdx + 1);
  const toolSepIdx = toolArgs.indexOf("--");
  const toolHead = toolSepIdx === -1 ? toolArgs : toolArgs.slice(0, toolSepIdx);
  if (toolHead.some((a) => isVersionProbe(tool, a))) {
    return false;
  }
  if (tool === "prettier") {
    const hasCheck = toolArgs.some((a) => a === "--check" || a === "-c" || a === "--list-different" || a === "-l");
    const hasWrite = toolArgs.some((a) => a === "--write" || a === "-w");
    return hasCheck && !hasWrite;
  }
  if (tool === "eslint") {
    return isEslintSafeArgs(toolArgs);
  }
  if (tool === "tsx") {
    return isTsxVerification(toolArgs);
  }
  if (tool === "biome") {
    return !toolArgs.some((a) => a === "--write" || a === "--apply" || a === "--apply-unsafe" || a === "--unsafe");
  }
  if ((tool === "vitest" || tool === "jest" || tool === "playwright" || tool === "cypress" || tool === "mocha" || tool === "ava" || tool === "tap") && !isJsTestToolArgsSafe(tool, toolArgs)) {
    return false;
  }
  return PACKAGE_EXEC_VERIFICATION_TOOLS.has(tool);
}

function isScriptRunnerVerification(baseBin, args) {
  const sepIdx = args.indexOf("--");
  const headArgs = sepIdx === -1 ? args : args.slice(0, sepIdx);
  const positional = [];
  for (let i = 0; i < headArgs.length; i += 1) {
    const tok = headArgs[i];
    if (SCRIPT_RUNNER_BLOCKED_FLAG_RE.test(tok)) {
      return false;
    }
    if (SCRIPT_RUNNER_SAFE_VALUE_FLAGS.has(tok)) {
      const val = headArgs[i + 1];
      if (!val || val.startsWith("-")) {
        return false;
      }
      i += 1;
      continue;
    }
    if (!tok.startsWith("-")) {
      positional.push(tok);
    }
  }
  const sub = positional[0] ?? "";
  const isNamedRun = (sub === "run" || sub === "run-script") && isVerificationScriptName(positional[1]);
  if (baseBin === "bun") {
    return sub === "test" || isNamedRun;
  }
  if (baseBin === "npm") {
    return NPM_TEST_SUBCOMMANDS.has(sub) || isNamedRun;
  }
  return PNPM_YARN_DIRECT_CHECK_SUBCOMMANDS.has(sub) || isNamedRun;
}

function isChainPrepCommand({ words, redirects }) {
  if (redirects > 0) {
    return false;
  }
  const idx = skipCommandPrefix(words);
  if (idx === -1 || idx >= words.length) {
    return false;
  }
  const baseBin = posix.basename(toPosix(words[idx]));
  if (baseBin !== "npm") {
    return false;
  }
  const args = words.slice(idx + 1);
  if (args.some((a) => SCRIPT_RUNNER_BLOCKED_FLAG_RE.test(a) || /^--save|^-(?:D|S|g)$|^--global$/.test(a))) {
    return false;
  }
  const positional = args.filter((tok) => !tok.startsWith("-"));
  return positional.length === 1 && (positional[0] === "ci" || positional[0] === "install");
}

export function extractChainPrepSignature(segment) {
  if (typeof segment !== "string" || segment.trim().length === 0) {
    return null;
  }
  const cmds = lexVerificationChain(segment);
  if (!cmds || cmds.length !== 1) {
    return null;
  }
  const parsed = cmds[0];
  if (!isChainPrepCommand(parsed)) {
    return null;
  }
  const prefix = parseCommandPrefix(parsed.words);
  const idx = prefix.binIdx;
  if (idx === -1 || idx >= parsed.words.length) {
    return null;
  }
  const dirParts = prefix.chdirs.map((dir) => posix.normalize(toPosix(dir)));
  if (prefix.chdirOpaque) {
    dirParts.push("$opaque");
  }
  const prefixTag = dirParts.length > 0 ? `@wrapperDir(${dirParts.join("->")}) ` : "";
  return `${prefixTag}${["npm", ...parsed.words.slice(idx + 1)].join(" ")}`;
}

export function commandMatchesExpectedTokens(commandLine, expectedTokens) {
  if (typeof commandLine !== "string" || !Array.isArray(expectedTokens) || expectedTokens.length === 0) {
    return false;
  }
  const cmds = lexVerificationChain(commandLine);
  if (!cmds) {
    return false;
  }
  for (const cmd of cmds) {
    const idx = skipCommandPrefix(cmd.words);
    if (idx === -1 || idx >= cmd.words.length) {
      continue;
    }
    const execWords = cmd.words.slice(idx);
    const baseBin = posix.basename(toPosix(execWords[0]));
    const normWords = [baseBin, ...execWords.slice(1)];
    if (normWords.length >= expectedTokens.length && expectedTokens.every((tok, k) => normWords[k] === tok)) {
      return true;
    }
    if (SHELL_INTERPRETERS.has(baseBin)) {
      const body = inlineInterpreterBody(baseBin, execWords.slice(1));
      if (body && commandMatchesExpectedTokens(body, expectedTokens)) {
        return true;
      }
    }
  }
  return false;
}

// A known test runner, optionally behind safe assignments and wrappers. A shell `-c` body must itself match the
// grammar with nothing after it on the outer command line.
function isRunnerCommand({ words, redirects }) {
  const idx = skipCommandPrefix(words);
  if (idx === -1 || idx >= words.length || words.slice(0, idx).some((tok) => tok === "!" || tok === "(")) {
    return false;
  }
  const rawBin = words[idx];
  const baseBin = posix.basename(toPosix(rawBin));
  const args = words.slice(idx + 1);
  if (!VERIFICATION_BINARIES.has(baseBin) && !rawBin.startsWith("./") && !rawBin.startsWith("../")) {
    return false;
  }
  if (args.length === 1 && isVersionProbe(baseBin, args[0])) {
    return false;
  }
  if (baseBin !== "node" && baseBin !== "tsx" && baseBin !== "python" && baseBin !== "python3" && !SHELL_INTERPRETERS.has(baseBin) && hasLeadingVersionProbe(baseBin, args)) {
    return false;
  }
  // `node <script>` runs any program, so node counts only for its test runner or a test file.
  if (baseBin === "node" && !isNodeOrTsxVerification("node", args)) {
    return false;
  }
  if (baseBin === "tsx" && !isTsxVerification(args)) {
    return false;
  }
  if (baseBin === "eslint" && !isEslintSafeArgs(args)) {
    return false;
  }
  if ((baseBin === "python" || baseBin === "python3") && !pythonRunsTests(args)) {
    return false;
  }
  if ((baseBin === "pytest" || baseBin === "py.test") && hasPytestNonExecFlag(args)) {
    return false;
  }
  if (baseBin === "cargo" && !isCargoVerification(args)) {
    return false;
  }
  if (baseBin === "deno" && !isDenoVerification(args)) {
    return false;
  }
  if ((baseBin === "vitest" || baseBin === "jest" || baseBin === "playwright" || baseBin === "cypress") && !isJsTestToolArgsSafe(baseBin, args)) {
    return false;
  }
  if (baseBin === "make" && !isMakeVerification(args)) {
    return false;
  }
  if (PACKAGE_EXEC_RUNNERS.has(baseBin) && !isPackageExecVerification(args)) {
    return false;
  }
  if (BARE_SCRIPT_RUNNERS.has(baseBin) && !isScriptRunnerVerification(baseBin, args)) {
    return false;
  }
  if (baseBin === "go" && (!GO_VERIFICATION_SUBCOMMANDS.has(args[0] ?? "") || args.slice(1).some((a) => GO_EXEC_FLAG_RE.test(a)))) {
    return false;
  }
  // A local script or one a shell reads from a file runs anything, so only a test or check script counts.
  if (!VERIFICATION_BINARIES.has(baseBin) && !CHECK_SCRIPT_RE.test(rawBin)) {
    return false;
  }
  const body = inlineInterpreterBody(baseBin, args);
  if (body === null && SHELL_INTERPRETERS.has(baseBin)) {
    return CHECK_SCRIPT_RE.test(shellScriptArg(args));
  }
  return body === null || (body !== "" && redirects === 0 && matchesVerificationGrammar(body));
}

export function commandHasPrepSideEffect(commandLine) {
  if (typeof commandLine !== "string" || commandLine.trim().length === 0) {
    return false;
  }
  const cmds = lexVerificationChain(commandLine);
  if (!cmds) {
    return false;
  }
  for (let i = 0; i < cmds.length; i += 1) {
    const cmd = cmds[i];
    if (cmd.op !== "|" && cmd.op !== "" && isChainPrepCommand(cmd)) {
      return true;
    }
    const idx = skipCommandPrefix(cmd.words);
    if (idx !== -1 && idx < cmd.words.length) {
      const baseBin = posix.basename(toPosix(cmd.words[idx]));
      const body = inlineInterpreterBody(baseBin, cmd.words.slice(idx + 1));
      if (body && commandHasPrepSideEffect(body)) {
        return true;
      }
    }
    if (cmd.op === "|" || cmd.op === "") {
      return false;
    }
  }
  return false;
}

// [prefix &&]… [VAR=value]… RUNNER ARGS [REDIRECT]…, plus one `| tail/head/grep` when pipefail is on.
function matchesVerificationGrammar(commandLine) {
  const cmds = lexVerificationChain(commandLine);
  if (!cmds) {
    return false;
  }
  let pipefail = false;
  for (let i = 0; i < cmds.length; i += 1) {
    const cmd = cmds[i];
    if (cmd.op === "|") {
      const filter = cmds[i + 1];
      return pipefail && i + 2 === cmds.length && isRunnerCommand(cmd) && PIPE_FILTERS.has(filter.words[0]) && filter.redirects === 0;
    }
    if (cmd.op === "") {
      return isRunnerCommand(cmd);
    }
    pipefail = applyPipefailState(cmd, pipefail);
    if (!isPrefixCommand(cmd) && !isRunnerCommand(cmd) && !isChainPrepCommand(cmd)) {
      return false;
    }
  }
  return false;
}

// `$(…)` and backticks run even inside double quotes; `<(…)`/`>(…)` only unquoted. Single quotes stay literal.
function hasCommandSubstitution(commandLine) {
  let quote = null;
  for (let i = 0; i < commandLine.length; i += 1) {
    const ch = commandLine[i];
    if (quote === "'") {
      quote = ch === "'" ? null : quote;
      continue;
    }
    if (ch === "\\") {
      i += 1;
      continue;
    }
    if (ch === "`" || (ch === "$" && commandLine[i + 1] === "(")) {
      return true;
    }
    if (ch === '"') {
      quote = quote ? null : '"';
    } else if (!quote && ch === "'") {
      quote = "'";
    } else if (!quote && (ch === "<" || ch === ">") && commandLine[i + 1] === "(") {
      return true;
    }
  }
  return false;
}

// verification only when the whole line matches the runner grammar; read_only when every segment is read-only;
// anything else is other.
export function classifyCommand(commandLine) {
  if (typeof commandLine !== "string" || commandLine.trim().length === 0) {
    return "read_only";
  }
  if (hasCommandSubstitution(commandLine)) {
    return "other";
  }
  if (matchesVerificationGrammar(commandLine)) {
    return "verification";
  }
  return splitShellChain(commandLine).every(({ text }) => classifySingleSegment(text) !== "other") ? "read_only" : "other";
}

export function inferExecutionFailure(result) {
  if (!result || typeof result !== "object") {
    return false;
  }
  const normStatus = typeof result.status === "string" ? result.status.trim().toUpperCase() : "";
  if (normStatus === "ERROR" || normStatus === "FAILED") {
    return true;
  }
  if (typeof result.error === "string" && result.error.trim().length > 0) {
    return true;
  }
  const head = typeof result.head === "string" ? result.head : "";
  const tail = typeof result.tail === "string" ? result.tail : typeof result.content === "string" ? result.content : "";
  if (head.length === 0 && tail.length === 0) {
    return false;
  }
  if (
    RUN_CHECKS_FAIL_HEADER_RE.test(head) ||
    RUN_CHECKS_FAIL_HEADER_RE.test(tail) ||
    RUN_CHECKS_FAIL_BLOCK_RE.test(head) ||
    RUN_CHECKS_FAIL_BLOCK_RE.test(tail)
  ) {
    return true;
  }
  if (RUN_CHECKS_ALL_PASSED_HEADER_RE.test(head) || RUN_CHECKS_ALL_PASSED_HEADER_RE.test(tail)) {
    return false;
  }
  if (tail.length === 0) {
    return false;
  }
  if (EXIT_CODE_FAIL_RE.test(tail)) {
    return true;
  }
  if (TAP_FAIL_NONZERO_RE.test(tail)) {
    return true;
  }
  if (TAP_FAIL_ZERO_RE.test(tail)) {
    return false;
  }
  for (const line of tail.split(/\r?\n/)) {
    if (PASSING_TEST_LINE_RE.test(line)) {
      continue;
    }
    if (FAILURE_LINE_PATTERNS.some((pattern) => pattern.test(line))) {
      return true;
    }
  }
  return false;
}

export function unwrapSerialized(value, depth = 0) {
  if (typeof value !== "string" || depth >= MAX_UNWRAP_DEPTH) {
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

export function asObject(value) {
  const unwrapped = unwrapSerialized(value);
  return unwrapped && typeof unwrapped === "object" && !Array.isArray(unwrapped) ? unwrapped : null;
}

export function asArray(value) {
  const unwrapped = unwrapSerialized(value);
  return Array.isArray(unwrapped) ? unwrapped : null;
}

export function pickString(obj, keys) {
  for (const key of keys) {
    if (typeof obj[key] === "string" && obj[key].trim().length > 0) {
      return obj[key].trim();
    }
  }
  return "";
}

export function extractToolPaths(call, cwd = "", gitRoot = "") {
  if (!call || typeof call !== "object") {
    return { readPaths: [], writePaths: [] };
  }
  const name = typeof call.name === "string" ? call.name : "";
  const args = asObject(call.args);
  if (!args) {
    return { readPaths: [], writePaths: [] };
  }

  const readPaths = [];
  const writePaths = [];
  const pushNorm = (target, raw, baseCwd = cwd) => {
    const normalized = normalizeWorkspacePath(raw, baseCwd, gitRoot);
    if (normalized.length > 0) {
      target.push(normalized);
    }
  };

  if (READ_TOOL_NAMES.has(name)) {
    const raw = pickRawPathString(args, ["Path", "path", "AbsolutePath", "absolute_path", "file_path"]);
    pushNorm(readPaths, raw);
  } else if (name === "mcp_agy-fast_fast_apply_edits" || name === "mcp_agy-fast_apply_edits") {
    const baseCwd = pickRawPathString(args, ["cwd"]) || cwd;
    for (const rawEdit of asArray(args.edits) ?? []) {
      const edit = asObject(rawEdit);
      if (!edit) {
        continue;
      }
      const raw = pickRawPathString(edit, ["path", "Path"]);
      pushNorm(writePaths, raw, baseCwd);
      if (edit.create !== undefined) {
        pushNorm(readPaths, raw, baseCwd);
      }
    }
  } else if (WRITE_TOOL_NAMES.has(name)) {
    const raw = pickRawPathString(args, ["Path", "path", "TargetFile", "target_file", "AbsolutePath", "absolute_path"]);
    pushNorm(writePaths, raw);
    if (CREATE_AS_READ_TOOL_NAMES.has(name)) {
      pushNorm(readPaths, raw);
    }
  }

  return { readPaths, writePaths };
}

function extractCommandLine(call) {
  const args = asObject(call?.args);
  if (!args) {
    return "";
  }
  return pickString(args, ["CommandLine", "commandLine", "command"]);
}

function pickRawPathString(obj, keys) {
  for (const key of keys) {
    const value = obj?.[key];
    if (typeof value === "string" && value.trim().length > 0) {
      return value;
    }
  }
  return "";
}

function extractCommandCwd(call, fallbackCwd = "") {
  const args = asObject(call?.args);
  if (!args) {
    return fallbackCwd;
  }
  return pickRawPathString(args, ["Cwd", "cwd"]) || fallbackCwd;
}

export function extractMcpCheckCommands(call) {
  const args = asObject(call?.args);
  if (!args) {
    return { commands: [], labels: [] };
  }
  const commands = [];
  const labels = [];
  const rawList = asArray(args.commands) ?? asArray(args.checks);
  if (rawList) {
    for (const rawItem of rawList) {
      if (typeof rawItem === "string") {
        const trimmed = rawItem.trim();
        if (trimmed.length > 0) {
          commands.push(trimmed);
        }
        continue;
      }
      const item = asObject(rawItem);
      if (!item) {
        continue;
      }
      const cmd = pickString(item, ["command", "CommandLine", "commandLine"]);
      if (cmd.length > 0) {
        commands.push(cmd);
      }
      const label = pickString(item, ["name", "label"]);
      if (label.length > 0) {
        labels.push(label);
      }
    }
  } else {
    const single = pickString(args, ["command", "CommandLine", "commandLine"]);
    if (single.length > 0) {
      commands.push(single);
    }
  }
  return { commands, labels };
}

// With no commands the tool runs the project's configured checks; otherwise each command is judged like run_command.
function classifyMcpCheckCommands(commands) {
  if (commands.length === 0) {
    return "verification";
  }
  const kinds = commands.map(classifyCommand);
  return kinds.includes("other") ? "other" : kinds.includes("verification") ? "verification" : "read_only";
}

function extractHead(content) {
  if (typeof content !== "string" || content.length === 0) {
    return "";
  }
  if (content.length <= RESULT_HEAD_MAX_CHARS) {
    return content;
  }
  let end = RESULT_HEAD_MAX_CHARS;
  const code = content.charCodeAt(end - 1);
  if (code >= 0xd800 && code <= 0xdbff) {
    end -= 1;
  }
  return content.slice(0, end);
}

function extractTail(content, maxChars = RESULT_TAIL_MAX_CHARS) {
  if (typeof content !== "string") {
    return "";
  }
  if (content.length <= maxChars) {
    return content;
  }
  let start = content.length - maxChars;
  const code = content.charCodeAt(start);
  if (code >= 0xdc00 && code <= 0xdfff && start + 1 < content.length) {
    start += 1;
  }
  return content.slice(start);
}

export function extractSubagentTypeNames(call) {
  const args = asObject(call?.args);
  if (!args) {
    return [];
  }
  const names = [];
  const topType = pickString(args, ["TypeName", "typeName", "type_name", "subagent_type"]);
  if (topType.length > 0) {
    names.push(topType);
  }
  const subagents = asArray(args.Subagents ?? args.subagents);
  if (subagents) {
    for (const rawItem of subagents) {
      const item = asObject(rawItem);
      if (!item) {
        continue;
      }
      const itemType = pickString(item, ["TypeName", "typeName", "type_name", "subagent_type"]);
      if (itemType.length > 0) {
        names.push(itemType);
      }
    }
  }
  return names;
}

function isAuditorTypeName(typeName) {
  return typeName === AUDITOR_AGENT_NAME || typeName === `hstack:${AUDITOR_AGENT_NAME}`;
}

function isChallengerTypeName(typeName) {
  return typeName === CHALLENGER_AGENT_NAME || typeName === `hstack:${CHALLENGER_AGENT_NAME}`;
}

function isWorkerTypeName(typeName) {
  return typeName === WORKER_AGENT_NAME || typeName === `hstack:${WORKER_AGENT_NAME}`;
}

function extractSubagentPrompts(call) {
  const args = asObject(call?.args);
  if (!args) {
    return [];
  }
  const prompts = [];
  const topPrompt = typeof args.Prompt === "string" ? args.Prompt : typeof args.prompt === "string" ? args.prompt : "";
  const topType = pickString(args, ["TypeName", "typeName", "type_name", "subagent_type"]);
  if (topType.length > 0) {
    prompts.push(topPrompt);
  }
  const subagents = asArray(args.Subagents ?? args.subagents);
  if (subagents) {
    for (const rawItem of subagents) {
      const item = asObject(rawItem);
      if (!item) {
        continue;
      }
      const itemType = pickString(item, ["TypeName", "typeName", "type_name", "subagent_type"]);
      if (itemType.length > 0) {
        prompts.push(typeof item.Prompt === "string" ? item.Prompt : typeof item.prompt === "string" ? item.prompt : "");
      }
    }
  }
  return prompts;
}

function extractLastMeaningfulLine(fullContent) {
  const tail = extractTail(fullContent, AUDIT_TAIL_MAX_CHARS);
  const lines = tail
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith(PRE_TOOL_NOTICE_PREFIX) && !SYSTEM_WRAPPER_LINE_RE.test(line));
  if (lines.length === 0) {
    return "";
  }
  return lines[lines.length - 1].replace(/^[*_\s]+|[*_\s]+$/g, "");
}

export function parseAuditVerdictFromText(fullContent, { status = "", error = "" } = {}) {
  const normStatus = typeof status === "string" ? status.trim().toUpperCase() : "";
  const normError = typeof error === "string" ? error.trim() : "";
  if (normStatus === "ERROR" || normStatus === "FAILED" || normError.length > 0) {
    return "ERROR";
  }
  if (typeof fullContent !== "string" || fullContent.trim().length === 0) {
    return "MISSING_VERDICT";
  }
  const lastLine = extractLastMeaningfulLine(fullContent);
  if (lastLine === AUDIT_PASS_TAG) {
    return "PASS";
  }
  if (lastLine === AUDIT_REJECT_TAG) {
    return "REJECT";
  }
  return "MISSING_VERDICT";
}

export function parsePreflightVerdictFromText(fullContent, { status = "", error = "" } = {}) {
  const normStatus = typeof status === "string" ? status.trim().toUpperCase() : "";
  const normError = typeof error === "string" ? error.trim() : "";
  if (normStatus === "ERROR" || normStatus === "FAILED" || normError.length > 0) {
    return "ERROR";
  }
  if (typeof fullContent !== "string" || fullContent.trim().length === 0) {
    return "MISSING_VERDICT";
  }
  const lastLine = extractLastMeaningfulLine(fullContent);
  if (lastLine === PREFLIGHT_PROCEED_TAG) {
    return "PROCEED";
  }
  if (lastLine === PREFLIGHT_CONDITIONAL_TAG) {
    return "CONDITIONAL";
  }
  if (lastLine === PREFLIGHT_RETHINK_TAG) {
    return "RETHINK";
  }
  return "MISSING_VERDICT";
}

function parseUserVoteResult(rawContent, { status = "", error = "", isDenial = false } = {}) {
  const normStatus = typeof status === "string" ? status.trim().toUpperCase() : "";
  const normError = typeof error === "string" ? error.trim() : "";
  if (isDenial || normStatus === "ERROR" || normStatus === "FAILED" || normStatus === "CANCELED" || normError.length > 0) {
    return { answered: false, errored: true };
  }
  if (typeof rawContent !== "string" || rawContent.trim().length === 0) {
    return { answered: false, errored: false };
  }
  const meaningfulLines = rawContent
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(
      (line) =>
        line.length > 0 &&
        !line.startsWith(PRE_TOOL_NOTICE_PREFIX) &&
        !VOTE_TIMESTAMP_LINE_RE.test(line) &&
        !SYSTEM_WRAPPER_LINE_RE.test(line),
    );
  if (meaningfulLines.length === 0) {
    return { answered: false, errored: false };
  }
  if (VOTE_ERROR_CONTENT_RE.test(meaningfulLines[0]) || meaningfulLines.some((line) => VOTE_ERROR_CONTENT_RE.test(line))) {
    return { answered: false, errored: true };
  }
  for (const line of meaningfulLines) {
    const answerMatch = line.match(VOTE_ANSWER_LINE_RE);
    if (answerMatch && answerMatch[1].trim().length > 0) {
      return { answered: true, errored: false };
    }
  }
  return { answered: false, errored: false };
}

function extractSubagentConversationIds(text) {
  if (typeof text !== "string" || text.length === 0) {
    return [];
  }
  const ids = [];
  for (const match of text.matchAll(SUBAGENT_CONVERSATION_ID_GLOBAL_RE)) {
    if (match[1]) {
      ids.push(match[1]);
    }
  }
  return ids;
}

function isAsyncSubagentLaunchAck(text) {
  if (typeof text !== "string" || text.length === 0 || text.length > MAX_ASYNC_LAUNCH_ACK_CHARS) {
    return false;
  }
  const trimmed = text.trim();
  const isStructuredOrHintAck =
    trimmed.startsWith("{") || trimmed.startsWith("[") || ASYNC_LAUNCH_ACK_HINT_RE.test(trimmed);
  return (
    SUBAGENT_CONVERSATION_ID_RE.test(trimmed) &&
    isStructuredOrHintAck &&
    !trimmed.includes(AUDIT_PASS_TAG) &&
    !trimmed.includes(AUDIT_REJECT_TAG) &&
    !trimmed.includes(PREFLIGHT_PROCEED_TAG) &&
    !trimmed.includes(PREFLIGHT_CONDITIONAL_TAG) &&
    !trimmed.includes(PREFLIGHT_RETHINK_TAG)
  );
}

function applyAsyncSubagentMessage(trackedMap, senderId, msgContent, stepIndex, { parseVerdict, finalVerdicts, holdCompletionUntilFinal }) {
  const tracked = trackedMap.get(senderId);
  if (!tracked) {
    return;
  }
  tracked.tail = extractTail(msgContent, AUDIT_TAIL_MAX_CHARS);
  const parsedVerdict = parseVerdict(msgContent);
  tracked.verdict = parsedVerdict;
  const isFinal = finalVerdicts.has(parsedVerdict);
  if (isFinal) {
    tracked.completedStepIndex = Math.max(
      tracked.completedStepIndex >= 0 ? tracked.completedStepIndex : tracked.launchedStepIndex,
      stepIndex,
    );
    tracked.stepIndex = tracked.completedStepIndex;
    trackedMap.delete(senderId);
  } else if (!holdCompletionUntilFinal) {
    tracked.completedStepIndex = Math.max(
      tracked.completedStepIndex >= 0 ? tracked.completedStepIndex : tracked.launchedStepIndex,
      stepIndex,
    );
    tracked.stepIndex = tracked.completedStepIndex;
  } else {
    tracked.receivedMessage = true;
  }
}

function applyManagedSubagentGeneric(entries, { rawText, convIds, status, error, stepIndex, isDenial, isLaunchAck, parseVerdict, asyncMap, setCompletedOnSync }) {
  if (entries.length === 0) {
    return;
  }
  const directVerdict = parseVerdict(rawText, { status, error });
  const isMixedBatch = entries.some((e) => e.totalSlots > 1);
  for (const entry of entries) {
    entry.tail = extractTail(rawText, AUDIT_TAIL_MAX_CHARS);
    const matchedId = entry.totalSlots > 1 ? (convIds[entry.slotIndex] ?? "") : (convIds[0] ?? "");
    if (matchedId) {
      entry.conversationId = matchedId;
    }
    if (isDenial) {
      entry.verdict = "ERROR";
      if (setCompletedOnSync) {
        entry.completedStepIndex = stepIndex;
        entry.stepIndex = stepIndex;
      }
    } else if (matchedId && isLaunchAck) {
      entry.verdict = "MISSING_VERDICT";
      if (setCompletedOnSync) {
        entry.completedStepIndex = -1;
      }
      asyncMap.set(matchedId, entry);
    } else if (isMixedBatch && !matchedId) {
      entry.verdict = directVerdict === "ERROR" ? "ERROR" : "MISSING_VERDICT";
      if (setCompletedOnSync) {
        entry.completedStepIndex = stepIndex;
        entry.stepIndex = stepIndex;
      }
    } else {
      entry.verdict = directVerdict;
      if (setCompletedOnSync) {
        entry.completedStepIndex = stepIndex;
        entry.stepIndex = stepIndex;
      }
    }
  }
}

function normalizeRoleLines(content) {
  if (typeof content !== "string" || content.length === 0) {
    return [];
  }
  return content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !SYSTEM_WRAPPER_LINE_RE.test(line));
}

function pickHigherSessionRole(current, candidate) {
  const currentRank = SESSION_ROLE_PRIORITY[current] ?? 0;
  const candidateRank = SESSION_ROLE_PRIORITY[candidate] ?? 0;
  return candidateRank > currentRank ? candidate : current;
}

export function classifySessionRoleFromText(content) {
  const lines = normalizeRoleLines(content);
  if (lines.length === 0) {
    return "main";
  }
  const tailStart = Math.max(0, lines.length - 6);
  let detected = "main";
  for (let i = tailStart; i < lines.length; i += 1) {
    let candidate = null;
    if (AUDITOR_MARKER_LINE_RE.test(lines[i])) {
      candidate = "auditor";
    } else if (CHALLENGER_MARKER_LINE_RE.test(lines[i])) {
      candidate = "challenger";
    } else if (WORKER_MARKER_LINE_RE.test(lines[i])) {
      candidate = "worker";
    }
    if (!candidate) {
      continue;
    }
    // Only the hook-injected trailing block (marker, then 작업 경로:, then other injected lines) carries a role.
    const remaining = lines.slice(i + 1);
    const validBlock =
      remaining.length > 0 && remaining[0].startsWith("작업 경로:") && remaining.every((line) => INJECTED_CONTEXT_LINE_RE.test(line));
    if (!validBlock) {
      continue;
    }
    detected = pickHigherSessionRole(detected, candidate);
    if (detected === "auditor") {
      return "auditor";
    }
  }
  return detected;
}

export function detectSessionRoleFromUserInput(content) {
  return classifySessionRoleFromText(content);
}

export function detectSessionRoleFromHeaderStep(step) {
  if (!step || typeof step !== "object") {
    return "main";
  }
  const content = typeof step.content === "string" ? step.content : "";
  if (content.length === 0) {
    return "main";
  }
  if (step.type === "USER_INPUT") {
    return classifySessionRoleFromText(content);
  }
  if (step.type === "SYSTEM_MESSAGE") {
    const rawSource = typeof step.source === "string" ? step.source.trim() : "";
    if (rawSource.length > 0 && !ALLOWED_SUBAGENT_SYSTEM_SOURCES.has(rawSource)) {
      return "main";
    }
    return classifySessionRoleFromText(content);
  }
  return "main";
}

export function detectSessionRoleFromHeaderSteps(steps) {
  if (!Array.isArray(steps) || steps.length === 0) {
    return "main";
  }
  let seenFirstUserInput = false;
  let role = "main";
  for (const step of steps) {
    if (!step || typeof step !== "object") {
      continue;
    }
    if (step.type === "PLANNER_RESPONSE") {
      break;
    }
    if (step.type === "USER_INPUT") {
      if (seenFirstUserInput) {
        continue;
      }
      seenFirstUserInput = true;
    } else if (step.type !== "SYSTEM_MESSAGE") {
      continue;
    }
    const candidate = detectSessionRoleFromHeaderStep(step);
    role = pickHigherSessionRole(role, candidate);
    if (role === "auditor") {
      return "auditor";
    }
  }
  return role;
}

export function readLatestTranscriptTokens(transcriptPath) {
  const empty = { inputTokens: null, cacheReadTokens: null, outputTokens: null };
  if (typeof transcriptPath !== "string" || transcriptPath.trim().length === 0) {
    return empty;
  }
  const TAIL_BYTES = 64 * 1024;
  for (const candidatePath of resolveTranscriptCandidates(transcriptPath.trim())) {
    let fd = null;
    try {
      fd = openSync(candidatePath, "r");
      const size = fstatSync(fd).size;
      if (size <= 0) {
        continue;
      }
      const readLen = Math.min(size, TAIL_BYTES);
      const buf = Buffer.allocUnsafe(readLen);
      const bytesRead = readSync(fd, buf, 0, readLen, size - readLen);
      const text = buf.subarray(0, bytesRead).toString("utf8");
      const lines = text.split("\n");
      for (let i = lines.length - 1; i >= 0; i -= 1) {
        const line = lines[i].trim();
        if (!line.includes("PLANNER_RESPONSE")) {
          continue;
        }
        const parsed = parseRawRecord(line);
        if (parsed && parsed.type === "PLANNER_RESPONSE") {
          const tokens = extractLatestTokens(parsed);
          if (tokens) {
            return tokens;
          }
        }
      }
      return empty;
    } catch {
      continue;
    } finally {
      if (fd !== null) {
        try {
          closeSync(fd);
        } catch {
        }
      }
    }
  }
  return empty;
}

function parseGateVerdictFromText(fullContent) {
  if (typeof fullContent !== "string" || fullContent.length === 0) {
    return "UNKNOWN";
  }
  for (const rawLine of fullContent.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith(PRE_TOOL_NOTICE_PREFIX)) {
      continue;
    }
    for (const [header, verdict] of VERDICT_HEADER_ENTRIES) {
      if (line.startsWith(header)) {
        return verdict;
      }
    }
  }
  return "UNKNOWN";
}

function extractTokenNumber(obj, keys) {
  for (const key of keys) {
    const value = obj?.[key];
    if (typeof value === "number" && Number.isFinite(value)) {
      return value;
    }
  }
  return null;
}

function extractLatestTokens(parsed) {
  const usage = parsed.usage ?? parsed.tokenUsage ?? parsed.token_usage ?? parsed;
  const inputTokens = extractTokenNumber(usage, ["inputTokens", "input_tokens", "promptTokens", "prompt_tokens"]);
  const cacheReadTokens = extractTokenNumber(usage, [
    "cacheReadTokens",
    "cache_read_tokens",
    "cachedInputTokens",
    "cached_input_tokens",
  ]);
  const outputTokens = extractTokenNumber(usage, [
    "outputTokens",
    "output_tokens",
    "completionTokens",
    "completion_tokens",
  ]);
  if (inputTokens === null && cacheReadTokens === null && outputTokens === null) {
    return null;
  }
  return { inputTokens, cacheReadTokens, outputTokens };
}

const WRITE_PROBE_MAX_BYTES = 1024 * 1024;
// shortcut: drift trackers replay only the last 500 steps of a session, so a cap streak older than that restarts; widen if long sessions nag past the cap.
const DRIFT_STEP_WINDOW = 500;
const PROSE_SKIP_MIN_BYTES = 1024 * 1024;
const MANUAL_PREFLIGHT_CMD_RE = /\/(?:hstack:)?hstack-preflight\b/i;

function createEmptyLedger(transcriptAvailable = false) {
  return {
    transcriptAvailable,
    sessionRole: "main",
    sessionReadFiles: new Set(),
    turnStartStepIndex: 0,
    turnWrittenFiles: new Set(),
    turnCodeWrittenFiles: new Set(),
    turnToolWriteSteps: new Map(),
    lastWriteStepIndex: -1,
    lastCodeWriteStepIndex: -1,
    turnExecutions: [],
    turnFailedExecutionCount: 0,
    turnVerifyFailures: 0,
    turnConsecutiveVerifyFailures: 0,
    fileEditCounts: new Map(),
    maxSingleFileEdits: 0,
    mostEditedFile: "",
    turnGateAttempts: [],
    turnSubagentAudits: [],
    pendingAsyncAuditorCount: 0,
    pendingAsyncAuditsAfterLastWrite: 0,
    pendingAsyncAuditLaunchSteps: [],
    turnPreflightChallenges: [],
    pendingAsyncChallenges: 0,
    pendingAsyncChallengesAfterLastWrite: 0,
    pendingAsyncChallengeLaunchSteps: [],
    turnUserVotes: [],
    turnHasManualPreflightCommand: false,
    turnAutoChallengeTriggered: false,
    turnAutoHandoffTriggered: false,
    turnWorkerDispatched: false,
    turnWorkerCompleted: false,
    turnWorkerConversationIds: [],
    latestTokens: { inputTokens: null, cacheReadTokens: null, outputTokens: null },
    gateBlockedThisTurn: false,
    commitNumstatUnavailable: false,
    turnCommittedFiles: new Set(),
  };
}

// With `turnStart`, scans from that turn's USER_INPUT (a byte offset) with the role the header scan settled;
// returns undefined when a record there has no numeric step index, since its fallback index needs the full count.
function scanTranscriptToLedger(filePath, cwd, gitRoot, onUserInput = null, turnStart = null) {
  const ledger = createEmptyLedger(true);
  let pendingCalls = [];
  let seenGenericInCurrentPlanner = false;
  let seenFirstUserInput = turnStart !== null;
  let seenFirstPlannerResponse = turnStart !== null;
  let indexed = true;
  if (turnStart !== null) {
    ledger.sessionRole = turnStart.sessionRole;
  }
  const asyncAuditsByConversationId = new Map();
  const asyncChallengesByConversationId = new Map();
  const asyncWorkersByConversationId = new Map();

  const applyHeaderSessionRole = (record) => {
    if (seenFirstPlannerResponse || ledger.sessionRole === "auditor") {
      return;
    }
    const candidate = detectSessionRoleFromHeaderStep(record);
    ledger.sessionRole = pickHigherSessionRole(ledger.sessionRole, candidate);
  };

  const commitWriteToolResult = (pendingWrite) => {
    for (const p of pendingWrite.readPaths) {
      ledger.sessionReadFiles.add(p);
    }
    for (const p of pendingWrite.writePaths) {
      ledger.turnWrittenFiles.add(p);
      ledger.turnToolWriteSteps.set(p, pendingWrite.stepIndex);
      const nextCount = (ledger.fileEditCounts.get(p) ?? 0) + 1;
      ledger.fileEditCounts.set(p, nextCount);
      if (nextCount > ledger.maxSingleFileEdits) {
        ledger.maxSingleFileEdits = nextCount;
        ledger.mostEditedFile = p;
      }
      ledger.lastWriteStepIndex = Math.max(ledger.lastWriteStepIndex, pendingWrite.stepIndex);
      if (!isExemptDocOrAssetPath(p)) {
        ledger.turnCodeWrittenFiles.add(p);
        ledger.lastCodeWriteStepIndex = Math.max(ledger.lastCodeWriteStepIndex, pendingWrite.stepIndex);
      }
    }
  };

  const flushSyntheticWritesWithoutGenerics = () => {
    if (pendingCalls.length === 0 || seenGenericInCurrentPlanner) {
      pendingCalls = [];
      return;
    }
    for (const pending of pendingCalls) {
      if (pending.kind === "write") {
        commitWriteToolResult(pending);
      }
    }
    pendingCalls = [];
  };

  const resetTurn = (stepIndex, userContent = "") => {
    ledger.turnStartStepIndex = stepIndex;
    ledger.turnWrittenFiles = new Set();
    ledger.turnCodeWrittenFiles = new Set();
    ledger.turnToolWriteSteps = new Map();
    ledger.lastWriteStepIndex = -1;
    ledger.lastCodeWriteStepIndex = -1;
    ledger.turnExecutions = [];
    ledger.turnFailedExecutionCount = 0;
    ledger.turnVerifyFailures = 0;
    ledger.turnConsecutiveVerifyFailures = 0;
    ledger.fileEditCounts = new Map();
    ledger.maxSingleFileEdits = 0;
    ledger.mostEditedFile = "";
    ledger.turnGateAttempts = [];
    ledger.turnSubagentAudits = [];
    ledger.pendingAsyncAuditorCount = 0;
    ledger.pendingAsyncAuditsAfterLastWrite = 0;
    ledger.turnPreflightChallenges = [];
    ledger.pendingAsyncChallenges = 0;
    ledger.pendingAsyncChallengesAfterLastWrite = 0;
    ledger.turnUserVotes = [];
    ledger.turnHasManualPreflightCommand = MANUAL_PREFLIGHT_CMD_RE.test(userContent);
    ledger.turnAutoChallengeTriggered = false;
    ledger.turnAutoHandoffTriggered = false;
    ledger.turnWorkerDispatched = false;
    ledger.turnWorkerCompleted = false;
    ledger.turnWorkerConversationIds = [];
    ledger.gateBlockedThisTurn = false;
    ledger.commitNumstatUnavailable = false;
    ledger.turnCommittedFiles = new Set();
    pendingCalls = [];
    seenGenericInCurrentPlanner = false;
    asyncAuditsByConversationId.clear();
    asyncChallengesByConversationId.clear();
    asyncWorkersByConversationId.clear();
  };

  const peekNeedsGeneric = () => {
    const nextPending = pendingCalls[0];
    if (!nextPending) {
      return false;
    }
    if (nextPending.kind === "write") {
      return WRITE_PROBE_MAX_BYTES;
    }
    return (
      nextPending.kind === "exec" ||
      nextPending.kind === "gate" ||
      nextPending.kind === "managed_subagent" ||
      nextPending.kind === "user_vote"
    );
  };

  const skipProse = statSync(filePath).size > PROSE_SKIP_MIN_BYTES;
  const result = streamTranscriptRecords(
    filePath,
    (prefixType, lineBuf, recordIndex) => {
      if (lineBuf === null) {
        if (prefixType === "USER_INPUT" || prefixType === "PLANNER_RESPONSE" || prefixType === "SYSTEM_MESSAGE" || prefixType === null) {
          return true;
        }
        if (prefixType === "GENERIC") {
          return peekNeedsGeneric();
        }
        return false;
      }

      const lean =
        skipProse && (prefixType === "PLANNER_RESPONSE" || (prefixType === "GENERIC" && pendingCalls[0]?.kind === "write"));
      let parsed = parseRawRecord(lean ? decodeWithoutLeadingContent(lineBuf) : lineBuf.toString("utf8"));
      if (lean && parsed && (parsed.type !== prefixType || (parsed.type === "GENERIC" && mayBeDenialResult(parsed)))) {
        parsed = parseRawRecord(lineBuf.toString("utf8"));
      }
      if (!parsed) {
        return false;
      }

      const rawIndex = parsed.step_index !== undefined ? parsed.step_index : parsed.stepIndex;
      const stepIndex = parseStepIndex(rawIndex, recordIndex);
      indexed &&= turnStart === null || parseStepIndex(rawIndex, null) !== null;

      if (parsed.type === "USER_INPUT") {
        const userContent = typeof parsed.content === "string" ? parsed.content : "";
        if (!seenFirstUserInput) {
          seenFirstUserInput = true;
          applyHeaderSessionRole(parsed);
        }
        onUserInput?.(parsed, recordIndex);
        resetTurn(stepIndex, userContent);
        return true;
      }

      if (parsed.type === "SYSTEM_MESSAGE") {
        applyHeaderSessionRole(parsed);
        const msgContent = typeof parsed.content === "string" ? parsed.content : "";
        if (msgContent.includes(GATE_STOP_MARKER)) {
          ledger.gateBlockedThisTurn = true;
        }
        if (msgContent.includes(AUTO_CHALLENGER_MARKER)) {
          ledger.turnAutoChallengeTriggered = true;
        }
        if (msgContent.includes(AUTO_HANDOFF_MARKER)) {
          ledger.turnAutoHandoffTriggered = true;
        }
        const rawSource = typeof parsed.source === "string" ? parsed.source.trim() : "";
        const allowedSubagentSource = rawSource.length === 0 || ALLOWED_SUBAGENT_SYSTEM_SOURCES.has(rawSource);
        if (
          allowedSubagentSource &&
          (asyncAuditsByConversationId.size > 0 ||
            asyncChallengesByConversationId.size > 0 ||
            asyncWorkersByConversationId.size > 0) &&
          msgContent.length > 0
        ) {
          const senderMatch = msgContent.match(SUBAGENT_SENDER_MSG_RE);
          const senderId = senderMatch ? senderMatch[1] : "";
          if (senderId) {
            applyAsyncSubagentMessage(asyncAuditsByConversationId, senderId, msgContent, stepIndex, {
              parseVerdict: parseAuditVerdictFromText,
              finalVerdicts: FINAL_AUDIT_VERDICTS,
              holdCompletionUntilFinal: false,
            });
            applyAsyncSubagentMessage(asyncChallengesByConversationId, senderId, msgContent, stepIndex, {
              parseVerdict: parsePreflightVerdictFromText,
              finalVerdicts: FINAL_PREFLIGHT_VERDICTS,
              holdCompletionUntilFinal: true,
            });
            if (asyncWorkersByConversationId.has(senderId)) {
              ledger.turnWorkerCompleted = true;
              asyncWorkersByConversationId.delete(senderId);
            }
          }
        }
        return true;
      }

      if (parsed.type === "PLANNER_RESPONSE") {
        flushSyntheticWritesWithoutGenerics();
        seenFirstPlannerResponse = true;
        seenGenericInCurrentPlanner = false;
        pendingCalls = [];
        const tokens = extractLatestTokens(parsed);
        if (tokens) {
          ledger.latestTokens = tokens;
        }

        for (const call of getToolCalls(parsed)) {
          const name = typeof call?.name === "string" ? call.name : "";
          const { readPaths, writePaths } = extractToolPaths(call, cwd, gitRoot);

          if (writePaths.length > 0 || WRITE_TOOL_NAMES.has(name)) {
            if (writePaths.length > 0) {
              pendingCalls.push({ kind: "write", writePaths, readPaths, stepIndex });
            } else {
              for (const p of readPaths) {
                ledger.sessionReadFiles.add(p);
              }
              pendingCalls.push({ kind: "other" });
            }
            continue;
          }

          for (const p of readPaths) {
            ledger.sessionReadFiles.add(p);
          }

          if (EXEC_TOOL_NAMES.has(name)) {
            const command = extractCommandLine(call);
            const execCwd = extractCommandCwd(call, cwd);
            const entry = {
              stepIndex,
              command,
              execCwd,
              kind: classifyCommand(command),
              hasPrepSideEffect: commandHasPrepSideEffect(command),
              passed: true,
              hasResult: false,
              status: "",
              error: "",
              tail: "",
            };
            ledger.turnExecutions.push(entry);
            pendingCalls.push({ kind: "exec", entry });
          } else if (MCP_VERIFICATION_TOOL_NAMES.has(name)) {
            const { commands, labels } = extractMcpCheckCommands(call);
            const execCwd = extractCommandCwd(call, cwd);
            const entry = {
              stepIndex,
              toolName: name,
              command: commands.join(" && ") || name,
              execCwd,
              subCommands: commands,
              checkLabels: labels,
              kind: classifyMcpCheckCommands(commands),
              hasPrepSideEffect: commands.some((cmd) => commandHasPrepSideEffect(cmd)),
              passed: true,
              hasResult: false,
              status: "",
              error: "",
              tail: "",
            };
            ledger.turnExecutions.push(entry);
            pendingCalls.push({ kind: "exec", entry });
          } else if (name === GATE_TOOL_NAME) {
            const entry = {
              stepIndex,
              verdict: "UNKNOWN",
              passed: false,
            };
            ledger.turnGateAttempts.push(entry);
            pendingCalls.push({ kind: "gate", entry });
          } else if (USER_VOTE_TOOL_NAMES.has(name)) {
            const entry = {
              toolName: name,
              launchedStepIndex: stepIndex,
              completedStepIndex: -1,
              answered: false,
              errored: false,
            };
            ledger.turnUserVotes.push(entry);
            pendingCalls.push({ kind: "user_vote", entry });
          } else if (name === SUBAGENT_TOOL_NAME) {
            const typeNames = extractSubagentTypeNames(call);
            const subPrompts = extractSubagentPrompts(call);
            const auditEntries = [];
            const challengeEntries = [];
            const workerEntries = [];
            for (let idx = 0; idx < typeNames.length; idx += 1) {
              const promptAtSlot = subPrompts[idx] ?? "";
              if (isAuditorTypeName(typeNames[idx])) {
                const entry = {
                  stepIndex,
                  launchedStepIndex: stepIndex,
                  completedStepIndex: stepIndex,
                  slotIndex: idx,
                  totalSlots: typeNames.length,
                  typeName: AUDITOR_AGENT_NAME,
                  verdict: "MISSING_VERDICT",
                  conversationId: "",
                  tail: "",
                };
                ledger.turnSubagentAudits.push(entry);
                auditEntries.push(entry);
              } else if (isChallengerTypeName(typeNames[idx])) {
                const isExplicitAuto = promptAtSlot.includes(AUTO_CHALLENGER_MARKER);
                const challengeMode = ledger.turnHasManualPreflightCommand
                  ? "manual"
                  : isExplicitAuto || ledger.turnAutoChallengeTriggered
                    ? "auto"
                    : "manual";
                const entry = {
                  stepIndex,
                  launchedStepIndex: stepIndex,
                  completedStepIndex: -1,
                  slotIndex: idx,
                  totalSlots: typeNames.length,
                  typeName: CHALLENGER_AGENT_NAME,
                  mode: challengeMode,
                  verdict: "MISSING_VERDICT",
                  conversationId: "",
                  tail: "",
                };
                ledger.turnPreflightChallenges.push(entry);
                challengeEntries.push(entry);
              } else if (isWorkerTypeName(typeNames[idx])) {
                ledger.turnWorkerDispatched = true;
                workerEntries.push({ slotIndex: idx, totalSlots: typeNames.length, stepIndex });
              }
            }
            if (auditEntries.length > 0 || challengeEntries.length > 0 || workerEntries.length > 0) {
              pendingCalls.push({ kind: "managed_subagent", auditEntries, challengeEntries, workerEntries });
            } else {
              pendingCalls.push({ kind: "other" });
            }
          } else if (READ_TOOL_NAMES.has(name)) {
            pendingCalls.push({ kind: "read" });
          } else {
            pendingCalls.push({ kind: "other" });
          }
        }
        return true;
      }

      if (parsed.type === "GENERIC") {
        seenGenericInCurrentPlanner = true;
        const pending = pendingCalls.shift();
        if (!pending) {
          return true;
        }
        const status = typeof parsed.status === "string" ? parsed.status : "";
        const error = typeof parsed.error === "string" ? parsed.error : "";
        const normStatus = status.trim().toUpperCase();

        if (pending.kind === "write") {
          const denied = isPreToolDenialStep(parsed);
          if (denied && typeof parsed.content === "string" && parsed.content.includes("서킷브레이커")) {
            ledger.turnAutoChallengeTriggered = true;
          }
          const errored = normStatus === "ERROR" || normStatus === "FAILED" || error.trim().length > 0;
          if (!denied && !errored) {
            commitWriteToolResult(pending);
          }
          return true;
        }

        if (pending.kind === "exec") {
          const tail = extractTail(parsed.content);
          const head = pending.entry.toolName ? extractHead(parsed.content) : "";
          const hasFailBlock =
            Boolean(pending.entry.toolName) &&
            typeof parsed.content === "string" &&
            RUN_CHECKS_FAIL_BLOCK_RE.test(parsed.content);
          pending.entry.hasResult = true;
          pending.entry.status = status;
          pending.entry.error = error;
          pending.entry.tail = tail;
          pending.entry.passed =
            !isPreToolDenialStep(parsed) &&
            !hasFailBlock &&
            !inferExecutionFailure({ status, error, head, tail });
          if (!pending.entry.passed) {
            ledger.turnFailedExecutionCount += 1;
            if (pending.entry.kind === "verification") {
              ledger.turnVerifyFailures += 1;
              ledger.turnConsecutiveVerifyFailures += 1;
            }
          } else if (pending.entry.kind === "verification") {
            ledger.turnConsecutiveVerifyFailures = 0;
          }
        } else if (pending.kind === "gate") {
          const verdict = parseGateVerdictFromText(typeof parsed.content === "string" ? parsed.content : "");
          pending.entry.verdict = verdict;
          pending.entry.passed = PASSING_VERDICTS.has(verdict);
        } else if (pending.kind === "user_vote") {
          const rawText = typeof parsed.content === "string" ? parsed.content : "";
          const voteRes = parseUserVoteResult(rawText, {
            status,
            error,
            isDenial: isPreToolDenialStep(parsed),
          });
          pending.entry.completedStepIndex = stepIndex;
          pending.entry.answered = voteRes.answered;
          pending.entry.errored = voteRes.errored;
        } else if (pending.kind === "managed_subagent") {
          const rawText = typeof parsed.content === "string" ? parsed.content : "";
          const convIds = extractSubagentConversationIds(rawText);
          const isDenial = isPreToolDenialStep(parsed);
          const isLaunchAck = isAsyncSubagentLaunchAck(rawText);

          applyManagedSubagentGeneric(pending.auditEntries, {
            rawText,
            convIds,
            status,
            error,
            stepIndex,
            isDenial,
            isLaunchAck,
            parseVerdict: parseAuditVerdictFromText,
            asyncMap: asyncAuditsByConversationId,
            setCompletedOnSync: false,
          });
          applyManagedSubagentGeneric(pending.challengeEntries, {
            rawText,
            convIds,
            status,
            error,
            stepIndex,
            isDenial,
            isLaunchAck,
            parseVerdict: parsePreflightVerdictFromText,
            asyncMap: asyncChallengesByConversationId,
            setCompletedOnSync: true,
          });
          if (pending.workerEntries && pending.workerEntries.length > 0 && !isDenial) {
            for (const wid of convIds) {
              if (wid && !ledger.turnWorkerConversationIds.includes(wid)) {
                ledger.turnWorkerConversationIds.push(wid);
              }
            }
            if (isLaunchAck && convIds.length > 0) {
              for (const w of pending.workerEntries) {
                const wid = w.totalSlots > 1 ? (convIds[w.slotIndex] ?? "") : (convIds[0] ?? "");
                if (wid) {
                  asyncWorkersByConversationId.set(wid, w);
                }
              }
            } else if (!isLaunchAck && status.toUpperCase() !== "ERROR" && error.length === 0) {
              ledger.turnWorkerCompleted = true;
            }
          }
        }
        return true;
      }

      return true;
    },
    {
      onSkipped(prefixType, isValid) {
        if (prefixType === "GENERIC" && isValid) {
          seenGenericInCurrentPlanner = true;
          if (pendingCalls.length > 0) {
            pendingCalls.shift();
          }
        }
      },
      startOffset: turnStart === null ? 0 : turnStart.offset - 1,
      shouldStop: () => !indexed,
    },
  );

  if (!indexed) {
    return undefined;
  }
  if (!result.hasContent) {
    return null;
  }
  ledger.pendingAsyncAuditorCount = asyncAuditsByConversationId.size;
  ledger.pendingAsyncAuditLaunchSteps = Array.from(asyncAuditsByConversationId.values()).map((entry) => entry.launchedStepIndex);
  let pendingAfterLastWrite = 0;
  for (const entry of asyncAuditsByConversationId.values()) {
    if (entry.launchedStepIndex > ledger.lastWriteStepIndex) {
      pendingAfterLastWrite += 1;
    }
  }
  ledger.pendingAsyncAuditsAfterLastWrite = pendingAfterLastWrite;
  ledger.pendingAsyncChallenges = asyncChallengesByConversationId.size;
  ledger.pendingAsyncChallengeLaunchSteps = Array.from(asyncChallengesByConversationId.values()).map((entry) => entry.launchedStepIndex);
  let pendingChallengesAfterLastWrite = 0;
  for (const entry of asyncChallengesByConversationId.values()) {
    if (entry.launchedStepIndex > ledger.lastWriteStepIndex) {
      pendingChallengesAfterLastWrite += 1;
    }
  }
  ledger.pendingAsyncChallengesAfterLastWrite = pendingChallengesAfterLastWrite;
  return ledger;
}

const PARTIAL_SCAN_MIN_BYTES = 1024 * 1024;
// Prefix types the full scan always parses; a record of another prefix type may be skipped, so a tail scan
// that finds one parsing as a USER_INPUT or a token-bearing planner cannot tell what the full scan did.
const ALWAYS_PARSED_PREFIX_TYPES = new Set([null, "USER_INPUT", "PLANNER_RESPONSE", "SYSTEM_MESSAGE"]);
const AMBIGUOUS_LINE = Symbol("ambiguous");
// Every token key extractLatestTokens reads ends in `okens`.
const TOKEN_KEY_NEEDLE = 'okens"';
// shortcut: tokens from a planner more than 4MiB before the last turn read as null (the full scan would find
// them), since parsing every null-token planner back to the header took ~500ms on a 77MB session; widen it if
// the context-pollution check ever needs token counts that stale.
const TOKEN_FALLBACK_WINDOW_BYTES = 4 * 1024 * 1024;

function lineRecordOfType(lineBuf, type) {
  const parsed = parseRawRecord(lineBuf.toString("utf8"));
  if (!parsed || parsed.type !== type) {
    return null;
  }
  return ALWAYS_PARSED_PREFIX_TYPES.has(extractLinePrefixType(lineBuf.subarray(0, 256))) ? parsed : AMBIGUOUS_LINE;
}

// The session role from the header window (records before the first PLANNER_RESPONSE), exactly as the full scan
// settles it, reading no further. Null when the file holds no valid record.
function scanHeaderRole(filePath) {
  let role = "main";
  let seenUserInput = false;
  let done = false;
  const { hasContent } = streamTranscriptRecords(
    filePath,
    (prefixType, lineBuf) => {
      if (lineBuf === null) {
        return ALWAYS_PARSED_PREFIX_TYPES.has(prefixType);
      }
      const parsed = parseRawRecord(lineBuf.toString("utf8"));
      if (!parsed) {
        return false;
      }
      if (parsed.type === "PLANNER_RESPONSE") {
        done = true;
      } else if (parsed.type === "SYSTEM_MESSAGE" || (parsed.type === "USER_INPUT" && !seenUserInput)) {
        role = pickHigherSessionRole(role, detectSessionRoleFromHeaderStep(parsed));
        done = role === "auditor";
      }
      seenUserInput ||= parsed.type === "USER_INPUT";
      return true;
    },
    { shouldStop: () => done },
  );
  return hasContent ? role : null;
}

// Header role plus a scan from the last USER_INPUT. Every ledger field but sessionReadFiles resets per turn, so
// they match the full scan; latestTokens falls back to the last token-bearing planner before the turn.
// sessionReadFiles holds this turn's reads only. Undefined means "use the full scan".
function scanTurnFromTail(filePath, cwd, gitRoot, onUserInput) {
  const sessionRole = scanHeaderRole(filePath);
  if (sessionRole === null) {
    return undefined;
  }
  // A turn longer than half the file saves under half the full scan, so the search stops there.
  const turn = findLastLine(filePath, '"USER_INPUT"', (lineBuf) => lineRecordOfType(lineBuf, "USER_INPUT"), {
    start: Math.floor(statSync(filePath).size / 2),
  });
  if (!turn || turn === LINE_TOO_LONG || turn.value === AMBIGUOUS_LINE || turn.offset === 0) {
    return undefined;
  }
  const ledger = scanTranscriptToLedger(filePath, cwd, gitRoot, onUserInput, { offset: turn.offset, sessionRole });
  if (!ledger || Object.values(ledger.latestTokens).some((count) => count !== null)) {
    return ledger ?? undefined;
  }
  const earlier = findLastLine(
    filePath,
    TOKEN_KEY_NEEDLE,
    (lineBuf) => {
      const parsed = lineRecordOfType(lineBuf, "PLANNER_RESPONSE");
      return parsed === AMBIGUOUS_LINE ? parsed : parsed && extractLatestTokens(parsed);
    },
    { start: Math.max(0, turn.offset - TOKEN_FALLBACK_WINDOW_BYTES), end: turn.offset },
  );
  if (earlier === LINE_TOO_LONG || earlier?.value === AMBIGUOUS_LINE) {
    return undefined;
  }
  if (earlier) {
    ledger.latestTokens = earlier.value;
  }
  return ledger;
}

function scanFirstLedgerCandidate(transcriptPath, cwd, gitRoot, onUserInput, partialMinBytes = Infinity) {
  fsMemo = new Map();
  try {
    for (const candidatePath of resolveTranscriptCandidates(transcriptPath.trim())) {
      try {
        const partial = statSync(candidatePath).size > partialMinBytes ? scanTurnFromTail(candidatePath, cwd, gitRoot, onUserInput) : undefined;
        const ledger = partial ?? scanTranscriptToLedger(candidatePath, cwd, gitRoot, onUserInput);
        if (ledger) {
          return { ledger, candidatePath };
        }
      } catch {
        continue;
      }
    }
    return { ledger: createEmptyLedger(false), candidatePath: "" };
  } finally {
    fsMemo = null;
  }
}

export function readFactLedger(transcriptPath, cwd = "", gitRoot = "") {
  if (typeof transcriptPath !== "string" || transcriptPath.trim().length === 0) {
    return createEmptyLedger(false);
  }
  return scanFirstLedgerCandidate(transcriptPath, cwd, gitRoot).ledger;
}

// For hooks that read only the current turn and the session role (Stop, PostInvocation, PreInvocation): a file
// over 1MB is read from its header and its last turn, so sessionReadFiles lists this turn's reads only.
// Consumers of the session-wide read set (verify_completion's R1, handoff snapshots) use readFactLedger.
export function readTurnLedger(transcriptPath, cwd = "", gitRoot = "", { partialMinBytes = PARTIAL_SCAN_MIN_BYTES } = {}) {
  if (typeof transcriptPath !== "string" || transcriptPath.trim().length === 0) {
    return createEmptyLedger(false);
  }
  return scanFirstLedgerCandidate(transcriptPath, cwd, gitRoot, null, partialMinBytes).ledger;
}

// The session role alone, from the header window: O(header) on any transcript size.
export function readSessionRole(transcriptPath) {
  if (typeof transcriptPath !== "string" || transcriptPath.trim().length === 0) {
    return "unknown";
  }
  for (const candidatePath of resolveTranscriptCandidates(transcriptPath.trim())) {
    try {
      const role = scanHeaderRole(candidatePath);
      if (role !== null) {
        return role;
      }
    } catch {
      continue;
    }
  }
  return "unknown";
}

// Stop and PostInvocation: the turn ledger and the drift steps both read from the tail.
export function readFactLedgerAndSteps(transcriptPath, cwd = "", gitRoot = "") {
  if (typeof transcriptPath !== "string" || transcriptPath.trim().length === 0) {
    return { ledger: createEmptyLedger(false), steps: [] };
  }
  let latestUser = null;
  const onUserInput = (parsed, recordIndex) => {
    latestUser = { parsed, recordIndex };
  };
  const { ledger, candidatePath } = scanFirstLedgerCandidate(transcriptPath, cwd, gitRoot, onUserInput, PARTIAL_SCAN_MIN_BYTES);
  let steps = [];
  try {
    steps = candidatePath ? readTailTranscriptSteps(candidatePath, DRIFT_STEP_WINDOW) : [];
  } catch {
    steps = [];
  }
  if (steps.length === 0) {
    // The step reader moves on to the next candidate when this one holds records but no steps.
    return { ledger, steps: readTranscriptSteps(transcriptPath) };
  }
  if (latestUser && !steps.some((step) => step.type === "USER_INPUT")) {
    steps = [recordToStep(latestUser.parsed, latestUser.recordIndex), ...steps];
  }
  return { ledger, steps };
}

const CONTENT_MEMBER = Buffer.from('"content":"');
const INVALID_JSON_STRING_RE = /[\x00-\x1f]|\\(?:[^"\\/bfnrtu]|u(?![0-9a-fA-F]{4}))/;

function closingQuoteAt(buf, from) {
  for (let i = from; ; ) {
    const quote = buf.indexOf(0x22, i);
    if (quote < 0) {
      return -1;
    }
    let slashes = 0;
    while (buf[quote - 1 - slashes] === 0x5c) {
      slashes += 1;
    }
    if (slashes % 2 === 0) {
      return quote;
    }
    i = quote + 1;
  }
}

// A write result needs its content only to spot a denial, which carries an error or a non-DONE status.
function mayBeDenialResult(parsed) {
  return typeof parsed.status !== "string" || parsed.status === "" || parsed.status === "ERROR" || (typeof parsed.error === "string" && parsed.error !== "");
}

// The ledger never reads planner prose or a clean write result's output, so a large scan skips decoding
// the leading top-level "content" string. Only scalar members may precede it, proving it is top-level.
function decodeWithoutLeadingContent(buf) {
  const keyAt = buf.indexOf(CONTENT_MEMBER);
  const open = buf.indexOf(0x7b);
  if (keyAt < 0 || open < 0 || open > keyAt) {
    return buf.toString("utf8");
  }
  for (let i = open + 1; i < keyAt; i += 1) {
    if (buf[i] === 0x7b || buf[i] === 0x5b) {
      return buf.toString("utf8");
    }
  }
  const valueStart = keyAt + CONTENT_MEMBER.length;
  const valueEnd = closingQuoteAt(buf, valueStart);
  // A string JSON.parse would reject keeps the full decode, so the record stays invalid exactly as before.
  if (valueEnd < 0 || INVALID_JSON_STRING_RE.test(buf.toString("latin1", valueStart, valueEnd))) {
    return buf.toString("utf8");
  }
  return buf.toString("utf8", 0, valueStart) + buf.toString("utf8", valueEnd);
}

function countTextFileLinesLightweight(absPath) {
  let fd;
  try {
    const lst = lstatSync(absPath);
    if (!lst.isFile()) {
      return null;
    }
    const openFlags = (fsConstants.O_RDONLY ?? 0) | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0);
    fd = openSync(absPath, openFlags);
    const fst = fstatSync(fd);
    if (!fst.isFile()) {
      return null;
    }
    const size = fst.size;
    if (size === 0) {
      return 0;
    }
    const readBytes = Math.min(size, MAX_UNTRACKED_COUNT_BYTES);
    const buf = Buffer.allocUnsafe(readBytes);
    const actual = readSync(fd, buf, 0, readBytes, 0);
    if (actual < size) {
      return null;
    }
    let lines = 0;
    for (let i = 0; i < actual; i += 1) {
      if (buf[i] === 0x00) {
        return 0;
      }
      if (buf[i] === 0x0a) {
        lines += 1;
      }
    }
    if (actual > 0 && buf[actual - 1] !== 0x0a) {
      lines += 1;
    }
    return lines;
  } catch {
    return null;
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
      }
    }
  }
}

function parseNumstatOutput(output, gitRoot, diffNumstat, isNulDelimited = false) {
  if (typeof output !== "string" || output.length === 0) {
    return;
  }
  const addStat = (rawPath, added, deleted) => {
    const relPath = normalizeWorkspacePath(rawPath, gitRoot, gitRoot);
    if (!relPath) {
      return;
    }
    const prev = diffNumstat.get(relPath);
    if (prev) {
      prev.added += added;
      prev.deleted += deleted;
    } else {
      diffNumstat.set(relPath, { added, deleted });
    }
  };

  if (isNulDelimited) {
    const tokens = output.split("\0");
    for (let i = 0; i < tokens.length; i += 1) {
      const entry = tokens[i];
      if (entry.length === 0) {
        continue;
      }
      const parts = entry.split("\t");
      if (parts.length < 3) {
        continue;
      }
      const added = /^\d+$/.test(parts[0]) ? Number(parts[0]) : 0;
      const deleted = /^\d+$/.test(parts[1]) ? Number(parts[1]) : 0;
      const pathPart = parts.slice(2).join("\t");
      if (pathPart.length === 0) {
        const oldPath = tokens[i + 1] ?? "";
        const newPath = tokens[i + 2] ?? "";
        i += 2;
        addStat(newPath || oldPath, added, deleted);
      } else {
        addStat(pathPart, added, deleted);
      }
    }
    return;
  }

  for (const line of output.split(/\r?\n/)) {
    if (line.length === 0) {
      continue;
    }
    const parts = line.split("\t");
    if (parts.length < 3) {
      continue;
    }
    const added = /^\d+$/.test(parts[0]) ? Number(parts[0]) : 0;
    const deleted = /^\d+$/.test(parts[1]) ? Number(parts[1]) : 0;
    addStat(parts.slice(2).join("\t"), added, deleted);
  }
}

export function resolveGitRootFast(startDir) {
  if (typeof startDir !== "string" || startDir.trim().length === 0) {
    return "";
  }
  let dir;
  try {
    dir = realpathSync(startDir);
  } catch {
    dir = resolve(startDir);
  }
  for (let i = 0; i < 20; i += 1) {
    if (existsSync(resolve(dir, ".git"))) {
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) {
      break;
    }
    dir = parent;
  }
  return "";
}

// git status runs ~7ms median here but reached 589ms under parallel suite load, and a timed-out snapshot fails
// closed, so 250ms blocked Stop on committed verified work. Stop's four git calls at 750ms fit the 5s hook timeout.
const SNAPSHOT_GIT_TIMEOUT_MS = 750;
const SNAPSHOT_MAX_FILES = 2000;

const SNAPSHOT_MAX_BUFFER = 16 * 1024 * 1024;

const MAX_SNAPSHOT_HASH_BYTES = 1024 * 1024;

const SNAPSHOT_READ_CHUNK_BYTES = 65536;

export const SNAPSHOT_UNREADABLE_SIGNATURE = "__UNREADABLE__";

function isMissingFsError(err) {
  return err?.code === "ENOENT" || err?.code === "ENOTDIR";
}

export function statSnapshotFile(gitRoot, relPath) {
  let fd = -1;
  try {
    const fullPath = join(gitRoot, relPath);
    const st = lstatSync(fullPath);
    const modeSig = (st.mode & 0o170000) | (st.mode & 0o111);
    if (st.isSymbolicLink()) {
      return [st.mtimeMs, st.size, modeSig, readlinkSync(fullPath)];
    }
    if (!st.isFile()) {
      return SNAPSHOT_UNREADABLE_SIGNATURE;
    }
    if (st.size <= MAX_SNAPSHOT_HASH_BYTES) {
      const flags = fsConstants.O_RDONLY | (fsConstants.O_NONBLOCK ?? 0) | (fsConstants.O_NOFOLLOW ?? 0);
      fd = openSync(fullPath, flags);
      const fstBefore = fstatSync(fd);
      if (!fstBefore.isFile() || fstBefore.size > MAX_SNAPSHOT_HASH_BYTES) {
        return SNAPSHOT_UNREADABLE_SIGNATURE;
      }
      const chunk = Buffer.allocUnsafe(SNAPSHOT_READ_CHUNK_BYTES);
      const hasher = createHash("sha1");
      let total = 0;
      while (total <= MAX_SNAPSHOT_HASH_BYTES) {
        const n = readSync(fd, chunk, 0, Math.min(SNAPSHOT_READ_CHUNK_BYTES, MAX_SNAPSHOT_HASH_BYTES + 1 - total), null);
        if (n <= 0) {
          break;
        }
        total += n;
        if (total > MAX_SNAPSHOT_HASH_BYTES) {
          return SNAPSHOT_UNREADABLE_SIGNATURE;
        }
        hasher.update(chunk.subarray(0, n));
      }
      const fstAfter = fstatSync(fd);
      if (
        !fstAfter.isFile() ||
        total !== fstBefore.size ||
        total !== fstAfter.size ||
        fstBefore.size !== fstAfter.size ||
        fstBefore.mtimeMs !== fstAfter.mtimeMs ||
        fstBefore.ctimeMs !== fstAfter.ctimeMs
      ) {
        return SNAPSHOT_UNREADABLE_SIGNATURE;
      }
      const digest = hasher.digest("hex");
      return [fstAfter.mtimeMs, fstAfter.size, (fstAfter.mode & 0o170000) | (fstAfter.mode & 0o111), digest];
    }
    return [st.mtimeMs, st.size, modeSig];
  } catch (err) {
    return isMissingFsError(err) ? null : SNAPSHOT_UNREADABLE_SIGNATURE;
  } finally {
    if (fd !== -1) {
      try {
        closeSync(fd);
      } catch {
      }
    }
  }
}

// Cheap working-tree fingerprint: separates tracked changes (`-uno`) from untracked code files (`ls-files`)
// so 2,000+ untracked code files degrade only untracked diffing while keeping tracked file edits exact.
export function snapshotWorkingTree(cwd) {
  const gitRoot = resolveGitRootFast(cwd);
  if (!gitRoot) {
    return null;
  }
  let trackedOut;
  try {
    trackedOut = execFileSync("git", ["-c", "core.quotepath=false", "status", "--porcelain=v1", "-uno", "-z"], {
      cwd: gitRoot,
      timeout: SNAPSHOT_GIT_TIMEOUT_MS,
      maxBuffer: SNAPSHOT_MAX_BUFFER,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return null;
  }
  let head = "";
  try {
    head = execFileSync("git", ["rev-parse", "-q", "--verify", "HEAD"], {
      cwd: gitRoot,
      timeout: SNAPSHOT_GIT_TIMEOUT_MS,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch (err) {
    // An unborn HEAD exits 1 with no output; anything else leaves the snapshot unusable.
    if (err?.status !== 1 || String(err.stdout ?? "").trim().length > 0) {
      return null;
    }
  }
  const files = Object.create(null);
  const docFiles = Object.create(null);
  let trackedCodeCount = 0;
  let trackedDocCount = 0;
  let docFilesTruncated = false;
  const trackedTokens = trackedOut.split("\0");
  for (let i = 0; i < trackedTokens.length; i += 1) {
    const entry = trackedTokens[i];
    if (entry.length < 4) {
      continue;
    }
    const isRename = entry[0] === "R" || entry[1] === "R";
    const isCopy = entry[0] === "C" || entry[1] === "C";
    let origPath = "";
    if (isRename || isCopy) {
      origPath = trackedTokens[i + 1] ?? "";
      i += 1;
    }
    const destPath = entry.slice(3);
    const candidates = isRename && origPath && origPath !== destPath ? [origPath, destPath] : [destPath];
    for (const relPath of candidates) {
      if (isExemptDocOrAssetPath(relPath)) {
        if (trackedDocCount < SNAPSHOT_MAX_FILES) {
          trackedDocCount += 1;
          docFiles[relPath] = statSnapshotFile(gitRoot, relPath);
        } else {
          docFilesTruncated = true;
        }
        continue;
      }
      trackedCodeCount += 1;
      if (trackedCodeCount > SNAPSHOT_MAX_FILES) {
        return null;
      }
      files[relPath] = statSnapshotFile(gitRoot, relPath);
    }
  }

  let untrackedFiles = Object.create(null);
  let untrackedTruncated = false;
  try {
    const untrackedOut = execFileSync("git", ["-c", "core.quotepath=false", "ls-files", "--others", "--exclude-standard", "-z"], {
      cwd: gitRoot,
      timeout: SNAPSHOT_GIT_TIMEOUT_MS,
      maxBuffer: SNAPSHOT_MAX_BUFFER,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    let untrackedCodeCount = 0;
    for (const relPath of untrackedOut.split("\0")) {
      if (!relPath) {
        continue;
      }
      if (isExemptDocOrAssetPath(relPath)) {
        if (trackedDocCount < SNAPSHOT_MAX_FILES) {
          trackedDocCount += 1;
          docFiles[relPath] = statSnapshotFile(gitRoot, relPath);
        } else {
          docFilesTruncated = true;
        }
        continue;
      }
      untrackedCodeCount += 1;
      if (untrackedCodeCount > SNAPSHOT_MAX_FILES) {
        untrackedTruncated = true;
        untrackedFiles = null;
        continue;
      }
      if (!untrackedTruncated) {
        untrackedFiles[relPath] = statSnapshotFile(gitRoot, relPath);
      }
    }
  } catch {
    untrackedTruncated = true;
    untrackedFiles = null;
    docFilesTruncated = true;
  }

  return { gitRoot, head, files, docFiles, docFilesTruncated, untrackedFiles, untrackedTruncated, capturedAtMs: Date.now() };
}

const EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

// Paths that commits between two snapshot HEADs touched ("" is an unborn HEAD), or null when git cannot say.
// --no-renames preserves both old and new paths when a code file is moved/renamed into an exempt directory.
export function listCommittedPaths(gitRoot, fromHead, toHead) {
  try {
    const out = execFileSync(
      "git",
      ["-c", "core.quotepath=false", "diff", "--no-renames", "--name-only", "-z", fromHead || EMPTY_TREE_SHA, toHead || EMPTY_TREE_SHA, "--"],
      { cwd: gitRoot, timeout: SNAPSHOT_GIT_TIMEOUT_MS, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
    );
    return new Set(out.split("\0").filter(Boolean));
  } catch {
    return null;
  }
}

export function readNumstatSinceHead(gitRoot, fromHead) {
  const numstat = new Map();
  if (!gitRoot || fromHead === null) {
    return numstat;
  }
  try {
    const out = execFileSync(
      "git",
      ["-c", "core.quotepath=false", "diff", "--no-renames", "--numstat", "-z", fromHead || EMPTY_TREE_SHA],
      { cwd: gitRoot, timeout: SNAPSHOT_GIT_TIMEOUT_MS, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
    );
    parseNumstatOutput(out, gitRoot, numstat, true);
    return numstat;
  } catch {
    return null;
  }
}

export function readGitLedger(cwd) {
  const empty = {
    gitAvailable: false,
    gitRoot: null,
    gitDirtyFiles: new Set(),
    dirtyFilesAvailable: false,
    diffNumstat: new Map(),
    numstatUnavailable: false,
    gitBranch: "",
    gitHead: "",
  };
  if (typeof cwd !== "string" || cwd.trim().length === 0) {
    return empty;
  }
  const deadline = Date.now() + GIT_TIMEOUT_MS;
  const remainingTimeout = () => Math.max(100, deadline - Date.now());
  try {
    const gitRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd,
      timeout: remainingTimeout(),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).replace(process.platform === "win32" ? /\r?\n$/ : /\n$/, "");
    if (!gitRoot) {
      return empty;
    }

    let statusOut;
    try {
      statusOut = execFileSync("git", ["-c", "core.quotepath=false", "status", "--porcelain=v1", "-uall", "-z"], {
        cwd: gitRoot,
        timeout: remainingTimeout(),
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      });
    } catch {
      return { ...empty, gitAvailable: true, gitRoot, dirtyFilesAvailable: false, numstatUnavailable: true };
    }

    const gitDirtyFiles = new Set();
    const untrackedFiles = [];
    const tokens = statusOut.split("\0");
    for (let i = 0; i < tokens.length; i += 1) {
      const entry = tokens[i];
      if (entry.length < 4) {
        continue;
      }
      const x = entry[0];
      const y = entry[1];
      const path1 = normalizeWorkspacePath(entry.slice(3), gitRoot, gitRoot);
      if (path1) {
        gitDirtyFiles.add(path1);
        if (x === "?" && y === "?") {
          untrackedFiles.push(path1);
        }
      }
      if (x === "R" || x === "C" || y === "R" || y === "C") {
        i += 1;
        const oldPath = i < tokens.length ? normalizeWorkspacePath(tokens[i], gitRoot, gitRoot) : "";
        if (oldPath) {
          gitDirtyFiles.add(oldPath);
        }
      }
    }

    const diffNumstat = new Map();
    let numstatUnavailable = gitDirtyFiles.size > 0;
    if (Date.now() < deadline) {
      try {
        const numstatOut = execFileSync("git", ["-c", "core.quotepath=false", "diff", "--numstat", "-z", "HEAD"], {
          cwd: gitRoot,
          timeout: remainingTimeout(),
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        });
        parseNumstatOutput(numstatOut, gitRoot, diffNumstat, true);
        numstatUnavailable = false;
      } catch {
        let allSubDiffsOk = true;
        for (const diffArgs of [
          ["-c", "core.quotepath=false", "diff", "--numstat", "-z", "--cached"],
          ["-c", "core.quotepath=false", "diff", "--numstat", "-z"],
        ]) {
          if (Date.now() >= deadline) {
            allSubDiffsOk = false;
            break;
          }
          try {
            const out = execFileSync("git", diffArgs, {
              cwd: gitRoot,
              timeout: remainingTimeout(),
              encoding: "utf8",
              stdio: ["ignore", "pipe", "ignore"],
            });
            parseNumstatOutput(out, gitRoot, diffNumstat, true);
          } catch {
            allSubDiffsOk = false;
          }
        }
        numstatUnavailable = !allSubDiffsOk;
      }
    }

    for (const relPath of untrackedFiles) {
      if (isExemptDocOrAssetPath(relPath) || diffNumstat.has(relPath)) {
        continue;
      }
      const lines = countTextFileLinesLightweight(join(gitRoot, relPath));
      if (lines === null) {
        numstatUnavailable = true;
      } else if (lines > 0) {
        diffNumstat.set(relPath, { added: lines, deleted: 0 });
      }
    }

    let gitBranch = "";
    let gitHead = "";
    if (Date.now() < deadline) {
      try {
        gitBranch = execFileSync("git", ["symbolic-ref", "--short", "HEAD"], {
          cwd: gitRoot,
          timeout: remainingTimeout(),
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        }).trim();
      } catch {
        gitBranch = "HEAD";
      }
    }
    if (Date.now() < deadline) {
      try {
        gitHead = execFileSync("git", ["rev-parse", "--short", "HEAD"], {
          cwd: gitRoot,
          timeout: remainingTimeout(),
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        }).trim();
      } catch {
        gitHead = "";
      }
    }

    return { gitAvailable: true, gitRoot, gitDirtyFiles, dirtyFilesAvailable: true, diffNumstat, numstatUnavailable, gitBranch, gitHead };
  } catch {
    return empty;
  }
}

function scanTestInfraDir(dir, indicators) {
  if (!dir) {
    return { uncertain: false };
  }
  if (!existsSync(dir)) {
    return { uncertain: true };
  }
  let uncertain = false;

  const pkgPath = join(dir, "package.json");
  if (existsSync(pkgPath)) {
    const res = readRegularFileBounded(pkgPath);
    if (!res.ok) {
      uncertain = true;
    } else {
      try {
        const pkg = JSON.parse(res.text);
        const testScript = typeof pkg?.scripts?.test === "string" ? pkg.scripts.test.trim() : "";
        if (testScript.length > 0 && !/no test specified/i.test(testScript)) {
          indicators.add("package.json:scripts.test");
        }
      } catch {
        uncertain = true;
      }
    }
  }

  for (const testDir of ["test", "tests"]) {
    if (existsSync(join(dir, testDir))) {
      indicators.add(`${testDir}/`);
    }
  }

  for (const exact of TEST_INFRA_EXACT_FILES) {
    if (existsSync(join(dir, exact))) {
      indicators.add(exact);
    }
  }

  for (const [cfgName, sectionRe] of [
    ["tox.ini", /^\[pytest\][ \t]*$/im],
    ["setup.cfg", /^\[tool:pytest\][ \t]*$/im],
  ]) {
    const cfgPath = join(dir, cfgName);
    if (existsSync(cfgPath)) {
      const res = readRegularFileBounded(cfgPath);
      if (!res.ok) {
        uncertain = true;
      } else if (sectionRe.test(res.text)) {
        indicators.add(cfgName);
      }
    }
  }

  try {
    for (const entry of readdirSync(dir)) {
      if (TEST_INFRA_CONFIG_PREFIXES.some((prefix) => entry.startsWith(prefix))) {
        indicators.add(entry);
      }
    }
  } catch {
    uncertain = true;
  }
  return { uncertain };
}

function resolveNormalizedPath(dir) {
  try {
    return realpathSync(dir);
  } catch {
    return resolve(dir);
  }
}

function addAncestorDirs(roots, dir, stopRoot = "", maxDepth = 64) {
  if (typeof dir !== "string" || dir.trim().length === 0) {
    return { truncated: false };
  }
  const curResolved = resolveNormalizedPath(dir);
  roots.add(curResolved);
  const stop = typeof stopRoot === "string" && stopRoot.trim().length > 0 ? resolveNormalizedPath(stopRoot) : "";
  if (!stop) {
    return { truncated: false };
  }
  const relFromStop = relative(stop, curResolved);
  const isOutsideStop =
    relFromStop === ".." ||
    relFromStop.startsWith(`..${sep}`) ||
    relFromStop.startsWith("../") ||
    isAbsolute(relFromStop);
  if (isOutsideStop) {
    return { truncated: false };
  }
  let cur = curResolved;
  for (let depth = 0; depth < maxDepth; depth += 1) {
    roots.add(cur);
    if (cur === stop) {
      return { truncated: false };
    }
    const parent = dirname(cur);
    if (parent === cur) {
      return { truncated: false };
    }
    cur = parent;
  }
  return { truncated: cur !== stop };
}

export function detectTestInfrastructure(cwd, gitRoot = null, { maxDepth = 64 } = {}) {
  const indicators = new Set();
  const roots = new Set();
  const walk = addAncestorDirs(roots, cwd, gitRoot, maxDepth);
  if (typeof gitRoot === "string" && gitRoot.trim().length > 0) {
    roots.add(gitRoot);
  }
  let scanUncertain = false;
  for (const root of roots) {
    const scan = scanTestInfraDir(root, indicators);
    if (scan.uncertain) {
      scanUncertain = true;
    }
  }
  const uncertain = Boolean(walk?.truncated || scanUncertain || roots.size === 0);
  return {
    hasTestSuite: indicators.size > 0,
    indicators: [...indicators],
    ...(uncertain ? { uncertain: true } : {}),
  };
}
