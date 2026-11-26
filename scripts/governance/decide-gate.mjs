import { posix } from "node:path";
import {
  ALLOWED_AUDIT_ESCALATION_MODES,
  ALLOWED_SCHEMA_REGISTERS,
  PASSING_VERDICTS,
  POLLUTION_WARNING_LINE,
  REGISTER_COPY,
  RISK_REASON_LABELS,
} from "./constants.mjs";
import { classifyCommand, normalizeWorkspacePath, splitShellSegments } from "./fact-ledger.mjs";
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

function normalizeExecDir(dir) {
  if (typeof dir !== "string" || dir.trim().length === 0) {
    return ".";
  }
  const norm = posix.normalize(dir.trim().replace(/\\/g, "/"));
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

function isChainPrepText(norm) {
  const tok = norm.split(" ");
  if (tok[0] !== "npm") {
    return false;
  }
  const positional = tok.slice(1).filter((t) => !t.startsWith("-"));
  return positional.length === 1 && (positional[0] === "ci" || positional[0] === "install");
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
    const norm = normalizeCommandText(seg);
    if (norm.length === 0) {
      continue;
    }
    const dirMatch = /^(cd|pushd|popd)(?:\s+(.*))?$/.exec(norm);
    if (dirMatch) {
      seq += 1;
      state = advanceDir(state, dirMatch[1], dirMatch[2]?.trim(), seq);
      continue;
    }
    if (isChainPrepText(norm)) {
      prepPrefixes.push(norm);
      continue;
    }
    if (classifyCommand(norm) === "verification") {
      entries.push({ seg: norm, dir: state.dir, prepKey: prepPrefixes.join(" && ") });
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

function isPathTarget(token) {
  return !token.startsWith("-") && !token.includes("=") && (/[/\\*]/.test(token) || /\.[A-Za-z0-9]+$/.test(token));
}

const RUNNER_VALUE_FLAGS = new Set([
  "-c",
  "--config",
  "-r",
  "--reporter",
  "--test-reporter",
  "--test-reporter-destination",
  "--test-name-pattern",
  "--test-skip-pattern",
  "--test-shard",
  "--test-concurrency",
  "--test-timeout",
  "-t",
  "--testNamePattern",
  "--testPathPattern",
  "--testPathIgnorePatterns",
  "--root",
  "--dir",
  "--environment",
  "--mode",
  "--project",
  "--projects",
  "--outputFile",
  "--coverage.reporter",
  "--setupFiles",
  "--setupFilesAfterEnv",
  "-k",
  "-m",
  "-o",
  "--rootdir",
  "--confcutdir",
  "--junitxml",
  "-n",
  "--maxfail",
  "--tb",
  "-p",
  "--import",
  "--require",
  "--loader",
  "--env-file",
  "--tsconfig",
]);

function isDefaultDiscoverableTestTarget(target, runnerPrefix) {
  const norm = target.replace(/\\/g, "/").replace(/^\.\//, "");
  if (runnerPrefix.includes("pytest")) {
    const filePart = norm.split("::")[0];
    return /(?:^|\/)test_[^/]*\.py$|_test\.py$/.test(filePart);
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
function segmentResolvedBy(failedSeg, passedSeg) {
  if (failedSeg.length === 0 || passedSeg.length === 0) {
    return false;
  }
  if (failedSeg === passedSeg) {
    return true;
  }
  const failed = failedSeg.split(" ");
  const passed = passedSeg.split(" ");
  if ([...failed, ...passed].some((token) => SHELL_OPERATOR_TOKEN_RE.test(token))) {
    return false;
  }
  const runner = runnerPrefixLength(failed);
  if (!runner || failed.slice(0, runner.end).join(" ") !== passed.slice(0, runner.end).join(" ")) {
    return false;
  }
  if (runner.kind === "go") {
    const isGoTarget = (token) => token === "." || isPathTarget(token);
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
  const isTarget = (tokens, index) =>
    isPathTarget(tokens[index]) && !(index - 1 >= runner.end && RUNNER_VALUE_FLAGS.has(tokens[index - 1]));
  const droppedOnlyTargets = dropped.every((index) =>
    failed[index] === "--"
      ? failed.slice(index + 1).every((_, k) => dropped.includes(index + 1 + k))
      : isTarget(failed, index) && isDefaultDiscoverableTestTarget(failed[index], runner.prefix),
  );
  return droppedOnlyTargets && !passed.some((_, index) => index >= runner.end && isTarget(passed, index));
}

function entriesMatchForResolution(failedEntry, passedEntry) {
  if (failedEntry.dir !== passedEntry.dir) {
    return false;
  }
  if (failedEntry.prepKey && passedEntry.prepKey !== failedEntry.prepKey) {
    return false;
  }
  return segmentResolvedBy(failedEntry.seg, passedEntry.seg);
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
    return failedEntries.every((failedEntry) => passedEntries.some((passedEntry) => entriesMatchForResolution(failedEntry, passedEntry)));
  }
  return normalizeExecDir(failedBaseDir) === normalizeExecDir(passedBaseDir) && segmentResolvedBy(failedNorm, passedNorm);
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

function commandMatchesExecution(normClaim, execCommand) {
  const normExec = normalizeCommandText(execCommand);
  if (normClaim.length === 0 || normExec.length === 0) {
    return false;
  }
  if (normExec === normClaim) {
    return true;
  }
  const allowPrefixMatch = !isBareRuntimeLauncher(normClaim);
  const execSegments = splitShellSegments(execCommand).map(normalizeCommandText).filter(Boolean);
  for (const seg of execSegments) {
    if (seg === normClaim) {
      return true;
    }
    if (allowPrefixMatch && seg.startsWith(`${normClaim} `)) {
      return true;
    }
  }
  return allowPrefixMatch && normExec.startsWith(`${normClaim} `);
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
  if (commandMatchesExecution(normClaim, exec.command)) {
    return true;
  }
  if (Array.isArray(exec.subCommands)) {
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

  const hasCodeWrite = ledger.lastCodeWriteStepIndex !== -1;
  const postWriteExecutions = hasCodeWrite
    ? ledger.turnExecutions.filter((exec) => exec.stepIndex > ledger.lastCodeWriteStepIndex)
    : ledger.turnExecutions;
  const postWriteVerifications = hasCodeWrite
    ? postWriteExecutions.filter((exec) => exec.kind === "verification")
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

  for (const writtenFile of ledger.turnWrittenFiles) {
    if (gitLedger.gitAvailable && !gitLedger.gitDirtyFiles.has(writtenFile)) {
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
    const normClaim = normalizeCommandText(run.command);
    const matchingExecs =
      normClaim.length > 0
        ? postWriteExecutions.filter((exec) => exec.kind !== "read_only" && claimMatchesExecution(normClaim, exec))
        : [];
    const matchedPass = matchingExecs.some((exec) => exec.passed === true);
    const coveredByR3Failure =
      hasCodeWrite &&
      blockedRules.includes("R3_CONCEALED_FAILURE") &&
      matchingExecs.some((exec) => exec.kind === "verification" && !exec.passed);
    if (!matchedPass && !coveredByR3Failure) {
      details.fabricatedCommands.push(run.command || "(비어 있는 명령)");
    }
  }
  if (details.fabricatedCommands.length > 0) {
    blockedRules.push("R5_FABRICATED_COMMAND");
  }

  for (const reportedFile of reportedModified) {
    if (!ledger.turnWrittenFiles.has(reportedFile) && !gitLedger.gitDirtyFiles.has(reportedFile)) {
      details.phantomModified.push(reportedFile);
    }
  }
  if (details.phantomModified.length > 0) {
    if (ledger.turnWrittenFiles.size === 0 && gitLedger.gitAvailable) {
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
    hasCodeWrite && auditEscalation === "auto" && risk.tier === "TIER_1" && sessionRole === "main";

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
