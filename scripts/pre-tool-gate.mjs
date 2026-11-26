#!/usr/bin/env node

import { closeSync, existsSync, fstatSync, openSync, readSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { appendAuditRecord } from "./governance/audit-log.mjs";
import { readGovernanceConfig, resolveAutonomyMode, resolveAutonomyThresholds } from "./governance/config.mjs";
import {
  AUDITOR_AGENT_NAME,
  AUDITOR_ROLE_LABEL,
  AUDITOR_SESSION_MARKER,
  CHALLENGER_AGENT_NAME,
  CHALLENGER_ROLE_LABEL,
  CHALLENGER_SESSION_MARKER,
  GATE_TOOL_NAME,
  HANDOFF_TOOL_NAME,
  PENDING_CHALLENGER_DENY_REASON,
  READ_ONLY_ROLE_WRITE_DENY_REASON,
  RETHINK_UNVOTED_DENY_REASON,
  SUBAGENT_TOOL_NAME,
  WORKER_AGENT_NAME,
  WORKER_ROLE_LABEL,
  WORKER_SESSION_MARKER,
  WRITE_TOOL_NAMES,
  buildCircuitBreakerDenyReason,
} from "./governance/constants.mjs";
import { detectDestructiveEdit, normalizeWriteOperations } from "./governance/destructive-edit.mjs";
import { normalizeWorkspacePath, readFactLedger, resolveGitRootFast, snapshotWorkingTree } from "./governance/fact-ledger.mjs";
import {
  claimAutonomyTurnFlag,
  hasAutonomyTurnFlag,
  resolveEffectiveConversationKey,
  saveGateSnapshot,
} from "./governance/handoff-store.mjs";
import {
  isDirectExecution,
  parseHookPayload,
  pickPreferredTranscriptPath,
  resolvePluginDataDir,
  runHookCli,
} from "./hook-io.mjs";

const HSTACK_MCP_TOOL_RE = /^mcp_hstack_.*$/;
const GATE_TOOL_SUMMARY = "증거 기반 완료 검증 실행";
const HANDOFF_TOOL_SUMMARY = "팩트 증류 컨텍스트 핸드오프 처리";
const MAX_EXISTING_READ_BYTES = 2 * 1024 * 1024;
const CHALLENGER_GUIDANCE_LINE =
  "위 작업 경로의 실제 파일과 호출 관계를 직접 읽고 사용자의 유도 전제에 동조하지 않은 채 근거(`파일:줄`) 기반 반론과 지정 판정 태그로만 보고하라.";
const INJECTED_TAIL_LINE_RE =
  /^(?:작업 경로:|세션 기록 경로:|현재 턴 시작 스텝:|-\s*작업 디렉터리:|위 작업 경로의 실제 파일과 호출 관계를 직접 읽고)/;

function classifyManagedAgent(rawTypeName) {
  if (typeof rawTypeName !== "string") {
    return null;
  }
  const normalized = rawTypeName.trim();
  if (normalized === AUDITOR_AGENT_NAME || normalized === `hstack:${AUDITOR_AGENT_NAME}`) {
    return "auditor";
  }
  if (normalized === CHALLENGER_AGENT_NAME || normalized === `hstack:${CHALLENGER_AGENT_NAME}`) {
    return "challenger";
  }
  if (normalized === WORKER_AGENT_NAME || normalized === `hstack:${WORKER_AGENT_NAME}`) {
    return "worker";
  }
  return null;
}

const ROLE_MARKER_LINES = new Set([AUDITOR_SESSION_MARKER, CHALLENGER_SESSION_MARKER, WORKER_SESSION_MARKER]);

function isForgeableLine(line) {
  const trimmed = line.trim();
  return ROLE_MARKER_LINES.has(trimmed) || INJECTED_TAIL_LINE_RE.test(trimmed);
}

function hasRoleMarkerLine(promptText) {
  return typeof promptText === "string" && promptText.split(/\r?\n/).some((line) => ROLE_MARKER_LINES.has(line.trim()));
}

// Model-written role markers and injected-context lines are never trusted; only this hook writes them.
function stripForgeableLines(promptText) {
  if (typeof promptText !== "string") {
    return "";
  }
  return promptText
    .split(/\r?\n/)
    .filter((line) => !isForgeableLine(line))
    .join("\n")
    .trimEnd();
}

function buildInjectedPrompt(kind, existingPrompt, { cwd, transcriptPath, turnStartStepIndex }) {
  const base = stripForgeableLines(existingPrompt);
  const marker =
    kind === "auditor"
      ? AUDITOR_SESSION_MARKER
      : kind === "challenger"
        ? CHALLENGER_SESSION_MARKER
        : WORKER_SESSION_MARKER;
  const lines = [marker, `작업 경로: \`${cwd}\``];
  if (kind === "auditor" || kind === "challenger") {
    if (transcriptPath) {
      lines.push(`세션 기록 경로: \`${transcriptPath}\``);
    }
    if (typeof turnStartStepIndex === "number" && Number.isFinite(turnStartStepIndex)) {
      lines.push(`현재 턴 시작 스텝: \`${turnStartStepIndex}\``);
    }
  }
  if (kind === "challenger") {
    lines.push(CHALLENGER_GUIDANCE_LINE);
  }
  const block = lines.join("\n");
  return base.length === 0 ? block : `${base}\n\n${block}`;
}

function resolveTurnStartStepIndex(transcriptPath, cwd) {
  if (!transcriptPath) {
    return 0;
  }
  try {
    const ledger = readFactLedger(transcriptPath, cwd, "");
    return ledger.transcriptAvailable ? ledger.turnStartStepIndex : 0;
  } catch {
    return 0;
  }
}

function rewriteSubagentEntry(entry, { cwd, transcriptPath, getTurnStart }) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    return { matched: false, value: entry };
  }
  const kind = classifyManagedAgent(entry.TypeName ?? entry.typeName ?? entry.type_name);
  if (!kind) {
    const forgedKeys = ["Prompt", "prompt"].filter((key) => hasRoleMarkerLine(entry[key]));
    if (forgedKeys.length === 0) {
      return { matched: false, value: entry };
    }
    const value = { ...entry };
    for (const key of forgedKeys) {
      value[key] = stripForgeableLines(entry[key]);
    }
    return { matched: true, value };
  }
  const roleLabel =
    kind === "auditor"
      ? AUDITOR_ROLE_LABEL
      : kind === "challenger"
        ? CHALLENGER_ROLE_LABEL
        : WORKER_ROLE_LABEL;
  const promptKey = "Prompt" in entry || !("prompt" in entry) ? "Prompt" : "prompt";
  const roleKey = "Role" in entry || !("role" in entry) ? "Role" : "role";
  return {
    matched: true,
    value: {
      ...entry,
      [roleKey]: roleLabel,
      [promptKey]: buildInjectedPrompt(kind, entry[promptKey], {
        cwd,
        transcriptPath,
        turnStartStepIndex: kind === "auditor" || kind === "challenger" ? getTurnStart() : null,
      }),
    },
  };
}

function handleSubagentPreTool(toolCall, { cwd, transcriptPath }) {
  const args = toolCall.args && typeof toolCall.args === "object" && !Array.isArray(toolCall.args) ? toolCall.args : null;
  if (!args) {
    return { decision: "allow" };
  }

  let turnStartCache = null;
  const getTurnStart = () => {
    if (turnStartCache === null) {
      turnStartCache = resolveTurnStartStepIndex(transcriptPath, cwd);
    }
    return turnStartCache;
  };

  const arrayKey = Array.isArray(args.Subagents) ? "Subagents" : Array.isArray(args.subagents) ? "subagents" : "";
  if (arrayKey) {
    let matchedAny = false;
    const rewritten = args[arrayKey].map((entry) => {
      const res = rewriteSubagentEntry(entry, { cwd, transcriptPath, getTurnStart });
      if (res.matched) {
        matchedAny = true;
      }
      return res.value;
    });
    if (!matchedAny) {
      return { decision: "allow" };
    }
    return {
      decision: "allow",
      overwrite: {
        [arrayKey]: rewritten,
      },
    };
  }

  const singleRes = rewriteSubagentEntry(args, { cwd, transcriptPath, getTurnStart });
  if (!singleRes.matched) {
    return { decision: "allow" };
  }

  const overwrite = {};
  for (const key of ["Role", "role", "Prompt", "prompt"]) {
    if (singleRes.value[key] !== args[key]) {
      overwrite[key] = singleRes.value[key];
    }
  }
  return { decision: "allow", overwrite };
}

function readBoundedFileHead(absPath) {
  let fd = null;
  try {
    fd = openSync(absPath, "r");
    const size = fstatSync(fd).size;
    const toRead = Math.min(size, MAX_EXISTING_READ_BYTES);
    const buf = Buffer.allocUnsafe(toRead);
    let offset = 0;
    while (offset < toRead) {
      const n = readSync(fd, buf, offset, toRead - offset, offset);
      if (n <= 0) break;
      offset += n;
    }
    const text = buf.subarray(0, offset).toString("utf8");
    const avgLineCount = size > offset && offset > 0
      ? Math.ceil((text.split("\n").length / offset) * size)
      : text.split("\n").length;
    return { content: text, lineCount: avgLineCount };
  } finally {
    if (fd !== null) {
      try {
        closeSync(fd);
      } catch {
      }
    }
  }
}

function readExistingContentsMap(toolName, toolInput, cwd, gitRoot, readTextFile) {
  const ops = normalizeWriteOperations(toolName, toolInput, cwd, gitRoot);
  const contents = new Map();
  for (const op of ops) {
    const base = op.baseCwd || cwd || process.cwd();
    const candidateAbs = op.rawPath ? resolve(base, op.rawPath) : resolve(base, op.targetPath);
    let effectivePath = op.targetPath;
    try {
      if (existsSync(candidateAbs)) {
        const realAbs = realpathSync(candidateAbs);
        const normReal = normalizeWorkspacePath(realAbs, cwd, gitRoot);
        if (normReal) {
          effectivePath = normReal;
        }
      }
    } catch {
    }
    try {
      if (typeof readTextFile === "function") {
        const text = readTextFile(candidateAbs);
        contents.set(op.targetPath, typeof text === "string" ? { content: text, effectivePath } : null);
      } else if (existsSync(candidateAbs)) {
        const headInfo = readBoundedFileHead(candidateAbs);
        contents.set(op.targetPath, { content: headInfo.content, lineCount: headInfo.lineCount, effectivePath });
      } else {
        contents.set(op.targetPath, null);
      }
    } catch {
      contents.set(op.targetPath, null);
    }
  }
  return contents;
}

function analyzeChallengerState(ledger) {
  const allChallenges = Array.isArray(ledger?.turnPreflightChallenges) ? ledger.turnPreflightChallenges : [];
  const completed = allChallenges.filter(
    (entry) => typeof entry?.completedStepIndex === "number" && entry.completedStepIndex >= 0,
  );
  const pendingAsync = Number.isFinite(ledger?.pendingAsyncChallenges) ? ledger.pendingAsyncChallenges : 0;
  if (completed.length === 0) {
    return { completed, unvotedRethink: false, hasValidVerdict: false, pendingAsync };
  }
  const votes = Array.isArray(ledger?.turnUserVotes) ? ledger.turnUserVotes : [];
  const hasVoteAfter = (challenge) =>
    votes.some(
      (vote) =>
        vote &&
        vote.answered === true &&
        vote.errored !== true &&
        typeof vote.completedStepIndex === "number" &&
        vote.completedStepIndex > challenge.completedStepIndex,
    );
  const unvotedRethink = completed.some((ch) => ch.verdict === "RETHINK" && !hasVoteAfter(ch));
  const hasValidVerdict = completed.some(
    (ch) => ch.verdict === "PROCEED" || ch.verdict === "CONDITIONAL" || ch.verdict === "RETHINK",
  );
  return { completed, unvotedRethink, hasValidVerdict, pendingAsync };
}

function handleWriteToolCircuitBreaker(toolCall, { cwd, transcriptPath, conversationId, options }) {
  const dataDir = options?.dataDir ?? resolvePluginDataDir();
  const gitRoot = options?.gitRoot ?? resolveGitRootFast(cwd);
  const ledger =
    options?.ledger ??
    (transcriptPath ? readFactLedger(transcriptPath, cwd, gitRoot) : null);
  const sessionRole = ledger?.transcriptAvailable ? ledger.sessionRole : "main";
  if (sessionRole === "auditor" || sessionRole === "challenger") {
    return { decision: "deny", reason: READ_ONLY_ROLE_WRITE_DENY_REASON };
  }
  if (sessionRole !== "main") {
    return { decision: "allow" };
  }

  const governanceConfig = options?.governanceConfig ?? readGovernanceConfig(dataDir);
  const autonomyMode = resolveAutonomyMode(dataDir, governanceConfig);
  if (autonomyMode !== "smart") {
    return { decision: "allow" };
  }

  const turnStartStepIndex = ledger?.transcriptAvailable ? ledger.turnStartStepIndex : 0;
  const { hasValidVerdict, unvotedRethink, pendingAsync } = analyzeChallengerState(ledger);

  if (unvotedRethink) {
    if (options?.skipAuditLog !== true) {
      appendAuditRecord(
        {
          ts: new Date().toISOString(),
          event: "autonomy_event",
          eventType: "autonomy_event",
          kind: "circuit_breaker",
          subkind: "rethink_unvoted_block",
          conversationId,
          turnStartStepIndex,
          toolName: toolCall.name,
          reasons: ["rethink_unvoted"],
        },
        dataDir,
      );
    }
    return {
      decision: "deny",
      reason: RETHINK_UNVOTED_DENY_REASON,
    };
  }

  if (pendingAsync > 0) {
    return {
      decision: "deny",
      reason: PENDING_CHALLENGER_DENY_REASON,
    };
  }

  if (hasValidVerdict) {
    return { decision: "allow" };
  }

  const effectiveCid = resolveEffectiveConversationKey(conversationId, cwd);
  const turnKey = `${effectiveCid}:${turnStartStepIndex}`;
  if (hasAutonomyTurnFlag({ conversationId: effectiveCid, flagName: "circuitBreakerTurns", turnKey, dataDir })) {
    return { decision: "allow" };
  }

  const thresholds = resolveAutonomyThresholds(dataDir, governanceConfig);
  const existingContentsByPath =
    options?.existingContentsByPath ??
    readExistingContentsMap(toolCall.name, toolCall.args, cwd, gitRoot, options?.readTextFile);

  const inspection = detectDestructiveEdit({
    toolName: toolCall.name,
    toolInput: toolCall.args,
    cwd,
    gitRoot,
    existingContentsByPath,
    config: governanceConfig,
    thresholds,
  });

  if (!inspection.destructive) {
    return { decision: "allow" };
  }

  const claimed = claimAutonomyTurnFlag({
    conversationId: effectiveCid,
    flagName: "circuitBreakerTurns",
    turnKey,
    dataDir,
  });
  if (claimed === false) {
    return { decision: "allow" };
  }

  if (options?.skipAuditLog !== true) {
    appendAuditRecord(
      {
        ts: new Date().toISOString(),
        event: "autonomy_event",
        eventType: "autonomy_event",
        kind: "circuit_breaker",
        ...(claimed === null ? { subkind: "lock_contended_fail_closed" } : {}),
        conversationId: effectiveCid,
        turnStartStepIndex,
        toolName: toolCall.name,
        targetPath: inspection.targetPath,
        reasons: inspection.reasons,
        deletedLines: inspection.deletedLines,
        removedPrimitives: inspection.removedPrimitives,
      },
      dataDir,
    );
  }

  return {
    decision: "deny",
    reason: buildCircuitBreakerDenyReason(inspection),
  };
}

export function handlePreToolGate(stdinText, options = {}) {
  const payload = parseHookPayload(stdinText, "PreToolUse");
  const toolCall = payload?.toolCall ?? payload?.tool_call;
  if (!payload || !toolCall || typeof toolCall !== "object") {
    return { decision: "allow" };
  }

  const toolName = typeof toolCall.name === "string" ? toolCall.name : "";
  const rawTranscriptPath = payload.transcriptPath ?? payload.transcript_path;
  const transcriptPath = pickPreferredTranscriptPath(rawTranscriptPath);
  const rawConversationId = payload.conversationId ?? payload.conversation_id;
  const conversationId = typeof rawConversationId === "string" ? rawConversationId.trim() : "";
  const cwd = typeof payload.cwd === "string" ? payload.cwd.trim() : "";

  if (toolName === SUBAGENT_TOOL_NAME) {
    return handleSubagentPreTool(toolCall, { cwd, transcriptPath });
  }

  if (WRITE_TOOL_NAMES.has(toolName)) {
    return handleWriteToolCircuitBreaker(toolCall, { cwd, transcriptPath, conversationId, options });
  }

  if (!HSTACK_MCP_TOOL_RE.test(toolName)) {
    return { decision: "allow" };
  }

  // Stop dates later shell-made tree changes against what verify_completion saw.
  if (toolName === GATE_TOOL_NAME && cwd) {
    saveGateSnapshot({
      conversationId: resolveEffectiveConversationKey(conversationId, cwd),
      snapshot: snapshotWorkingTree(cwd),
      dataDir: options?.dataDir ?? resolvePluginDataDir(),
    });
  }

  const toolSummary = toolName === HANDOFF_TOOL_NAME ? HANDOFF_TOOL_SUMMARY : GATE_TOOL_SUMMARY;

  return {
    decision: "auto_approve",
    overwrite: {
      toolSummary,
      _session: {
        conversationId,
        transcriptPath,
        cwd,
      },
    },
  };
}

if (isDirectExecution(import.meta.url)) {
  runHookCli(handlePreToolGate, { decision: "allow" });
}
