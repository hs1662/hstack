#!/usr/bin/env node

import { statSync } from "node:fs";
import { join } from "node:path";

import { appendAuditRecord } from "./governance/audit-log.mjs";
import { PASSING_VERDICTS, isExemptDocOrAssetPath } from "./governance/constants.mjs";
import {
  listCommittedPaths,
  readFactLedgerAndSteps,
  readGitLedger,
  resolveGitRootFast,
  snapshotWorkingTree,
} from "./governance/fact-ledger.mjs";
import { readTurnSnapshot, resolveEffectiveConversationKey } from "./governance/handoff-store.mjs";
import { isDirectExecution, loadHookContext, parseHookPayload, payloadTranscriptPath, runHookCli } from "./hook-io.mjs";
import { DRIFT_MARKER, GATE_STOP_MARKER, decideStopAction } from "./transcript.mjs";

const GLOBAL_STOP_EXECUTION_CAP = 2;

const DUAL_VIOLATION_REASON = `${GATE_STOP_MARKER} ${DRIFT_MARKER}[대상:응답] 이번 턴에서 파일을 수정했으나 완료 검증 도구를 통과하지 않았고 직전 최종 응답도 영어로 작성되었다. 먼저 내장 완료 검증 도구를 호출해 변경 사항과 검증 결과를 대조받아 통과한 뒤, 최종 응답을 자연스러운 한국어 문장으로 다시 작성하라.`;

const GATE_ONLY_REASON = `${GATE_STOP_MARKER} 이번 턴에서 파일을 수정했으나 수정 이후 완료 검증 도구를 통과한 기록이 없다. 지금 즉시 내장 완료 검증 도구를 호출해 수정 파일과 검증 실행 결과를 대조받아 통과한 뒤 최종 보고를 작성하라.`;

function tryLogStopTelemetry(payload, info) {
  try {
    const rawConversationId = payload.conversationId ?? payload.conversation_id;
    const conversationId = typeof rawConversationId === "string" ? rawConversationId.trim() : "";
    appendAuditRecord({
      ts: new Date().toISOString(),
      event: "stop_decision",
      conversationId,
      decision: info.decision,
      gateViolation: info.gateViolation,
      gateBlockedThisTurn: info.gateBlockedThisTurn,
      langDrift: info.langDrift,
      executionNum: info.executionNum,
    });
  } catch {
  }
}

// The [mtimeMs, size] signature snapshotWorkingTree records, or null for a missing file.
function statSignature(gitRoot, relPath) {
  try {
    const st = statSync(join(gitRoot, relPath));
    return [st.mtimeMs, st.size];
  } catch {
    return null;
  }
}

function sameFileSignature(a, b) {
  return Array.isArray(a) && Array.isArray(b) ? a[0] === b[0] && a[1] === b[1] : a === b;
}

// Shell commands (sed -i, redirects) write files no write tool records; diff the tree against the turn-start snapshot.
// Returns true when a possibly writing shell command ran in a git tree that could not be diffed (fail closed).
function mergeShellWrittenFiles(ledger, payload, cwd) {
  const shellExecs = ledger.turnExecutions.filter((exec) => !exec.toolName);
  if (ledger.sessionRole !== "main" || shellExecs.length === 0 || !cwd) {
    return false;
  }
  const writers = shellExecs.filter((exec) => exec.kind !== "read_only");
  const writeStep = (writers.length > 0 ? writers : shellExecs).at(-1).stepIndex;
  const rawConversationId = payload.conversationId ?? payload.conversation_id;
  const baseline = readTurnSnapshot({
    conversationId: resolveEffectiveConversationKey(typeof rawConversationId === "string" ? rawConversationId : "", cwd),
    turnStartStepIndex: ledger.turnStartStepIndex,
  });
  const current = baseline ? snapshotWorkingTree(cwd) : null;
  // Commits made this turn leave a clean tree, so the files they touched count as changed too.
  const committedSince = (head) =>
    head === null || head === current.head ? new Set() : listCommittedPaths(current.gitRoot, head, current.head);
  const sinceTurn = current && current.gitRoot === baseline.gitRoot ? committedSince(baseline.head) : null;
  const sinceGate = sinceTurn && baseline.gate ? committedSince(baseline.gate.head) : new Set();
  if (!sinceTurn || !sinceGate) {
    if (writers.length === 0 || !resolveGitRootFast(cwd)) {
      return false;
    }
    ledger.lastWriteStepIndex = Math.max(ledger.lastWriteStepIndex, writeStep);
    return true;
  }
  // A committed file is clean now, so its signature comes from disk; one that still matches the snapshot was
  // dirty before the turn and only committed, not edited.
  const changedSince = (files, committed, relPath) => {
    const now = relPath in current.files ? current.files[relPath] : committed.has(relPath) ? statSignature(current.gitRoot, relPath) : undefined;
    return relPath in files ? !sameFileSignature(files[relPath], now) : now !== undefined;
  };
  // A change the verify_completion snapshot did not see happened after it, whatever the command looked like.
  const lastGateStep = ledger.turnGateAttempts.at(-1)?.stepIndex ?? -1;
  const postGateShell = baseline.gate ? shellExecs.filter((exec) => exec.stepIndex > lastGateStep) : [];
  for (const relPath of new Set([...Object.keys(current.files), ...Object.keys(baseline.files), ...sinceTurn])) {
    if (!changedSince(baseline.files, sinceTurn, relPath) || isExemptDocOrAssetPath(relPath)) {
      continue;
    }
    const step =
      postGateShell.length > 0 && changedSince(baseline.gate.files, sinceGate, relPath) ? postGateShell.at(-1).stepIndex : writeStep;
    ledger.turnWrittenFiles.add(relPath);
    ledger.turnCodeWrittenFiles.add(relPath);
    ledger.lastWriteStepIndex = Math.max(ledger.lastWriteStepIndex, step);
    ledger.lastCodeWriteStepIndex = Math.max(ledger.lastCodeWriteStepIndex, step);
  }
  return false;
}

export function handleStop(stdinText, readTextFile) {
  const payload = parseHookPayload(stdinText, "Stop");
  if (!payload) {
    return {};
  }
  const rawTerminationReason = payload.terminationReason ?? payload.termination_reason;
  const terminationReason = typeof rawTerminationReason === "string" ? rawTerminationReason.trim() : "";
  if (terminationReason !== "NO_TOOL_CALL") {
    return {};
  }

  const executionNum = Number(payload.executionNum ?? payload.execution_num ?? 0);
  if (Number.isFinite(executionNum) && executionNum >= GLOBAL_STOP_EXECUTION_CAP) {
    if (typeof readTextFile !== "function" && loadHookContext(stdinText, "Stop", readTextFile)?.steps.length > 0) {
      tryLogStopTelemetry(payload, {
        decision: "allow_cap",
        gateViolation: false,
        gateBlockedThisTurn: false,
        langDrift: false,
        executionNum,
      });
    }
    return {};
  }

  const cwd = typeof payload.cwd === "string" ? payload.cwd.trim() : "";
  const transcriptPath = payloadTranscriptPath(payload);
  let ledger = null;
  let steps;
  if (typeof readTextFile !== "function" && transcriptPath.length > 0) {
    const gitLedger = cwd.length > 0 ? readGitLedger(cwd) : { gitRoot: "" };
    ({ ledger, steps } = readFactLedgerAndSteps(transcriptPath, cwd, gitLedger.gitRoot || ""));
  } else {
    steps = loadHookContext(stdinText, "Stop", readTextFile)?.steps ?? [];
  }
  if (steps.length === 0) {
    return {};
  }
  const undiffableShellWrite = Boolean(ledger?.transcriptAvailable && mergeShellWrittenFiles(ledger, payload, cwd));

  const isReadOnlyGovernanceRole = ledger?.sessionRole === "auditor" || ledger?.sessionRole === "challenger";
  const hasPendingAsyncAuditor = Boolean(ledger && ledger.pendingAsyncAuditsAfterLastWrite > 0);
  const hasPendingAsyncChallenges = Boolean(ledger && ledger.pendingAsyncChallengesAfterLastWrite > 0);
  const gateBlockedThisTurn = Boolean(ledger?.gateBlockedThisTurn);
  const hasPassingPostWriteGate = Boolean(
    ledger &&
      ledger.turnGateAttempts.some(
        (attempt) => attempt.stepIndex > ledger.lastWriteStepIndex && PASSING_VERDICTS.has(attempt.verdict),
      ),
  );
  const gateViolation = Boolean(
    !isReadOnlyGovernanceRole &&
      !hasPendingAsyncAuditor &&
      !hasPendingAsyncChallenges &&
      ledger &&
      ledger.transcriptAvailable &&
      (ledger.turnWrittenFiles.size > 0 || undiffableShellWrite) &&
      !hasPassingPostWriteGate,
  );

  const langDecision = decideStopAction(steps, {
    lastUserInput: payload.lastUserInput ?? payload.last_user_input,
    continuationActive: (payload.continuationActive ?? payload.continuation_active) === true,
    terminationReason,
  });
  const langDrift = langDecision.action === "continue";
  const shouldBlockGate = gateViolation && !gateBlockedThisTurn;

  let result = {};
  let telemetryDecision = "allow";

  if (shouldBlockGate && langDrift) {
    telemetryDecision = "continue_dual";
    result = {
      decision: "continue",
      reason: DUAL_VIOLATION_REASON,
    };
  } else if (shouldBlockGate) {
    telemetryDecision = "continue_gate";
    result = {
      decision: "continue",
      reason: GATE_ONLY_REASON,
    };
  } else if (langDrift) {
    telemetryDecision = "continue_lang";
    result = langDecision.reasonMessage
      ? { decision: "continue", reason: langDecision.reasonMessage }
      : { decision: "continue" };
  }

  if (typeof readTextFile !== "function" && result.decision === "continue") {
    tryLogStopTelemetry(payload, {
      decision: telemetryDecision,
      gateViolation,
      gateBlockedThisTurn,
      langDrift,
      executionNum: Number.isFinite(executionNum) ? executionNum : 0,
    });
  }

  return result;
}

if (isDirectExecution(import.meta.url)) {
  runHookCli(handleStop);
}
