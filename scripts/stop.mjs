#!/usr/bin/env node

import { appendAuditRecord } from "./governance/audit-log.mjs";
import { PASSING_VERDICTS, isExemptDocOrAssetPath } from "./governance/constants.mjs";
import { readFactLedger, readGitLedger, snapshotWorkingTree } from "./governance/fact-ledger.mjs";
import { readTurnSnapshot, resolveEffectiveConversationKey } from "./governance/handoff-store.mjs";
import { isDirectExecution, loadHookContext, runHookCli } from "./hook-io.mjs";
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

function sameFileSignature(a, b) {
  return Array.isArray(a) && Array.isArray(b) ? a[0] === b[0] && a[1] === b[1] : a === b;
}

// Shell commands (sed -i, redirects) write files no write tool records; diff the tree against the turn-start snapshot.
function mergeShellWrittenFiles(ledger, payload, cwd) {
  const shellExecs = ledger.turnExecutions.filter((exec) => !exec.toolName);
  if (ledger.sessionRole !== "main" || shellExecs.length === 0 || !cwd) {
    return;
  }
  const rawConversationId = payload.conversationId ?? payload.conversation_id;
  const baseline = readTurnSnapshot({
    conversationId: resolveEffectiveConversationKey(typeof rawConversationId === "string" ? rawConversationId : "", cwd),
    turnStartStepIndex: ledger.turnStartStepIndex,
  });
  const current = baseline ? snapshotWorkingTree(cwd) : null;
  if (!current || current.gitRoot !== baseline.gitRoot) {
    return;
  }
  const writers = shellExecs.filter((exec) => exec.kind !== "read_only");
  const writeStep = (writers.length > 0 ? writers : shellExecs).at(-1).stepIndex;
  for (const [relPath, signature] of Object.entries(current.files)) {
    if ((relPath in baseline.files && sameFileSignature(baseline.files[relPath], signature)) || isExemptDocOrAssetPath(relPath)) {
      continue;
    }
    ledger.turnWrittenFiles.add(relPath);
    ledger.turnCodeWrittenFiles.add(relPath);
    ledger.lastWriteStepIndex = Math.max(ledger.lastWriteStepIndex, writeStep);
    ledger.lastCodeWriteStepIndex = Math.max(ledger.lastCodeWriteStepIndex, writeStep);
  }
}

export function handleStop(stdinText, readTextFile) {
  const context = loadHookContext(stdinText, "Stop", readTextFile);
  if (!context || context.steps.length === 0) {
    return {};
  }
  const { payload, steps, transcriptPath } = context;

  const rawTerminationReason = payload.terminationReason ?? payload.termination_reason;
  const terminationReason = typeof rawTerminationReason === "string" ? rawTerminationReason.trim() : "";
  if (terminationReason !== "NO_TOOL_CALL") {
    return {};
  }

  const executionNum = Number(payload.executionNum ?? payload.execution_num ?? 0);
  if (Number.isFinite(executionNum) && executionNum >= GLOBAL_STOP_EXECUTION_CAP) {
    if (typeof readTextFile !== "function") {
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
  let ledger = null;
  if (typeof readTextFile !== "function" && transcriptPath.length > 0) {
    const gitLedger = cwd.length > 0 ? readGitLedger(cwd) : { gitRoot: "" };
    ledger = readFactLedger(transcriptPath, cwd, gitLedger.gitRoot || "");
    if (ledger.transcriptAvailable) {
      mergeShellWrittenFiles(ledger, payload, cwd);
    }
  }

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
      ledger.turnWrittenFiles.size > 0 &&
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
