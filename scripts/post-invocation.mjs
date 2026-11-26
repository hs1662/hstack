#!/usr/bin/env node

import { appendAuditRecord } from "./governance/audit-log.mjs";
import { readGovernanceConfig, resolveAutonomyMode, resolveAutonomyThresholds } from "./governance/config.mjs";
import { DEFAULT_POLLUTION_THRESHOLDS, buildAutoHandoffSystemMessage } from "./governance/constants.mjs";
import { detectSessionRoleFromHeaderSteps, readFactLedger, readFactLedgerAndSteps } from "./governance/fact-ledger.mjs";
import {
  claimAutonomyTurnFlag,
  markPreflightChallengeLogged,
  resolveEffectiveConversationKey,
  updateSessionPollutionState,
} from "./governance/handoff-store.mjs";
import { evaluateThrashing } from "./governance/thrashing-detector.mjs";
import {
  isDirectExecution,
  loadHookContext,
  parseHookPayload,
  payloadTranscriptPath,
  readTranscriptSteps,
  resolvePluginDataDir,
  runHookCli,
} from "./hook-io.mjs";
import { decideHookAction } from "./transcript.mjs";

export { readTranscriptSteps };

function tryLogCompletedPreflightChallenges(conversationId, ledger, dataDir) {
  if (!ledger?.transcriptAvailable || ledger.sessionRole !== "main") {
    return;
  }
  const challenges = Array.isArray(ledger.turnPreflightChallenges) ? ledger.turnPreflightChallenges : [];
  const completed = challenges.filter(
    (entry) => typeof entry?.completedStepIndex === "number" && entry.completedStepIndex >= 0,
  );
  if (completed.length === 0) {
    return;
  }
  const turnUserVotes = Array.isArray(ledger.turnUserVotes) ? ledger.turnUserVotes : [];
  const codeWritten = ledger.turnCodeWrittenFiles.size > 0;

  for (const challenge of completed) {
    const voted = turnUserVotes.some(
      (vote) =>
        vote &&
        vote.answered === true &&
        vote.errored !== true &&
        typeof vote.completedStepIndex === "number" &&
        vote.completedStepIndex > challenge.completedStepIndex,
    );
    const launchIdx =
      typeof challenge.launchedStepIndex === "number" ? challenge.launchedStepIndex : challenge.completedStepIndex;
    const slotIdx = typeof challenge.slotIndex === "number" ? challenge.slotIndex : 0;
    const votePhase = voted ? "voted" : "unvoted";
    let shouldLog = !conversationId;
    if (!shouldLog) {
      // A session lock timeout skips this dedup write only, never the later hook stages.
      try {
        shouldLog = markPreflightChallengeLogged({
          conversationId,
          dedupKey: `${conversationId}:${ledger.turnStartStepIndex}:${launchIdx}:${slotIdx}:${votePhase}`,
          dataDir,
        });
      } catch {
        shouldLog = false;
      }
    }
    if (!shouldLog) {
      continue;
    }
    appendAuditRecord(
      {
        ts: new Date().toISOString(),
        event: "preflight_complete",
        eventType: "preflight_complete",
        conversationId,
        turnStartStepIndex: ledger.turnStartStepIndex,
        mode: challenge.mode === "auto" ? "auto" : "manual",
        verdict: challenge.verdict,
        voted,
        codeWritten,
        challengeStepIndex: challenge.completedStepIndex,
      },
      dataDir,
    );
  }
}

function evaluateAndLogPostInvocation(context, decision, options = {}) {
  let autoHandoffMessage = null;
  try {
    const { payload, transcriptPath, steps } = context;
    const dataDir = options.dataDir ?? resolvePluginDataDir();
    const rawConversationId = payload.conversationId ?? payload.conversation_id;
    const conversationId = typeof rawConversationId === "string" ? rawConversationId.trim() : "";
    const latestStep = steps[steps.length - 1];
    const cwd = typeof payload.cwd === "string" ? payload.cwd.trim() : "";
    const ledger = options.ledger ?? (transcriptPath ? readFactLedger(transcriptPath, cwd, "") : null);
    const sessionRole = ledger?.transcriptAvailable ? ledger.sessionRole : detectSessionRoleFromHeaderSteps(steps);
    const tokens = ledger?.latestTokens ?? { inputTokens: null, cacheReadTokens: null, outputTokens: null };
    const cfg = options.governanceConfig ?? readGovernanceConfig(dataDir);
    const autonomyMode = resolveAutonomyMode(dataDir, cfg);

    let pollutionState = null;
    if (sessionRole !== "auditor" && sessionRole !== "challenger" && conversationId) {
      const thresholds = {
        ...DEFAULT_POLLUTION_THRESHOLDS,
        ...(cfg?.pollutionThresholds && typeof cfg.pollutionThresholds === "object" ? cfg.pollutionThresholds : {}),
      };
      try {
        pollutionState = updateSessionPollutionState({
          conversationId,
          turnStartStepIndex: ledger?.turnStartStepIndex ?? 0,
          inputTokens: tokens.inputTokens,
          failedExecutionsInTurn: ledger?.turnFailedExecutionCount ?? 0,
          maxSingleFileEdits: ledger?.maxSingleFileEdits ?? 0,
          thresholds,
          dataDir,
        });
      } catch {
        // Lock timeout: keep going so preflight logging, autonomy and the audit record still run.
      }
    }

    if (sessionRole === "main" && ledger) {
      tryLogCompletedPreflightChallenges(conversationId, ledger, dataDir);
    }

    if (
      autonomyMode === "smart" &&
      sessionRole === "main" &&
      ledger?.transcriptAvailable &&
      !ledger.turnAutoHandoffTriggered &&
      !ledger.turnWorkerCompleted
    ) {
      const autonomyThresholds = resolveAutonomyThresholds(dataDir, cfg);
      const thrashResult = evaluateThrashing({
        turnVerifyFailures: ledger.turnVerifyFailures ?? 0,
        turnConsecutiveVerifyFailures: ledger.turnConsecutiveVerifyFailures ?? 0,
        maxSameFileEdits: ledger.maxSingleFileEdits ?? 0,
        mostEditedFile: ledger.mostEditedFile ?? "",
        inputTokens: tokens.inputTokens,
        thresholds: autonomyThresholds,
      });
      if (thrashResult.thrashing) {
        const effectiveCid = resolveEffectiveConversationKey(conversationId, cwd);
        const turnKey = `${effectiveCid}:${ledger.turnStartStepIndex}`;
        const claimed = claimAutonomyTurnFlag({
          conversationId: effectiveCid,
          flagName: "autoHandoffTurns",
          turnKey,
          dataDir,
        });
        if (claimed === true) {
          appendAuditRecord(
            {
              ts: new Date().toISOString(),
              event: "autonomy_event",
              eventType: "autonomy_event",
              kind: "auto_handoff",
              conversationId,
              turnStartStepIndex: ledger.turnStartStepIndex,
              reasons: thrashResult.reasons,
              turnVerifyFailures: thrashResult.summary.turnVerifyFailures,
              maxSameFileEdits: thrashResult.summary.maxSameFileEdits,
              inputTokens: thrashResult.summary.inputTokens,
            },
            dataDir,
          );
          autoHandoffMessage = buildAutoHandoffSystemMessage({
            reasons: thrashResult.reasons,
            turnVerifyFailures: thrashResult.summary.turnVerifyFailures,
            maxSameFileEdits: thrashResult.summary.maxSameFileEdits,
            mostEditedFile: thrashResult.summary.mostEditedFile,
            inputTokens: thrashResult.summary.inputTokens,
          });
        }
      }
    }

    appendAuditRecord(
      {
        ts: new Date().toISOString(),
        event: "post_invocation",
        conversationId,
        stepCount: steps.length,
        latestStepIndex: typeof latestStep?.stepIndex === "number" ? latestStep.stepIndex : null,
        langAction: decision.action,
        langReason: decision.reason ?? (decision.action === "inject" ? "drifted" : "ok"),
        driftedFields: Array.isArray(decision.driftedFields) ? decision.driftedFields : [],
        pollutionAlert: Boolean(pollutionState?.pollutionAlert),
        metrics: {
          inputTokens: tokens.inputTokens,
          cacheReadTokens: tokens.cacheReadTokens,
          outputTokens: tokens.outputTokens,
        },
      },
      dataDir,
    );
  } catch {
  }
  return autoHandoffMessage;
}

// One transcript pass yields both the drift steps and the ledger the audit stage needs.
function loadContextWithLedger(stdinText) {
  const payload = parseHookPayload(stdinText, "PostInvocation");
  if (!payload) return null;
  const transcriptPath = payloadTranscriptPath(payload);
  if (!transcriptPath) return { payload, transcriptPath, steps: [] };
  const cwd = typeof payload.cwd === "string" ? payload.cwd.trim() : "";
  return { payload, transcriptPath, ...readFactLedgerAndSteps(transcriptPath, cwd, "") };
}

export function handlePostInvocation(stdinText, readTextFileOrOptions) {
  const isFn = typeof readTextFileOrOptions === "function";
  const readTextFile = isFn ? readTextFileOrOptions : readTextFileOrOptions?.readTextFile;
  let options = isFn ? {} : (readTextFileOrOptions ?? {});

  const shareLedger = !isFn && !readTextFile && !options.ledger;
  const context = shareLedger ? loadContextWithLedger(stdinText) : loadHookContext(stdinText, "PostInvocation", readTextFile);
  if (context?.ledger) {
    options = { ...options, ledger: context.ledger };
  }
  if (!context || context.steps.length === 0) {
    return {};
  }
  const { payload, steps } = context;

  const rawLastUserInput = payload.lastUserInput ?? payload.last_user_input;
  const langOptions = typeof rawLastUserInput === "string" ? { lastUserInput: rawLastUserInput } : {};
  const decision = decideHookAction(steps, langOptions);

  let autoHandoffMessage = null;
  if (!isFn) {
    autoHandoffMessage = evaluateAndLogPostInvocation(context, decision, options);
  }

  const injectSteps = [];
  if (decision.action === "inject") {
    injectSteps.push({
      systemMessage: {
        systemMessage: decision.message,
      },
    });
  }
  if (autoHandoffMessage) {
    injectSteps.push({
      systemMessage: {
        systemMessage: autoHandoffMessage,
      },
    });
  }

  if (injectSteps.length === 0) {
    return {};
  }

  return { injectSteps };
}

if (isDirectExecution(import.meta.url)) {
  runHookCli(handlePostInvocation);
}
