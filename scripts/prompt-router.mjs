#!/usr/bin/env node

import { appendAuditRecord } from "./governance/audit-log.mjs";
import { readGovernanceConfig, resolveAutonomyMode } from "./governance/config.mjs";
import {
  DEFAULT_POLLUTION_THRESHOLDS,
  KOREAN_THINKING_ANCHOR_MESSAGE,
  PROMPT_ROUTE_SYSTEM_MESSAGE,
} from "./governance/constants.mjs";
import { detectSessionRoleFromUserInput, readTurnLedger, snapshotWorkingTree } from "./governance/fact-ledger.mjs";
import {
  claimAutonomyTurnFlag,
  readSessionState,
  resolveEffectiveConversationKey,
  saveTurnSnapshot,
} from "./governance/handoff-store.mjs";
import {
  isDirectExecution,
  parseHookPayload,
  pickPreferredTranscriptPath,
  resolvePluginDataDir,
  runHookCli,
} from "./hook-io.mjs";

const SLASH_COMMAND_BYPASS_RE = /\/(?:hstack:)?hstack-(?:preflight|handoff)\b/i;

const SAFETY_TARGET_RE =
  /(?:timingSafeEqual|파일\s*잠금|락\s*파일|withFileLock|withSessionLock|lock|임시\s*파일(?:\s*rename)?|원자적\s*교체|만료\s*(?:시간\s*)?검증|서명\s*검증|권한\s*검증|입력\s*검증|인증\s*검증|CSRF|하위\s*호환|폴백|fallback|legacy)/i;
const SAFETY_REMOVAL_ACTION_RE = /(?:빼|제거|삭제|걷어내|단순화|바꾸|바꿔|교체|끄|생략|없이)/;
const MASSIVE_ARCH_RE =
  /(?:전면\s*리팩터링|아키텍처\s*전면\s*교체|메모리\s*(?:Map|객체)?\s*캐시로\s*(?:다\s*)?바꾸|이벤트\s*버스|플러그인\s*구조|DI\s*컨테이너|DB\s*계약|API\s*계약\s*파손|스키마\s*전면\s*변경)/i;

const LEADING_REVIEW_CONTEXT_RE =
  /(?:깔끔하지\s*않|맞지|낫지\s*않|괜찮을까|어떨까|바꾸자|바꿔\s*줘|걷어내자|빼고|설계\s*검토|타당성(?:만)?\s*검토|단순화해서|바로\s*수정해\s*줘)/;

export function shouldAutoChallengePrompt(promptText) {
  if (typeof promptText !== "string") {
    return { matched: false, signals: [] };
  }
  const trimmed = promptText.trim();
  if (trimmed.length === 0 || SLASH_COMMAND_BYPASS_RE.test(trimmed)) {
    return { matched: false, signals: [] };
  }

  const signals = [];
  if (SAFETY_TARGET_RE.test(trimmed) && SAFETY_REMOVAL_ACTION_RE.test(trimmed)) {
    signals.push("safety_removal_proposal");
  }
  if (MASSIVE_ARCH_RE.test(trimmed)) {
    signals.push("architecture_overhaul_proposal");
  }

  if (signals.length === 0 || !LEADING_REVIEW_CONTEXT_RE.test(trimmed)) {
    return { matched: false, signals: [] };
  }

  signals.push("leading_or_design_review_context");
  return { matched: true, signals };
}

export function handlePreInvocation(stdinText, options = {}) {
  const payload = parseHookPayload(stdinText, "PreInvocation");
  if (!payload) {
    return {};
  }

  const rawInv = payload.invocationNum ?? payload.invocation_num;
  const invocationNum = rawInv === undefined || rawInv === null || rawInv === "" ? 0 : Number(rawInv);
  if (Number.isFinite(invocationNum) && invocationNum > 0) {
    return {};
  }

  const dataDir = options?.dataDir ?? resolvePluginDataDir();
  const rawConversationId = payload.conversationId ?? payload.conversation_id;
  const conversationId = typeof rawConversationId === "string" ? rawConversationId.trim() : "";
  const cwd = typeof payload.cwd === "string" && payload.cwd.trim().length > 0 ? payload.cwd : "";
  const transcriptPath = pickPreferredTranscriptPath(payload.transcriptPath ?? payload.transcript_path);
  const effectiveCid = resolveEffectiveConversationKey(conversationId, cwd);

  const ledger =
    options?.ledger ??
    (transcriptPath ? readTurnLedger(transcriptPath, cwd, "") : null);
  const turnStartStepIndex = ledger?.transcriptAvailable ? ledger.turnStartStepIndex : 0;

  // Turn-start baseline so Stop can see files that shell commands change during this turn.
  if (cwd && ledger?.transcriptAvailable) {
    saveTurnSnapshot({ conversationId: effectiveCid, turnStartStepIndex, snapshot: snapshotWorkingTree(cwd), dataDir });
  }

  const governanceConfig = options?.governanceConfig ?? readGovernanceConfig(dataDir);
  const rawPrompt = payload.lastUserInput ?? payload.last_user_input;
  const sessionRole = ledger?.transcriptAvailable
    ? ledger.sessionRole
    : typeof rawPrompt === "string"
      ? detectSessionRoleFromUserInput(rawPrompt)
      : "main";
  const turnKey = `${effectiveCid}:${turnStartStepIndex}`;
  const injectSteps = [];

  if (sessionRole === "main") {
    const sessionState = conversationId ? readSessionState(conversationId, dataDir) : null;
    const rawThresholds = governanceConfig?.pollutionThresholds;
    const threshold =
      rawThresholds && typeof rawThresholds === "object" && Number.isFinite(rawThresholds.inputTokensWarning)
        ? rawThresholds.inputTokensWarning
        : DEFAULT_POLLUTION_THRESHOLDS.inputTokensWarning;
    const totalContextTokens = (ledger?.latestTokens?.inputTokens ?? 0) + (ledger?.latestTokens?.cacheReadTokens ?? 0);
    const isHighContext = Boolean(sessionState?.pollutionAlert) || totalContextTokens >= threshold;
    if (isHighContext) {
      const claimedAnchor = claimAutonomyTurnFlag({
        conversationId: effectiveCid,
        flagName: "koreanAnchorTurns",
        turnKey,
        dataDir,
      });
      if (claimedAnchor === true) {
        injectSteps.push({
          systemMessage: {
            systemMessage: KOREAN_THINKING_ANCHOR_MESSAGE,
          },
        });
      }
    }
  }

  if (resolveAutonomyMode(dataDir, governanceConfig) !== "smart") {
    return injectSteps.length > 0 ? { injectSteps } : {};
  }

  const evaluation = shouldAutoChallengePrompt(rawPrompt);
  if (!evaluation.matched) {
    return injectSteps.length > 0 ? { injectSteps } : {};
  }

  if (sessionRole !== "main") {
    return injectSteps.length > 0 ? { injectSteps } : {};
  }

  const claimed = claimAutonomyTurnFlag({
    conversationId: effectiveCid,
    flagName: "promptRouteTurns",
    turnKey,
    dataDir,
  });
  if (claimed !== true) {
    return injectSteps.length > 0 ? { injectSteps } : {};
  }

  if (options?.skipAuditLog !== true) {
    appendAuditRecord(
      {
        ts: new Date().toISOString(),
        event: "autonomy_event",
        eventType: "autonomy_event",
        kind: "prompt_route",
        conversationId: effectiveCid,
        turnStartStepIndex,
        signals: evaluation.signals,
      },
      dataDir,
    );
  }

  injectSteps.push({
    systemMessage: {
      systemMessage: PROMPT_ROUTE_SYSTEM_MESSAGE,
    },
  });

  return { injectSteps };
}

if (isDirectExecution(import.meta.url)) {
  runHookCli(handlePreInvocation);
}
