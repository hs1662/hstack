#!/usr/bin/env node

import { existsSync } from "node:fs";
import { appendAuditRecord } from "./governance/audit-log.mjs";
import { readGovernanceConfig, resolveAutonomyMode } from "./governance/config.mjs";
import { PROMPT_ROUTE_SYSTEM_MESSAGE } from "./governance/constants.mjs";
import { readFactLedger } from "./governance/fact-ledger.mjs";
import { claimAutonomyTurnFlag } from "./governance/handoff-store.mjs";
import {
  isDirectExecution,
  parseHookPayload,
  resolvePluginDataDir,
  resolveTranscriptCandidates,
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

/**
 * 사용자 프롬프트가 고위험 안전장치 제거 또는 유도성 아키텍처 변경 제안인지 판별한다.
 */
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

  if (signals.length === 0) {
    return { matched: false, signals: [] };
  }

  if (!LEADING_REVIEW_CONTEXT_RE.test(trimmed)) {
    return { matched: false, signals: [] };
  }

  signals.push("leading_or_design_review_context");
  return { matched: true, signals };
}

function pickPreferredTranscriptPath(rawTranscriptPath) {
  if (typeof rawTranscriptPath !== "string") {
    return "";
  }
  const trimmed = rawTranscriptPath.trim();
  if (trimmed.length === 0) {
    return "";
  }
  for (const candidate of resolveTranscriptCandidates(trimmed)) {
    try {
      if (existsSync(candidate)) {
        return candidate;
      }
    } catch {
      continue;
    }
  }
  return trimmed;
}

export function handlePreInvocation(stdinText, options = {}) {
  const payload = parseHookPayload(stdinText, "PreInvocation");
  if (!payload) {
    return {};
  }

  const invocationNum = payload.invocationNum ?? payload.invocation_num;
  if (typeof invocationNum === "number" && Number.isFinite(invocationNum) && invocationNum > 0) {
    return {};
  }

  const dataDir = options?.dataDir ?? resolvePluginDataDir();
  const governanceConfig = options?.governanceConfig ?? readGovernanceConfig(dataDir);
  if (resolveAutonomyMode(dataDir, governanceConfig) !== "smart") {
    return {};
  }

  const rawPrompt = payload.lastUserInput ?? payload.last_user_input;
  const evaluation = shouldAutoChallengePrompt(rawPrompt);
  if (!evaluation.matched) {
    return {};
  }

  const rawConversationId = payload.conversationId ?? payload.conversation_id;
  const conversationId = typeof rawConversationId === "string" ? rawConversationId.trim() : "";
  const cwd = typeof payload.cwd === "string" ? payload.cwd.trim() : "";
  const transcriptPath = pickPreferredTranscriptPath(payload.transcriptPath ?? payload.transcript_path);

  const ledger =
    options?.ledger ??
    (transcriptPath ? readFactLedger(transcriptPath, cwd, "") : null);
  const sessionRole = ledger?.transcriptAvailable ? ledger.sessionRole : "main";
  if (sessionRole !== "main") {
    return {};
  }

  const turnStartStepIndex = ledger?.transcriptAvailable ? ledger.turnStartStepIndex : 0;
  const turnKey = `${conversationId || "anon"}:${turnStartStepIndex}`;
  if (conversationId) {
    const claimed = claimAutonomyTurnFlag({
      conversationId,
      flagName: "promptRouteTurns",
      turnKey,
      dataDir,
    });
    if (!claimed) {
      return {};
    }
  }

  if (options?.skipAuditLog !== true) {
    appendAuditRecord(
      {
        ts: new Date().toISOString(),
        event: "autonomy_event",
        eventType: "autonomy_event",
        kind: "prompt_route",
        conversationId,
        turnStartStepIndex,
        signals: evaluation.signals,
      },
      dataDir,
    );
  }

  return {
    injectSteps: [
      {
        systemMessage: {
          systemMessage: PROMPT_ROUTE_SYSTEM_MESSAGE,
        },
      },
    ],
  };
}

if (isDirectExecution(import.meta.url)) {
  runHookCli(handlePreInvocation);
}
