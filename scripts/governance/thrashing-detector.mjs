import { resolveAutonomyThresholds } from "./config.mjs";
import { DEFAULT_AUTONOMY_THRESHOLDS } from "./constants.mjs";

/**
 * 현재 턴의 검증 실패, 동일 파일 수정, 누적 토큰 지표를 바탕으로 반복 삽질 여부를 판정한다.
 */
export function evaluateThrashing({
  turnVerifyFailures = 0,
  turnConsecutiveVerifyFailures = 0,
  maxSameFileEdits = 0,
  mostEditedFile = "",
  inputTokens = null,
  thresholds = DEFAULT_AUTONOMY_THRESHOLDS,
  config = null,
} = {}) {
  const resolved = config ? resolveAutonomyThresholds(undefined, config) : {
    ...DEFAULT_AUTONOMY_THRESHOLDS,
    ...(thresholds && typeof thresholds === "object" ? thresholds : {}),
  };

  const verifyFailures = Number.isFinite(turnVerifyFailures) ? Math.max(0, turnVerifyFailures) : 0;
  const consecutiveFailures = Number.isFinite(turnConsecutiveVerifyFailures)
    ? Math.max(0, turnConsecutiveVerifyFailures)
    : 0;
  const sameFileEdits = Number.isFinite(maxSameFileEdits) ? Math.max(0, maxSameFileEdits) : 0;
  const tokens = typeof inputTokens === "number" && Number.isFinite(inputTokens) ? inputTokens : null;

  const reasons = [];
  if (verifyFailures >= resolved.thrashingVerifyFailures) {
    reasons.push("verify_failures_accumulated");
  }
  if (sameFileEdits >= resolved.thrashingSameFileEdits && verifyFailures >= 2) {
    reasons.push("same_file_churn_with_failures");
  }
  if (tokens !== null && tokens >= resolved.thrashingHighTokens && consecutiveFailures >= 2) {
    reasons.push("high_tokens_consecutive_failures");
  }

  return {
    thrashing: reasons.length > 0,
    reasons,
    summary: {
      turnVerifyFailures: verifyFailures,
      turnConsecutiveVerifyFailures: consecutiveFailures,
      maxSameFileEdits: sameFileEdits,
      mostEditedFile: typeof mostEditedFile === "string" ? mostEditedFile : "",
      inputTokens: tokens,
    },
  };
}
