import { resolveAutonomyThresholds } from "./config.mjs";
import { DEFAULT_AUTONOMY_THRESHOLDS } from "./constants.mjs";

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
