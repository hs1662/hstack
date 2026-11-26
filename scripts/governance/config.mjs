import { resolvePluginDataDir } from "../hook-io.mjs";
import { readGovernanceConfig } from "./audit-log.mjs";
import {
  ALLOWED_AUTONOMY_MODES,
  DEFAULT_AUTONOMY_MODE,
  DEFAULT_AUTONOMY_THRESHOLDS,
} from "./constants.mjs";

export { readGovernanceConfig };

function toPositiveInt(value, fallback) {
  const num = Number(value);
  return Number.isInteger(num) && num >= 1 ? num : fallback;
}

export function resolveAutonomyMode(dataDir = resolvePluginDataDir(), configOverride = null) {
  const envVal =
    typeof process.env.HSTACK_AUTONOMY_MODE === "string"
      ? process.env.HSTACK_AUTONOMY_MODE.trim().toLowerCase()
      : "";
  if (ALLOWED_AUTONOMY_MODES.has(envVal)) {
    return envVal;
  }

  const config = configOverride ?? readGovernanceConfig(dataDir);
  const cfgVal =
    typeof config?.autonomyMode === "string" ? config.autonomyMode.trim().toLowerCase() : "";
  if (ALLOWED_AUTONOMY_MODES.has(cfgVal)) {
    return cfgVal;
  }

  return DEFAULT_AUTONOMY_MODE;
}

export function resolveAutonomyThresholds(dataDir = resolvePluginDataDir(), configOverride = null) {
  const config = configOverride ?? readGovernanceConfig(dataDir);
  const raw =
    config?.autonomyThresholds && typeof config.autonomyThresholds === "object" && !Array.isArray(config.autonomyThresholds)
      ? config.autonomyThresholds
      : {};

  return {
    destructiveDeleteLines: toPositiveInt(
      raw.destructiveDeleteLines,
      DEFAULT_AUTONOMY_THRESHOLDS.destructiveDeleteLines,
    ),
    thrashingVerifyFailures: toPositiveInt(
      raw.thrashingVerifyFailures,
      DEFAULT_AUTONOMY_THRESHOLDS.thrashingVerifyFailures,
    ),
    thrashingSameFileEdits: toPositiveInt(
      raw.thrashingSameFileEdits,
      DEFAULT_AUTONOMY_THRESHOLDS.thrashingSameFileEdits,
    ),
    thrashingHighTokens: toPositiveInt(
      raw.thrashingHighTokens,
      DEFAULT_AUTONOMY_THRESHOLDS.thrashingHighTokens,
    ),
  };
}
