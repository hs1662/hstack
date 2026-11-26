import { resolvePluginDataDir } from "../hook-io.mjs";
import { readGovernanceConfig } from "./audit-log.mjs";
import {
  ALLOWED_AUDIT_ESCALATION_MODES,
  DEFAULT_RISK_THRESHOLDS,
  DEFAULT_SENSITIVE_PATTERNS,
} from "./constants.mjs";

export function resolveAuditEscalationMode(dataDir = resolvePluginDataDir(), configOverride = null) {
  const envVal =
    typeof process.env.HSTACK_AUDIT_ESCALATION === "string"
      ? process.env.HSTACK_AUDIT_ESCALATION.trim().toLowerCase()
      : "";
  if (ALLOWED_AUDIT_ESCALATION_MODES.has(envVal)) {
    return envVal;
  }

  const config = configOverride ?? readGovernanceConfig(dataDir);
  const cfgVal =
    typeof config?.auditEscalation === "string" ? config.auditEscalation.trim().toLowerCase() : "";
  if (ALLOWED_AUDIT_ESCALATION_MODES.has(cfgVal)) {
    return cfgVal;
  }

  return "auto";
}

const MAX_CUSTOM_SENSITIVE_PATTERNS = 50;

// Length of the quantifier at `i` ("*", "+", "?", "{n}", "{n,}", "{n,m}", each optionally lazy), or 0.
function quantifierAt(source, i) {
  const ch = source[i];
  let end = 0;
  if (ch === "*" || ch === "+" || ch === "?") {
    end = i + 1;
  } else if (ch === "{") {
    const match = /^\{\d+(?:,\d*)?\}/.exec(source.slice(i));
    end = match ? i + match[0].length : 0;
  }
  if (end === 0) {
    return 0;
  }
  return (source[end] === "?" ? end + 1 : end) - i;
}

// Linear scan of a pattern's groups: a quantified group whose body already holds a quantifier or an
// alternation (star height 2, as in `(a+)+`, `((a+))+`, `(a|a)+`, `([a-z]+){2,}`) can backtrack
// exponentially, and so can a backreference. Character classes and escapes are opaque atoms.
function isSafeCustomRegex(source) {
  if (typeof source !== "string") {
    return false;
  }
  const trimmed = source.trim();
  if (trimmed.length === 0 || trimmed.length > 200) {
    return false;
  }
  const groups = [{ quantified: false, alternation: false }];
  let i = 0;
  const markQuantified = () => {
    groups[groups.length - 1].quantified = true;
  };
  while (i < trimmed.length) {
    const ch = trimmed[i];
    if (ch === "\\") {
      if (/[1-9k]/.test(trimmed[i + 1] ?? "")) {
        return false;
      }
      i += 2;
    } else if (ch === "[") {
      i += 1;
      if (trimmed[i] === "^") i += 1;
      if (trimmed[i] === "]") i += 1;
      while (i < trimmed.length && trimmed[i] !== "]") {
        i += trimmed[i] === "\\" ? 2 : 1;
      }
      i += 1;
    } else if (ch === "(") {
      groups.push({ quantified: false, alternation: false });
      i += 1;
      continue;
    } else if (ch === ")") {
      if (groups.length === 1) {
        return false;
      }
      const inner = groups.pop();
      i += 1;
      const length = quantifierAt(trimmed, i);
      if (length > 0) {
        if (inner.quantified || inner.alternation) {
          return false;
        }
        markQuantified();
        i += length;
      }
      const outer = groups[groups.length - 1];
      outer.quantified ||= inner.quantified;
      outer.alternation ||= inner.alternation;
      continue;
    } else if (ch === "|") {
      groups[groups.length - 1].alternation = true;
      i += 1;
      continue;
    } else {
      i += 1;
    }
    const length = quantifierAt(trimmed, i);
    if (length > 0) {
      markQuantified();
      i += length;
    }
  }
  return groups.length === 1;
}

function compileSensitivePatterns(rawPatterns) {
  if (!Array.isArray(rawPatterns) || rawPatterns.length === 0) {
    return DEFAULT_SENSITIVE_PATTERNS;
  }
  const compiled = [];
  for (const item of rawPatterns.slice(0, MAX_CUSTOM_SENSITIVE_PATTERNS)) {
    if (item instanceof RegExp) {
      if (isSafeCustomRegex(item.source)) {
        compiled.push(item);
      }
    } else if (isSafeCustomRegex(item)) {
      try {
        compiled.push(new RegExp(item.trim(), "i"));
      } catch {
        continue;
      }
    }
  }
  return compiled.length > 0 ? compiled : DEFAULT_SENSITIVE_PATTERNS;
}

export function isSensitiveFilePath(filePath, config = null) {
  if (typeof filePath !== "string" || filePath.length === 0) {
    return false;
  }
  const patterns = compileSensitivePatterns(config?.sensitivePatterns);
  return patterns.some((re) => re.test(filePath));
}

function toPositiveInt(value, fallback) {
  const num = Number(value);
  return Number.isInteger(num) && num >= 1 ? num : fallback;
}

function sumChangedLines(codeFiles, diffNumstat) {
  if (!(diffNumstat instanceof Map) || diffNumstat.size === 0) {
    return 0;
  }
  let total = 0;
  for (const filePath of codeFiles) {
    const stat = diffNumstat.get(filePath);
    if (!stat || typeof stat !== "object") {
      continue;
    }
    const added = Number.isFinite(stat.added) ? Math.max(0, stat.added) : 0;
    const deleted = Number.isFinite(stat.deleted) ? Math.max(0, stat.deleted) : 0;
    total += added + deleted;
  }
  return total;
}

export function classifyRisk({ turnCodeWrittenFiles, gitLedger, config = null } = {}) {
  const codeFiles =
    turnCodeWrittenFiles instanceof Set
      ? Array.from(turnCodeWrittenFiles)
      : Array.isArray(turnCodeWrittenFiles)
        ? Array.from(new Set(turnCodeWrittenFiles.filter((p) => typeof p === "string" && p.length > 0)))
        : [];

  if (codeFiles.length === 0) {
    return {
      tier: "TIER_0",
      reasons: [],
      matchedSensitiveFiles: [],
      changedLines: 0,
    };
  }

  const patterns = compileSensitivePatterns(config?.sensitivePatterns);
  const minCodeFiles = toPositiveInt(config?.riskThresholds?.minCodeFiles, DEFAULT_RISK_THRESHOLDS.minCodeFiles);
  const minChangedLines = toPositiveInt(
    config?.riskThresholds?.minChangedLines,
    DEFAULT_RISK_THRESHOLDS.minChangedLines,
  );

  const matchedSensitiveFiles = [];
  for (const filePath of codeFiles) {
    if (patterns.some((re) => re.test(filePath))) {
      matchedSensitiveFiles.push(filePath);
    }
  }

  const changedLines = sumChangedLines(codeFiles, gitLedger?.diffNumstat);
  const reasons = [];
  if (matchedSensitiveFiles.length > 0) {
    reasons.push("sensitive_path");
  }
  if (codeFiles.length >= minCodeFiles) {
    reasons.push("large_file_count");
  }
  if (changedLines >= minChangedLines) {
    reasons.push("large_diff_lines");
  }

  return {
    tier: reasons.length > 0 ? "TIER_1" : "TIER_0",
    reasons,
    matchedSensitiveFiles,
    changedLines,
  };
}
