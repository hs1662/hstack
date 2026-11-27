// Advisory Korean-language canary: a pure classifier plus a pure state transition.
// No IO, no clock, no globals; callers own persistence and decide what to do with the event.
import { MIN_HANGUL_RATIO } from "../analyzer/constants.mjs";
import {
  HAS_HANGUL_RE,
  englishWords,
  hasEnglishProseFunctionWord,
  hasEnglishSentenceFiniteWord,
  measureLanguage,
} from "../analyzer/lexicon.mjs";
import { extractNaturalText } from "../analyzer/stripper.mjs";
import { isExplicitEnglishOutputRequest } from "../transcript/english-request.mjs";

export const DEFAULT_CANARY_CONFIG = Object.freeze({
  kWarn: 2,
  kReset: 3,
  minProseChars: 40,
  recoverCleanTurns: 3,
  cooldownTurns: 5,
  minHangulRatio: MIN_HANGUL_RATIO,
});

const INTEGER_MINIMUMS = { kWarn: 1, kReset: 1, minProseChars: 0, recoverCleanTurns: 1, cooldownTurns: 0 };

function resolveConfig(overrides = {}) {
  const config = { ...DEFAULT_CANARY_CONFIG, ...overrides };
  for (const [key, min] of Object.entries(INTEGER_MINIMUMS)) {
    if (!Number.isInteger(config[key]) || config[key] < min) {
      throw new TypeError(`language canary: ${key} must be an integer >= ${min}`);
    }
  }
  if (typeof config.minHangulRatio !== "number" || config.minHangulRatio < 0 || config.minHangulRatio > 1) {
    throw new TypeError("language canary: minHangulRatio must be a number in [0, 1]");
  }
  if (config.kWarn > config.kReset) {
    throw new RangeError("language canary: kWarn must not exceed kReset");
  }
  return Object.freeze(config);
}

export function createCanaryState() {
  return Object.freeze({
    status: "clean",
    firstApplicableSeen: false,
    consecutiveDrifts: 0,
    consecutiveNormal: 0,
    cooldownRemaining: 0,
  });
}

// ---- prose extraction (every pass is linear in the number of lines) ---------------------------

const HANGUL_CLASS = "\\u1100-\\u11FF\\u3131-\\u318E\\uAC00-\\uD7A3";
const FENCE_RE = /^[ \t]*(`{3,}|~{3,})/;
const MAX_FENCE_LEN = 16;
const QUOTED_LINE_RE = /^[ \t]*>/;
// Single quotes open only after a non-Latin char; an apostrophe between Latin letters (don't, it’s) never closes a
// span, while a closer may touch a Korean particle ('done'라고).
const QUOTED_SPAN_RES = [
  /"[^"\n]*"/g,
  /“[^”\n]*”/g,
  /(?<![A-Za-z0-9‘’])‘(?:[^‘’\n]|(?<=[A-Za-z])’(?=[A-Za-z]))+’(?![A-Za-z0-9])/g,
  /(?<![A-Za-z0-9'])'(?:[^'\n]|(?<=[A-Za-z])'(?=[A-Za-z]))+'(?![A-Za-z0-9])/g,
  /「[^」\n]*」/g,
  /『[^』\n]*』/g,
];
const HASH_RE = /\b(?:sha\d*[:-])?(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{7,64}\b/gi;
// `한국어(English Gloss)` / `한국어 (gloss words)`: a short Hangul-free parenthetical right after Hangul.
const GLOSS_RE = new RegExp(`([${HANGUL_CLASS}])[ \\t]?\\(([^()\\n${HANGUL_CLASS}]{1,80})\\)`, "g");
const MAX_GLOSS_WORDS = 6;
const JSON_OPEN_RE = /^[ \t]*[{[]/;
const JSON_STRING_RE = /"(?:[^"\\\n]|\\.)*"/g;
const JSON_RESIDUE_RE = /^(?:[\s{}[\],:.eE+\-\d]|true|false|null)*$/;
const YAML_KEY_RE = /^([ \t]*)(?:-[ \t]+)?[A-Za-z0-9_.-]+:(?:[ \t]+(.*))?$/;
const YAML_BLOCK_SCALAR_RE = /^[|>][+-]?\d?[ \t]*(?:#.*)?$/;
const YAML_ITEM_RE = /^[ \t]*-[ \t]+\S/;
const YAML_DOC_RE = /^[ \t]*---[ \t]*$/;
const MIN_PROSE_LINE_WORDS = 5;

function isEnglishSentence(text) {
  const words = englishWords(text);
  return words.length >= MIN_PROSE_LINE_WORDS && hasEnglishProseFunctionWord(words) && hasEnglishSentenceFiniteWord(words);
}

function bareFence(line) {
  const m = FENCE_RE.exec(line);
  return m && line.trim() === m[1] ? m[1] : null;
}

// Closed fences are dropped whole; an unclosed opener drops only its own marker line.
// A backward pass records, per fence char and length, the next bare closer, so each opener is O(1).
function stripClosedFences(lines) {
  const nextCloser = new Array(lines.length).fill(-1);
  const pending = { "`": new Array(MAX_FENCE_LEN + 1).fill(-1), "~": new Array(MAX_FENCE_LEN + 1).fill(-1) };
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const open = FENCE_RE.exec(lines[i]);
    if (!open) continue;
    const marker = open[1];
    nextCloser[i] = pending[marker[0]][Math.min(marker.length, MAX_FENCE_LEN)];
    const bare = bareFence(lines[i]);
    if (bare) {
      const slots = pending[bare[0]];
      for (let len = 3; len <= Math.min(bare.length, MAX_FENCE_LEN); len += 1) slots[len] = i;
    }
  }
  const out = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (!FENCE_RE.test(lines[i])) out.push(lines[i]);
    else if (nextCloser[i] !== -1) i = nextCloser[i];
  }
  return out;
}

function bracketDelta(withoutStrings) {
  let delta = 0;
  for (const ch of withoutStrings) {
    if (ch === "{" || ch === "[") delta += 1;
    else if (ch === "}" || ch === "]") delta -= 1;
  }
  return delta;
}

// A JSON block starts at a line opening with `{`/`[`, ends at the first line where the bracket depth returns to
// the start level, and every line outside string literals holds only JSON punctuation and literals. Bracketed prose
// (`[Note] I checked...`) and unbalanced blocks are kept. Prefix depths plus a monotonic stack give each start its
// end in O(1), so many unclosed brackets stay linear.
function stripJsonBlocks(lines) {
  const n = lines.length;
  const prefix = new Array(n + 1);
  const jsonLike = new Array(n);
  prefix[0] = 0;
  for (let i = 0; i < n; i += 1) {
    const residue = lines[i].replace(JSON_STRING_RE, "");
    jsonLike[i] = JSON_RESIDUE_RE.test(residue);
    prefix[i + 1] = prefix[i] + bracketDelta(residue);
  }
  // nextLe[t]: smallest m > t with prefix[m] <= prefix[t].
  const nextLe = new Array(n + 1).fill(-1);
  const stack = [];
  for (let m = 0; m <= n; m += 1) {
    while (stack.length > 0 && prefix[m] <= prefix[stack[stack.length - 1]]) nextLe[stack.pop()] = m;
    stack.push(m);
  }
  // firstNonJson[i]: first index >= i whose line is not JSON-like.
  const firstNonJson = new Array(n + 1);
  firstNonJson[n] = n;
  for (let i = n - 1; i >= 0; i -= 1) firstNonJson[i] = jsonLike[i] ? firstNonJson[i + 1] : i;

  const out = [];
  for (let i = 0; i < n; i += 1) {
    const end = JSON_OPEN_RE.test(lines[i]) && nextLe[i] !== -1 ? nextLe[i] - 1 : -1;
    if (end >= i && end < firstNonJson[i]) i = end;
    else out.push(lines[i]);
  }
  return out;
}

function yamlKey(line) {
  if (HAS_HANGUL_RE.test(line)) return null;
  const m = YAML_KEY_RE.exec(line);
  if (!m || isEnglishSentence(m[2] ?? "")) return null;
  return { indent: m[1].length, blockScalar: YAML_BLOCK_SCALAR_RE.test(m[2] ?? "") };
}

function isYamlItem(line) {
  return !HAS_HANGUL_RE.test(line) && YAML_ITEM_RE.test(line) && !isEnglishSentence(line);
}

function indentOf(line) {
  return line.length - line.trimStart().length;
}

// A YAML run is consecutive key/item lines plus the indented body of any block scalar (`key: |`, `key: >-`).
// It is dropped when it holds two keys, a block scalar, or follows `---`. A failed run is emitted whole, so long
// Markdown lists are scanned once.
function stripYamlBlocks(lines) {
  const out = [];
  for (let i = 0; i < lines.length; ) {
    let j = i;
    let keys = 0;
    let hasBlockScalar = false;
    while (j < lines.length) {
      const key = yamlKey(lines[j]);
      if (key) {
        keys += 1;
        j += 1;
        if (key.blockScalar) {
          let k = j;
          while (k < lines.length && (lines[k].trim() === "" || indentOf(lines[k]) > key.indent)) k += 1;
          while (k > j && lines[k - 1].trim() === "") k -= 1;
          hasBlockScalar ||= k > j;
          j = k;
        }
      } else if (isYamlItem(lines[j])) {
        j += 1;
      } else {
        break;
      }
    }
    if (j === i) {
      out.push(lines[i]);
      i += 1;
      continue;
    }
    if (!(keys >= 2 || hasBlockScalar || (keys >= 1 && i > 0 && YAML_DOC_RE.test(lines[i - 1])))) {
      for (let k = i; k < j; k += 1) out.push(lines[k]);
    }
    i = j;
  }
  return out;
}

export function extractCanaryProse(rawText) {
  if (typeof rawText !== "string" || rawText.length === 0) {
    return "";
  }
  let lines = rawText.replace(/\r\n?/g, "\n").split("\n");
  lines = stripClosedFences(lines).filter((line) => !QUOTED_LINE_RE.test(line));
  lines = stripYamlBlocks(stripJsonBlocks(lines));
  const unquoted = QUOTED_SPAN_RES.reduce((acc, re) => acc.replace(re, " "), lines.join("\n"));
  return extractNaturalText(unquoted)
    .replace(HASH_RE, " ")
    .replace(GLOSS_RE, (full, hangul, inner) => (englishWords(inner).length <= MAX_GLOSS_WORDS ? hangul : full))
    .split("\n")
    .map((line) => line.replace(/[ \t]+/g, " ").trim())
    .join("\n")
    .trim();
}

// ---- classification ---------------------------------------------------------------------------

export function classifyCanaryTurn({ text = "", userRequest = "" } = {}, overrides) {
  const config = resolveConfig(overrides);
  const prose = extractCanaryProse(text);
  const { hangulCount, latinCount, naturalCharCount, hangulRatio } = measureLanguage(prose);
  const metrics = { proseChars: naturalCharCount, hangulCount, latinCount, hangulRatio };
  if (typeof userRequest === "string" && userRequest.length > 0 && isExplicitEnglishOutputRequest(userRequest)) {
    return Object.freeze({ applicable: false, drift: false, reason: "explicit_english_request", ...metrics });
  }
  if (naturalCharCount < config.minProseChars) {
    return Object.freeze({ applicable: false, drift: false, reason: "below_min_prose_chars", ...metrics });
  }
  const drift = hangulRatio < config.minHangulRatio;
  return Object.freeze({ applicable: true, drift, reason: drift ? "drift" : "korean", ...metrics });
}

// ---- transition -------------------------------------------------------------------------------

// Events: not_applicable | normal | recovered | load_failure | drift | suspect | handoff_required | handoff_suppressed
export function transitionCanary(state, classification, overrides) {
  const config = resolveConfig(overrides);
  if (!classification.applicable) {
    return { state: Object.freeze({ ...state }), event: "not_applicable" };
  }
  const firstApplicable = !state.firstApplicableSeen;
  const suppressed = state.cooldownRemaining > 0;
  const next = {
    ...state,
    firstApplicableSeen: true,
    cooldownRemaining: Math.max(0, state.cooldownRemaining - 1),
  };
  let event;

  if (!classification.drift) {
    next.consecutiveDrifts = 0;
    next.consecutiveNormal = state.consecutiveNormal + 1;
    if (state.status !== "clean" && next.consecutiveNormal >= config.recoverCleanTurns) {
      next.status = "clean";
      event = "recovered";
    } else {
      event = "normal";
    }
  } else if (firstApplicable) {
    // The first applicable turn drifting is a context-load failure, not a drift streak.
    next.consecutiveNormal = 0;
    event = "load_failure";
  } else {
    next.consecutiveNormal = 0;
    next.consecutiveDrifts = state.consecutiveDrifts + 1;
    const escalated = state.status === "handoff_required";
    if (next.consecutiveDrifts >= config.kReset && !suppressed) {
      next.status = "handoff_required";
      next.consecutiveDrifts = 0;
      next.cooldownRemaining = config.cooldownTurns;
      event = "handoff_required";
    } else if (next.consecutiveDrifts === config.kReset) {
      event = "handoff_suppressed";
    } else if (next.consecutiveDrifts === config.kWarn && !escalated) {
      next.status = "suspect";
      event = "suspect";
    } else {
      event = "drift";
    }
  }
  return { state: Object.freeze(next), event };
}

// One advisory report per turn: classification, transition, resulting state and event.
export function evaluateLanguageCanary(state, turn, overrides) {
  const config = resolveConfig(overrides);
  const classification = classifyCanaryTurn(turn, config);
  const { state: nextState, event } = transitionCanary(state, classification, config);
  return {
    advisory: true,
    event,
    classification,
    transition: { from: state.status, to: nextState.status },
    previousState: state,
    state: nextState,
    config,
  };
}
