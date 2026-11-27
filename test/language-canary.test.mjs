import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  DEFAULT_CANARY_CONFIG,
  classifyCanaryTurn,
  createCanaryState,
  evaluateLanguageCanary,
  extractCanaryProse,
  transitionCanary,
} from "../scripts/governance/language-canary.mjs";
import { timeUnderCpuLock } from "./helpers.mjs";

const KO =
  "요청한 변경 사항을 모두 반영했고 관련 단위 테스트를 다시 실행해서 전부 통과하는 것을 직접 확인했습니다. 남은 위험 요소는 없습니다.";
const EN =
  "I have applied every requested change and reran the related unit tests, and all of them are passing cleanly now.";
const SHORT_EN = "All tests pass now.";

const drift = { applicable: true, drift: true };
const normal = { applicable: true, drift: false };
const skip = { applicable: false, drift: false };

function run(classifications, config) {
  let state = createCanaryState();
  const events = [];
  for (const c of classifications) {
    const out = transitionCanary(state, c, config);
    events.push(out.event);
    state = out.state;
  }
  return { state, events };
}

describe("language canary prose extraction", () => {
  it("drops code fences, inline code, paths, urls, hashes, quotes, JSON/YAML and English glosses", () => {
    const text = [
      "변경 내용을 정리했습니다(Language Canary).",
      "```js",
      "const result = await runTests({ verbose: true }); // run the whole suite now",
      "```",
      "`node --test test/*.test.mjs` 명령으로 /root/work/hstack/scripts/governance/language-canary.mjs 를 검증했습니다.",
      "커밋 3f9a2c1d4e5b 와 https://example.com/docs/guide?x=1 링크를 참고했습니다.",
      '사용자는 "Please make sure the tests are all passing before you finish" 라고 말했습니다.',
      "> This quoted line is English prose that the user wrote earlier.",
      "{",
      '  "status": "passing",',
      '  "message": "All the tests were executed and they are passing"',
      "}",
      "name: canary",
      "enabled: true",
    ].join("\n");
    const prose = extractCanaryProse(text);
    assert.doesNotMatch(prose, /[A-Za-z]/, prose);
    assert.match(prose, /변경 내용을 정리했습니다/);
    assert.match(prose, /링크를 참고했습니다/);
  });

  it("does not let an unclosed fence or unbalanced JSON swallow later real prose", () => {
    const unclosedFence = ["```", "Now the real answer is written in English and it keeps going for a while."].join("\n");
    assert.match(extractCanaryProse(unclosedFence), /real answer is written in English/);

    const unbalancedJson = ["{", "I think the configuration is broken and we should rewrite it from scratch."].join("\n");
    assert.match(extractCanaryProse(unbalancedJson), /configuration is broken/);

    const unclosedQuote = 'He said "wait\nThe rest of this reply is plain English prose and it is drifting badly.';
    assert.match(extractCanaryProse(unclosedQuote), /plain English prose/);

    const longParen = "설명 (this parenthetical is actually a whole English sentence that keeps going and going)";
    assert.match(extractCanaryProse(longParen), /whole English sentence/);
  });

  it("drops YAML block scalars with indented English narrative but resumes at the next dedented prose", () => {
    const text = [
      "description: |",
      "  This service is responsible for handling every request that the users send.",
      "  It was written a long time ago and nobody wants to touch it anymore.",
      "notes: >-",
      "  We should probably rewrite it when there is time.",
      "After that block, I have decided to keep writing my answer in English prose.",
    ].join("\n");
    const prose = extractCanaryProse(text);
    assert.doesNotMatch(prose, /responsible|nobody|rewrite it/);
    assert.match(prose, /keep writing my answer in English prose/);
  });

  it("keeps bracketed plain prose that is not JSON", () => {
    const text = ["[Note] I have checked the files and they are all broken now.", "[", "this is not json at all and it keeps going", "]"].join("\n");
    const prose = extractCanaryProse(text);
    assert.match(prose, /checked the files/);
    assert.match(prose, /not json at all/);
    assert.equal(extractCanaryProse('[1, 2, {"a": "some English words in here"}]\n한국어 문장입니다'), "한국어 문장입니다");
  });

  it("strips single-quoted prose while keeping apostrophes in real prose", () => {
    const quoted = extractCanaryProse("사용자는 'I don't want this behaviour at all, please revert it' 라고 했습니다.");
    assert.doesNotMatch(quoted, /[A-Za-z]/, quoted);
    const curly = extractCanaryProse("사용자는 ‘I don’t want this, revert it’ 라고 했습니다.");
    assert.doesNotMatch(curly, /[A-Za-z]/, curly);
    const prose = extractCanaryProse("I don't think it's fine, the users' files aren't saved and we can't ship.");
    assert.match(prose, /I don't think it's fine, the users' files aren't saved and we can't ship\./);
  });

  it("scans many unclosed fences, brackets and list items in linear time", () => {
    const n = 20000;
    const samples = [
      Array.from({ length: n }, (_, i) => (i % 2 ? "```js" : "~~~")).join("\n"),
      Array.from({ length: n }, () => "{").join("\n"),
      Array.from({ length: n }, () => "[ {").join("\n"),
      Array.from({ length: n }, (_, i) => `- item number ${i} in the list`).join("\n"),
      Array.from({ length: n }, (_, i) => (i % 3 ? `- key${i}: value` : "plain")).join("\n"),
    ];
    for (const sample of samples) {
      const { elapsedMs } = timeUnderCpuLock(() => extractCanaryProse(sample));
      assert.ok(elapsedMs < 2000, `took ${elapsedMs}ms`);
    }
  });

  it("keeps prose-looking key: value lines that are English sentences", () => {
    const text = ["Summary: I have checked the files and they are all broken now.", "Next: we should rewrite the parser."].join(
      "\n",
    );
    assert.match(extractCanaryProse(text), /checked the files/);
  });
});

describe("language canary turn classification", () => {
  it("classifies pure Korean as applicable normal and English prose as drift", () => {
    assert.equal(classifyCanaryTurn({ text: KO }).drift, false);
    assert.equal(classifyCanaryTurn({ text: KO }).applicable, true);
    const en = classifyCanaryTurn({ text: EN });
    assert.equal(en.applicable, true);
    assert.equal(en.drift, true);
    assert.equal(en.reason, "drift");
  });

  it("marks explicit English requests and short prose as not applicable", () => {
    const req = classifyCanaryTurn({ text: EN, userRequest: "Please reply in English." });
    assert.equal(req.applicable, false);
    assert.equal(req.reason, "explicit_english_request");
    const korReq = classifyCanaryTurn({ text: EN, userRequest: "이 문단을 영어로 번역해 줘" });
    assert.equal(korReq.applicable, false);

    const short = classifyCanaryTurn({ text: SHORT_EN });
    assert.equal(short.applicable, false);
    assert.equal(short.reason, "below_min_prose_chars");
    assert.ok(short.proseChars < DEFAULT_CANARY_CONFIG.minProseChars);
  });

  it("does not flag Korean answers mixed with code, logs, paths and hashes (false positives)", () => {
    const mixed = [
      "테스트 실패 원인을 찾았습니다. 설정 파일에서 경로 처리 로직이 잘못되어 있었고 이를 고쳤습니다.",
      "```",
      "TypeError: Cannot read properties of undefined (reading 'path')",
      "    at loadConfig (/root/work/hstack/scripts/governance/config.mjs:42:13)",
      "```",
      "`loadConfig()` 함수와 scripts/governance/config.mjs 파일을 수정했고 커밋 a1b2c3d4e5f6 에 반영되어 있습니다.",
      "> Error: something went wrong while the tests were running in the background",
      '{"ok": true, "message": "the tests were all passing after the fix"}',
    ].join("\n");
    const result = classifyCanaryTurn({ text: mixed });
    assert.equal(result.applicable, true);
    assert.equal(result.drift, false);

    const codeOnly = ["```js", "export function run() { return 'This is English inside code'; }", "```"].join("\n");
    assert.equal(classifyCanaryTurn({ text: codeOnly }).applicable, false);
  });

  it("respects a configured minProseChars", () => {
    assert.equal(classifyCanaryTurn({ text: SHORT_EN }, { minProseChars: 5 }).applicable, true);
  });
});

describe("language canary transitions", () => {
  it("treats not-applicable turns as no-ops for counters and cooldown", () => {
    const start = createCanaryState();
    const out = transitionCanary(start, skip);
    assert.equal(out.event, "not_applicable");
    assert.deepEqual(out.state, start);

    const mid = run([drift, drift, drift]).state;
    const after = transitionCanary(mid, skip);
    assert.deepEqual(after.state, mid);
  });

  it("emits load_failure for the first applicable drift and excludes it from the counter", () => {
    const { state, events } = run([skip, drift]);
    assert.deepEqual(events, ["not_applicable", "load_failure"]);
    assert.equal(state.consecutiveDrifts, 0);
    assert.equal(state.status, "clean");
  });

  it("only a drift on the first applicable turn is load_failure; a normal first turn consumes it", () => {
    assert.deepEqual(run([normal, drift, drift, drift]).events, ["normal", "drift", "suspect", "handoff_required"]);
    assert.deepEqual(run([skip, normal, skip, drift, drift]).events, ["not_applicable", "normal", "not_applicable", "drift", "suspect"]);
    assert.deepEqual(run([drift, normal, drift]).events, ["load_failure", "normal", "drift"]);
  });

  it("goes suspect after 2 counted drifts and fires handoff_required once at 3", () => {
    const { state, events } = run([drift, drift, drift, drift, drift, drift]);
    assert.deepEqual(events, ["load_failure", "drift", "suspect", "handoff_required", "drift", "drift"]);
    assert.equal(events.filter((e) => e === "handoff_required").length, 1);
    assert.equal(state.status, "handoff_required");
  });

  it("does not count drifts interrupted by a normal turn as consecutive", () => {
    const { events, state } = run([drift, drift, normal, drift, normal, drift]);
    assert.deepEqual(events, ["load_failure", "drift", "normal", "drift", "normal", "drift"]);
    assert.equal(state.status, "clean");
  });

  it("recovers to clean after 3 normal applicable turns", () => {
    const { state, events } = run([drift, drift, drift, drift, normal, skip, normal, normal]);
    assert.deepEqual(events.slice(-5), ["handoff_required", "normal", "not_applicable", "normal", "recovered"]);
    assert.equal(state.status, "clean");
    assert.equal(state.consecutiveNormal, 3);
  });

  it("suppresses re-trigger for 5 applicable turns after reset, recovery included", () => {
    // trigger, 3 recovery turns, then 3 drifts: the 4th and 5th applicable turns are still in cooldown.
    const seq = [drift, drift, drift, drift, normal, normal, normal, drift, drift, drift, drift];
    const { events } = run(seq);
    assert.deepEqual(events.slice(3), [
      "handoff_required",
      "normal",
      "normal",
      "recovered",
      "drift",
      "suspect",
      "handoff_required",
      "drift",
    ]);
    const cooled = run([drift, drift, drift, drift, drift, drift, drift]).events;
    assert.deepEqual(cooled, ["load_failure", "drift", "suspect", "handoff_required", "drift", "drift", "handoff_suppressed"]);
    const afterCooldown = run([drift, drift, drift, drift, drift, drift, drift, drift, drift, drift]).events;
    assert.deepEqual(afterCooldown.slice(6), ["handoff_suppressed", "drift", "drift", "handoff_required"]);
    assert.ok(!afterCooldown.slice(4).includes("suspect"), "no suspect flood while handoff_required");
  });

  it("honors custom thresholds", () => {
    const config = { kWarn: 1, kReset: 2, recoverCleanTurns: 1, cooldownTurns: 1 };
    const { events } = run([drift, drift, drift, normal, drift, drift], config);
    assert.deepEqual(events, ["load_failure", "suspect", "handoff_required", "recovered", "suspect", "handoff_required"]);
  });

  it("rejects invalid configuration at the boundary", () => {
    assert.throws(() => transitionCanary(createCanaryState(), drift, { kWarn: 0 }), TypeError);
    assert.throws(() => transitionCanary(createCanaryState(), drift, { kWarn: 4, kReset: 3 }), RangeError);
  });

  it("never mutates the input state, classification or config", () => {
    const state = run([drift, drift]).state;
    const snapshot = structuredClone(state);
    const classification = { ...drift };
    const config = { kWarn: 2 };
    const out = transitionCanary(state, classification, config);
    assert.deepEqual(state, snapshot);
    assert.deepEqual(classification, drift);
    assert.deepEqual(config, { kWarn: 2 });
    assert.notEqual(out.state, state);
    assert.ok(Object.isFrozen(out.state));
    assert.ok(Object.isFrozen(DEFAULT_CANARY_CONFIG));
  });
});

describe("language canary report", () => {
  it("returns advisory report with transition, state and event and is deterministic", () => {
    const state = createCanaryState();
    const turn = { text: EN, userRequest: "구조를 분석해 줘" };
    const a = evaluateLanguageCanary(state, turn);
    const b = evaluateLanguageCanary(state, turn);
    assert.deepEqual(a, b);
    assert.equal(a.advisory, true);
    assert.equal(a.event, "load_failure");
    assert.deepEqual(a.previousState, state);
    assert.equal(a.state.firstApplicableSeen, true);
    assert.equal(a.classification.drift, true);
    assert.deepEqual(a.transition, { from: "clean", to: "clean" });
    assert.deepEqual(a.config, DEFAULT_CANARY_CONFIG);
  });
});
