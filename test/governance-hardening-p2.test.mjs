// v0.1.2 Checkpoint 3 (P2): long-session hook latency, corrupt handoff snapshots, custom-pattern ReDoS,
// MCP protocol negotiation, tool-result offsets, runner-aware failure clearing, and the 0.1.2 version.
import assert from "node:assert/strict";
import { closeSync, mkdirSync, openSync, readFileSync, writeFileSync, writeSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  AUDITOR_AGENT_NAME,
  AUTO_CHALLENGER_MARKER,
  AUTO_HANDOFF_MARKER,
  CHALLENGER_AGENT_NAME,
  GATE_TOOL_NAME,
  WORKER_AGENT_NAME,
} from "../scripts/governance/constants.mjs";
import { decideGate } from "../scripts/governance/decide-gate.mjs";
import * as factLedger from "../scripts/governance/fact-ledger.mjs";
import { readFactLedger } from "../scripts/governance/fact-ledger.mjs";
import { computeWorkspaceKey, loadHandoffSnapshot } from "../scripts/governance/handoff-store.mjs";
import { isSensitiveFilePath } from "../scripts/governance/risk-classifier.mjs";
import * as hookIo from "../scripts/hook-io.mjs";
import { readTranscriptSteps } from "../scripts/hook-io.mjs";
import { createMcpServerHandler } from "../scripts/mcp/server.mjs";
import { handlePreToolGate } from "../scripts/pre-tool-gate.mjs";
import { GATE_STOP_MARKER, decideHookAction, parseTranscriptJsonl } from "../scripts/transcript.mjs";
import { deniedToolCallIndexes } from "../scripts/transcript/steps.mjs";
import { HOOK_SCRIPT, PLUGIN_ROOT, STOP_HOOK_SCRIPT, createTempDir, runHookSubprocess, timeUnderCpuLock, toJsonl, withCpuLock } from "./helpers.mjs";

const KOREAN_PROSE = "작업 중입니다 ".repeat(20);

// Same shape as the audit's 60,000-step transcript: one USER_INPUT, then edit_file planners with Korean prose
// and their GENERIC results, ending with an English answer so both drift checks run on the bounded tail.
function writeLongSession(path, repo, pairs, userContent = "수정해 줘") {
  const fd = openSync(path, "w");
  let buf = `${JSON.stringify({ step_index: 0, type: "USER_INPUT", content: userContent })}\n`;
  let step = 1;
  for (let i = 0; i < pairs; i += 1) {
    const planner = {
      step_index: step,
      type: "PLANNER_RESPONSE",
      content: KOREAN_PROSE,
      tool_calls: [{ name: "edit_file", args: { Path: join(repo, `f${step}.mjs`), CodeContent: "x".repeat(285) } }],
    };
    buf += `${JSON.stringify(planner)}\n`;
    step += 1;
    buf += `${JSON.stringify({ step_index: step, type: "GENERIC", status: "DONE", content: "ok ".repeat(100) })}\n`;
    step += 1;
    if (buf.length > 1 << 20) {
      writeSync(fd, buf);
      buf = "";
    }
  }
  buf += `${JSON.stringify({ step_index: step, type: "PLANNER_RESPONSE", content: "I finished every change and all the tests pass now. Let me know what else you need." })}\n`;
  writeSync(fd, buf);
  closeSync(fd);
}

// Fastest of `runs` wall-clock runs: other test files keep the CPU busy, and contention only ever adds time.
function fastestHookMs(script, payload, runs = 3) {
  const samples = [];
  let last = null;
  for (let i = 0; i < runs; i += 1) {
    const dataDir = createTempDir("hstack-p2-hookdata-");
    const t0 = performance.now();
    last = runHookSubprocess(script, JSON.stringify(payload), { env: { ...process.env, HSTACK_DATA_DIR: dataDir } });
    samples.push(performance.now() - t0);
  }
  return { fastest: Math.min(...samples), output: JSON.parse(last.stdout) };
}

describe("#7 hooks on a long single-turn session stay far under the 5s hook timeout", () => {
  // In-suite fixture: 20,000 tool calls (40,000 records, ~26MB), a third of the audit's 60,000-call / 77MB
  // file, so the suite stays fast. On a quiet box v0.1.1 needs ~1.3s for each hook here (PostInvocation also
  // replays a drift check on every planner) and v0.1.2 ~0.45s; under full-suite load v0.1.2's 3-run median
  // reached ~1.2s, so the bound applies to the fastest run. The 60,000-call medians are measured outside.
  it("Stop and PostInvocation each finish a 20,000-call transcript in under 1000ms (fastest of 3 runs)", () => {
    const dir = createTempDir("hstack-p2-long-");
    const repo = join(dir, "repo");
    mkdirSync(repo);
    const transcriptPath = join(dir, "transcript_full.jsonl");
    writeLongSession(transcriptPath, repo, 20_000);
    const base = { conversationId: "p2-long", cwd: repo, transcriptPath };

    withCpuLock(() => {
      const stop = fastestHookMs(STOP_HOOK_SCRIPT, { ...base, hookEventName: "Stop", terminationReason: "NO_TOOL_CALL", executionNum: 0 });
      assert.equal(stop.output.decision, "continue");
      assert.ok(stop.fastest < 1000, `Stop fastest run ${stop.fastest.toFixed(0)}ms (>= 1000ms)`);

      const post = fastestHookMs(HOOK_SCRIPT, { ...base, hookEventName: "PostInvocation" });
      assert.ok(Array.isArray(post.output.injectSteps), "the English answer is still flagged on the bounded tail");
      assert.ok(post.fastest < 1000, `PostInvocation fastest run ${post.fastest.toFixed(0)}ms (>= 1000ms)`);
    });
  });

  it("reads the same ledger whether or not a >1MB scan skips planner prose and clean write output", () => {
    const records = [
      { step_index: 0, type: "USER_INPUT", content: "기능을 구현해 줘" },
      { step_index: 1, type: "SYSTEM_MESSAGE", content: "세션 시작" },
    ];
    let step = 2;
    const push = (record) => records.push({ step_index: step++, ...record });
    for (let i = 0; i < 300; i += 1) {
      push({ type: "PLANNER_RESPONSE", content: `${KOREAN_PROSE.repeat(10)} \\"따옴표\\" \\u0041 ${i}`, tool_calls: [{ name: "edit_file", args: { Path: `/repo/src/m${i % 7}.mjs` } }] });
      push({ type: "GENERIC", status: "DONE", content: "변경 완료 ".repeat(200) });
    }
    push({ type: "PLANNER_RESPONSE", content: KOREAN_PROSE, tool_calls: [{ name: "write_file", args: { Path: "/repo/src/denied.mjs" } }] });
    push({ type: "GENERIC", status: "ERROR", content: "tool call denied by pre-tool hook: 서킷브레이커 발동" });
    push({ type: "PLANNER_RESPONSE", content: KOREAN_PROSE, tool_calls: [{ name: "edit_file", args: { Path: "/repo/src/err.mjs" } }] });
    push({ type: "GENERIC", status: "DONE", error: "permission denied", content: "실패 ".repeat(50) });
    push({ type: "PLANNER_RESPONSE", tool_calls: [{ name: "edit_file", args: { Path: "/repo/src/late.mjs" } }], content: KOREAN_PROSE });
    push({ type: "GENERIC", status: "DONE", content: "ok" });
    push({ type: "PLANNER_RESPONSE", content: KOREAN_PROSE, usage: { input_tokens: 9000, output_tokens: 300 }, tool_calls: [{ name: "run_command", args: { CommandLine: "node --test" } }] });
    push({ type: "GENERIC", status: "DONE", content: "ℹ tests 3\nℹ pass 2\nℹ fail 1\n" });
    records.push({ type: "PLANNER_RESPONSE", content: KOREAN_PROSE, tool_calls: [{ name: "edit_file", args: { Path: "/repo/src/noindex.mjs" } }] });
    records.push({ type: "GENERIC", status: "DONE", content: "ok" });

    // Same records with the prose the ledger never reads cut short, so the file stays under 1MB.
    const short = records.map((record) => {
      const isCleanWriteResult = record.type === "GENERIC" && record.status === "DONE" && !record.error && !String(record.content).includes("ℹ");
      return record.type === "PLANNER_RESPONSE" || isCleanWriteResult ? { ...record, content: record.content ? "짧음" : record.content } : record;
    });
    const dir = createTempDir("hstack-p2-lean-");
    const bigPath = join(dir, "big.jsonl");
    const shortPath = join(dir, "short.jsonl");
    writeFileSync(bigPath, toJsonl(records), "utf8");
    writeFileSync(shortPath, toJsonl(short), "utf8");
    assert.ok(readFileSync(bigPath).length > 1024 * 1024);
    assert.ok(readFileSync(shortPath).length < 1024 * 1024);

    const lean = readFactLedger(bigPath, "/repo", "/repo");
    assert.deepEqual(lean, readFactLedger(shortPath, "/repo", "/repo"));
    assert.equal(lean.turnWrittenFiles.has("src/denied.mjs"), false);
    assert.equal(lean.turnWrittenFiles.has("src/err.mjs"), false);
    assert.equal(lean.turnWrittenFiles.has("src/noindex.mjs"), true);
    assert.equal(lean.turnAutoChallengeTriggered, true);
    assert.equal(lean.maxSingleFileEdits, 43);
  });

  it("reads tail steps identical to a full read on small transcripts and to its last steps on medium ones", () => {
    const dir = createTempDir("hstack-p2-tail-");
    const build = (turns, prose) => {
      const records = [];
      let step = 0;
      for (let turn = 0; turn < turns; turn += 1) {
        records.push({ step_index: step++, type: "USER_INPUT", content: turn === turns - 1 ? "please answer in English" : "계속해 줘" });
        for (let k = 0; k < 40; k += 1) {
          records.push({ step_index: step++, type: "PLANNER_RESPONSE", content: `${prose} ${turn}-${k}`, tool_calls: [{ name: "run_command", args: { CommandLine: "ls" } }] });
          records.push({ step_index: step++, type: "EPHEMERAL_MESSAGE", content: "x" });
          records.push({ step_index: step++, type: "GENERIC", status: k % 9 === 0 ? "" : "DONE", content: k % 9 === 0 ? "tool call denied by pre-tool hook: 한국어로" : "ok" });
        }
      }
      return records;
    };
    const smallPath = join(dir, "small.jsonl");
    writeFileSync(smallPath, toJsonl(build(3, KOREAN_PROSE)), "utf8");
    assert.deepEqual(hookIo.readTailTranscriptSteps(smallPath, 10), readTranscriptSteps(smallPath));

    const mediumPath = join(dir, "medium.jsonl");
    writeFileSync(mediumPath, toJsonl(build(20, KOREAN_PROSE.repeat(8))), "utf8");
    assert.ok(readFileSync(mediumPath).length > 2 * 1024 * 1024);
    const full = readTranscriptSteps(mediumPath);
    for (const limit of [5, 60, 500]) {
      const tail = full.slice(-limit);
      const lastUser = full.findLast((s) => s.type === "USER_INPUT");
      const expected = tail.includes(lastUser) ? tail : [lastUser, ...tail];
      assert.deepEqual(hookIo.readTailTranscriptSteps(mediumPath, limit), expected, `limit ${limit}`);
    }
  });

  it("gives Stop and PostInvocation the last 500 steps plus the turn's USER_INPUT on a long turn", () => {
    const dir = createTempDir("hstack-p2-window-");
    const path = join(dir, "transcript_full.jsonl");
    writeLongSession(path, join(dir, "repo"), 1500);
    assert.ok(readFileSync(path).length > 1024 * 1024);
    const full = readTranscriptSteps(path);
    const { ledger, steps } = factLedger.readFactLedgerAndSteps(path, join(dir, "repo"), "");
    assert.equal(ledger.turnWrittenFiles.size, 1500);
    assert.equal(steps.length, 501);
    assert.deepEqual(steps[0], full[0]);
    assert.deepEqual(steps.slice(1), full.slice(-500));
  });
});

describe("low #1 a null or non-object latest.json is a corrupt snapshot, not a crash", () => {
  for (const raw of ["null", "[]", "5", '"snapshot"', "true"]) {
    it(`latest.json = ${raw}`, () => {
      const dataDir = createTempDir("hstack-p2-handoff-");
      const workspaceDir = join(dataDir, "handoffs", computeWorkspaceKey("/repo"));
      mkdirSync(workspaceDir, { recursive: true });
      writeFileSync(join(workspaceDir, "latest.json"), raw, "utf8");
      const loaded = loadHandoffSnapshot({ cwd: "/repo", dataDir });
      assert.equal(loaded.ok, false);
      assert.match(loaded.error, /손상/);
    });
  }
});

describe("low #2 custom sensitive patterns with nested quantifiers are rejected by a star-height scan", () => {
  const hostile = "a".repeat(28) + "!";
  for (const pattern of ["((a+))+", "(a+)+", "(a*)*", "(a|a)+", "([a-z]+){2,}", "(a+)+$", "(a)\\1", "(?<x>a)\\k<x>"]) {
    it(`rejects ${pattern} without running it`, () => {
      const { result, elapsedMs } = timeUnderCpuLock(() => isSensitiveFilePath(hostile, { sensitivePatterns: [pattern] }));
      assert.equal(result, false);
      assert.ok(elapsedMs < 50, "the pattern was never executed");
      // Rejected custom patterns leave the defaults in force.
      assert.equal(isSensitiveFilePath("lib/auth/login.mjs", { sensitivePatterns: [pattern] }), true);
    });
  }
  for (const [pattern, match] of [["^auth/", "auth/login.mjs"], ["npm test", "scripts/npm test.sh"], ["vitest", "vitest.config.ts"], ["(^|/)secrets?/", "app/secret/key.mjs"]]) {
    it(`accepts ${pattern}`, () => {
      assert.equal(isSensitiveFilePath(match, { sensitivePatterns: [pattern] }), true);
      // An accepted custom list replaces the defaults.
      assert.equal(isSensitiveFilePath("lib/auth/login.mjs", { sensitivePatterns: [pattern] }), false);
    });
  }
});

describe("low #3 MCP initialize negotiates a supported protocol version", () => {
  const initialize = (protocolVersion) =>
    createMcpServerHandler({ dataDir: createTempDir("hstack-p2-mcp-") })({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion } })
      .result.protocolVersion;
  for (const version of ["2025-06-18", "2025-03-26", "2024-11-05"]) {
    it(`echoes supported ${version}`, () => assert.equal(initialize(version), version));
  }
  for (const version of ["1999-01-01", "2030-01-01", "garbage", "", 20241105, undefined]) {
    it(`answers ${JSON.stringify(version)} with the latest supported version`, () => assert.equal(initialize(version), "2025-06-18"));
  }
});

describe("low #4 a denied tool result maps to its own tool call when untracked records sit between", () => {
  const records = (between) =>
    [
      { type: "USER_INPUT", step_index: 9, content: "버그 고쳐줘" },
      {
        type: "PLANNER_RESPONSE",
        step_index: 10,
        content: "",
        tool_calls: [{ name: "update_steps", args: { steps: [{ title: "Check the session lock file now" }] } }, { name: "run_command", args: {} }],
      },
      ...between,
      { type: "GENERIC", step_index: 11 + between.length, error: "tool call denied by pre-tool hook" },
      { type: "GENERIC", step_index: 12 + between.length, status: "DONE", content: "ok" },
    ];
  const cases = {
    "nothing between": [],
    "an EPHEMERAL_MESSAGE between": [{ type: "EPHEMERAL_MESSAGE", step_index: 11, content: "x" }],
    "two dropped records between": [
      { type: "EPHEMERAL_MESSAGE", step_index: 11, content: "x" },
      { type: "CHECKPOINT", step_index: 12 },
    ],
    "a kept SYSTEM_MESSAGE between": [{ type: "SYSTEM_MESSAGE", step_index: 11, content: "시스템" }],
  };
  for (const [label, between] of Object.entries(cases)) {
    it(`${label}: stream and text readers both map the denial to call 0`, () => {
      const dir = createTempDir("hstack-p2-deny-");
      const path = join(dir, "t.jsonl");
      writeFileSync(path, toJsonl(records(between)), "utf8");
      for (const steps of [readTranscriptSteps(path), parseTranscriptJsonl(toJsonl(records(between)))]) {
        const plannerPos = steps.findIndex((s) => s.type === "PLANNER_RESPONSE");
        assert.deepEqual([...deniedToolCallIndexes(steps, plannerPos)], [0]);
        assert.notEqual(decideHookAction(steps).action, "inject", "the denied English step title is not judged");
      }
    });
  }

  it("counts a GENERIC result too large to parse as the first result", () => {
    const dir = createTempDir("hstack-p2-deny-big-");
    const path = join(dir, "t.jsonl");
    const base = records([]);
    base.splice(2, 0, { type: "GENERIC", step_index: 11, status: "DONE", content: "y".repeat(1100 * 1024) });
    base[3].step_index = 12;
    base[4].step_index = 13;
    writeFileSync(path, toJsonl(base), "utf8");
    const steps = readTranscriptSteps(path);
    assert.deepEqual([...deniedToolCallIndexes(steps, steps.findIndex((s) => s.type === "PLANNER_RESPONSE"))], [1]);
  });
});

describe("B a passing superset clears a narrower failure only on runners whose target-less form runs everything", () => {
  function gate(commands, claim) {
    const dir = createTempDir("hstack-p2-gate-");
    const records = [
      { step_index: 0, type: "USER_INPUT", content: "구현해 줘" },
      { step_index: 1, type: "PLANNER_RESPONSE", tool_calls: [{ name: "write_file", args: { Path: "/repo/src/a.mjs" } }] },
      { step_index: 2, type: "GENERIC", status: "DONE", content: "ok" },
    ];
    let step = 3;
    for (const [cmd, out] of commands) {
      records.push({ step_index: step++, type: "PLANNER_RESPONSE", tool_calls: [{ name: "run_command", args: { CommandLine: cmd } }] });
      records.push({ step_index: step++, type: "GENERIC", status: "DONE", content: out });
    }
    const transcript = join(dir, "t.jsonl");
    writeFileSync(transcript, toJsonl(records), "utf8");
    return decideGate(
      { modified_files: ["src/a.mjs"], inspected_files: [], verification_runs: [{ command: claim, outcome: "pass" }], unverified_scope: [], self_assessment: "" },
      {
        cwd: "/repo",
        ledger: readFactLedger(transcript, "/repo", "/repo"),
        gitLedger: { gitAvailable: false, gitRoot: "/repo", gitDirtyFiles: new Set() },
        testInfra: { hasTestSuite: true },
        auditEscalation: "off",
      },
    ).verdict;
  }
  const FAIL = "AssertionError: boom";

  for (const [failed, passed] of [
    ["node --test test/a.test.mjs", "node --test"],
    ["node --test test/a.test.mjs test/b.test.mjs", "node --test"],
    ["node --test --test-name-pattern auth test/a.test.mjs", "node --test --test-name-pattern auth"],
    ["npm test -- test/a.test.mjs", "npm test"],
    ["npm run test -- src/a.test.ts", "npm run test"],
    ["npx vitest run src/a.test.ts", "npx vitest run"],
    ["npx jest src/a.test.js", "npx jest"],
    ["pytest tests/test_a.py::test_one", "pytest"],
    ["go test ./pkg/x", "go test ./..."],
    ["go test", "go test ./..."],
    ["go test -race ./pkg/x ./pkg/y", "go test -race ./..."],
  ]) {
    it(`PASS: failing \`${failed}\` then passing \`${passed}\``, () => {
      const out = failed.startsWith("go ") ? "FAIL\tpkg/x" : FAIL;
      assert.equal(gate([[failed, out], [passed, passed.startsWith("go ") ? "ok  \trepo\t0.01s" : "# pass 3"]], passed), "PASS");
    });
  }

  for (const [failed, passed] of [
    ["go test ./...", "go test"],
    ["go test ./...", "go test ./pkg/x"],
    ["go test ../other/...", "go test ./..."],
    ["go test -run TestA ./...", "go test ./..."],
    ["node --test", "node --test test/a.test.mjs"],
    ["node --test --test-only test/a.test.mjs", "node --test"],
    ["node --test test/a.test.mjs test/b.test.mjs", "node --test test/b.test.mjs"],
    ["npx vitest run --dir src/a", "npx vitest run --dir"],
    ["npm test -- --grep auth", "npm test"],
    ["npm run test", "npm run"],
    ["npx vitest run auth", "npx vitest run"],
    ["cargo test parser", "cargo test"],
  ]) {
    it(`REJECT: failing \`${failed}\` then passing \`${passed}\``, () => {
      const out = failed.startsWith("go ") ? "FAIL\tpkg/x" : FAIL;
      assert.equal(gate([[failed, out], [passed, passed.startsWith("go ") ? "ok  \trepo\t0.01s" : "# pass 3"]], passed), "REJECT");
    });
  }
});

describe("version 0.1.2", () => {
  it("plugin.json and the MCP server report 0.1.2", () => {
    assert.equal(JSON.parse(readFileSync(join(PLUGIN_ROOT, "plugin.json"), "utf8")).version, "0.1.2");
    const init = createMcpServerHandler({ dataDir: createTempDir("hstack-p2-ver-") })({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    assert.equal(init.result.serverInfo.version, "0.1.2");
  });
});

// Seeded multi-turn transcripts that exercise every turn-scoped ledger field, plus the session-wide ones the
// head and tail scans must recover: header role (auditor/challenger/worker prompts), tokens from an earlier
// turn, and records with no step index (their fallback index needs the whole file, so the scan reads it all).
function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function rolePrompts() {
  const dir = createTempDir("hstack-p2-roles-");
  const mainPath = join(dir, "main.jsonl");
  writeFileSync(mainPath, toJsonl([{ step_index: 0, type: "USER_INPUT", content: "검토해 줘" }]), "utf8");
  const inject = (TypeName) =>
    handlePreToolGate(
      JSON.stringify({ hookEventName: "PreToolUse", conversationId: "p2-roles", cwd: "/repo", transcriptPath: mainPath, toolCall: { name: "invoke_subagent", args: { TypeName, Prompt: "검토" } } }),
      { dataDir: dir, skipAuditLog: true },
    ).overwrite.Prompt;
  return [inject(AUDITOR_AGENT_NAME), inject(CHALLENGER_AGENT_NAME), inject(WORKER_AGENT_NAME)];
}

function generateSession(rand, prompts, { unindexed = false } = {}) {
  const pick = (items) => items[Math.floor(rand() * items.length)];
  const records = [];
  let step = 0;
  const push = (record) => {
    records.push(unindexed && rand() < 0.05 ? record : { step_index: step, ...record });
    step += 1;
  };
  const uid = () => `${Math.floor(rand() * 0xffffffff).toString(16).padStart(8, "0")}-1111-2222-3333-444444444444`;
  const header = rand() < 0.4 ? pick(prompts) : "기능을 구현해 줘";
  push({ type: "USER_INPUT", content: header });
  if (rand() < 0.3) {
    push({ type: "SYSTEM_MESSAGE", content: rand() < 0.5 ? pick(prompts) : "세션 시작" });
  }
  const turns = 1 + Math.floor(rand() * 6);
  for (let turn = 0; turn < turns; turn += 1) {
    if (turn > 0) {
      push({ type: "USER_INPUT", content: pick(["계속해 줘", "/hstack-preflight 검토", "고쳐 줘", pick(prompts)]) });
    }
    const pendingAsync = [];
    const actions = 1 + Math.floor(rand() * 10);
    for (let a = 0; a < actions; a += 1) {
      const usage = rand() < 0.3 ? { usage: { input_tokens: Math.floor(rand() * 1e5), output_tokens: 7 } } : {};
      const kind = pick(["edit", "edit", "deny", "exec", "exec", "gate", "audit", "audit_async", "worker", "challenge", "vote", "sys", "read", "decoy"]);
      const file = `/repo/src/m${Math.floor(rand() * 5)}.mjs`;
      if (kind === "edit" || kind === "deny") {
        push({ type: "PLANNER_RESPONSE", content: "수정", ...usage, tool_calls: [{ name: pick(["edit_file", "write_file"]), args: { Path: file } }] });
        if (kind === "deny") {
          push({ type: "GENERIC", status: "ERROR", error: "tool call denied by pre-tool hook", content: "tool call denied by pre-tool hook: 서킷브레이커 발동" });
        } else {
          push({ type: "GENERIC", status: pick(["DONE", "DONE", "ERROR"]), content: "ok" });
        }
      } else if (kind === "exec") {
        push({ type: "PLANNER_RESPONSE", ...usage, tool_calls: [{ name: "run_command", args: { CommandLine: pick(["node --test", "npm test", "ls", "sed -i s/a/b/ x.mjs", "npm test || true"]) } }] });
        push({ type: "GENERIC", status: "DONE", content: pick(["ℹ pass 3\nℹ fail 0", "ℹ pass 1\nℹ fail 2", "AssertionError: boom", "ok"]) });
      } else if (kind === "gate") {
        push({ type: "PLANNER_RESPONSE", ...usage, tool_calls: [{ name: GATE_TOOL_NAME, args: {} }] });
        push({ type: "GENERIC", status: "DONE", content: pick(["[완료 검증 통과]", "[검증 반려] R1"]) });
      } else if (kind === "audit" || kind === "challenge") {
        const TypeName = kind === "audit" ? AUDITOR_AGENT_NAME : CHALLENGER_AGENT_NAME;
        push({ type: "PLANNER_RESPONSE", ...usage, tool_calls: [{ name: "invoke_subagent", args: { TypeName, Prompt: rand() < 0.5 ? "[hstack:자동사전검토] 검토" : "감사" } }] });
        push({ type: "GENERIC", status: "DONE", content: pick(["결함 없음\n[감사 판정: 통과]", "[사전검토 판정: PROCEED]", "[감사 판정: 기각]"]) });
      } else if (kind === "audit_async" || kind === "worker") {
        const id = uid();
        const TypeName = kind === "worker" ? WORKER_AGENT_NAME : pick([AUDITOR_AGENT_NAME, CHALLENGER_AGENT_NAME]);
        push({ type: "PLANNER_RESPONSE", ...usage, tool_calls: [{ name: "invoke_subagent", args: { TypeName, Prompt: "작업" } }] });
        push({ type: "GENERIC", status: "DONE", content: `Subagent launched with conversationId: ${id}` });
        pendingAsync.push(id);
      } else if (kind === "vote") {
        push({ type: "PLANNER_RESPONSE", ...usage, tool_calls: [{ name: "ask_question", args: {} }] });
        push({ type: "GENERIC", status: "DONE", content: "A1: 진행" });
      } else if (kind === "sys") {
        const id = pendingAsync.length > 0 && rand() < 0.7 ? pendingAsync.shift() : uid();
        push({
          type: "SYSTEM_MESSAGE",
          content: pick([
            `${GATE_STOP_MARKER} 검증 먼저`,
            `${AUTO_CHALLENGER_MARKER} 사전검토`,
            `${AUTO_HANDOFF_MARKER} 위임`,
            `[Message] sender=${id} content=결함 없음\n[감사 판정: 통과]`,
            `[Message] sender=${id} content=[사전검토 판정: RETHINK]`,
          ]),
        });
      } else if (kind === "read") {
        push({ type: "PLANNER_RESPONSE", ...usage, tool_calls: [{ name: "read_file", args: { Path: file } }] });
        push({ type: "GENERIC", status: "DONE", content: "export const x = 1;" });
      } else {
        // Tool output that quotes a transcript: the tail scan must not take it for a turn start.
        push({ type: "PLANNER_RESPONSE", ...usage, tool_calls: [{ name: "run_command", args: { CommandLine: "cat t.jsonl" } }] });
        push({ type: "GENERIC", status: "DONE", content: '{"step_index":9,"type":"USER_INPUT","content":"가짜"}\n"type":"USER_INPUT"' });
        if (rand() < 0.3) {
          records.push({ content: "x", type: "USER_INPUT_NOTE", note: '"type":"USER_INPUT"' });
        }
        if (rand() < 0.3) {
          // Duplicate keys: the prefix says GENERIC (skipped without a pending call), JSON.parse says USER_INPUT.
          records.push(`{"step_index":${step++},"type":"GENERIC","type":"USER_INPUT","content":"중복"}`);
        }
      }
    }
    if (rand() < 0.5) {
      push({ type: "PLANNER_RESPONSE", content: pick(["완료했습니다.", "All done, tests pass."]) });
    }
  }
  return records;
}

const withoutReadFiles = (ledger) => ({ ...ledger, sessionReadFiles: null });

describe("#7 head and tail scans read only the header and the current turn of a long session", () => {
  it("matches the full scan on generated multi-turn sessions in every field but the session-wide read set", () => {
    const prompts = rolePrompts();
    const dir = createTempDir("hstack-p2-prop-");
    const rand = mulberry32(0x5eed);
    let partialRoles = 0;
    for (let i = 0; i < 300; i += 1) {
      const path = join(dir, `s${i}.jsonl`);
      const lines = generateSession(rand, prompts, { unindexed: i % 10 === 9 }).map((r) => (typeof r === "string" ? r : JSON.stringify(r)));
      writeFileSync(path, `${lines.join("\n")}\n`, "utf8");
      const full = readFactLedger(path, "/repo", "/repo");
      const partial = factLedger.readTurnLedger(path, "/repo", "/repo", { partialMinBytes: 0 });
      assert.deepEqual(withoutReadFiles(partial), withoutReadFiles(full), `session ${i}`);
      for (const p of partial.sessionReadFiles) {
        assert.ok(full.sessionReadFiles.has(p), `session ${i} read ${p}`);
      }
      assert.equal(factLedger.readSessionRole(path), full.sessionRole, `session ${i} role`);
      // Small files never take the partial path, so their ledger is the full one, read set included.
      assert.deepEqual(factLedger.readTurnLedger(path, "/repo", "/repo"), full, `session ${i} small`);
      partialRoles += full.sessionRole === "main" ? 0 : 1;
    }
    assert.ok(partialRoles > 50, `${partialRoles} sessions carry a governance role`);
  });

  it("reads a 100-turn ~26MB session's ledger in well under the full-scan time", () => {
    const dir = createTempDir("hstack-p2-multi-");
    const path = join(dir, "transcript_full.jsonl");
    const fd = openSync(path, "w");
    let step = 0;
    let buf = "";
    for (let turn = 0; turn < 100; turn += 1) {
      buf += `${JSON.stringify({ step_index: step++, type: "USER_INPUT", content: `수정해 줘 ${turn}` })}\n`;
      for (let k = 0; k < 200; k += 1) {
        buf += `${JSON.stringify({ step_index: step++, type: "PLANNER_RESPONSE", content: KOREAN_PROSE, tool_calls: [{ name: "edit_file", args: { Path: `/repo/f${k}.mjs`, CodeContent: "x".repeat(285) } }] })}\n`;
        buf += `${JSON.stringify({ step_index: step++, type: "GENERIC", status: "DONE", content: "ok ".repeat(100) })}\n`;
      }
      writeSync(fd, buf);
      buf = "";
    }
    closeSync(fd);
    assert.ok(readFileSync(path).length > 20 * 1024 * 1024);
    withCpuLock(() => {
      const samples = [];
      let ledger;
      for (let i = 0; i < 3; i += 1) {
        const t0 = performance.now();
        ({ ledger } = factLedger.readFactLedgerAndSteps(path, "/repo", "/repo"));
        samples.push(performance.now() - t0);
      }
      assert.equal(ledger.turnStartStepIndex, 99 * 401);
      assert.equal(ledger.turnWrittenFiles.size, 200);
      assert.ok(Math.min(...samples) < 100, `readFactLedgerAndSteps fastest ${Math.min(...samples).toFixed(0)}ms (>= 100ms)`);
    });
  });

  it("settles a run_command's session role from the header of a ~26MB transcript", () => {
    const dir = createTempDir("hstack-p2-rc-");
    const [auditorPrompt] = rolePrompts();
    const path = join(dir, "transcript_full.jsonl");
    writeLongSession(path, join(dir, "repo"), 20_000, auditorPrompt);
    const call = (CommandLine) =>
      handlePreToolGate(
        JSON.stringify({ hookEventName: "PreToolUse", conversationId: "p2-rc", cwd: "/repo", transcriptPath: path, toolCall: { name: "run_command", args: { CommandLine } } }),
        { dataDir: dir, skipAuditLog: true, governanceConfig: { autonomyMode: "off" } },
      );
    withCpuLock(() => {
      const samples = [];
      for (let i = 0; i < 3; i += 1) {
        const t0 = performance.now();
        assert.equal(call("sed -i s/a/b/ app.mjs").decision, "deny");
        samples.push(performance.now() - t0);
      }
      // Read-only roles get no shell at all (gate audit run 1); a main session would allow both.
      assert.equal(call("node --test").decision, "deny");
      assert.ok(Math.min(...samples) < 50, `run_command gate fastest ${Math.min(...samples).toFixed(0)}ms (>= 50ms)`);
    });
  });
});

describe("#7 a record that starts exactly on a 256KiB read boundary keeps its first bytes", () => {
  it("reads the write in a planner whose line begins at byte 262144", () => {
    const dir = createTempDir("hstack-p2-boundary-");
    const path = join(dir, "t.jsonl");
    const first = { step_index: 0, type: "USER_INPUT", content: "" };
    first.content = "가".repeat(Math.floor((256 * 1024 - Buffer.byteLength(JSON.stringify(first)) - 1) / 3));
    let line = JSON.stringify(first);
    line = JSON.stringify({ ...first, content: first.content + "x".repeat(256 * 1024 - 1 - Buffer.byteLength(line)) });
    assert.equal(Buffer.byteLength(line) + 1, 256 * 1024);
    const rest = [
      { step_index: 1, type: "PLANNER_RESPONSE", content: KOREAN_PROSE, tool_calls: [{ name: "edit_file", args: { Path: "/repo/src/edge.mjs" } }] },
      { step_index: 2, type: "GENERIC", status: "DONE", content: "ok" },
    ];
    writeFileSync(path, `${line}\n${toJsonl(rest)}`, "utf8");
    assert.equal(readFactLedger(path, "/repo", "/repo").turnWrittenFiles.has("src/edge.mjs"), true);
    assert.deepEqual(
      readTranscriptSteps(path).map((s) => s.stepIndex),
      [0, 1],
    );
  });
});
