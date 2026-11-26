// v0.1.2 Checkpoint 3 (P2): long-session hook latency, corrupt handoff snapshots, custom-pattern ReDoS,
// MCP protocol negotiation, tool-result offsets, runner-aware failure clearing, and the 0.1.2 version.
import assert from "node:assert/strict";
import { closeSync, mkdirSync, openSync, readFileSync, writeFileSync, writeSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import { decideGate } from "../scripts/governance/decide-gate.mjs";
import * as factLedger from "../scripts/governance/fact-ledger.mjs";
import { readFactLedger } from "../scripts/governance/fact-ledger.mjs";
import { computeWorkspaceKey, loadHandoffSnapshot } from "../scripts/governance/handoff-store.mjs";
import { isSensitiveFilePath } from "../scripts/governance/risk-classifier.mjs";
import * as hookIo from "../scripts/hook-io.mjs";
import { readTranscriptSteps } from "../scripts/hook-io.mjs";
import { createMcpServerHandler } from "../scripts/mcp/server.mjs";
import { decideHookAction, parseTranscriptJsonl } from "../scripts/transcript.mjs";
import { deniedToolCallIndexes } from "../scripts/transcript/steps.mjs";
import { HOOK_SCRIPT, PLUGIN_ROOT, STOP_HOOK_SCRIPT, createTempDir, runHookSubprocess, toJsonl, withCpuLock } from "./helpers.mjs";

const KOREAN_PROSE = "작업 중입니다 ".repeat(20);

// Same shape as the audit's 60,000-step transcript: one USER_INPUT, then edit_file planners with Korean prose
// and their GENERIC results, ending with an English answer so both drift checks run on the bounded tail.
function writeLongSession(path, repo, pairs) {
  const fd = openSync(path, "w");
  let buf = `${JSON.stringify({ step_index: 0, type: "USER_INPUT", content: "수정해 줘" })}\n`;
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

function medianHookMs(script, payload, runs = 3) {
  const samples = [];
  let last = null;
  for (let i = 0; i < runs; i += 1) {
    const dataDir = createTempDir("hstack-p2-hookdata-");
    const t0 = performance.now();
    last = runHookSubprocess(script, JSON.stringify(payload), { env: { ...process.env, HSTACK_DATA_DIR: dataDir } });
    samples.push(performance.now() - t0);
  }
  samples.sort((a, b) => a - b);
  return { median: samples[Math.floor(runs / 2)], output: JSON.parse(last.stdout) };
}

describe("#7 hooks on a long single-turn session stay far under the 5s hook timeout", () => {
  // In-suite fixture: 20,000 tool calls (40,000 records, ~26MB), a third of the audit's 60,000-call / 77MB
  // file, so the suite stays fast. v0.1.1 needs ~1.4s for Stop here and longer for PostInvocation, which
  // replays a drift check on every planner; v0.1.2 needs ~0.5s. The 60,000-call run is measured outside.
  it("Stop and PostInvocation each finish a 20,000-call transcript in under 1000ms (3-run median)", () => {
    const dir = createTempDir("hstack-p2-long-");
    const repo = join(dir, "repo");
    mkdirSync(repo);
    const transcriptPath = join(dir, "transcript_full.jsonl");
    writeLongSession(transcriptPath, repo, 20_000);
    const base = { conversationId: "p2-long", cwd: repo, transcriptPath };

    withCpuLock(() => {
      const stop = medianHookMs(STOP_HOOK_SCRIPT, { ...base, hookEventName: "Stop", terminationReason: "NO_TOOL_CALL", executionNum: 0 });
      assert.equal(stop.output.decision, "continue");
      assert.ok(stop.median < 1000, `Stop median ${stop.median.toFixed(0)}ms (>= 1000ms)`);

      const post = medianHookMs(HOOK_SCRIPT, { ...base, hookEventName: "PostInvocation" });
      assert.ok(Array.isArray(post.output.injectSteps), "the English answer is still flagged on the bounded tail");
      assert.ok(post.median < 1000, `PostInvocation median ${post.median.toFixed(0)}ms (>= 1000ms)`);
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
      const t0 = performance.now();
      assert.equal(isSensitiveFilePath(hostile, { sensitivePatterns: [pattern] }), false);
      assert.ok(performance.now() - t0 < 50, "the pattern was never executed");
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
