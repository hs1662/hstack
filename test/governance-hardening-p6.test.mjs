// v0.1.2 gate audit run 1: read-only roles and shell, verification credit, gate snapshot, lock ownership, tail scan.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { closeSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync, writeSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import { analyzeField } from "../scripts/analyzer.mjs";
import { AUDITOR_SESSION_MARKER, CHALLENGER_SESSION_MARKER, GATE_TOOL_NAME, VERDICT_HEADERS } from "../scripts/governance/constants.mjs";
import { classifyCommand, readFactLedger } from "../scripts/governance/fact-ledger.mjs";
import * as store from "../scripts/governance/handoff-store.mjs";
import * as hookIo from "../scripts/hook-io.mjs";
import { createMcpServerHandler } from "../scripts/mcp/server.mjs";
import { handlePreToolGate } from "../scripts/pre-tool-gate.mjs";
import { handlePreInvocation } from "../scripts/prompt-router.mjs";
import { handleStop } from "../scripts/stop.mjs";
import { GATE_STOP_MARKER } from "../scripts/transcript.mjs";
import { createTempDir, toJsonl } from "./helpers.mjs";

const DATA_DIR = createTempDir("hstack-p6-data-");
process.env.HSTACK_DATA_DIR = DATA_DIR;

const WRITES_DISGUISED_AS_CHECKS = [
  "node --version > src/auth/token.mjs",
  "python3 --version > app.mjs",
  `python3 -c"open('app.mjs','w').write('x')"`,
  `bash -c "node --version > app.mjs"`,
  `bash -c"node --version > app.mjs"`,
  `node -e"require('fs').writeFileSync('app.mjs','x')"`,
  "npm test > src/auth/token.mjs",
];

describe("F1 auditor and challenger sessions never run a shell command", () => {
  const dir = createTempDir("hstack-p6-role-");
  const call = (marker, commandLine) => {
    const tp = join(dir, `${Math.random().toString(36).slice(2)}.jsonl`);
    writeFileSync(tp, toJsonl([{ step_index: 0, type: "USER_INPUT", content: `감사해 줘\n${marker}\n작업 경로: \`/repo\`\n세션 기록 경로: \`/x\`` }]));
    return handlePreToolGate(
      JSON.stringify({ hookEventName: "PreToolUse", conversationId: "c", cwd: "/repo", transcriptPath: tp, toolCall: { name: "run_command", args: { CommandLine: commandLine } } }),
      { dataDir: dir, skipAuditLog: true, governanceConfig: { autonomyMode: "smart" } },
    );
  };

  for (const [role, marker] of [["auditor", AUDITOR_SESSION_MARKER], ["challenger", CHALLENGER_SESSION_MARKER]]) {
    it(`${role} is denied every run_command with the Korean read-only reason`, () => {
      for (const cmd of [...WRITES_DISGUISED_AS_CHECKS, "npx prettier --write .", "npm test", "node --test", "git diff", "rg -n x src", ""]) {
        const out = call(marker, cmd);
        assert.equal(out.decision, "deny", cmd);
        assert.equal(analyzeField("content", out.reason).status, "korean");
      }
    });
  }
});

describe("F1/F2 a write disguised as a check earns no verification credit", () => {
  it("classifies redirected and attached-flag interpreter writes as other", () => {
    for (const cmd of WRITES_DISGUISED_AS_CHECKS) {
      assert.equal(classifyCommand(cmd), "other", cmd);
    }
  });

  it("keeps real checks credited", () => {
    for (const cmd of [
      "npm test",
      "node --test",
      "cd x && node --test",
      "node --test 2>/dev/null",
      "npm test 2>&1",
      `bash -c "npm test"`,
      `bash -c"npm test"`,
      "python -m pytest -q",
      "python3 -mpytest",
      "pytest -q",
    ]) {
      assert.equal(classifyCommand(cmd), "verification", cmd);
    }
  });
});

describe("F3 a rejected verify_completion never hides a shell edit made after the passing one", () => {
  const git = (cwd, args) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

  function makeRepo() {
    const repo = createTempDir("hstack-p6-repo-");
    git(repo, ["init", "-q"]);
    git(repo, ["config", "user.email", "t@example.com"]);
    git(repo, ["config", "user.name", "T"]);
    mkdirSync(join(repo, "src"));
    writeFileSync(join(repo, "app.mjs"), "export const v = 1;\n");
    writeFileSync(join(repo, "src", "x.mjs"), "a\n");
    git(repo, ["add", "."]);
    git(repo, ["commit", "-qm", "init"]);
    writeFileSync(join(repo, ".git", "info", "exclude"), ".t.jsonl\n");
    return repo;
  }

  // Each gate step runs the real PreToolUse hook and the real MCP server, so its verdict comes from the ledger.
  function runTurn(repo, conversationId, steps) {
    const transcriptPath = join(repo, ".t.jsonl");
    const user = "app.mjs 고쳐 줘";
    const records = [{ step_index: 0, type: "USER_INPUT", content: user }];
    const flush = () => writeFileSync(transcriptPath, toJsonl(records));
    flush();
    handlePreInvocation(JSON.stringify({ hookEventName: "PreInvocation", invocationNum: 0, conversationId, cwd: repo, transcriptPath }), {
      dataDir: DATA_DIR,
      skipAuditLog: true,
    });
    const server = createMcpServerHandler({ dataDir: DATA_DIR, register: "neutral" });
    const verdicts = [];
    for (const step of steps) {
      let call;
      let result = "ok";
      if (step.gate) {
        call = { name: GATE_TOOL_NAME, args: step.gate };
        records.push({ step_index: records.length, type: "PLANNER_RESPONSE", tool_calls: [call] });
        flush();
        const pre = handlePreToolGate(JSON.stringify({ hookEventName: "PreToolUse", conversationId, cwd: repo, transcriptPath, toolCall: call }), {
          dataDir: DATA_DIR,
          skipAuditLog: true,
        });
        const res = server({ jsonrpc: "2.0", id: records.length, method: "tools/call", params: { name: "verify_completion", arguments: { ...step.gate, ...pre.overwrite } } });
        result = res.result.content[0].text;
        verdicts.push(result.split("\n")[0]);
        records.push({ step_index: records.length, type: "GENERIC", status: "DONE", content: result });
        flush();
        continue;
      }
      if (step.write) {
        writeFileSync(join(repo, step.write), step.content);
        call = { name: "write_file", args: { Path: join(repo, step.write), Content: step.content } };
      } else {
        step.effect?.();
        call = { name: "run_command", args: { CommandLine: step.cmd, Cwd: repo } };
        result = step.output ?? "ok";
      }
      records.push({ step_index: records.length, type: "PLANNER_RESPONSE", tool_calls: [call] });
      records.push({ step_index: records.length, type: "GENERIC", status: "DONE", content: result });
      flush();
    }
    records.push({ step_index: records.length, type: "PLANNER_RESPONSE", content: "수정을 완료했습니다. 이제 정상 동작합니다." });
    flush();
    const out = handleStop(
      JSON.stringify({ hookEventName: "Stop", terminationReason: "NO_TOOL_CALL", executionNum: 0, conversationId, cwd: repo, transcriptPath, lastUserInput: user }),
    );
    return { out, verdicts };
  }

  const claim = (command) => ({
    modified_files: ["app.mjs"],
    inspected_files: ["app.mjs"],
    verification_runs: [{ command, outcome: "pass" }],
    unverified_scope: ["없음"],
    self_assessment: "수정 사항과 테스트 통과 결과를 직접 확인했습니다.",
  });
  const verifiedEdit = [
    { write: "app.mjs", content: "export const v = 2;\n" },
    { cmd: "node --test", output: "ℹ tests 1\nℹ pass 1\nℹ fail 0\n" },
    { gate: claim("node --test") },
  ];
  const disguisedEdit = { cmd: "git status", effect: (repo) => writeFileSync(join(repo, "src", "x.mjs"), "b\n") };

  it("blocks Stop after pass, a shell edit, then a rejected gate", () => {
    const repo = makeRepo();
    const { out, verdicts } = runTurn(repo, "p6-f3-reject", [
      ...verifiedEdit,
      { ...disguisedEdit, effect: () => disguisedEdit.effect(repo) },
      { gate: claim("npm run never-ran") },
    ]);
    assert.equal(verdicts[0], VERDICT_HEADERS.PASS, verdicts.join(" | "));
    assert.notEqual(verdicts[1], VERDICT_HEADERS.PASS, verdicts.join(" | "));
    assert.equal(out.decision, "continue", JSON.stringify(out));
    assert.ok(out.reason.includes(GATE_STOP_MARKER), out.reason);
  });

  it("still allows Stop after a verified edit with no later change", () => {
    const repo = makeRepo();
    const { out, verdicts } = runTurn(repo, "p6-f3-ok", verifiedEdit);
    assert.equal(verdicts[0], VERDICT_HEADERS.PASS);
    assert.deepEqual(out, {});
  });

  it("still allows Stop when a rejected gate is followed by a passing one with no later change", () => {
    const repo = makeRepo();
    const { out, verdicts } = runTurn(repo, "p6-f3-reject-then-pass", [
      { write: "app.mjs", content: "export const v = 2;\n" },
      { cmd: "node --test", output: "ℹ tests 1\nℹ pass 1\nℹ fail 0\n" },
      { gate: claim("npm run never-ran") },
      { gate: claim("node --test") },
    ]);
    assert.notEqual(verdicts[0], VERDICT_HEADERS.PASS);
    assert.equal(verdicts[1], VERDICT_HEADERS.PASS, verdicts.join(" | "));
    assert.deepEqual(out, {});
  });
});

describe("F4 a session lock owner releases only its own lock", () => {
  it("leaves a lock another process reclaimed and re-acquired untouched", () => {
    const dir = createTempDir("hstack-p6-lock-");
    const file = join(dir, "s.json");
    const lockPath = `${file}.lock`;
    const theirs = JSON.stringify({ pid: process.pid, createdAt: Date.now(), nonce: "other-owner" });
    store.withSessionLock(file, () => {
      // What a reclaimer does after the 120s cap: move the old lock away, then a new owner creates its own.
      renameSync(lockPath, `${lockPath}.stale.test`);
      writeFileSync(lockPath, theirs);
    });
    assert.equal(readFileSync(lockPath, "utf8"), theirs);
  });

  it("still removes its own lock", () => {
    const dir = createTempDir("hstack-p6-lock-");
    const file = join(dir, "s.json");
    assert.equal(store.withSessionLock(file, () => 7), 7);
    assert.throws(() => readFileSync(`${file}.lock`), { code: "ENOENT" });
  });
});

describe("F5 findLastLine stays bounded and sees the line at its start offset", () => {
  const dir = createTempDir("hstack-p6-tail-");

  it("finds a line that starts exactly at a non-zero start", () => {
    const path = join(dir, "start.jsonl");
    const head = "a\n".repeat(1000);
    writeFileSync(path, `${head}NEEDLE first\nb\nc\n`);
    const hit = hookIo.findLastLine(path, "NEEDLE", (line) => line.toString(), { start: head.length });
    assert.deepEqual(hit, { offset: head.length, value: "NEEDLE first" });
    // A line that began before start stays out of range.
    assert.equal(hookIo.findLastLine(path, "NEEDLE", (line) => line.toString(), { start: head.length + 1 }), null);
  });

  it("finds a match on the first chunk boundary and in the file's first line", () => {
    const path = join(dir, "first.jsonl");
    writeFileSync(path, `NEEDLE 0\n${"z".repeat(300 * 1024)}\nq\n`);
    assert.deepEqual(hookIo.findLastLine(path, "NEEDLE", (line) => line.toString()), { offset: 0, value: "NEEDLE 0" });
  });

  it("gives up on a line over 4MiB instead of growing its buffer to the line", () => {
    const path = join(dir, "long.jsonl");
    const fd = openSync(path, "w");
    writeSync(fd, "NEEDLE ");
    const block = Buffer.alloc(1 << 20, 0x7a);
    for (let i = 0; i < 24; i += 1) {
      writeSync(fd, block);
    }
    writeSync(fd, "\nshort\n");
    closeSync(fd);
    const realAlloc = Buffer.allocUnsafe;
    let maxAlloc = 0;
    Buffer.allocUnsafe = (n) => {
      maxAlloc = Math.max(maxAlloc, n);
      return realAlloc(n);
    };
    let hit;
    try {
      hit = hookIo.findLastLine(path, "NEEDLE", () => true);
    } finally {
      Buffer.allocUnsafe = realAlloc;
    }
    assert.ok(hookIo.LINE_TOO_LONG !== undefined && hit === hookIo.LINE_TOO_LONG, String(hit));
    assert.ok(maxAlloc <= 8 * 1024 * 1024, `allocated ${maxAlloc} bytes`);
  });

  it("falls back to the full scan when the last USER_INPUT line is over 4MiB", () => {
    const path = join(dir, "huge-turn.jsonl");
    const pad = "가".repeat(200);
    const rows = [{ step_index: 0, type: "USER_INPUT", content: "처음 요청" }];
    for (let i = 1; i < 15000; i += 1) {
      rows.push({ step_index: i, type: "GENERIC", status: "DONE", content: pad });
    }
    rows.push({ step_index: 15000, type: "USER_INPUT", content: `x${"y".repeat(9 * 1024 * 1024)}` });
    rows.push({ step_index: 15001, type: "PLANNER_RESPONSE", content: "답변" });
    writeFileSync(path, toJsonl(rows));
    assert.equal(readFactLedger(path, "", "").turnStartStepIndex, 15000);
  });
});
