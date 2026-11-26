// v0.1.2 gate audit run 2: verification credit is a positive grammar, shell edits reach verify_completion,
// and mcp_agy-fast_fast_run_checks is gated like run_command.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import { analyzeField } from "../scripts/analyzer.mjs";
import { AUDITOR_SESSION_MARKER, CHALLENGER_SESSION_MARKER, GATE_TOOL_NAME, VERDICT_HEADERS } from "../scripts/governance/constants.mjs";
import { classifyCommand, readFactLedger } from "../scripts/governance/fact-ledger.mjs";
import { createMcpServerHandler } from "../scripts/mcp/server.mjs";
import { handlePreToolGate } from "../scripts/pre-tool-gate.mjs";
import { handlePreInvocation } from "../scripts/prompt-router.mjs";
import { handleStop } from "../scripts/stop.mjs";
import { GATE_STOP_MARKER } from "../scripts/transcript.mjs";
import { HOOKS_JSON_PATH, createTempDir, toJsonl } from "./helpers.mjs";

const DATA_DIR = createTempDir("hstack-p7-data-");
process.env.HSTACK_DATA_DIR = DATA_DIR;
const CHECK_TOOL = "mcp_agy-fast_fast_run_checks";

describe("G1 verification credit needs the whole command to match the runner grammar", () => {
  it("gives no credit to the audit's run 2 strings or other shell syntax around a runner", () => {
    for (const cmd of [
      'bash -c "npm test" > src/auth/token.mjs',
      "(! npm test >/dev/null 2>&1)",
      "( npm test )",
      "{ npm test; }",
      'bash -c "npm test" extra',
      'bash -c "npm test" 2>&1',
      "set -n && npm test",
      "set -o noexec && npm test",
      "NODE_OPTIONS=--require=./x.cjs npm test",
      "LD_PRELOAD=/tmp/x.so npm test",
      "BASH_ENV=/tmp/x bash -c 'npm test'",
      "ENV=/tmp/x sh -c 'npm test'",
      "npm test < input.txt",
      "npm test >> src/a.mjs",
      "npm test 2> src/a.mjs",
      "npm test &> /dev/null",
      "npm test | tail -5",
      "set -o pipefail && npm test | tee out.log",
      "set -o pipefail && npm test | tail -5 | cat",
      'npm test "$X"',
      "npm test $X",
      "npm test \\; true",
    ]) {
      assert.equal(classifyCommand(cmd), "other", cmd);
    }
  });

  it("credits runner commands with allowed prefixes, assignments and redirects", () => {
    for (const cmd of [
      "npm test",
      "cd x && npm test",
      "set -euo pipefail && npm test 2>&1 | tail -20",
      "CI=1 npm test >/dev/null 2>&1",
      "npm test > test.log 2>&1",
      "npm ci && npm run build && npm test",
      "bash -c 'npm test'",
      'sh -c "cd pkg && node --test"',
      "node --test test/*.test.mjs 2>/dev/null",
      "npm test;",
    ]) {
      assert.equal(classifyCommand(cmd), "verification", cmd);
    }
  });
});

function checkLedgerKind(args) {
  const dir = createTempDir("hstack-p7-ledger-");
  const p = join(dir, "t.jsonl");
  writeFileSync(
    p,
    toJsonl([
      { step_index: 0, type: "USER_INPUT", content: "x" },
      { step_index: 1, type: "PLANNER_RESPONSE", tool_calls: [{ name: CHECK_TOOL, args }] },
      { step_index: 2, type: "GENERIC", status: "DONE", content: "ok" },
    ]),
  );
  return readFactLedger(p, "/repo", "/repo").turnExecutions[0].kind;
}

describe("G2 mcp_agy-fast_fast_run_checks commands go through the same grammar", () => {
  it("does not credit a masked or writing check command", () => {
    for (const args of [
      { command: "npm test || true" },
      { command: "sed -i s/a/b/ src/auth/token.mjs" },
      { commands: [{ command: "node --test", name: "t" }, { command: "sed -i s/a/b/ x.mjs", name: "w" }] },
    ]) {
      assert.equal(checkLedgerKind(args), "other", JSON.stringify(args));
    }
  });

  it("still credits a real check command", () => {
    assert.equal(checkLedgerKind({ commands: [{ command: "node --test test/*.test.mjs", name: "t" }] }), "verification");
  });
});

describe("G3 a shell edit counts for verify_completion exactly like a write_file edit", () => {
  const git = (cwd, args) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

  function makeRepo() {
    const repo = createTempDir("hstack-p7-repo-");
    git(repo, ["init", "-q"]);
    git(repo, ["config", "user.email", "t@example.com"]);
    git(repo, ["config", "user.name", "T"]);
    mkdirSync(join(repo, "src", "auth"), { recursive: true });
    mkdirSync(join(repo, "test"));
    writeFileSync(join(repo, "package.json"), '{"scripts":{"test":"node --test"}}\n');
    writeFileSync(join(repo, "test", "a.test.mjs"), "import 'node:test';\n");
    writeFileSync(join(repo, "src", "auth", "token.mjs"), "timingSafeEqual(a, b);\n");
    writeFileSync(join(repo, "app.mjs"), "export const v = 1;\n");
    git(repo, ["add", "."]);
    git(repo, ["commit", "-qm", "init"]);
    writeFileSync(join(repo, ".git", "info", "exclude"), ".t.jsonl\n");
    return repo;
  }

  // The edit is made by `via`: write_file, run_command or the agy-fast check tool. Then each step runs, then the
  // real PreToolUse hook and MCP server judge `claim`, then Stop.
  function runTurn(via, file, content, after, claim) {
    const repo = makeRepo();
    const conversationId = `p7-${via}-${Math.random().toString(36).slice(2)}`;
    const transcriptPath = join(repo, ".t.jsonl");
    const user = "고쳐 줘";
    const records = [{ step_index: 0, type: "USER_INPUT", content: user }];
    const flush = () => writeFileSync(transcriptPath, toJsonl(records));
    const push = (call, result = "ok") => {
      records.push({ step_index: records.length, type: "PLANNER_RESPONSE", tool_calls: [call] });
      records.push({ step_index: records.length, type: "GENERIC", status: "DONE", content: result });
    };
    flush();
    handlePreInvocation(JSON.stringify({ hookEventName: "PreInvocation", invocationNum: 0, conversationId, cwd: repo, transcriptPath }), {
      dataDir: DATA_DIR,
      skipAuditLog: true,
    });
    writeFileSync(join(repo, file), content);
    const sed = `sed -i s/x/y/ ${file}`;
    if (via === "write_file") {
      push({ name: "write_file", args: { Path: join(repo, file), Content: content } });
    } else if (via === "run_command") {
      push({ name: "run_command", args: { CommandLine: sed, Cwd: repo } });
    } else {
      push({ name: CHECK_TOOL, args: { command: sed } });
    }
    for (const cmd of after) {
      push({ name: "run_command", args: { CommandLine: cmd, Cwd: repo } }, "ℹ tests 1\nℹ pass 1\nℹ fail 0\n");
    }
    const call = { name: GATE_TOOL_NAME, args: claim };
    records.push({ step_index: records.length, type: "PLANNER_RESPONSE", tool_calls: [call] });
    flush();
    const pre = handlePreToolGate(JSON.stringify({ hookEventName: "PreToolUse", conversationId, cwd: repo, transcriptPath, toolCall: call }), {
      dataDir: DATA_DIR,
      skipAuditLog: true,
    });
    const server = createMcpServerHandler({ dataDir: DATA_DIR, register: "neutral" });
    const text = server({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "verify_completion", arguments: { ...claim, ...pre.overwrite } } }).result
      .content[0].text;
    records.push({ step_index: records.length, type: "GENERIC", status: "DONE", content: text });
    records.push({ step_index: records.length, type: "PLANNER_RESPONSE", content: "수정을 완료했습니다." });
    flush();
    const stop = handleStop(
      JSON.stringify({ hookEventName: "Stop", terminationReason: "NO_TOOL_CALL", executionNum: 0, conversationId, cwd: repo, transcriptPath, lastUserInput: user }),
    );
    return { verdict: text.split("\n")[0], stop };
  }

  const claim = (files, runs) => ({
    modified_files: files,
    inspected_files: files,
    verification_runs: runs.map((command) => ({ command, outcome: "pass" })),
    unverified_scope: ["없음"],
    self_assessment: "수정 사항과 테스트 통과 결과를 직접 확인했습니다.",
  });
  const CASES = [
    ["an unreported, untested auth edit", "src/auth/token.mjs", "x(a, b);\n", [], claim([], [])],
    ["a reported, tested auth edit", "src/auth/token.mjs", "x(a, b);\n", ["node --test"], claim(["src/auth/token.mjs"], ["node --test"])],
    ["a reported, tested plain edit", "app.mjs", "export const v = 2;\n", ["node --test"], claim(["app.mjs"], ["node --test"])],
  ];

  for (const [label, file, content, after, gateClaim] of CASES) {
    it(`gives ${label} the same verdict and Stop decision through every edit tool`, () => {
      const base = runTurn("write_file", file, content, after, gateClaim);
      for (const via of ["run_command", CHECK_TOOL]) {
        const got = runTurn(via, file, content, after, gateClaim);
        assert.equal(got.verdict, base.verdict, `${via}: ${got.verdict} vs ${base.verdict}`);
        assert.equal(got.stop.decision, base.stop.decision, `${via}: ${JSON.stringify(got.stop)}`);
      }
    });
  }

  it("rejects the unreported shell auth edit and blocks Stop (audit run 2 finding 1)", () => {
    const got = runTurn("run_command", "src/auth/token.mjs", "x(a, b);\n", [], claim([], []));
    assert.notEqual(got.verdict, VERDICT_HEADERS.PASS);
    assert.equal(got.stop.decision, "continue");
    assert.ok(got.stop.reason.includes(GATE_STOP_MARKER), got.stop.reason);
  });

  it("escalates a tested shell auth edit to the independent audit", () => {
    assert.equal(runTurn("run_command", "src/auth/token.mjs", "x(a, b);\n", ["node --test"], claim(["src/auth/token.mjs"], ["node --test"])).verdict, VERDICT_HEADERS.ESCALATE_AUDIT_REQUIRED);
  });
});

describe("G4 read-only roles cannot reach a shell through mcp_agy-fast_fast_run_checks", () => {
  it("routes the check tool through pre-tool-gate", () => {
    const hooks = JSON.parse(readFileSync(HOOKS_JSON_PATH, "utf8"));
    const gate = Object.values(hooks)
      .flatMap((group) => group.PreToolUse ?? [])
      .find((entry) => entry.hooks.some((hook) => hook.command.includes("scripts/pre-tool-gate.mjs")));
    assert.ok(new RegExp(gate.matcher).test(CHECK_TOOL), gate.matcher);
  });

  const call = (marker, args) => {
    const dir = createTempDir("hstack-p7-role-");
    const tp = join(dir, "t.jsonl");
    const content = marker ? `감사해 줘\n${marker}\n작업 경로: \`/repo\`\n세션 기록 경로: \`/x\`` : "고쳐 줘";
    writeFileSync(tp, toJsonl([{ step_index: 0, type: "USER_INPUT", content }]));
    return handlePreToolGate(
      JSON.stringify({ hookEventName: "PreToolUse", conversationId: "c", cwd: "/repo", transcriptPath: tp, toolCall: { name: CHECK_TOOL, args } }),
      { dataDir: dir, skipAuditLog: true, governanceConfig: { autonomyMode: "smart" } },
    );
  };

  for (const [role, marker] of [["auditor", AUDITOR_SESSION_MARKER], ["challenger", CHALLENGER_SESSION_MARKER]]) {
    it(`denies every check call from a ${role} session with the Korean read-only reason`, () => {
      for (const args of [{ command: "sed -i s/a/b/ x" }, { commands: [{ command: "node --test", name: "t" }] }, {}]) {
        const out = call(marker, args);
        assert.equal(out.decision, "deny", JSON.stringify(args));
        assert.equal(analyzeField("content", out.reason).status, "korean");
      }
    });
  }

  it("allows the check tool in a main session", () => {
    assert.equal(call("", { command: "node --test" }).decision, "allow");
  });
});
