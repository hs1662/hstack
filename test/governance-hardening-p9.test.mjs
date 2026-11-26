// v0.1.2 gate audit run 4: committing verified work, interpreter scripts as writers, sequential alternation ReDoS.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import { GATE_TOOL_NAME, VERDICT_HEADERS } from "../scripts/governance/constants.mjs";
import { classifyCommand } from "../scripts/governance/fact-ledger.mjs";
import { isSensitiveFilePath } from "../scripts/governance/risk-classifier.mjs";
import { createMcpServerHandler } from "../scripts/mcp/server.mjs";
import { handlePreToolGate } from "../scripts/pre-tool-gate.mjs";
import { handlePreInvocation } from "../scripts/prompt-router.mjs";
import { handleStop } from "../scripts/stop.mjs";
import { GATE_STOP_MARKER } from "../scripts/transcript.mjs";
import { createTempDir, toJsonl, withCpuLock } from "./helpers.mjs";

// A suite run from a git hook would otherwise point every temp repo at the outer repository.
for (const key of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"]) delete process.env[key];
const DATA_DIR = createTempDir("hstack-p9-data-");
process.env.HSTACK_DATA_DIR = DATA_DIR;
const git = (cwd, args) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const PASS_OUTPUT = "ℹ tests 1\nℹ pass 1\nℹ fail 0\n";

function makeRepo() {
  const repo = createTempDir("hstack-p9-repo-");
  git(repo, ["init", "-q"]);
  git(repo, ["config", "user.email", "t@example.com"]);
  git(repo, ["config", "user.name", "T"]);
  mkdirSync(join(repo, "test"));
  writeFileSync(join(repo, "package.json"), '{"scripts":{"test":"node --test"}}\n');
  writeFileSync(join(repo, "test", "a.test.mjs"), "import 'node:test';\n");
  writeFileSync(join(repo, "app.mjs"), "export const v = 1;\n");
  git(repo, ["add", "."]);
  git(repo, ["commit", "-qm", "init"]);
  writeFileSync(join(repo, ".git", "info", "exclude"), ".t.jsonl\n");
  return repo;
}

// Each gate step runs the real PreToolUse hook and the real MCP server, so its verdict comes from the ledger.
function runTurn(conversationId, steps) {
  const repo = makeRepo();
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
      step.effect?.(repo);
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
const test = { cmd: "node --test", output: PASS_OUTPUT };
const edit = { write: "app.mjs", content: "export const v = 2;\n" };
const verifiedEdit = [edit, test, { gate: claim("node --test") }];
const shellWrite = (cmd, content) => ({ cmd, effect: (repo) => writeFileSync(join(repo, "app.mjs"), content) });
const commit = { cmd: "git add -A && git commit -qm fix", effect: (repo) => git(repo, ["commit", "-qam", "fix"]) };

function assertGateBlocked(out) {
  assert.equal(out.decision, "continue", JSON.stringify(out));
  assert.ok(out.reason.includes(GATE_STOP_MARKER), out.reason);
}

describe("G1 committing the exact content a passing gate verified", () => {
  it("allows Stop after edit, test, gate, git commit", () => {
    const { out, verdicts } = runTurn("p9-g1-commit", [...verifiedEdit, commit]);
    assert.deepEqual(verdicts, [VERDICT_HEADERS.PASS]);
    assert.deepEqual(out, {});
  });

  it("allows Stop after edit, test, gate, git status, git commit", () => {
    const { out } = runTurn("p9-g1-status-commit", [...verifiedEdit, { cmd: "git status" }, commit]);
    assert.deepEqual(out, {});
  });

  it("still blocks a write_file re-edit after the gate that is committed without a test", () => {
    const { out } = runTurn("p9-g1-reedit-commit", [...verifiedEdit, { write: "app.mjs", content: "export const v = 3;\n" }, commit]);
    assertGateBlocked(out);
  });

  it("still blocks a sed -i re-edit after the gate that is committed without a test", () => {
    const { out } = runTurn("p9-g1-sed-commit", [...verifiedEdit, shellWrite("sed -i s/2/3/ app.mjs", "export const v = 3;\n"), commit]);
    assertGateBlocked(out);
  });

  it("still blocks a commit whose command also rewrote the verified file", () => {
    const sneaky = { cmd: "git add -A && git commit -qm fix", effect: (repo) => { writeFileSync(join(repo, "app.mjs"), "export const v = 30;\n"); git(repo, ["commit", "-qam", "fix"]); } };
    const { out } = runTurn("p9-g1-commit-rewrites", [...verifiedEdit, sneaky]);
    assertGateBlocked(out);
  });
});

describe("G2 interpreters and scripts are runners only for tests", () => {
  it("treats version and help probes as read-only", () => {
    for (const cmd of ["python3 --version", "python -V", "npm --version", "npm -v", "go version", "bun --version", "cargo --version", "pytest --version", "vitest --help", "deno -V"]) {
      assert.equal(classifyCommand(cmd), "read_only", cmd);
    }
  });

  it("treats non-test scripts as writers", () => {
    for (const cmd of ["./noop.sh", "./mutate.sh", "bash mutate.sh", "sh scripts/build.sh", "python3 mutate.py", "python -m http.server", "python3 -W ignore mutate.py", "bun mutate.ts", "bun run mutate.ts", "bun x cowsay"]) {
      assert.equal(classifyCommand(cmd), "other", cmd);
    }
  });

  it("keeps crediting real test runs", () => {
    for (const cmd of [
      "python3 -m pytest",
      "python -m pytest -q tests/",
      "python3 -m unittest discover",
      "python3 test_calc.py",
      "python3 pkg/calc_test.py",
      "python3 tests/run.py",
      "pytest -v",
      "bun test",
      "bun test src/",
      "bash test/run.sh",
      "sh scripts/run-tests.sh",
      "./test/run.sh",
      "./scripts/test.sh",
      "go test ./...",
      "npm test",
      "bash -c 'npm test'",
    ]) {
      assert.equal(classifyCommand(cmd), "verification", cmd);
    }
  });

  for (const cmd of ["python3 --version", "./noop.sh", "npm --version", "go version"]) {
    it(`rejects an edit whose only check was ${cmd}`, () => {
      const { out, verdicts } = runTurn(`p9-g2-only-${cmd}`, [edit, { cmd, output: "ok" }, { gate: claim(cmd) }]);
      assert.notEqual(verdicts[0], VERDICT_HEADERS.PASS, verdicts.join(" | "));
      assertGateBlocked(out);
    });
  }

  for (const cmd of ["python3 mutate.py", "bash mutate.sh", "./mutate.sh", "sed -i s/2/9/ app.mjs"]) {
    it(`rejects a file ${cmd} rewrote after the last test`, () => {
      const { out, verdicts } = runTurn(`p9-g2-tamper-${cmd}`, [edit, test, shellWrite(cmd, "export const v = 9;\n"), { gate: claim("node --test") }]);
      assert.notEqual(verdicts[0], VERDICT_HEADERS.PASS, verdicts.join(" | "));
      assertGateBlocked(out);
    });
  }
});

describe("G3 sequential alternation groups that match the same input", () => {
  const hostile = "a".repeat(24) + "/calc.mjs";
  for (const pattern of ["^" + "(a|a)".repeat(24) + "!", "(a|a)".repeat(12) + "!", "^" + "(a|b|c)".repeat(8) + "!", "^(?:x|x)(?:x|x)(?:x|x)(?:x|x)(?:x|x)(?:x|x)(?:x|x)(?:x|x)(?:x|x)(?:x|x)(?:x|x)!"]) {
    it(`rejects ${pattern.slice(0, 40)} in under 1ms per call`, () => withCpuLock(() => {
      const t0 = performance.now();
      let calls = 0;
      while (calls < 100 && performance.now() - t0 < 1000) {
        isSensitiveFilePath(hostile, { sensitivePatterns: [pattern] });
        calls += 1;
      }
      assert.ok((performance.now() - t0) / calls < 1, "rejection took 1ms or more");
      // A rejected custom list leaves the defaults in force.
      assert.equal(isSensitiveFilePath("lib/auth/login.mjs", { sensitivePatterns: [pattern] }), true);
    }));
  }

  for (const [pattern, match] of [["^auth/", "auth/x.mjs"], ["^src/.*/auth/", "src/a/auth/x.mjs"], ["npm test", "npm test"], ["vitest", "vitest.config.mjs"], ["(foo|bar)/", "src/bar/x.mjs"], ["^(src|lib)/(keys|certs)/", "lib/keys/k.mjs"]]) {
    it(`accepts ${pattern}`, () => {
      assert.equal(isSensitiveFilePath(match, { sensitivePatterns: [pattern] }), true);
      // An accepted custom list replaces the defaults.
      assert.equal(isSensitiveFilePath("lib/auth/login.mjs", { sensitivePatterns: [pattern] }), false);
    });
  }
});
