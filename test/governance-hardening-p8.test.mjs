// v0.1.2 gate audit run 3: re-editing after a passing gate, `node <script>` as a writer, per-branch ReDoS cost.
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

const DATA_DIR = createTempDir("hstack-p8-data-");
process.env.HSTACK_DATA_DIR = DATA_DIR;
const git = (cwd, args) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const PASS_OUTPUT = "ℹ tests 1\nℹ pass 1\nℹ fail 0\n";

function makeRepo() {
  const repo = createTempDir("hstack-p8-repo-");
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
const verifiedEdit = [{ write: "app.mjs", content: "export const v = 2;\n" }, test, { gate: claim("node --test") }];
const shellWrite = (cmd, content) => ({ cmd, effect: (repo) => writeFileSync(join(repo, "app.mjs"), content) });

function assertGateBlocked(out) {
  assert.equal(out.decision, "continue", JSON.stringify(out));
  assert.ok(out.reason.includes(GATE_STOP_MARKER), out.reason);
}

describe("F1 a re-edit after a passing gate passes again once tests rerun", () => {
  const reEdits = {
    write_file: { write: "app.mjs", content: "export const v = Number(3);\n" },
    "sed -i": shellWrite("sed -i s/2/Number(3)/ app.mjs", "export const v = Number(3);\n"),
  };
  for (const [via, reEdit] of Object.entries(reEdits)) {
    it(`passes edit, test, gate, ${via} re-edit, test, gate, test, gate and allows Stop`, () => {
      const { out, verdicts } = runTurn(`p8-f1-${via}`, [...verifiedEdit, reEdit, test, { gate: claim("node --test") }, test, { gate: claim("node --test") }]);
      assert.deepEqual(verdicts, [VERDICT_HEADERS.PASS, VERDICT_HEADERS.PASS, VERDICT_HEADERS.PASS]);
      assert.deepEqual(out, {});
    });

    it(`still rejects a ${via} re-edit after the gate that no test followed`, () => {
      const { out, verdicts } = runTurn(`p8-f1-untested-${via}`, [...verifiedEdit, reEdit, { gate: claim("node --test") }]);
      assert.equal(verdicts[0], VERDICT_HEADERS.PASS);
      assert.notEqual(verdicts[1], VERDICT_HEADERS.PASS, verdicts.join(" | "));
      assertGateBlocked(out);
    });
  }

  it("still rejects a change a test-looking command made after the gate when nothing ran after it", () => {
    const { out, verdicts } = runTurn("p8-f1-check-writes", [...verifiedEdit, { ...shellWrite("node --test", "export const v = 9;\n"), output: PASS_OUTPUT }, { gate: claim("node --test") }]);
    assert.notEqual(verdicts[1], VERDICT_HEADERS.PASS, verdicts.join(" | "));
    assertGateBlocked(out);
  });
});

describe("F2 node is a runner only for tests", () => {
  it("credits node --test and test files only", () => {
    for (const cmd of ["node --test", "node --test test/a.test.mjs", "node --test-reporter=spec --test", "node test/run.mjs", "node src/x.spec.mjs", "node ./a.test.cjs"]) {
      assert.equal(classifyCommand(cmd), "verification", cmd);
    }
    for (const cmd of ["node ./mutate.mjs", "node scripts/build.mjs", "node -r ./x.cjs app.mjs"]) {
      assert.equal(classifyCommand(cmd), "other", cmd);
    }
    for (const cmd of ["node --version", "node -v"]) {
      assert.equal(classifyCommand(cmd), "read_only", cmd);
    }
  });

  it("rejects an edit whose only check was node --version", () => {
    const { out, verdicts } = runTurn("p8-f2-version", [{ write: "app.mjs", content: "export const v = 2;\n" }, { cmd: "node --version", output: "v22.11.0" }, { gate: claim("node --version") }]);
    assert.notEqual(verdicts[0], VERDICT_HEADERS.PASS, verdicts.join(" | "));
    assertGateBlocked(out);
  });

  it("rejects a file a node script rewrote after the last test, as it does for sed -i", () => {
    for (const cmd of ["node ./mutate.mjs", "sed -i s/2/9/ app.mjs"]) {
      const { out, verdicts } = runTurn(`p8-f2-${cmd}`, [{ write: "app.mjs", content: "export const v = 2;\n" }, test, shellWrite(cmd, "export const v = 9;\n"), { gate: claim("node --test") }]);
      assert.notEqual(verdicts[0], VERDICT_HEADERS.PASS, `${cmd}: ${verdicts.join(" | ")}`);
      assertGateBlocked(out);
    }
  });
});

describe("F3 each top-level alternative pays its own anchor and quantifier cost", () => {
  const hostile = "src/" + "d/".repeat(900) + "calc.mjs";
  for (const pattern of ["^x|.*.*!", "^x|a*a*!", "^a*a*!", "^.*.*!", "^a|b|.*.*!", "^src/\\w+\\w*!"]) {
    it(`rejects ${pattern} in under 1ms per call`, () => withCpuLock(() => {
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

  for (const [pattern, match] of [["^auth/|^lib/secret/", "lib/secret/k.mjs"], ["^src/.*/auth/|^keys/", "src/a/auth/x.mjs"], ["^src/.*\\.secret\\.mjs$", "src/x.secret.mjs"]]) {
    it(`accepts ${pattern}`, () => {
      assert.equal(isSensitiveFilePath(match, { sensitivePatterns: [pattern] }), true);
      assert.equal(isSensitiveFilePath("lib/auth/login.mjs", { sensitivePatterns: [pattern] }), false);
    });
  }
});
