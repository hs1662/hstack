// v0.1.2 second audit: per-segment chain classification, hidden shell writers, Stop after committing
// pre-existing edits, pipefail pipes, and the bounded token fallback on long sessions.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { closeSync, mkdirSync, openSync, writeFileSync, writeSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import { analyzeField } from "../scripts/analyzer.mjs";
import { AUDITOR_SESSION_MARKER, GATE_TOOL_NAME, REGISTER_COPY, VERDICT_HEADERS } from "../scripts/governance/constants.mjs";
import { decideGate } from "../scripts/governance/decide-gate.mjs";
import { classifyCommand, readFactLedger, readTurnLedger, snapshotWorkingTree } from "../scripts/governance/fact-ledger.mjs";
import { saveGateSnapshot } from "../scripts/governance/handoff-store.mjs";
import { handlePreToolGate } from "../scripts/pre-tool-gate.mjs";
import { handlePreInvocation } from "../scripts/prompt-router.mjs";
import { handleStop } from "../scripts/stop.mjs";
import { GATE_STOP_MARKER } from "../scripts/transcript.mjs";
import { createTempDir, toJsonl, withCpuLock } from "./helpers.mjs";

const DATA_DIR = createTempDir("hstack-p5-data-");
process.env.HSTACK_DATA_DIR = DATA_DIR;

const dir = createTempDir("hstack-p5-");
let n = 0;

function auditorGate(cmd) {
  const tp = join(dir, `role${n++}.jsonl`);
  writeFileSync(
    tp,
    toJsonl([{ step_index: 0, type: "USER_INPUT", content: `감사해 줘\n${AUDITOR_SESSION_MARKER}\n작업 경로: \`/repo\`\n세션 기록 경로: \`/x\`` }]),
  );
  const payload = { hookEventName: "PreToolUse", conversationId: "c", cwd: "/repo", transcriptPath: tp, toolCall: { name: "run_command", args: { CommandLine: cmd } } };
  return handlePreToolGate(JSON.stringify(payload), { dataDir: dir, skipAuditLog: true, governanceConfig: { autonomyMode: "smart" } }).decision;
}

// A code write, then each [command, output] run, then verify_completion claiming `claim` passed.
function gate(cmds, claim) {
  const recs = [
    { step_index: 0, type: "USER_INPUT", content: "구현해 줘" },
    { step_index: 1, type: "PLANNER_RESPONSE", tool_calls: [{ name: "write_file", args: { Path: "/repo/src/a.mjs" } }] },
    { step_index: 2, type: "GENERIC", status: "DONE", content: "ok" },
  ];
  for (const [cmd, out, status = "DONE"] of cmds) {
    recs.push({ step_index: recs.length, type: "PLANNER_RESPONSE", tool_calls: [{ name: "run_command", args: { CommandLine: cmd } }] });
    recs.push({ step_index: recs.length, type: "GENERIC", status, content: out });
  }
  const p = join(dir, `g${n++}.jsonl`);
  writeFileSync(p, toJsonl(recs));
  return decideGate(
    { modified_files: ["src/a.mjs"], inspected_files: [], verification_runs: [{ command: claim, outcome: "pass" }], unverified_scope: [], self_assessment: "" },
    {
      cwd: "/repo",
      ledger: readFactLedger(p, "/repo", "/repo"),
      gitLedger: { gitAvailable: false, gitRoot: "/repo", gitDirtyFiles: new Set() },
      testInfra: { hasTestSuite: true },
      auditEscalation: "off",
    },
  );
}

const PASS_OUT = "ℹ tests 20\nℹ pass 20\nℹ fail 0";
const FAIL = ["npm test", "AssertionError: boom", "ERROR"];

describe("HIGH1 a chain is verification only when every other segment is read-only or neutral setup", () => {
  const WRITER_CHAINS = [
    "sed -i s/timingSafeEqual//g src/auth/token.mjs && npm test",
    "echo x > src/a.mjs && npm test",
    "rm -rf src && node --test",
    "bash -c 'sed -i s/a/b/ src/x.mjs && npm test'",
    "cp /tmp/x src/a.mjs && npm test",
  ];

  it("classifies a writer segment anywhere in the chain as other", () => {
    for (const cmd of WRITER_CHAINS) {
      assert.equal(classifyCommand(cmd), "other", cmd);
    }
  });

  it("denies those chains in an auditor session", () => {
    for (const cmd of WRITER_CHAINS) {
      assert.equal(auditorGate(cmd), "deny", cmd);
    }
  });

  it("keeps setup and install chains verification", () => {
    for (const cmd of [
      "cd x && npm test",
      "cd x && pushd y && npm test",
      "npm ci && npm test",
      "npm install && npm test",
      "npm run build && npm test",
      "set -e && npm test",
      "export CI=1 && npm test",
      "CI=1 npm test",
    ]) {
      assert.equal(classifyCommand(cmd), "verification", cmd);
      // Read-only roles get no shell at all (gate audit run 1).
      assert.equal(auditorGate(cmd), "deny", cmd);
    }
  });

  it("does not count a chain whose last segment is not verification", () => {
    assert.equal(classifyCommand("npm test && echo done"), "other");
  });
});

describe("MED2 setup that can force exit 0 never passes or clears a failure", () => {
  const FORCING = [
    "npm() ( : ) && npm test",
    "function npm { :; } && npm test",
    "PATH=/tmp/fakebin:$PATH && npm test",
    "export PATH=/tmp/fakebin:$PATH && npm test",
    "PATH=/tmp/fakebin npm test",
    "env PATH=/tmp/fakebin npm test",
    "trap 'exit 0' EXIT && npm test",
    "alias npm=true && npm test",
    "exec >/dev/null && npm test",
  ];

  it("classifies them as other", () => {
    for (const cmd of FORCING) {
      assert.equal(classifyCommand(cmd), "other", cmd);
    }
  });

  it("keeps the npm test failure after a forced-exit rerun", () => {
    for (const cmd of FORCING) {
      assert.equal(gate([FAIL, [cmd, ""]], "npm test").verdict, "REJECT", cmd);
    }
  });

  it("still clears the failure with a real rerun", () => {
    assert.equal(gate([FAIL, ["cd /repo && npm test", PASS_OUT]], "npm test").verdict, "PASS");
  });
});

describe("MED3 read-only commands that run a hidden writer are other", () => {
  const HIDDEN = [
    "echo $(sed -i s/a/b/ src/x.mjs)",
    'echo "$(sed -i s/a/b/ src/x.mjs)"',
    "ls `rm -rf src`",
    "cat <(sed -i s/a/b/ src/x.mjs)",
    "tee >(cat) < x",
    "env -S 'sed -i s/a/b/ x' ls",
    "env --split-string='sed -i s/a/b/ x' ls",
    "git -c core.fsmonitor='touch src/pwn.mjs' status",
    "git -c diff.external=/tmp/x diff",
    "git --config-env=core.pager=X log",
    "GIT_EXTERNAL_DIFF=/tmp/x git diff",
    "echo hi > src/a.mjs",
    "cat x >> src/a.mjs",
  ];

  it("classifies them as other and denies them to an auditor", () => {
    for (const cmd of HIDDEN) {
      assert.equal(classifyCommand(cmd), "other", cmd);
      assert.equal(auditorGate(cmd), "deny", cmd);
    }
  });

  it("keeps quoted text, fd dups and /dev/null read-only", () => {
    for (const cmd of ["echo '$(x)'", "echo '`x`'", "grep -n 'a<(b' src", "ls 2>&1", "ls > /dev/null", "git -C repo log", "git status"]) {
      assert.equal(classifyCommand(cmd), "read_only", cmd);
    }
  });
});

describe("LOW5 a pipe counts as verification only under pipefail", () => {
  it("passes a pipefail pipe", () => {
    for (const cmd of [
      "set -o pipefail && npm test 2>&1 | tail -20",
      "set -euo pipefail && npm test 2>&1 | tail -20",
      "bash -o pipefail -c 'npm test 2>&1 | tail -20'",
    ]) {
      assert.equal(classifyCommand(cmd), "verification", cmd);
      assert.equal(gate([[cmd, PASS_OUT]], cmd).verdict, "PASS", cmd);
    }
  });

  it("keeps a failure after a pipefail pipe that fails", () => {
    const cmd = "set -o pipefail && npm test 2>&1 | tail -20";
    assert.equal(gate([FAIL, [cmd, "AssertionError: boom", "ERROR"]], "npm test").verdict, "REJECT");
  });

  it("rejects a plain pipe with a Korean reason that says how to rerun", () => {
    const r = gate([["npm test 2>&1 | tail -20", PASS_OUT]], "npm test 2>&1 | tail -20");
    assert.equal(r.verdict, "REJECT");
    assert.ok(r.blockedRules.includes("R2_STALE_VERIFICATION"));
    assert.ok(r.receiptText.includes("set -o pipefail"), r.receiptText);
    assert.equal(analyzeField("content", r.receiptText).status, "korean");
    for (const register of ["neutral", "audit"]) {
      const line = REGISTER_COPY[register].ruleMessages.R2_STALE_VERIFICATION(["npm test 2>&1 | tail -20"]);
      assert.ok(line.includes("set -o pipefail"), line);
      assert.equal(analyzeField("content", line).status, "korean", line);
    }
  });
});

describe("MED4 Stop ignores committed files that were already dirty at turn start", () => {
  const git = (cwd, args) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  function makeRepo() {
    const repo = createTempDir("hstack-p5-repo-");
    mkdirSync(join(repo, "src"));
    git(repo, ["init", "-q"]);
    git(repo, ["config", "user.email", "t@example.com"]);
    git(repo, ["config", "user.name", "T"]);
    writeFileSync(join(repo, "app.mjs"), "export const v = 1;\n");
    writeFileSync(join(repo, "src", "x.mjs"), "a\n");
    git(repo, ["add", "."]);
    git(repo, ["commit", "-qm", "init"]);
    writeFileSync(join(repo, ".git", "info", "exclude"), ".t.jsonl\n");
    return { repo, git: (args) => git(repo, args) };
  }
  function runTurn(repo, steps, user = "커밋해 줘") {
    const transcriptPath = join(repo, ".t.jsonl");
    const conversationId = `p5-${n++}`;
    const records = [{ step_index: 0, type: "USER_INPUT", content: user }];
    writeFileSync(transcriptPath, toJsonl(records));
    handlePreInvocation(JSON.stringify({ hookEventName: "PreInvocation", invocationNum: 0, conversationId, cwd: repo, transcriptPath }), {
      dataDir: DATA_DIR,
      skipAuditLog: true,
    });
    for (const step of steps) {
      let call;
      let result = "ok";
      if (step.gate) {
        call = { name: GATE_TOOL_NAME, args: {} };
        // What the MCP server records on a passing verdict.
        saveGateSnapshot({ conversationId, snapshot: snapshotWorkingTree(repo), dataDir: DATA_DIR });
        result = `${VERDICT_HEADERS.PASS}\n`;
      } else if (step.write) {
        writeFileSync(join(repo, step.write), step.content);
        call = { name: "write_file", args: { Path: join(repo, step.write), Content: step.content } };
      } else {
        step.effect?.();
        call = { name: "run_command", args: { CommandLine: step.cmd, Cwd: repo } };
      }
      records.push({ step_index: records.length, type: "PLANNER_RESPONSE", tool_calls: [call] });
      records.push({ step_index: records.length, type: "GENERIC", status: "DONE", content: result });
    }
    records.push({ step_index: records.length, type: "PLANNER_RESPONSE", content: "완료했습니다." });
    writeFileSync(transcriptPath, toJsonl(records));
    return handleStop(
      JSON.stringify({ hookEventName: "Stop", terminationReason: "NO_TOOL_CALL", executionNum: 0, conversationId, cwd: repo, transcriptPath, lastUserInput: user }),
    );
  }
  const assertBlocked = (out) => {
    assert.equal(out.decision, "continue", JSON.stringify(out));
    assert.ok(out.reason.includes(GATE_STOP_MARKER), out.reason);
  };

  it("allows Stop after committing an edit made in an earlier turn", () => {
    const { repo, git: g } = makeRepo();
    writeFileSync(join(repo, "app.mjs"), "export const v = 2;\n");
    assert.deepEqual(runTurn(repo, [{ cmd: "git status" }, { cmd: "git commit -qam wip", effect: () => g(["commit", "-qam", "wip"]) }]), {});
  });

  it("blocks Stop after a shell edit committed in the same turn", () => {
    const { repo, git: g } = makeRepo();
    const out = runTurn(repo, [
      {
        cmd: "sed -i s/1/2/ app.mjs && git commit -qam wip",
        effect: () => {
          writeFileSync(join(repo, "app.mjs"), "export const v = 2;\n");
          g(["commit", "-qam", "wip"]);
        },
      },
    ]);
    assertBlocked(out);
  });

  it("blocks Stop after a pre-existing dirty file is edited again and committed", () => {
    const { repo, git: g } = makeRepo();
    writeFileSync(join(repo, "app.mjs"), "export const v = 2;\n");
    const out = runTurn(repo, [
      {
        cmd: "sed -i s/2/33/ app.mjs && git commit -qam wip",
        effect: () => {
          writeFileSync(join(repo, "app.mjs"), "export const v = 33;\n");
          g(["commit", "-qam", "wip"]);
        },
      },
    ]);
    assertBlocked(out);
  });

  it("keeps a git pull that brings new code blocked until verified", () => {
    const { repo: up, git: gu } = makeRepo();
    const clone = createTempDir("hstack-p5-clone-");
    execFileSync("git", ["clone", "-q", up, clone]);
    writeFileSync(join(clone, ".git", "info", "exclude"), ".t.jsonl\n");
    writeFileSync(join(up, "src", "x.mjs"), "b\n");
    gu(["commit", "-qam", "up"]);
    assertBlocked(runTurn(clone, [{ cmd: "git pull -q", effect: () => git(clone, ["pull", "-q"]) }], "최신으로 받아 줘"));
  });

  it("blocks Stop after a command-substitution write past a passing gate", () => {
    const { repo } = makeRepo();
    const out = runTurn(
      repo,
      [
        { write: "app.mjs", content: "export const v = 2;\n" },
        { cmd: "npm test" },
        { gate: true },
        { cmd: "echo $(sed -i s/a/b/ src/x.mjs)", effect: () => writeFileSync(join(repo, "src", "x.mjs"), "b\n") },
      ],
      "고쳐 줘",
    );
    assertBlocked(out);
  });
});

describe("LOW6 the token fallback before the last turn reads a bounded window", () => {
  // ~38MB, a half-size cousin of the audit's 77MB session: every planner carries null token keys, and the last
  // turn (in the back half of the file) has no token-bearing planner. Unbounded, the fallback parsed ~30,000
  // planners (~500ms on the 77MB file); bounded it reads the window before the turn only.
  it("reads the turn ledger in under 150ms (fastest of 3)", () => {
    const path = join(dir, "null-tokens.jsonl");
    const fd = openSync(path, "w");
    let buf = "";
    let step = 0;
    const w = (r) => {
      buf += `${JSON.stringify({ step_index: step++, ...r })}\n`;
      if (buf.length > 1 << 20) {
        writeSync(fd, buf);
        buf = "";
      }
    };
    w({ type: "USER_INPUT", content: "수정해 줘" });
    w({ type: "PLANNER_RESPONSE", content: "시작", usage: { inputTokens: 777, outputTokens: 7 } });
    for (let i = 0; i < 30_000; i += 1) {
      if (i === 29_500) w({ type: "USER_INPUT", content: "계속해 줘" });
      w({ type: "PLANNER_RESPONSE", content: "작업 중입니다 ".repeat(20), usage: { inputTokens: null, outputTokens: null }, tool_calls: [{ name: "edit_file", args: { Path: `/repo/f${i}.mjs`, CodeContent: "x".repeat(285) } }] });
      w({ type: "GENERIC", status: "DONE", content: "ok ".repeat(100) });
    }
    writeSync(fd, buf);
    closeSync(fd);
    withCpuLock(() => {
      const samples = [];
      let ledger;
      for (let i = 0; i < 3; i += 1) {
        const t0 = performance.now();
        ledger = readTurnLedger(path, "/repo", "/repo");
        samples.push(performance.now() - t0);
      }
      assert.equal(ledger.turnStartStepIndex, 1 + 1 + 29_500 * 2);
      assert.ok(Math.min(...samples) < 150, `fastest ${Math.min(...samples).toFixed(0)}ms`);
    });
  });
});
