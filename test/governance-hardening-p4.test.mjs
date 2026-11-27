// v0.1.2 Checkpoint 4 audit: Stop-gate, verification-masking, role, analyzer, destructive-edit, ReDoS and lock regressions.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import { analyzeField } from "../scripts/analyzer.mjs";
import {
  AUDITOR_SESSION_MARKER,
  CHALLENGER_SESSION_MARKER,
  GATE_TOOL_NAME,
  VERDICT_HEADERS,
} from "../scripts/governance/constants.mjs";
import { decideGate } from "../scripts/governance/decide-gate.mjs";
import { detectDestructiveEdit } from "../scripts/governance/destructive-edit.mjs";
import { classifyCommand, readFactLedger, snapshotWorkingTree } from "../scripts/governance/fact-ledger.mjs";
import { readTurnSnapshot, saveGateSnapshot, saveTurnSnapshot } from "../scripts/governance/handoff-store.mjs";
import { isSensitiveFilePath } from "../scripts/governance/risk-classifier.mjs";
import { handlePreToolGate } from "../scripts/pre-tool-gate.mjs";
import { handlePreInvocation } from "../scripts/prompt-router.mjs";
import { handleStop } from "../scripts/stop.mjs";
import { GATE_STOP_MARKER } from "../scripts/transcript.mjs";
import { HOOKS_JSON_PATH, createTempDir, toJsonl, withCpuLock } from "./helpers.mjs";

// Stop and the turn-start snapshot resolve the plugin data dir from the environment.
const DATA_DIR = createTempDir("hstack-p4-data-");
process.env.HSTACK_DATA_DIR = DATA_DIR;

const git = (cwd, args) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

function makeRepo() {
  const repo = createTempDir("hstack-p4-repo-");
  git(repo, ["init", "-q"]);
  git(repo, ["config", "user.email", "t@example.com"]);
  git(repo, ["config", "user.name", "T"]);
  mkdirSync(join(repo, "src", "auth"), { recursive: true });
  writeFileSync(join(repo, "app.mjs"), "export const v = 1;\n");
  writeFileSync(join(repo, "src", "auth", "token.mjs"), "timingSafeEqual(a, b);\n");
  git(repo, ["add", "."]);
  git(repo, ["commit", "-qm", "init"]);
  writeFileSync(join(repo, ".git", "info", "exclude"), ".t.jsonl\n");
  return repo;
}

const USER = { step_index: 0, type: "USER_INPUT", content: "app.mjs 고쳐 줘" };
const DONE_REPLY = "수정을 완료했습니다. 이제 정상 동작합니다.";

// Drives one turn: PreInvocation snapshot, then each step either a shell call (with its real tree effect),
// a write_file, or a passing verify_completion (which first runs the PreToolUse gate hook).
function runTurn(repo, conversationId, steps) {
  const transcriptPath = join(repo, ".t.jsonl");
  const records = [USER];
  writeFileSync(transcriptPath, toJsonl(records));
  handlePreInvocation(
    JSON.stringify({ hookEventName: "PreInvocation", invocationNum: 0, conversationId, cwd: repo, transcriptPath }),
    { dataDir: DATA_DIR, skipAuditLog: true },
  );
  let passCount = 0;
  for (const step of steps) {
    let call;
    let result = "ok";
    if (step.gate) {
      call = { name: GATE_TOOL_NAME, args: {} };
      passCount += 1;
      // What the MCP server records on a passing verdict.
      saveGateSnapshot({ conversationId, snapshot: snapshotWorkingTree(repo), dataDir: DATA_DIR, gatePassCount: passCount });
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
    writeFileSync(transcriptPath, toJsonl(records));
  }
  records.push({ step_index: records.length, type: "PLANNER_RESPONSE", content: DONE_REPLY });
  writeFileSync(transcriptPath, toJsonl(records));
  return handleStop(
    JSON.stringify({
      hookEventName: "Stop",
      terminationReason: "NO_TOOL_CALL",
      executionNum: 0,
      conversationId,
      cwd: repo,
      transcriptPath,
      lastUserInput: USER.content,
    }),
  );
}

function assertGateBlocked(out) {
  assert.equal(out.decision, "continue", JSON.stringify(out));
  assert.ok(out.reason.includes(GATE_STOP_MARKER), out.reason);
}

const verifiedEdit = (repo) => [
  { write: "app.mjs", content: "export const v = 2;\n" },
  { cmd: "npm test" },
  { gate: true },
];

describe("H1 a shell edit after a passing verify_completion reaches the Stop gate", () => {
  it("classifies find with -exec/-execdir/-ok/-okdir/-delete/-fprint as a writer", () => {
    for (const cmd of [
      "find src -name token.mjs -exec sed -i s/a/b/ {} +",
      "find . -execdir rm {} ;",
      "find . -ok rm {} ;",
      "find . -okdir rm {} ;",
      "find src -delete",
      "find . -fprint out.txt",
      "git diff --output=src/a.mjs",
      "rg --pre sh pattern",
      "tree -o out.txt",
    ]) {
      assert.equal(classifyCommand(cmd), "other", cmd);
    }
    for (const cmd of ["find src -name '*.mjs'", "find . -type f -newer app.mjs", "git -C repo --no-pager diff --stat", "rg -n timingSafeEqual src"]) {
      assert.equal(classifyCommand(cmd), "read_only", cmd);
    }
  });

  it("blocks Stop after find -exec sed -i runs past the passing gate", () => {
    const repo = makeRepo();
    const out = runTurn(repo, "p4-h1-exec", [
      ...verifiedEdit(repo),
      {
        cmd: "find src -name token.mjs -exec sed -i s/timingSafeEqual/x/ {} +",
        effect: () => writeFileSync(join(repo, "src", "auth", "token.mjs"), "x(a, b);\n"),
      },
    ]);
    assertGateBlocked(out);
  });

  it("blocks Stop after find -delete runs past the passing gate", () => {
    const repo = makeRepo();
    const out = runTurn(repo, "p4-h1-delete", [
      ...verifiedEdit(repo),
      { cmd: "find src/auth -name token.mjs -delete", effect: () => execFileSync("rm", [join(repo, "src", "auth", "token.mjs")]) },
    ]);
    assertGateBlocked(out);
  });

  it("dates a tree change against the verify_completion snapshot even when the command looks read-only", () => {
    const repo = makeRepo();
    const out = runTurn(repo, "p4-h1-dating", [
      ...verifiedEdit(repo),
      // A read-only-classed command whose real effect (an unknown write path) still edits code.
      { cmd: "cat app.mjs", effect: () => writeFileSync(join(repo, "src", "auth", "token.mjs"), "x(a, b);\n") },
    ]);
    assertGateBlocked(out);
  });

  it("still allows Stop for read-only commands after a passing gate", () => {
    const repo = makeRepo();
    assert.deepEqual(runTurn(repo, "p4-h1-ro", [...verifiedEdit(repo), { cmd: "git status && cat app.mjs" }]), {});
  });
});

describe("H2 masked verification never passes or clears a failure", () => {
  const dir = createTempDir("hstack-p4-mask-");
  let n = 0;
  function gate(cmds, claim) {
    const recs = [
      { step_index: 0, type: "USER_INPUT", content: "구현해 줘" },
      { step_index: 1, type: "PLANNER_RESPONSE", tool_calls: [{ name: "write_file", args: { Path: "/repo/src/a.mjs" } }] },
      { step_index: 2, type: "GENERIC", status: "DONE", content: "ok" },
    ];
    let s = 3;
    for (const [cmd, out] of cmds) {
      recs.push({ step_index: s++, type: "PLANNER_RESPONSE", tool_calls: [{ name: "run_command", args: { CommandLine: cmd } }] });
      recs.push({ step_index: s++, type: "GENERIC", status: "DONE", content: out });
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
  const FAIL = "AssertionError: boom";
  const MASKED = [
    "npm test | cat",
    "npm test; true",
    "npm test ; exit 0",
    "npm test || ls",
    "npm test || /bin/true",
    "npm test || true >/dev/null",
    "npm test || { true; }",
    "ls || npm test",
    "npm test || exit 0 # x",
    "npm test &",
    "! npm test",
    "npm test\ntrue",
  ];

  it("classifies masked runner chains as other", () => {
    for (const cmd of MASKED) {
      assert.equal(classifyCommand(cmd), "other", JSON.stringify(cmd));
    }
  });

  it("keeps an npm test failure after a masked rerun", () => {
    for (const cmd of MASKED) {
      const r = gate([["npm test", FAIL], [cmd, "ok"]], "npm test");
      assert.equal(r.verdict, "REJECT", JSON.stringify(cmd));
      assert.ok(r.blockedRules.includes("R3_CONCEALED_FAILURE"), `${JSON.stringify(cmd)} ${r.blockedRules}`);
    }
  });

  it("keeps && chains, env prefixes and plain redirects as verification that clears the failure", () => {
    for (const cmd of ["cd x && npm test", "FOO=1 npm test", "npm test 2>&1", "npm test > out.log 2>&1", "npm ci && npm test"]) {
      assert.equal(classifyCommand(cmd), "verification", cmd);
      const r = gate([[cmd, FAIL], [cmd, "ok"]], cmd);
      assert.equal(r.verdict, "PASS", `${cmd} ${r.blockedRules}`);
    }
    const sameDir = gate([["npm test", FAIL], ["cd /repo && npm test", "ok"]], "npm test");
    assert.equal(sameDir.verdict, "PASS", sameDir.blockedRules.join(","));
    const crossDir = gate([["npm test", FAIL], ["cd x && npm test", "ok"]], "npm test");
    assert.equal(crossDir.verdict, "REJECT", crossDir.blockedRules.join(","));
    assert.ok(crossDir.blockedRules.includes("R3_CONCEALED_FAILURE"));
  });
});

describe("H3 an unusable working-tree snapshot fails closed", () => {
  // More dirty files than the snapshot cap; building the tree is a CPU burst, so keep it off the perf tests.
  const runHugeDirtyTurn = (conversationId, steps) =>
    withCpuLock(() => {
      const repo = makeRepo();
      for (let i = 0; i < 2001; i += 1) writeFileSync(join(repo, `n${i}.txt`), "");
      return runTurn(repo, conversationId, steps.map((step) => (step.edit ? { cmd: step.cmd, effect: () => writeFileSync(join(repo, "app.mjs"), step.edit) } : step)));
    });
  const SED = { cmd: "sed -i s/1/2/ app.mjs", edit: "export const v = 2;\n" };

  it("blocks Stop after a shell edit when the tree has more dirty files than the snapshot cap", () => {
    assertGateBlocked(runHugeDirtyTurn("p4-h3", [SED]));
  });

  it("allows Stop once verify_completion passes after that shell edit", () => {
    assert.deepEqual(runHugeDirtyTurn("p4-h3-ok", [SED, { gate: true }]), {});
  });

  it("keeps read-only turns over a huge dirty tree unblocked", () => {
    assert.deepEqual(runHugeDirtyTurn("p4-h3-ro", [{ cmd: "git status" }]), {});
  });
});

describe("Known-A a same-turn commit still reaches the Stop gate", () => {
  it("blocks Stop after sed -i && git commit", () => {
    const repo = makeRepo();
    const out = runTurn(repo, "p4-ka", [
      {
        cmd: "sed -i s/1/2/ app.mjs && git commit -qam x",
        effect: () => {
          writeFileSync(join(repo, "app.mjs"), "export const v = 2;\n");
          git(repo, ["commit", "-qam", "x"]);
        },
      },
    ]);
    assertGateBlocked(out);
  });
});

describe("Known-B auditor and challenger sessions cannot write through run_command", () => {
  const dir = createTempDir("hstack-p4-role-");
  const call = (marker, commandLine) => {
    const tp = join(dir, `${Math.random().toString(36).slice(2)}.jsonl`);
    writeFileSync(tp, toJsonl([{ step_index: 0, type: "USER_INPUT", content: `감사해 줘\n${marker}\n작업 경로: \`/repo\`\n세션 기록 경로: \`/x\`` }]));
    return handlePreToolGate(
      JSON.stringify({ hookEventName: "PreToolUse", conversationId: "c", cwd: "/repo", transcriptPath: tp, toolCall: { name: "run_command", args: { CommandLine: commandLine } } }),
      { dataDir: dir, skipAuditLog: true, governanceConfig: { autonomyMode: "smart" } },
    );
  };

  for (const [role, marker] of [["auditor", AUDITOR_SESSION_MARKER], ["challenger", CHALLENGER_SESSION_MARKER]]) {
    it(`${role} is denied a writing shell command with a Korean reason`, () => {
      for (const cmd of ["sed -i s/timingSafeEqual//g src/auth/token.mjs", "find src -delete", "echo x > src/a.mjs", "npm test || true"]) {
        const out = call(marker, cmd);
        assert.equal(out.decision, "deny", cmd);
        assert.equal(analyzeField("content", out.reason).status, "korean");
      }
    });
    // Gate audit run 1: a check can run arbitrary code, so read-only roles get no shell at all.
    it(`${role} is denied read-only and verification commands too`, () => {
      for (const cmd of ["git diff", "rg -n timingSafeEqual src", "npm test", "cd x && node --test"]) {
        assert.equal(call(marker, cmd).decision, "deny", cmd);
      }
    });
  }

  it("main sessions keep run_command allowed", () => {
    const tp = join(dir, "main.jsonl");
    writeFileSync(tp, toJsonl([USER]));
    const out = handlePreToolGate(
      JSON.stringify({ hookEventName: "PreToolUse", conversationId: "c", cwd: "/repo", transcriptPath: tp, toolCall: { name: "run_command", args: { CommandLine: "sed -i s/a/b/ x" } } }),
      { dataDir: dir, skipAuditLog: true },
    );
    assert.equal(out.decision, "allow");
  });

  it("routes run_command through the pre-tool gate hook", () => {
    const hooks = JSON.parse(readFileSync(HOOKS_JSON_PATH, "utf8"));
    const gateEntry = Object.values(hooks)
      .flatMap((group) => group.PreToolUse ?? [])
      .find((entry) => entry.hooks.some((hook) => hook.command.includes("scripts/pre-tool-gate.mjs")));
    assert.ok(new RegExp(gateEntry.matcher).test("run_command"));
  });
});

describe("M1 English prose with a trailing delimiter inside code blocks stays analyzed", () => {
  const prose0 = [
    "I have finished the change and everything works as you asked,",
    "The session lock now retries when another process holds it,",
    "You should run the tests again before merging this branch,",
    "Let me know if you would like me to continue with the next item,",
  ];
  const prose = [...prose0, ...prose0, ...prose0];
  const cases = {
    indentedComma: "수정했습니다.\n\n" + prose.map((l) => `    ${l}`).join("\n"),
    unclosedFenceComma: "수정했습니다.\n\n```\n" + prose.join("\n"),
    unclosedFenceParen: "수정했습니다.\n\n```\n" + prose.map((l) => l.replace(/,$/, " (done)")).join("\n"),
    unclosedFenceSemicolon: "수정했습니다.\n\n```\n" + prose.map((l) => l.replace(/,$/, ";")).join("\n"),
  };
  for (const [name, text] of Object.entries(cases)) {
    it(`${name} is drifted`, () => assert.equal(analyzeField("content", text).status, "drifted"));
  }

  it("real code lines in an unclosed fence stay stripped", () => {
    const text =
      "이번 변경으로 세션 잠금 로직이 원자적으로 동작하도록 수정했습니다. 테스트도 모두 통과했고 성능 저하는 없었습니다.\n```js\nconst lock = acquire(path, { retries: 3 });\nfor (const item of items) {\n  process(item, options);\n}\n";
    assert.equal(analyzeField("content", text).status, "korean");
  });
});

describe("M2 a regex literal with a quote never hides a commented-out safety primitive", () => {
  const edit = (oldText, newText) =>
    detectDestructiveEdit({
      toolName: "replace_file_content",
      toolInput: { TargetFile: "/repo/src/auth/token.mjs", TargetContent: oldText, ReplacementContent: newText },
      cwd: "/repo",
      gitRoot: "/repo",
      existingFileContent: "x",
    }).destructive;

  it("flags commenting out timingSafeEqual after a regex literal holding a backtick or apostrophe", () => {
    assert.equal(edit("const re = /`/;\ntimingSafeEqual(a, b);\nconst z = 1;", "const re = /`/;\n// timingSafeEqual(a, b);\nconst z = 1;"), true);
    assert.equal(edit("const re = /'/; timingSafeEqual(a, b);", "const re = /'/; // timingSafeEqual(a, b);"), true);
    assert.equal(edit('const re = /"/;\ntimingSafeEqual(a, b);', 'const re = /"/;\n/* timingSafeEqual(a, b); */'), true);
  });

  it("keeps comment-only and URL-string edits non-destructive", () => {
    assert.equal(edit("// don't\ntimingSafeEqual(a, b);", "// do not\ntimingSafeEqual(a, b);"), false);
    assert.equal(edit('const u = "http://a"; timingSafeEqual(a, b);', 'const u = "http://b"; timingSafeEqual(a, b);'), false);
  });
});

describe("M3 polynomial custom patterns are rejected quickly", () => {
  const hostile = [
    ["a?".repeat(25) + "a".repeat(25), "a".repeat(25)],
    ["^" + ".*".repeat(8) + "!$", "src/" + "a".repeat(20)],
    ["\\w+\\w+\\w+\\w+\\w+\\w+!", "a".repeat(30)],
    [".*.*!", "src/" + "a".repeat(500)],
    ["a{0,20}a{0,20}b", "a".repeat(60)],
  ];
  for (const [pattern, input] of hostile) {
    it(`rejects ${pattern} in under 1ms per call`, () => withCpuLock(() => {
      assert.equal(isSensitiveFilePath(input, { sensitivePatterns: [pattern] }), false);
      // Inputs are sized so an executed pattern costs tens of ms; a rejected one never runs.
      const t0 = performance.now();
      let calls = 0;
      while (calls < 100 && performance.now() - t0 < 1000) {
        isSensitiveFilePath(input, { sensitivePatterns: [pattern] });
        calls += 1;
      }
      assert.ok((performance.now() - t0) / calls < 1, "rejection took 1ms or more");
      // A rejected custom list leaves the defaults in force.
      assert.equal(isSensitiveFilePath("lib/auth/login.mjs", { sensitivePatterns: [pattern] }), true);
    }));
  }
  for (const [pattern, match] of [["^auth/", "auth/login.mjs"], ["^src/.*/auth/", "src/a/b/auth/x.mjs"], ["npm test", "scripts/npm test.sh"], ["vitest", "vitest.config.ts"], ["^src/.*\\.secret\\.mjs$", "src/x.secret.mjs"]]) {
    it(`accepts ${pattern}`, () => {
      assert.equal(isSensitiveFilePath(match, { sensitivePatterns: [pattern] }), true);
      assert.equal(isSensitiveFilePath("lib/auth/login.mjs", { sensitivePatterns: [pattern] }), false);
    });
  }
});

describe("L1 a session lock held too long is reclaimed even when its pid is alive", () => {
  it("reclaims an hour-old lock recorded under a live pid", () => {
    const dir = createTempDir("hstack-p4-lock-");
    assert.equal(saveTurnSnapshot({ conversationId: "c1", turnStartStepIndex: 0, snapshot: { gitRoot: "/r", files: {} }, dataDir: dir }), true);
    const lockPath = join(dir, "sessions", "c1.json.lock");
    writeFileSync(lockPath, JSON.stringify({ pid: process.pid, createdAt: 0 }));
    const old = new Date(Date.now() - 3600e3);
    utimesSync(lockPath, old, old);
    assert.equal(saveTurnSnapshot({ conversationId: "c1", turnStartStepIndex: 5, snapshot: { gitRoot: "/r", files: {} }, dataDir: dir }), true);
    assert.equal(readTurnSnapshot({ conversationId: "c1", turnStartStepIndex: 5, dataDir: dir })?.gitRoot, "/r");
  });
});
