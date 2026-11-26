// v0.1.2 Checkpoint 2 (P1): session lock, destructive-edit comment stripping, Korean drift false positives,
// English-switch requests, and verification-equivalence regressions found by the independent audit.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { pathToFileURL } from "node:url";

import { analyzeField } from "../scripts/analyzer.mjs";
import { decideGate } from "../scripts/governance/decide-gate.mjs";
import { detectDestructiveEdit } from "../scripts/governance/destructive-edit.mjs";
import { readFactLedger } from "../scripts/governance/fact-ledger.mjs";
import { claimAutonomyTurnFlag } from "../scripts/governance/handoff-store.mjs";
import { handlePostInvocation } from "../scripts/post-invocation.mjs";
import { isExplicitEnglishOutputRequest } from "../scripts/transcript.mjs";
import { PLUGIN_ROOT, createTempDir, toJsonl, withCpuLock } from "./helpers.mjs";

const HANDOFF_STORE_URL = pathToFileURL(join(PLUGIN_ROOT, "scripts", "governance", "handoff-store.mjs")).href;

// Long-lived children (started once, so 10 trials do not pay 160 node startups): on each message a child
// sleeps until the shared start time, then claims its own key and one key every child shares.
const CLAIM_CHILD = `
const { claimAutonomyTurnFlag } = await import(${JSON.stringify(HANDOFF_STORE_URL)});
process.on("message", ({ dataDir, key, startAt }) => {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(0, startAt - Date.now()));
  const own = claimAutonomyTurnFlag({ conversationId: "conv1", flagName: "autoHandoffTurns", turnKey: key, dataDir });
  const shared = claimAutonomyTurnFlag({ conversationId: "conv1", flagName: "autoHandoffTurns", turnKey: "shared", dataDir });
  process.send({ own, shared });
});
process.send("ready");
`;

function nextMessage(child) {
  return new Promise((resolvePromise, reject) => {
    const onExit = (code) => reject(new Error(`claim child exited with ${code}`));
    child.once("exit", onExit);
    child.once("message", (msg) => {
      child.off("exit", onExit);
      resolvePromise(msg);
    });
  });
}

function startClaimChild() {
  return spawn(process.execPath, ["--input-type=module", "-e", CLAIM_CHILD], { stdio: ["ignore", "ignore", "inherit", "ipc"] });
}

function sessionPath(dataDir) {
  return join(dataDir, "sessions", "conv1.json");
}

function deadPid() {
  return spawnSync(process.execPath, ["-e", ""]).pid;
}

describe("#5 session lock is exclusive under contention and reclaims stale locks atomically", () => {
  it("keeps 16/16 parallel claims and grants a shared key exactly once across 10 trials with a pre-aged stale lock", () =>
    withCpuLock(async () => {
      const CHILDREN = 16;
      const TRIALS = 10;
      const children = Array.from({ length: CHILDREN }, startClaimChild);
      try {
        await Promise.all(children.map(nextMessage));
        for (let trial = 0; trial < TRIALS; trial += 1) {
          const dataDir = createTempDir("hstack-p1-lock-");
          mkdirSync(join(dataDir, "sessions"));
          const lockPath = `${sessionPath(dataDir)}.lock`;
          writeFileSync(lockPath, "");
          const aged = new Date(Date.now() - 60_000);
          utimesSync(lockPath, aged, aged);

          const startAt = Date.now() + 50;
          const results = await Promise.all(
            children.map((child, i) => {
              const reply = nextMessage(child);
              child.send({ dataDir, key: `k${i}`, startAt });
              return reply;
            }),
          );
          const persisted = JSON.parse(readFileSync(sessionPath(dataDir), "utf8")).autoHandoffTurns;
          const label = `trial ${trial + 1}`;
          assert.deepEqual(
            results.map((r) => r.own),
            Array(CHILDREN).fill(true),
            `${label}: every child acquires the lock`,
          );
          assert.equal(results.filter((r) => r.shared === true).length, 1, `${label}: shared key granted exactly once`);
          assert.equal(results.filter((r) => r.shared === false).length, CHILDREN - 1, `${label}: others see it taken`);
          for (let i = 0; i < CHILDREN; i += 1) {
            assert.ok(persisted.includes(`k${i}`), `${label}: k${i} persisted`);
        }
        assert.equal(persisted.filter((k) => k === "shared").length, 1, `${label}: shared persisted once`);
        assert.equal(persisted.length, CHILDREN + 1, `${label}: 0 lost, 0 duplicate records`);
        }
      } finally {
        for (const child of children) {
          child.kill();
        }
      }
    }));

  it("reclaims a fresh lock left by a dead pid and never reclaims an old lock held by a live pid", () => {
    const deadDir = createTempDir("hstack-p1-lock-dead-");
    mkdirSync(join(deadDir, "sessions"));
    writeFileSync(`${sessionPath(deadDir)}.lock`, JSON.stringify({ pid: deadPid(), createdAt: Date.now() }));
    assert.equal(
      claimAutonomyTurnFlag({ conversationId: "conv1", flagName: "autoHandoffTurns", turnKey: "a", dataDir: deadDir }),
      true,
    );

    const liveDir = createTempDir("hstack-p1-lock-live-");
    mkdirSync(join(liveDir, "sessions"));
    const liveLock = `${sessionPath(liveDir)}.lock`;
    writeFileSync(liveLock, JSON.stringify({ pid: process.pid, createdAt: Date.now() - 60_000 }));
    const aged = new Date(Date.now() - 60_000);
    utimesSync(liveLock, aged, aged);
    assert.equal(
      claimAutonomyTurnFlag({ conversationId: "conv1", flagName: "autoHandoffTurns", turnKey: "a", dataDir: liveDir }),
      null,
    );
    assert.ok(existsSync(liveLock), "a live holder's lock stays in place");
    assert.equal(existsSync(sessionPath(liveDir)), false);
  });

  it("still writes the post_invocation audit record and drift injection when the session lock times out", () => {
    const dataDir = createTempDir("hstack-p1-post-");
    const trPath = join(dataDir, "tr.jsonl");
    writeFileSync(
      trPath,
      toJsonl([
        { step_index: 0, type: "USER_INPUT", content: "상태를 확인해 줘" },
        {
          step_index: 1,
          type: "PLANNER_RESPONSE",
          content: "Let me explain the whole architecture in English right now because it is easier for me to write.",
        },
      ]),
      "utf8",
    );
    mkdirSync(join(dataDir, "sessions"));
    // A live holder (this process) keeps the lock for the whole call, so every acquisition times out.
    writeFileSync(join(dataDir, "sessions", "conv-lock.json.lock"), JSON.stringify({ pid: process.pid, createdAt: Date.now() }));

    const out = handlePostInvocation(
      JSON.stringify({ hookEventName: "PostInvocation", conversationId: "conv-lock", cwd: dataDir, transcriptPath: trPath }),
      { dataDir, governanceConfig: {} },
    );
    assert.equal(out.injectSteps?.length, 1, "drift correction still injected");
    const audit = readFileSync(join(dataDir, "audit.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const post = audit.find((r) => r.event === "post_invocation");
    assert.ok(post, "post_invocation audit record still written");
    assert.equal(post.langAction, "inject");
  });
});

describe("#6 destructive-edit comment stripping respects strings", () => {
  const edit = (oldText, newText) =>
    detectDestructiveEdit({
      toolName: "replace_file_content",
      toolInput: { TargetFile: "/repo/src/auth/token.mjs", TargetContent: oldText, ReplacementContent: newText },
      cwd: "/repo",
      gitRoot: "/repo",
      existingFileContent: "x",
    });

  it("detects timingSafeEqual removal on a line that also holds a URL string", () => {
    const res = edit('const u = "https://example.com"; timingSafeEqual(a, b);', 'const u = "https://example.com";');
    assert.equal(res.destructive, true);
    assert.ok(res.reasons.includes("safety_primitive_removed"));
  });

  it("detects removals next to // or /* inside single-quoted and template strings", () => {
    assert.equal(edit("const u = 'http://x/*'; requireAuth(req);", "const u = 'http://x/*';").destructive, true);
    assert.equal(edit("const u = `${a}//b`; timingSafeEqual(a, b);", "const u = `${a}//b`;").destructive, true);
    assert.equal(edit('const s = "a\\"//"; timingSafeEqual(a, b);', 'const s = "a\\"//";').destructive, true);
  });

  it("still blocks hiding the primitive in a real comment", () => {
    const old = "timingSafeEqual(a, b);";
    assert.equal(edit(old, "// timingSafeEqual(a, b);").destructive, true);
    assert.equal(edit(old, "/* timingSafeEqual(a, b); */").destructive, true);
    assert.equal(edit(old, 'const u = "x"; // timingSafeEqual(a, b);').destructive, true);
  });
});

describe("#8 Korean answers with technical markdown stay korean", () => {
  const ko = "이번 변경으로 세션 잠금 로직이 원자적으로 동작하도록 수정했습니다. 테스트도 모두 통과했고 성능 저하는 없었습니다. ";
  const koreanCases = {
    links:
      ko +
      "\n\n참고 자료:\n- [Node.js File System documentation for rename](https://nodejs.org/api/fs.html)\n- [Atomic writes and the rename trick on POSIX](https://example.com/atomic)\n- [How to avoid race conditions with lock files](file:///docs/lock.md)",
    techBullets: ko + "\n\n지원 형식:\n- Markdown and HTML\n- Plain text or rich text\n- JSON or YAML\n- Node.js and TypeScript",
    tableCells:
      ko + "\n\n| 항목 | 결과 |\n|---|---|\n| Unit tests for the session lock module | 통과 |\n| Integration tests with the real server | 통과 |",
    unclosedFence:
      ko +
      "\n```js\n// This function retries the request when the server returns an error\n// and gives up after three attempts so we do not hammer the server\nfunction retry() {}\n",
    indentedCode:
      ko +
      "\n\n    // This function retries the request when the server returns an error\n    // and gives up after three attempts so we do not hammer the server\n",
    htmlComment:
      ko +
      "\n<!-- TODO: remove this section once the migration is finished -->\n<!--\nThis block explains the legacy layout and will be deleted after the next release.\n-->",
  };
  for (const [name, text] of Object.entries(koreanCases)) {
    it(`${name} is korean in content and thinking`, () => {
      assert.equal(analyzeField("content", text).status, "korean");
      assert.equal(analyzeField("thinking", text).status, "korean");
    });
  }

  const driftCases = {
    longSentenceInLink:
      ko + "자세한 내용은 [Let me explain the whole migration plan in English right now for everyone](https://x.io) 를 보세요.",
    longSentenceInLinkNoOpener:
      ko +
      "\n\n- [The parser now rejects every malformed header before it ever reaches the router](https://x.io)\n- [We rewrote the whole lock module because the old one kept losing records](https://y.io)",
    longSentenceInTableCell:
      ko +
      "\n\n| 항목 | 결과 |\n|---|---|\n| The parser now rejects every malformed header before it reaches the router | 통과 |\n| We rewrote the lock module because it kept losing records | 통과 |",
    proseBulletsWithAnd:
      ko + "\n\n- Check the config and run the tests\n- Read the logs and fix the parser\n- Update the docs and ship it",
    longSentenceBullets:
      ko +
      "\n\n- I updated the parser so that it now handles every malformed header correctly\n- Then I will rewrite the remaining lock helpers and run the whole suite again",
    indentedProse:
      ko +
      "\n\n    Now let me explain the entire architecture in English because it is much easier for me.\n    I will keep writing English sentences here until the very end of this answer.",
  };
  for (const [name, text] of Object.entries(driftCases)) {
    it(`${name} stays drifted`, () => {
      assert.equal(analyzeField("content", text).status, "drifted");
    });
  }
});

describe("#9 English-switch requests are recognized", () => {
  const yes = [
    "Switch to English",
    "Please switch to English.",
    "Please use English",
    "Use English",
    "Speak in English",
    "Talk in English",
    "Respond in English",
    "Reply in English",
    "From now on, English",
    "From now on respond in English",
    "Can we talk in English?",
    "Let's speak English from now on.",
    "영어로 대화하자",
    "영어로 대화해",
    "영어로 말해",
    "영어로 진행하자",
    "영어로 부탁해",
    "영어로 답해줘",
    "영어로 써줘",
  ];
  const no = [
    "영어 이탈 오탐을 고쳐줘",
    "영어 요청 정규식을 점검해",
    "왜 자꾸 영어로 대화해?",
    "영어로 대화하지 마",
    "Don't switch to English",
    "Do not use English",
    "Why did you switch to English?",
    "You switched to English again",
  ];
  for (const text of yes) {
    it(`true: ${text}`, () => assert.equal(isExplicitEnglishOutputRequest(text), true));
  }
  for (const text of no) {
    it(`false: ${text}`, () => assert.equal(isExplicitEnglishOutputRequest(text), false));
  }
});

describe("#3 follow-up: only an equivalent verification command clears a failure", () => {
  function gate(commands, claim) {
    const dir = createTempDir("hstack-p1-gate-");
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
      {
        modified_files: ["src/a.mjs"],
        inspected_files: [],
        verification_runs: [{ command: claim, outcome: "pass" }],
        unverified_scope: [],
        self_assessment: "",
      },
      {
        cwd: "/repo",
        ledger: readFactLedger(transcript, "/repo", "/repo"),
        gitLedger: { gitAvailable: false, gitRoot: "/repo", gitDirtyFiles: new Set() },
        testInfra: { hasTestSuite: true },
        auditEscalation: "off",
      },
    );
  }

  it("a passing `go test` does not clear a failed `go test ./...`", () => {
    const res = gate([["go test ./...", "FAIL\tpkg/x"], ["go test", "ok  \trepo\t0.01s"]], "go test");
    assert.equal(res.verdict, "REJECT");
    assert.ok(res.blockedRules.includes("R3_CONCEALED_FAILURE"));
  });

  it("a narrower or differently targeted rerun does not clear a failure on any runner", () => {
    assert.equal(gate([["node --test", "AssertionError: boom"], ["node --test test/a.test.mjs", "# pass 3"]], "node --test test/a.test.mjs").verdict, "REJECT");
    assert.equal(gate([["node --test test/a.test.mjs", "AssertionError: boom"], ["node --test test/b.test.mjs", "# pass 3"]], "node --test test/b.test.mjs").verdict, "REJECT");
    assert.equal(gate([["npm test -- --grep auth", "AssertionError: boom"], ["npm test", "ok"]], "npm test").verdict, "REJECT");
  });

  it("rerunning the same command clears the failure", () => {
    const res = gate([["go test ./...", "FAIL\tpkg/x"], ["go test ./...", "ok  \trepo\t0.01s"]], "go test ./...");
    assert.equal(res.verdict, "PASS");
    assert.deepEqual(res.blockedRules, []);
  });
});
