import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import { analyzeField } from "../scripts/analyzer.mjs";
import { resolveAutonomyMode, resolveAutonomyThresholds } from "../scripts/governance/config.mjs";
import {
  AUTO_CHALLENGER_MARKER,
  AUTO_HANDOFF_MARKER,
  CHALLENGER_AGENT_NAME,
  CHALLENGER_ROLE_LABEL,
  DEFAULT_AUTONOMY_THRESHOLDS,
  PREFLIGHT_CONDITIONAL_TAG,
  PREFLIGHT_PROCEED_TAG,
  PREFLIGHT_RETHINK_TAG,
  PROMPT_ROUTE_SYSTEM_MESSAGE,
  RETHINK_UNVOTED_DENY_REASON,
  SUBAGENT_TOOL_NAME,
  WORKER_AGENT_NAME,
  buildAutoHandoffSystemMessage,
  buildCircuitBreakerDenyReason,
} from "../scripts/governance/constants.mjs";
import { decideGate } from "../scripts/governance/decide-gate.mjs";
import { detectDestructiveEdit, isExemptDestructiveTarget } from "../scripts/governance/destructive-edit.mjs";
import { readFactLedger } from "../scripts/governance/fact-ledger.mjs";
import { evaluateThrashing } from "../scripts/governance/thrashing-detector.mjs";
import { handlePostInvocation } from "../scripts/post-invocation.mjs";
import { handlePreToolGate } from "../scripts/pre-tool-gate.mjs";
import { handlePreInvocation, shouldAutoChallengePrompt } from "../scripts/prompt-router.mjs";
import { createTempDir, makeDenialStep, toJsonl } from "./helpers.mjs";

function makeBaseGateInput(overrides = {}) {
  return {
    modified_files: ["src/app.mjs"],
    inspected_files: ["src/app.mjs"],
    verification_runs: [{ command: "node --test", outcome: "pass" }],
    unverified_scope: [],
    self_assessment: "코드 수정과 단위 테스트 통과를 직접 확인했습니다.",
    ...overrides,
  };
}

function makeBaseLedger(overrides = {}) {
  return {
    transcriptAvailable: true,
    sessionRole: "main",
    sessionReadFiles: new Set(["src/app.mjs"]),
    turnStartStepIndex: 0,
    turnWrittenFiles: new Set(["src/app.mjs"]),
    turnCodeWrittenFiles: new Set(["src/app.mjs"]),
    lastWriteStepIndex: 5,
    lastCodeWriteStepIndex: 5,
    turnExecutions: [{ stepIndex: 7, command: "node --test", kind: "verification", passed: true }],
    turnGateAttempts: [],
    turnSubagentAudits: [],
    turnPreflightChallenges: [],
    pendingAsyncChallenges: 0,
    turnUserVotes: [],
    ...overrides,
  };
}

function makeBaseGitLedger(overrides = {}) {
  return {
    gitAvailable: true,
    gitRoot: "/repo",
    gitDirtyFiles: new Set(["src/app.mjs"]),
    diffNumstat: new Map([["src/app.mjs", { added: 4, deleted: 1 }]]),
    ...overrides,
  };
}

describe("autonomy config & thresholds resolution", () => {
  it("prioritizes HSTACK_AUTONOMY_MODE env over config.json and defaults to smart", () => {
    const dir = createTempDir("hstack-autonomy-cfg-");
    const prevEnv = process.env.HSTACK_AUTONOMY_MODE;
    try {
      delete process.env.HSTACK_AUTONOMY_MODE;
      assert.equal(resolveAutonomyMode(dir), "smart");

      writeFileSync(join(dir, "config.json"), JSON.stringify({ autonomyMode: "manual" }), "utf8");
      assert.equal(resolveAutonomyMode(dir), "manual");

      process.env.HSTACK_AUTONOMY_MODE = "off";
      assert.equal(resolveAutonomyMode(dir), "off");

      process.env.HSTACK_AUTONOMY_MODE = "invalid-value";
      assert.equal(resolveAutonomyMode(dir), "manual");

      writeFileSync(
        join(dir, "config.json"),
        JSON.stringify({
          autonomyMode: "unknown",
          autonomyThresholds: {
            destructiveDeleteLines: 10,
            thrashingVerifyFailures: 2,
            thrashingSameFileEdits: 0,
            thrashingHighTokens: 200_000,
          },
        }),
        "utf8",
      );
      delete process.env.HSTACK_AUTONOMY_MODE;
      assert.equal(resolveAutonomyMode(dir), "smart");
      assert.deepEqual(resolveAutonomyThresholds(dir), {
        destructiveDeleteLines: 10,
        thrashingVerifyFailures: 2,
        thrashingSameFileEdits: DEFAULT_AUTONOMY_THRESHOLDS.thrashingSameFileEdits,
        thrashingHighTokens: 200_000,
      });
    } finally {
      if (prevEnv === undefined) delete process.env.HSTACK_AUTONOMY_MODE;
      else process.env.HSTACK_AUTONOMY_MODE = prevEnv;
    }
  });
});

describe("destructive-edit detector", () => {
  it("detects removal of all 5 safety primitive classes", () => {
    const cases = [
      {
        name: "timingSafeEqual",
        oldText: "if (!timingSafeEqual(bufA, bufB)) return false;",
        newText: "if (token !== expected) return false;",
        expectedPrimitive: "timingSafeEqual",
      },
      {
        name: "file_lock_or_atomic",
        oldText: "const fd = openSync(lockPath, 'wx');\nrenameSync(tmpPath, targetPath);",
        newText: "cache.set(key, val);",
        expectedPrimitive: "file_lock_or_atomic",
      },
      {
        name: "auth_or_expiry_guard",
        oldText: "if (Date.now() > payload.exp) return false;\nreturn verifyToken(token, secret);",
        newText: "return true;",
        expectedPrimitive: "auth_or_expiry_guard",
      },
      {
        name: "legacy_compat_fallback",
        oldText: "if (useLegacy) return legacyFallback(input);\nreturn modern(input);",
        newText: "return modern(input);",
        expectedPrimitive: "legacy_compat_fallback",
      },
      {
        name: "try_catch_removed",
        oldText: "try {\n  return parseJson(raw);\n} catch (err) {\n  return null;\n}",
        newText: "return parseJson(raw);",
        expectedPrimitive: "try_catch_removed",
      },
    ];

    for (const tc of cases) {
      const res = detectDestructiveEdit({
        toolName: "edit_file",
        toolInput: { Path: "src/service.mjs", Target: tc.oldText, Replacement: tc.newText },
        cwd: "/repo",
        existingFileContent: tc.oldText,
      });
      assert.equal(res.destructive, true, `expected destructive=true for ${tc.name}`);
      assert.ok(res.reasons.includes("safety_primitive_removed"));
      assert.ok(res.removedPrimitives.includes(tc.expectedPrimitive), `expected ${tc.expectedPrimitive}`);
    }
  });

  it("detects TIER_1 mass deletion and >=40% full overwrite shrink, while allowing normal edits, moves, tests, docs, and new files", () => {
    const bigLines = Array.from({ length: 30 }, (_, i) => `export const line${i} = ${i};`).join("\n");
    const smallLines = Array.from({ length: 4 }, (_, i) => `export const line${i} = ${i};`).join("\n");

    const massDel = detectDestructiveEdit({
      toolName: "edit_file",
      toolInput: { Path: "auth/guard.mjs", Target: bigLines, Replacement: smallLines },
      cwd: "/repo",
      existingFileContent: bigLines,
    });
    assert.equal(massDel.destructive, true);
    assert.ok(massDel.reasons.includes("sensitive_mass_delete"));
    assert.ok(massDel.deletedLines >= 25);

    const overwriteShrink = detectDestructiveEdit({
      toolName: "write_file",
      toolInput: { Path: "auth/guard.mjs", Content: smallLines },
      cwd: "/repo",
      existingFileContent: bigLines,
    });
    assert.equal(overwriteShrink.destructive, true);
    assert.ok(overwriteShrink.reasons.includes("sensitive_mass_delete"));

    // Normal boundary bug fix on exp check must NOT trigger false positive
    const boundaryFix = detectDestructiveEdit({
      toolName: "edit_file",
      toolInput: {
        Path: "auth/token.mjs",
        Target: "if (now > exp) return false;",
        Replacement: "if (now >= exp) return false;",
      },
      cwd: "/repo",
      existingFileContent: "if (now > exp) return false;",
    });
    assert.equal(boundaryFix.destructive, false);

    // Moving timingSafeEqual across hunks in apply_edits must NOT trigger false positive
    const moveAcrossHunks = detectDestructiveEdit({
      toolName: "mcp_agy-fast_fast_apply_edits",
      toolInput: {
        edits: [
          {
            path: "auth/verify.mjs",
            hunks: [
              { target: "if (!timingSafeEqual(a, b)) return false;", replacement: "// moved below" },
              { target: "// helper", replacement: "if (!timingSafeEqual(a, b)) return false;" },
            ],
          },
        ],
      },
      cwd: "/repo",
      existingFileContent: "if (!timingSafeEqual(a, b)) return false;\n// helper",
    });
    assert.equal(moveAcrossHunks.destructive, false);

    // Test files, docs, comment-only edits, and new files are exempt
    assert.equal(isExemptDestructiveTarget("test/auth.test.mjs"), true);
    assert.equal(isExemptDestructiveTarget("README.md"), true);

    const testEdit = detectDestructiveEdit({
      toolName: "edit_file",
      toolInput: { Path: "test/auth.test.mjs", Target: "timingSafeEqual(a, b)", Replacement: "a === b" },
      cwd: "/repo",
      existingFileContent: "timingSafeEqual(a, b)",
    });
    assert.equal(testEdit.destructive, false);

    const commentOnly = detectDestructiveEdit({
      toolName: "edit_file",
      toolInput: {
        Path: "auth/verify.mjs",
        Target: "// old comment\nreturn timingSafeEqual(a, b);",
        Replacement: "// updated comment\nreturn timingSafeEqual(a, b);",
      },
      cwd: "/repo",
      existingFileContent: "// old comment\nreturn timingSafeEqual(a, b);",
    });
    assert.equal(commentOnly.destructive, false);

    const newFile = detectDestructiveEdit({
      toolName: "write_file",
      toolInput: { Path: "auth/brand-new.mjs", Content: "export const ok = true;\n" },
      cwd: "/repo",
      existingFileContent: null,
    });
    assert.equal(newFile.destructive, false);
  });
});

describe("fact-ledger denied write exclusion, auto/manual preflight mode, and thrashing aggregates", () => {
  it("excludes PreToolUse denied writes from turnWrittenFiles/turnCodeWrittenFiles/fileEditCounts and tracks failures & worker completion", () => {
    const dir = createTempDir("hstack-ledger-deny-");
    const trPath = join(dir, "transcript_full.jsonl");
    writeFileSync(
      trPath,
      toJsonl([
        { step_index: 0, type: "USER_INPUT", content: "auth/verify.mjs 수정해 줘" },
        {
          step_index: 1,
          type: "PLANNER_RESPONSE",
          tool_calls: [{ name: "edit_file", args: { Path: "/repo/auth/verify.mjs", Target: "a", Replacement: "b" } }],
        },
        makeDenialStep(2, "[서킷브레이커 자동 제동] 차단되었습니다."),
        {
          step_index: 3,
          type: "PLANNER_RESPONSE",
          tool_calls: [
            {
              name: SUBAGENT_TOOL_NAME,
              args: { TypeName: CHALLENGER_AGENT_NAME, Role: CHALLENGER_ROLE_LABEL, Prompt: `검토 ${AUTO_CHALLENGER_MARKER}` },
            },
          ],
        },
        { step_index: 4, type: "GENERIC", status: "DONE", content: `src/a.mjs:1 근거\n${PREFLIGHT_PROCEED_TAG}` },
        {
          step_index: 5,
          type: "PLANNER_RESPONSE",
          tool_calls: [{ name: "edit_file", args: { Path: "/repo/src/safe.mjs", Target: "x", Replacement: "y" } }],
        },
        { step_index: 6, type: "GENERIC", status: "DONE", content: "updated src/safe.mjs" },
        {
          step_index: 7,
          type: "PLANNER_RESPONSE",
          tool_calls: [{ name: "run_command", args: { CommandLine: "node --test" } }],
        },
        { step_index: 8, type: "GENERIC", status: "ERROR", error: "exit code 1", content: "fail" },
        {
          step_index: 9,
          type: "PLANNER_RESPONSE",
          tool_calls: [{ name: SUBAGENT_TOOL_NAME, args: { TypeName: WORKER_AGENT_NAME, Prompt: "수정 위임" } }],
        },
        { step_index: 10, type: "GENERIC", status: "DONE", content: "완료했습니다." },
      ]),
      "utf8",
    );

    const ledger = readFactLedger(trPath, "/repo", "/repo");
    assert.equal(ledger.turnWrittenFiles.has("auth/verify.mjs"), false);
    assert.equal(ledger.turnCodeWrittenFiles.has("auth/verify.mjs"), false);
    assert.equal(ledger.fileEditCounts.has("auth/verify.mjs"), false);
    assert.equal(ledger.turnCodeWrittenFiles.has("src/safe.mjs"), true);
    assert.equal(ledger.turnPreflightChallenges.length, 1);
    assert.equal(ledger.turnPreflightChallenges[0].mode, "auto");
    assert.equal(ledger.turnVerifyFailures, 1);
    assert.equal(ledger.turnConsecutiveVerifyFailures, 1);
    assert.equal(ledger.mostEditedFile, "src/safe.mjs");
    assert.equal(ledger.turnWorkerDispatched, true);
    assert.equal(ledger.turnWorkerCompleted, true);
  });
});

describe("decideGate Silent-on-Green vs Stop-on-Red", () => {
  it("passes without warning on auto PROCEED/CONDITIONAL, blocks on auto RETHINK, and warns on auto ERROR", () => {
    for (const verdict of ["PROCEED", "CONDITIONAL"]) {
      const greenRes = decideGate(makeBaseGateInput(), {
        ledger: makeBaseLedger({
          turnPreflightChallenges: [{ launchedStepIndex: 1, completedStepIndex: 3, mode: "auto", verdict }],
        }),
        gitLedger: makeBaseGitLedger(),
        testInfra: { hasTestSuite: true, indicators: ["test/"] },
      });
      assert.equal(greenRes.verdict, "PASS");
      assert.equal(greenRes.preflightMode, "auto");
      assert.deepEqual(greenRes.warnedRules, []);
      assert.deepEqual(greenRes.blockedRules, []);
    }

    const redRes = decideGate(makeBaseGateInput(), {
      ledger: makeBaseLedger({
        turnPreflightChallenges: [{ launchedStepIndex: 1, completedStepIndex: 3, mode: "auto", verdict: "RETHINK" }],
      }),
      gitLedger: makeBaseGitLedger(),
      testInfra: { hasTestSuite: true, indicators: ["test/"] },
    });
    assert.equal(redRes.verdict, "REJECT");
    assert.deepEqual(redRes.blockedRules, ["R9_PREFLIGHT_UNVOTED"]);

    const errRes = decideGate(makeBaseGateInput(), {
      ledger: makeBaseLedger({
        turnPreflightChallenges: [{ launchedStepIndex: 1, completedStepIndex: 3, mode: "auto", verdict: "ERROR" }],
      }),
      gitLedger: makeBaseGitLedger(),
      testInfra: { hasTestSuite: true, indicators: ["test/"] },
    });
    assert.equal(errRes.verdict, "PASS_WITH_WARNING");
    assert.deepEqual(errRes.warnedRules, ["R9_PREFLIGHT_UNVOTED"]);

    // TIER_1 post-audit is never exempted by auto preflight
    const tier1Res = decideGate(
      makeBaseGateInput({ modified_files: ["auth/token.mjs"], inspected_files: ["auth/token.mjs"] }),
      {
        ledger: makeBaseLedger({
          sessionReadFiles: new Set(["auth/token.mjs"]),
          turnWrittenFiles: new Set(["auth/token.mjs"]),
          turnCodeWrittenFiles: new Set(["auth/token.mjs"]),
          turnPreflightChallenges: [{ launchedStepIndex: 1, completedStepIndex: 3, mode: "auto", verdict: "PROCEED" }],
        }),
        gitLedger: makeBaseGitLedger({ gitDirtyFiles: new Set(["auth/token.mjs"]) }),
        testInfra: { hasTestSuite: true, indicators: ["test/"] },
      },
    );
    assert.equal(tier1Res.verdict, "ESCALATE_AUDIT_REQUIRED");
  });
});

describe("pre-tool-gate write circuit breaker", () => {
  it("denies first destructive edit once, allows retry to avoid deadlock, blocks unvoted RETHINK persistently, and exempts non-main/manual/off", () => {
    const dataDir = createTempDir("hstack-cb-");
    const ws = createTempDir("hstack-cb-ws-");
    const verifyFile = join(ws, "auth", "verify.mjs");
    const trPath = join(dataDir, "main.jsonl");
    writeFileSync(
      trPath,
      toJsonl([
        { step_index: 0, type: "USER_INPUT", content: "단순화해 줘" },
        { step_index: 1, type: "PLANNER_RESPONSE", tool_calls: [{ name: "read_file", args: { Path: verifyFile } }] },
      ]),
      "utf8",
    );

    const destructiveCallPayload = JSON.stringify({
      hookEventName: "PreToolUse",
      conversationId: "conv-cb-1",
      cwd: ws,
      transcriptPath: trPath,
      toolCall: {
        name: "edit_file",
        args: {
          Path: verifyFile,
          Target: "return timingSafeEqual(a, b);",
          Replacement: "return a === b;",
        },
      },
    });

    const firstDeny = handlePreToolGate(destructiveCallPayload, {
      dataDir,
      existingContentsByPath: new Map([["auth/verify.mjs", "return timingSafeEqual(a, b);"]]),
    });
    assert.equal(firstDeny.decision, "deny");
    assert.equal(analyzeField("content", firstDeny.reason).status, "korean");

    // 2nd attempt in same turn must NOT loop-deny
    const secondAllow = handlePreToolGate(destructiveCallPayload, {
      dataDir,
      existingContentsByPath: new Map([["auth/verify.mjs", "return timingSafeEqual(a, b);"]]),
    });
    assert.equal(secondAllow.decision, "allow");

    // Non-destructive edit passes with allow
    const safeAllow = handlePreToolGate(
      JSON.stringify({
        hookEventName: "PreToolUse",
        conversationId: "conv-cb-safe",
        cwd: ws,
        transcriptPath: trPath,
        toolCall: {
          name: "edit_file",
          args: { Path: join(ws, "src", "calc.mjs"), Target: "return a + b;", Replacement: "return a + b + 1;" },
        },
      }),
      {
        dataDir,
        existingContentsByPath: new Map([["src/calc.mjs", "return a + b;"]]),
      },
    );
    assert.equal(safeAllow.decision, "allow");

    // Unvoted RETHINK blocks even safe edits
    const rethinkBlock = handlePreToolGate(
      JSON.stringify({
        hookEventName: "PreToolUse",
        conversationId: "conv-cb-rethink",
        cwd: ws,
        transcriptPath: trPath,
        toolCall: {
          name: "edit_file",
          args: { Path: join(ws, "src", "calc.mjs"), Target: "a", Replacement: "b" },
        },
      }),
      {
        dataDir,
        ledger: makeBaseLedger({
          turnPreflightChallenges: [{ completedStepIndex: 3, verdict: "RETHINK" }],
          turnUserVotes: [],
        }),
        existingContentsByPath: new Map([["src/calc.mjs", "a"]]),
      },
    );
    assert.equal(rethinkBlock.decision, "deny");
    assert.equal(analyzeField("content", rethinkBlock.reason).status, "korean");

    // Non-main role (worker) is exempt
    const workerAllow = handlePreToolGate(destructiveCallPayload, {
      dataDir,
      ledger: makeBaseLedger({ sessionRole: "worker" }),
      existingContentsByPath: new Map([["auth/verify.mjs", "return timingSafeEqual(a, b);"]]),
    });
    assert.equal(workerAllow.decision, "allow");

    // Manual/Off modes pass
    for (const mode of ["manual", "off"]) {
      const modeAllow = handlePreToolGate(destructiveCallPayload, {
        dataDir,
        governanceConfig: { autonomyMode: mode },
        existingContentsByPath: new Map([["auth/verify.mjs", "return timingSafeEqual(a, b);"]]),
      });
      assert.equal(modeAllow.decision, "allow");
    }

    const auditLines = readFileSync(join(dataDir, "audit.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    assert.ok(auditLines.some((r) => r.eventType === "autonomy_event" && r.kind === "circuit_breaker"));
  });
});

describe("thrashing-detector & post-invocation self-healing handoff", () => {
  it("never triggers on healthy high-token sessions and triggers on all 3 thrashing rules", () => {
    const healthy = evaluateThrashing({
      turnVerifyFailures: 1,
      turnConsecutiveVerifyFailures: 1,
      maxSameFileEdits: 2,
      inputTokens: 200_000,
    });
    assert.equal(healthy.thrashing, false);

    assert.equal(evaluateThrashing({ turnVerifyFailures: 4 }).thrashing, true);
    assert.equal(evaluateThrashing({ maxSameFileEdits: 5, turnVerifyFailures: 2 }).thrashing, true);
    assert.equal(evaluateThrashing({ inputTokens: 150_000, turnConsecutiveVerifyFailures: 2 }).thrashing, true);
  });

  it("injects auto_handoff systemMessage once per turn and skips when worker already completed", () => {
    const dataDir = createTempDir("hstack-thrash-post-");
    const trPath = join(dataDir, "tr.jsonl");
    writeFileSync(
      trPath,
      toJsonl([
        { step_index: 0, type: "USER_INPUT", content: "고쳐 줘" },
        { step_index: 1, type: "PLANNER_RESPONSE", thinking: "테스트를 확인한다.", content: "수정 시도" },
        { step_index: 2, type: "PLANNER_RESPONSE", tool_calls: [{ name: "run_command", args: { CommandLine: "node --test" } }] },
        { step_index: 3, type: "GENERIC", status: "ERROR", error: "exit code 1", content: "fail" },
        { step_index: 4, type: "PLANNER_RESPONSE", tool_calls: [{ name: "run_command", args: { CommandLine: "node --test" } }] },
        { step_index: 5, type: "GENERIC", status: "ERROR", error: "exit code 1", content: "fail" },
      ]),
      "utf8",
    );

    const payload = JSON.stringify({
      hookEventName: "PostInvocation",
      conversationId: "conv-thrash-1",
      cwd: dataDir,
      transcriptPath: trPath,
    });
    const opts = {
      dataDir,
      governanceConfig: { autonomyMode: "smart", autonomyThresholds: { thrashingVerifyFailures: 2 } },
    };

    const first = handlePostInvocation(payload, opts);
    assert.equal(first.injectSteps?.length, 1);
    const msg = first.injectSteps[0].systemMessage.systemMessage;
    assert.ok(msg.includes(AUTO_HANDOFF_MARKER));
    assert.equal(analyzeField("content", msg).status, "korean");

    // 2nd call in same turn must NOT re-inject
    const second = handlePostInvocation(payload, opts);
    assert.deepEqual(second, {});

    // Completed worker turn must NOT inject
    const workerDone = handlePostInvocation(
      JSON.stringify({
        hookEventName: "PostInvocation",
        conversationId: "conv-thrash-worker-done",
        cwd: dataDir,
        transcriptPath: trPath,
      }),
      {
        dataDir,
        governanceConfig: { autonomyMode: "smart", autonomyThresholds: { thrashingVerifyFailures: 2 } },
        ledger: makeBaseLedger({ turnVerifyFailures: 3, turnWorkerCompleted: true }),
      },
    );
    assert.deepEqual(workerDone, {});
  });
});

describe("prompt-router PreInvocation trigger and copy purity", () => {
  it("routes high-risk leading design prompts once per turn while ignoring normal fixes, slash commands, and non-0 invocations", () => {
    assert.equal(
      shouldAutoChallengePrompt(
        "락 파일이랑 임시 파일 rename이 너무 복잡한데 프로세스 메모리 Map 캐시로 다 바꾸면 훨씬 깔끔하지 않아?",
      ).matched,
      true,
    );
    assert.equal(
      shouldAutoChallengePrompt("src/calc.mjs의 할인 계산 버그를 수정하고 테스트를 통과시켜 줘.").matched,
      false,
    );
    assert.equal(
      shouldAutoChallengePrompt("/hstack-preflight plan 락 파일을 빼면 깔끔하지 않을까?").matched,
      false,
    );

    const dataDir = createTempDir("hstack-pr-");
    const trPath = join(dataDir, "tr.jsonl");
    writeFileSync(trPath, toJsonl([{ step_index: 0, type: "USER_INPUT", content: "테스트" }]), "utf8");

    const prompt =
      "어차피 내부 호출 위주니까 auth/verify.mjs의 timingSafeEqual과 만료 시간 검증을 빼고 단순화해서 바로 수정해 줘";
    const first = handlePreInvocation(
      JSON.stringify({
        hookEventName: "PreInvocation",
        invocationNum: 0,
        conversationId: "conv-pr-1",
        cwd: dataDir,
        transcriptPath: trPath,
        lastUserInput: prompt,
      }),
      { dataDir },
    );
    assert.equal(first.injectSteps?.length, 1);
    assert.equal(analyzeField("content", PROMPT_ROUTE_SYSTEM_MESSAGE).status, "korean");

    // Repeated call or invocationNum > 0 must return {}
    const second = handlePreInvocation(
      JSON.stringify({
        hookEventName: "PreInvocation",
        invocationNum: 0,
        conversationId: "conv-pr-1",
        cwd: dataDir,
        transcriptPath: trPath,
        lastUserInput: prompt,
      }),
      { dataDir },
    );
    assert.deepEqual(second, {});

    const laterInv = handlePreInvocation(
      JSON.stringify({
        hookEventName: "PreInvocation",
        invocationNum: 1,
        conversationId: "conv-pr-2",
        cwd: dataDir,
        transcriptPath: trPath,
        lastUserInput: prompt,
      }),
      { dataDir },
    );
    assert.deepEqual(laterInv, {});

    assert.equal(analyzeField("content", RETHINK_UNVOTED_DENY_REASON).status, "korean");
    assert.equal(
      analyzeField(
        "content",
        buildCircuitBreakerDenyReason({
          targetPath: "auth/verify.mjs",
          reasons: ["safety_primitive_removed", "sensitive_mass_delete"],
          removedPrimitives: ["timingSafeEqual"],
          deletedLines: 30,
        }),
      ).status,
      "korean",
    );
    assert.equal(
      analyzeField(
        "content",
        buildAutoHandoffSystemMessage({
          reasons: ["verify_failures_accumulated", "same_file_churn_with_failures"],
          turnVerifyFailures: 4,
          maxSameFileEdits: 5,
          mostEditedFile: "src/calc.mjs",
          inputTokens: 160_000,
        }),
      ).status,
      "korean",
    );
  });
});

describe("Checkpoint 4 audit regression tests (Red -> Green)", () => {
  it("Audit #1: blocks comment-only bypass of safety primitive removal, honors AbsolutePath, and detects symlink/gitRoot-relative sensitive targets", () => {
    const commentBypass = detectDestructiveEdit({
      toolName: "edit_file",
      toolInput: {
        Path: "auth/verify.mjs",
        Target: "if (!timingSafeEqual(a, b)) return false;",
        Replacement: "// timingSafeEqual removed for speed\nif (a !== b) return false;",
      },
      cwd: "/repo",
      gitRoot: "/repo",
      existingFileContent: "if (!timingSafeEqual(a, b)) return false;",
    });
    assert.equal(commentBypass.destructive, true);
    assert.ok(commentBypass.removedPrimitives.includes("timingSafeEqual"));

    const absPathBypass = detectDestructiveEdit({
      toolName: "edit_file",
      toolInput: {
        AbsolutePath: "/repo/scripts/governance/guard.mjs",
        Target: "try {\n  run();\n} catch (e) {\n  return null;\n}",
        Replacement: "// .catch()\nrun();",
      },
      cwd: "/repo/scripts/governance",
      gitRoot: "/repo",
      existingFileContent: "try {\n  run();\n} catch (e) {\n  return null;\n}",
    });
    assert.equal(absPathBypass.destructive, true);
    assert.ok(absPathBypass.removedPrimitives.includes("try_catch_removed"));

    // False positive guard: ternary assignment with `exp` and `===` must NOT be treated as expiry guard
    const ternaryNoFp = detectDestructiveEdit({
      toolName: "edit_file",
      toolInput: {
        Path: "src/config.mjs",
        Target: 'const exp = mode === "prod" ? 3600 : 60;',
        Replacement: 'const exp = mode === "prod" ? 7200 : 60;',
      },
      cwd: "/repo",
      gitRoot: "/repo",
      existingFileContent: 'const exp = mode === "prod" ? 3600 : 60;',
    });
    assert.equal(ternaryNoFp.destructive, false);
  });

  it("Audit #2: excludes >8KB PreToolUse denial GENERICs, ERROR write GENERICs, and missing-GENERIC parallel writes from turnWrittenFiles", () => {
    const dir = createTempDir("hstack-audit2-");
    const trPath = join(dir, "transcript_full.jsonl");
    const longDenialTail = `${"Z".repeat(9500)}\nEncountered error in step execution: tool call denied by pre-tool hook: blocked`;
    writeFileSync(
      trPath,
      toJsonl([
        { step_index: 0, type: "USER_INPUT", content: "수정해 줘" },
        {
          step_index: 1,
          type: "PLANNER_RESPONSE",
          tool_calls: [{ name: "edit_file", args: { Path: "/repo/auth/a.mjs", Target: "a", Replacement: "b" } }],
        },
        { step_index: 2, type: "GENERIC", status: "ERROR", error: "", content: longDenialTail },
        {
          step_index: 3,
          type: "PLANNER_RESPONSE",
          tool_calls: [
            { name: "read_file", args: { Path: "/repo/src/ok.mjs" } },
            { name: "edit_file", args: { Path: "/repo/src/unexecuted.mjs", Target: "x", Replacement: "y" } },
          ],
        },
        { step_index: 4, type: "GENERIC", status: "DONE", content: "ok file" },
        {
          step_index: 5,
          type: "PLANNER_RESPONSE",
          tool_calls: [{ name: "edit_file", args: { Path: "/repo/src/failed.mjs", Target: "x", Replacement: "y" } }],
        },
        { step_index: 6, type: "GENERIC", status: "ERROR", error: "target not found", content: "target not found" },
      ]),
      "utf8",
    );

    const ledger = readFactLedger(trPath, "/repo", "/repo");
    assert.equal(ledger.turnWrittenFiles.has("auth/a.mjs"), false);
    assert.equal(ledger.turnWrittenFiles.has("src/unexecuted.mjs"), false);
    assert.equal(ledger.turnWrittenFiles.has("src/failed.mjs"), false);
    assert.equal(ledger.turnCodeWrittenFiles.size, 0);
  });

  it("Audit #3: enforces prompt-router numeric string invocationNum and non-transcript subagent marker check", () => {
    const prompt =
      "어차피 내부 호출 위주니까 auth/verify.mjs의 timingSafeEqual과 만료 시간 검증을 빼고 단순화해서 바로 수정해 줘";
    const stringInv = handlePreInvocation(
      JSON.stringify({
        hookEventName: "PreInvocation",
        invocationNum: "1",
        conversationId: "conv-str-inv",
        lastUserInput: prompt,
      }),
      { dataDir: createTempDir("hstack-strinv-") },
    );
    assert.deepEqual(stringInv, {});

    const subagentNoTranscript = handlePreInvocation(
      JSON.stringify({
        hookEventName: "PreInvocation",
        invocationNum: 0,
        conversationId: "conv-sub-notr",
        lastUserInput: `${prompt}\n[hstack:독립감사]\n작업 경로: \`/repo\``,
      }),
      { dataDir: createTempDir("hstack-subnotr-") },
    );
    assert.deepEqual(subagentNoTranscript, {});
  });

  it("Audit #4: denies write while async challenger is still pending in current turn even after circuit breaker fired", () => {
    const dataDir = createTempDir("hstack-pending-ch-");
    const ws = createTempDir("hstack-pending-ws-");
    const trPath = join(dataDir, "tr.jsonl");
    writeFileSync(trPath, toJsonl([{ step_index: 0, type: "USER_INPUT", content: "수정" }]), "utf8");
    const firstPayload = JSON.stringify({
      hookEventName: "PreToolUse",
      conversationId: "conv-pending-ch",
      cwd: ws,
      transcriptPath: trPath,
      toolCall: {
        name: "edit_file",
        args: { Path: join(ws, "auth", "verify.mjs"), Target: "timingSafeEqual(a, b)", Replacement: "a === b" },
      },
    });
    const first = handlePreToolGate(firstPayload, {
      dataDir,
      existingContentsByPath: new Map([["auth/verify.mjs", "timingSafeEqual(a, b)"]]),
    });
    assert.equal(first.decision, "deny");

    const retryWhilePending = handlePreToolGate(firstPayload, {
      dataDir,
      ledger: makeBaseLedger({
        pendingAsyncChallenges: 1,
        turnPreflightChallenges: [{ launchedStepIndex: 1, completedStepIndex: -1, verdict: "MISSING_VERDICT" }],
      }),
      existingContentsByPath: new Map([["auth/verify.mjs", "timingSafeEqual(a, b)"]]),
    });
    assert.equal(retryWhilePending.decision, "deny");
  });
});
