// v0.1.2 gate audit run 5 (Round H): untracked overflow vs tracked edits, strict npx/npm/go whitelist, sequential pipefail.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import { GATE_TOOL_NAME, VERDICT_HEADERS } from "../scripts/governance/constants.mjs";
import { decideGate } from "../scripts/governance/decide-gate.mjs";
import { classifyCommand, readFactLedger, snapshotWorkingTree } from "../scripts/governance/fact-ledger.mjs";
import { resolveSessionStatePath } from "../scripts/governance/handoff-store.mjs";
import { createMcpServerHandler } from "../scripts/mcp/server.mjs";
import { handlePreToolGate } from "../scripts/pre-tool-gate.mjs";
import { handlePreInvocation } from "../scripts/prompt-router.mjs";
import { handleStop } from "../scripts/stop.mjs";
import { GATE_STOP_MARKER } from "../scripts/transcript.mjs";
import { createTempDir, toJsonl, withCpuLock } from "./helpers.mjs";

for (const key of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"]) delete process.env[key];
const DATA_DIR = createTempDir("hstack-p10-data-");
process.env.HSTACK_DATA_DIR = DATA_DIR;
const git = (cwd, args) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const PASS_OUTPUT = "ℹ tests 1\nℹ pass 1\nℹ fail 0\n";
const FAIL_OUTPUT = "ℹ tests 1\nℹ pass 0\nℹ fail 1\nAssertionError: boom\n";

function makeRepo() {
  const repo = createTempDir("hstack-p10-repo-");
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

function runTurnOnRepo(repo, conversationId, steps, { dropSnapshot = false } = {}) {
  const transcriptPath = join(repo, ".t.jsonl");
  const user = "app.mjs 상태 확인하고 필요한 작업만 해 줘";
  const records = [{ step_index: 0, type: "USER_INPUT", content: user }];
  const flush = () => writeFileSync(transcriptPath, toJsonl(records));
  flush();
  handlePreInvocation(
    JSON.stringify({ hookEventName: "PreInvocation", invocationNum: 0, conversationId, cwd: repo, transcriptPath }),
    { dataDir: DATA_DIR, skipAuditLog: true },
  );
  if (dropSnapshot) {
    rmSync(resolveSessionStatePath(conversationId, DATA_DIR), { force: true });
  }
  const server = createMcpServerHandler({ dataDir: DATA_DIR, register: "neutral" });
  const verdicts = [];
  for (const step of steps) {
    let call;
    let result = "ok";
    if (step.gate) {
      call = { name: GATE_TOOL_NAME, args: step.gate };
      records.push({ step_index: records.length, type: "PLANNER_RESPONSE", tool_calls: [call] });
      flush();
      const pre = handlePreToolGate(
        JSON.stringify({ hookEventName: "PreToolUse", conversationId, cwd: repo, transcriptPath, toolCall: call }),
        { dataDir: DATA_DIR, skipAuditLog: true },
      );
      const res = server({
        jsonrpc: "2.0",
        id: records.length,
        method: "tools/call",
        params: { name: "verify_completion", arguments: { ...step.gate, ...pre.overwrite } },
      });
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
  records.push({ step_index: records.length, type: "PLANNER_RESPONSE", content: "확인을 마쳤습니다. 요청한 결과를 보고합니다." });
  flush();
  const out = handleStop(
    JSON.stringify({
      hookEventName: "Stop",
      terminationReason: "NO_TOOL_CALL",
      executionNum: 0,
      conversationId,
      cwd: repo,
      transcriptPath,
      lastUserInput: user,
    }),
  );
  return { out, verdicts };
}

function assertGateBlocked(out) {
  assert.equal(out.decision, "continue", JSON.stringify(out));
  assert.ok(out.reason.includes(GATE_STOP_MARKER), out.reason);
}

describe("H1 untracked overflow and snapshot timeout precision in Stop gate", () => {
  it("allows Stop on a test-only turn even with 2,100 untracked code files", () => {
    withCpuLock(() => {
      const repo = makeRepo();
      mkdirSync(join(repo, "untracked"));
      for (let i = 0; i < 2100; i += 1) {
        writeFileSync(join(repo, "untracked", `u${i}.mjs`), `export const n = ${i};\n`);
      }
      const { out } = runTurnOnRepo(repo, "p10-h1-untracked-test", [
        { cmd: "node --test", output: PASS_OUTPUT },
      ]);
      assert.deepEqual(out, {});
    });
  });

  it("blocks Stop when a tracked code file is edited via sed -i in a repo with 2,100 untracked code files", () => {
    withCpuLock(() => {
      const repo = makeRepo();
      mkdirSync(join(repo, "untracked"));
      for (let i = 0; i < 2100; i += 1) {
        writeFileSync(join(repo, "untracked", `u${i}.mjs`), `export const n = ${i};\n`);
      }
      const { out } = runTurnOnRepo(repo, "p10-h1-untracked-sed", [
        {
          cmd: "sed -i s/1/2/ app.mjs",
          effect: (r) => writeFileSync(join(r, "app.mjs"), "export const v = 2;\n"),
        },
      ]);
      assertGateBlocked(out);
    });
  });

  it("excludes .gitignore targets and exempt doc/asset files from the 2,000-file code snapshot cap", () => {
    withCpuLock(() => {
      const repo = makeRepo();
      writeFileSync(join(repo, ".gitignore"), "ignored/\n");
      mkdirSync(join(repo, "ignored"));
      mkdirSync(join(repo, "docs"));
      for (let i = 0; i < 2100; i += 1) {
        writeFileSync(join(repo, "ignored", `f${i}.mjs`), `export const x = ${i};\n`);
        writeFileSync(join(repo, "docs", `note${i}.txt`), `doc ${i}\n`);
      }
      const snap = snapshotWorkingTree(repo);
      assert.ok(snap && typeof snap.files === "object", "expected a complete snapshot");
      assert.equal(snap.untrackedTruncated, false);
    });
  });

  it("allows Stop on test-only turns and blocks Stop on arbitrary shell turns when snapshot is missing", () => {
    const repo = makeRepo();
    const passTestOnly = runTurnOnRepo(
      repo,
      "p10-h1-missing-test",
      [{ cmd: "git status" }, { cmd: "node --test", output: PASS_OUTPUT }],
      { dropSnapshot: true },
    );
    assert.deepEqual(passTestOnly.out, {});

    for (const [idx, cmd] of [
      "sed -i s/1/2/ app.mjs",
      "sh -c 'true'",
      `node -e "process.exit(0)"`,
      `python3 -c "pass"`,
    ].entries()) {
      const blocked = runTurnOnRepo(
        makeRepo(),
        `p10-h1-missing-shell-${idx}`,
        [{ cmd }],
        { dropSnapshot: true },
      );
      assertGateBlocked(blocked.out);
    }
  });

  it("allows Stop on test-only turns and blocks Stop on arbitrary shell turns under forced git snapshot timeout", () => {
    withCpuLock(() => {
      const binDir = createTempDir("hstack-p10-slowgit-");
      const realGit = execFileSync("which", ["git"], { encoding: "utf8" }).trim();
      const fakeGit = join(binDir, "git");
      writeFileSync(
        fakeGit,
        `#!/bin/sh\nif printf '%s\\n' "$*" | grep -q -- '--porcelain=v1'; then sleep 0.9; fi\nexec "${realGit}" "$@"\n`,
      );
      chmodSync(fakeGit, 0o755);

      const prevPath = process.env.PATH ?? "";
      process.env.PATH = `${binDir}:${prevPath}`;
      try {
        const repo = makeRepo();
        assert.equal(snapshotWorkingTree(repo), null);

        const testOnly = runTurnOnRepo(repo, "p10-h1-timeout-test", [
          { cmd: "node --test", output: PASS_OUTPUT },
        ]);
        assert.deepEqual(testOnly.out, {});

        const shellEdit = runTurnOnRepo(makeRepo(), "p10-h1-timeout-shell", [
          {
            cmd: "sed -i s/1/2/ app.mjs",
            effect: (r) => writeFileSync(join(r, "app.mjs"), "export const v = 2;\n"),
          },
        ]);
        assertGateBlocked(shellEdit.out);
      } finally {
        process.env.PATH = prevPath;
      }
    });
  });
});

describe("H2 strict verification whitelist for npx/pnpx/bunx, npm/pnpm/yarn/bun, and go", () => {
  it("rejects non-verification npx/pnpx/bunx, npm/pnpm/yarn inspection, and go run commands", () => {
    for (const cmd of [
      "npx true",
      "npx echo ok",
      "npx cowsay hi",
      "npx ts-node mutate.ts",
      "npx prettier --write .",
      "npx tsx mutate.ts",
      'npx -c "sed -i s/1/2/ app.mjs"',
      "npx -p evil vitest",
      "pnpx true",
      "bunx echo hi",
      "npm ls",
      "npm list",
      "npm view hstack",
      "npm info hstack",
      "npm whoami",
      "npm version",
      "npm version patch",
      "npm help",
      "pnpm ls",
      "pnpm list",
      "yarn info hstack",
      "yarn list",
      "go run mutate.go",
      "go run ./cmd/mutate",
      "go generate ./...",
      "go env",
    ]) {
      assert.equal(classifyCommand(cmd), "other", cmd);
    }
  });

  it("continues accepting legitimate verification commands", () => {
    for (const cmd of [
      "npx vitest run",
      "npx jest",
      "npx mocha",
      "npx ava",
      "npx tap",
      "npx playwright test",
      "npx cypress run",
      "npx tsc --noEmit",
      "npx eslint src",
      "npx oxlint",
      "npx biome check .",
      "npx prettier --check .",
      "npx tsx --test",
      "npx tsx test/a.test.ts",
      "pnpx vitest run",
      "bunx vitest run",
      "npm test",
      "npm t",
      "npm run test",
      "npm run lint",
      "pnpm test",
      "pnpm run lint",
      "yarn test",
      "bun test",
      "go test ./...",
      "go vet ./...",
      "go build ./...",
    ]) {
      assert.equal(classifyCommand(cmd), "verification", cmd);
    }
  });

  it("refuses npx true, npm ls, and go run mutate.go as verification and never clears prior test failures", () => {
    const dir = createTempDir("hstack-p10-h2-");
    let seq = 0;
    const runGateWithCmds = (cmds, claimCmd) => {
      const recs = [
        { step_index: 0, type: "USER_INPUT", content: "수정해 줘" },
        { step_index: 1, type: "PLANNER_RESPONSE", tool_calls: [{ name: "write_file", args: { Path: "/repo/app.mjs" } }] },
        { step_index: 2, type: "GENERIC", status: "DONE", content: "ok" },
      ];
      let step = 3;
      for (const [cmd, out] of cmds) {
        recs.push({ step_index: step++, type: "PLANNER_RESPONSE", tool_calls: [{ name: "run_command", args: { CommandLine: cmd } }] });
        recs.push({ step_index: step++, type: "GENERIC", status: "DONE", content: out });
      }
      const p = join(dir, `t-${seq++}.jsonl`);
      writeFileSync(p, toJsonl(recs));
      return decideGate(
        {
          modified_files: ["app.mjs"],
          inspected_files: [],
          verification_runs: [{ command: claimCmd, outcome: "pass" }],
          unverified_scope: [],
          self_assessment: "확인했습니다.",
        },
        {
          cwd: "/repo",
          ledger: readFactLedger(p, "/repo", "/repo"),
          gitLedger: { gitAvailable: false, gitRoot: "/repo", gitDirtyFiles: new Set() },
          testInfra: { hasTestSuite: true },
          auditEscalation: "off",
        },
      );
    };

    for (const fake of ["npx true", "npm ls", "go run mutate.go"]) {
      const onlyFake = runGateWithCmds([[fake, "ok"]], fake);
      assert.equal(onlyFake.verdict, "REJECT", `${fake} alone must not pass`);
      assert.ok(onlyFake.blockedRules.includes("R2_STALE_VERIFICATION"), `${fake}: ${onlyFake.blockedRules}`);

      const afterFailure = runGateWithCmds([["node --test", FAIL_OUTPUT], [fake, "ok"]], fake);
      assert.equal(afterFailure.verdict, "REJECT", `${fake} must not clear prior failure`);
      assert.ok(afterFailure.blockedRules.includes("R3_CONCEALED_FAILURE"), `${fake}: ${afterFailure.blockedRules}`);
    }

    for (const [real, out] of [
      ["npx vitest run", "Tests  1 passed (1)"],
      ["npm test", PASS_OUTPUT],
      ["go test ./...", "ok  \trepo\t0.01s"],
    ]) {
      const resolved = runGateWithCmds([[real, FAIL_OUTPUT], [real, out]], real);
      assert.equal(resolved.verdict, "PASS", `${real} should pass: ${resolved.blockedRules}`);
    }
  });
});

describe("H3 sequential pipefail state tracking", () => {
  it("rejects piped commands when pipefail is turned off before the pipe", () => {
    for (const cmd of [
      "set +o pipefail && npm test | head -3",
      "set -o pipefail && set +o pipefail && npm test | head -3",
      "set -o pipefail +o pipefail && npm test | head -3",
      "bash -o pipefail +o pipefail -c 'npm test | head -3'",
    ]) {
      assert.equal(classifyCommand(cmd), "other", cmd);
    }
  });

  it("accepts piped commands when pipefail stays enabled at the pipe", () => {
    for (const cmd of [
      "set -o pipefail && npm test | head -3",
      "set +o pipefail && set -o pipefail && npm test | head -3",
      "set -euo pipefail && npm test 2>&1 | tail -20",
    ]) {
      assert.equal(classifyCommand(cmd), "verification", cmd);
    }
  });

  it("enforces sequential pipefail state inside decideGate", () => {
    const dir = createTempDir("hstack-p10-h3-");
    let seq = 0;
    const runPipeGate = (cmd) => {
      const p = join(dir, `p-${seq++}.jsonl`);
      writeFileSync(
        p,
        toJsonl([
          { step_index: 0, type: "USER_INPUT", content: "수정해 줘" },
          { step_index: 1, type: "PLANNER_RESPONSE", tool_calls: [{ name: "write_file", args: { Path: "/repo/app.mjs" } }] },
          { step_index: 2, type: "GENERIC", status: "DONE", content: "ok" },
          { step_index: 3, type: "PLANNER_RESPONSE", tool_calls: [{ name: "run_command", args: { CommandLine: cmd } }] },
          { step_index: 4, type: "GENERIC", status: "DONE", content: PASS_OUTPUT },
        ]),
      );
      return decideGate(
        {
          modified_files: ["app.mjs"],
          inspected_files: [],
          verification_runs: [{ command: cmd, outcome: "pass" }],
          unverified_scope: [],
          self_assessment: "확인했습니다.",
        },
        {
          cwd: "/repo",
          ledger: readFactLedger(p, "/repo", "/repo"),
          gitLedger: { gitAvailable: false, gitRoot: "/repo", gitDirtyFiles: new Set() },
          testInfra: { hasTestSuite: true },
          auditEscalation: "off",
        },
      );
    };

    for (const bad of [
      "set +o pipefail && npm test | head -3",
      "set -o pipefail && set +o pipefail && npm test | head -3",
    ]) {
      const res = runPipeGate(bad);
      assert.equal(res.verdict, "REJECT", bad);
      assert.ok(res.blockedRules.includes("R2_STALE_VERIFICATION"), `${bad}: ${res.blockedRules}`);
    }

    const good = runPipeGate("set -o pipefail && npm test | head -3");
    assert.equal(good.verdict, "PASS", good.blockedRules.join(","));
  });
});
