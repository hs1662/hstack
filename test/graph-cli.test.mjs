import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, it } from "node:test";

import { EXIT_CODES, runCli } from "../scripts/graph/cli.mjs";
import { PLUGIN_ROOT, createTempDir } from "./helpers.mjs";

const CLI = join(PLUGIN_ROOT, "scripts", "graph", "cli.mjs");
const CLEAN_ENV = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
  !["PLUGIN_DATA", "PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA", "CLAUDE_PLUGIN_ROOT", "HSTACK_DATA_DIR", "HSTACK_HOST"].includes(key)));

function gitRepo() {
  const dir = createTempDir("hstack-graph-cli-");
  const init = spawnSync("git", ["init", "-q", dir], { encoding: "utf8" });
  assert.equal(init.status, 0, init.stderr);
  return dir;
}

// Runs the CLI in-process with a recording engine; returns the parsed JSON envelope and every dispatch call.
async function run(argv, { cwd, env = CLEAN_ENV, dispatch } = {}) {
  const calls = [];
  let written = "";
  const exitCode = await runCli(argv, {
    cwd,
    env,
    stdout: { write: (chunk) => { written += chunk; } },
    dispatch: async (command, options) => {
      calls.push({ command, options });
      return dispatch ? dispatch(command, options) : { echoed: command };
    },
  });
  const lines = written.split("\n").filter(Boolean);
  assert.equal(lines.length, 1, `expected exactly one JSON line, got ${JSON.stringify(written)}`);
  return { exitCode, out: JSON.parse(lines[0]), calls };
}

function runProcess(args, { cwd, env = CLEAN_ENV, timeout } = {}) {
  const result = spawnSync(process.execPath, [CLI, ...args], { cwd, env, encoding: "utf8", timeout });
  assert.equal(result.error?.code, undefined, `CLI did not finish: ${result.error?.code}`);
  const lines = result.stdout.split("\n").filter(Boolean);
  assert.equal(lines.length, 1, `stdout must be one JSON line: ${result.stdout} / ${result.stderr}`);
  return { status: result.status, out: JSON.parse(lines[0]) };
}

function treeDigest(dir) {
  const hash = createHash("sha256");
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const path = join(current, name);
      const stat = statSync(path);
      hash.update(`${relative(dir, path)}\0${stat.isDirectory() ? "d" : stat.size}\0`);
      if (stat.isDirectory()) walk(path);
      else hash.update(readFileSync(path));
    }
  };
  walk(dir);
  return hash.digest("hex");
}

describe("graph CLI argument surface", () => {
  it("maps every common flag to camelCase dispatch options and reads payload files by content", async () => {
    const repo = gitRepo();
    const root = join(createTempDir("hstack-graph-root-"), "graph");
    const spec = { schemaVersion: 1, nodes: [] };
    writeFileSync(join(repo, "spec.json"), JSON.stringify(spec));
    writeFileSync(join(repo, "patch.json"), JSON.stringify({ add: [] }));
    writeFileSync(join(repo, "receipt.json"), JSON.stringify({ outcome: "ok" }));

    const { exitCode, out, calls } = await run([
      "amend", "--root", root, "--workspace", repo, "--run", "r1", "--spec", "spec.json", "--patch=patch.json",
      "--receipt", "receipt.json", "--node", "a", "--expected-rev", "7", "--op-id", "op-1", "--outcome", "succeeded",
      "--token", "tok", "--host-handle", "h1", "--as-of", "2026-11-27T00:00:00Z", "--cursor", "c2",
    ], { cwd: repo });

    assert.equal(exitCode, 0);
    assert.deepEqual(out, { ok: true, command: "amend", result: { echoed: "amend" } });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].command, "amend");
    assert.deepEqual(calls[0].options, {
      root, workspace: repo, run: "r1", spec, patch: { add: [] }, receipt: { outcome: "ok" }, node: "a",
      expectedRev: 7, opId: "op-1", outcome: "succeeded", token: "tok", hostHandle: "h1",
      asOf: "2026-11-27T00:00:00Z", cursor: "c2",
    });
  });

  it("dispatches revalidate as its own command with only the run, node, revision and op", async () => {
    const repo = gitRepo();
    const { exitCode, calls } = await run(["revalidate", "--run", "r", "--node", "a", "--expected-rev", "3", "--op-id", "rv"], { cwd: repo });
    assert.equal(exitCode, 0);
    assert.equal(calls[0].command, "revalidate");
    const { root, workspace, ...rest } = calls[0].options;
    assert.deepEqual(rest, { run: "r", node: "a", expectedRev: 3, opId: "rv" });
  });

  it("passes the token through verbatim so start and settle need no --run", async () => {
    const repo = gitRepo();
    const root = join(repo, "custom-root");
    for (const command of ["start", "settle"]) {
      const { exitCode, calls } = await run([command, "--root", root, "--token", "../../etc/passwd", "--op-id", "x"], { cwd: repo });
      assert.equal(exitCode, 0);
      assert.equal(calls[0].options.token, "../../etc/passwd");
      assert.equal("run" in calls[0].options, false);
    }
  });

  for (const [label, argv, code] of [
    ["unknown flags", ["ready", "--run", "r", "--bogus", "1"], "ERR_CLI_UNKNOWN_FLAG"],
    ["prototype-named flags", ["ready", "--__proto__", "x"], "ERR_CLI_UNKNOWN_FLAG"],
    ["missing flag values", ["ready", "--run"], "ERR_CLI_FLAG_VALUE"],
    ["flag-looking values", ["ready", "--run", "--node"], "ERR_CLI_FLAG_VALUE"],
    ["empty values", ["ready", "--run="], "ERR_CLI_FLAG_VALUE"],
    ["duplicate flags", ["ready", "--run", "a", "--run", "b"], "ERR_CLI_FLAG_VALUE"],
    ["non-integer revisions", ["claim", "--expected-rev", "1.5"], "ERR_CLI_FLAG_VALUE"],
    ["padded revisions", ["claim", "--expected-rev", "07"], "ERR_CLI_FLAG_VALUE"],
    ["unsafe revisions", ["claim", "--expected-rev", "9007199254740993"], "ERR_CLI_FLAG_VALUE"],
    ["stray positionals", ["ready", "extra"], "ERR_CLI_USAGE"],
    ["patches without --expected-rev", ["expand", "--node", "b", "--op-id", "x", "--patch", "p.json"], "ERR_CLI_MISSING_FLAG"],
    ["amend without --patch", ["amend", "--node", "b", "--op-id", "x", "--expected-rev", "1"], "ERR_CLI_MISSING_FLAG"],
    ["repair without --node", ["inject-repair", "--op-id", "x", "--expected-rev", "1"], "ERR_CLI_MISSING_FLAG"],
    ["revalidate without --expected-rev", ["revalidate", "--run", "r", "--node", "a", "--op-id", "x"], "ERR_CLI_MISSING_FLAG"],
    ["caller-supplied local keys", ["revalidate", "--run", "r", "--node", "a", "--expected-rev", "1", "--op-id", "x", "--local-key", "k"], "ERR_CLI_UNKNOWN_FLAG"],
    ["missing commands", [], "ERR_CLI_USAGE"],
    ["unknown commands", ["launch"], "ERR_CLI_UNKNOWN_COMMAND"],
    ["inherited command names", ["constructor"], "ERR_CLI_UNKNOWN_COMMAND"],
  ]) {
    it(`rejects ${label} with a JSON failure before dispatch`, async () => {
      const repo = gitRepo();
      const { exitCode, out, calls } = await run(argv, { cwd: repo });
      assert.equal(out.ok, false);
      assert.equal(out.error.code, code);
      assert.equal(exitCode, EXIT_CODES.usage);
      assert.equal(calls.length, 0);
    });
  }

  it("rejects unreadable and non-object payload files without dispatching", async () => {
    const repo = gitRepo();
    writeFileSync(join(repo, "bad.json"), "{nope");
    writeFileSync(join(repo, "array.json"), "[]");
    for (const [file, code] of [["missing.json", "ERR_CLI_INPUT_FILE"], ["bad.json", "ERR_CLI_INPUT_JSON"], ["array.json", "ERR_CLI_INPUT_JSON"]]) {
      const { exitCode, out, calls } = await run(["init", "--spec", file], { cwd: repo });
      assert.equal(out.error.code, code);
      assert.equal(exitCode, EXIT_CODES.input);
      assert.equal(calls.length, 0);
    }
  });

  it("carries settle --gate-log as host evidence separate from the worker receipt", async () => {
    const repo = gitRepo();
    const gate = { argv: ["npm", "test"], exitCode: 0, factDigest: "f".repeat(64) };
    const worker = { gateEvidence: { passed: true } };
    writeFileSync(join(repo, "gate.json"), JSON.stringify(gate));
    writeFileSync(join(repo, "worker.json"), JSON.stringify(worker));
    const { exitCode, calls } = await run(["settle", "--token", "t", "--outcome", "accepted", "--receipt", "worker.json",
      "--gate-log", "gate.json", "--op-id", "s1"], { cwd: repo });
    assert.equal(exitCode, 0);
    assert.deepEqual(calls[0].options.gateLog, gate);
    assert.deepEqual(calls[0].options.receipt, worker);

    const elsewhere = await run(["claim", "--gate-log", "gate.json"], { cwd: repo });
    assert.equal(elsewhere.out.error.code, "ERR_CLI_UNKNOWN_FLAG");
    assert.equal(elsewhere.calls.length, 0);
    writeFileSync(join(repo, "list.json"), "[0]");
    const malformed = await run(["settle", "--token", "t", "--gate-log", "list.json"], { cwd: repo });
    assert.equal(malformed.out.error.code, "ERR_CLI_INPUT_JSON");
    assert.equal(malformed.calls.length, 0);
  });

  it("reads payloads only from bounded regular files, never blocking on a FIFO or following a link", async () => {
    const repo = gitRepo();
    assert.equal(spawnSync("mkfifo", [join(repo, "spec.fifo")]).status, 0);
    const fifo = runProcess(["compile", "--run", "r", "--spec", "spec.fifo"], { cwd: repo, timeout: 20_000 });
    assert.equal(fifo.out.error.code, "ERR_CLI_INPUT_FILE");
    assert.equal(fifo.status, EXIT_CODES.input);

    writeFileSync(join(repo, "real.json"), "{}");
    symlinkSync(join(repo, "real.json"), join(repo, "link.json"));
    const linked = await run(["compile", "--spec", "link.json"], { cwd: repo });
    assert.equal(linked.out.error.code, "ERR_CLI_INPUT_FILE");
    assert.equal(linked.calls.length, 0);

    const wide = { schemaVersion: 1, nodes: [], note: "x".repeat(64 * 1024) };
    writeFileSync(join(repo, "wide.json"), JSON.stringify(wide));
    const minified = await run(["compile", "--spec", "wide.json"], { cwd: repo });
    assert.equal(minified.exitCode, 0, JSON.stringify(minified.out));
    assert.deepEqual(minified.calls[0].options.spec, wide);
  });

  it("refuses integrate with the v2 code and never dispatches it", async () => {
    const repo = gitRepo();
    const { exitCode, out, calls } = await run(["integrate", "--run", "r"], { cwd: repo });
    assert.equal(out.error.code, "ERR_V2_WRITE_INTEGRATION_NOT_ENABLED");
    assert.equal(exitCode, EXIT_CODES.unavailable);
    assert.equal(calls.length, 0);
  });
});

describe("graph CLI error mapping", () => {
  for (const [code, exit] of [
    ["ERR_GRAPH_STALE_REV", 49],
    ["ERR_STALE_EPOCH", 49],
    ["ERR_GRAPH_CYCLE", EXIT_CODES.engine],
    ["ERR_V2_WRITE_INTEGRATION_NOT_ENABLED", EXIT_CODES.unavailable],
  ]) {
    it(`maps ${code} to exit ${exit} with the code in the envelope`, async () => {
      const repo = gitRepo();
      const { exitCode, out } = await run(["claim", "--run", "r", "--node", "a", "--expected-rev", "1"], {
        cwd: repo,
        dispatch: () => { throw Object.assign(new Error("boom"), { code }); },
      });
      assert.equal(exitCode, exit);
      assert.deepEqual(out, { ok: false, command: "claim", error: { code, message: "boom" } });
    });
  }

  it("reports uncoded engine faults as internal, never as success", async () => {
    const repo = gitRepo();
    const { exitCode, out } = await run(["status", "--run", "r"], { cwd: repo, dispatch: () => { throw new TypeError("x is undefined"); } });
    assert.equal(exitCode, EXIT_CODES.internal);
    assert.equal(out.error.code, "ERR_INTERNAL");
  });
});

describe("graph CLI root and workspace resolution", () => {
  it("defaults the workspace to the git root and the root to repo .hstack/graph", async () => {
    const repo = gitRepo();
    const sub = join(repo, "pkg", "deep");
    mkdirSync(sub, { recursive: true });
    const { exitCode, calls } = await run(["ready", "--run", "r"], { cwd: sub });
    assert.equal(exitCode, 0);
    assert.equal(calls[0].options.workspace, repo);
    assert.equal(calls[0].options.root, join(repo, ".hstack", "graph"));
  });

  it("init creates the fallback root through fs-guard and keeps it out of git status, idempotently", async () => {
    const repo = gitRepo();
    const sub = join(repo, "pkg");
    mkdirSync(sub);
    const status = spawnSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: repo, encoding: "utf8" }).stdout;
    const first = await run(["init"], { cwd: sub });
    assert.equal(first.exitCode, 0, JSON.stringify(first.out));
    assert.equal(first.out.result.root, join(repo, ".hstack", "graph"));
    assert.equal(first.calls.length, 0);
    await run(["init"], { cwd: sub });
    const exclude = readFileSync(join(repo, ".git", "info", "exclude"), "utf8");
    assert.equal(exclude.match(/^\/\.hstack\/graph\/$/gm).length, 1);
    writeFileSync(join(repo, ".hstack", "graph", "x"), "1");
    const after = spawnSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: repo, encoding: "utf8" }).stdout;
    assert.equal(after, status);
  });

  it("gc runs collectGarbage on the resolved root", () => {
    const repo = gitRepo();
    const root = join(createTempDir("hstack-graph-gc-"), "graph");
    assert.equal(runProcess(["init", "--root", root, "--workspace", repo], { cwd: repo }).status, 0);
    const gc = runProcess(["gc", "--root", root, "--workspace", repo], { cwd: repo });
    assert.equal(gc.status, 0, JSON.stringify(gc.out));
    assert.equal(gc.out.ok, true);
  });

  for (const [label, redirect] of [
    ["a symlinked .hstack", (repo, outside) => symlinkSync(outside, join(repo, ".hstack"))],
    ["a symlinked .hstack/graph", (repo, outside) => { mkdirSync(join(repo, ".hstack")); symlinkSync(outside, join(repo, ".hstack", "graph")); }],
  ]) {
    it(`fails closed on ${label} fallback for init and reads alike`, async () => {
      const repo = gitRepo();
      const outside = createTempDir("hstack-graph-outside-");
      redirect(repo, outside);
      for (const argv of [["init"], ["ready", "--run", "r"]]) {
        const { exitCode, out, calls } = await run(argv, { cwd: repo });
        assert.equal(out.error.code, "ERR_CLI_PATH", JSON.stringify(out));
        assert.equal(exitCode, EXIT_CODES.input);
        assert.equal(calls.length, 0);
      }
      assert.deepEqual(readdirSync(outside), []);
      assert.doesNotMatch(readFileSync(join(repo, ".git", "info", "exclude"), "utf8"), /hstack/);
    });
  }

  it("does not touch the exclude file for read commands or an explicit root", async () => {
    const repo = gitRepo();
    const before = readFileSync(join(repo, ".git", "info", "exclude"), "utf8");
    await run(["ready", "--run", "r"], { cwd: repo });
    await run(["init", "--root", join(createTempDir("hstack-graph-root-"), "g")], { cwd: repo });
    assert.equal(readFileSync(join(repo, ".git", "info", "exclude"), "utf8"), before);
  });

  it("uses existing host data, keyed per workspace, before the repo fallback", async () => {
    const repo = gitRepo();
    const data = createTempDir("hstack-graph-data-");
    const { calls } = await run(["status", "--run", "r"], { cwd: repo, env: { ...CLEAN_ENV, HSTACK_DATA_DIR: data } });
    const root = calls[0].options.root;
    assert.equal(root.startsWith(join(data, "graph") + "/"), true, root);
    const other = gitRepo();
    const { calls: otherCalls } = await run(["status", "--run", "r"], { cwd: other, env: { ...CLEAN_ENV, HSTACK_DATA_DIR: data } });
    assert.notEqual(otherCalls[0].options.root, root);

    const { calls: missing } = await run(["status", "--run", "r"], { cwd: repo, env: { ...CLEAN_ENV, HSTACK_DATA_DIR: join(data, "absent") } });
    assert.equal(missing[0].options.root, join(repo, ".hstack", "graph"));
  });

  for (const [label, setup] of [
    ["a missing workspace", (repo) => ["--workspace", join(repo, "nope")]],
    ["a file workspace", (repo) => { writeFileSync(join(repo, "f"), ""); return ["--workspace", join(repo, "f")]; }],
    ["a root equal to the workspace", (repo) => ["--root", repo]],
    ["a root containing the workspace", (repo) => ["--root", join(repo, "..")]],
    ["a file root", (repo) => { writeFileSync(join(repo, "r"), ""); return ["--root", join(repo, "r")]; }],
  ]) {
    it(`rejects ${label}`, async () => {
      const repo = gitRepo();
      const { exitCode, out, calls } = await run(["init", ...setup(repo)], { cwd: repo });
      assert.equal(out.error.code, "ERR_CLI_PATH");
      assert.equal(exitCode, EXIT_CODES.input);
      assert.equal(calls.length, 0);
    });
  }
});

describe("graph CLI subprocess", () => {
  it("prints one JSON failure line and a usage exit for malformed flags", () => {
    const repo = gitRepo();
    const { status, out } = runProcess(["ready", "--nope"], { cwd: repo });
    assert.equal(status, EXIT_CODES.usage);
    assert.equal(out.error.code, "ERR_CLI_UNKNOWN_FLAG");
  });

  it("refuses integrate as a real process", () => {
    const repo = gitRepo();
    const { status, out } = runProcess(["integrate"], { cwd: repo });
    assert.equal(status, EXIT_CODES.unavailable);
    assert.equal(out.error.code, "ERR_V2_WRITE_INTEGRATION_NOT_ENABLED");
  });

  it("reports host capabilities as hints without touching the workspace", () => {
    const repo = gitRepo();
    const { status, out } = runProcess(["host-caps"], { cwd: repo, env: { ...CLEAN_ENV, HSTACK_HOST: "claude-code" } });
    assert.equal(status, 0);
    assert.equal(out.result.host, "claude-code");
    assert.equal(out.result.hintOnly, true);
    assert.equal(existsSync(join(repo, ".hstack")), false);
  });
});

const nodeSpec = (id, fields = {}) => ({
  id, kind: "read", dependsOn: [], readScope: [], writeScope: [],
  estimatedMinutes: 5, priority: 0, prompt: `Investigate ${id}`, skills: [], rules: [], ...fields,
});

// What a read worker hands back: provenance over a real workspace file, with its own fact digest.
async function workerReceipt(extra = {}) {
  const { factDigest } = await import("../scripts/graph/reducer.mjs");
  const provenance = { evidenceSpans: [{ spanId: "s", path: "source", startLine: 1, endLine: 1 }],
    claims: [{ claimId: "c", spanIds: ["s"], text: "a fact" }], edgeCases: [], failureEvidence: [] };
  provenance.factDigest = factDigest(provenance);
  return { schemaVersion: 1, workerReportedStatus: "completed", provenance, inlineSummary: "a fact", ...extra };
}

// Trusted host gate command recorded in graph policy at compile time.
const PASSING_GATE = [process.execPath, "-e", "process.exitCode=0"];
const gated = (id, fields = {}) => nodeSpec(id, { gateArgv: PASSING_GATE, ...fields });

// init + compile through the public CLI; returns a runner that prefixes --root/--workspace/--run.
function compiledRun(nodes, runId = "host") {
  const repo = gitRepo();
  const root = join(createTempDir("hstack-graph-run-"), "graph");
  const base = ["--root", root, "--workspace", repo];
  writeFileSync(join(repo, "source"), "evidence\n");
  writeFileSync(join(repo, "spec.json"), JSON.stringify({ schemaVersion: 1, nodes }));
  assert.equal(runProcess(["init", ...base], { cwd: repo }).status, 0);
  const cli = (args) => runProcess([args[0], ...base, "--run", runId, ...args.slice(1)], { cwd: repo });
  const compile = cli(["compile", "--spec", "spec.json", "--op-id", "compile"]);
  assert.equal(compile.status, 0, JSON.stringify(compile.out));
  const json = (name, value) => { writeFileSync(join(repo, name), JSON.stringify(value)); return name; };
  return { repo, root, runId, cli, json };
}

describe("graph CLI host evidence and metrics", () => {
  it("carries --telemetry and --probe as host data apart from the worker receipt, only on attempt commands", async () => {
    const repo = gitRepo();
    const telemetry = { usage: { inputTokens: 12, outputTokens: 3, costUsd: 0.25 }, canaryEvent: "suspect",
      budgetContext: { verified: true, W_eff: 8000, reservedTokens: 1000, actualUsage: { inputTokens: 12, outputTokens: 3 },
        contentTokens: { ["a".repeat(64)]: 40 } } };
    const probe = { sessionId: "session-1", probePassed: false, schemaError: true };
    writeFileSync(join(repo, "t.json"), JSON.stringify(telemetry));
    writeFileSync(join(repo, "p.json"), JSON.stringify(probe));
    writeFileSync(join(repo, "w.json"), JSON.stringify({ usage: { inputTokens: 1 } }));
    const { exitCode, calls } = await run(["settle", "--token", "t", "--outcome", "accepted", "--receipt", "w.json",
      "--telemetry", "t.json", "--probe", "p.json", "--op-id", "s"], { cwd: repo });
    assert.equal(exitCode, 0);
    assert.deepEqual([calls[0].options.telemetry, calls[0].options.probe, calls[0].options.receipt],
      [telemetry, probe, { usage: { inputTokens: 1 } }]);
    for (const command of ["claim", "start"]) {
      assert.equal((await run([command, "--telemetry", "t.json"], { cwd: repo })).exitCode, 0);
    }
    for (const argv of [["compile", "--telemetry", "t.json"], ["ready", "--probe", "p.json"]]) {
      const rejected = await run(argv, { cwd: repo });
      assert.equal(rejected.out.error.code, "ERR_CLI_UNKNOWN_FLAG");
      assert.equal(rejected.calls.length, 0);
    }
  });

  const telemetryOf = (patch) => ({ usage: { inputTokens: 1 }, ...patch });
  for (const [label, flag, value] of [
    ["negative token usage", "--telemetry", telemetryOf({ usage: { inputTokens: -1 } })],
    ["fractional token usage", "--telemetry", telemetryOf({ usage: { outputTokens: 1.5 } })],
    ["non-finite cost", "--telemetry", { usage: { costUsd: "0.1" } }],
    ["worker-style usage keys", "--telemetry", { usage: { tokens: 5 } }],
    ["unknown telemetry keys", "--telemetry", telemetryOf({ receiptUsage: { inputTokens: 1 } })],
    ["unknown canary events", "--telemetry", telemetryOf({ canaryEvent: "handoff" })],
    ["unverified-looking budget flags", "--telemetry", { budgetContext: { verified: "yes" } }],
    ["unsafe budget windows", "--telemetry", { budgetContext: { W_eff: 2 ** 53 } }],
    ["content token keys that are not digests", "--telemetry", { budgetContext: { contentTokens: { summary: 4 } } }],
    ["unknown budget keys", "--telemetry", { budgetContext: { perIssueTokens: 512 } }],
    ["probes without a session", "--probe", { probePassed: true, schemaError: false }],
    ["stringly probe results", "--probe", { sessionId: "s", probePassed: "true", schemaError: false }],
    ["unknown probe keys", "--probe", { sessionId: "s", probePassed: true, schemaError: false, passed: true }],
  ]) {
    it(`rejects ${label} in host data before dispatch`, async () => {
      const repo = gitRepo();
      writeFileSync(join(repo, "host.json"), JSON.stringify(value));
      const { exitCode, out, calls } = await run(["settle", "--token", "t", flag, "host.json"], { cwd: repo });
      assert.equal(out.error?.code, "ERR_CLI_HOST_DATA", JSON.stringify(out));
      assert.equal(exitCode, EXIT_CODES.input);
      assert.equal(calls.length, 0);
    });
  }

  it("reports metrics read-only from the journal", () => {
    const { repo, root, cli } = compiledRun([nodeSpec("a"), nodeSpec("b", { dependsOn: ["a"] })]);
    const before = treeDigest(root);
    const first = cli(["metrics"]);
    assert.equal(first.status, 0, JSON.stringify(first.out));
    assert.ok(Object.hasOwn(first.out.result, "canaryStats"));
    assert.deepEqual(cli(["metrics"]).out, first.out);
    assert.equal(treeDigest(root), before, "metrics must not write");
    const missing = runProcess(["metrics", "--root", root, "--run", "nope"], { cwd: repo });
    assert.equal(missing.out.error.code, "ERR_RUN_NOT_FOUND");
    assert.equal(missing.status, EXIT_CODES.engine);
  });

  it("pairs metrics with the baseline run named in the run's telemetry, from the same root", async () => {
    const repo = gitRepo();
    const root = join(createTempDir("hstack-graph-base-"), "graph");
    assert.equal(runProcess(["init", "--root", root, "--workspace", repo], { cwd: repo }).status, 0);
    const { transaction } = await import("../scripts/graph/wal-store.mjs");
    const seed = (runId, baseline) => transaction(root, runId, { opId: "seed", type: "GraphCompiled", payload: {} }, async () => ({
      state: { schemaVersion: 1, runId, graphRev: 1, status: "open", nodes: {}, joinMembers: {}, logicalOutputMap: {},
        attemptsIssued: 0, telemetry: { attempts: [], ready: {}, canary: {}, baseline } },
      response: { runId },
    }));
    await seed("dag", { pairId: "p", mode: "dag", baselineRunId: "single" });
    await seed("single", { pairId: "p", mode: "single-layer" });
    await seed("orphan", { pairId: "p", mode: "dag", baselineRunId: "absent" });
    const paired = runProcess(["metrics", "--root", root, "--workspace", repo, "--run", "dag"], { cwd: repo });
    assert.equal(paired.status, 0, JSON.stringify(paired.out));
    assert.equal(paired.out.result.baselineComparison.paired, true);
    assert.notEqual(paired.out.result.baselineComparison.baseline, null);
    const orphan = runProcess(["metrics", "--root", root, "--workspace", repo, "--run", "orphan"], { cwd: repo });
    assert.equal(orphan.status, 0, JSON.stringify(orphan.out));
    assert.deepEqual([orphan.out.result.baselineComparison.paired, orphan.out.result.baselineComparison.baseline], [false, null]);
  });

  it("gate runs the policy argv, never the worker's, and records the measurement with checked spans", async () => {
    const policyArgv = [process.execPath, "-e", "process.stdout.write('x');process.exitCode=3"];
    const { repo, root, cli, json } = compiledRun([nodeSpec("a", { gateArgv: policyArgv })]);
    const receipt = await workerReceipt({ gateArgv: ["/bin/true"], gateEvidence: { passed: true } });
    const before = treeDigest(root);
    const gate = cli(["gate", "--node", "a", "--receipt", json("r.json", receipt), "--out", "gate.json"]);
    assert.equal(gate.status, 0, JSON.stringify(gate.out));
    const log = JSON.parse(readFileSync(join(repo, "gate.json"), "utf8"));
    assert.deepEqual(gate.out.result, log);
    assert.deepEqual(log.argv, policyArgv);
    assert.deepEqual([log.exit, log.exitCode, log.signal, log.timedOut], [3, 3, null, false]);
    assert.equal(log.subjectDigest, receipt.provenance.factDigest);
    assert.equal(log.factDigest, receipt.provenance.factDigest);
    assert.deepEqual(log.checkedSpans, receipt.provenance.evidenceSpans);
    assert.match(log.envDigest, /^[a-f0-9]{64}$/);
    assert.equal(log.stdoutDigest, createHash("sha256").update("x").digest("hex"));
    assert.deepEqual([log.runId, log.nodeId], ["host", "a"]);
    assert.equal(treeDigest(root), before, "gate must not write engine state");

    const again = cli(["gate", "--node", "a", "--receipt", "r.json", "--out", "gate.json"]);
    assert.equal(again.out.error.code, "ERR_CLI_PATH");
    assert.deepEqual(JSON.parse(readFileSync(join(repo, "gate.json"), "utf8")), log, "an existing log is never overwritten");
  });

  it("gate fails closed without a trusted policy command or a fact digest", async () => {
    const { repo, cli, json } = compiledRun([nodeSpec("plain"), gated("g")]);
    const receipt = json("r.json", await workerReceipt({ gateArgv: ["/bin/true"] }));
    const none = cli(["gate", "--node", "plain", "--receipt", receipt, "--out", "none.json"]);
    assert.equal(none.out.error.code, "ERR_GATE_POLICY");
    assert.equal(existsSync(join(repo, "none.json")), false);
    const undigested = cli(["gate", "--node", "g", "--receipt", json("u.json", { provenance: {} }), "--out", "u-gate.json"]);
    assert.equal(undigested.out.error.code, "ERR_GATE_POLICY");
    assert.equal(existsSync(join(repo, "u-gate.json")), false);
    const unknown = cli(["gate", "--node", "ghost", "--receipt", receipt, "--out", "ghost.json"]);
    assert.equal(unknown.out.error.code, "ERR_GRAPH_SCHEMA");
    const incomplete = await run(["gate", "--node", "g", "--receipt", receipt], { cwd: repo });
    assert.equal(incomplete.out.error.code, "ERR_CLI_MISSING_FLAG");
  });
});

// A policy gate that counts its own runs, so tests can see every spawn.
const countingGate = (counter, exitCode = 0) =>
  [process.execPath, "-e", `require("fs").appendFileSync(${JSON.stringify(counter)}, "x");process.exitCode=${exitCode}`];
const spawns = (counter) => (existsSync(counter) ? readFileSync(counter, "utf8").length : 0);

function startedAttempt(cli, node, tag) {
  const claim = cli(["claim", "--node", node, "--expected-rev", "1", "--op-id", `claim-${tag}`]);
  assert.equal(claim.status, 0, JSON.stringify(claim.out));
  const token = claim.out.result.instructionPath;
  assert.equal(cli(["start", "--token", token, "--host-handle", `h-${tag}`, "--op-id", `start-${tag}`]).status, 0);
  return token;
}

describe("graph CLI settle runs the trusted policy gate", () => {
  it("measures node.gateArgv once, ignores worker gate claims, and replays without respawning", async () => {
    const counter = join(createTempDir("hstack-graph-count-"), "spawns");
    const { cli, json } = compiledRun([nodeSpec("a", { gateArgv: countingGate(counter) })]);
    const token = startedAttempt(cli, "a", "a");
    const receipt = json("r.json", await workerReceipt({ gateArgv: ["/bin/false"], gateEvidence: { passed: true } }));
    const settle = ["settle", "--token", token, "--outcome", "accepted", "--receipt", receipt, "--op-id", "settle-a"];
    const first = cli(settle);
    assert.equal(first.status, 0, JSON.stringify(first.out));
    assert.equal(spawns(counter), 1);
    const replay = cli(settle);
    assert.deepEqual(replay.out, first.out, "identical replay returns the committed response");
    assert.equal(spawns(counter), 1, "identical replay never spawns another gate");
  });

  it("refuses a caller --gate-log on a policy-gated node without spawning or changing the attempt", async () => {
    const counter = join(createTempDir("hstack-graph-count-"), "spawns");
    const { cli, json } = compiledRun([nodeSpec("a", { gateArgv: countingGate(counter) })]);
    const token = startedAttempt(cli, "a", "a");
    const receipt = json("r.json", await workerReceipt());
    const forged = json("forged-gate.json", { argv: ["/bin/true"], exitCode: 0, factDigest: "0".repeat(64) });
    const refused = cli(["settle", "--token", token, "--outcome", "accepted", "--receipt", receipt, "--gate-log", forged, "--op-id", "s"]);
    assert.equal(refused.out.error.code, "ERR_GATE_POLICY");
    assert.equal(spawns(counter), 0);
    assert.equal(cli(["status"]).out.result.nodes.a.status, "running");
  });

  it("a failing policy gate is submitted as measured and never yields acceptance", async () => {
    const counter = join(createTempDir("hstack-graph-count-"), "spawns");
    const { cli, json } = compiledRun([nodeSpec("a", { gateArgv: countingGate(counter, 1) })]);
    const token = startedAttempt(cli, "a", "a");
    const settle = cli(["settle", "--token", token, "--outcome", "accepted", "--receipt", json("r.json", await workerReceipt()), "--op-id", "s"]);
    assert.equal(settle.status, 0, JSON.stringify(settle.out));
    assert.equal(spawns(counter), 1);
    assert.notEqual(cli(["status"]).out.result.nodes.a.status, "accepted");
  });

  it("never spawns for an attempt that is not running or for a non-accepting outcome", async () => {
    const counter = join(createTempDir("hstack-graph-count-"), "spawns");
    const { cli, json } = compiledRun([nodeSpec("a", { gateArgv: countingGate(counter) })]);
    const receipt = json("r.json", await workerReceipt());
    const claimed = cli(["claim", "--node", "a", "--expected-rev", "1", "--op-id", "claim-a"]).out.result.instructionPath;
    const early = cli(["settle", "--token", claimed, "--outcome", "accepted", "--receipt", receipt, "--op-id", "s-early"]);
    assert.equal(early.out.ok, false);
    assert.equal(cli(["start", "--token", claimed, "--host-handle", "h", "--op-id", "start-a"]).status, 0);
    assert.equal(cli(["settle", "--token", claimed, "--outcome", "blocked", "--receipt", receipt, "--op-id", "s-a"]).status, 0);
    assert.equal(spawns(counter), 0);
  });
});

describe("graph CLI against the real engine", () => {
  it("reaches accepted through the public CLI alone, with the policy gate", async () => {
    const repo = gitRepo();
    const root = join(createTempDir("hstack-graph-e2e-"), "graph");
    const runId = "e2e";
    writeFileSync(join(repo, "source"), "evidence\n");
    writeFileSync(join(repo, "spec.json"), JSON.stringify({ schemaVersion: 1, nodes: [gated("a"), gated("b"),
      nodeSpec("c", { gateArgv: [process.execPath, "-e", "process.exitCode=1"] })] }));
    const base = ["--root", root, "--workspace", repo];

    assert.equal(runProcess(["init", ...base], { cwd: repo }).status, 0);
    const compile = runProcess(["compile", ...base, "--run", runId, "--spec", "spec.json", "--op-id", "compile-1"], { cwd: repo });
    assert.equal(compile.status, 0, JSON.stringify(compile.out));
    const graphRev = 1;

    const before = treeDigest(root);
    const first = runProcess(["ready", ...base, "--run", runId], { cwd: repo });
    const second = runProcess(["ready", ...base, "--run", runId], { cwd: repo });
    assert.equal(first.status, 0, JSON.stringify(first.out));
    assert.deepEqual(second.out, first.out);
    assert.equal(treeDigest(root), before, "ready must not write");
    const cursor = first.out.result.nextCursor;
    if (cursor !== undefined && cursor !== null) {
      const page = runProcess(["ready", ...base, "--run", runId, "--cursor", String(cursor)], { cwd: repo });
      assert.equal(page.status, 0, JSON.stringify(page.out));
      assert.equal(treeDigest(root), before, "paged ready must not write");
    }

    const claim = runProcess(["claim", ...base, "--run", runId, "--node", "a", "--expected-rev", String(graphRev), "--op-id", "claim-a"], { cwd: repo });
    assert.equal(claim.status, 0, JSON.stringify(claim.out));
    const token = claim.out.result.instructionPath;
    assert.equal(typeof token, "string");
    assert.equal("nonce" in claim.out.result, false);

    const replay = runProcess(["claim", ...base, "--run", runId, "--node", "a", "--expected-rev", String(graphRev), "--op-id", "claim-a"], { cwd: repo });
    assert.deepEqual(replay.out, claim.out, "same opId and body must replay the stored response");

    const start = runProcess(["start", ...base, "--token", token, "--host-handle", "host-1", "--op-id", "start-a"], { cwd: repo });
    assert.equal(start.status, 0, JSON.stringify(start.out));
    const receipt = await workerReceipt();
    writeFileSync(join(repo, "receipt.json"), JSON.stringify(receipt));
    const settle = runProcess(["settle", ...base, "--token", token, "--outcome", "accepted", "--receipt", "receipt.json",
      "--op-id", "settle-a"], { cwd: repo });
    assert.equal(settle.status, 0, JSON.stringify(settle.out));

    // A worker that claims its own passing gate is not accepted when the policy gate actually fails.
    const forgedClaim = runProcess(["claim", ...base, "--run", runId, "--node", "c", "--expected-rev", String(graphRev), "--op-id", "claim-c"], { cwd: repo });
    const forgedToken = forgedClaim.out.result.instructionPath;
    runProcess(["start", ...base, "--token", forgedToken, "--host-handle", "host-2", "--op-id", "start-c"], { cwd: repo });
    writeFileSync(join(repo, "forged.json"), JSON.stringify(await workerReceipt({ gateEvidence: { passed: true, exitCode: 0 } })));
    runProcess(["settle", ...base, "--token", forgedToken, "--outcome", "accepted", "--receipt", "forged.json", "--op-id", "settle-c"], { cwd: repo });

    const status = runProcess(["status", ...base, "--run", runId], { cwd: repo });
    assert.equal(status.status, 0, JSON.stringify(status.out));
    const state = status.out.result;
    assert.equal(state.nodes.a.status, "accepted", JSON.stringify(state.nodes.a));
    assert.match(state.nodes.a.receiptUri, /^cas:\/\/sha256\/[a-f0-9]{64}$/);
    assert.notEqual(state.nodes.c.status, "accepted", JSON.stringify(state.nodes.c));

    const stale = runProcess(["claim", ...base, "--run", runId, "--node", "b", "--expected-rev", String(graphRev + 1), "--op-id", "claim-b-stale"], { cwd: repo });
    assert.equal(stale.out.ok, false);
    assert.equal(stale.status, 49, JSON.stringify(stale.out));
  });

  it("revalidates a gate-amended accepted node against its pinned artifact and expands into a closed join", async () => {
    const repo = gitRepo();
    const root = join(createTempDir("hstack-graph-patch-"), "graph");
    const runId = "patches";
    const base = ["--root", root, "--workspace", repo];
    const cli = (args) => runProcess([...args.slice(0, 1), ...base, "--run", runId, ...args.slice(1)], { cwd: repo });
    const json = (name, value) => { writeFileSync(join(repo, name), JSON.stringify(value)); return name; };
    writeFileSync(join(repo, "source"), "evidence\n");
    assert.equal(runProcess(["init", ...base], { cwd: repo }).status, 0);
    assert.equal(cli(["compile", "--spec", json("spec.json", { schemaVersion: 1, nodes: [gated("a"), gated("b")] }), "--op-id", "c"]).status, 0);

    const accept = async (node, rev, tag, receipt) => {
      const claim = cli(["claim", "--node", node, "--expected-rev", String(rev), "--op-id", `claim-${tag}`]);
      assert.equal(claim.status, 0, JSON.stringify(claim.out));
      const token = claim.out.result.instructionPath;
      assert.equal(cli(["start", "--token", token, "--host-handle", `h-${tag}`, "--op-id", `start-${tag}`]).status, 0);
      const settle = cli(["settle", "--token", token, "--outcome", "accepted", "--receipt", json(`r-${tag}.json`, receipt),
        "--op-id", `settle-${tag}`]);
      assert.equal(settle.status, 0, JSON.stringify(settle.out));
      return claim.out.result;
    };
    const receipt = await workerReceipt();
    await accept("a", 1, "a1", receipt);
    const accepted = cli(["status"]).out.result.nodes.a;
    assert.equal(accepted.status, "accepted");

    const amend = cli(["amend", "--node", "a", "--expected-rev", "1", "--op-id", "amend-a",
      "--patch", json("amend.json", { gate: { gateVersion: 2 }, reason: "stricter gate" })]);
    assert.equal(amend.status, 0, JSON.stringify(amend.out));
    const rev = amend.out.result.graphRev;
    const amended = cli(["status"]).out.result.nodes.a;
    assert.notEqual(amended.status, "accepted");
    assert.equal(amended.execKey, accepted.execKey);
    assert.equal(amended.revalidateReceiptUri, accepted.receiptUri);

    await accept("a", rev, "a2", receipt);
    const revalidated = cli(["status"]).out.result.nodes.a;
    assert.equal(revalidated.status, "accepted", JSON.stringify(revalidated));

    const expand = cli(["expand", "--node", "b", "--expected-rev", String(rev), "--op-id", "expand-b",
      "--patch", json("expand.json", { shards: [{ stableShardKey: "k1" }, { stableShardKey: "k2", obligationId: "o2" }] })]);
    assert.equal(expand.status, 0, JSON.stringify(expand.out));
    const state = cli(["status"]).out.result;
    assert.ok(Object.hasOwn(state.nodes, "b"), "the expanded source keeps its ID as the reducer");
    const members = state.joinMembers.b;
    assert.deepEqual(members.map((member) => member.obligationId), ["k1", "o2"]);
    for (const { shardId } of members) assert.ok(Object.hasOwn(state.nodes, shardId), shardId);

    const reopen = cli(["expand", "--node", "b", "--expected-rev", String(rev), "--op-id", "expand-b-again",
      "--patch", "expand.json"]);
    assert.equal(reopen.out.ok, false, "an old revision cannot reopen the closed membership");
    assert.deepEqual(cli(["status"]).out.result.joinMembers.b, members);
  });

  it("binds external --gate-log metadata to the current run, node, revision, and epoch", async () => {
    const { repo, cli, json } = compiledRun([gated("a"), nodeSpec("plain"), nodeSpec("other")]);
    const rPlain = await workerReceipt();
    const rPlainFile = json("r-plain.json", rPlain);
    const foreignGate = cli(["gate", "--node", "a", "--receipt", rPlainFile, "--out", "foreign-gate.json"]);
    assert.equal(foreignGate.status, 0, JSON.stringify(foreignGate.out));

    const tPlain = startedAttempt(cli, "plain", "plain");
    const wrongNode = cli(["settle", "--token", tPlain, "--outcome", "accepted", "--receipt", rPlainFile,
      "--gate-log", "foreign-gate.json", "--op-id", "settle-wrong-node"]);
    assert.equal(wrongNode.status, 0, JSON.stringify(wrongNode.out));
    assert.equal(wrongNode.out.result.status, "failed_logic");
    assert.equal(cli(["status"]).out.result.nodes.plain.attempt.failureClass, "ERR_FORGED_EVIDENCE");

    const baseLog = JSON.parse(readFileSync(join(repo, "foreign-gate.json"), "utf8"));
    for (const [tag, bad] of [
      ["run", { ...baseLog, runId: "other-run", nodeId: "other", graphRev: 1, epoch: 1 }],
      ["rev", { ...baseLog, runId: "host", nodeId: "other", graphRev: 2, epoch: 1 }],
      ["epoch", { ...baseLog, runId: "host", nodeId: "other", graphRev: 1, epoch: 99 }],
    ]) {
      const tok = startedAttempt(cli, "other", tag);
      const res = cli(["settle", "--token", tok, "--outcome", "accepted", "--receipt", rPlainFile,
        "--gate-log", json(`bad-${tag}.json`, bad), "--op-id", `s-${tag}`]);
      assert.equal(res.out.result.status, "failed_logic", tag);
    }

    const { repo: repo2, cli: cli2, json: json2 } = compiledRun([nodeSpec("ok")]);
    const tOk = startedAttempt(cli2, "ok", "ok");
    const rOkFile = json2("r-ok.json", rPlain);
    const { measureGate } = await import("../scripts/graph/verify-gate.mjs");
    const measured = await measureGate({ argv: PASSING_GATE, cwd: repo2, subjectDigest: rPlain.provenance.factDigest });
    const bound = { ...measured, runId: "host", nodeId: "ok", graphRev: 1, epoch: 1 };
    const accepted = cli2(["settle", "--token", tOk, "--outcome", "accepted", "--receipt", rOkFile,
      "--gate-log", json2("ok-gate.json", bound), "--op-id", "settle-ok"]);
    assert.equal(accepted.status, 0, JSON.stringify(accepted.out));
    assert.equal(accepted.out.result.status, "accepted");
  });
});
