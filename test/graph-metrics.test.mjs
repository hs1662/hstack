import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { saveHandoffSnapshot } from "../scripts/governance/handoff-store.mjs";
import { factDigest } from "../scripts/graph/reducer.mjs";
import { measureGate } from "../scripts/graph/verify-gate.mjs";

const api = () => import("../scripts/graph/metrics.mjs");
const node = (id, dependsOn = [], logicalId = id) => ({ id, logicalId, dependsOn });
const state = (runId, ...nodes) => ({ runId, nodes: Object.fromEntries(nodes.map(n => [n.id, n])) });

function claim(m, s, nodeId, atMs, epoch = 1) {
  s.nodes[nodeId].attempt = { epoch };
  m.captureClaim(s, { nodeId, atMs });
}

function finish(m, s, nodeId, startMs, verificationStartedAtMs, atMs, outcome, usage) {
  m.captureStart(s, { nodeId, atMs: startMs });
  m.captureFinish(s, { nodeId, atMs, verificationStartedAtMs, outcome, usage });
}

test("W counts accepted worker time; L retains rejected and superseded work on the longest causal path", async () => {
  const m = await api();
  const s = state("graph", node("draft"), node("parallel"), node("join", ["draft", "parallel"]));
  m.captureReady(s, { atMs: 0, nodeIds: ["draft", "parallel"] });
  claim(m, s, "draft", 2);
  claim(m, s, "parallel", 3);
  finish(m, s, "draft", 4, 9, 10, "superseded");
  m.captureReady(s, { atMs: 10, nodeIds: ["draft"] });
  claim(m, s, "draft", 12, 3);
  finish(m, s, "draft", 14, 23, 25, "rejected");
  finish(m, s, "parallel", 5, 28, 30, "accepted");

  delete s.nodes.draft;
  s.nodes.repair = node("repair", [], "draft");
  s.nodes.join.dependsOn = ["repair", "parallel"];
  m.captureReady(s, { atMs: 25, nodeIds: ["repair"] });
  claim(m, s, "repair", 27);
  finish(m, s, "repair", 28, 39, 40, "accepted");
  m.captureReady(s, { atMs: 40, nodeIds: ["join"] });
  claim(m, s, "join", 43);
  finish(m, s, "join", 44, 48, 50, "accepted");

  const snapshot = structuredClone(s);
  const { usefulWorkMs, criticalPathMs, queueWaitMs, dispatchOverheadMs, verificationMs,
    reworkCount, rejectedCount } = m.metrics(s);
  assert.deepEqual({ usefulWorkMs, criticalPathMs, queueWaitMs, dispatchOverheadMs, verificationMs,
    reworkCount, rejectedCount }, {
    usefulWorkMs: 38, criticalPathMs: 50, queueWaitMs: 12, dispatchOverheadMs: 8, verificationMs: 8,
    reworkCount: 2, rejectedCount: 1,
  });
  assert.deepEqual(s, snapshot);
});

test("expansion retains fenced work before the shards without double-counting overlapping readiness", async () => {
  const m = await api();
  const s = state("expand", node("read"));
  m.captureReady(s, { atMs: 1, nodeIds: ["read"] });
  claim(m, s, "read", 3);
  finish(m, s, "read", 4, undefined, 10, "superseded");
  s.nodes.left = node("left");
  s.nodes.right = node("right");
  s.nodes.read.dependsOn = ["left", "right"];
  s.joinMembers = { read: [{ shardId: "left" }, { shardId: "right" }] };
  m.captureReady(s, { atMs: 8, nodeIds: ["left", "right"] });
  claim(m, s, "left", 12);
  claim(m, s, "right", 13);
  finish(m, s, "left", 14, 17, 19, "accepted");
  finish(m, s, "right", 15, 20, 22, "accepted");
  m.captureReady(s, { atMs: 22, nodeIds: ["read"] });
  claim(m, s, "read", 23, 3);
  finish(m, s, "read", 24, 28, 30, "accepted");

  assert.equal(m.metrics(s).criticalPathMs, 29);
});

test("usage totals require observations on every claimed attempt, independently by dimension", async () => {
  const m = await api();
  const s = state("usage", node("first"), node("second"));
  assert.deepEqual(m.metrics(s).usage, { inputTokens: null, outputTokens: null, costUsd: null });
  m.captureReady(s, { atMs: 0, nodeIds: ["first", "second"] });
  claim(m, s, "first", 1);
  finish(m, s, "first", 2, undefined, 3, "accepted", { inputTokens: 0, outputTokens: 3, costUsd: 0 });
  claim(m, s, "second", 4);
  assert.deepEqual(m.metrics(s).usage, { inputTokens: null, outputTokens: null, costUsd: null });
  finish(m, s, "second", 5, undefined, 6, "rejected", { inputTokens: 7, costUsd: -1 });
  assert.deepEqual(m.metrics(s).usage, { inputTokens: 7, outputTokens: null, costUsd: null });
  assert.deepEqual(m.metrics({ ...s, attemptsIssued: 3 }).usage,
    { inputTokens: null, outputTokens: null, costUsd: null });
});

test("single-layer comparisons require the named run and the same pair, never substitute estimates", async () => {
  const m = await api();
  const s = state("dag", node("a"));
  const b = state("baseline", node("a"));
  m.captureBaseline(s, { pairId: "task-1", mode: "dag", baselineRunId: "baseline" });
  m.captureBaseline(b, { pairId: "other", mode: "single-layer" });
  assert.equal(m.metrics(s, b).baselineComparison.paired, false);
  m.captureBaseline(b, { pairId: "task-1", mode: "single-layer" });
  claim(m, b, "a", 3);
  finish(m, b, "a", 4, undefined, 9, "accepted");

  assert.deepEqual(m.metrics(s, b).baselineComparison, {
    pairId: "task-1", mode: "dag", baselineRunId: "baseline", paired: true,
    baseline: { usefulWorkMs: 5, criticalPathMs: 6, queueWaitMs: 0, dispatchOverheadMs: 1, verificationMs: 0,
      reworkCount: 0, rejectedCount: 0, usage: { inputTokens: null, outputTokens: null, costUsd: null } },
  });
  assert.equal(m.metrics(s, { ...b, runId: "another" }).baselineComparison.paired, false);
});

test("diagnostic tallies survive later recovery and do not depend on active canary state", async () => {
  const m = await api();
  const s = state("diagnostic");
  for (const event of ["loadFailures", "suspects", "probeFailures", "handoffs", "recoveries", "suspects"]) {
    m.captureCanary(s, event);
  }
  assert.deepEqual(m.metrics(structuredClone(s)).canaryStats, {
    loadFailures: 1, suspects: 2, probeFailures: 1, handoffs: 1, recoveries: 1,
  });
  assert.throws(() => m.captureCanary(s, "invalid"), { code: "ERR_GRAPH_METRICS" });
});

test("metrics --run reads measured journaled attempts, retained handoffs and the paired baseline", async t => {
  const workspace = await mkdtemp(join(tmpdir(), "graph-metrics-"));
  t.after(() => rm(workspace, { recursive: true, force: true }));
  const root = join(workspace, "store");
  const dataDir = join(workspace, "host-data");
  const cliPath = fileURLToPath(new URL("../scripts/graph/cli.mjs", import.meta.url));
  const { runCli } = await import("../scripts/graph/cli.mjs");
  const { dispatch } = await import("../scripts/graph/state-machine.mjs");
  const clock = Date.now();
  const at = async (ms, call) => {
    const original = Date.now;
    Date.now = () => clock + ms;
    try { return await call(); }
    finally { Date.now = original; }
  };
  const flags = ["--root", root, "--workspace", workspace];
  const cli = async (ms, command, ...opts) => at(ms, async () => {
    let stdout = "";
    const code = await runCli([command, ...flags, ...opts], {
      cwd: workspace, stdout: { write: chunk => { stdout += chunk; } },
    });
    assert.equal(code, 0, stdout);
    return JSON.parse(stdout).result;
  });
  const file = async (name, value) => {
    await writeFile(join(workspace, name), JSON.stringify(value));
    return name;
  };
  const graphNode = { id: "a", kind: "read", dependsOn: [], prompt: "read source", estimatedMinutes: 90 };
  const compile = async (run, baselineComparison) => cli(0, "compile", "--run", run, "--spec",
    await file(`${run}.json`, { schemaVersion: 1, nodes: [graphNode], baselineComparison }));
  const start = async (run, id, claimAt, startAt) => {
    const { instructionPath } = await cli(claimAt, "claim", "--run", run, "--node", "a",
      "--expected-rev", "1", "--op-id", `claim-${id}`);
    await cli(startAt, "start", "--token", instructionPath, "--host-handle", `host-${id}`);
    return instructionPath;
  };
  const provenance = {
    evidenceSpans: [{ spanId: "s", path: "source", startLine: 1, endLine: 1 }],
    claims: [{ claimId: "c", text: "checked", spanIds: ["s"] }], edgeCases: [], failureEvidence: [],
  };
  provenance.factDigest = factDigest(provenance);
  await writeFile(join(workspace, "source"), "checked\n");
  const measuredGate = await measureGate({ argv: [process.execPath, "-e", "process.exit(0)"],
    cwd: workspace, subjectDigest: provenance.factDigest });
  const gate = await file("gate.json", measuredGate);
  const settle = async (token, endAt, telemetry) => cli(endAt, "settle", "--token", token,
    "--op-id", "accepted", "--outcome", "accepted", "--gate-log", gate, "--receipt",
    await file("receipt.json", { workerReportedStatus: "completed", provenance, inlineSummary: "checked",
      usage: { inputTokens: 999, outputTokens: 999, costUsd: 999 } }),
    ...(telemetry ? ["--telemetry", await file("telemetry.json", telemetry)] : []));

  await cli(0, "init");
  await compile("baseline", { pairId: "read-source", mode: "single-layer" });
  const baselineToken = await start("baseline", "single", 3, 7);
  const baselineTelemetry = { usage: { inputTokens: 9, outputTokens: 2, costUsd: 0 }, canaryEvent: "recovered" };
  assert.equal((await settle(baselineToken, 17, baselineTelemetry)).status, "accepted");
  assert.equal((await settle(baselineToken, 18, baselineTelemetry)).status, "accepted");
  const baselineState = await cli(18, "metrics", "--run", "baseline");
  assert.equal(baselineState.canaryStats.recoveries, 1);

  await compile("worker-only", { pairId: "unpaired", mode: "dag" });
  await settle(await start("worker-only", "worker-only", 3, 7), 17);
  const workerOnly = await cli(18, "metrics", "--run", "worker-only");
  assert.deepEqual(workerOnly.usage, { inputTokens: null, outputTokens: null, costUsd: null });

  await compile("dag", { pairId: "read-source", mode: "dag", baselineRunId: "baseline" });
  const token = await start("dag", "original", 2, 6);
  const { snapshot } = saveHandoffSnapshot({ cwd: workspace, dataDir, input: { verified_facts: ["checked"] } });
  await at(10, () => dispatch("settle", {
    root, token, dataDir, outcome: "context_rot_abort", opId: "rotate",
    telemetry: { usage: { inputTokens: 4 }, canaryEvent: "suspect" },
    receipt: { sessionId: "metrics-host", snapshotId: snapshot.snapshotId, verifiedFacts: snapshot.verifiedFacts,
      usage: { inputTokens: 999, outputTokens: 999, costUsd: 999 } },
  }));
  assert.equal((await settle(await start("dag", "recovered", 12, 17), 29,
    { usage: { inputTokens: 6, outputTokens: 8 } })).status, "accepted");

  const stdout = execFileSync(process.execPath, [cliPath, "metrics", ...flags, "--run", "dag"], {
    cwd: workspace, encoding: "utf8",
  });
  const { result } = JSON.parse(stdout);
  const { usefulWorkMs, criticalPathMs, queueWaitMs, dispatchOverheadMs, verificationMs,
    reworkCount, rejectedCount, usage } = result;
  assert.deepEqual({ usefulWorkMs, criticalPathMs, queueWaitMs, dispatchOverheadMs, verificationMs,
    reworkCount, rejectedCount, usage }, {
    usefulWorkMs: 12, criticalPathMs: 29, queueWaitMs: 4, dispatchOverheadMs: 9, verificationMs: 0,
    reworkCount: 1, rejectedCount: 0, usage: { inputTokens: 10, outputTokens: null, costUsd: null },
  });
  assert.deepEqual(result.canaryStats, { loadFailures: 0, suspects: 1, probeFailures: 0, handoffs: 1, recoveries: 0 });
  assert.deepEqual(result.baselineComparison, {
    pairId: "read-source", mode: "dag", baselineRunId: "baseline", paired: true,
    baseline: { usefulWorkMs: 10, criticalPathMs: 17, queueWaitMs: 3, dispatchOverheadMs: 4, verificationMs: 0,
      reworkCount: 0, rejectedCount: 0, usage: { inputTokens: 9, outputTokens: 2, costUsd: 0 } },
  });
});
