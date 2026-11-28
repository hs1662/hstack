import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

// The fault tier runs the real-engine case at 64 shards; full keeps it at 8 (SSOT D25).
const shardCount = Number(process.env.HSTACK_TEST_MASS_SHARDS ?? 8);
if (!Number.isSafeInteger(shardCount) || shardCount < 2) throw new Error("HSTACK_TEST_MASS_SHARDS must be an integer >= 2");
const evidenceFile = "sample.txt";
const gateArgv = [process.execPath, "-e",
  `process.exitCode = require("node:fs").readFileSync(${JSON.stringify(evidenceFile)}, "utf8").length > 0 ? 0 : 1`];

test("mass rejects duplicate shard IDs instead of silently losing obligations", async () => {
  const { compileMassSpec } = await import("../scripts/graph/mass.mjs");
  assert.throws(() => compileMassSpec({
    shards: [{ id: "same" }, { id: "same" }],
  }), { code: "ERR_MASS_SPEC" });
});

test("mass builds a bounded fan-in between the shard and final work", async () => {
  const { compileMassSpec } = await import("../scripts/graph/mass.mjs");
  const spec = compileMassSpec({
    clusterSize: 2,
    shards: [{ id: "one" }, { id: "two" }, { id: "three" }],
  });
  const nodes = new Map(spec.nodes.map((node) => [node.id, node]));
  const final = nodes.get("mass-final");
  assert.deepEqual(final.dependsOn.map((id) => nodes.get(id).dependsOn), [
    ["one", "two"], ["three"],
  ]);
});

test("an unsettled sealed member stays missing even if the caller supplies alternate leaves", async () => {
  const { reduceRun } = await import("../scripts/graph/mass.mjs");
  const state = {
    runId: "missing", graphRev: 1, workspace: process.cwd(),
    nodes: {
      join: { id: "join", kind: "reducer", status: "pending", dependsOn: ["leaf"] },
      leaf: { id: "leaf", kind: "read", status: "running", highestIssuedEpoch: 2 },
    },
    joinMembers: { join: [{ shardId: "leaf", obligationId: "obligation" }] },
  };
  const io = memoryCas();
  const { response, state: next } = await reduceRun(state, {
    node: "join", expected: [], leaves: [{ shardId: "leaf", validEpoch: 2 }],
  }, io);
  assert.equal(response.status, "partial");
  const index = JSON.parse(await io.get(response.indexUri));
  assert.deepEqual(index.missing, [{ shardId: "leaf", validEpoch: 2, obligationId: "obligation" }]);
  assert.notEqual(next.nodes.join.status, "accepted");
});

test("accepted state with invalid receipt bytes cannot complete the reducer", async () => {
  const { reduceRun } = await import("../scripts/graph/mass.mjs");
  const io = memoryCas();
  const receiptUri = await io.put(Buffer.from('{"workerReportedStatus":"completed"}'));
  const state = {
    runId: "invalid", graphRev: 1, workspace: process.cwd(),
    nodes: {
      join: { id: "join", kind: "reducer", status: "pending", dependsOn: ["constructor"] },
      constructor: { id: "constructor", kind: "read", status: "accepted", highestIssuedEpoch: 3, receiptUri },
    },
    joinMembers: { join: [{ shardId: "constructor", obligationId: "required" }] },
  };
  const { response, state: next } = await reduceRun(state, { node: "join" }, io);
  assert.equal(response.status, "partial");
  const index = JSON.parse(await io.get(response.indexUri));
  assert.deepEqual(index.missing, [{ shardId: "constructor", validEpoch: 3, obligationId: "required" }]);
  assert.equal(index.issues[0].code, "ERR_MISSING_EVIDENCE");
  assert.notEqual(next.nodes.join.status, "accepted");
});

test("complete coverage supplies proof without accepting a running or gate-controlled reducer", async (t) => {
  const { reduceRun } = await import("../scripts/graph/mass.mjs");
  const { factDigest, validateReceipt } = await import("../scripts/graph/reducer.mjs");
  const { measureGate } = await import("../scripts/graph/verify-gate.mjs");
  const io = memoryCas();
  const workspace = await mkdtemp(join(tmpdir(), "hstack-mass-gate-"));
  t.after(() => rm(workspace, { recursive: true, force: true }));
  await writeFile(join(workspace, evidenceFile), "Sourced fixture evidence\n");
  const provenance = {
    evidenceSpans: [{ spanId: "source", path: evidenceFile, startLine: 1, endLine: 1 }],
    claims: [{ claimId: "claim", text: "One claim", spanIds: ["source"] }],
    edgeCases: [], failureEvidence: [],
  };
  provenance.factDigest = factDigest(provenance);
  async function storeMeasuredGate(subjectDigest) {
    return io.put(Buffer.from(JSON.stringify(await measureGate({ argv: gateArgv, cwd: workspace, subjectDigest }))));
  }
  const gateLogUri = await storeMeasuredGate(provenance.factDigest);
  const accepted = await validateReceipt({
    workerReportedStatus: "completed", inlineSummary: "one", provenance,
  }, { ...io, workspaceRoot: workspace, gateLogUri });
  const receiptUri = await io.put(Buffer.from(JSON.stringify(accepted)));
  const leaf = { id: "leaf", kind: "read", status: "accepted", highestIssuedEpoch: 1, receiptUri };
  const state = {
    runId: "proof", graphRev: 1, workspace,
    joinMembers: { join: [{ shardId: "leaf", obligationId: "leaf" }] },
  };
  for (const control of [
    { status: "running" }, { status: "pending", testPlan: ["verify"] },
    { status: "pending", gateArgv },
    { status: "pending", revalidateReceiptUri: receiptUri },
  ]) {
    const join = { id: "join", kind: "reducer", dependsOn: ["leaf"], ...control };
    const { response, state: next } = await reduceRun({ ...state, nodes: { leaf, join } }, { node: "join" }, io);
    assert.equal(response.status, "complete");
    assert.equal(response.receiptUri, null);
    assert.equal(next.nodes.join.status, control.status);
    assert.equal(next.nodes.join.reductionUri, response.indexUri);
    assert.equal(JSON.parse(await io.get(next.nodes.join.reductionUri)).status, "complete");
  }
  const reducerNode = { id: "join", kind: "reducer", status: "pending", dependsOn: ["leaf"] };
  const linked = { ...provenance, claims: [{ ...provenance.claims[0], contradicts: "absent-claim" }] };
  linked.factDigest = factDigest(linked);
  const linkedLogUri = await storeMeasuredGate(linked.factDigest);
  const linkedReceipt = await validateReceipt({
    workerReportedStatus: "completed", inlineSummary: "one", provenance: linked,
  }, { ...io, workspaceRoot: workspace, gateLogUri: linkedLogUri });
  const linkedUri = await io.put(Buffer.from(JSON.stringify(linkedReceipt)));
  const broken = await reduceRun({
    ...state,
    nodes: { join: reducerNode, leaf: { ...leaf, receiptUri: linkedUri }, other: { id: "other", kind: "read", status: "pending" } },
    joinMembers: { ...state.joinMembers, final: [
      { shardId: "join", obligationId: "join" }, { shardId: "other", obligationId: "other" },
    ] },
  }, { node: "join" }, io);
  assert.equal(broken.response.status, "partial");
  for (const unchecked of [
    { ...accepted, verifierEvidence: null },
    { ...accepted, workerClaim: { ...accepted.workerClaim, inlineSummary: "worker mismatch" } },
    {
      ...accepted,
      gateEvidence: { logUri: `cas://sha256/${"f".repeat(64)}` },
      verifierEvidence: { ...accepted.verifierEvidence, logUri: `cas://sha256/${"f".repeat(64)}` },
    },
  ]) {
    const badUri = await io.put(Buffer.from(JSON.stringify(unchecked)));
    const { response } = await reduceRun({
      ...state, nodes: { join: reducerNode, leaf: { ...leaf, receiptUri: badUri } },
    }, { node: "join" }, io);
    assert.equal(response.status, "partial");
    assert.equal(response.missingCount, 1);
  }
  const stale = await reduceRun({
    ...state, nodes: { join: reducerNode, leaf: { ...leaf, attempt: { epoch: 1 }, highestIssuedEpoch: 2 } },
  }, { node: "join" }, io);
  assert.deepEqual(JSON.parse(await io.get(stale.response.indexUri)).missing, [
    { shardId: "leaf", validEpoch: 2, obligationId: "leaf" },
  ]);
  const budgetContext = {
    verified: true, actualUsage: { inputTokens: 1, outputTokens: 1 },
    W_eff: 100, reservedTokens: 20,
    contentTokens: { [createHash("sha256").update("one").digest("hex")]: 2 },
  };
  for (const [trust, options, mode] of [
    [io, { budgetContext }, "bytes"],
    [{ ...io, budgetContext }, {}, "tokens"],
  ]) {
    const { response } = await reduceRun({ ...state, nodes: { leaf, join: reducerNode } }, { node: "join", ...options }, trust);
    const index = JSON.parse(await io.get(response.indexUri));
    assert.equal(index.budget.mode, mode);
    if (mode === "tokens") {
      assert.equal(index.budget.B, 80);
      assert.equal(index.budget.inlineTokens, 2);
    }
  }
});

function memoryCas() {
  const objects = new Map();
  return {
    get: async (uri) => objects.get(uri),
    put: async (bytes) => {
      const uri = `cas://sha256/${createHash("sha256").update(bytes).digest("hex")}`;
      objects.set(uri, bytes);
      return uri;
    },
  };
}

test("reduction follows the expanded parent's closed membership through physical repair", async (t) => {
  const { dispatch } = await import("../scripts/graph/state-machine.mjs");
  const { getBlob } = await import("../scripts/graph/gc.mjs");
  const fixture = await mkdtemp(join(tmpdir(), "hstack-mass-patch-"));
  t.after(() => rm(fixture, { recursive: true, force: true }));
  const workspace = join(fixture, "workspace");
  const root = join(fixture, "graph");
  await Promise.all([mkdir(workspace), mkdir(root)]);
  t.diagnostic(`mass patch evidence root: ${root}`);
  const shared = { root, workspace, run: "patched" };
  const node = "parent";
  await dispatch("compile", {
    ...shared, spec: {
      schemaVersion: 1,
      nodes: [
        { id: node, kind: "read", prompt: "Collect evidence." },
        { id: "join", kind: "reducer", prompt: "Reduce evidence.", dependsOn: [node] },
      ],
      joinMembers: { join: [] },
    },
  });
  const initial = await dispatch("reduce", { ...shared, node: "join", expectedRev: 1, opId: "initial" });
  assert.deepEqual(JSON.parse(await getBlob(root, initial.indexUri)).missing, [
    { shardId: node, validEpoch: 0, obligationId: node },
  ]);
  await dispatch("expand", {
    ...shared, node, expectedRev: 1, opId: "expand",
    patch: { shards: [{ stableShardKey: "leaf", obligationId: "required" }] },
  });
  const leaf = "parent::shard::leaf";
  const { instructionPath: token } = await dispatch("claim", {
    ...shared, node: leaf, expectedRev: 2, opId: "claim",
  });
  await dispatch("start", { root, token, hostHandle: "patch-fixture" });
  await dispatch("settle", { root, token, outcome: "logic_terminal", opId: "reject" });
  const { nodeId: replacement } = await dispatch("inject-repair", {
    ...shared, node: leaf, expectedRev: 2, opId: "repair", patch: { prompt: "Collect corrected evidence." },
  });
  const result = await dispatch("reduce", { ...shared, node, expectedRev: 3, opId: "reduce" });
  assert.equal(result.status, "partial");
  const index = JSON.parse(await getBlob(root, result.indexUri));
  assert.deepEqual(index.missing, [{ shardId: replacement, validEpoch: 0, obligationId: "required" }]);
});

test(`${shardCount} real engine shards leave the final partial until the last sealed receipt, with all evidence indexed`, async (t) => {
  const { dispatch } = await import("../scripts/graph/state-machine.mjs");
  const { compileMassSpec } = await import("../scripts/graph/mass.mjs");
  const { factDigest } = await import("../scripts/graph/reducer.mjs");
  const { getBlob } = await import("../scripts/graph/gc.mjs");
  const fixture = await mkdtemp(join(tmpdir(), "hstack-mass-"));
  t.after(() => rm(fixture, { recursive: true, force: true }));
  const workspace = join(fixture, "workspace");
  const root = join(fixture, "graph");
  await mkdir(workspace);
  await mkdir(root);
  t.diagnostic(`mass engine evidence root: ${root}`);
  const run = "many";
  const shared = { root, workspace, run };
  const ids = Array.from({ length: shardCount }, (_, i) => `shard-${String(i + 1).padStart(2, "0")}`);
  const shards = ids.map((id) => ({ id, obligationId: `required-${id}`, readScope: [evidenceFile], gateArgv }));
  const spec = compileMassSpec({ shards });
  const final = spec.nodes.at(-1);
  await writeFile(join(workspace, evidenceFile), "one line of evidence\n");
  await dispatch("compile", {
    ...shared, spec: {
      preset: "mass",
      shards,
      joinMembers: { [final.id]: [{ shardId: ids[0], obligationId: "forged", validEpoch: 99 }] },
    },
  });

  let seq = 0;
  const op = (prefix) => `${prefix}-${++seq}`;
  async function settle(node, receipt) {
    const { instructionPath: token } = await dispatch("claim", {
      ...shared, node, expectedRev: 1, opId: op("claim"),
    });
    await dispatch("start", { root, token, hostHandle: `host-${node}` });
    return dispatch("settle", { root, token, opId: op("settle"), outcome: "completed", receipt });
  }
  async function settleShard(id) {
    const detailed = id === ids[0] || id === ids.at(-1);
    const provenance = {
      evidenceSpans: [{ spanId: `span-${id}`, path: evidenceFile, startLine: 1, endLine: 1 }],
      claims: [{
        claimId: `claim-${id}`, text: `Claim from ${id}`, spanIds: [`span-${id}`],
        ...(id === ids.at(-1) ? { contradicts: `claim-${ids[0]}` } : {}),
      }],
      edgeCases: detailed ? [{
        edgeCaseId: `edge-${id}`, occurrenceId: `edge-occ-${id}`, signature: "boundary",
        causalPredecessor: id === ids[0] ? null : `edge-occ-${ids[0]}`,
        seq: id === ids[0] ? 1 : 3, spanIds: [`span-${id}`],
      }] : [],
      failureEvidence: detailed ? [{
        failureId: `failure-${id}`, occurrenceId: `failure-occ-${id}`, signature: "timeout",
        causalPredecessor: `edge-occ-${id}`, seq: id === ids[0] ? 2 : 4,
      }] : [],
    };
    provenance.factDigest = factDigest(provenance);
    const result = await settle(id, { workerReportedStatus: "completed", inlineSummary: id, provenance });
    assert.equal(result.status, "accepted");
  }
  const reduce = (node) => dispatch("reduce", { ...shared, node, expectedRev: 1, opId: op("reduce") });

  for (const id of ids.slice(0, -1)) await settleShard(id);
  for (const id of final.dependsOn.slice(0, -1)) await reduce(id);
  const partial = await reduce(final.id);
  assert.equal(partial.status, "partial");
  assert.deepEqual(JSON.parse(await getBlob(root, partial.indexUri)).missing.map(({ shardId }) => shardId), [ids.at(-1)]);
  assert.notEqual((await dispatch("status", shared)).nodes[final.id].status, "accepted");

  await settleShard(ids.at(-1));
  const cluster = await reduce(final.dependsOn.at(-1));
  assert.equal(cluster.status, "complete");
  const clusterIndex = JSON.parse(await getBlob(root, cluster.indexUri));
  const clusterProof = JSON.parse(await getBlob(root, clusterIndex.indexRoot));
  const remote = clusterProof.dispositions.find(({ shardId }) => shardId === ids.at(-1)).target;
  assert.equal(remote.shardId, ids[0]);
  const remoteReceipt = JSON.parse(await getBlob(root, remote.receiptUri));
  assert.equal(remoteReceipt.workerClaim.provenance.claims[remote.index].claimId, `claim-${ids[0]}`);
  await dispatch("amend", {
    ...shared, node: final.id, expectedRev: 1, opId: op("gate"),
    patch: { gate: { gateArgv } },
  });
  const preindex = await dispatch("reduce", { ...shared, node: final.id, expectedRev: 2, opId: op("reduce") });
  assert.equal(preindex.status, "complete");
  const pending = (await dispatch("status", shared)).nodes[final.id];
  assert.equal(pending.status, "pending");
  assert.equal(pending.reductionUri, preindex.indexUri);
  const { instructionPath: token } = await dispatch("claim", {
    ...shared, node: final.id, expectedRev: 2, opId: op("claim"),
  });
  await dispatch("start", { root, token, hostHandle: "final-verifier" });
  const provenance = {
    evidenceSpans: [{ spanId: "final-span", path: evidenceFile, startLine: 1, endLine: 1 }],
    claims: [{ claimId: "final-claim", text: "Verified final", spanIds: ["final-span"] }],
    edgeCases: [], failureEvidence: [],
  };
  provenance.factDigest = factDigest(provenance);
  const result = await dispatch("settle", {
    root, token, opId: op("settle"), outcome: "completed",
    receipt: { workerReportedStatus: "completed", inlineSummary: "final", provenance },
  });
  assert.equal(result.status, "accepted");
  const completed = await dispatch("status", shared);
  const accepted = completed.nodes[final.id];
  assert.equal(accepted.reductionUri, result.receiptUri);
  assert.notEqual(accepted.workerReceiptUri, accepted.reductionUri);
  assert.equal(JSON.parse(await getBlob(root, accepted.workerReceiptUri)).verifierEvidence.exit, 0);
  assert.equal(completed.status, "completed");
  const index = JSON.parse(await getBlob(root, result.receiptUri));
  assert.equal(index.expected.length, shardCount);
  assert.deepEqual(index.expected.sort((a, b) => a.shardId.localeCompare(b.shardId)),
    ids.map((shardId) => ({ shardId, validEpoch: 1, obligationId: `required-${shardId}` })));
  assert.equal(index.clusterIndexes.length, Math.ceil(shardCount / 8));
  const indexed = JSON.parse(await getBlob(root, index.indexRoot));
  assert.deepEqual(indexed.dispositions.map(({ claimId }) => claimId).sort(), ids.map((id) => `claim-${id}`));
  assert.equal(indexed.dispositions.find(({ shardId }) => shardId === ids.at(-1)).target.shardId, ids[0]);
  const ends = [ids[0], ids.at(-1)];
  for (const [kind, key, prefix] of [
    ["edgeCases", "edgeCaseId", "edge"], ["failureEvidence", "failureId", "failure"],
  ]) {
    const entries = indexed[kind].flatMap((group) => group.entries);
    assert.deepEqual(entries.map(({ value }) => value[key]).sort(), ends.map((id) => `${prefix}-${id}`));
    assert.deepEqual(entries.map(({ occurrenceId, seq, causalPredecessor }) => [occurrenceId, seq, causalPredecessor]), [
      [`${prefix}-occ-${ends[0]}`, prefix === "edge" ? 1 : 2, prefix === "edge" ? null : `edge-occ-${ends[0]}`],
      [`${prefix}-occ-${ends[1]}`, prefix === "edge" ? 3 : 4, `edge-occ-${prefix === "edge" ? ends[0] : ends[1]}`],
    ]);
    for (const { source, value } of entries) {
      const receipt = JSON.parse(await getBlob(root, source.receiptUri));
      assert.deepEqual(receipt.provenance[kind][source.index], value);
    }
  }
});
