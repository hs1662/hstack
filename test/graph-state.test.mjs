import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import "./helpers.mjs";
import { computeWorkspaceKey, listPinnedSnapshots, saveHandoffSnapshot } from "../scripts/governance/handoff-store.mjs";

const moduleUrl = new URL("../scripts/graph/state-machine.mjs", import.meta.url).href;
const read = (id, extra) => ({ id, kind: "read", dependsOn: [], prompt: id, estimatedMinutes: 5,
  gateArgv: [process.execPath, "-e", "require('fs').accessSync('source')"], ...extra });
const send = async (command, options) => (await import(moduleUrl)).dispatch(command, options);
async function fixture(t, nodes, limits = {}, settings = {}) {
  const workspace = await fs.mkdtemp(join(tmpdir(), "graph-state-"));
  t.after(() => fs.rm(workspace, { recursive: true, force: true }));
  const root = join(workspace, "store");
  await fs.mkdir(root, { mode: 0o700 });
  await fs.writeFile(join(workspace, "source"), "evidence\n");
  const run = "trial";
  const call = (cmd, opts = {}) => send(cmd, { root, run, ...opts });
  await call("compile", { workspace, opId: "compile", spec: { schemaVersion: 1, nodes, limits, ...settings } });
  const claim = (node, opId = `claim-${node}`) => call("claim", { node, expectedRev: 1, opId });
  const start = async (node, opId) => {
    const { instructionPath: token } = await claim(node, opId);
    await send("start", { root, token, hostHandle: `worker:${node}` });
    return token;
  };
  const settle = (token, outcome, receipt, opId = `settle-${outcome}`) =>
    send("settle", { root, token, outcome, receipt, opId });
  return { root, workspace, run, call, claim, start, settle };
}

async function proof(f) {
  const { factDigest } = await import("../scripts/graph/reducer.mjs");
  const provenance = { evidenceSpans: [{ spanId: "s", path: "source", startLine: 1, endLine: 1 }],
    claims: [{ claimId: "c", spanIds: ["s"], text: "a fact" }], edgeCases: [], failureEvidence: [] };
  provenance.factDigest = factDigest(provenance);
  return { schemaVersion: 1, workerReportedStatus: "completed", provenance, inlineSummary: "a fact" };
}

test("simultaneous OS processes cannot both claim; replay returns one durable directive", async t => {
  const f = await fixture(t, [read("a"), read("b")]);
  const workers = ["one", "two"].map(opId => {
    const script = `import { dispatch } from ${JSON.stringify(moduleUrl)};
      process.send('ready'); process.once('message',async()=>{
        try { process.send({result:await dispatch('claim',JSON.parse(process.argv[1]))}); }
        catch(e) { process.send({error:e.code}); } finally { process.disconnect(); } });`;
    const child = spawn(process.execPath, ["--input-type=module", "-e", script,
      JSON.stringify({ root: f.root, run: f.run, node: "a", expectedRev: 1, opId })],
    { stdio: ["ignore", "ignore", "inherit", "ipc"] });
    t.after(() => { if (child.exitCode === null) child.kill(); });
    return { opId, child, ready: once(child, "message") };
  });
  await Promise.all(workers.map(w => w.ready));
  const both = await Promise.all(workers.map(async ({ child }) => {
    const msg = once(child, "message");
    child.send("claim");
    return (await msg)[0];
  }));
  assert.equal(both.filter(v => v.result).length, 1);
  assert.ok(both.some(v => v.error));
  const winner = both.findIndex(v => v.result);
  const opId = workers[winner].opId;
  const again = await f.claim("a", opId);
  assert.deepEqual(again, both[winner].result);
  await assert.rejects(f.claim("b", opId), { code: "ERR_OP_CONFLICT" });
  const directive = JSON.parse(await fs.readFile(again.instructionPath));
  assert.equal((await fs.stat(again.instructionPath)).mode & 0o077, 0);
  assert.match(directive.nonce, /^[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(again).includes(directive.nonce), false);
  const wal = await fs.readFile(join(f.root, "runs", f.run, "wal/events.jsonl"), "utf8");
  assert.equal(wal.includes(directive.nonce), false);
  assert.equal((await f.call("status")).nodes.a.highestIssuedEpoch, 1);
});

test("copied or symlinked directives do not authorize starts, including against another run", async t => {
  const f = await fixture(t, [read("a")]);
  const { instructionPath } = await f.claim("a");
  const copy = join(f.workspace, "copy.json");
  await fs.copyFile(instructionPath, copy);
  const tryStart = (token, run) => send("start", { root: f.root, token, run, hostHandle: "actual" });
  await assert.rejects(tryStart(copy, f.run), { code: "ERR_STALE_FENCING_TOKEN" });
  await assert.rejects(tryStart(instructionPath, "another"), { code: "ERR_STALE_FENCING_TOKEN" });
  await fs.unlink(instructionPath);
  await fs.symlink(copy, instructionPath);
  await assert.rejects(tryStart(instructionPath, f.run), { code: "ERR_STALE_FENCING_TOKEN" });
  assert.equal((await f.call("status")).nodes.a.status, "claimed");
});

test("context reset pins exactly the validated snapshot, fences prior replay and cannot change pins", async t => {
  const f = await fixture(t, [read("a")]);
  const old = await f.start("a");
  const dataDir = join(f.workspace, "handoffs-data");
  const snapshot = saveHandoffSnapshot({ cwd: f.workspace, dataDir, input: { verified_facts: ["source checked"] } }).snapshot;
  const receipt = { sessionId: "session", snapshotId: snapshot.snapshotId, verifiedFacts: snapshot.verifiedFacts };
  const rotate = (r, opId) => send("settle", { root: f.root, token: old, outcome: "context_rot_abort", opId, receipt: r, dataDir });
  await assert.rejects(rotate({ ...receipt, verifiedFacts: ["invented"] }, "bad-pin"));
  await rotate(receipt, "rotate");
  const prior = (await f.call("status")).nodes.a;
  assert.equal(prior.status, "fresh_reset_ready");
  assert.equal(prior.infraRetries, 0);
  assert.equal(prior.handoffCarryoverUri.endsWith("/" + snapshot.snapshotId), true);
  await f.start("a", "next");
  const pins = () => listPinnedSnapshots(computeWorkspaceKey(f.workspace), dataDir);
  const before = await f.call("status");
  const beforePins = pins();
  assert.deepEqual(beforePins.map(p => p.snapshotId), [snapshot.snapshotId]);
  const wal = join(f.root, "runs", f.run, "wal/events.jsonl");
  const roots = join(f.root, "gcroots", `${f.run}.pin.json`);
  const bytes = await Promise.all([fs.readFile(wal), fs.readFile(roots)]);
  for (const request of [() => send("start", { root: f.root, token: old, hostHandle: "worker:a" }),
    () => rotate(receipt, "rotate"), () => rotate(receipt, "stale-pin"),
    () => f.settle(old, "unresolved_blocked", { unpin: true }, "stale-release")]) {
    await assert.rejects(request(), { code: "ERR_STALE_FENCING_TOKEN", exitCode: 49 });
  }
  const cli = new URL("../scripts/graph/cli.mjs", import.meta.url);
  await assert.rejects(promisify(execFile)(process.execPath, [cli.pathname, "settle", "--root", f.root,
    "--workspace", f.workspace, "--token", old, "--outcome", "unresolved_blocked", "--op-id", "stale-cli"]), { code: 49 });
  assert.deepEqual(await f.call("status"), before);
  assert.deepEqual(pins(), beforePins);
  assert.deepEqual(await Promise.all([fs.readFile(wal), fs.readFile(roots)]), bytes);
});

for (const mode of ["blocked", "missing", "forged", "logic_terminal"]) {
  test(`${mode}: freeze required descendants, preserve independent acceptance, never falsely complete`, async t => {
    const f = await fixture(t, [read("parent"), read("child", { dependsOn: ["parent"] }), read("sibling")]);
    const good = await proof(f);
    await f.settle(await f.start("sibling"), "accepted", good, "ok");
    const token = await f.start("parent");
    const bad = structuredClone(good);
    if (mode === "forged") bad.provenance.claims[0].spanIds = ["imaginary"];
    if (mode === "blocked") bad.workerReportedStatus = "needs_clarification";
    if (mode === "missing") delete bad.provenance.factDigest;
    await f.settle(token, mode === "logic_terminal" ? mode : "accepted", bad);
    const state = await f.call("status");
    assert.deepEqual([state.nodes.parent.status, state.nodes.child.status, state.nodes.sibling.status, state.status],
      [mode === "blocked" || mode === "missing" ? "held_blocked" : "failed_logic", "held_upstream", "accepted", "held"]);
    assert.match(state.nodes.parent.receiptUri, /^cas:\/\/sha256\/[a-f0-9]{64}$/);
    await assert.rejects(f.call("retry", { node: "parent", opId: "bypass" }));
    assert.deepEqual((await f.call("ready")).ready, []);
  });
}

test("infra retry waits for recorded Retry-After and refuses a fourth retry even with a future ready preview", async t => {
  const f = await fixture(t, [read("a")]);
  let now = Date.now();
  for (let i = 0; i < 4; i++) {
    const actions = [
      ["claim", { node: "a", expectedRev: 1, opId: `c${i}` }],
      ["start", { hostHandle: `h${i}` }],
      ["settle", { outcome: "infra_transient", receipt: { retryAfter: 8 }, opId: `s${i}` }],
    ];
    const script = `import { dispatch } from ${JSON.stringify(moduleUrl)};
      Date.now=()=>${now};let token;for(const [cmd,opts] of JSON.parse(process.argv[1])){
      const res=await dispatch(cmd,{root:${JSON.stringify(f.root)},run:'trial',...opts,...token&&{token}});
      if(res.instructionPath)token=res.instructionPath;}`;
    await promisify(execFile)(process.execPath, ["--input-type=module", "-e", script, JSON.stringify(actions)]);
    const n = (await f.call("status")).nodes.a;
    if (i < 3) {
      assert.equal(n.status, "retry_wait");
      assert.ok(Date.parse(n.notBefore) >= now + 8000);
      assert.deepEqual((await f.call("ready", { asOf: new Date(now + 7999).toISOString() })).ready, []);
      await assert.rejects(f.call("retry", { node: "a", asOf: n.notBefore, opId: `jump${i}` }));
      now = Date.parse(n.notBefore) + 1;
    } else {
      assert.equal(n.status, "held_infra");
      assert.deepEqual((await f.call("ready", { asOf: "2099-01-01T00:00:00Z" })).ready, []);
    }
  }
});

test("readiness pages fit 8 KiB including cursor, preserve ordering, and do not append WAL", async t => {
  const ids = Array.from({ length: 140 }, (_, i) => `id-${String(i).padStart(3, "0")}-${"a".repeat(24)}`);
  const f = await fixture(t, [...ids].reverse().map(id => read(id)),
    { maxWidth: 160, maxNodes: 160 });
  const wal = join(f.root, "runs", f.run, "wal/events.jsonl");
  const before = await fs.readFile(wal);
  const all = [];
  let cursor;
  do {
    const page = await f.call("ready", { cursor, asOf: "2030-01-01T00:00:00Z" });
    assert.ok(Buffer.byteLength(JSON.stringify(page)) + 1 <= 8192);
    all.push(...page.ready.map(n => n.id));
    cursor = page.nextCursor;
  } while (cursor);
  assert.deepEqual(all, ids);
  assert.deepEqual(await fs.readFile(wal), before);
});

test("actual loaded skill pins, slot pressure, and the run attempt budget constrain claims", async t => {
  const f = await fixture(t, [read("__proto__", { skills: ["source"], rules: ["source"] }), read("constructor"),
    read("writer", { kind: "write", writeScope: ["output"] })], { maxPins: 2, readConcurrency: 1, maxAttempts: 2 });
  const token = await f.start("__proto__");
  const d = JSON.parse(await fs.readFile(token));
  const { getBlob } = await import("../scripts/graph/gc.mjs");
  assert.equal(String(await getBlob(f.root, d.skills[0].uri)), "evidence\n");
  assert.deepEqual(d.rules, d.skills);
  for (const id of ["constructor", "writer"]) await assert.rejects(f.claim(id), { code: "ERR_HELD_CAPACITY" });
  await f.settle(token, "logic_terminal", { diagnostic: "intentional" });
  await f.start("writer");
  await assert.rejects(f.claim("constructor", "budget-limit"), { code: "ERR_HELD_CAPACITY" });
});

test("claim refuses to issue a directive when its input files exceed pin capacity", async t => {
  const f = await fixture(t, [read("over", { skills: ["source"], rules: ["source"] }), read("fits")], { maxPins: 1 });
  assert.deepEqual((await f.call("ready")).ready.map(n => n.id), ["fits"]);
  await assert.rejects(f.claim("over"), { code: "ERR_HELD_CAPACITY" });
  const n = (await f.call("status")).nodes.over;
  assert.deepEqual([n.status, n.attempt, n.highestIssuedEpoch], ["pending", null, 0]);
});

test("single_session admission serializes independent reads even if claim offers a wider limit", async t => {
  const f = await fixture(t, [read("small-a"), read("small-b")], { readConcurrency: 16 });
  assert.equal((await f.call("status")).recommendation, "single_session");
  const first = await f.start("small-a");
  await assert.rejects(f.call("claim", { node: "small-b", expectedRev: 1, opId: "override",
    limits: { readConcurrency: 16 }, recommendation: "dag_approved" }), { code: "ERR_HELD_CAPACITY" });
  assert.deepEqual((await f.call("ready")).ready, []);
  await f.settle(first, "unresolved_blocked", { workerReportedStatus: "blocked" });
  assert.equal((await f.claim("small-b")).nodeId, "small-b");
});

test("gate-only amend revalidates the pinned artifact without generating new content", async t => {
  const f = await fixture(t, [read("a", { skills: ["source"] })]);
  const original = await proof(f);
  await f.settle(await f.start("a"), "completed", original);
  const before = (await f.call("status")).nodes.a;
  assert.equal(before.cacheable, false);
  await f.call("amend", { node: "a", expectedRev: 1, opId: "policy", patch: { gate: { gateVersion: 2 } } });
  const recheck = await f.call("claim", { node: "a", expectedRev: 2, opId: "recheck" });
  const d = JSON.parse(await fs.readFile(recheck.instructionPath));
  assert.deepEqual([d.mode, d.revalidateReceiptUri, d.execKey], ["revalidate", before.receiptUri, before.execKey]);
  await send("start", { root: f.root, token: recheck.instructionPath, hostHandle: "reviewer" });
  await f.settle(recheck.instructionPath, "completed", { ...original, inlineSummary: "substituted output" }, "forgery");
  assert.equal((await f.call("status")).nodes.a.status, "failed_logic");
});

test("gate-only revalidation keeps artifact identity when a new budget spills the same summary to CAS", async t => {
  const f = await fixture(t, [read("a")]);
  const r = await proof(f);
  await f.settle(await f.start("a"), "accepted", r, "before");
  const original = (await f.call("status")).nodes.a;
  await f.call("amend", { node: "a", expectedRev: 1, opId: "rev", patch: { gate: { timeoutMs: 3001 } } });
  const { instructionPath: token } = await f.call("claim", { node: "a", expectedRev: 2, opId: "recheck" });
  const directive = JSON.parse(await fs.readFile(token));
  assert.equal(directive.gate.timeoutMs, 3001);
  await send("start", { root: f.root, token, hostHandle: "review" });
  const result = await send("settle", { root: f.root, token, opId: "after", outcome: "accepted", receipt: r,
    telemetry: { budgetContext: { verified: true, actualUsage: { inputTokens: 1, outputTokens: 1 },
      W_eff: 1, reservedTokens: 1, contentTokens: {} } } });
  assert.equal(result.status, "accepted");
  const current = (await f.call("status")).nodes.a;
  assert.equal(current.artifactDigest, original.artifactDigest);
  assert.notEqual(current.gateKey, original.gateKey);
  const { getBlob } = await import("../scripts/graph/gc.mjs");
  const checked = JSON.parse(await getBlob(f.root, result.receiptUri));
  assert.match(checked.inlineSummary, /^cas:\/\/sha256\//);
  assert.equal((await getBlob(f.root, checked.inlineSummary)).toString(), r.inlineSummary);
});

test("external gate files enter CAS only as host evidence and remain audit roots on rejection", async t => {
  const nodes = ["ok", "missing", "wrong-policy"].map(id => ({ id, kind: "read", prompt: id }));
  const f = await fixture(t, nodes);
  const receipt = await proof(f);
  const { measureGate } = await import("../scripts/graph/verify-gate.mjs");
  const log = await measureGate({ argv: [process.execPath, "-e", "require('fs').accessSync('source')"],
    cwd: f.workspace, subjectDigest: receipt.provenance.factDigest });
  const { getBlob, collectGarbage } = await import("../scripts/graph/gc.mjs");
  const cases = [["ok", log, "accepted"], ["missing", null, "held_blocked"],
    ["wrong-policy", { ...log, gateKey: "0".repeat(64) }, "failed_logic"]];
  for (const [node, evidence, status] of cases) {
    const token = await f.start(node);
    const receiptFile = join(f.workspace, `${node}-worker.json`);
    await fs.writeFile(receiptFile, JSON.stringify({ ...receipt, gateEvidence: { passed: true }, gateLog: log }));
    const args = ["settle", "--root", f.root, "--workspace", f.workspace, "--token", token,
      "--receipt", receiptFile, "--outcome", "accepted", "--op-id", "s-" + node];
    if (evidence) {
      const file = join(f.workspace, `${node}-gate.json`);
      await fs.writeFile(file, JSON.stringify(evidence));
      args.push("--gate-log", file);
    }
    const cli = new URL("../scripts/graph/cli.mjs", import.meta.url);
    const result = await promisify(execFile)(process.execPath, [cli.pathname, ...args]);
    assert.equal(JSON.parse(result.stdout).result.status, status, node);
    await collectGarbage(f.root);
    if (evidence) {
      const n = (await f.call("status")).nodes[node];
      assert.deepEqual(JSON.parse(await getBlob(f.root, n.attempt.gateLogUri)), evidence);
    }
  }
});

test("worker reducer settlement pins the current partial index instead of reusing a complete claim index", async t => {
  const f = await fixture(t, [read("leaf", { obligationId: "fact" }),
    read("join", { kind: "reducer", dependsOn: ["leaf"] })]);
  const r = await proof(f);
  await f.settle(await f.start("leaf"), "accepted", r, "leaf-result");
  const token = await f.start("join");
  const { getBlob, collectGarbage } = await import("../scripts/graph/gc.mjs");
  const pre = JSON.parse(await fs.readFile(token)).reductionUri;
  assert.equal(JSON.parse(await getBlob(f.root, pre)).status, "complete");
  await fs.rename(join(f.workspace, "source"), join(f.workspace, "moved"));
  await fs.writeFile(join(f.workspace, "source"), ""); // old leaf's cited first line no longer exists
  const current = structuredClone(r);
  current.provenance.evidenceSpans[0].path = "moved";
  current.provenance.factDigest = (await import("../scripts/graph/reducer.mjs")).factDigest(current.provenance);
  current.expected = []; // not a source of coverage
  current.reductionUri = pre;
  const result = await f.settle(token, "accepted", current, "join-result");
  assert.equal(result.status, "held_blocked");
  await collectGarbage(f.root);
  const joinNode = (await f.call("status")).nodes.join;
  const finalIndex = JSON.parse(await getBlob(f.root, joinNode.reductionUri));
  assert.equal(finalIndex.status, "partial");
  assert.deepEqual(finalIndex.missing, [{ shardId: "leaf", obligationId: "fact", validEpoch: 1 }]);
});

test("steering: optional failure degrades only after the required work is checked", async t => {
  const f = await fixture(t, [read("necessary"), read("optional", { required: false })]);
  await f.settle(await f.start("optional"), "logic_terminal", {});
  assert.equal((await f.call("status")).status, "open");
  const token = (await f.claim("necessary")).instructionPath;
  const phase = async () => (await f.call("resume")).nodes.necessary.attempt.receiptPhase;
  assert.equal(await phase(), "prepared");
  await send("start", { root: f.root, token, hostHandle: "worker" });
  assert.equal(await phase(), "delivered");
  await f.settle(token, "accepted", await proof(f), "required");
  assert.equal(await phase(), "checked");
  assert.equal((await f.call("status")).status, "degraded");
});

test("steering: first failing gate and bounded green diagnostics stay pinned without promotion", async t => {
  const f = await fixture(t, [read("flaky", { flaky: true, gateArgv: [process.execPath, "-e",
    "const f=require('fs');f.appendFileSync('runs','x');process.exitCode=Number(f.readFileSync('runs').length===1)"] })],
  { maxFlakyDiagnostics: 2 });
  const result = await f.settle(await f.start("flaky"), "accepted", await proof(f));
  assert.equal(result.status, "held_flaky");
  const { getBlob, collectGarbage } = await import("../scripts/graph/gc.mjs");
  await collectGarbage(f.root);
  const node = (await f.call("status")).nodes.flaky;
  const records = await Promise.all([node.firstFailureUri, ...node.diagnosticUris].map(uri => getBlob(f.root, uri)));
  assert.deepEqual(records.map(b => JSON.parse(b).exitCode), [1, 0, 0]);
  assert.deepEqual((await f.call("ready")).ready, []);
  await assert.rejects(f.call("retry", { node: "flaky", opId: "force" }));
});

test("steering: trusted budget and canary telemetry are captured only once, never from a worker", async t => {
  const f = await fixture(t, [read("a")]);
  const token = await f.start("a");
  const receipt = { ...await proof(f), usage: { inputTokens: 999 }, canaryEvent: "recovered" };
  const budgetContext = { verified: true, W_eff: 100, reservedTokens: 20,
    actualUsage: { inputTokens: 3, outputTokens: 2 }, contentTokens: {} };
  const opts = { root: f.root, token, receipt, outcome: "accepted", opId: "ok",
    telemetry: { usage: { inputTokens: 3 }, canaryEvent: "suspect", budgetContext } };
  const first = await send("settle", opts);
  assert.deepEqual(await send("settle", opts), first);
  const { metrics } = await import("../scripts/graph/metrics.mjs");
  const m = metrics(await f.call("status"));
  assert.deepEqual(m.usage, { inputTokens: 3, outputTokens: null, costUsd: null });
  assert.deepEqual([m.canaryStats.suspects, m.canaryStats.recoveries], [1, 0]);
  const checked = JSON.parse(await (await import("../scripts/graph/gc.mjs")).getBlob(f.root, first.receiptUri));
  assert.equal(checked.budget.B, 80);
});

test("steering: dirty required read needs explicit revalidation, and a volatile sibling cannot reuse", async t => {
  const f = await fixture(t, [read("a"), ...["child", "volatile"].map(id => ({
    id, kind: "read", prompt: id, dependsOn: ["a"], projection: "facts-v1",
    ...(id === "volatile" && { volatility: { dynamicReads: [{ name: "unstable" }] } }),
  }))], {}, { hostProfile: { id: "host", model: "model-1.0", toolchain: "tool-1" } });
  const proof1 = await proof(f);
  const external = await (await import("../scripts/graph/verify-gate.mjs")).measureGate({
    argv: [process.execPath, "-e", "process.exit(0)"], cwd: f.workspace, subjectDigest: proof1.provenance.factDigest });
  await f.settle(await f.start("a"), "accepted", proof1, "parent1");
  const { getBlob } = await import("../scripts/graph/gc.mjs");
  const parentUri = (await f.call("status")).nodes.a.receiptUri;
  for (const id of ["child", "volatile"]) {
    const token = await f.start(id);
    const directive = await fs.readFile(token, "utf8");
    const { inputUris } = JSON.parse(directive);
    assert.equal(inputUris.length, 1);
    assert.deepEqual(JSON.parse(await getBlob(f.root, inputUris[0])), proof1.provenance);
    assert.equal(directive.includes(parentUri), false);
    assert.ok((await f.call("status")).nodes[id].attempt.inputUris.includes(parentUri), "engine pins original, never delivers it");
    await send("settle", { root: f.root, token, opId: "s-"+id, outcome: "accepted", receipt: proof1, gateLog: external });
  }
  const previous = (await f.call("status")).nodes.child.receiptUri;
  await f.call("amend", { node: "a", expectedRev: 1, opId: "change", patch: { exec: { prompt: "new prompt" } } });
  const next = await f.call("claim", { node: "a", expectedRev: 2, opId: "c2" });
  await send("start", { root: f.root, token: next.instructionPath, hostHandle: "again" });
  await f.settle(next.instructionPath, "accepted", { ...proof1, inlineSummary: "different wording" }, "parent2");
  assert.equal((await f.call("status")).nodes.child.status, "pending");
  const cli = new URL("../scripts/graph/cli.mjs", import.meta.url);
  const { stdout } = await promisify(execFile)(process.execPath, [cli.pathname, "revalidate", "--root", f.root,
    "--workspace", f.workspace, "--run", f.run, "--node", "child", "--expected-rev", "2", "--op-id", "reuse"]);
  const reused = JSON.parse(stdout).result;
  assert.equal(reused.status, "accepted");
  await assert.rejects(f.call("revalidate", { node: "volatile", expectedRev: 2, opId: "unsafe" }),
    { code: "ERR_REVALIDATION_REQUIRED" });
  const frames = (await fs.readFile(join(f.root, "runs", f.run, "wal/events.jsonl"), "utf8")).trim().split("\n").map(JSON.parse);
  const records = frames.filter(r => r.type === "NodeRevalidated");
  assert.deepEqual(records.map(r => [r.body.nodeId, r.body.graphRev, r.body.priorReceiptUri]), [["child", 2, previous]]);
  assert.ok(records[0].body.reason);
  // A frame names each URI once (D26); the run's root union still holds the prior receipt.
  assert.ok(frames.slice(0, frames.indexOf(records[0]) + 1).some(r => r.body.refs.includes(previous)));
});

test("explicit full receipt input prevents a facts-v1 delivery marker", async t => {
  const f = await fixture(t, [{ id: "p", kind: "read", prompt: "p" }]);
  const r = await proof(f);
  const log = await (await import("../scripts/graph/verify-gate.mjs")).measureGate({ argv: ["test", "-f", "source"],
    cwd: f.workspace, subjectDigest: r.provenance.factDigest });
  const finish = token => send("settle", { root: f.root, token, receipt: r, gateLog: log, outcome: "accepted", opId: "done" });
  const { receiptUri } = await finish(await f.start("p"));
  const o = { root: f.root, run: "second" };
  await send("compile", { ...o, workspace: f.workspace, spec: { schemaVersion: 1,
    nodes: [{ id: "p", kind: "read", prompt: "p" }, { id: "c", kind: "read", prompt: "c",
      dependsOn: ["p"], projection: "facts-v1", inputUris: [receiptUri] }] } });
  const claim = node => send("claim", { ...o, node, expectedRev: 1, opId: "claim-" + node });
  const token = (await claim("p")).instructionPath;
  await send("start", { root: f.root, token, hostHandle: "host" });
  assert.equal((await finish(token)).receiptUri, receiptUri);
  const directive = JSON.parse(await fs.readFile((await claim("c")).instructionPath));
  assert.deepEqual(directive.inputUris, [receiptUri]);
  assert.equal((await send("status", o)).nodes.c.attempt.deliveredProjection, null);
});

test("gate runs outside the graph lock and stale completion cannot publish its measurement", async t => {
  // A socket handshake establishes that the actual gate process is running;
  // the test releases it only after the patch has fenced its attempt.
  const { createServer } = await import("node:net");
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const script = `require("net").connect(${server.address().port},"127.0.0.1").resume();
    require("fs").appendFileSync("gate-spawns","1")`;
  const f = await fixture(t, [read("a", { gateArgv: [process.execPath, "-e", script], timeoutMs: 4000 })]);
  const token = await f.start("a");
  const connection = once(server, "connection");
  const opts = { root: f.root, token, outcome: "accepted", opId: "s", receipt: await proof(f) };
  const completion = send("settle", opts).then(result => ({ result }), error => ({ error }));
  const [socket] = await connection;
  try {
    const duplicate = await send("settle", opts).then(result => ({ result }), error => ({ error }));
    assert.equal(duplicate.error?.code, "ERR_GATE_IN_PROGRESS");
    await f.call("amend", { node: "a", expectedRev: 1, opId: "fence", patch: { exec: { prompt: "changed" } } });
  } finally { socket.end(); }
  assert.equal((await completion).error?.code, "ERR_STALE_FENCING_TOKEN");
  assert.equal(await fs.readFile(join(f.workspace, "gate-spawns"), "utf8"), "1");
  assert.equal((await f.call("status")).nodes.a.receiptUri, null);
});

test("a timed-out gate records the measured policy argv and exact fact digest, never worker success", async t => {
  const gateArgv = [process.execPath, "-e", "setInterval(()=>{},1000)"];
  const f = await fixture(t, [read("timed", { gateArgv, timeoutMs: 100 })]);
  const r = { ...await proof(f), gateArgv: ["/bin/true"], gateEvidence: { passed: true } };
  const token = await f.start("timed");
  const opts = { root: f.root, token, receipt: r, outcome: "accepted", opId: "finish" };
  const first = await send("settle", opts);
  assert.equal(first.status, "failed_logic");
  assert.deepEqual(await send("settle", opts), first);
  const uri = (await f.call("status")).nodes.timed.attempt.gateLogUri;
  const log = JSON.parse(await (await import("../scripts/graph/gc.mjs")).getBlob(f.root, uri));
  assert.deepEqual([log.argv, log.timedOut, log.factDigest, log.subjectDigest],
    [gateArgv, true, r.provenance.factDigest, r.provenance.factDigest]);
});

for (const fenced of [false, true]) test(`SIGKILL before the final settlement ${
  fenced ? "cannot replay measured evidence after fencing" : "reuses durable gate evidence, not another verifier spawn"}`, async t => {
  const f = await fixture(t, [read("a", { gateArgv: [process.execPath, "-e",
    "require('fs').appendFileSync('gate-count','x')"] })]);
  const opts = { root: f.root, token: await f.start("a"), receipt: await proof(f), opId: "s", outcome: "accepted" };
  const script = `
    import fs from "node:fs/promises";
    import {syncBuiltinESMExports} from "node:module";
    const original = fs.open.bind(fs);
    fs.open = async (path,...args) => {
      const fd = await original(path,...args);
      if (path === ${JSON.stringify(join(f.root, "runs", f.run, "wal/events.jsonl"))} && args[0] === "a") {
        const write = fd.writeFile.bind(fd);
        fd.writeFile = async data => {
          if (JSON.parse(data).type === "AttemptSettled") process.kill(process.pid, "SIGKILL");
          return write(data);
        };
      }
      return fd;
    };
    syncBuiltinESMExports();
    const {dispatch} = await import(${JSON.stringify(moduleUrl)});
    await dispatch("settle",JSON.parse(process.argv[1]));`;
  const child = spawn(process.execPath, ["--input-type=module", "-e", script, JSON.stringify(opts)]);
  assert.deepEqual(await once(child, "exit"), [null, "SIGKILL"]);
  const recovered = await f.call("resume");
  assert.match(recovered.nodes.a.attempt.measuredUri, /^cas:\/\/sha256\/[a-f0-9]{64}$/);
  assert.equal(recovered.nodes.a.status, "running");
  if (fenced) {
    await f.call("amend", { node: "a", expectedRev: 1, opId: "fence", patch: { exec: { prompt: "different" } } });
    await f.call("claim", { node: "a", expectedRev: 2, opId: "replacement" });
    const wal = join(f.root, "runs", f.run, "wal/events.jsonl");
    const before = await fs.readFile(wal);
    await assert.rejects(send("settle", opts), { code: "ERR_STALE_FENCING_TOKEN", exitCode: 49 });
    assert.deepEqual(await fs.readFile(wal), before);
    assert.equal(await fs.readFile(join(f.workspace, "gate-count"), "utf8"), "x");
    return;
  }
  await assert.rejects(send("settle", { ...opts, outcome: "blocked" }), { code: "ERR_OP_CONFLICT" });
  const result = await send("settle", opts);
  assert.equal(result.status, "accepted");
  assert.deepEqual(await send("settle", opts), result);
  assert.equal(await fs.readFile(join(f.workspace, "gate-count"), "utf8"), "x");
});
