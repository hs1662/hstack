import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { factDigest, reduce, validateReceipt as validate } from "../scripts/graph/reducer.mjs";
import { canonical } from "../scripts/graph/fingerprint.mjs";

const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const measuredGate = { argv:["node","--check","file"], envDigest:sha("host environment"), signal:null };
// These boundary fixtures act as the host that ran the gate. Trust-boundary
// tests below instead call validate directly, without this explicit binding.
const validateReceipt = (r, io) => validate(r, { ...io, gateLogUri:r.gateEvidence?.logUri });
const text = "α\r\nbeta\n\nlast\n";
let dir, workspaceRoot;
before(async () => {
  dir = await mkdtemp(join(tmpdir(), "hstack-reduce-"));
  workspaceRoot = join(dir, "work");
  await mkdir(workspaceRoot);
  await writeFile(join(workspaceRoot, "file"), text);
  await writeFile(join(workspaceRoot, "empty"), "");
  await writeFile(join(dir, "private"), text);
  await symlink("../private", join(workspaceRoot, "escape"));
  await symlink("..", join(workspaceRoot, "parent"));
  await symlink("file", join(workspaceRoot, "alias"));
});
after(() => rm(dir, { recursive: true, force: true }));

function storage() {
  const blobs = new Map();
  return {
    workspaceRoot,
    put: async (bytes) => {
      const uri = `cas://sha256/${sha(bytes)}`;
      blobs.set(uri, Buffer.from(bytes));
      return uri;
    },
    get: async (uri) => blobs.get(uri),
  };
}

async function seal(r, io) {
  r.provenance.factDigest = factDigest(r.provenance);
  r.gateEvidence = { logUri: await io.put(Buffer.from(JSON.stringify({
    ...measuredGate, exitCode: 0, factDigest: r.provenance.factDigest,
  }))) };
  return r;
}

async function receipt(i, io) {
  return seal({
    workerReportedStatus: "completed", inlineSummary: "Everything fine; nothing to report.",
    provenance: {
      evidenceSpans: [{ spanId: `s${i}`, path: "file", startLine: 2, endLine: 4, sha256: sha(text) }],
      claims: [{ claimId: `c${i}`, text: `finding ${i}`, spanIds: [`s${i}`] }],
      edgeCases: [{ edgeCaseId: `e${i}`, signature: "boundary", spanIds: [`s${i}`], detail: i }],
      failureEvidence: [{ failureId: `f${i}`, signature: `fault${i % 2}`, stderr: `raw ${i}` }],
    },
  }, io);
}

async function wave(n = 65) {
  const io = storage();
  const expected = Array.from({ length: n }, (_, i) => ({
    shardId: `node-${String(i).padStart(2, "0")}`, validEpoch: 1, obligationId: "audit",
  }));
  const leaves = await Promise.all(expected.map(async (tuple, i) => ({
    ...tuple, receipt: await receipt(i, io), get gateLogUri() { return this.receipt?.gateEvidence.logUri; },
  })));
  return { ...io, leaves, expected };
}

const bad = "ERR_FORGED_EVIDENCE";
const missing = "ERR_MISSING_EVIDENCE";
for (const [name, edit, code] of [
  ["omitted citations", p => delete p.claims[0].spanIds, missing],
  ["empty edge citations", p => p.edgeCases[0].spanIds = [], missing],
  ["unlisted claim span", p => p.claims[0].spanIds.push("absent"), bad],
  ["unlisted edge span", p => p.edgeCases[0].spanIds.push("absent"), bad],
  ["wrong file digest", p => p.evidenceSpans[0].sha256 = sha("other"), bad],
  ["fabricated file", p => p.evidenceSpans[0].path = "missing", bad],
  ["absolute path", p => p.evidenceSpans[0].path = join(workspaceRoot, "file"), bad],
  ["lexical traversal", p => p.evidenceSpans[0].path = "../private", bad],
  ["symlink escape", p => p.evidenceSpans[0].path = "escape", bad],
  ["parent symlink escape", p => p.evidenceSpans[0].path = "parent/private", bad],
  ["directory", p => p.evidenceSpans[0].path = ".", bad],
  ["zero line", p => p.evidenceSpans[0].startLine = 0, bad],
  ["fractional line", p => p.evidenceSpans[0].startLine = 1.5, bad],
  ["reversed interval", p => p.evidenceSpans[0].endLine = 1, bad],
  ["phantom line after final newline", p => p.evidenceSpans[0].endLine = 5, bad],
  ["empty file has no first line", p => Object.assign(p.evidenceSpans[0], { path: "empty", sha256: sha(""), startLine: 1, endLine: 1 }), bad],
  ["ambiguous local span", p => p.evidenceSpans.push({ ...p.evidenceSpans[0], startLine: 1 }), bad],
]) {
  test(`validator distinguishes ${name}`, async () => {
    const io = storage(), r = await receipt(0, io);
    edit(r.provenance);
    await seal(r, io);
    await assert.rejects(validateReceipt(r, io), { code });
  });
}

test("confined symlink and last actual line are valid even without a digest", async () => {
  const io = storage(), r = await receipt(0, io);
  const s = r.provenance.evidenceSpans[0];
  delete s.sha256;
  Object.assign(s, { path: "alias", startLine: 4 });
  await seal(r, io);
  assert.equal((await validateReceipt(r, io)).provenance.factDigest, r.provenance.factDigest);
});

for (const [name, edit, code] of [
  ["self-reported pass", r => r.gateEvidence = { passed: true }, missing],
  ["missing CAS log", r => r.gateEvidence.logUri = `cas://sha256/${"0".repeat(64)}`, bad],
  ["gate on different facts", async (r, io) => r.gateEvidence.logUri = await io.put(Buffer.from(JSON.stringify({ exitCode: 0, factDigest: sha("old") }))), bad],
  ["failed gate", async (r, io) => r.gateEvidence.logUri = await io.put(Buffer.from(JSON.stringify({ exitCode: 1, factDigest: r.provenance.factDigest }))), "ERR_GATE_FAILED"],
  ["changed content behind digest", r => r.provenance.claims[0].text += " altered", bad],
  ["missing facts", r => delete r.provenance.factDigest, missing],
  ["missing summary", r => delete r.inlineSummary, missing],
  ["missing worker status", r => delete r.workerReportedStatus, missing],
  ["worker blocked", r => r.workerReportedStatus = "blocked", missing],
  ["empty evidence despite claimed completion", async (r, io) => { for (const k of ["claims","edgeCases","failureEvidence","evidenceSpans"]) r.provenance[k] = []; await seal(r, io); }, missing],
]) {
  test(`validator refuses ${name}`, async () => {
    const io = storage(), r = await receipt(0, io);
    await edit(r, io);
    await assert.rejects(validateReceipt(r, io), { code });
  });
}

test("65-shard reduction groups every exception and failure verbatim and maps every input claim", async () => {
  const w = await wave();
  const p = w.leaves[64].receipt.provenance;
  p.claims[0].contradicts = "c0";
  p.claims.push({ ...w.leaves[64].receipt.provenance.claims[0], claimId: "unknown", contradicts: undefined });
  delete p.claims[1].contradicts;
  p.claims[1].unresolved = true;
  await seal(w.leaves[64].receipt, w);
  const out = await reduce(w);
  assert.equal(out.status, "complete");
  assert.equal(out.clusters.length, 9);
  assert.deepEqual(out.counts, { expected:65, seen:65, claims:66, edgeCases:65, failureEvidence:65 });
  for (const collection of ["edgeCases", "failureEvidence"]) {
    const values = out[collection].flatMap(g => g.entries.map(e => e.value));
    assert.deepEqual(values.sort((a,b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
      w.leaves.flatMap(l => l.receipt.provenance[collection]).sort((a,b) => JSON.stringify(a).localeCompare(JSON.stringify(b))));
  }
  assert.deepEqual(out.failureEvidence.map(g => [g.signature,g.entries.length]), [["fault0",33],["fault1",32]]);
  assert.deepEqual(out.dispositions.map(d => d.claimId).sort(), w.leaves.flatMap(l => l.receipt.provenance.claims.map(c => c.claimId)).sort());
  assert.equal(out.dispositions.find(d => d.claimId === "c64").kind, "contradicts");
  assert.equal(out.dispositions.find(d => d.claimId === "unknown").kind, "unresolved");
  for (const d of out.dispositions) {
    const raw = JSON.parse(await w.get(d.receiptUri));
    assert.equal(raw.provenance.claims[d.index].claimId, d.claimId);
  }
  assert.deepEqual(await reduce({ ...w, expected:w.expected.reverse(), leaves:w.leaves.reverse() }), out);
});

test("absent final cluster member cannot be filled by another obligation or stale epoch", async () => {
  const w = await wave();
  const lost = w.leaves.pop();
  w.leaves.push({ ...lost, validEpoch:0 }, { ...lost, obligationId:"other" });
  const out = await reduce(w);
  assert.equal(out.status, "partial");
  assert.deepEqual(out.missing, [w.expected[64]]);
  assert.equal(out.counts.seen, 64);
});

for (const [kind, id] of [["claims","claimId"],["edgeCases","edgeCaseId"],["failureEvidence","failureId"],["evidenceSpans","spanId"]]) {
  test(`cross-cluster ${id} collision survives both stages`, async () => {
    const w = await wave();
    const r = w.leaves.at(-1).receipt;
    r.provenance[kind][0][id] = w.leaves[0].receipt.provenance[kind][0][id];
    if (kind === "evidenceSpans") {
      r.provenance[kind][0].startLine = 1;
      for (const k of ["claims","edgeCases"]) r.provenance[k][0].spanIds = ["s0"];
    }
    await seal(r, w);
    const out = await reduce(w);
    assert.equal(out.status, "partial");
    assert.ok(out.issues.some(e => e.code === "ID_COLLISION" && e.collection === kind));
    assert.equal(out.counts.claims, 65);
    assert.equal(out.counts.failureEvidence, 65);
  });
}

test("exact duplicate facts are linked to the retained occurrence, not dropped", async () => {
  const w = await wave(2);
  w.leaves[1].receipt = structuredClone(w.leaves[0].receipt);
  const out = await reduce(w);
  assert.equal(out.status, "complete");
  assert.deepEqual(out.dispositions.map(d => d.kind), ["retained", "duplicateOf"]);
  assert.equal(out.dispositions[1].target.shardId, w.expected[0].shardId);
});

test("an absent contradiction target is unresolved, never accepted as a real reverse pointer", async () => {
  const w = await wave(2);
  w.leaves[0].receipt.provenance.claims[0].contradicts = "not_in_wave";
  await seal(w.leaves[0].receipt, w);
  const out = await reduce(w);
  assert.equal(out.status, "partial");
  assert.equal(out.dispositions[0].kind, "unresolved");
});

test("CAS receipt reverse pointer cannot be substituted or omitted", async () => {
  const w = await wave(2);
  const leaf = w.leaves[1];
  Object.defineProperty(leaf,"gateLogUri",{ value:leaf.receipt.gateEvidence.logUri });
  leaf.receiptUri = await w.put(Buffer.from(JSON.stringify(leaf.receipt)));
  delete leaf.receipt;
  assert.equal((await reduce(w)).status, "complete");
  const out = await reduce({ ...w, get: uri => uri === leaf.receiptUri ? Buffer.from("{}") : w.get(uri) });
  assert.equal(out.status, "partial");
  assert.deepEqual(out.missing, [w.expected[1]]);
});

test("two variants of the same tuple are partial and neither failure is discarded", async () => {
  const w = await wave(1);
  w.leaves.push({ ...w.leaves[0], receipt: await receipt(2,w) });
  const out = await reduce(w);
  assert.equal(out.status, "partial");
  assert.deepEqual(out.failureEvidence.flatMap(g => g.entries.map(e => e.value.stderr)).sort(), ["raw 0","raw 2"]);
});

test("forged leaf stays unaccepted but its claims and failures remain accountable", async () => {
  const w = await wave(3);
  w.leaves[1].receipt.provenance.evidenceSpans[0].endLine = 800;
  await seal(w.leaves[1].receipt, w);
  const out = await reduce(w);
  assert.equal(out.status, "partial");
  assert.deepEqual(out.missing, [w.expected[1]]);
  assert.equal(out.dispositions.find(d => d.claimId === "c1").kind, "unresolved");
  assert.equal(out.counts.failureEvidence, 3);
});

test("node summary over 4500 UTF-8 bytes is recoverable without truncation", async () => {
  const io = storage(), r = await receipt(0, io);
  r.inlineSummary = "한".repeat(1500);
  assert.equal((await validateReceipt(r, io)).inlineSummary, r.inlineSummary);
  r.inlineSummary += "!";
  const validated = await validateReceipt(r, io);
  assert.equal((await io.get(validated.inlineSummary)).toString(), r.inlineSummary);
  assert.equal((await validateReceipt(validated, io)).inlineSummary, validated.inlineSummary);
});

test("wave overflow preserves counts, every index, and all original summaries", async () => {
  const w = await wave(65);
  for (const leaf of w.leaves) leaf.receipt.inlineSummary = `${leaf.shardId}${"語".repeat(105)}`;
  const out = await reduce(w);
  assert.equal(out.status, "complete");
  assert.equal(out.counts.failureEvidence, 65);
  assert.equal(out.dispositions.length, 65);
  const rows = JSON.parse(await w.get(out.summaries));
  assert.deepEqual(rows.map(r => r.inlineSummary), w.leaves.map(l => l.receipt.inlineSummary));
});

for (const [name, edit, code] of [
  ["unsupported artifact version", r => r.schemaVersion = 2, bad],
  ["digest alias mismatch", r => r.provenance.evidenceSpans[0].blobDigest = sha("wrong"), bad],
  ["missing line interval", r => delete r.provenance.evidenceSpans[0].startLine, missing],
  ["absent path", r => delete r.provenance.evidenceSpans[0].path, missing],
  ["absent text", r => delete r.provenance.claims[0].text, missing],
  ["two different facts under a local ID", r => r.provenance.claims.push({ ...r.provenance.claims[0], text:"changed" }), bad],
  ["unlisted failure citation", r => r.provenance.failureEvidence[0].spanIds = ["bogus"], bad],
  ["contradictory relation directives", r => Object.assign(r.provenance.claims[0], { unresolved:true, duplicateOf:"other" }), bad],
  ["non-ID relation", r => r.provenance.claims[0].contradicts = true, bad],
  ["missing edge signature", r => delete r.provenance.edgeCases[0].signature, missing],
  ["missing failure identifier", r => delete r.provenance.failureEvidence[0].failureId, missing],
  ["missing node-summary object", r => r.inlineSummary = `cas://sha256/${sha("absent")}`, bad],
]) {
  test(`artifact integrity: ${name}`, async () => {
    const io = storage(), r = await receipt(0, io);
    edit(r);
    await seal(r, io);
    await assert.rejects(validateReceipt(r, io), { code });
  });
}

test("missing CAS read (ENOENT) cannot promote a referenced gate log", async () => {
  const io = storage(), r = await receipt(0,io);
  await assert.rejects(validateReceipt(r, { ...io, get() { throw Object.assign(new Error(), {code:"ENOENT"}); } }), {code:bad});
});

test("unrelated I/O failures are not reported as worker forgery", async () => {
  const io = storage(), r = await receipt(0,io);
  await assert.rejects(validateReceipt(r, { ...io, get() { throw Object.assign(new Error(), {code:"EIO"}); } }), {code:"EIO"});
});

test("an unterminated final line is a real line", async () => {
  const io = storage(), r = await receipt(0,io);
  await writeFile(join(workspaceRoot,"unterminated"), "one\ntwo");
  Object.assign(r.provenance.evidenceSpans[0], { path:"unterminated", startLine:2, endLine:2, sha256:sha("one\ntwo") });
  await seal(r,io);
  assert.equal((await validateReceipt(r,io)).provenance.factDigest,r.provenance.factDigest);
});

test("a repeated delivery of one receipt is idempotent", async () => {
  const w = await wave(1);
  w.leaves.push(structuredClone(w.leaves[0]));
  const out = await reduce(w);
  assert.equal(out.status,"complete");
  assert.equal(out.counts.claims,1);
});

test("no seen leaves reports the entire closed manifest, never vacuous success", async () => {
  const w = await wave(3);
  const out = await reduce({ ...w, leaves:[] });
  assert.equal(out.status,"partial");
  assert.deepEqual(out.missing,w.expected);
});

test("duplicate host expectations cannot be silently coalesced", async () => {
  const w = await wave(1);
  w.expected.push(structuredClone(w.expected[0]));
  const out = await reduce(w);
  assert.equal(out.status,"partial");
  assert.ok(out.issues.some(e => e.code === "DUPLICATE_EXPECTATION"));
});

test("an unsafe epoch is rejected rather than rounded", async () => {
  const w = await wave(1);
  w.expected[0].validEpoch = 2 ** 53;
  await assert.rejects(reduce(w),{code:"ERR_GRAPH_SCHEMA"});
});

test("two fields containing delimiters still yield distinct tuple keys", async () => {
  const w = await wave(2);
  for (const [i, fields] of [{shardId:"a|1|b",obligationId:"c"},{shardId:"a",obligationId:"b|1|c"}].entries()) {
    Object.assign(w.leaves[i],fields);
    Object.assign(w.expected[i],fields);
  }
  const out = await reduce(w);
  assert.equal(out.status,"complete");
  assert.equal(out.counts.seen,2);
});

test("spilled indexes reverse-resolve local claims and local grouped failures before final merge", async () => {
  const w = await wave(9);
  const r = w.leaves[8].receipt;
  r.provenance.claims[0].contradicts = "c0";
  await seal(r,w);
  const out = await reduce(w);
  const cluster = JSON.parse(await w.get(out.clusters[1].indexRoot));
  assert.deepEqual(cluster.dispositions.map(d => [d.claimId,d.kind]),[["c8","unresolved"]]);
  assert.deepEqual(cluster.failureEvidence.flatMap(g => g.entries.map(e => e.value.stderr)),["raw 8"]);
  assert.equal(out.dispositions.at(-1).target.shardId,"node-00");
});

test("a CAS index root restores the full final evidence index", async () => {
  const w = await wave(3);
  const out = await reduce(w);
  const index = JSON.parse(await w.get(out.indexRoot));
  assert.deepEqual(index.failureEvidence.flatMap(g => g.entries.map(e => e.value.stderr)).sort(),["raw 0","raw 1","raw 2"]);
  assert.deepEqual(index.dispositions.map(d => d.claimId),["c0","c1","c2"]);
});

test("unrelated claims cannot be collapsed by a worker duplicateOf hint", async () => {
  const w = await wave(2);
  w.leaves[1].receipt.provenance.claims[0].duplicateOf = "c0";
  await seal(w.leaves[1].receipt,w);
  const out = await reduce(w);
  assert.equal(out.status,"partial");
  assert.equal(out.dispositions[1].kind,"unresolved");
});

test("self-contradiction may not reverse-resolve to another occurrence of the same ID", async () => {
  const w = await wave(2);
  w.leaves[0].receipt.provenance.claims[0].contradicts = "c0";
  await seal(w.leaves[0].receipt,w);
  w.leaves[1].receipt = structuredClone(w.leaves[0].receipt);
  const out = await reduce(w);
  assert.deepEqual(out.dispositions.map(d => d.kind),["unresolved","unresolved"]);
});

for (const [name, fields, code] of [
  ["timed-out verifier", {timedOut:true}, "ERR_GATE_FAILED"],
  ["signaled verifier", {signal:"SIGTERM",exitCode:null}, "ERR_GATE_FAILED"],
  ["inconsistent measured exit", {exit:23}, bad],
  ["different measured subject", {subjectDigest:sha("elsewhere")}, bad],
]) {
  test(`a zero or absent exit code cannot hide a ${name}`, async () => {
    const io = storage(), r = await receipt(0, io);
    r.gateEvidence.logUri = await io.put(Buffer.from(JSON.stringify({
      exitCode:0, factDigest:r.provenance.factDigest, ...fields,
    })));
    await assert.rejects(validateReceipt(r,io),{ code });
  });
}

const context = (overrides = {}) => ({
  actualUsage:{inputTokens:100,outputTokens:7}, verified:true, W_eff:108, reservedTokens:8,
  contentTokens:{}, ...overrides,
});
test("adaptive node budget binds measured summary counts to exact bytes, not text length", async () => {
  const io = storage(), r = await receipt(0,io);
  r.inlineSummary = "한".repeat(5000);
  io.budgetContext = context({ contentTokens:{ [sha(r.inlineSummary)]:10 } });
  const out = await validateReceipt(r,io);
  assert.equal(out.inlineSummary,r.inlineSummary);
  assert.deepEqual([out.budget.B,out.budget.perIssueTokens,out.budget.totalTokens],[100,10,30]);
  r.inlineSummary += "!";
  assert.equal((await io.get((await validateReceipt(r,io)).inlineSummary)).toString(),r.inlineSummary);
});
for (const [name, ctx, limit] of [
  ["zero remaining context",context({reservedTokens:200}),0],
  ["hard per-issue ceiling",context({W_eff:10000}),512],
  ["fractional allowance floors",context({W_eff:109}),10],
]) test(name, async () => {
  const io = storage(), r = await receipt(0,io);
  io.budgetContext = {...ctx, contentTokens:{ [sha(r.inlineSummary)]:limit+1 }};
  const out = await validateReceipt(r,io);
  assert.equal(out.budget.perIssueTokens,limit);
  assert.equal((await io.get(out.inlineSummary)).toString(),r.inlineSummary);
});
for (const [name, budgetContext] of [
  ["absent usage",context({actualUsage:null})], ["unverified context",context({verified:false})],
  ["missing reservation",context({reservedTokens:null})],
]) test(`byte fallback only: ${name}`,async () => {
  const io = storage(), r = await receipt(0,io);
  r.budgetContext = context();
  const out = await validateReceipt(r,{...io,budgetContext,maxInlineBytesPerNode:1});
  for (const k of ["B","W_eff","reservedTokens","perIssueTokens","totalTokens","inlineTokens"]) assert.equal(out.budget[k],null,k);
  assert.equal((await io.get(out.inlineSummary)).toString(),r.inlineSummary);
});
test("wave charges exact issue and summary counts to a single allowance",async () => {
  const w = await wave(3), contentTokens = {};
  for (const l of w.leaves) {
    contentTokens[sha(l.receipt.inlineSummary)] = 6;
    for (const k of ["edgeCases","failureEvidence"]) contentTokens[sha(canonical(l.receipt.provenance[k][0]))] = 5;
  }
  const out = await reduce({...w,budgetContext:context({contentTokens})});
  const s = out.summaries.filter(x => !x.inlineSummary.startsWith("cas://")).length * 6;
  const entries = [...out.edgeCases,...out.failureEvidence].flatMap(g => g.entries);
  const tokens = s + entries.filter(e => e.value !== undefined).length * 5;
  assert.equal(out.budget.inlineTokens,tokens);
  assert.ok(tokens <= 30 && tokens >= 25);
  for (const e of entries.filter(e => e.value === undefined)) assert.ok(JSON.parse(await w.get(e.valueUri)).signature);
});
test("missing measurements externalize every issue without dropping occurrence pointers",async () => {
  const w = await wave(2);
  const out = await reduce({...w,budgetContext:context()});
  assert.equal(out.budget.inlineTokens,0);
  for(const g of [...out.edgeCases,...out.failureEvidence]) for(const e of g.entries) {
    assert.equal(e.value,undefined);
    assert.equal(JSON.parse(await w.get(e.valueUri)).signature,g.signature);
  }
  assert.deepEqual(out.counts,{ expected:2, seen:2, claims:2, edgeCases:2, failureEvidence:2 });
});
test("worker cannot supply its own verifier attestation or gate pointer",async () => {
  const io = storage(), r = await receipt(0,io);
  r.verifierEvidence = {...measuredGate,exit:0,logUri:r.gateEvidence.logUri};
  await assert.rejects(validate(r,io),{code:missing});
});
test("checked receipt reifies independently measured gate and real span results",async () => {
  const io = storage(), r = await receipt(0,io);
  delete r.provenance.evidenceSpans[0].sha256;
  await seal(r,io);
  r.verifierEvidence = {argv:["worker"],spanResolutions:[{path:"fake"}]};
  const out = await validateReceipt(r,io);
  assert.equal(out.workerClaim.workerReportedStatus,"completed");
  assert.deepEqual(out.verifierEvidence.argv,measuredGate.argv);
  assert.deepEqual([out.verifierEvidence.envDigest,out.verifierEvidence.exit,out.verifierEvidence.signal,out.verifierEvidence.subjectDigest],
    [measuredGate.envDigest,0,null,r.provenance.factDigest]);
  assert.deepEqual(out.verifierEvidence.spanResolutions,[{spanId:"s0",path:"file",startLine:2,endLine:4,actualLines:4,sha256:sha(text)}]);
});
test("a host-attached gate with no command measurements is insufficient",async () => {
  const io = storage(), r = await receipt(0,io);
  r.gateEvidence.logUri = await io.put(Buffer.from(JSON.stringify({factDigest:r.provenance.factDigest,exitCode:0})));
  await assert.rejects(validateReceipt(r,io),{code:missing});
});
test("independent events with similar signatures keep occurrence IDs, chronology and all source pointers",async () => {
  const w = await wave(3);
  for (const [i,l] of w.leaves.entries()) {
    l.receipt.provenance.failureEvidence = [{ failureId:"signal", signature:"fault", stderr:"same text",
      occurrenceId:i ? "later" : "first", seq:i ? 8 : 7, causalPredecessor:i ? "first" : null }];
    await seal(l.receipt,w);
  }
  const out = await reduce({...w,clusterSize:1});
  assert.equal(out.status,"complete");
  const rows = out.failureEvidence[0].entries;
  assert.deepEqual(rows.map(x=>[x.occurrenceId,x.seq,x.causalPredecessor,x.sources.length]),[["first",7,null,1],["later",8,"first",2]]);
});
test("same occurrence ID with different digest across clusters stays partial and lossless",async () => {
  const w = await wave(2);
  for (const l of w.leaves) {
    Object.assign(l.receipt.provenance.failureEvidence[0],{occurrenceId:"one",seq:1,causalPredecessor:null});
    await seal(l.receipt,w);
  }
  const out = await reduce({...w,clusterSize:1});
  assert.equal(out.status,"partial");
  assert.ok(out.issues.some(e=>e.code==="OCCURRENCE_COLLISION" && e.occurrenceId==="one"));
  assert.equal(out.failureEvidence.flatMap(g=>g.entries).length,2);
});

test("reopening an accepted receipt pins the measured file even when the worker omitted its digest",async () => {
  const w = await wave(1), leaf = w.leaves[0], r = leaf.receipt;
  const s = r.provenance.evidenceSpans[0];
  s.path = "mutable";
  delete s.sha256;
  await writeFile(join(workspaceRoot,"mutable"),text);
  await seal(r,w);
  const checked = await validateReceipt(r,w);
  const receiptUri = await w.put(Buffer.from(canonical(checked)));
  w.leaves = [{...w.expected[0],receiptUri}];
  assert.equal((await reduce(w)).status,"complete");
  await writeFile(join(workspaceRoot,"mutable"),text.replace("beta","zeta"));
  const out = await reduce(w);
  assert.equal(out.status,"partial");
  assert.ok(out.issues.some(e=>e.code===bad));
});

test("identical wording is not authority to collapse different claim IDs",async () => {
  const w = await wave(2);
  const a = w.leaves[0].receipt.provenance.claims[0], b = w.leaves[1].receipt.provenance.claims[0];
  b.duplicateOf = a.claimId;
  b.text = a.text;
  await seal(w.leaves[1].receipt,w);
  const out = await reduce(w);
  assert.equal(out.status,"partial");
  assert.equal(out.dispositions.at(-1).kind,"unresolved");
});
