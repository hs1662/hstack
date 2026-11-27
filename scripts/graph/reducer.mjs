// Graph v1 artifact verification and two-stage reduction. A pointer always
// names an occurrence (tuple, immutable receipt, collection offset), not just an ID.
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, realpath, stat } from "node:fs/promises";
import { isAbsolute, join, relative, sep, win32 } from "node:path";
import { canonical } from "./fingerprint.mjs";
import { graphError, isRecord } from "./schema.mjs";

const collections = { evidenceSpans: "spanId", claims: "claimId", edgeCases: "edgeCaseId", failureEvidence: "failureId" };
const missing = (field) => graphError("ERR_MISSING_EVIDENCE", `Missing evidence: ${field}`);
const forged = (field) => graphError("ERR_FORGED_EVIDENCE", `Invalid evidence: ${field}`);
const text = value => typeof value === "string" && value.trim().length > 0;
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const uriOf = bytes => `cas://sha256/${hash(bytes)}`;
const casUri = /^cas:\/\/sha256\/[a-f0-9]{64}$/;
const positive = n => Number.isSafeInteger(n) && n > 0;
const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const count = n => Number.isSafeInteger(n) && n >= 0;

function budgeting(io) {
  const c = io.budgetContext;
  const B = c?.verified === true && count(c.actualUsage?.inputTokens) && count(c.actualUsage?.outputTokens)
    && count(c.W_eff) && count(c.reservedTokens) ? Math.max(0, c.W_eff - c.reservedTokens) : null;
  return { mode:B === null ? "bytes" : "tokens", W_eff:B === null ? null : c.W_eff,
    reservedTokens:B === null ? null : c.reservedTokens, B, perIssueTokens:B === null ? null : Math.min(512,Math.floor(B/10)),
    totalTokens:B === null ? null : Number(3n*BigInt(B)/10n), inlineTokens:B === null ? null : 0,
    maxInlineBytesPerNode:io.maxInlineBytesPerNode ?? 4500, maxInlineBytesPerWave:io.maxInlineBytesPerWave ?? 15000 };
}

function charge(budget, io, bytes) {
  if (budget.mode === "bytes") return bytes.length <= budget.maxInlineBytesPerNode;
  const n = io.budgetContext.contentTokens?.[hash(bytes)];
  if (!count(n) || n > budget.perIssueTokens || n > budget.totalTokens-budget.inlineTokens) return false;
  budget.inlineTokens += n;
  return true;
}

export function factDigest(p) {
  const facts = {};
  for (const k of Object.keys(collections)) {
    if (!Array.isArray(p?.[k])) throw missing(k);
    facts[k] = p[k];
  }
  return hash(canonical(facts));
}

async function load(uri, io) {
  if (typeof uri !== "string" || !casUri.test(uri)) throw forged("CAS address");
  let bytes;
  try { bytes = await io.get(uri); }
  catch (e) {
    if (e.code === "ENOENT") throw forged(`nonexistent CAS object ${uri}`);
    throw e;
  }
  if (!(bytes instanceof Uint8Array) || uriOf(bytes) !== uri) throw forged(`CAS contents ${uri}`);
  return Buffer.from(bytes);
}

async function store(bytes, io) {
  const expected = uriOf(bytes);
  if (await io.put(bytes) !== expected) throw forged("CAS write address");
  await load(expected, io);
  return expected;
}

function parse(bytes, name) {
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch (err) {
    if (err instanceof SyntaxError || err.code === "ERR_ENCODING_INVALID_ENCODED_DATA") throw forged(name);
    throw err;
  }
}

function confined(root, path) {
  const rel = relative(root, path);
  return rel !== "" && rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

async function fileEvidence(root, path) {
  if (!text(path) || path.includes("\0") || win32.isAbsolute(path) || path.split(/[\\/]/).includes("..")) throw forged("file path");
  try {
    const resolved = await realpath(join(root, path));
    if (!confined(root, resolved)) throw forged(path);
    const fd = await open(resolved, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const opened = await fd.stat({ bigint: true });
      const current = await realpath(resolved);
      const linked = await stat(current, { bigint: true });
      if (!opened.isFile() || !confined(root, current) || opened.dev !== linked.dev || opened.ino !== linked.ino) throw forged(path);
      const digest = createHash("sha256");
      let lines = 0, last = 10;
      for await (const bytes of fd.createReadStream({ autoClose: false })) {
        digest.update(bytes);
        for (let i = bytes.indexOf(10); i >= 0; i = bytes.indexOf(10, i + 1)) lines++;
        last = bytes[bytes.length - 1];
      }
      return { lines: lines + Number(last !== 10), digest: digest.digest("hex") };
    } finally { await fd.close(); }
  } catch (err) {
    if (["ENOENT", "ELOOP", "ENOTDIR", "ENXIO"].includes(err.code)) throw forged(path);
    throw err;
  }
}

function identity(record, key) {
  if (!text(record?.[key])) throw missing(key);
  return record[key];
}

async function validate(r, io, files) {
  if (!isRecord(r) || !isRecord(r.provenance)) throw missing("provenance");
  if (r.schemaVersion !== undefined && r.schemaVersion !== 1) throw forged("schemaVersion");
  identity(r, "workerReportedStatus");
  if (typeof r.inlineSummary !== "string") throw missing("inlineSummary");
  const p = r.provenance;
  if (!text(p.factDigest)) throw missing("factDigest");
  if (p.factDigest !== factDigest(p)) throw forged("factDigest");
  if (!p.evidenceSpans.length || !(p.claims.length || p.edgeCases.length)) throw missing("cited source span");
  const spans = new Set(), spanResolutions = [];
  for (const s of p.evidenceSpans) {
    const id = identity(s, "spanId");
    if (spans.has(id)) throw forged(`duplicate spanId ${id}`);
    spans.add(id);
    const path = identity(s, "path");
    if (s.startLine == null || s.endLine == null) throw missing(`line range ${id}`);
    if (!positive(s.startLine) || !positive(s.endLine) || s.endLine < s.startLine) throw forged(`line range ${id}`);
    if (!files.has(path)) files.set(path, await fileEvidence(await realpath(io.workspaceRoot), path));
    const file = files.get(path);
    if (s.endLine > file.lines || ["sha256", "digest", "blobDigest"].some(k => k in s && s[k] !== file.digest)) throw forged(`file evidence ${id}`);
    spanResolutions.push({spanId:id,path,startLine:s.startLine,endLine:s.endLine,actualLines:file.lines,sha256:file.digest});
  }
  for (const [k, key] of Object.entries(collections).slice(1)) {
    const seen = new Map();
    for (const value of p[k]) {
      const id = identity(value, k !== "claims" && value?.occurrenceId !== undefined ? "occurrenceId" : key), digest = hash(canonical(value));
      if (("seq" in value && !count(value.seq)) || ("causalPredecessor" in value && value.causalPredecessor !== null && !text(value.causalPredecessor))) throw forged(`event chronology ${id}`);
      if (seen.has(id) && seen.get(id) !== digest) throw forged(`conflicting ${key} ${id}`);
      seen.set(id, digest);
      if (k === "claims") {
        identity(value, "text");
        if (["contradicts","duplicateOf"].some(f => f in value && !text(value[f]))
            || ("unresolved" in value && typeof value.unresolved !== "boolean")
            || [value.contradicts,value.duplicateOf,value.unresolved].filter(Boolean).length > 1) throw forged(`claim relation ${id}`);
      } else identity(value, "signature");
      if (k !== "failureEvidence" || "spanIds" in value) {
        if (!Array.isArray(value.spanIds) || !value.spanIds.length) throw missing(`spanIds ${id}`);
        if (value.spanIds.some(ref => !spans.has(ref))) throw forged(`unlisted span for ${id}`);
      }
    }
  }
  const uri = identity(io, "gateLogUri");
  if (r.gateEvidence?.logUri != null && r.gateEvidence.logUri !== uri) throw forged("worker gate pointer");
  const log = parse(await load(uri, io), "gate log");
  if (!isRecord(log) || (log.factDigest ?? log.subjectDigest) !== p.factDigest || ("subjectDigest" in log && log.subjectDigest !== p.factDigest)
      || ("exit" in log && log.exit !== log.exitCode)) throw forged("gate binding");
  if (log.timedOut === true || log.signal != null) throw graphError("ERR_GATE_FAILED", "Gate was terminated");
  if (!Number.isSafeInteger(log.exitCode)) throw forged("gate exit");
  if (log.exitCode !== 0) throw graphError("ERR_GATE_FAILED", `Gate exited ${log.exitCode}`);
  if (!Array.isArray(log.argv) || !log.argv.length || !text(log.argv[0]) || !log.argv.every(a => typeof a === "string")
      || !/^[a-f0-9]{64}$/.test(log.envDigest ?? "") || log.signal !== null) throw missing("measured gate argv, envDigest, signal");
  if (r.workerReportedStatus === "failed") throw graphError("ERR_GATE_FAILED", "Worker reported failure");
  if (r.workerReportedStatus !== "completed") throw missing("completed work");
  const budget = budgeting(io);
  const bytes = r.inlineSummary.startsWith("cas://") ? await load(r.inlineSummary, io) : Buffer.from(r.inlineSummary);
  const inlineSummary = charge(budget,io,bytes) ? bytes.toString() : await store(bytes,io);
  const workerClaim = { workerReportedStatus:r.workerReportedStatus, inlineSummary, provenance:p };
  const verifierEvidence = { logUri:uri, argv:log.argv, envDigest:log.envDigest, exit:log.exitCode, signal:log.signal,
    subjectDigest:p.factDigest, spanResolutions };
  return { schemaVersion:1,...workerClaim,workerClaim,verifierEvidence,gateEvidence:{logUri:uri},budget };
}

function checkIO(io) {
  if (!text(io?.workspaceRoot) || typeof io.put !== "function" || typeof io.get !== "function"
      || !count(io.maxInlineBytesPerNode ?? 4500) || !count(io.maxInlineBytesPerWave ?? 15000)) throw graphError("ERR_GRAPH_SCHEMA", "Invalid reducer I/O or budgets");
}

export async function validateReceipt(receipt, io) {
  checkIO(io);
  return validate(receipt, io, new Map());
}

function tuple({ shardId, validEpoch, obligationId }) {
  if (!text(shardId) || !Number.isSafeInteger(validEpoch) || validEpoch < 0 || !text(obligationId)) {
    throw graphError("ERR_GRAPH_SCHEMA", "Expected {shardId, validEpoch, obligationId}");
  }
  return { shardId, validEpoch, obligationId };
}
const keyOf = t => JSON.stringify([t.shardId,t.validEpoch,t.obligationId]);
const knownEvidenceError = e => ["ERR_MISSING_EVIDENCE","ERR_FORGED_EVIDENCE","ERR_GATE_FAILED"].includes(e.code);
function append(map, key, value) {
  if (!map.has(key)) map.set(key, []);
  map.get(key).push(value);
}

// Stage one reads original receipt bytes, never a worker's list of retained IDs.
async function readLeaf(leaf, io, files) {
  const member = tuple(leaf);
  let receipt, uri = null;
  try {
    if ("receiptUri" in leaf) {
      uri = leaf.receiptUri;
      receipt = parse(await load(uri, io), "receipt");
      if ("receipt" in leaf && canonical(leaf.receipt) !== canonical(receipt)) throw forged("receipt pointer");
    } else {
      if (!isRecord(leaf.receipt)) throw missing("receipt");
      const bytes = Buffer.from(canonical(leaf.receipt));
      receipt = parse(bytes, "receipt");
      uri = await store(bytes, io);
    }
    const gateLogUri = leaf.gateLogUri ?? (leaf.receiptUri ? receipt?.verifierEvidence?.logUri : null);
    const verified = await validate(receipt, { ...io, gateLogUri }, files);
    if (leaf.receiptUri && receipt.verifierEvidence
        && canonical(receipt.verifierEvidence) !== canonical(verified.verifierEvidence)) throw forged("accepted verifier evidence changed");
    return { member, uri, receipt, inlineSummary: verified.inlineSummary };
  } catch (e) {
    if (!knownEvidenceError(e)) throw e;
    return { member, uri, receipt, issue: { ...member, code:e.code, detail:e.message } };
  }
}

function cluster(rows, expected, issues) {
  const records = Object.fromEntries(Object.keys(collections).map(k => [k, []]));
  const summaries = [], sources = [], seen = new Set();
  for (const row of rows) {
    const { member, uri, receipt } = row;
    const key = keyOf(member), eligible = expected.has(key) && !row.issue;
    if (!expected.has(key)) issues.push({ ...member, code:"UNEXPECTED_TUPLE" });
    if (row.issue) issues.push(row.issue);
    if (eligible) seen.add(key);
    const source = { ...member, receiptUri:uri };
    sources.push(source);
    if (eligible) summaries.push({ ...source, inlineSummary:row.inlineSummary });
    for (const [k, id] of Object.entries(collections)) {
      const values = receipt?.provenance?.[k];
      if (!Array.isArray(values)) continue;
      for (const [index, value] of values.entries()) {
        const occurrence = k === "edgeCases" || k === "failureEvidence" ? value?.occurrenceId : undefined;
        records[k].push({ source:{ ...source,index }, id:occurrence ?? value?.[id] ?? null, value, eligible });
      }
    }
  }
  return { records, summaries, sources, seen };
}

function groupEvidence(entries) {
  const groups = new Map(), occurrences = new Map();
  for (const { id, value, source } of entries) {
    const occurrenceId = value?.occurrenceId ?? id, digest = hash(canonical(value));
    const key = canonical([occurrenceId,digest]);
    if (occurrenceId && occurrences.has(key)) {
      occurrences.get(key).sources.push(source);
      continue;
    }
    const entry = { source, sources:[source], value, occurrenceId, digest,
      causalPredecessor:value?.causalPredecessor ?? null, seq:value?.seq ?? null };
    occurrences.set(key,entry);
    append(groups, value?.signature ?? "", entry);
  }
  return [...groups.keys()].sort().map(signature => ({ signature, entries:groups.get(signature) }));
}

function indexRecords(records, issues) {
  const indexes = {};
  for (const k of Object.keys(collections)) {
    const ids = new Map();
    for (const r of records[k]) append(ids, r.id, r);
    for (const [id, rows] of ids) {
      if (new Set(rows.map(r => canonical(r.value))).size > 1) {
        issues.push({ code:"ID_COLLISION", collection:k, id });
        for (const r of rows) r.eligible = false;
      }
    }
    indexes[k] = ids;
  }
  return indexes;
}

function dispositionsFor(entries, byId, issues) {
  return entries.map(entry => {
    const d = { ...entry.source, claimId:entry.id };
    if (!entry.eligible || entry.value.unresolved) return { ...d, kind:"unresolved" };
    const claim = entry.value, repeated = byId.get(entry.id).find(r => r.eligible);
    const kind = claim.contradicts ? "contradicts" : claim.duplicateOf || repeated !== entry ? "duplicateOf" : "retained";
    if (kind === "retained") return { ...d, kind };
    const ref = claim[kind];
    const target = ref ? byId.get(ref)?.find(r => r.eligible && !r.value.unresolved) : repeated;
    // Duplicate links terminate at a retained input, never at a chain or cycle.
    if (!target || ref === entry.id || target === entry || (kind === "duplicateOf" && (target.id !== entry.id
        || target.value.duplicateOf || target.value.contradicts))) {
      issues.push({ code:"BROKEN_CLAIM_POINTER", source:entry.source, target:ref ?? entry.id });
      return { ...d, kind:"unresolved" };
    }
    return { ...d, kind, target:target.source };
  });
}

// Check cardinality and identity in both directions, against leaf bytes rather
// than against the generated index itself. Identical replayed leaves count once.
function audit(rows, mappings, issues) {
  const accounted = new Map();
  for (const { member, uri, receipt } of rows) {
    const claims = receipt?.provenance?.claims;
    if (!Array.isArray(claims)) continue;
    for (const [i, claim] of claims.entries()) accounted.set(JSON.stringify([keyOf(member),uri,i]), claim?.claimId ?? null);
  }
  for (const d of mappings) {
    const k = JSON.stringify([keyOf(d),d.receiptUri,d.index]);
    if (!accounted.has(k) || accounted.get(k) !== d.claimId) issues.push({ code:"BROKEN_REVERSE_POINTER", claimId:d.claimId });
    accounted.delete(k);
  }
  for (const claimId of accounted.values()) issues.push({ code:"MISSING_DISPOSITION", claimId });
}

function evidenceIndex(records, rows, issues) {
  const indexes = indexRecords(records, issues);
  const dispositions = dispositionsFor(records.claims, indexes.claims, issues);
  audit(rows, dispositions, issues);
  const edgeCases = groupEvidence(records.edgeCases), failureEvidence = groupEvidence(records.failureEvidence);
  const ids = new Map();
  for (const group of [...edgeCases,...failureEvidence]) for (const entry of group.entries) {
    if (entry.value?.occurrenceId) append(ids,entry.occurrenceId,entry.digest);
  }
  for (const [occurrenceId,digests] of ids) if (new Set(digests).size > 1) issues.push({code:"OCCURRENCE_COLLISION",occurrenceId});
  return { dispositions, edgeCases, failureEvidence };
}

// The CAS index is always lossless. Only its delivery view is budgeted.
async function deliver(index, summaries, io) {
  const budget = budgeting(io);
  const rendered = {};
  // In byte fallback, preserve small issue bodies but spill a large wave of
  // descriptions. Metadata, counts, pointers and IDs are never truncated.
  let remaining = budget.maxInlineBytesPerWave;
  for (const k of ["failureEvidence","edgeCases"]) {
    rendered[k] = [];
    for (const group of index[k]) {
      const entries = [];
      for (const entry of group.entries) {
        const { value,...pointer } = entry;
        const bytes = Buffer.from(canonical(value));
        const fits = budget.mode === "tokens" ? charge(budget,io,bytes)
          : bytes.length <= budget.maxInlineBytesPerNode && bytes.length <= remaining;
        if (fits && budget.mode === "bytes") remaining -= bytes.length;
        entries.push(fits ? entry : {...pointer,valueUri:await store(bytes,io)});
      }
      rendered[k].push({signature:group.signature,entries});
    }
  }
  let view;
  if (budget.mode === "tokens") {
    view = [];
    for (const row of summaries) {
      if (row.inlineSummary.startsWith("cas://")) { view.push(row); continue; }
      const bytes = Buffer.from(row.inlineSummary);
      view.push(charge(budget,io,bytes) ? row : {...row,inlineSummary:await store(bytes,io)});
    }
  } else {
    const bytes = Buffer.from(canonical(summaries));
    view = bytes.length <= remaining ? summaries : await store(bytes,io);
  }
  return {...rendered,budget,summaries:view};
}

export async function reduce(io) {
  checkIO(io);
  const size = io.clusterSize ?? 8;
  if (!Array.isArray(io.expected) || !io.expected.length || !Array.isArray(io.leaves) || !positive(size)) {
    throw graphError("ERR_GRAPH_SCHEMA", "A non-empty closed manifest, leaves and positive clusterSize are required");
  }
  const expected = new Map(), issues = [];
  for (const item of io.expected) {
    const member = tuple(item), key = keyOf(member);
    if (expected.has(key)) issues.push({ ...member, code:"DUPLICATE_EXPECTATION" });
    expected.set(key, member);
  }
  const files = new Map(), byTuple = new Map();
  for (const leaf of io.leaves) {
    const row = await readLeaf(leaf, io, files);
    append(byTuple, keyOf(row.member), row);
  }
  const keys = [...new Set([...expected.keys(),...byTuple.keys()])].sort();
  const parts = [], rows = [], clusters = [];
  for (let i = 0; i < keys.length; i += size) {
    const batch = [];
    for (const key of keys.slice(i,i+size)) {
      const variants = new Map();
      for (const r of byTuple.get(key) ?? []) {
        variants.set(canonical([r.uri,r.issue ?? null]), r);
      }
      if (variants.size > 1) issues.push({ ...variants.values().next().value.member, code:"TUPLE_COLLISION" });
      batch.push(...[...variants].sort(([a],[b]) => compare(a,b)).map(([,v]) => v));
    }
    rows.push(...batch);
    const part = cluster(batch, expected, issues);
    const localIssues = [];
    const local = evidenceIndex(part.records, batch, localIssues);
    const indexRoot = await store(Buffer.from(canonical({ ...local, issues:localIssues })), io);
    clusters.push({ sources:part.sources, claimCount:local.dispositions.length, indexRoot });
    parts.push(part);
  }
  // Stage two reconciles all IDs in the wave, including duplicates and
  // contradiction targets which are invisible to a single cluster.
  const records = Object.fromEntries(Object.keys(collections).map(k => [k, parts.flatMap(c => c.records[k])]));
  const seen = new Set(parts.flatMap(c => [...c.seen]));
  const absent = keys.filter(k => expected.has(k) && !seen.has(k)).map(k => expected.get(k));
  const counts = { expected:expected.size, seen:seen.size, claims:records.claims.length,
    edgeCases:records.edgeCases.length, failureEvidence:records.failureEvidence.length };
  const index = { clusters, ...evidenceIndex(records, rows, issues) };
  const delivery = await deliver(index,parts.flatMap(c => c.summaries),io);
  return { status:absent.length || issues.length ? "partial" : "complete", missing:absent,
    issues:issues.sort((a,b) => compare(canonical(a),canonical(b))), counts, ...index,
    indexRoot:await store(Buffer.from(canonical(index)), io), ...delivery };
}
