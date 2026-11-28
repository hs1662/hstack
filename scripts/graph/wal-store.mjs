import * as fs from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { canonical } from "./fingerprint.mjs";
import { graphError, isRecord, nonempty } from "./schema.mjs";
import { withLock } from "./lock.mjs";
import {
  atomicFile, casUri, corrupt, digest, directory, entries, getBlob, optionalFile,
  pendingIntent, putBlob, refsIn, syncDir, trace, uncertain, validateUris, withIntent,
} from "./gc.mjs";

function paths(root, runId) {
  if (typeof runId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(runId)) {
    throw graphError("ERR_GRAPH_SCHEMA", "Invalid run ID");
  }
  const run = join(root, "runs", runId);
  return {
    root, runId, run, snapshots: join(run, "snapshots"),
    file: join(run, "wal", "events.jsonl"), pin: join(root, "gcroots", `${runId}.pin.json`),
  };
}

function parse(bytes, label) {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (err) {
    throw corrupt(`Invalid ${label}: ${err.message}`);
  }
}

const checksum = (frame) => digest(canonical(frame));
const hex = /^[a-f0-9]{64}$/;

// V1 commits a complete addressed post-image: replay is replacement, not
// re-execution of the command that measured time, issued tokens, or ran gates.
export function foldCommitted(prev, frame, state) {
  const { recordHash, ...header } = frame;
  if (header.schemaVersion !== 1 || header.seq !== (prev?.lastSeq ?? 0) + 1 ||
      header.prevHash !== (prev?.lastHash ?? null) || checksum(header) !== recordHash ||
      !isRecord(state) || header.body?.stateUri !== `cas://sha256/${checksum(state)}`) {
    throw corrupt("Invalid v1 post-image transition");
  }
  return { lastSeq: header.seq, lastHash: recordHash, state };
}

function verifySnapshot(bytes, frame, acceptLegacy = false) {
  let s = parse(bytes, "snapshot");
  if (acceptLegacy && isRecord(s) && isRecord(s.state) &&
      Object.keys(s).sort().join(",") === "recordHash,schemaVersion,seq,state") {
    s = { ...s, lastSeq: s.seq, lastHash: s.recordHash, stateHash: checksum(s.state) };
  }
  if (!frame || s?.schemaVersion !== 1 || s.lastSeq !== frame.seq || s.lastHash !== frame.recordHash ||
      !isRecord(s.state) || !hex.test(s.stateHash) || `cas://sha256/${s.stateHash}` !== frame.body.stateUri ||
      checksum(s.state) !== s.stateHash) throw corrupt("Snapshot does not match its committed post-image");
  return s;
}

// `roots` keeps first-seen order; `rootCounts[i]` is its size after frame i + 1,
// so the roots first seen up to a checkpoint are a prefix of that order.
function framesFrom(bytes) {
  const frames = [], ops = new Map(), roots = new Set(), rootCounts = [];
  let offset = 0;
  for (let end; (end = bytes.indexOf(10, offset)) !== -1; offset = end + 1) {
    const frame = parse(bytes.subarray(offset, end), `WAL at byte ${offset}`);
    if (!isRecord(frame)) throw corrupt(`Invalid frame at ${offset}`);
    const { recordHash, ...data } = frame;
    const { body, opId, type, payloadDigest } = data;
    if (data.schemaVersion !== 1 || data.seq !== frames.length + 1 ||
        data.prevHash !== (frames.at(-1)?.recordHash ?? null) || !hex.test(payloadDigest) ||
        typeof type !== "string" || !type || typeof opId !== "string" || !opId || ops.has(opId) ||
        !isRecord(body) || !Object.hasOwn(body, "response") || !casUri.test(body.stateUri) ||
        !validateUris(body.refs)) throw corrupt(`Invalid WAL frame at byte ${offset}`);
    try {
      if (recordHash !== checksum(data)) throw corrupt(`WAL checksum mismatch at byte ${offset}`);
    } catch (err) {
      if (err.code === "ERR_GRAPH_FINGERPRINT") throw corrupt(`Noncanonical frame at ${offset}`);
      throw err;
    }
    frames.push(frame);
    ops.set(opId, frame);
    for (const uri of refsIn(body)) roots.add(uri);
    rootCounts.push(roots.size);
  }
  return { frames, ops, roots, rootCounts, offset };
}

function assertPublic(value) {
  const pending = [value];
  while (pending.length) {
    const item = pending.pop();
    if (!item || typeof item !== "object") continue;
    for (const [key, child] of Object.entries(item)) {
      if (/^(?:attemptToken|token|nonce|secretToken)$/i.test(key) && child != null) {
        throw graphError("ERR_SECRET_IN_RECORD", "Raw tokens belong in private dispatch instructions");
      }
      pending.push(child);
    }
  }
}

// Read the checkpoint names first: a lock-free reader may then observe *newer*
// WAL commits, never a checkpoint from the future relative to its WAL bytes.
// A commit writes checkpoint k only after tracing every root of frames <= k, and
// getBlob verifies digests on each read. So a transaction (`incremental`) traces
// only roots first seen after the verified checkpoint; resume and GC trace all.
async function inspect(p, { marked = new Set(), incremental = false } = {}) {
  await directory(p.root, ["runs", p.runId, "wal"], false);
  await directory(p.root, ["runs", p.runId, "snapshots"], false);
  const names = await entries(p.snapshots);
  const latest = names.reduce((max, name) => /^[1-9]\d*\.json$/.test(name)
    ? Math.max(max, Number(name.slice(0, -5))) : max, 0);
  const bytes = await optionalFile(p.file) ?? Buffer.alloc(0);
  const log = framesFrom(bytes);
  let head = null;
  if (latest) {
    head = verifySnapshot(await optionalFile(join(p.snapshots, `${latest}.json`)), log.frames[latest - 1], true);
  }
  const roots = [...log.roots];
  const verified = incremental && latest ? log.rootCounts[latest - 1] : 0;
  for (const uri of roots.slice(0, verified)) marked.add(uri);
  await trace(p.root, roots.slice(verified), marked);
  for (let i = latest; i < log.frames.length; i++) {
    const frame = log.frames[i];
    const state = parse(await getBlob(p.root, frame.body.stateUri), "committed post-state");
    head = foldCommitted(head, frame, state);
  }
  const last = log.frames.at(-1);
  return { ...log, bytes, marked, state: head?.state ?? null, last, checkpointSeq: latest };
}

// Internal collector entry point: caller already holds the global lock.
export async function markJournal(root, runId, marked) {
  return (await inspect(paths(root, runId), { marked })).frames.length;
}

async function pins(p, log, staging = []) {
  const index = { schemaVersion: 1, runId: p.runId, seq: log.last?.seq ?? 0, refs: [...log.roots], staging };
  await directory(p.root, ["gcroots"]);
  await atomicFile(p.pin, JSON.stringify(index), true);
}

async function checkpoint(p, frame, state) {
  await directory(p.root, ["runs", p.runId, "snapshots"]);
  const path = join(p.snapshots, `${frame.seq}.json`);
  // The global lock allocates one new sequence number; never replace a checkpoint.
  if (await optionalFile(path)) throw corrupt(`Checkpoint already exists at ${frame.seq}`);
  await atomicFile(path, canonical({ schemaVersion: 1, lastSeq: frame.seq, lastHash: frame.recordHash,
    stateHash: checksum(state), state }), true);
  try {
    verifySnapshot(await optionalFile(path), frame);
  } catch (err) {
    throw uncertain(p.runId, err);
  }
}

async function stabilize(p, log) {
  if (!log.bytes.length) return;
  if (log.offset !== log.bytes.length) {
    // Preserve all original bytes, including invalid UTF-8, before truncation.
    await atomicFile(`${p.file}.damaged.${randomUUID()}`, log.bytes);
  }
  const fd = await fs.open(p.file, "r+");
  try {
    if (log.offset !== log.bytes.length) await fd.truncate(log.offset);
    // A previous process can die between its last write and its fsync.
    await fd.sync();
  } finally { await fd.close(); }
  await syncDir(dirname(p.file));
}

export async function readState(root, runId) {
  const p = paths(root, runId);
  await pendingIntent(root, runId);
  return (await inspect(p)).state;
}

// Last writer wins; progress is not state, authorization, or a GC root.
export async function writeHeartbeats(root, runId, progress) {
  paths(root, runId);
  if (!isRecord(progress)) throw graphError("ERR_GRAPH_SCHEMA", "Expected a heartbeat map");
  const bytes = canonical(progress);
  assertPublic(progress);
  if (!await directory(root, ["runs", runId], false)) throw graphError("ERR_RUN_NOT_FOUND", "Unknown run");
  return withLock(root, () => withIntent(root, runId, async () => {
    const runtime = await directory(root, ["runs", runId, "runtime"]);
    await atomicFile(join(runtime, "heartbeats.json"), bytes, true);
  }));
}

export async function recover(root, runId) {
  const p = paths(root, runId);
  return withLock(root, async () => {
    await pendingIntent(root, runId);
    const log = await inspect(p);
    return withIntent(root, runId, async () => {
      await stabilize(p, log);
      if (log.last && log.checkpointSeq !== log.last.seq) await checkpoint(p, log.last, log.state);
      if (log.last || await optionalFile(p.pin)) await pins(p, log);
      return log.state;
    });
  });
}

export async function transaction(root, runId, { opId, type, payload, guard, beforeReplay }, callback) {
  const p = paths(root, runId);
  nonempty(opId, "opId");
  nonempty(type, "type");
  const payloadDigest = checksum(["hstack.transaction/v1", type, payload]);
  return withLock(root, async () => {
    await pendingIntent(root, runId);
    const log = await inspect(p, { incremental: true });
    if (guard) await guard(log.state); // Fencing must apply even to a cached receipt.
    const prior = log.ops.get(opId);
    if (prior && prior.payloadDigest !== payloadDigest) {
      throw graphError("ERR_OP_CONFLICT", "Operation ID already committed with different input");
    }
    if (prior && beforeReplay) await beforeReplay(log.state);
    return withIntent(root, runId, async () => {
    if (prior || log.offset !== log.bytes.length) await stabilize(p, log);
    if (prior) return prior.body.response;

    const staging = new Set();
    let pending = Promise.resolve(), open = true;
    const io = {
      get: (uri) => getBlob(root, uri),
      put(bytes) {
        if (!open) throw graphError("ERR_TRANSACTION_CLOSED", "Transaction already closed");
        // Own the bytes before yielding; serialize pin updates for Promise.all callers.
        const owned = Buffer.from(bytes);
        pending = pending.then(async () => {
          const uri = await putBlob(root, owned);
          staging.add(uri);
          await pins(p, log, [...staging]);
          return uri;
        });
        return pending;
      },
    };
    let frame, state;
    try {
      let output;
      try { output = await callback(log.state, io); }
      finally { open = false; await pending; }
      const data = JSON.parse(canonical(output));
      state = data.state;
      if (!isRecord(state) || !Object.hasOwn(data, "response") || !validateUris(data.refs ?? []) ||
          (data.body !== undefined && !isRecord(data.body))) {
        throw graphError("ERR_GRAPH_SCHEMA", "Invalid transaction result");
      }
      assertPublic(data);
      const stateUri = await putBlob(root, Buffer.from(canonical(state)));
      // Readers use the union of all frame refs, so a frame names only URIs new
      // to this run's log; the same union is what full-refs frames produced.
      const refs = [...new Set([...refsIn(state), ...(data.refs ?? [])])].filter(uri => !log.roots.has(uri));
      const body = { ...data.body, refs, stateUri, response: data.response };
      await trace(root, refsIn(body), log.marked);
      const eventType = nonempty(data.eventType ?? type, "eventType");
      const header = { schemaVersion: 1, seq: log.frames.length + 1,
        prevHash: log.last?.recordHash ?? null, opId, payloadDigest, type: eventType, body };
      frame = { ...header, recordHash: checksum(header) };
    } catch (err) {
      if (staging.size && !["EIO", "ENOSPC"].includes(err.code)) await pins(p, log);
      throw err;
    }
    await directory(root, ["runs", runId, "wal"]);
    const fd = await fs.open(p.file, "a", 0o600);
    try {
      await fd.writeFile(`${canonical(frame)}\n`);
      await fd.sync();
    } finally { await fd.close(); }
    await syncDir(dirname(p.file));
    for (const uri of refsIn(frame.body)) log.roots.add(uri);
    await pins(p, { ...log, last: frame });
    await checkpoint(p, frame, state);
    return frame.body.response;
    });
  });
}
