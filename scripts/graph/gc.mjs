import * as fs from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { graphError } from "./schema.mjs";
import { commonDir, gitOk } from "./git.mjs";
import { acceptedRef, candRef, nodeKey, pinRef } from "./worktree.mjs";
import { withLock } from "./lock.mjs";
import { markJournal } from "./wal-store.mjs";

export const corrupt = (message) => graphError("ERR_JOURNAL_CORRUPT", message);
export const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
export const casUri = /^cas:\/\/sha256\/([a-f0-9]{64})$/;
export const validateUris = (refs) =>
  Array.isArray(refs) && refs.every(ref => typeof ref === "string" && casUri.test(ref));

export async function syncDir(path) {
  const fd = await fs.open(path, "r");
  try { await fd.sync(); } finally { await fd.close(); }
}

// Namespace is private to the engine; reject links rather than traverse them.
export async function directory(root, parts, create = true) {
  let path = root;
  for (const part of parts) {
    const parent = path;
    path = join(parent, part);
    const st = await fs.lstat(path).catch(err => {
      if (err.code !== "ENOENT") throw err;
      return null;
    });
    if (st && !st.isDirectory()) throw corrupt(`Not a store directory: ${path}`);
    if (!st) {
      if (!create) return;
      try { await fs.mkdir(path, { mode: 0o700 }); } catch (err) {
        if (err.code !== "EEXIST") throw err;
        if (!(await fs.lstat(path)).isDirectory()) throw corrupt(`Not a store directory: ${path}`);
      }
      await syncDir(parent);
    }
  }
  return path;
}

export async function entries(path) {
  try { return await fs.readdir(path); } catch (err) {
    if (err.code !== "ENOENT") throw err;
    return [];
  }
}

export async function optionalFile(path) {
  try {
    if (!(await fs.lstat(path)).isFile()) throw corrupt(`Not a store file: ${path}`);
    return await fs.readFile(path);
  } catch (err) {
    if (err.code !== "ENOENT") throw err;
    return null;
  }
}

export function uncertain(runId, cause) {
  return Object.assign(graphError("ERR_IO_UNCERTAIN", `Run ${runId}: durability unknown; offline inspection required`),
    { status: "IO_UNCERTAIN", outcome: "IO_UNKNOWN", cause });
}

const intentName = /^\.io-intent\.([a-f0-9-]{36})\.(.+)$/;

// The lock grave is positive evidence of owner death. An intent left by a
// normally released lock is NOT a killed writer and must never be auto-cleared.
export async function pendingIntent(root, runId) {
  const names = await entries(root);
  if (names.includes(`.io-uncertain.${runId}`)) throw uncertain(runId);
  const abandoned = [];
  for (const name of names) {
    const match = intentName.exec(name);
    if (match?.[2] !== runId) continue;
    const token = match[1];
    if (!(await entries(join(root, "graveyard"))).some(n => n.startsWith(`lock.${token}.`))) {
      // A lock-free read can race normal completion; don't poison after release.
      const owner = await optionalFile(join(root, "lock", "owner.json"));
      if (owner && JSON.parse(owner).lockToken === token) {
        throw graphError("ERR_LOCK_BUSY", "Run durability decision in progress");
      }
      if ((await entries(root)).includes(name)) throw uncertain(runId);
    } else abandoned.push(join(root, name));
  }
  return abandoned;
}

// Under the global lock. The durable intent precedes *all* run writes. If
// publishing a poison marker also fails, retaining the intent is sufficient:
// the caller releases its lock normally before exposing the uncertain outcome.
export async function withIntent(root, runId, fn) {
  const abandoned = await pendingIntent(root, runId);
  const { lockToken } = JSON.parse(await fs.readFile(join(root, "lock", "owner.json")));
  const path = join(root, `.io-intent.${lockToken}.${runId}`);
  await fs.mkdir(path, { mode: 0o700 });
  try {
    await syncDir(root);
    for (const prior of abandoned) await fs.rmdir(prior);
    const result = await fn({ abandoned: abandoned.length > 0 });
    // No further commit IO after disarming. A reappearing intent after power
    // loss conservatively holds rather than trusting an ambiguous device.
    await fs.rmdir(path);
    return result;
  } catch (err) {
    if (["EIO", "ENOSPC", "ERR_IO_UNCERTAIN"].includes(err.code)) {
      try {
        await fs.rename(path, join(root, `.io-uncertain.${runId}`));
        await syncDir(root);
      } catch {
        // Never clear the already-armed intent just because poisoning failed.
      }
      throw uncertain(runId, err);
    }
    await fs.rmdir(path);
    throw err;
  }
}

export const nextCandidateId = s => `g${s.integrationGeneration}.${1 + Object.values(s.candidates)
  .filter(c => c.generation === s.integrationGeneration).length}`;

// Only names derived from the verified run identity are eligible, never arbitrary paths in a record.
export async function reclaimRefLocks(s) {
  if (s?.schemaVersion !== 2) return;
  if (typeof s.runId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(s.runId)) throw corrupt("Invalid ref namespace");
  const dir = await commonDir(s.workspace), refs = [candRef(s.runId, nextCandidateId(s))];
  if (s.pendingPublish?.ref === acceptedRef(s.runId)) refs.push(s.pendingPublish.ref);
  for (const n of Object.values(s.nodes)) {
    if (n.kind === "write" && n.status === "running") refs.push(pinRef(s.runId, nodeKey(n.id), n.attempt.epoch));
  }
  for (const c of Object.values(s.candidates)) {
    if (["built", "gating"].includes(c.state) && /^g\d+(?:\.\d+)+$/.test(c.candidateId)) refs.push(candRef(s.runId, c.candidateId));
  }
  for (const ref of refs) {
    const parent = await directory(dir, dirname(ref).split("/"), false);
    if (!parent) continue;
    try { await fs.unlink(join(dir, `${ref}.lock`)); }
    catch (error) { if (error.code === "ENOENT") continue; throw error; }
    await syncDir(parent);
  }
}

export async function updateRef(workspace, args) {
  try { await gitOk(["update-ref", "--no-deref", ...args], { cwd: workspace }); }
  catch (error) {
    if (error.code === "ERR_GIT_FAILED" && /\.lock['":].*File exists/.test(error.stderr)) throw graphError("ERR_LOCK_BUSY", "Git ref lock is busy");
    throw error;
  }
}

// Only mutable indexes use rename. For immutable objects, link is the POSIX
// no-replace publication point; even a preexisting corrupted inode is not replaced.
export async function atomicFile(path, bytes, mutable = false) {
  const dir = dirname(path);
  const tmp = join(dir, `.tmp-${randomUUID()}`);
  const fd = await fs.open(tmp, "wx", 0o600);
  try {
    try { await fd.writeFile(bytes); await fd.sync(); } finally { await fd.close(); }
    if (mutable) await fs.rename(tmp, path);
    else {
      try { await fs.link(tmp, path); } catch (err) {
        if (err.code !== "EEXIST") throw err;
        if (!(await optionalFile(path))?.equals(Buffer.from(bytes))) throw corrupt(`Immutable file mismatch: ${path}`);
      }
    }
    await syncDir(dir);
  } finally { await fs.rm(tmp, { force: true }); }
}

export async function putBlob(root, bytes) {
  const hash = digest(bytes);
  const dir = await directory(root, ["cas", "sha256", hash.slice(0, 2)]);
  await atomicFile(join(dir, hash), bytes);
  return `cas://sha256/${hash}`;
}

export async function getBlob(root, uri) {
  const hash = typeof uri === "string" && casUri.exec(uri)?.[1];
  if (!hash) throw corrupt("Invalid CAS address");
  const parts = ["cas", "sha256", hash.slice(0, 2)];
  await directory(root, parts, false);
  const bytes = await optionalFile(join(root, ...parts, hash));
  if (!bytes || digest(bytes) !== hash) throw corrupt(`Missing or damaged ${uri}`);
  return bytes;
}

// A bare CAS URI in JSON is an edge. Other bytes (including raw logs) are leaves.
export function refsIn(value) {
  const pending = [value], refs = new Set();
  while (pending.length) {
    const item = pending.pop();
    if (typeof item === "string" && casUri.test(item)) refs.add(item);
    if (item && typeof item === "object") {
      for (const [key, child] of Object.entries(item)) {
        if (casUri.test(key)) refs.add(key);
        pending.push(child);
      }
    }
  }
  return refs;
}

export async function trace(root, roots, marked = new Set()) {
  const work = [...roots];
  while (work.length) {
    const uri = work.pop();
    if (marked.has(uri)) continue;
    const bytes = await getBlob(root, uri);
    marked.add(uri);
    let value;
    try { value = JSON.parse(bytes.toString("utf8")); } catch (err) {
      if (err instanceof SyntaxError) continue;
      throw err;
    }
    for (const child of refsIn(value)) work.push(child);
  }
}

async function markPins(root, histories, marked) {
  await directory(root, ["gcroots"], false);
  const dir = join(root, "gcroots");
  for (const name of await entries(dir)) {
    if (!name.endsWith(".pin.json")) continue;
    const runId = name.slice(0, -9);
    let pin;
    try { pin = JSON.parse(await optionalFile(join(dir, name))); } catch (err) {
      if (err instanceof SyntaxError) throw corrupt(`Malformed pin index: ${name}`);
      throw err;
    }
    if (pin?.schemaVersion !== 1 || pin.runId !== runId || !Number.isSafeInteger(pin.seq) ||
        pin.seq < 0 || pin.seq > (histories.get(runId) ?? 0) ||
        !validateUris(pin.refs) || !validateUris(pin.staging)) throw corrupt(`Invalid pin index: ${name}`);
    await trace(root, [...pin.refs, ...pin.staging], marked);
  }
}

const trashName = /^[a-f0-9]{64}\.[a-f0-9-]{36}$/;
const tmpName = /^\.tmp-[a-f0-9-]{36}$/;

export async function collectGarbage(root) {
  return withLock(root, async () => {
    const marked = new Set(), histories = new Map();
    // A first transaction can be uncertain before it even publishes runs/<id>.
    for (const name of await entries(root)) {
      if (name.startsWith(".io-uncertain.")) throw uncertain(name.slice(".io-uncertain.".length));
      const match = intentName.exec(name);
      if (match) await pendingIntent(root, match[2]);
    }
    await directory(root, ["runs"], false);
    for (const id of await entries(join(root, "runs"))) {
      histories.set(id, await markJournal(root, id, marked));
    }
    await markPins(root, histories, marked);

    // Only begin moving after the entire mark pass verified every root.
    const trash = await directory(root, ["trash"]);
    for (const name of await entries(trash)) {
      if (trashName.test(name)) await fs.unlink(join(trash, name));
    }
    let removed = 0;
    await directory(root, ["cas", "sha256"], false);
    for (const prefix of await entries(join(root, "cas", "sha256"))) {
      if (!/^[a-f0-9]{2}$/.test(prefix)) continue;
      const dir = await directory(root, ["cas", "sha256", prefix], false);
      let moved = false;
      for (const hash of await entries(dir)) {
        if (tmpName.test(hash)) {
          await fs.unlink(join(dir, hash)); // interrupted publication, never an address
          continue;
        }
        if (!/^[a-f0-9]{64}$/.test(hash) || !hash.startsWith(prefix) || marked.has(`cas://sha256/${hash}`)) continue;
        await fs.rename(join(dir, hash), join(trash, `${hash}.${randomUUID()}`));
        moved = true;
        removed++;
      }
      if (moved) await syncDir(dir);
    }
    await syncDir(trash);
    for (const name of await entries(trash)) {
      if (trashName.test(name)) await fs.unlink(join(trash, name));
    }
    await syncDir(trash);
    return { removed, retained: marked.size };
  });
}
