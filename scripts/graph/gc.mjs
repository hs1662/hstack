import * as fs from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { graphError } from "./schema.mjs";
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
