import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readdir, readlink, rm } from "node:fs/promises";
import { dirname, isAbsolute, join, posix } from "node:path";
import { covers } from "./admission.mjs";
import { commitTree, gitOk, objectFormat, splitZ } from "./git.mjs";
import { graphError } from "./schema.mjs";

const gitComponent = path => path.split("/").some(part => part.toLowerCase() === ".git");
const invalidPath = path => gitComponent(path) || /[\r\n]/.test(path);
const sha256 = bytes => createHash("sha256").update(bytes).digest("hex");
const blobHash = (format, size) => createHash(format).update(`blob ${size}\0`);
const gitError = message => graphError("ERR_GIT_FAILED", message);
const limitError = message => graphError("ERR_SEAL_LIMIT", message);
const violation = (path, reason) => ({ path, reason });

function requireScope(violations) {
  if (violations.length) {
    throw Object.assign(graphError("ERR_SCOPE_VIOLATION",
      `Cannot seal ${JSON.stringify(violations[0].path)}: ${violations[0].reason}`), { violations });
  }
}

function baseEntries(output) {
  return new Map(splitZ(output).map(record => {
    const tab = record.indexOf("\t");
    const [mode, , oid] = record.slice(0, tab).split(" ");
    if (tab < 0 || !/^(100644|100755|120000|160000)$/.test(mode) || !oid) {
      throw gitError("Unexpected ls-tree record while sealing");
    }
    return [record.slice(tab + 1), { mode, oid }];
  }));
}

function rawChanges(output) {
  const fields = splitZ(output);
  if (fields.length % 2) throw gitError("Unexpected raw seal diff length");
  const changes = [];
  for (let i = 0; i < fields.length; i += 2) {
    const match = /^:(\d{6}) (\d{6}) [0-9a-f]+ [0-9a-f]+ ([ADMT])$/.exec(fields[i]);
    if (!match || !fields[i + 1]) throw gitError("Unexpected raw seal diff record");
    const [, oldMode, newMode, status] = match;
    changes.push({ status, path: fields[i + 1], oldMode, newMode });
  }
  return changes;
}

// Git omits special files and can hide nested metadata; this walk audits disk names, not ignore rules.
async function auditDisk(worktree, nested) {
  const violations = [];
  const dirs = [""];
  while (dirs.length) {
    const dir = dirs.pop();
    for (const entry of await readdir(join(worktree, dir), { withFileTypes: true })) {
      if (!dir && entry.name === ".git") continue; // The linked worktree's own administrative file.
      const path = dir ? `${dir}/${entry.name}` : entry.name;
      if (nested.has(path)) continue;
      if (invalidPath(path)) violations.push(violation(path, "forbidden path"));
      else if (entry.isDirectory()) dirs.push(path);
      else if (!entry.isFile() && !entry.isSymbolicLink()) violations.push(violation(path, "special file"));
    }
  }
  return violations;
}

async function statIfPresent(file) {
  try {
    return await lstat(file);
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "ENOTDIR") return null;
    throw error;
  }
}

const sameFile = (a, b) => b !== null && a.dev === b.dev && a.ino === b.ino && a.nlink === b.nlink &&
  a.size === b.size && a.mode === b.mode && a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs;

async function regularBlob(file, initial, { format, capture = false, protectedFile }) {
  if (initial.nlink !== 1) return { reason: "hardlinked file" };
  const fd = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await fd.stat();
    if (!before.isFile() || !sameFile(initial, before)) {
      return { reason: "file changed before reading" };
    }
    const hash = blobHash(format, before.size);
    const digest = protectedFile ? createHash("sha256") : null;
    const bytes = capture ? Buffer.alloc(before.size) : null;
    const chunk = Buffer.alloc(Math.min(64 * 1024, before.size + 1));
    let size = 0;
    while (size <= before.size) {
      const { bytesRead } = await fd.read(chunk, 0, Math.min(chunk.length, before.size - size + 1), null);
      if (!bytesRead) break;
      const block = chunk.subarray(0, bytesRead);
      hash.update(block);
      digest?.update(block);
      if (bytes) block.copy(bytes, size);
      size += bytesRead;
    }
    const after = await fd.stat();
    if (size !== before.size || !sameFile(before, after) || !sameFile(after, await statIfPresent(file))) {
      return { reason: "file changed while reading" };
    }
    return { mode: before.mode & 0o100 ? "100755" : "100644", oid: hash.digest("hex"), size,
      bytes, digest: digest?.digest("hex") };
  } finally {
    await fd.close();
  }
}

async function inspect(worktree, path, options) {
  const parts = path.split("/");
  let file = worktree;
  for (const part of parts.slice(0, -1)) {
    file = join(file, part);
    if (!(await statIfPresent(file))?.isDirectory()) return null;
  }
  file = join(file, parts.at(-1));
  const stat = await statIfPresent(file);
  if (!stat || stat.isDirectory()) return null;
  if (stat.isFile()) {
    if (options.capture && stat.size !== options.size) return { reason: "file changed after scanning" };
    return regularBlob(file, stat, options);
  }
  if (!stat.isSymbolicLink()) return { reason: "special file" };
  if (!options.allowSymlinks || options.protectedFile) return { reason: "symlink is not allowed" };
  const bytes = await readlink(file, { encoding: "buffer" });
  const target = bytes.toString("utf8");
  const relative = posix.normalize(posix.join(posix.dirname(path), target));
  if (posix.isAbsolute(target) || relative === ".." || relative.startsWith("../") || gitComponent(target)) {
    return { reason: "unsafe symlink target" };
  }
  if (!sameFile(stat, await statIfPresent(file))) return { reason: "symlink changed while reading" };
  return { mode: "120000", oid: blobHash(options.format, bytes.length).update(bytes).digest("hex"),
    size: bytes.length, bytes };
}

function caseViolations(paths) {
  const spellings = new Map();
  const collisions = new Set();
  for (const path of paths) {
    for (let part = path; part !== "."; part = posix.dirname(part)) {
      const folded = part.toLowerCase();
      const previous = spellings.get(folded);
      if (previous === part) break;
      if (previous === undefined) spellings.set(folded, part);
      else {
        collisions.add(previous);
        collisions.add(part);
      }
    }
  }
  return [...collisions].sort().map(path => violation(path, "case-only path collision"));
}

async function scan(options, plumbing) {
  const { worktree, writeScope, protectedFiles, policy, baseSha } = options;
  const { git, format } = plumbing;
  const base = baseEntries(await git(["ls-tree", "-r", "-z", baseSha]));
  const all = splitZ(await git(["ls-files", "-z", "--others"]));
  const visible = splitZ(await git(["ls-files", "-z", "--others", "--exclude-standard"]));
  const nested = new Set(all.filter(path => path.endsWith("/")).map(path => path.slice(0, -1)));
  const outside = path => !writeScope.some(scope => covers(scope, path));
  const violations = await auditDisk(worktree, nested);
  for (const path of nested) violations.push(violation(path, "nested repository"));
  for (const [path, entry] of base) {
    if (entry.mode === "160000") violations.push(violation(path, "gitlink"));
    if (invalidPath(path)) violations.push(violation(path, "forbidden path"));
  }
  for (const path of visible) {
    if (!path.endsWith("/") && outside(path)) violations.push(violation(path, "outside write scope"));
  }
  requireScope(violations);

  const protectedByPath = new Map(protectedFiles.map(entry => [entry.path, entry]));
  const adopted = new Set([...base.keys(), ...visible]);
  const changed = [];
  const finalPaths = [];
  for (const path of new Set([...adopted, ...protectedByPath.keys()])) {
    const protectedFile = protectedByPath.get(path);
    const current = await inspect(worktree, path, { format, allowSymlinks: policy.allowSymlinks, protectedFile });
    const previous = base.get(path);
    if (current?.reason) violations.push(violation(path, current.reason));
    else if (protectedFile && current?.digest !== protectedFile.sha256) {
      violations.push(violation(path, "protected file changed or disappeared"));
    }
    if (!adopted.has(path) || current?.reason) continue;
    if (current) finalPaths.push(path);
    if (current?.oid !== previous?.oid || current?.mode !== previous?.mode) {
      if (previous && outside(path)) violations.push(violation(path, "outside write scope"));
      changed.push({ path, current });
    }
  }
  requireScope([...violations, ...caseViolations(finalPaths)]);
  return changed;
}

export async function seal({ worktree, baseSha, writeScope, policy, indexPath, claimSec, message, protectedFiles = [] }) {
  const { maxChangedPaths = 2000, maxBlobBytes = 1048576, allowSymlinks = false } = policy;
  if (!isAbsolute(indexPath)) throw gitError("Sealing needs an absolute private index path");
  const env = { GIT_INDEX_FILE: indexPath };
  const options = { cwd: worktree, env };
  const git = (args, input) => gitOk(args, { ...options, input });
  try {
    await mkdir(dirname(indexPath), { recursive: true });
    await rm(indexPath, { force: true });
    await git(["read-tree", baseSha]);
    const format = await objectFormat(worktree, options);
    const changed = await scan({ worktree, baseSha, writeScope, policy, protectedFiles }, { git, format });
    if (changed.length > maxChangedPaths) throw limitError(`Too many changed paths: ${changed.length}`);
    const large = changed.find(({ current }) => current && current.size > maxBlobBytes);
    if (large) throw limitError(`Adopted blob is too large: ${JSON.stringify(large.path)}`);

    const removes = [];
    const updates = [];
    for (const { path, current } of changed) {
      if (!current) {
        removes.push(`${path}\0`);
        continue;
      }
      const blob = await inspect(worktree, path, { format, allowSymlinks, capture: true, size: current.size });
      requireScope(blob?.oid === current.oid && blob.mode === current.mode
        ? [] : [violation(path, "file changed after scanning")]);
      const oid = (await git(["hash-object", "-w", "--no-filters", "--stdin"], blob.bytes)).toString("utf8").trim();
      if (oid !== current.oid) throw gitError(`Unexpected blob ID for ${JSON.stringify(path)}`);
      updates.push(`${current.mode} ${oid}\t${path}\0`);
    }
    if (removes.length) await git(["update-index", "-z", "--force-remove", "--stdin"], removes.join(""));
    if (updates.length) await git(["update-index", "-z", "--index-info"], updates.join(""));
    const tree = (await git(["write-tree"])).toString("utf8").trim();
    const commit = await commitTree(worktree, { tree, parents: [baseSha], dateSec: claimSec, message, env });
    const diff = await git(["diff-tree", "-r", "-z", "--raw", "--no-renames", baseSha, commit]);
    const changes = rawChanges(diff);
    requireScope(changes.filter(({ path }) => !writeScope.some(scope => covers(scope, path)))
      .map(({ path }) => violation(path, "outside write scope")));
    return { commit, tree, scopeDiffDigest: sha256(diff), changes };
  } catch (cause) {
    if (typeof cause?.syscall === "string") {
      throw Object.assign(gitError(`Could not read or update seal inputs: ${cause.message}`), { cause });
    }
    throw cause;
  }
}
