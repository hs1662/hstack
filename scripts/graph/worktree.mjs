// Engine-owned worktree names and lifecycle (SSOT 4.3, D19, D23). A raw node ID never reaches a path or a
// ref: node IDs may hold "/", "..", "::" or a newline, so paths and refs use nodeKey = sha256(nodeId).
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, readFile, realpath, rm, statfs, writeFile } from "node:fs/promises";
import { availableParallelism } from "node:os";
import { dirname, join, resolve } from "node:path";
import { gitOk, revParse, splitZ } from "./git.mjs";
import { graphError } from "./schema.mjs";

export const nodeKey = nodeId => createHash("sha256").update(nodeId).digest("hex");
export const attemptKey = (key, epoch) => `${key}.e${epoch}`;
export const worktreePath = (root, runId, wtId) => join(root, "worktrees", runId, wtId);
export const candidatePath = (root, runId, candidateId) => join(root, "worktrees", runId, `cand-${candidateId}`);
export const tmpPath = (root, runId, id) => join(root, "runs", runId, "tmp", id);
export const sealIndexPath = (root, runId, wtId) => join(root, "runs", runId, "seal", `${wtId}.index`);
export const inboxPath = (root, runId, key) => join(root, "runs", runId, "inbox", `${key}.json`);
export const lockReason = (runId, key, epoch, wtId) => `hstack:${runId}/${key}/e${epoch}/${wtId}`;
export const candidateLockReason = (runId, candidateId) => `hstack:${runId}/cand/${candidateId}`;
export const pinRef = (runId, key, epoch) => `refs/hstack/pin/${runId}/${key}/e${epoch}`;
export const candRef = (runId, candidateId) => `refs/hstack/cand/${runId}/${candidateId}`;
export const acceptedRef = runId => `refs/hstack/runs/${runId}/accepted`;
// Worker and candidate worktrees share these slots; this machine-sized value is only the initial policy.
export const defaultMaxOpenWorktrees = (cpus = availableParallelism()) => Math.max(1, Math.min(4, Math.floor(cpus / 2)));

const failure = message => graphError("ERR_GIT_FAILED", message);

/** `git worktree list --porcelain -z`: one record per worktree; a reason-less lock reads as "". */
export async function listWorktrees(workspace) {
  const records = [];
  let current = null;
  for (const item of splitZ(await gitOk(["worktree", "list", "--porcelain", "-z"], { cwd: workspace }))) {
    if (item === "") { current = null; continue; }
    const space = item.indexOf(" ");
    const [label, value] = space < 0 ? [item, ""] : [item.slice(0, space), item.slice(space + 1)];
    if (label === "worktree") {
      current = { path: value, head: null, detached: false, branch: null, locked: null, prunable: null };
      records.push(current);
    } else if (label === "HEAD") current.head = value;
    else if (label === "detached") current.detached = true;
    else if (label === "branch") current.branch = value;
    else if (label === "locked") current.locked = value;
    else if (label === "prunable") current.prunable = value;
  }
  return records;
}

// git records a worktree under its real path; a caller may name it through a symlinked parent.
async function listed(workspace, path) {
  let real = resolve(path);
  try { real = await realpath(path); } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  return (await listWorktrees(workspace)).find(item => item.path === path || item.path === real) ?? null;
}

// Policy files (.worktreeinclude) are copied as bytes and mode; a symlink or a directory is never followed.
async function copyIncluded(workspace, path, include) {
  const manifest = [];
  for (const rel of include) {
    const source = join(workspace, rel);
    const stat = await lstat(source);
    if (!stat.isFile()) throw failure(`worktree include ${rel} is not a regular file`);
    const bytes = await readFile(source);
    const mode = stat.mode & 0o7777;
    const target = join(path, rel);
    await mkdir(dirname(target), { recursive: true });
    await rm(target, { force: true });
    await writeFile(target, bytes, { flag: "wx", mode });
    await chmod(target, mode);
    manifest.push({ path: rel, sha256: createHash("sha256").update(bytes).digest("hex"), mode });
  }
  return manifest;
}

/** Idempotent: a listed path with the same reason and HEAD is reused; any other listed state is ERR_GIT_FAILED. */
export async function provision({ workspace, path, baseSha, reason, include, tmpDir }) {
  const existing = await listed(workspace, path);
  if (existing && existing.locked !== reason) {
    throw failure(`worktree ${path} is listed with lock reason ${JSON.stringify(existing.locked)}, not ${JSON.stringify(reason)}`);
  }
  if (existing && existing.head !== baseSha) throw failure(`worktree ${path} has HEAD ${existing.head}, not ${baseSha}`);
  if (!existing) {
    await mkdir(dirname(path), { recursive: true });
    await gitOk(["worktree", "add", "--detach", "--lock", "--reason", reason, path, baseSha], { cwd: workspace });
  }
  const head = await revParse(path, "HEAD");
  if (head !== baseSha) throw failure(`worktree ${path} checked out HEAD ${head}, not ${baseSha}`);
  const manifest = await copyIncluded(workspace, path, include);
  const env = { TMPDIR: tmpDir, npm_config_cache: join(tmpDir, "npm-cache"), XDG_CACHE_HOME: join(tmpDir, "xdg-cache") };
  for (const dir of [env.npm_config_cache, env.XDG_CACHE_HOME]) await mkdir(dir, { recursive: true, mode: 0o700 });
  return { manifest, env };
}

/** Idempotent: unlock, remove and prune a listed worktree, then drop its tmpDir and seal index. */
export async function release({ workspace, path, tmpDir, sealIndex }) {
  const existing = await listed(workspace, path);
  if (existing) {
    if (existing.locked !== null) await gitOk(["worktree", "unlock", existing.path], { cwd: workspace });
    await gitOk(["worktree", "remove", "--force", existing.path], { cwd: workspace });
  }
  await gitOk(["worktree", "prune"], { cwd: workspace });
  await rm(tmpDir, { recursive: true, force: true });
  await rm(sealIndex, { force: true });
}

/** Bytes available to an unprivileged writer on the filesystem holding `path`. */
export async function freeBytes(path) {
  const { bavail, bsize } = await statfs(path);
  return bavail * bsize;
}
