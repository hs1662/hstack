import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { commitTree, git, gitOk, isAncestor, repoConfigDigest, revParse, splitZ } from "./git.mjs";
import { classifyMergeTree } from "./merge-tree.mjs";
import { graphError } from "./schema.mjs";
import { acceptedRef, worktreePath } from "./worktree.mjs";

const user = { scope: "user" };
const precondition = message => graphError("ERR_LAND_PRECONDITION", message);
const dirty = message => graphError("ERR_LAND_DIRTY", message);
const text = bytes => bytes.toString("utf8").trimEnd();

async function checkConfig(cwd, expected) {
  if (await repoConfigDigest(cwd, user) !== expected) {
    throw graphError("ERR_REPO_CONFIG_TAMPERED", "Shared repository configuration changed since the run started");
  }
}

// An ignored directory can be reported as one record. File/directory replacements can collide too.
function overlaps(path, changed) {
  const name = path.endsWith("/") ? path.slice(0, -1) : path;
  return changed.some(target => target === name || target.startsWith(`${name}/`) || name.startsWith(`${target}/`));
}

async function checkDirty(opts, accepted, allow) {
  const records = splitZ(await gitOk(["status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignored=matching"], opts));
  const changed = splitZ(await gitOk(["diff", "--no-renames", "--name-only", "-z", "HEAD", accepted, "--"], opts));
  for (let i = 0; i < records.length; i += 1) {
    const record = records[i];
    const kind = record[0];
    const fields = record.split(" ");
    let paths;
    switch (kind) {
      case "u": throw dirty("The index contains unresolved changes");
      case "1": paths = [fields.slice(8).join(" ")]; break;
      case "2": paths = [fields.slice(9).join(" "), records[++i]]; break;
      case "?":
      case "!": paths = [record.slice(2)]; break;
      default: throw graphError("ERR_GIT_FAILED", "Unexpected Git porcelain v2 status record");
    }
    if (kind === "!") {
      if (paths.some(path => overlaps(path, changed))) throw dirty("Landing would overwrite an ignored path");
    } else if (!allow.includes("dirty-nonoverlap") || paths.some(path => overlaps(path, changed))) {
      throw dirty("The checkout has local changes that prevent landing");
    }
  }
}

async function preview(opts, accepted) {
  const result = classifyMergeTree(await git(["merge-tree", "--write-tree", "-z", "--name-only", "HEAD", accepted], opts));
  switch (result.kind) {
    case "clean": return result.tree;
    case "conflict": throw graphError("ERR_LAND_CONFLICT", `Landing conflicts at: ${result.paths.join(", ")}`);
    default: throw graphError("ERR_GIT_FAILED", "Unexpected merge-tree result");
  }
}

async function runGate({ opts, root, runId, tree, parents }, gate) {
  const path = worktreePath(root, runId, `land-${randomUUID()}`);
  const commit = await commitTree(opts.cwd, { tree, parents, dateSec: 0, message: "hstack land preview", ...user });
  await mkdir(dirname(path), { recursive: true });
  await gitOk(["worktree", "add", "--detach", path, commit], opts);
  try {
    let result;
    try {
      result = await gate(path);
    } catch (cause) {
      throw Object.assign(graphError("ERR_GATE_FAILED", "Landing gate threw an error"), { cause });
    }
    if (result === false) throw graphError("ERR_GATE_FAILED", "Landing gate rejected the preview");
  } finally {
    await gitOk(["worktree", "remove", "--force", "--", path], opts);
  }
}

async function createBranch(opts, name, accepted) {
  if (typeof name !== "string" || name.includes("\0")) throw precondition("Landing branch needs a valid name");
  const checked = await git(["check-ref-format", "--branch", name], opts);
  if (checked.code !== 0 || text(checked.stdout) !== name) throw precondition(`Invalid branch name: ${name}`);
  const targetRef = `refs/heads/${name}`;
  if (await revParse(opts.cwd, targetRef, user)) throw precondition(`Branch already exists: ${name}`);
  await gitOk(["branch", "--", name, accepted], opts);
  return targetRef;
}

async function writePatch(opts, state, out) {
  if (!out) throw precondition("Patch landing requires an output path");
  const patch = await gitOk(["diff", "--binary", "--no-renames", "--no-ext-diff", "--no-textconv", state.startBase,
    state.acceptedTip, "--"], opts);
  try {
    await writeFile(out, patch, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if (error instanceof Error && error.code === "EEXIST") throw precondition(`Patch output already exists: ${out}`);
    throw error;
  }
}

/** Land a published v2 result. A gate rejects by returning false or throwing. */
export async function land({ workspace, root, state, mode = "ff-only", branch, out, allow = [], gate }) {
  if (!["ff-only", "merge", "branch", "patch"].includes(mode)) throw precondition(`Unknown landing mode: ${mode}`);
  const { runId, acceptedTip, status, lastPublished } = state;
  if (!acceptedTip || lastPublished?.new !== acceptedTip) throw precondition("Run has no published accepted tip");
  if (status !== "completed" && !(status === "degraded" && allow.includes("partial"))) {
    throw precondition("Landing requires a completed run, or a degraded run with partial allowance");
  }
  if (await revParse(workspace, acceptedRef(runId), user) !== acceptedTip) {
    throw precondition("The accepted ref does not match the published tip");
  }
  const opts = { cwd: workspace, ...user };
  const head = await git(["symbolic-ref", "--quiet", "HEAD"], opts);
  if (head.code !== 0 && !(head.code === 1 && mode === "branch")) {
    throw precondition("Landing from detached HEAD requires branch mode");
  }
  const oldHead = await revParse(workspace, "HEAD", user);
  if (!oldHead) throw precondition("Landing requires an existing HEAD");
  await checkConfig(workspace, state.repoConfigDigest);
  const acceptedTree = await revParse(workspace, `${acceptedTip}^{tree}`, user);
  const receipt = { mode, oldHead, newHead: acceptedTip, verifiedTree: acceptedTree, verified: true };

  switch (mode) {
    case "branch": return { ...receipt, targetRef: await createBranch(opts, branch ?? `hstack/${runId}`, acceptedTip) };
    case "patch":
      await writePatch(opts, state, out);
      return { ...receipt, targetRef: null, newHead: oldHead, patchPath: out };
    case "ff-only":
    case "merge": break;
    default: throw precondition(`Unknown landing mode: ${mode}`);
  }

  await checkDirty(opts, acceptedTip, allow);
  const targetRef = text(head.stdout);
  if (mode === "ff-only" && await isAncestor(workspace, oldHead, acceptedTip, user)) {
    await gitOk(["merge", "--ff-only", acceptedTip], opts);
    if (await revParse(workspace, "HEAD", user) !== acceptedTip) throw precondition("Fast-forward did not reach the accepted tip");
    return { ...receipt, targetRef };
  }

  const tree = await preview(opts, acceptedTip);
  if (mode === "ff-only") throw precondition("HEAD diverged; choose branch, merge, or patch mode");
  if (gate) {
    await runGate({ opts, root, runId, tree, parents: [oldHead, acceptedTip] }, gate);
    await checkConfig(workspace, state.repoConfigDigest);
    if (await revParse(workspace, "HEAD", user) !== oldHead ||
        text(await gitOk(["symbolic-ref", "--quiet", "HEAD"], opts)) !== targetRef) {
      throw precondition("Checkout HEAD changed while the landing gate ran");
    }
    await checkDirty(opts, acceptedTip, allow);
  }
  await gitOk(["merge", "--no-ff", "--no-edit", acceptedTip], opts);
  if (await revParse(workspace, "HEAD^{tree}", user) !== tree) {
    throw precondition("Landed merge tree differs from the preview");
  }
  return { ...receipt, targetRef, newHead: await revParse(workspace, "HEAD", user), verifiedTree: tree, verified: Boolean(gate) };
}
