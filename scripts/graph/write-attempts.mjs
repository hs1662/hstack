import { createHash, randomUUID } from "node:crypto";
import { basename, join } from "node:path";
import { issue } from "./attempts.mjs";
import { canonical } from "./fingerprint.mjs";
import { directory, reclaimRefLocks, updateRef } from "./gc.mjs";
import { git, isAncestor, repoConfigDigest, revParse, zeroOid } from "./git.mjs";
import { withLock } from "./lock.mjs";
import { validateEvidence } from "./reducer.mjs";
import { graphError, validateRunRecords } from "./schema.mjs";
import { seal } from "./seal.mjs";
import { readState, transaction } from "./wal-store.mjs";
import { attemptKey, freeBytes, inboxPath, listWorktrees, lockReason, nodeKey, pinRef, provision, release,
  sealIndexPath, tmpPath, worktreePath } from "./worktree.mjs";

const notReady = message => graphError("ERR_NOT_READY", message);
const tampered = "ERR_REPO_CONFIG_TAMPERED";
const diverged = "ERR_INTEGRATION_DIVERGED";
const heldForIntegration = new Set(["sealed", "integrating", "held_conflict", "held_integration"]);
const current = (node, record) => node?.attempt?.epoch === record.epoch && node.highestIssuedEpoch === record.epoch;
const recordFor = (s, token) => Object.values(s.worktrees).find(w => w.instructionPath === token);
const changedConfig = async s => await repoConfigDigest(s.workspace) !== s.repoConfigDigest;

export async function claimWriter(s, n, o) {
  if (await freeBytes(o.root) < 2 * s.checkoutBytes) throw graphError("ERR_HELD_CAPACITY", "held:capacity: disk");
  const baseSha = s.acceptedTip ?? s.startBase;
  const ancestors = new Set(n.dependsOn);
  for (const id of ancestors) {
    const parent = s.nodes[id];
    if (parent.kind === "write" && (!parent.sealedCommit || !await isAncestor(s.workspace, parent.sealedCommit, baseSha))) {
      throw notReady(`Write ancestor ${id} is not in the attempt base`);
    }
    for (const dep of parent.dependsOn) ancestors.add(dep);
  }
  if (await changedConfig(s)) {
    Object.assign(n, { status: "held_integration", heldReason: tampered });
    return { error: { code: tampered, message: "Repository configuration changed before claim" } };
  }
  const id = randomUUID(), key = nodeKey(n.id), epoch = n.highestIssuedEpoch + 1;
  const path = worktreePath(o.root, s.runId, id), tmpDir = tmpPath(o.root, s.runId, id);
  const receiptPath = inboxPath(o.root, s.runId, attemptKey(key, epoch));
  await directory(o.root, ["runs", s.runId, "inbox"]);
  const fields = { baseSha, worktreePath: path, tmpDir, receiptPath, dispatch: { cwd: path, isolation: "none" },
    env: { TMPDIR: tmpDir, npm_config_cache: join(tmpDir, "npm-cache"), XDG_CACHE_HOME: join(tmpDir, "xdg-cache") } };
  const response = await issue(s, n, { ...o, writer: fields });
  const location = { path, lockReason: lockReason(s.runId, key, epoch, id), phase: "planned" };
  Object.assign(n.attempt, { baseSha, claimSec: Math.floor(Date.now() / 1000), tmpDir, inboxPath: receiptPath,
    repoConfigDigest: s.repoConfigDigest, includeManifest: [], worktree: { id, ...location } });
  const { instructionPath, directiveDigest, nonceHash, graphRev } = n.attempt;
  s.worktrees[id] = { kind: "worker", nodeId: n.id, epoch, instructionPath, directiveDigest, graphRev, nonceHash,
    ...location, tmpDir, settled: false };
  return response;
}

// Serialize effects only for this worktree. A concurrent claim replay must never copy includes over
// a started worker, nor race a fenced worker's release. No caller holds the journal lock here.
async function exclusive(ctx, id, fn) {
  const dir = await directory(ctx.root, ["runs", ctx.run, "worktree-locks", id]);
  return withLock(dir, async () => {
    const s = await withLock(ctx.root, () => readState(ctx.root, ctx.run));
    return fn(s, s.worktrees[id]);
  });
}

function reserved(ctx, type, callback) {
  const prefix = type === "AttemptSealed" ? "@hstack-seal/" : "@hstack-worktree/";
  return transaction(ctx.root, ctx.run, { type, opId: prefix + ctx.opId, payload: ctx.payload, reclaim: reclaimRefLocks }, async s => {
    const response = await callback(s);
    ctx.refresh(s);
    return { state: validateRunRecords(s), response };
  });
}

export async function ensureProvisioned(ctx, c) {
  const id = basename(c.worktreePath);
  await exclusive(ctx, id, async (s, w) => {
    if (w.provisionError) throw graphError(w.provisionError.code, w.provisionError.message);
    if (w.phase !== "planned" || !current(s.nodes[w.nodeId], w)) return;
    let result, error;
    try {
      result = await provision({ workspace: s.workspace, path: w.path, baseSha: c.baseSha, reason: w.lockReason,
        include: s.worktreeInclude, tmpDir: w.tmpDir });
    } catch (cause) {
      if (cause.code !== "ERR_GIT_FAILED") throw cause;
      error = { code: cause.code, message: cause.message };
    }
    await reserved(ctx, "WorktreeProvisioned", state => {
      const record = state.worktrees[id], node = state.nodes[w.nodeId];
      if (error) {
        record.provisionError = error;
        if (current(node, record)) Object.assign(node, { status: "held_infra", heldReason: error.code });
      } else {
        record.phase = "ready";
        if (current(node, record)) {
          node.attempt.worktree.phase = "ready";
          node.attempt.includeManifest = result.manifest;
        }
      }
      return error ? { error } : { phase: record.phase };
    });
    if (error) throw graphError(error.code, error.message);
  });
}

export class SealWork extends Error {
  constructor(id) { super("Seal the worker worktree"); this.id = id; }
  async perform(ctx) {
    await exclusive(ctx, this.id, async (s, w) => {
      const n = s.nodes[w.nodeId], a = n.attempt;
      if (!current(n, w) || n.status !== "running" || a.sealedCommit || a.sealFailure) return;
      const key = nodeKey(n.id), ref = pinRef(s.runId, key, w.epoch);
      let sealed, failure;
      try {
        sealed = await seal({ worktree: w.path, baseSha: a.baseSha, writeScope: n.writeScope, policy: s.policy.seal,
          indexPath: sealIndexPath(ctx.root, s.runId, this.id), claimSec: a.claimSec, protectedFiles: a.includeManifest,
          message: `hstack seal ${s.runId}/${key}/e${w.epoch}` });
      } catch (err) {
        if (!["ERR_SCOPE_VIOLATION", "ERR_SEAL_LIMIT", "ERR_GIT_FAILED"].includes(err.code)) throw err;
        failure = { code: err.code, ...(err.violations && { violations: err.violations }) };
      }
      await reserved(ctx, "AttemptSealed", async state => {
        await ctx.guard(state);
        const node = state.nodes[n.id];
        if (!current(node, w) || node.status !== "running") throw notReady("Attempt no longer running");
        if (await changedConfig(state)) failure = { code: tampered };
        if (!failure) {
          try {
            const old = await revParse(s.workspace, ref);
            if (old === null) await updateRef(s.workspace, [ref, sealed.commit, zeroOid(sealed.commit.length === 64 ? "sha256" : "sha1")]);
            else if (old !== sealed.commit) failure = { code: diverged };
          } catch (err) {
            if (err.code !== "ERR_GIT_FAILED") throw err;
            failure = { code: err.code };
          }
        }
        Object.assign(node.attempt, failure ? { sealFailure: failure } : { sealedCommit: sealed.commit,
          sealedTree: sealed.tree, scopeDiffDigest: sealed.scopeDiffDigest, pinRef: ref });
        Object.assign(node.attempt, { verifierOp: ctx.opId, verifierRequestDigest: ctx.requestDigest });
        return { nodeId: n.id, epoch: w.epoch };
      });
    });
  }
}

export function sealedEvidenceFile(workspace, commit) {
  return async path => {
    const { code, stdout } = await git(["cat-file", "blob", `${commit}:${path}`], { cwd: workspace });
    if (code !== 0) throw graphError("ERR_FORGED_EVIDENCE", `Not a sealed blob: ${path}`);
    let lines = Number(stdout.length > 0 && stdout.at(-1) !== 10);
    for (let i = stdout.indexOf(10); i >= 0; i = stdout.indexOf(10, i + 1)) lines++;
    return { lines, digest: createHash("sha256").update(stdout).digest("hex") };
  };
}

// Read and hash evidence outside the engine lock; only the immutable commit may satisfy the retry.
export class EvidenceWork extends Error {
  constructor(workspace, commit) { super("Check worker evidence"); Object.assign(this, { workspace, commit }); }
  async check(receipt) {
    try {
      await validateEvidence(receipt, { evidenceFile: sealedEvidenceFile(this.workspace, this.commit) });
      if (receipt.workerReportedStatus !== "completed") throw graphError("ERR_MISSING_EVIDENCE", "Worker did not complete");
      return { commit: this.commit };
    } catch (err) {
      if (!["ERR_MISSING_EVIDENCE", "ERR_FORGED_EVIDENCE", "ERR_GIT_FAILED"].includes(err.code)) throw err;
      return { commit: this.commit, error: err.code };
    }
  }
}

const failures = new Map([
  ["ERR_SCOPE_VIOLATION", "failed_logic"], ["ERR_SEAL_LIMIT", "held_blocked"], ["ERR_GIT_FAILED", "held_infra"],
  [diverged, "held_integration"], [tampered, "held_integration"], ["ERR_MISSING_EVIDENCE", "held_blocked"],
  ["ERR_FORGED_EVIDENCE", "failed_logic"],
]);
export async function settleWriter(s, n, o, io) {
  const a = n.attempt;
  if (!a.sealFailure && !a.sealedCommit) throw new SealWork(a.worktree.id);
  if (!a.sealFailure && io.evidence?.commit !== a.sealedCommit) throw new EvidenceWork(s.workspace, a.sealedCommit);
  const reason = a.sealFailure?.code ?? io.evidence?.error;
  if (reason) {
    Object.assign(n, { status: failures.get(reason), heldReason: reason });
    return reason;
  }
  const { workerReportedStatus, inlineSummary, provenance } = o.receipt;
  n.workerReceiptUri = await io.put(Buffer.from(canonical({ workerReportedStatus, inlineSummary, provenance })));
  n.status = "sealed";
  return "sealed";
}

export function requestRelease(s, token, recorded) {
  const w = recordFor(s, token), n = s.nodes[w.nodeId];
  if (current(n, w) && (["claimed", "running"].includes(n.status) || heldForIntegration.has(n.status))) {
    throw notReady("Active or retained worktree");
  }
  if (!recorded) throw new ReleaseWork(w);
  return { runId: s.runId, nodeId: n.id, epoch: w.epoch, status: "released" };
}

export class ReleaseWork extends Error {
  constructor(w) { super("Release worker worktree"); this.id = basename(w.path); }
  async perform(ctx) {
    await exclusive(ctx, this.id, async (s, w) => {
      if (w.phase !== "released") {
        const entry = (await listWorktrees(s.workspace)).find(item => item.path === w.path);
        if (entry && entry.locked !== w.lockReason && (entry.locked !== null || w.phase === "planned")) {
          throw graphError("ERR_GIT_FAILED", "Refusing to release a foreign worktree");
        }
        await release({ workspace: s.workspace, path: w.path, tmpDir: w.tmpDir, sealIndex: sealIndexPath(ctx.root, s.runId, this.id) });
      }
      await reserved(ctx, "WorktreeReleased", state => {
        state.worktrees[this.id].phase = "released";
        const a = state.nodes[w.nodeId].attempt;
        if (a?.worktree?.id === this.id) a.worktree.phase = "released";
        return { phase: "released" };
      });
    });
  }
}

export async function autoRelease(ctx, token, status) {
  if (heldForIntegration.has(status)) return;
  const s = await withLock(ctx.root, () => readState(ctx.root, ctx.run));
  const w = recordFor(s, token);
  if (w?.settled && w.phase !== "released" && !(current(s.nodes[w.nodeId], w) && heldForIntegration.has(s.nodes[w.nodeId].status))) {
    await new ReleaseWork(w).perform(ctx);
  }
}
