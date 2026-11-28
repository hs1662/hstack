// allow: SIZE_OK - the B=1 promotion state machine and its crash continuations share one WAL/ref protocol.
import { dirname, join } from "node:path";
import { gatePolicy, validatedArtifact } from "./attempts.mjs";
import { canonical, gateKey } from "./fingerprint.mjs";
import { directory, getBlob, nextCandidateId, reclaimRefLocks, syncDir, updateRef, withIntent } from "./gc.mjs";
import { commitTree, commonDir, hasObject, isAncestor, repoConfigDigest, revParse } from "./git.mjs";
import { recordVerified } from "./incremental.mjs";
import { withLock } from "./lock.mjs";
import { mergeTree } from "./merge-tree.mjs";
import { validateReceipt } from "./reducer.mjs";
import { graphError, Receipt, validateRunRecords, V2_WRITE_ERROR } from "./schema.mjs";
import { readState, transaction } from "./wal-store.mjs";
import { measureGate } from "./verify-gate.mjs";
import { candRef, candidateLockReason, candidatePath, provision, release, sealIndexPath, tmpPath } from "./worktree.mjs";
import { autoRelease, sealedEvidenceFile } from "./write-attempts.mjs";

const diverged = "ERR_INTEGRATION_DIVERGED", tampered = "ERR_REPO_CONFIG_TAMPERED";
const zero = oid => "0".repeat(oid.length);
const changedConfig = async s => await repoConfigDigest(s.workspace) !== s.repoConfigDigest;
const head = ctx => withLock(ctx.root, () => readState(ctx.root, ctx.run));
const busy = () => graphError("ERR_GATE_IN_PROGRESS", "Candidate gate already reserved");
const stale = () => graphError("ERR_NOT_READY", "Candidate no longer current");
const nodeOf = (s, c) => s.nodes[c.orderedAttempts[0].nodeId];
const put = (io, value) => io.put(Buffer.from(canonical(value)));
const held = (n, reason) => Object.assign(n, { status: "held_integration", heldReason: reason });
const response = (s, n, cid) => ({ runId: s.runId, status: n.status, nodeId: n.id, candidateId: cid,
  acceptedTip: s.acceptedTip, generation: s.integrationGeneration, ...(n.heldReason && { reason: n.heldReason }) });
const pending = s => Object.values(s.candidates).find(c => ["gating", "green"].includes(c.state));
const selected = s => Object.values(s.nodes).filter(n => n.status === "sealed").sort((a, b) =>
  a.priority - b.priority || a.topoRank - b.topoRank || (a.id < b.id ? -1 : 1))[0];

function transition(ctx, request, apply) {
  return transaction(ctx.root, ctx.run, request, async (s, io) => {
    if (s?.schemaVersion !== 2) throw graphError(V2_WRITE_ERROR, "Write integration requires a v2 run");
    const result = await apply(s, io);
    ctx.refresh(s);
    return { state: validateRunRecords(s), response: result };
  });
}

async function build(ctx, plan) {
  const { s, n, cid } = plan, a = n.attempt, ours = s.acceptedTip ?? s.startBase;
  let merge, commit, reason = plan.reason;
  if (!reason) {
    try {
      merge = await mergeTree(s.workspace, { base: a.baseSha, ours, theirs: a.sealedCommit });
      if (merge.kind === "clean") commit = await commitTree(s.workspace, { tree: merge.tree, parents: [ours, a.sealedCommit],
        dateSec: a.claimSec, message: `hstack integrate ${s.runId}/${cid}` });
    } catch (error) {
      if (!["ERR_GIT_MERGE_INPUT", "ERR_GIT_MERGE_FAILED"].includes(error.code)) throw error;
      reason = error.code;
    }
  }
  let winner = false;
  const id = `cand-${cid}`;
  await transition(ctx, { type: "ReceiptDelivered", opId: `@hstack-verifier/${ctx.opId}`, payload: ctx.payload }, async (state, io) => {
    const node = state.nodes[n.id];
    if (pending(state)) throw busy();
    if (nextCandidateId(state) !== cid || selected(state)?.id !== n.id || node.attempt.sealedCommit !== a.sealedCommit ||
        node.attempt.epoch !== a.epoch || node.attempt.graphRev !== a.graphRev) throw stale();
    if (await changedConfig(state)) reason = tampered;
    if (await revParse(state.workspace, state.integrationRef) !== state.acceptedTip) reason = diverged;
    const pin = candRef(s.runId, cid);
    if (!reason && merge.kind === "clean") {
      const existing = await revParse(s.workspace, pin);
      if (existing === null) await updateRef(s.workspace, [pin, commit, zero(commit)]);
      else if (existing !== commit) reason = diverged;
    }
    if (reason) held(node, reason);
    else if (merge.kind === "conflict") {
      node.conflict = { paths: merge.paths, messagesUri: await io.put(merge.messages) };
      Object.assign(node, { status: "held_conflict", heldReason: "ERR_MERGE_CONFLICT" });
      node.receiptUri = await put(io, { reason: node.heldReason, conflict: node.conflict });
    } else {
      state.candidates[cid] = { candidateId: cid, generation: s.integrationGeneration,
        orderedAttempts: [{ runId: s.runId, nodeId: n.id, epoch: a.epoch, graphRev: a.graphRev }], workerOids: [a.sealedCommit],
        expectedTip: ours, candidateTree: merge.tree, candidateCommit: commit, scopeDiffDigest: a.scopeDiffDigest,
        pinRefs: [pin], gateKey: null, checkReceiptIds: [], promotionOp: ctx.opId, state: "gating" };
      node.attempt.candidateId = cid;
      node.status = "integrating";
      state.worktrees[id] = { kind: "candidate", nodeId: n.id, epoch: a.epoch, path: candidatePath(ctx.root, s.runId, cid),
        tmpDir: tmpPath(ctx.root, s.runId, id), lockReason: candidateLockReason(s.runId, cid), phase: "planned", settled: false };
      winner = true;
    }
    return { ...response(state, node, cid), requestDigest: ctx.requestDigest };
  });
  if (winner) await gate(ctx, cid);
}

async function gate(ctx, cid) {
  const id = `cand-${cid}`, lock = await directory(ctx.root, ["runs", ctx.run, "worktree-locks", id]);
  await withLock(lock, async () => {
    const s = await head(ctx), c = s.candidates[cid], n = nodeOf(s, c), w = s.worktrees[id];
    if (c.state !== "gating" || n.status !== "integrating") throw stale();
    const receipt = JSON.parse(await getBlob(ctx.root, n.workerReceiptUri)), subjectDigest = receipt.provenance.factDigest;
    const location = { workspace: s.workspace, path: w.path, tmpDir: w.tmpDir };
    const { env } = await provision({ ...location, reason: w.lockReason, baseSha: c.candidateCommit, include: s.worktreeInclude });
    let first;
    const diagnostics = [];
    try {
      const measure = () => measureGate({ argv: n.gateArgv, cwd: w.path, timeoutMs: n.timeoutMs, subjectDigest,
        env: { ...process.env, ...env } });
      first = await measure();
      if (n.flaky && (first.exitCode !== 0 || first.signal || first.timedOut)) {
        for (let i = 0; i < s.limits.maxFlakyDiagnostics; i++) {
          try { diagnostics.push(await measure()); } catch (error) {
            if (error.code !== "ERR_GATE_SPAWN") throw error;
            diagnostics.push({ error: error.code, argv: n.gateArgv, subjectDigest });
          }
        }
      }
    } finally { await release({ ...location, sealIndex: sealIndexPath(ctx.root, s.runId, id) }); }
    await transition(ctx, { type: "GateMeasured", opId: `@hstack-gate-proof/${ctx.opId}`, payload: ctx.payload }, async (state, io) => {
      const cand = state.candidates[cid], node = nodeOf(state, cand);
      if (cand.state === "discarded") {
        Object.assign(state.worktrees[id], { phase: "released", settled: true });
        return { ...response(state, node, cid), discarded: true };
      }
      if (cand.state !== "gating" || node.status !== "integrating" || node.attempt.candidateId !== cid) throw stale();
      cand.measuredUri = await put(io, { first, diagnostics });
      Object.assign(state.worktrees[id], { phase: "released", settled: true });
      const gateLogUri = await put(io, first);
      node.attempt.gateLogUri = gateLogUri;
      if (first.exitCode === 0 && !first.signal && !first.timedOut) {
        const checked = Receipt(await validateReceipt(receipt, { ...io, workspaceRoot: s.workspace, gateLogUri,
          evidenceFile: sealedEvidenceFile(s.workspace, c.workerOids[0]), maxInlineBytesPerNode: s.limits.maxInlineBytesPerNode,
          maxInlineBytesPerWave: s.limits.maxInlineBytesPerWave }));
        const uri = await put(io, checked);
        cand.checkReceiptIds = [uri.slice("cas://sha256/".length)];
        cand.gateKey = gateKey({ ...gatePolicy(node), candidateTree: cand.candidateTree, environment: s.environment });
        cand.state = "green";
      } else {
        cand.state = "red";
        Object.assign(node, { status: n.flaky ? "held_flaky" : "failed_logic", heldReason: n.flaky ? "ERR_FLAKY_GATE" : "ERR_GATE_FAILED" });
        node.receiptUri = await put(io, { candidateCommit: cand.candidateCommit, measuredUri: cand.measuredUri, reason: node.heldReason });
        if (n.flaky) {
          node.firstFailureUri = gateLogUri;
          node.diagnosticUris = await Promise.all(diagnostics.map(d => put(io, d)));
        } else node.failedExecKeys = [...new Set([...(node.failedExecKeys ?? []), node.execKey])];
      }
      return { ...response(state, node, cid), ...(cand.state === "green" && { receiptUri: `cas://sha256/${cand.checkReceiptIds[0]}` }) };
    });
  });
}

const publishPayload = (ctx, p) => ({ command: "publish", runId: ctx.run, ...p });
async function intend(ctx, p) {
  await transition(ctx, { type: "PublishIntended", opId: `@hstack-publish/${p.promotionOp}`, payload: publishPayload(ctx, p) }, async s => {
    const c = s.candidates[p.candidateId], n = nodeOf(s, c);
    if (s.integrationGeneration !== c.generation || c.state !== "green" || !c.measuredUri || n.status !== "integrating") throw stale();
    if (await changedConfig(s)) { held(n, tampered); c.state = "discarded"; }
    else s.pendingPublish = p;
    return response(s, n, c.candidateId);
  });
}

async function finish(ctx, p, repair) {
  const suffix = repair ? `/repair/${repair}` : "";
  const payload = publishPayload(ctx, p);
  return transition(ctx, { type: repair ? "PublishRepaired" : "Published",
    opId: `@hstack-published/${p.promotionOp}${suffix}`, payload }, async (s, io) => {
    const c = s.candidates[p.candidateId], n = nodeOf(s, c);
    if ((repair ? s.lastPublished : s.pendingPublish)?.candidateId !== p.candidateId ||
        (repair ? s.publishRepairs + 1 !== repair : c.state !== "green" || n.status !== "integrating")) throw stale();
    const current = await revParse(s.workspace, p.ref);
    let matches = current === p.new;
    if (!matches && (current ?? zero(p.new)) === p.old && await hasObject(s.workspace, p.new) &&
        (repair || await revParse(s.workspace, c.pinRefs[0]) === p.new)) {
      try {
        await updateRef(s.workspace, ["--create-reflog", "-m", `hstack ${s.runId} ${c.candidateId} g${p.generation}`, p.ref, p.new, p.old]);
        matches = true;
      } catch (error) {
        if (error.code !== "ERR_GIT_FAILED" || await revParse(s.workspace, p.ref) === current) throw error;
      }
    }
    if (matches) {
      const dir = await commonDir(s.workspace);
      await syncDir(dirname(join(dir, p.ref)));
      await syncDir(dir);
      matches = await revParse(s.workspace, p.ref) === p.new;
    }
    if (!matches) {
      held(n, diverged);
      if (!repair) { c.state = "discarded"; s.pendingPublish = null; }
    } else if (repair) s.publishRepairs = repair;
    else {
      const receiptUri = `cas://sha256/${c.checkReceiptIds[0]}`, checked = JSON.parse(await io.get(receiptUri));
      Object.assign(n, { status: "accepted", receiptUri, artifactDigest: await validatedArtifact(checked, io),
        gateKey: c.gateKey, sealedCommit: c.workerOids[0] });
      recordVerified(s, n, checked);
      Object.assign(s, { acceptedTip: p.new, integrationGeneration: p.generation + 1, lastPublished: p, pendingPublish: null });
      c.state = "published";
    }
    return { ...response(s, n, c.candidateId), tokenPath: n.attempt.instructionPath };
  });
}

export async function recoverPublication(ctx, state) {
  const s = state ?? await head(ctx);
  if (s?.schemaVersion !== 2) return s;
  if (s.pendingPublish) {
    const p = s.pendingPublish, result = await finish(ctx, p, 0);
    if (p.promotionOp !== ctx.opId) await autoRelease({ ...ctx, opId: p.promotionOp, payload: publishPayload(ctx, p) },
      result.tokenPath, result.status);
  }
  else if (s.lastPublished && (await revParse(s.workspace, s.integrationRef) ?? zero(s.startBase)) === s.lastPublished.old) {
    await finish(ctx, s.lastPublished, s.publishRepairs + 1);
  } else return s;
  return head(ctx);
}

export async function collectGit(root, run) {
  return withLock(root, async () => {
    const s = await readState(root, run);
    if (s?.schemaVersion !== 2) throw graphError("ERR_GRAPH_SCHEMA", "Git GC requires a v2 run");
    return withIntent(root, run, async ({ abandoned }) => {
      if (abandoned) await reclaimRefLocks(s);
      const removed = [], retained = [];
      if (s.acceptedTip) retained.push(s.integrationRef);
      const prune = async (ref, oid, dead) => {
        const current = await revParse(s.workspace, ref);
        if (current === null) return;
        if (!dead || current !== oid) { retained.push(ref); return; }
        await updateRef(s.workspace, ["-d", ref, oid]);
        removed.push(ref);
      };
      for (const n of Object.values(s.nodes)) {
        const a = n.attempt;
        if (a?.pinRef) await prune(a.pinRef, a.sealedCommit, n.status === "accepted" && s.acceptedTip &&
          await isAncestor(s.workspace, a.sealedCommit, s.acceptedTip));
      }
      for (const c of Object.values(s.candidates)) await prune(candRef(run, c.candidateId), c.candidateCommit,
        ["published", "discarded"].includes(c.state) && c.generation < s.integrationGeneration);
      return { removed, retained };
    });
  });
}

class Step extends Error {
  constructor(plan) { super("Continue outside the WAL lock"); this.plan = plan; }
}

export async function integrate(ctx) {
  await recoverPublication(ctx);
  for (;;) {
    try {
      const result = await transition(ctx, { type: "Integrated", opId: ctx.opId, payload: ctx.payload, guard: ctx.guard }, async (s, io) => {
        if (s.pendingPublish) throw new Step({ finish: s.pendingPublish });
        const built = io.responseOf(`@hstack-verifier/${ctx.opId}`);
        if (built && built.requestDigest !== ctx.requestDigest) throw graphError("ERR_OP_CONFLICT", "Candidate reservation differs");
        if (built) {
          const c = s.candidates[built.candidateId];
          if (built.status !== "integrating") {
            const { requestDigest, ...result } = built;
            return result;
          }
          if (c.state === "green") throw new Step({ intent: { candidateId: c.candidateId, generation: c.generation,
            promotionOp: ctx.opId, requestDigest: ctx.requestDigest, ref: s.integrationRef, old: s.acceptedTip ?? zero(s.startBase), new: c.candidateCommit } });
          if (c.state === "gating") throw busy();
          const published = io.responseOf(`@hstack-published/${ctx.opId}`);
          if (published) {
            const { tokenPath, ...result } = published;
            return result;
          }
          if (c.state === "red") return io.responseOf(`@hstack-gate-proof/${ctx.opId}`);
          return response(s, nodeOf(s, c), c.candidateId);
        }
        if (pending(s)) throw busy();
        const n = selected(s);
        if (!n) throw new Step({ idle: true });
        let reason;
        if (await revParse(s.workspace, s.integrationRef) !== s.acceptedTip) reason = diverged;
        else if (await changedConfig(s)) reason = tampered;
        else if (!await isAncestor(s.workspace, n.attempt.baseSha, s.acceptedTip ?? s.startBase) ||
            !await isAncestor(s.workspace, n.attempt.baseSha, n.attempt.sealedCommit)) reason = "ERR_GIT_MERGE_FAILED";
        throw new Step({ s, n, cid: nextCandidateId(s), reason });
      });
      if (["accepted", "failed_logic", "held_flaky"].includes(result.status)) {
        const s = await head(ctx), w = Object.values(s.worktrees).find(w => w.kind === "worker" &&
          w.nodeId === result.nodeId && w.epoch === s.candidates[result.candidateId].orderedAttempts[0].epoch);
        if (w && w.phase !== "released") await autoRelease(ctx, w.instructionPath, result.status);
      }
      return result;
    } catch (error) {
      if (!(error instanceof Step)) throw error;
      const plan = error.plan;
      if (plan.idle) return { status: "idle" };
      if (plan.finish) await finish(ctx, plan.finish, 0);
      else if (plan.intent) await intend(ctx, plan.intent);
      else await build(ctx, plan);
    }
  }
}
