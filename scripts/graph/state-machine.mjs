// allow: SIZE_OK — command transitions share a single locked protocol and storage boundary.
import { randomInt } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { compileGraph, pathSet } from "./admission.mjs";
import { authenticate, currentLocalKey, failureRecord, gatePolicy, inputs, issue, locate, projectionEligible, validatedArtifact } from "./attempts.mjs";
import { artifactDigest, canonical, crossRunCacheDisabled, gateKey } from "./fingerprint.mjs";
import { git, repoConfigDigest, revParse, treeBytes } from "./git.mjs";
import { canaryStats, pinCarryover, recheckSuspect } from "./host-bridge.mjs";
import { recordVerified, revalidateNode } from "./incremental.mjs";
import { integrate, recoverPublication } from "./integrator.mjs";
import { captureBaseline, captureCanary, captureClaim, captureFinish, captureReady, captureStart } from "./metrics.mjs";
import { compileMassSpec, reduceRun } from "./mass.mjs";
import { applyPatch } from "./patch.mjs";
import { validateReceipt } from "./reducer.mjs";
import { graphError, isRecord, isRunSchemaVersion, nonempty, normalizeV2Policy, Receipt, safeInteger,
  STATE_SCHEMA_V2, validateRunRecords, V2_WRITE_ERROR } from "./schema.mjs";
import { readState, recover, transaction } from "./wal-store.mjs";
import { measureGate } from "./verify-gate.mjs";
import { acceptedRef, defaultMaxOpenWorktrees } from "./worktree.mjs";
import { autoRelease, claimWriter, ensureProvisioned, EvidenceWork, ReleaseWork, requestRelease, SealWork, settleWriter } from "./write-attempts.mjs";

const own = (map, id) => Object.hasOwn(map, id) ? map[id] : undefined;
const held = new Set(["held_blocked", "held_infra", "held_upstream", "failed_logic", "held_flaky", "held_conflict", "held_integration"]);
const active = n => n.status === "claimed" || n.status === "running";
const pending = (n, now) => n.status === "pending" || n.status === "fresh_reset_ready" ||
  (n.status === "retry_wait" && now >= Date.parse(n.notBefore));
const bad = msg => graphError("ERR_GRAPH_SCHEMA", msg);
const notReady = msg => graphError("ERR_NOT_READY", msg);
const reservePrefix = "@hstack-verifier/";
const measuredPrefix = "@hstack-gate-proof/";
export const RESERVED_OP_PREFIXES = Object.freeze([
  reservePrefix, measuredPrefix, "@hstack-worktree/", "@hstack-seal/", "@hstack-publish/", "@hstack-published/",
]);
class CompileWork extends Error {}
class GateWork extends Error {
  constructor(policy) { super("Host verification needed"); this.policy = policy; }
}
const getNode = (state, id) => {
  if (typeof id !== "string" || !own(state.nodes, id)) throw bad("Unknown graph node");
  return state.nodes[id];
};
const runState = state => {
  if (!state) throw graphError("ERR_RUN_NOT_FOUND", "No such graph run");
  if (!isRunSchemaVersion(state.schemaVersion)) throw bad("Unknown run schema version");
  return state;
};
const types = new Map(Object.entries({
  compile: "GraphCompiled", claim: "AttemptClaimed", start: "AttemptStarted", settle: "AttemptSettled", release: "Released",
  retry: "RetryOpened", reduce: "RunReduced", revalidate: "NodeRevalidated", amend: "GraphPatched", expand: "GraphPatched", "inject-repair": "GraphPatched",
}));

async function v2CompileState(workspace, { run, spec }) {
  const opts = { cwd: workspace };
  const top = await git(["rev-parse", "--show-toplevel"], opts);
  if (top.code !== 0 || top.stdout.toString("utf8").replace(/\n$/, "") !== workspace) {
    throw bad("v2 workspace must equal the Git toplevel");
  }
  const integrationRef = acceptedRef(run);
  if ((await git(["check-ref-format", integrationRef], opts)).code !== 0) throw bad("Invalid v2 run ref");
  const { baseSha } = spec;
  if (baseSha !== undefined && (typeof baseSha !== "string" || !/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/.test(baseSha))) {
    throw bad("baseSha must be a commit OID");
  }
  const startBase = await revParse(workspace, `${baseSha ?? "HEAD"}^{commit}`);
  if (!startBase || (baseSha !== undefined && baseSha !== startBase)) throw bad("baseSha must identify a commit");
  const policy = normalizeV2Policy(spec.policy, defaultMaxOpenWorktrees());
  const [include, configDigest, checkoutBytes] = await Promise.all([
    readFile(join(workspace, ".worktreeinclude"), "utf8").catch(error => {
      if (error.code !== "ENOENT") throw error;
      return "";
    }),
    repoConfigDigest(workspace),
    treeBytes(workspace, startBase),
  ]);
  const worktreeInclude = pathSet(include.split(/\r?\n/).filter(line => line.trim() && !line.trimStart().startsWith("#")), ".worktreeinclude");
  return { startBase, acceptedTip: null, integrationGeneration: 0, integrationRef, repoConfigDigest: configDigest,
    worktrees: {}, candidates: {}, worktreeInclude, checkoutBytes, pendingPublish: null, lastPublished: null,
    publishRepairs: 0, policy };
}

async function compile(opts) {
  const { run: runId, spec } = opts;
  if (!isRecord(spec) || (spec.schemaVersion !== undefined && !isRunSchemaVersion(spec.schemaVersion)) ||
      !isAbsolute(opts.workspace ?? "")) throw bad("compile needs a supported spec and absolute workspace");
  const workspace = await realpath(opts.workspace);
  const v2 = spec.schemaVersion === STATE_SCHEMA_V2 ? await v2CompileState(workspace, opts) : {};
  const source = spec.preset === "mass" ? { ...compileMassSpec(spec), schemaVersion: spec.schemaVersion ?? 1 } : spec;
  const { maxPins = 1024, maxAttempts = Number.MAX_SAFE_INTEGER, maxInfraRetries = 3 } = source.limits ?? {};
  for (const [key, value] of Object.entries({ maxPins, maxAttempts, maxInfraRetries })) safeInteger(value, key);
  if (maxInfraRetries > 3) throw bad("maxInfraRetries cannot exceed 3");
  const admitted = compileGraph(source);
  const specs = new Map(source.nodes.map(n => [n.id, n]));
  const nodes = Object.fromEntries(admitted.nodes.map(n => {
    const raw = specs.get(n.id);
    const context = Object.fromEntries(["inputUris", "obligationId", "required", "testPlan", "auditPolicy",
      "gateVersion", "messages", "flaky"].filter(key => Object.hasOwn(raw, key)).map(key => [key, raw[key]]));
    if ("flaky" in context && typeof context.flaky !== "boolean") throw bad("flaky must be a boolean");
    if ("required" in context && typeof context.required !== "boolean") throw bad("required must be a boolean");
    if (context.inputUris && (!Array.isArray(context.inputUris) ||
        context.inputUris.some(uri => typeof uri !== "string" || !/^cas:\/\/sha256\/[a-f0-9]{64}$/.test(uri)))) throw bad("Invalid inputUris");
    return [n.id, { ...n, ...context, volatile: crossRunCacheDisabled(spec.hostProfile, n.volatility),
      schemaVersion: 1, logicalId: n.id, status: "pending",
      highestIssuedEpoch: 0, infraRetries: 0, attempt: null, receiptUri: null, execKey: null, gateKey: null }];
  }));
  const joinMembers = Object.fromEntries(Object.values(nodes).filter(n => n.kind === "reducer").map(n => {
    if (!n.dependsOn.length) throw bad("A reducer needs a nonempty sealed membership");
    return [n.id, n.dependsOn.map(shardId => ({ shardId, obligationId: nodes[shardId].obligationId ?? shardId }))];
  }));
  const state = { schemaVersion: admitted.schemaVersion, runId, workspace, graphRev: 1, status: "open", nodes,
    logicalOutputMap: Object.fromEntries(Object.keys(nodes).map(id => [id, id])), joinMembers,
    limits: { ...admitted.limits, maxPins, maxAttempts, maxInfraRetries }, metrics: admitted.metrics,
    recommendation: admitted.recommendation, attemptsIssued: 0, hostProfile: spec.hostProfile ?? null,
    baseSha: spec.baseSha ?? null, environment: spec.environment ?? {}, policy: spec.policy ?? null, ...v2 };
  const now = Date.now();
  if (spec.baselineComparison) captureBaseline(state, spec.baselineComparison);
  captureReadiness(state, now);
  return { state:validateRunRecords(state), response: { runId, graphRev: 1, metrics: state.metrics, recommendation: state.recommendation } };
}

function capacity(s, n) {
  if (s.attemptsIssued >= s.limits.maxAttempts) return "attempt budget exhausted";
  const peers = Object.values(s.nodes).filter(active);
  const readSlots = s.recommendation === "dag_approved" ? s.limits.readConcurrency : 1;
  if (s.schemaVersion === STATE_SCHEMA_V2) {
    if (n.kind === "write") {
      const open = Object.values(s.worktrees).filter(worktree => worktree.phase !== "released").length;
      if (open >= s.policy.integration.maxOpenWorktrees) return "worktree slots";
    } else if (peers.filter(peer => peer.kind !== "write").length >= readSlots) return "no read slot";
  } else if (n.kind === "write" ? peers.length : peers.some(n => n.kind === "write") || peers.length >= readSlots) {
    return "no exclusive write/read slot";
  }
  const pins = peers.reduce((sum, peer) => sum + peer.attempt.pinSlots, 0);
  if (pins + pinSlots(s, n) > s.limits.maxPins) return "input pin budget exhausted";
  return null;
}
const pinSlots = (s, n) => inputs(s, n).length + n.skills.length + n.rules.length +
  Number(Boolean(n.handoffCarryoverUri)) + Number(n.kind === "reducer") +
  (projectionEligible(n) ? n.dependsOn.length : 0);
const parentsAccepted = (s, n) => n.dependsOn.every(id => getNode(s, id).status === "accepted");

function captureReadiness(s, atMs) {
  captureReady(s, { atMs, nodeIds: Object.values(s.nodes).filter(n => pending(n, atMs) && parentsAccepted(s, n)).map(n => n.id) });
}

function refresh(s) {
  const live = Object.values(s.nodes).filter(n => n.status !== "superseded_by_repair")
    .sort((a, b) => a.topoRank - b.topoRank);
  for (const n of live) {
    if (!["pending", "held_upstream", "fresh_reset_ready", "retry_wait"].includes(n.status)) continue;
    if (n.dependsOn.some(id => held.has(getNode(s, id).status))) n.status = "held_upstream";
    else if (n.status === "held_upstream") n.status = "pending";
  }
  const blockers = live.some(n => n.required !== false && held.has(n.status));
  const unfinished = live.some(n => n.status !== "accepted" && !held.has(n.status));
  const progress = live.some(n => active(n) || ["sealed", "integrating"].includes(n.status) ||
    (["pending", "retry_wait", "fresh_reset_ready"].includes(n.status) &&
    parentsAccepted(s, n) && !capacity(s, n)));
  s.status = !blockers && !unfinished ? (live.some(n => held.has(n.status)) ? "degraded" : "completed") : progress ? "open" : "held";
}

function ready(s, o) {
  const now = o.asOf === undefined ? Date.now() : Date.parse(o.asOf);
  if (!Number.isFinite(now)) throw bad("Invalid asOf timestamp");
  const rows = Object.values(s.nodes).filter(n => pending(n, now) && parentsAccepted(s, n) && !capacity(s, n))
    .map(n => ({ id: n.id, priority: n.priority, topologicalRank: n.topoRank }))
    .sort((a, b) => a.priority - b.priority || a.topologicalRank - b.topologicalRank || (a.id < b.id ? -1 : 1));
  const version = artifactDigest([s.runId, s.graphRev, rows]);
  const [digest, offset] = typeof o.cursor === "string" ? o.cursor.split(":") : [];
  const start = o.cursor == null ? 0 : Number(offset);
  if (o.cursor != null && (!Number.isSafeInteger(start) || start < 1 || start >= rows.length ||
      o.cursor !== `${version}:${start}` || digest !== version)) throw bad("Invalid or outdated ready cursor");
  const page = { runId: s.runId, graphRev: s.graphRev, ready: [], nextCursor: null };
  for (let i = start; i < rows.length; i++) {
    page.ready.push(rows[i]);
    page.nextCursor = i + 1 < rows.length ? `${version}:${i + 1}` : null;
    if (Buffer.byteLength(JSON.stringify({ ok: true, command: "ready", result: page })) + 1 > 8192) {
      page.ready.pop();
      if (!page.ready.length) throw bad("Node ID exceeds ready page size");
      page.nextCursor = `${version}:${i}`;
      break;
    }
  }
  return page;
}

function backoff(n, receipt, now) {
  const ms = 1000 * 2 ** n.infraRetries;
  const jitterMs = randomInt(0, ms + 1);
  const hint = receipt?.retryAfter ?? receipt?.["Retry-After"] ?? 0;
  const retryFloor = typeof hint === "number" || /^\d+$/.test(hint) ? now + Number(hint) * 1000 : Date.parse(hint);
  const date = new Date(Math.max(now + ms + jitterMs, retryFloor));
  if (!Number.isFinite(date.getTime())) throw bad("Invalid Retry-After");
  Object.assign(n, { infraRetries: n.infraRetries + 1, jitterMs, notBefore: date.toISOString(), status: "retry_wait" });
}

async function accept(s, n, o, io) {
  const receipt = o.receipt;
  if (n.gateArgv && o.gateLog !== undefined) throw graphError("ERR_GATE_POLICY", "Cannot replace the admitted gate");
  const subjectDigest = receipt?.provenance?.factDigest;
  if (!subjectDigest) throw graphError("ERR_MISSING_EVIDENCE", "Missing subject digest");
  if (!/^[a-f0-9]{64}$/.test(subjectDigest)) throw graphError("ERR_FORGED_EVIDENCE", "Invalid subject digest");
  if (receipt.workerReportedStatus === "blocked" || receipt.workerReportedStatus === "needs_clarification")
    throw graphError("ERR_MISSING_EVIDENCE", "Worker needs clarification");
  const policy = gatePolicy(n);
  if (policy.gateArgv && !io.measurements) {
    throw new GateWork({ argv:policy.gateArgv, cwd:s.workspace, subjectDigest, timeoutMs:policy.timeoutMs,
      diagnostics:n.flaky ? s.limits.maxFlakyDiagnostics : 0 });
  }
  const log = n.gateArgv ? io.measurements.first : o.gateLog;
  if (!isRecord(log)) throw graphError("ERR_MISSING_EVIDENCE", "Missing host gate measurement");
  if (!n.gateArgv && (
    (Object.hasOwn(log, "runId") && log.runId !== s.runId) ||
    (Object.hasOwn(log, "nodeId") && log.nodeId !== n.id) ||
    (Object.hasOwn(log, "graphRev") && log.graphRev !== n.attempt.graphRev) ||
    (Object.hasOwn(log, "epoch") && log.epoch !== n.attempt.epoch)
  )) throw graphError("ERR_FORGED_EVIDENCE", "Gate log does not match this run, node, or attempt");
  const gateLogUri = await io.put(Buffer.from(canonical(log)));
  n.attempt.gateLogUri = gateLogUri;
  if (n.flaky === true && (Number.isInteger(log.exitCode) && log.exitCode !== 0 || log.timedOut === true || typeof log.signal === "string")) {
    n.firstFailureUri = gateLogUri;
    n.diagnosticUris = [];
    for (const [i, measured] of (io.measurements?.diagnostics ?? []).entries()) {
      n.diagnosticUris.push(await io.put(Buffer.from(canonical({ ...measured, diagnostic: i + 1, firstFailureUri: gateLogUri }))));
    }
    throw graphError("ERR_FLAKY_GATE", "Diagnostic reruns cannot certify a failing gate");
  }
  const checked = Receipt(await validateReceipt(receipt, { ...io, workspaceRoot: s.workspace, gateLogUri }));
  const artifact = await validatedArtifact(checked, io);
  const key = gateKey({ ...policy, candidateTree: artifact, environment: s.environment });
  if (n.revalidateReceiptUri) {
    const pinned = JSON.parse(await io.get(n.kind === "reducer" ? n.workerReceiptUri ?? n.revalidateReceiptUri : n.revalidateReceiptUri));
    if (await validatedArtifact(pinned, io) !== artifact) throw graphError("ERR_FORGED_EVIDENCE", "Revalidation changed the pinned artifact");
  }
  const requiresPolicyKey = !n.gateArgv && (n.revalidateReceiptUri || n.testPlan?.length || n.auditPolicy || n.gateVersion);
  if ((requiresPolicyKey || Object.hasOwn(log, "gateKey")) && log.gateKey !== key)
    throw graphError("ERR_GATE_FAILED", "Gate log is not bound to this policy and artifact");
  let uri = await io.put(Buffer.from(canonical(checked)));
  if (n.kind === "reducer") {
    const reduced = await reduceRun(s, { node: n.id }, io);
    n.reductionUri = reduced.response.indexUri;
    if (reduced.response.status !== "complete") throw graphError("ERR_MISSING_EVIDENCE", "Incomplete sealed reducer coverage");
    n.workerReceiptUri = uri;
    uri = reduced.response.indexUri;
  }
  Object.assign(n, { status: "accepted", receiptUri: uri, artifactDigest: artifact, gateKey: key });
  delete n.revalidateReceiptUri;
  recordVerified(s, n, checked);
}

async function settle(s, n, o, io, now) {
  if (n.status !== "running") throw notReady("Only running attempts may settle");
  const outcome = nonempty(o.outcome, "outcome").toLowerCase();
  const receipt = o.receipt;
  let reason = outcome;
  switch (outcome) {
    case "success": case "completed": case "accepted":
      if (n.attempt.worktree) {
        reason = await settleWriter(s, n, o, io);
        break;
      }
      try { await accept(s, n, o, io); }
      catch (err) {
        reason = err.code;
        if (err.code === "ERR_MISSING_EVIDENCE") n.status = "held_blocked";
        else if (err.code === "ERR_FLAKY_GATE") { n.status = "held_flaky"; n.heldReason = "held:flaky"; }
        else if (["ERR_FORGED_EVIDENCE", "ERR_GATE_FAILED"].includes(err.code)) n.status = "failed_logic";
        else throw err;
      }
      break;
    case "infra_transient":
      if (n.infraRetries >= s.limits.maxInfraRetries) n.status = "held_infra";
      else backoff(n, receipt, now);
      break;
    case "context_rot_abort": {
      const { sessionId, snapshotId, verifiedFacts } = receipt ?? {};
      const carry = pinCarryover({ cwd: s.workspace, sessionId, snapshotId, verifiedFacts,
        attemptId: canonical([o.root, s.runId, n.id, n.attempt.epoch]), dataDir: o.dataDir });
      Object.assign(n, { ...carry, status: "fresh_reset_ready" });
      break;
    }
    case "unresolved_blocked": case "blocked": case "needs_clarification": n.status = "held_blocked"; break;
    case "logic_terminal": n.status = "failed_logic"; break;
    default: throw bad("Unknown settlement outcome");
  }
  const succeeded = n.status === "accepted" || n.status === "sealed";
  if (!succeeded) n.receiptUri = await io.put(Buffer.from(canonical(failureRecord(receipt, reason))));
  if (n.status === "failed_logic") n.failedExecKeys = [...new Set([...(n.failedExecKeys ?? []), n.execKey])];
  // GateWork abandons its first draft. Only the committing draft may touch
  // the canary session or count a host observation.
  observeHost(s, n, o);
  n.attempt.settleOp = o.opId;
  n.attempt.failureClass = succeeded ? null : reason;
  const verified = ["success", "completed", "accepted"].includes(outcome);
  if (verified && n.attempt.gateLogUri) n.attempt.receiptPhase = "checked";
  captureFinish(s, { nodeId: n.id, atMs: Date.now(), verificationStartedAtMs: verified ? n.attempt.verificationStartedAtMs ?? now : undefined,
    usage: n.attempt.observedUsage, outcome: succeeded ? "accepted" :
      ["context_rot_abort", "infra_transient"].includes(outcome) ? "infra" : "rejected" });
  if (outcome === "context_rot_abort") captureCanary(s, "handoffs");
  n.attempt.inputUris = [];
  if (n.attempt.worktree) s.worktrees[n.attempt.worktree.id].settled = true;
  return { runId: s.runId, graphRev: s.graphRev, nodeId: n.id, epoch: n.attempt.epoch, status: n.status, receiptUri: n.receiptUri,
    ...(n.attempt.worktree && { reason }) };
}

export async function dispatch(command, options = {}) {
  if (!isAbsolute(options.root ?? "")) throw bad("root must be an absolute directory");
  const o = { ...options, root: await realpath(options.root) };
  if (typeof o.opId === "string" && RESERVED_OP_PREFIXES.some(prefix => o.opId.startsWith(prefix))) {
    throw bad("Reserved operation ID");
  }
  if (command === "integrate" && !o.run) throw graphError(V2_WRITE_ERROR, "Write integration requires a v2 run");
  const authorized = command === "start" || command === "settle" || command === "release";
  if (authorized) o.run = locate(o.root, o.token, o.run);
  const run = nonempty(o.run, "run");
  if (command === "resume") return recoverPublication({ root: o.root, run, refresh }, runState(await recover(o.root, run)));
  if (command === "status" || command === "ready") {
    const s = runState(await readState(o.root, run));
    return command === "status" ? s : ready(s, o);
  }
  const type = command === "integrate" ? "Integrated" : types.get(command);
  if (!type) throw bad("Unknown graph command");
  if (command === "compile") o.opId ??= "compile";
  if (command === "start") o.opId ??= `start-${artifactDigest(o.token)}`;
  nonempty(o.opId, "opId");
  const { root, opId, ...args } = o;
  const payload = { command, ...Object.fromEntries(Object.entries(args).filter(([, v]) => v !== undefined)) };
  const requestDigest = artifactDigest(payload);
  let authenticated;
  const guard = async s => {
    if (authorized) authenticated = (await authenticate(s, { ...o, command })).id;
    const owner = Object.values(s?.nodes ?? {}).find(n => n.attempt?.verifierOp === opId);
    if (owner && owner.attempt.verifierRequestDigest !== requestDigest)
      throw graphError("ERR_OP_CONFLICT", "Request differs from the reserved verification");
  };
  const effects = { root, run, opId, payload, requestDigest, refresh, guard };
  if (command === "integrate") return integrate(effects);
  let compiledV2, evidence, releaseRecorded = false;
  const commit = () => transaction(root, run, { opId, payload, type, guard }, async (state, store) => {
    const io = { ...store, evidence, budgetContext: o.telemetry?.budgetContext ?? o.hostBudget,
      maxInlineBytesPerNode: state?.limits?.maxInlineBytesPerNode, maxInlineBytesPerWave: state?.limits?.maxInlineBytesPerWave };
    if (command === "compile") {
      if (state) throw graphError("ERR_RUN_EXISTS", "Run already compiled");
      if (o.spec?.schemaVersion === STATE_SCHEMA_V2) {
        if (!compiledV2) throw new CompileWork();
        return compiledV2;
      }
      return compile(o);
    }
    const s = runState(state);
    const now = Date.now();
    let response;
    let extra;
    if (authorized) {
      const n = getNode(s, authenticated);
      if (command === "settle" && n.attempt.verifierOp && n.attempt.verifierOp !== opId)
        throw graphError("ERR_GATE_IN_PROGRESS", "Another settlement owns this attempt");
      if (command === "settle" && n.attempt.measuredUri)
        io.measurements = JSON.parse(await store.get(n.attempt.measuredUri));
      if (command === "release") response = requestRelease(s, o.token, releaseRecorded);
      else if (command === "start") {
        if (n.status !== "claimed") throw notReady("Only claimed attempts may start");
        if (n.attempt.worktree && n.attempt.worktree.phase !== "ready") throw notReady("Worktree is not ready");
        n.attempt.hostHandle = nonempty(o.hostHandle, "hostHandle");
        observeHost(s, n, o);
        n.status = "running";
        n.attempt.receiptPhase = "delivered";
        captureStart(s, { nodeId: n.id, atMs: now });
        response = { runId: run, nodeId: n.id, epoch: n.attempt.epoch, status: n.status };
      } else response = await settle(s, n, o, io, now);
    } else if (type === "GraphPatched") {
      extra = await applyPatch(s, command, o, io);
    } else {
      const n = getNode(s, o.node);
      switch (command) {
        case "claim": {
          if (o.expectedRev !== s.graphRev) throw graphError("ERR_STALE_GRAPH_REV", "Graph revision changed");
          if (!pending(n, now) || !parentsAccepted(s, n)) throw notReady("Node or prerequisites not ready");
          const reason = capacity(s, n);
          if (reason) throw graphError("ERR_HELD_CAPACITY", `held:capacity: ${reason}`);
          captureReadiness(s, now);
          if (n.kind === "reducer") {
            const reduced = await reduceRun(s, { node: n.id }, io);
            n.reductionUri = reduced.response.indexUri;
          }
          const issueAttempt = s.schemaVersion === STATE_SCHEMA_V2 && n.kind === "write" ? claimWriter : issue;
          response = await issueAttempt(s, n, { root, opId, io });
          if (response.error) break;
          n.attempt.pinSlots = pinSlots(s, n);
          s.attemptsIssued++;
          captureClaim(s, { nodeId: n.id, atMs: now });
          observeHost(s, n, o);
          break;
        }
        case "revalidate":
          extra = await revalidateNode(s, o, io, await currentLocalKey(s, n, root));
          break;
        case "retry":
          if (n.status !== "retry_wait" || !pending(n, now)) throw notReady("No eligible infrastructure retry");
          n.status = "pending";
          response = { runId: run, nodeId: n.id, status: n.status };
          break;
        case "reduce":
          if (o.expectedRev !== undefined && o.expectedRev !== s.graphRev) throw graphError("ERR_STALE_GRAPH_REV", "Graph revision changed");
          if (active(n) || ["failed_logic", "superseded_by_repair", "held_blocked", "held_infra", "held_flaky"].includes(n.status))
            throw notReady("Cannot supersede an active or fenced reducer");
          extra = await reduceRun(s, { node: n.id }, io);
          break;
        default: throw bad("Unsupported transition");
      }
    }
    const result = extra ?? { state: s, response };
    refresh(result.state);
    captureReadiness(result.state, Date.now());
    result.state = validateRunRecords(result.state);
    return result;
  });
  try {
    for (;;) {
      let result;
      try { result = await commit(); }
      catch (work) {
        if (work instanceof SealWork || work instanceof ReleaseWork) {
          await work.perform(effects);
          if (work instanceof ReleaseWork) releaseRecorded = true;
        } else if (work instanceof EvidenceWork) evidence = await work.check(o.receipt);
        else throw work;
        continue;
      }
      if (command === "claim" && result.error) throw graphError(result.error.code, result.error.message);
      if (command === "claim" && result.worktreePath) await ensureProvisioned(effects, result);
      if (command === "settle" && result.reason) await autoRelease(effects, o.token, result.status);
      return result;
    }
  }
  catch (err) {
    if (err instanceof CompileWork) {
      compiledV2 = await compile(o);
      return commit();
    }
    if (!(err instanceof GateWork)) throw err;
    // Reserve the external side effect before releasing the journal mutex. A lost
    // verifier is not safe to repeat: an operator can fence it with an amendment.
    let winner = false;
    await transaction(root, run, {opId:reservePrefix + opId, payload, type:"ReceiptDelivered", guard}, async (state, io) => {
      const n = getNode(state, authenticated);
      if (n.status !== "running" || n.attempt.verifierOp) throw notReady("Verification already reserved");
      const uri = await io.put(Buffer.from(canonical(failureRecord(o.receipt, "delivered"))));
      Object.assign(n.attempt, {verifierOp:opId, verifierRequestDigest:requestDigest,
        deliveredUri:uri, verificationStartedAtMs:Date.now()});
      winner = true;
      return {state:validateRunRecords(state),response:{nodeId:n.id,epoch:n.attempt.epoch},refs:[uri]};
    });
    if (!winner) {
      // The earlier verifier may already have committed; a replay returns that
      // exact response. A still-pending reservation must not run the command twice.
      try { return await commit(); } catch (pending) {
        if (!(pending instanceof GateWork)) throw pending;
        throw graphError("ERR_GATE_IN_PROGRESS", "Verification reserved; inspect before fencing");
      }
    }
    const {diagnostics:limit, ...policy} = err.policy;
    const measure = async () => ({ ...await measureGate(policy), factDigest: policy.subjectDigest });
    const first = await measure();
    const diagnostics = [];
    if (first.exitCode !== 0 || first.signal || first.timedOut) {
      for (let i=0; i<limit; i++) {
        try { diagnostics.push(await measure()); }
        catch (cause) {
          if (cause.code !== "ERR_GATE_SPAWN") throw cause;
          diagnostics.push({error:cause.code,argv:policy.argv,subjectDigest:policy.subjectDigest});
        }
      }
    }
    await transaction(root, run, {opId:measuredPrefix + opId, payload, type:"GateMeasured", guard}, async (state, io) => {
      const n = getNode(state, authenticated);
      if (n.status !== "running" || n.attempt.verifierOp !== opId) throw notReady("Gate no longer reserved");
      const uri = await io.put(Buffer.from(canonical({first, diagnostics})));
      n.attempt.measuredUri = uri;
      return {state:validateRunRecords(state), response:{nodeId:n.id, epoch:n.attempt.epoch}, refs:[uri]};
    });
    return commit();
  }
}

function observeHost(s, n, o) {
  const event = o.telemetry?.canaryEvent;
  const kinds = new Map([["load_failure", "loadFailures"], ["suspect", "suspects"], ["recovered", "recoveries"]]);
  if (kinds.has(event)) captureCanary(s, kinds.get(event));
  if (o.telemetry?.dispatch === "headless-process" && o.telemetry.usageSource === "host-json") {
    n.attempt.usageSource = "host-json";
  }
  if (o.telemetry?.usage) n.attempt.observedUsage = { ...n.attempt.observedUsage,
    ...Object.fromEntries(["inputTokens", "outputTokens", "costUsd"].filter(k =>
      Number.isFinite(o.telemetry.usage[k]) && o.telemetry.usage[k] >= 0).map(k => [k, o.telemetry.usage[k]])) };
  if (!o.probe) return;
  const { sessionId } = o.probe;
  const params = { sessionId, dataDir: o.dataDir };
  const previous = canaryStats(params);
  n.attempt.probe = recheckSuspect({ ...params, cwd: s.workspace, probe: o.probe });
  const current = canaryStats(params);
  if (current.probeFailures > previous.probeFailures) captureCanary(s, "probeFailures");
  n.attempt.canaryStats = current;
}
