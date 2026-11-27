import { graphError } from "./schema.mjs";

const canaryKinds = ["loadFailures", "suspects", "probeFailures", "handoffs", "recoveries"];
const usageFields = ["inputTokens", "outputTokens", "costUsd"];
const outcomes = ["accepted", "rejected", "infra", "superseded"];
const invalid = message => graphError("ERR_GRAPH_METRICS", message);
const own = (record, key) => Object.hasOwn(record, key) ? record[key] : undefined;
const text = value => typeof value === "string" && value.trim().length > 0;
const measured = value => Number.isFinite(value) && value >= 0;

function time(value) {
  if (!measured(value)) throw invalid("Expected a nonnegative timestamp in milliseconds");
  return value;
}

function telemetry(state) {
  return state.telemetry ??= { attempts: [], ready: {}, canary: {} };
}

/** Capture structural readiness, independent of slot/host admission. */
export function captureReady(state, { atMs, nodeIds }) {
  const readyAt = time(atMs);
  const data = telemetry(state);
  data.ready = Object.fromEntries(nodeIds.map(id => [id, own(data.ready, id) ?? readyAt]));
}

function attemptNode(state, id) {
  const node = own(state.nodes, id);
  if (!Number.isSafeInteger(node?.attempt?.epoch) || node.attempt.epoch < 1) {
    throw invalid(`No issued attempt for ${id}`);
  }
  return node;
}

/** Snapshot causal edges while this revision and its dependency attempts are current. */
export function captureClaim(state, { nodeId, atMs }) {
  const claimedAtMs = time(atMs);
  const node = attemptNode(state, nodeId);
  const data = telemetry(state);
  const logicalId = node.logicalId ?? nodeId;
  const latest = new Map();
  let previous;
  for (const [i, a] of data.attempts.entries()) {
    latest.set(a.nodeId, i);
    if (a.logicalId === logicalId) previous = i;
  }
  if (data.attempts[latest.get(nodeId)]?.epoch === node.attempt.epoch) return;
  const parents = node.dependsOn.map(id => latest.get(id));
  parents.push(previous);
  if (!latest.has(nodeId)) {
    // On expansion, the old read can now precede shards rather than the reducer.
    for (const [id, members] of Object.entries(state.joinMembers ?? {})) {
      if (members.some(member => member.shardId === nodeId)) parents.push(latest.get(id));
    }
  }
  data.attempts.push({
    nodeId, logicalId, epoch: node.attempt.epoch, rework: previous !== undefined,
    parents: [...new Set(parents.filter(i => i !== undefined))],
    readyAtMs: own(data.ready, nodeId) ?? null, claimedAtMs,
  });
  delete data.ready[nodeId];
}

function currentAttempt(state, nodeId) {
  const { attempt: { epoch } } = attemptNode(state, nodeId);
  const attempt = state.telemetry?.attempts.find(a => a.nodeId === nodeId && a.epoch === epoch);
  // Old journals may contain a claim made before metrics capture was installed.
  return attempt;
}

export function captureStart(state, { nodeId, atMs }) {
  const startedAtMs = time(atMs);
  const attempt = currentAttempt(state, nodeId);
  if (attempt && attempt.outcome === undefined) attempt.startedAtMs ??= startedAtMs;
}

/** The transition supplies host-observed usage only; never pass a worker receipt. */
export function captureFinish(state, { nodeId, atMs, outcome, verificationStartedAtMs, usage }) {
  const finishedAtMs = time(atMs);
  if (!outcomes.includes(outcome)) throw invalid(`Unknown attempt outcome: ${outcome}`);
  const attempt = currentAttempt(state, nodeId);
  if (!attempt || attempt.outcome !== undefined) return;
  const verification = verificationStartedAtMs == null ? null : time(verificationStartedAtMs);
  const observed = Object.fromEntries(usageFields.flatMap(key => {
    const value = usage?.[key];
    return measured(value) && (key === "costUsd" || Number.isSafeInteger(value)) ? [[key, value]] : [];
  }));
  Object.assign(attempt, { finishedAtMs, verificationStartedAtMs: verification, outcome, usage: observed });
}

/** Record an observed diagnostic event, independent of the attempt's outcome. */
export function captureCanary(state, kind) {
  if (!canaryKinds.includes(kind)) throw invalid(`Unknown canary event: ${kind}`);
  const { canary } = telemetry(state);
  canary[kind] = (canary[kind] ?? 0) + 1;
}

export function captureBaseline(state, { pairId, mode, baselineRunId } = {}) {
  if (!text(pairId) || !["dag", "single-layer"].includes(mode) ||
      (baselineRunId !== undefined && (mode !== "dag" || !text(baselineRunId) || baselineRunId === state.runId))) {
    throw invalid("Expected a pairId, dag or single-layer mode, and an optional distinct DAG baselineRunId");
  }
  telemetry(state).baseline = { pairId, mode, baselineRunId: baselineRunId ?? null };
}

const duration = (from, to) => measured(from) && measured(to) ? Math.max(0, to - from) : 0;

function phases(a) {
  const workEnd = a.verificationStartedAtMs ?? a.finishedAtMs;
  return {
    queue: [a.readyAtMs, a.claimedAtMs],
    dispatch: [a.claimedAtMs, a.startedAtMs ?? a.verificationStartedAtMs ?? a.finishedAtMs],
    work: [a.startedAtMs, workEnd],
    verification: [a.verificationStartedAtMs, a.finishedAtMs],
  };
}

function spanFor(attempt, intervals, paths) {
  function extend({ weight, end }) {
    for (const [from, to] of intervals) {
      if (duration(from, to) > 0) {
        weight += duration(Math.max(from, end), to);
        end = Math.max(end, to);
      }
    }
    return { weight, end };
  }
  // A captured parent must precede the claim, but its tail may overlap queue
  // readiness (for example, when fencing a read and opening replacement shards).
  let best = extend({ weight: 0, end: 0 });
  for (const index of attempt.parents) {
    const candidate = extend(paths[index]);
    if (candidate.weight > best.weight) best = candidate;
  }
  return best;
}

function summarize(state) {
  const attempts = state.telemetry?.attempts ?? [];
  const result = {
    usefulWorkMs: 0, criticalPathMs: 0, queueWaitMs: 0, dispatchOverheadMs: 0, verificationMs: 0,
    reworkCount: 0, rejectedCount: 0,
  };
  const paths = [];
  for (const a of attempts) {
    const p = phases(a);
    if (a.outcome === "accepted") result.usefulWorkMs += duration(...p.work);
    result.queueWaitMs += duration(...p.queue);
    result.dispatchOverheadMs += duration(...p.dispatch);
    result.verificationMs += duration(...p.verification);
    result.reworkCount += Number(a.rework);
    result.rejectedCount += Number(a.outcome === "rejected");
    const path = spanFor(a, Object.values(p), paths);
    paths.push(path);
    result.criticalPathMs = Math.max(result.criticalPathMs, path.weight);
  }
  const usage = Object.fromEntries(usageFields.map(key => {
    if (!attempts.length || state.attemptsIssued > attempts.length ||
        attempts.some(a => a.usage?.[key] === undefined)) return [key, null];
    const total = attempts.reduce((sum, a) => sum + a.usage[key], 0);
    return [key, measured(total) && (key === "costUsd" || Number.isSafeInteger(total)) ? total : null];
  }));
  return { ...result, usage };
}

function baselineComparison(state, baselineState) {
  const config = state.telemetry?.baseline;
  if (!config) return null;
  const baseline = baselineState?.telemetry?.baseline;
  const paired = config.mode === "dag" && config.baselineRunId !== null &&
    config.baselineRunId === baselineState?.runId && baseline?.mode === "single-layer" &&
    config.pairId === baseline.pairId;
  return { ...config, paired, baseline: paired ? summarize(baselineState) : null };
}

/** Read only captured events, never estimates, current node status, or the live clock. */
export function metrics(state, baselineState) {
  const data = state.telemetry;
  return {
    ...summarize(state),
    canaryStats: Object.fromEntries(canaryKinds.map(kind => [kind, data?.canary?.[kind] ?? 0])),
    baselineComparison: baselineComparison(state, baselineState),
  };
}
