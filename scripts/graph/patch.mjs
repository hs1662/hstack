import { compileGraph } from './admission.mjs';
import { artifactDigest, canonical, crossRunCacheDisabled } from './fingerprint.mjs';
import { markDirty } from './incremental.mjs';
import { captureFinish } from './metrics.mjs';
import { graphError, immutable, isRecord, isRunSchemaVersion, safeInteger, STATE_SCHEMA_V2, V2_WRITE_ERROR } from './schema.mjs';

const invalid = message => graphError('ERR_GRAPH_PATCH', message);
const retired = 'superseded_by_repair';
const generation = ['prompt', 'skills', 'rules', 'readScope', 'dependsOn', 'projection', 'projectionConfig', 'volatility'];
const policy = ['testPlan', 'auditPolicy', 'gateVersion', 'gateArgv', 'timeoutMs'];
const definition = ['schemaVersion', 'id', 'kind', 'dependsOn', 'writeScope', 'estimatedMinutes', 'priority',
  ...generation, ...policy, 'messages', 'required', 'logicalId', 'obligationId', 'inputUris',
  'repairOf', 'repairDepth', 'failureReceiptUri'];
const pick = (object, keys) => Object.fromEntries(keys.filter(k => Object.hasOwn(object, k)).map(k => [k, object[k]]));
const text = value => typeof value === 'string' && value.trim().length > 0;
const cas = value => typeof value === 'string' && /^cas:\/\/sha256\/[a-f0-9]{64}$/.test(value);

function fields(object, allowed) {
  if (!isRecord(object)) throw invalid('expected a patch object');
  if (['integrate', 'write'].includes(object.kind) || Object.hasOwn(object, 'writeScope')) {
    throw graphError(V2_WRITE_ERROR, 'patches cannot introduce writes or integration');
  }
  for (const key of Object.keys(object)) {
    if (!allowed.includes(key)) throw invalid(`unexpected patch field: ${key}`);
  }
}

function insert(state, id, source) {
  if (Object.hasOwn(state.nodes, id) || Object.hasOwn(state.logicalOutputMap, id)) {
    throw invalid(`generated ID already exists: ${id}`);
  }
  const node = {
    ...pick(source, definition), id, logicalId: id, highestIssuedEpoch: 0, status: 'pending',
    attempt: null, receiptUri: null, execKey: null, gateKey: null, infraRetries: 0,
  };
  // IDs are data, including "__proto__"; never assign through inherited setters.
  Object.defineProperty(state.nodes, id, { value: node, writable: true, enumerable: true, configurable: true });
  return node;
}

function expand(state, node, patch) {
  if (node.kind === 'write') throw graphError(V2_WRITE_ERROR, 'a writer cannot fan out');
  if (node.kind !== 'read' || !Array.isArray(patch.shards) || !patch.shards.length) {
    throw invalid('expand requires a read node and a nonempty shard list');
  }
  const members = patch.shards.map(shard => {
    fields(shard, ['stableShardKey', 'obligationId', 'prompt', 'readScope']);
    const key = shard.stableShardKey;
    if (typeof key !== 'string' || !/^[a-zA-Z0-9_.-]+$/.test(key)) throw invalid('invalid stableShardKey');
    const obligationId = shard.obligationId ?? key;
    if (!text(obligationId)) throw invalid('invalid obligationId');
    const shardId = `${node.id}::shard::${key}`;
    const child = insert(state, shardId, node);
    Object.assign(child, pick(shard, ['prompt', 'readScope']), { obligationId });
    state.logicalOutputMap[shardId] = shardId;
    return { shardId, obligationId };
  }).sort((a, b) => a.shardId < b.shardId ? -1 : 1);
  Object.defineProperty(state.joinMembers, node.id, {
    value: members, writable: true, configurable: true, enumerable: true,
  });
  node.kind = 'reducer';
  node.dependsOn = members.map(m => m.shardId);
}

function amend(node, patch) {
  const changes = {};
  for (const [group, keys] of [['exec', generation], ['gate', policy]]) {
    if (!Object.hasOwn(patch, group)) continue;
    fields(patch[group], keys);
    Object.assign(changes, patch[group]);
  }
  if (Object.hasOwn(changes, 'dependsOn') && node.kind === 'reducer') throw invalid('cannot edit a sealed reducer membership');
  if (Object.hasOwn(changes, 'gateVersion')) safeInteger(changes.gateVersion, 'gateVersion', 1);
  if (Object.hasOwn(changes, 'auditPolicy') && !isRecord(changes.auditPolicy)) throw invalid('invalid auditPolicy');
  if (Object.hasOwn(changes, 'testPlan') &&
      !(Array.isArray(changes.testPlan) && changes.testPlan.every(text))) throw invalid('invalid testPlan');
  const changed = Object.keys(changes).filter(key =>
    !Object.hasOwn(node, key) || canonical(changes[key]) !== canonical(node[key]));
  if (!changed.length) throw invalid('amend requires a change to execution or gate policy');
  const policyOnly = changed.every(key => policy.includes(key));
  if (policyOnly && node.status === 'failed_logic' && !node.revalidateReceiptUri) {
    throw invalid('repair failed generation before attempting revalidation');
  }
  Object.assign(node, changes);
  return policyOnly;
}

async function repair(state, source, patch, io) {
  const failure = source.receiptUri;
  if (source.status !== 'failed_logic' || !cas(failure)) throw invalid('repair requires a failed node with CAS evidence');
  const depth = safeInteger(source.repairDepth ?? 0, 'repairDepth') + 1;
  if (depth > 2) throw graphError('ERR_REPAIR_DEPTH', 'maximum repair depth is two');
  if (Object.hasOwn(patch, 'prompt') && !text(patch.prompt)) throw invalid('invalid repair prompt');
  await io.get(failure);
  const id = `${source.id}::repair::e${depth}`;
  const target = insert(state, id, source);
  Object.assign(target, {
    logicalId: source.logicalId, repairOf: source.id, repairDepth: depth, failureReceiptUri: failure,
    inputUris: [...new Set([...(source.inputUris ?? []), failure])], prompt: patch.prompt ?? source.prompt,
  });
  source.status = retired;
  // Keep the original attempt for audit, but not as a replay authorization.
  if (source.attempt) source.highestIssuedEpoch = safeInteger(source.highestIssuedEpoch + 1, 'fencing epoch', 1);
  for (const n of Object.values(state.nodes)) {
    if (n.status === retired) continue;
    if (n.dependsOn.includes(source.id)) n.dependsOn = n.dependsOn.map(dep => dep === source.id ? id : dep);
    if (Object.hasOwn(state.joinMembers, n.id)) {
      state.joinMembers[n.id] = state.joinMembers[n.id].map(m => m.shardId === source.id ? { ...m, shardId: id } : m);
    }
  }
  if (Object.hasOwn(state.joinMembers, source.id)) state.joinMembers[id] = structuredClone(state.joinMembers[source.id]);
  for (const [logical, physical] of Object.entries(state.logicalOutputMap)) {
    if (physical === source.id) state.logicalOutputMap[logical] = id;
  }
  return target;
}

// Traverse the newly admitted DAG in topological order. Invalidating only direct
// consumers leaves old grandchild tokens (and previously accepted results) valid.
function invalidate(state, node, reuse) {
  // Fencing a token cannot stop a host that is already writing to the v1
  // workspace. Its slot must stay occupied until the host settles the attempt.
  if (state.schemaVersion !== STATE_SCHEMA_V2 && node.kind === 'write' && ['claimed', 'running'].includes(node.status)) {
    throw graphError(V2_WRITE_ERROR, 'cannot invalidate an active workspace writer');
  }
  if (node.status === 'integrating') {
    for (const candidate of Object.values(state.candidates)) {
      if (candidate.orderedAttempts.some(attempt => attempt.nodeId === node.id &&
          attempt.epoch === node.attempt?.epoch)) candidate.state = 'discarded';
    }
  }
  if (node.highestIssuedEpoch > 0 || node.attempt) {
    node.highestIssuedEpoch = safeInteger(node.highestIssuedEpoch + 1, 'fencing epoch', 1);
  }
  Object.assign(node, { status: 'pending', attempt: null, receiptUri: null, gateKey: null });
  if (!reuse) node.execKey = null;
  if (!reuse) delete node.artifactDigest;
  for (const key of ['revalidateReceiptUri', 'notBefore', 'handoffCarryoverUri', 'reductionUri', 'workerReceiptUri']) {
    delete node[key];
  }
  if (state.schemaVersion === STATE_SCHEMA_V2 && node.kind === 'write') {
    delete node.sealedCommit;
    delete node.conflict;
    delete node.heldReason;
  }
  if (reuse) node.revalidateReceiptUri = reuse;
}

const commands = { expand: ['shards'], amend: ['exec', 'gate'], 'inject-repair': ['prompt'] };

/** Compute one GraphPatched WAL transaction; never publish or mutate the caller's state. */
export async function applyPatch(previous, command, options, io) {
  if (!Object.hasOwn(commands, command)) throw invalid('unknown patch command');
  if (!isRunSchemaVersion(previous?.schemaVersion)) throw invalid('expected supported run state');
  if (!Number.isSafeInteger(options.expectedRev) || options.expectedRev !== previous.graphRev) {
    throw graphError('ERR_STALE_GRAPH_REV', 'expectedRev does not match the current graph revision');
  }
  const graphRev = safeInteger(previous.graphRev + 1, 'graphRev', 1);
  const patch = immutable(options.patch ?? {});
  fields(patch, ['patchId', 'reason', ...commands[command]]);
  const { patchId = options.opId, reason = command } = patch;
  if (!text(options.opId) || !text(patchId) || !text(reason)) throw invalid('expected nonempty opId, patchId and reason');
  if (!text(options.node) || !Object.hasOwn(previous.nodes, options.node)) throw invalid('patch target does not exist');
  const state = structuredClone(previous);
  const source = state.nodes[options.node];
  if (source.status === retired) throw invalid('cannot mutate a superseded node');
  let target = source;
  let reuse = null;
  switch (command) {
    case 'expand': expand(state, source, patch); break;
    case 'inject-repair': target = await repair(state, source, patch, io); break;
    case 'amend':
      if (amend(source, patch)) {
        reuse = source.revalidateReceiptUri ??
          (source.status === 'accepted' ? source.workerReceiptUri ?? source.receiptUri : null);
        if (reuse != null) {
          if (!cas(reuse)) throw invalid('cannot revalidate a mutable receipt');
          await io.get(reuse);
        }
      }
      break;
  }
  const live = Object.values(state.nodes).filter(n => n.status !== retired);
  const admitted = compileGraph({ schemaVersion: state.schemaVersion, limits: state.limits,
    nodes: state.schemaVersion === STATE_SCHEMA_V2 ? live.map(({ schemaVersion, ...spec }) => spec) : live });
  if (admitted.nodes.length !== live.length) throw graphError(V2_WRITE_ERROR, 'patch would merge live writer identities');
  const affected = markDirty(previous, state, [...new Set([source.id, target.id])]);
  const retiredAtMs = Date.now();
  for (const spec of admitted.nodes) {
    const node = state.nodes[spec.id];
    if (affected.has(node.id)) {
      if (node.attempt && ['claimed', 'running'].includes(node.status)) {
        captureFinish(state, { nodeId: node.id, atMs: retiredAtMs, outcome: 'superseded' });
      }
      invalidate(state, node, node.id === target.id ? reuse : null);
    }
    if (affected.has(node.id) || !Object.hasOwn(previous.nodes, node.id)) {
      Object.assign(node, spec, { volatile: crossRunCacheDisabled(state.hostProfile, spec.volatility) });
    }
  }
  state.graphRev = graphRev;
  state.metrics = admitted.metrics;
  state.recommendation = admitted.recommendation;
  const newGraphHash = artifactDigest({
    schemaVersion: state.schemaVersion, nodes: admitted.nodes.map(n => pick(state.nodes[n.id], definition)),
    limits: state.limits, joinMembers: state.joinMembers, logicalOutputMap: state.logicalOutputMap,
  });
  const ops = [{ op: command, node: source.id, ...pick(patch, commands[command]) }];
  const refs = reuse ? [reuse] : command === 'inject-repair' ? [target.failureReceiptUri] : [];
  return {
    state, refs, response: { runId: state.runId, graphRev, patchId, newGraphHash, nodeId: target.id },
    body: { parentRev: previous.graphRev, patchId, reason, ops, newGraphHash },
  };
}
