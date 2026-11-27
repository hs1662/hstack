import { artifactDigest, canonical, crossRunCacheDisabled } from './fingerprint.mjs';
import { graphError, schemaError, SCHEMA_VERSION } from './schema.mjs';

const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const lookup = (map, id) => Object.hasOwn(map, id) ? map[id] : null;
const needsWork = message => graphError('ERR_REVALIDATION_REQUIRED', message);

/** Only a declared, closed receipt schema is narrower than the full artifact. */
export function edgeViewKey(consumer, parent) {
  if (consumer.kind === 'read' && consumer.projection === 'facts-v1' &&
      consumer.projectionConfig == null && hash(parent.factViewDigest)) {
    return artifactDigest(['edge:facts-v1', parent.factViewDigest]);
  }
  return hash(parent.artifactDigest) ? parent.artifactDigest : null;
}

function deliveredView(consumer, parent, projection) {
  return projection === 'facts-v1' ? edgeViewKey(consumer, parent) :
    hash(parent.artifactDigest) ? parent.artifactDigest : null;
}

function views(state, node, projection) {
  return Object.fromEntries(node.dependsOn.map(id => {
    const parent = lookup(state.nodes, id);
    return [id, parent?.status === 'accepted' ? deliveredView(node, parent, projection) : null];
  }));
}

// Both edge sets matter: after removal or repair the old reverse path can
// be absent, and after an addition the new path need not have existed before.
export function markDirty(previous, next, roots) {
  const reverse = new Map();
  for (const graph of [previous, next]) {
    for (const node of Object.values(graph.nodes)) {
      if (node.status === 'superseded_by_repair') continue;
      for (const parent of node.dependsOn) {
        if (!reverse.has(parent)) reverse.set(parent, new Set());
        reverse.get(parent).add(node.id);
      }
    }
  }
  const affected = new Set(roots);
  for (const id of affected) {
    for (const child of reverse.get(id) ?? []) affected.add(child);
  }
  for (const id of affected) {
    const n = lookup(next.nodes, id);
    if (!n || n.status === 'superseded_by_repair') continue;
    const old = lookup(previous.nodes, id);
    if (old?.status === 'accepted' && old.verifiedResult) n.priorVerified = old.verifiedResult;
    const reasons = new Map((n.dirtyReasons ?? []).map(r => [r.parentId ?? null, r]));
    if (roots.includes(id)) reasons.set(null, { kind: 'definition' });
    const before = new Set(old?.dependsOn ?? []), after = new Set(n.dependsOn);
    for (const parentId of new Set([...before, ...after])) {
      const kind = !after.has(parentId) ? 'removed' : !before.has(parentId) ? 'added' : 'upstream';
      if (kind !== 'upstream' || (affected.has(parentId) && !reasons.has(parentId))) {
        reasons.set(parentId, { kind, parentId });
      }
    }
    n.dirtyReasons = [...reasons.values()];
  }
  return affected;
}

function discharge(state, parent) {
  for (const n of Object.values(state.nodes)) {
    if (!n.dirtyReasons?.some(r => r.kind === 'upstream' && r.parentId === parent.id)) continue;
    const key = deliveredView(n, parent, n.priorVerified?.deliveredProjection);
    if (key && n.priorVerified && lookup(n.priorVerified.inputs, parent.id) === key) {
      n.dirtyReasons = n.dirtyReasons.filter(r => r.kind !== 'upstream' || r.parentId !== parent.id);
    }
  }
}

/** Called only after trusted verification of the new receipt in the transaction draft. */
export function recordVerified(state, node, checkedReceipt) {
  if (state.schemaVersion !== SCHEMA_VERSION) throw schemaError('verification requires a v1 run');
  if (!hash(node.execKey)) throw schemaError('verification requires the issued execution key');
  if (node.status !== 'accepted' || !hash(node.artifactDigest)) throw needsWork('missing verified artifact');
  const old = node.priorVerified ?? node.verifiedResult;
  node.verifiedAtRev = state.graphRev;
  node.changedAtRev = old?.artifactDigest === node.artifactDigest ? old.changedAtRev : state.graphRev;
  node.factViewDigest = hash(checkedReceipt?.provenance?.factDigest) ? checkedReceipt.provenance.factDigest : null;
  node.verifiedResult = {
    schemaVersion: SCHEMA_VERSION, receiptUri: node.receiptUri, execKey: node.execKey, gateKey: node.gateKey,
    localKey: node.attempt?.localKey ?? null, artifactDigest: node.artifactDigest,
    factViewDigest: node.factViewDigest, changedAtRev: node.changedAtRev,
    deliveredProjection: node.attempt?.deliveredProjection ?? null,
    inputs: views(state, node, node.attempt?.deliveredProjection),
  };
  node.dirtyReasons = [];
  delete node.priorVerified;
  discharge(state, node);
}

/** Transaction callback for NodeRevalidated, never for ready, claim or GraphPatched. */
export async function revalidateNode(previous, { node: id, expectedRev }, io, localKey) {
  if (previous.schemaVersion !== SCHEMA_VERSION) throw schemaError('revalidation requires a v1 run');
  if (!Number.isSafeInteger(expectedRev) || previous.graphRev !== expectedRev) {
    throw graphError('ERR_STALE_GRAPH_REV', 'stale revalidation');
  }
  const n = lookup(previous.nodes, id);
  const proof = n?.priorVerified;
  if (proof && (proof.schemaVersion !== SCHEMA_VERSION || !hash(proof.execKey))) {
    throw schemaError('revalidation requires a v1 verification snapshot with an execution key');
  }
  if (!proof || n.volatile || n.status !== 'pending' || n.kind !== 'read' || n.dirtyReasons?.length ||
      n.revalidateReceiptUri || n.gateArgv || n.testPlan?.length || n.auditPolicy || n.gateVersion ||
      !hash(localKey) || proof.localKey !== localKey || n.failedExecKeys?.includes(proof.execKey) ||
      crossRunCacheDisabled(previous.hostProfile, n.volatility) || !/^cas:\/\/sha256\/[a-f0-9]{64}$/.test(proof.receiptUri)) {
    throw needsWork('fresh execution or trusted gate required');
  }
  const current = views(previous, n, proof.deliveredProjection);
  if (Object.values(current).some(key => !key) || canonical(current) !== canonical(proof.inputs)) {
    throw needsWork('input identity or value changed');
  }
  await io.get(proof.receiptUri);
  const state = structuredClone(previous);
  const node = state.nodes[id];
  Object.assign(node, {
    status: 'accepted', receiptUri: proof.receiptUri, execKey: proof.execKey, gateKey: proof.gateKey,
    verifiedAtRev: expectedRev, changedAtRev: proof.changedAtRev, artifactDigest: proof.artifactDigest,
    factViewDigest: proof.factViewDigest, verifiedResult: node.priorVerified,
  });
  delete node.priorVerified;
  discharge(state, node);
  const body = { nodeId: id, graphRev: expectedRev, priorReceiptUri: proof.receiptUri, reason: 'unchanged verified inputs' };
  return { state, response: { ...body, status: 'accepted' }, refs: [proof.receiptUri], body };
}
