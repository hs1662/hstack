import { graphError, immutable, isRecord, nonempty, normalizeGateCommand,
  normalizeVolatility, safeInteger, schemaError, SCHEMA_VERSION, V2_WRITE_ERROR } from './schema.mjs';

const defaults = Object.freeze({
  maxNodes: 256, maxWidth: 64, maxDepth: 64, readConcurrency: 6,
  minParallelFraction: 0.65, maxEdgeDensity: 1.2, minEstimatedMinutes: 15, minIndependent: 3,
  maxInfraRetries: 3,
});
const optionalLimits = ['maxPins', 'maxAttempts'];
const limitError = message => graphError('ERR_GRAPH_LIMIT', message);
const v2Error = message => graphError(V2_WRITE_ERROR, message);
const duplicate = message => graphError('ERR_GRAPH_DUPLICATE', message);
const uniqueSorted = values => [...new Set(values)].sort();

function normalizeLimits(input = {}) {
  if (!isRecord(input)) throw schemaError('limits must be an object');
  for (const key of Object.keys(input)) {
    if (!Object.hasOwn(defaults, key) && !optionalLimits.includes(key)) throw schemaError(`unknown graph limit: ${key}`);
  }
  const limits = { ...defaults, ...input };
  for (const key of ['maxNodes', 'maxWidth', 'maxDepth', 'readConcurrency', 'minEstimatedMinutes', 'minIndependent']) {
    if (!Number.isSafeInteger(limits[key]) || limits[key] < 1) throw limitError(`${key} must be a positive safe integer`);
  }
  for (const key of ['maxInfraRetries', ...optionalLimits]) {
    if (Object.hasOwn(limits, key) && (!Number.isSafeInteger(limits[key]) || limits[key] < 0)) {
      throw limitError(`${key} must be a nonnegative safe integer`);
    }
  }
  if (limits.readConcurrency > 16) throw limitError('readConcurrency must not exceed 16');
  if (limits.maxNodes > 1024) throw limitError('maxNodes must not exceed 1024');
  for (const key of ['minParallelFraction', 'maxEdgeDensity']) {
    if (!Number.isFinite(limits[key]) || limits[key] < 0) throw limitError(`${key} must be finite and nonnegative`);
  }
  if (limits.minParallelFraction > 1) throw limitError('minParallelFraction must not exceed 1');
  return limits;
}

function strings(value, label) {
  if (!Array.isArray(value)) throw schemaError(`${label} must be an array`);
  return Array.from(value, entry => nonempty(entry, label));
}

function pathSet(value, label) {
  return uniqueSorted(strings(value, label).map(path => {
    if (path === '.') return path;
    const relative = path.replace(/\/$/, '');
    if (/^[A-Za-z]:|[\\\0\r\n]/.test(relative)
        || relative.split('/').some(part => part === '' || part === '..' || part === '.')) {
      throw schemaError(`${label} must use repository-relative literal paths: ${JSON.stringify(path)}`);
    }
    return relative;
  }));
}

function normalizeNode(input) {
  if (!isRecord(input)) throw schemaError('node must be an object');
  const id = nonempty(input.id, 'node.id');
  const kind = input.kind;
  if (kind === 'integrate') throw v2Error(`integration is reserved for v2: ${id}`);
  if (!['read', 'verify', 'reducer', 'write'].includes(kind)) throw schemaError(`invalid kind for ${id}`);
  const deps = strings(input.dependsOn ?? [], `${id}.dependsOn`);
  const dependsOn = uniqueSorted(deps);
  if (deps.length !== dependsOn.length) throw duplicate(`duplicate dependency for ${id}`);
  const writeScope = pathSet(input.writeScope ?? [], `${id}.writeScope`);
  if ((kind === 'write') !== (writeScope.length > 0)) {
    throw schemaError(`${id} must declare a nonempty writeScope exactly when kind is write`);
  }
  const required = Object.hasOwn(input, 'required') ? input.required : true;
  if (typeof required !== 'boolean') throw schemaError(`${id}.required must be a boolean`);
  return {
    id, kind, required, dependsOn, writeScope, readScope: pathSet(input.readScope ?? [], `${id}.readScope`),
    estimatedMinutes: safeInteger(input.estimatedMinutes ?? 1, `${id}.estimatedMinutes`, 1),
    priority: safeInteger(input.priority ?? 0, `${id}.priority`, Number.MIN_SAFE_INTEGER),
    prompt: nonempty(input.prompt ?? '', `${id}.prompt`),
    skills: strings(input.skills ?? [], `${id}.skills`), rules: strings(input.rules ?? [], `${id}.rules`),
    ...normalizeGateCommand(input),
    ...Object.fromEntries(['projection', 'projectionConfig'].filter(key => Object.hasOwn(input, key))
      .map(key => [key, immutable(input[key])])),
    ...(Object.hasOwn(input, 'volatility') && { volatility: normalizeVolatility(input.volatility) }),
  };
}

function analyze(nodes, limits) {
  const byId = new Map(nodes.map(node => [node.id, node]));
  if (byId.size !== nodes.length) throw duplicate('duplicate node ID');
  const children = new Map(nodes.map(node => [node.id, []]));
  const pending = new Map();
  for (const node of nodes) {
    pending.set(node.id, node.dependsOn.length);
    for (const id of node.dependsOn) {
      if (!byId.has(id)) throw graphError('ERR_GRAPH_DANGLING', `${node.id} depends on missing node ${id}`);
      children.get(id).push(node.id);
    }
  }
  const ready = nodes.filter(node => node.dependsOn.length === 0).map(node => node.id);
  const ordered = [];
  const ancestry = new Map();
  const ranks = new Map();
  const minutes = new Map();
  let estimatedMinutes = 0;
  for (let index = 0; index < ready.length; index++) {
    const id = ready[index];
    const node = byId.get(id);
    const ancestors = new Set();
    let topoRank = 0;
    let upstreamMinutes = 0;
    for (const parent of node.dependsOn) {
      ancestors.add(parent);
      for (const ancestor of ancestry.get(parent)) ancestors.add(ancestor);
      topoRank = Math.max(topoRank, ranks.get(parent) + 1);
      upstreamMinutes = Math.max(upstreamMinutes, minutes.get(parent));
    }
    if (topoRank >= limits.maxDepth) throw limitError(`graph depth exceeds ${limits.maxDepth}`);
    estimatedMinutes = safeInteger(estimatedMinutes + node.estimatedMinutes, 'total estimated minutes');
    ancestry.set(id, ancestors);
    ranks.set(id, topoRank);
    minutes.set(id, upstreamMinutes + node.estimatedMinutes);
    ordered.push({ ...node, topoRank, topologicalRank: topoRank });
    for (const child of children.get(id)) {
      pending.set(child, pending.get(child) - 1);
      if (pending.get(child) === 0) ready.push(child);
    }
  }
  if (ordered.length !== nodes.length) throw graphError('ERR_GRAPH_CYCLE', 'graph contains a dependency cycle');
  ordered.sort((a, b) => a.topoRank - b.topoRank || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return { ordered, ancestry, estimatedMinutes, criticalPathMinutes: Math.max(...minutes.values()) };
}

// Dilworth: maximum independent set (antichain) = |V| - maximum matching
// between the two copies of the graph linked by transitive dependency edges.
function width(ids, ancestry) {
  const eligible = new Set(ids);
  const edges = new Map(ids.map(id => [id, [...ancestry.get(id)].filter(parent => eligible.has(parent))]));
  const matching = new Map();
  function augment(id, seen) {
    for (const parent of edges.get(id)) {
      if (seen.has(parent)) continue;
      seen.add(parent);
      if (!matching.has(parent) || augment(matching.get(parent), seen)) {
        matching.set(parent, id);
        return true;
      }
    }
    return false;
  }
  for (const id of ids) augment(id, new Set());
  return ids.length - matching.size;
}

const covers = (a, b) => a === '.' || a === b || b.startsWith(`${a}/`);
const overlap = (a, b) => a.some(x => b.some(y => covers(x, y) || covers(y, x)));

function scopeCompatibleFraction(nodes, ancestry) {
  let incomparable = 0;
  let compatible = 0;
  for (let i = 0; i < nodes.length; i++) {
    const a = nodes[i];
    for (let j = i + 1; j < nodes.length; j++) {
      const b = nodes[j];
      if (ancestry.get(b.id).has(a.id)) continue;
      incomparable++;
      if (!overlap(a.writeScope, b.readScope) && !overlap(b.writeScope, a.readScope)
          && !overlap(a.writeScope, b.writeScope)) compatible++;
    }
  }
  return incomparable === 0 ? 0 : compatible / incomparable;
}

function coalesce(ordered, ancestry) {
  const writes = ordered.filter(node => node.kind === 'write');
  const ranges = writes.map((_, i) => i);
  for (let i = 0; i < writes.length; i++) {
    for (let j = i + 1; j < writes.length; j++) {
      const a = writes[i];
      const b = writes[j];
      if (!ancestry.get(b.id).has(a.id)) throw v2Error(`parallel writes are not enabled: ${a.id}, ${b.id}`);
      if (overlap(a.writeScope, b.writeScope)) ranges[i] = j;
    }
  }
  const groups = new Map();
  const representatives = new Map();
  for (let i = 0; i < writes.length; ) {
    let end = ranges[i];
    for (let j = i + 1; j <= end; j++) end = Math.max(end, ranges[j]);
    if (end > i) {
      const group = writes.slice(i, end + 1);
      const first = group[0].id;
      const last = group.at(-1).id;
      if (ordered.some(node => node.kind !== 'write' && ancestry.get(node.id).has(first)
          && ancestry.get(last).has(node.id))) {
        throw v2Error(`cannot coalesce overlapping writes across an intervening non-write node: ${first}, ${last}`);
      }
      groups.set(first, group);
      for (const node of group) representatives.set(node.id, first);
    }
    i = end + 1;
  }
  if (groups.size === 0) return ordered;

  return ordered.filter(node => !representatives.has(node.id) || groups.has(node.id)).map(node => {
    const group = groups.get(node.id) ?? [node];
    const dependsOn = uniqueSorted(group.flatMap(member => member.dependsOn).map(id => representatives.get(id) ?? id))
      .filter(id => id !== node.id);
    if (group.length === 1) return { ...node, dependsOn };
    const volatility = {};
    const gateCommands = new Map();
    for (const member of group) {
      for (const [kind, entries] of Object.entries(member.volatility ?? {})) (volatility[kind] ??= []).push(...entries);
      const command = normalizeGateCommand(member);
      if (Object.keys(command).length) gateCommands.set(JSON.stringify(command), command);
    }
    if (gateCommands.size > 1) throw v2Error(`cannot coalesce distinct gate commands: ${node.id}`);
    return {
      ...node, dependsOn, coalescedFrom: group.map(member => member.id),
      ...gateCommands.values().next().value,
      required: group.some(member => member.required),
      ...(Object.keys(volatility).length > 0 && { volatility }),
      readScope: uniqueSorted(group.flatMap(member => member.readScope)),
      writeScope: uniqueSorted(group.flatMap(member => member.writeScope)),
      estimatedMinutes: group.reduce((total, member) => total + member.estimatedMinutes, 0),
      priority: Math.min(...group.map(member => member.priority)),
      prompt: group.map(member => `Write step ${JSON.stringify(member.id)}:\n${member.prompt}`).join('\n\n'),
      skills: group.flatMap(member => member.skills), rules: group.flatMap(member => member.rules),
    };
  });
}

export function compileGraph(spec) {
  if (!isRecord(spec) || spec.schemaVersion !== SCHEMA_VERSION) throw schemaError('graph schemaVersion must be 1');
  if (!Array.isArray(spec.nodes) || spec.nodes.length === 0) throw schemaError('graph must have at least one node');
  const limits = normalizeLimits(spec.limits);
  if (spec.nodes.length > limits.maxNodes) throw limitError(`graph count exceeds ${limits.maxNodes}`);
  const original = analyze(Array.from(spec.nodes, normalizeNode), limits);
  if (width(original.ordered.map(node => node.id), original.ancestry) > limits.maxWidth) {
    throw limitError(`graph width exceeds ${limits.maxWidth}`);
  }
  const normalized = coalesce(original.ordered, original.ancestry);
  const analysis = normalized === original.ordered ? original : analyze(normalized, limits);
  const { ordered: nodes, ancestry, estimatedMinutes, criticalPathMinutes } = analysis;
  const nodeCount = nodes.length;
  const edgeCount = nodes.reduce((total, node) => total + node.dependsOn.length, 0);
  const independent = width(nodes.filter(node => node.kind !== 'write').map(node => node.id), ancestry);
  const f = scopeCompatibleFraction(nodes, ancestry);
  const d = edgeCount / nodeCount;
  const metrics = {
    nodeCount, edgeCount, depth: nodes.at(-1).topoRank + 1, width: width(nodes.map(node => node.id), ancestry),
    estimatedMinutes, criticalPathMinutes, independent, f, d,
  };
  const recommendation = f >= limits.minParallelFraction && d < limits.maxEdgeDensity
    && estimatedMinutes >= limits.minEstimatedMinutes && independent >= limits.minIndependent
    && limits.readConcurrency >= 2 ? 'dag_approved' : 'single_session';
  return immutable({ schemaVersion: SCHEMA_VERSION, nodes, metrics, limits, recommendation });
}
