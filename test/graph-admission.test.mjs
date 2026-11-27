import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const admission = () => import('../scripts/graph/admission.mjs');
const fingerprint = () => import('../scripts/graph/fingerprint.mjs');
const schema = () => import('../scripts/graph/schema.mjs');
const node = (id, fields = {}) => ({
  id, kind: 'read', dependsOn: [], readScope: [], writeScope: [],
  estimatedMinutes: 5, priority: 0, prompt: `Investigate ${id}`, skills: [], rules: [], ...fields,
});
const graph = (nodes, limits) => ({ schemaVersion: 1, nodes, ...(limits && { limits }) });
const write = (id, writeScope, dependsOn = []) => node(id, { kind: 'write', writeScope, dependsOn });

test('three independent 5-minute reads recommend parallel work, unlike a chain', async () => {
  const { compileGraph } = await admission();
  const parallel = compileGraph(graph([node('c'), node('a'), node('b')]));
  const serial = compileGraph(graph([node('c', { dependsOn: ['b'] }), node('a'), node('b', { dependsOn: ['a'] })]));
  assert.equal(parallel.recommendation, 'dag_approved');
  assert.equal(serial.recommendation, 'single_session');
  assert.deepEqual(serial.nodes.map(n => [n.id, n.topoRank]), [['a', 0], ['b', 1], ['c', 2]]);
  assert.equal(parallel.metrics.estimatedMinutes, 15);
  assert.equal(parallel.metrics.criticalPathMinutes, 5);
  assert.equal(parallel.limits.readConcurrency, 6);
});

test('admission keeps transition budgets and publishes the scheduler rank', async () => {
  const { compileGraph } = await admission();
  const { limits, nodes } = compileGraph(graph([node('a'), node('b', { dependsOn: ['a'] })], {
    maxInfraRetries: 0, maxPins: 8, maxAttempts: 4,
  }));
  assert.equal(limits.maxInfraRetries, 0);
  assert.equal(limits.maxPins, 8);
  assert.equal(limits.maxAttempts, 4);
  assert.equal(nodes[1].topologicalRank, 1);
});

test('width includes independent nodes from different topological levels', async () => {
  const { compileGraph } = await admission();
  const nodes = [node('early'), node('root'), node('left', { dependsOn: ['root'] }), node('right', { dependsOn: ['root'] })];
  assert.throws(() => compileGraph(graph(nodes, { maxWidth: 2 })), { code: 'ERR_GRAPH_LIMIT' });
});

test('edge density equal to the configured limit recommends serial work', async () => {
  const { compileGraph } = await admission();
  const nodes = ['a', 'b', 'c', 'd'].map(id => node(id, { estimatedMinutes: 10 }));
  nodes.push(node('join', { dependsOn: ['a', 'b', 'c'], estimatedMinutes: 1 }));
  assert.equal(compileGraph(graph(nodes, { maxEdgeDensity: 0.6 })).recommendation, 'single_session');
  assert.equal(compileGraph(graph(nodes, { maxEdgeDensity: 0.61 })).recommendation, 'dag_approved');
});

test('scope-compatible fraction distinguishes shared reads from incomparable write/read conflicts', async () => {
  const { compileGraph } = await admission();
  const readers = ['a', 'b', 'c'].map(id => node(id, { readScope: ['src/ui/file'] }));
  const conflict = compileGraph(graph([...readers, write('edit', ['src/ui'])]));
  const disjoint = compileGraph(graph([...readers, write('edit', ['src/ui-tests'])]));
  assert.equal(conflict.metrics.f, 0.5);
  assert.equal(conflict.recommendation, 'single_session');
  assert.equal(disjoint.metrics.f, 1);
  assert.equal(disjoint.recommendation, 'dag_approved');
  assert.equal(compileGraph(graph([...readers, write('edit', ['src/ui'])], {
    minParallelFraction: 0.5,
  })).recommendation, 'dag_approved');
});

test('parallel recommendation requires three mutually independent non-write nodes by default', async () => {
  const { compileGraph } = await admission();
  const nodes = [node('a', { estimatedMinutes: 10 }), node('b', { estimatedMinutes: 10 }), write('edit', ['src'])];
  assert.equal(compileGraph(graph(nodes)).metrics.independent, 2);
  assert.equal(compileGraph(graph(nodes)).recommendation, 'single_session');
  assert.equal(compileGraph(graph(nodes, { minIndependent: 2 })).recommendation, 'dag_approved');
});

for (const [label, spec, code] of [
  ['duplicate IDs', graph([node('a'), node('a')]), 'ERR_GRAPH_DUPLICATE'],
  ['duplicate edges', graph([node('a'), node('b', { dependsOn: ['a', 'a'] })]), 'ERR_GRAPH_DUPLICATE'],
  ['dangling edges', graph([node('a', { dependsOn: ['missing'] })]), 'ERR_GRAPH_DANGLING'],
  ['cycles', graph([node('a', { dependsOn: ['b'] }), node('b', { dependsOn: ['a'] })]), 'ERR_GRAPH_CYCLE'],
  ['count overflow', graph([node('a'), node('b')], { maxNodes: 1 }), 'ERR_GRAPH_LIMIT'],
  ['width overflow', graph([node('a'), node('b')], { maxWidth: 1 }), 'ERR_GRAPH_LIMIT'],
  ['depth overflow', graph([node('a'), node('b', { dependsOn: ['a'] })], { maxDepth: 1 }), 'ERR_GRAPH_LIMIT'],
  ['read cap overflow', graph([node('a')], { readConcurrency: 17 }), 'ERR_GRAPH_LIMIT'],
  ['unsafe estimates', graph([node('a', { estimatedMinutes: 2 ** 53 })]), 'ERR_GRAPH_SCHEMA'],
  ['non-write nodes declaring writes', graph([node('a', { writeScope: ['src'] })]), 'ERR_GRAPH_SCHEMA'],
  ['traversing write scopes', graph([write('a', ['src/../../outside'])]), 'ERR_GRAPH_SCHEMA'],
  ['integration', graph([node('a', { kind: 'integrate' })]), 'ERR_V2_WRITE_INTEGRATION_NOT_ENABLED'],
  ['parallel disjoint writes', graph([write('a', ['src']), write('b', ['tests'])]), 'ERR_V2_WRITE_INTEGRATION_NOT_ENABLED'],
]) {
  test(`admission rejects ${label}`, async () => {
    const { compileGraph } = await admission();
    assert.throws(() => compileGraph(spec), { code });
  });
}

test('coalescing serial nested write scopes preserves both instructions and rewrites external edges', async () => {
  const { compileGraph } = await admission();
  const result = compileGraph(graph([
    node('tail', { dependsOn: ['edit-b', 'edit-a'] }),
    write('edit-b', ['src/ui'], ['edit-a', 'pre']),
    write('edit-a', ['src'], ['pre']),
    node('pre'),
  ]));
  const combined = result.nodes.find(n => n.kind === 'write');
  assert.deepEqual(result.nodes.map(n => n.id), ['pre', 'edit-a', 'tail']);
  assert.deepEqual(combined.dependsOn, ['pre']);
  assert.deepEqual(result.nodes.at(-1).dependsOn, ['edit-a']);
  assert.match(combined.prompt, /Investigate edit-a[\s\S]*Investigate edit-b/);
  assert.equal(combined.estimatedMinutes, 10);
  assert.ok(Object.isFrozen(combined.dependsOn));
});

test('a read between overlapping writes keeps its original dependency boundary', async () => {
  const { compileGraph } = await admission();
  assert.throws(() => compileGraph(graph([
    write('a', ['src']), node('observe', { dependsOn: ['a'] }), write('b', ['src/file'], ['observe']),
  ])), { code: 'ERR_V2_WRITE_INTEGRATION_NOT_ENABLED' });
});

const execution = {
  spec: { id: 'a', kind: 'read' }, renderedPrompt: 'Final prompt\n', messages: [],
  readScope: ['src'], writeScope: [], baseSha: 'a'.repeat(40), inputReceiptDigests: ['b'.repeat(64)],
  skills: [], rules: [], host: { id: 'local', model: 'pinned-model-1', toolchain: 'node18' },
  environment: { LANG: 'C' },
};

test('execution hashes loaded skill/rule bytes in order, ignoring physical installation paths', async t => {
  const { execKey } = await fingerprint();
  const dir = await mkdtemp(join(tmpdir(), 'hstack-graph-admission-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const one = join(dir, 'one');
  const two = join(dir, 'two');
  await writeFile(one, Buffer.from([0xff, 0x0a]));
  await writeFile(two, Buffer.from([0xff, 0x0d]));
  const file = { name: 'review', path: one, bytes: await readFile(one) };
  const other = { name: 'second', bytes: 'other' };
  const input = { ...execution, skills: [file, other], rules: [other, file] };
  const original = execKey(input);
  assert.match(original, /^[a-f0-9]{64}$/);
  assert.equal(execKey({ ...input, skills: [{ ...file, path: two }, other] }), original);
  assert.notEqual(execKey({ ...input, skills: [{ ...file, bytes: '\ufffd\n' }, other] }), original);
  assert.notEqual(execKey({ ...input, skills: [{ ...file, bytes: await readFile(two) }, other] }), original);
  assert.notEqual(execKey({ ...input, skills: [{ ...file, name: 'renamed' }, other] }), original);
  assert.notEqual(execKey({ ...input, skills: [other, file] }), original);
  assert.notEqual(execKey({ ...input, rules: [file, other] }), original);
});

test('execution key follows the final prompt and parent digests', async () => {
  const { execKey } = await fingerprint();
  const original = execKey(execution);
  assert.notEqual(execKey({ ...execution, renderedPrompt: 'Final prompt' }), original);
  assert.notEqual(execKey({ ...execution, inputReceiptDigests: ['c'.repeat(64)] }), original);
});

test('unknown hosts keep a stable same-input fencing key without cross-run reuse', async () => {
  const { execKey, crossRunCacheDisabled } = await fingerprint();
  const unknown = { ...execution, host: { id: 'unknown' } };
  const key = execKey(unknown);
  assert.match(key, /^[a-f0-9]{64}$/);
  assert.match(execKey({ ...unknown, host: undefined }), /^[a-f0-9]{64}$/);
  assert.equal(execKey({ ...unknown, host: { ...unknown.host } }), key);
  assert.notEqual(execKey({ ...unknown, renderedPrompt: 'repair prompt' }), key);
  assert.equal(crossRunCacheDisabled(unknown.host), true);
  assert.equal(crossRunCacheDisabled(undefined), true);
  assert.equal(crossRunCacheDisabled({ ...execution.host, model: 'latest' }), true);
  assert.equal(crossRunCacheDisabled(execution.host), false);
  assert.equal(crossRunCacheDisabled({ ...execution.host, cacheable: false }), true);
  assert.equal(execKey({ ...execution, host: { ...execution.host, cacheable: false } }), execKey(execution));
});

for (const kind of ['dynamicReads', 'networkInputs', 'externalInputs']) {
  test(`unpinned ${kind} disable reuse without discarding the fencing key`, async () => {
    const { execKey, crossRunCacheDisabled } = await fingerprint();
    const volatility = { [kind]: [{ name: 'logical-input' }] };
    const pinned = { [kind]: [{ name: 'logical-input', digest: 'a'.repeat(64) }] };
    assert.equal(crossRunCacheDisabled(execution.host, volatility), true);
    assert.equal(crossRunCacheDisabled(execution.host, pinned), false);
    const key = execKey({ ...execution, volatility });
    assert.match(key, /^[a-f0-9]{64}$/);
    assert.equal(execKey({ ...execution, volatility }), key);
    assert.notEqual(execKey({ ...execution, volatility: pinned }), key);
  });
}

test('moving model aliases and explicitly unpinned models disable cross-run reuse', async () => {
  const { execKey, crossRunCacheDisabled } = await fingerprint();
  for (const model of ['latest', 'provider/model-latest', 'family:latest', 'model-preview']) {
    const host = { ...execution.host, model };
    assert.equal(crossRunCacheDisabled(host), true);
    assert.match(execKey({ ...execution, host }), /^[a-f0-9]{64}$/);
  }
  assert.equal(crossRunCacheDisabled({ ...execution.host, modelPinned: false }), true);
  assert.equal(crossRunCacheDisabled({ ...execution.host, model: 'release-2026-11-preview' }), false);
});

test('admission preserves projection and volatile execution config and defaults required to true', async () => {
  const { compileGraph } = await admission();
  const { execKey } = await fingerprint();
  const config = {
    required: false, projection: 'manifest', projectionConfig: { version: 1 },
    volatility: { dynamicReads: [{ name: 'generated-input' }] },
  };
  const { nodes: [a, b] } = compileGraph(graph([node('a', config), node('b')]));
  assert.equal(b.required, true);
  for (const [key, value] of Object.entries(config)) assert.deepEqual(a[key], value);
  assert.throws(() => compileGraph(graph([node('invalid', { required: null })])), { code: 'ERR_GRAPH_SCHEMA' });
  assert.throws(() => compileGraph(graph([node('invalid', { volatility: { dynamicReads: [{ name: 'x', digest: 'latest' }] } })])), { code: 'ERR_GRAPH_SCHEMA' });
  const key = execKey({ ...execution, ...config });
  assert.notEqual(execKey({ ...execution, ...config, projectionConfig: { version: 2 } }), key);
});

test('gate-only changes do not invalidate execution; audit policy and candidate each invalidate the gate', async () => {
  const { execKey, gateKey } = await fingerprint();
  const gate = { candidateTree: 'a'.repeat(40), testPlan: ['node --test'], auditPolicy: { level: 1 }, gateVersion: 1, environment: {} };
  const strongerGate = { ...gate, auditPolicy: { level: 2 } };
  assert.equal(execKey({ ...execution, auditPolicy: strongerGate.auditPolicy }), execKey(execution));
  assert.notEqual(gateKey(strongerGate), gateKey(gate));
  assert.notEqual(gateKey({ ...gate, candidateTree: 'b'.repeat(40) }), gateKey(gate));
  assert.equal(gateKey({ ...gate, renderedPrompt: 'different' }), gateKey(gate));
});

test('admission preserves exact gate argv and timeout and rejects policies the verifier cannot run', async () => {
  const { compileGraph } = await admission();
  const gateArgv = ['node', '--test', '', 'literal space'];
  const [verify] = compileGraph(graph([node('verify', { kind: 'verify', gateArgv, timeoutMs: 100 })])).nodes;
  assert.deepEqual(verify.gateArgv, gateArgv);
  assert.equal(verify.timeoutMs, 100);
  for (const fields of [{ gateArgv: [] }, { gateArgv: ['node', 'a\0b'] }, { timeoutMs: 0 }, { timeoutMs: 2 ** 31 }]) {
    assert.throws(() => compileGraph(graph([node('a', fields)])), { code: 'ERR_GRAPH_SCHEMA' });
  }
});

test('gate argv order and timeout each invalidate only the gate key', async () => {
  const { execKey, gateKey } = await fingerprint();
  const gate = { candidateTree: 'a'.repeat(40), testPlan: [], auditPolicy: {}, gateVersion: 1 };
  const policy = { gateArgv: ['node', '--test', 'a.mjs', 'b.mjs'], timeoutMs: 30_000 };
  const key = gateKey({ ...gate, ...policy });
  assert.notEqual(gateKey({ ...gate, ...policy, timeoutMs: 60_000 }), key);
  assert.notEqual(gateKey({ ...gate, ...policy, gateArgv: ['node', '--test', 'b.mjs', 'a.mjs'] }), key);
  assert.equal(execKey({ ...execution, ...policy, spec: { ...execution.spec, ...policy } }), execKey(execution));
});

test('canonical objects ignore insertion order but preserve types, array order, and ambiguous boundaries', async () => {
  const { artifactDigest, canonical } = await fingerprint();
  assert.equal(canonical({ a: 1, b: ['x', 'y'] }), canonical({ b: ['x', 'y'], a: 1 }));
  assert.notEqual(artifactDigest(['ab', 'c']), artifactDigest(['a', 'bc']));
  assert.notEqual(artifactDigest(['x', 'y']), artifactDigest(['y', 'x']));
  assert.notEqual(artifactDigest('1'), artifactDigest(1));
  assert.throws(() => canonical({ a: undefined }), { code: 'ERR_GRAPH_FINGERPRINT' });
});

test('records own their nested values, reject unsafe integers, and reserve integration for v2', async () => {
  const { Run, Node, Attempt, Receipt } = await schema();
  const run = { runId: 'r', repoIdentity: 'repo', startBase: 'a'.repeat(40), integrationRef: 'refs/hstack/r',
    graphRev: 1, specDigest: 'a'.repeat(64), policyDigest: 'b'.repeat(64), seq: 0, headHash: null,
    budget: { attempts: 3 }, status: 'open' };
  const frozen = Run(run);
  run.budget.attempts = 4;
  assert.equal(frozen.budget.attempts, 3);
  assert.throws(() => { frozen.budget.attempts = 5; }, TypeError);
  assert.throws(() => Run({ ...run, seq: 2 ** 53 }), { code: 'ERR_GRAPH_SCHEMA' });
  assert.throws(() => Node({ schemaVersion: 2 }), { code: 'ERR_GRAPH_SCHEMA' });
  assert.throws(() => Attempt({ runId: 'r', nodeId: 'a', graphRev: 1, epoch: -1 }), { code: 'ERR_GRAPH_SCHEMA' });
  assert.throws(() => Receipt({ receiptId: 'a'.repeat(64) }), { code: 'ERR_GRAPH_SCHEMA' });
});

test('valid reserved integration records are immutable data, not integration commands', async () => {
  const { IntegrationCandidate } = await schema();
  const sha = 'a'.repeat(40);
  const hash = 'b'.repeat(64);
  const input = {
    schemaVersion: 1, candidateId: 'candidate', orderedAttempts: [{ runId: 'r', nodeId: 'a', graphRev: 1, epoch: 1 }],
    workerOids: [sha], expectedTip: sha, candidateCommit: sha, candidateTree: sha, scopeDiffDigest: hash,
    gateKey: hash, checkReceiptIds: [hash], pinRefs: [], promotionOp: null, state: 'sealed',
  };
  const candidate = IntegrationCandidate(input);
  assert.equal(candidate.schemaVersion, 1);
  assert.throws(() => IntegrationCandidate({ ...input, schemaVersion: 2 }), { code: 'ERR_GRAPH_SCHEMA' });
  input.orderedAttempts[0].epoch = 3;
  assert.equal(candidate.orderedAttempts[0].epoch, 1);
  assert.throws(() => { candidate.orderedAttempts[0].epoch = 4; }, TypeError);
  assert.throws(() => IntegrationCandidate({ ...input, candidateCommit: 'mutable' }), { code: 'ERR_GRAPH_SCHEMA' });
  assert.throws(() => IntegrationCandidate({ ...input, schemaVersion: 3 }), { code: 'ERR_GRAPH_SCHEMA' });
});
