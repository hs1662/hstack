import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const receipt = Buffer.from('{"failure":"wrong line"}');
const uri = `cas://sha256/${createHash('sha256').update(receipt).digest('hex')}`;
const io = { get: async key => {
  assert.equal(key, uri);
  return receipt;
} };
const node = (id, props = {}) => ({
  schemaVersion: 1, id, logicalId: id, kind: 'read', prompt: id, skills: [], rules: [],
  dependsOn: [], readScope: [], writeScope: [], priority: 0, estimatedMinutes: 5,
  status: 'pending', highestIssuedEpoch: 0, attempt: null, receiptUri: null, execKey: null,
  gateKey: null, infraRetries: 0, ...props,
});
const graph = (...nodes) => ({
  schemaVersion: 1, runId: 'demo', graphRev: 3, workspace: '/tmp', limits: {}, joinMembers: {},
  nodes: Object.fromEntries(nodes.map(n => [n.id, n])),
  logicalOutputMap: Object.fromEntries(nodes.map(n => [n.logicalId, n.id])),
});
const mutate = async (state, command, id, patch, extra = {}) =>
  (await import('../scripts/graph/patch.mjs')).applyPatch(state, command, {
    node: id, expectedRev: state.graphRev, opId: 'patch01', patch, ...extra,
  }, io);

test('expansion preserves consumers and seals named mandatory shards independent of array order', async () => {
  const state = graph(node('base'), node('scan', { dependsOn: ['base'] }), node('tail', { dependsOn: ['scan'] }));
  const shards = [{ stableShardKey: 'ui', obligationId: 'review-ui', readScope: ['ui'] },
    { stableShardKey: 'api', obligationId: 'review-api', readScope: ['api'] }];
  const result = await mutate(state, 'expand', 'scan', { shards, reason: 'parallel review' });
  const reverse = await mutate(state, 'expand', 'scan', { shards: [...shards].reverse() });
  assert.equal(result.body.newGraphHash, reverse.body.newGraphHash);
  assert.notEqual(result.body.newGraphHash, (await mutate(state, 'expand', 'scan', { shards: [shards[0]] })).body.newGraphHash);
  assert.deepEqual(result.state.joinMembers.scan, [
    { shardId: 'scan::shard::api', obligationId: 'review-api' },
    { shardId: 'scan::shard::ui', obligationId: 'review-ui' },
  ]);
  assert.equal(result.state.nodes.scan.kind, 'reducer');
  assert.deepEqual(result.state.nodes.scan.dependsOn, ['scan::shard::api', 'scan::shard::ui']);
  assert.deepEqual(result.state.nodes['scan::shard::api'].dependsOn, ['base']);
  assert.deepEqual(result.state.nodes['scan::shard::api'].readScope, ['api']);
  assert.deepEqual(result.state.nodes.tail.dependsOn, ['scan']);
  assert.equal(result.body.parentRev, 3);
  assert.equal(result.state.graphRev, 4);
  assert.equal(result.body.reason, 'parallel review');
  assert.equal(result.body.patchId, 'patch01');
});

test('amending an accepted ancestor fences the running grandchild but not another branch', async () => {
  const state = graph(node('base', { status: 'accepted', receiptUri: uri }),
    node('middle', { status: 'accepted', dependsOn: ['base'], receiptUri: uri }),
    node('leaf', { dependsOn: ['middle'], status: 'running', highestIssuedEpoch: 9, attempt: { epoch: 9 } }),
    node('other', { status: 'running', highestIssuedEpoch: 7, attempt: { epoch: 7 } }));
  state.telemetry = { attempts: [{nodeId:'leaf',epoch:9}, {nodeId:'other',epoch:7}] };
  const before = Date.now();
  const next = (await mutate(state, 'amend', 'base', { exec: { prompt: 'review the new interface' } })).state;
  assert.equal(next.telemetry.attempts[0].outcome, 'superseded');
  assert.ok(next.telemetry.attempts[0].finishedAtMs >= before && next.telemetry.attempts[0].finishedAtMs <= Date.now());
  assert.equal(next.telemetry.attempts[1].finishedAtMs, undefined);
  assert.equal(state.telemetry.attempts[0].finishedAtMs, undefined);
  assert.equal(next.nodes.leaf.highestIssuedEpoch, 10);
  assert.equal(next.nodes.leaf.attempt, null);
  assert.equal(next.nodes.leaf.status, 'pending');
  assert.equal(next.nodes.middle.receiptUri, null);
  assert.equal(next.nodes.base.prompt, 'review the new interface');
  assert.deepEqual(next.nodes.other, state.nodes.other);
  assert.equal(state.nodes.leaf.attempt.epoch, 9);
});

test('policy-only revalidation pins the original artifact across successive amendments', async () => {
  const state = graph(node('scan', { status: 'accepted', receiptUri: uri, execKey: 'a'.repeat(64) }));
  const first = await mutate(state, 'amend', 'scan', { gate: { auditPolicy: { level: 2 } } });
  const next = await mutate(first.state, 'amend', 'scan', { gate: { auditPolicy: { level: 3 } } });
  assert.equal(next.state.nodes.scan.revalidateReceiptUri, uri);
  assert.equal(next.state.nodes.scan.execKey, state.nodes.scan.execKey);
  assert.notEqual(next.state.nodes.scan.status, 'accepted');
  assert.ok(next.refs.includes(uri));
  assert.notEqual(first.body.newGraphHash, next.body.newGraphHash);
  const gen = await mutate(next.state, 'amend', 'scan', { exec: { prompt: 'fresh work' } });
  assert.equal(gen.state.nodes.scan.revalidateReceiptUri ?? null, null);
});

test('repair preserves failed evidence, rebinds closed membership and cannot reset depth via repair of repair', async () => {
  const state = graph(node('shard', { status: 'failed_logic', highestIssuedEpoch: 7, receiptUri: uri,
    required: false, attempt: { epoch: 7, settleOp: 'failed' } }),
    node('join', { kind: 'reducer', dependsOn: ['shard'], status: 'held_upstream' }));
  state.joinMembers.join = [{ shardId: 'shard', obligationId: 'coverage' }];
  const repair = (s, id) => mutate(s, 'inject-repair', id, { prompt: 'correct the line' });
  const { state: next, refs } = await repair(state, 'shard');
  const id = 'shard::repair::e1';
  assert.equal(next.nodes.shard.status, 'superseded_by_repair');
  assert.equal(next.nodes.shard.receiptUri, uri);
  assert.ok(next.nodes.shard.highestIssuedEpoch > next.nodes.shard.attempt.epoch);
  assert.ok(refs.includes(uri));
  assert.equal(next.nodes[id].failureReceiptUri, uri);
  assert.equal(next.nodes[id].required, false);
  assert.equal(next.nodes[id].repairOf, 'shard');
  assert.deepEqual(next.nodes[id].inputUris, [uri]);
  assert.equal(next.logicalOutputMap.shard, id);
  assert.deepEqual(next.nodes.join.dependsOn, [id]);
  assert.deepEqual(next.joinMembers.join, [{ shardId: id, obligationId: 'coverage' }]);
  Object.assign(next.nodes[id], { status: 'failed_logic', receiptUri: uri });
  const twice = (await repair(next, id)).state;
  const id2 = `${id}::repair::e2`;
  assert.equal(twice.logicalOutputMap.shard, id2);
  Object.assign(twice.nodes[id2], { status: 'failed_logic', receiptUri: uri });
  await assert.rejects(repair(twice, id2), { code: 'ERR_REPAIR_DEPTH' });
  await assert.rejects(repair(twice, 'shard'), { code: 'ERR_GRAPH_PATCH' });
});

test('policy change on a worker-settled reducer pins the validated worker artifact, not its derived mass index', async () => {
  const index = `cas://sha256/${'b'.repeat(64)}`;
  const state = graph(node('leaf'), node('join', { kind: 'reducer', dependsOn: ['leaf'],
    status: 'accepted', workerReceiptUri: uri, receiptUri: index, execKey: 'c'.repeat(64) }));
  state.joinMembers.join = [{ shardId: 'leaf', obligationId: 'leaf' }];
  const { state: next } = await mutate(state, 'amend', 'join', { gate: { gateVersion: 2 } });
  assert.equal(next.nodes.join.revalidateReceiptUri, uri);
});

test('amend cannot release a live writer slot by changing a read ancestor', async () => {
  const state = graph(node('review', { status: 'accepted', receiptUri: uri }),
    node('edit', { kind: 'write', dependsOn: ['review'], writeScope: ['src'], status: 'running',
      highestIssuedEpoch: 2, attempt: { epoch: 2 } }));
  await assert.rejects(mutate(state, 'amend', 'review', { exec: { prompt: 'reconsider' } }),
    { code: 'ERR_V2_WRITE_INTEGRATION_NOT_ENABLED' });
  assert.equal(state.nodes.edit.status, 'running');
});

test('invalidating a reducer clears its old materialized reduction and policy validation key', async () => {
  const state = graph(node('scan'), node('join', { kind: 'reducer', dependsOn: ['scan'],
    reductionUri: uri, gateKey: 'previous-key', receiptUri: uri, status: 'accepted' }));
  const { state: next } = await mutate(state, 'amend', 'scan', { exec: { prompt: 'expand the review' } });
  assert.equal(next.nodes.join.reductionUri ?? null, null);
  assert.equal(next.nodes.join.gateKey, null);
});

for (const [name, setup, command, patch, code, extra] of [
  ['parallel writes', {}, 'expand', { shards: [{ stableShardKey: 'w', kind: 'write' }] }, 'ERR_V2_WRITE_INTEGRATION_NOT_ENABLED'],
  ['runtime field injection', {}, 'amend', { exec: { status: 'accepted' } }, 'ERR_GRAPH_PATCH'],
  ['duplicate nominal shard', {}, 'expand', { shards: [{ stableShardKey: 'a' }, { stableShardKey: 'a' }] }, 'ERR_GRAPH_PATCH'],
  ['unfailed source', {}, 'inject-repair', {}, 'ERR_GRAPH_PATCH'],
  ['mutable failure URI', { status: 'failed_logic', receiptUri: 'file:///failure.json' }, 'inject-repair', {}, 'ERR_GRAPH_PATCH'],
  ['stale parent revision', {}, 'amend', { exec: { prompt: 'x' } }, 'ERR_STALE_GRAPH_REV', { expectedRev: 2 }],
  ['inherited map entry', {}, 'inject-repair', {}, 'ERR_GRAPH_PATCH', { node: 'toString' }],
]) {
  test(`rejects ${name} without changing the supplied state`, async () => {
    const state = graph(node('scan', setup));
    const saved = structuredClone(state);
    await assert.rejects(mutate(state, command, 'scan', patch, extra), { code });
    assert.deepEqual(state, saved);
  });
}

test('expansion exceeding the admitted width cannot publish a partially rewritten join', async () => {
  const state = graph(node('scan'));
  state.limits.maxWidth = 1;
  await assert.rejects(mutate(state, 'expand', 'scan', {
    shards: [{ stableShardKey: 'a' }, { stableShardKey: 'b' }],
  }), { code: 'ERR_GRAPH_LIMIT' });
  assert.deepEqual(Object.keys(state.nodes), ['scan']);
  assert.deepEqual(state.joinMembers, {});
});

test('dispatch rejects an old token after expanding an actively claimed node; replay emits no second patch', async t => {
  const { dispatch } = await import('../scripts/graph/state-machine.mjs');
  const dir = await mkdtemp(join(tmpdir(), 'graph-patch-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await mkdir(join(dir, 'data'), { mode: 0o700 });
  const call = (command, opts) => dispatch(command, { run: 'run', root: join(dir, 'data'), workspace: dir, ...opts });
  await call('compile', { opId: 'compile', spec: { schemaVersion: 1, nodes: [{ id: 'scan', kind: 'read', prompt: 'inspect' }] } });
  const claimed = await call('claim', { node: 'scan', expectedRev: 1, opId: 'claim' });
  const opts = { node: 'scan', expectedRev: 1, opId: 'expand', patch: { shards: [{ stableShardKey: 'core' }] } };
  const response = await call('expand', opts);
  assert.deepEqual(await call('expand', opts), response);
  const before = await call('status', {});
  await assert.rejects(call('settle', { token: claimed.instructionPath, opId: 'late', outcome: 'LOGIC_TERMINAL', receipt: {} }),
    { code: 'ERR_STALE_FENCING_TOKEN', exitCode: 49 });
  assert.deepEqual(await call('status', {}), before);
  assert.deepEqual((await call('ready', {})).ready.map(n => n.id), ['scan::shard::core']);
  const wal = (await readFile(join(dir, 'data/runs/run/wal/events.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  const frames = wal.filter(frame => frame.type === 'GraphPatched');
  assert.equal(frames.length, 1);
  assert.equal(frames[0].body.parentRev, 1);
  assert.equal(frames[0].body.newGraphHash, response.newGraphHash);
});

const inc = () => import('../scripts/graph/incremental.mjs');
const localKey = '1'.repeat(64);
const facts = '2'.repeat(64);
const accept = async (s, id, digest = '3'.repeat(64)) => {
  const n = s.nodes[id];
  Object.assign(n, { status: 'accepted', receiptUri: uri, artifactDigest: digest,
    execKey: localKey, gateKey: '4'.repeat(64), attempt: { localKey } });
  (await inc()).recordVerified(s, n, { provenance: { factDigest: facts } });
};

async function diamond(extra = {}) {
  const s = graph(node('root'), node('A', { dependsOn: ['root'] }), node('B', { dependsOn: ['root'] }),
    node('C', { dependsOn: ['A', 'B'], ...extra }));
  s.hostProfile = { id: 'h', model: 'm-1.0', toolchain: 'node18' };
  for (const id of ['root', 'A', 'B', 'C']) await accept(s, id);
  const { state } = await mutate(s, 'amend', 'root', { exec: { prompt: 'updated upstream' } });
  await accept(state, 'root');
  return state;
}

test('diamond: an unchanged A clears only its edge, a changed B keeps C dirty', async () => {
  const { revalidateNode } = await inc();
  const s = await diamond();
  assert.deepEqual(s.nodes.C.dirtyReasons.map(r => r.parentId).sort(), ['A', 'B']);
  await accept(s, 'A');
  assert.deepEqual(s.nodes.C.dirtyReasons.map(r => r.parentId), ['B']);
  await accept(s, 'B', '5'.repeat(64));
  await assert.rejects(revalidateNode(s, { node: 'C', expectedRev: 4 }, io, localKey), { code: 'ERR_REVALIDATION_REQUIRED' });
  assert.equal(s.nodes.C.status, 'pending');
  assert.equal(s.nodes.B.changedAtRev, 4);
});

test('edge replacement dirties both removed and added edges and fences their downstream checks', async () => {
  const s = graph(node('A'), node('B'), node('C', { dependsOn: ['A'] }),
    node('check', { kind: 'verify', dependsOn: ['C'], status: 'running', highestIssuedEpoch: 5, attempt: { epoch: 5 } }));
  const { state } = await mutate(s, 'amend', 'C', { exec: { dependsOn: ['B'] } });
  assert.deepEqual(state.nodes.C.dependsOn, ['B']);
  assert.deepEqual(state.nodes.C.dirtyReasons.filter(r => r.parentId).map(r => [r.parentId, r.kind]).sort(),
    [['A', 'removed'], ['B', 'added']]);
  assert.equal(state.nodes.check.highestIssuedEpoch, 6);
  await assert.rejects(mutate(state, 'amend', 'C', { exec: { dependsOn: ['check'] } }), { code: 'ERR_GRAPH_CYCLE' });
});

test('only a fixed facts-v1 read view ignores changes outside the fact record', async () => {
  const { edgeViewKey } = await inc();
  const s = await diamond();
  const previous = structuredClone(s.nodes.root);
  await accept(s, 'root', '7'.repeat(64));
  for (const consumer of [node('free'), node('verify', { kind: 'verify', projection: 'facts-v1' }),
    node('custom', { projection: 'facts-v1', projectionConfig: { fields: ['title'] } })]) {
    assert.equal(edgeViewKey(consumer, previous), previous.artifactDigest);
    assert.equal(edgeViewKey(consumer, s.nodes.root), '7'.repeat(64));
  }
  assert.equal(edgeViewKey(node('doc', { projection: 'facts-v1' }), previous),
    edgeViewKey(node('doc', { projection: 'facts-v1' }), s.nodes.root));
});

test('declaring a facts projection cannot narrow a prior attempt that actually received full parent receipts', async () => {
  const { revalidateNode } = await inc();
  const s = await diamond({ projection: 'facts-v1' });
  await accept(s, 'A', '7'.repeat(64));
  await accept(s, 'B');
  await assert.rejects(revalidateNode(s, { node: 'C', expectedRev: 4 }, io, localKey),
    { code: 'ERR_REVALIDATION_REQUIRED' });
});

test('volatile inputs, mismatched local key and required verify gates forbid silent backdating', async () => {
  const { revalidateNode } = await inc();
  for (const extra of [{ volatility: { networkInputs: [{ name: 'head' }] } }, { kind: 'verify' }, { testPlan: ['lint'] }, {}]) {
    const s = await diamond(extra);
    await accept(s, 'A'); await accept(s, 'B');
    await assert.rejects(revalidateNode(s, { node: 'C', expectedRev: 4 }, io,
      Object.keys(extra).length ? localKey : '6'.repeat(64)), { code: 'ERR_REVALIDATION_REQUIRED' });
    assert.equal(s.nodes.C.status, 'pending');
  }
});

test('a volatile run records a versioned verification with an execution identity but cannot reuse it', async () => {
  const { revalidateNode, recordVerified } = await inc();
  const { execKey } = await import('../scripts/graph/fingerprint.mjs');
  const key = execKey({ spec: { id: 'read' }, renderedPrompt: 'inspect', host: null });
  const s = graph(node('read', { status: 'accepted', receiptUri: uri, artifactDigest: facts,
    execKey: key, attempt: { localKey } }));
  recordVerified(s, s.nodes.read, {});
  assert.deepEqual([s.nodes.read.verifiedResult.schemaVersion, s.nodes.read.verifiedResult.execKey], [1, key]);
  assert.match(key, /^[a-f0-9]{64}$/);
  const pending = { ...s.nodes.read, status: 'pending', priorVerified: s.nodes.read.verifiedResult };
  s.nodes.read = pending;
  await assert.rejects(revalidateNode(s, { node: 'read', expectedRev: 3 }, io, localKey), { code: 'ERR_REVALIDATION_REQUIRED' });
  s.hostProfile = { id: 'h', model: 'm-1.0', toolchain: 'node18' };
  for (const [runVersion, proofVersion] of [[1, 2], [2, 1]]) {
    s.schemaVersion = runVersion;
    pending.priorVerified.schemaVersion = proofVersion;
    await assert.rejects(revalidateNode(s, { node: 'read', expectedRev: 3 }, io, localKey), { code: 'ERR_GRAPH_SCHEMA' });
  }
});

test('changing verifier argv or timeout revalidates the pinned artifact without rerunning generation', async () => {
  const s = graph(node('read', { status: 'accepted', receiptUri: uri, execKey: localKey,
    gateArgv: ['old'], timeoutMs: 10 }));
  const { state } = await mutate(s, 'amend', 'read', { gate: { gateArgv: ['node', ''], timeoutMs: 20 } });
  assert.deepEqual([state.nodes.read.execKey, state.nodes.read.revalidateReceiptUri], [localKey, uri]);
  assert.deepEqual(state.nodes.read.gateArgv, ['node', '']);
  assert.equal(state.nodes.read.timeoutMs, 20);
});

test('patch derives volatility from admitted inputs and host, not a caller cache flag', async () => {
  const s = graph(node('read'));
  s.hostProfile = { id: 'h', model: 'm-1.0', toolchain: 'node18' };
  const amend = (state, descriptor) => mutate(state, 'amend', 'read', { exec: {
    projection: 'facts-v1', volatility: { externalInputs: [descriptor] },
  } });
  const first = (await amend(s, { name: 'catalog' })).state;
  assert.equal(first.nodes.read.volatile, true);
  assert.equal(first.nodes.read.required, true);
  const next = (await amend(first, { name: 'catalog', digest: facts })).state;
  assert.equal(next.nodes.read.volatile, false);
  next.hostProfile = null;
  const expanded = (await mutate(next, 'expand', 'read', { shards: [{ stableShardKey: 'one' }] })).state;
  assert.equal(expanded.nodes['read::shard::one'].volatile, true);
  assert.equal(expanded.nodes['read::shard::one'].projection, 'facts-v1');
  await assert.rejects(mutate(next, 'amend', 'read', { exec: { volatile: false } }), { code: 'ERR_GRAPH_PATCH' });
});

test('only a NodeRevalidated transaction restores prior receipt and advances verification but not change revision', async t => {
  const { revalidateNode } = await inc();
  const { transaction, readState } = await import('../scripts/graph/wal-store.mjs');
  const root = await mkdtemp(join(tmpdir(), 'patch-backdate-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const s = await diamond();
  await accept(s, 'A'); await accept(s, 'B');
  assert.equal(s.nodes.C.status, 'pending');
  await transaction(root, 'r', { type: 'FixturePrepared', opId: 'prepare', payload: {} }, async (_, io) => {
    await io.put(receipt);
    return { state: s, response: {} };
  });
  const op = { type: 'NodeRevalidated', opId: 'verify-c', payload: { node: 'C', expectedRev: 4 } };
  const run = () => transaction(root, 'r', op, (prev, io) => revalidateNode(prev, op.payload, io, localKey));
  assert.deepEqual(await run(), await run());
  const { nodes: { C } } = await readState(root, 'r');
  assert.deepEqual([C.verifiedAtRev, C.changedAtRev, C.status, C.receiptUri], [4, 3, 'accepted', uri]);
  const events = (await readFile(join(root, 'runs/r/wal/events.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.deepEqual(events.map(e => e.type), ['FixturePrepared', 'NodeRevalidated']);
  assert.deepEqual([events[1].body.graphRev, events[1].body.priorReceiptUri], [4, uri]);
  assert.ok(events[1].body.reason);
});

test('inject-repair accepts an omitted patch via applyPatch and the public CLI', async t => {
  const s = graph(node('scan', { status: 'failed_logic', receiptUri: uri, prompt: 'scan carefully' }));
  const { state, body } = await mutate(s, 'inject-repair', 'scan', undefined);
  assert.equal(body.nodeId, 'scan::repair::e1');
  assert.equal(state.nodes['scan::repair::e1'].prompt, 'scan carefully');

  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const { writeFile } = await import('node:fs/promises');
  const root = await mkdtemp(join(tmpdir(), 'patch-repair-cli-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const data = join(root, 'graph');
  await mkdir(data, { mode: 0o700 });
  const cli = fileURLToPathForTest();
  const run = args => promisify(execFile)(process.execPath, [cli, ...args, '--root', data, '--workspace', root], { encoding: 'utf8' });
  await writeFile(join(root, 'source'), 'evidence\n');
  await writeFile(join(root, 'spec.json'), JSON.stringify({ schemaVersion: 1, nodes: [{ id: 'a', kind: 'read', prompt: 'read source' }] }));
  await run(['init']);
  await run(['compile', '--run', 'r1', '--spec', 'spec.json', '--op-id', 'c1']);
  const claim = JSON.parse((await run(['claim', '--run', 'r1', '--node', 'a', '--expected-rev', '1', '--op-id', 'k1'])).stdout);
  await run(['start', '--token', claim.result.instructionPath, '--host-handle', 'h1', '--op-id', 's1']);
  await writeFile(join(root, 'fail.json'), JSON.stringify({ workerReportedStatus: 'failed' }));
  await run(['settle', '--token', claim.result.instructionPath, '--outcome', 'logic_terminal', '--receipt', 'fail.json', '--op-id', 't1']);
  const repaired = JSON.parse((await run(['inject-repair', '--run', 'r1', '--node', 'a', '--expected-rev', '1', '--op-id', 'rep1'])).stdout);
  assert.equal(repaired.ok, true);
  assert.equal(repaired.result.nodeId, 'a::repair::e1');
});

function fileURLToPathForTest() {
  return new URL('../scripts/graph/cli.mjs', import.meta.url).pathname;
}
