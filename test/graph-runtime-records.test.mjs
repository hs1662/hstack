import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { compileGraph } from '../scripts/graph/admission.mjs';
import { collectGarbage, digest, getBlob } from '../scripts/graph/gc.mjs';
import { factDigest } from '../scripts/graph/reducer.mjs';
import * as schema from '../scripts/graph/schema.mjs';
import { dispatch } from '../scripts/graph/state-machine.mjs';

const invalid = { code: 'ERR_GRAPH_SCHEMA' };

async function settled(t) {
  const workspace = await mkdtemp(join(tmpdir(), 'graph-records-'));
  t.after(() => rm(workspace, { recursive: true, force: true }));
  const root = join(workspace, 'store');
  await mkdir(root, { mode: 0o700 });
  await writeFile(join(workspace, 'source'), 'record evidence\n');
  const run = 'runtime-records';
  const send = (command, options = {}) => dispatch(command, { root, run, ...options });
  await send('compile', { workspace, spec: { schemaVersion: 1, nodes: [
    { id: 'read::source', kind: 'read', prompt: 'Read source' },
    { id: 'verify', kind: 'verify', prompt: 'Verify source', dependsOn: ['read::source'] },
  ] } });
  const claim = await send('claim', { node: 'read::source', expectedRev: 1, opId: 'claim-source' });
  const token = claim.instructionPath;
  const nonce = JSON.parse(await readFile(token, 'utf8')).nonce;
  await send('start', { token, hostHandle: 'worker:source' });
  const provenance = {
    evidenceSpans: [{ spanId: 'source#1', path: 'source', startLine: 1, endLine: 1 }],
    claims: [{ claimId: 'fact:1', spanIds: ['source#1'], text: 'record evidence' }],
    edgeCases: [], failureEvidence: [],
  };
  provenance.factDigest = factDigest(provenance);
  const result = await send('settle', { token, outcome: 'accepted', opId: 'settle-source',
    receipt: { workerReportedStatus: 'completed', inlineSummary: 'record evidence', provenance },
    gateLog: { factDigest: provenance.factDigest, exitCode: 0, signal: null,
      argv: ['verify-source', ''], envDigest: digest('gate-env') } });
  assert.equal(result.status, 'accepted');
  const state = await send('status');
  return { root, run, state, claim, result, nonce };
}

test('runtime parsers accept the persisted run, node, attempt, and checked CAS envelope', async t => {
  const { root, state, result } = await settled(t);
  const node = state.nodes['read::source'];
  const receipt = JSON.parse(await getBlob(root, result.receiptUri));
  for (const [name, input, nested] of [
    ['Run', state, value => value.nodes['read::source'].dependsOn],
    ['Node', node, value => value.attempt.inputUris],
    ['Attempt', node.attempt, value => value.inputUris],
    ['Receipt', receipt, value => value.verifierEvidence.spanResolutions[0]],
  ]) {
    await t.test(name, () => {
      const record = schema[name](input);
      assert.deepEqual(record, input);
      assert.notEqual(record, input);
      assert.notEqual(nested(record), nested(input));
      assert.equal(Object.isFrozen(nested(record)), true);
      assert.equal(Object.isFrozen(nested(input)), false);
      assert.throws(() => schema[name]({ ...input, schemaVersion: 2 }), invalid);
    });
  }
});

test('commit validator rejects invalid nested versions, counters, identities, and CAS addresses', async t => {
  const { state } = await settled(t);
  const valid = schema.validateRunRecords(state);
  assert.deepEqual(valid, state);
  assert.throws(() => { valid.nodes['read::source'].attempt.epoch = 7; }, TypeError);
  for (const [recordName, field, value] of [
    ['run', 'runId', '../escape'], ['run', 'graphRev', Number.MAX_SAFE_INTEGER + 1],
    ['run', 'attemptsIssued', 0.5], ['run', 'nodes', []],
    ['node', 'schemaVersion', 2], ['node', 'highestIssuedEpoch', 1.5],
    ['node', 'id', 'wrong-node'], ['node', 'receiptUri', 'mutable/receipt.json'],
    ['attempt', 'schemaVersion', 3], ['attempt', 'epoch', 1.5],
    ['attempt', 'runId', 'another-run'], ['attempt', 'nodeId', 'verify'],
    ['attempt', 'nonceHash', 'not-a-digest'], ['attempt', 'inputUris', ['mutable/input.json']],
  ]) {
    const candidate = structuredClone(state);
    const node = candidate.nodes['read::source'];
    const record = { run: candidate, node, attempt: node.attempt }[recordName];
    record[field] = value;
    assert.throws(() => schema.validateRunRecords(candidate), invalid, `${recordName}.${field}`);
  }
});

test('checked receipt parser rejects malformed measured references, IDs, and fractional line counters', async t => {
  const { root, result } = await settled(t);
  const receipt = JSON.parse(await getBlob(root, result.receiptUri));
  for (const [field, value] of [
    ['logUri', 'gate.log'], ['subjectDigest', 'latest'], ['envDigest', 'env'],
    ['spanResolutions', [{ ...receipt.verifierEvidence.spanResolutions[0], spanId: '' }]],
    ['spanResolutions', [{ ...receipt.verifierEvidence.spanResolutions[0], actualLines: 1.5 }]],
  ]) {
    const verifierEvidence = { ...receipt.verifierEvidence, [field]: value };
    assert.throws(() => schema.Receipt({ ...receipt, verifierEvidence }), invalid, field);
  }
});

test('GC retains the committed post-image and checked receipt without exposing the directive nonce', async t => {
  const { root, run, state, claim, result, nonce } = await settled(t);
  const wal = await readFile(join(root, 'runs', run, 'wal', 'events.jsonl'), 'utf8');
  const last = JSON.parse(wal.trimEnd().split('\n').at(-1));
  await collectGarbage(root);
  const postImage = await getBlob(root, last.body.stateUri);
  const checked = await getBlob(root, result.receiptUri);
  assert.equal(last.body.stateUri, `cas://sha256/${digest(postImage)}`);
  assert.equal(result.receiptUri, `cas://sha256/${digest(checked)}`);
  assert.deepEqual(JSON.parse(postImage), state);
  assert.match(nonce, /^[a-f0-9]{64}$/);
  assert.equal(state.nodes['read::source'].attempt.nonceHash, digest(nonce));
  for (const wire of [wal, postImage.toString(), checked.toString(), JSON.stringify(claim)]) {
    assert.equal(wire.includes(nonce), false);
    assert.equal(wire.includes('"nonce"'), false);
  }
});

test('raw graph admission rejects explicitly unknown node schema versions', () => {
  const compile = schemaVersion => compileGraph({ schemaVersion: 1, nodes: [
    { id: 'verify', kind: 'verify', prompt: 'Verify input', schemaVersion },
  ] });
  assert.equal(compile(1).nodes[0].id, 'verify');
  for (const version of [2, null, '1']) assert.throws(() => compile(version), invalid);
});
