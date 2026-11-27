import { isAbsolute } from 'node:path';

export const SCHEMA_VERSION = 1;
export const V2_WRITE_ERROR = 'ERR_V2_WRITE_INTEGRATION_NOT_ENABLED';

export function graphError(code, message) {
  return Object.assign(new Error(message), { code });
}

export function schemaError(message) {
  return graphError('ERR_GRAPH_SCHEMA', message);
}

export function isRecord(value) {
  if (value === null || typeof value !== 'object') return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function safeInteger(value, label, min = 0) {
  if (!Number.isSafeInteger(value) || value < min) throw schemaError(`${label} must be a safe integer >= ${min}`);
  return value;
}

export function nonempty(value, label) {
  if (typeof value !== 'string' || value.trim() === '') throw schemaError(`${label} must be a nonempty string`);
  return value;
}

// Copy protocol data instead of freezing objects still owned by the caller.
export function immutable(value, ancestors = new Set()) {
  if (value === null || ['string', 'boolean'].includes(typeof value)) return value;
  if (typeof value === 'number' && Number.isFinite(value)
      && (!Number.isInteger(value) || Number.isSafeInteger(value))) return value;
  if (ancestors.has(value)) throw schemaError('record data must be acyclic');
  ancestors.add(value);
  let copy;
  if (Array.isArray(value)) {
    copy = Array.from({ length: value.length }, (_, index) => immutable(Object.getOwnPropertyDescriptor(value, index)?.value, ancestors));
  } else if (isRecord(value)) {
    copy = Object.fromEntries(Object.keys(value).map(key =>
      [key, immutable(Object.getOwnPropertyDescriptor(value, key).value, ancestors)]));
  } else {
    throw schemaError('record data must be plain JSON with safe integers');
  }
  ancestors.delete(value);
  return Object.freeze(copy);
}

const oid = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/;
const digest = /^[a-f0-9]{64}$/;
const matching = pattern => (value, label) => {
  if (typeof value !== 'string' || !pattern.test(value)) throw schemaError(`${label} has invalid format`);
};
const hash = matching(digest);
const gitOid = matching(oid);
const runId = matching(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
const casAddress = matching(/^cas:\/\/sha256\/[a-f0-9]{64}$/);
const optional = validator => (value, label) => { if (value != null) validator(value, label); };
const nullable = validator => (value, label) => { if (value !== null) validator(value, label); };
const string = (value, label) => {
  if (typeof value !== 'string') throw schemaError(`${label} must be a string`);
};
const absolute = (value, label) => {
  if (typeof value !== 'string' || !isAbsolute(value) || value.includes('\0')) throw schemaError(`${label} must be an absolute path`);
};
const object = (value, label) => {
  if (!isRecord(value)) throw schemaError(`${label} must be an object`);
};
const list = (value, label) => {
  if (!Array.isArray(value)) throw schemaError(`${label} must be an array`);
};
const items = validator => (value, label) => {
  list(value, label);
  value.forEach((item, index) => validator(item, `${label}[${index}]`));
};
const oneOf = (...values) => (value, label) => {
  if (!values.includes(value)) throw schemaError(`${label} must be one of ${values.join(', ')}`);
};
const fields = schema => (value, label) => { object(value, label); validateFields(value, schema, label); };
const positive = (value, label) => safeInteger(value, label, 1);

export function normalizeGateCommand({ gateArgv, timeoutMs }) {
  const policy = {};
  if (gateArgv !== undefined) {
    const argv = immutable(gateArgv);
    if (!Array.isArray(argv) || !argv[0] || argv.some(arg => typeof arg !== 'string' || arg.includes('\0'))) {
      throw schemaError('gateArgv must be a nonempty argv array without NUL bytes');
    }
    policy.gateArgv = argv;
  }
  if (timeoutMs !== undefined) {
    if (positive(timeoutMs, 'timeoutMs') > 2_147_483_647) throw schemaError('timeoutMs exceeds the host timer limit');
    policy.timeoutMs = timeoutMs;
  }
  return policy;
}

export function normalizeVolatility(value = {}) {
  const copy = immutable(value);
  object(copy, 'volatility');
  for (const [kind, reads] of Object.entries(copy)) {
    if (!['dynamicReads', 'networkInputs', 'externalInputs'].includes(kind)) {
      throw schemaError(`unknown volatility category: ${kind}`);
    }
    items((entry, label) => {
      object(entry, label);
      validateFields(entry, { name: nonempty, digest: optional(hash) }, label);
    })(reads, `volatility.${kind}`);
  }
  return copy;
}

const tuple = { runId: nonempty, nodeId: nonempty, graphRev: positive, epoch: positive };
const producer = fields(tuple);
const runStatus = oneOf('open', 'held', 'completed', 'degraded');
const nodeKind = oneOf('read', 'verify', 'reducer', 'write');
const records = {
  Run: {
    runId: nonempty, repoIdentity: nonempty, startBase: gitOid, integrationRef: optional(nonempty),
    graphRev: positive, specDigest: hash, policyDigest: hash, seq: safeInteger, headHash: optional(hash),
    budget: object, status: runStatus,
  },
  Node: {
    nodeId: nonempty, graphRev: positive, kind: nodeKind,
    specDigest: hash, requiredDeps: list, inputs: list, writeScope: list, gates: list,
    dirtyReasons: list, currentEpoch: safeInteger, retryBudget: safeInteger, state: nonempty,
  },
  Attempt: {
    ...tuple, claimOp: nonempty, execKey: optional(hash), baseSha: gitOid, inputRefs: list,
    worktreeId: optional(nonempty), hostTicket: optional(nonempty), startedAt: optional(safeInteger),
    notBefore: optional(safeInteger), failureClass: optional(nonempty), resultReceipt: optional(hash), state: nonempty,
  },
  Receipt: {
    receiptId: hash,
    producerTuple: producer,
    kind: nonempty, subjectOid: optional(gitOid), manifest: object, edgeValueKeys: object, sourceRefs: list,
    coverageRoot: optional(hash), missingIds: list, failures: list, checks: list, host: nonempty,
    sessionMode: nonempty, usageSource: nonempty,
  },
  IntegrationCandidate: {
    candidateId: nonempty, orderedAttempts: items(producer), workerOids: items(gitOid), expectedTip: gitOid,
    candidateCommit: gitOid, candidateTree: gitOid, scopeDiffDigest: hash, gateKey: hash,
    checkReceiptIds: items(hash), pinRefs: items(nonempty), promotionOp: optional(nonempty), state: nonempty,
  },
};

const span = { spanId: nonempty, path: nonempty, startLine: positive, endLine: positive };
const provenance = fields({
  factDigest: hash, evidenceSpans: items(fields(span)), claims: items(fields({
    claimId: nonempty, spanIds: items(nonempty), text: nonempty, seq: optional(safeInteger),
  })), edgeCases: items(object), failureEvidence: items(object),
});
const workerClaim = { workerReportedStatus: oneOf('completed'), inlineSummary: string, provenance };
const runtimeRecords = {
  Run: {
    runId, workspace: absolute, graphRev: positive, status: runStatus, nodes: object,
    attemptsIssued: safeInteger, baseSha: optional(gitOid), limits: fields({
      maxPins: safeInteger, maxAttempts: safeInteger, maxInfraRetries: safeInteger,
      readConcurrency: positive, maxFlakyDiagnostics: safeInteger,
      maxInlineBytesPerNode: safeInteger, maxInlineBytesPerWave: safeInteger,
    }),
  },
  Node: {
    id: nonempty, logicalId: nonempty, kind: nodeKind, status: oneOf('pending', 'claimed', 'running',
      'accepted', 'retry_wait', 'fresh_reset_ready', 'held_blocked', 'held_infra', 'held_upstream',
      'failed_logic', 'held_flaky', 'superseded_by_repair'),
    highestIssuedEpoch: safeInteger, infraRetries: safeInteger, topoRank: safeInteger, topologicalRank: safeInteger,
    estimatedMinutes: positive, priority: (value, label) => safeInteger(value, label, Number.MIN_SAFE_INTEGER),
    dependsOn: items(nonempty), inputUris: optional(items(casAddress)), attempt: nullable(object),
    receiptUri: nullable(casAddress), execKey: nullable(hash), gateKey: nullable(hash),
    artifactDigest: optional(hash), repairDepth: optional(positive), gateVersion: optional(positive),
    timeoutMs: optional(positive), jitterMs: optional(safeInteger),
  },
  Attempt: {
    ...tuple, runId, claimOp: nonempty, execKey: hash, instructionPath: absolute, nonceHash: hash,
    directiveDigest: hash, localKey: hash, pinSlots: safeInteger, inputUris: items(casAddress),
    receiptPhase: oneOf('prepared', 'delivered', 'checked'), hostHandle: optional(nonempty),
    settleOp: optional(nonempty), verifierOp: optional(nonempty), verificationStartedAtMs: optional(safeInteger),
    gateLogUri: optional(casAddress), deliveredUri: optional(casAddress),
  },
  Receipt: {
    ...workerClaim, workerClaim: fields(workerClaim), gateEvidence: fields({ logUri: casAddress }),
    verifierEvidence: fields({ logUri: casAddress, argv: items(string), envDigest: hash,
      exit: oneOf(0), signal: oneOf(null), subjectDigest: hash,
      spanResolutions: items(fields({ ...span, actualLines: positive, sha256: hash })),
    }),
    budget: fields({ mode: oneOf('bytes', 'tokens'), W_eff: nullable(safeInteger),
      reservedTokens: nullable(safeInteger), B: nullable(safeInteger), perIssueTokens: nullable(safeInteger),
      totalTokens: nullable(safeInteger), inlineTokens: nullable(safeInteger),
      maxInlineBytesPerNode: safeInteger, maxInlineBytesPerWave: safeInteger,
    }),
  },
};
const runtimeKeys = {
  Run: ['workspace', 'nodes', 'attemptsIssued'],
  Node: ['id', 'logicalId', 'highestIssuedEpoch'],
  Attempt: ['instructionPath', 'nonceHash', 'receiptPhase'],
  Receipt: ['workerClaim', 'verifierEvidence', 'gateEvidence'],
};

function validateFields(value, fields, label) {
  for (const [key, validate] of Object.entries(fields)) {
    validate(Object.hasOwn(value, key) ? value[key] : undefined, `${label}.${key}`);
  }
}

function validateVersion(name, value, required) {
  if ((required || Object.hasOwn(value, 'schemaVersion')) && value.schemaVersion !== SCHEMA_VERSION) {
    throw schemaError(`${name}.schemaVersion must be ${SCHEMA_VERSION}`);
  }
}

function validateRuntime(name, value) {
  object(value, name);
  validateVersion(name, value, true);
  validateFields(value, runtimeRecords[name], name);
  if (name === 'Run') {
    for (const [id, node] of Object.entries(value.nodes)) {
      validateRuntime('Node', node);
      if (node.id !== id || (node.attempt && (node.attempt.runId !== value.runId || node.attempt.graphRev > value.graphRev))) {
        throw schemaError(`Run.nodes[${JSON.stringify(id)}] does not match its persisted identity`);
      }
    }
  } else if (name === 'Node' && value.attempt) {
    validateRuntime('Attempt', value.attempt);
    if (value.attempt.nodeId !== value.id || value.attempt.epoch > value.highestIssuedEpoch) {
      throw schemaError('Node.attempt does not match its persisted identity');
    }
  } else if (name === 'Receipt' && (value.verifierEvidence.logUri !== value.gateEvidence.logUri
      || value.verifierEvidence.subjectDigest !== value.provenance.factDigest)) {
    throw schemaError('Receipt verifier evidence does not match the checked subject or log');
  }
}

function parseRecord(name, input, runtimeOnly = false) {
  object(input, name);
  const copy = immutable(input);
  if (runtimeOnly || runtimeKeys[name]?.some(key => Object.hasOwn(copy, key))) {
    validateRuntime(name, copy);
    return copy;
  }
  validateVersion(name, copy, false);
  validateFields(copy, records[name], name);
  return Object.freeze({ ...copy, schemaVersion: SCHEMA_VERSION });
}

export const Run = input => parseRecord('Run', input);
export const Node = input => parseRecord('Node', input);
export const Attempt = input => parseRecord('Attempt', input);
export const Receipt = input => parseRecord('Receipt', input);
export const IntegrationCandidate = input => parseRecord('IntegrationCandidate', input);

// Validate the durable post-image, never the mutable transition object in place.
export const validateRunRecords = state => parseRecord('Run', state, true);
