import { createHash } from 'node:crypto';
import { graphError, isRecord, normalizeGateCommand, normalizeVolatility, SCHEMA_VERSION } from './schema.mjs';

const fail = message => graphError('ERR_GRAPH_FINGERPRINT', message);

// Write sorted keys directly: JSON.stringify(object) reorders integer-looking keys.
export function canonical(value) {
  const ancestors = new Set();
  function encode(item) {
    if (item === null || typeof item === 'boolean' || typeof item === 'string') return JSON.stringify(item);
    if (typeof item === 'number' && Number.isFinite(item)
        && (!Number.isInteger(item) || Number.isSafeInteger(item))) return JSON.stringify(item);
    if (ancestors.has(item)) throw fail('canonical data must be acyclic');
    ancestors.add(item);
    let result;
    if (Array.isArray(item)) {
      result = `[${Array.from({ length: item.length }, (_, index) =>
        encode(Object.getOwnPropertyDescriptor(item, index)?.value)).join(',')}]`;
    } else if (isRecord(item)) {
      result = `{${Object.keys(item).sort().map(key =>
        `${JSON.stringify(key)}:${encode(Object.getOwnPropertyDescriptor(item, key).value)}`).join(',')}}`;
    } else {
      throw fail('canonical data must be plain JSON with safe integers');
    }
    ancestors.delete(item);
    return result;
  }
  return encode(value);
}

function hash(domain, parts) {
  const digest = createHash('sha256');
  for (const part of ['hstack.graph', String(SCHEMA_VERSION), domain, ...parts]) {
    const bytes = typeof part === 'string' ? Buffer.from(part, 'utf8') : part;
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.byteLength));
    digest.update(length).update(bytes);
  }
  return digest.digest('hex');
}

function loadedFiles(files, label) {
  if (!Array.isArray(files)) throw fail(`${label} must contain ordered loaded files`);
  return Array.from(files, file => {
    if (!isRecord(file) || typeof file.name !== 'string' || file.name.trim() === '') {
      throw fail(`${label} entries require a logical name`);
    }
    if (typeof file.bytes !== 'string' && !(file.bytes instanceof Uint8Array)) {
      throw fail(`${label} entries require loaded UTF-8 text or raw bytes`);
    }
    return hash(label, [canonical(file.name), file.bytes]);
  });
}

function scopeSet(scope, label) {
  if (!Array.isArray(scope) || Array.from(scope).some(value => typeof value !== 'string')) {
    throw fail(`${label} must contain declared paths`);
  }
  return [...new Set(scope)].sort();
}

const pinned = value => typeof value === 'string' && value.trim() !== ''
  && !/(?:^|[/:@._-])(?:unknown|latest)$/i.test(value.trim());

function movingModel(model) {
  const name = model.trim();
  return /(?:^|[/:@._-])(?:stable|default|auto|current|rolling|nightly|experimental)$/i.test(name)
    || (/(?:^|[/:@._-])preview$/i.test(name) && !/\d{4}-\d{2}(?:-\d{2})?-preview$/i.test(name));
}

export function crossRunCacheDisabled(host, volatility) {
  const inputs = normalizeVolatility(volatility);
  return !isRecord(host) || host.cacheable === false || host.modelPinned === false
    || ![host.id, host.model, host.toolchain].every(pinned) || movingModel(host.model)
    || Object.values(inputs).some(reads => reads.some(read => read.digest == null));
}

// An unresolved host still has an execution identity for local failure fencing.
export function execKey({
  spec, renderedPrompt, messages = [], readScope = [], writeScope = [], baseSha = null,
  inputReceiptDigests = [], skills = [], rules = [], host, environment = {}, policy = null,
  projection, projectionConfig, volatility,
}) {
  if (!isRecord(spec)) throw fail('execKey requires the canonical execution spec');
  const identity = isRecord(host) ? host : {};
  if (typeof renderedPrompt !== 'string' && !(renderedPrompt instanceof Uint8Array)) {
    throw fail('execKey requires the final rendered prompt text or raw bytes');
  }
  if (!Array.isArray(inputReceiptDigests) || Array.from(inputReceiptDigests).some(
    digest => typeof digest !== 'string' || !/^[a-f0-9]{64}$/.test(digest))) {
    throw fail('execKey requires ordered parent receipt digests');
  }
  const executionSpec = Object.fromEntries(Object.entries(spec).filter(([key]) =>
    !['gateArgv', 'timeoutMs', 'testPlan', 'auditPolicy', 'gateVersion'].includes(key)));
  const context = {
    spec: executionSpec, messages, readScope: scopeSet(readScope, 'readScope'), writeScope: scopeSet(writeScope, 'writeScope'),
    baseSha, inputReceiptDigests, skills: loadedFiles(skills, 'skill'), rules: loadedFiles(rules, 'rule'),
    host: {
      id: identity.id ?? null, model: identity.model ?? null,
      toolchain: identity.toolchain ?? null, config: identity.config ?? null,
    },
    environment, policy,
    ...(projection != null && { projection }),
    ...(projectionConfig != null && { projectionConfig }),
    ...(volatility !== undefined && { volatility: normalizeVolatility(volatility) }),
  };
  return hash('exec', [canonical(context), renderedPrompt]);
}

export function gateKey({ candidateTree, testPlan, auditPolicy, gateVersion, environment = {}, gateArgv, timeoutMs }) {
  const command = normalizeGateCommand({ gateArgv, timeoutMs: timeoutMs === undefined && gateArgv !== undefined ? 30_000 : timeoutMs });
  return hash('gate', [canonical({ candidateTree, testPlan, auditPolicy, gateVersion, environment, ...command })]);
}

export function artifactDigest(value) {
  return value instanceof Uint8Array
    ? hash('artifact/bytes', [value])
    : hash('artifact/json', [canonical(value)]);
}
