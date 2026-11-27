import { createHash, randomBytes, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { artifactDigest, crossRunCacheDisabled, execKey } from "./fingerprint.mjs";
import { graphError, safeInteger } from "./schema.mjs";

const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const stale = () => Object.assign(graphError("ERR_STALE_FENCING_TOKEN", "Attempt is no longer authorized"), { exitCode: 49 });
const within = (root, path) => path === root || path.startsWith(root + sep);

// The path supplies an untrusted run *locator* only. Never open it until the
// transaction has matched the whole path to an attempt in that run's journal.
export function locate(root, token, run) {
  if (typeof token !== "string" || !isAbsolute(token)) throw stale();
  const parts = relative(root, token).split(sep);
  if (parts.length !== 4 || parts[0] !== "runs" || parts[2] !== "directives" ||
      !/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(parts[1]) ||
      !/^[a-f0-9-]{36}\.json$/.test(parts[3]) || token !== join(root, ...parts) ||
      (run !== undefined && run !== parts[1])) throw stale();
  return parts[1];
}

export async function authenticate(state, { token, command, opId }) {
  const n = Object.values(state?.nodes ?? {}).find(n => n.attempt?.instructionPath === token);
  if (!n || n.attempt.epoch !== n.highestIssuedEpoch ||
      !["claimed", "running"].includes(n.status) && !(command === "settle" && n.attempt.settleOp === opId)) throw stale();
  const a = n.attempt;
  try {
    if (await realpath(token) !== token) throw stale();
    const fd = await open(a.instructionPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const st = await fd.stat();
      if (!st.isFile() || (st.mode & 0o077) || st.uid !== process.getuid() || st.nlink !== 1) throw stale();
      const bytes = await fd.readFile();
      if (hash(bytes) !== a.directiveDigest) throw stale();
      const d = JSON.parse(bytes);
      if (d.epoch !== a.epoch || d.runId !== state.runId || d.nodeId !== n.id ||
          d.graphRev !== a.graphRev || hash(d.nonce) !== a.nonceHash) throw stale();
    } finally { await fd.close(); }
  } catch (err) {
    if (["ENOENT", "ELOOP", "ENOTDIR", "EACCES"].includes(err.code)) throw stale();
    throw err;
  }
  return n;
}

async function syncDir(path) {
  const fd = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await fd.sync(); } finally { await fd.close(); }
}

async function directive(root, run, value) {
  const dir = join(root, "runs", run, "directives");
  if (await realpath(dirname(dir)) !== dirname(dir)) throw stale();
  try {
    await mkdir(dir, { mode: 0o700 });
    await syncDir(dirname(dir));
  } catch (err) { if (err.code !== "EEXIST") throw err; }
  const stat = await lstat(dir);
  if (!stat.isDirectory() || stat.uid !== process.getuid() || stat.mode & 0o077) throw stale();
  const instructionPath = join(dir, `${randomUUID()}.json`);
  const nonce = randomBytes(32).toString("hex");
  const bytes = Buffer.from(JSON.stringify({ ...value, nonce }));
  const fd = await open(instructionPath, constants.O_WRONLY | constants.O_NOFOLLOW |
    constants.O_CREAT | constants.O_EXCL, 0o400);
  try { await fd.writeFile(bytes); await fd.sync(); } finally { await fd.close(); }
  await syncDir(dir);
  return { instructionPath, nonceHash: hash(nonce), directiveDigest: hash(bytes) };
}

async function loadFile(workspace, name, root) {
  const error = () => graphError("ERR_GRAPH_INPUT", `Invalid workspace file: ${name}`);
  if (typeof name !== "string" || isAbsolute(name) || name.split(/[\\/]/).some(s => !s || s === "..")) throw error();
  const path = await realpath(resolve(workspace, name));
  if (!within(workspace, path) || within(root, path)) throw error();
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    if (!(await fd.stat()).isFile()) throw error();
    return { name, bytes: await fd.readFile() };
  } finally { await fd.close(); }
}

export function inputs(state, n) {
  return [...new Set([...n.dependsOn.map(id => state.nodes[id].receiptUri), ...(n.inputUris ?? []),
    n.failureReceiptUri, n.revalidateReceiptUri].filter(Boolean))];
}

async function generationContext(state, n, root) {
  const load = names => Promise.all(names.map(name => loadFile(state.workspace, name, root)));
  const [skills, rules] = await Promise.all([load(n.skills), load(n.rules)]);
  return {
    spec: { id: n.logicalId, kind: n.kind, handoffCarryoverUri: n.handoffCarryoverUri ?? null },
    renderedPrompt: n.prompt, messages: n.messages ?? [], readScope: n.readScope, writeScope: n.writeScope,
    host: state.hostProfile, baseSha: state.baseSha, skills, rules, environment: state.environment, policy: state.policy ?? null,
    projection: n.projection, projectionConfig: n.projectionConfig, volatility: n.volatility,
  };
}

function localKey(n, generation) {
  return execKey({ ...generation, inputReceiptDigests: [...new Set([...(n.inputUris ?? []),
    n.failureReceiptUri].filter(Boolean))].map(uri => uri.slice("cas://sha256/".length)) });
}

export async function currentLocalKey(s, n, root) {
  return localKey(n, await generationContext(s, n, root));
}

export async function issue(state, n, { root, opId }, io) {
  const epoch = safeInteger(n.highestIssuedEpoch + 1, "epoch", 1);
  const projected = n.kind === "read" && n.projection === "facts-v1" && n.projectionConfig == null &&
    n.dependsOn.every(id => Boolean(state.nodes[id].factViewDigest));
  const extra = [ ...(n.inputUris ?? []), n.failureReceiptUri, n.revalidateReceiptUri ].filter(Boolean);
  const parents = [];
  for (const id of n.dependsOn) {
    const parent = state.nodes[id];
    if (!projected) { parents.push(parent.receiptUri); continue; }
    const checked = JSON.parse(await io.get(parent.workerReceiptUri ?? parent.receiptUri));
    const { evidenceSpans, claims, edgeCases, failureEvidence, factDigest } = checked.provenance;
    parents.push(await io.put(Buffer.from(JSON.stringify({ evidenceSpans, claims, edgeCases, failureEvidence, factDigest }))));
  }
  const inputUris = [...new Set([...parents, ...extra])];
  for (const uri of inputUris) await io.get(uri);
  const generation = await generationContext(state, n, root);
  const { skills, rules } = generation;
  generation.inputReceiptDigests = inputUris.map(uri => uri.slice("cas://sha256/".length));
  const key = n.revalidateReceiptUri ? n.execKey : execKey(generation);
  if (n.failedExecKeys?.includes(key)) throw graphError("ERR_LOGIC_RETRY", "A terminal failure fenced this generation");
  const pinFiles = files => Promise.all(files.map(async ({ name, bytes }) => ({ name, uri: await io.put(bytes) })));
  const pinnedSkills = await pinFiles(skills), pinnedRules = await pinFiles(rules);
  const identity = { schemaVersion: 1, runId: state.runId, graphRev: state.graphRev, nodeId: n.id, epoch, execKey: key };
  const instructions = { ...identity, kind: n.kind, mode: n.revalidateReceiptUri ? "revalidate" : "execute",
    prompt: n.prompt, skills: pinnedSkills, rules: pinnedRules, messages: generation.messages,
    readScope: n.readScope, writeScope: n.writeScope, inputUris, handoffCarryoverUri: n.handoffCarryoverUri ?? null,
    revalidateReceiptUri: n.revalidateReceiptUri ?? null, gate: gatePolicy(n), reductionUri: n.reductionUri ?? null,
    dispatch: { workspace: state.workspace } };
  const issued = await directive(root, state.runId, instructions);
  Object.assign(n, { status: "claimed", highestIssuedEpoch: epoch, execKey: key, cacheable: !crossRunCacheDisabled(state.hostProfile, n.volatility),
    attempt: { ...identity, ...issued, claimOp: opId, receiptPhase: "prepared", localKey: localKey(n, generation),
      deliveredProjection: projected ? "facts-v1" : null, inputUris: [...new Set([...inputUris,
      ...pinnedSkills.map(f => f.uri), ...pinnedRules.map(f => f.uri), ...[n.reductionUri].filter(Boolean)])] } });
  return { ...identity, cacheable: n.cacheable, instructionPath: issued.instructionPath };
}

export const gatePolicy = n => ({
  testPlan: n.testPlan ?? [], auditPolicy: n.auditPolicy ?? {}, gateVersion: n.gateVersion ?? 1,
  ...(n.gateArgv ? { gateArgv: n.gateArgv, timeoutMs: n.timeoutMs ?? 30000 } : {}),
});

// Preserve evidence of rejected receipts without letting its unverified CAS
// strings masquerade as GC roots. Accepted receipts are stored as plain JSON.
export function failureRecord(receipt, reason) {
  return { schemaVersion: 1, reason, encoding: "base64", raw: Buffer.from(JSON.stringify(receipt ?? null)).toString("base64") };
}

export async function validatedArtifact(receipt, io) {
  // Presentation may spill the same summary under a tighter delivery budget.
  const summary = receipt.inlineSummary;
  const inlineSummary = summary.startsWith("cas://") ? (await io.get(summary)).toString("utf8") : summary;
  return artifactDigest({ provenance: receipt.provenance, inlineSummary });
}
