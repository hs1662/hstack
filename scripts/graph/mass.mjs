import { canonical } from "./fingerprint.mjs";
import { casUri, digest } from "./gc.mjs";
import { reduce } from "./reducer.mjs";
import { graphError, isRecord, SCHEMA_VERSION } from "./schema.mjs";

const own = (map, key) => (map && Object.hasOwn(map, key) ? map[key] : undefined);

function checkedClaimIssue(receipt) {
  if (!isRecord(receipt.workerClaim) || !isRecord(receipt.verifierEvidence)) return "ERR_MISSING_EVIDENCE";
  const claim = { workerReportedStatus: receipt.workerReportedStatus ?? null,
    inlineSummary: receipt.inlineSummary ?? null, provenance: receipt.provenance ?? null };
  return canonical(claim) === canonical(receipt.workerClaim) ? null : "ERR_FORGED_EVIDENCE";
}
/**
 * Build a v1 graph from ordered `shards: [{id, prompt?, readScope?, ...}]`.
 * `clusterSize` (default 8) caps cluster fan-in; `limits` passes through.
 * Dispatch can also compile this input directly with `preset: "mass"`.
 */
export function compileMassSpec(spec) {
  if (!isRecord(spec)) throw graphError("ERR_MASS_SPEC", "mass requires a spec object");
  const { shards, clusterSize = 8, limits } = spec;
  if (!Array.isArray(shards) || shards.length === 0
      || !Number.isSafeInteger(clusterSize) || clusterSize < 1) {
    throw graphError("ERR_MASS_SPEC", "mass requires shards and a positive clusterSize");
  }
  const ids = new Set(["mass-final"]);
  const clusters = Array.from({ length: Math.ceil(shards.length / clusterSize) }, (_, index) => {
    const id = `mass-cluster-${index + 1}`;
    ids.add(id);
    return { id, kind: "reducer", prompt: `Reduce the sealed shard cluster ${index + 1}.`, dependsOn: [] };
  });
  const reads = Array.from(shards, (shard, index) => {
    if (!isRecord(shard) || !Object.hasOwn(shard, "id") || typeof shard.id !== "string"
        || shard.id.trim() === "" || ids.has(shard.id)) {
      throw graphError("ERR_MASS_SPEC", "mass shard IDs must be nonempty, unique and not reserved");
    }
    if (Object.hasOwn(shard, "obligationId")
        && (typeof shard.obligationId !== "string" || shard.obligationId.trim() === "")) {
      throw graphError("ERR_MASS_SPEC", `invalid obligationId for ${shard.id}`);
    }
    ids.add(shard.id);
    clusters[Math.floor(index / clusterSize)].dependsOn.push(shard.id);
    return { prompt: `Collect evidence for shard ${shard.id}.`, ...shard, kind: "read" };
  });
  return {
    schemaVersion: SCHEMA_VERSION,
    ...(limits === undefined ? {} : { limits }),
    nodes: [...reads, ...clusters, {
      id: "mass-final", kind: "reducer", prompt: "Reduce the sealed shard clusters.",
      dependsOn: clusters.map(({ id }) => id),
    }],
  };
}

async function readAccepted(node, io) {
  if (node?.status !== "accepted" || typeof node.receiptUri !== "string" || !casUri.test(node.receiptUri)
      || (node.attempt && node.attempt.epoch !== node.highestIssuedEpoch)) return null;
  try {
    const bytes = await io.get(node.receiptUri);
    if (!(bytes instanceof Uint8Array)
        || `cas://sha256/${digest(bytes)}` !== node.receiptUri) return null;
    const receipt = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return isRecord(receipt) ? receipt : null;
  } catch (err) {
    if (err instanceof SyntaxError || err.code === "ERR_ENCODING_INVALID_ENCODED_DATA"
        || ["ERR_JOURNAL_CORRUPT", "ENOENT"].includes(err.code)) return null;
    throw err;
  }
}

// Collect closed coverage independently of accepted output availability.
// A missing cluster cannot hide its missing leaves from the final reducer.
async function collect(state, nodeId, io, verifyIndexes = true) {
  const expected = [], leaves = [], receiptIssues = [], dependencyIssues = [], clusterIndexes = [];
  async function visit(joinId, ancestors) {
    if (ancestors.has(joinId)) throw graphError("ERR_MASS_MEMBERSHIP", "cycle in sealed join membership");
    const members = own(state.joinMembers, joinId);
    if (!Array.isArray(members) || members.length === 0) {
      throw graphError("ERR_MASS_MEMBERSHIP", `no sealed membership for ${joinId}`);
    }
    const direct = [];
    for (const { shardId, obligationId } of members) {
      const node = own(state.nodes, shardId);
      const validEpoch = node?.highestIssuedEpoch ?? 0;
      const tuple = { shardId, validEpoch, obligationId };
      const receipt = node?.kind === "reducer" && !verifyIndexes ? null : await readAccepted(node, io);
      direct.push({ ...tuple, receiptUri: receipt ? node.receiptUri : null });
      if (node?.kind === "reducer") {
        const inputs = await visit(shardId, new Set([...ancestors, joinId]));
        if (!verifyIndexes) continue;
        if (receipt?.kind === "mass-index" && receipt.status === "complete"
            && receipt.runId === state.runId && receipt.nodeId === shardId
            && receipt.epoch === node.highestIssuedEpoch && Array.isArray(receipt.inputs)
            && canonical(receipt.inputs) === canonical(inputs)) {
          clusterIndexes.push({ ...tuple, receiptUri: node.receiptUri });
        } else {
          dependencyIssues.push({ ...tuple, code: "ERR_MASS_CLUSTER_INDEX" });
        }
      } else {
        expected.push(tuple);
        if (receipt && validEpoch > 0) {
          const code = checkedClaimIssue(receipt);
          if (code) receiptIssues.push({ ...tuple, code });
          else leaves.push({ ...tuple, receiptUri: node.receiptUri });
        }
      }
    }
    return direct;
  }
  const inputs = await visit(nodeId, new Set());
  return { expected, leaves, inputs, receiptIssues, dependencyIssues, clusterIndexes };
}

// A remote link requires an independently resolved disposition in the same
// closed root. A root with another unresolved link is not usable as proof.
async function verifyRemoteLinks(state, nodeId, local, io) {
  const unresolved = local.issues.filter(({ code }) => code === "BROKEN_CLAIM_POINTER");
  if (!unresolved.length) return local;
  const outer = new Set([nodeId]);
  for (const id of outer) {
    for (const [parent, members] of Object.entries(state.joinMembers)) {
      if (members.some(({ shardId }) => shardId === id)) outer.add(parent);
    }
  }
  const nested = new Set(Array.from(outer).flatMap((id) =>
    state.joinMembers[id].map(({ shardId }) => shardId)));
  const roots = Array.from(outer).filter((id) => !nested.has(id));
  if (roots.length !== 1 || roots[0] === nodeId) return local;
  const { expected, leaves, receiptIssues } = await collect(state, roots[0], io, false);
  const global = await reduce({ ...io, workspaceRoot: state.workspace, expected, leaves });
  if (receiptIssues.length || global.status !== "complete") return local;

  const occurrence = ({ shardId, validEpoch, obligationId, receiptUri, index }) =>
    canonical([shardId, validEpoch, obligationId, receiptUri, index]);
  const links = new Map(global.dispositions.filter(({ target }) => target)
    .map((entry) => [occurrence(entry), entry]));
  const verified = unresolved.filter(({ source }) => links.has(occurrence(source)));
  if (!verified.length) return local;
  const covered = new Set(verified.map(({ source }) => occurrence(source)));
  const dispositions = local.dispositions.map((entry) => {
    const key = occurrence(entry);
    return covered.has(key) ? links.get(key) : entry;
  });
  const issues = local.issues.filter((issue) => !verified.includes(issue));
  const original = JSON.parse(await io.get(local.indexRoot));
  const indexRoot = await io.put(Buffer.from(canonical({ ...original, dispositions,
    remoteLinkProofUri: global.indexRoot })));
  return { ...local, dispositions, issues, indexRoot };
}

/**
 * Reducer transaction callback. Caller selects only the node; sealed join
 * members and current accepted CAS receipts are supplied by the engine state.
 * `io.get(uri)` returns bytes and `io.put(bytes)` returns a pinned CAS URI.
 * The response always supplies `indexUri`; `receiptUri` is the acceptance
 * receipt only for a complete built-in reduction. Worker settlement uses the
 * index as pre-merge proof and applies its gate separately.
 */
export async function reduceRun(state, { node: nodeId }, io) {
  const node = own(state.nodes, nodeId);
  if (node?.kind !== "reducer") throw graphError("ERR_MASS_NODE", `not a reducer: ${nodeId}`);
  const { expected, leaves, inputs, receiptIssues, dependencyIssues, clusterIndexes } = await collect(state, nodeId, io);
  const { get, put, budgetContext, maxInlineBytesPerNode, maxInlineBytesPerWave } = io;
  const reducerIO = { get, put, budgetContext, maxInlineBytesPerNode, maxInlineBytesPerWave };
  const local = await reduce({
    ...reducerIO,
    expected, leaves, workspaceRoot: state.workspace,
  });
  const result = await verifyRemoteLinks(state, nodeId, local, reducerIO);
  const status = !result.missing.length && !dependencyIssues.length && !result.issues.length
    ? "complete" : "partial";
  const index = {
    ...result, schemaVersion: SCHEMA_VERSION, kind: "mass-index", status,
    runId: state.runId, nodeId, epoch: node.highestIssuedEpoch ?? 0,
    issues: [...receiptIssues, ...result.issues],
    expected, inputs, dependencyIssues, clusterIndexes,
  };
  const indexUri = await io.put(Buffer.from(canonical(index)));
  const builtin = ["pending", "held_upstream", "accepted"].includes(node.status)
    && !node.revalidateReceiptUri && !node.workerReceiptUri
    && !node.gateArgv && !node.testPlan?.length && !node.auditPolicy && !node.gateVersion;
  const accepted = status === "complete" && builtin;
  const nextNode = accepted
    ? { ...node, status: "accepted", receiptUri: indexUri }
    : status === "partial" && node.status === "accepted" ? { ...node, status: "pending", receiptUri: null } : node;
  const response = {
    runId: state.runId, graphRev: state.graphRev, nodeId, status, indexUri,
    receiptUri: accepted ? indexUri : null, missingCount: result.missing.length,
    dependencyIssueCount: dependencyIssues.length,
  };
  return {
    state: { ...state, nodes: { ...state.nodes, [nodeId]: { ...nextNode, reductionUri: indexUri } } },
    response, refs: [indexUri], body: { nodeId, status, indexUri },
  };
}
