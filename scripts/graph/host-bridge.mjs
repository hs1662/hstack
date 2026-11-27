// Graph v1 host bridge: capability hints, the canary's probe and abort signal, and handoff carryover between attempts.
import { createHash } from "node:crypto";
import { renameSync, writeFileSync } from "node:fs";
import { isAbsolute } from "node:path";
import { SUBAGENT_TOOL_NAME } from "../governance/constants.mjs";
import { readGitLedger, resolveGitRootFast } from "../governance/fact-ledger.mjs";
import {
  computeWorkspaceKey,
  listPinnedSnapshots,
  loadHandoffSnapshot,
  pinSnapshot,
  readSessionState,
  resolveSessionStatePath,
  saveHandoffSnapshot,
  withSessionLock,
} from "../governance/handoff-store.mjs";
import { DEFAULT_CANARY_CONFIG } from "../governance/language-canary.mjs";
import { detectHost, getHostCapabilities } from "../host/host-adapter.mjs";

const MAX_CANARY_OBSERVATIONS = 50;
const NO_CANARY_STATS = { probes: 0, probeFailures: 0, schemaErrors: 0, escalations: 0, observations: [] };

function fail(code, message, cause) {
  throw Object.assign(new Error(message, { cause }), { code });
}

const isText = (value) => typeof value === "string" && value.trim().length > 0;
const shortHash = (value) => createHash("sha256").update(value).digest("hex").slice(0, 24);
const isPinListed = (workspaceKey, snapshotId, pinOwner, dataDir) => listPinnedSnapshots(workspaceKey, dataDir)
  .some((item) => item.snapshotId === snapshotId && item.pinOwners.includes(pinOwner));

const DISPATCH_TOOLS = { antigravity: SUBAGENT_TOOL_NAME, "claude-code": "Agent" };

// What this package can do on the host, not what the current session was granted.
export function hostCaps(host = detectHost()) {
  const caps = getHostCapabilities(host);
  return Object.freeze({ ...caps, dispatchHint: caps.spawn ? DISPATCH_TOOLS[caps.host] : null, hintOnly: true });
}

// Reads only the state recordLanguageCanaryTurn persisted, so reply text claiming the event cannot raise it.
export function contextRotAbort({ sessionId, dataDir } = {}) {
  if (!isText(sessionId)) fail("E_CARRYOVER_INPUT", "sessionId is required");
  const state = readSessionState(sessionId, dataDir);
  if (state?.languageCanary?.status !== "handoff_required" || !state.canaryHandoff) return null;
  return { reason: "context_rot_abort", sessionId, snapshotId: state.canaryHandoff.snapshotId };
}

export function canaryStats({ sessionId, dataDir } = {}) {
  if (!isText(sessionId)) fail("E_PROBE_INPUT", "sessionId is required");
  return readSessionState(sessionId, dataDir)?.canaryStats ?? structuredClone(NO_CANARY_STATS);
}

function recordObservation(stats = NO_CANARY_STATS, observation) {
  const { turn, probePassed, schemaError, escalated } = observation;
  // A replayed probe of the same turn with the same answer is one observation.
  if (stats.observations.some((seen) =>
    seen.turn === turn && seen.probePassed === probePassed && seen.schemaError === schemaError)) return stats;
  return {
    probes: stats.probes + 1,
    probeFailures: stats.probeFailures + Number(!probePassed),
    schemaErrors: stats.schemaErrors + Number(schemaError),
    escalations: stats.escalations + Number(escalated),
    observations: [...stats.observations, observation].slice(-MAX_CANARY_OBSERVATIONS),
  };
}

// The same handoff the canary publishes on its own third drift, verified as pinned before state refers to it.
function publishCanaryHandoff({ cwd, sessionId, dataDir }) {
  const pinOwner = `canary:${shortHash(sessionId)}`;
  try {
    const gitLedger = readGitLedger(cwd);
    const { snapshot, workspaceKey } = saveHandoffSnapshot({
      conversationId: sessionId, cwd, gitLedger, dataDir, pinOwner,
      input: {
        objective: "카나리아 재검사에 실패한 세션의 작업 상태 인계",
        remaining_tasks: ["새 세션에서 작업 목표와 미검증 항목을 재확인하세요."],
      },
    });
    const { snapshotId } = snapshot;
    if (loadHandoffSnapshot({ cwd, gitLedger, snapshotId, dataDir }).ok
      && isPinListed(workspaceKey, snapshotId, pinOwner, dataDir)) return { snapshotId, pinOwner };
  } catch (error) {
    fail("E_PIN_FAILED", "Could not publish the canary handoff", error);
  }
  fail("E_PIN_FAILED", "The canary handoff is not readable and pinned");
}

// Applies a trusted format/semantic probe to a session the canary persisted as suspect at kWarn drifts. A failed
// probe forces handoff_required; a healthy one changes no canary state. Advisory only: it accepts nothing.
export function recheckSuspect({ cwd, sessionId, probe, dataDir } = {}) {
  if (!isText(sessionId)) fail("E_PROBE_INPUT", "sessionId is required");
  if (!isText(cwd) || !isAbsolute(cwd)) fail("E_PROBE_INPUT", "cwd must be an absolute path");
  const { probePassed, schemaError } = probe ?? {};
  if (typeof probePassed !== "boolean" || typeof schemaError !== "boolean") {
    fail("E_PROBE_INPUT", "probe must be { probePassed: boolean, schemaError: boolean }");
  }

  const statePath = resolveSessionStatePath(sessionId, dataDir);
  return withSessionLock(statePath, () => {
    const session = readSessionState(sessionId, dataDir);
    const canary = session?.languageCanary;
    const handoffRequired = (snapshotId) => ({ advisory: true, event: "handoff_required", snapshotId });
    if (canary?.status === "handoff_required" && session.canaryHandoff) {
      return handoffRequired(session.canaryHandoff.snapshotId);
    }
    if (canary?.status !== "suspect" || canary.consecutiveDrifts < DEFAULT_CANARY_CONFIG.kWarn) {
      return { advisory: true, event: "not_suspect" };
    }

    const escalated = !probePassed || schemaError;
    const next = {
      ...session,
      canaryStats: recordObservation(session.canaryStats, {
        turn: session.canaryTurn, consecutiveDrifts: canary.consecutiveDrifts, probePassed, schemaError, escalated,
      }),
    };
    if (escalated) {
      next.canaryHandoff = publishCanaryHandoff({ cwd, sessionId, dataDir });
      next.languageCanary = {
        ...canary, status: "handoff_required", consecutiveDrifts: 0, consecutiveNormal: 0,
        cooldownRemaining: DEFAULT_CANARY_CONFIG.cooldownTurns,
      };
    }
    // shortcut: handoff-store keeps its atomic JSON writer private, use it here once it is exported.
    const tmpPath = `${statePath}.tmp-${process.pid}`;
    writeFileSync(tmpPath, `${JSON.stringify(next, null, 2)}\n`, "utf8");
    renameSync(tmpPath, statePath);
    return escalated ? handoffRequired(next.canaryHandoff.snapshotId) : { advisory: true, event: "probe_healthy" };
  });
}

const factSet = (facts) => JSON.stringify([...new Set(facts.map((fact) => fact.trim()).filter(Boolean))].sort());

// Pins one concrete snapshot for a session's attempt. verifiedFacts must be exactly the snapshot's facts, so
// nothing the caller has not vouched for travels with the URI.
export function pinCarryover({ cwd, sessionId, attemptId, snapshotId, verifiedFacts, dataDir } = {}) {
  for (const [name, value] of Object.entries({ cwd, sessionId, attemptId, snapshotId })) {
    if (!isText(value)) fail("E_CARRYOVER_INPUT", `${name} is required`);
  }
  if (!isAbsolute(cwd)) fail("E_CARRYOVER_INPUT", "cwd must be an absolute path");
  if (!Array.isArray(verifiedFacts) || !verifiedFacts.every((fact) => typeof fact === "string")) {
    fail("E_CARRYOVER_INPUT", "verifiedFacts must be an array of strings");
  }

  const gitRoot = resolveGitRootFast(cwd);
  const workspaceKey = computeWorkspaceKey(cwd, gitRoot);
  const loaded = loadHandoffSnapshot({ cwd, gitLedger: { gitRoot }, snapshotId, dataDir });
  // The store resolves "latest" (and padded IDs) to another name; only the exact stored ID may be carried.
  if (!loaded.ok || loaded.snapshot.snapshotId !== snapshotId) {
    fail("E_SNAPSHOT_UNVERIFIED", `No readable snapshot ${snapshotId} in workspace ${workspaceKey}`);
  }
  if (!Array.isArray(loaded.snapshot.verifiedFacts) || factSet(loaded.snapshot.verifiedFacts) !== factSet(verifiedFacts)) {
    fail("E_FACTS_MISMATCH", `verifiedFacts differ from the facts stored in snapshot ${snapshotId}`);
  }

  const pinOwner = `graph:${shortHash(JSON.stringify([sessionId, attemptId]))}`;
  let pinned;
  try {
    pinSnapshot(workspaceKey, snapshotId, pinOwner, dataDir);
    // pinSnapshot returns false both for an existing pin and a vanished snapshot; the pin list tells them apart.
    pinned = isPinListed(workspaceKey, snapshotId, pinOwner, dataDir);
  } catch (error) {
    fail("E_PIN_FAILED", `Could not pin snapshot ${snapshotId}`, error);
  }
  if (!pinned) fail("E_PIN_FAILED", `Pin for snapshot ${snapshotId} is not listed`);

  return { handoffCarryoverUri: `hstack-handoff://${workspaceKey}/${snapshotId}`, workspaceKey, snapshotId, pinOwner };
}
