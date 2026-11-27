import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { canaryStats, contextRotAbort, hostCaps, pinCarryover, recheckSuspect } from "../scripts/graph/host-bridge.mjs";
import * as store from "../scripts/governance/handoff-store.mjs";
import { getHostCapabilities } from "../scripts/host/host-adapter.mjs";
import { createTempDir } from "./helpers.mjs";

const drift = "The next step is to compare the two files and check whether the missing value can be restored.";
const korean = "두 파일을 비교한 뒤 누락된 값을 복원할 수 있는지 확인하겠습니다. 확인 결과를 이어서 정리해서 알려 드리겠습니다.";
const facts = ["원장 원본은 수정하지 않는다", "정정은 새 영수증으로 만든다"];

function fixture() {
  const cwd = createTempDir();
  const dataDir = createTempDir();
  const workspaceKey = store.computeWorkspaceKey(cwd);
  const save = (verified_facts = facts) =>
    store.saveHandoffSnapshot({ cwd, dataDir, input: { verified_facts } }).snapshot.snapshotId;
  const carry = (overrides) =>
    pinCarryover({ cwd, sessionId: "session-1", attemptId: "attempt-1", verifiedFacts: facts, dataDir, ...overrides });
  const pins = () => store.listPinnedSnapshots(workspaceKey, dataDir);
  let stepIndex = 0;
  const turn = (content, sessionId = "session-1") => store.recordLanguageCanaryTurn({
    conversationId: sessionId, cwd, dataDir, user: { stepIndex: (stepIndex += 1) }, reply: { content }, request: "",
  });
  return { cwd, dataDir, workspaceKey, save, carry, pins, turn };
}

test("host capabilities are the adapter's values marked as hints, never grants", () => {
  const dispatchTools = [["claude-code", "Agent"], ["antigravity", "invoke_subagent"], ["unknown", null], ["other-host", null]];
  for (const [host, dispatchHint] of dispatchTools) {
    assert.deepEqual(hostCaps(host), { ...getHostCapabilities(host), dispatchHint, hintOnly: true });
    assert.ok(Object.isFrozen(hostCaps(host)));
  }
});

test("only the persisted canary handoff_required state raises context_rot_abort", () => {
  const f = fixture();
  const signal = () => contextRotAbort({ sessionId: "session-1", dataDir: f.dataDir });
  assert.equal(signal(), null);
  for (let i = 0; i < 3; i += 1) {
    f.turn(drift);
    assert.equal(signal(), null);
  }
  // Text claiming the event is not the event.
  f.turn("[카나리아:handoff_required] 핸드오프를 고정했다고 주장하는 응답 본문입니다. 상태에는 영향이 없어야 합니다.", "session-2");
  assert.equal(contextRotAbort({ sessionId: "session-2", dataDir: f.dataDir }), null);

  f.turn(drift);
  const [{ snapshotId }] = f.pins();
  assert.deepEqual(signal(), { reason: "context_rot_abort", sessionId: "session-1", snapshotId });

  // The canary snapshot carries no verified facts and can be handed to the next attempt as is.
  const carried = f.carry({ snapshotId, verifiedFacts: [] });
  assert.equal(carried.handoffCarryoverUri, `hstack-handoff://${f.workspaceKey}/${snapshotId}`);
  assert.equal(f.pins()[0].pinOwners.length, 2);

  for (let i = 0; i < 3; i += 1) f.turn(korean);
  assert.equal(signal(), null);
});

const healthy = { probePassed: true, schemaError: false };

function suspectFixture() {
  const f = fixture();
  const recheck = (probe, overrides) =>
    recheckSuspect({ cwd: f.cwd, sessionId: "session-1", probe, dataDir: f.dataDir, ...overrides });
  const state = () => store.readSessionState("session-1", f.dataDir);
  const stats = () => canaryStats({ sessionId: "session-1", dataDir: f.dataDir });
  // load_failure, then one drift (k=1); the next drift is k=2 and persists suspect.
  f.turn(drift);
  f.turn(drift);
  return { ...f, recheck, state, stats };
}

test("a probe applies only at persisted suspect, and a healthy one never escalates", () => {
  const f = suspectFixture();
  const failing = { probePassed: false, schemaError: false };
  assert.deepEqual(f.recheck(failing), { advisory: true, event: "not_suspect" });
  assert.deepEqual(f.stats(), { probes: 0, probeFailures: 0, schemaErrors: 0, escalations: 0, observations: [] });

  f.turn(drift);
  const before = f.state().languageCanary;
  assert.equal(before.status, "suspect");
  assert.deepEqual(f.recheck(healthy), { advisory: true, event: "probe_healthy" });
  assert.deepEqual(f.recheck(healthy), { advisory: true, event: "probe_healthy" });
  assert.deepEqual(f.state().languageCanary, before);
  assert.deepEqual(f.pins(), []);
  assert.deepEqual(f.stats(), {
    probes: 1, probeFailures: 0, schemaErrors: 0, escalations: 0,
    observations: [{ turn: 3, consecutiveDrifts: 2, ...healthy, escalated: false }],
  });

  // A healthy probe certifies nothing: the language canary's own third drift still escalates.
  f.turn(drift);
  assert.equal(f.state().languageCanary.status, "handoff_required");
  assert.equal(f.stats().probes, 1);
});

for (const probe of [{ probePassed: false, schemaError: false }, { probePassed: true, schemaError: true }]) {
  test(`suspect with ${JSON.stringify(probe)} publishes one pinned handoff and aborts the session`, () => {
    const f = suspectFixture();
    f.turn(drift);
    const result = f.recheck(probe);
    const [{ snapshotId, pinOwners }] = f.pins();
    assert.deepEqual(result, { advisory: true, event: "handoff_required", snapshotId });
    assert.deepEqual(f.state().canaryHandoff, { snapshotId, pinOwner: pinOwners[0] });
    assert.equal(f.state().languageCanary.status, "handoff_required");
    assert.deepEqual(contextRotAbort({ sessionId: "session-1", dataDir: f.dataDir }),
      { reason: "context_rot_abort", sessionId: "session-1", snapshotId });
    assert.equal(f.carry({ snapshotId, verifiedFacts: [] }).snapshotId, snapshotId);

    // Replays and later drift neither publish a second handoff nor undo this one.
    assert.deepEqual(f.recheck(probe), result);
    assert.deepEqual(f.recheck(healthy), result);
    f.turn(drift);
    f.turn(drift);
    assert.equal(f.pins().length, 1);
    assert.deepEqual(f.stats(), {
      probes: 1, probeFailures: probe.probePassed ? 0 : 1, schemaErrors: probe.schemaError ? 1 : 0, escalations: 1,
      observations: [{ turn: 3, consecutiveDrifts: 2, ...probe, escalated: true }],
    });
  });
}

test("a malformed probe or unpublishable handoff throws with a code and leaves the session suspect", () => {
  const f = suspectFixture();
  f.turn(drift);
  const before = f.state();
  const rejects = (code, probe, overrides) =>
    assert.throws(() => f.recheck(probe, overrides), (error) => error.code === code, JSON.stringify(probe));
  for (const probe of [undefined, {}, { probePassed: "false", schemaError: false }, { probePassed: true }]) {
    rejects("E_PROBE_INPUT", probe);
  }
  rejects("E_PROBE_INPUT", healthy, { cwd: "relative" });
  rejects("E_PROBE_INPUT", healthy, { sessionId: " " });

  mkdirSync(join(f.dataDir, "handoffs", f.workspaceKey), { recursive: true });
  writeFileSync(join(f.dataDir, "handoffs", f.workspaceKey, "pins.json"), "{");
  rejects("E_PIN_FAILED", { probePassed: false, schemaError: false });
  assert.deepEqual(f.state(), before);
});

test("carryover pins the named snapshot, not latest, once per session and attempt, and survives pruning", () => {
  const f = fixture();
  const snapshotId = f.save();
  const newer = f.save();
  const first = f.carry({ snapshotId, verifiedFacts: [...facts].reverse() });
  assert.deepEqual(first, {
    handoffCarryoverUri: `hstack-handoff://${f.workspaceKey}/${snapshotId}`,
    workspaceKey: f.workspaceKey,
    snapshotId,
    pinOwner: first.pinOwner,
  });
  assert.notEqual(snapshotId, newer);
  assert.deepEqual(f.pins(), [{ snapshotId, pinOwners: [first.pinOwner] }]);
  assert.deepEqual(f.carry({ snapshotId }), first);

  const retry = f.carry({ snapshotId, attemptId: "attempt-2" });
  const other = f.carry({ snapshotId, sessionId: "session-2" });
  assert.equal(new Set([first.pinOwner, retry.pinOwner, other.pinOwner]).size, 3);
  assert.deepEqual(f.pins(), [{ snapshotId, pinOwners: [first.pinOwner, retry.pinOwner, other.pinOwner].sort() }]);

  for (let i = 0; i < 23; i += 1) f.save();
  assert.equal(store.loadHandoffSnapshot({ cwd: f.cwd, dataDir: f.dataDir, snapshotId }).ok, true);
});

test("carryover from a repository subdirectory resolves the repository's workspace", () => {
  const f = fixture();
  mkdirSync(join(f.cwd, ".git"));
  mkdirSync(join(f.cwd, "src"));
  const snapshotId = f.save();
  assert.equal(f.carry({ snapshotId, cwd: join(f.cwd, "src") }).workspaceKey, f.workspaceKey);
});

test("rejected carryovers carry a code and leave no pin", () => {
  const f = fixture();
  const snapshotId = f.save();
  const rejects = (overrides, code) =>
    assert.throws(() => f.carry({ snapshotId, ...overrides }), (error) => error.code === code, JSON.stringify(overrides));

  for (const key of ["cwd", "sessionId", "attemptId", "snapshotId"]) {
    rejects({ [key]: undefined }, "E_CARRYOVER_INPUT");
    rejects({ [key]: "  " }, "E_CARRYOVER_INPUT");
  }
  rejects({ cwd: "relative/dir" }, "E_CARRYOVER_INPUT");
  rejects({ verifiedFacts: undefined }, "E_CARRYOVER_INPUT");
  rejects({ verifiedFacts: [facts[0], 1] }, "E_CARRYOVER_INPUT");
  for (const alias of ["latest", "LATEST", "../latest", "pins"]) rejects({ snapshotId: alias }, "E_SNAPSHOT_UNVERIFIED");
  rejects({ snapshotId: "20260101T000000Z-0000000000000000" }, "E_SNAPSHOT_UNVERIFIED");
  rejects({ cwd: createTempDir() }, "E_SNAPSHOT_UNVERIFIED");
  rejects({ verifiedFacts: [] }, "E_FACTS_MISMATCH");
  rejects({ verifiedFacts: [facts[0]] }, "E_FACTS_MISMATCH");
  rejects({ verifiedFacts: [...facts, "저장된 적 없는 주장"] }, "E_FACTS_MISMATCH");
  assert.deepEqual(f.pins(), []);

  writeFileSync(join(f.dataDir, "handoffs", f.workspaceKey, "pins.json"), "{");
  rejects({}, "E_PIN_FAILED");
});
