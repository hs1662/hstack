import assert from "node:assert/strict";
import { appendFileSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { it } from "node:test";
import { handlePostInvocation } from "../scripts/post-invocation.mjs";
import { computeWorkspaceKey, listPinnedSnapshots, readSessionState } from "../scripts/governance/handoff-store.mjs";
import { createMcpServerHandler } from "../scripts/mcp/server.mjs";
import { createTempDir } from "./helpers.mjs";

const drift = "The next step is to compare the two files and check whether the missing value can be restored.";

function createSession() {
  const cwd = createTempDir();
  const dataDir = createTempDir();
  const conversationId = "canary-session";
  const transcriptPath = join(cwd, "conversation.jsonl");
  const payload = JSON.stringify({ hookEventName: "PostInvocation", conversationId, transcriptPath, cwd });
  let index = 0;
  const record = (type, content, extra = {}) =>
    appendFileSync(transcriptPath, `${JSON.stringify({ type, content, step_index: index++, ...extra })}\n`);
  return {
    cwd, dataDir, conversationId, transcriptPath, record,
    post: () => JSON.stringify(handlePostInvocation(payload, { dataDir })),
    state: () => readSessionState(conversationId, dataDir),
  };
}

it("counts finished user turns once and keeps the handoff that its advisory identifies", () => {
  const s = createSession();
  function turn(text = drift, prompt = "원인을 설명해 줘") {
    s.record("USER_INPUT", prompt);
    s.record("PLANNER_RESPONSE", text);
    return s.post();
  }
  turn("짧은 응답");
  turn(drift, "답변을 영어로 작성해 줘");
  assert.match(turn(), /load_failure/);
  assert.doesNotMatch(s.post(), /load_failure|suspect|handoff_required/);
  s.record("USER_INPUT", "다음 작업을 진행해 줘");
  s.record("PLANNER_RESPONSE", drift, { tool_calls: [{ name: "view_file", args: {} }] });
  assert.doesNotMatch(s.post(), /suspect|handoff_required/);
  s.record("PLANNER_RESPONSE", drift);
  s.post();
  assert.match(turn(), /suspect/);
  const warning = turn();
  assert.match(warning, /handoff_required/);
  const dir = join(s.dataDir, "handoffs", computeWorkspaceKey(s.cwd));
  const snapshot = JSON.parse(readFileSync(join(dir, "latest.json"), "utf8"));
  assert.ok(warning.includes(snapshot.snapshotId));
  assert.deepEqual(snapshot.verifiedFacts, []);
  assert.deepEqual(listPinnedSnapshots(snapshot.workspaceKey, s.dataDir), [
    { snapshotId: snapshot.snapshotId, pinOwners: [s.state().canaryHandoff.pinOwner] },
  ]);
  const savedEntries = readdirSync(dir).sort();
  assert.doesNotMatch(s.post(), /handoff_required/);
  assert.deepEqual(readdirSync(dir).sort(), savedEntries);
});

it("a handoff warning cannot certify an unsupported completion claim or overturn verification", () => {
  const s = createSession();
  s.record("USER_INPUT", "원인을 확인해 줘");
  s.record("PLANNER_RESPONSE", drift);
  const rpc = createMcpServerHandler({ dataDir: s.dataDir });
  const verify = (runs) => rpc({
    jsonrpc: "2.0", id: 1, method: "tools/call", params: {
      name: "verify_completion", arguments: {
        _session: { cwd: s.cwd, transcriptPath: s.transcriptPath, conversationId: s.conversationId },
        modified_files: [], inspected_files: [], verification_runs: runs,
        unverified_scope: [], self_assessment: "",
      },
    },
  }).result.content[0].text.split("\n")[0];
  const claims = [[], [{ command: "node --test never-ran.test.mjs", outcome: "pass" }]];
  const before = claims.map(verify);
  for (let i = 0; i < 4; i++) {
    s.record("USER_INPUT", "다시 확인해 줘");
    s.record("PLANNER_RESPONSE", drift);
    s.post();
  }
  assert.equal(s.state().languageCanary.status, "handoff_required");
  assert.deepEqual(before, ["[완료 검증 통과]", "[검증 반려]"]);
  assert.deepEqual(claims.map(verify), before);
});
