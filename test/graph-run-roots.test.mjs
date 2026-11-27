import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { dispatch } from "../scripts/graph/state-machine.mjs";
import { collectGarbage, getBlob, putBlob } from "../scripts/graph/gc.mjs";
import { listPinnedSnapshots, saveHandoffSnapshot } from "../scripts/governance/handoff-store.mjs";

test("mass refuses a future schema before expanding and execution policy changes the claimed key", async t => {
  const root = await mkdtemp(join(tmpdir(), "graph-policy-"));
  t.after(() => rm(root, {recursive:true, force:true}));
  const workspace = join(root, "repo");
  await mkdir(workspace);
  const options = {root,workspace,run:"future"};
  await assert.rejects(dispatch("compile", {...options,spec:{schemaVersion:2,preset:"mass",shards:[{id:"one"}]}}),
    {code:"ERR_GRAPH_SCHEMA"});
  const keys = [];
  for (const mode of ["exact","relative"]) {
    const ctx = {...options,run:mode};
    await dispatch("compile",{...ctx,spec:{schemaVersion:1,policy:{mode},nodes:[{id:"n",kind:"read",prompt:"same"}]}});
    const {execKey} = await dispatch("claim",{...ctx,expectedRev:1,node:"n",opId:"claim"});
    keys.push(execKey);
  }
  assert.notEqual(keys[0],keys[1]);
});

test("GC preserves claimed instructions, blocked evidence and immutable handoff carryover", async t => {
  const base = await mkdtemp(join(tmpdir(), "graph-run-roots-"));
  t.after(() => rm(base, {recursive:true, force:true}));
  const root = join(base,"store"), workspace = join(base,"workspace"), dataDir = join(base,"handoffs-data");
  await mkdir(root); await mkdir(workspace);
  await writeFile(join(workspace,"read-rule"), "read only\n");
  const run = "pinned", cmd = (command, options = {}) => dispatch(command, {root,workspace,run,...options});
  await cmd("compile", {spec:{schemaVersion:1,nodes:["review","blocked","spare"].map(id=>({
    id, kind:"read", estimatedMinutes:5, prompt:id, rules:["read-rule"],
  }))}});
  const claim = id => cmd("claim",{node:id,expectedRev:1,opId:`claim-${id}`});
  const first = await claim("review");
  const orphan = await putBlob(root, Buffer.from("unreachable"));
  const { rules } = JSON.parse(await readFile(first.instructionPath,"utf8"));
  await collectGarbage(root);
  assert.equal((await getBlob(root,rules[0].uri)).toString(),"read only\n");
  await assert.rejects(getBlob(root,orphan), {code:"ERR_JOURNAL_CORRUPT"});
  await cmd("start",{token:first.instructionPath,hostHandle:"worker-1"});
  const { workspaceKey, snapshot } = saveHandoffSnapshot({cwd:workspace,dataDir,input:{verified_facts:["checked"]}});
  await cmd("settle",{token:first.instructionPath,opId:"carry",outcome:"context_rot_abort",
    dataDir,receipt:{sessionId:"worker-1",snapshotId:snapshot.snapshotId,verifiedFacts:["checked"]}});
  const second = await claim("blocked");
  await cmd("start",{token:second.instructionPath,hostHandle:"worker-2"});
  const rejected=await cmd("settle",{token:second.instructionPath,opId:"blocked",outcome:"blocked",receipt:{reason:"need input"}});
  await collectGarbage(root);
  const state=await cmd("status");
  assert.equal(state.nodes.blocked.status,"held_blocked");
  assert.ok((await getBlob(root,rejected.receiptUri)).length>0);
  assert.equal(state.nodes.review.handoffCarryoverUri,`hstack-handoff://${workspaceKey}/${snapshot.snapshotId}`);
  assert.ok(listPinnedSnapshots(workspaceKey,dataDir).some(pin=>pin.snapshotId===snapshot.snapshotId && pin.pinOwners.length));
});
