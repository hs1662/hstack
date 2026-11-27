import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, stat, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { factDigest } from "../scripts/graph/reducer.mjs";

const cli = fileURLToPath(new URL("../scripts/graph/cli.mjs", import.meta.url));

test("a host verifier can await a sibling's committed claim without holding the graph mutex", { timeout: 24_000 }, async t => {
  const dir = await mkdtemp(join(tmpdir(), "graph-sibling-gate-"));
  const root = join(dir, "state"), workspace = join(dir, "repo");
  await mkdir(workspace);
  const children = new Set();
  t.after(async () => {
    for (const child of children) child.kill("SIGKILL");
    await rm(dir, {recursive: true, force: true});
  });
  async function call(command, flags) {
    const child = spawn(process.execPath, [cli, command, "--root", root, "--workspace", workspace, ...flags],
      { stdio: ["ignore", "pipe", "pipe"], timeout: 15_000, killSignal: "SIGKILL" });
    children.add(child);
    let stdout = "", stderr = "";
    child.stdout.setEncoding("utf8").on("data", data => { stdout += data; });
    child.stderr.setEncoding("utf8").on("data", data => { stderr += data; });
    const rc = await new Promise((resolve, reject) => {
      child.once("error", reject); child.once("close", resolve);
    });
    children.delete(child);
    assert.equal(rc, 0, `${command}: ${stdout} ${stderr}`);
    return JSON.parse(stdout).result;
  }
  const gate = `const fs=require('node:fs'); fs.appendFileSync('started','1'); const t=setInterval(()=>{
    if(fs.existsSync('sibling-claimed')) clearInterval(t);
  },20);`;
  const nodes = ["a", "b", "c"].map(id => ({id, kind: "read", prompt: id, estimatedMinutes: 7,
    ...(id === "a" && {gateArgv: [process.execPath, "-e", gate], timeoutMs: 8000})}));
  const spec = join(dir, "spec.json"), receipt = join(dir, "receipt.json");
  await writeFile(spec, JSON.stringify({schemaVersion: 1, nodes}));
  await writeFile(join(workspace, "source"), "ok\n");
  const p = {evidenceSpans: [{spanId:"s", path:"source", startLine:1, endLine:1}],
    claims:[{claimId:"ok", text:"ok", spanIds:["s"]}], edgeCases:[], failureEvidence:[]};
  p.factDigest = factDigest(p);
  await writeFile(receipt, JSON.stringify({workerReportedStatus:"completed", inlineSummary:"ok", provenance:p}));
  const run = ["--run","sibling"];
  await call("init", []);
  await call("compile", [...run,"--spec",spec]);
  const claim = id => call("claim", [...run,"--node",id,"--op-id",`claim-${id}`,"--expected-rev","1"]);
  const {instructionPath} = await claim("a");
  await call("start", ["--token",instructionPath,"--host-handle","host-a"]);
  const args = ["--token",instructionPath,"--outcome","accepted","--receipt",receipt,"--op-id","settle-a"];
  const pending = call("settle", args);
  pending.catch(() => {}); // observed below, even if the verifier never starts
  try {
    const deadline = Date.now() + 6000;
    while (!await stat(join(workspace,"started")).catch(() => null)) {
      assert.ok(Date.now() < deadline, "configured verifier did not start");
      await delay(20);
    }
    await claim("b");
    await writeFile(join(workspace,"sibling-claimed"), "1");
  } finally {
    const result = await pending;
    assert.equal(result.status, "accepted", "host gate could not observe committed sibling work before timeout");
  }
  assert.equal((await call("settle", args)).status, "accepted");
  assert.equal(await readFile(join(workspace,"started"),"utf8"), "1", "replay reran the external verifier");
});
