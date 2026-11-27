import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { measureGate } from "../scripts/graph/verify-gate.mjs";

const hash = text => createHash("sha256").update(text).digest("hex");
const inputs = { cwd: process.cwd(), subjectDigest: hash("subject"), env: { CHECK: "checked" } };

test("host gate records the actual argv, environment and both streams even on failure", async () => {
  const argv = [process.execPath, "-e", "process.stdout.write(process.env.CHECK);process.stderr.write(process.argv[1]);process.exitCode=3", "literal;$HOME"];
  const measured = await measureGate({ ...inputs, argv });
  assert.deepEqual(measured.argv, argv);
  assert.equal(measured.exit, 3);
  assert.equal(measured.signal, null);
  assert.equal(measured.stdoutDigest, hash("checked"));
  assert.equal(measured.stderrDigest, hash("literal;$HOME"));
  assert.equal(measured.subjectDigest, inputs.subjectDigest);
  const changed = await measureGate({ ...inputs, argv, env: { CHECK: "different" } });
  assert.notEqual(measured.envDigest, changed.envDigest);
  assert.ok(!JSON.stringify(changed).includes("different"));
});

test("a missing executable or hard timeout never produces a passing verifier receipt", async () => {
  await assert.rejects(measureGate({ ...inputs, argv: ["/no-such-hstack-executable"] }), { code: "ERR_GATE_SPAWN" });
  const result = await measureGate({ ...inputs, argv: [process.execPath, "-e", "setInterval(()=>{},500)"], timeoutMs: 100 });
  assert.equal(result.timedOut, true);
  assert.equal(result.signal, "SIGKILL");
  assert.equal(result.exit, null);
});
