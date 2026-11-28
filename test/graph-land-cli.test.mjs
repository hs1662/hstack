import assert from "node:assert/strict";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { exec, fixture, ref, writer } from "./graph-integrate.test.mjs";

const cli = fileURLToPath(new URL("../scripts/graph/cli.mjs", import.meta.url));

function landCli(f, args, run = "r") {
  return exec(process.execPath, [cli, "land", "--root", f.root, "--run", run, ...args],
    { cwd: f.workspace, timeout: 20_000 });
}

const failsWith = (exit, code) => error => {
  assert.equal(error.code, exit, error.stdout);
  assert.equal(JSON.parse(error.stdout).error.code, code);
  return true;
};

async function published(t, nodes = [writer("B")]) {
  const f = await fixture(t, nodes);
  for (const { id } of nodes) {
    await f.seal(id);
    assert.equal((await f.integrate(`publish-${id}`)).status, "accepted");
  }
  return f;
}

async function checkout(f) {
  const files = (await readdir(f.workspace)).filter(name => name !== ".git").sort();
  return {
    head: await f.git("rev-parse", "HEAD"),
    branch: await f.git("symbolic-ref", "HEAD"),
    index: await readFile(join(f.workspace, ".git/index")),
    files: await Promise.all(files.map(async name => [name, await readFile(join(f.workspace, name))])),
  };
}

test("fast-forward land journals an unchanged run and replays the exact receipt", async t => {
  const f = await published(t);
  const state = await f.call("status");
  const args = ["--op-id", "land-once"];
  const { stdout } = await landCli(f, args);
  assert.equal(await f.git("rev-parse", "HEAD"), await f.git("rev-parse", ref));
  assert.deepEqual(await f.call("status"), state);

  // Fresh land would now fail; replay must bypass checkout preconditions.
  await f.git("config", "user.name", "Changed after landing");
  const beforeReplay = await checkout(f);
  const replay = await landCli(f, args);
  assert.equal(replay.stdout, stdout);
  assert.deepEqual(await checkout(f), beforeReplay);

  const frames = await f.frames();
  const landed = frames.filter(frame => frame.type === "Landed");
  assert.equal(landed.length, 1);
  assert.equal(landed[0].opId, "land-once");
  assert.equal(landed[0].body.stateUri, frames.at(-2).body.stateUri);
  const { response, refs, stateUri, ...receipt } = landed[0].body;
  assert.deepEqual(receipt, JSON.parse(stdout).result);
  assert.deepEqual(response, receipt);
});

test("branch land creates the requested ref without changing the checkout", async t => {
  const f = await published(t);
  const before = await checkout(f);
  const { stdout } = await landCli(f, ["--op-id", "branch", "--mode", "branch", "--branch", "hstack/x"]);
  assert.equal(JSON.parse(stdout).result.targetRef, "refs/heads/hstack/x");
  assert.equal(await f.git("rev-parse", "refs/heads/hstack/x"), await f.git("rev-parse", ref));
  assert.deepEqual(await checkout(f), before);
});

test("patch land resolves --out relative to the caller's cwd", async t => {
  const f = await published(t);
  const before = await checkout(f);
  const { stdout } = await landCli(f, ["--op-id", "patch", "--mode", "patch", "--out", "../result.patch"]);
  assert.equal(JSON.parse(stdout).result.patchPath, join(f.dir, "result.patch"));
  assert.deepEqual(await checkout(f), before);
  await f.git("apply", "--check", "--3way", "../result.patch");
});

test("merge land runs each distinct accepted gate in order and writes nothing if a gate fails", async t => {
  const argv = label => [process.execPath, "-e",
    `const fs = require("node:fs"), label = ${JSON.stringify(label)};
     if (fs.existsSync("local")) {
       fs.appendFileSync("../../../land-gates", label);
       if (label === "2" && fs.readFileSync("local", "utf8") === "red\\n") process.exit(1);
     }`];
  const f = await published(t, [
    writer("A", { gateArgv: argv("1") }), writer("B", { gateArgv: argv("1") }),
    writer("C", { gateArgv: argv("2") }),
  ]);
  const log = join(f.root, "land-gates");
  await writeFile(join(f.workspace, "local"), "red\n");
  await f.git("add", "local");
  await f.git("commit", "-qm", "local change");
  const before = await checkout(f);
  const journal = await readFile(f.wal);
  const args = ["--op-id", "merge", "--mode", "merge"];
  await assert.rejects(landCli(f, args), failsWith(1, "ERR_GATE_FAILED"));
  assert.equal(await readFile(log, "utf8"), "12");
  assert.deepEqual(await checkout(f), before);
  assert.deepEqual(await readFile(f.wal), journal);

  await writeFile(join(f.workspace, "local"), "green\n");
  await f.git("commit", "-qam", "make local change pass the gate");
  const { stdout } = await landCli(f, args);
  const receipt = JSON.parse(stdout).result;
  assert.equal(receipt.verified, true);
  assert.equal(await f.git("rev-parse", "HEAD^{tree}"), receipt.verifiedTree);
  assert.equal(await readFile(log, "utf8"), "1212");
});

test("land rejects invalid --mode and --allow values as CLI usage errors", async t => {
  const f = await fixture(t);
  for (const flag of ["--mode", "--allow"]) {
    await assert.rejects(landCli(f, ["--op-id", "bad", flag, "bogus"]), failsWith(64, "ERR_CLI_FLAG_VALUE"));
  }
});

test("land forwards comma-separated allowances and preserves a nonoverlapping edit", async t => {
  const f = await published(t);
  const file = join(f.workspace, "source");
  await writeFile(file, "my edit\n");
  const args = ["--op-id", "allow-dirty"];
  await assert.rejects(landCli(f, args), failsWith(1, "ERR_LAND_DIRTY"));
  await landCli(f, [...args, "--allow", "partial,dirty-nonoverlap"]);
  assert.equal(await f.git("rev-parse", "HEAD"), await f.git("rev-parse", ref));
  assert.equal(await readFile(file, "utf8"), "my edit\n");
});

test("land refuses a v1 run with exit 69", async t => {
  const f = await fixture(t);
  await f.call("compile", { run: "legacy", spec: { schemaVersion: 1, nodes: [
    { id: "read", kind: "read", prompt: "Read source", readScope: ["source"] },
  ] } });
  await assert.rejects(landCli(f, ["--op-id", "legacy-land"], "legacy"),
    failsWith(69, "ERR_V2_WRITE_INTEGRATION_NOT_ENABLED"));
});

test("land rejects a changed shared config before changing HEAD, index, files or WAL", async t => {
  const f = await published(t);
  await f.git("config", "user.name", "Changed");
  const before = await checkout(f);
  const wal = await readFile(f.wal);
  await assert.rejects(landCli(f, ["--op-id", "tampered"]), failsWith(1, "ERR_REPO_CONFIG_TAMPERED"));
  assert.deepEqual(await checkout(f), before);
  assert.deepEqual(await readFile(f.wal), wal);
});
