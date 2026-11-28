import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { exec, fixture, ref, writer } from "./graph-integrate.test.mjs";

async function interrupt(f, point, target = ref) {
  const script = `
    import fs from "node:fs/promises";
    import cp from "node:child_process";
    import { PassThrough } from "node:stream";
    import { createInterface } from "node:readline";
    import { syncBuiltinESMExports } from "node:module";
    const point = ${JSON.stringify(point)}, die = () => process.kill(process.pid, "SIGKILL");
    const open = fs.open;
    fs.open = async (...args) => {
      const fd = await open(...args);
      if (args[0] === ${JSON.stringify(f.wal)} && args[1] === "a") {
        const write = fd.writeFile.bind(fd), sync = fd.sync.bind(fd);
        let frame;
        fd.writeFile = async bytes => {
          frame = JSON.parse(bytes);
          if (point === "EIO" && frame.type === "Published") throw Object.assign(new Error("fault"), {code:"EIO"});
          return write(bytes);
        };
        fd.sync = async () => { await sync(); if (point === frame.type) die(); };
      }
      return fd;
    };
    const execFile = cp.execFile;
    cp.execFile = (cmd, argv, opts, cb) => {
      if (cmd === "git" && argv.includes("update-ref") && argv.includes(${JSON.stringify(target)})) {
        if (point === "CAS") return execFile(cmd, argv, opts, (err, ...rest) => err ? cb(err,...rest) : die());
        if (point === "prepare") {
          const i = argv.indexOf("update-ref");
          const git = cp.spawn(cmd, [...argv.slice(0,i), "update-ref", "--stdin"], opts);
          const lines = createInterface({input:git.stdout});
          lines.on("line", line => { if (line === "prepare: ok") git.kill("SIGKILL"); });
          git.once("exit", (code, signal) => { if (signal === "SIGKILL") die(); else process.exitCode = 31; });
          git.stdin.write("start\\nupdate " + argv.slice(-3).join(" ") + "\\nprepare\\n");
          return {stdin:new PassThrough()};
        }
      }
      return execFile(cmd, argv, opts, cb);
    };
    syncBuiltinESMExports();
    const { dispatch } = await import(${JSON.stringify(new URL("../scripts/graph/state-machine.mjs", import.meta.url).href)});
    try { await dispatch("integrate", {...${JSON.stringify(f.options)}, opId:"publish"}); }
    catch (err) { if (point === "EIO" && err.code === "ERR_IO_UNCERTAIN") process.exitCode = 77; else throw err; }`;
  await assert.rejects(exec(process.execPath, ["--input-type=module", "-e", script], { timeout: 30000 }),
    e => { assert.equal(point === "EIO" ? e.code : e.signal, point === "EIO" ? 77 : "SIGKILL", e.stderr); return true; });
}

test("O-P-4: an abandoned verifier permits only WAL-selected seal and candidate pin locks", async t => {
  const f = await fixture(t, [writer("B"), writer("C")]);
  await f.seal("B");
  await f.start("C");
  const next = "refs/hstack/cand/r/g0.1", gitDir = join(f.workspace, ".git");
  const pin = (await f.call("status")).nodes.B.attempt.pinRef;
  const hash = (await import("node:crypto")).createHash("sha256").update("C").digest("hex");
  const running = join(gitDir, "refs/hstack/pin/r", hash, "e1.lock");
  const unrelated = [join(gitDir, pin + ".lock"), join(gitDir, "refs/hstack/cand/r/g0.2.lock")];
  await interrupt(f, "prepare", next);
  assert.equal(existsSync(join(gitDir, next + ".lock")), true);
  await mkdir(dirname(running), { recursive: true });
  for (const path of [running, ...unrelated]) await writeFile(path, "probe");
  await f.call("resume");
  assert.equal(existsSync(running), false);
  assert.equal(existsSync(join(gitDir, next + ".lock")), false);
  for (const path of unrelated) assert.equal(await readFile(path, "utf8"), "probe");
  assert.equal((await f.integrate("publish")).status, "accepted");
});

for (const [id, point] of [["O-P-1", "GateMeasured"], ["O-P-2", "PublishIntended"], ["O-P-3", "CAS"], ["O-P-4", "prepare"]]) {
  test(`${id}: recover exactly one promotion after ${point}`, async t => {
    const f = await fixture(t);
    await f.seal("B");
    const acceptedLock = join(f.workspace, ".git", ref + ".lock");
    const retained = ["packed-refs.lock", "refs/heads/main.lock", "refs/hstack/unrelated.lock"].map(p => join(f.workspace, ".git", p));
    await interrupt(f, point);
    const before = await f.frames();
    assert.equal(before.at(-1).type, point === "GateMeasured" ? point : "PublishIntended");
    const beforeOid = await f.git("for-each-ref", "--format=%(objectname)", ref);
    assert.equal(Boolean(beforeOid), point === "CAS");
    if (point === "prepare") {
      assert.equal(existsSync(acceptedLock), true);
      for (const path of retained) await writeFile(path, "retain");
    }
    if (point !== "GateMeasured") await f.call("resume");
    const r = await f.integrate("publish"), frames = await f.frames();
    assert.equal(r.status, "accepted");
    assert.equal(await f.git("rev-parse", ref), r.acceptedTip);
    assert.equal(frames.filter(frame => frame.type === "GateMeasured").length, 1);
    assert.equal(frames.filter(frame => frame.type === "Published").length, 1);
    assert.equal((await f.git("reflog", "show", "--format=%H", ref)).split("\n").length, 1);
    if (point === "prepare") {
      assert.equal(existsSync(acceptedLock), false);
      for (const path of retained) assert.equal(await readFile(path, "utf8"), "retain");
    }
  });
}

test("O-P-5: pending publication recovery preserves a third-party value", async t => {
  const f = await fixture(t), c = await f.seal("B");
  await interrupt(f, "PublishIntended");
  await f.git("update-ref", ref, c.baseSha);
  const s = await f.call("resume");
  assert.deepEqual([s.nodes.B.status, s.nodes.B.heldReason, s.pendingPublish],
    ["held_integration", "ERR_INTEGRATION_DIVERGED", null]);
  assert.equal(await f.git("rev-parse", ref), c.baseSha);
});

test("O-P-4 control: an accepted.lock without an abandoned writer remains busy", async t => {
  const f = await fixture(t);
  await f.seal("B");
  const lock = join(f.workspace, ".git", ref + ".lock");
  await mkdir(dirname(lock), { recursive: true });
  await writeFile(lock, "live");
  await assert.rejects(f.integrate("publish"), { code: "ERR_LOCK_BUSY" });
  assert.equal(await readFile(lock, "utf8"), "live");
});

test("O-P-7: EIO appending Published poisons all further run commands", async t => {
  const f = await fixture(t);
  await f.seal("B");
  await interrupt(f, "EIO");
  assert.equal(existsSync(join(f.root, ".io-uncertain.r")), true);
  for (const command of ["status", "resume", "integrate", "ready", "claim"]) {
    await assert.rejects(f.call(command, { opId: "another" }), { code: "ERR_IO_UNCERTAIN" });
  }
});
