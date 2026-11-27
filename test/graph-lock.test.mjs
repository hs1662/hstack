import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  access, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, writeFile,
} from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const guard = () => import("../scripts/graph/fs-guard.mjs");
const lockModule = new URL("../scripts/graph/lock.mjs", import.meta.url).href;
const lock = () => import(lockModule);
const recovery = { code: "ERR_LOCK_RECOVERY_REQUIRED", status: "held" };

async function sandbox(t) {
  const dir = await mkdtemp(join(tmpdir(), "graph-lock-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return realpath(dir);
}

test("init rejects an unverified repository or state mount before creating state", async (t) => {
  const dir = await sandbox(t);
  const repo = join(dir, "repo");
  await mkdir(repo);
  const root = join(dir, "missing", "graph");
  const { initializeRoot } = await guard();
  for (const [bad, type] of [[repo, "9p"], [dir, "nfs"], [dir, "unrecognized"]]) {
    const probeFs = (path) => path === bad ? type : "ext4";
    await assert.rejects(initializeRoot(root, repo, { probeFs }), { code: "ERR_UNSUPPORTED_FS" });
    await assert.rejects(access(join(dir, "missing")), { code: "ENOENT" });
  }
});

test("guard rejects WSL, network and cloud paths including missing children through aliases", async (t) => {
  const dir = await sandbox(t);
  await mkdir(join(dir, "Dropbox"));
  await symlink(join(dir, "Dropbox"), join(dir, "alias"));
  const { assertLocalFs } = await guard();
  for (const path of ["/mnt/c/Projects", "//server/share", join(dir, "alias", "new"),
    join(dir, "Library", "Mobile Documents", "repo"), join(dir, "OneDrive - Work", "repo")]) {
    await assert.rejects(assertLocalFs(path), { code: "ERR_UNSUPPORTED_FS" });
  }
  if (process.platform === "linux") {
    await assert.rejects(assertLocalFs("/proc"), { code: "ERR_UNSUPPORTED_FS" });
  }
});

test("fallback preserves existing exclude bytes and registers once, without a tracked ignore", async (t) => {
  const repo = await sandbox(t);
  const info = join(repo, ".git", "info");
  await mkdir(info, { recursive: true });
  const exclude = join(info, "exclude");
  await writeFile(exclude, "keep-me");
  const { initializeRoot } = await guard();
  const root = join(repo, ".hstack", "graph");
  await Promise.all(Array.from({ length: 4 }, () => initializeRoot(root, repo)));
  assert.equal(await readFile(exclude, "utf8"), "keep-me\n/.hstack/graph/\n");
  assert.equal((await lstat(root)).mode & 0o777, 0o700);
  await assert.rejects(access(join(repo, ".gitignore")), { code: "ENOENT" });
});

test("fallback refuses redirected metadata or state before allocating the graph", async (t) => {
  const dir = await sandbox(t);
  const { initializeRoot } = await guard();
  for (const part of ["exclude", "info", ".git", ".hstack"]) {
    const repo = join(dir, `repo-${part}`);
    const dest = join(dir, `target-${part}`);
    const info = join(repo, ".git", "info");
    await mkdir(info, { recursive: true });
    const src = part === "exclude" ? join(info, part) : part === "info" ? info : join(repo, part);
    await rm(src, { recursive: true, force: true });
    if (part === "exclude") await writeFile(dest, "not yours");
    else await mkdir(dest);
    await symlink(dest, src);
    const root = join(repo, ".hstack", "graph");
    await assert.rejects(initializeRoot(root, repo));
    await assert.rejects(access(root), { code: "ENOENT" });
    if (part === "exclude") assert.equal(await readFile(dest, "utf8"), "not yours");
    else assert.deepEqual(await readdir(dest), []);
  }
});

test("callback sees a private, identified lock and exceptions release it", async (t) => {
  const root = await sandbox(t);
  const { withLock } = await lock();
  const dir = join(root, "lock");
  const fault = new Error("callback failed");
  await assert.rejects(withLock(root, async () => {
    assert.equal((await lstat(dir)).mode & 0o777, 0o700);
    const owner = JSON.parse(await readFile(join(dir, "owner.json"), "utf8"));
    assert.equal(owner.pid, process.pid);
    assert.equal(owner.host, hostname());
    assert.ok(Number.isSafeInteger(owner.acquiredAtMs));
    assert.ok(owner.lockToken && owner.startTicks);
    if (process.platform === "linux") {
      const stat = await readFile("/proc/self/stat", "utf8");
      assert.equal(String(owner.startTicks), stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19]);
    }
    throw fault;
  }), (err) => err === fault);
  assert.equal(await withLock(root, () => 42), 42);
});

function fixtureOwner() {
  return { host: hostname(), pid: process.pid, lockToken: "old-owner", acquiredAtMs: 1,
    startTicks: process.platform === "darwin" ? "Mon Jan 01 00:00:00 1990" : "1" };
}

test("unknown, malformed and foreign generations stay held, even if very old", async (t) => {
  const root = await sandbox(t);
  const { withLock } = await lock();
  const dir = join(root, "lock");
  await mkdir(dir);
  const file = join(dir, "owner.json");
  const owner = fixtureOwner();
  for (const bytes of [null, "{", JSON.stringify({ ...owner, host: "somewhere-else" }),
    JSON.stringify({ ...owner, startTicks: "unknown" }), JSON.stringify({ ...owner, lockToken: "../escape" })]) {
    if (bytes !== null) await writeFile(file, bytes);
    await assert.rejects(withLock(root, () => assert.fail("must not enter")), recovery);
    if (bytes !== null) assert.equal(await readFile(file, "utf8"), bytes);
  }
});

test("release never removes a replacement owner", async (t) => {
  const root = await sandbox(t);
  const { withLock } = await lock();
  const dir = join(root, "lock");
  const bytes = JSON.stringify(fixtureOwner());
  await assert.rejects(withLock(root, async () => {
    await rename(dir, join(root, "saved"));
    await mkdir(dir);
    await writeFile(join(dir, "owner.json"), bytes);
  }), recovery);
  assert.equal(await readFile(join(dir, "owner.json"), "utf8"), bytes);
});

// Each child waits at an IPC barrier *after* loading the module. The exclusive
// sentinel and the shared increment expose overlap independently of the lock.
function worker(t, root, body) {
  const source = `
    import { once } from "node:events";
    import { mkdir, rmdir, readFile, writeFile } from "node:fs/promises";
    import { withLock } from ${JSON.stringify(lockModule)};
    const root = process.argv[1];
    const start = once(process, "message"); process.send("ready"); await start;
    await withLock(root, async () => { ${body} });
    process.disconnect();
  `;
  const child = spawn(process.execPath, ["--input-type=module", "-e", source, root],
    { stdio: ["ignore", "ignore", "inherit", "ipc"], timeout: 15_000, killSignal: "SIGKILL" });
  t.after(() => { if (child.exitCode === null && !child.signalCode) child.kill("SIGKILL"); });
  return { child, ready: once(child, "message"), exit: once(child, "exit") };
}

for (const cause of ["SIGKILL", "reused PID"]) {
  test(`real contenders serialize and bury exactly one ${cause} generation`, { timeout: 25_000 }, async (t) => {
    const root = await sandbox(t);
    await lock();
    const dir = join(root, "lock");
    if (cause === "SIGKILL") {
      const holder = worker(t, root, `process.send("entered"); await once(process, "message");`);
      await holder.ready;
      const entered = once(holder.child, "message");
      holder.child.send("go");
      assert.deepEqual(await entered, ["entered", undefined]);
      holder.child.kill("SIGKILL");
      assert.deepEqual(await holder.exit, [null, "SIGKILL"]);
    } else {
      await mkdir(dir);
      await writeFile(join(dir, "owner.json"), JSON.stringify(fixtureOwner()));
    }
    const stale = await readFile(join(dir, "owner.json"), "utf8");
    await writeFile(join(root, "count"), "0");
    const workers = Array.from({ length: 6 }, () => worker(t, root, `
      await mkdir(root + "/critical");
      const n = Number(await readFile(root + "/count"));
      await writeFile(root + "/count", String(n + 1));
      await rmdir(root + "/critical");
    `));
    await Promise.all(workers.map(w => w.ready));
    workers.forEach(w => w.child.send("go"));
    for (const result of await Promise.all(workers.map(w => w.exit))) assert.deepEqual(result, [0, null]);
    const graves = await readdir(join(root, "graveyard"));
    assert.equal(graves.length, 1);
    assert.ok(graves[0].startsWith(`lock.${JSON.parse(stale).lockToken}.`));
    assert.equal(await readFile(join(root, "graveyard", graves[0], "owner.json"), "utf8"), stale);
    assert.equal(await readFile(join(root, "count"), "utf8"), "6");
  });
}

test("a suspended reaper cannot retire the generation that replaced its observation", { timeout: 15_000 }, async (t) => {
  const root = await sandbox(t);
  const { withLock } = await lock();
  const dir = join(root, "lock");
  await mkdir(dir);
  await writeFile(join(dir, "owner.json"), JSON.stringify(fixtureOwner()));
  // Freeze the child *after* its liveness verdict, at its first recovery write.
  // Fault injection stays in this process; production has no scheduler hooks.
  const source = `
    import fs from "node:fs/promises";
    import { once } from "node:events";
    import { syncBuiltinESMExports } from "node:module";
    let paused = false;
    for (const name of ["mkdir", "rename"]) {
      const actual = fs[name];
      fs[name] = async (...args) => {
        if (!paused && (args[0] !== process.argv[1] + "/lock" || name === "rename")) {
          paused = true;
          const resume = once(process, "message"); process.send("paused"); await resume;
        }
        return actual(...args);
      };
    }
    syncBuiltinESMExports();
    const { withLock } = await import(${JSON.stringify(lockModule)});
    try { await withLock(process.argv[1], () => { throw new Error("entered"); }); }
    catch (e) { process.send(e.code ?? e.message); }
    process.disconnect();
  `;
  const child = spawn(process.execPath, ["--input-type=module", "-e", source, root],
    { stdio: ["ignore", "ignore", "inherit", "ipc"], timeout: 12_000, killSignal: "SIGKILL" });
  t.after(() => { if (child.exitCode === null && !child.signalCode) child.kill("SIGKILL"); });
  assert.equal((await once(child, "message"))[0], "paused");
  // Let a different process finish recovery, then install an unverifiable successor.
  await withLock(root, () => {});
  await mkdir(dir);
  const bytes = JSON.stringify({ ...fixtureOwner(), host: "foreign", lockToken: "replacement" });
  await writeFile(join(dir, "owner.json"), bytes);
  const result = once(child, "message");
  child.send("continue");
  assert.equal((await result)[0], recovery.code);
  assert.equal(await readFile(join(dir, "owner.json"), "utf8"), bytes);
  assert.equal((await readdir(join(root, "graveyard"))).length, 1);
});
