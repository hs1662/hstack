import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import { hostname } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

const exec = promisify(execFile);
const held = (message, cause) => Object.assign(new Error(message, { cause }), {
  code: "ERR_LOCK_RECOVERY_REQUIRED", status: "held",
});
const stamp = /^(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {0,1}\d{1,2} \d\d:\d\d:\d\d \d{4}$/;

function validStart(value) {
  return typeof value === "string" && (process.platform === "linux" ? /^(?:0|[1-9]\d*)$/.test(value) :
    process.platform === "darwin" && stamp.test(value));
}

async function startTicks(pid) {
  let ticks;
  if (process.platform === "linux") {
    const stat = await readFile(`/proc/${pid}/stat`, "utf8");
    // comm can contain whitespace, newlines and even ')'. Field 3 starts after the final ') '.
    ticks = stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19];
  } else if (process.platform === "darwin") {
    const { stdout } = await exec("/bin/ps", ["-p", String(pid), "-o", "lstart="], {
      env: { LC_ALL: "C", TZ: "UTC0" }, timeout: 2000,
    });
    ticks = stdout.trim().replace(/\s+/g, " ");
  }
  if (!validStart(ticks)) throw held(`Cannot identify process ${pid}`);
  return ticks;
}

async function ownerAt(dir) {
  let file;
  try {
    if (!(await lstat(dir)).isDirectory()) throw held("Lock path is not a directory");
    file = await open(join(dir, "owner.json"), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > 4096) throw held("Invalid owner metadata");
    const owner = JSON.parse(await file.readFile("utf8"));
    if (!owner || typeof owner.host !== "string" || !owner.host || !Number.isSafeInteger(owner.pid) ||
        owner.pid <= 0 || owner.pid > 0x7fffffff || !validStart(owner.startTicks) ||
        typeof owner.lockToken !== "string" || !/^[a-zA-Z0-9_-]{1,128}$/.test(owner.lockToken) ||
        !Number.isSafeInteger(owner.acquiredAtMs) || owner.acquiredAtMs < 0) throw held("Invalid owner metadata");
    return owner;
  } catch (err) {
    if (err.code === "ENOENT") return null; // Between mkdir and publish, or already moved.
    if (err.code === "ERR_LOCK_RECOVERY_REQUIRED") throw err;
    throw held("Cannot read lock owner", err);
  } finally {
    if (file) await file.close();
  }
}

async function confirmedStale(owner) {
  if (owner.host !== hostname()) throw held(`Lock belongs to another host: ${owner.host}`);
  try {
    process.kill(owner.pid, 0);
  } catch (err) {
    if (err.code === "ESRCH") return true;
    throw held("Cannot determine whether owner exists", err);
  }
  try {
    const current = await startTicks(owner.pid);
    return current !== owner.startTicks.replace(/\s+/g, " ");
  } catch (err) {
    // ENOENT in /proc is not proof of death (hidepid, namespace, or a disappearing process).
    throw held("Cannot determine owner process start time", err);
  }
}

async function bury(root, owner) {
  const dir = join(root, "lock");
  const graves = join(root, "graveyard");
  await mkdir(graves, { mode: 0o700, recursive: true });
  if (!(await lstat(graves)).isDirectory()) throw held("Unsafe lock graveyard");
  try {
    // One irreversible ticket for this generation, carried away with the grave.
    // Never remove or steal a ticket, not even when its winner appears dead.
    await mkdir(join(dir, `.recover.${owner.lockToken}`), { mode: 0o700 });
  } catch (err) {
    if (err.code === "ENOENT" || err.code === "EEXIST") return false;
    throw err;
  }
  // A delayed mkdir may have landed in a replacement directory. Its token differs.
  // After this check, no cooperating process can retire this confirmed-dead owner:
  // only this ticket winner may rename it, and a dead owner cannot release.
  if ((await ownerAt(dir))?.lockToken !== owner.lockToken) return false;
  await rename(dir, join(graves, `lock.${owner.lockToken}.${randomUUID()}`));
  return true;
}

/** Run a short metadata operation in an existing initialized state root. Not reentrant. */
export async function withLock(root, fn) {
  const dir = join(root, "lock");
  let ticks;
  try {
    ticks = await startTicks(process.pid);
  } catch (err) {
    throw held("Cannot prove this process's identity", err);
  }
  const lockToken = randomUUID();
  const deadline = performance.now() + 10_000;
  let unpublishedSince;
  for (;;) {
    try {
      await mkdir(dir, { mode: 0o700 });
      break;
    } catch (err) {
      if (err.code !== "EEXIST") throw err;
    }
    const owner = await ownerAt(dir);
    if (!owner) {
      unpublishedSince ??= performance.now();
      if (performance.now() - unpublishedSince >= 300) throw held("Lock owner was not published");
    } else {
      unpublishedSince = undefined;
      if (await confirmedStale(owner)) {
        if (await bury(root, owner)) continue;
        if (performance.now() >= deadline) throw held("Unfinished recovery ticket; inspect lock");
      }
    }
    if (performance.now() >= deadline) {
      throw Object.assign(new Error("Graph lock is busy"), { code: "ERR_LOCK_BUSY", status: "held" });
    }
    await delay(10);
  }

  // A crash during publication intentionally leaves an unidentified, held lock.
  const staging = join(dir, `owner.${lockToken}.tmp`);
  const owner = { host: hostname(), pid: process.pid, startTicks: ticks, lockToken, acquiredAtMs: Date.now() };
  await writeFile(staging, JSON.stringify(owner) + "\n", { mode: 0o600, flag: "wx" });
  await rename(staging, join(dir, "owner.json"));
  try {
    return await fn();
  } finally {
    if ((await ownerAt(dir))?.lockToken !== lockToken) throw held("Lock ownership changed before release");
    // A live owner cannot be recovered. Detach its generation before recursive cleanup;
    // never unlink through a public name that the next acquirer can already reuse.
    const retired = join(root, `.released.${lockToken}`);
    await rename(dir, retired);
    await rm(retired, { recursive: true });
  }
}
