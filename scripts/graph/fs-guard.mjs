import { execFile } from "node:child_process";
import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, realpath, rename, unlink } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

const exec = promisify(execFile);
const localTypes = new Set(["ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "tmpfs", "apfs", "hfs"]);
const cloud = /^(?:Dropbox|OneDrive|Google Drive|GoogleDrive|iCloud Drive|iCloudDrive|Mobile Documents|CloudStorage|Box|Nextcloud|ownCloud)(?:$|[ (-])/i;
const unsupported = (message, cause) => Object.assign(new Error(message, { cause }), { code: "ERR_UNSUPPORTED_FS" });

function checkName(path) {
  if (/^(?:\/\/|\\\\|[A-Za-z]:[\\/])/.test(path) || /^\/mnt\/[a-z](?:\/|$)/i.test(path) ||
      path.split("/").some(name => cloud.test(name))) {
    throw unsupported(`Graph state requires a local, unsynchronized filesystem: ${path}`);
  }
}

async function entry(path) {
  try {
    return await lstat(path);
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw err;
  }
}

const unescapeMount = value => value.replace(/\\([0-7]{3})/g, (_, n) => String.fromCharCode(parseInt(n, 8)));

async function probeLocalType(path) {
  if (process.platform === "darwin") {
    // Darwin's df filters the statfs result for this specific path (-T),
    // returning nonzero on a mismatch. Do not parse human-readable columns.
    for (const type of ["apfs", "hfs"]) {
      try {
        await exec("/bin/df", ["-T", type, path], { timeout: 3000 });
        return type;
      } catch (err) {
        if (err.code !== 1) throw err;
      }
    }
    throw unsupported(`Unsupported filesystem at ${path}`);
  }
  if (process.platform !== "linux") throw unsupported("Unsupported POSIX filesystem probe");
  const mounts = await readFile("/proc/self/mountinfo", "utf8");
  let best = -1;
  let match;
  for (const line of mounts.trimEnd().split("\n")) {
    const [fields, fs] = line.split(" - ");
    const [, , , rawRoot, rawMount] = fields.split(" ");
    const mount = unescapeMount(rawMount);
    if (mount !== "/" && path !== mount && !path.startsWith(`${mount}/`)) continue;
    if (mount.length < best) continue;
    // Ambiguous stacked mounts: never guess which one backs the path.
    match = mount.length === best ? undefined : { type: fs.split(" ")[0], root: unescapeMount(rawRoot), mount };
    best = mount.length;
  }
  if (!match) throw unsupported(`Cannot identify mount for ${path}`);
  checkName(join(match.root, path.slice(match.mount.length)));
  return match.type;
}

/** Validate a directory (including a not-yet-created suffix); return its canonical path. */
export async function assertLocalFs(path, { probeFs = probeLocalType } = {}) {
  if (typeof path !== "string" || !path || path.includes("\0")) throw unsupported("Expected a directory path");
  checkName(path);
  const absolute = resolve(path);
  checkName(absolute);
  try {
    let existing = absolute;
    while (!(await entry(existing))) existing = dirname(existing);
    const ancestor = await realpath(existing); // dangling symlinks are not missing directories
    if (!(await lstat(ancestor)).isDirectory()) throw unsupported(`Not a directory: ${existing}`);
    const canonical = resolve(ancestor, ...absolute.slice(existing.length).split("/").filter(Boolean));
    checkName(canonical);
    const type = await probeFs(ancestor);
    if (!localTypes.has(type)) {
      throw unsupported(`Unsupported filesystem ${String(type)} at ${ancestor}`);
    }
    return canonical;
  } catch (err) {
    if (err.code === "ERR_UNSUPPORTED_FS") throw err;
    throw unsupported(`Cannot verify local filesystem for ${path}`, err);
  }
}

async function registerFallback(repo, options) {
  const git = join(repo, ".git");
  const info = join(git, "info");
  if (!(await entry(git))?.isDirectory()) throw unsupported("Fallback requires a local .git directory");
  if (await assertLocalFs(info, options) !== info) throw unsupported("Refusing redirected .git/info");
  await mkdir(info, { recursive: true, mode: 0o700 });
  const exclude = join(info, "exclude");
  const ticket = `${exclude}.lock`;
  let handle;
  for (let i = 0; !handle; ++i) {
    try {
      handle = await open(ticket, "wx", 0o600);
    } catch (err) {
      if (err.code !== "EEXIST") throw err;
      if (i >= 100) throw unsupported("Git info/exclude is locked", err);
      await delay(10);
    }
  }
  let published = false;
  try {
    let old = Buffer.alloc(0);
    const stat = await entry(exclude);
    if (stat) {
      if (!stat.isFile() || stat.nlink !== 1) throw unsupported("Unsafe .git/info/exclude");
      const source = await open(exclude, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      try {
        old = await source.readFile();
      } finally {
        await source.close();
      }
      await handle.chmod(stat.mode & 0o777);
    }
    const rule = "/.hstack/graph/";
    if (old.toString("utf8").split(/\r?\n/).includes(rule)) return;
    await handle.writeFile(Buffer.concat([old, Buffer.from(`${old.length && old.at(-1) !== 10 ? "\n" : ""}${rule}\n`)]));
    await handle.sync();
    await rename(ticket, exclude);
    published = true;
  } finally {
    await handle.close();
    if (!published) await unlink(ticket);
  }
}

/** Validate both inputs before side effects; only the exact repo fallback edits Git metadata. */
export async function initializeRoot(root, repo, options) {
  const repository = await assertLocalFs(repo, options);
  if (!(await entry(repository))?.isDirectory()) throw unsupported("Repository directory does not exist");
  const state = await assertLocalFs(root, options);
  if (resolve(root) === join(resolve(repo), ".hstack", "graph") ||
      state === join(repository, ".hstack", "graph")) {
    if (state !== join(repository, ".hstack", "graph")) throw unsupported("Refusing redirected .hstack/graph");
    await registerFallback(repository, options);
  }
  await mkdir(state, { recursive: true, mode: 0o700 });
  return state;
}
