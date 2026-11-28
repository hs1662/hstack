// The only git spawn of the graph engine (SSOT 4.2): execFile without a shell, byte output, a timeout,
// a fixed environment and fixed config. Engine paths (seal, integrate, provision, gc) also drop the
// user's global config; land keeps it and is guarded by the shared repository config digest instead.
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readdir, readFile, readlink } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { canonical } from "./fingerprint.mjs";
import { graphError } from "./schema.mjs";

export const GIT_FIXED_ARGS = Object.freeze([
  "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.quotePath=false",
  "-c", "core.fsync=committed", "-c", "gc.auto=0", "-c", "maintenance.auto=false",
]);
const FIXED_ENV = Object.freeze({ GIT_OPTIONAL_LOCKS: "0", GIT_TERMINAL_PROMPT: "0", GIT_CONFIG_NOSYSTEM: "1", LC_ALL: "C" });
// A landing commit is the user's own; their identity and global config location stay theirs.
const USER_KEPT = new Set(["GIT_CONFIG_GLOBAL", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"]);
const IDENTITY = { name: "hstack-graph", email: "hstack-graph@invalid" };
const sha256 = bytes => createHash("sha256").update(bytes).digest("hex");
const decoder = new TextDecoder("utf-8", { fatal: true });

const failure = (message, extra) => Object.assign(graphError("ERR_GIT_FAILED", message), extra);

// Inherited GIT_* variables (GIT_DIR, GIT_INDEX_FILE, GIT_CONFIG_PARAMETERS, ...) never leak into a call.
export function gitEnv(scope = "engine", extra = {}) {
  if (scope !== "engine" && scope !== "user") throw failure(`Unknown git scope: ${scope}`);
  const env = Object.fromEntries(Object.entries(process.env)
    .filter(([key]) => !key.startsWith("GIT_") || (scope === "user" && USER_KEPT.has(key))));
  Object.assign(env, FIXED_ENV, scope === "engine" ? { GIT_CONFIG_GLOBAL: "/dev/null" } : {});
  return { ...env, ...extra };
}

/** Resolves { code, stdout, stderr } for any exit status; rejects ERR_GIT_FAILED on spawn error, signal or timeout. */
export function git(args, { cwd, scope = "engine", env = {}, input, timeoutMs = 120_000, maxBuffer = 256 * 1024 * 1024 } = {}) {
  if (typeof cwd !== "string" || !isAbsolute(cwd)) throw failure("git needs an absolute cwd");
  if (!Array.isArray(args) || !args.length || args.some(arg => typeof arg !== "string" || arg.includes("\0"))) {
    throw failure("git needs string arguments without NUL");
  }
  return new Promise((resolve, reject) => {
    const child = execFile("git", [...GIT_FIXED_ARGS, ...args], { cwd, env: gitEnv(scope, env), encoding: "buffer",
      maxBuffer, timeout: timeoutMs, killSignal: "SIGKILL", shell: false, windowsHide: true }, (error, stdout, stderr) => {
      if (!error) resolve({ code: 0, stdout, stderr });
      else if (typeof error.code === "number") resolve({ code: error.code, stdout, stderr });
      else {
        const reason = error.killed ? `timed out after ${timeoutMs} ms` : error.signal ?? error.code ?? error.message;
        reject(failure(`git ${args[0]} failed: ${reason}`, { args, stderr: String(stderr ?? ""), cause: error }));
      }
    });
    // A command that exits before reading its input closes the pipe; its exit status decides.
    child.stdin.on("error", error => { if (error.code !== "EPIPE") reject(failure(`git ${args[0]} stdin: ${error.code}`, { cause: error })); });
    child.stdin.end(input);
  });
}

/** Stdout bytes of a zero exit; any other exit is ERR_GIT_FAILED with exitCode and stderr. */
export async function gitOk(args, options) {
  const result = await git(args, options);
  if (result.code !== 0) {
    const stderr = result.stderr.toString("utf8");
    throw failure(`git ${args[0]} exited ${result.code}: ${stderr.trim().slice(0, 500)}`, { args, exitCode: result.code, stderr });
  }
  return result.stdout;
}

const line = async (args, options) => (await gitOk(args, options)).toString("utf8").trim();

export async function revParse(cwd, ref, options = {}) {
  const result = await git(["rev-parse", "--verify", "-q", ref], { ...options, cwd });
  if (result.code === 0) return result.stdout.toString("utf8").trim();
  if (result.code === 1) return null;
  throw failure(`git rev-parse exited ${result.code}`, { exitCode: result.code, stderr: result.stderr.toString("utf8") });
}

export async function hasObject(cwd, spec, options = {}) {
  return (await git(["cat-file", "-e", spec], { ...options, cwd })).code === 0;
}

export async function isAncestor(cwd, ancestor, descendant, options = {}) {
  const result = await git(["merge-base", "--is-ancestor", ancestor, descendant], { ...options, cwd });
  if (result.code === 0) return true;
  if (result.code === 1) return false;
  throw failure(`git merge-base --is-ancestor exited ${result.code}`, { exitCode: result.code, stderr: result.stderr.toString("utf8") });
}

export const commonDir = (cwd, options = {}) => line(["rev-parse", "--path-format=absolute", "--git-common-dir"], { ...options, cwd });
export const gitDir = (cwd, options = {}) => line(["rev-parse", "--path-format=absolute", "--git-dir"], { ...options, cwd });
export const objectFormat = (cwd, options = {}) => line(["rev-parse", "--show-object-format"], { ...options, cwd });
export const zeroOid = (format = "sha1") => "0".repeat(format === "sha256" ? 64 : 40);

/** A commit whose bytes depend only on its inputs: fixed identity, UTC second, no signature. `env` may add
 * variables such as a private GIT_INDEX_FILE, never override the identity or date. */
export async function commitTree(cwd, { tree, parents, dateSec, message, scope = "engine", env: extra = {} }) {
  if (!Number.isSafeInteger(dateSec) || dateSec < 0) throw failure("commit date must be a nonnegative safe integer");
  if (typeof message !== "string" || !message || message.includes("\0")) throw failure("commit message must be nonempty without NUL");
  const date = `@${dateSec} +0000`;
  const env = { ...extra, GIT_AUTHOR_NAME: IDENTITY.name, GIT_AUTHOR_EMAIL: IDENTITY.email, GIT_AUTHOR_DATE: date,
    GIT_COMMITTER_NAME: IDENTITY.name, GIT_COMMITTER_EMAIL: IDENTITY.email, GIT_COMMITTER_DATE: date };
  return line(["commit-tree", "--no-gpg-sign", tree, ...parents.flatMap(parent => ["-p", parent]), "-m", message],
    { cwd, scope, env });
}

/** Sum of blob sizes in a tree: the checkout-size estimate for worktree disk capacity. */
export async function treeBytes(cwd, treeish, options = {}) {
  let total = 0;
  for (const entry of splitZ(await gitOk(["ls-tree", "-r", "-l", "-z", treeish], { ...options, cwd }))) {
    const size = entry.slice(0, entry.indexOf("\t")).trim().split(/\s+/)[3];
    if (/^\d+$/.test(size)) total += Number(size); // gitlinks report "-"
  }
  return total;
}

/** NUL-separated git output as strings; a trailing terminator yields no empty item. */
export function splitZ(buffer) {
  let text;
  try { text = decoder.decode(buffer); } catch (cause) {
    if (cause instanceof TypeError) throw failure("git output is not valid UTF-8", { cause });
    throw cause;
  }
  const parts = text.split("\0");
  if (parts.at(-1) === "") parts.pop();
  return parts;
}

async function fileDigest(path) {
  let stat;
  try { stat = await lstat(path); } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  if (stat.isSymbolicLink()) return `symlink:${await readlink(path)}`;
  if (!stat.isFile()) return `type:${stat.mode & 0o170000}`;
  return sha256(await readFile(path));
}

/** sha256(canonical({config, attributes, exclude, hooks})) of $GIT_COMMON_DIR, the same from every worktree. */
export async function repoConfigDigest(cwd, options = {}) {
  const dir = await commonDir(cwd, options);
  let names = [];
  try { names = (await readdir(join(dir, "hooks"))).sort(); } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const hooks = [];
  for (const name of names) hooks.push([name, await fileDigest(join(dir, "hooks", name))]);
  return sha256(canonical({
    config: await fileDigest(join(dir, "config")),
    attributes: await fileDigest(join(dir, "info", "attributes")),
    exclude: await fileDigest(join(dir, "info", "exclude")),
    hooks,
  }));
}
