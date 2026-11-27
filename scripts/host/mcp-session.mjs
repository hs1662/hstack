import { createHash, randomBytes } from "node:crypto";
import {
  closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readFileSync,
  readdirSync, unlinkSync, writeFileSync,
} from "node:fs";
import { isAbsolute, join } from "node:path";
import { resolvePluginDataDir } from "../hook-io.mjs";

const TTL_MS = 120_000;
const tools = new Set(["verify_completion", "manage_handoff"]);
const digest = token => createHash("sha256").update(token).digest("hex");
const fresh = mtimeMs => Math.abs(Date.now() - mtimeMs) < TTL_MS;
const owned = stat => !process.getuid || stat.uid === process.getuid();

function validSession(s) {
  return typeof s?.conversationId === "string" && s.conversationId.trim().length > 0 &&
    typeof s.cwd === "string" && isAbsolute(s.cwd) &&
    typeof s.transcriptPath === "string" && isAbsolute(s.transcriptPath);
}

function storeDir(dataDir, create) {
  if (!isAbsolute(dataDir)) throw new Error("Expected absolute plugin data directory");
  if (create) mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const root = lstatSync(dataDir);
  if (!root.isDirectory() || !owned(root) || (root.mode & 0o022)) throw new Error("Unsafe plugin data directory");
  const dir = join(dataDir, "mcp-context");
  if (create) mkdirSync(dir, { recursive: true, mode: 0o700 });
  const stat = lstatSync(dir);
  if (!stat.isDirectory() || !owned(stat) || (stat.mode & 0o077)) throw new Error("Unsafe context directory");
  return dir;
}

// The hook is the only issuer. Even a directory listing does not reveal a redeemable reference.
export function issueMcpContext(toolName, session, dataDir = resolvePluginDataDir()) {
  try {
    if (!tools.has(toolName) || !validSession(session)) throw new Error("Invalid hook session");
    const dir = storeDir(dataDir, true);
    let live = 0;
    for (const name of readdirSync(dir)) {
      if (!/^[a-f0-9]{64}$/.test(name)) continue;
      const path = join(dir, name);
      try {
        if (fresh(lstatSync(path).mtimeMs)) live++;
        else unlinkSync(path);
      } catch (err) {
        if (err.code !== "ENOENT") throw err; // Concurrent redemption or sweep is fine.
      }
    }
    if (live >= 1024) throw new Error("Context store full");
    const token = randomBytes(32).toString("hex");
    const { conversationId, cwd, transcriptPath } = session;
    writeFileSync(join(dir, digest(token)), JSON.stringify({ toolName, conversationId, cwd, transcriptPath }),
      { flag: "wx", mode: 0o600 });
    return token;
  } catch {
    // System error messages include file paths; never pass transport material to a hook log.
    throw new Error("Unable to issue Claude MCP context");
  }
}

export function consumeMcpContext(toolName, token, dataDir = resolvePluginDataDir()) {
  if (!tools.has(toolName) || typeof token !== "string" || !/^[a-f0-9]{64}$/.test(token)) return null;
  try {
    const path = join(storeDir(dataDir, false), digest(token));
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      // Several processes can open the inode, but only the winner of unlink may read it.
      unlinkSync(path);
      const stat = fstatSync(fd);
      if (!stat.isFile() || !owned(stat) || (stat.mode & 0o077) || !fresh(stat.mtimeMs)) return null;
      const record = JSON.parse(readFileSync(fd, "utf8"));
      if (record.toolName !== toolName || !validSession(record)) return null;
      const { conversationId, cwd, transcriptPath } = record;
      return { conversationId, cwd, transcriptPath };
    } finally {
      closeSync(fd);
    }
  } catch {
    return null;
  }
}
