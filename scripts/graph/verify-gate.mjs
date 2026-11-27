import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";

// The host chooses argv at admission. Never interpret a command in a worker receipt.
export async function measureGate({ argv, cwd, subjectDigest, env = process.env, timeoutMs = 30_000 }) {
  if (!Array.isArray(argv) || !argv.length || !argv.every(v => typeof v === "string" && !v.includes("\0")) ||
      !argv[0] || !/^[0-9a-f]{64}$/.test(subjectDigest) ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2_147_483_647) {
    throw Object.assign(new Error("Invalid host verifier policy"), { code: "ERR_GATE_POLICY" });
  }
  const started = performance.now();
  const envDigest = createHash("sha256").update(JSON.stringify(Object.keys(env).sort().map(key => [key, env[key]]))).digest("hex");
  const stdout = createHash("sha256"), stderr = createHash("sha256");
  const child = spawn(argv[0], argv.slice(1), { env, cwd, shell: false, detached: true, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.on("data", bytes => stdout.update(bytes));
  child.stderr.on("data", bytes => stderr.update(bytes));
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    // Kill the verifier's POSIX group: a grandchild holding a pipe must not defeat the timeout.
    if (child.pid) {
      try { process.kill(-child.pid, "SIGKILL"); }
      catch (error) { if (error.code !== "ESRCH") child.kill("SIGKILL"); }
    }
  }, timeoutMs);
  try {
    const [exit, signal] = await new Promise((resolve, reject) => {
      child.once("error", cause => reject(Object.assign(new Error("Could not start host verifier", { cause }), { code: "ERR_GATE_SPAWN" })));
      child.once("close", (code, sig) => resolve([code, sig]));
    });
    return { argv: [...argv], envDigest, subjectDigest, exit, exitCode: exit, signal, timedOut,
      durationMs: Math.round(performance.now() - started), stdoutDigest: stdout.digest("hex"), stderrDigest: stderr.digest("hex") };
  } finally {
    clearTimeout(timer);
  }
}
