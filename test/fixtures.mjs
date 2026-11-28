// Lock-free shared fixtures. Graph tests import this module instead of helpers.mjs so they never join the
// shared CPU lock that wall-clock tests take exclusive; a long graph case then cannot convoy the suite.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after } from "node:test";
import { fileURLToPath } from "node:url";

export const PLUGIN_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const tempDirs = [];

after(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
});

export function createTempDir(prefix = "hstack-test-") {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}
