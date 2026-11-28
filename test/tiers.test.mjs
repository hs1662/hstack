import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { FAST, FAULT, TEST_DIR, allTestFiles, forbiddenMarkers } from "./tiers.mjs";

const source = (file) => readFileSync(join(TEST_DIR, file), "utf8");

test("every tier entry names an existing test file", () => {
  const files = new Set(allTestFiles());
  assert.deepEqual([...FAST, ...FAULT].filter((file) => !files.has(file)), []);
});

test("fast files use no timing lock, synchronous child process, or kill injection", () => {
  const offenders = FAST.map((file) => [file, forbiddenMarkers(source(file))]).filter(([, found]) => found.length);
  assert.deepEqual(offenders, []);
});

test("graph tests stay off the shared CPU lock that wall-clock tests take exclusive", () => {
  const locked = allTestFiles().filter((file) => file.startsWith("graph-") && source(file).includes("helpers.mjs"));
  assert.deepEqual(locked, []);
});
