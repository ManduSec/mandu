import { test } from "node:test";
import assert from "node:assert/strict";
import { runCaptured } from "./paired-process.js";
import { tmpdir } from "node:os";

test("process evidence preserves unsuccessful exit and missing executable", async () => {
  const exited = await runCaptured({ command: process.execPath, args: ["-e", "console.log('partial'); process.exit(7)"], env: {} }, tmpdir(), 3000);
  assert.equal(exited.code, 7);
  assert.match(exited.stdout, /partial/);
  assert.equal(exited.timedOut, false);
  const missing = await runCaptured({ command: "/absent/paired-agent", args: [], env: {} }, tmpdir(), 3000);
  assert.match(missing.error ?? "", /ENOENT/);
});

test("deadline stops the owned process group and keeps partial output", async () => {
  const r = await runCaptured({ command: process.execPath, args: ["-e", "console.log('started'); setInterval(() => {}, 1000)"], env: {} }, tmpdir(), 300);
  assert.equal(r.timedOut, true);
  assert.match(r.stdout, /started/);
  assert.ok(r.durationMs < 3000);
});

test("large output is explicitly truncated, never silently complete", async () => {
  const r = await runCaptured({ command: process.execPath, args: ["-e", "process.stdout.write('x'.repeat(5 * 1024 * 1024))"], env: {} }, tmpdir(), 5000);
  assert.equal(r.code, 0);
  assert.equal(r.truncated, true);
  assert.equal(r.stdout.length, 4 * 1024 * 1024);
});
