/**
 * ndjson-lines.test.ts — the dashboard's twin of the arbiter's linear NDJSON
 * line splitter (src/event-source/ndjson-lines.ts). The arbiter's own suite
 * (arbiter/test/unit/ndjson-lines.test.ts) pins the two copies identical; this
 * one guards the framing the dashboard's socket readers rely on (dashboard.md
 * §3.3, 2026-09-17: a 16 MB single-line `events` reply must frame linearly).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { NdjsonLineSplitter } from "../../../src/event-source/ndjson-lines.js";

test("frames lines split across chunks and keeps a trailing fragment", () => {
  const s = new NdjsonLineSplitter();
  assert.deepEqual(s.push('{"a":1}\n{"b":'), ['{"a":1}']);
  assert.deepEqual(s.push('2}\n{"c":3}\n'), ['{"b":2}', '{"c":3}']);
  assert.deepEqual(s.push('{"d"'), []);
  assert.deepEqual(s.push(":4}\n"), ['{"d":4}']);
  assert.equal(s.pendingLength, 0);
});

test("a 16 MB single line in 64 KiB chunks frames in linear time", () => {
  const chunk = "x".repeat(64 * 1024);
  const s = new NdjsonLineSplitter();
  const t0 = Date.now();
  for (let i = 0; i < 256; i++) s.push(chunk);
  const lines = s.push("\n");
  const elapsed = Date.now() - t0;
  assert.equal(lines.length, 1);
  assert.equal(lines[0]!.length, 256 * 64 * 1024);
  assert.ok(elapsed < 1500, `framed 16 MiB in ${elapsed} ms (the quadratic idiom takes seconds)`);
});
