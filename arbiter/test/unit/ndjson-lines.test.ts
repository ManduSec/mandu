/**
 * ndjson-lines.test.ts — the linear NDJSON line splitter (ipc/ndjson-lines.ts).
 *
 * Mandu-new test (no reference origin). Guards both the framing semantics
 * (lines split across chunks, several lines per chunk, a trailing fragment)
 * and the reason the module exists: one multi-MB line arriving in socket-sized
 * chunks must frame in time proportional to its size, not quadratic in it
 * (dashboard.md §3.3, 2026-09-17 — the sidebar's 16 MB `events` reply).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

import { NdjsonLineSplitter } from "../../ipc/ndjson-lines.js";

test("frames lines split across chunks, several per chunk, and keeps a trailing fragment", () => {
  const s = new NdjsonLineSplitter();
  assert.deepEqual(s.push('{"a":1}\n{"b":'), ['{"a":1}']);
  assert.equal(s.pendingLength, '{"b":'.length);
  assert.deepEqual(s.push("2}\n\n{\"c\":3}\n{\"d\""), ['{"b":2}', "", '{"c":3}']);
  assert.deepEqual(s.push(":4}"), []);
  assert.deepEqual(s.push("\n"), ['{"d":4}']);
  assert.equal(s.pendingLength, 0);
  assert.deepEqual(s.push(""), []);
});

test("a multi-byte fragment is reassembled byte-exact across chunks", () => {
  const s = new NdjsonLineSplitter();
  const line = '{"label":"héllo 🚀 wörld"}';
  const mid = line.indexOf("🚀") + 1; // split INSIDE the surrogate pair
  assert.deepEqual(s.push(line.slice(0, mid)), []);
  assert.deepEqual(s.push(line.slice(mid) + "\n"), [line]);
});

test("a 16 MB single line in 64 KiB chunks frames in linear time", () => {
  // The quadratic idiom (`buf += chunk; buf.indexOf("\n")` from 0) takes 6–7 s
  // on this shape (measured 2026-09-17 against the live arbiter); linear
  // framing takes tens of milliseconds. The bound is generous so a loaded CI
  // box cannot flake it while still ruling the quadratic shape out.
  const chunk = "x".repeat(64 * 1024);
  const chunks = 256; // 16 MiB
  const s = new NdjsonLineSplitter();
  const t0 = Date.now();
  let lines: string[] = [];
  for (let i = 0; i < chunks; i++) lines = s.push(chunk);
  lines = s.push("\n");
  const elapsed = Date.now() - t0;
  assert.equal(lines.length, 1);
  assert.equal(lines[0]!.length, chunk.length * chunks);
  assert.ok(elapsed < 1500, `framed 16 MiB in ${elapsed} ms (quadratic framing takes seconds)`);
});

test("the dashboard twin is identical to this module apart from its provenance header", () => {
  // The dashboard deliberately does not import the arbiter package, so it
  // carries a copy; this pins the two together (edit both or neither).
  const here = dirname(fileURLToPath(import.meta.url));
  const strip = (src: string): string => src.replace(/^\/\*\*[\s\S]*?\*\/\n/, "");
  const ours = strip(readFileSync(join(here, "..", "..", "ipc", "ndjson-lines.ts"), "utf8"));
  const twin = strip(
    readFileSync(join(here, "..", "..", "..", "dashboard", "src", "event-source", "ndjson-lines.ts"), "utf8"),
  );
  assert.equal(twin, ours, "dashboard/src/event-source/ndjson-lines.ts drifted from arbiter/ipc/ndjson-lines.ts");
});
