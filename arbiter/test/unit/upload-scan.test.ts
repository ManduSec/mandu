/**
 * upload-scan.test — the upload gate's STREAMED scan of a file for registered
 * secret values (policy/upload-scan.ts, `RegisteredValueIndex.stream`;
 * confidentiality.md §7, "A tool that uploads a local file"). Mandu-new.
 *
 * Proves:
 *   - the stream answers exactly what `hits` over the whole text answers,
 *     whatever the pieces (randomized, values and lines straddling pieces);
 *   - the file scan decodes exactly as `readFileSync(path, "utf8")` (a
 *     character split across two reads, invalid bytes, a byte-order mark),
 *     so its coverage is the value backstop's, no more and no less;
 *   - a value straddling two reads is found; a file with none passes;
 *   - past the size bound, past the deadline, not a regular file (a folder,
 *     a FIFO, which never blocks the read), missing: unreadable;
 *   - the automaton's root table answers exactly as before over text with
 *     code units outside ASCII (U+FFFD, accents, surrogate pairs).
 *
 * Axes: secrets (the scan serves the confidentiality axis; no server here).
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ValueMatcher } from "../../prompt-filter/value-matcher.js";
import { RegisteredValueIndex, type ValueHitStream } from "../../prompt-filter/registered-values.js";
import { scanFileForValues } from "../../policy/upload-scan.js";
import type { SymbolEntry, SymbolMap } from "../../symbol-table/symbol-table.js";
import type { ConfidentialityLevel } from "../../symbol-table/confidentiality.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), "mdu-upload-scan-")); dirs.push(d); return d; };

/** mulberry32: a failure reproduces. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function entry(value: string, level: ConfidentialityLevel = "no-model"): SymbolEntry {
  return {
    value, tool: "Read", field: null, origin: null, session_key: null, call_id: null, created_at: 0,
    obsoleted_at: null, obsoleted_by: null, derived_from: null, line_range: null,
    confidentiality: level, bindings: null, integrity: "untrusted",
  };
}

function indexOf(values: readonly string[]): RegisteredValueIndex {
  const map: SymbolMap = { symbols: new Map(values.map((v, i) => [`$MDU:Read[${(0x1000 + i).toString(16)}]`, entry(v)])) };
  const idx = new RegisteredValueIndex();
  idx.sync(map);
  return idx;
}

/** A stream that also records what it was fed (the decode check). */
function recording(inner: ValueHitStream): ValueHitStream & { text: () => string } {
  const parts: string[] = [];
  return { overlap: inner.overlap, push: (p) => { parts.push(p); inner.push(p); }, hits: () => inner.hits(), text: () => parts.join("") };
}

const KEY = "sk_live_fake_STREAMED_0123456789abcdef";
const DOC = "Acme agrees to pay 4,200,000 USD on signing\nTermination requires ninety days written notice\n";

test("the stream answers exactly what hits() over the whole text answers, whatever the pieces (randomized)", () => {
  const r = rng(11);
  const values = [KEY, DOC, "pässwörd-sëcret-ünïcode-1234", "ghp_0123456789abcdefABCDEF0123", "x".repeat(40)];
  const idx = indexOf(values);
  let found = 0;
  for (let round = 0; round < 300; round++) {
    const parts = Array.from({ length: 1 + Math.floor(r() * 6) }, () => {
      const k = r();
      const v = values[Math.floor(r() * values.length)]!;
      if (k < 0.3) return v;
      if (k < 0.5) return v.split("\n")[0]!;
      if (k < 0.7) return v.slice(0, Math.floor(r() * v.length));
      return "noise �é ".repeat(Math.floor(r() * 5));
    });
    const text = parts.join(r() < 0.5 ? "" : "\n");
    const s = idx.stream();
    for (let at = 0; at < text.length;) {
      const n = 1 + Math.floor(r() * 30);
      s.push(text.slice(at, at + n));
      at += n;
    }
    const whole = idx.hits(text);
    assert.deepEqual(s.hits(), whole, `round ${round}`);
    if (whole.length > 0) found++;
  }
  assert.ok(found > 100, `the corpus exercises hits (${found})`);
});

test("the file scan decodes exactly as readFileSync(path, 'utf8'): split characters, invalid bytes, a byte-order mark", async () => {
  const r = rng(5);
  const dir = tmp();
  const idx = indexOf([KEY]);
  for (let round = 0; round < 60; round++) {
    const bytes = Buffer.alloc(200 + Math.floor(r() * 400));
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(r() * 256);
    // sprinkle valid multi-byte characters and a BOM at the start
    const valid = Buffer.from("﻿é€😀", "utf8");
    valid.copy(bytes, 0);
    Buffer.from("€😀", "utf8").copy(bytes, 100);
    const p = join(dir, `r${round}.bin`);
    writeFileSync(p, bytes);
    const s = recording(idx.stream());
    const got = await scanFileForValues(p, s, { maxBytes: 1 << 20, chunkBytes: 1 + Math.floor(r() * 13), deadline: Number.MAX_SAFE_INTEGER });
    assert.equal(got.kind, "read");
    assert.equal(s.text(), readFileSync(p, "utf8"), `round ${round}`);
  }
});

test("a value straddling two reads is found (a multi-byte character split too); a file with none passes", async () => {
  const dir = tmp();
  const UNI = "pässwörd-sëcret-ünïcode-1234";
  const idx = indexOf([KEY, UNI]);
  const chunk = 64;
  // KEY starts 10 bytes before the first read ends; UNI's `ä` is cut in two
  const body = Buffer.concat([
    Buffer.alloc(chunk - 10, 0xff), Buffer.from(KEY), Buffer.alloc(2 * chunk - (chunk - 10 + KEY.length) - 2, 0x20),
    Buffer.from(UNI, "utf8"), Buffer.alloc(chunk, 0x00),
  ]);
  assert.equal(body.indexOf(Buffer.from("ä", "utf8")), 2 * chunk - 1, "the two bytes of ä straddle the second read");
  const p = join(dir, "straddle.bin");
  writeFileSync(p, body);
  const got = await scanFileForValues(p, idx.stream(), { maxBytes: 1 << 20, chunkBytes: chunk, deadline: Number.MAX_SAFE_INTEGER });
  assert.equal(got.kind, "read");
  assert.deepEqual(got.kind === "read" ? got.hits.map((h) => h.how) : [], ["value", "value"]);
  // the same bytes with the key's middle changed: nothing
  const clean = Buffer.from(body);
  clean[chunk] = 0x21;
  clean.fill(0x78, body.indexOf(Buffer.from(UNI, "utf8")) + 4, body.indexOf(Buffer.from(UNI, "utf8")) + 6);
  const q = join(dir, "clean.bin");
  writeFileSync(q, clean);
  const none = await scanFileForValues(q, idx.stream(), { maxBytes: 1 << 20, chunkBytes: chunk, deadline: Number.MAX_SAFE_INTEGER });
  assert.deepEqual(none.kind === "read" ? none.hits : null, []);
});

test("a long registered value is matched across reads smaller than it (the read grows to the overlap)", async () => {
  const dir = tmp();
  const LONG = Array.from({ length: 40 }, (_, i) => `line ${i} of a labelled document, long enough to stand`).join("\n");
  const idx = indexOf([LONG]);
  const p = join(dir, "long.txt");
  writeFileSync(p, `${"-".repeat(1000)}\n${LONG}\n${"-".repeat(1000)}`);
  const got = await scanFileForValues(p, idx.stream(), { maxBytes: 1 << 20, chunkBytes: 16, deadline: Number.MAX_SAFE_INTEGER });
  assert.deepEqual(got.kind === "read" ? got.hits.map((h) => h.how) : null, ["value"]);
});

test("unreadable: past the size bound, past the deadline, a folder, a FIFO (never blocks), nothing there", async () => {
  const dir = tmp();
  const idx = indexOf([KEY]);
  const p = join(dir, "f.bin");
  writeFileSync(p, Buffer.alloc(4096, 0x61));
  const big = await scanFileForValues(p, idx.stream(), { maxBytes: 4095, chunkBytes: 1024, deadline: Number.MAX_SAFE_INTEGER });
  assert.deepEqual(big, { kind: "unreadable", why: "larger than 4095 bytes" });
  let t = 0;
  const late = await scanFileForValues(p, idx.stream(), { maxBytes: 1 << 20, chunkBytes: 1024, deadline: 2, now: () => t++ });
  assert.deepEqual(late, { kind: "unreadable", why: "the check did not finish in time" });
  assert.deepEqual(await scanFileForValues(dir, idx.stream(), { maxBytes: 1 << 20, chunkBytes: 1024, deadline: Number.MAX_SAFE_INTEGER }), { kind: "unreadable", why: "not a regular file" });
  const fifo = join(dir, "pipe");
  let haveFifo = true;
  try { execFileSync("mkfifo", [fifo]); } catch { haveFifo = false; }
  if (haveFifo) {
    assert.deepEqual(await scanFileForValues(fifo, idx.stream(), { maxBytes: 1 << 20, chunkBytes: 1024, deadline: Number.MAX_SAFE_INTEGER }), { kind: "unreadable", why: "not a regular file" });
  }
  assert.deepEqual(await scanFileForValues(join(dir, "missing"), idx.stream(), { maxBytes: 1 << 20, chunkBytes: 1024, deadline: Number.MAX_SAFE_INTEGER }), { kind: "unreadable", why: "ENOENT" });
  // every chunk is reported (the server's progress)
  const seen: number[] = [];
  await scanFileForValues(p, idx.stream(), { maxBytes: 1 << 20, chunkBytes: 1024, deadline: Number.MAX_SAFE_INTEGER, onChunk: (n) => seen.push(n) });
  assert.deepEqual(seen, [1024, 2048, 3072, 4096]);
});

test("the automaton's root table: the same occurrences as a naive search over text outside ASCII (randomized)", () => {
  const r = rng(23);
  const alpha = ["a", "b", "\n", "�", "é", "\uD83D", "\uDE00", "\u0000", "€"];
  const word = (n: number): string => Array.from({ length: n }, () => alpha[Math.floor(r() * alpha.length)]).join("");
  for (let round = 0; round < 300; round++) {
    const patterns = Array.from({ length: 1 + Math.floor(r() * 8) }, () => word(1 + Math.floor(r() * 24)));
    const text = word(Math.floor(r() * 200));
    const naive: Array<[number, number]> = [];
    patterns.forEach((p, id) => { for (let i = text.indexOf(p); i >= 0; i = text.indexOf(p, i + 1)) naive.push([id, i]); });
    const got = new ValueMatcher(patterns).occurrences(text).map((o) => [o.pattern, o.start] as [number, number]);
    const order = (a: [number, number], b: [number, number]): number => a[0] - b[0] || a[1] - b[1];
    assert.deepEqual(got.sort(order), naive.sort(order), `round ${round}`);
  }
});
