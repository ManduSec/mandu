/**
 * event-chain — the session log's hash chain (comparisons.md §3.9,
 * events/event-store.ts): intact logs verify, an edited / dropped / reordered
 * line is named, a restarted store continues the chain, a pre-chain prefix is
 * skipped, and a caller cannot forge its own link.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { EventStore, verifyChainText } from "../../events/event-store.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // the event log is axis-independent; the suite states one anyway

function store(): { s: EventStore; dir: string; file: (id: string) => string; done: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mdu-chain-"));
  return { s: new EventStore(dir), dir, file: (id) => join(dir, `${id}.ndjson`), done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("an appended log verifies; each line's chain is its last key", () => {
  const { s, file, done } = store();
  try {
    for (let i = 0; i < 5; i++) s.append({ sessionId: "s1", id: `e${i}`, kind: "emit", n: i } as never);
    const v = s.verifyChain("s1");
    assert.deepEqual({ ok: v.ok, chained: v.chained, unchained: v.unchained }, { ok: true, chained: 5, unchained: 0 });
    const lines = readFileSync(file("s1"), "utf8").trim().split("\n");
    assert.equal(v.head, JSON.parse(lines[4]!).chain);
    assert.ok(lines.every((l) => Object.keys(JSON.parse(l)).pop() === "chain"));
  } finally { done(); }
});

test("an edited, dropped or reordered line is named by seq", () => {
  const { s, file, done } = store();
  try {
    for (let i = 0; i < 4; i++) s.append({ sessionId: "s1", id: `e${i}`, kind: "emit", n: i } as never);
    const lines = readFileSync(file("s1"), "utf8").trim().split("\n");
    const edited = [...lines]; edited[1] = edited[1]!.replace('"n":1', '"n":9');
    assert.deepEqual([verifyChainText(edited.join("\n")).ok, verifyChainText(edited.join("\n")).brokenAt], [false, 2]);
    const dropped = lines.filter((_, i) => i !== 1);
    assert.equal(verifyChainText(dropped.join("\n")).brokenAt, 3);
    const swapped = [lines[0], lines[2], lines[1], lines[3]];
    assert.equal(verifyChainText(swapped.join("\n")).ok, false);
    writeFileSync(file("s1"), edited.join("\n") + "\n");
    assert.equal(s.verifyChain("s1").brokenAt, 2, "the store's verifier reads the file");
  } finally { done(); }
});

test("a restarted store continues the chain; a pre-chain prefix is skipped; a caller's chain is ignored", () => {
  const { s, dir, file, done } = store();
  try {
    writeFileSync(file("s2"), JSON.stringify({ sessionId: "s2", id: "old", seq: 1 }) + "\n");
    s.append({ sessionId: "s2", id: "a", kind: "emit" } as never);
    const again = new EventStore(dir);
    again.append({ sessionId: "s2", id: "b", kind: "emit", chain: "forged" } as never);
    const v = again.verifyChain("s2");
    assert.deepEqual({ ok: v.ok, chained: v.chained, unchained: v.unchained }, { ok: true, chained: 2, unchained: 1 });
    assert.ok(!readFileSync(file("s2"), "utf8").includes("forged"));
    assert.deepEqual(again.verifyChain("no-such-session"), { ok: true, chained: 0, unchained: 0, head: null });
  } finally { done(); }
});
