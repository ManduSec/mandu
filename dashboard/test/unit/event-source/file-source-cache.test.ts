/**
 * file-source-cache.test.ts — FileEventSource.listSessions stat-keyed ref memo
 * (Mandu-new, no reference origin).
 *
 * listSessions memoizes each session's derived SessionRef at the file's
 * (ino, size, mtime) identity — the append-only twin of ArbiterEventSource's
 * (count, lastTs) memo. Its OBSERVABLE contract must stay that of the
 * always-re-derive scan: appended lines refresh the ref, a removed file drops
 * out, and an in-place replacement re-derives from the new content.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { FileEventSource } from "../../../src/event-source.js";
import { tmpDir } from "../tmp-dir.js";

function line(sessionId: string, id: string, seq: number, ts: string, extra: Record<string, unknown> = {}): string {
  return (
    JSON.stringify({ sessionId, id, seq, ts, kind: "tllm_call", view: "AgentView", ...extra }) + "\n"
  );
}

test("listSessions refreshes memoized refs on append, replacement, and removal", async () => {
  const dir = tmpDir("mandu-filesrc-cache-");
  const source = new FileEventSource(dir);
  try {
    writeFileSync(join(dir, "s1.ndjson"), line("s1", "a", 1, "2026-07-18T01:00:00.000Z"));
    writeFileSync(join(dir, "s2.ndjson"), line("s2", "a", 1, "2026-07-18T02:00:00.000Z"));

    const cold = await source.listSessions();
    assert.deepEqual(cold.map((s) => [s.id, s.eventCount]), [["s2", 1], ["s1", 1]]);

    // Unchanged files → the memo answers; the refs must be the same content.
    assert.deepEqual(await source.listSessions(), cold);

    // Append (incl. a violating event): that session's ref refreshes.
    appendFileSync(
      join(dir, "s1.ndjson"),
      line("s1", "b", 2, "2026-07-18T03:00:00.000Z", {
        kind: "tool_result",
        invariant: { violatedInvariant: true, detail: "unsymbolized" },
      }),
    );
    const grown = await source.listSessions();
    const s1 = grown.find((s) => s.id === "s1")!;
    assert.equal(s1.eventCount, 2);
    assert.equal(s1.lastTs, "2026-07-18T03:00:00.000Z");
    assert.equal(s1.violated, true);
    assert.equal(grown[0]!.id, "s1", "recency order follows the refreshed lastTs");

    // In-place replacement (shrink) re-derives from the new content.
    writeFileSync(join(dir, "s1.ndjson"), line("s1", "z", 9, "2026-07-18T04:00:00.000Z"));
    const replaced = await source.listSessions();
    const s1b = replaced.find((s) => s.id === "s1")!;
    assert.equal(s1b.eventCount, 1);
    assert.equal(s1b.violated, false);

    // External removal: evicted from the listing (not resurrected from the memo).
    unlinkSync(join(dir, "s2.ndjson"));
    assert.deepEqual((await source.listSessions()).map((s) => s.id), ["s1"]);
  } finally {
    source.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("listSessions marks a session whose agent exited (`exited`), and drops the mark when activity follows the exit or the log is replaced (dashboard.md §4.10.4)", async () => {
  const dir = tmpDir("mandu-filesrc-exited-");
  const source = new FileEventSource(dir);
  try {
    const log = join(dir, "s1.ndjson");
    writeFileSync(log, line("s1", "a", 1, "2026-07-18T01:00:00.000Z") + line("s1", "b", 2, "2026-07-18T01:00:05.000Z", { kind: "tool_result" }));
    writeFileSync(join(dir, "s2.ndjson"), line("s2", "a", 1, "2026-07-18T02:00:00.000Z"));
    const before = await source.listSessions();
    assert.equal(before.find((s) => s.id === "s1")!.exited, undefined, "no recorded exit: no mark");

    // The launcher's session_exit after the last activity: the agent exited.
    appendFileSync(log, line("s1", "c", 3, "2026-07-18T01:00:06.000Z", { kind: "session_exit", view: "HumanView", emitter: "launcher", code: 0 }));
    const ended = await source.listSessions();
    assert.equal(ended.find((s) => s.id === "s1")!.exited, true, "the recorded exit marks the row");
    assert.equal(ended.find((s) => s.id === "s2")!.exited, undefined, "another session keeps none");
    assert.deepEqual(await source.listSessions(), ended, "the memo answers an unchanged log with the same mark");

    // A resumed session writing to the same log: activity after the exit.
    appendFileSync(log, line("s1", "d", 4, "2026-07-18T01:10:00.000Z"));
    assert.equal((await source.listSessions()).find((s) => s.id === "s1")!.exited, undefined, "activity after the exit drops the mark");

    // Replaced in place by a log that ends with an exit again: re-derived.
    writeFileSync(log, line("s1", "z", 1, "2026-07-18T05:00:00.000Z") + line("s1", "y", 2, "2026-07-18T05:00:01.000Z", { kind: "session_exit", view: "HumanView" }));
    assert.equal((await source.listSessions()).find((s) => s.id === "s1")!.exited, true);
  } finally {
    source.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
