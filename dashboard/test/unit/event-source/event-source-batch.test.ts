/**
 * event-source-batch.test — FileEventSource exposes a session's batchId on its
 * SessionRef (read from the first event that carries one), so the sidebar can
 * group sessions run together. See session-batches.ts + docs/design/ui/dashboard.md §4.10.1.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";

import { FileEventSource } from "../../../src/event-source.js";
import { tmpDir } from "../tmp-dir.js";

let n = 0;
function ev(sessionId: string, batchId?: string): string {
  return JSON.stringify({
    id: `e-${n++}`, sessionId, turn: 0, ts: "2026-06-20T10:00:00.000Z", seq: 1,
    callId: null, parentId: null, kind: "tllm_call", view: "AgentView",
    boundary: "model_context", emitter: "anthropic-proxy", input: null, output: null,
    invariant: { violatedInvariant: false }, ...(batchId ? { batchId } : {}),
  });
}

test("FileEventSource.listSessions exposes batchId from a session's events (else undefined)", async () => {
  const dir = tmpDir("mandu-evsrc-batch-");
  try {
    // A batched session: a later event carries batchId — listSessions should find it.
    writeFileSync(join(dir, "s-batched.ndjson"), `${ev("s-batched")}\n${ev("s-batched", "B1")}\n`);
    // A loose session: no event carries a batchId.
    writeFileSync(join(dir, "s-loose.ndjson"), `${ev("s-loose")}\n`);

    const refs = await new FileEventSource(dir).listSessions();
    const batched = refs.find((r) => r.id === "s-batched");
    const loose = refs.find((r) => r.id === "s-loose");
    assert.equal(batched?.batchId, "B1", "batchId is read from the event that carries one");
    assert.equal(loose?.batchId, undefined, "no batchId when no event carries one");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
