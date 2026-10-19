/**
 * event-file-planted — E2E over a real ArbiterServer and the production
 * client (runtime-instances.md §2, "planted paths", 2026-10-17): an
 * interceptor's `emit` for a session whose event file the agent replaced by
 * a link to one of the user's files (a per-launch arbiter keeps its events
 * in the session's scope dir, which the agent may write) is refused, and the
 * linked file gets no byte; another session's emit still records.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the default mode's arbiter; the event store is mode-independent

test("emit into a session whose event file is a planted link: refused, the linked file untouched", async () => {
  const work = realpathSync(mkdtempSync(join(tmpdir(), "mandu-evplant-")));
  const eventDir = join(work, "scope", "events");
  mkdirSync(eventDir, { recursive: true, mode: 0o700 });
  const victim = join(work, "victim.rc");
  writeFileSync(victim, "# rc\n");
  symlinkSync(victim, join(eventDir, "s-planted.ndjson"));
  const server = new ArbiterServer({
    socketPath: join(work, "arbiter.sock"),
    humanSocketPath: join(work, "human", "h.sock"),
    dbPath: join(work, "symbols.db"),
    eventDir,
    log: () => {},
  });
  await server.listen();
  const client = new ArbiterClient(join(work, "arbiter.sock"));
  await client.connect();
  try {
    await assert.rejects(client.emit({ sessionId: "s-planted", id: "e1", ts: new Date().toISOString(), kind: "tllm_call", note: "AGENT-STEERED" }));
    assert.equal(readFileSync(victim, "utf8"), "# rc\n", "nothing appended through the link");
    assert.equal(await client.emit({ sessionId: "s-ok", id: "e2", ts: new Date().toISOString(), kind: "tllm_call" }), 1);
    assert.match(readFileSync(join(eventDir, "s-ok.ndjson"), "utf8"), /"id":"e2"/);
  } finally {
    client.close();
    await server.close();
    rmSync(work, { recursive: true, force: true });
  }
});
