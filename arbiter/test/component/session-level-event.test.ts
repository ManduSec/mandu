/**
 * component — the `session_level` event (dashboard.md §4.35): when a granted
 * in-context read (`declassify_symbol`, rung 3) raises a session's
 * high-watermark, the arbiter says so in that session's own event stream:
 * from → to, the symbol's name and the session's bindings. Never the content
 * it released. Only a CHANGE is an event: a second read at the same level, or
 * a refused read, adds none.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF (the product default)

const MEMO = "Deal memo: the reference code is SESSION_LEVEL_EVENT_CANARY.";
const LAW: PolicyFileConfig = {
  version: 1,
  paths: [
    { path: "/h/notes/memo.md", level: "any-model", bindings: ["example.com"] },
    { path: "/h/keys/key.txt", level: "no-model" },
  ],
};

async function withStack(fn: (data: ArbiterClient, eventDir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-session-level-"));
  const eventDir = join(dir, "events");
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir,
    log: () => {}, confidentiality: true, integrity: false, policyDocument: LAW, policyPollMs: 0,
  });
  await server.listen();
  const data = new ArbiterClient(join(dir, "a.sock"));
  try {
    await data.connect();
    await fn(data, eventDir);
  } finally {
    data.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

function levelEvents(eventDir: string, session: string): Array<Record<string, unknown>> {
  const f = join(eventDir, session + ".ndjson");
  if (!existsSync(f)) return [];
  return readFileSync(f, "utf8").split("\n").filter(Boolean)
    .map((l) => JSON.parse(l) as Record<string, unknown>)
    .filter((e) => e.kind === "session_level");
}

test("a granted read that raises the session emits one session_level event: from → to, the symbol's name, the bindings, never the content", async () => {
  await withStack(async (data, eventDir) => {
    const symbol = (await data.symbolizeFull({ tool: "Read", value: MEMO, origin: "/h/notes/memo.md", integrity: "trusted", sessionKey: "s" })).symbol;
    const r = await data.declassifySymbol({ symbol, sessionKey: "s" });
    assert.equal(r.allowed, true, r.reason);
    const evs = levelEvents(eventDir, "s");
    assert.equal(evs.length, 1);
    const e = evs[0]!;
    assert.equal(e.sessionId, "s", "in the session's own stream");
    assert.equal(e.emitter, "arbiter");
    assert.deepEqual(e.sessionLevel, { from: "public", to: "any-model", symbol, bindings: ["example.com"] });
    assert.ok(!JSON.stringify([e.input, e.output]).includes("$MDU:"), "the name is in the detail alone, never the text a trace counts as a masked item");
    assert.ok(!JSON.stringify(e).includes("SESSION_LEVEL_EVENT_CANARY"), "the event never carries what the read released");
    // the same level again: no change, no event
    const again = (await data.symbolizeFull({ tool: "Read", value: MEMO + " (2)", origin: "/h/notes/memo.md", integrity: "trusted", sessionKey: "s" })).symbol;
    assert.equal((await data.declassifySymbol({ symbol: again, sessionKey: "s" })).allowed, true);
    assert.equal(levelEvents(eventDir, "s").length, 1, "a raise that changes nothing is not an event");
  });
});

test("a refused read raises nothing and emits nothing", async () => {
  await withStack(async (data, eventDir) => {
    const symbol = (await data.symbolizeFull({ tool: "Read", value: "KEY", origin: "/h/keys/key.txt", integrity: "trusted", sessionKey: "t" })).symbol;
    const r = await data.declassifySymbol({ symbol, sessionKey: "t" });
    assert.equal(r.allowed, false);
    assert.equal((await data.sessionState("t")).high, false);
    assert.deepEqual(levelEvents(eventDir, "t"), []);
  });
});
