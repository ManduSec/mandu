/**
 * events-lineage-notes — what `/api/events` adds for the developer view's
 * *Where each went* (symbol-lineage.md §5.6): `flowNotes`, each registered
 * placeholder's file (`~/…`) and an earlier leak the kept scan found, and
 * `recordUnchecked` when Mandu could not check the record. Display only: no
 * facts, a failed read, or a `sinceSeq` tail adds neither; the body never
 * carries a value the signed-out projection would not.
 *
 * Axes: none (the route reads recorded events; no arbiter runs).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { apiEvents } from "../../../src/server/api-routes.js";
import type { EventSource } from "../../../src/event-source.js";
import type { LineageFacts } from "../../../src/view-model/secret-path.js";
import { BASE, CMD, events, FILE, HOME, SESSION, TWIN, VALUE } from "../view-model/plugin-path-fixture.js";

/** The route's answer, as JSON. */
async function body(o: { claimed?: boolean; facts?: () => Promise<LineageFacts | null>; query?: string; values?: boolean } = {}): Promise<Record<string, any>> {
  const all = events({ claimed: o.claimed });
  const source = { readEvents: async () => all } as unknown as EventSource;
  let text = "";
  const res = { writeHead() { return res; }, setHeader() {}, end(s: string) { text = s; } } as any;
  await apiEvents(source, () => {}, `/api/events?session=${encodeURIComponent(SESSION)}${o.query ?? ""}`, res, o.values ?? true, undefined, o.facts);
  return JSON.parse(text);
}

const FACTS: LineageFacts = {
  files: new Map([[BASE, FILE]]),
  scan: {
    version: 1, ranAt: "2026-10-28T08:00:00.000Z", sessions: { openclaw: 1 }, duringMandu: 0, known: 1, dropped: 0,
    capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 }, suggestions: null,
    findings: [{
      kind: "known", preview: "Ju…", source: { path: "~/app/.env", name: "ORDERHUB_PASSPHRASE" }, sessions: 1, agents: ["openclaw"], how: { "command-output": 1 }, projects: [], duringMandu: 0,
      examples: [{ at: "2026-10-27T00:37:00.000Z", agent: "openclaw", how: "command-output", command: CMD, mandu: "without" }],
    }],
  },
  home: HOME,
};

test("flowNotes: the registered placeholder's file and its earlier leak", async () => {
  const b = await body({ facts: async () => FACTS });
  assert.deepEqual(Object.keys(b.flowNotes), [TWIN]);
  assert.equal(b.flowNotes[TWIN].file, "~/app/.env");
  assert.match(b.flowNotes[TWIN].earlier.map((p: { text: string }) => p.text).join(""), /^Without Mandu, OpenClaw gave the AI its real value/);
  assert.equal("recordUnchecked" in b, false, "a checked record says nothing");
});

test("no facts, none known, or a failed read: no notes, the body as before", async () => {
  assert.equal("flowNotes" in await body(), false);
  assert.equal("flowNotes" in await body({ facts: async () => null }), false);
  assert.equal("flowNotes" in await body({ facts: async () => ({ ...FACTS, files: new Map() }) }), false);
  assert.equal("flowNotes" in await body({ facts: async () => { throw new Error("arbiter down"); } }), false);
});

test("recordUnchecked: an unchecked record says so; a `sinceSeq` tail cannot tell", async () => {
  assert.equal((await body({ claimed: true })).recordUnchecked, true);
  assert.equal("recordUnchecked" in await body({ claimed: true, query: "&sinceSeq=3" }), false);
});

test("signed out: the notes carry names, paths and times, never the value", async () => {
  const b = await body({ facts: async () => FACTS, values: false });
  assert.equal(JSON.stringify(b.flowNotes).includes(VALUE), false);
  assert.equal(JSON.stringify(b).includes(VALUE), false);
});
