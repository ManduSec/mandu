/**
 * after-the-fact-concurrent — confidentiality.md §7.1, "Masked after the
 * fact", *Two launches at once* (2026-10-17): two launches resumed on the
 * same conversation each ask the arbiter about the other's ids; an id one of
 * them did not know at its first ask may be forwarded in clear by the other
 * later. The ledger then learns it from the next answer's `recent` (the ids
 * recorded since the generation it last saw), in the same one op per
 * request, and asks nothing while it holds no unknown id. The same test as
 * the anthropic-proxy's, over this package's mirror of after-the-fact.ts.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { ClearResultLedger, type ClearResultAnswer, type ClearResultStore } from "../../src/after-the-fact.js";

/** A store over one shared table, as two arbiters over one mandu.db are:
 *  rows in insertion order, the generation the latest row's number. */
function sharedTable() {
  const rows: string[] = [];
  const calls: Array<{ op: string; ids: string[]; since?: number }> = [];
  let base = 0; // rows dropped from the front (a rebuilt file restarts it)
  const store = (): ClearResultStore => ({
    known: async (ids) => { calls.push({ op: "known", ids: [...ids] }); return ids.filter((id) => rows.includes(id)); },
    record: async (ids) => { calls.push({ op: "record", ids: [...ids] }); for (const id of ids) if (!rows.includes(id)) rows.push(id); },
    knownSince: async (ids, since): Promise<ClearResultAnswer> => {
      calls.push({ op: "knownSince", ids: [...ids], ...(since !== undefined ? { since } : {}) });
      const generation = base + rows.length;
      const answer: ClearResultAnswer = { ids: ids.filter((id) => rows.includes(id)), generation };
      if (since !== undefined && since <= generation) {
        answer.recent = rows.slice(Math.max(0, since - base));
        answer.recentComplete = true;
      }
      return answer;
    },
  });
  return { rows, calls, store, reset: () => { rows.length = 0; base = 0; } };
}

test("two launches at once: an id launch B held as unknown is known once launch A records it, in B's next request's one op", async () => {
  const t = sharedTable();
  const a = new ClearResultLedger(100, { store: t.store() });
  const b = new ClearResultLedger(100, { store: t.store() });
  // Both resume the same history; neither knows toolu_x yet.
  await a.prime(["toolu_x"]);
  await b.prime(["toolu_x"]);
  assert.equal(b.wasClear("toolu_x"), false);
  // A forwards that result in clear and records it.
  await a.remember(["toolu_x"]);
  assert.deepEqual(t.rows, ["toolu_x"]);
  // B's next request: one op, and the id is known now.
  t.calls.length = 0;
  await b.prime(["toolu_x"]);
  assert.equal(b.wasClear("toolu_x"), true, "B learns what A forwarded since its first ask");
  assert.equal(t.calls.length, 1, "one arbiter op for the request");
  assert.equal(t.calls[0]!.op, "knownSince");
  // Nothing unknown held, nothing new to ask: no op at all.
  t.calls.length = 0;
  await b.prime(["toolu_x"]);
  assert.deepEqual(t.calls, []);
});

test("a request with new ids and unknown ones held: still one op, carrying both", async () => {
  const t = sharedTable();
  const a = new ClearResultLedger(100, { store: t.store() });
  const b = new ClearResultLedger(100, { store: t.store() });
  await b.prime(["toolu_1"]);
  await a.remember(["toolu_1", "toolu_2"]);
  t.calls.length = 0;
  await b.prime(["toolu_1", "toolu_2", "toolu_3"]);
  assert.equal(t.calls.length, 1);
  assert.deepEqual(t.calls[0]!.ids, ["toolu_2", "toolu_3"], "only the ids never asked go by name");
  assert.ok(b.wasClear("toolu_1") && b.wasClear("toolu_2"));
  assert.equal(b.wasClear("toolu_3"), false);
});

test("an id recorded for another conversation is not adopted: only ids held as unknown are learned", async () => {
  const t = sharedTable();
  const a = new ClearResultLedger(100, { store: t.store() });
  const b = new ClearResultLedger(100, { store: t.store() });
  await b.prime(["toolu_mine"]);
  await a.remember(["toolu_elsewhere"]);
  await b.prime([]);
  assert.equal(b.wasClear("toolu_elsewhere"), false);
  assert.equal(b.wasClear("toolu_mine"), false);
});

test("a generation that went down (the store emptied or rebuilt): every unknown id is forgotten and asked again by name", async () => {
  const t = sharedTable();
  const a = new ClearResultLedger(100, { store: t.store() });
  const b = new ClearResultLedger(100, { store: t.store() });
  await a.remember(["toolu_old1", "toolu_old2"]);
  await b.prime(["toolu_y"]); // generation 2 seen, toolu_y unknown
  t.reset();
  await a.remember(["toolu_y"]); // generation 1 now: below what B saw
  t.calls.length = 0;
  await b.prime(["toolu_y"]); // the regress is seen: forget
  await b.prime(["toolu_y"]); // asked again by name
  assert.equal(b.wasClear("toolu_y"), true);
  assert.deepEqual(t.calls.map((c) => c.ids), [[], ["toolu_y"]]);
});

test("a recent list cut short: every unknown id is asked again by name", async () => {
  const calls: string[][] = [];
  let answer: ClearResultAnswer = { ids: [], generation: 5 };
  const store: ClearResultStore = {
    known: async () => [],
    record: async () => {},
    knownSince: async (ids) => { calls.push([...ids]); return answer; },
  };
  const l = new ClearResultLedger(100, { store });
  await l.prime(["toolu_z"]);
  answer = { ids: [], generation: 20_000, recent: [], recentComplete: false };
  await l.prime(["toolu_z"]);
  answer = { ids: ["toolu_z"], generation: 20_000, recent: [], recentComplete: true };
  await l.prime(["toolu_z"]);
  assert.deepEqual(calls, [["toolu_z"], [], ["toolu_z"]]);
  assert.equal(l.wasClear("toolu_z"), true);
});

test("a store without knownSince (an older arbiter): the first answer stands, no further ask (the behavior before)", async () => {
  const known: string[][] = [];
  const store: ClearResultStore = { known: async (ids) => { known.push([...ids]); return []; }, record: async () => {} };
  const l = new ClearResultLedger(100, { store });
  await l.prime(["toolu_q"]);
  await l.prime(["toolu_q"]);
  assert.deepEqual(known, [["toolu_q"]]);
});
