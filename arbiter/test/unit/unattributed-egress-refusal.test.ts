/**
 * unattributed-egress-refusal — confidentiality plan 10 §11.8, "A refusal no
 * process is tied to" (2026-10-17): the egress proxy refused a connection
 * and found no process holding it. The store records the KIND for the
 * session (never a host, never a guessed process), only while a call of the
 * session is running, at most one row per (session, kind) per span of calls,
 * and folds it into every call whose window (the proxy's relay of the call
 * to its first ask) holds it, one entry per kind. Display only: the fold is
 * never a mask input. ProvenanceStore directly, on a controlled clock.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ProvenanceStore } from "../../provenance/provenance-store.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis: the refused: note of the model proxies

function store(): { p: ProvenanceStore; advance: (ms?: number) => void; done: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-unattr-refusal-"));
  let now = 1_000_000;
  const p = new ProvenanceStore({ dbPath: join(dir, "p.db"), wallClock: () => now });
  return { p, advance: (ms = 10) => { now += ms; }, done: () => { p.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("no call running: nothing is recorded, and a call relayed later does not carry it", () => {
  const { p, advance, done } = store();
  try {
    assert.equal(p.recordUnattributedEgressRefusal({ kind: "unattributed", session: "s1" }), false);
    advance();
    p.recordCallPending("call_later", "s1");
    advance();
    assert.deepEqual(p.unattributedEgressRefusalsFor("call_later", "s1"), []);
  } finally {
    done();
  }
});

test("a refusal while a call runs folds into that call, one entry per kind; a retry loop adds no row", () => {
  const { p, advance, done } = store();
  try {
    p.recordCallPending("call_a", "s1");
    advance();
    assert.equal(p.recordUnattributedEgressRefusal({ kind: "unattributed", session: "s1" }), true);
    for (let i = 0; i < 20; i++) {
      advance(1);
      assert.equal(p.recordUnattributedEgressRefusal({ kind: "unattributed", session: "s1" }), false, "the same kind again in the same call: deduplicated");
    }
    advance();
    assert.equal(p.recordUnattributedEgressRefusal({ kind: "this-machine", session: "s1" }), true, "another kind is its own line");
    advance();
    p.callTree("call_a", { session: "s1" }); // the proxy's first ask closes the window
    assert.deepEqual(p.unattributedEgressRefusalsFor("call_a", "s1"), ["unattributed", "this-machine"]);
    // After the ask nothing is running: a later refusal is not this call's,
    // and the call's answer does not change (the note is stable).
    advance();
    assert.equal(p.recordUnattributedEgressRefusal({ kind: "fingerprint", session: "s1" }), false);
    assert.deepEqual(p.unattributedEgressRefusalsFor("call_a", "s1"), ["unattributed", "this-machine"]);
  } finally {
    done();
  }
});

test("two calls running together: a refusal made while both run is in both; one made after the first was asked is only in the second", () => {
  const { p, advance, done } = store();
  try {
    p.recordCallPending("call_a", "s1");
    advance();
    assert.equal(p.recordUnattributedEgressRefusal({ kind: "symbol", session: "s1" }), true);
    advance();
    p.recordCallPending("call_b", "s1");
    advance();
    assert.equal(p.recordUnattributedEgressRefusal({ kind: "symbol", session: "s1" }), true, "call_b's window holds no row yet: recorded");
    advance();
    assert.equal(p.recordUnattributedEgressRefusal({ kind: "symbol", session: "s1" }), false, "both windows hold one now");
    advance();
    p.callTree("call_a", { session: "s1" });
    advance();
    assert.equal(p.recordUnattributedEgressRefusal({ kind: "blocked-destination", session: "s1" }), true);
    advance();
    p.callTree("call_b", { session: "s1" });
    assert.deepEqual(p.unattributedEgressRefusalsFor("call_a", "s1"), ["symbol"], "one entry per kind");
    assert.deepEqual(p.unattributedEgressRefusalsFor("call_b", "s1"), ["symbol", "blocked-destination"]);
  } finally {
    done();
  }
});

test("another session's refusal, and a call whose relay is unknown, carry nothing", () => {
  const { p, advance, done } = store();
  try {
    p.recordCallPending("call_s1", "s1");
    p.recordCallPending("call_s2", "s2");
    advance();
    assert.equal(p.recordUnattributedEgressRefusal({ kind: "unattributed", session: "s2" }), true);
    advance();
    assert.deepEqual(p.unattributedEgressRefusalsFor("call_s1", "s1"), []);
    assert.deepEqual(p.unattributedEgressRefusalsFor("call_s2", "s2"), ["unattributed"]);
    assert.deepEqual(p.unattributedEgressRefusalsFor("call_never_relayed", "s2"), [], "no window: no guess at which call it was");
  } finally {
    done();
  }
});

test("the fold is not taint: a call with only an unattributed refusal has no level and no rows", () => {
  const { p, advance, done } = store();
  try {
    p.recordCallPending("call_a", "s1");
    advance();
    p.recordUnattributedEgressRefusal({ kind: "unattributed", session: "s1" });
    advance();
    const t = p.callTree("call_a", { session: "s1" });
    assert.equal(t.level, null);
    assert.deepEqual(t.rows, []);
    assert.equal(t.refusedEgress, undefined, "the tree's own refusals hold only attributed ones");
  } finally {
    done();
  }
});
