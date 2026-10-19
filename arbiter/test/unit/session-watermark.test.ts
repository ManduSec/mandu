/**
 * session-watermark.test — §3.3 rung 3, §4, §9 rule 2 (Plan 8, Phase C).
 *
 * Three pure oracles + the store. The one that matters most is the LAST family:
 * a high session's egress is gated even when the payload carries NO SYMBOL —
 * which is the whole reason the watermark exists, and the one thing the
 * per-symbol egress gate structurally cannot do.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SessionLabelStore, UNKNOWN_SOURCE, deriveSessionBindings } from "../../policy/session-labels.js";
import Database from "../../db/sqlite.js";
import { decideDeclassify } from "../../policy/declassify.js";
import { decideSessionEgress, destinationIsBound } from "../../policy/session-egress.js";

// ── the store ────────────────────────────────────────────────────────────────

function withStore(fn: (s: SessionLabelStore, dbPath: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "mdu-session-"));
  const dbPath = join(dir, "a.db");
  const s = new SessionLabelStore({ dbPath });
  try {
    fn(s, dbPath);
  } finally {
    s.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test("an unseen session is public and clean — never invent a level", () => {
  withStore((s) => {
    const st = s.get("nobody");
    assert.equal(st.confidentiality, "public");
    assert.equal(st.untrustedTainted, false);
    assert.equal(s.isHigh("nobody"), false);
  });
});

test("the watermark is MONOTONE — it never falls", () => {
  withStore((s) => {
    s.raise("sess", "any-model");
    assert.equal(s.get("sess").confidentiality, "any-model");
    // A session that has read a secret cannot un-read it. "The task moved on"
    // is not a declassification.
    s.raise("sess", "public");
    assert.equal(s.get("sess").confidentiality, "any-model");
    s.raise("sess", "no-model");
    assert.equal(s.get("sess").confidentiality, "no-model");
    s.raise("sess", "any-model");
    assert.equal(s.get("sess").confidentiality, "no-model");
  });
});

test("untrusted taint is sticky, and SURVIVES a restart", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-session-"));
  const dbPath = join(dir, "a.db");
  try {
    const s1 = new SessionLabelStore({ dbPath });
    s1.taint("sess");
    s1.raise("sess", "any-model", ["docs.corp"]);
    s1.close();

    // The watermark is security state. An arbiter restart that dropped it would
    // silently DE-confine a high session.
    const s2 = new SessionLabelStore({ dbPath });
    const st = s2.get("sess");
    assert.equal(st.untrustedTainted, true);
    assert.equal(st.confidentiality, "any-model");
    assert.deepEqual(st.bindings, ["docs.corp"]);
    s2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("bindings INTERSECT across reads — the session keeps only the sinks every datum it read was bound for (plan 13 D1, §9 R3)", () => {
  withStore((s) => {
    s.raise("sess", "any-model", ["a.example"]);
    s.raise("sess", "any-model", ["b.example", "a.example"]);
    assert.deepEqual(s.get("sess").bindings, ["a.example"]);
    s.raise("sess", "any-model", ["b.example"]);
    assert.deepEqual(s.get("sess").bindings, [], "disjoint: no sink admits both data");
  });
});

// ── decideDeclassify: rung 3's door ──────────────────────────────────────────

test("THE ONE INVARIANT: an UNTRUSTED datum is REFUSED into context — with no approval path", () => {
  // Rung 3 puts RAW CONTENT in front of the privileged model. If that content is
  // untrusted, this is exactly what the whole system exists to prevent, and an
  // approval dialog only moves the regression behind a click no human can
  // evaluate ("read this contract" is not "be injected by page 40").
  //
  // We diverge from §9 rule 2's letter here — it says this "escalates to human
  // approval" — because rule 3 of the same section already gives the danger cell
  // its answer: the QUARANTINE is the designated mechanism. See declassify.ts.
  const d = decideDeclassify({
    level: "any-model",
    integrity: "untrusted",
    sessionUntrustedTainted: false,
  });
  assert.equal(d.allow, false);
  assert.equal(d.requiresApproval, false, "no approval opens the one invariant");
  assert.match(d.reason, /inspect_symbol/, "and the model is pointed at the path that DOES work");
});

test("no-model is REFUSED into context — no approval, at any price", () => {
  const d = decideDeclassify({
    level: "no-model",
    integrity: "trusted",
    sessionUntrustedTainted: false,
  });
  assert.equal(d.allow, false);
  assert.equal(d.requiresApproval, false, "the residency claim is not a default to click through");
  assert.match(d.reason, /relabel/i, "the way in is to RELABEL — a visible change to the standing surface");
});

test("trusted × model-ok in a CLEAN session: allowed, logged, and the session goes HIGH", () => {
  const d = decideDeclassify({
    level: "any-model",
    integrity: "trusted",
    sessionUntrustedTainted: false,
  });
  assert.equal(d.allow, true);
  assert.equal(d.requiresApproval, false);
  assert.equal(d.watermark, "any-model", "granting the read without the watermark would be theater (§4)");
});

test("§9 RULE 2 (session half): trusted × model-ok in an UNTRUSTED-TAINTED session ⇒ human approval", () => {
  // A different question from the datum half, and it has a different answer.
  // The DATUM is trusted, so reading it injects nothing. The risk is that the
  // model has already ingested untrusted symbols — an injected model would be
  // holding the secret. That is a confidentiality exposure a human CAN
  // meaningfully authorize.
  const d = decideDeclassify({
    level: "any-model",
    integrity: "trusted",
    sessionUntrustedTainted: true,
  });
  assert.equal(d.allow, false);
  assert.equal(d.requiresApproval, true, "escalates to a human — it does not silently refuse");
  assert.equal(d.watermark, "any-model", "and if approved, the session floats");
});

test("a public symbol is not a declassification — declassify_symbol is not a general resolver", () => {
  const d = decideDeclassify({
    level: "public",
    integrity: "untrusted",
    sessionUntrustedTainted: false,
  });
  assert.equal(d.allow, false);
  assert.equal(d.requiresApproval, false);
});

// ── decideSessionEgress: what the watermark actually buys ────────────────────

test("NO REGRESSION: a public session is inert at every boundary", () => {
  for (const boundary of ["network", "shell", "filesystem"] as const) {
    const d = decideSessionEgress({
      sessionLevel: "public", sessionBindings: [], boundary, destination: "evil.test",
    });
    assert.equal(d.allow, true, `${boundary} must be byte-identical to today in a low session`);
    assert.equal(d.requiresApproval, false);
  }
});

test("THE POINT: a HIGH session's egress is gated with NO SYMBOL in the payload", () => {
  // This is the test that proves the watermark does something the per-symbol
  // egress gate structurally cannot. There is no symbol here at all — the model
  // has PARAPHRASED the secret it read — and it is still stopped.
  const d = decideSessionEgress({
    sessionLevel: "any-model",
    sessionBindings: ["docs.corp"],
    boundary: "network",
    destination: "evil.test",
  });
  assert.equal(d.allow, false);
  assert.equal(d.requiresApproval, true);
  assert.match(d.reason, /paraphrase/i);
});

test("a high session may still reach a BOUND destination without a fresh decision", () => {
  const d = decideSessionEgress({
    sessionLevel: "any-model",
    sessionBindings: ["docs.corp"],
    boundary: "network",
    destination: "https://api.docs.corp/v1/upload",
  });
  assert.equal(d.allow, true, "the read data's own standing release rule still holds");
});

test("§9 rule 1(b): an UNTRUSTED-TAINTED high session loses the standing bound release", () => {
  // The danger cell at the session level: the session is high AND has ingested
  // untrusted data, so an injection can aim a paraphrased secret at the very
  // host the label permits. The standing release is suspended — even the bound
  // destination now takes a human decision.
  const tainted = decideSessionEgress({
    sessionLevel: "any-model",
    sessionBindings: ["docs.corp"],
    boundary: "network",
    destination: "https://api.docs.corp/v1/upload",
    untrustedTainted: true,
  });
  assert.equal(tainted.allow, false, "a bound destination is no longer a standing release once tainted");
  assert.equal(tainted.requiresApproval, true);
  assert.match(tainted.reason, /9 rule 1b|attacker-steerable/i);

  // The trusted-only high session (the CONF-bound-host-release cell) is
  // unchanged: no taint ⇒ the standing release still holds.
  const clean = decideSessionEgress({
    sessionLevel: "any-model",
    sessionBindings: ["docs.corp"],
    boundary: "network",
    destination: "https://api.docs.corp/v1/upload",
    untrustedTainted: false,
  });
  assert.equal(clean.allow, true, "a trusted-only high session keeps its bound release");
});

test("§9 1(b) also covers the net-enabled shell hop of a tainted high session", () => {
  const d = decideSessionEgress({
    sessionLevel: "any-model",
    sessionBindings: ["docs.corp"],
    boundary: "shell",
    destination: "api.docs.corp",
    netEnabled: true,
    untrustedTainted: true,
  });
  assert.equal(d.requiresApproval, true, "curl to a bound host from a tainted high session still needs approval");
});

test("a net-enabled HumanShell is a network sink wearing a different hat", () => {
  const gated = decideSessionEgress({
    sessionLevel: "any-model", sessionBindings: [], boundary: "shell",
    destination: "evil.test", netEnabled: true,
  });
  assert.equal(gated.requiresApproval, true, "the model can hand a paraphrased secret to curl as an argv");

  // AgentShell has no way out — gating it costs utility and buys nothing.
  const agentShell = decideSessionEgress({
    sessionLevel: "any-model", sessionBindings: [], boundary: "shell", netEnabled: false,
  });
  assert.equal(agentShell.allow, true);
});

test("filesystem is LABELED, not blocked — the workspace is the human's own", () => {
  const d = decideSessionEgress({
    sessionLevel: "any-model", sessionBindings: [], boundary: "filesystem",
  });
  assert.equal(d.allow, true, "§4/§7②: high-session writes are labeled at the watermark, not refused");
});

test("an absent destination FAILS CLOSED — we cannot prove it is bound", () => {
  const d = decideSessionEgress({
    sessionLevel: "any-model", sessionBindings: ["docs.corp"], boundary: "network",
  });
  assert.equal(d.requiresApproval, true);
});

test("binding match is LABEL-BOUNDARY aware — evil-example.com does not match example.com", () => {
  // A raw endsWith would be a silent hole an attacker simply picks a hostname to
  // walk through. Same shape as the path-segment rule in path-labels.ts.
  assert.equal(destinationIsBound("api.example.com", ["example.com"]), true);
  assert.equal(destinationIsBound("example.com", ["example.com"]), true);
  assert.equal(destinationIsBound("evil-example.com", ["example.com"]), false);
  assert.equal(destinationIsBound("notexample.com", ["example.com"]), false);
  // ...and it normalizes scheme/port/path off the destination.
  assert.equal(destinationIsBound("https://api.example.com:8443/x", ["example.com"]), true);
});

// ── plan 11: local-model at rung 3 ───────────────────────────────────────────

test("plan 11 D3: local-model is REFUSED into an external T-LLM's context, with no approval path", () => {
  for (const tllmLocation of [undefined, "external"] as const) {
    const d = decideDeclassify({ level: "local-model", integrity: "trusted", sessionUntrustedTainted: false, ...(tllmLocation ? { tllmLocation } : {}) });
    assert.equal(d.allow, false, String(tllmLocation));
    assert.equal(d.requiresApproval, false, "no click opens it");
    assert.equal(d.watermark, null);
    assert.match(d.reason, /inspect_symbol/, "the model is pointed at the helper, which reaches the user's own model");
  }
});

test("plan 11 D3: under a LOCAL T-LLM (phase 3), local-model behaves as any-model with a local-model watermark", () => {
  const clean = decideDeclassify({ level: "local-model", integrity: "trusted", sessionUntrustedTainted: false, tllmLocation: "local" });
  assert.deepEqual([clean.allow, clean.requiresApproval, clean.watermark], [true, false, "local-model"]);
  const tainted = decideDeclassify({ level: "local-model", integrity: "trusted", sessionUntrustedTainted: true, tllmLocation: "local" });
  assert.deepEqual([tainted.allow, tainted.requiresApproval, tainted.watermark], [false, true, "local-model"]);
  // A local T-LLM changes nothing for no-model or untrusted data.
  assert.equal(decideDeclassify({ level: "no-model", integrity: "trusted", sessionUntrustedTainted: false, tllmLocation: "local" }).allow, false);
  const untrusted = decideDeclassify({ level: "local-model", integrity: "untrusted", sessionUntrustedTainted: false, tllmLocation: "local" });
  assert.deepEqual([untrusted.allow, untrusted.requiresApproval], [false, false]);
});

// ── the bindings follow the law in force (confidentiality.md §2.1, §4) ───────

const SA = "$MDU:anymodel_Read[aa01]";
const SB = "$MDU:anymodel_Read[bb02]";

test("rederive: a high session's bindings are where EVERY symbol it read may go NOW — narrowing at once, widening only where all sources allow", () => {
  withStore((s) => {
    const law = new Map<string, string[] | null>([[SA, ["x.example", "shared.example"]], [SB, ["y.example", "shared.example"]]]);
    const current = (sym: string) => law.get(sym) ?? null;
    s.raise("sess", "any-model", law.get(SA)!, SA);
    s.raise("sess", "any-model", law.get(SB)!, SB);
    assert.deepEqual(s.get("sess").bindings, ["shared.example"]);
    assert.deepEqual(s.rederive(current), [], "nothing changed: nothing written");

    // A binding removed from one source: gone from the session.
    law.set(SB, ["y.example"]);
    assert.deepEqual(s.rederive(current), ["sess"]);
    assert.deepEqual(s.get("sess").bindings, []);
    // y added to the other source: both may go to y now.
    law.set(SA, ["x.example", "y.example"]);
    s.rederive(current);
    assert.deepEqual(s.get("sess").bindings, ["y.example"]);
    assert.equal(s.get("sess").confidentiality, "any-model", "the level never falls");

    // A source row gone: the session is bound nowhere.
    law.set(SA, null);
    s.rederive(current);
    assert.deepEqual(s.get("sess").bindings, []);
  });
});

test("rederive fails closed: a secret read with no named source, or a high session from before the sources table, is bound nowhere", () => {
  assert.deepEqual(deriveSessionBindings([], () => ["a.example"]), []);
  assert.deepEqual(deriveSessionBindings([UNKNOWN_SOURCE], () => ["a.example"]), []);
  assert.deepEqual(deriveSessionBindings([SA, UNKNOWN_SOURCE], () => ["a.example"]), []);
  withStore((s) => {
    s.raise("anon", "any-model", ["a.example"]);
    assert.deepEqual(s.sourcesOf("anon"), [UNKNOWN_SOURCE]);
    // A public read names nothing and changes nothing.
    s.raise("low", "public", [], SA);
    assert.deepEqual(s.sourcesOf("low"), []);
    s.rederive(() => ["a.example"]);
    assert.deepEqual(s.get("anon").bindings, [], "unknown source: nowhere");
    assert.equal(s.get("low").confidentiality, "public");
  });

  // A v7 file: a high session row and no sources table yet.
  const dir = mkdtempSync(join(tmpdir(), "mdu-session-"));
  const dbPath = join(dir, "a.db");
  try {
    const raw = new Database(dbPath);
    raw.exec("CREATE TABLE session_labels (session_key TEXT PRIMARY KEY, confidentiality TEXT NOT NULL DEFAULT 'public', untrusted_tainted INTEGER NOT NULL DEFAULT 0, bindings TEXT, updated_at INTEGER NOT NULL)");
    raw.prepare("INSERT INTO session_labels VALUES (?, ?, 0, ?, 1)").run("old", "any-model", JSON.stringify(["docs.corp"]));
    raw.close();
    const s = new SessionLabelStore({ dbPath });
    assert.deepEqual(s.get("old").bindings, ["docs.corp"], "read as written");
    assert.deepEqual(s.sourcesOf("old"), [UNKNOWN_SOURCE]);
    // A later read with a known source cannot hide the unknown one.
    s.raise("old", "any-model", ["docs.corp"], SB);
    s.rederive(() => ["docs.corp"]);
    assert.deepEqual(s.get("old").bindings, [], "what it read before is unknown: nowhere");
    s.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the sources survive a restart, so the re-derivation after it reads the same reads", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-session-"));
  const dbPath = join(dir, "a.db");
  try {
    const s1 = new SessionLabelStore({ dbPath });
    s1.raise("sess", "any-model", ["docs.corp"], SA);
    s1.close();
    const s2 = new SessionLabelStore({ dbPath });
    assert.deepEqual(s2.sourcesOf("sess"), [SA]);
    s2.rederive((sym) => (sym === SA ? [] : null));
    assert.deepEqual(s2.get("sess").bindings, [], "the binding removed while the arbiter was down");
    s2.close();
    const s3 = new SessionLabelStore({ dbPath });
    assert.deepEqual(s3.get("sess").bindings, [], "persisted");
    s3.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
