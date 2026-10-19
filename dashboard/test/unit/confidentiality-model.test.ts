/**
 * The confidentiality label on the event model (confidentiality.md §2; plan 5).
 * PRESENTATION ONLY — the arbiter decides; these fields let the dashboard and
 * the §12 oracle SEE what it decided.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fromSymbolEntry, isManduEvent, type ManduEvent } from "../../src/event-model.js";

test("fromSymbolEntry projects a SECRET level onto the SymbolRef", () => {
  const ref = fromSymbolEntry("$MDU:nomodel_Read[3fa9]", {
    value: "AKIA-REAL",
    tool: "Read",
    field: null,
    origin: "/home/u/.aws/credentials",
    confidentiality: "no-model",
  });
  assert.equal(ref.confidentiality, "no-model");
  assert.equal(ref.origin, "/home/u/.aws/credentials");
});

test("public and absent levels carry NO field (no churn on every ordinary symbol)", () => {
  const pub = fromSymbolEntry("$MDU:web_fetch[a1b2]", {
    value: "page", tool: "web_fetch", field: null, origin: "https://x.test",
    confidentiality: "public",
  });
  assert.equal("confidentiality" in pub, false);

  // A pre-axis entry (no field at all) — the dashboard must not invent a level.
  const legacy = fromSymbolEntry("$MDU:web_fetch[a1b2]", {
    value: "page", tool: "web_fetch", field: null, origin: null,
  });
  assert.equal("confidentiality" in legacy, false);
});

test("an event carrying a secret label still validates as an ManduEvent", () => {
  const e: ManduEvent = {
    id: "e1",
    sessionId: "s1",
    seq: 1,
    ts: "2026-07-12T00:00:00.000Z",
    kind: "symbolize",
    view: "AgentView",
    boundary: "model_context",
    emitter: "anthropic-proxy",
    input: null,
    output: {
      symbolized: "$MDU:nomodel_Read[3fa9]",
      original: "AKIA-REAL",
      differs: true,
      symbols: [{
        name: "$MDU:nomodel_Read[3fa9]",
        tool: "Read",
        field: null,
        origin: "/home/u/.aws/credentials",
        value: "AKIA-REAL",
        confidentiality: "no-model",
      }],
    },
    // The normal shape for a credential file: TRUSTED integrity, secret
    // confidentiality — symbolized by PROVENANCE, not by distrust.
    policy: { trust: "TRUSTED", confidentiality: "no-model" },
    invariant: { violatedInvariant: false },
  } as ManduEvent;

  assert.ok(isManduEvent(e));
  assert.equal(e.policy?.confidentiality, "no-model");
});
