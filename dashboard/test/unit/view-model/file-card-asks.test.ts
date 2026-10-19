/**
 * file-card-asks.test — a FILE's card (egress-hold.md "One card per file",
 * 2026-10-19; dashboard.md §4.25e): a request carrying several placeholders
 * of one registered file asks on ONE card keyed on the file's base symbol,
 * and the arbiter attaches `fileValues` (how many of the file's values the
 * answer covers) at read time. The card says "the secrets in <file>" and
 * that one answer covers all of them; a lone key's card still names its key;
 * a base symbol with no `fileValues` (a document's whole-file placeholder)
 * keeps "a secret from <file>". Provenance only: never a value.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import type { PolicySnapshot, VerdictEntry } from "../../../src/policy-model.js";

const BARE: PolicySnapshot = { specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__" };
const EXT = { posture: { integrity: false, confidentiality: true }, usage: { rules: [], sensitivePaths: [] } };
const STMT = "/home/u/inbox/bank/statement-2026-09.md";
const BASE = "$MDU:nomodel_Read[5a1c]";

function row(over: Partial<VerdictEntry> = {}): VerdictEntry {
  return {
    id: "egr-3", symbol: BASE, destination: "parktax.test", status: "pending",
    reason: "secret symbol (no-model) at unbound destination 'parktax.test' → human declassification required", count: 7, firstSeen: 10, lastSeen: 20,
    sessions: ["s-1"], source: { tool: "Read", origin: STMT },
    ...over,
  } as VerdictEntry;
}
const text = (parts: { text: string }[]): string => parts.map((p) => p.text).join("");
const card = (r: VerdictEntry) => toPolicyPanelViewModel({ ...BARE, ...EXT, verdicts: [r] } as PolicySnapshot).queue[0]!;

test("a file's card names the file and says one answer covers all its values", () => {
  const c = card(row({ fileValues: 7 } as Partial<VerdictEntry>));
  assert.equal(c.fileValues, 7);
  assert.equal(text(c.words.sentence), `The agent wants to send the secrets in ${STMT} to parktax.test`);
  assert.match(String(c.words.why), /^One answer covers all 7 of them\. Mandu masked them, so the AI never read them\. Sending them would show the real secrets to parktax\.test\.$/);
  assert.ok(!/\$MDU/.test(text(c.words.sentence) + String(c.words.why)), "no placeholder in the words");
});

test("a base symbol with no fileValues (a whole-file placeholder) and a lone key keep their words", () => {
  const whole = card(row());
  assert.equal(whole.fileValues, undefined);
  assert.equal(text(whole.words.sentence), `The agent wants to send a secret from ${STMT} to parktax.test`);
  const lone = card(row({ symbol: `${BASE}.STRIPE_KEY`, source: { tool: "Read", origin: "/home/u/proj/.env" }, fileValues: 2 } as Partial<VerdictEntry>));
  assert.equal(text(lone.words.sentence), "The agent wants to send your secret STRIPE_KEY to parktax.test", "a key's own card names the key");
  // a malformed count is no count
  const odd = card(row({ fileValues: 1.5 } as Partial<VerdictEntry>));
  assert.equal(odd.fileValues, undefined);
});
