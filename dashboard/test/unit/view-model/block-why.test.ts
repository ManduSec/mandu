/**
 * block-why.test — why Mandu blocked or held a step, in the product's
 * words, from the rule the step's event recorded (dashboard.md §4.25b, "A
 * block says why"; view-model/block-why.ts). Contracts:
 *   - a known rule gives its sentence, with the recorded host as code and
 *     the secret counted from the items the send carried;
 *   - no rule, an unknown id, an allowing rule, an integrity-only id and
 *     `egress:secret-bound-approval` give no line (the step reads as before);
 *   - a standing answer of the person's (a verdict) is said only of a block;
 *   - a line never carries a token, a value, or the developer's words;
 *   - `checkOutcome` reads a check as the inspector draws its line (§4.2f):
 *     the recorded decision, else the block words in its recorded text.
 *
 * Axes: none (pure presentation; the rule ids are the arbiter's catalog).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { blockWhy, checkOutcome, WHY_RULE_IDS } from "../../../src/view-model/block-why.js";

const words = (parts: { kind: string; text: string }[] | null) => (parts ? parts.map((p) => (p.kind === "code" ? `\`${p.text}\`` : p.text)).join("") : null);
const rule = (id: string) => ({ source: "rule", id });

test("a secret at a host no rule lets it go to: the host as code, how a secret may leave, and the count it carried", () => {
  const one = blockWhy(rule("egress:secret-unbound"), { outcome: "blocked", host: "api.stripe.com", carried: 1 });
  assert.equal(words(one), "No rule lets this secret go to `api.stripe.com`. Mandu sends a secret only where a rule lets it go, or with your OK.");
  assert.deepEqual(one!.filter((p) => p.kind === "code").map((p) => p.text), ["api.stripe.com"], "the host is code, nothing else is");
  assert.equal(words(blockWhy(rule("egress:secret-unbound"), { outcome: "blocked", host: "paste.example", carried: 2 })),
    "No rule lets one of these secrets go to `paste.example`. Mandu sends a secret only where a rule lets it go, or with your OK.");
  assert.equal(words(blockWhy(rule("egress:secret-unbound"), { outcome: "waiting" })),
    "No rule lets the secret it carried go there. Mandu sends a secret only where a rule lets it go, or with your OK.");
});

test("each worded rule says what its branch decides, in the product's words", () => {
  const w = (id: string, host?: string) => words(blockWhy(rule(id), { outcome: "blocked", ...(host ? { host } : {}) }));
  assert.equal(w("session:high-unbound", "evil.example"), "This session read a secret, and `evil.example` is not a place it may go. The AI could pass a secret on in its own words, which no placeholder marks.");
  assert.equal(w("session:high-unbound"), "This session read a secret, and this place is not a place it may go. The AI could pass a secret on in its own words, which no placeholder marks.");
  assert.equal(w("egress:secret-https-only"), "Mandu fills this secret in only in requests it knows are HTTPS, and this one was not.");
  assert.equal(w("egress:secret-wire-position"), "Mandu fills this login secret in only in a request's Authorization header, and could not confirm that is the only place this request carried it.");
  assert.equal(w("egress:secret-unknown-destination"), "Mandu could not tell where this request was going. Mandu sends a secret only where a rule lets it go, or with your OK.");
  assert.equal(w("egress:user-rule-block"), "One of your rules blocks sending this data there.");
  assert.equal(w("exec:symbol-in-command"), "The command would run a placeholder as code, and Mandu never runs one.");
  assert.equal(w("exec:tainted-program-text"), "It runs code downloaded from the internet, which can do anything the site that served it wants.");
  assert.equal(w("fs:default-deny"), "The file is outside the folders this agent works in, so Mandu asks first.");
  assert.equal(w("fs:sensitive-path"), "Files like this hold keys and passwords, so Mandu asks before the AI can use one.");
  assert.equal(w("proxy:arbiter-unreachable"), "Mandu's service did not answer, so Mandu blocked it to be safe.");
  // Every worded id gives a line, a block or a wait alike.
  for (const id of WHY_RULE_IDS) {
    for (const outcome of ["blocked", "waiting"] as const) {
      const parts = blockWhy({ source: "fail-closed", id }, { outcome, host: "h.example", carried: 1 });
      assert.ok(parts && parts.length > 0, `${id} (${outcome}) has words`);
    }
  }
});

test("no rule, an unknown id, an allowing rule, an integrity-only id or an ambiguous one: no line", () => {
  const ctx = { outcome: "blocked" as const, host: "api.example", carried: 1 };
  assert.equal(blockWhy(null, ctx), null);
  assert.equal(blockWhy(undefined, ctx), null);
  assert.equal(blockWhy({ source: "rule", id: undefined as unknown as string }, ctx), null);
  for (const id of [
    "egress:secret-bound-trusted", "egress:trusted-destination", "egress:user-rule-allow", "exec:no-symbol-in-command",
    "fs:workspace-root", "session:high-bound-release", "egress:unknown-symbol",
    "egress:symbol-as-command", "egress:untrusted-destination", "egress:unknown-destination", "session:high-tainted-bound",
    "egress:secret-bound-approval", "egress:secret-issuer", "exec.symbol-in-command", "tool:refused", "toString", "__proto__", "",
  ]) assert.equal(blockWhy(rule(id), ctx), null, id);
});

test("a standing answer of yours: said of a block, never of a wait", () => {
  assert.equal(words(blockWhy({ source: "verdict", id: "verdict:egr-7" }, { outcome: "blocked" })), "An answer you gave earlier blocks this.");
  assert.equal(blockWhy({ source: "verdict", id: "verdict:egr-7" }, { outcome: "waiting" }), null);
});

test("never a token, a value or the developer's words", () => {
  for (const id of WHY_RULE_IDS) {
    const all = JSON.stringify(blockWhy(rule(id), { outcome: "blocked", host: "api.example", carried: 1 }));
    assert.doesNotMatch(all, /\$MDU:|symbol|egress|binding|bound|AgentView|HumanView|arbiter|declassif|fail-closed|T-LLM/i, `${id}: ${all}`);
  }
});

test("checkOutcome: a check's decision as its line draws it: the recorded usage first, else the block words in its text", () => {
  assert.equal(checkOutcome("deny", "exec_action"), "blocked");
  assert.equal(checkOutcome("needs_approval", "net_action · blocked x.example"), "waiting", "a hold is a wait, whatever the text says");
  assert.equal(checkOutcome("allow", "net_action · blocked x.example"), null, "an allowed check never gets a why");
  for (const text of ["BLOCKED → exit 77", "blocked", "denied", "Mandu refused the connection", "rejected"]) {
    assert.equal(checkOutcome(null, text), "blocked", text);
    assert.equal(checkOutcome(undefined, text), "blocked", text);
  }
  for (const text of ["forwarded", "tunneled", "ALLOW (AgentShell)", "exec_action", "", null]) assert.equal(checkOutcome(null, text), null, String(text));
});
