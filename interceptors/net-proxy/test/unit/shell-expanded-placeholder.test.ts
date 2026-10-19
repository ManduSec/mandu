/**
 * shell-expanded-placeholder.test — a request carrying a secret's placeholder
 * whose `$MDU` a shell expanded to nothing is refused with how to quote it,
 * never filled in (src/egress.ts; confidentiality.md §7, "A placeholder the
 * agent's shell would expand").
 *
 * A script the agent wrote with `curl -H "Authorization: Bearer $MDU:…"`
 * sends `Bearer :nomodel_Read[de31].STRIPE_KEY`: no value, no placeholder,
 * and the service answered 401 with no hint. Pinned: the forms each shell
 * leaves (bash/dash/sh, and zsh's modifier forms), the places a request
 * carries them, the arbiter's table check (look-alike text is never
 * refused), no release and no approval asked, and that an arbiter without
 * the op, or one that fails, leaves the request to the gates as before.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { gateRequest, refusalKindOf, strippedPlaceholderCandidates, SHELL_EXPANDED_RULE } from "../../src/egress.js";
import { MockArbiter } from "../../src/arbiter-client.js";

const P = "$MDU:nomodel_Read[de31].STRIPE_KEY";
const A = "$MDU:anymodel_Read[7b21]";
const L = "$MDU:localmodel_Env[c4d8].GITHUB_TOKEN";
const req = (o: { url?: string; headers?: Record<string, string>; body?: string }) => ({
  method: "POST", destinationHost: "api.stripe.com", url: o.url ?? "http://api.stripe.com/v1/customers",
  headers: o.headers ?? {}, bodyText: o.body ?? "",
});

test("candidates: each shell's leftover maps back to the placeholder name; a whole placeholder is not one", () => {
  // bash, dash, sh (and zsh for nomodel_): `$MDU` gone, the `:` kept
  const c = strippedPlaceholderCandidates(req({ headers: { authorization: `Bearer ${P.slice(4)}` } }));
  assert.deepEqual([...c], [[P, ":nomodel_Read[de31].STRIPE_KEY"]]);
  // zsh: `$MDU:a…` / `$MDU:l…` read as modifiers, `:a` / `:l` gone too
  const z = strippedPlaceholderCandidates(req({ body: `k=nymodel_Read[7b21]&t=ocalmodel_Env[c4d8].GITHUB_TOKEN` }));
  assert.deepEqual([...z.keys()], [A, L]);
  // a whole placeholder (escaped or not) is the per-symbol gate's, not this
  assert.equal(strippedPlaceholderCandidates(req({ body: `${P} \\${A} "${L}"` })).size, 0);
  // inside a word, after a letter: still the shell's leftover (`x$MDU:…`)
  assert.deepEqual([...strippedPlaceholderCandidates(req({ body: `tok${P.slice(4)}` })).keys()], [P]);
  // look-alike words without the marker's shape are no candidate
  assert.equal(strippedPlaceholderCandidates(req({ body: "anymodel_x and localmodel_y and :nomodel_z" })).size, 0);
});

test("candidates: URL (and percent-decoded), body (and decoded), every header, a Basic credential's pair", () => {
  const basic = `Basic ${Buffer.from(`${P.slice(4)}:`).toString("base64")}`;
  for (const r of [
    req({ url: `http://api.stripe.com/v1/x?key=${P.slice(4)}` }),
    req({ url: `http://api.stripe.com/v1/x?key=${encodeURIComponent(P.slice(4))}` }),
    req({ body: `amount=1&note=${encodeURIComponent(P.slice(4))}` }),
    req({ body: JSON.stringify({ key: P.slice(4) }) }),
    req({ headers: { "x-api-key": P.slice(4) } }),
    req({ headers: { authorization: basic } }),
  ]) {
    assert.deepEqual([...strippedPlaceholderCandidates(r).keys()], [P], JSON.stringify(r));
  }
});

test("gateRequest: a known stripped placeholder is refused with how to quote it; nothing is released and nothing is asked", async () => {
  const arbiter = new MockArbiter({ knownSecretSymbols: [P], values: { [P]: "sk_live_x" }, decisionFn: () => ({ allow: true, reason: "bound" }) });
  const r = await gateRequest({ ...req({ headers: { authorization: `Bearer ${P.slice(4)}` } }), arbiter, sessionKey: "s1" });
  assert.equal(r.action, "block");
  if (r.action !== "block") return;
  assert.match(r.reason, /carried :nomodel_Read\[de31\]\.STRIPE_KEY, which is the placeholder \$MDU:nomodel_Read\[de31\]\.STRIPE_KEY after a shell expanded "\$MDU" to nothing/);
  assert.match(r.reason, /Put the placeholder in single quotes \('\$MDU:nomodel_Read\[de31\]\.STRIPE_KEY'\)/);
  assert.ok(r.reason.endsWith(`[${SHELL_EXPANDED_RULE}]`));
  assert.deepEqual(r.withheld.map((w) => [w.symbol, w.requiresApproval, w.ruleRef?.id]), [[P, false, SHELL_EXPANDED_RULE]]);
  assert.equal(refusalKindOf(r.reason), "shell-expanded");
  assert.equal(arbiter.decisionCalls.length, 0, "no release is decided, so no approval row is filed");
  assert.deepEqual(arbiter.strippedCalls, [{ candidates: [P], sessionKey: "s1" }]);
  // the request is refused whole, whatever else it carries
  const mixed = await gateRequest({ ...req({ headers: { authorization: `Bearer ${P}` }, body: `note=${P.slice(4)}` }), arbiter });
  assert.equal(mixed.action, "block");
});

test("gateRequest: text the table does not know, an arbiter without the op, or one that fails: the request goes to the gates as before", async () => {
  const look = await gateRequest({ ...req({ body: "id=:nomodel_Read[0000].X" }), arbiter: new MockArbiter({ knownSecretSymbols: [P] }) });
  assert.deepEqual(look, { action: "forward" }, "a look-alike the table does not hold is not refused");
  const failing = new MockArbiter({ knownSecretSymbols: [P], failStripped: true });
  assert.deepEqual(await gateRequest({ ...req({ body: `k=${P.slice(4)}` }), arbiter: failing }), { action: "forward" });
  const old = new MockArbiter({ knownSecretSymbols: [P] });
  (old as { strippedPlaceholders?: unknown }).strippedPlaceholders = undefined;
  assert.deepEqual(await gateRequest({ ...req({ body: `k=${P.slice(4)}` }), arbiter: old }), { action: "forward" });
  // no candidate: no ask at all
  const quiet = new MockArbiter({ knownSecretSymbols: [P] });
  await gateRequest({ ...req({ body: "plain" }), arbiter: quiet });
  assert.equal(quiet.strippedCalls.length, 0);
});
