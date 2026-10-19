/**
 * net-denial-notice.test.ts — the net gate's notice and the refusal notice
 * (confidentiality plan 10 §11.8, "The net gate's notice", "Refused calls"):
 * built from the gate's decision, never from the request.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { gateNetToolUse, netBlockNotice } from "../../src/net-gate.js";
import { refusalNotice } from "../../src/path-denial-notice.js";
import { CLAUDE_CODE_GATE_SURFACE } from "../../src/gate-surface.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

test("netBlockNotice: one plain sentence per leg, the approvals hint only when the arbiter filed one, the rule id; never the arbiter's reason", () => {
  const session = netBlockNotice("high-session-egress-requires-approval", "HIGH SESSION (any-model): egress to 'leak.evil.test' … human approval required (§4).", { source: "rule", id: "egress:high-session" });
  // The session leg files no approval whatever its reason says (the arbiter's
  // sessionEgressDecision queues nothing): no Approvals hint, a new session instead.
  assert.equal(session, "mandu-net-gate: network use blocked, nothing was sent: this session has read a secret, and this request goes to a host that secret is not bound to; start a new session for work that needs it. (rule: egress:high-session)");
  assert.ok(!session.includes("evil.test"), "the arbiter's reason (which names the host) is not echoed");
  const sym = netBlockNotice("symbol-egress-requires-approval", "secret symbol (no-model) at unbound destination 'x.test' → human declassification required", { source: "rule", id: "egress:secret-unbound" });
  assert.match(sym, /masked value \(\$MDU placeholder\) that may not be sent where this tool sends it\. The user can allow it/);
  const tls = netBlockNotice("symbol-cannot-be-released-inside-this-tools-https-request", "…", { source: "fail-closed", id: "proxy:symbol-in-tls-tunnel" });
  assert.match(tls, /cannot put back inside this tool's HTTPS request/);
  const bound = netBlockNotice("symbol-egress-requires-approval", "17 symbols … fail closed", { source: "fail-closed", id: "proxy:net-gate-symbol-bound" });
  assert.match(bound, /Mandu could not check this request/, "a fail-closed leg says so");
  const down = netBlockNotice("symbol-egress-requires-approval", "arbiter unreachable — fail closed: ECONNREFUSED /run/x.sock", { source: "fail-closed", id: "proxy:arbiter-unreachable" });
  assert.match(down, /the Mandu service is not answering/);
  assert.ok(!down.includes("Approvals") && !down.includes("ECONNREFUSED"));
  const plainDeny = netBlockNotice("symbol-egress-requires-approval", "denied by rule", { source: "rule", id: "egress:x" });
  assert.ok(!plainDeny.includes("Approvals"), "no approval filed, no hint");
});

test("a blocked call's outcome carries the notice; a tool with no destination field gets the notice as its query, not the reason", async () => {
  const arbiter = new MockArbiter();
  (arbiter as unknown as { sessionEgressDecision: unknown }).sessionEgressDecision = async () => ({ allow: false, requiresApproval: true, reason: "HIGH SESSION: 'leak.evil.test' is unbound → approval required" });
  const fetch = await gateNetToolUse("WebFetch", { url: "https://leak.evil.test/x", prompt: "p" }, { arbiter, sessionKey: "s", netTools: CLAUDE_CODE_GATE_SURFACE.net });
  assert.equal(fetch.outcome?.decision, "block");
  assert.match(fetch.outcome!.notice!, /^mandu-net-gate: network use blocked, nothing was sent: this session has read a secret/);
  const search = await gateNetToolUse("WebSearch", { query: "acme q3" }, { arbiter, sessionKey: "s", netTools: CLAUDE_CODE_GATE_SURFACE.net });
  assert.equal((search.input as { query: string }).query, search.outcome!.notice);
  assert.ok(!(search.input as { query: string }).query.includes("evil.test"));
});

test("the session leg's notice when the arbiter ASKED the user (confidentiality.md §4, the human half): tell the user, make it again after the answer; a Block is final", () => {
  const asked = netBlockNotice("high-session-egress-requires-approval", "HIGH SESSION (any-model): … 'leak.evil.test' … → pending", { source: "rule", id: "session:high-unbound" }, true);
  assert.equal(asked, "mandu-net-gate: network use blocked, nothing was sent: this session has read a secret, and this request goes to a host that secret is not bound to, so Mandu stopped it and asked the user on Mandu's Approvals page (mandu dashboard). Tell the user, and make the request again after they answer: if they allowed it, it goes through once. (rule: session:high-unbound)");
  assert.ok(!asked.includes("evil.test"), "never the host the model wrote");
  const blocked = netBlockNotice("high-session-egress-requires-approval", "HIGH SESSION (any-model): … — human-denied (egr-4)", { source: "verdict", id: "verdict:egr-4" });
  assert.match(blocked, /the user blocked requests from this session to this host; do not retry it\./);
  assert.ok(!blocked.includes("Approvals"), "a Block asks nothing");
});

test("a session-leg refusal that filed a row goes to the ASKED sentinel and carries its id; one that did not stays on the blocked host", async () => {
  const arbiter = new MockArbiter();
  let id: string | undefined = "egr-7";
  (arbiter as unknown as { sessionEgressDecision: unknown }).sessionEgressDecision = async () => ({
    allow: false, requiresApproval: true, reason: "HIGH SESSION: unbound → pending", ruleRef: { source: "rule", id: "session:high-unbound" }, ...(id ? { approvalId: id } : {}),
  });
  const asked = await gateNetToolUse("WebFetch", { url: "https://leak.evil.test/x", prompt: "p" }, { arbiter, sessionKey: "s", netTools: CLAUDE_CODE_GATE_SURFACE.net });
  assert.equal(asked.outcome?.decision, "block");
  assert.equal(asked.outcome?.approvalId, "egr-7");
  assert.equal((asked.input as { url: string }).url, "https://asked.mandu.invalid/high-session-egress-requires-approval");
  assert.match(asked.outcome!.notice!, /asked the user on Mandu's Approvals page/);
  id = undefined;
  const final = await gateNetToolUse("WebFetch", { url: "https://leak.evil.test/x", prompt: "p" }, { arbiter, sessionKey: "s", netTools: CLAUDE_CODE_GATE_SURFACE.net });
  assert.equal(final.outcome?.approvalId, undefined);
  assert.equal((final.input as { url: string }).url, "https://blocked.mandu.invalid/high-session-egress-requires-approval");
  // an ALLOW after the human's Allow once passes byte-identical
  (arbiter as unknown as { sessionEgressDecision: unknown }).sessionEgressDecision = async () => ({ allow: true, requiresApproval: false, reason: "human-approved (egr-7, once)", ruleRef: { source: "verdict", id: "verdict:egr-7" } });
  const passed = await gateNetToolUse("WebFetch", { url: "https://leak.evil.test/x", prompt: "p" }, { arbiter, sessionKey: "s", netTools: CLAUDE_CODE_GATE_SURFACE.net });
  assert.equal(passed.outcome, undefined);
  assert.deepEqual(passed.input, { url: "https://leak.evil.test/x", prompt: "p" });
});

test("refusalNotice: the refusal's words under one prefix; a gate notice is kept as it is", () => {
  assert.equal(refusalNotice("apply_patch touches /v/api.env, nothing was applied"), "mandu: refused, nothing ran: apply_patch touches /v/api.env, nothing was applied");
  assert.equal(refusalNotice("mandu-net-gate: network use blocked, nothing was sent: x."), "mandu-net-gate: network use blocked, nothing was sent: x.");
});
