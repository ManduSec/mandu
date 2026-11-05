/**
 * browser-story — "On web pages" (dashboard.md §4.25af) from the DevTools
 * relay's events and the egress proxy's model-service sends: secret names
 * only, never a value or a placeholder; null for a session with no browser.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { browserStory, refusalCause, UNKNOWN_SECRET } from "../../../src/view-model/browser-story.js";
import type { ManduEvent } from "../../../src/event-model.js";

const KEY = "$MDU:nomodel_Read[eeda].STRIPE_SECRET_KEY";
const WH = "$MDU:nomodel_Read[eeda].WEBHOOK_SIGNING_SECRET";
const ev = (kind: string, fields: Record<string, unknown>): ManduEvent => ({ kind, sessionId: "s", id: Math.random().toString(36), ts: "2026-10-18T12:00:00Z", ...fields }) as unknown as ManduEvent;

test("no browser_action event: no story (a session without a browser)", () => {
  assert.equal(browserStory([]), null);
  assert.equal(browserStory([ev("net_action", { action: "forwarded", destination: "api.typesafe.ai", keptOpaque: [KEY] })]), null);
});

test("reads, typing both ways, stopped commands, withheld reads and the model services, by name", () => {
  const s = browserStory([
    ev("browser_action", { action: "masked", method: "Runtime.evaluate", symbols: [KEY] }),
    ev("browser_action", { action: "masked", method: "Runtime.evaluate", symbols: [KEY, WH] }),
    ev("browser_action", { action: "released", method: "Input.insertText", page: "localhost:41237", symbols: [KEY] }),
    ev("browser_action", { action: "refused", method: "Input.insertText", symbols: [KEY], reason: "not bound" }),
    ev("browser_action", { action: "refused", method: "Input.insertText", symbols: [KEY], reason: "not bound" }),
    ev("browser_action", { action: "blocked", method: "Page.captureScreenshot", reason: "pixels" }),
    ev("browser_action", { action: "blocked", method: "Page.captureScreenshot", reason: "pixels" }),
    ev("browser_action", { action: "blocked", method: "Storage.getCookies", reason: "cookies" }),
    ev("browser_action", { action: "withheld", method: "Network.getResponseBody", reason: "base64" }),
    ev("net_action", { action: "forwarded", destination: "api.typesafe.ai", keptOpaque: [KEY] }),
    ev("net_action", { action: "forwarded", destination: "api.typesafe.ai", keptOpaque: [WH, KEY] }),
    ev("net_action", { action: "forwarded", destination: "openrouter.ai", keptOpaque: [KEY] }),
    ev("net_action", { action: "forwarded", destination: "pypi.org" }),
  ])!;
  assert.equal(s.maskedReads, 2);
  assert.deepEqual(s.secrets, ["STRIPE_SECRET_KEY", "WEBHOOK_SIGNING_SECRET"]);
  assert.deepEqual(s.typed, [
    { secret: "STRIPE_SECRET_KEY", site: "localhost:41237", outcome: "filled", why: null, count: 1 },
    { secret: "STRIPE_SECRET_KEY", site: null, outcome: "refused", why: null, count: 2 },
  ]);
  assert.deepEqual(s.stopped, [{ what: "screenshot", count: 2 }, { what: "cookie read", count: 1 }]);
  assert.equal(s.withheld, 1);
  assert.deepEqual(s.services, [
    { host: "api.typesafe.ai", requests: 2, masked: ["STRIPE_SECRET_KEY", "WEBHOOK_SIGNING_SECRET"] },
    { host: "openrouter.ai", requests: 1, masked: ["STRIPE_SECRET_KEY"] },
  ], "only hosts a request reached with secrets left masked");
  assert.ok(!JSON.stringify(s).includes("$MDU:"), "no placeholder on the page");
});

test("a placeholder without a field name reads as 'a secret'; an unknown command as a browser command", () => {
  const s = browserStory([
    ev("browser_action", { action: "masked", symbols: ["$MDU:nomodel_Env[ab12]"] }),
    ev("browser_action", { action: "blocked", method: "Something.new" }),
    ev("browser_action", { action: "refused", method: "Input.insertText" }),
  ])!;
  assert.deepEqual(s.secrets, ["a secret"]);
  assert.deepEqual(s.stopped, [{ what: "browser command", count: 1 }]);
  assert.deepEqual(s.typed, [{ secret: "a secret", site: null, outcome: "refused", why: null, count: 1 }]);
});

test("a placeholder that names nothing (the relay's `unknown placeholder`): its own line, counted, never the name it spelled", () => {
  const madeUp = "$MDU:nomodel_Read[eedb].STRIPE_SECRET_KEY";
  const s = browserStory([
    ev("browser_action", { action: "refused", method: "Input.insertText", symbols: [madeUp], unknown: [madeUp], reason: "unknown placeholder" }),
    ev("browser_action", { action: "refused", method: "Input.dispatchKeyEvent", symbols: [madeUp], reason: "unknown placeholder" }),
    ev("browser_action", { action: "refused", method: "Input.insertText", symbols: [KEY], reason: "not bound" }),
    ev("browser_action", { action: "released", method: "Input.insertText", page: "vercel.com", symbols: [KEY] }),
  ])!;
  assert.deepEqual(s.typed, [
    { secret: UNKNOWN_SECRET, site: null, outcome: "unknown", why: null, count: 2 },
    { secret: "STRIPE_SECRET_KEY", site: null, outcome: "refused", why: null, count: 1 },
    { secret: "STRIPE_SECRET_KEY", site: "vercel.com", outcome: "filled", why: null, count: 1 },
  ]);
  assert.ok(!JSON.stringify(s).includes("$MDU:"), "no placeholder on the page");
});

/** The relay's refusal reasons, word for word (cdp-relay release.ts). */
const PREFIX = "Mandu: the placeholder was not typed: ";
const LEAVE = "leave it out (name it in plain words if the text needs it, never its placeholder) and go on";
const REASON = {
  notAllowed: (host: string) => `${PREFIX}${KEY} may not go to ${host} (human-denied); ${LEAVE}`,
  needsApproval: (host: string) => `${PREFIX}${host} may not have ${KEY} without the person's approval in Mandu; ${LEAVE}; ask the person only if they asked for it to go there, then type it again`,
  declined: `${PREFIX}you chose to go on without ${KEY}`,
  failed: [
    `${PREFIX}the release gate could not be asked (arbiter socket closed)`,
    `${PREFIX}the value could not be read (timeout)`,
    `${PREFIX}it could not be looked up (ECONNREFUSED)`,
    `${PREFIX}Chrome did not name the page (Target closed)`,
    `${PREFIX}Chrome named no main frame`,
    `${PREFIX}the page has no origin a secret can be released to`,
    `${PREFIX}a data: page has no origin a secret can be released to`,
  ],
};
const refused = (reason: string, symbols = [KEY]) => ev("browser_action", { action: "refused", method: "Input.insertText", symbols, reason });

test("a refusal says its cause, read from the relay's words: not allowed and needs your OK with their site, declined and could not check without one", () => {
  assert.deepEqual(refusalCause(REASON.notAllowed("evil.example")), { why: "not-allowed", site: "evil.example" });
  assert.deepEqual(refusalCause(REASON.needsApproval("forms.example")), { why: "needs-approval", site: "forms.example" });
  assert.deepEqual(refusalCause(REASON.needsApproval("localhost:41237")), { why: "needs-approval", site: "localhost:41237" });
  assert.deepEqual(refusalCause(REASON.declined), { why: "declined", site: null });
  for (const r of REASON.failed) assert.deepEqual(refusalCause(r), { why: "failed", site: null }, r);
  for (const r of ["not bound", "unknown placeholder", "", undefined, 42, `${PREFIX}something new`, `the release gate could not be asked (x)`]) {
    assert.deepEqual(refusalCause(r), { why: null, site: null }, String(r));
  }
});

test("a refusal's host is kept only when it is a host name: a space, a slash or a $ keeps the cause and drops the site", () => {
  for (const bad of ["evil example", "evil.example/collect", "$MDU:x", "evil.example:99999999", ""]) {
    assert.deepEqual(refusalCause(REASON.notAllowed(bad)), { why: "not-allowed", site: null }, bad);
    assert.deepEqual(refusalCause(REASON.needsApproval(bad)), { why: "needs-approval", site: null }, bad);
  }
  // A host cannot spell another cause: each is anchored after the prefix.
  assert.deepEqual(refusalCause(REASON.notAllowed("could.not.be.asked")), { why: "not-allowed", site: "could.not.be.asked" });
});

test("the story keeps each cause and its site, one line per cause, and never the reason or a placeholder", () => {
  const s = browserStory([
    refused(REASON.notAllowed("evil.example")),
    refused(REASON.notAllowed("evil.example")),
    refused(REASON.needsApproval("forms.example")),
    refused(REASON.declined),
    refused(REASON.failed[0]!),
    refused(REASON.failed[2]!),
    refused(REASON.notAllowed("evil example")),
    refused("not bound"),
  ])!;
  assert.deepEqual(s.typed, [
    { secret: "STRIPE_SECRET_KEY", site: "evil.example", outcome: "refused", why: "not-allowed", count: 2 },
    { secret: "STRIPE_SECRET_KEY", site: "forms.example", outcome: "refused", why: "needs-approval", count: 1 },
    { secret: "STRIPE_SECRET_KEY", site: null, outcome: "refused", why: "declined", count: 1 },
    { secret: "STRIPE_SECRET_KEY", site: null, outcome: "refused", why: "failed", count: 2 },
    { secret: "STRIPE_SECRET_KEY", site: null, outcome: "refused", why: "not-allowed", count: 1 },
    { secret: "STRIPE_SECRET_KEY", site: null, outcome: "refused", why: null, count: 1 },
  ]);
  const json = JSON.stringify(s);
  assert.ok(!json.includes("$MDU:"), "no placeholder anywhere in the data");
  for (const words of ["may not", "the person's approval", "chose", "could not", "Mandu:", "human-denied"]) assert.ok(!json.includes(words), `no reason text: ${words}`);
});
