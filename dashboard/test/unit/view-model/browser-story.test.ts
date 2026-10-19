/**
 * browser-story — "On web pages" (dashboard.md §4.25af) from the DevTools
 * relay's events and the egress proxy's model-service sends: secret names
 * only, never a value or a placeholder; null for a session with no browser.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { browserStory, UNKNOWN_SECRET } from "../../../src/view-model/browser-story.js";
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
    { secret: "STRIPE_SECRET_KEY", site: "localhost:41237", outcome: "filled", count: 1 },
    { secret: "STRIPE_SECRET_KEY", site: null, outcome: "refused", count: 2 },
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
  assert.deepEqual(s.typed, [{ secret: "a secret", site: null, outcome: "refused", count: 1 }]);
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
    { secret: UNKNOWN_SECRET, site: null, outcome: "unknown", count: 2 },
    { secret: "STRIPE_SECRET_KEY", site: null, outcome: "refused", count: 1 },
    { secret: "STRIPE_SECRET_KEY", site: "vercel.com", outcome: "filled", count: 1 },
  ]);
  assert.ok(!JSON.stringify(s).includes("$MDU:"), "no placeholder on the page");
});
