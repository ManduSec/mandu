/**
 * home-js-agent-path — dashboard.md §4.25b *Where it went*: a secret card
 * draws its path (one row a fact, each marked on your computer, at the AI
 * or, for a host Mandu sent the real value to, off your computer, an
 * unknown side as on your computer; a time opening its step), then an earlier leak the kept scan found,
 * with the Scan page one click away; an unchecked record's secrets are drawn
 * under "What this session's record says", tagged "Unchecked record", with
 * their path and no line, count or real value. Text is text, never markup.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, T, load, tick } from "./home-js-fixtures.js";

const URL1 = "http://127.0.0.1:4500/mandu/agents/s1";
const C = (text: string) => ({ kind: "code", text });
const PATH = [
  { side: "computer", label: "Kept in", parts: [C("~/app/.env")], tone: "plain" },
  { side: "computer", label: "How it came in", parts: [T("Ran "), C("DEBUG=1 sh <b>sync</b>.sh"), T(", at "), { kind: "time", text: "2026-09-25T10:00:05.000Z", step: "tool:c2" }], tone: "plain" },
  { side: "ai", label: "The AI got", parts: [T("its masked version, in 5 requests")], tone: "good" },
  { side: "off", label: "Sent with its real value to", parts: [C("api.stripe.com")], tone: "plain" },
  { side: "computer", label: "Stopped on its way to", parts: [C("paste.example")], tone: "good" },
  // A side an older or newer server names that this page does not know.
  { side: "moon", label: "Waiting for your OK", parts: [T("1 step")], tone: "warn" },
];
const EARLIER = [T("Without Mandu, OpenClaw gave the AI its real value on "), { kind: "time", text: "2026-09-24T00:37:00.000Z", clock: true }, T(": "), C("DEBUG=1 sh sync.sh"), T(" printed it.")];
const CARD = {
  what: [C("ORDERHUB_PASSPHRASE"), T(" in "), C("~/app/.env")], level: "No AI", saw: "masked", file: "~/app/.env",
  lines: [{ tone: "good", parts: [T("The AI got only its masked version, never the real value.")] }],
  path: PATH, earlier: EARLIER, scanItem: "f2",
};

test("a card's path: one row a fact, its side said, the AI's rows set in; the time opens its step", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...AGENT, secrets: { mode: "secrets", flagged: false, more: 0, counts: { masked: 1, early: 0 }, secrets: [CARD] } } } });
  await tick();
  const card = doc.querySelector("#agent-secrets .secret-card") as any;
  assert.equal(card.querySelector(".secret-path-head").textContent, "Where it went");
  const rows = [...card.querySelectorAll(".secret-path .path-node")] as any[];
  assert.deepEqual(rows.map((r) => [r.querySelector(".path-label").textContent, r.querySelector(".path-side").textContent, r.classList.contains("ai")]), [
    ["Kept in", "on your computer", false],
    ["How it came in", "on your computer", false],
    ["The AI got", "at the AI", true],
    ["Sent with its real value to", "off your computer", false],
    ["Stopped on its way to", "on your computer", false],
    ["Waiting for your OK", "on your computer", false],
  ]);
  assert.deepEqual(rows.map((r) => [...r.classList].filter((c: string) => c !== "path-node")), [
    ["computer", "plain"], ["computer", "plain"], ["ai", "good"], ["off", "plain"], ["computer", "good"], ["computer", "warn"],
  ], "the send keeps the computer rows' indent and dot; an unknown side draws as the computer's");
  assert.match(rows[1].textContent, /Ran DEBUG=1 sh <b>sync<\/b>\.sh, at \d{2}:\d{2}/, "the command is text, never markup");
  assert.equal(card.querySelector(".secret-path b"), null);
  const link = rows[1].querySelector(".step-link");
  assert.ok(link, "the time is a link");
  assert.equal(link.dataset.opens, "tool:c2");
  // The earlier leak: its line, red, with Scan one click away.
  const earlier = card.querySelector(".secret-earlier");
  assert.equal(earlier.getAttribute("role"), "note");
  assert.match(earlier.textContent, /^Without Mandu, OpenClaw gave the AI its real value on .+: DEBUG=1 sh sync\.sh printed it\. See it in Scan$/);
  const scan = earlier.querySelector("a.secret-earlier-link");
  assert.equal(scan.getAttribute("href"), "/mandu/scan?item=f2", "the Scan page at the finding's row (§4.25ai *Where the real value is now*)");
  assert.equal(scan.dataset.pageLink, "scan");
  assert.equal(scan.dataset.land, "item:f2");
  // No unchecked block on a checked record.
  assert.equal(doc.getElementById("agent-recorded").hidden, true);
});

test("a card with no path and no earlier leak draws neither", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...AGENT, secrets: { mode: "secrets", flagged: false, more: 0, counts: { masked: 1, early: 0 }, secrets: [{ ...CARD, path: undefined, earlier: undefined }] } } } });
  await tick();
  const card = doc.querySelector("#agent-secrets .secret-card") as any;
  assert.equal(card.querySelector(".secret-path"), null);
  assert.equal(card.querySelector(".secret-path-head"), null);
  assert.equal(card.querySelector(".secret-earlier"), null);
});

test("an unchecked record: its secrets under \"What this session's record says\", tagged, with the path and no real value", async () => {
  const recorded = [{ what: CARD.what, level: "No AI", file: "~/app/.env", path: PATH.slice(0, 3), earlier: EARLIER, scanItem: "../x" }];
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...AGENT, secrets: { mode: "secrets", flagged: false, more: 0, counts: { masked: 0, early: 0 }, secrets: [], unchecked: true, recorded } } } });
  await tick();
  assert.match(doc.getElementById("agent-secrets-intro").textContent, /^Mandu could not check this session's record/);
  const block = doc.getElementById("agent-recorded");
  assert.equal(block.hidden, false);
  assert.equal(block.querySelector(".recorded-title").textContent, "What this session's record says");
  assert.match(block.textContent, /not what Mandu can vouch for/);
  const card = block.querySelector(".secret-card.recorded") as any;
  assert.deepEqual([...card.querySelectorAll(".secret-head .tag")].map((x: any) => x.textContent), ["No AI", "Unchecked record"]);
  assert.equal(card.querySelectorAll(".path-node").length, 3);
  assert.ok(card.querySelector(".secret-earlier"));
  assert.equal(card.querySelector("a.secret-earlier-link").getAttribute("href"), "/mandu/scan", "an id of another shape: the page itself");
  assert.equal(card.querySelector("button.secret-reveal"), null, "no real value to show");
  assert.equal(card.querySelector(".secret-lines"), null, "no line: nothing here is a checked claim");
  assert.equal(card.querySelector("a.secret-rule-link").getAttribute("href"), "/mandu/rules?file=~/app/.env");
  // The checked cards' list stays empty.
  assert.equal(doc.querySelectorAll("#agent-secrets .secret-card").length, 0);
});
