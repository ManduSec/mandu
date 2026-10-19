/**
 * home-js-send-without.test — "Send without it" on the product's Approvals
 * card (dashboard.md §4.34 "Send without it", confidentiality.md §4,
 * 2026-10-17). Mandu-new.
 *
 *   - a card whose answers the server lists with `strip` draws the button
 *     (between Always allow and Block) and the cell that says what it does;
 *     a click posts `send-without` for that card;
 *   - a card the server does not offer it on (a program's send, a card from
 *     an older server listing no answers) never draws it;
 *   - Answered earlier says what happened ("Sent without it").
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { ASK, home, load, tick } from "./home-js-fixtures.js";

const APPROVALS_URL = "http://127.0.0.1:4500/mandu/approvals";
const STRIP_ASK = {
  ...ASK,
  id: "egr-9",
  actions: [
    { approve: true, label: "Allow once", scope: "once" },
    { approve: true, label: "Always allow" },
    { approve: false, label: "Send without it", scope: "once", strip: true },
    { approve: false, label: "Block" },
  ],
};

const verbsOf = (doc: any, id: string): string[] =>
  [...doc.querySelectorAll(`#approvals-waiting .ask[data-id="${id}"] .ask-actions button`)].map((b: any) => b.textContent);

test("an offered card draws Send without it and its cell; a click posts send-without", async () => {
  const { doc, calls } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [STRIP_ASK] }) });
  await tick();
  assert.deepEqual(verbsOf(doc, "egr-9"), ["Allow once", "Always allow", "Send without it", "Block"]);
  assert.equal(doc.querySelectorAll('#approvals-waiting .ask[data-id="egr-9"] .ask-detail > div').length, 3, "the three cells stay three");
  const note = doc.querySelector('#approvals-waiting .ask[data-id="egr-9"] .ask-without');
  assert.ok(note, "the card says what the answer does");
  assert.match(note.textContent, /^If you click Send without it: /);
  assert.match(note.textContent, /\[hidden by Mandu\] where the secret was/);
  assert.match(note.textContent, /The secret is not sent/);

  const btn = [...doc.querySelectorAll('#approvals-waiting .ask[data-id="egr-9"] .ask-actions button')].find((b: any) => b.textContent === "Send without it") as any;
  btn.click();
  await tick();
  const posted = calls.filter((c) => c.method === "POST").map((c) => c.url);
  assert.ok(posted.some((u) => u.endsWith("/api/egress/approvals/egr-9/send-without")), posted.join(", "));
  assert.ok(!posted.some((u) => /\/egr-9\/(deny|approve-once)$/.test(u)), "never the other verbs");
});

test("not offered: a card without the answer, and an older server's card listing no answers, never draw it", async () => {
  const older = { ...ASK, id: "egr-3", actions: [] };
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [ASK, older] }) });
  await tick();
  assert.ok(!verbsOf(doc, "egr-1").includes("Send without it"));
  assert.deepEqual(verbsOf(doc, "egr-3"), ["Allow once", "Always allow", "Block"], "the old default answers only");
  assert.doesNotMatch(doc.getElementById("approvals-waiting").textContent, /If you click Send without it/);
});

test("Answered earlier says what happened", async () => {
  const answered = [
    { id: "a1", sentence: [{ kind: "text", text: "A send" }], outcome: "without-used", decidedAt: Date.now() - 60_000, sessions: [], actions: [] },
    { id: "a2", sentence: [{ kind: "text", text: "Another send" }], outcome: "without", decidedAt: Date.now() - 60_000, sessions: [], actions: [] },
  ];
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ answered }) });
  await tick();
  const out = (id: string) => doc.querySelector(`#approvals-answered .row.answered[data-id="${id}"] .outcome`).textContent;
  assert.equal(out("a1"), "Sent without it");
  assert.equal(out("a2"), "Send without it, unused");
});
