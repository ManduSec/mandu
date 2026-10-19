/**
 * home-js-holder-send.test — the product's Approvals card for a program's
 * send of the secret files it holds (confidentiality plan 13 §5.4, §9 R2;
 * dashboard.md §4.34 "A send names every file"): every file with where it
 * may go, one Always button per file in the way (each posts that file alone
 * to `always-source`), the reason where a file takes none, the line saying
 * which files are left, "Allow this session" as the server words it, and
 * the third cell named for answers that are not Allow once / Always allow.
 * The text floor (12px) and the phone-width wrap of the new rules.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { ASK, home, load, tick, PUB } from "./home-js-fixtures.js";

const APPROVALS_URL = "http://127.0.0.1:4500/mandu/approvals";
const H = "hooks.slack.com";
const HOLDER = {
  ...ASK, id: "egr-7",
  sentence: [{ kind: "text", text: "Claude Code's program wants to send data from " }, { kind: "code", text: "~/ws/app/.env" }, { kind: "text", text: " and " }, { kind: "code", text: "~/data/customers.csv" }, { kind: "text", text: " to " }, { kind: "code", text: H }],
  why: "A program that read these files may send only where every one of them may go.",
  aiNow: `The AI's program has not sent anything: Mandu refused its connection to ${H}.`,
  ifAllowed: "Allow once lets the program's next connection go.",
  actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Allow this session" }, { approve: false, label: "Block" }],
  sources: [
    { path: "/home/u/ws/app/.env", name: "~/ws/app/.env", mayGo: "may go to: api.stripe.com, *.amazonaws.com", blocks: true, always: `Always: add ${H} to .env` },
    { path: "/home/u/data/customers.csv", name: "~/data/customers.csv", mayGo: "may go nowhere", blocks: true, always: `Always: add ${H} to customers.csv` },
    { path: "/home/u/keys/id", name: "~/keys/id", mayGo: "may go nowhere", blocks: true, noAlways: "Its rule covers a whole folder, so Mandu does not change it from here. Change it under Rules." },
    { path: "/home/u/notes.env", name: "~/notes.env", via: "~/out/copy.txt", mayGo: `may go to: ${H}`, blocks: false },
  ],
  sourcesLeft: `The send goes once every file may go to ${H}. Still in the way: ~/data/customers.csv.`,
};

test("the card lists every file, one Always per file in the way, and why a file takes none", async () => {
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [HOLDER] }) });
  await tick();
  const card = doc.querySelector('#approvals-waiting .ask[data-id="egr-7"]');
  assert.ok(card, "the card is drawn");
  const items = [...card.querySelectorAll(".ask-source")];
  assert.equal(items.length, 4);
  assert.match(items[0].textContent, /^~\/ws\/app\/\.env may go to: api\.stripe\.com, \*\.amazonaws\.com Not to this place\./);
  assert.match(items[1].textContent, /^~\/data\/customers\.csv may go nowhere Not to this place\./);
  assert.match(items[3].textContent, /^~\/notes\.env \(copied into ~\/out\/copy\.txt\) may go to: hooks\.slack\.com$/, "a file not in the way: no button, no warning");
  const always = [...card.querySelectorAll(".ask-source-always")].map((b: any) => b.textContent);
  assert.deepEqual(always, [`Always: add ${H} to .env`, `Always: add ${H} to customers.csv`]);
  assert.match(items[2].querySelector(".ask-source-why").textContent, /covers a whole folder/);
  assert.equal(items[2].querySelector("button"), null);
  assert.equal(card.querySelector(".ask-sources-left").textContent, HOLDER.sourcesLeft);
  // The answers, in the server's words; the third cell is not "Allow once or Always allow".
  const verbs = [...card.querySelectorAll(".ask-actions button")].map((b: any) => b.textContent);
  assert.deepEqual(verbs, ["Allow once", "Allow this session", "Block"]);
  const labels = [...card.querySelectorAll(".ask-detail > div .k")].map((k: any) => k.childNodes[0].textContent);
  assert.equal(labels[2], "What each answer does");
  assert.doesNotMatch(card.textContent, /placeholder|binding|symbol|egress/i);
});

test("an Always posts that one file to always-source; a file left keeps the card and says so", async () => {
  const { doc, calls } = load({
    url: APPROVALS_URL, homeVm: home({ waiting: [HOLDER] }),
    routes: { "POST egress/approvals/egr-7/always-source": { applied: true, changeId: "chg-1", released: false, left: ["/home/u/data/customers.csv"] } },
  });
  await tick();
  const btn = [...doc.querySelectorAll('#approvals-waiting .ask[data-id="egr-7"] .ask-source-always')][0] as any;
  btn.click();
  await tick(30);
  const post = calls.filter((c) => c.method === "POST");
  assert.equal(post.length, 1);
  assert.match(post[0]!.url, /\/api\/egress\/approvals\/egr-7\/always-source$/);
  assert.deepEqual(post[0]!.body, { path: "/home/u/ws/app/.env" }, "the one file, never the others");
  assert.equal(post[0]!.headers["X-Mandu-Control"], "1");
  const card = doc.querySelector('#approvals-waiting .ask[data-id="egr-7"]');
  assert.match(card.textContent, /Done: ~\/ws\/app\/\.env may go there now\. Still in the way: ~\/data\/customers\.csv\./);
});

test("the last Always: the page says the next send goes", async () => {
  const { doc } = load({
    url: APPROVALS_URL, homeVm: home({ waiting: [HOLDER] }),
    routes: { "POST egress/approvals/egr-7/always-source": { applied: true, changeId: "chg-2", released: true, left: [] } },
  });
  await tick();
  ([...doc.querySelectorAll('#approvals-waiting .ask[data-id="egr-7"] .ask-source-always')][1] as any).click();
  await tick(30);
  assert.match(doc.getElementById("approvals-waiting").textContent, /every file may go there now, so the program's next send goes/);
});

test("a refusal (the file's rule changed meanwhile) is shown on the card, the buttons on again", async () => {
  const { doc } = load({
    url: APPROVALS_URL, homeVm: home({ waiting: [HOLDER] }),
    routes: { "POST egress/approvals/egr-7/always-source": { status: 409, body: { error: "Your rules changed while you were deciding. Nothing was changed. Try again." } } },
  });
  await tick();
  ([...doc.querySelectorAll('#approvals-waiting .ask[data-id="egr-7"] .ask-source-always')][0] as any).click();
  await tick(30);
  const card = doc.querySelector('#approvals-waiting .ask[data-id="egr-7"]');
  assert.match(card.querySelector(".ask-error").textContent, /Your rules changed while you were deciding/);
  assert.ok([...card.querySelectorAll("button")].every((b: any) => !b.disabled));
});

test("Home's short card has no file list (it links to Approvals); its answers keep the server's words", async () => {
  const { doc } = load({ homeVm: home({ waiting: [HOLDER] }) });
  await tick();
  const card = doc.querySelector('#home-waiting .ask[data-id="egr-7"]');
  assert.equal(card.querySelector(".ask-sources"), null);
  assert.deepEqual([...card.querySelectorAll(".ask-actions button")].map((b: any) => b.textContent), ["Allow once", "Allow this session", "Block"]);
});

test("the new rules keep the 12px floor and wrap at phone width", () => {
  const css = readFileSync(join(PUB, "app.css"), "utf8");
  const block = css.slice(css.indexOf(".ask-sources {"), css.indexOf(".ask-source-always"));
  assert.ok(block.length > 0);
  for (const m of block.matchAll(/font-size:\s*(\d+)px/g)) assert.ok(Number(m[1]) >= 12, `font-size ${m[1]}px`);
  assert.match(css, /\.ask-source \{[^}]*flex-wrap: wrap/);
  assert.match(css, /\.ask-source-what \{[^}]*overflow-wrap: anywhere/);
});
