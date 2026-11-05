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

/** An Always on the first of two files, its route answering with
 *  `changeId` (none: an older server). */
function firstAlways(changeId?: string) {
  return load({
    url: APPROVALS_URL, homeVm: home({ waiting: [HOLDER] }),
    routes: { "POST egress/approvals/egr-7/always-source": { applied: true, ...(changeId ? { changeId } : {}), released: false, left: ["/home/u/data/customers.csv"] } },
  });
}

test("an Always on a file that is not the last: the card's words end with Undo it in Approvals, a link to that rule change", async () => {
  const { doc } = firstAlways("pc-000003");
  await tick();
  ([...doc.querySelectorAll('#approvals-waiting .ask[data-id="egr-7"] .ask-source-always')][0] as any).click();
  await tick(30);
  const card = doc.querySelector('#approvals-waiting .ask[data-id="egr-7"]');
  const done = card.querySelector(".prompt-let-done");
  assert.equal(words(done), "Done: ~/ws/app/.env may go there now. Still in the way: ~/data/customers.csv. Undo it in Approvals");
  const links = [...done.querySelectorAll("a")] as any[];
  assert.equal(links.length, 1);
  assert.equal(links[0].textContent, "Undo it in Approvals");
  assert.equal(links[0].getAttribute("href"), "/mandu/approvals/pc-000003", "the #48 landing: Rule changes, that change marked, its Undo");
  assert.equal(links[0].dataset.ask, "pc-000003");
  assert.equal(links[0].dataset.pageLink, "approvals");
  assert.ok([...card.querySelectorAll(".ask-source-always")].some((b: any) => b.textContent === `Always: add ${H} to customers.csv`), "the next file's Always stays");
  assert.equal(doc.querySelector("#approvals-waiting .answer-line"), null, "no line while a file is left");
});

test("an Always on a file that is not the last, from an older server (no change id): the words have no link", async () => {
  const { doc } = firstAlways();
  await tick();
  ([...doc.querySelectorAll('#approvals-waiting .ask[data-id="egr-7"] .ask-source-always')][0] as any).click();
  await tick(30);
  const done = doc.querySelector('#approvals-waiting .ask[data-id="egr-7"] .prompt-let-done');
  assert.equal(words(done), "Done: ~/ws/app/.env may go there now. Still in the way: ~/data/customers.csv.");
  assert.equal(done.querySelector("a"), null);
});

test("the last Always on a card no answer line is drawn for: the words say every file may go there, with Undo it in Approvals", async () => {
  const { doc } = released("pc-000004");
  await tick();
  // Taken out of its list: no place a poll draws, so no line either.
  const card = doc.querySelector('#approvals-waiting .ask[data-id="egr-7"]');
  doc.body.append(card);
  ([...card.querySelectorAll(".ask-source-always")][1] as any).click();
  await tick(30);
  assert.equal(doc.querySelector(".answer-line"), null, "no answer line");
  const said = card.querySelector(".ask-error");
  assert.equal(words(said), "Done: every file may go there now, so the program's next send goes. Undo it in Approvals");
  assert.equal(said.querySelector("a").getAttribute("href"), "/mandu/approvals/pc-000004");
});

/** The last Always over a mocked Home that, as the arbiter does, no longer
 *  lists the question once its last file may go. */
function released(changeId?: string, url = APPROVALS_URL) {
  // eslint-disable-next-line prefer-const
  let page: ReturnType<typeof load>;
  page = load({
    url, homeVm: home({ waiting: [RELEASED] }),
    routes: { "POST egress/approvals/egr-7/always-source": () => (page.setHome(home({ waiting: [] })), { applied: true, ...(changeId ? { changeId } : {}), released: true, left: [] }) },
  });
  return page;
}
/** The question as Approvals has it with one file left in the way. */
const RELEASED = {
  ...HOLDER,
  whatParts: HOLDER.sentence.slice(),
  afterAllow: "Tell Claude Code to try again.",
};
const words = (x: any) => String(x.textContent).replace(/\s+/g, " ").trim(); // eslint-disable-line @typescript-eslint/no-explicit-any

test("the last Always: the card's place holds an answer line, with Undo it in Approvals on that rule change", async () => {
  const { doc } = released("pc-000002");
  await tick();
  ([...doc.querySelectorAll('#approvals-waiting .ask[data-id="egr-7"] .ask-source-always')][1] as any).click();
  await tick(30);
  const list = doc.getElementById("approvals-waiting");
  assert.equal(list.querySelector('.ask[data-id="egr-7"]'), null, "the arbiter retired the question: its card is gone");
  const lines = list.querySelectorAll(".answer-line");
  assert.equal(lines.length, 1, "one line where the card was");
  const line = lines[0];
  assert.equal(line.getAttribute("role"), "status");
  assert.equal(line.querySelector("strong").textContent, "Always allowed:");
  assert.equal(words(line), `Always allowed: Claude Code's program wants to send data from ~/ws/app/.env and ~/data/customers.csv to ${H}. Tell Claude Code to try again. Undo it in Approvals`);
  assert.deepEqual([...line.querySelectorAll("code")].map((c: any) => c.textContent), ["~/ws/app/.env", "~/data/customers.csv", H]);
  const link = line.querySelector("a");
  assert.equal(link.textContent, "Undo it in Approvals");
  assert.equal(link.getAttribute("href"), "/mandu/approvals/pc-000002", "the #48 landing: Rule changes, that change marked, its Undo");
  assert.equal(link.dataset.ask, "pc-000002");
  assert.doesNotMatch(list.textContent, /After you answer|Change your answer/);
  assert.doesNotMatch(doc.body.textContent, /After you answer/);
});

test("the last Always from an older server (no change id): the line has no link", async () => {
  const { doc } = released();
  await tick();
  ([...doc.querySelectorAll('#approvals-waiting .ask[data-id="egr-7"] .ask-source-always')][1] as any).click();
  await tick(30);
  const line = doc.querySelector("#approvals-waiting .answer-line");
  assert.ok(line, "the line is drawn");
  assert.match(words(line), /^Always allowed: .* Tell Claude Code to try again\.$/);
  assert.equal(line.querySelector("a"), null);
});

test("the last Always takes the focus the answer gives on, and a question the page opened at is no longer marked", async () => {
  const { doc, window } = released("pc-000002", `${APPROVALS_URL}/egr-7`);
  await tick();
  assert.ok(doc.querySelector('#approvals-waiting .ask[data-id="egr-7"]').classList.contains("focus"), "the page opened at the question");
  const btn = [...doc.querySelectorAll('#approvals-waiting .ask[data-id="egr-7"] .ask-source-always')][1] as any;
  // Enter on the button: the browser drops the focus of the button the
  // answer turns off to <body>.
  btn.focus();
  btn.click();
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
  await tick(30);
  const line = doc.querySelector("#approvals-waiting .answer-line");
  assert.equal(doc.activeElement, line, "the line has the focus");
  assert.equal(window.location.pathname, "/mandu/approvals", "the URL no longer names the retired question");
  assert.equal(doc.getElementById("approvals-focus-note").hidden, true, "no \"no longer waiting\" note");
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
