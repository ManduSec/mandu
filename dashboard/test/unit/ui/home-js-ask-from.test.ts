/**
 * home-js-ask-from.test — a waiting question says which session asked
 * (public/js/home.js `askedFrom`; view-model/home.ts `HomeAsk.askerCwd`;
 * dashboard.md §4.25u *A question says which session asked*).
 *
 * Two agents of one kind, say Claude Code in ~/projects/shop and Claude
 * Code in ~/projects/blog, raised questions whose cards named only "Claude
 * Code", so the person could not tell which agent asked before answering.
 * Now the card's moment line ends "· from Claude Code in ~/projects/shop"
 * (the folder as a card names a name: whole, or cut at its slashes), or
 * "· from 2 sessions, last Claude Code in …", on Approvals' full card and
 * Home's short card. Without a known folder the line is as before. The
 * period rule (§4.25u *A moment line ends where it ends*) still holds.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter, proxy and dashboard,
 * tests/stack/ask-from-session.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ASK, CLOCK, home, load, tick } from "./home-js-fixtures.js";

const APPROVALS_URL = "http://127.0.0.1:4500/mandu/approvals";
const askedAt = Date.now() - 2 * 60_000;
const SHOP = { ...ASK, id: "shop-1", askedAt, count: 1, askerCwd: "/home/u/projects/shop", askerAgent: "Claude Code", askerSessions: 1 };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const card = (doc: Doc, sel: string, id: string) => doc.querySelector(`${sel} .ask[data-id="${id}"]`);

test("§4.25u Approvals' full card: the moment line names the session that asked, its folder as code, and ends with no period", async () => {
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [SHOP] }) });
  await tick();
  const sub = card(doc, "#approvals-waiting", "shop-1").querySelector(".ask-sub");
  assert.match(sub.textContent, new RegExp(`^${CLOCK} · 2 minutes ago · from Claude Code in ~/projects/shop$`));
  const code = sub.querySelector(".ask-from code");
  assert.equal(code.textContent, "~/projects/shop", "the folder under the home folder, as Running now draws it");
  assert.ok(code.classList.contains("code-whole"), "a short folder is kept whole");
  // The link under the card still opens the session that asked.
  const link = card(doc, "#approvals-waiting", "shop-1").querySelector("a.ask-link");
  assert.equal(link.getAttribute("data-session"), "s1");
});

test("§4.25u Home's short card names it too, and keeps the period before Details in Approvals", async () => {
  const { doc } = load({ homeVm: home({ waiting: [SHOP] }) });
  await tick();
  const sub = card(doc, "#home-waiting", "shop-1").querySelector(".ask-sub");
  assert.match(sub.textContent, new RegExp(`${CLOCK} · 2 minutes ago · from Claude Code in ~/projects/shop\\. Details in Approvals$`));
  assert.equal(sub.querySelector(".ask-from code").textContent, "~/projects/shop");
});

test("§4.25u more than one session asked: '· from 2 sessions, last …'; with a count and an ended agent the period follows the folder", async () => {
  const both = { ...SHOP, id: "both-1", count: 3, askerSessions: 2, askerAgent: "Codex", askerCwd: "/home/u/projects/blog", askerEnded: true };
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [both] }) });
  await tick();
  const sub = card(doc, "#approvals-waiting", "both-1").querySelector(".ask-sub");
  assert.match(sub.textContent, new RegExp(`^${CLOCK} · 2 minutes ago, 3 times · from 2 sessions, last Codex in ~/projects/blog\\. The agent that asked has ended`));
});

test("§4.25u no folder known: the line is as before", async () => {
  const bare = { ...ASK, id: "bare-1", askedAt, count: 1 };
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [bare] }) });
  await tick();
  const sub = card(doc, "#approvals-waiting", "bare-1").querySelector(".ask-sub");
  assert.match(sub.textContent, new RegExp(`^${CLOCK} · 2 minutes ago$`));
  assert.equal(sub.querySelector(".ask-from"), null);
  assert.doesNotMatch(sub.textContent, /from/);
});

test("§4.25u a long folder breaks only at its slashes; a folder outside the home folder is as recorded", async () => {
  const long = { ...SHOP, id: "long-1", askerCwd: "/home/u/projects/mandu-try/customer-portal-backend/services" };
  const other = { ...SHOP, id: "other-1", askerCwd: "/srv/shop" };
  const { doc } = load({ url: APPROVALS_URL, homeVm: home({ waiting: [long, other] }) });
  await tick();
  const code = card(doc, "#approvals-waiting", "long-1").querySelector(".ask-from code");
  assert.equal([...code.querySelectorAll(".name-part")].map((p: Doc) => p.textContent).join(" | "), "~/ | projects/ | mandu-try/ | customer-portal-backend/ | services");
  assert.equal(code.textContent, "~/projects/mandu-try/customer-portal-backend/services", "the words are the same");
  assert.equal(card(doc, "#approvals-waiting", "other-1").querySelector(".ask-from code").textContent, "/srv/shop");
});
