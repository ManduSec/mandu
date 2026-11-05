/**
 * home-js-host-check.test — Rules › Who may get your secrets › Check a host
 * (dashboard.md §4.25aa *Check a host*): public/js/home.js sends the typed
 * host to GET policy/host-check and draws the server's sentences
 * (view-model/host-check.ts), its links and its file buttons, in jsdom over
 * the fetch stub of home-js-fixtures.ts. The box writes nothing.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { tick, load, rowOf, home, ASK } from "./home-js-fixtures.js";
import { byWhoRules, toByWhoVM } from "../../../src/view-model/rules-by-who.js";
import { hostCheckWords } from "../../../src/view-model/host-check.js";

const VM = toByWhoVM(byWhoRules([
  { path: "/home/u/proj/.env", level: "no-model", bindings: ["api.stripe.com"], recursive: false },
], []), [], { home: "/home/u" });

const lockRow = (path: string) => ({
  id: `lock:${path}`, kind: "lock", subject: path, effect: "x", reach: null, hits: null, covers: "exact", bindings: [], level: "no-model",
  actions: { remove: true, flip: null },
  plain: { subject: path, reach: "this file only", effect: "No AI" },
});
const PANEL = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [lockRow("/home/u/proj/.env")] } };

const STRIPE = { check: hostCheckWords({
  host: "api.stripe.com",
  axis: true,
  bound: [
    { path: "/home/u/proj/.env", level: "no-model", binding: ["api.stripe.com"], source: "label" },
    { path: "/home/u/other/key.txt", level: "no-model", binding: ["api.stripe.com"], source: "registry" },
  ],
  release: { bound: null, unbound: { decision: { allow: false, requiresApproval: true }, stage: "built-in" } },
  destinations: [{ host: "api.stripe.com", port: 443, proto: "tcp", connect: "allow" }],
  verdicts: [{ symbol: "$MDU:nomodel_Read[1]", status: "approved", scope: "always" }],
  pending: [{ id: "pc-1" }],
  issuer: { id: "stripe", name: "Stripe", shapes: [], on: true },
}, "/home/u") };

const page = (routes: Record<string, unknown> = {}) =>
  load({ url: "http://127.0.0.1:4500/mandu/rules", routes: { "GET policy/panel": PANEL, "GET policy/by-who": { byWho: VM }, ...routes } });

const form = (doc: any) => doc.getElementById("host-check");
const box = (doc: any) => doc.getElementById("host-check-q");
const answer = (doc: any) => doc.getElementById("host-check-answer");
const lines = (doc: any) => ([...answer(doc).querySelectorAll("li")] as any[]).map((li) => li.textContent);
async function check(doc: any, host: string, by: "enter" | "button" = "enter") {
  box(doc).value = host;
  if (by === "enter") { box(doc).focus(); form(doc).requestSubmit(); }
  else { const b = doc.getElementById("host-check-go"); b.focus(); b.click(); }
  await tick();
}

test("§4.25aa Check a host: a box and Check under the card's lists, in the card", async () => {
  const { doc, err } = page();
  await tick();
  assert.equal(err, null);
  assert.equal(doc.getElementById("by-who-block").hidden, false);
  assert.ok(doc.getElementById("by-who-block").contains(form(doc)));
  assert.equal(form(doc).hidden, false);
  assert.equal(doc.getElementById("host-check-title").textContent, "Check a host");
  assert.equal(box(doc).getAttribute("placeholder"), "api.example.com");
  assert.equal(box(doc).getAttribute("aria-label"), "Host name");
  assert.equal(doc.getElementById("host-check-go").textContent, "Check");
  assert.equal(answer(doc).getAttribute("role"), "status");
  assert.equal(answer(doc).textContent, "", "nothing until asked");
});

test("the typed host is sent, and the sentences, links and file buttons drawn; the focus stays in the form", async () => {
  const { doc, calls } = page({ "GET policy/host-check?host=api.stripe.com": STRIPE });
  await tick();
  await check(doc, "  api.stripe.com ");
  assert.ok(calls.some((c) => c.url.endsWith("/api/policy/host-check?host=api.stripe.com") && c.method === "GET"), "the typed host, trimmed");
  assert.deepEqual(lines(doc), [
    "2 of your secrets may be sent there: ~/proj/.env, ~/other/key.txt.",
    "Any other secret sent there: Mandu asks you first.",
    "This is Stripe's API host: a Stripe key goes here without asking.",
    "Your agent's programs may connect to it on port 443 (your rule).",
    "You answered 1 earlier send to this host. Find them in Approvals.",
    "A rule change waiting in Approvals would change this.",
  ]);
  assert.equal(doc.activeElement, box(doc), "Enter: the focus stays in the box");
  // A file whose rule is drawn in Your rules is a button; another plain code.
  const bound = answer(doc).querySelector('li[data-kind="bound"]');
  const buttons = [...bound.querySelectorAll("button.by-who-link")] as any[];
  assert.equal(buttons.length, 1);
  assert.equal(buttons[0].textContent, "~/proj/.env");
  assert.equal(buttons[0].getAttribute("aria-label"), "Show the rule for ~/proj/.env in Your rules");
  assert.deepEqual(([...bound.querySelectorAll("code")] as any[]).map((c) => c.textContent), ["~/proj/.env", "~/other/key.txt"], "every name is code");
  // The links: Answered earlier found by the host, and Approvals.
  const found = answer(doc).querySelector('li[data-kind="answered"] a');
  assert.equal(found.getAttribute("href"), "/mandu/approvals?q=api.stripe.com");
  assert.equal(found.dataset.pageLink, "approvals");
  assert.equal(answer(doc).querySelector('li[data-kind="pending"] a').getAttribute("href"), "/mandu/approvals");
  assert.ok(!answer(doc).textContent.includes("$MDU:"));
  // Check pressed: the focus stays on it.
  await check(doc, "api.stripe.com", "button");
  assert.equal(doc.activeElement, doc.getElementById("host-check-go"));
  assert.ok(form(doc).contains(doc.activeElement));
});

test("a file button opens its rule under Your rules", async () => {
  const { doc } = page({ "GET policy/host-check?host=api.stripe.com": STRIPE });
  await tick();
  await check(doc, "api.stripe.com");
  answer(doc).querySelector("button.by-who-link").click();
  await tick();
  const row = ([...doc.querySelectorAll("#files-tree .row.file-rule")] as any[]).find((r) => r.getAttribute("data-path") === "/home/u/proj/.env");
  assert.ok(row.classList.contains("open"));
  assert.equal(doc.activeElement, row.querySelector(".file-more"));
});

test("Find them in Approvals opens Approvals with Answered earlier found by the host", async () => {
  const { doc, window, calls } = page({ "GET policy/host-check?host=api.stripe.com": STRIPE });
  await tick();
  await check(doc, "api.stripe.com");
  answer(doc).querySelector('li[data-kind="answered"] a').click();
  await tick();
  assert.equal(window.location.pathname, "/mandu/approvals");
  assert.equal(window.location.search, "?q=api.stripe.com");
  assert.equal(doc.getElementById("answered-q").value, "api.stripe.com");
  assert.ok(calls.some((c) => c.url.includes("/api/home/answered?") && c.url.includes("q=api.stripe.com")), "the search is read");
});

test("a send waiting now: its line links Approvals with no search, and opens it", async () => {
  const WAITING = { check: hostCheckWords({
    host: "uploads.example.com",
    axis: true,
    bound: [],
    release: { bound: null, unbound: { decision: { allow: false, requiresApproval: true }, stage: "built-in" } },
    destinations: [],
    verdicts: [
      { symbol: "$MDU:nomodel_Read[1].TOKEN", status: "pending", scope: "always" },
      { symbol: "$MDU:nomodel_Read[2]", status: "denied", scope: "once" },
    ],
  }, "/home/u") };
  const { doc, window } = page({ "GET policy/host-check?host=uploads.example.com": WAITING });
  await tick();
  await check(doc, "uploads.example.com");
  assert.deepEqual(lines(doc), [
    "None of your secrets may be sent there.",
    "Any other secret sent there: Mandu asks you first.",
    "You answered 1 earlier send to this host. Find them in Approvals.",
    "1 send to this host waits for your answer in Approvals.",
  ]);
  const link = answer(doc).querySelector('li[data-kind="waiting"] a');
  assert.equal(link.textContent, "Approvals");
  assert.equal(link.getAttribute("href"), "/mandu/approvals", "no ?q: Answered earlier's search finds no waiting card");
  assert.equal(link.dataset.pageLink, "approvals");
  assert.equal(link.dataset.land, undefined);
  assert.ok(!answer(doc).textContent.includes("$MDU:"));
  link.click();
  await tick();
  assert.equal(window.location.pathname, "/mandu/approvals");
  assert.equal(window.location.search, "");
});

test("a refusal's words show; the protection service down gives the page's words", async () => {
  const { doc } = page({
    "GET policy/host-check?host=user%40x.com": { status: 400, body: { error: "Type a host name, like api.example.com: no https://, no path." } },
    "GET policy/host-check?host=api.stripe.com": { status: 503, body: { error: "unreachable", unreachable: true } },
  });
  await tick();
  await check(doc, "user@x.com");
  assert.equal(answer(doc).querySelector(".ask-error").textContent, "Type a host name, like api.example.com: no https://, no path.");
  await check(doc, "api.stripe.com");
  assert.match(answer(doc).querySelector(".ask-error").textContent, /protection service/i);
  // Empty: said on the page, nothing asked.
  await check(doc, "   ");
  assert.equal(answer(doc).querySelector(".ask-error").textContent, "Type a host name, like api.example.com.");
  assert.equal(doc.activeElement, box(doc));
});

test("an older service (501) hides the box", async () => {
  const { doc } = page({ "GET policy/host-check?host=api.stripe.com": { status: 501, body: { error: "this Mandu service cannot check a host" } } });
  await tick();
  await check(doc, "api.stripe.com");
  assert.equal(form(doc).hidden, true);
});

test("the box changes nothing: no POST, no PUT, no DELETE", async () => {
  const { doc, calls } = page({ "GET policy/host-check?host=api.stripe.com": STRIPE });
  await tick();
  await check(doc, "api.stripe.com");
  await check(doc, "api.stripe.com", "button");
  assert.deepEqual(calls.filter((c) => c.method !== "GET").map((c) => `${c.method} ${c.url}`), []);
});

test("a file whose rule names a path where nothing is says so after its name, and in its button's name; the real file does not (queue item #225)", async () => {
  const both = toByWhoVM(byWhoRules([
    { path: "/home/u/shop/.env", level: "no-model", bindings: ["api.stripe.com"], recursive: false },
    { path: "/home/u/shop/.evn", level: "no-model", bindings: ["api.stripe.com"], recursive: false },
  ], []), [], { home: "/home/u" });
  const panel = { panel: { ...PANEL.panel, yourRules: [lockRow("/home/u/shop/.env"), { ...lockRow("/home/u/shop/.evn"), missing: true }] } };
  const answerOf = { check: hostCheckWords({
    host: "api.stripe.com",
    axis: true,
    bound: [
      { path: "/home/u/shop/.env", level: "no-model", binding: ["api.stripe.com"], source: "label" },
      { path: "/home/u/shop/.evn", level: "no-model", binding: ["api.stripe.com"], source: "label" },
    ],
    release: { bound: null, unbound: { decision: { allow: false, requiresApproval: true }, stage: "built-in" } },
    destinations: [],
    verdicts: [],
  }, "/home/u") };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: {
    "GET policy/panel": panel, "GET policy/by-who": { byWho: both }, "GET policy/host-check?host=api.stripe.com": answerOf,
  } });
  await tick();
  await check(doc, "api.stripe.com");
  const bound = answer(doc).querySelector('li[data-kind="bound"]');
  assert.equal(bound.textContent, "2 of your secrets may be sent there: ~/shop/.env, ~/shop/.evn (nothing at this path).");
  const buttons = [...bound.querySelectorAll("button.by-who-link")] as any[];
  assert.deepEqual(buttons.map((b) => b.getAttribute("aria-label")), [
    "Show the rule for ~/shop/.env in Your rules",
    "Show the rule for ~/shop/.evn in Your rules (nothing at this path)",
  ]);
  const marks = [...bound.querySelectorAll(".by-who-more")] as any[];
  assert.equal(marks.length, 1, "one mark");
  assert.equal(marks[0].previousElementSibling, buttons[1], "right after the misspelt file's button");
  assert.equal(marks[0].className, "by-who-more", "the card's plain grey words");
});

// ── Asked again at each Rules read (queue item #218) ─────────────────────────
// While an answer is drawn, each Rules read (loadRules) asks again for the
// host of that answer, and draws the new one only when it differs.

const WAITS = { check: hostCheckWords({
  host: "uploads.example.com",
  axis: true,
  bound: [],
  release: { bound: null, unbound: { decision: { allow: false, requiresApproval: true }, stage: "built-in" } },
  destinations: [],
  verdicts: [{ symbol: "$MDU:nomodel_Read[1].TOKEN", status: "pending", scope: "always" }],
}, "/home/u") };
const ALLOWED = { check: hostCheckWords({
  host: "uploads.example.com",
  axis: true,
  bound: [{ path: "/home/u/proj/.env", level: "no-model", binding: ["uploads.example.com"], source: "label" }],
  release: { bound: null, unbound: { decision: { allow: false, requiresApproval: true }, stage: "built-in" } },
  destinations: [],
  verdicts: [{ symbol: "$MDU:nomodel_Read[1].TOKEN", status: "approved", scope: "always" }],
}, "/home/u") };
async function poll(doc: any) {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
}
/** The very same nodes, not equal ones. */
const same = (a: unknown[], b: unknown[]) => a.length === b.length && a.length > 0 && a.every((x, i) => x === b[i]);
const UPLOADS = "GET policy/host-check?host=uploads.example.com";
const asks = (calls: any[]) => calls.filter((c) => c.url.includes("/api/policy/host-check?")).map((c) => c.url.slice(c.url.indexOf("?")));
/** Routes the test swaps after the page has loaded (the page reads each
 *  route on every fetch; `page` copies the object, so each is a function). */
const swap = (now: Record<string, unknown>) => Object.fromEntries(Object.keys(now).map((k) => [k, () => now[k]]));
const navRules = (doc: any) => (doc.querySelector('header a[data-page-link="rules"], nav a[data-page-link="rules"]') as any).click();

test("#218: answered in Approvals, back to Rules: the drawn host is asked once more and its new answer drawn, without a Check press", async () => {
  const routes: Record<string, unknown> = { [UPLOADS]: WAITS };
  const { doc, window, calls } = page(swap(routes));
  await tick();
  await check(doc, "uploads.example.com");
  assert.equal(lines(doc).at(-1), "1 send to this host waits for your answer in Approvals.");
  const before = asks(calls).length;
  routes[UPLOADS] = ALLOWED;
  answer(doc).querySelector('li[data-kind="waiting"] a').click();
  await tick();
  assert.equal(window.location.pathname, "/mandu/approvals");
  assert.equal(asks(calls).length, before, "Approvals asks nothing");
  navRules(doc);
  await tick();
  assert.equal(window.location.pathname, "/mandu/rules");
  assert.deepEqual(asks(calls).slice(before), ["?host=uploads.example.com"], "exactly one more, for the drawn host");
  assert.deepEqual(lines(doc), [
    "1 of your secrets may be sent there: ~/proj/.env.",
    "Any other secret sent there: Mandu asks you first.",
    "You answered 1 earlier send to this host. Find them in Approvals.",
  ]);
  assert.equal(answer(doc).querySelector(".dim"), null, "no Checking…");
  assert.ok(!answer(doc).textContent.includes("$MDU:"));
});

test("#218: a rule removed on Rules: the answer is asked again and drawn as it is now", async () => {
  const release = { id: "r-0001", kind: "release-allow", subject: "uploads.example.com", effect: "sending allowed", reach: "from any source to uploads.example.com", hits: 2, actions: { remove: true, flip: "block" } };
  const routes: Record<string, unknown> = {
    "GET policy/panel": { panel: { ...PANEL.panel, yourRules: [...PANEL.panel.yourRules, release] } },
    "POST policy/rules/change": { applied: true, changeId: "c-1" },
    [UPLOADS]: ALLOWED,
  };
  const { doc, calls } = page(swap(routes));
  await tick();
  await check(doc, "uploads.example.com");
  const before = asks(calls).length;
  routes[UPLOADS] = WAITS;
  routes["GET policy/panel"] = PANEL;
  const detail = rowOf(doc, /uploads\.example\.com/).querySelector(".file-more");
  detail.click();
  ([...rowOf(doc, /uploads\.example\.com/).nextElementSibling.querySelectorAll("button")] as any[]).find((b) => b.textContent === "Remove").click();
  await tick();
  assert.ok(calls.some((c) => c.method === "POST" && c.url.endsWith("/policy/rules/change")), "the rule was removed");
  assert.deepEqual(asks(calls).slice(before), ["?host=uploads.example.com"]);
  assert.equal(lines(doc)[0], "None of your secrets may be sent there.");
  assert.equal(lines(doc).at(-1), "1 send to this host waits for your answer in Approvals.");
});

test("#218: the host of the drawn answer is asked, not text typed since and never checked", async () => {
  const { doc, calls } = page({ [UPLOADS]: WAITS });
  await tick();
  await check(doc, "uploads.example.com");
  box(doc).value = "pastebin.com";
  const before = asks(calls).length;
  navRules(doc);
  await tick();
  assert.deepEqual(asks(calls).slice(before), ["?host=uploads.example.com"]);
  assert.equal(box(doc).value, "pastebin.com", "the box keeps what was typed");
});

test("#218: an unchanged answer is not drawn again: the same lines stay, and a focused file button keeps the focus", async () => {
  // A Rules read that keeps the focus where it is: a poll that sees your
  // rules changed elsewhere (§4.25 *Rules follows a change made elsewhere*).
  const { doc, calls, setHome } = load({ url: "http://127.0.0.1:4500/mandu/rules", homeVm: home({ rulesVersion: "v1" }), routes: {
    "GET policy/panel": PANEL, "GET policy/by-who": { byWho: VM }, "GET policy/host-check?host=api.stripe.com": STRIPE,
    "GET policy/changes?limit=1": { changes: [{ id: "pc-000042", createdAt: Date.now() + 3_600_000 }] },
  } });
  await tick();
  await poll(doc);
  await check(doc, "api.stripe.com");
  const lis = [...answer(doc).querySelectorAll("li")];
  const file = answer(doc).querySelector("button.by-who-link");
  file.focus();
  const before = asks(calls).length;
  const reads = calls.filter((c) => c.url.endsWith("/api/policy/panel")).length;
  setHome(home({ rulesVersion: "v2" }));
  await poll(doc);
  assert.equal(calls.filter((c) => c.url.endsWith("/api/policy/panel")).length, reads + 1, "Rules read again");
  assert.deepEqual(asks(calls).slice(before), ["?host=api.stripe.com"], "asked again");
  assert.ok(same(lis, [...answer(doc).querySelectorAll("li")]), "the same nodes");
  assert.equal(doc.activeElement, file, "the focus stays on the file");
});

test("#218: a file's rule gone from Your rules: the answer is drawn again, its file plain code", async () => {
  const routes: Record<string, unknown> = { "GET policy/host-check?host=api.stripe.com": STRIPE, "GET policy/panel": PANEL };
  const { doc } = page(swap(routes));
  await tick();
  await check(doc, "api.stripe.com");
  assert.equal(answer(doc).querySelectorAll("button.by-who-link").length, 1);
  routes["GET policy/panel"] = { panel: { ...PANEL.panel, yourRules: [] } };
  navRules(doc);
  await tick();
  assert.equal(answer(doc).querySelectorAll("button.by-who-link").length, 0, "the same lines, the file no longer a button");
  assert.equal(lines(doc)[0], "2 of your secrets may be sent there: ~/proj/.env, ~/other/key.txt.");
});

test("#218: nothing checked, a refusal drawn, or a tab switch: no host is asked", async () => {
  const { doc, calls } = page({ "GET policy/host-check?host=user%40x.com": { status: 400, body: { error: "Type a host name, like api.example.com: no https://, no path." } } });
  await tick();
  navRules(doc);
  await tick();
  assert.equal(asks(calls).length, 0, "nothing checked yet");
  await check(doc, "user@x.com");
  assert.equal(asks(calls).length, 1);
  navRules(doc);
  await tick();
  assert.equal(asks(calls).length, 1, "a refusal is not asked again");
  assert.ok(answer(doc).querySelector(".ask-error"));
});

test("#218: a tab switch draws the saved answer and asks nothing", async () => {
  const { doc, calls } = page({ [UPLOADS]: WAITS });
  await tick();
  await check(doc, "uploads.example.com");
  const before = asks(calls).length;
  const lis = [...answer(doc).querySelectorAll("li")];
  doc.getElementById("by-who-tab-hosts").click();
  await tick();
  doc.getElementById("by-who-tab-programs").click();
  await tick();
  assert.equal(asks(calls).length, before);
  assert.ok(same(lis, [...answer(doc).querySelectorAll("li")]), "the same nodes, not drawn again");
});

test("#218: a re-ask that fails says so, as a failed Check does", async () => {
  const routes: Record<string, unknown> = { [UPLOADS]: WAITS };
  const { doc } = page(swap(routes));
  await tick();
  await check(doc, "uploads.example.com");
  routes[UPLOADS] = { status: 503, body: { error: "unreachable", unreachable: true } };
  navRules(doc);
  await tick();
  assert.equal(answer(doc).querySelectorAll("li").length, 0);
  assert.match(answer(doc).querySelector(".ask-error").textContent, /protection service/i);
});

test("#218: a Check pressed while a re-ask is in flight wins; the late re-ask draws nothing", async () => {
  let release: (v: unknown) => void = () => {};
  const routes: Record<string, unknown> = {
    [UPLOADS]: WAITS,
    "GET policy/host-check?host=api.stripe.com": STRIPE,
  };
  const { doc } = page(swap(routes));
  await tick();
  await check(doc, "uploads.example.com");
  routes[UPLOADS] = new Promise((r) => { release = r; });
  navRules(doc);
  await tick();
  await check(doc, "api.stripe.com");
  assert.equal(lines(doc)[0], "2 of your secrets may be sent there: ~/proj/.env, ~/other/key.txt.");
  release(ALLOWED);
  await tick();
  assert.equal(lines(doc)[0], "2 of your secrets may be sent there: ~/proj/.env, ~/other/key.txt.", "the newer answer stays");
  assert.match(answer(doc).querySelector("ul").getAttribute("aria-label"), /api\.stripe\.com/);
});

// ── Follows the questions waiting (queue item #269) ──────────────────────────
// `rulesVersion` leaves the questions waiting out, so a send that starts
// waiting, or one answered once elsewhere, reads no Rules: while an answer
// is drawn, a Home poll whose waiting ids changed asks its host again.

const NOTHING = { check: hostCheckWords({
  host: "uploads.example.com",
  axis: true,
  bound: [],
  release: { bound: null, unbound: { decision: { allow: false, requiresApproval: true }, stage: "built-in" } },
  destinations: [],
  verdicts: [],
}, "/home/u") };
const ONCE = { check: hostCheckWords({
  host: "uploads.example.com",
  axis: true,
  bound: [],
  release: { bound: null, unbound: { decision: { allow: false, requiresApproval: true }, stage: "built-in" } },
  destinations: [],
  verdicts: [{ symbol: "$MDU:nomodel_Read[1].TOKEN", status: "approved", scope: "once" }],
}, "/home/u") };
const ASK2 = { ...ASK, id: "egr-2" };
const WAITING_LINE = "1 send to this host waits for your answer in Approvals.";
/** Rules with the Home answer `waiting`, its routes swappable (swap), and
 *  one poll already compared, so the next poll compares with `waiting`. */
async function following(routes: Record<string, unknown>, waiting: unknown[], over: Record<string, unknown> = {}, before?: (w: any) => void) {
  const r = load({ url: "http://127.0.0.1:4500/mandu/rules", homeVm: home({ waiting, ...over }), before, routes: {
    "GET policy/panel": PANEL, "GET policy/by-who": { byWho: VM }, ...swap(routes),
  } });
  await tick();
  await poll(r.doc);
  return r;
}

test("#269: a send to the drawn host starts waiting: the next poll asks that host once and draws the waiting line", async () => {
  const routes: Record<string, unknown> = { [UPLOADS]: NOTHING };
  const { doc, calls, setHome } = await following(routes, []);
  await check(doc, "uploads.example.com");
  assert.ok(!lines(doc).includes(WAITING_LINE));
  const before = asks(calls).length;
  routes[UPLOADS] = WAITS;
  setHome(home({ waiting: [ASK] }));
  await poll(doc);
  assert.deepEqual(asks(calls).slice(before), ["?host=uploads.example.com"], "exactly one ask, for the drawn host");
  assert.equal(lines(doc).at(-1), WAITING_LINE);
  assert.equal(answer(doc).querySelector(".dim"), null, "no Checking…");
  assert.ok(!answer(doc).textContent.includes("$MDU:"));
});

test("#269: that send answered once elsewhere: the next poll asks again and the waiting line goes", async () => {
  const routes: Record<string, unknown> = { [UPLOADS]: WAITS };
  const { doc, calls, setHome } = await following(routes, [ASK]);
  await check(doc, "uploads.example.com");
  assert.equal(lines(doc).at(-1), WAITING_LINE);
  const before = asks(calls).length;
  routes[UPLOADS] = ONCE;
  setHome(home({ waiting: [] }));
  await poll(doc);
  assert.deepEqual(asks(calls).slice(before), ["?host=uploads.example.com"]);
  assert.ok(!lines(doc).includes(WAITING_LINE), lines(doc).join(" | "));
  assert.ok(lines(doc).includes("You answered 1 earlier send to this host. Find them in Approvals."), lines(doc).join(" | "));
});

test("#269: a poll with the same ids waiting, in any order, asks nothing", async () => {
  const { doc, calls, setHome } = await following({ [UPLOADS]: WAITS }, [ASK, ASK2]);
  await check(doc, "uploads.example.com");
  const before = asks(calls).length;
  await poll(doc);
  setHome(home({ waiting: [ASK2, ASK] }));
  await poll(doc);
  assert.equal(asks(calls).length, before, "no ask on a quiet poll");
});

test("#269: no answer drawn, a refusal drawn, or a service that cannot check a host: nothing is asked", async () => {
  const { doc, calls, setHome } = await following({
    "GET policy/host-check?host=user%40x.com": { status: 400, body: { error: "Type a host name, like api.example.com: no https://, no path." } },
    "GET policy/host-check?host=api.stripe.com": { status: 501, body: { error: "this Mandu service cannot check a host" } },
  }, []);
  setHome(home({ waiting: [ASK] }));
  await poll(doc);
  assert.equal(asks(calls).length, 0, "nothing checked yet");
  await check(doc, "user@x.com");
  setHome(home({ waiting: [] }));
  await poll(doc);
  assert.equal(asks(calls).length, 1, "a refusal is not asked again");
  await check(doc, "api.stripe.com");
  assert.equal(form(doc).hidden, true);
  setHome(home({ waiting: [ASK] }));
  await poll(doc);
  assert.equal(asks(calls).length, 2, "a service that cannot check is not asked again");
});

test("#269: a Check pressed while the re-ask is out wins; the late re-ask draws nothing", async () => {
  let release: (v: unknown) => void = () => {};
  const routes: Record<string, unknown> = { [UPLOADS]: NOTHING, "GET policy/host-check?host=api.stripe.com": STRIPE };
  const { doc, setHome } = await following(routes, []);
  await check(doc, "uploads.example.com");
  routes[UPLOADS] = new Promise((r) => { release = r; });
  setHome(home({ waiting: [ASK] }));
  await poll(doc);
  await check(doc, "api.stripe.com");
  assert.equal(lines(doc)[0], "2 of your secrets may be sent there: ~/proj/.env, ~/other/key.txt.");
  release(WAITS);
  await tick();
  assert.equal(lines(doc)[0], "2 of your secrets may be sent there: ~/proj/.env, ~/other/key.txt.", "the newer answer stays");
  assert.match(answer(doc).querySelector("ul").getAttribute("aria-label"), /api\.stripe\.com/);
});

test("#269: the same answer after the change is not drawn again: a focused file button keeps the focus", async () => {
  const { doc, calls, setHome } = await following({ "GET policy/host-check?host=api.stripe.com": STRIPE }, []);
  await check(doc, "api.stripe.com");
  const lis = [...answer(doc).querySelectorAll("li")];
  const file = answer(doc).querySelector("button.by-who-link");
  file.focus();
  const before = asks(calls).length;
  setHome(home({ waiting: [ASK] }));
  await poll(doc);
  assert.deepEqual(asks(calls).slice(before), ["?host=api.stripe.com"], "asked again");
  assert.ok(same(lis, [...answer(doc).querySelectorAll("li")]), "the same nodes");
  assert.equal(doc.activeElement, file, "the focus stays on the file");
});

test("#269: your rules and the questions waiting changed in one poll: the host is asked once, by the Rules read", async () => {
  const routes: Record<string, unknown> = { [UPLOADS]: WAITS, "GET policy/changes?limit=1": { changes: [] } };
  const { doc, calls, setHome } = await following(routes, [ASK], { rulesVersion: "v1" });
  // Check pressed, not Enter: no Rules read while the focus is in a text box.
  await check(doc, "uploads.example.com", "button");
  const before = asks(calls).length;
  const reads = calls.filter((c) => c.url.endsWith("/api/policy/panel")).length;
  routes[UPLOADS] = ALLOWED;
  setHome(home({ waiting: [], rulesVersion: "v2" }));
  await poll(doc);
  assert.equal(calls.filter((c) => c.url.endsWith("/api/policy/panel")).length, reads + 1, "Rules read again");
  assert.deepEqual(asks(calls).slice(before), ["?host=uploads.example.com"], "one ask, not two");
  assert.equal(lines(doc)[0], "1 of your secrets may be sent there: ~/proj/.env.");
});

test("#269: a hidden tab compares nothing; the first poll after its return asks", async () => {
  let tickPoll: () => void = () => {};
  const routes: Record<string, unknown> = { [UPLOADS]: NOTHING };
  const { doc, calls, setHome } = await following(routes, [], {}, (w) => { w.setInterval = (f: () => void) => { tickPoll = f; return 0; }; });
  await check(doc, "uploads.example.com");
  const before = asks(calls).length;
  const homes = () => calls.filter((c) => c.url.endsWith("/api/home")).length;
  routes[UPLOADS] = WAITS;
  setHome(home({ waiting: [ASK] }));
  Object.defineProperty(doc, "visibilityState", { value: "hidden", configurable: true });
  const read = homes();
  tickPoll();
  await tick(30);
  assert.equal(homes(), read + 1, "the hidden tab still polls Home");
  assert.equal(asks(calls).length, before, "but asks no host");
  await poll(doc);
  assert.deepEqual(asks(calls).slice(before), ["?host=uploads.example.com"]);
  assert.equal(lines(doc).at(-1), WAITING_LINE);
});

test("#269: on another page nothing is asked; back on Rules its read asks once, and the next poll with the same ids nothing", async () => {
  const routes: Record<string, unknown> = { [UPLOADS]: NOTHING };
  const { doc, window, calls, setHome } = await following(routes, []);
  await check(doc, "uploads.example.com");
  const before = asks(calls).length;
  (doc.querySelector('header a[data-page-link="approvals"], nav a[data-page-link="approvals"]') as any).click();
  await tick();
  assert.equal(window.location.pathname, "/mandu/approvals");
  routes[UPLOADS] = WAITS;
  setHome(home({ waiting: [ASK] }));
  await poll(doc);
  assert.equal(asks(calls).length, before, "Approvals asks nothing");
  navRules(doc);
  await tick();
  assert.deepEqual(asks(calls).slice(before), ["?host=uploads.example.com"], "the Rules read asks once");
  assert.equal(lines(doc).at(-1), WAITING_LINE);
  await poll(doc);
  assert.equal(asks(calls).length, before + 1, "the poll after it: the same ids, nothing");
});

// ── A Rules read that answers inside a slow poll (queue item #303) ───────────
// A Rules read asked while a Home poll is out (a `rulesVersion` change taken
// by the poll before, a Remove) asks the drawn host with the ids it knew.
// When it answers before that poll does, the poll compares as usual: the
// read is left the ask only while it is still out. No file row is drawn
// here (no file rule, no folder, no typed path), so #284's file follow,
// which would read again, cannot mend it by accident.

type Held = { promise: Promise<unknown>; release: (v: unknown) => void };
const held = (): Held => { let release: (v: unknown) => void = () => {}; const promise = new Promise((r) => { release = r; }); return { promise, release }; };
/** A rule that is no file rule: a send allowed to a host, with Remove. */
const HOST_RULE = { id: "r-0001", kind: "release-allow", subject: "uploads.example.com", effect: "sending allowed", reach: "from any source to uploads.example.com", hits: 2, actions: { remove: true, flip: "block" } };
const NO_FILES = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [HOST_RULE] } };

/** Rules with no file row, `waiting` waiting at rulesVersion v1, one poll
 *  compared and the drawn host checked (Check pressed: no text box has the
 *  focus). `pollHeld` asks a poll whose answer waits for its `release`;
 *  `holdPanel` holds the answer of the next Rules read. Once none is held,
 *  each answers at once, Home with `now.home`. */
async function racing(routes: Record<string, unknown>, waiting: unknown[]) {
  const homes: Held[] = [];
  const panels: Held[] = [];
  const now = { home: home({ waiting, rulesVersion: "v1" }) as unknown };
  const r = load({ url: "http://127.0.0.1:4500/mandu/rules", routes: {
    "GET policy/by-who": { byWho: VM }, "GET secrets": { panel: { labels: [] } }, "GET policy/changes?limit=1": { changes: [] },
    "POST policy/rules/change": { applied: true, changeId: "c-1" },
    ...swap(routes),
    "GET home": () => homes.shift()?.promise ?? now.home,
    "GET policy/panel": () => panels.shift()?.promise ?? NO_FILES,
  } });
  await tick();
  await poll(r.doc);
  await check(r.doc, "uploads.example.com", "button");
  assert.equal(r.doc.querySelector("#page-rules .file-row, #page-rules [data-path]"), null, "no file row drawn");
  const hold = (list: Held[]) => { const h = held(); list.push(h); return h; };
  const pollHeld = () => {
    const h = hold(homes);
    Object.defineProperty(r.doc, "visibilityState", { value: "visible", configurable: true });
    r.doc.dispatchEvent(new r.doc.defaultView.Event("visibilitychange"));
    return h;
  };
  /** Releases `h` with `answer`, which later polls answer too. */
  const answerWith = (h: Held, answer: unknown) => { now.home = answer; h.release(answer); };
  return { ...r, pollHeld, answerWith, holdPanel: () => hold(panels) };
}
const panelReads = (calls: any[]) => calls.filter((c) => c.url.endsWith("/api/policy/panel")).length;

for (const [name, from, to, drawn, then] of [
  ["a send to the drawn host starts waiting", [] as unknown[], [ASK] as unknown[], NOTHING, WAITS],
  ["that send answered once elsewhere", [ASK] as unknown[], [] as unknown[], WAITS, ONCE],
] as const) {
  test(`#303: ${name} while a Rules read answered first: that poll still asks the host, and the waiting line follows`, async () => {
    const routes: Record<string, unknown> = { [UPLOADS]: drawn };
    const { doc, calls, pollHeld, answerWith } = await racing(routes, from);
    assert.equal(lines(doc).includes(WAITING_LINE), from.length > 0);
    const before = asks(calls).length;
    const reads = panelReads(calls);
    // Poll A (your rules changed elsewhere) and poll P, both out.
    const a = pollHeld();
    const p = pollHeld();
    // A answers first: its Rules read is asked after P was, and answers
    // before P does, with the ids A knew.
    answerWith(a, home({ waiting: from, rulesVersion: "v2" }));
    await tick(30);
    assert.equal(panelReads(calls), reads + 1, "Rules read again");
    assert.deepEqual(asks(calls).slice(before), ["?host=uploads.example.com"], "the read asked the host");
    // Then the questions waiting change on the server, and P answers.
    routes[UPLOADS] = then;
    answerWith(p, home({ waiting: to, rulesVersion: "v2" }));
    await tick(30);
    assert.deepEqual(asks(calls).slice(before), ["?host=uploads.example.com", "?host=uploads.example.com"], "P asked once more");
    assert.equal(lines(doc).includes(WAITING_LINE), to.length > 0, lines(doc).join(" | "));
    assert.equal(panelReads(calls), reads + 1, "and read no Rules");
    await poll(doc);
    assert.equal(asks(calls).length, before + 2, "the poll after it, the same ids: nothing");
  });
}

test("#303: a Rules read still out when the poll answers: the poll asks nothing, and the read's answer asks once", async () => {
  const routes: Record<string, unknown> = { [UPLOADS]: NOTHING };
  const { doc, calls, pollHeld, answerWith, holdPanel } = await racing(routes, []);
  const before = asks(calls).length;
  const a = pollHeld();
  const p = pollHeld();
  const read = holdPanel();
  answerWith(a, home({ waiting: [], rulesVersion: "v2" }));
  await tick(30);
  routes[UPLOADS] = WAITS;
  answerWith(p, home({ waiting: [ASK], rulesVersion: "v2" }));
  await tick(30);
  assert.equal(asks(calls).length, before, "the read is out: the poll leaves it the ask");
  read.release(NO_FILES);
  await tick(30);
  assert.deepEqual(asks(calls).slice(before), ["?host=uploads.example.com"], "one ask, not two");
  assert.equal(lines(doc).at(-1), WAITING_LINE);
  await poll(doc);
  assert.equal(asks(calls).length, before + 1, "and the next poll nothing");
});

test("#303: a Rules read dropped as older (a Remove's read overtook it) is not waited for: the poll asks the host itself", async () => {
  const routes: Record<string, unknown> = { [UPLOADS]: NOTHING };
  const { doc, calls, pollHeld, answerWith, holdPanel } = await racing(routes, []);
  const before = asks(calls).length;
  const a = pollHeld();
  const p = pollHeld();
  // A's Rules read (your rules changed elsewhere) stays out...
  const late = holdPanel();
  answerWith(a, home({ waiting: [], rulesVersion: "v2" }));
  await tick(30);
  // ...while a Remove pressed meanwhile writes, and its own read answers.
  rowOf(doc, /uploads\.example\.com/).querySelector(".file-more").click();
  ([...rowOf(doc, /uploads\.example\.com/).nextElementSibling.querySelectorAll("button")] as any[]).find((b) => b.textContent === "Remove").click();
  await tick(30);
  assert.ok(calls.some((c) => c.method === "POST" && c.url.endsWith("/policy/rules/change")), "the rule was removed");
  assert.deepEqual(asks(calls).slice(before), ["?host=uploads.example.com"], "the Remove's read asked the host");
  routes[UPLOADS] = WAITS;
  answerWith(p, home({ waiting: [ASK], rulesVersion: "v3" }));
  await tick(30);
  assert.deepEqual(asks(calls).slice(before), ["?host=uploads.example.com", "?host=uploads.example.com"], "A's read, still out, will be dropped: P asks");
  assert.equal(lines(doc).at(-1), WAITING_LINE);
  late.release(NO_FILES);
  await tick(30);
  assert.equal(asks(calls).length, before + 2, "the dropped read asks nothing");
  assert.equal(lines(doc).at(-1), WAITING_LINE, "nor draws over the newer answer");
});

test("#303: a Rules read that failed is no longer out: the poll it began in asks the host itself", async () => {
  const routes: Record<string, unknown> = { [UPLOADS]: NOTHING };
  const { doc, window, calls, pollHeld, answerWith } = await racing(routes, []);
  const before = asks(calls).length;
  const p = pollHeld();
  // A read fails only when a draw throws: made here by hand, once.
  const real = window.renderByWho;
  window.renderByWho = () => { window.renderByWho = real; throw new Error("draw failed"); };
  const ended = window.eval("loadRules().then(() => 'answered', () => 'failed')");
  await tick(30);
  assert.equal(await ended, "failed");
  assert.equal(asks(calls).length, before, "the failed read asked no host");
  routes[UPLOADS] = WAITS;
  answerWith(p, home({ waiting: [ASK], rulesVersion: "v1" }));
  await tick(30);
  assert.deepEqual(asks(calls).slice(before), ["?host=uploads.example.com"], "asked at that poll");
  assert.equal(lines(doc).at(-1), WAITING_LINE);
});
