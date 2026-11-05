/**
 * home-js-plugins — the Plugins page on the product page (public/js/home.js;
 * dashboard.md §4.25aj), in jsdom over the shared fetch stub
 * (home-js-fixtures.ts), drawn from the server's view model
 * (view-model/plugins.ts):
 *
 *   - /plugins is a page: Plugins marked current, its tab title, the read
 *     of `GET plugins`;
 *   - one live attachment: the service's line with its mark, OpenClaw's
 *     group with what it covers (the command as code), the card's state
 *     with its mark, its facts, since when, the posture name and its
 *     sentence, the cost notice with the fix's commands as code, and its
 *     links: the session page (`/agents/openclaw%3Amain`, opened in place)
 *     and History found by "OpenClaw";
 *   - nothing attached: the set-up's commands as code, in order; the
 *     service stopped: plain with nothing attached (no mark, not the warn
 *     ink, no command), amber with its mark and how to start it once an
 *     agent is declared;
 *   - with a clipboard, each command the page asks you to run has a Copy
 *     (#118's runCode, dashboard.md §4.25b): the set-up's steps, the
 *     stopped service line's two, a card's notice's three and a lost
 *     route's three; a click copies exactly the command; the agent and
 *     session names on a card, the stopped card's start command and the
 *     covers line's command stay plain code;
 *   - a read that fails says so; a Home poll reads the page again, and an
 *     answer the same as the last draws nothing again;
 *   - server words are text, never markup.
 * Axes: none (display only). Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PUB, load, tick } from "./home-js-fixtures.js";
import { perSelector, resolveCssVars, stylesAt } from "./css-flatten.js";
import { pluginsPage, type PluginFacts, type PluginSessionFacts } from "../../../src/view-model/plugins.js";

const SESSION = "openclaw:main";
const URL_ = "http://127.0.0.1:4500/mandu/plugins";

function session(over: Partial<PluginSessionFacts> = {}): PluginSessionFacts {
  return { session: SESSION, kind: "openclaw-plugin", agent: "main", declared: true, answering: true, poolState: null, secrets: { found: 2, registered: 2, at: "2026-10-25T09:00:01.000Z" }, route: null, ...over };
}
function facts(over: Partial<PluginFacts> = {}): PluginFacts {
  return { serviceRunning: true, sessions: [session()], live: new Map([[SESSION, Date.now() - 60_000]]), known: new Set([SESSION]), ...over };
}
const routes = (f: PluginFacts) => ({ "GET plugins": { plugins: JSON.parse(JSON.stringify(pluginsPage(f))) } });
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (n: any): string => String(n?.textContent ?? "").replace(/\s+/g, " ").trim();

/** The product page's own styles, as index.html links them. */
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");
/** The color jsdom computes for `n` once the page's styles cascade
 *  (css-dim-ink.test.ts), and the warn ink's. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function inks(doc: any, n: any): { color: string; warn: string } {
  const sheet = doc.createElement("style");
  sheet.textContent = perSelector(resolveCssVars(stylesAt(CSS, 1280), "light"));
  doc.head.append(sheet);
  const probe = doc.createElement("i");
  probe.style.color = /\.token-probe \{ --probe:\s*([^;]+);/.exec(resolveCssVars(`${CSS}\n.token-probe { --probe: var(--warn); }`, "light"))![1]!.trim();
  doc.body.append(probe);
  const out = { color: doc.defaultView.getComputedStyle(n).color, warn: doc.defaultView.getComputedStyle(probe).color };
  probe.remove();
  sheet.remove();
  return out;
}

test("/plugins is a page: Plugins is current, the tab says so, and the page is read", async () => {
  const { doc, err, calls } = load({ url: URL_, routes: routes(facts()) });
  assert.equal(err, null);
  await tick(30);
  assert.equal(doc.getElementById("page-plugins").hidden, false);
  assert.equal(doc.querySelector('#nav a[aria-current="page"]').getAttribute("data-page-link"), "plugins");
  assert.match(doc.title, /Plugins/);
  assert.ok(calls.some((c) => c.url === "/mandu/api/plugins"), "GET /api/plugins");
});

test("one live attachment: the service, OpenClaw's group, the card's state, facts, posture, cost and links", async () => {
  const { doc } = load({ url: URL_, routes: routes(facts()) });
  await tick(30);
  assert.equal(text(doc.getElementById("plugins-intro")), "Where Mandu is attached to an agent it does not start itself: a plugin inside the agent's own app, beside the Mandu service.");
  const svc = doc.getElementById("plugins-service");
  assert.equal(svc.hidden, false);
  assert.equal(svc.dataset.tone, "ok");
  assert.ok(svc.querySelector("h2 .tone-mark svg"), "a mark beside the words, not the color alone");
  assert.equal(text(svc.querySelector("h2")), "The Mandu service is running.");
  const host = doc.getElementById("plugins-host-openclaw-plugin");
  assert.equal(text(host.querySelector("h2")), "Mandu in OpenClaw");
  assert.deepEqual([...host.querySelectorAll(".plugins-covers code")].map(text), ["mandu openclaw gateway"]);
  const card = host.querySelector(".plugin-card");
  assert.equal(card.dataset.state, "attached");
  assert.equal(card.dataset.tone, "ok");
  assert.equal(card.dataset.session, SESSION);
  assert.equal(text(card.querySelector(".plugin-state")), "Attached");
  assert.ok(card.querySelector(".plugin-state .tone-mark svg"));
  const dts = [...card.querySelectorAll(".plugin-facts dt")].map(text);
  assert.deepEqual(dts, ["Agent", "AI requests", "Registered", "Secret files", "Since"]);
  assert.deepEqual([...card.querySelectorAll(".plugin-facts dd")].slice(0, 4).map(text), [
    "OpenClaw's agent main, session openclaw:main", "Mandu's proxy answers.", "Yes, Mandu holds it.", "2 secret files registered.",
  ]);
  assert.ok(card.querySelector(".plugin-facts dd time.when"), "since when, as the page's times are drawn");
  assert.match(text(card.querySelector(".plugin-posture")), /^Protection here: gated\. The AI sees your secrets masked, because every model call goes through Mandu\./);
  const notice = card.querySelector(".plugin-notice");
  assert.equal(text(notice.querySelector(".posture-title")), "While this runs, your other agents lose a check.");
  assert.deepEqual([...notice.querySelectorAll("code")].map(text), ["mandu openclaw gateway", "mandu serve stop", "mandu openclaw uninstall"]);
  const [open, hist] = [...card.querySelectorAll(".plugin-links a")];
  assert.equal(open.getAttribute("href"), "/mandu/agents/openclaw%3Amain");
  assert.equal(text(open), "Open its session");
  assert.equal(hist.getAttribute("href"), "/mandu/history?q=OpenClaw");
  assert.equal(host.querySelector(".plugins-setup"), null, "attached: no set-up");
});

test("the card's links open the session page and History found by OpenClaw, in place", async () => {
  const { doc, window } = load({ url: URL_, routes: routes(facts()) });
  await tick(30);
  doc.querySelector('.plugin-links a[data-page-link="history"]').click();
  await tick(10);
  assert.equal(doc.getElementById("page-history").hidden, false);
  assert.equal(doc.getElementById("history-q").value, "OpenClaw", "History opens found by the host's name");
  assert.equal(window.location.pathname + window.location.search, "/mandu/history?q=OpenClaw");
  window.history.back();
  await tick(30);
  const again = load({ url: URL_, routes: routes(facts()) });
  await tick(30);
  again.doc.querySelector('.plugin-links a[data-page-link="agent"]').click();
  await tick(10);
  assert.equal(again.doc.getElementById("page-agent").hidden, false);
  assert.equal(again.window.location.pathname, "/mandu/agents/openclaw%3Amain");
});

test("nothing attached: the set-up's commands as code, in order; the service stopped: how to start it", async () => {
  const { doc } = load({ url: URL_, routes: routes(facts({ sessions: [], live: new Map(), known: new Set() })) });
  await tick(30);
  const setup = doc.querySelector("#plugins-host-openclaw-plugin .plugins-setup");
  assert.equal(text(setup.querySelector("p")), "Not attached. To attach OpenClaw, run:");
  assert.deepEqual([...setup.querySelectorAll("li code")].map(text), ["mandu openclaw install", "openclaw gateway restart"]);
  assert.equal(doc.querySelector(".plugin-card"), null);

  // Nothing attached and the service stopped: a plain fact, no mark, not
  // the warn ink (§4.25aj, 2026-10-26); the set-up starts with the service's.
  const down = load({ url: URL_, routes: routes(facts({ serviceRunning: false, sessions: [], live: null, known: new Set() })) });
  await tick(30);
  const svc = down.doc.getElementById("plugins-service");
  assert.equal(svc.dataset.tone, "plain");
  assert.equal(svc.querySelector(".tone-mark"), null, "no mark");
  assert.equal(text(svc.querySelector("h2")), "The Mandu service is not running.");
  assert.equal(text(svc.querySelector("p")), "You need it only to attach Mandu to an agent as a plugin; the steps are below.");
  assert.equal(svc.querySelector("p code"), null);
  const plain = inks(down.doc, svc.querySelector("h2"));
  assert.notEqual(plain.color, plain.warn, "the headline is not drawn in the warn ink");
  assert.deepEqual([...down.doc.querySelectorAll(".plugins-setup li code")].map(text), ["mandu serve install", "mandu openclaw install", "openclaw gateway restart"]);

  // An agent declared and the service stopped: amber, its mark, how to start it.
  const held = load({ url: URL_, routes: routes(facts({ serviceRunning: false, sessions: [session({ answering: false })], live: null })) });
  await tick(30);
  const warn = held.doc.getElementById("plugins-service");
  assert.equal(warn.dataset.tone, "warn");
  assert.ok(warn.querySelector("h2 .tone-mark svg"), "the warn line keeps its mark");
  assert.equal(text(warn.querySelector("h2")), "The Mandu service is not running.");
  assert.deepEqual([...warn.querySelectorAll("p code")].map(text), ["mandu serve start", "mandu serve install"]);
  const amber = inks(held.doc, warn.querySelector("h2"));
  assert.equal(amber.color, amber.warn, "the headline is drawn in the warn ink");
  assert.equal(held.doc.querySelector(".plugin-card").dataset.state, "stopped");
});

test("a lapsed one is red with its mark; a failed read says so; server words stay text", async () => {
  const { doc } = load({ url: URL_, routes: routes(facts({ live: new Map() })) });
  await tick(30);
  const card = doc.querySelector(".plugin-card");
  assert.deepEqual([card.dataset.state, card.dataset.tone, text(card.querySelector(".plugin-state"))], ["lapsed", "bad", "Not registered"]);
  assert.equal(card.querySelector(".plugin-notice"), null);

  const failed = load({ url: URL_, routes: { "GET plugins": { status: 500, body: { error: "the Plugins page could not be read" } } } });
  await tick(30);
  assert.match(text(failed.doc.getElementById("plugins-intro")), /^The Plugins page could not be read\./);
  assert.equal(failed.doc.getElementById("plugins-service").hidden, true);

  const vm = pluginsPage(facts());
  vm.hosts[0]!.cards[0]!.headline = "<img src=x onerror=alert(1)>";
  const marked = load({ url: URL_, routes: { "GET plugins": { plugins: vm } } });
  await tick(30);
  assert.equal(marked.doc.querySelector(".plugin-card img"), null, "markup in server words stays text");
  assert.match(text(marked.doc.querySelector(".plugin-state")), /<img src=x/);
});

test("a lost route draws the card red with what changed and the re-attach commands as code", async () => {
  const lost = session({ route: { state: "lost", since: null, problems: ["Anthropic calls go to Anthropic directly, not through Mandu"] }, recorded: { posture: "gated", gap: "model-route-lost" } });
  const { doc } = load({ url: URL_, routes: routes(facts({ sessions: [lost] })) });
  await tick(30);
  const card = doc.querySelector(".plugin-card");
  assert.deepEqual([card.dataset.state, card.dataset.tone, text(card.querySelector(".plugin-state"))], ["route-lost", "bad", "Not going through Mandu"]);
  assert.match(text(card.querySelector(".plugin-sentence")), /config was changed: Anthropic calls go to Anthropic directly/);
  assert.deepEqual([...card.querySelectorAll(".plugin-sentence code")].map(text), ["mandu openclaw install", "openclaw gateway restart", "mandu openclaw uninstall"]);
  assert.match(text(card.querySelector(".plugin-posture")), /no longer sends every model call through Mandu/);
});

test("a Home poll reads the page again: the same answer draws nothing again, a changed one does", async () => {
  let n = 0;
  let vm = JSON.parse(JSON.stringify(pluginsPage(facts())));
  const { doc, window } = load({ url: URL_, routes: { "GET plugins": () => { n++; return { plugins: vm }; } } });
  await tick(30);
  const before = doc.querySelector(".plugin-card");
  const reads = n;
  assert.ok(reads >= 1, "read when the page opened (and by the first poll)");
  // The page's poll (loadHome), as a return to the tab runs it.
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick(30);
  assert.ok(n > reads, "the poll read the Plugins page again");
  assert.equal(doc.querySelector(".plugin-card"), before, "the same answer: the card is not drawn again");
  // The proxy stops answering: the next poll draws it.
  vm = JSON.parse(JSON.stringify(pluginsPage(facts({ sessions: [session({ answering: false })] }))));
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick(30);
  assert.equal(doc.querySelector(".plugin-card").dataset.state, "down");
});

/** The page at /plugins over `f` with a stubbed clipboard; writes kept in `wrote`. */
function withClipboard(f: PluginFacts) {
  const wrote: string[] = [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const page = load({ url: URL_, routes: routes(f), before: (w: any) => {
    Object.defineProperty(w.navigator, "clipboard", { configurable: true, value: { writeText: (t: string) => (wrote.push(t), w.Promise.resolve()) } });
  } });
  assert.equal(page.err, null);
  return { ...page, wrote };
}
/** Each run-code's command and its Copy's name under `root`. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function copies(root: any): Array<[string, string]> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return [...root.querySelectorAll(".run-code")].map((r: any) => [text(r.querySelector(":scope > code")), r.querySelector(":scope > button.code-copy.run-copy").getAttribute("aria-label")]);
}

test("with a clipboard: the set-up's steps, the stopped service's line, a card's notice and a lost route's fix each have a Copy per command; names stay plain", async () => {
  // Nothing attached, the service stopped: the three set-up steps.
  const fresh = withClipboard(facts({ serviceRunning: false, sessions: [], live: null, known: new Set() }));
  await tick(30);
  const steps = ["mandu serve install", "mandu openclaw install", "openclaw gateway restart"];
  assert.deepEqual(copies(fresh.doc.querySelector(".plugins-setup-steps")), steps.map((c) => [c, `Copy ${c}`]));
  for (const b of fresh.doc.querySelectorAll(".plugins-setup-steps button.code-copy")) b.click();
  await tick();
  assert.deepEqual(fresh.wrote, steps, "each step's exact command");
  assert.equal(fresh.doc.querySelector("#plugins-service .run-code"), null, "the plain line names no command");
  assert.equal(fresh.doc.querySelector(".plugins-covers .run-code"), null, "what Mandu covers names a command; it does not ask you to run it");

  // An agent declared, the service stopped: the line's two; the card's own start stays plain.
  const held = withClipboard(facts({ serviceRunning: false, sessions: [session({ answering: false })], live: null }));
  await tick(30);
  assert.deepEqual(copies(held.doc.getElementById("plugins-service-sentence")).map(([c]) => c), ["mandu serve start", "mandu serve install"]);
  held.doc.querySelector("#plugins-service-sentence button.code-copy").click();
  await tick();
  assert.deepEqual(held.wrote, ["mandu serve start"]);
  assert.equal(held.doc.querySelector(".plugin-card .run-code"), null);

  // Attached: the notice's three; the agent and session names have none.
  const live = withClipboard(facts());
  await tick(30);
  const card = live.doc.querySelector(".plugin-card");
  const fix = ["mandu openclaw gateway", "mandu serve stop", "mandu openclaw uninstall"];
  assert.deepEqual(copies(card.querySelector(".plugin-notice")), fix.map((c) => [c, `Copy ${c}`]));
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const b of [...card.querySelectorAll(".plugin-notice button.code-copy")] as any[]) b.click();
  await tick();
  assert.deepEqual(live.wrote, fix);
  assert.deepEqual([...card.querySelectorAll(".plugin-facts code")].map(text), ["main", "openclaw:main"]);
  assert.equal(card.querySelector(".plugin-facts .run-code, .plugin-facts button"), null, "an agent or a session is no command");
  assert.equal(live.doc.querySelectorAll("#page-plugins button.code-copy").length, 3, "nothing else on the page");

  // A lost route: the fix's three; the words about what changed have none.
  const lost = session({ route: { state: "lost", since: null, problems: ["Anthropic calls go to Anthropic directly, not through Mandu"] }, recorded: { posture: "gated", gap: "model-route-lost" } });
  const red = withClipboard(facts({ sessions: [lost] }));
  await tick(30);
  const sentence = red.doc.querySelector(".plugin-card .plugin-sentence");
  const reattach = ["mandu openclaw install", "openclaw gateway restart", "mandu openclaw uninstall"];
  assert.deepEqual(copies(sentence).map(([c]) => c), reattach);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const b of [...sentence.querySelectorAll("button.code-copy")] as any[]) b.click();
  await tick();
  assert.deepEqual(red.wrote, reattach);
});
