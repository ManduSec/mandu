/**
 * home-js-scan — the last `mandu scan` on the product page (public/js/home.js;
 * dashboard.md §4.25ai): Home's card and the Scan page, in jsdom over the
 * shared fetch stub (home-js-fixtures.ts), drawn from the server's view
 * models (view-model/last-scan.ts):
 *
 *   - Home: before any scan the card says how to run one, the command as
 *     code, and offers no page; after one it leads with how many of your
 *     secrets left, names the top one by name and file, says what waits, and
 *     links the Scan page; an answer without `scan` draws no card;
 *   - the Scan page at /scan: the story steps of each finding, the footnote,
 *     the long tier folded with its filter (typing asks the server for the
 *     section's matches, once per pause; Show more reads the next page),
 *     the detail panel's examples read and drawn when opened, once; History
 *     links it (§4.25ai *A long scan, in pages*);
 *   - a part that could not be read says why and reads again (the next
 *     opening, the next press); a failed page read reads again once a Home
 *     poll answers; a part of another scan (409) reads the page again;
 *   - a finding whose secret lives in a file ends its story with *Change it
 *     in Rules*, a plain link to `/rules?file=<path>` under the base path
 *     (Home's top rows too); a key not in your files has none;
 *   - everything server data is text, never markup; no 8-character run of a
 *     planted value is on either page.
 * Axes: none (display only). Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { home, JS, load, tick } from "./home-js-fixtures.js";
import { homeScanCard, scanPageVM, type LastScanWire } from "../../../src/view-model/last-scan.js";
import { scanAfter, scanHead, scanItemDetail, scanSectionPage } from "../../../src/view-model/last-scan-pages.js";

/** `GET scan`: the head, as the server sends it (rev `r1`). */
function scanRoutes(rec: LastScanWire, rev = "r1"): Record<string, unknown> {
  return { "GET scan": { scan: scanHead(scanPageVM(rec), rev) } };
}
/** The paged reads (`scan/section/<id>`, `scan/item/<id>`), answered from
 *  the server's own paging over `rec`, each asked path kept in `asked`; a
 *  `fail` path answers as `fail` says (0: no answer). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function paged(rec: LastScanWire, asked: string[] = [], fail: (path: string) => number | null = () => null, rev = "r1"): (window: any) => void {
  const page = scanPageVM(rec);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (window: any) => {
    const inner = window.fetch;
    window.fetch = (url: string, init: unknown) => {
      const m = /\/api\/(scan\/(section|item)\/([^?]+))(?:\?(.*))?$/.exec(url);
      if (!m) return inner(url, init);
      const path = `${m[1]}${m[4] ? `?${m[4]}` : ""}`;
      asked.push(path);
      const status = fail(path);
      if (status === 0) return Promise.reject(new TypeError("Failed to fetch"));
      const params = new URLSearchParams(m[4] ?? "");
      const answer = (s: number, body: unknown) => Promise.resolve({ ok: s < 400, status: s, json: () => Promise.resolve(body) });
      if (status !== null) return answer(status, { error: "refused" });
      if (params.get("rev") !== rev) return answer(409, { error: "the scan changed: read the page again", changed: true });
      const body = m[2] === "section"
        ? scanSectionPage(page, decodeURIComponent(m[3]!), { after: scanAfter(params.get("after")), q: params.get("q") ?? "" })
        : scanItemDetail(page, decodeURIComponent(m[3]!));
      return body === null ? answer(404, { error: "no such row" }) : answer(200, body);
    };
  };
}
const wait = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8Nb4C`;

function record(): LastScanWire {
  return {
    version: 1, ranAt: "2026-10-21T09:00:00.000Z", sessions: { "claude-code": 3 }, duringMandu: 0, known: 2,
    findings: [
      {
        kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, sessions: 2, agents: ["claude-code"],
        first: "2026-10-01T10:00:00.000Z", last: "2026-10-19T10:00:00.000Z", how: { "command-output": 2 }, projects: ["~/shop"], duringMandu: 0,
        examples: [{ at: "2026-10-19T10:00:00.000Z", agent: "claude-code", how: "command-output", command: "cat .env <img src=x onerror=alert(1)>", project: "~/shop", mandu: "without" }],
      },
      ...Array.from({ length: 40 }, (_, i) => ({ kind: "github-token", preview: "ghp_…", sessions: 1, agents: ["codex"], how: { "your-message": 1 }, projects: [i === 7 ? "~/needle" : `~/fixtures-${i}`], duringMandu: 0 })),
    ],
    dropped: 0, capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 },
    sends: [], sendsDropped: 0, suggestions: { pending: 1, filed: 1, covered: 0 },
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function noValue(where: string, doc: any): void {
  const text = doc.body.textContent as string;
  for (let i = 0; i + 8 <= STRIPE.length; i++) {
    const piece = STRIPE.slice(i, i + 8);
    if (piece !== "sk_live_") assert.ok(!text.includes(piece), `${where} shows "${piece}"`);
  }
}

test("Home: before any scan the card says how to run one", async () => {
  const { doc, err } = load({ homeVm: { ...home(), scan: homeScanCard(null) } });
  assert.equal(err, null);
  await tick();
  const card = doc.getElementById("home-scan");
  assert.equal(card.hidden, false);
  assert.equal(card.dataset.ran, "no");
  assert.equal(doc.getElementById("home-scan-headline").textContent, "Did your agents already send a secret to the AI?");
  assert.deepEqual([...card.querySelectorAll("code")].map((c: { textContent: string }) => c.textContent), ["mandu scan", "mandu scan"]);
  assert.equal(doc.getElementById("home-scan-open").hidden, true);
});

test("Home: after a scan the card leads with what left, names the top one, says what waits and links the Scan page", async () => {
  const { doc } = load({ homeVm: { ...home(), scan: homeScanCard(record()) } });
  await tick();
  assert.equal(doc.getElementById("home-scan").dataset.ran, "yes");
  assert.equal(doc.getElementById("home-scan-headline").textContent, "1 of your secrets left this computer in your agents' requests");
  assert.equal(doc.getElementById("home-scan-when").textContent, "Scanned 21 Oct · 3 past sessions");
  const top = doc.querySelector("#home-scan-top li");
  assert.deepEqual([...top.querySelectorAll("code")].map((c: { textContent: string }) => c.textContent), ["STRIPE_KEY", "~/shop/.env"]);
  assert.match(doc.getElementById("home-scan-sentence").textContent, /start your agent with mandu claude/);
  assert.match(doc.getElementById("home-scan-suggested").textContent, /1 file that holds them has no rule yet.*Review them/);
  assert.equal(doc.getElementById("home-scan-open").hidden, false);
  noValue("Home", doc);
});

test("Home: an answer without `scan` draws no card", async () => {
  const { doc } = load({ homeVm: home() });
  await tick();
  assert.equal(doc.getElementById("home-scan").hidden, true);
});

test("the Scan page: the stories, the footnote, the long tier folded with its filter and Show more, the examples on opening; markup stays text", async () => {
  const rec = record();
  const asked: string[] = [];
  const { doc, window, calls } = load({ url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), scan: homeScanCard(rec) }, routes: scanRoutes(rec), before: paged(rec, asked) });
  await tick(30);
  assert.ok(calls.some((c) => c.url.endsWith("/api/scan")));
  assert.equal(doc.getElementById("page-scan").hidden, false);
  assert.equal(doc.getElementById("scan-headline").textContent, "1 of your secrets left this computer in your agents' requests");
  const yours = doc.querySelector('[data-section="yours"]');
  const steps = [...yours.querySelectorAll(".scan-step")].map((s: { dataset: { step: string } }) => s.dataset.step);
  assert.deepEqual(steps, ["lived", "when", "did", "went", "instead"]);
  assert.match(yours.querySelector('.scan-step[data-step="went"]').textContent, /left this computer in Claude Code's next request to Anthropic/);
  assert.equal(yours.querySelector(".scan-footnote").textContent, "2 sessions without Mandu.");
  assert.equal(doc.querySelector("img"), null, "a command carrying markup stays text");
  // The examples are read and drawn when the panel opens (scan/item/<id>).
  const fold = yours.querySelector("details.scan-more");
  assert.equal(fold.querySelector(".scan-examples"), null);
  assert.equal(asked.length, 0, "nothing read past the head before a fold opens");
  fold.open = true;
  await wait(20);
  await tick(10);
  assert.deepEqual(asked, ["scan/item/f0?rev=r1"]);
  assert.match(fold.querySelector(".scan-examples li").textContent, /^19 Oct · ~\/shop · Claude CodeThe agent ran: cat .env/);
  assert.equal(fold.querySelector(".scan-examples code").textContent, "cat .env <img src=x onerror=alert(1)>");
  fold.open = false;
  await wait(20);
  fold.open = true;
  await wait(20);
  await tick(10);
  assert.equal(asked.length, 1, "read once");
  assert.equal(fold.querySelectorAll(".scan-detail").length, 1);
  // The long tier: folded, its first 25 rows from the head, Show more reads
  // the next page, and the filter asks the server over the whole section.
  const looks = doc.querySelector('[data-section="looks"]');
  assert.ok(looks.querySelector("details.scan-fold"));
  assert.equal(looks.querySelectorAll(".scan-item").length, 25);
  const more = looks.querySelector("button.btn");
  assert.equal(more.textContent, "Show 15 more");
  more.click();
  await tick(10);
  assert.equal(asked[asked.length - 1], "scan/section/looks?after=25&rev=r1");
  assert.equal(looks.querySelectorAll(".scan-item").length, 40);
  assert.equal(more.hidden, true, "the section's end: no more");
  const input = looks.querySelector("input.scan-filter");
  // ~/needle is row 8 (in the head), so find one the head never sent too.
  input.value = "  FIXTURES-39 ";
  input.dispatchEvent(new window.Event("input"));
  await wait(200);
  await tick(10);
  assert.equal(asked[asked.length - 1], "scan/section/looks?after=0&q=fixtures-39&rev=r1");
  assert.equal(looks.querySelectorAll(".scan-item").length, 1);
  input.value = "nee";
  input.dispatchEvent(new window.Event("input"));
  input.value = "needle";
  input.dispatchEvent(new window.Event("input"));
  await wait(200);
  await tick(10);
  assert.equal(asked.filter((p) => p.includes("q=nee&")).length, 0, "the keys typed in a row are asked once");
  assert.equal(looks.querySelectorAll(".scan-item").length, 1);
  input.value = "nothing-like-it";
  input.dispatchEvent(new window.Event("input"));
  await wait(200);
  await tick(10);
  assert.equal(looks.querySelector(".empty").textContent, "None matches.");
  // Cleared: the head's rows again, without a read.
  const before = asked.length;
  input.value = "";
  input.dispatchEvent(new window.Event("input"));
  await wait(200);
  await tick(10);
  assert.equal(asked.length, before);
  assert.equal(looks.querySelectorAll(".scan-item").length, 25);
  assert.equal(more.hidden, false);
  noValue("the Scan page", doc);
});

test("a part that could not be read says why, and reads again: a row's examples on the next opening, the next rows on the next press", async () => {
  const rec = record();
  const asked: string[] = [];
  let down = true;
  const { doc, window } = load({ url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), scan: homeScanCard(rec) }, routes: scanRoutes(rec), before: paged(rec, asked, () => (down ? 0 : null)) });
  await tick(30);
  const fold = doc.querySelector('[data-section="yours"] details.scan-more');
  fold.open = true;
  await wait(20);
  await tick(10);
  assert.equal(fold.querySelector(".scan-unread").textContent, "The examples could not be read. The dashboard could not reach its own server. Refresh in a moment.");
  const looks = doc.querySelector('[data-section="looks"]');
  const more = looks.querySelector("button.btn");
  more.click();
  await tick(10);
  assert.equal(looks.querySelectorAll(".scan-item").length, 25, "the rows drawn stay");
  assert.match(looks.querySelector(".scan-unread").textContent, /^The next rows could not be read\. The dashboard could not reach its own server/);
  assert.equal(more.hidden, false, "Show more stays, to try again");
  down = false;
  fold.open = false;
  await wait(20);
  fold.open = true;
  await wait(20);
  await tick(10);
  assert.equal(fold.querySelector(".scan-unread"), null);
  assert.ok(fold.querySelector(".scan-examples li"));
  more.click();
  await tick(10);
  assert.equal(looks.querySelectorAll(".scan-item").length, 40);
  assert.equal(looks.querySelector(".scan-unread").hidden, true);
});

test("a Scan page whose read failed reads again once a Home poll answers; a part of another scan (409) reads the page again", async () => {
  const rec = record();
  let first = true;
  const asked: string[] = [];
  const { doc, window, calls } = load({
    url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), scan: homeScanCard(rec) },
    routes: { "GET scan": () => (first ? { status: 502, body: null } : { scan: scanHead(scanPageVM(rec), "r2") }) },
    before: paged(rec, asked),
  });
  await tick(30);
  assert.match(doc.getElementById("scan-sentence").textContent, /^The last scan could not be read\. The dashboard server answered with an error \(502\)/);
  first = false;
  const reads = (): number => calls.filter((c) => c.url.endsWith("/api/scan")).length;
  const failed = reads();
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick(30);
  assert.equal(reads(), failed + 1, "read again after the poll");
  assert.equal(doc.getElementById("scan-headline").textContent, "1 of your secrets left this computer in your agents' requests");
  // The head is of rev r2; the server pages r1: a part asked is refused, and the page reads its head again.
  const fold = doc.querySelector('[data-section="yours"] details.scan-more');
  fold.open = true;
  await wait(20);
  await tick(30);
  assert.deepEqual(asked, ["scan/item/f0?rev=r2"]);
  assert.equal(reads(), failed + 2, "the page read again");
  // Once the page is read, a poll does not read it again.
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick(30);
  assert.equal(reads(), failed + 2);
});

test("color and the figure (§4.25ai): the tones the server sent, each with a mark; the figure's two rows in both layouts, with the finding's facts as text", async () => {
  const rec = record();
  rec.findings[0]!.examples![0]!.provider = "anthropic";
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), scan: homeScanCard(rec) }, routes: scanRoutes(rec), before: paged(rec) });
  await tick(30);
  assert.equal(doc.getElementById("page-scan").dataset.tone, "bad");
  assert.ok(doc.querySelector("#scan-headline .tone-mark svg"), "the headline's ✗ says it beside the red");
  // The figure: without Mandu (red), with it (green), wide and tall.
  const fig = doc.querySelector("#scan-figure figure.scan-fig");
  assert.equal(doc.getElementById("scan-figure").hidden, false);
  assert.equal(fig.querySelector(".scan-fig-title").textContent, "What happened, and what Mandu does instead");
  const rows = [...fig.querySelectorAll(".scan-fig-row")];
  assert.deepEqual(rows.map((r: { dataset: { row: string; tone: string } }) => [r.dataset.row, r.dataset.tone]), [["without", "bad"], ["with", "ok"]]);
  for (const r of rows) {
    assert.equal(r.querySelectorAll("svg.sf-svg.sf-w").length, 1);
    assert.equal(r.querySelectorAll("svg.sf-svg.sf-t").length, 1);
    const labels = [...r.querySelectorAll("svg.sf-w text.sf-lbl")].map((t: { textContent: string }) => t.textContent);
    assert.deepEqual(labels, ["~/shop/.env", "Claude Code", "Anthropic"]);
    assert.equal(r.querySelectorAll(".scan-fig-steps li").length, 3);
  }
  assert.ok(rows[0].querySelector("svg.sf-w .sf-got-bad") && rows[0].querySelector("svg.sf-w .sf-net:not(.sf-net-calm)"), "without: the real value at the model, the internet red");
  assert.ok(rows[1].querySelector("svg.sf-w .sf-got-ok") && rows[1].querySelector("svg.sf-w .sf-zone") && rows[1].querySelector("svg.sf-w .sf-pill"), "with: Mandu's zone, its pill, only the mask at the model");
  assert.ok(rows[1].querySelector("svg.sf-w .sf-net-calm"), "with: the internet is not red");
  assert.match(fig.querySelector(".scan-safe").textContent, /^With Mandu, this secret stays safe: the AI sees only its mask/);
  assert.equal(doc.querySelector('use[href="#scan-key"]') !== null && doc.getElementById("scan-key") !== null, true, "the glyphs are the page's own");
  // The sections and rows: tone, mark and word.
  const yours = doc.querySelector('[data-section="yours"]');
  assert.equal(yours.dataset.tone, "bad");
  assert.ok(yours.querySelector("h2 .tone-mark"));
  const item = yours.querySelector(".scan-item");
  assert.equal(item.dataset.tone, "bad");
  assert.equal(item.querySelector(".scan-badge").textContent, "Reached the AI");
  assert.equal(item.querySelector(".scan-flow").textContent, "~/shop/.env→Claude Code→Anthropic’s AI got the real value");
  assert.equal(item.querySelector('.scan-step[data-step="went"]').dataset.tone, "bad");
  assert.equal(item.querySelector('.scan-step[data-step="instead"]').dataset.tone, "ok");
  assert.equal(item.querySelector('.scan-footnote span[data-tone="bad"]').textContent, "2 sessions without Mandu.");
  assert.equal(doc.querySelector('[data-section="looks"]').dataset.tone, "warn");
  noValue("the Scan page", doc);
});

test("Home's card: red when your secrets left, with the two small flows and the green line; green when none did", async () => {
  const rec = record();
  rec.findings[0]!.examples![0]!.provider = "anthropic";
  const { doc } = load({ homeVm: { ...home(), scan: homeScanCard(rec) } });
  await tick();
  const card = doc.getElementById("home-scan");
  assert.equal(card.dataset.tone, "bad");
  assert.ok(card.querySelector("#home-scan-headline .tone-mark"));
  assert.equal(doc.getElementById("home-scan-headline").textContent, "1 of your secrets left this computer in your agents' requests");
  const flows = [...card.querySelectorAll("#home-scan-figure .scan-flow")];
  assert.deepEqual(flows.map((f: { dataset: { tone: string } }) => f.dataset.tone), ["bad", "ok"]);
  assert.match(flows[1].textContent, /masked by Mandu→Claude Code→Anthropic’s AI got only the mask$/);
  assert.equal(doc.getElementById("home-scan-safe").hidden, false);
  assert.match(doc.getElementById("home-scan-safe").textContent, /^With Mandu, this secret stays safe/);
  noValue("Home", doc);
  const none = load({ homeVm: { ...home(), scan: homeScanCard({ ...record(), findings: [], sends: [] }) } });
  await tick();
  assert.equal(none.doc.getElementById("home-scan").dataset.tone, "ok");
  assert.equal(none.doc.getElementById("home-scan-figure").hidden, true, "nothing happened: no flows");
  assert.match(none.doc.getElementById("home-scan-safe").textContent, /^With Mandu, your secrets stay safe/);
});

test("Change it in Rules (§4.25ai): a file finding's story and a send end with the link to its rule, Home's top rows carry it, a key not in your files has none; a path with markup stays text", async () => {
  const rec = record();
  const odd = "~/shop/<img src=x onerror=alert(1)>.env";
  rec.findings.splice(1, 0, { ...rec.findings[0]!, preview: `OTHER in ${odd}`, source: { path: odd, name: "OTHER" } });
  rec.sends = [{ kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, to: "other-host", host: "hooks.vendor.dev", sessions: 1, ran: 1, stoppedByMandu: 0, via: ["curl"], by: ["variable"], agents: ["claude-code"], duringMandu: 0 }];
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), scan: homeScanCard(rec) }, routes: scanRoutes(rec), before: paged(rec) });
  await tick(30);
  const yours = doc.querySelector('[data-section="yours"]');
  const items = [...yours.querySelectorAll(".scan-item")];
  assert.equal(items.length, 2);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const links = items.map((i: any) => [...i.querySelectorAll("a.secret-rule-link")]);
  assert.deepEqual(links.map((l) => l.length), [1, 1], "one link per file finding");
  const a = links[0]![0];
  assert.equal(a.textContent, "Change it in Rules");
  assert.equal(a.getAttribute("aria-label"), "Change the rule for ~/shop/.env in Rules");
  assert.equal(a.getAttribute("href"), "/mandu/rules?file=~/shop/.env");
  assert.equal(a.dataset.pageLink, "rules");
  assert.equal(a.dataset.file, "~/shop/.env");
  // After the story's last step (what Mandu would have done), before the footnote and the fold.
  const box = a.parentElement;
  assert.equal(box.previousElementSibling.lastElementChild.dataset.step, "instead");
  assert.ok(box.nextElementSibling.classList.contains("scan-footnote"));
  assert.equal(items[0].querySelector("details.scan-more").previousElementSibling.classList.contains("scan-footnote"), true);
  // The path with markup: text in the label and the address, never an element.
  const b = links[1]![0];
  assert.equal(b.getAttribute("aria-label"), `Change the rule for ${odd} in Rules`);
  assert.equal(b.dataset.file, odd);
  assert.equal(doc.querySelector("img"), null, "markup in a path stays text");
  // A key not in your files: no link.
  assert.equal(doc.querySelectorAll('[data-section="looks"] a.secret-rule-link').length, 0);
  assert.equal(doc.querySelectorAll('[data-section="sends-other"] .scan-item a.secret-rule-link').length, 1, "a send from a file links it too");
  noValue("the Scan page", doc);
  // Home's card: each top row with a file carries the same link, after its line.
  const h = load({ homeVm: { ...home(), scan: homeScanCard(rec) } });
  await tick();
  const rows = [...h.doc.querySelectorAll("#home-scan-top li")];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const homeLinks = rows.map((r: any) => r.querySelector("a.secret-rule-link"));
  assert.equal(homeLinks[0].getAttribute("href"), "/mandu/rules?file=~/shop/.env");
  assert.equal(homeLinks[0].getAttribute("aria-label"), "Change the rule for ~/shop/.env in Rules");
  assert.ok(homeLinks[0].parentElement.previousElementSibling.classList.contains("scan-top-how"), "after its line");
  assert.equal(homeLinks[1].dataset.file, odd);
  assert.equal(h.doc.querySelector("img"), null);
  noValue("Home", h.doc);
});

test("home.js declares each top-level function once (a module refuses a second; jsdom's script took the later one silently)", () => {
  const names = [...JS.matchAll(/^(?:async )?function\s+([A-Za-z0-9_$]+)\s*\(/gm)].map((m) => m[1]!);
  const twice = names.filter((n, i) => names.indexOf(n) !== i);
  assert.deepEqual(twice, []);
});

test("History links the Scan page", async () => {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/history" });
  await tick();
  const a = doc.querySelector('#history-scan a[data-page-link="scan"]');
  assert.equal(a.getAttribute("href"), "/mandu/scan", "under the base path, as the page writes its links");
});
