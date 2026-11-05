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
 *   - the page follows a scan kept while it is open (§4.25ai *The Scan page
 *     follows a new scan*): a poll whose card names another `rev` reads the
 *     head once and draws it, a status line saying so once; the same `rev`
 *     reads nothing (an open fold and *Find one* stay); a read out is not
 *     doubled; a card with no `rev` (an older server) reads nothing new;
 *   - a finding whose secret lives in a file ends its story with *Change it
 *     in Rules*, a plain link to `/rules?file=<path>` under the base path
 *     (Home's top rows too); a key not in your files has none;
 *   - a key not in your files, or a send of one, says where its company
 *     replaces it: a link after the story, in a new tab, no referrer;
 *   - a card with nothing to act on folds to one line (§4.25ai *A card with
 *     nothing to act on folds*): Fold on the not-run and the clean card
 *     only, the line and its mark, kept per browser under the scan's
 *     `ranAt` (a new scan opens it; a red card never folds), Show with the
 *     focus on the heading, held for the page where storage is refused;
 *   - the page's start commands follow Home's `start` (§4.25ai *The Scan
 *     page names the agent you use*): the stop line and the summary name
 *     its list; an older server's answer leaves the page's own words; an
 *     answer that arrives after the page's read fixes the line, and an
 *     unchanged poll draws nothing again;
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

test("the Scan page before any scan (§4.25ai): its step first, with its Copy and the line under it, then the way to stop it; the empty sections take no room; after a scan, as before; a failed read shows no such line", async () => {
  const rec = record();
  let answer: unknown = { scan: scanHead(scanPageVM(null), null) };
  const { doc, window, setHome } = load({ url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), scan: { ...homeScanCard(null), rev: null } }, routes: { "GET scan": () => answer }, before: (w: any) => { // eslint-disable-line @typescript-eslint/no-explicit-any
    paged(rec)(w);
    Object.defineProperty(w.navigator, "clipboard", { configurable: true, value: { writeText: () => w.Promise.resolve() } });
  } });
  await tick(30);
  const end = doc.getElementById("scan-end");
  const step = doc.getElementById("scan-step");
  const note = doc.getElementById("scan-step-note");
  const stop = doc.getElementById("scan-stop");
  const again = doc.getElementById("scan-again");
  const shown = (): string[] => [...end.children].filter((e: { hidden: boolean }) => !e.hidden).map((e: { id: string }) => e.id);
  assert.deepEqual(shown(), ["scan-step", "scan-step-note", "scan-stop"], "the step, its line, then the way to stop it");
  assert.equal(step.textContent.replace(/Copy$/, ""), "Run it in a terminal: mandu scan");
  assert.equal(step.classList.contains("note"), false, "at body size, not a note");
  assert.equal(step.querySelector(".run-code button")?.getAttribute("aria-label"), "Copy mandu scan", "#118's Copy came along");
  assert.equal(note.textContent, "This page shows what it found when it finishes.");
  assert.match(stop.textContent, /^To keep your secrets from the AI from now on, start your agent with mandu claude/);
  assert.equal(again.hidden, true);
  assert.equal(again.textContent, "");
  assert.equal(doc.getElementById("scan-sections").hidden, true, "no section: no room");
  // A scan kept: the next poll draws it as before, Run it again last.
  answer = { scan: scanHead(scanPageVM(rec), "r1") };
  setHome({ ...home(), scan: { ...homeScanCard(rec), rev: "r1" } });
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick(30);
  assert.equal(doc.getElementById("scan-headline").textContent, homeScanCard(rec).headline);
  assert.deepEqual(shown(), ["scan-suggested", "scan-stop", "scan-again"], "as before: Run it again closes the page");
  assert.equal(step.textContent, "");
  assert.equal(note.textContent, "");
  assert.equal(again.textContent.replace(/Copy$/, ""), "Run it again: mandu scan");
  assert.doesNotMatch(doc.body.textContent, /shows what it found when it finishes/);
  assert.equal(doc.getElementById("scan-sections").hidden, false);
  assert.ok(doc.querySelector('#scan-sections [data-section="yours"] .scan-item'), "the findings draw");
  noValue("the Scan page", doc);
});

test("a Scan page whose first read failed shows neither the step nor its line", async () => {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), scan: homeScanCard(null) }, routes: { "GET scan": { status: 502, body: null } } });
  await tick(30);
  assert.match(doc.getElementById("scan-sentence").textContent, /^The last scan could not be read\./);
  assert.equal(doc.getElementById("scan-step").hidden, true);
  assert.equal(doc.getElementById("scan-step-note").hidden, true);
  assert.doesNotMatch(doc.body.textContent, /shows what it found when it finishes/);
  assert.equal(doc.getElementById("scan-sections").hidden, true);
  assert.equal(doc.getElementById("scan-end").hidden, true, "nothing of a scan under the failure");
  assert.equal(doc.getElementById("page-scan").dataset.tone, undefined, "no tone it cannot back");
});

test("a Scan page that cannot be read again shows nothing from the last read (§4.25ai): the plain headline, uncoloured, and the failure; a later read draws in full", async () => {
  const rec = record();
  let fail = false;
  const { doc, window } = load({
    url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), scan: homeScanCard(rec) },
    routes: { "GET scan": () => (fail ? { status: 502, body: null } : { scan: scanHead(scanPageVM(rec), "r1") }) },
    before: paged(rec),
  });
  await tick(30);
  const page = doc.getElementById("page-scan");
  const end = doc.getElementById("scan-end");
  const lines = ["scan-suggested", "scan-stop", "scan-again"].map((id) => doc.getElementById(id));
  assert.equal(page.dataset.tone, "bad", "drawn: the kept scan, red");
  assert.equal(lines[0].hidden, false);
  assert.match(lines[2].textContent, /Run it again: mandu scan/);
  // Home, then Scan again while its read answers 502.
  doc.querySelector('#nav [data-page-link="home"]').click();
  await tick(30);
  fail = true;
  doc.getElementById("home-scan-open").click();
  await tick(30);
  assert.equal(page.hidden, false);
  assert.match(doc.getElementById("scan-sentence").textContent, /^The last scan could not be read\. The dashboard server answered with an error \(502\)/);
  assert.equal(doc.getElementById("scan-headline").textContent, "What your agents already sent to the AI");
  assert.equal(page.dataset.tone, undefined, "no tone");
  assert.equal(doc.querySelector("#scan-headline .tone-mark"), null, "no mark");
  assert.equal(end.hidden, true);
  assert.deepEqual(lines.map((l: { textContent: string }) => l.textContent), ["", "", ""], "no stale words for Find or a screen reader");
  assert.doesNotMatch(page.textContent, /no rule yet|from now on|Run it again/);
  // The next Home poll whose read answers draws the page in full.
  fail = false;
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick(30);
  assert.equal(doc.getElementById("scan-headline").textContent, homeScanCard(rec).headline);
  assert.equal(page.dataset.tone, "bad");
  assert.equal(end.hidden, false);
  assert.equal(lines[0].hidden, false);
  assert.equal(lines[2].textContent.replace(/Copy$/, ""), "Run it again: mandu scan");
  noValue("the Scan page", doc);
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

test("Find one says how many values match (§4.25ai): a status line under the box, its words only on a change, hidden when cleared or when the read failed; the query as typed, cut, as text", async () => {
  const rec = record();
  const asked: string[] = [];
  const { doc, window } = load({ url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), scan: homeScanCard(rec) }, routes: scanRoutes(rec), before: paged(rec, asked, (path) => (path.includes("q=boom") ? 500 : null)) });
  await tick(30);
  const looks = doc.querySelector('[data-section="looks"]');
  const input = looks.querySelector("input.scan-filter");
  const line = doc.getElementById("scan-find-count-looks");
  assert.ok(line, "the section's count line");
  assert.equal(line.getAttribute("role"), "status");
  assert.ok(line.classList.contains("history-count"));
  assert.equal(input.getAttribute("aria-describedby"), "scan-find-count-looks");
  assert.equal(line.parentElement.className, "scan-filter-row", "in the filter row, after the box");
  assert.equal(line.previousElementSibling, input);
  assert.equal(line.hidden, true, "no search: hidden");
  assert.equal(line.textContent, "");
  const type = async (text: string) => {
    input.value = text;
    input.dispatchEvent(new window.Event("input"));
    await wait(200);
    await tick(10);
  };
  await type("  FIXTURES-39 ");
  assert.equal(line.textContent, "1 of 40 values matches \u201cFIXTURES-39\u201d.", "the typed text, trimmed");
  assert.equal(line.hidden, false);
  assert.equal(line.classList.contains("sr-only"), false, "a count is shown");
  await type("needle");
  assert.equal(line.textContent, "1 of 40 values matches \u201cneedle\u201d.");
  await type("fixtures");
  const total = looks.querySelectorAll(".scan-item").length;
  assert.equal(total, 25);
  assert.equal(line.textContent, "39 of 40 values match \u201cfixtures\u201d.", "the server's total, not the rows drawn");
  // Show more under the query: the same total, so the line is not written again.
  const node = line.firstChild;
  const more = looks.querySelector(".scan-section-body > button.btn");
  assert.equal(more.textContent, "Show 14 more");
  more.click();
  await tick(10);
  assert.equal(looks.querySelectorAll(".scan-item").length, 39);
  assert.equal(line.firstChild, node, "the same text node: nothing said again");
  assert.equal(line.textContent, "39 of 40 values match \u201cfixtures\u201d.");
  // None: the list keeps its words; the line says it, to a screen reader.
  await type("nothing-like-it");
  assert.equal(looks.querySelector(".empty").textContent, "None matches.");
  assert.equal(line.textContent, "No value of 40 matches \u201cnothing-like-it\u201d.");
  assert.equal(line.hidden, false, "not hidden, so it is heard");
  // A long paste is cut to 60 characters; markup stays text.
  await type(`<img src=x>${"x".repeat(300)}`);
  assert.equal(line.textContent, `No value of 40 matches \u201c<img src=x>${"x".repeat(49)}\u2026\u201d.`);
  assert.equal(line.querySelector("img"), null);
  // A failed find: the "could not be read" line, no count beside it.
  await type("boom");
  assert.match(looks.querySelector(".scan-unread").textContent, /^The matching rows could not be read\./);
  assert.equal(line.hidden, true);
  assert.equal(line.textContent, "");
  // Cleared: hidden and empty, the head's rows without a read.
  await type("needle");
  assert.equal(line.hidden, false);
  const before = asked.length;
  await type("");
  assert.equal(asked.length, before);
  assert.equal(line.hidden, true);
  assert.equal(line.textContent, "");
  assert.equal(looks.querySelectorAll(".scan-item").length, 25);
  // A section without Find one has no line.
  assert.equal(doc.querySelector('[data-section="yours"] .history-count'), null);
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

/** A clean scan: none of your secrets left, nothing worth a look, no rule waiting. */
const clean = (ranAt = "2026-10-21T09:00:00.000Z"): LastScanWire => ({ ...record(), ranAt, findings: [], sends: [], suggestions: { pending: 0, filed: 0, covered: 0 } });
const FOLD_KEY = "mandu.home.scanFolded";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const foldedNow = (doc: any): boolean => doc.getElementById("home-scan-folded").hidden === false;

test("A card with nothing to act on folds (§4.25ai): Fold on the not-run and the clean card, none on red, amber, worth a look or a rule waiting", async () => {
  const warn = { ...clean(), capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0, compressed: 2 } };
  const worth: LastScanWire = { ...clean(), sends: [{ kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, to: "other-host", host: "hooks.vendor.dev", sessions: 1, ran: 0, stoppedByMandu: 0, via: ["curl"], by: ["variable"], agents: ["claude-code"], last: "2026-10-19T10:00:00.000Z", duringMandu: 0 }] };
  const waiting = { ...clean(), suggestions: { pending: 1, filed: 0, covered: 0 } };
  for (const [name, rec, can] of [["not run", null, true], ["ok", clean(), true], ["bad", record(), false], ["warn", warn, false], ["worth a look", worth, false], ["a rule waiting", waiting, false]] as const) {
    const { doc, err } = load({ homeVm: { ...home(), scan: homeScanCard(rec) } });
    assert.equal(err, null);
    await tick();
    assert.equal(doc.getElementById("home-scan").hidden, false, name);
    assert.equal(doc.getElementById("home-scan-fold").hidden, !can, `${name}: Fold ${can ? "offered" : "not offered"}`);
    assert.equal(foldedNow(doc), false, `${name}: open at first`);
  }
});

test("Fold draws the one line, kept under the scan's ranAt, and a poll keeps it; Show opens it and focuses the heading", async () => {
  const { doc, window, setHome } = load({ homeVm: { ...home(), scan: homeScanCard(clean()) } });
  await tick();
  const poll = async (): Promise<void> => { doc.dispatchEvent(new window.Event("visibilitychange")); await tick(30); };
  const fold = doc.getElementById("home-scan-fold");
  assert.equal(fold.textContent, "Fold");
  fold.click();
  assert.equal(foldedNow(doc), true);
  assert.equal(doc.getElementById("home-scan").dataset.folded, "yes");
  assert.equal(doc.getElementById("home-scan-head").hidden, true);
  assert.equal(doc.getElementById("home-scan-body").hidden, true);
  const line = doc.getElementById("home-scan-folded-text");
  assert.equal(line.textContent, "Last scan, 21 Oct: none of your secrets left this computer.");
  assert.ok(line.querySelector(".tone-mark"), "the green mark");
  assert.equal(line.querySelector("a").getAttribute("href"), "/mandu/scan", "the line links the Scan page");
  assert.equal(doc.getElementById("home-scan").getAttribute("aria-labelledby"), "home-scan-folded-text");
  assert.equal(doc.activeElement, doc.getElementById("home-scan-show"), "the focus goes on to Show");
  assert.equal(window.localStorage.getItem(FOLD_KEY), "2026-10-21T09:00:00.000Z");
  // The next poll, the same card or a new answer of the same scan: still folded.
  await poll();
  assert.equal(foldedNow(doc), true);
  setHome({ ...home(), scan: { ...homeScanCard(clean()), rev: "r2" } });
  await poll();
  assert.equal(foldedNow(doc), true, "a redraw of the same scan stays folded");
  doc.getElementById("home-scan-show").click();
  assert.equal(foldedNow(doc), false);
  assert.equal(doc.getElementById("home-scan-head").hidden, false);
  assert.equal(doc.getElementById("home-scan-body").hidden, false);
  assert.equal(doc.activeElement, doc.getElementById("home-scan-headline"), "Show gives the card's heading the focus");
  assert.equal(window.localStorage.getItem(FOLD_KEY), null);
  await poll();
  assert.equal(foldedNow(doc), false, "opened stays open");
  noValue("Home", doc);
});

test("a folded card before any scan keeps the question's words, no mark and no link; a later scan opens it", async () => {
  const { doc, window, setHome } = load({ homeVm: { ...home(), scan: homeScanCard(null) } });
  await tick();
  doc.getElementById("home-scan-fold").click();
  assert.equal(foldedNow(doc), true);
  const line = doc.getElementById("home-scan-folded-text");
  assert.equal(line.textContent, "Did your agents already send a secret to the AI?");
  assert.equal(line.querySelector(".tone-mark"), null, "never a ✓ before a scan");
  assert.equal(line.querySelector("a"), null, "the open card links no page either");
  assert.equal(window.localStorage.getItem(FOLD_KEY), "none");
  setHome({ ...home(), scan: homeScanCard(clean()) });
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick(30);
  assert.equal(foldedNow(doc), false, "a scan opens the card");
  assert.equal(doc.getElementById("home-scan-fold").hidden, false);
});

test("a fold is kept per scan: a new ok scan opens again, a fold of an ok scan does not fold a later bad card, a fold kept in this browser folds on load", async () => {
  // Kept from an earlier visit: folded on load.
  const kept = load({ homeVm: { ...home(), scan: homeScanCard(clean()) }, storage: { [FOLD_KEY]: "2026-10-21T09:00:00.000Z" } });
  await tick();
  assert.equal(foldedNow(kept.doc), true);
  // A new scan, clean again: open.
  const again = load({ homeVm: { ...home(), scan: homeScanCard(clean("2026-10-28T09:00:00.000Z")) }, storage: { [FOLD_KEY]: "2026-10-21T09:00:00.000Z" } });
  await tick();
  assert.equal(foldedNow(again.doc), false, "a new ranAt opens it, also when ok");
  // Secrets left: never folded, even under the very key.
  const bad = { ...record(), ranAt: "2026-10-21T09:00:00.000Z" };
  const red = load({ homeVm: { ...home(), scan: homeScanCard(bad) }, storage: { [FOLD_KEY]: "2026-10-21T09:00:00.000Z" } });
  await tick();
  assert.equal(foldedNow(red.doc), false);
  assert.equal(red.doc.getElementById("home-scan-body").hidden, false);
  assert.equal(red.doc.getElementById("home-scan-fold").hidden, true);
  // The same page: folded on ok, then the next poll says secrets left.
  const { doc, window, setHome } = load({ homeVm: { ...home(), scan: homeScanCard(clean()) } });
  await tick();
  doc.getElementById("home-scan-fold").click();
  assert.equal(foldedNow(doc), true);
  setHome({ ...home(), scan: homeScanCard({ ...record(), ranAt: "2026-10-28T09:00:00.000Z" }) });
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick(30);
  assert.equal(foldedNow(doc), false);
  assert.equal(doc.getElementById("home-scan").dataset.tone, "bad");
  assert.equal(doc.getElementById("home-scan-fold").hidden, true);
});

test("with storage refused (a private window), Fold folds for this page and Show opens it; nothing breaks", async () => {
  const { doc, window, err, setHome } = load({ homeVm: { ...home(), scan: homeScanCard(clean()) }, before: (w: any) => { // eslint-disable-line @typescript-eslint/no-explicit-any
    const refuse = () => { throw new w.DOMException("refused", "SecurityError"); };
    w.Storage.prototype.getItem = refuse;
    w.Storage.prototype.setItem = refuse;
    w.Storage.prototype.removeItem = refuse;
  } });
  assert.equal(err, null);
  await tick();
  doc.getElementById("home-scan-fold").click();
  assert.equal(foldedNow(doc), true);
  setHome({ ...home(), scan: { ...homeScanCard(clean()), rev: "r2" } });
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick(30);
  assert.equal(foldedNow(doc), true, "held for this page");
  doc.getElementById("home-scan-show").click();
  assert.equal(foldedNow(doc), false);
  assert.equal(doc.activeElement, doc.getElementById("home-scan-headline"));
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

test("a key links to where it is replaced (§4.25ai): after the story and before the footnote, in a new tab with no referrer; a row with no line has none", async () => {
  const rec = record();
  rec.findings[2]!.looksLikeTest = true;
  rec.sends = [{ kind: "openai-key", preview: "sk-proj-…", to: "other-host", host: "hooks.vendor.dev", sessions: 1, ran: 1, stoppedByMandu: 0, via: ["curl"], by: ["value"], agents: ["codex"], duringMandu: 0 }];
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/scan", homeVm: home(), routes: scanRoutes(rec), before: paged(rec) });
  await tick(30);
  const looks = [...doc.querySelectorAll('[data-section="looks"] .scan-item')];
  assert.ok(looks.length >= 2);
  const p = looks[0].querySelector("p.scan-replace");
  assert.equal(p.textContent, "If this key is still yours, replace it on GitHub: Personal access tokens");
  const a = p.querySelector("a");
  assert.equal(a.textContent, "Personal access tokens");
  assert.equal(a.getAttribute("href"), "https://github.com/settings/tokens");
  assert.equal(a.getAttribute("target"), "_blank");
  assert.equal(a.getAttribute("rel"), "noopener noreferrer");
  assert.ok(p.classList.contains("detail-note"));
  assert.ok(p.previousElementSibling.classList.contains("scan-story"), "after the story");
  assert.ok(p.nextElementSibling.classList.contains("scan-footnote"), "before the footnote");
  assert.equal(looks[0].querySelectorAll("p.scan-replace").length, 1);
  // A test value, and one of your secrets: no line (their replaceAt is empty).
  assert.equal(looks[1].querySelector("p.scan-replace"), null, "a test value");
  assert.equal(doc.querySelector('[data-section="yours"] p.scan-replace'), null, "your own secret");
  // A send of a key: OpenAI's own conditional lead.
  const send = doc.querySelector('[data-section="sends-other"] .scan-item p.scan-replace');
  assert.equal(send.textContent, "If it is your OpenAI key, replace it on OpenAI: API keys");
  assert.equal(send.querySelector("a").getAttribute("href"), "https://platform.openai.com/api-keys");
  noValue("the Scan page", doc);
});

test("home.js declares each top-level function once (a module refuses a second; jsdom's script took the later one silently)", () => {
  const names = [...JS.matchAll(/^(?:async )?function\s+([A-Za-z0-9_$]+)\s*\(/gm)].map((m) => m[1]!);
  const twice = names.filter((n, i) => names.indexOf(n) !== i);
  assert.deepEqual(twice, []);
});

test("History links the Scan page", async () => {
  // Its line follows Home's card (home-js-history-scan-line.test.ts): each
  // state links the Scan page under the base path.
  for (const scan of [undefined, homeScanCard(null), homeScanCard(record())]) {
    const { doc } = load({ url: "http://127.0.0.1:4500/mandu/history", homeVm: { ...home(), scan } });
    await tick();
    const a = doc.querySelector('#history-scan a[data-page-link="scan"]');
    assert.equal(a.getAttribute("href"), "/mandu/scan", "under the base path, as the page writes its links");
  }
});

test("the Scan page follows a scan kept while it is open (§4.25ai): none, then one, then another; the same rev reads nothing and keeps the fold and the filter", async () => {
  const rec1 = record();
  const rec2: LastScanWire = { ...record(), findings: record().findings.slice(1), ranAt: "2026-10-26T09:00:00.000Z" };
  // What the server keeps now: none, then rec1 (r1), then rec2 (r2).
  let kept: { rec: LastScanWire | null; rev: string | null } = { rec: null, rev: null };
  let hold: (() => void) | null = null;
  let held = false;
  let heldReads = 0;
  const asked: string[] = [];
  const { doc, window, calls, setHome } = load({
    url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), scan: { ...homeScanCard(null), rev: null } },
    routes: { "GET scan": () => ({ scan: scanHead(scanPageVM(kept.rec), kept.rev) }) },
    before: (w) => {
      paged(rec1, asked)(w);
      // A head read can be held unanswered (a read already out).
      const inner = w.fetch;
      w.fetch = (url: string, init: unknown) => {
        if (!held || !url.endsWith("/api/scan")) return inner(url, init);
        heldReads++;
        return new Promise((r) => { hold = () => r(inner(url, init)); });
      };
    },
  });
  await tick(30);
  const reads = (): number => calls.filter((c) => c.url.endsWith("/api/scan")).length;
  const poll = async (): Promise<void> => { doc.dispatchEvent(new window.Event("visibilitychange")); await tick(30); };
  const status = doc.getElementById("scan-followed");
  assert.equal(doc.getElementById("scan-headline").textContent, "Did your agents already send a secret to the AI?");
  assert.equal(status.hidden, true);
  assert.equal(status.getAttribute("role"), "status");
  assert.equal(reads(), 1);

  // The same (none kept): no read.
  await poll();
  assert.equal(reads(), 1, "the same rev reads nothing");

  // `mandu scan` keeps one: the next poll reads the head once and draws it.
  kept = { rec: rec1, rev: "r1" };
  setHome({ ...home(), scan: { ...homeScanCard(rec1), rev: "r1" } });
  await poll();
  assert.equal(reads(), 2, "read once");
  assert.equal(doc.getElementById("scan-headline").textContent, homeScanCard(rec1).headline);
  assert.equal(status.hidden, false);
  assert.equal(status.textContent, "A new scan finished. This page shows it.");

  // The same rev again: no read, no redraw; an open fold and the filter stay.
  const fold = doc.querySelector('[data-section="yours"] details.scan-more');
  fold.open = true;
  await wait(20);
  await tick(10);
  const input = doc.querySelector('[data-section="looks"] input.scan-filter');
  input.value = "needle";
  input.dispatchEvent(new window.Event("input"));
  await wait(200);
  await tick(10);
  const said: string[] = [];
  new window.MutationObserver(() => said.push(status.textContent)).observe(status, { childList: true, characterData: true, subtree: true });
  for (let i = 0; i < 3; i++) await poll();
  assert.equal(reads(), 2, "no read while the kept scan is the same");
  assert.equal(doc.querySelector('[data-section="yours"] details.scan-more'), fold, "not drawn again");
  assert.equal(fold.open, true);
  assert.ok(fold.querySelector(".scan-detail"), "the examples stay");
  assert.equal(doc.querySelector('[data-section="looks"] input.scan-filter').value, "needle");
  assert.deepEqual(said, [], "the status line is said once");
  // A card that names another rev (a poll that raced the read) whose head is
  // still the scan drawn: read once, nothing drawn again.
  setHome({ ...home(), scan: { ...homeScanCard(rec1), rev: "r0" } });
  await poll();
  await poll();
  assert.equal(reads(), 3, "read once for that rev");
  assert.equal(doc.querySelector('[data-section="yours"] details.scan-more'), fold, "the same head: not drawn again");
  assert.equal(doc.querySelector('[data-section="looks"] input.scan-filter').value, "needle");
  assert.deepEqual(said, []);

  // Another scan, while a read is already out: one read, not two.
  kept = { rec: rec2, rev: "r2" };
  setHome({ ...home(), scan: { ...homeScanCard(rec2), rev: "r2" } });
  held = true;
  await poll();
  await poll();
  assert.equal(heldReads, 1, "a read out is not doubled");
  assert.equal(reads(), 3);
  held = false;
  (hold as unknown as () => void)();
  await tick(30);
  await poll();
  assert.equal(reads(), 4, "the held read answered; no other");
  assert.equal(doc.getElementById("scan-headline").textContent, homeScanCard(rec2).headline);
  assert.equal(doc.querySelector('[data-section="looks"] input.scan-filter').value, "", "another scan: drawn anew");
  noValue("the Scan page", doc);
});

test("a server whose card has no rev: the Scan page reads nothing new on a poll (today's behaviour); a follow that cannot read keeps the page", async () => {
  const rec = record();
  let answer: unknown = { scan: scanHead(scanPageVM(null), null) };
  const { doc, window, calls, setHome } = load({
    url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), scan: homeScanCard(null) },
    routes: { "GET scan": () => answer },
  });
  await tick(30);
  const reads = (): number => calls.filter((c) => c.url.endsWith("/api/scan")).length;
  const poll = async (): Promise<void> => { doc.dispatchEvent(new window.Event("visibilitychange")); await tick(30); };
  setHome({ ...home(), scan: homeScanCard(rec) });
  await poll();
  assert.equal(reads(), 1, "no rev: no read");
  assert.equal(doc.getElementById("scan-headline").textContent, "Did your agents already send a secret to the AI?");
  // A newer server: the read fails, the page stays as drawn; the next poll reads again.
  answer = { status: 502, body: null };
  setHome({ ...home(), scan: { ...homeScanCard(rec), rev: "r1" } });
  await poll();
  assert.equal(reads(), 2);
  assert.equal(doc.getElementById("scan-headline").textContent, "Did your agents already send a secret to the AI?");
  assert.doesNotMatch(doc.getElementById("scan-sentence").textContent, /could not be read/);
  answer = { scan: scanHead(scanPageVM(rec), "r1") };
  await poll();
  assert.equal(reads(), 3);
  assert.equal(doc.getElementById("scan-headline").textContent, homeScanCard(rec).headline);
});

// ── the agents you use (§4.25ai *The Scan page names the agent you use*) ────

const codesIn = (node: any): string[] => [...node.querySelectorAll("code")].map((c: any) => c.textContent); // eslint-disable-line @typescript-eslint/no-explicit-any

test("the Scan page names the commands of Home's `start`: no scan kept, `mandu goose` alone in the stop line", async () => {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), start: ["mandu goose"], scan: { ...homeScanCard(null), rev: null } }, routes: { "GET scan": { scan: scanHead(scanPageVM(null), null) } } });
  await tick(30);
  const stop = doc.getElementById("scan-stop");
  assert.equal(stop.textContent, "To keep your secrets from the AI from now on, start your agent with mandu goose.");
  assert.deepEqual(codesIn(stop), ["mandu goose"]);
  assert.doesNotMatch(doc.getElementById("page-scan").textContent, /mandu codex/);
});

test("after a Claude Code scan, Home's two commands name both the summary and the stop line; an unchanged poll draws neither again", async () => {
  const rec = record();
  const { doc, window } = load({ url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), start: ["mandu opencode", "mandu claude"], scan: { ...homeScanCard(rec, ["mandu opencode", "mandu claude"]), rev: "r1" } }, routes: scanRoutes(rec), before: paged(rec) });
  await tick(30);
  const sentence = doc.getElementById("scan-sentence");
  const stop = doc.getElementById("scan-stop");
  assert.deepEqual(codesIn(sentence), ["mandu opencode", "mandu claude"]);
  assert.match(sentence.textContent, /start your agent with mandu opencode \(or mandu claude\)\.$/);
  assert.deepEqual(codesIn(stop), ["mandu opencode", "mandu claude"]);
  assert.equal(stop.textContent, "To keep your secrets from the AI from now on, start your agent with mandu opencode (or mandu claude).");
  const drawn = stop.querySelector("code");
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick(30);
  assert.equal(stop.querySelector("code"), drawn, "the same list: nothing drawn again");
});

test("an older server's Home answer, with no `start`: the Scan page's own words, as before", async () => {
  const rec: LastScanWire = { ...record(), sessions: { goose: 4 } };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), scan: { ...homeScanCard(rec), rev: "r1" } }, routes: scanRoutes(rec), before: paged(rec) });
  await tick(30);
  assert.deepEqual(codesIn(doc.getElementById("scan-stop")), ["mandu goose"]);
  assert.deepEqual(codesIn(doc.getElementById("scan-sentence")), ["mandu goose"]);
  assert.equal(doc.getElementById("scan-stop").textContent, "To keep your secrets from the AI from now on, start your agent with mandu goose.");
});

test("a Home answer that arrives after the Scan page's read fixes its commands without a reload; the rest of the page stays", async () => {
  let release: () => void = () => {};
  const held = new Promise<void>((r) => { release = r; });
  const { doc } = load({
    url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), start: ["mandu goose"], scan: { ...homeScanCard(null), rev: null } },
    routes: { "GET scan": { scan: scanHead(scanPageVM(null), null) } },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    before: (w: any) => {
      const inner = w.fetch;
      w.fetch = (url: string, init: unknown) => (url.endsWith("/api/home") ? held.then(() => inner(url, init)) : inner(url, init));
    },
  });
  await tick(30);
  const stop = doc.getElementById("scan-stop");
  assert.deepEqual(codesIn(stop), ["mandu claude", "mandu codex"], "no Home answer yet: the page's own words");
  const step = doc.getElementById("scan-step").firstChild;
  release();
  await tick(30);
  assert.deepEqual(codesIn(stop), ["mandu goose"]);
  assert.equal(stop.textContent, "To keep your secrets from the AI from now on, start your agent with mandu goose.");
  assert.equal(doc.getElementById("scan-step").firstChild, step, "only the two sentences draw again");
});
