/**
 * home-js-scan-where — dashboard.md §4.25ai *Where the real value is now*
 * (the lineage mock's ★2): a finding of yours opens on where its real value
 * sits now (where it belongs, the AI service that got it, each chat-history
 * file, a chat history under Mandu with its sessions linked) and what to
 * do; the address `?item=f0` (a session card's earlier leak) opens the
 * Scan page at that row with its fold open. Text is text, never markup.
 * Mandu-new.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { home, load, tick } from "./home-js-fixtures.js";
import { homeScanCard, scanPageVM, withPresence, type LastScanWire } from "../../../src/view-model/last-scan.js";
import { scanAfter, scanHead, scanItemDetail, scanSectionPage } from "../../../src/view-model/last-scan-pages.js";

const wait = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const text = (el: { textContent?: string | null } | null) => String(el?.textContent ?? "").replace(/\s+/g, " ").trim();

function record(): LastScanWire {
  return {
    version: 1, ranAt: "2026-10-28T09:00:00.000Z", sessions: { openclaw: 3 }, duringMandu: 1, sessionsUnderMandu: 1, known: 1,
    findings: [{
      kind: "known", preview: "ORDERHUB_PASSPHRASE in ~/app/.env", source: { path: "~/app/.env", name: "ORDERHUB_PASSPHRASE" }, sessions: 2, agents: ["openclaw"],
      first: "2026-10-27T00:37:00.000Z", last: "2026-10-28T00:37:00.000Z", how: { "command-output": 2 }, projects: ["~/app"], duringMandu: 1, sessionsUnderMandu: 1,
      examples: [{ at: "2026-10-27T00:37:00.000Z", agent: "openclaw", how: "command-output", command: "DEBUG=1 sh sync.sh", project: "~/app", mandu: "without", provider: "openai" }],
      places: [
        { agent: "openclaw", file: "~/.openclaw/agents/main/sessions/<b>7c7c</b>.jsonl", mandu: "without", first: "2026-10-27T00:37:00.000Z", sessions: 1 },
        { agent: "openclaw", file: "~/.openclaw/agents/main/sessions/9e9e.jsonl", mandu: "under", first: "2026-10-28T00:37:00.000Z", sessions: 1, manduSessions: ["openclaw:main"] },
      ],
    }],
    dropped: 0, capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 }, sends: [], sendsDropped: 0, suggestions: null,
  };
}

/** `scan/item/<id>` answered as the server answers it: the row's detail
 *  with each file's presence (the first file still there, the other gone). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function items(rec: LastScanWire, asked: string[]): (window: any) => void {
  const page = scanPageVM(rec);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (window: any) => {
    const inner = window.fetch;
    window.fetch = (url: string, init: unknown) => {
      const m = /\/api\/scan\/item\/([^?]+)/.exec(url);
      if (!m) return inner(url, init);
      asked.push(m[1]!);
      const item = scanItemDetail(page, decodeURIComponent(m[1]!));
      const body = item && { ...item, detail: withPresence(item.detail, (p) => p.includes("7c7c")) };
      return Promise.resolve({ ok: !!body, status: body ? 200 : 404, json: () => Promise.resolve(body ?? { error: "no such row" }) });
    };
  };
}

test("a finding of yours opens on where its real value is now: each place in its tone, the file as text, a chat history under Mandu linked to its session, then what to do", async () => {
  const rec = record();
  const asked: string[] = [];
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), scan: homeScanCard(rec) }, routes: { "GET scan": { scan: scanHead(scanPageVM(rec), "r1") } }, before: items(rec, asked) });
  await tick(30);
  const fold = doc.querySelector('[data-section="yours"] details.scan-more');
  fold.open = true;
  await wait(20);
  await tick(10);
  assert.deepEqual(asked, ["f0"]);
  const where = fold.querySelector(".scan-where");
  assert.ok(where, "drawn first in the fold");
  assert.equal(fold.querySelector(".scan-detail").firstElementChild, where);
  assert.equal(text(where.querySelector(".scan-where-title")), "Where the real value is now");
  const rows = [...where.querySelectorAll(".scan-where-row")] as any[];
  assert.deepEqual(rows.map((r) => [r.dataset.kind, r.dataset.tone, text(r.querySelector(".scan-where-name")), text(r.querySelector(".scan-where-now"))]), [
    ["belongs", "plain", "Where it belongs", "You keep it here"],
    ["provider", "bad", "OpenAI", "Can't be taken back"],
    ["history", "bad", "OpenClaw's chat history", "Still there"],
    ["under", "ok", "OpenClaw's chat history", "Gone from this computer · Open the session"],
  ]);
  assert.equal(rows[2].querySelector("code").textContent, "~/.openclaw/agents/main/sessions/<b>7c7c</b>.jsonl");
  assert.equal(where.querySelector("b"), null, "a path is text, never markup");
  const link = rows[3].querySelector("a.scan-where-session");
  assert.equal(link.getAttribute("href"), "/mandu/agents/openclaw%3Amain");
  assert.equal(link.dataset.pageLink, "agent");
  assert.equal(link.dataset.session, "openclaw:main");
  assert.match(text(where.querySelector(".scan-where-advice")), /^What reached OpenAI can't be taken back: change the secret where it was issued\. Mandu only shows these places; it never changes an agent's chat history\.$/);
  assert.ok(rows.every((r) => r.querySelector(".tone-mark") || r.dataset.tone === "plain"), "a tone has its mark too");
});

test("the address ?item=f0 opens the Scan page at that row, its fold open and read, the focus on it; an id of another shape opens the page as it was", async () => {
  const rec = record();
  const asked: string[] = [];
  const { doc, window } = load({ url: "http://127.0.0.1:4500/mandu/scan?item=f0", homeVm: { ...home(), scan: homeScanCard(rec) }, routes: { "GET scan": { scan: scanHead(scanPageVM(rec), "r1") } }, before: items(rec, asked) });
  await tick(30);
  await wait(20);
  await tick(10);
  const row = doc.querySelector('.scan-item[data-id="f0"]');
  assert.equal(row.querySelector("details.scan-more").open, true);
  assert.deepEqual(asked, ["f0"], "read once");
  assert.ok(row.querySelector(".scan-where"));
  assert.equal(doc.activeElement, row);
  assert.equal(window.location.search, "", "used once: the address is the page's own");
  const other = load({ url: "http://127.0.0.1:4500/mandu/scan?item=../x", homeVm: { ...home(), scan: homeScanCard(rec) }, routes: { "GET scan": { scan: scanHead(scanPageVM(rec), "r1") } }, before: items(rec, []) });
  await tick(30);
  assert.equal(other.doc.querySelector('.scan-item[data-id="f0"] details.scan-more').open, false);
});

// ── A row past the first page (§4.25ai *A session card opens its row*) ──────
/** A scan with `n` of your secrets that reached the AI (f0…f<n-1>). */
function many(n: number): LastScanWire {
  const one = record().findings[0]!;
  return {
    ...record(), known: n,
    findings: Array.from({ length: n }, (_, i) => ({ ...one, preview: `KEY_${i} in ~/app-${i}/.env`, source: { path: `~/app-${i}/.env`, name: `KEY_${i}` } })),
  };
}
/** The paged reads answered from the server's own paging over `rec` (rev
 *  `r1`), each path kept in `asked`; `hold` makes a section read wait for
 *  the promise it returns; `fail` answers a path with that status. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function paged(rec: LastScanWire, asked: string[], opts: { fail?: (path: string) => number | null; hold?: (path: string) => Promise<void> | null } = {}): (window: any) => void {
  const page = scanPageVM(rec);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (window: any) => {
    const inner = window.fetch;
    window.fetch = async (url: string, init: unknown) => {
      const m = /\/api\/(scan\/(section|item)\/([^?]+))(?:\?(.*))?$/.exec(url);
      if (!m) return inner(url, init);
      const path = `${m[1]}${m[4] ? `?${m[4]}` : ""}`;
      asked.push(path);
      const held = opts.hold?.(path);
      if (held) await held;
      const answer = (s: number, body: unknown) => ({ ok: s < 400, status: s, json: () => Promise.resolve(body) });
      const status = opts.fail?.(path) ?? null;
      if (status !== null) return answer(status, { error: "refused" });
      const params = new URLSearchParams(m[4] ?? "");
      if (m[2] === "section") {
        const body = scanSectionPage(page, decodeURIComponent(m[3]!), { after: scanAfter(params.get("after")) });
        return body ? answer(200, body) : answer(404, { error: "no such section" });
      }
      const item = scanItemDetail(page, decodeURIComponent(m[3]!));
      return item ? answer(200, { ...item, detail: withPresence(item.detail, () => true) }) : answer(404, { error: "no such row" });
    };
  };
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function opened(rec: LastScanWire, item: string, asked: string[], opts: Parameters<typeof paged>[2] = {}): { doc: any; window: any } {
  return load({ url: `http://127.0.0.1:4500/mandu/scan?item=${item}`, homeVm: { ...home(), scan: homeScanCard(rec) }, routes: { "GET scan": { scan: scanHead(scanPageVM(rec), "r1") } }, before: paged(rec, asked, opts) });
}
const settle = async () => { for (let i = 0; i < 4; i++) { await tick(20); await wait(10); } };

test("a link to a row past the first page reads on, a page at a time, to it: f30 one page, f55 two; then its fold opens and is read, the focus on it", async () => {
  const rec = many(60);
  for (const [item, reads] of [["f30", ["scan/section/yours?after=25&rev=r1"]], ["f55", ["scan/section/yours?after=25&rev=r1", "scan/section/yours?after=50&rev=r1"]]] as const) {
    const asked: string[] = [];
    const { doc } = opened(rec, item, asked);
    await settle();
    assert.deepEqual(asked, [...reads, `scan/item/${item}?rev=r1`], `${item}: the pages up to it, then its examples`);
    const row = doc.querySelector(`.scan-item[data-id="${item}"]`);
    assert.ok(row, `${item} drawn`);
    assert.equal(row.querySelector("details.scan-more").open, true);
    assert.ok(row.querySelector(".scan-where"), "its places read");
    assert.equal(doc.activeElement, row, "the focus on it");
    assert.equal(doc.getElementById("scan-item-missing").hidden, true, "nothing said");
    assert.equal(doc.documentElement.style.overflowAnchor, "", "scroll anchoring back on");
  }
});

test("a link to a row the list no longer has reads to the section's end, then says so under the headline; no row is opened or focused", async () => {
  const rec = many(60);
  const asked: string[] = [];
  const { doc } = opened(rec, "f80", asked);
  await settle();
  assert.deepEqual(asked, ["scan/section/yours?after=25&rev=r1", "scan/section/yours?after=50&rev=r1"], "to the end, no row read");
  const line = doc.getElementById("scan-item-missing");
  assert.equal(line.hidden, false);
  assert.equal(line.getAttribute("role"), "status");
  assert.equal(text(line), "That secret is not in the last scan's list any more. A newer scan may have changed it.");
  assert.equal(doc.querySelectorAll('[data-section="yours"] .scan-item').length, 60);
  assert.equal(doc.querySelectorAll("details.scan-more[open]").length, 0);
  assert.ok(!doc.activeElement?.classList?.contains("scan-item"), "no row has the focus");
  // The page opened again without the link says nothing.
  const again = load({ url: "http://127.0.0.1:4500/mandu/scan", homeVm: { ...home(), scan: homeScanCard(rec) }, routes: { "GET scan": { scan: scanHead(scanPageVM(rec), "r1") } }, before: paged(rec, []) });
  await settle();
  assert.equal(again.doc.getElementById("scan-item-missing").hidden, true);
});

test("a page that could not be read stops the reading on and says why under the headline", async () => {
  const rec = many(60);
  const asked: string[] = [];
  const { doc } = opened(rec, "f55", asked, { fail: (p) => (p.includes("after=25") ? 500 : null) });
  await settle();
  assert.deepEqual(asked, ["scan/section/yours?after=25&rev=r1"], "no read after the failed one");
  const line = doc.getElementById("scan-item-missing");
  assert.equal(line.hidden, false);
  assert.match(text(line), /^The page could not read on to that secret\. \S/);
  assert.doesNotMatch(text(line), /not in the last scan/);
  assert.ok(!doc.activeElement?.classList?.contains("scan-item"), "no row has the focus");
});

test("leaving the Scan page while it reads on stops it: no further page read, no row opened, no focus taken", async () => {
  const rec = many(60);
  const asked: string[] = [];
  let release = () => {};
  const gate = new Promise<void>((r) => { release = r; });
  const { doc } = opened(rec, "f55", asked, { hold: (p) => (p.includes("after=25") ? gate : null) });
  await settle();
  assert.deepEqual(asked, ["scan/section/yours?after=25&rev=r1"]);
  doc.querySelector('#nav [data-page-link="home"]').click();
  await settle();
  release();
  await settle();
  assert.deepEqual(asked, ["scan/section/yours?after=25&rev=r1"], "no further read");
  assert.equal(doc.querySelectorAll("details.scan-more[open]").length, 0, "no row opened");
  assert.ok(!doc.activeElement?.classList?.contains("scan-item"), "no row has the focus");
  assert.equal(doc.getElementById("scan-item-missing").hidden, true, "nothing said");
});

test("a person who moved the focus while the page read on keeps it: the row still opens and is read", async () => {
  const rec = many(60);
  const asked: string[] = [];
  let release = () => {};
  const gate = new Promise<void>((r) => { release = r; });
  const { doc } = opened(rec, "f30", asked, { hold: (p) => (p.includes("after=25") ? gate : null) });
  await settle();
  const own = doc.querySelector('#page-scan a[data-page-link="home"]');
  own.focus();
  release();
  await settle();
  const row = doc.querySelector('.scan-item[data-id="f30"]');
  assert.equal(row.querySelector("details.scan-more").open, true);
  assert.deepEqual(asked.at(-1), "scan/item/f30?rev=r1");
  assert.equal(doc.activeElement, own, "the focus stays where the person put it");
});
