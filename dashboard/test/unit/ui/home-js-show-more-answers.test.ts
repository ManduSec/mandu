/**
 * home-js-show-more-answers.test — the product page's two Show more buttons
 * that read the server for the next page: History's (dashboard.md §4.25ae)
 * and the file browser's under Rules › Add a rule (§4.25m). Until
 * 2026-10-15 a History Show more that failed was drawn away, its words in
 * its place: the focus fell to <body> and nothing tried again until a poll
 * brought the button back. The file browser's said nothing at all when its
 * read failed, and when it answered, the focus fell to <body>.
 *
 *   M1  History: a failed Show more says why in place of the count, the
 *       button stays on, described by those words, and has the focus back;
 *       a poll that answers brings the count back with the focus kept; a
 *       second press reads the same cursor and its first row takes the
 *       focus;
 *   M2  History: each cause in the page's words; a focus moved while the
 *       read was out stays where it was moved;
 *   M3  the file browser: an answered Show more gives the focus to the
 *       first entry it brought; a failed one says why over the button,
 *       which keeps the focus and tries again; a new folder drops the words;
 *   M4  the file browser: each cause in the page's words (the stopped
 *       service with its link to Settings); a focus moved while the read
 *       was out stays where it was moved, on a failure and on an answer;
 *   M5  the file browser: an answer the filter hides entirely gives the
 *       focus to the last row shown.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { FILES_URL, WS_LIST, NONE, fileRows, home, list, load, tick } from "./home-js-fixtures.js";

// ── History ──────────────────────────────────────────────────────────────────

const HISTORY_URL = "http://127.0.0.1:4500/mandu/history";
const row = (id: string) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", startedAt: "2026-09-01T10:00:00.000Z", lastAt: "2026-09-01T10:05:00.000Z", state: "idle",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 1, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null,
});
const FIRST = { total: 4, rows: [row("s1"), row("s2")], next: "s2" };
const SECOND = { total: 4, rows: [row("s3"), row("s4")], next: null };
const DOWN = { status: 503, body: { error: "the protection service is not running", unreachable: true } };
const NO_ANSWER = () => { throw new TypeError("fetch failed"); };

/** A route answering each read with the next answer (the last one again
 *  once they run out); a function among them runs (and may throw). */
function answers(...items: unknown[]) {
  let i = 0;
  return () => {
    const a = items[Math.min(i++, items.length - 1)];
    return typeof a === "function" ? (a as () => unknown)() : a;
  };
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ids = (doc: any) => [...doc.querySelectorAll("#history-list .row.agent")].map((r: any) => r.dataset.session);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const historyMore = (doc: any) => doc.querySelector("#history-list .history-more") as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const describedBy = (doc: any, btn: any) => doc.getElementById(btn.getAttribute("aria-describedby"))?.textContent;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const poll = async (doc: any) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };

test("M1: History's Show more that fails says why beside the button, which stays on with the focus; a poll brings the count back; pressed again it reads the same cursor and lands on the first new row", async () => {
  const { doc, calls } = load({ extensions: "", url: HISTORY_URL, homeVm: home(), routes: {
    "GET home/history": FIRST,
    "GET home/history?after=s2": answers(DOWN, SECOND),
  } });
  await tick();
  assert.deepEqual(ids(doc), ["s1", "s2"]);
  let btn = historyMore(doc).querySelector("button");
  btn.focus();
  btn.click();
  await tick();
  assert.deepEqual(ids(doc), ["s1", "s2"], "the rows drawn stay");
  assert.equal(historyMore(doc).textContent, "Could not read more of the history. The protection service is not running. Show more");
  btn = historyMore(doc).querySelector("button");
  assert.ok(btn, "Show more stays, to try again");
  assert.equal(btn.disabled, false);
  assert.equal(describedBy(doc, btn), "Could not read more of the history. The protection service is not running.", "its words say why");
  assert.equal(doc.activeElement, btn, "the focus is back on Show more, never on <body>");

  // The service is back: the next poll's read brings the count back, the focus kept.
  await poll(doc);
  btn = historyMore(doc).querySelector("button");
  assert.equal(describedBy(doc, btn), "2 more sessions.");
  assert.equal(doc.activeElement, btn, "the poll keeps the focus on Show more");

  btn.click();
  await tick();
  const asked = calls.map((c) => c.url).filter((u) => u.startsWith("/mandu/api/home/history?after="));
  assert.deepEqual(asked, ["/mandu/api/home/history?after=s2", "/mandu/api/home/history?after=s2"], "the second press reads the same cursor");
  assert.deepEqual(ids(doc), ["s1", "s2", "s3", "s4"]);
  assert.equal(doc.activeElement, doc.querySelector('#history-list .row.agent[data-session="s3"]'), "the first new row takes the focus");
  assert.equal(historyMore(doc), null, "nothing more");
});

test("M2: History's failed Show more names each cause in the page's words; a focus moved while the read was out stays", async () => {
  const causes: [unknown, string][] = [
    [NO_ANSWER, "Could not read more of the history. The dashboard could not reach its own server. Refresh in a moment."],
    [{ status: 500, body: { error: "boom" } }, "Could not read more of the history. The dashboard server answered with an error (500). Refresh in a moment."],
  ];
  for (const [answer, words] of causes) {
    const { doc } = load({ extensions: "", url: HISTORY_URL, homeVm: home(), routes: { "GET home/history": FIRST, "GET home/history?after=s2": answers(answer) } });
    await tick();
    const heading = doc.querySelector("#page-history h1");
    heading.setAttribute("tabindex", "-1");
    historyMore(doc).querySelector("button").focus();
    historyMore(doc).querySelector("button").click();
    heading.focus();
    assert.equal(doc.activeElement, heading);
    await tick();
    const btn = historyMore(doc).querySelector("button");
    assert.equal(describedBy(doc, btn), words);
    assert.doesNotMatch(historyMore(doc).textContent, /fetch failed|boom/, "never the browser's or the server's own words");
    assert.equal(doc.activeElement, heading, "a focus moved while the read was out is not taken back");
  }
});

// ── The file browser (Rules › Add a rule) ───────────────────────────────────

const entry = (name: string) => ({ name, path: `/home/u/ws/${name}`, display: `~/ws/${name}`, kind: "file", link: null, label: NONE, inside: 0 });
const PAGE_ONE = { ...WS_LIST, total: 6, more: true };
const PAGE_TWO = { ...WS_LIST, entries: [entry("zeta.txt"), entry("zulu.txt")], total: 6, offset: 4, more: false };
const MORE = `${list("/home/u/ws")}&offset=4`;
const GONE_FOLDER = { status: 404, body: { error: "That folder does not exist. Use ~ to go to your home folder.", path: "/home/u/ws" } };

async function browser(more: unknown, extra: Record<string, unknown> = {}): Promise<ReturnType<typeof load>> {
  const page = load({ url: FILES_URL, routes: { [list("/home/u/ws")]: PAGE_ONE, [MORE]: more, ...extra } });
  await tick();
  page.doc.getElementById("rules-add").click();
  await tick();
  return page;
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const moreBtn = (doc: any) => doc.querySelector("#files-list .files-more") as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const moreWords = (doc: any) => doc.getElementById("files-more-words")?.textContent ?? null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const names = (doc: any) => fileRows(doc).map((r: any) => r.getAttribute("data-path").slice("/home/u/ws/".length));

test("M3: the file browser's Show more gives the focus to the first entry it brought; one that fails says why over the button, which keeps the focus and tries again; a new folder drops the words", async () => {
  // The folder grew meanwhile: a third page is left after the second.
  const { doc, calls } = await browser(answers(GONE_FOLDER, { ...PAGE_TWO, total: 7, more: true }));
  assert.equal(fileRows(doc).length, 4);
  let btn = moreBtn(doc);
  assert.equal(btn.textContent, "Show more (2 more)");
  assert.equal(moreWords(doc), null);
  btn.focus();
  btn.click();
  await tick();
  assert.equal(moreWords(doc), "Could not read more of this folder: That folder does not exist. Use ~ to go to your home folder.", "a failed read says why, in the server's words for the folder");
  btn = moreBtn(doc);
  assert.equal(btn.textContent, "Show more (2 more)", "the button stays, to try again");
  assert.equal(btn.getAttribute("aria-describedby"), "files-more-words");
  assert.equal(doc.activeElement, btn, "the focus is back on Show more, never on <body>");
  assert.equal(fileRows(doc).length, 4, "the entries drawn stay");

  btn.click();
  await tick();
  assert.deepEqual(calls.filter((c) => c.url.includes("&offset=")).map((c) => c.url), ["/mandu/api/files/list?path=%2Fhome%2Fu%2Fws&offset=4", "/mandu/api/files/list?path=%2Fhome%2Fu%2Fws&offset=4"]);
  assert.deepEqual(names(doc).slice(-2), ["zeta.txt", "zulu.txt"]);
  const first = fileRows(doc).find((r: any) => r.getAttribute("data-path") === "/home/u/ws/zeta.txt");
  assert.equal(doc.activeElement, first.querySelector(".file-tick"), "the first entry it brought takes the focus, on its tick box as the arrow keys move");
  assert.equal(moreWords(doc), null, "an answer drops the words");
  assert.equal(moreBtn(doc).textContent, "Show more (1 more)");
  assert.equal(moreBtn(doc).getAttribute("aria-describedby"), null);

  // A failure, then another folder: its words go with the folder.
  const again = await browser(answers(GONE_FOLDER), { [list("/home/u/ws/config")]: { ...PAGE_ONE, path: "/home/u/ws/config", display: "~/ws/config" } });
  moreBtn(again.doc).click();
  await tick();
  assert.match(moreWords(again.doc), /^Could not read more of this folder: /);
  fileRows(again.doc).find((r: any) => r.getAttribute("data-path") === "/home/u/ws/config").querySelector(".file-open").click();
  await tick();
  assert.ok(again.calls.some((c) => c.url === "/mandu/api/files/list?path=%2Fhome%2Fu%2Fws%2Fconfig"), "the folder was opened");
  assert.equal(moreWords(again.doc), null, "a new folder drops the words");
  assert.equal(moreBtn(again.doc).textContent, "Show more (2 more)");
});

test("M4: the file browser's failed Show more names each cause in the page's words; a focus moved while the read was out stays", async () => {
  const causes: [unknown, string, string[][]][] = [
    [NO_ANSWER, "Could not read more of this folder. The dashboard could not reach its own server. Refresh in a moment.", []],
    [{ status: 503, body: { error: "arbiter connection failed", unreachable: true } }, "Could not read more of this folder. The protection service is not running. Start it under Settings, or try again in a moment.", [["Start it under Settings", "settings"]]],
    [{ status: 500, body: { error: "could not list the folder: EIO: i/o error" } }, "Could not read more of this folder: could not list the folder: EIO: i/o error.", []],
    [{ status: 403, body: { error: "admin session required: open the sign-in link" } }, "Could not read more of this folder. Sign in first: in your own terminal, run mandu dashboard and open the sign-in link it prints (each link works once), or sign in with the dashboard's password if it has one.", []],
    [{ status: 502, body: null }, "Could not read more of this folder. The dashboard server answered with an error (502). Refresh in a moment.", []],
  ];
  for (const [answer, words, links] of causes) {
    const { doc } = await browser(answers(answer));
    moreBtn(doc).focus();
    moreBtn(doc).click();
    await tick();
    assert.equal(moreWords(doc), words);
    assert.deepEqual([...doc.querySelectorAll("#files-more-words a")].map((a: any) => [a.textContent, a.getAttribute("data-page-link")]), links);
    assert.equal(doc.activeElement, moreBtn(doc));
  }
  // The person moves on before the answer comes: the focus stays where they put it.
  for (const answer of [GONE_FOLDER, PAGE_TWO]) {
    const { doc } = await browser(answers(answer));
    moreBtn(doc).focus();
    moreBtn(doc).click();
    const filter = doc.getElementById("files-filter");
    filter.focus();
    await tick();
    assert.equal(doc.activeElement, filter, "a focus moved while the read was out is not taken back");
  }
});

test("M5: an answer the filter hides entirely gives the focus to the last row shown", async () => {
  const { doc } = await browser(answers(PAGE_TWO));
  const filter = doc.getElementById("files-filter");
  filter.value = "READ";
  filter.dispatchEvent(new doc.defaultView.Event("input"));
  assert.deepEqual(names(doc), ["README.md"]);
  moreBtn(doc).focus();
  moreBtn(doc).click();
  await tick();
  assert.deepEqual(names(doc), ["README.md"], "the new entries are filtered out");
  assert.equal(doc.activeElement, fileRows(doc)[0].querySelector(".file-tick"), "the last row shown takes the focus, never <body>");
});
