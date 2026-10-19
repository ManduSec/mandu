/**
 * home-js-files-big-folder.test — a folder of hundreds of rows drawn in the
 * file browser under Rules › Add a rule costs the page work in proportion
 * to it, never to its square (public/js/home.js `pollPlace`,
 * `pollRefocus`, `listed`, `sendMeaning`; dashboard.md §4.25 *The poll
 * keeps the focus*, §4.25m).
 *
 * Until 2026-10-15 two things went over the whole page once per element:
 * the poll's place (where the focus is, kept across a redraw) spread live
 * HTMLCollections, which reads their length at every step, and in jsdom
 * that read scans the whole collection; and each row's second menu looked
 * up the glossary's words with a query over every element drawn. With 521
 * rows and the focus in one, a poll took 7 s on an idle host and over a
 * minute on the CI guest, past the served page's wait
 * (tests/stack/product-files-again-pages.test.ts, pipelines 10830 to
 * 10834). Now:
 *
 *   B1  a poll with the focus on a row past the first hundreds keeps the
 *       focus there, and reads each collection's length once: the reads
 *       stay far under the rows drawn;
 *   B2  drawing the folder asks the page (document) for no query per row:
 *       the glossary is looked up under itself, and each menu's choices
 *       still carry the glossary's sentence.
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts).
 * Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, WS_LIST, NONE, list, fileRows, rowFor } from "./home-js-fixtures.js";

const ROWS = 600;
const name = (i: number) => `f${String(i).padStart(3, "0")}.txt`;
const BIG = {
  ...WS_LIST,
  entries: Array.from({ length: ROWS }, (_, i) =>
    ({ name: name(i), path: `/home/u/ws/${name(i)}`, display: `~/ws/${name(i)}`, kind: "file", link: null, label: NONE, inside: 0 })),
  total: ROWS, more: false,
};
const LAST = { "mandu.files.folder": "/home/u/ws" };

/** Counts, on the window, each read of a live collection's length (every
 *  getElementsByTagName answer is wrapped to count them) and each query
 *  asked of the whole document. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function counting(w: any) {
  const n = { lengths: 0, docQueries: 0 };
  for (const proto of [w.Element.prototype, w.Document.prototype]) {
    const real = proto.getElementsByTagName;
    proto.getElementsByTagName = function (this: unknown, tag: string) {
      const coll = real.call(this, tag);
      return new Proxy(coll, {
        get(target, p) {
          if (p === "length") n.lengths++;
          const v = Reflect.get(target, p, target);
          // The array iterator (spread, for…of) runs on the wrapper, so its
          // reads are counted; the collection's own methods on itself.
          return typeof v === "function" && p !== Symbol.iterator ? v.bind(target) : v;
        },
      });
    };
  }
  const realQsa = w.Document.prototype.querySelectorAll;
  w.Document.prototype.querySelectorAll = function (this: unknown, sel: string) {
    n.docQueries++;
    return realQsa.call(this, sel);
  };
  return n;
}

test("B1: a poll with the focus in a folder of 600 rows keeps it and reads each collection's length once", async () => {
  let n = { lengths: 0, docQueries: 0 };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { doc } = load({ url: FILES_URL, storage: LAST, routes: { [list("/home/u/ws")]: BIG }, before: (w: any) => { n = counting(w); } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  assert.equal(fileRows(doc).length, ROWS);
  const tickBox = rowFor(doc, /^f550\.txt/).querySelector(".file-tick");
  tickBox.focus();
  assert.equal(doc.activeElement, tickBox);

  n.lengths = 0;
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick();
  assert.equal(doc.activeElement, rowFor(doc, /^f550\.txt/).querySelector(".file-tick"), "the focus stays on its row");
  assert.ok(n.lengths < 50, `a poll reads a collection's length once, not once an element (${n.lengths} reads with ${ROWS} rows)`);
});

test("B2: drawing a folder of 600 rows asks the whole page no query per row, and the menus keep the glossary's words", async () => {
  let n = { lengths: 0, docQueries: 0 };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { doc } = load({ url: FILES_URL, storage: LAST, routes: { [list("/home/u/ws")]: BIG }, before: (w: any) => { n = counting(w); } });
  await tick();
  n.docQueries = 0;
  doc.getElementById("rules-add").click();
  await tick();
  assert.equal(fileRows(doc).length, ROWS);
  assert.ok(n.docQueries < ROWS / 4, `no document query per row (${n.docQueries} with ${ROWS} rows)`);
  // The words the glossary gives "Needs your OK", as the menu's choice says them.
  const dt = [...doc.querySelectorAll("#rules-glossary dt")].find((x) => x.textContent === "Needs your OK");
  assert.ok(dt, "the glossary lists Needs your OK");
  const ask = rowFor(doc, /^f599\.txt/).querySelector('select.send-select option[value="ask"]');
  assert.equal(ask.getAttribute("title"), `Needs your OK. ${dt.nextElementSibling.textContent}`);
});
