/**
 * rules-made-from-secrets.test — Rules › Files made from your secrets
 * (dashboard.md §4.25aa *Files made from your secrets*), across the REAL
 * components, `secrets` axes. Mandu-new.
 *
 * Mandu labels a file on its own when what wrote it held a secret
 * (confidentiality.md §4, §8), and until 2026-10-26 the product page never
 * listed those files: a later session that could not read `.env.bak` was
 * given no reason. This suite raises each of the arbiter's three kinds of
 * record through the real ArbiterServer, then reads them back through the
 * real dashboard server and its served Rules page (index.html and home.js in
 * jsdom):
 *
 *   M1  a HIGH session (it read a memo labelled `any-model` as it was) writes
 *       `summary.md` with Write; a program that read the registered `.env`
 *       writes `dist/config.js`; the guard follows `cp .env .env.bak`;
 *   M2  `/api/secrets` sends the three as `panel.derived`, at the levels a
 *       later session reads;
 *   M3  the served page: the card, closed, with the count; Show lists each
 *       file with its level ("No AI" for the two made from `.env`) and what
 *       wrote it in words, the session's write linking its page and the
 *       others linking nothing; Change who may read it opens the file in
 *       Rules;
 *   M4  the oracle: the card holds only paths and fixed words, never the key
 *       in `.env`, the memo the session read, a written file's bytes or a raw
 *       key (`proc:…`, `guard`), and neither does the route;
 *   M6  a build writes a tree (#191): the program writes 24 more files in
 *       `dist/`, so it holds 25; the card reads (28) and folds each folder
 *       of 3 or more into one row: `dist/` "25 files", "No AI", "written by
 *       a program that held a secret"; `app/` "3 files" and, its files at
 *       two levels by two writers, neither; Show lists 20, Show more the
 *       rest; each file still opens in Add a rule; M4 holds for the folder
 *       rows (paths and fixed words only);
 *   M5  Add a rule says what wrote each file as its card row does (#189): the
 *       build "Written by a program that held a secret", the summary "Written
 *       by the AI's Write", a copy named like no built-in shape (`notes.txt`)
 *       "Copied from a secret file"; `.env.bak` keeps the built-in rule that
 *       decides it; no file says the AI wrote it when the AI did not; See it
 *       in Files made from your secrets focuses the file's row again.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const KEY_VALUE = "sk_" + "live_madeFromSecretsStackCanary0000001";
const MEMO = "Acme pays $4,200,000 on 2026-09-30. MEMO_CANARY_130";
const BYTES = "BYTES_CANARY_130";
const SESSION = "1791300000-130";
const PROC = "build-node-130";

test("Rules lists the files made from your secrets: a HIGH session's write, a program's and a copy, each in words, no value (real arbiter and dashboard)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-made-from-"));
  const home = join(tmp, "home");
  const app = join(home, "app");
  mkdirSync(join(app, "dist"), { recursive: true });
  mkdirSync(join(home, "memos"), { recursive: true });
  const env = join(app, ".env");
  const copy = join(app, ".env.bak");
  const built = join(app, "dist", "config.js");
  const summary = join(app, "summary.md");
  const notes = join(app, "notes.txt"); // a copy named like no built-in shape
  const memo = join(home, "memos", "q3.md");
  const chunks = Array.from({ length: 24 }, (_, i) => join(app, "dist", `chunk-${String(i).padStart(2, "0")}.js`));
  for (const c of chunks) writeFileSync(c, `export const k = "${BYTES}";\n`);
  writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
  writeFileSync(copy, `STRIPE_KEY=${KEY_VALUE}\n`);
  writeFileSync(notes, `STRIPE_KEY=${KEY_VALUE}\n`);
  writeFileSync(built, `export const key = "${BYTES}";\n`);
  writeFileSync(summary, `${BYTES}\n`);
  writeFileSync(memo, MEMO);

  const socketPath = join(tmp, "arbiter.sock");
  const adminPath = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminPath, humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(socketPath); await gate.connect();
  const admin = new ArbiterClient(adminPath); await admin.connect();
  const human = new ArbiterClient(humanPath); await human.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminPath }));
  assert.ok(wired?.secrets, "the production secrets adapter");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter,
    secretsArbiter: wired.secrets,
    policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  try {
    // ── M1: the three writers ─────────────────────────────────────────────
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    assert.ok(reg.twin, `the .env is registered: ${JSON.stringify(reg)}`);
    // A session that read the memo as it was is HIGH; its Write is labelled.
    await admin.setPathLabel({ path: join(home, "memos"), confidentiality: "any-model", bindings: [] });
    const s = await admin.symbolizeFull({ tool: "Read", value: MEMO, field: "content", origin: memo, integrity: "trusted", sessionKey: SESSION });
    assert.equal((await admin.declassifySymbol({ symbol: s.symbol, sessionKey: SESSION })).allowed, true);
    assert.equal((await admin.sessionState(SESSION)).high, true);
    const wrote = await admin.labelWrittenPath({ sessionKey: SESSION, path: summary, tool: "Write" });
    assert.equal(wrote.labeled, true, JSON.stringify(wrote));
    // A program that read the .env writes its build (the guard's calls, on the human plane).
    await human.taintProcessSecret({ procKey: PROC, path: env, level: "no-model", app: "node" });
    const prog = await human.labelWrittenPathTainted({ path: built, procKey: PROC });
    assert.equal(prog.labeled, true, JSON.stringify(prog));
    // M6: the same build writes the rest of dist/.
    for (const c of chunks) {
      const r = await human.labelWrittenPathTainted({ path: c, procKey: PROC });
      assert.equal(r.labeled, true, JSON.stringify(r));
    }
    // cp .env .env.bak, followed by the guard.
    const followed = await human.followDerivedLabel({ from: env, to: copy, how: "identity" });
    assert.equal(followed.labeled, true, JSON.stringify(followed));
    const followedNotes = await human.followDerivedLabel({ from: env, to: notes, how: "identity" });
    assert.equal(followedNotes.labeled, true, JSON.stringify(followedNotes));

    // ── M2: the route sends them ──────────────────────────────────────────
    const route = await (await pageFetch(`${base}/api/secrets`)).text();
    const derived = (JSON.parse(route) as { panel: { derived: Array<{ path: string; effective: string; sessionKey: string; tool: string }> } }).panel.derived;
    const byPath = new Map(derived.map((d) => [d.path, d]));
    assert.equal(byPath.get(summary)?.effective, "any-model", "the session's write, at what it read");
    assert.equal(byPath.get(built)?.effective, "no-model", "the build, at the .env's level");
    assert.equal(byPath.get(copy)?.effective, "no-model", "the copy, at the .env's level");
    assert.equal(byPath.get(built)?.sessionKey, `proc:${PROC}`);
    assert.equal(byPath.get(copy)?.sessionKey, "guard");
    for (const canary of [KEY_VALUE, MEMO, "MEMO_CANARY_130", BYTES]) assert.ok(!route.includes(canary), `/api/secrets carries no ${canary.slice(0, 12)}…`);

    // ── M3 + M4: the served Rules page ────────────────────────────────────
    const card = (doc: any) => doc.getElementById("made-from-block"); // eslint-disable-line @typescript-eslint/no-explicit-any
    await servedProductPage(base, "/rules", (doc) => card(doc) && !card(doc).hidden, async (doc) => {
      assert.equal(doc.getElementById("made-from-title").textContent, "Files made from your secrets (28)", "the heading counts files");
      assert.equal(doc.getElementById("made-from-view").hidden, true, "closed by default");
      doc.getElementById("made-from-open").click();
      // ── M6: a folder of 3 or more is one row ──────────────────────────
      const folderOf = (at: string) => [...doc.querySelectorAll("#made-from-list .made-from-folder")].find((f: any) => f.getAttribute("data-folder") === at) as any; // eslint-disable-line @typescript-eslint/no-explicit-any
      await waitWhile(() => !folderOf(app + "/") || !folderOf(join(app, "dist") + "/"));
      assert.equal(doc.querySelectorAll("#made-from-list > li").length, 2, "two entries: the two folders");
      assert.equal(doc.querySelectorAll("#made-from-list .made-from-row").length, 0, "their files folded");
      const head = (at: string) => {
        const h = folderOf(at).querySelector(".made-from-folder-head");
        return { code: h.querySelector("code").textContent, files: h.querySelector(".made-from-files").textContent,
          level: h.querySelector(".made-from-level")?.textContent ?? null, how: h.querySelector(".made-from-how")?.textContent ?? null,
          when: !!h.querySelector("time.when"), change: h.querySelector("a") };
      };
      assert.deepEqual(head(join(app, "dist") + "/"), { code: "~/app/dist/", files: "25 files", level: "No AI", how: "written by a program that held a secret", when: true, change: null });
      assert.deepEqual(head(app + "/"), { code: "~/app/", files: "3 files", level: null, how: null, when: true, change: null }, "two levels, two writers: neither is claimed");
      // M4 for the folder rows: only a path, a count and fixed words.
      for (const at of [app + "/", join(app, "dist") + "/"]) {
        const words = (folderOf(at).querySelector(".made-from-folder-head").textContent ?? "").replace(folderOf(at).querySelector("time.when").textContent, "");
        assert.match(words, /^\S+\/ · \d+ files( · No AI)?( · written by a program that held a secret)? · {2}Show$/, words);
      }
      const dist = () => folderOf(join(app, "dist") + "/");
      dist().querySelector("button.made-from-folder-open").click();
      await waitWhile(() => dist().querySelectorAll(".made-from-row").length < 20);
      assert.equal(dist().querySelector("button.made-from-folder-open").getAttribute("aria-expanded"), "true");
      assert.equal(dist().querySelectorAll(".made-from-row").length, 20, "Show lists 20 of its files");
      dist().querySelector("button.show-rest").click();
      await waitWhile(() => dist().querySelectorAll(".made-from-row").length < 25);
      assert.equal(dist().querySelectorAll(".made-from-row").length, 25, "Show more lists the rest");
      assert.equal(dist().querySelector("button.show-rest"), null);
      folderOf(app + "/").querySelector("button.made-from-folder-open").click();
      await waitWhile(() => doc.querySelectorAll("#made-from-list .made-from-row").length < 28);
      const rowOf = (p: string) => doc.querySelector(`#made-from-list .made-from-row[data-path="${p}"]`);
      const words = (p: string) => ({
        level: rowOf(p).querySelector(".made-from-level").textContent,
        how: rowOf(p).querySelector(".made-from-how").textContent,
        session: rowOf(p).querySelector("a.made-from-session")?.getAttribute("href") ?? null,
        change: rowOf(p).querySelector("a.made-from-change").getAttribute("href"),
      });
      assert.deepEqual(words(summary), { level: "Any AI, when it asks", how: "written by the AI's Write in this session", session: `/agents/${SESSION}`, change: `/rules?file=${summary}` });
      assert.deepEqual(words(built), { level: "No AI", how: "written by a program that held a secret", session: null, change: `/rules?file=${built}` });
      assert.deepEqual(words(copy), { level: "No AI", how: "copied from a secret file", session: null, change: `/rules?file=${copy}` });
      const text = card(doc).textContent ?? "";
      for (const canary of [KEY_VALUE, "MEMO_CANARY_130", "4,200,000", BYTES, "proc:", PROC, "guard", SESSION]) {
        assert.ok(!text.includes(canary), `the card carries no ${canary}`);
      }
      assert.doesNotMatch(text, /taint|derived|watermark|\$MDU/i, "the product's words");
      const page = doc.body.textContent ?? "";
      assert.ok(!page.includes(KEY_VALUE) && !page.includes("MEMO_CANARY_130") && !page.includes(BYTES), "nor does the page");

      // Change who may read it opens the file in Add a rule.
      rowOf(copy).querySelector("a.made-from-change").click();
      await waitWhile(() => !doc.querySelector(`#files-list .row.file.open[data-path="${copy}"]`));
      assert.ok(doc.querySelector(`#files-list .row.file.open[data-path="${copy}"]`), "the copy is open under Add a rule");
      assert.ok(!(doc.body.textContent ?? "").includes(KEY_VALUE), "the opened file shows no value");

      // ── M5: Add a rule says the card's writer, and leads back to its row ──
      const landed = async (p: string) => {
        await waitWhile(() => !rowOf(p));
        rowOf(p).querySelector("a.made-from-change").click();
        await waitWhile(() => !doc.querySelector(`#files-list .row.file.open[data-path="${p}"]`));
        const row = doc.querySelector(`#files-list .row.file.open[data-path="${p}"]`);
        const line = row.querySelector(".file-from");
        return { row, line: line.firstChild.textContent, detail: doc.querySelector("#files-list .file-detail .detail-label span.dim").textContent };
      };
      for (const [p, said] of [
        [built, "Written by a program that held a secret"],
        [summary, "Written by the AI's Write"],
        [notes, "Copied from a secret file"],
      ] as const) {
        const { row, line, detail } = await landed(p);
        assert.equal(line, said, `${p}: its line in Add a rule`);
        assert.equal(detail, said, `${p}: its opened row`);
        assert.equal(row.querySelector("button.made-from-see")?.textContent, "See it in Files made from your secrets");
      }
      // The copy .env.bak also matches environment files at the same level: the catalog keeps the deciding rule.
      // A file inside a folder row still opens in Add a rule (M6).
      const chunk = await landed(chunks[23]!);
      assert.equal(chunk.line, "Written by a program that held a secret");
      assert.equal(rowOf(chunks[23]!).closest(".made-from-folder"), dist(), "its folder stayed open across the Rules read");
      const bak = await landed(copy);
      assert.equal(bak.line, "Built in: environment files");
      assert.equal(bak.row.querySelector("button.made-from-see"), null, "a built-in rule decides it: no line about a writer");
      // No file says the AI wrote it when the AI did not.
      assert.ok(!(doc.getElementById("page-rules").textContent ?? "").includes("Written by the AI after it read a secret"));
      // See it in Files made from your secrets, pressed on the copy: its card row's link has the focus.
      const back = await landed(notes);
      back.row.querySelector("button.made-from-see").click();
      await waitWhile(() => doc.activeElement !== rowOf(notes)?.querySelector("a.made-from-change"));
      assert.equal(doc.activeElement, rowOf(notes).querySelector("a.made-from-change"), "the focus is on the copy's row");
      assert.equal(rowOf(notes).querySelector(".made-from-how").textContent, "copied from a secret file");
      assert.ok(!(doc.body.textContent ?? "").includes(KEY_VALUE), "still no value on the page");
    }, { headers: { Cookie: ADMIN_COOKIE } });
  } finally {
    await dashboard.close();
    gate.close(); admin.close(); human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
