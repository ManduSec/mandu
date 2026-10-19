/**
 * rules-name-room — on the product page's Rules, a file row's name keeps
 * its room in a window up to 1000 px wide, across the REAL components
 * (dashboard.md §4.25p *The name keeps its room*). Mandu-new.
 *
 * Each file row is a grid of the name and two fixed menus (240 px and
 * 230 px; 220 and 250 until 2026-10-17). Until 2026-10-15 the menus went under the name only at 720 px
 * and below: a headless Chromium measured Your rules' name column at
 * 41 px in a 721 px window and 114 px at 800, and Add a rule's browser,
 * in its padded panel, had none at 721 and 32 px at 800. Names were drawn
 * a letter or two per line. From 801 to 1000 px (2026-10-15, the middle
 * layout) the two menus sit side by side under the name, each in half of
 * the row and at least as wide as beside the name. jsdom lays out nothing, so the served page
 * runs here with its served stylesheets as a window that wide applies them
 * (css-flatten.ts stylesAt), and the name column is computed from the
 * served stylesheet's own numbers (files-name-room.ts).
 *
 * A real ArbiterServer (secrets) holds a policy.yaml of nested file rules
 * (a folder, a file in it, a file in a folder in it) over real files that
 * hold a key; a real DashboardServer over the production adapter serves
 * Rules, signed in, with Add a rule's browser on the real home folder:
 *
 *   W1  860 px: Your rules' rows and the browser's rows put the name across
 *       the row and the two menus side by side under it, each in its own
 *       column with its caption, and the heads are hidden;
 *   W1b 800 px: each menu goes on its own line under the name, with its
 *       caption;
 *   W2  1001 px: both keep the menus beside the name, under the heads,
 *       and the notes folder's rule shows "Your own AI only (none
 *       listed)" (no model of your own is listed), a choice M2 measures;
 *   W3  the served stylesheet: at every window width where a file row
 *       keeps its columns, the name column of each list has at least
 *       200 px; wherever the menus sit side by side (801 to 1000 px), each
 *       menu's column has at least 250 px; beside the name, each menu's
 *       column shows its choices whole (240 px for the first menu, whose
 *       longest choice needs 236; 220 px cut it until 2026-10-17);
 *   W4  the oracle: no page or answer read here carries the key, and
 *       policy.yaml is as it was.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { FILE_LISTS, MENU_CHOICES, MENU_MIN, NAME_MIN, WIDE_MENUS, fileNameRoom, menuNeeds, px, sidePadding } from "../../dashboard/test/unit/ui/files-name-room.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_live_rulesNameRoomStackCanary0000000000";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** Each drawn row of `sel` with menus: its tracks, the columns its name
 *  takes, and per menu cell the columns it takes and whether its caption
 *  shows. */
function rowsOf(doc: Doc, sel: string): Array<{ tracks: string; name: string; cells: string[] }> {
  const win = doc.defaultView;
  const col = (e: Doc): string => win.getComputedStyle(e).gridColumn || "auto";
  return ([...doc.querySelectorAll(sel)] as Doc[]).filter((r) => r.querySelector(".q-cell")).map((r) => {
    assert.ok(!/grid/.test(r.getAttribute("style") ?? ""), "no inline tracks: the served stylesheet decides");
    const cells = ([...r.querySelectorAll(":scope > .q-cell")] as Doc[]).map((c) => `${col(c)} caption ${win.getComputedStyle(c.querySelector(".q-cap")).display}`);
    return { tracks: win.getComputedStyle(r).gridTemplateColumns, name: col(r.querySelector(":scope > .file-cell")), cells };
  });
}

test("Rules over the real arbiter: up to 1000 px every file row puts its menus under the name, side by side from 801 px; wider, the name has at least 200 px; no key on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-name-room-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  mkdirSync(join(proj, "deploy"), { recursive: true });
  mkdirSync(join(proj, "notes"), { recursive: true });
  const staging = join(proj, "deploy", "staging.conf");
  const notes = join(proj, "notes");
  const contract = join(notes, "contract.md");
  for (const f of [join(proj, ".env"), staging, contract]) writeFileSync(f, `API_KEY=${KEY}\n`);
  const policyPath = join(tmp, "policy.yaml");
  const policy = [
    "version: 1",
    "paths:",
    `  - path: "${proj}"`,
    "    level: no-model",
    `  - path: "${staging}"`,
    "    level: any-model",
    "    recursive: false",
    `  - path: "${notes}"`,
    "    level: local-model",
    `  - path: "${contract}"`,
    "    level: no-model",
    "    recursive: false",
    "",
  ].join("\n");
  writeFileSync(policyPath, policy);
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc, "the production adapter has the secrets and policy surfaces");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const signedIn = { Cookie: ADMIN_COOKIE };
  const pages: string[] = [];
  const bodies: string[] = [];
  const served = async (path: string): Promise<string> => {
    const r = await pageFetch(base + path, { headers: signedIn });
    assert.equal(r.status, 200, `${path} is served`);
    return r.text();
  };
  const tree = "#files-tree .row.file-rule";
  const browser = "#files-list .row.file:not(.up)";
  const ready = (doc: Doc) => [staging, contract].every((p) => [...doc.querySelectorAll(tree)].some((r: Doc) => r.getAttribute("data-path") === p));
  /** Rules with Add a rule's browser opened on the real home folder. */
  const rules = async (width: number, fn: (doc: Doc) => void) => {
    const css = resolveCssVars(stylesAt(`${await served("/mandu.css")}\n${await served("/app.css")}`, width));
    await servedProductPage(base, "/rules", ready, async (doc) => {
      doc.getElementById("rules-add").click();
      await waitWhile(() => rowsOf(doc, browser).length === 0);
      assert.ok(rowsOf(doc, browser).length > 0, `${width}px: the browser lists the home folder`);
      fn(doc);
      pages.push(doc.documentElement.outerHTML);
    }, { headers: signedIn, css });
  };
  try {
    // ── W1: 860 px ──
    await rules(860, (doc) => {
      const win = doc.defaultView;
      assert.equal(win.getComputedStyle(doc.querySelector(".files-heads")).display, "none", "860px: the heads are hidden; each menu has its caption");
      const t = rowsOf(doc, tree);
      assert.ok(t.length >= 3, `860px: the folder rule and the two inside it are drawn: ${t.length}`);
      for (const r of t) assert.deepEqual(r, { tracks: "minmax(0, 1fr) minmax(0, 1fr) 32px", name: "1 / 3", cells: ["1 caption block", "2 caption block"] }, "860px: Your rules' name spans the row, the two menus side by side under it");
      for (const r of rowsOf(doc, browser)) assert.deepEqual(r, { tracks: "20px minmax(0, 1fr) minmax(0, 1fr) 32px", name: "2 / 4", cells: ["2 caption block", "3 caption block"] }, "860px: the browser's likewise, after the tick box");
      const nested = ([...doc.querySelectorAll(tree)] as Doc[]).find((r) => r.getAttribute("data-path") === contract);
      assert.match(nested.querySelector(".file-name").textContent, /contract\.md/, "the rule two folders down is drawn by its name");
    });
    // ── W1b: 800 px ──
    await rules(800, (doc) => {
      const win = doc.defaultView;
      assert.equal(win.getComputedStyle(doc.querySelector(".files-heads")).display, "none", "800px: the heads are hidden; each menu has its caption");
      const t = rowsOf(doc, tree);
      assert.ok(t.length >= 3, `800px: the folder rule and the two inside it are drawn: ${t.length}`);
      for (const r of t) assert.deepEqual(r, { tracks: "minmax(0, 1fr) 32px", name: "1", cells: ["1 / -1 caption block", "1 / -1 caption block"] }, "800px: Your rules' menus go under the name, across the row");
      for (const r of rowsOf(doc, browser)) assert.deepEqual(r, { tracks: "20px minmax(0, 1fr) 32px", name: "2", cells: ["2 / -1 caption block", "2 / -1 caption block"] }, "800px: the browser's menus go under the name, after the tick box");
    });

    // ── W2: 1001 px ──
    await rules(1001, (doc) => {
      const win = doc.defaultView;
      assert.equal(win.getComputedStyle(doc.querySelector(".files-heads")).display, "grid", "1001px: the heads name the columns");
      for (const r of rowsOf(doc, tree)) assert.deepEqual(r, { tracks: "minmax(0, 1fr) 240px 230px 32px", name: "auto", cells: ["auto caption none", "auto caption none"] }, "1001px: Your rules keeps its columns");
      for (const r of rowsOf(doc, browser)) assert.deepEqual(r, { tracks: "20px minmax(0, 1fr) 240px 230px 32px", name: "auto", cells: ["auto caption none", "auto caption none"] }, "1001px: the browser keeps its columns");
      const notesRow = ([...doc.querySelectorAll(tree)] as Doc[]).find((r) => r.getAttribute("data-path") === notes);
      const menu = notesRow?.querySelector("select.label-select:not(.send-select)");
      assert.equal(menu?.options[menu.selectedIndex].textContent, "Your own AI only (none listed)", "1001px: the notes folder's first menu says its label and that no model of your own is listed");
      assert.ok((MENU_CHOICES.label.medium as readonly string[]).includes("Your own AI only (none listed)"), "M2 measures that choice");
    });

    // ── W3: the served stylesheet's geometry ──
    const room = fileNameRoom(`${await served("/mandu.css")}\n${await served("/app.css")}`);
    for (const l of FILE_LISTS) {
      const windows = room.wideWindows(l);
      assert.ok(windows.length > 0 && windows[0]!.w > 800, `${l.list}: the columns come back only above 800px`);
      for (const { w, name } of windows) assert.ok(name >= NAME_MIN, `${l.list}: ${name.toFixed(1)}px of name beside the menus in a ${w}px window`);
      const middle = room.middleWindows(l);
      assert.deepEqual([middle[0]?.w, middle.at(-1)?.w, middle.length], [801, 1000, 200], `${l.list}: the menus sit side by side from 801 to 1000px`);
      for (const { w, menu } of middle) assert.ok(menu >= MENU_MIN, `${l.list}: ${menu.toFixed(1)}px for each menu side by side in a ${w}px window`);
      for (const w of [1001, 1280]) {
        assert.deepEqual(room.nameColumn(l, w).tracks.filter((t) => t.endsWith("px")).slice(-3, -1), [...WIDE_MENUS], `${l.list}: the menus' columns at ${w}px`);
        const pad = sidePadding(room.at(w, ".label-pick select", "padding"), w);
        for (const weight of ["medium", "regular"] as const) assert.ok(menuNeeds(MENU_CHOICES.label[weight], weight, pad) <= px(WIDE_MENUS[0], w), `${l.list}: the first menu shows its ${weight} choices whole at ${w}px`);
        for (const weight of ["medium", "regular"] as const) assert.ok(menuNeeds(MENU_CHOICES.send[weight], weight, pad) <= px(WIDE_MENUS[1], w), `${l.list}: the second menu shows its ${weight} choices whole at ${w}px (regular: an inherited label's, greyed)`);
      }
    }

    // ── W4: the oracle ──
    for (const path of ["/api/policy/panel", "/api/secrets", "/api/home", `/api/files/list?path=${encodeURIComponent(proj)}`]) {
      const r = await pageFetch(base + path, { headers: CSRF_ADMIN });
      bodies.push(await r.text());
    }
    assert.ok(bodies[0]!.includes("contract.md"), "the panel answer names the rules");
    assert.equal(pages.length, 3);
    for (const t of [...pages, ...bodies]) assert.ok(!t.includes(KEY), "CONFIDENTIALITY VIOLATION: a page or an answer carries the key");
    assert.equal(readFileSync(policyPath, "utf8"), policy, "nothing was saved");
  } finally {
    await dashboard.close();
    wired.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
