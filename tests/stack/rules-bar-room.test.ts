/**
 * rules-bar-room.test — on the product page's Rules, Changes to save never
 * hides the keyboard focus, across the REAL components (dashboard.md §4.25n
 * *It never hides the focus*). Mandu-new.
 *
 * The bar is sticky at the bottom of the window, over the rules. Until
 * 2026-10-14 the page kept no room for it: in a headless Chromium at
 * 1280×800 with three changes waiting, 48 of 118 Tab stops were scrolled
 * entirely under it (75 at 390×844), and a label chosen near the window's
 * bottom left its menu under the bar that came up with it. jsdom lays out
 * nothing and has no ResizeObserver, so the served page runs here with
 * fake-resize.ts's and each step gives the bar and the focused menu their
 * place in an 800px window (the bar's 259px measured in Chromium).
 *
 * A real ArbiterServer (secrets) holds a policy.yaml of four file rules; a
 * real DashboardServer over the production adapter serves Rules, signed in:
 *
 *   R1  the served app.css keeps `--bar-room` below what the window scrolls
 *       into view, except while the focus is in the bar, and the bar is
 *       sticky 12px above the window's bottom;
 *   R2  a label chosen in the tree for a rule of policy.yaml waits in the
 *       bar, and the menu keeps the focus; the bar laid out over that menu
 *       keeps its room (259 + 12 + 8) and scrolls the menu into view; a
 *       menu above the bar, or Save in it, moves nothing;
 *   R3  Discard hides the bar, and no room is kept; policy.yaml is as it was;
 *   R4  the oracle: no page or answer read here carries a key.
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
import { fakeResize } from "../../dashboard/test/unit/ui/fake-resize.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_" + "live_rulesBarRoomStackCanary000000000";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** Put `el` at `top` in the window, `height` high. */
function place(el: Doc, top: number, height: number): void {
  el.getBoundingClientRect = () => ({ top, bottom: top + height, height, left: 20, right: 1260, width: 1240, x: 20, y: top });
}
/** Each scrollIntoView `el` is asked for, by its `block`. */
function scrolls(el: Doc): string[] {
  const asked: string[] = [];
  el.scrollIntoView = (o: Doc) => { asked.push(String(o && o.block)); };
  return asked;
}
/** The served stylesheet, comments dropped, as `selector { body }` rules. */
function rulesOf(css: string): Array<{ sel: string; body: string }> {
  return [...css.replace(/\/\*[\s\S]*?\*\//g, "").matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({ sel: m[1]!.trim(), body: m[2]!.trim() }));
}
const BAR_TOP = 800 - 12 - 259;

test("Rules over the real arbiter: Changes to save keeps its room below a focused rule's menu and scrolls the menu above it; Save and Discard move nothing; no key on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-bar-room-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  const files = ["a.env", "b.env", "deploy.token", "notes.md"].map((f) => join(proj, f));
  for (const f of files) writeFileSync(f, `API_KEY=${KEY}\n`);
  const policyPath = join(tmp, "policy.yaml");
  const policy = [
    "version: 1",
    "paths:",
    ...files.flatMap((p) => [`  - path: "${p}"`, "    level: no-model", "    recursive: false"]),
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
  const pages: string[] = [];
  const bodies: string[] = [];
  const menuOf = (doc: Doc, path: string) => doc.querySelector(`#files-tree .row.file-rule[data-path="${path}"] select.label-select:not(.send-select)`);
  const ready = (doc: Doc) => files.every((f) => !!menuOf(doc, f));
  try {
    // R1: the served stylesheet.
    const css = rulesOf(await (await pageFetch(`${base}/app.css`)).text());
    const padding = css.filter((r) => /scroll-padding/.test(r.body));
    assert.deepEqual(padding.map((r) => `${r.sel} { ${r.body} }`), ["html:not(:has(#files-pending:focus-within)) { scroll-padding-bottom: var(--bar-room, 0px); }"],
      "the window keeps the bar's room, except while the focus is in the bar");
    assert.match(css.find((r) => r.sel === ".files-pending")?.body ?? "", /position: sticky; bottom: 12px;/);

    const ro = fakeResize();
    await servedProductPage(base, "/rules", ready, async (doc) => {
      const bar = doc.getElementById("files-pending");
      const room = () => doc.documentElement.style.getPropertyValue("--bar-room");
      assert.equal(bar.hidden, true, "nothing waits yet");
      assert.equal(ro.watched(bar), true, "the served page watches the bar");

      // R2: a label chosen for the last rule of policy.yaml, near the window's bottom.
      const last = files[3]!;
      const old = menuOf(doc, last);
      old.focus();
      old.value = "any-model";
      old.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
      await waitWhile(() => bar.hidden);
      assert.equal(bar.hidden, false, "the choice waits in Changes to save");
      assert.match(doc.getElementById("files-pending-list").textContent, /notes\.md/);
      const menu = menuOf(doc, last);
      assert.equal(doc.activeElement, menu, "the menu, drawn again, keeps the focus");
      const asked = scrolls(menu);
      place(bar, BAR_TOP, 259);
      place(menu, 740, 34);
      ro.resized(bar);
      assert.equal(room(), "279px", "the bar's 259px, its 12px margin and 8px");
      assert.deepEqual(asked, ["nearest"], "the menu under the bar is scrolled into view, above it");
      // A menu above the bar stays where it is.
      place(menu, 300, 34);
      ro.resized(bar);
      assert.equal(asked.length, 1);
      // Save, in the bar, is the bar's own.
      const save = doc.getElementById("files-save");
      const saveAsked = scrolls(save);
      save.focus();
      place(save, BAR_TOP + 210, 34);
      ro.resized(bar);
      assert.deepEqual(saveAsked, [], "a control in the bar never scrolls the window");
      pages.push(doc.body.textContent ?? "");

      // R3: Discard hides the bar; no room is kept.
      doc.getElementById("files-discard").click();
      await waitWhile(() => !bar.hidden);
      assert.equal(bar.hidden, true);
      place(bar, 0, 0);
      ro.resized(bar);
      assert.equal(room(), "", "no bar, no room");
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: (w) => ro.install(w) });
    assert.equal(readFileSync(policyPath, "utf8"), policy, "nothing was saved");

    // R4: the oracle.
    for (const path of ["/api/policy/panel", "/api/secrets", "/api/home"]) {
      bodies.push(await (await pageFetch(base + path, { headers: CSRF_ADMIN })).text());
    }
    assert.ok(bodies[0]!.includes("notes.md"), "the panel answer names the rules");
    for (const t of [...pages, ...bodies]) assert.ok(!t.includes(KEY), "no page or answer carries the key");
  } finally {
    await dashboard.close();
    wired.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
