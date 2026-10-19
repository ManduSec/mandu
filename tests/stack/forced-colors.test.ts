/**
 * forced-colors — under a forced palette (Windows' contrast themes) the
 * served product page still draws its Protection switch, the current page
 * and the picked tab, across the REAL arbiter, server and served pages and
 * styles (dashboard.md §4.25k *Forced colors*). Mandu-new.
 *
 * Until 2026-10-14 neither stylesheet had a forced-colors rule: a headless
 * Chromium with the mode emulated drew no Protection switch at all, the
 * three tabs of Who may get your secrets alike, and the current page by its
 * weight alone.
 *
 *   a real ArbiterServer (`secrets` axes) with a registered `.env`; its
 *   real egress gate asks about the key at a host no rule binds it to, so
 *   one ask waits; a real DashboardServer over the production adapter; the
 *   served pages with their served stylesheets as a browser under a forced
 *   palette applies them (jsdom applies no media query and forces nothing:
 *   css-flatten `stylesAt(…, { forcedColors: true })` unwraps the forced
 *   block, `forcedColorsModel` forces every other color as the browser
 *   does):
 *
 *   F1  Settings, signed out: the switch as the page draws it from the
 *       saved setting: on (no config.toml) filled in `Highlight` with its
 *       knob in `HighlightText` on the right; off (`mode = "off"`) an
 *       outlined track with its knob in `ButtonText` on the left; without
 *       forced colors, no edge, as before;
 *   F2  Rules, signed out: of the three tabs, only the picked one has an
 *       edge, in `Highlight`; the page's own click on Hosts moves it there;
 *   F3  Approvals, signed out: the top bar's current page (Approvals, with
 *       its count of the waiting ask) is underlined in `Highlight`, no
 *       other page is, and no word sits on a selection-color fill;
 *   F4  the oracle: no page or answer the signed-out reader got carries the
 *       key, the admin token or the session secret.
 *
 * Axes: `secrets` stated. What is under test is the served styles and
 * scripts; the stack supplies the saved setting, the rules and an ask for
 * the pages to draw.
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
import { ADMIN_OPTS, ADMIN_TOKEN, SESSION_SECRET } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { forcedColorsModel, resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const KEY_VALUE = `sk_live_forcedColorsCanary_${process.pid}_7c1d`;
const SESSION = "1791300000-911";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** What jsdom computes for a system color (its own fixed palette). */
function sys(doc: El, name: string): string {
  const probe = doc.createElement("i");
  probe.style.color = name;
  doc.body.append(probe);
  const v = doc.defaultView.getComputedStyle(probe).color as string;
  probe.remove();
  return v;
}

async function until(cond: () => boolean, what: string, ms = 10_000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error(`never happened: ${what}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

test("under a forced palette the served product page draws its switch, current page and picked tab (secrets axes)", { timeout: 90_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-forced-colors-"));
  const home = join(tmp, "home");
  const manduHome = join(tmp, "mandu-home");
  mkdirSync(join(home, "proj"), { recursive: true });
  mkdirSync(manduHome, { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath: join(tmp, "policy.yaml"), policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(socketPath);
  await gate.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production adapter is wired");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, secretsArbiter: wired.secrets,
    postureArbiter: wired.posture, auditArbiter: wired.audit,
    fileBrowserHome: home, configEnv: { MANDU_HOME: manduHome, HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const signedOutReads: string[] = [];
  const out = { "Sec-Fetch-Site": "same-origin" };
  try {
    // One ask waits: the key of a registered `.env`, at a host no rule binds it to.
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const symbol = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(symbol, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const d = await gate.desymbolizationDecision({ symbol, boundary: "network", destination: "api.stripe.com", sessionKey: SESSION, scheme: "https" });
    assert.equal(d.allow, false);
    assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "the gate asks");
    for (const route of ["/api/home", "/api/config/axes", "/api/policy/by-who"]) signedOutReads.push(await (await pageFetch(base + route, { headers: out })).text());

    const served = async (f: string): Promise<string> => {
      const r = await pageFetch(base + f, { headers: out });
      assert.equal(r.status, 200, `${f} is served`);
      return r.text();
    };
    const sheet = resolveCssVars(`${await served("/mandu.css")}\n${await served("/app.css")}`);
    /** The served styles as a desktop browser applies them, under a forced
     *  palette or not. */
    const styles = (forced: boolean): string => (forced ? forcedColorsModel(stylesAt(sheet, 1280, { forcedColors: true })) : stylesAt(sheet, 1280));

    // ── F1: the Settings switch, on then off, as the saved setting says ──
    const sw = (doc: El): El => doc.getElementById("switch-protection");
    const drawn = (doc: El): boolean => !!sw(doc) && !sw(doc).disabled;
    for (const [saved, checked] of [["none", "true"], ["off", "false"]] as const) {
      if (saved === "off") writeFileSync(join(manduHome, "config.toml"), 'mode = "off"\n');
      await servedProductPage(base, "/settings", drawn, (doc) => {
        const w = doc.defaultView;
        assert.equal(sw(doc).getAttribute("aria-checked"), checked, `the page draws the saved setting (${saved})`);
        const s = w.getComputedStyle(sw(doc));
        const k = w.getComputedStyle(sw(doc).querySelector(".knob"));
        if (checked === "true") {
          assert.deepEqual([s.borderTopStyle, s.backgroundColor, k.backgroundColor, k.left], ["solid", sys(doc, "Highlight"), sys(doc, "HighlightText"), "20px"], "on: filled in the selection color, the knob on the right");
        } else {
          assert.deepEqual([`${s.borderTopWidth} ${s.borderTopStyle} ${s.borderTopColor}`, s.backgroundColor, k.backgroundColor, k.left], [`1px solid ${sys(doc, "ButtonText")}`, sys(doc, "ButtonFace"), sys(doc, "ButtonText"), "2px"], "off: an outlined track, the knob on the left");
        }
        assert.notEqual(k.backgroundColor, s.backgroundColor, "the knob is seen on its track");
        signedOutReads.push(doc.documentElement.outerHTML);
      }, { headers: out, css: styles(true) });
      await servedProductPage(base, "/settings", drawn, (doc) => {
        assert.equal(doc.defaultView.getComputedStyle(sw(doc)).borderTopStyle, "none", `without forced colors (${saved}): no edge, as before`);
      }, { headers: out, css: styles(false) });
    }

    // ── F2: Who may get your secrets' tabs ──
    const tabs = (doc: El): El[] => [...doc.querySelectorAll('#by-who-block [role="tab"]')];
    await servedProductPage(base, "/rules", (doc) => !doc.getElementById("by-who-block").hidden, async (doc) => {
      const w = doc.defaultView;
      const edged = (): string[] => tabs(doc).filter((t) => {
        const s = w.getComputedStyle(t);
        return s.borderBottomStyle !== "none" && parseFloat(s.borderBottomWidth) > 0 && s.borderBottomColor !== sys(doc, "Canvas");
      }).map((t) => t.id);
      assert.deepEqual(edged(), ["by-who-tab-programs"], "only the picked tab, Programs, has an edge");
      assert.equal(w.getComputedStyle(doc.getElementById("by-who-tab-programs")).borderBottomColor, sys(doc, "Highlight"));
      doc.getElementById("by-who-tab-hosts").dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
      await until(() => doc.getElementById("by-who-tab-hosts").getAttribute("aria-selected") === "true", "the page picks Hosts");
      assert.deepEqual(edged(), ["by-who-tab-hosts"], "the page's own click moves the edge to Hosts");
      signedOutReads.push(doc.documentElement.outerHTML);
    }, { headers: out, css: styles(true) });

    // ── F3: the top bar's current page ──
    await servedProductPage(base, "/approvals", (doc) => !doc.getElementById("nav-approvals-count").hidden, (doc) => {
      const w = doc.defaultView;
      const links = [...doc.querySelectorAll("#nav a")] as El[];
      const current = links.filter((a) => a.getAttribute("aria-current") === "page");
      assert.deepEqual(current.map((a) => a.dataset.pageLink), ["approvals"], "Approvals is the current page");
      assert.equal(doc.getElementById("nav-approvals-count").textContent, "1", "its count of the waiting ask");
      for (const a of links) {
        const s = w.getComputedStyle(a);
        const isCurrent = a === current[0];
        assert.equal(s.textDecorationLine === "underline" && s.textDecorationColor === sys(doc, "Highlight"), isCurrent, `${a.dataset.pageLink}: ${isCurrent ? "underlined" : "not underlined"} in the selection color`);
        assert.notEqual(s.backgroundColor, sys(doc, "Highlight"), `${a.dataset.pageLink}: no word on a selection-color fill`);
      }
      signedOutReads.push(doc.documentElement.outerHTML);
    }, { headers: out, css: styles(true) });

    // ── F4: the oracle ──
    assert.equal(signedOutReads.length, 7);
    for (const body of signedOutReads) {
      assert.equal(body.includes(KEY_VALUE), false, "no page or answer the signed-out reader got carries the key");
      assert.equal(body.includes(ADMIN_TOKEN), false, "the admin token is never served");
      assert.equal(body.includes(SESSION_SECRET), false, "the session secret is never served");
    }
  } finally {
    await dashboard.close();
    gate.close();
    wired.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
