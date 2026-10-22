/**
 * tab-icon-state.test — the browser tab says the protection state, across
 * the REAL components (dashboard.md §4.25 *The tab says the protection
 * state*). Mandu-new.
 *
 * Until 2026-10-22 the tab's icon was the green shield with its check, and
 * its title "Mandu", in every state but a waiting question: with protection
 * off, or the service stopped. A pinned or background tab shows only that
 * icon, so it said "protected" exactly when nothing was. Here a real
 * ArbiterServer runs at stated axes and a real DashboardServer reads it over
 * a real ArbiterEventSource; the served product page (its own index.html
 * and home.js in jsdom) is read at each:
 *
 *   T1  the `secrets` axes: the green shield with its check, exactly the
 *       page's own icon, and the title "Mandu";
 *   T2  the `off` axes: the grey shield with the hero's cross, and the title
 *       "Protection off · Mandu";
 *   T3  the arbiter stops under the open page: its next poll draws the grey
 *       shield with no mark, and the title "Not connected · Mandu";
 *   T4  the oracle: no title or icon carries the labelled file's value or a
 *       token.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // T1 and T3; T2 states the `off` axes on its own arbiter

const KEY_VALUE = "sk_" + "live_tabIconStateStackCanary0001";
/** The page's own icon, as index.html serves it. */
const BASE_ICON = /<link rel="icon" id="favicon" href="([^"]+)">/.exec(readFileSync(new URL("../../dashboard/public/index.html", import.meta.url), "utf8"))![1]!;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const icon = (doc: any): string => decodeURIComponent(String(doc.getElementById("favicon").href).replace(/^data:image\/svg\+xml,/, ""));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const fill = (doc: any): string => /<path d='M16 3[^']*' fill='([^']+)'/.exec(icon(doc))?.[1] ?? "";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const verdict = (doc: any): string | undefined => doc.getElementById("hero")?.dataset.verdict;
const CHECK = /M11 16l3\.5 3\.5L21 13/;

/** A real arbiter at the given axes, a dashboard over it, a labelled secret file. */
async function stack(axes: { confidentiality: boolean; integrity: boolean }) {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-tab-icon-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    ...axes,
  });
  await arbiter.listen();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const env = join(home, "proj", ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
  await admin.setPathLabel({ path: env, confidentiality: "no-model", bindings: [], recursive: false });
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    fileBrowserHome: home,
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  let arbiterOpen = true;
  return {
    base,
    stopArbiter: async () => { admin.close(); await arbiter.close(); arbiterOpen = false; },
    close: async () => {
      await dashboard.close();
      if (arbiterOpen) { admin.close(); await arbiter.close(); }
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

/** T4 on what the tab shows. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function oracle(doc: any, what: string): void {
  const shown = `${doc.defaultView.document.title}\n${icon(doc)}`;
  assert.ok(!shown.includes(KEY_VALUE), `${what}: no secret value in the tab`);
  assert.doesNotMatch(shown, /\$MDU/, `${what}: nor a token`);
}

test("the tab's icon and title say the protection state: on, off, not connected (real arbiter, dashboard, served page)", { timeout: 240_000 }, async () => {
  // T1 and T3: the `secrets` axes, then the arbiter stopped under the open page.
  const on = await stack({ confidentiality: true, integrity: false }); // the `secrets` axes, stated
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await servedProductPage(on.base, "/", (doc: any) => verdict(doc) === "secrets-only", async (doc) => {
      const w = doc.defaultView;
      assert.equal(w.document.title, "Mandu");
      assert.equal(doc.getElementById("favicon").href, BASE_ICON, "the page's own green check");
      assert.equal(fill(doc), "#1e7f4f");
      assert.match(icon(doc), CHECK);
      oracle(doc, "on");

      await on.stopArbiter();
      doc.dispatchEvent(new w.Event("visibilitychange"));
      await waitWhile(() => w.document.title !== "Not connected · Mandu");
      assert.equal(w.document.title, "Not connected · Mandu");
      assert.equal(fill(doc), "#6c6c74", "a grey shield");
      assert.doesNotMatch(icon(doc), /stroke|circle/, "with no mark: never the check");
      assert.equal(doc.getElementById("hero-headline").textContent, "Not connected.", "as the hero says");
      oracle(doc, "not connected");
    });
  } finally {
    await on.close();
  }

  // T2: the `off` axes.
  const off = await stack({ confidentiality: false, integrity: false }); // the `off` axes, stated
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await servedProductPage(off.base, "/", (doc: any) => verdict(doc) === "off", async (doc) => {
      assert.match(doc.defaultView.document.title, /^Protection off · Mandu$/);
      assert.equal(fill(doc), "#6c6c74", "a grey shield");
      assert.match(icon(doc), /M12 11l8 8M20 11l-8 8/, "with the hero's cross");
      assert.doesNotMatch(icon(doc), CHECK, "never the check");
      assert.equal(doc.getElementById("hero-headline").textContent, "Protection is off.");
      oracle(doc, "off");
    });
  } finally {
    await off.close();
  }
});
