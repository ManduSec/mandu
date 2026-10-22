/**
 * settings-about.test — Settings › About Mandu across the REAL components
 * (dashboard.md §4.25 *About Mandu*). Mandu-new.
 *
 * Until 2026-10-20 the product page never said which Mandu ran, nor where
 * the guide, Troubleshooting or the issue tracker were, except on a preview
 * agent's tag: a bug report needed `mandu --version` from a terminal.
 *
 * Here a real ArbiterServer runs at the `secrets` axes with a registered
 * key, and a real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`) serves the page, signed in:
 *
 *   S1  `/api/home` carries `about`: the release every manifest names (the
 *       launcher's, the dashboard's), the guide and its Troubleshooting
 *       section at the public docs base, and the issue tracker;
 *   S2  the served `/settings`, in jsdom, draws the card: "Mandu <release>",
 *       the three links at those public addresses, each in a new tab with
 *       noopener noreferrer, and the version to name in a report;
 *   S3  `/settings#about` lands on the card, its heading focused;
 *   S4  parity with the launcher (the docs base, the issue tracker, the
 *       release) and the guide's Troubleshooting heading are proved by
 *       about-mandu-parity.test.ts, in the docs lane;
 *   S5  the oracle: no page or answer read here carries the registered
 *       key's value, and the product page no token (`$MDU`);
 *   S6  *A newer release* (2026-10-22): with the launcher's update-check
 *       cache (written by the launcher's own writer) naming a newer release
 *       with security fixes, `/api/home` carries the answer, the served
 *       `/settings` row names it with its install command as code, and the
 *       served Home shows the security notice; no socket is opened to
 *       anything but the arbiter and the dashboard itself (the dashboard
 *       only reads the file);
 *   S7  the cache removed: neither the row's words nor the notice, and the
 *       row says when Mandu checks.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the served page and its read; the stack supplies them.
 *
 * docs-lane-exempt: it names docs/usage.md only as the path in the links'
 * public URLs and reads no doc (about-mandu-parity.test.ts reads it).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { Socket } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import * as launcherDocs from "../../launcher/src/docs-url.js";
import * as launcherVersions from "../../launcher/src/agent-versions.js";
import * as launcherUpdate from "../../launcher/src/update-check.js";
import { manduPath } from "../../dashboard/src/generated/mandu-paths.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const VALUE = `sk_live_settingsAboutCanary_${process.pid}_000000`;
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const versionOf = (pkg: string): string => (JSON.parse(readFileSync(join(REPO, pkg, "package.json"), "utf8")) as { version: string }).version;
const RELEASE = versionOf("launcher");
const SIGNED_IN = { Cookie: ADMIN_COOKIE };

let stack: { base: string; port: number; tmp: string; updateCache: string; reads: string[]; close: () => Promise<void> } | null = null;
async function start() {
  if (stack) return stack;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-settings-about-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: VALUE }] });
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production wiring connects");
  const configEnv = { MANDU_HOME: join(tmp, "mandu-home") };
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter,
    fileBrowserHome: home,
    configEnv,
    log: () => {},
    ...ADMIN_OPTS,
  });
  const port = await dashboard.listen(0);
  stack = {
    base: `http://127.0.0.1:${port}`,
    port,
    tmp,
    updateCache: manduPath("update-check", configEnv, home),
    reads: [],
    close: async () => {
      await dashboard.close();
      wired.close();
      data.close();
      await arbiter.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
  return stack;
}
after(async () => {
  const s = stack;
  // S5: every answer and page read here, the oracle.
  try {
    for (const text of s?.reads ?? []) {
      assert.ok(!text.includes(VALUE), "CONFIDENTIALITY VIOLATION: a read carries the registered key's value");
    }
  } finally {
    await s?.close();
  }
});

/** `/api/home` as the page reads it, signed in. */
async function homeAnswer(headers: Record<string, string> = SIGNED_IN): Promise<{ status: number; body: any }> {
  const s = await start();
  const r = await pageFetch(`${s.base}/api/home`, { headers });
  const text = await r.text();
  s.reads.push(text);
  return { status: r.status, body: JSON.parse(text) };
}

const drawn = (doc: any) => /^Mandu /.test(doc.getElementById("settings-about-version")?.textContent ?? "");

test("S1 /api/home carries the release and the three public links (secrets axes, explicit)", async () => {
  const { status, body } = await homeAnswer();
  assert.equal(status, 200);
  assert.deepEqual(body.about, {
    version: RELEASE,
    guideUrl: launcherDocs.docsUrl("docs/usage.md"),
    troubleshootingUrl: launcherDocs.docsUrl("docs/usage.md#troubleshooting"),
    issuesUrl: launcherVersions.ISSUES_URL,
    // No update-check cache in this Mandu home yet: no answer (S6, S7).
    update: { state: "unknown" },
  });
  // Signed out, the read gate is the one /api/home had: no new route, no
  // new answer, and still no value.
  await homeAnswer({});
});

test("S2, S3 the served /settings draws About Mandu with the release and its links; /settings#about lands on it", async () => {
  const s = await start();
  for (const path of ["/settings", "/settings#about"]) {
    const scrolled: string[] = [];
    await servedProductPage(s.base, path, drawn, (doc) => {
      const text = doc.body.textContent as string;
      s.reads.push(text);
      assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: the rendered ${path} carries the key's value`);
      assert.doesNotMatch(text, /\$MDU/, `the rendered ${path} carries no token`);
      const card = doc.getElementById("settings-about-block");
      assert.equal(card.querySelector("h2").textContent, "About Mandu");
      assert.equal(doc.getElementById("settings-about-version").textContent, `Mandu ${RELEASE}`);
      const links = [...card.querySelectorAll("#settings-about-links a")] as any[];
      assert.deepEqual(links.map((a) => [a.textContent, a.getAttribute("href"), a.getAttribute("target"), a.getAttribute("rel")]), [
        ["Guide", launcherDocs.docsUrl("docs/usage.md"), "_blank", "noopener noreferrer"],
        ["Troubleshooting", launcherDocs.docsUrl("docs/usage.md#troubleshooting"), "_blank", "noopener noreferrer"],
        ["Report a problem", launcherVersions.ISSUES_URL, "_blank", "noopener noreferrer"],
      ]);
      assert.equal(doc.getElementById("settings-about-report").textContent, `When you report a problem, say which version you run: Mandu ${RELEASE}.`);
      assert.ok(doc.querySelector('#page-settings nav.section-links a[data-section="about"]'), "the row under the title links it");
      if (path.endsWith("#about")) {
        assert.deepEqual(scrolled, ["settings-about-block"], "one scroll, to the card");
        assert.equal(doc.activeElement, doc.getElementById("settings-about-title"), "its heading has the focus");
      } else {
        assert.deepEqual(scrolled, [], "no hash, no scroll");
      }
    }, {
      headers: SIGNED_IN,
      beforeScripts: (w) => { w.HTMLElement.prototype.scrollIntoView = function (this: any) { scrolled.push(this.id); }; },
    });
  }
});

// ── S6, S7: A newer release (dashboard.md §4.25 *A newer release*) ──────────

const NEWER = "99.0.0";
/** The dashboard runs from source here (a dev layout): the release's install.sh line. */
const INSTALL = launcherUpdate.installLine(NEWER, "release");

/** Every socket connect made while `fn` runs, by target. */
async function connectsDuring(fn: () => Promise<void>): Promise<string[]> {
  const seen: string[] = [];
  const orig = Socket.prototype.connect;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  Socket.prototype.connect = function (this: Socket, ...args: any[]) {
    const a = Array.isArray(args[0]) ? args[0][0] : args[0];
    seen.push(typeof a === "string" ? a : typeof a === "number" ? `${args[1] ?? "localhost"}:${a}` : a && typeof a === "object" ? (a.path ?? `${a.host ?? "localhost"}:${a.port}`) : String(a));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (orig as any).apply(this, args);
  } as typeof orig;
  try {
    await fn();
  } finally {
    Socket.prototype.connect = orig;
  }
  return seen;
}

test("S6 a security release in the launcher's cache: the About row and the Home notice, and no socket but the arbiter's and the page's", async () => {
  const s = await start();
  const now = Date.now();
  assert.ok(launcherUpdate.writeUpdateCache(s.updateCache, {
    v: 1, checkedAt: now - 3 * 3_600_000, ok: true, releasesAt: now - 3 * 3_600_000,
    releases: [{ version: NEWER, security: true }, { version: RELEASE, security: false }],
  }), "the launcher's writer wrote the cache");
  const seen = await connectsDuring(async () => {
    const { body } = await homeAnswer();
    assert.deepEqual(body.about.update, { state: "newer", at: now - 3 * 3_600_000, newest: NEWER, security: true, install: INSTALL });
    await servedProductPage(s.base, "/settings", (doc) => /is out/.test(doc.getElementById("settings-about-version")?.textContent ?? ""), (doc) => {
      s.reads.push(doc.body.textContent as string);
      const row = doc.getElementById("settings-about-version");
      assert.match(row.textContent, new RegExp(`^Mandu ${RELEASE.replace(/\./g, "\\.")}\\. Mandu ${NEWER.replace(/\./g, "\\.")} is out with security fixes\\. Update now: `));
      assert.equal(row.querySelector("code").textContent, INSTALL, "the command as code");
      assert.ok(row.querySelector(".about-update.security"), "in the warn tint");
      assert.equal(doc.getElementById("settings-about-check").hidden, true);
    }, { headers: SIGNED_IN });
    await servedProductPage(s.base, "/", (doc) => doc.getElementById("home-update")?.hidden === false, (doc) => {
      s.reads.push(doc.body.textContent as string);
      assert.equal(doc.getElementById("update-sentence").textContent, `Mandu ${NEWER} fixes security problems in the version you run (${RELEASE}).`);
      assert.equal(doc.querySelector("#update-fix code").textContent, INSTALL);
      assert.match(doc.querySelector("#update-fix a").getAttribute("href"), /\/settings#about$/);
    }, { headers: SIGNED_IN });
  });
  assert.ok(seen.includes(`127.0.0.1:${s.port}`), `the spy saw the page's own requests (${seen.join(", ")})`);
  for (const t of seen) {
    const ok = t.startsWith(s.tmp + "/") || t === `127.0.0.1:${s.port}` || t === `localhost:${s.port}`;
    assert.ok(ok, `a socket to ${t}: the dashboard must only read the file, never ask the network`);
  }
});

test("S7 the cache removed: no update words, no Home notice, and the row says when Mandu checks", async () => {
  const s = await start();
  rmSync(s.updateCache, { force: true });
  const { body } = await homeAnswer();
  assert.deepEqual(body.about.update, { state: "unknown" });
  await servedProductPage(s.base, "/settings", (doc) => drawn(doc) && doc.getElementById("settings-about-check")?.hidden === false, (doc) => {
    assert.equal(doc.getElementById("settings-about-version").textContent, `Mandu ${RELEASE}`);
    assert.equal(doc.getElementById("settings-about-check").textContent, "Mandu checks for a newer release when you start an agent from a terminal.");
  }, { headers: SIGNED_IN });
  await servedProductPage(s.base, "/", (doc) => drawn(doc) && doc.getElementById("settings-about-check")?.hidden === false, (doc) => {
    assert.equal(doc.getElementById("home-update").hidden, true);
  }, { headers: SIGNED_IN });
});
