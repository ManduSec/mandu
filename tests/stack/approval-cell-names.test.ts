/**
 * approval-cell-names — an Approvals card's cells name the key, its file and
 * the host as code, as its headline does, across the REAL components and the
 * served page (dashboard.md §4.25u *The cells name things as the headline
 * does*). Mandu-new.
 *
 * Until 2026-10-16 the three cells were plain strings: headless Chromium
 * over the served page drew `STRIPE_KEY` and the host as code in the
 * headline and, under it, "STRIPE_KEY comes from ~/mandu-try/.env. …" as
 * text, broken "~/mandu-" / "try/.env" at its hyphen (Approvals at 980 and
 * 320 px, Home's short card at 320 px). Here a real ArbiterServer runs at
 * the `secrets` axes and registers `~/mandu-try/.env`, whose key gets its
 * own symbol; its real egress gate refuses the key's send to a host no rule
 * binds it to and asks for an OK. A real DashboardServer over the
 * production adapter (`makeApprovalsArbiter`) serves:
 *
 *   A1  `/api/home`: the waiting card's cells as parts, each joined to its
 *       string, with the key, `~/mandu-try/.env` and the host as code;
 *   A2  the served Approvals page in jsdom under its served styles at
 *       320 px: the cells draw those names as code, kept on one line
 *       (`white-space: nowrap`), the headline's too; the words read as the
 *       strings;
 *   A3  the served Home page: the short card's why line names the same;
 *   A4  the oracle: no page or answer read here carries the key's value,
 *       and none a token (`$MDU`).
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the words the served page draws; the stack supplies the
 * real request they are about.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import type { HomeVM, HomeTextPart } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = `1791850000-${process.pid}`;
const VALUE = `sk_live_cellNamesCanary_${process.pid}_00000000`;
const HOST = "uploads.names.example";
const NAMES = ["STRIPE_KEY", "~/mandu-try/.env", HOST];

const text = (parts: HomeTextPart[]): string => parts.map((p) => p.text).join("");
const codes = (parts: HomeTextPart[]): string[] => parts.filter((p) => p.kind === "code").map((p) => p.text);

test("an Approvals card's cells name the key, its file and the host as code, kept whole, on the real stack with its served page, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-cell-names-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "mandu-try"), { recursive: true });
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(sock); await gate.connect();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const noValue = (body: string, where: string) => {
    assert.ok(!body.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the .env value`);
  };
  const served = async (f: string): Promise<string> => {
    const r = await pageFetch(base + f);
    assert.equal(r.status, 200, `${f} is served`);
    return r.text();
  };
  try {
    // A registered `.env` under the home folder: its key gets its own symbol.
    const env = join(home, "mandu-try", ".env");
    writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    // The real gate refuses its send to a host no rule binds it to, and asks.
    const d = await gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: HOST, sessionKey: SESSION, scheme: "https" });
    assert.equal(d.allow, false, `the real gate refuses ${HOST}`);
    assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "and asks for an OK");

    // ── A1: the answer the page reads ──
    const homeText = await served("/api/home");
    noValue(homeText, "/api/home");
    const vm = JSON.parse(homeText) as HomeVM;
    assert.equal(vm.waiting.length, 1, "one request waits for an OK");
    const ask = vm.waiting[0]!;
    assert.deepEqual(codes(ask.sentence), ["STRIPE_KEY", HOST], "the headline's names");
    assert.equal(ask.why, `STRIPE_KEY comes from ~/mandu-try/.env. Mandu masked it, so the AI never read it. Sending it would show the real secret to ${HOST}.`);
    for (const [s, parts, name] of [[ask.why, ask.whyParts, "why"], [ask.aiNow, ask.aiNowParts, "aiNow"], [ask.ifAllowed, ask.ifAllowedParts, "ifAllowed"]] as const) {
      assert.equal(text(parts), s, `${name}: its parts are its words`);
    }
    assert.deepEqual(codes(ask.whyParts), NAMES, "why it stopped names the key, its file and the host as code");
    assert.deepEqual(codes(ask.aiNowParts), [], "what the AI has now names nothing");
    assert.deepEqual(codes(ask.ifAllowedParts), [HOST], "what Allow does names the host");

    // ── A2: the served Approvals page under its served styles, a 320 px phone ──
    const sheets = `${await served("/mandu.css")}\n${await served("/app.css")}`;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const drawn = (doc: any) => doc.querySelectorAll(".ask .ask-detail .v").length === 3;
    await servedProductPage(base, "/approvals", drawn, (doc) => {
      const win = doc.defaultView;
      const card = doc.querySelector("#approvals-waiting .ask");
      const v = [...card.querySelectorAll(".ask-detail .v")];
      assert.deepEqual(v.map((x) => x.textContent), [ask.why, ask.aiNow, ask.ifAllowed], "the cells read as the words");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const whole = (node: any): string[] => [...node.querySelectorAll("code")].map((c) => {
        assert.equal(win.getComputedStyle(c).whiteSpace, "nowrap", `${c.textContent} stays on one line`);
        assert.equal(c.className, "code-whole");
        return c.textContent;
      });
      assert.deepEqual(whole(v[0]), NAMES, "why it stopped: the names as code, kept whole");
      assert.deepEqual(whole(v[1]), []);
      assert.deepEqual(whole(v[2]), [HOST]);
      assert.deepEqual(whole(card.querySelector(".ask-sentence")), ["STRIPE_KEY", HOST], "the headline's names, kept whole too");
      noValue(doc.body.textContent, "the rendered Approvals page");
      assert.doesNotMatch(doc.body.textContent, /\$MDU/, "the rendered page carries no token");
    }, { css: resolveCssVars(stylesAt(sheets, 320)) });

    // ── A3: the served Home page: the short card's why line ──
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await servedProductPage(base, "/", (doc: any) => !!doc.querySelector("#home-waiting .ask .ask-sub code"), (doc) => {
      const sub = doc.querySelector("#home-waiting .ask .ask-sub");
      assert.ok(sub.textContent.startsWith(`${ask.why} `), sub.textContent);
      assert.deepEqual([...sub.querySelectorAll("code.code-whole")].map((c) => c.textContent), NAMES, "the same names, kept whole");
      noValue(doc.body.textContent, "the rendered Home page");
      assert.doesNotMatch(doc.body.textContent, /\$MDU/, "the rendered page carries no token");
    }, { css: resolveCssVars(stylesAt(sheets, 320)) });

    // ── A4: the oracle ──
    for (const route of ["/api/home", "/api/home/history", `/api/home/agent?session=${SESSION}`, "/approvals", "/"]) {
      const body = await (await pageFetch(base + route)).text();
      noValue(body, route);
      assert.doesNotMatch(body, /\$MDU/, `${route} carries no token`);
    }
  } finally {
    await dashboard.close();
    wired?.close();
    gate.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
