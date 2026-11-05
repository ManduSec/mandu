/**
 * product-adopted-refusals.test — an answer on the product page from a
 * dashboard that did not start its protection service, across the REAL
 * components (dashboard.md §4.25 "Refusals", *An answer this dashboard
 * cannot pass on*). Mandu-new.
 *
 * A dashboard that found the service already running adopts it and holds
 * no admin channel (server-main.ts adminTarget), so every answer from the
 * page is refused before anything runs. Until 2026-10-25 the card printed
 * the adapter's text as written: "admin channel unavailable: this dashboard
 * did not start the arbiter (adopted instance), … restart the services from
 * Settings …", a button Settings does not offer for an adopted service.
 *
 *   A1  a real arbiter (`secrets` axes) asks about a registered `.env` key
 *       at a host no rule binds it to; a real DashboardServer over the
 *       production adapter with NO admin channel
 *       (`makeApprovalsArbiter(sock, () => undefined)`, the adopted wiring)
 *       serves Home with its card;
 *   A2  the real route answers 503 with the adapter's words; Allow once on
 *       the served page says the page's sentence instead, `mandu stop` as
 *       code, none of the developer words; the question is still pending in
 *       the arbiter (nothing changed);
 *   A3  a dashboard whose admin target is the data socket gets the arbiter's
 *       own "admin-only:" refusal (server.ts adminOnlyError), which the page
 *       says the same way;
 *   A4  the oracle: neither page nor any route answer carries the secret's
 *       value or a token.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer, adminOnlyError } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { ADMIN_UNAVAILABLE_PREFIX } from "../../dashboard/src/server/http-util.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { ADMIN_OPTS, ADMIN_COOKIE, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const KEY_VALUE = "sk_" + "live_productAdoptedRefusalsCanary0001";
const SESSION = "1791900000-919";
const ADMIN_CHANNEL_WORDS = "This dashboard cannot pass on your answers: the protection service was already running when the dashboard started. Nothing was changed. To fix it, run mandu stop when no agent is running with mandu, then start your agent again.";
/** What the refusal's server text says, which the page must not. */
const DEVELOPER = /arbiter|admin channel|adopted|data socket|\bfd\b|admin-only|supervisor/i;
const SIGNED_IN = { headers: { Cookie: ADMIN_COOKIE } };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const codes = (node: any): string[] => [...node.querySelectorAll("code")].map((c: any) => c.textContent);

test("a dashboard that did not start its protection service says why an answer did not count, and what to do (real arbiter, adapter, dashboard)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-adopted-refusals-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
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

  // The production adapter, adopted: the data socket, no admin channel.
  const adopted = await makeApprovalsArbiter(socketPath, () => undefined);
  // The same adapter whose admin target is the data socket: the arbiter
  // itself refuses the op there.
  const misrouted = await makeApprovalsArbiter(socketPath, () => ({ socketPath }));
  assert.ok(adopted && misrouted, "the adapter connects to the running arbiter");
  const dashboardOver = (surfaces: NonNullable<typeof adopted>) => new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: surfaces.arbiter,
    secretsArbiter: surfaces.secrets,
    postureArbiter: surfaces.posture,
    auditArbiter: surfaces.audit,
    policyDocArbiter: surfaces.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const dashboards = [dashboardOver(adopted), dashboardOver(misrouted)];
  const [base, misroutedBase] = await Promise.all(dashboards.map(async (d) => `http://127.0.0.1:${await d.listen(0)}`));
  const rendered: string[] = [];
  const answers: string[] = [];
  try {
    // ── A1: a send question, and Home's card for it ──────────────────────────
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const d = await gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: "collector.example", sessionKey: SESSION, scheme: "https" });
    assert.equal(d.allow, false);
    const id = String((d as { approvalId?: string }).approvalId);
    assert.ok((await admin.egressApprovals("pending")).some((a) => a.id === id), "the gate queued a question");
    for (const at of [base, misroutedBase]) {
      for (let i = 0; i < 100; i++) {
        const vm = (await (await pageFetch(`${at}/api/home`, SIGNED_IN)).json()) as HomeVM;
        answers.push(JSON.stringify(vm));
        if (vm.waiting.some((w) => w.id === id)) break;
        await new Promise((r) => setTimeout(r, 20));
      }
    }

    // ── A2 / A3: each route's refusal, then the served page's words ─────────
    const cases = [
      { at: base!, prefix: `${ADMIN_UNAVAILABLE_PREFIX}: `, label: "no admin channel (adopted)" },
      { at: misroutedBase!, prefix: adminOnlyError("resolveEgressApproval"), label: "the arbiter's own refusal on its data socket" },
    ];
    for (const c of cases) {
      const raw = await pageFetch(`${c.at}/api/egress/approvals/${encodeURIComponent(id)}/approve-once`, { method: "POST", headers: CSRF_ADMIN });
      const text = await raw.text();
      answers.push(text);
      assert.equal(raw.status, 503, `${c.label}: ${text}`);
      const error = String((JSON.parse(text) as { error?: string }).error);
      assert.ok(error.startsWith(c.prefix), `${c.label}: the route passes the server's words on: ${error}`);
      assert.match(error, DEVELOPER, "words the page must not show");

      const card = `#home-waiting .ask[data-id="${id}"]`;
      await servedProductPage(c.at, "/", (doc) => doc.querySelector(card) !== null, async (doc) => {
        const allow = [...doc.querySelectorAll(`${card} .ask-actions button`)].find((b: any) => b.textContent === "Allow once") as any;
        assert.ok(allow, "the card has Allow once");
        allow.click();
        await waitWhile(() => !doc.querySelector(`${card} .ask-error`));
        const line = doc.querySelector(`${card} .ask-error`);
        assert.equal(line.textContent, ADMIN_CHANNEL_WORDS, `${c.label}: the page's own sentence on the card`);
        assert.deepEqual(codes(line), ["mandu stop"], "the command is code");
        assert.doesNotMatch(doc.getElementById("page-home").textContent ?? "", DEVELOPER, "no developer word on the page");
        rendered.push(doc.body.textContent ?? "");
      }, SIGNED_IN);

      // Nothing changed: the question still waits in the arbiter.
      const pending = await admin.egressApprovals("pending");
      assert.ok(pending.some((a) => a.id === id), `${c.label}: the question is still pending`);
    }

    // ── A4: no value, no token anywhere shown or answered ───────────────────
    for (const page of rendered) {
      assert.ok(!page.includes(KEY_VALUE), "no rendered page carries the secret value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    }
    for (const body of answers) assert.ok(!body.includes(KEY_VALUE), "no route answer carries the secret value");
  } finally {
    await Promise.all(dashboards.map((d) => d.close()));
    adopted?.close();
    misrouted?.close();
    gate.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
