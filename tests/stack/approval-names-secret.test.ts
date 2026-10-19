/**
 * approval-names-secret.test — a send question names the secret it would
 * send, across the REAL components (dashboard.md §4.34 "A send names its
 * secret"). Mandu-new.
 *
 * A real ArbiterServer (`secrets` axes) registers a secret file (a `.env`
 * whose key gets its own field symbol, the registry's structured twin) and
 * an environment variable, and its real egress gate asks about each at a
 * host no rule binds it to. A real DashboardServer over a real
 * ArbiterEventSource, with the real admin-socket client behind its approval
 * routes, serves the queue:
 *
 *   N1  /api/home: the waiting cards say "your secret STRIPE_KEY" and "your
 *       secret GITHUB_TOKEN", the file `~/…` under the dashboard's home;
 *   N2  /api/policy/panel: the inspector's words name them too, with the
 *       full path, from the provenance the arbiter attached at read time;
 *   N3  an answer (Allow once, over the real route and the real resolve op):
 *       Answered earlier names the secret, and the served Approvals page
 *       draws that row whole, when under its words, never cut to one line
 *       (dashboard.md §4.25, Approvals, *Read in full*);
 *   N4  no answer of either route, nor the session page's, carries a value
 *       or a `$MDU` token on the product side.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer, type ApprovalsArbiter } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { PolicyPanelVM } from "../../dashboard/src/view-model/policy-panel.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets");

const KEY_VALUE = "sk_live_approvalNamesStackCanary000000001";
const ENV_VALUE = "ghp_approvalNamesStackCanary0000000000000002";
const SESSION = "1791200000-321";
const CSRF = { "X-Mandu-Control": "1" };

const said = (parts: { text: string }[]) => parts.map((p) => p.text).join("");

test("a send question names its secret on the product page and in the inspector; no value reaches either", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-approval-names-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(socketPath); await gate.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const approvalsArbiter: ApprovalsArbiter = {
    egressApprovals: (status) => admin.egressApprovals(status),
    resolveEgressApproval: (approvalId, approve, scope) => admin.resolveEgressApproval(approvalId, approve, scope),
  };
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  try {
    // A registered `.env`: its key gets its own symbol (the structured twin).
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\nDEBUG=1\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    // A masked environment variable.
    const vars = await gate.registerEnvSecrets({ vars: [{ name: "GITHUB_TOKEN", value: ENV_VALUE }], sessionKey: SESSION });
    const envSym = vars.vars[0]?.symbol;
    assert.match(String(envSym), /^\$MDU:nomodel_Env\[/);

    // The real gate asks about each at a host no rule binds it to.
    const asked: Record<string, string> = {};
    for (const [sym, dest] of [[keySym!, "api.stripe.com"], [envSym!, "gist.github.com"]] as const) {
      const d = await gate.desymbolizationDecision({ symbol: sym, boundary: "network", destination: dest, sessionKey: SESSION, scheme: "https" });
      assert.equal(d.allow, false, dest);
      assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, dest);
      asked[dest] = String((d as { approvalId?: string }).approvalId);
    }

    // N1: the product's cards name each secret; the file reads `~/…`.
    const homeVm = async () => (await (await pageFetch(`${base}/api/home`)).json()) as HomeVM;
    const vm = await homeVm();
    const card = (id: string) => vm.waiting.find((a) => a.id === id)!;
    assert.equal(said(card(asked["api.stripe.com"]!).sentence), "The agent wants to send your secret STRIPE_KEY to api.stripe.com");
    assert.equal(card(asked["api.stripe.com"]!).why, "STRIPE_KEY comes from ~/proj/.env. Mandu masked it, so the AI never read it. Sending it would show the real secret to api.stripe.com.");
    assert.equal(said(card(asked["gist.github.com"]!).sentence), "The agent wants to send your secret GITHUB_TOKEN to gist.github.com");
    assert.match(card(asked["gist.github.com"]!).why, /^GITHUB_TOKEN is an environment variable\. /);

    // N2: the inspector's words, from the arbiter's read-time provenance.
    const panel = ((await (await pageFetch(`${base}/api/policy/panel`)).json()) as { panel: PolicyPanelVM }).panel;
    const row = panel.queue.find((r) => r.id === asked["api.stripe.com"])!;
    assert.equal(row.origin, env);
    assert.equal(said(row.words.sentence), "The agent wants to send your secret STRIPE_KEY to api.stripe.com");
    assert.equal(row.words.why, `STRIPE_KEY comes from ${env}. Mandu masked it, so the AI never read it. Sending it would show the real secret to api.stripe.com.`);
    assert.equal(panel.queue.find((r) => r.id === asked["gist.github.com"])!.origin, "env:GITHUB_TOKEN");

    // N3: Allow once over the real route; Answered earlier names it.
    const once = await pageFetch(`${base}/api/egress/approvals/${asked["api.stripe.com"]}/approve-once`, { method: "POST", headers: { ...CSRF, Cookie: dashboard.adminCookie() } });
    assert.equal(once.status, 200);
    const after = await homeVm();
    const answered = after.answered.find((a) => a.id === asked["api.stripe.com"]);
    assert.ok(answered, "the answer is under Answered earlier");
    assert.equal(said(answered!.sentence), "The agent wants to send your secret STRIPE_KEY to api.stripe.com");
    // The served page draws the row whole: until 2026-10-08 it kept one
    // ellipsized line, so a phone read "…your secret STRIPE_…" above Block
    // instead. And the page itself names, never shows, the secret.
    const rowSel = `#approvals-answered .row.answered[data-id="${asked["api.stripe.com"]}"]`;
    await servedProductPage(base, "/approvals", (doc) => doc.querySelector(rowSel) !== null, (doc) => {
      const row = doc.querySelector(rowSel);
      assert.ok(row, "the served page lists the answer");
      assert.equal(row.querySelector(".ellipsis"), null, "nothing in the row is cut to one line");
      const what = row.firstElementChild;
      assert.equal(what.className, "answered-what");
      assert.equal(what.querySelector(".answered-sentence").textContent, "The agent wants to send your secret STRIPE_KEY to api.stripe.com");
      assert.equal(what.lastElementChild.className, "dim answered-when", "when is on the line under the words");
      assert.ok(what.lastElementChild.querySelector("time"), "as a <time>");
      assert.equal(row.children[1].textContent, "Allowed once, unused");
      const page = doc.body.textContent ?? "";
      assert.ok(!page.includes(KEY_VALUE) && !page.includes(ENV_VALUE), "the served page carries no secret value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    });

    // N4: names, never values; the product side never carries a token.
    const bodies = {
      home: await (await pageFetch(`${base}/api/home`)).text(),
      panel: await (await pageFetch(`${base}/api/policy/panel`)).text(),
      agent: await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`)).text(),
    };
    for (const [route, body] of Object.entries(bodies)) {
      assert.ok(!body.includes(KEY_VALUE) && !body.includes(ENV_VALUE), `${route} carries no secret value`);
    }
    assert.doesNotMatch(bodies.home, /\$MDU/, "the product's home carries no token");
  } finally {
    await dashboard.close();
    gate.close(); admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
