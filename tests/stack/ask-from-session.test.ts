/**
 * ask-from-session.test — a waiting question says which session asked,
 * across the REAL components (dashboard.md §4.25u *A question says which
 * session asked*). Mandu-new.
 *
 * Two Claude Code agents, one in ~/projects/shop and one in
 * ~/projects/blog, each raised a question, and both cards read "Claude Code
 * wants to send …" with nothing to tell them apart. Here a real
 * ArbiterServer runs at the `secrets` axes; two REAL anthropic-proxy
 * sessions on the production client (`new ArbiterClientAdapter(data,
 * human)`) each carry one turn whose system prompt names its folder
 * (Claude Code's " - Primary working directory: …"); each session's masked
 * variable is then asked for by the real egress gate at a host no rule
 * binds it to. A real DashboardServer over the production adapter serves,
 * signed in:
 *
 *   F1  `/api/home`: each waiting card's `askerCwd` is its own session's
 *       folder, `askerAgent` "Claude Code", `askerSessions` 1;
 *   F2  the served Approvals page (jsdom): each card's moment line ends
 *       "· from Claude Code in ~/projects/<its folder>", the folder as
 *       code, with no period after it; its *See what the agent was doing*
 *       opens the session whose folder it names;
 *   F3  the served Home page: each short card names its folder before
 *       ". Details in Approvals";
 *   F4  the oracle: the model never got a value, and no page or answer
 *       read here carries a variable's value or a token (`$MDU`).
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { Readable } from "node:stream";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars } from "../../dashboard/test/unit/ui/css-flatten.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const CLOCK = String.raw`[A-Z][a-z]{2} \d{1,2}(?:, \d{4})?, \d{2}:\d{2}`;
const AGENTS = [
  { session: "ask-from-shop", folder: "shop", name: "STRIPE_KEY", value: "sk_live_askFromSessionShop000000000001", host: "api.stripe.com" },
  { session: "ask-from-blog", folder: "blog", name: "GITHUB_TOKEN", value: "ghp_askFromSessionBlog0000000000000002", host: "gist.github.com" },
] as const;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

test("two agents of one kind: Approvals and Home name the folder of the session that asked each question, and its link opens that session; no secret anywhere (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-ask-from-"));
  const home = join(tmp, "home");
  for (const a of AGENTS) mkdirSync(join(home, "projects", a.folder), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath); await data.connect();
  const human = new ArbiterClient(humanPath); await human.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production adapter");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome") },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(buildTextSse("Done.", { deltas: 1 }), "utf8")]) };
  };
  const proxies: AnthropicProxy[] = [];
  const bodies: string[] = [];
  const signedIn = { headers: { Cookie: ADMIN_COOKIE } };
  try {
    for (const a of AGENTS) {
      // One turn through the real proxy: Claude Code's environment list names its folder.
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: a.session, log: () => {} });
      proxies.push(proxy);
      const port = await proxy.listen(0);
      const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-mandu-session-id": a.session, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({
          model: "claude-opus-4", stream: true, max_tokens: 256,
          system: [{ type: "text", text: `You are Claude Code.\n\n# Environment\n - Primary working directory: ${join(home, "projects", a.folder)}\n - Platform: linux` }],
          messages: [{ role: "user", content: "Deploy the site." }],
        }),
      });
      assert.equal(res.status, 200, await res.text());
      // Its masked variable, asked for at a host no rule binds it to.
      const vars = await data.registerEnvSecrets({ vars: [{ name: a.name, value: a.value }], sessionKey: a.session });
      const d = await data.desymbolizationDecision({ symbol: String(vars.vars[0]?.symbol), boundary: "network", destination: a.host, sessionKey: a.session, scheme: "https" });
      assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, `${a.session}: the gate asks the human`);
    }

    // ── F1: /api/home ──
    type Ask = HomeVM["waiting"][number];
    const byHost = (vm: HomeVM, host: string): Ask | undefined => vm.waiting.find((w) => JSON.stringify(w.sentence).includes(host));
    let vm: HomeVM | undefined;
    for (let i = 0; i < 400; i++) {
      const text = await (await pageFetch(`${base}/api/home`, { headers: CSRF_ADMIN })).text();
      vm = JSON.parse(text) as HomeVM;
      if (AGENTS.every((a) => byHost(vm!, a.host)?.askerCwd)) { bodies.push(text); break; }
      await new Promise((r) => setTimeout(r, 25));
    }
    for (const a of AGENTS) {
      const ask = byHost(vm!, a.host);
      assert.ok(ask, `${a.session}: its question waits`);
      assert.equal(ask.askerCwd, join(home, "projects", a.folder), `${a.session}: its own folder`);
      assert.equal(ask.askerAgent, "Claude Code");
      assert.equal(ask.askerSessions, 1);
      assert.deepEqual(ask.sessions, [a.session]);
    }
    const css = resolveCssVars(`${await (await pageFetch(`${base}/mandu.css`)).text()}\n${await (await pageFetch(`${base}/app.css`)).text()}`);
    const pages: string[] = [];
    const cardFor = (doc: Doc, sel: string, host: string): Doc => [...doc.querySelectorAll(sel)].find((c: Doc) => c.querySelector(".ask-sentence").textContent.includes(host));

    // ── F2: Approvals ──
    await servedProductPage(base, "/approvals", (doc: Doc) => doc.querySelectorAll("#approvals-waiting .ask.expanded .ask-from").length === AGENTS.length, (doc: Doc) => {
      for (const a of AGENTS) {
        const card = cardFor(doc, "#approvals-waiting .ask.expanded", a.host);
        assert.ok(card, `${a.host}: its card`);
        const sub = card.querySelector(".ask-sub");
        assert.match(sub.textContent, new RegExp(`^${CLOCK} · just now · from Claude Code in ~/projects/${a.folder}$`), `${a.host}: ${sub.textContent}`);
        assert.equal(sub.querySelector(".ask-from code").textContent, `~/projects/${a.folder}`, "the folder as code");
        const link = card.querySelector("a.ask-link");
        assert.equal(link.textContent, "See what the agent was doing");
        assert.equal(link.getAttribute("data-session"), a.session, `${a.host}: the link opens the session in ~/projects/${a.folder}`);
        assert.ok(link.getAttribute("href").includes(encodeURIComponent(a.session)), link.getAttribute("href"));
      }
      pages.push(doc.documentElement.outerHTML);
    }, { css, ...signedIn });

    // ── F3: Home ──
    await servedProductPage(base, "/", (doc: Doc) => doc.querySelectorAll("#home-waiting .ask .ask-from").length === AGENTS.length, (doc: Doc) => {
      for (const a of AGENTS) {
        const sub = cardFor(doc, "#home-waiting .ask", a.host).querySelector(".ask-sub");
        assert.match(sub.textContent, new RegExp(`${CLOCK} · just now · from Claude Code in ~/projects/${a.folder}\\. Details in Approvals$`), sub.textContent);
      }
      pages.push(doc.documentElement.outerHTML);
    }, { css, ...signedIn });

    // ── F4: the oracle ──
    assert.equal(seen.length, AGENTS.length, "each turn reached the model");
    for (const a of AGENTS) assert.ok(!seen.join("\n").includes(a.value), "CONFIDENTIALITY VIOLATION: the model got a value");
    for (const route of ["/api/home", ...AGENTS.map((a) => `/api/home/agent?session=${a.session}`)]) {
      const r = await pageFetch(base + route, { headers: CSRF_ADMIN });
      assert.equal(r.status, 200, `${route} is served`);
      bodies.push(await r.text());
    }
    for (const text of [...pages, ...bodies]) {
      for (const a of AGENTS) assert.ok(!text.includes(a.value), "CONFIDENTIALITY VIOLATION: a value in a page or an answer");
      assert.doesNotMatch(text, /\$MDU/, "no token in a page or an answer");
    }
  } finally {
    for (const p of proxies) await p.close();
    await dashboard.close();
    wired?.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
