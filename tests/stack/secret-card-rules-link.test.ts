/**
 * secret-card-rules-link — a session page's *Your secrets* card that names a
 * file links that file to Rules, "Change it in Rules", and following it
 * opens Add a rule's file browser at the file, its row opened and the focus
 * on its ⋯, the address back at `/rules` (dashboard.md §4.25b *A card opens
 * its file in Rules*), across the REAL components: a real ArbiterServer in
 * `secrets`, the real anthropic-proxy in its production wiring (`new
 * ArbiterClientAdapter(data, human)`) with a scripted model behind it, and
 * the real dashboard over the arbiter's store (`ArbiterEventSource`), with
 * the production approvals adapter (`makeApprovalsArbiter`), signed in, and
 * its file browser on the test's home folder. The served product page (its
 * own index.html and home.js) runs in jsdom.
 *
 * The first-session tour's `.env` read (as secret-card-names-file replays
 * it): `~/mandu-try/.env` is registered, the agent Reads its twin, then
 * uses the key in a Bash `curl`. Then:
 *
 *   R1  the REAL session page (`/api/home/agent`): the key's card carries
 *       its file, `~/mandu-try/.env`;
 *   R2  the served page at `/agents/<id>`: the card links
 *       `/rules?file=~/mandu-try/.env`, named "Change the rule for
 *       ~/mandu-try/.env in Rules"; a click opens Rules with the file's row
 *       opened in the file browser, the focus on its ⋯, and the address
 *       back at `/rules`;
 *   R3  the address itself, as a new tab or a bookmark opens it: the same;
 *   R4  the oracle: no page drawn, no address and no answer read here
 *       carries the key's value, and nothing was changed (policy.yaml is as
 *       it was).
 *
 * Every request goes through `pageFetch` (a socket of its own), as a stack
 * test that runs a served page must (served-page-fetch).
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm test  (tests/)
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const VALUE = `sk_live_cardRulesLink_${process.pid}_00000000`;
const HOST = "api.stripe.com";
const FILE = "~/mandu-try/.env";

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const words = (parts: { kind: string; text: string }[]) => parts.map((p) => p.text).join("");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const cardLink = (doc: Doc) => doc.querySelector("#agent-secrets a.secret-rule-link");
const openRow = (doc: Doc) => doc.querySelector("#files-list .row.file.open");

test("a secret's card names its file and opens it in Rules: the file's row opened in Add a rule, the focus on its ⋯, the address /rules; no value anywhere (secrets axes, explicit)", { timeout: 240_000 }, async () => {
  const session = `secret-card-rules-link-${process.pid}`;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-card-rules-"));
  dirs.push(tmp);
  const home = join(tmp, "home");
  mkdirSync(join(home, "mandu-try"), { recursive: true });
  const env = join(home, "mandu-try", ".env");
  writeFileSync(env, `STRIPE_KEY='${VALUE}'\nDEBUG=1\n`);
  writeFileSync(join(home, "mandu-try", "README.md"), "a tour\n");
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const policy = join(tmp, "policy.yaml");
  const policyText = "version: 1\npaths: []\n";
  writeFileSync(policy, policyText);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    policyPath: policy, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const gate = await open(sock);

  const sent: { bodyText: string }[] = [];
  let answers: MockUpstream[] = [];
  const upstream: UpstreamFetcher = async (a) => {
    const m = answers[Math.min(sent.length, answers.length - 1)]!;
    const res = await m.fetcher(a);
    sent.push(m.requests.at(-1)!);
    return res;
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), await open(humanSock)), upstream, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets, "the production adapter has the secrets surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policy },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;

  type Msg = { role: string; content: unknown };
  const send = async (messages: Msg[]): Promise<void> => {
    const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 256, tools: [{ name: "Read", input_schema: { type: "object" } }, { name: "Bash", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
  };
  const rendered: string[] = [];
  const addresses: string[] = [];

  try {
    // ── The tour's read: the registered file's twin, then the key in a curl ──
    const reg = await gate.registerSecret({ path: env, sessionKey: session });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, "the key has its own symbol");
    const curl = `curl -sS https://${HOST}/v1/customers -u '${keySym}:' -d limit=100 -G`;
    answers = [
      buildToolUseSse({ id: "toolu_read", name: "Read", input: { file_path: env } }),
      buildToolUseSse({ id: "toolu_bash", name: "Bash", input: { command: curl, description: "List Stripe customers" } }),
      buildTextSse("The request needs your OK in Approvals."),
    ].map((sse) => new MockUpstream({ sse }));
    const ask: Msg[] = [{ role: "user", content: "Read .env and list my Stripe customers." }];
    await send(ask);
    const readRender = (reg.twin ?? "").split("\n").map((l, i) => `${i + 1}\t${l}`).join("\n");
    const turn1: Msg[] = [
      ...ask,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_read", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_read", content: readRender }] },
    ];
    await send(turn1);
    await send([
      ...turn1,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_bash", name: "Bash", input: { command: curl, description: "List Stripe customers" } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_bash", content: "Mandu blocked this request: it needs your OK." }] },
    ]);
    for (const s of sent) assert.ok(!s.bodyText.includes(VALUE), "CONFIDENTIALITY VIOLATION: the key's value reached the model");

    // ── R1: the real session page carries the card's file ──
    let page: AgentPageVM | undefined;
    let body = "";
    const card = () => page?.secrets?.secrets.find((s) => /STRIPE_KEY/.test(words(s.what)));
    for (let i = 0; i < 150; i++) {
      // emission is best-effort and asynchronous
      const r = await pageFetch(`${base}/api/home/agent?session=${session}`, { headers: { Cookie: ADMIN_COOKIE } });
      if (r.status === 200) {
        body = await r.text();
        page = JSON.parse(body) as AgentPageVM;
        if (card()?.file && page.story.some((t) => t.steps.some((s) => s.kind === "action" && /curl|stripe/i.test(words(s.sentence))))) break;
      }
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(card(), `the page lists the key: ${body.slice(0, 400)}`);
    assert.equal(words(card()!.what), `STRIPE_KEY in ${FILE}`);
    assert.equal(card()!.file, FILE, "the card carries its file, as the page names it");
    assert.ok(!body.includes(VALUE), "CONFIDENTIALITY VIOLATION: the session page carries the key's value");

    // ── R2: the served page: the link, and following it ──
    await servedProductPage(base, `/agents/${encodeURIComponent(session)}`, (doc: Doc) => !!cardLink(doc), async (doc: Doc) => {
      const w = doc.defaultView;
      const link = cardLink(doc);
      assert.equal(link.textContent, "Change it in Rules");
      assert.equal(link.getAttribute("aria-label"), `Change the rule for ${FILE} in Rules`);
      assert.equal(link.getAttribute("href"), `/rules?file=${FILE}`);
      rendered.push(doc.body.textContent ?? "");
      link.focus();
      link.click();
      await waitWhile(() => !openRow(doc), 20_000);
      addresses.push(w.location.href);
      assert.equal(w.location.pathname + w.location.search, "/rules", "the address drops ?file= once used");
      assert.equal(doc.getElementById("page-rules").hidden, false);
      assert.equal(doc.getElementById("lock-form").hidden, false, "Add a rule's browser is open");
      const row = openRow(doc);
      assert.equal(row.getAttribute("data-path"), env, "the file's row is opened");
      await waitWhile(() => doc.activeElement !== row.querySelector(".file-more"), 5_000);
      assert.equal(doc.activeElement, row.querySelector(".file-more"), "the focus on its ⋯");
      assert.ok(row.closest("#files-list").querySelectorAll(".row.file").length >= 2, "in its folder's listing");
      rendered.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // ── R3: the address itself (a new tab, a bookmark) ──
    await servedProductPage(base, `/rules?file=${FILE}`, (doc: Doc) => !!openRow(doc), async (doc: Doc) => {
      const w = doc.defaultView;
      addresses.push(w.location.href);
      assert.equal(w.location.pathname + w.location.search, "/rules", "replaced with /rules");
      const row = openRow(doc);
      assert.equal(row.getAttribute("data-path"), env);
      await waitWhile(() => doc.activeElement !== row.querySelector(".file-more"), 5_000);
      assert.equal(doc.activeElement, row.querySelector(".file-more"));
      rendered.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // ── R4: the oracle ──
    assert.equal(rendered.length, 3);
    for (const text of [...rendered, ...addresses]) {
      assert.ok(!text.includes(VALUE), "CONFIDENTIALITY VIOLATION: a page or an address carries the key's value");
      assert.doesNotMatch(text, /\$MDU:/, "nor a token");
    }
    const homeBody = await (await pageFetch(`${base}/api/home`, { headers: { Cookie: ADMIN_COOKIE } })).text();
    assert.ok(!homeBody.includes(VALUE), "CONFIDENTIALITY VIOLATION: Home carries the key's value");
    assert.equal(readFileSync(policy, "utf8"), policyText, "following the link changed no rule");
  } finally {
    await dashboard.close();
    await proxy.close();
    for (const c of clients) c.close();
    await arbiter.close();
  }
});
