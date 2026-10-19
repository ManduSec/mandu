/**
 * secret-card-names-file — a key the AI read from a file is named by that
 * file on the session page's *Your secrets*, "STRIPE_KEY in ~/mandu-try/.env",
 * not "STRIPE_KEY in a file" (dashboard.md §4.25b *Your secrets*), across the
 * REAL components: a real ArbiterServer in `secrets`, the real
 * anthropic-proxy in its production wiring (`new ArbiterClientAdapter(data,
 * human)`) with a scripted model behind it, and the real dashboard over the
 * arbiter's store (`ArbiterEventSource`).
 *
 * The first-session tour (Claude Code 2.1.289): `~/mandu-try/.env` is
 * registered, so the agent reads its twin, whose key is already a token
 * (`$MDU:nomodel_Read[…].STRIPE_KEY`): the proxy mints nothing for that Read
 * and the token's later uses record no origin. The card read "STRIPE_KEY in
 * a file" while the step said "Read .env" and Approvals named the file.
 * Replayed:
 *
 *   N1  the arbiter registers the `.env` (as the launcher's secret twins
 *       do): its key gets its own symbol in the twin;
 *   N2  the model Reads the file and gets the twin; then uses the key in a
 *       Bash `curl`; nothing the proxy forwards carries the value;
 *   N3  the REAL session page (`/api/home/agent`): the key's card is the
 *       first and names its file under the home folder, "STRIPE_KEY in
 *       ~/mandu-try/.env", from the Read that first returned it;
 *   N4  the oracle: neither the page nor Home's answer carries the key's
 *       value.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm test  (tests/)
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const VALUE = `sk_live_cardNamesFile_${process.pid}_00000000`;
const HOST = "api.stripe.com";

const dirs: string[] = [];
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const words = (parts: { kind: string; text: string }[]) => parts.map((p) => p.text).join("");

test("a key read from a registered file: the real session page's first secret card names the file, \"STRIPE_KEY in ~/mandu-try/.env\", and no page carries its value (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const session = `secret-card-names-file-${process.pid}`;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-card-file-"));
  dirs.push(tmp);
  const home = join(tmp, "home");
  mkdirSync(join(home, "mandu-try"), { recursive: true });
  const env = join(home, "mandu-try", ".env");
  writeFileSync(env, `STRIPE_KEY='${VALUE}'\nDEBUG=1\n`);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
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
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }), fileBrowserHome: home, log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;

  type Msg = { role: string; content: unknown };
  const send = async (messages: Msg[]): Promise<void> => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 256, tools: [{ name: "Read", input_schema: { type: "object" } }, { name: "Bash", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
  };

  try {
    // ── N1: the file is registered; its key has its own symbol in the twin ──
    const reg = await gate.registerSecret({ path: env, sessionKey: session });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify({ ...reg, twin: undefined })}`);
    assert.ok(!(reg.twin ?? "").includes(VALUE), "the twin holds no value");

    // ── N2: the Read gets the twin; the key goes into a Bash curl ──
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
    const turn2: Msg[] = [
      ...turn1,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_bash", name: "Bash", input: { command: curl, description: "List Stripe customers" } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_bash", content: "Mandu blocked this request: it needs your OK." }] },
    ];
    await send(turn2);
    assert.equal(sent.length, 3, "three requests reached the model");
    for (const s of sent) assert.ok(!s.bodyText.includes(VALUE), "CONFIDENTIALITY VIOLATION: the key's value reached the model");

    // ── N3: the real session page names the file ──
    const firstCard = (p: AgentPageVM | undefined) => p?.secrets?.secrets[0];
    let page: AgentPageVM | undefined;
    let body = "";
    for (let i = 0; i < 150; i++) {
      // emission is best-effort and asynchronous
      const r = await fetch(`${base}/api/home/agent?session=${session}`);
      if (r.status === 200) {
        body = await r.text();
        page = JSON.parse(body) as AgentPageVM;
        if (firstCard(page) && /STRIPE_KEY/.test(words(firstCard(page)!.what)) && page.story.some((t) => t.steps.some((s) => s.kind === "action" && /curl|stripe/i.test(words(s.sentence))))) break;
      }
      await new Promise((r) => setTimeout(r, 20));
    }
    const card = firstCard(page);
    assert.ok(card, `the page lists the key: ${body.slice(0, 400)}`);
    assert.equal(words(card!.what), "STRIPE_KEY in ~/mandu-try/.env", "the card names the file the Read returned it from");
    assert.ok(!(page!.secrets.secrets.some((s) => /in a file/.test(words(s.what)))), "no card says only \"in a file\"");
    assert.doesNotMatch(JSON.stringify(page!.secrets), new RegExp(home.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), "the home folder reads ~");

    // ── N4: the oracle ──
    assert.ok(!body.includes(VALUE), "CONFIDENTIALITY VIOLATION: the session page carries the key's value");
    const homeBody = await (await fetch(`${base}/api/home`)).text();
    assert.ok(!homeBody.includes(VALUE), "CONFIDENTIALITY VIOLATION: Home carries the key's value");
  } finally {
    await dashboard.close();
    await proxy.close();
    for (const c of clients) c.close();
    await arbiter.close();
  }
});
