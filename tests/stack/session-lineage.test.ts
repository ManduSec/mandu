/**
 * session-lineage — where a secret went, over the REAL components
 * (dashboard.md §4.25b *Where it went*, symbol-lineage.md §5.6): the
 * OpenClaw plugin demo's shape. A registered `.env`'s passphrase is printed
 * by a script's debug output; the real anthropic-proxy (production wiring,
 * `new ArbiterClientAdapter(new ArbiterClient(sock))`) masks it to the
 * file's twin before the scripted model sees it; the real dashboard, wired
 * to the real arbiter as server-main wires it (`makeApprovalsArbiter`), with
 * a kept `mandu scan` under its Mandu home, serves the session page and the
 * events route.
 *
 * Asserted:
 *   - the invariant: the model's requests never carry the value;
 *   - the card is named by the file the registry says the placeholder stands
 *     for, never by the command that printed it (the 2026-10-28 card
 *     "`ORDERHUB_PASSPHRASE` in `DEBUG=1 sh …`" and its Rules link to a file
 *     of that name);
 *   - the card's path (kept in, how it came in, what the AI got, never left
 *     with its real value), and the step's "from `~/app/.env`";
 *   - the earlier leak the kept scan found, on the card (its link opens the
 *     finding's Scan row, `scanItem`) and in `/api/events`' `flowNotes`
 *     (the developer view's *Where each went*);
 *   - nothing in either answer carries the value.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
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
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const SESSION = `lineage-${process.pid}`;
const VALUE = "Juniper-Harbor-6038-Wren-e2e";
const CMD = "DEBUG=1 sh orders-app/bin/sync-orders.sh";
const words = (parts: { text: string }[]) => parts.map((p) => p.text).join("");

const closers: Array<() => Promise<void>> = [];
const dirs: string[] = [];
after(async () => {
  for (const c of closers.reverse()) await c();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

test("the plugin demo's session page: the card names the registered file, draws its path and the earlier leak; the model never got the value (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-lineage-e2e-"));
  dirs.push(tmp);
  const home = join(tmp, "home");
  const app = join(home, "app");
  mkdirSync(app, { recursive: true });
  const env = join(app, ".env");
  writeFileSync(env, `ORDERHUB_URL=https://api.orderhub.test\nORDERHUB_USER=bakery-shop\nORDERHUB_PASSPHRASE=${VALUE}\n`);
  // The kept scan: the same key reached an AI without Mandu the day before.
  const manduHome = join(tmp, "mandu-home");
  mkdirSync(join(manduHome, "state"), { recursive: true, mode: 0o700 });
  writeFileSync(join(manduHome, "state", "last-scan.json"), JSON.stringify({
    version: 1, ranAt: "2026-10-28T08:00:00.000Z", sessions: { openclaw: 1 }, duringMandu: 0, known: 1, dropped: 0,
    capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 }, suggestions: null,
    findings: [{
      kind: "known", preview: "Ju…2e", source: { path: "~/app/.env", name: "ORDERHUB_PASSPHRASE" }, sessions: 1, agents: ["openclaw"],
      how: { "command-output": 1 }, projects: ["~/app"], duringMandu: 0, first: "2026-10-27T00:37:00.000Z", last: "2026-10-27T00:37:00.000Z",
      examples: [{ at: "2026-10-27T00:37:00.000Z", agent: "openclaw", how: "command-output", command: CMD, mandu: "without" }],
    }],
  }), { mode: 0o600 });

  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const gate = await open(sock);
  assert.equal((await gate.setSessionSpec({ sessionKey: SESSION, spec: "openclaw-agent", requestedBy: "session-lineage e2e" })).bound, "openclaw-agent");
  const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
  assert.ok(reg.twin, `the .env is registered with a twin: ${JSON.stringify(reg).slice(0, 200)}`);

  // The scripted model: run the script, then answer.
  const seen: string[] = [];
  let calls = 0;
  const upstream: UpstreamFetcher = async (a) => {
    const m = new MockUpstream({ sse: calls++ === 0 ? buildToolUseSse({ id: "call_sync_1", name: "exec", input: { command: CMD } }) : buildTextSse("The script reads ORDERHUB_PASSWORD; the file has ORDERHUB_PASSPHRASE.") });
    const res = await m.fetcher(a);
    seen.push(m.requests.at(-1)!.bodyText);
    return res;
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), await open(humanSock)), upstream, sessionKey: SESSION, log: () => {} });
  const port = await proxy.listen(0);
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock }), log: () => {}, ...ADMIN_OPTS,
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, configEnv: { MANDU_HOME: manduHome, HOME: home },
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  closers.push(async () => {
    await dashboard.close(); await proxy.close(); wired.close();
    for (const c of clients) c.close();
    await arbiter.close();
  });

  type Msg = { role: string; content: unknown };
  const ask = async (messages: Msg[]) => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 1024, tools: [{ name: "exec", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
  };
  const question: Msg = { role: "user", content: `Our order sync broke. Run it with debug output, ${CMD}, and fix it.` };
  await ask([question]);
  await ask([
    question,
    { role: "assistant", content: [{ type: "tool_use", id: "call_sync_1", name: "exec", input: { command: CMD } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "call_sync_1", content: `sync: url=https://api.orderhub.test user=bakery-shop pass=${VALUE}\nsync: 401 Unauthorized\n` }] },
  ]);

  // The invariant: the model never got the value, only the file's twin.
  assert.equal(seen.length, 2);
  assert.ok(seen.every((b) => !b.includes(VALUE)), "the value never reached the model");
  const token = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.ORDERHUB_PASSPHRASE/.exec(seen[1]!)?.[0];
  assert.ok(token, `the AI got the file's twin: ${seen[1]!.slice(-400)}`);

  // The session page.
  const text = await (await pageFetch(`${base}/api/home/agent?session=${encodeURIComponent(SESSION)}`)).text();
  assert.equal(text.includes(VALUE), false, "the page's data never carries the value");
  const page = JSON.parse(text) as AgentPageVM;
  const card = page.secrets.secrets.find((s) => words(s.what).startsWith("ORDERHUB_PASSPHRASE"));
  assert.ok(card, `a card for the passphrase: ${JSON.stringify(page.secrets.secrets.map((s) => words(s.what)))}`);
  assert.equal(words(card!.what), "ORDERHUB_PASSPHRASE in ~/app/.env", "named by the registered file, never by the command");
  assert.equal(card!.file, "~/app/.env");
  assert.deepEqual(card!.path!.map((n) => n.label), ["Kept in", "How it came in", "The AI got", "Left this computer"]);
  assert.match(words(card!.path![1]!.parts), /^Ran DEBUG=1 sh orders-app\/bin\/sync-orders\.sh, at /);
  assert.match(words(card!.earlier!), /^Without Mandu, OpenClaw gave the AI its real value on .+: DEBUG=1 sh orders-app\/bin\/sync-orders\.sh printed it\./);
  assert.equal(card!.scanItem, "f0", "the line's link opens that finding's row on the Scan page (§4.25ai *Where the real value is now*)");
  const real = page.story.flatMap((t) => t.steps).flatMap((s) => (s.kind === "action" && s.split ? [words(s.split.real)] : []));
  assert.ok(real.includes("The result held your secret ORDERHUB_PASSPHRASE from ~/app/.env."), JSON.stringify(real));

  // The developer view's notes ride the events route.
  const events = await (await pageFetch(`${base}/api/events?session=${encodeURIComponent(SESSION)}`)).text();
  assert.equal(events.includes(VALUE), false, "signed out: no value");
  const notes = (JSON.parse(events) as { flowNotes?: Record<string, { file?: string; earlier?: { text: string }[] }> }).flowNotes ?? {};
  assert.equal(notes[token!]?.file, "~/app/.env");
  assert.match(words(notes[token!]!.earlier!), /^Without Mandu, OpenClaw gave the AI its real value/);
});
