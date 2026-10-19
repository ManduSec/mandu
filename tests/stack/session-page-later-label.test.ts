/**
 * session-page-later-label — a session that read files as they were, ended,
 * and only then saw them marked secret: the product's session page and Home
 * learn of the labels from the rule-change log and the Rules page's own
 * record (dashboard.md §4.25b, *Labelled after the session*), across the
 * REAL components: a real ArbiterServer in `secrets`, the real
 * anthropic-proxy in its production wiring (`new ArbiterClientAdapter(data,
 * human)`) with a scripted model behind it, and the real dashboard over the
 * arbiter's store with the PRODUCTION surfaces (`makeApprovalsArbiter`: the
 * secrets surface's `pathLevels` and `confidentialityState`, the policy
 * surface's `policyChanges`).
 *
 * The first-session tour, step 3, exited before the rule: the AI read
 * deploy/staging.conf as it was, the session ended, then the file was
 * marked a secret. The ended session's page showed that read as a plain one
 * ("Nothing here needed guarding.") though the AI got what is now a secret.
 *
 *   L1  the session reads deploy/staging.conf and notes.txt; each reaches
 *       the model as read (nothing labels them), the AI answers, the session
 *       sends nothing more;
 *   L2  before any label: the page and Home say nothing of either file;
 *   L3  staging.conf is marked through the rule-change log (a tightening the
 *       arbiter applies at once and records), notes.txt on the Rules page
 *       (the admin channel's `setPathLabel`);
 *   L4  the same ended session's page: each Read says the AI got it as it
 *       was and when it was marked; *Your secrets* tells both files with no
 *       placeholder ("Show the real value" absent), the read and the label
 *       times, never "never the real value"; the tiles count both as read
 *       before they were marked; no token and no file byte on the page;
 *   L5  Home's row for the session (its facts cached while the listing has
 *       not moved) and the hero count both, the same as the page's tiles.
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
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const TOKEN = "ghp_FakeLaterLabel7Qm2Xw9Kd4Rt6Zp1Vn";
const CONF = `[staging]\nhost = "staging.later.example"\ntoken = "${TOKEN}"\n`;
const NOTES = "remember: the vault passphrase is LaterLabelNotes-4417\n";
const BYTES = [TOKEN, "staging.later.example", "LaterLabelNotes-4417"];
const render = (s: string) => s.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const words = (parts: { kind: string; text: string }[]) => parts.map((p) => (p.kind === "time" ? "<t>" : p.text)).join("");

test("a session that ended before its files were marked secret: its page and Home learn of the labels from the rule-change log and the Rules page, with no placeholder and never \"never the real value\" (secrets axes, explicit)", async () => {
  const session = `later-label-${process.pid}`;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-later-label-"));
  dirs.push(tmp);
  const ws = join(tmp, "mandu-try");
  mkdirSync(join(ws, "deploy"), { recursive: true });
  const conf = join(ws, "deploy", "staging.conf");
  const notes = join(ws, "notes.txt");
  writeFileSync(conf, CONF);
  writeFileSync(notes, NOTES);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${join(tmp, "other.key")}\n    level: no-model\n`);
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    policyPath, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const agentClient = await open(sock);

  const answers = [
    buildToolUseSse({ id: "toolu_conf", name: "Read", input: { file_path: conf } }),
    buildToolUseSse({ id: "toolu_notes", name: "Read", input: { file_path: notes } }),
    buildTextSse("staging.conf holds a GitHub token, and notes.txt a passphrase."),
  ].map((sse) => new MockUpstream({ sse }));
  const sent: { bodyText: string }[] = [];
  const upstream: UpstreamFetcher = async (a) => {
    const m = answers[Math.min(sent.length, answers.length - 1)]!;
    const res = await m.fetcher(a);
    sent.push(m.requests.at(-1)!);
    return res;
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), await open(humanSock)), upstream, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  // The production surfaces, as server-main wires them.
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets?.pathLevels && wired.policyDoc?.policyChanges, "the production wiring offers the three reads");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock }), log: () => {},
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;

  type Msg = { role: string; content: unknown };
  const send = async (messages: Msg[]): Promise<string> => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 256, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
    return sent.at(-1)!.bodyText;
  };
  const getPage = async (): Promise<AgentPageVM> => {
    const r = await fetch(`${base}/api/home/agent?session=${session}`);
    assert.equal(r.status, 200);
    return (await r.json()) as AgentPageVM;
  };
  const getHome = async (): Promise<HomeVM> => (await (await fetch(`${base}/api/home`)).json()) as HomeVM;
  const readSteps = (p: AgentPageVM) => p.story.flatMap((t) => t.steps).filter((s) => s.kind === "action" && s.icon === "file");

  try {
    // ── L1: the session reads both files as they are, answers, and ends ────
    const ask: Msg[] = [{ role: "user", content: "What is in deploy/staging.conf and notes.txt?" }];
    await send(ask);
    const t1: Msg[] = [
      ...ask,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_conf", name: "Read", input: { file_path: conf } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_conf", content: render(CONF) }] },
    ];
    assert.ok((await send(t1)).includes(TOKEN), "unlabelled: the Read reaches the model as read");
    const t2: Msg[] = [
      ...t1,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_notes", name: "Read", input: { file_path: notes } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_notes", content: render(NOTES) }] },
    ];
    assert.ok((await send(t2)).includes("LaterLabelNotes-4417"));

    // ── L2: before any label, the page and Home say nothing of them ────────
    let page: AgentPageVM | undefined;
    for (let i = 0; i < 100; i++) {
      // emission is best-effort and asynchronous
      page = await getPage();
      if (readSteps(page).length === 2) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(readSteps(page!).length, 2, JSON.stringify(page!.story.map((t) => t.summary)));
    assert.deepEqual(readSteps(page!).map((s) => s.kind === "action" && s.outcome), ["plain", "plain"]);
    assert.equal(page!.secrets.secrets.length, 0);
    const row0 = (await getHome()).agents.find((a) => a.id === session);
    assert.ok(row0, "the session is a Home row");
    assert.deepEqual(row0.secrets, { masked: 0, early: 0 });
    await new Promise((r) => setTimeout(r, 20)); // the labels come strictly after the reads

    // ── L3: staging.conf through the rule-change log, notes.txt on the Rules page ──
    const locked = await agentClient.policyPropose({ edits: [{ op: "lock-path", path: conf, level: "no-model" }], sessionKey: "another-session" });
    assert.ok("applied" in locked && locked.applied, `the tightening applies at once: ${JSON.stringify(locked)}`);
    assert.equal((await wired.policyDoc!.policyChanges!(5)).changes.length, 1, "and is recorded");
    await wired.secrets!.setPathLabel({ path: notes, confidentiality: "no-model" });

    // ── L4: the same ended session's page ──────────────────────────────────
    page = await getPage();
    const steps = readSteps(page);
    for (const s of steps) {
      assert.ok(s.kind === "action");
      assert.equal(s.outcome, "raw", "the AI got it as it was");
      assert.equal(s.note, "The AI got this as it was: nothing marked it a secret when it read it.");
      assert.equal(words(s.later!), "Marked a secret at <t>, after this read: the AI saw its real value.");
    }
    assert.match(page.story.map((t) => t.summary ?? "").join("\n"), /The AI read your secrets? .*as (it was|they were): .*marked secret only later\./);
    const cards = page.secrets.secrets;
    assert.deepEqual(cards.map((c) => words(c.what)).sort(), [`The file ${conf}`, `The file ${notes}`].sort());
    for (const c of cards) {
      assert.equal(c.saw, "early");
      assert.equal(c.ref, undefined, "no placeholder: no Show the real value");
      assert.ok(c.since, "the tag says since when it is marked");
      assert.deepEqual(c.lines.map((l) => words(l.parts)), [
        "The AI read its real value at <t>, before it was marked a secret at <t>, so nothing in this session masked it.",
        "If it holds a key or a password, change it: the AI saw it as it was.",
      ]);
    }
    assert.deepEqual(page.secrets.counts, { masked: 0, early: 2 });
    const body = JSON.stringify(page);
    assert.doesNotMatch(body, /never the real value|Nothing here needed guarding|\$MDU:/);
    for (const b of BYTES) assert.ok(!body.includes(b), `no file byte on the page: ${b}`);

    // ── L5: Home's row and hero, though the session's listing never moved ──
    const home = await getHome();
    const row = home.agents.find((a) => a.id === session)!;
    assert.deepEqual(row.secrets, page.secrets.counts, "the row counts as its page's tiles");
    assert.ok(home.window.secretsEarly >= 2, "the hero adds the row up");
  } finally {
    await proxy.close();
    await dashboard.close();
    wired?.close();
    for (const c of clients) c.close();
    await arbiter.close();
  }
});
