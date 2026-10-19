/**
 * early-read-own-words — a secret the AI read before it was marked: the
 * product's *Your secrets* card says what the real proxy does with the AI's
 * own words (dashboard.md §4.25b, *Your secrets*, "The AI"), across the REAL
 * components: a real ArbiterServer in `secrets`, the real mandu-policy tool
 * (`new PolicyArbiterAdapter(new ArbiterClient(sock))`), the real
 * anthropic-proxy in its production wiring (`new ArbiterClientAdapter(data,
 * human)`) with a scripted model behind it, and the real dashboard over the
 * arbiter's store (`ArbiterEventSource`).
 *
 * The live tour (Claude Code 2.1.289): the AI read deploy/staging.conf as it
 * was, replied quoting it, then locked it with Mandu's policy tool. Later
 * requests carry the earlier Read masked, but the AI's own reply goes on as
 * written (confidentiality.md §7.1, the residual). The card said "From 10:42
 * on it got only a placeholder": an over-claim. Replayed:
 *
 *   L1  request 1 carries the Read raw (no rule covers the file); the model
 *       answers quoting it;
 *   L2  the policy tool locks the file; request 2 re-sends the history: the
 *       Read is a symbol now, and the AI's reply quoting the file is
 *       forwarded as written (the fact the card states);
 *   L3  the REAL dashboard over the arbiter's store: the file's card says
 *       the AI read its real value before it was marked, then "got a
 *       placeholder in its place, in N requests" (never "only a
 *       placeholder"), then "Anything the AI wrote from its real value went
 *       back to the AI as written with each later request: Mandu does not
 *       mask the AI's own words."; its level tag is not drawn as held
 *       (`saw` "early", §4.25b "The tag agrees with the card") and says
 *       since when, the card's own "From … on" moment (`since`); no token
 *       on the page, and the file's bytes only in the AI's own reply,
 *       quoted as it wrote it;
 *   L4  the inspector's short counts over the same store (dashboard.md
 *       §4.33): the session row (`/api/sessions`) and the header
 *       (`/api/events`) count the Read the AI got as it was as `early`
 *       ("read before marked"), never as `masked`, and agree.
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
import { PolicyArbiterAdapter } from "../../interceptors/policy-mcp/src/arbiter-client.js";
import { handleRpc } from "../../interceptors/policy-mcp/src/mcp-server.js";
import { envDeps } from "../../interceptors/policy-mcp/src/server-main.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const TOKEN = "ghp_FakeEarlyRead5Kq2Lm8Nw3Zx7Vb1Hd4";
const FILE = `[staging]\nhost = "staging.early.example"\ntoken = "${TOKEN}"\n`;
const FILE_PIECES = [TOKEN, "ghp_FakeEarly", "staging.early.example"];
/** Claude Code's Read rendering of FILE. */
const READ_RENDER = FILE.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";
const DEDUP = "Wasted call — file unchanged since your last Read. Refer to that earlier tool_result instead.";
const SYM_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]$/;
const OWN_WORDS = "Anything the AI wrote from its real value went back to the AI as written with each later request: Mandu does not mask the AI's own words.";

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const words = (parts: { kind: string; text: string }[]) => parts.map((p) => (p.kind === "time" ? "<t>" : p.text)).join("");

test("a file the AI read before it was marked: the real proxy forwards the AI's reply quoting it as written, and the real session page's card says the AI's own words are not masked, never \"only a placeholder\" (secrets axes, explicit)", async () => {
  const session = `early-read-own-words-${process.pid}`;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-early-read-"));
  dirs.push(tmp);
  const ws = join(tmp, "mandu-try");
  mkdirSync(join(ws, "deploy"), { recursive: true });
  const path = join(ws, "deploy", "staging.conf");
  writeFileSync(path, FILE);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${join(tmp, "other.key")}\n    level: no-model\n`);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    policyPath, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const policyClient = await open(sock);

  // The scripted model, one answer per request, as the tour went: the Read,
  // the reply quoting the file, the policy call, the second Read, the last
  // reply.
  const reply = `\`deploy/staging.conf\` has three lines:\n\n\`\`\`\n${FILE}\`\`\`\n\nThe token is a GitHub personal access token and nothing protects it. Want me to lock it?`;
  const answers = [
    buildToolUseSse({ id: "toolu_read1", name: "Read", input: { file_path: path } }),
    buildTextSse(reply),
    buildToolUseSse({ id: "toolu_pol", name: "mcp__mandu-policy__mandu_policy_propose", input: { edits: [{ op: "lock-path", path: "deploy/staging.conf", level: "no-model" }] } }),
    buildToolUseSse({ id: "toolu_read2", name: "Read", input: { file_path: path } }),
    buildTextSse("Both reads now show a placeholder."),
  ].map((sse) => new MockUpstream({ sse }));
  const sent: { bodyText: string; json: () => unknown }[] = [];
  const upstream: UpstreamFetcher = async (a) => {
    const m = answers[Math.min(sent.length, answers.length - 1)]!;
    const res = await m.fetcher(a);
    sent.push(m.requests.at(-1)!);
    return res;
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), await open(humanSock)), upstream, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock }), log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;

  type Msg = { role: string; content: unknown };
  const send = async (messages: Msg[]): Promise<{ text: string; json: { messages: Msg[] } }> => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 256, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
    const last = sent.at(-1)!;
    return { text: last.bodyText, json: last.json() as { messages: Msg[] } };
  };
  const resultOf = (json: { messages: Msg[] }, id: string): string => {
    for (const m of json.messages) {
      if (!Array.isArray(m.content)) continue;
      for (const b of m.content as Array<{ type: string; tool_use_id?: string; content?: unknown }>) {
        if (b.type === "tool_result" && b.tool_use_id === id) return typeof b.content === "string" ? b.content : (b.content as Array<{ text: string }>).map((x) => x.text).join("");
      }
    }
    throw new Error(`no tool_result ${id}`);
  };

  try {
    // ── L1: nothing labels the file; the Read goes raw, the AI quotes it ────
    const ask: Msg[] = [{ role: "user", content: "What is in deploy/staging.conf?" }];
    await send(ask);
    const turn1: Msg[] = [
      ...ask,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_read1", name: "Read", input: { file_path: path } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_read1", content: READ_RENDER }] },
    ];
    const r1 = await send(turn1);
    assert.equal(resultOf(r1.json, "toolu_read1"), READ_RENDER, "unlabelled: the Read reaches the model as read");

    // ── L2: the policy tool locks it; the history goes masked, the AI's reply as written ──
    const lockAsk: Msg[] = [
      ...turn1,
      { role: "assistant", content: [{ type: "text", text: reply }] },
      { role: "user", content: "Use Mandu's policy tools to mark deploy/staging.conf as a secret hidden from you. Then read it again and tell me what you see." },
    ];
    await send(lockAsk);
    const deps = { arbiter: new PolicyArbiterAdapter(policyClient), ...envDeps({ MANDU_SCOPE_ID: session, MANDU_PROJECT_DIR: ws }) };
    const rpc = await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "mandu_policy_propose", arguments: { edits: [{ op: "lock-path", path: "deploy/staging.conf", level: "no-model" }], reason: "the user asked" } } }, deps);
    const policyText = (rpc!.result as { content: Array<{ text: string }> }).content[0]!.text;
    assert.equal((JSON.parse(policyText) as { applied?: boolean }).applied, true, `the tightening applies at once: ${policyText}`);
    const turn2: Msg[] = [
      ...lockAsk,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_pol", name: "mcp__mandu-policy__mandu_policy_propose", input: { edits: [{ op: "lock-path", path: "deploy/staging.conf", level: "no-model" }] } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_pol", content: policyText }] },
    ];
    const r2 = await send(turn2);
    assert.match(resultOf(r2.json, "toolu_read1").split("\n\n")[0]!, SYM_RE, "the earlier Read is masked now");
    const replyFwd = (r2.json.messages[3]!.content as Array<{ type: string; text: string }>)[0]!;
    assert.equal(replyFwd.text, reply, "the AI's own reply, quoting the file, is forwarded as written");
    const turn3: Msg[] = [
      ...turn2,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_read2", name: "Read", input: { file_path: path } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_read2", content: DEDUP }] },
    ];
    const r3 = await send(turn3);
    // The second Read is Claude Code's dedup notice: no file byte, so it
    // reaches the model as itself (confidentiality.md §7.1, "The Read dedup
    // notice"), never a symbol the AI could quote as the file.
    assert.equal(resultOf(r3.json, "toolu_read2"), DEDUP, "the second Read's dedup notice goes as written");
    assert.equal((r3.json.messages[3]!.content as Array<{ type: string; text: string }>)[0]!.text, reply, "…and the reply still goes as written");

    // ── L3: the real session page's card says what the proxy did ───────────
    const fileCard = (p: AgentPageVM | undefined) => p?.secrets?.secrets.find((s) => s.what.some((x) => x.text.endsWith("deploy/staging.conf")));
    let page: AgentPageVM | undefined;
    for (let i = 0; i < 100; i++) {
      // emission is best-effort and asynchronous
      const r = await fetch(`${base}/api/home/agent?session=${session}`);
      if (r.status === 200) {
        page = (await r.json()) as AgentPageVM;
        if (fileCard(page)?.lines.some((l) => /own words/.test(words(l.parts)))) break;
      }
      await new Promise((r) => setTimeout(r, 20));
    }
    const card = fileCard(page);
    assert.ok(card, `Your secrets lists the file: ${JSON.stringify(page?.secrets)}`);
    const lines = card.lines.map((l) => `${l.tone}: ${words(l.parts)}`);
    assert.match(lines[0]!, /^warn: The AI read its real value at <t>, before it was marked a secret\. From <t> on it got a placeholder in its place, in \d+ requests?\.$/, lines.join("\n"));
    assert.equal(lines[1], `warn: ${OWN_WORDS}`, lines.join("\n"));
    assert.ok(!lines.some((l) => /only a placeholder|never the real value/.test(l)), lines.join("\n"));
    assert.deepEqual(page!.secrets!.counts, { masked: 0, early: 1 }, "the tile counts it as read before it was marked");
    // The tag agrees with the card: read before its label, since the card's
    // own "From … on" moment (the first request that carried it masked).
    const from = card.lines[0]!.parts.filter((x) => x.kind === "time").map((x) => x.text);
    assert.equal(card.saw, "early", "the tag is coloured as the line under it");
    assert.equal(from.length, 2, lines[0]);
    assert.equal(card.since, from[1], "since the card's own \"From … on\" moment");
    assert.ok(!JSON.stringify(page).includes("$MDU:"), "no token on the product page");
    // The file's bytes are on the page only where the AI wrote them: its own
    // reply, quoted as it wrote it (§4.25b). Never on the card, never in a
    // step's result.
    const at: string[] = [];
    const walk = (v: unknown, where: string): void => {
      if (typeof v === "string") { if (FILE_PIECES.some((x) => v.includes(x))) at.push(where); }
      else if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${where}[${i}]`));
      else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) walk(x, `${where}.${k}`);
    };
    walk(page, "page");
    assert.ok(at.length > 0 && at.every((w) => /^page\.story\[\d+\]\.reply\./.test(w)), `file bytes only in the AI's own reply: ${JSON.stringify(at)}`);
    assert.ok(!FILE_PIECES.some((x) => JSON.stringify(page!.secrets).includes(x)), "none on Your secrets");

    // ── L4: the inspector's row and header never count it as masked ────────
    const head = (await (await fetch(`${base}/api/events?session=${session}`)).json()) as { counts?: Record<string, number> };
    assert.equal(head.counts?.early, 1, `the first Read is read before marked: ${JSON.stringify(head.counts)}`);
    assert.equal(head.counts?.masked ?? 0, 0, `the second Read is the dedup notice, forwarded as written: nothing is masked from the start: ${JSON.stringify(head.counts)}`);
    const rows: unknown[] = [];
    const walkRows = (v: unknown): void => {
      if (Array.isArray(v)) v.forEach(walkRows);
      else if (v && typeof v === "object") {
        const o = v as { id?: unknown; counts?: unknown };
        if (o.id === session && "counts" in o) rows.push(o.counts);
        Object.values(o).forEach(walkRows);
      }
    };
    walkRows(await (await fetch(`${base}/api/sessions`)).json());
    assert.ok(rows.length >= 1, "the session has a row");
    for (const c of rows) assert.deepEqual(c, head.counts, "the row's chips are the header's counts");
  } finally {
    await dashboard.close();
    await proxy.close();
    for (const c of clients) c.close();
    await arbiter.close();
  }
});
