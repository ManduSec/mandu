/**
 * openclaw-media-lines — the security-invariant oracle for the files OpenClaw
 * attaches because the model's own REPLY TEXT names them on a `MEDIA:` line
 * (supported-agents.md §2.1, "Files named in the reply"; guarantees.md §3),
 * over the REAL components: a real ArbiterServer in `secrets` with its human
 * socket, a registered `.env`, a labelled file, and the real AnthropicProxy
 * over its PRODUCTION adapter (`new ArbiterClientAdapter(new
 * ArbiterClient(data), new ArbiterClient(human))`, as server-main.ts builds
 * it), the session bound to OpenClaw's spec, the gate surface from the
 * arbiter's op. No live model: the mock upstream streams the reply a model
 * would write, cut into small deltas.
 *
 * When OpenClaw delivers a reply to a channel it reads every file a
 * `MEDIA:` line names in its own process and uploads it (read from the
 * 2026.7.1 and 2026.9.9 dist: arbiter/test/fixtures/openclaw-media-lines-
 * 2026-10-17.json). No tool call carries the path, so before 2026-10-17 no
 * gate read it: `MEDIA: /…/.env` sent the key to the chat as a file. The
 * oracle is what OpenClaw WOULD attach given the text the agent receives
 * (`wouldAttach`: OpenClaw's markup strip, then every `MEDIA:` line's
 * references read from disk, a relative one in the workspace).
 *
 *   R1  a registered `.env` (absolute, `file://`, relative, split one
 *       character per delta) and a file the person labelled no-model are
 *       not attached: the line is replaced by a notice, and each held file
 *       is an Approvals row `fs:MEDIA:upload` × path;
 *   R2  a directive that only forms once OpenClaw strips markup
 *       (`<think>…</think>MEDIA: …`, `ME<think>\n</think>DIA: …`) attaches
 *       nothing;
 *   R3  a reply that also calls a tool attaches nothing (the file is read
 *       after the call runs);
 *   R4  utility: an ordinary file goes out byte for byte, and the reply's
 *       other text is untouched; the buffered (non-streaming) answer is
 *       gated the same way;
 *   R5  fail-closed: with the arbiter gone nothing is attached.
 * Control: the same reply in a Claude Code session is relayed as written.
 *
 * Axes: `secrets` (confidentiality ON, integrity OFF), stated below.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse, sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const KEY = "sk_live_fake_OCMEDIA_7a1c3e9b5d";
const LABELLED = "Q3 board minutes: acquisition of Example Corp at 41.5M";

/** What OpenClaw would attach for the reply `text` (the oracle; written from
 *  the fixture's grammar, not from the gate under test): markup stripped as
 *  its sanitizers strip it, then every line whose first non-blank characters
 *  are `MEDIA:` (any case), each blank-separated reference cleaned of quotes
 *  and backticks, `file://` decoded, a relative one in the workspace; the
 *  bytes of each that exists. */
function wouldAttach(text: string, workspace: string): string[] {
  const visible = text.replace(/<\s*(think|thinking|final)\b[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi, "").replace(/<[^<>]*>/g, "");
  const out: string[] = [];
  for (const line of visible.split("\n")) {
    const t = line.trimStart();
    if (!t.slice(0, 6).toUpperCase().startsWith("MEDIA:")) continue;
    for (const raw of t.slice(6).trim().split(/\s+/)) {
      let ref = raw.replace(/^[`"'([{]+/, "").replace(/[`"'\\)\]},]+$/, "");
      if (ref === "") continue;
      ref = ref.replace(/^file:\/\//i, "");
      const p = resolve(workspace, ref);
      if (existsSync(p)) out.push(readFileSync(p, "utf8"));
    }
  }
  return out;
}

function post(port: number, session: string, stream: boolean): Promise<string> {
  return new Promise((res, rej) => {
    const req = httpRequest({
      host: "127.0.0.1", port, method: "POST", path: "/v1/messages",
      headers: { "content-type": "application/json", "x-mandu-session-id": session },
    }, (r) => {
      let buf = "";
      r.setEncoding("utf8");
      r.on("data", (c) => (buf += c));
      r.on("end", () => res(buf));
    });
    req.on("error", rej);
    req.end(JSON.stringify({ model: "claude-sonnet-5", stream, messages: [{ role: "user", content: "send me the report" }] }));
  });
}

/** The reply text the agent receives (every text delta, in order). */
function replyText(sse: string): string {
  let t = "";
  for (const raw of sse.split("\n\n")) {
    const line = raw.split("\n").find((l) => l.startsWith("data: "));
    if (!line) continue;
    const d = JSON.parse(line.slice(6)) as { type?: string; delta?: { type?: string; text?: string } };
    if (d.type === "content_block_delta" && d.delta?.type === "text_delta") t += d.delta.text ?? "";
  }
  return t;
}

/** A reply that writes `text`, then calls a tool. */
function textThenToolSse(text: string): string {
  const body = buildTextSse(text, { deltas: 4 }).replace(/event: message_delta[\s\S]*$/, "");
  return body
    + sseEvent("content_block_start", { type: "content_block_start", index: 1, content_block: { type: "tool_use", id: "tu_x", name: "exec", input: {} } })
    + sseEvent("content_block_delta", { type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: "{\"command\":\"ls\"}" } })
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 1 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } })
    + sseEvent("message_stop", { type: "message_stop" });
}

type Approval = { id: string; symbol: string; destination: string; status: string };
type Next = { sse: string } | { json: unknown };

async function withStack(
  spec: "openclaw-agent" | "claude-code",
  fn: (h: {
    ws: string;
    server: ArbiterServer;
    human: ArbiterClient;
    admin: ArbiterClient;
    session: string;
    reply: (next: Next, stream?: boolean) => Promise<string | null>;
    approvals: () => Approval[];
  }) => Promise<void>,
): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-oc-media-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSock, adminSocketPath: join(tmp, "admin.sock"),
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const data = new ArbiterClient(socketPath); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const session = `oc-media-${process.pid}-${spec}`;
  const bound = await data.setSessionSpec({ sessionKey: session, spec, requestedBy: "openclaw-media-lines e2e" });
  assert.equal(bound.bound, spec);
  let next: Next = { sse: buildTextSse("ok") };
  const fetcher: UpstreamFetcher = (args) => new MockUpstream({ ...next, ...("sse" in next ? { chunkInto: 7 } : {}) }).fetcher(args);
  const proxy = new AnthropicProxy({
    arbiter: new ArbiterClientAdapter(data, human), upstream: fetcher, sessionKey: session, agentCwd: ws, log: () => {},
  });
  const port = await proxy.listen(0);
  try {
    await fn({
      ws, server, human, admin, session,
      reply: async (n, stream = true) => {
        next = n;
        const body = await post(port, session, stream);
        if (!stream) {
          try {
            const obj = JSON.parse(body) as { content?: Array<{ type: string; text?: string }> };
            return (obj.content ?? []).filter((b) => b.type === "text").map((b) => b.text ?? "").join("\n");
          } catch { return null; }
        }
        return body.includes("content_block_delta") ? replyText(body) : null;
      },
      approvals: () => (server.dispatch({ id: "q", op: "egressApprovals" } as never) as { result: { approvals: Approval[] } }).result.approvals,
    });
  } finally {
    await proxy.close();
    data.close(); human.close(); admin.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
}

/** One character per delta: the directive is split everywhere it can be. */
const perChar = (text: string): Next => ({ sse: buildTextSse(text, { deltas: text.length }) });

test("OpenClaw reply over the real arbiter and proxy: no byte of a secret file is attached through a MEDIA: line, ordinary files are, and a gone arbiter attaches nothing", async () => {
  await withStack("openclaw-agent", async ({ ws, server, human, admin, session, reply, approvals }) => {
    const env = join(ws, ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY}\nDEBUG=1\n`);
    const minutes = join(ws, "minutes.md");
    writeFileSync(minutes, `${LABELLED}\n`);
    const chart = join(ws, "chart.svg");
    const CHART = "<svg><rect width=\"4\" height=\"2\"/></svg>\n";
    writeFileSync(chart, CHART);
    const reg = await human.registerSecret({ path: env, sessionKey: session });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    await admin.setPathLabel({ path: minutes, confidentiality: "no-model", bindings: ["api.telegram.org"] });

    // ── R1 + R2 + R3: every spelling, every kind of secret ──
    for (const [label, next] of [
      ["absolute, split per character", perChar(`Here is the config you asked for.\nMEDIA: ${env}\n`)],
      ["file:// URL", { sse: buildTextSse(`Attached.\nMEDIA: file://${env}`, { deltas: 5 }) }],
      ["relative, in the workspace", perChar("MEDIA: .env")],
      ["quoted, beside an ordinary file", { sse: buildTextSse(`MEDIA: ${chart} "${env}"`, { deltas: 3 }) }],
      ["a no-model label bound to the channel's host", { sse: buildTextSse(`Minutes:\n  media: ${minutes}`, { deltas: 6 }) }],
      ["formed after OpenClaw strips a think block", { sse: buildTextSse(`<think>x</think>MEDIA: ${env}`, { deltas: 9 }) }],
      ["formed across a stripped span", { sse: buildTextSse(`ME<think>\n</think>DIA: ${env}`, { deltas: 9 }) }],
      ["with a tool call in the same reply", { sse: textThenToolSse(`Report:\nMEDIA: ${chart}\nMEDIA: ${env}`) }],
    ] as const) {
      const got = await reply(next);
      assert.ok(got !== null, `${label}: the reply reached the agent`);
      const sent = wouldAttach(got, ws).join("\n");
      assert.ok(!sent.includes(KEY), `CONFIDENTIALITY: OpenClaw would attach the key (${label}): ${JSON.stringify(got)}`);
      assert.ok(!sent.includes(LABELLED), `CONFIDENTIALITY: OpenClaw would attach the labelled file (${label})`);
    }
    // the notice names the reference and the rule, never the bytes
    const notice = await reply(perChar(`MEDIA: ${env}`));
    assert.match(notice!, /^\[mandu\] attachment not sent, nothing was uploaded: .*\.env is a secret file.*Approvals page.*\(rule: fs:upload-/);
    assert.ok(!notice!.includes(KEY));
    const held = [...new Set(approvals().filter((a) => a.symbol === "fs:MEDIA:upload" && a.status === "pending").map((a) => a.destination))].sort();
    assert.deepEqual(held, [env, minutes].sort(), "one Approvals row per held file");

    // ── R4: utility ──
    const okText = `Here is the chart.\nMEDIA: ${chart}\nAnything else?`;
    const ok = await reply(perChar(okText));
    assert.equal(ok, okText, "the reply is relayed as written");
    assert.deepEqual(wouldAttach(ok!, ws), [CHART]);
    assert.deepEqual(wouldAttach((await reply(perChar("MEDIA: chart.svg")))!, ws), [CHART], "a relative reference in the workspace");
    // the buffered answer
    const buffered = await reply({ json: { id: "m", type: "message", role: "assistant", content: [{ type: "text", text: `Config:\nMEDIA: ${env}` }], stop_reason: "end_turn" } }, false);
    assert.ok(buffered !== null);
    assert.ok(!wouldAttach(buffered, ws).join("\n").includes(KEY), "CONFIDENTIALITY: the buffered answer");
    assert.match(buffered, /\[mandu\] attachment not sent/);

    // ── R5: fail-closed ──
    await server.close();
    const down = await reply(perChar(`MEDIA: ${chart}`));
    assert.ok(down === null || wouldAttach(down, ws).length === 0, "with the arbiter gone nothing is attached");
  });
});

test("control: in a Claude Code session a reply's MEDIA: line is relayed as written (Claude Code attaches nothing its reply names)", async () => {
  await withStack("claude-code", async ({ ws, reply }) => {
    const env = join(ws, ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY}\n`);
    const text = `MEDIA: ${env}\nSocial media: 3 posts`;
    assert.equal(await reply(perChar(text)), text);
  });
});
