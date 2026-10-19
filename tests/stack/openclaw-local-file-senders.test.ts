/**
 * openclaw-local-file-senders — the security-invariant oracle for OpenClaw's
 * tools that send a LOCAL FILE's bytes on by naming its path
 * (supported-agents.md §2.1, "Tools that send a local file"; guarantees.md
 * §3), over the REAL components: a real ArbiterServer in `secrets` with its
 * human socket, a registered `.env`, labelled files, and the real
 * AnthropicProxy over its PRODUCTION adapter (`new ArbiterClientAdapter(new
 * ArbiterClient(data), new ArbiterClient(human))`, as server-main.ts builds
 * it), the session bound to OpenClaw's spec, the gate surface from the
 * arbiter's op. No live model: the mock upstream replays the tool calls a
 * model would emit, in the shapes read from OpenClaw's dist
 * (arbiter/test/fixtures/openclaw-local-file-senders-2026-10-17.json).
 *
 * `message` attaches media to a chat channel send; OpenClaw reads each
 * source in its own process and sends the bytes to the channel, so they
 * never enter the model context. Before 2026-10-17 `message.media` was only
 * a read path (the sensitive-path gate, which runs with the view map only)
 * and `attachments[]` was read by nothing: a registered `.env` went to the
 * channel as a file. The oracle is what OpenClaw WOULD send given the input
 * the agent receives (`wouldAttach`: nothing for an `action` outside the
 * tool's enum, else the bytes of every source OpenClaw reads).
 *
 *   M1  a registered `.env` by `media`, by `attachments[].media`, by
 *       `attachments[].path`, by `filePath`, by `mediaUrls` and through the
 *       Tool Search dispatcher is refused whole: no byte of the key in what
 *       OpenClaw would send; each held file is an Approvals row
 *       `fs:message:upload` × path;
 *   M2  a copy of the key under an ordinary name is refused (the value in
 *       the bytes); a file the person labelled no-model, even bound to a
 *       host, is refused (a chat channel is no host a binding can name);
 *   M3  utility: an ordinary file goes out byte for byte;
 *   M4  view_image (to a model): an `any-model` image goes, a `no-model` one
 *       is held (the `toModel` form reaches the arbiter through the
 *       production adapter);
 *   M5  fail-closed: with the arbiter gone nothing is sent;
 *   M6  past the old 8 MiB read limit (2026-10-17, the scan is streamed): a
 *       24 MiB video with no registered value goes; the same bytes with the
 *       key inside are refused and queued.
 * Control: the same message in a Claude Code session (no `message` tool
 * there) is not touched.
 *
 * Axes: `secrets` (confidentiality ON, integrity OFF), stated below.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { REFUSED_ID_PREFIX } from "../../interceptors/anthropic-proxy/src/dispatch.js";
import { SseToolUseParser, type ReconstructedToolUse } from "../../interceptors/anthropic-proxy/src/sse-parser.js";
import { MockUpstream, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const here = dirname(fileURLToPath(import.meta.url));
const SENDERS = JSON.parse(readFileSync(join(here, "..", "..", "arbiter", "test", "fixtures", "openclaw-local-file-senders-2026-10-17.json"), "utf8")) as {
  message: { BASE_ACTION_MEDIA_SOURCE_PARAM_KEYS: string[]; STRUCTURED_ATTACHMENT_MEDIA_SOURCE_PARAM_KEYS: string[]; listParam: string };
};

const KEY = "sk_live_fake_OCMSG_5e2b9d71c4a0f3";
const LABELLED = "Q3 board minutes: acquisition of Example Corp at 41.5M";

/** What OpenClaw would send to the channel for `input`: nothing when the
 *  call's `action` is not a message action (the refusal), else the bytes of
 *  every media source it reads (its own key lists), a relative one in the
 *  workspace. */
function wouldAttach(input: Record<string, unknown>, workspace: string): string[] {
  const a = input["action"];
  if (typeof a !== "string" || a.startsWith(REFUSED_ID_PREFIX)) return [];
  const sources: string[] = [];
  for (const k of SENDERS.message.BASE_ACTION_MEDIA_SOURCE_PARAM_KEYS) if (typeof input[k] === "string") sources.push(input[k] as string);
  for (const v of (input[SENDERS.message.listParam] as unknown[] | undefined) ?? []) if (typeof v === "string") sources.push(v);
  for (const att of (input["attachments"] as Array<Record<string, unknown>> | undefined) ?? []) {
    for (const k of SENDERS.message.STRUCTURED_ATTACHMENT_MEDIA_SOURCE_PARAM_KEYS) {
      if (typeof att[k] === "string") { sources.push(att[k] as string); break; }
    }
  }
  return sources.map((s) => readFileSync(resolve(workspace, s.replace(/^file:\/\//, "")), "utf8"));
}

/** What view_image would load (and send to a model) for `input`. */
function wouldView(input: Record<string, unknown>): string[] {
  const refs = [...(typeof input["path"] === "string" ? [input["path"] as string] : []), ...((input["paths"] as string[] | undefined) ?? [])];
  return refs.map((p) => readFileSync(p, "utf8"));
}

function post(port: number, body: string, session: string): Promise<string> {
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
    req.end(body);
  });
}

function toolUseOf(sse: string): ReconstructedToolUse | null {
  const seen: ReconstructedToolUse[] = [];
  const p = new SseToolUseParser((tu) => seen.push(tu));
  p.feed(sse);
  p.end();
  return seen[0] ?? null;
}

type Approval = { id: string; symbol: string; destination: string; status: string };

async function withStack(
  spec: "openclaw-agent" | "claude-code",
  fn: (h: {
    tmp: string;
    ws: string;
    server: ArbiterServer;
    human: ArbiterClient;
    admin: ArbiterClient;
    session: string;
    reaches: (name: string, input: Record<string, unknown>) => Promise<Record<string, unknown> | null>;
    approvals: () => Approval[];
  }) => Promise<void>,
): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-oc-senders-"));
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
  const session = `oc-senders-${process.pid}-${spec}`;
  const bound = await data.setSessionSpec({ sessionKey: session, spec, requestedBy: "openclaw-local-file-senders e2e" });
  assert.equal(bound.bound, spec);
  let next: { name: string; input: Record<string, unknown> } = { name: "message", input: {} };
  const fetcher: UpstreamFetcher = (args) => new MockUpstream({
    sse: buildToolUseSse({ id: `tu_${Math.random().toString(36).slice(2, 8)}`, name: next.name, input: next.input }),
  }).fetcher(args);
  const proxy = new AnthropicProxy({
    arbiter: new ArbiterClientAdapter(data, human), upstream: fetcher, sessionKey: session, agentCwd: ws, log: () => {},
  });
  const port = await proxy.listen(0);
  try {
    await fn({
      tmp, ws, server, human, admin, session,
      reaches: async (name, input) => {
        next = { name, input };
        const sse = await post(port, JSON.stringify({ model: "claude-sonnet-5", stream: true, messages: [{ role: "user", content: "send the report to the team" }] }), session);
        return (toolUseOf(sse)?.input as Record<string, unknown> | undefined) ?? null;
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

test("OpenClaw message over the real arbiter and proxy: no byte of a secret file goes to a chat channel as an attachment, ordinary files go, a model-bound image follows its level, and a gone arbiter sends nothing", async () => {
  await withStack("openclaw-agent", async ({ ws, server, human, admin, session, reaches, approvals }) => {
    const env = join(ws, ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY}\nDEBUG=1\n`);
    const copy = join(ws, "notes.txt");
    writeFileSync(copy, `staging key for the demo: ${KEY}\n`);
    const minutes = join(ws, "minutes.md");
    writeFileSync(minutes, `${LABELLED}\n`);
    const chart = join(ws, "chart.svg");
    const CHART = "<svg><rect width=\"4\" height=\"2\"/></svg>\n";
    writeFileSync(chart, CHART);
    const shotAny = join(ws, "shot-any.png");
    writeFileSync(shotAny, "PNG any-model bytes\n");
    const shotNo = join(ws, "shot-no.png");
    writeFileSync(shotNo, "PNG no-model bytes\n");

    const reg = await human.registerSecret({ path: env, sessionKey: session });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    await admin.setPathLabel({ path: minutes, confidentiality: "no-model", bindings: ["api.telegram.org", "slack.com"] });
    await admin.setPathLabel({ path: shotAny, confidentiality: "any-model" });
    await admin.setPathLabel({ path: shotNo, confidentiality: "no-model" });

    const send = (extra: Record<string, unknown>): Record<string, unknown> => ({ action: "send", channel: "telegram", to: "@team", message: "the report", ...extra });

    // ── M1 + M2: every way OpenClaw reads a source, and every kind of secret ──
    for (const [label, name, input] of [
      ["media", "message", send({ media: env })],
      ["attachments[].media", "message", send({ attachments: [{ type: "file", media: chart }, { type: "file", media: env }] })],
      ["attachments[].path", "message", send({ attachments: [{ path: ".env", name: "config.txt" }] })],
      ["filePath (sendAttachment)", "message", { action: "sendAttachment", channel: "telegram", to: "@team", filePath: `file://${env}` }],
      ["mediaUrls", "message", send({ mediaUrls: [chart, env] })],
      ["a copy of the key", "message", send({ media: copy })],
      ["a no-model label bound to the channel's host", "message", send({ attachments: [{ type: "file", media: minutes }] })],
    ] as const) {
      const got = await reaches(name, input as Record<string, unknown>);
      assert.ok(got, `${label}: the call reached the agent`);
      const sent = wouldAttach(got, ws).join("\n");
      assert.ok(!sent.includes(KEY), `CONFIDENTIALITY: OpenClaw would attach the key via ${label}`);
      assert.ok(!sent.includes(LABELLED), `CONFIDENTIALITY: OpenClaw would attach the labelled file via ${label}`);
      assert.equal(sent, "", `${label}: the whole call is refused, nothing is sent`);
      assert.match(String(got["action"]), /mandu-upload-gate: upload refused, nothing was sent/, label);
    }
    // through the Tool Search dispatcher too
    const tc = await reaches("tool_call", { id: "message", args: send({ media: env }) });
    assert.ok(tc, "the dispatched call reached the agent");
    assert.deepEqual(Object.keys(tc), ["id"], `dispatched: refused whole, no args: ${JSON.stringify(tc)}`);
    assert.ok(String(tc["id"]).startsWith(REFUSED_ID_PREFIX));
    const held = [...new Set(approvals().filter((a) => a.symbol === "fs:message:upload" && a.status === "pending").map((a) => a.destination))].sort();
    assert.deepEqual(held, [copy, env, minutes].sort(), "one Approvals row per held file");

    // ── M3: utility ──
    const ok = send({ media: chart, attachments: [{ type: "file", media: "chart.svg" }] });
    const okGot = await reaches("message", ok);
    assert.deepEqual(okGot, ok);
    assert.deepEqual(wouldAttach(okGot!, ws), [CHART, CHART]);
    const text = { action: "send", channel: "telegram", to: "@team", message: "done" };
    assert.deepEqual(await reaches("message", text), text);

    // ── M4: a model-bound reference follows its level ──
    const any = { prompt: "what is in it", path: shotAny };
    assert.deepEqual(await reaches("view_image", any), any, "any-model admits the model");
    const no = await reaches("view_image", { prompt: "what is in it", paths: [shotAny, shotNo] });
    assert.ok(no);
    assert.equal(no["path"], undefined);
    assert.equal(no["paths"], undefined, "a no-model image is not loaded into any model");
    assert.match(String(no["action"]), /rule: fs:upload-secret-file/);
    assert.deepEqual(wouldView(no), []);

    // ── M6 (STREAMED, 2026-10-17): past the old 8 MiB read limit ──
    // A 24 MiB video with no registered value goes (it was held, unread);
    // the same bytes with the key 17 MiB in are held: the arbiter scans the
    // file in chunks, never whole, and finds the value across a read.
    const noise = Buffer.alloc(24 * 1024 * 1024);
    let x = 0x2545f491;
    for (let i = 0; i + 4 <= noise.length; i += 4) { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; noise.writeUInt32LE(x >>> 0, i); }
    const video = join(ws, "demo.mp4");
    writeFileSync(video, noise);
    const vid = send({ media: video });
    assert.deepEqual(await reaches("message", vid), vid, "UTILITY: a 24 MiB video with no registered value goes as written");
    const withKey = Buffer.from(noise);
    Buffer.from(KEY).copy(withKey, 17 * 1024 * 1024 - 3);
    const exported = join(ws, "export.pdf");
    writeFileSync(exported, withKey);
    const leak = await reaches("message", send({ media: exported }));
    assert.ok(leak, "the call reached the agent");
    assert.ok(!wouldAttach(leak, ws).join("").includes(KEY), "CONFIDENTIALITY: OpenClaw would attach the key inside a 24 MiB file");
    assert.match(String(leak["action"]), /mandu-upload-gate: upload refused, nothing was sent/);
    assert.ok(approvals().some((a) => a.symbol === "fs:message:upload" && a.destination === exported && a.status === "pending"), "the large file is an Approvals row");

    // ── M5: fail-closed ──
    await server.close();
    const down = await reaches("message", send({ media: chart }));
    assert.ok(down === null || wouldAttach(down, ws).length === 0, "with the arbiter gone nothing is sent");
  });
});

test("control: in a Claude Code session the tables name no `message` tool, and its input is left as written", async () => {
  await withStack("claude-code", async ({ ws, reaches }) => {
    const chart = join(ws, "chart.svg");
    writeFileSync(chart, "<svg/>\n");
    const input = { action: "send", channel: "telegram", to: "@team", message: "x", media: chart };
    // an unmapped tool there: the unmapped upload leg judges the path, a clean file passes
    assert.deepEqual(await reaches("message", input), input);
  });
});
