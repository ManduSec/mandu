/**
 * unmapped-upload — the security-invariant oracle for the upload-tool
 * residuals closed 2026-10-17 (guarantees.md §3, "A tool that uploads a
 * local file by its path"; supported-agents.md §2), over the REAL
 * components: a real ArbiterServer in `secrets` with its human and admin
 * sockets, a registered `.env`, and the real AnthropicProxy over its
 * PRODUCTION adapter (`new ArbiterClientAdapter(new ArbiterClient(data), new
 * ArbiterClient(human))`, as server-main.ts builds it), the gate surface
 * from the arbiter's op.
 *
 * The oracle is what each tool WOULD send given the input the agent
 * receives (`wouldSend`: every string of the call, and the bytes of every
 * local file a path in it names, read when the tool would read it).
 *
 *   U1  an MCP server's upload tool Mandu has never mapped, naming the
 *       registered `.env`, a copy of its key or a symlink to it, sends no
 *       byte of the key: each such path names no file when the agent gets
 *       the call, and each is an Approvals row (before 2026-10-17 the call
 *       reached the agent unchanged and the key left);
 *   U2  utility: a clean file and a remote API's path go unchanged, and a
 *       built-in the spec maps is not asked about;
 *   U3  the window: a Bash that copies the key into a fresh file, then the
 *       unmapped upload of that file, in ONE model turn: the upload's path is
 *       withheld, so after the copy runs the key still does not leave; the
 *       same for a mapped upload (Artifact) after a Bash;
 *   U4  the host: a page labelled secret and bound to `claude.ai` only is
 *       held from Artifact, whose bytes go to `api.anthropic.com` (before,
 *       the claude.ai binding released it there); bound to both, it goes;
 *   U5  fail-closed: with the arbiter gone every path is withheld.
 *
 * Axes: `secrets` (confidentiality ON, integrity OFF), stated below.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { SseToolUseParser, type ReconstructedToolUse } from "../../interceptors/anthropic-proxy/src/sse-parser.js";
import { MockUpstream, sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const KEY = "sk_live_fake_UNMAPPED_7c19e2a4b5d6";

/** Every string in a value. */
function strings(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const e of v) strings(e, out);
  else if (v && typeof v === "object") for (const e of Object.values(v)) strings(e, out);
  return out;
}

/** What a tool that uploads every local file its input names would send:
 *  the call's text and the bytes of each existing regular file at an
 *  absolute path string (read now: when the tool reads it). */
function wouldSend(input: unknown): string {
  const out = [JSON.stringify(input)];
  for (const s of strings(input)) {
    if (!s.startsWith("/")) continue;
    try { if (statSync(s).isFile()) out.push(readFileSync(s, "utf8")); } catch { /* names no file */ }
  }
  return out.join("\n");
}

/** One assistant message with several tool_use blocks, in order. */
function callsSse(calls: Array<{ name: string; input: Record<string, unknown> }>): string {
  let out = sseEvent("message_start", { type: "message_start", message: { id: "msg_u", role: "assistant", content: [] } });
  calls.forEach((c, index) => {
    const id = `tu_${index}_${Math.random().toString(36).slice(2, 8)}`;
    out += sseEvent("content_block_start", { type: "content_block_start", index, content_block: { type: "tool_use", id, name: c.name, input: {} } });
    out += sseEvent("content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: JSON.stringify(c.input) } });
    out += sseEvent("content_block_stop", { type: "content_block_stop", index });
  });
  out += sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } });
  out += sseEvent("message_stop", { type: "message_stop" });
  return out;
}

function post(port: number, body: string): Promise<string> {
  return new Promise((res, rej) => {
    const req = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } }, (r) => {
      let buf = "";
      r.setEncoding("utf8");
      r.on("data", (c) => (buf += c));
      r.on("end", () => res(buf));
    });
    req.on("error", rej);
    req.end(body);
  });
}

function toolUsesOf(sse: string): ReconstructedToolUse[] {
  const seen: ReconstructedToolUse[] = [];
  const p = new SseToolUseParser((tu) => seen.push(tu));
  p.feed(sse);
  p.end();
  return seen;
}

type Approval = { id: string; symbol: string; destination: string; status: string };

test("upload tools Mandu has not mapped, the check-to-upload window and the observed upload host, over the real arbiter and proxy: no byte of a registered key leaves", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-unmapped-upload-"));
  const app = join(tmp, "ws", "app");
  mkdirSync(join(app, "site"), { recursive: true });
  const env = join(app, ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY}\nDEBUG=1\n`);
  const notes = join(app, "notes.txt");
  writeFileSync(notes, `staging key for the demo: ${KEY}\n`);
  const link = join(app, "site", "theme.css");
  symlinkSync(env, link);
  const report = join(app, "site", "report.html");
  const REPORT = "<!doctype html><title>Q3</title><h1>Totals</h1>\n";
  writeFileSync(report, REPORT);
  const page = join(app, "site", "board.html");
  writeFileSync(page, "<h1>Board pack (confidential)</h1>\n");

  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const adminSock = join(tmp, "admin.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSock, adminSocketPath: adminSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const data = new ArbiterClient(socketPath); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const admin = new ArbiterClient(adminSock); await admin.connect();
  const session = `unmapped-upload-${process.pid}`;

  let next: Array<{ name: string; input: Record<string, unknown> }> = [];
  const fetcher: UpstreamFetcher = (args) => new MockUpstream({ sse: callsSse(next) }).fetcher(args);
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream: fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  /** The inputs the agent receives for one model turn. */
  const turn = async (calls: Array<{ name: string; input: Record<string, unknown> }>): Promise<Array<Record<string, unknown>>> => {
    next = calls;
    const sse = await post(port, JSON.stringify({ model: "claude-sonnet-5", stream: true, messages: [{ role: "user", content: "share the Q3 files" }] }));
    return toolUsesOf(sse).map((t) => t.input as Record<string, unknown>);
  };
  const approvals = (): Approval[] =>
    (server.dispatch({ id: "q", op: "egressApprovals" } as never) as { result: { approvals: Approval[] } }).result.approvals;

  try {
    const reg = await human.registerSecret({ path: env, sessionKey: session });
    assert.match(String(reg.symbol), /^\$MDU:nomodel_Read\[/, JSON.stringify(reg));

    // ── U1: an unmapped MCP upload tool: the file, a copy of its key, a symlink ──
    const UP = "mcp__drive__upload_file";
    for (const path of [env, notes, link]) {
      const call = { path, name: "q3.txt", folder: "Shared" };
      const [got] = await turn([{ name: UP, input: call }]);
      assert.ok(got, "the call reached the agent");
      const sent = wouldSend(got);
      assert.ok(!sent.includes(KEY), `CONFIDENTIALITY: ${UP} would upload the key (${path})`);
      assert.equal(got["path"], `/mandu/denied/upload${path}`, "the path names no file");
      assert.equal(got["name"], "q3.txt", "the rest of the call is the model's");
    }
    const chrome = "mcp__claude-in-chrome__file_upload";
    const [att] = await turn([{ name: chrome, input: { paths: [report, notes], ref: "input#file" } }]);
    assert.ok(!wouldSend(att).includes(KEY), `CONFIDENTIALITY: ${chrome} would attach the key`);
    assert.deepEqual(att!["paths"], [report, `/mandu/denied/upload${notes}`], "the clean report stays, the copy is withheld");
    const held = approvals().filter((a) => a.symbol === `fs:${UP}:upload` && a.status === "pending").map((a) => a.destination).sort();
    assert.deepEqual(held, [env, notes, link].sort(), "one Approvals row per held path");

    // ── U2: utility ──
    const clean = { path: report, name: "q3.html" };
    assert.deepEqual((await turn([{ name: UP, input: clean }]))[0], clean);
    const remote = { endpoint: "/v1/items", body: "{\"q\":3}" };
    assert.deepEqual((await turn([{ name: "mcp__crm__post", input: remote }]))[0], remote);
    assert.ok(wouldSend(clean).includes(REPORT), "the report goes out");

    // ── U3: the window, one turn: a Bash copies the key, then the upload ──
    const fresh = join(app, "site", "summary.txt");
    const [, up] = await turn([
      { name: "Bash", input: { command: `cp ${notes} ${fresh}` } },
      { name: UP, input: { path: fresh, name: "summary.txt" } },
    ]);
    assert.equal(up!["path"], `/mandu/denied/upload${fresh}`, "withheld: the Bash runs first");
    copyFileSync(notes, fresh); // the agent runs the Bash
    assert.ok(existsSync(fresh));
    assert.ok(!wouldSend(up).includes(KEY), "CONFIDENTIALITY: after the copy ran, the upload still sends no byte of the key");
    // a mapped upload after a Bash, the same
    const [, art] = await turn([
      { name: "Bash", input: { command: `cp ${notes} ${report}` } },
      { name: "Artifact", input: { file_path: report, icon: "chart" } },
    ]);
    assert.deepEqual(Object.keys(art!), ["action"], "Artifact refused whole");
    assert.match(String(art!["action"]), /rule: proxy:upload-after-write/);
    // on its own, next turn, the fresh file is judged by its bytes (now the key's copy): held
    const [again] = await turn([{ name: UP, input: { path: fresh, name: "summary.txt" } }]);
    assert.ok(!wouldSend(again).includes(KEY), "CONFIDENTIALITY: judged on its own, the copy is held");

    // ── U4: the host the bytes reach, not the one assumed ──
    await admin.setPathLabel({ path: page, confidentiality: "no-model", bindings: ["claude.ai"] });
    const pub = { file_path: page, icon: "doc" };
    const [p1] = await turn([{ name: "Artifact", input: pub }]);
    assert.deepEqual(Object.keys(p1!), ["action"], "bound to claude.ai only: held, the bytes go to api.anthropic.com");
    assert.match(String(p1!["action"]), /rule: fs:upload-secret-file/);
    await admin.setPathLabel({ path: page, confidentiality: "no-model", bindings: ["claude.ai", "api.anthropic.com"] });
    assert.deepEqual((await turn([{ name: "Artifact", input: pub }]))[0], pub, "bound to both hosts: it goes");

    // ── U5: fail-closed ──
    await server.close();
    const [down] = await turn([{ name: UP, input: clean }]);
    assert.ok(down === undefined || down["path"] === `/mandu/denied/upload${report}`, `with the arbiter gone every path is withheld: ${JSON.stringify(down)}`);
  } finally {
    await proxy.close();
    data.close(); human.close(); admin.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
});
