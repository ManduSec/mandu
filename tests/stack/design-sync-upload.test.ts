/**
 * design-sync-upload — the security-invariant oracle for Claude Code
 * 2.1.292's DesignSync (supported-agents.md §2, "Claude Code 2.1.292";
 * confidentiality.md §7, "A tool that uploads a local file"), over the REAL
 * components: a real ArbiterServer in `secrets` with its human socket, a
 * registered `.env`, and the real AnthropicProxy over its PRODUCTION adapter
 * (`new ArbiterClientAdapter(new ArbiterClient(data), new ArbiterClient(human))`,
 * as server-main.ts builds it), the gate surface from the arbiter's op.
 *
 * DesignSync's `write_files` reads each `files[].localPath` itself and
 * uploads the bytes to claude.ai: they never enter the model context. The
 * mock upstream replays DesignSync tool_use blocks in the captured 2.1.292
 * shape; the oracle is what DesignSync WOULD upload given the input the
 * agent receives (`wouldUpload`: its own schema from the capture, so a
 * refused input uploads nothing, then the bytes of every file it names).
 *
 *   L1  a plan with an absolute localDir reaches the agent unchanged;
 *   L2  an upload naming the `.env` (relative to the plan, escaping it), a
 *       copy of its key under an ordinary name, or a symlink to it is
 *       refused whole: no byte of the key in what DesignSync would upload;
 *       each held file is an Approvals row `fs:DesignSync:upload` × path;
 *   L3  a symbol of the key in inline `data` is refused (the egress gate:
 *       not bound to claude.ai), so it is never put back into the upload;
 *   L4  utility: an ordinary file goes out byte for byte;
 *   L5  the human's Allow once lets the held `.env` go exactly once (the
 *       invariant's "unless the human allows it"), asked on the human socket;
 *   L6  fail-closed: with the arbiter gone the upload is refused.
 *
 * Axes: `secrets` (confidentiality ON, integrity OFF), stated below.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { SseToolUseParser, type ReconstructedToolUse } from "../../interceptors/anthropic-proxy/src/sse-parser.js";
import { MockUpstream, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const here = dirname(fileURLToPath(import.meta.url));
const SCHEMA = (JSON.parse(readFileSync(join(here, "..", "..", "arbiter", "test", "fixtures", "claude-design-sync-tool-2026-10-07.json"), "utf8")) as {
  input_schema: { properties: Record<string, unknown>; required: string[] };
}).input_schema;

const KEY = "sk_live_fake_DSYNC_7a1c0e9f42b8d3";

/** What DesignSync would send to claude.ai for `input`: nothing for an input
 *  its schema rejects (the captured required + additionalProperties false)
 *  or a method that uploads no file; else each file's bytes, a `localPath`
 *  read relative to the plan's `localDir` as the tool reads it. */
function wouldUpload(input: Record<string, unknown>, localDir: string): string[] {
  if (!SCHEMA.required.every((k) => k in input)) return [];
  if (!Object.keys(input).every((k) => k in SCHEMA.properties)) return [];
  if (input["method"] !== "write_files" || !Array.isArray(input["files"])) return [];
  return (input["files"] as Array<{ localPath?: string; data?: string }>).map((f) =>
    f.localPath !== undefined ? readFileSync(resolve(localDir, f.localPath), "utf8") : f.data ?? "");
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

function toolUseOf(sse: string): ReconstructedToolUse | null {
  const seen: ReconstructedToolUse[] = [];
  const p = new SseToolUseParser((tu) => seen.push(tu));
  p.feed(sse);
  p.end();
  assert.ok(seen.length <= 1, sse.slice(0, 400));
  return seen[0] ?? null;
}

type Approval = { id: string; symbol: string; destination: string; status: string };

test("DesignSync over the real arbiter and proxy: no byte of a secret file goes out by localPath, inline symbols are not put back, ordinary files go, a human Allow once lets one go once, and a gone arbiter refuses", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-design-sync-"));
  const app = join(tmp, "ws", "app");
  const bundle = join(app, "ds-bundle");
  mkdirSync(join(bundle, "button"), { recursive: true });
  const env = join(app, ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY}\nDEBUG=1\n`);
  const BUTTON = "<!-- @dsCard group=\"Actions\" -->\n<button class=\"primary\">OK</button>\n";
  writeFileSync(join(bundle, "button", "index.html"), BUTTON);
  writeFileSync(join(bundle, "notes.txt"), `staging key for the demo: ${KEY}\n`);
  symlinkSync(env, join(bundle, "theme.css"));

  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const data = new ArbiterClient(socketPath); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const session = `design-sync-${process.pid}`;

  // The upstream replays one DesignSync call per request.
  let next: Record<string, unknown> = {};
  const fetcher: UpstreamFetcher = (args) => new MockUpstream({ sse: buildToolUseSse({ id: `tu_${Math.random().toString(36).slice(2, 8)}`, name: "DesignSync", input: next }) }).fetcher(args);
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream: fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  /** The input the agent receives; null when the proxy refused the whole
   *  request (no tool_use reached the agent at all). */
  const reaches = async (call: Record<string, unknown>): Promise<Record<string, unknown> | null> => {
    next = call;
    const sse = await post(port, JSON.stringify({ model: "claude-sonnet-5", stream: true, messages: [{ role: "user", content: "/design-sync push the button" }] }));
    return (toolUseOf(sse)?.input as Record<string, unknown> | undefined) ?? null;
  };
  const agentGets = async (call: Record<string, unknown>): Promise<Record<string, unknown>> => {
    const got = await reaches(call);
    assert.ok(got, "the call reached the agent");
    return got;
  };
  const write = (files: unknown[]) => ({ method: "write_files", projectId: "proj-1", planId: "plan-1", files });
  const approvals = (): Approval[] =>
    (server.dispatch({ id: "q", op: "egressApprovals" } as never) as { result: { approvals: Approval[] } }).result.approvals;

  try {
    const reg = await human.registerSecret({ path: env, sessionKey: session });
    assert.match(String(reg.symbol), /^\$MDU:nomodel_Read\[/, JSON.stringify(reg));

    // ── L1 ──
    const plan = { method: "finalize_plan", projectId: "proj-1", writes: ["components/**"], localDir: bundle };
    assert.deepEqual(await agentGets(plan), plan);

    // ── L2: the file, a copy of its key, a symlink to it ──
    for (const [localPath, rule] of [["../.env", "fs:upload-secret-file"], ["notes.txt", "fs:upload-secret-value"], ["theme.css", "fs:upload-secret-file"]] as const) {
      const got = await agentGets(write([
        { path: "components/button/index.html", localPath: "button/index.html" },
        { path: `components/${localPath}`, localPath },
      ]));
      const sent = wouldUpload(got, bundle).join("\n");
      assert.ok(!sent.includes(KEY), `CONFIDENTIALITY: DesignSync would upload the key via ${localPath}`);
      assert.deepEqual(sent, "", `${localPath}: the whole call is refused, nothing is sent`);
      assert.match(String(got["action"]), new RegExp(`rule: ${rule}`), localPath);
      assert.match(String(got["action"]), /Approvals page/);
    }
    const held = approvals().filter((a) => a.symbol === "fs:DesignSync:upload" && a.status === "pending").map((a) => a.destination).sort();
    assert.deepEqual(held, [env, join(bundle, "notes.txt"), join(bundle, "theme.css")].sort(), "one Approvals row per held file");

    // ── L3: the key's symbol in inline data is never put back into the upload ──
    const inline = await agentGets(write([{ path: "components/config.js", data: `export const key = "${reg.symbol}.STRIPE_KEY";` }]));
    assert.deepEqual(wouldUpload(inline, bundle), [], "refused whole");
    assert.match(String(inline["action"]), /mandu-net-gate: network use blocked, nothing was sent/);

    // ── L4: utility ──
    const ok = write([{ path: "components/button/index.html", localPath: "button/index.html" }, { path: "readme.md", data: "# Buttons" }]);
    const okGot = await agentGets(ok);
    assert.deepEqual(okGot, ok);
    assert.deepEqual(wouldUpload(okGot, bundle), [BUTTON, "# Buttons"]);

    // ── L5: the human's Allow once (the invariant's "unless the human allows it") ──
    const row = approvals().find((a) => a.symbol === "fs:DesignSync:upload" && a.destination === env)!;
    const v = server.dispatch({ id: "once", op: "resolveEgressApproval", approvalId: row.id, approve: true, scope: "once" } as never);
    assert.ok(v.ok, (v as { error?: string }).error);
    const once = write([{ path: "components/env.txt", localPath: "../.env" }]);
    const allowed = await agentGets(once);
    assert.deepEqual(allowed, once, "allowed once, on the human socket");
    assert.ok(wouldUpload(allowed, bundle).join("").includes(KEY), "the human's allow is what lets it go");
    const again = await agentGets(once);
    assert.equal(wouldUpload(again, bundle).length, 0, "spent: held again");

    // ── L6: fail-closed ──
    await server.close();
    // (the request leg refuses first: the prompt filter cannot run, so no
    // call reaches the agent; either way nothing is uploaded)
    const down = await reaches(write([{ path: "components/button/index.html", localPath: "button/index.html" }]));
    assert.ok(down === null || wouldUpload(down, bundle).length === 0, "with the arbiter gone nothing is uploaded");
  } finally {
    await proxy.close();
    data.close(); human.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("parity: the production adapter asks fileUploadDecision on the HUMAN socket (the data socket is refused a read)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-design-sync-parity-"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const data = new ArbiterClient(socketPath); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const file = join(tmp, "button.html");
  writeFileSync(file, "<button/>\n");
  try {
    const req = { tool: "DesignSync", path: file, destination: "claude.ai", sessionKey: "parity" };
    const viaData = await new ArbiterClientAdapter(data).fileUploadDecision(req);
    assert.equal(viaData.ruleRef?.id, "fs:upload-unattested", "the data socket never makes the arbiter read a file");
    data.close();
    const viaHuman = await new ArbiterClientAdapter(data, human).fileUploadDecision(req);
    assert.equal(viaHuman.allow, true, JSON.stringify(viaHuman));
    assert.equal(viaHuman.ruleRef?.id, "fs:upload-clean");
  } finally {
    human.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
