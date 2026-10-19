/**
 * artifact-upload — the security-invariant oracle for Claude Code's
 * interactive Artifact tools (supported-agents.md §2, "Claude Code 2.1.295";
 * confidentiality.md §7, "A tool that uploads a local file"), over the REAL
 * components: a real ArbiterServer in `secrets` with its human socket, a
 * registered `.env`, and the real AnthropicProxy over its PRODUCTION adapter
 * (`new ArbiterClientAdapter(new ArbiterClient(data), new ArbiterClient(human))`,
 * as server-main.ts builds it), the gate surface from the arbiter's op.
 *
 * `Artifact` publishes a local page (`file_path`) and its supporting `files`
 * to claude.ai; `ArtifactData` writes a document from a local JSON file
 * (`file_path`, `writes[].file_path`); `ArtifactComments` posts reply text.
 * The tools read the files themselves: the bytes never enter the model
 * context. The mock upstream replays the tool_use blocks in the captured
 * shapes (arbiter/test/fixtures/claude-artifact-tools-2026-10-09.json); the
 * oracle is what each tool WOULD send given the input the agent receives
 * (`wouldSend`: an `action` outside the captured enum is a schema rejection,
 * nothing sent; else the bytes of every local file it names, and its text).
 *
 *   A1  a publish naming the `.env` as a supporting file, a page holding a
 *       copy of its key, or a symlink to it is refused whole: no byte of the
 *       key in what Artifact would upload; each held file is an Approvals
 *       row `fs:Artifact:upload` × path;
 *   A2  an ArtifactData write from the `.env` (top level, or in a batch) is
 *       refused whole;
 *   A3  the key's symbol in a comment reply or in inline document data is
 *       never put back into what goes to claude.ai (the egress gate);
 *   A4  a page path relative to the working directory is refused (the gate
 *       cannot tell which file it names); nothing is asked or sent;
 *   A5  utility: an ordinary page and its files go out byte for byte, a
 *       comment reply and inline data go unchanged;
 *   A6  the human's Allow once lets the held `.env` go exactly once;
 *   A7  fail-closed: with the arbiter gone nothing is sent.
 *
 * Axes: `secrets` (confidentiality ON, integrity OFF), stated below.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
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
type Captured = { name: string; input_schema: { properties: Record<string, { enum?: string[] }> } };
const CAPTURED = JSON.parse(readFileSync(join(here, "..", "..", "arbiter", "test", "fixtures", "claude-artifact-tools-2026-10-09.json"), "utf8")) as Captured[];
const ACTIONS = (tool: string): string[] => CAPTURED.find((t) => t.name === tool)!.input_schema.properties["action"]!.enum!;

const KEY = "sk_live_fake_ARTIFACT_5b2d81c4e07a";

/** What the tool would send to claude.ai for `input`: nothing when its schema
 *  rejects the action; else every string it carries, and the bytes of each
 *  local file it reads (`files` sources against `root`, the agent's working
 *  directory `cwd` otherwise). */
function wouldSend(tool: string, input: Record<string, unknown>, cwd: string): string {
  const action = input["action"];
  if (action !== undefined && !ACTIONS(tool).includes(String(action))) return "";
  if (tool === "Artifact" && action === undefined && !ACTIONS(tool).includes("publish")) return "";
  const read = (p: string, base: string): string => readFileSync(isAbsolute(p) ? p : resolve(base, p), "utf8");
  const out: string[] = [JSON.stringify(input)];
  if (tool === "Artifact" && (action ?? "publish") === "publish") {
    const root = typeof input["root"] === "string" ? resolve(cwd, input["root"]) : cwd;
    if (typeof input["file_path"] === "string") out.push(read(input["file_path"], cwd));
    const files = input["files"];
    if (Array.isArray(files)) for (const f of files as Array<{ path: string }>) out.push(read(f.path, root));
    else if (files && typeof files === "object") {
      for (const src of Object.values(files as Record<string, unknown>)) {
        if (typeof src === "string") out.push(read(src, root));
        else if (src && typeof src === "object" && "from" in src) out.push(read(String((src as { from: string }).from), root));
      }
    }
  }
  if (tool === "ArtifactData") {
    if (typeof input["file_path"] === "string") out.push(read(input["file_path"], cwd));
    for (const w of (input["writes"] as Array<{ file_path?: string }> | undefined) ?? []) if (w.file_path) out.push(read(w.file_path, cwd));
  }
  return out.join("\n");
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

test("the Artifact tools over the real arbiter and proxy: no byte of a secret file goes out by path, symbols are not put back, ordinary pages go, a human Allow once lets one go once, and a gone arbiter refuses", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-artifact-"));
  const app = join(tmp, "ws", "app");
  const site = join(app, "site");
  mkdirSync(join(site, "css"), { recursive: true });
  const env = join(app, ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY}\nDEBUG=1\n`);
  const PAGE = "<!doctype html><title>Q3 report</title><h1>Totals</h1>\n";
  const CSS = "h1{color:#333}\n";
  writeFileSync(join(site, "index.html"), PAGE);
  writeFileSync(join(site, "css", "a.css"), CSS);
  writeFileSync(join(site, "notes.html"), `<p>staging key for the demo: ${KEY}</p>\n`);
  symlinkSync(env, join(site, "theme.css"));
  writeFileSync(join(app, "rows.json"), JSON.stringify({ total: 42 }));

  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const data = new ArbiterClient(socketPath); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const session = `artifact-${process.pid}`;

  // The upstream replays one call per request.
  let next: { name: string; input: Record<string, unknown> } = { name: "Artifact", input: {} };
  const fetcher: UpstreamFetcher = (args) =>
    new MockUpstream({ sse: buildToolUseSse({ id: `tu_${Math.random().toString(36).slice(2, 8)}`, name: next.name, input: next.input }) }).fetcher(args);
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream: fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  /** The input the agent receives; null when the proxy refused the whole request. */
  const reaches = async (name: string, input: Record<string, unknown>): Promise<Record<string, unknown> | null> => {
    next = { name, input };
    const sse = await post(port, JSON.stringify({ model: "claude-sonnet-5", stream: true, messages: [{ role: "user", content: "publish the Q3 report" }] }));
    return (toolUseOf(sse)?.input as Record<string, unknown> | undefined) ?? null;
  };
  const agentGets = async (name: string, input: Record<string, unknown>): Promise<Record<string, unknown>> => {
    const got = await reaches(name, input);
    assert.ok(got, "the call reached the agent");
    return got;
  };
  const approvals = (): Approval[] =>
    (server.dispatch({ id: "q", op: "egressApprovals" } as never) as { result: { approvals: Approval[] } }).result.approvals;

  try {
    const reg = await human.registerSecret({ path: env, sessionKey: session });
    assert.match(String(reg.symbol), /^\$MDU:nomodel_Read\[/, JSON.stringify(reg));

    // ── A1: the file as a supporting file, a page holding its key, a symlink to it ──
    for (const [call, rule] of [
      [{ file_path: join(site, "index.html"), root: site, files: { "env.txt": "../.env" }, icon: "chart" }, "fs:upload-secret-file"],
      [{ file_path: join(site, "notes.html"), icon: "doc" }, "fs:upload-secret-value"],
      [{ file_path: join(site, "index.html"), root: site, files: [{ path: "theme.css" }], icon: "chart" }, "fs:upload-secret-file"],
    ] as const) {
      const got = await agentGets("Artifact", call);
      const sent = wouldSend("Artifact", got, app);
      assert.ok(!sent.includes(KEY), `CONFIDENTIALITY: Artifact would upload the key (${JSON.stringify(call)})`);
      assert.equal(sent, "", "the whole call is refused, nothing is sent");
      assert.match(String(got["action"]), new RegExp(`rule: ${rule}`));
      assert.match(String(got["action"]), /Approvals page/);
    }
    const held = approvals().filter((a) => a.symbol === "fs:Artifact:upload" && a.status === "pending").map((a) => a.destination).sort();
    assert.deepEqual(held, [env, join(site, "notes.html"), join(site, "theme.css")].sort(), "one Approvals row per held file");

    // ── A2: ArtifactData from the .env, top level and in a batch ──
    for (const call of [
      { action: "set", url: "https://claude.ai/artifact/q3", collection: "rows", doc_id: "r1", file_path: env },
      { action: "batch", url: "https://claude.ai/artifact/q3", writes: [{ op: "set", collection: "rows", doc_id: "r1", file_path: join(app, "rows.json") }, { op: "update", collection: "rows", doc_id: "r2", file_path: env }] },
    ]) {
      const got = await agentGets("ArtifactData", call);
      assert.equal(wouldSend("ArtifactData", got, app), "", `refused whole: ${JSON.stringify(got).slice(0, 200)}`);
      assert.match(String(got["action"]), /rule: fs:upload-secret-file/);
    }
    assert.ok(approvals().some((a) => a.symbol === "fs:ArtifactData:upload" && a.destination === env), "ArtifactData's own Approvals row");

    // ── A3: the key's symbol in a comment reply and in inline data ──
    const tok = `${reg.symbol}.STRIPE_KEY`;
    for (const [name, call] of [
      ["ArtifactComments", { action: "reply", url: "https://claude.ai/artifact/q3", thread_id: "t1", text: `use ${tok}` }],
      ["ArtifactData", { action: "update", url: "https://claude.ai/artifact/q3", collection: "cfg", doc_id: "c1", data: { key: tok } }],
    ] as const) {
      const got = await agentGets(name, call);
      assert.equal(wouldSend(name, got, app), "", `${name}: refused whole`);
      assert.match(String(got["action"]), /mandu-net-gate: network use blocked, nothing was sent/);
    }

    // ── A4: a path relative to the working directory ──
    const rel = await agentGets("Artifact", { file_path: "site/index.html", icon: "chart" });
    assert.equal(wouldSend("Artifact", rel, app), "");
    assert.match(String(rel["action"]), /rule: proxy:upload-relative-path/);

    // ── A5: utility ──
    const page = { file_path: join(site, "index.html"), root: site, files: [{ path: "css/a.css" }], icon: "chart", title: "Q3 report" };
    const pageGot = await agentGets("Artifact", page);
    assert.deepEqual(pageGot, page);
    const pageSent = wouldSend("Artifact", pageGot, app);
    assert.ok(pageSent.includes(PAGE) && pageSent.includes(CSS), "the page and its stylesheet go out");
    const reply = { action: "reply", url: "https://claude.ai/artifact/q3", thread_id: "t1", text: "Fixed: the totals now add up." };
    assert.deepEqual(await agentGets("ArtifactComments", reply), reply);
    const rows = { action: "set", url: "https://claude.ai/artifact/q3", collection: "rows", doc_id: "r1", file_path: join(app, "rows.json") };
    assert.deepEqual(await agentGets("ArtifactData", rows), rows);

    // ── A6: the human's Allow once ──
    const row = approvals().find((a) => a.symbol === "fs:Artifact:upload" && a.destination === env)!;
    const v = server.dispatch({ id: "once", op: "resolveEgressApproval", approvalId: row.id, approve: true, scope: "once" } as never);
    assert.ok(v.ok, (v as { error?: string }).error);
    const once = { file_path: join(site, "index.html"), root: site, files: { "env.txt": "../.env" }, icon: "chart" };
    const allowed = await agentGets("Artifact", once);
    assert.deepEqual(allowed, once, "allowed once, on the human socket");
    assert.ok(wouldSend("Artifact", allowed, app).includes(KEY), "the human's allow is what lets it go");
    const again = await agentGets("Artifact", once);
    assert.equal(wouldSend("Artifact", again, app), "", "spent: held again");

    // ── A7: fail-closed ──
    await server.close();
    const down = await reaches("Artifact", page);
    assert.ok(down === null || wouldSend("Artifact", down, app) === "", "with the arbiter gone nothing is sent");
  } finally {
    await proxy.close();
    data.close(); human.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
});
