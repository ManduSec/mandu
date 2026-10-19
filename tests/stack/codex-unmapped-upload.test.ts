/**
 * codex-unmapped-upload — the security-invariant oracle for the openai-proxy's
 * unmapped upload leg (2026-10-17; guarantees.md §3, "A tool that uploads a
 * local file by its path"; supported-agents.md §2, "The upload residuals",
 * item 4), the Codex twin of unmapped-upload.test.ts, over the REAL
 * components: a real ArbiterServer in `secrets` with its human and admin
 * sockets, a registered `.env`, and the real OpenAiProxy over its PRODUCTION
 * adapter (`new ArbiterClientAdapter(new ArbiterClient(data), new
 * ArbiterClient(human))`, as server-main.ts builds it). Only the model
 * upstream is canned.
 *
 * The oracle is what each tool WOULD send given the call Codex receives
 * (`wouldSend`: every string of the call, and the bytes of every local file
 * an absolute path in it names, read when the tool would read it).
 *
 *   C1  a Codex MCP tool Mandu has never mapped (`{namespace: "mcp__drive",
 *       name: "upload_file"}`), naming the registered `.env`, a copy of its
 *       key or a symlink to it, sends no byte of the key: each path names no
 *       file when Codex gets the call, and each is an Approvals row
 *       `fs:mcp__drive__upload_file:upload` (before 2026-10-17 the call
 *       reached Codex unchanged and the key left);
 *   C2  utility: a clean file and a remote API's path go unchanged; codex's
 *       own `exec_command` is not asked about;
 *   C3  the window: an `exec_command` that copies the key into a fresh file,
 *       then the upload of that file, in ONE response: the upload's path is
 *       withheld, so after the copy runs the key still does not leave;
 *   C4  code mode: a cell (each in a fresh isolate) whose MCP call names the
 *       `.env` is replaced whole by the sentinel cell: nothing of the key in
 *       what the cell would send;
 *   C5  the next request: the withheld call's output is Mandu's notice, not
 *       the server's error;
 *   C6  fail-closed: with the arbiter gone the request is refused and no
 *       call is relayed;
 *   P   parity: the production adapter asks `fileUploadDecision` on the HUMAN
 *       socket (the data socket's answer is a refusal).
 *
 * Axes: `secrets` (confidentiality ON, integrity OFF), stated below.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { OpenAiProxy, type UpstreamFetcher } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream, buildCallsSse, deliveredItems, type TurnCall } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const KEY = "sk_live_fake_CODEXUPLOAD_4d2e8b1a9c";
const USER = { type: "message", role: "user", content: [{ type: "input_text", text: "share the Q3 files" }] };
const ISOLATED_EXEC = { type: "custom", name: "exec", description: "Run JavaScript code\n- Evaluates the provided JavaScript code in a fresh V8 isolate as an async module." };

/** Every string in a value. */
function strings(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const e of v) strings(e, out);
  else if (v && typeof v === "object") for (const e of Object.values(v)) strings(e, out);
  return out;
}

/** What a tool that uploads every local file its input names would send:
 *  the call's text and the bytes of each existing regular file at an
 *  absolute path string inside it (read now: when the tool reads it). */
function wouldSend(text: string): string {
  const out = [text];
  for (const m of text.matchAll(/\/[^\s"'`\\]+/g)) {
    try { if (statSync(m[0]).isFile()) out.push(readFileSync(m[0], "utf8")); } catch { /* names no file */ }
  }
  return out.join("\n");
}

/** A delivered call's payload: a function_call's arguments object, or a
 *  cell's text. */
const payload = (item: Record<string, unknown> | undefined): string => String(item?.["arguments"] ?? item?.["input"] ?? "");
const argsOf = (item: Record<string, unknown> | undefined): Record<string, unknown> => JSON.parse(payload(item)) as Record<string, unknown>;

/** A cell that still calls an MCP tool (by member or by a computed name):
 *  the sentinel cell runs only codex's shell, printing why. */
const MCP_CALL_RE = /tools\s*(?:\.|\[)\s*["']?mcp__/;

type Approval = { id: string; symbol: string; destination: string; status: string };

test("Codex: a tool Mandu has not mapped, an MCP call in a code cell and the same-turn window, over the real arbiter and proxy: no byte of a registered key leaves", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-codex-unmapped-upload-"));
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

  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSock, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const data = new ArbiterClient(socketPath); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const session = `codex-unmapped-upload-${process.pid}`;

  let next: TurnCall[] = [];
  const upstreams: MockUpstream[] = [];
  const fetcher: UpstreamFetcher = (args) => {
    const up = new MockUpstream({ sse: buildCallsSse(next) });
    upstreams.push(up);
    return up.fetcher(args);
  };
  // The PRODUCTION wiring: the real client on both sockets, no bridge.
  const realData: RealArbiterClient = data;
  const realHuman: RealArbiterClient = human;
  const proxy = new OpenAiProxy({ arbiter: new ArbiterClientAdapter(realData, realHuman), upstream: fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  /** The call items Codex receives for one model turn. */
  const turn = async (calls: TurnCall[], input: unknown[] = [USER], tools: unknown[] = []): Promise<Array<Record<string, unknown>>> => {
    next = calls;
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "gpt-6.1-sol", stream: true, input, tools }),
    });
    assert.equal(res.status, 200);
    return deliveredItems(await res.text());
  };
  const approvals = (): Approval[] =>
    (server.dispatch({ id: "q", op: "egressApprovals" } as never) as { result: { approvals: Approval[] } }).result.approvals;
  const UP = { name: "upload_file", namespace: "mcp__drive" };
  const TOOL = "mcp__drive__upload_file";

  try {
    const reg = await human.registerSecret({ path: env, sessionKey: session });
    assert.match(String(reg.symbol), /^\$MDU:nomodel_Read\[/, JSON.stringify(reg));

    // ── C1: an unmapped MCP upload tool: the file, a copy of its key, a symlink ──
    for (const path of [env, notes, link]) {
      const [got] = await turn([{ ...UP, arguments: { path, name: "q3.txt", folder: "Shared" } }]);
      assert.ok(got, "the call reached Codex");
      assert.ok(!wouldSend(payload(got)).includes(KEY), `CONFIDENTIALITY: ${TOOL} would upload the key (${path})`);
      assert.equal(argsOf(got)["path"], `/mandu/denied/upload${path}`, "the path names no file");
      assert.equal(argsOf(got)["name"], "q3.txt", "the rest of the call is the model's");
    }
    const held = approvals().filter((a) => a.symbol === `fs:${TOOL}:upload` && a.status === "pending").map((a) => a.destination).sort();
    assert.deepEqual(held, [env, notes, link].sort(), "one Approvals row per held path");

    // ── C2: utility ──
    const [clean] = await turn([{ ...UP, arguments: { path: report, name: "q3.html" } }]);
    assert.deepEqual(argsOf(clean), { path: report, name: "q3.html" });
    assert.ok(wouldSend(payload(clean)).includes(REPORT), "the report goes out");
    const [remote] = await turn([{ name: "post", namespace: "mcp__crm", arguments: { endpoint: "/v1/items", body: "{\"q\":3}" } }]);
    assert.deepEqual(argsOf(remote), { endpoint: "/v1/items", body: "{\"q\":3}" });
    const rows = approvals().length;
    await turn([{ name: "exec_command", arguments: { cmd: `wc -l ${env}` } }]);
    assert.equal(approvals().length, rows, "codex's own exec_command is not the upload leg's");

    // ── C3: the window, one response: an exec_command copies the key, then the upload ──
    const fresh = join(app, "site", "summary.txt");
    const [, up] = await turn([
      { name: "exec_command", arguments: { cmd: `cp ${notes} ${fresh}` } },
      { ...UP, arguments: { path: fresh, name: "summary.txt" } },
    ]);
    assert.equal(argsOf(up)["path"], `/mandu/denied/upload${fresh}`, "withheld: the exec_command runs first");
    copyFileSync(notes, fresh); // Codex runs the exec_command
    assert.ok(!wouldSend(payload(up)).includes(KEY), "CONFIDENTIALITY: after the copy ran, the upload still sends no byte of the key");
    const [again] = await turn([{ ...UP, arguments: { path: fresh, name: "summary.txt" } }]);
    assert.ok(!wouldSend(payload(again)).includes(KEY), "CONFIDENTIALITY: judged on its own, the copy is held");

    // ── C4: code mode: the MCP call rides an exec cell ──
    const cell = `const r = await tools.mcp__drive__upload_file({"path": "${env}", "name": "q3.txt"});\ntext(JSON.stringify(r));`;
    const [c] = await turn([{ name: "exec", input: cell, callId: "call_cell" }], [USER], [ISOLATED_EXEC]);
    const deliveredCell = payload(c);
    assert.ok(!deliveredCell.includes("tools.mcp__drive__upload_file"), `the cell is replaced whole: ${deliveredCell.slice(0, 160)}`);
    assert.match(deliveredCell, /exit 77/, "the sentinel cell");
    assert.ok(!MCP_CALL_RE.test(deliveredCell) && !deliveredCell.includes(KEY), "CONFIDENTIALITY: the cell calls no upload tool and holds no byte of the key");
    // an unidentified cell (the tool by a computed member, the path a literal)
    const odd = `const f = "${notes}";\nawait tools["mcp__drive__upload_file"]({ path: f });`;
    const [c2] = await turn([{ name: "exec", input: odd }], [USER], [ISOLATED_EXEC]);
    assert.ok(!payload(c2).includes("tools[\"mcp__drive__upload_file\"]"), "held through the literal");
    assert.ok(!MCP_CALL_RE.test(payload(c2)) && !payload(c2).includes(KEY), "CONFIDENTIALITY: the unidentified cell calls no upload tool");

    // ── C5: the next request: the output is Mandu's notice ──
    const [w] = await turn([{ ...UP, callId: "call_w", arguments: { path: env } }]);
    await turn([], [
      USER,
      { type: "function_call", call_id: "call_w", name: "upload_file", namespace: "mcp__drive", arguments: payload(w) },
      { type: "function_call_output", call_id: "call_w", output: [{ type: "input_text", text: "Wall time: 0.1 seconds\nOutput:" }, { type: "input_text", text: `ENOENT: no such file ${argsOf(w)["path"]}` }] },
    ]);
    const req = upstreams.at(-1)!.requests.at(-1)!.json() as { input: Array<Record<string, unknown>> };
    const fco = req.input.find((i) => i["type"] === "function_call_output")!;
    assert.match(String(fco["output"]), /^mandu-upload-gate: mcp__drive__upload_file was not given the file /, "the model reads why");
    for (const u of upstreams) for (const r of u.requests) assert.ok(!r.bodyText.includes(KEY), "CONFIDENTIALITY: the key never reaches the model");

    // ── C6: fail-closed ──
    // (an arbiter that fails only the upload ask withholds every path: the
    // openai-proxy unit `unmapped-upload.test.ts`, FAIL-CLOSED)
    await server.close(); // the arbiter gone: the request itself is refused, no call relayed
    next = [{ ...UP, arguments: { path: env } }];
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "gpt-6.1-sol", stream: true, input: [USER] }),
    });
    assert.equal(res.status, 502);
    assert.ok(!(await res.text()).includes(env), "no call relayed");
  } finally {
    await proxy.close();
    data.close(); human.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("parity: the openai-proxy's production adapter asks fileUploadDecision on the HUMAN socket (the data socket's answer is a refusal)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-codex-upload-parity-"));
  const file = join(tmp, "plain.txt");
  writeFileSync(file, "nothing secret\n");
  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const data: RealArbiterClient = new ArbiterClient(socketPath); await data.connect();
  const human: RealArbiterClient = new ArbiterClient(humanSock); await human.connect();
  try {
    const req = { tool: "mcp__drive__upload_file", path: file, destination: "", unmapped: true, sessionKey: "parity" };
    const viaData = await new ArbiterClientAdapter(data).fileUploadDecision(req);
    assert.equal(viaData.allow, false, `the data socket never reads a file: ${JSON.stringify(viaData)}`);
    const viaHuman = await new ArbiterClientAdapter(data, human).fileUploadDecision(req);
    assert.equal(viaHuman.allow, true, `the human socket judges the file: ${JSON.stringify(viaHuman)}`);
    assert.ok(viaHuman.ruleRef?.id, "with its rule");
  } finally {
    (data as ArbiterClient).close(); (human as ArbiterClient).close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
