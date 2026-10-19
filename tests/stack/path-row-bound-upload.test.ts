/**
 * path-row-bound-upload — confidentiality-plan-15-prompt-filter.md §13.12,
 * "What a path row registers", over the REAL components, in the shape the
 * live c6 demo (demo-notion-token, Codex, 2026-10-17) failed on:
 *
 *   1. `notes-app/.env` holds a Notion token, labelled no-model and bound to
 *      api.notion.com (policy.yaml), registered as the launcher does: every
 *      program is served its structured twin;
 *   2. Codex runs ONE command that prints `.env`, the app's script and the
 *      meeting notes; the guard bound the call's shell (the recorder) and no
 *      process in it read a secret raw. The result goes through the REAL
 *      openai-proxy in its production wiring and is masked whole (the
 *      command names `.env`: the path-derived precaution), as before;
 *   3. a program then POSTs the notes to api.notion.com with the token's
 *      placeholder in its Authorization header, through the REAL net-proxy:
 *      FORWARDED, the real token in the header and the notes in the body.
 *      Before the fix the §4 tripwire blocked it, matching the notes' lines
 *      as pieces of the masked batch's row (bound nowhere);
 *
 * and the oracle, which must hold with the fix:
 *
 *   4. the RAW token to an unbound host still trips the tripwire (its own
 *      row); a credential-shaped line the batch printed (from a plain file)
 *      re-sent to an unbound host still trips (a piece of the batch's row);
 *   5. a batch that ALSO names a labelled file nobody registered (the guard
 *      never confined it, so its raw text is in the output) is not narrowed:
 *      the notes' upload stays blocked, and the labelled file's own line to
 *      any host trips;
 *   6. no model request carries the token, the labelled file's text or the
 *      unmasked batch.
 *
 * A leading `cd` in Codex's command (2026-10-19, plan 15 §13.12 "A leading
 * cd"): `cd notes-app && …` (read from the call's `workdir`) and `cd
 * <abs>/notes-app && …` are placed in that folder like Claude Code's, so
 * the notes' upload goes through there too and the token stays a tripwire;
 * before, the wide reading of the unmapped `exec_command` input took the
 * cmd's own `cd` as moving every string and placed nothing.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy, type HttpForwarder } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { ArbiterClientAdapter as OpenAiAdapter, type RealArbiterClient as OpenAiRealClient } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { rewriteRequest as rewriteResponsesRequest } from "../../interceptors/openai-proxy/src/rewrite-request.js";
import type { ResponsesRequest } from "../../interceptors/openai-proxy/src/responses-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

// Made-up values (no real credential).
const TOKEN = "secret_PATHROW_C6_9Qm2Xv7Lk4Tz8Wp3Hn6Rb1";
const PLAN = "The acquisition of Parkside closes on 3 March; keep it quiet until then.";
const SCRIPT = [
  "#!/bin/sh",
  "# Add a markdown file to Notion as a new page under the team's notes page.",
  "set -a; . \"$here/.env\"; set +a",
  "DEPLOY_KEY=ghp_Zq8vT3nLk2Wp9Rx4Hb7Mc1Fd6Gs0Jy5Ua8Ee2",
  "",
].join("\n");
const NOTES = [
  "# Team sync, 16 October",
  "",
  "Shipped: the new signup page is live.",
  "Next: Mina drafts the October newsletter by Friday.",
  "Decision: the weekly sync moves to Thursdays at 10:00.",
  "",
].join("\n");
const NOTES_LINES = NOTES.split("\n").filter((l) => l.length >= 24);

function post(port: number, url: string, body: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const r = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: url, headers: { host: u.host, "content-type": "application/json", "content-length": Buffer.byteLength(body), ...headers } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    r.on("error", reject);
    r.end(body);
  });
}

/** The body notes-app/add-page.sh builds from the notes file. */
function notionBody(): string {
  const lines = NOTES.split("\n");
  const children = lines.slice(1).filter((l) => l !== "").map((l) => ({ object: "block", type: "paragraph", paragraph: { rich_text: [{ type: "text", text: { content: l } }] } }));
  return JSON.stringify({ parent: { page_id: "8f2e6c1a0b3d4c5e9f701a2b3c4d5e6f" }, properties: { title: { title: [{ type: "text", text: { content: lines[0]!.replace(/^# */, "") } }] } }, children });
}

interface Rig {
  ws: string;
  guard: ArbiterClient;
  codex: OpenAiAdapter;
  netPort: number;
  reached: string[];
  done(): Promise<void>;
}

async function rig(session: string): Promise<Rig> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-path-row-c6-"));
  const ws = join(tmp, "ws");
  for (const d of ["notes-app", "meetings", "secrets"]) mkdirSync(join(ws, d), { recursive: true });
  const env = join(ws, "notes-app", ".env");
  writeFileSync(env, `NOTION_TOKEN='${TOKEN}'\n`);
  writeFileSync(join(ws, "notes-app", "add-page.sh"), SCRIPT);
  writeFileSync(join(ws, "meetings", "2026-10-16-team-sync.md"), NOTES);
  writeFileSync(join(ws, "secrets", "plan.md"), `${PLAN}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, [
    "version: 1", "paths:",
    `  - path: ${env}`, "    level: no-model", "    bindings: [api.notion.com]",
    `  - path: ${join(ws, "secrets", "plan.md")}`, "    level: no-model",
    "",
  ].join("\n"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await server.listen();
  const guard = new ArbiterClient(humanPath); await guard.connect();
  const humanO = new ArbiterClient(humanPath); await humanO.connect();
  const realO: OpenAiRealClient = new ArbiterClient(socketPath); await realO.connect();
  const netData = new ArbiterClient(socketPath); await netData.connect();
  const netHuman = new ArbiterClient(humanPath); await netHuman.connect();
  const codex = new OpenAiAdapter(realO, humanO);
  const reached: string[] = [];
  const forwarder: HttpForwarder = async (req) => {
    const hdrs = Object.entries(req.headers ?? {}).map(([k, v]) => `${k}: ${String(v)}`).join("\n");
    reached.push(`${req.url}\n${hdrs}\n\n${req.body?.toString("utf8") ?? ""}`);
    return { status: 200, headers: { "content-type": "application/json" }, body: Buffer.from("{\"object\":\"page\"}") };
  };
  const net = new NetProxy({
    arbiter: new NetProxyAdapter(netData as unknown as NetProxyRealClient, netHuman as never), forwarder, log: () => {}, sessionId: session,
    // curl, which read the twin (no raw read: the process is clean).
    attributeHolders: () => [{ procKey: "curl-1", ancestors: ["sh-upload", "agent-0"] }],
  });
  const netPort = await net.listen(0);
  // The launcher's registration of the token's file. (A Codex session runs
  // under the default gate surface, whose `workdir` table is Codex's: the
  // command's relative paths are read in the `workdir` the call names.)
  const reg = await guard.registerSecret({ path: env, sessionKey: session });
  assert.ok(typeof reg.twin === "string" && !reg.twin.includes(TOKEN), JSON.stringify(reg));
  return {
    ws, guard, codex, netPort, reached,
    done: async () => {
      await net.close();
      guard.close(); humanO.close(); realO.close(); netData.close(); netHuman.close();
      await server.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

/** Codex's one batched command, as the guard and the proxies see it: the
 *  proxy records the command, the guard binds the shell, the result goes
 *  through the real openai-proxy. Returns what the model was shown. */
async function batch(r: Rig, session: string, callId: string, command: string, printed: string): Promise<{ shown: string; request: string }> {
  await r.guard.recordCallCommand({ callId, command, sessionKey: session });
  await r.guard.recordExecRoot({ procKey: `sh-${callId}`, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true, cwd: r.ws });
  const out = `Script completed\nWall time 0.7 seconds\nOutput:\n${printed}`;
  const o = await rewriteResponsesRequest({
    model: "gpt-test", instructions: "You are Codex.",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "show me notes-app/.env, then add today's meeting notes to Notion" }] },
      { type: "function_call", call_id: callId, name: "exec_command", arguments: JSON.stringify({ cmd: command, workdir: r.ws }) },
      { type: "function_call_output", call_id: callId, output: out },
    ],
  } as ResponsesRequest, { arbiter: r.codex, sessionKey: session });
  const shown = String((o.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);
  return { shown, request: JSON.stringify(o.request) };
}

test("c6: Codex's batched read of .env, the script and the notes; the notes' upload to the token's bound host goes through; the token and the credential line stay tripwires", async () => {
  const session = "s-path-row-c6";
  const r = await rig(session);
  try {
    const twin = (await r.guard.registerSecret({ path: join(r.ws, "notes-app", ".env"), sessionKey: session })).twin as string;
    const field = twin.match(/\$MDU:nomodel_Read\[[0-9a-f]+\]\.NOTION_TOKEN/)![0];
    const command = "printf '%s\\n' '--- notes-app/.env ---' && sed -n '1,160p' notes-app/.env && printf '%s\\n' '--- notes-app/add-page.sh ---' && sed -n '1,240p' notes-app/add-page.sh && printf '%s\\n' '--- meetings/2026-10-16-team-sync.md ---' && sed -n '1,240p' meetings/2026-10-16-team-sync.md";
    const printed = `--- notes-app/.env ---\n${twin}--- notes-app/add-page.sh ---\n${SCRIPT}--- meetings/2026-10-16-team-sync.md ---\n${NOTES}`;
    const { shown, request } = await batch(r, session, "call_batch", command, printed);
    // 2. masked whole, as before: the model sees one symbol and the note
    assert.match(shown, /\$MDU:nomodel_exec_command\[[0-9a-f]+\]/, shown);
    assert.match(shown, /the command names a secret file/, "the path-derived note");
    for (const l of NOTES_LINES) assert.ok(!shown.includes(l), "no notes line reaches the model in this result");
    assert.ok(!request.includes(TOKEN), "the token reaches no model request");

    // 3. the upload: the placeholder in the header, the notes in the body
    const up = await post(r.netPort, "http://api.notion.com/v1/pages", notionBody(), { authorization: `Bearer ${field}` });
    assert.equal(up.status, 200, `forwarded, not refused: ${up.body}`);
    assert.equal(r.reached.length, 1, "it reached api.notion.com");
    assert.ok(r.reached[0]!.includes(`Bearer ${TOKEN}`), "with the real token in its header");
    for (const l of NOTES_LINES.slice(1)) assert.ok(r.reached[0]!.includes(l), `and the notes in its body: ${l}`);
    assert.ok(!r.reached[0]!.includes("$MDU:"), "no placeholder on the wire");

    // 4. the oracle: the raw token and the batch's credential line, unbound
    const rawToken = await post(r.netPort, "http://httpbin.org/post", JSON.stringify({ t: TOKEN }));
    assert.equal(rawToken.status, 403, rawToken.body);
    assert.match(rawToken.body, /fingerprint tripwire/);
    const credLine = await post(r.netPort, "http://httpbin.org/post", JSON.stringify({ line: "DEPLOY_KEY=ghp_Zq8vT3nLk2Wp9Rx4Hb7Mc1Fd6Gs0Jy5Ua8Ee2" }));
    assert.equal(credLine.status, 403, credLine.body);
    assert.match(credLine.body, /fingerprint tripwire/);
    assert.match(credLine.body, /nomodel_exec_command/, "a piece of the batch's own row");
    assert.match(credLine.body, /"requiresApproval":false/, "a tripwire block offers no approval (none exists for it)");
    assert.equal(r.reached.length, 1, "nothing reached httpbin.org");
  } finally { await r.done(); }
});

test("c6, the oracle: a batch that also names a labelled file nobody registered is not narrowed; the notes' upload stays blocked and that file's line trips", async () => {
  const session = "s-path-row-c6-unconfined";
  const r = await rig(session);
  try {
    const twin = (await r.guard.registerSecret({ path: join(r.ws, "notes-app", ".env"), sessionKey: session })).twin as string;
    const field = twin.match(/\$MDU:nomodel_Read\[[0-9a-f]+\]\.NOTION_TOKEN/)![0];
    // The guard never confined secrets/plan.md, so `cat` printed it raw.
    const command = "cat notes-app/.env secrets/plan.md meetings/2026-10-16-team-sync.md";
    const { shown, request } = await batch(r, session, "call_unconfined", command, `${twin}${PLAN}\n${NOTES}`);
    assert.match(shown, /\$MDU:nomodel_exec_command\[[0-9a-f]+\]/, shown);
    assert.ok(!request.includes(PLAN) && !request.includes(TOKEN), "neither the plan nor the token reaches a model request");

    const up = await post(r.netPort, "http://api.notion.com/v1/pages", notionBody(), { authorization: `Bearer ${field}` });
    assert.equal(up.status, 403, `the notes' upload stays blocked: ${up.body}`);
    assert.match(up.body, /fingerprint tripwire/);
    const plan = await post(r.netPort, "http://api.notion.com/v1/pages", JSON.stringify({ text: PLAN }));
    assert.equal(plan.status, 403, plan.body);
    assert.match(plan.body, /fingerprint tripwire/);
    assert.equal(r.reached.length, 0, "nothing was sent");
  } finally { await r.done(); }
});

test("c6 with a leading cd (Codex, relative and absolute): the notes' upload goes through; the token stays a tripwire", async () => {
  for (const form of ["relative", "absolute"] as const) {
    const session = `s-path-row-c6-cd-${form}`;
    const r = await rig(session);
    try {
      const twin = (await r.guard.registerSecret({ path: join(r.ws, "notes-app", ".env"), sessionKey: session })).twin as string;
      const field = twin.match(/\$MDU:nomodel_Read\[[0-9a-f]+\]\.NOTION_TOKEN/)![0];
      const app = form === "relative" ? "notes-app" : join(r.ws, "notes-app");
      const notesPath = join(r.ws, "meetings", "2026-10-16-team-sync.md");
      const command = `cd ${app} && sed -n '1,160p' .env && sed -n '1,240p' add-page.sh && sed -n '1,240p' ${notesPath}`;
      const { shown, request } = await batch(r, session, `call_cd_${form}`, command, `${twin}${SCRIPT}${NOTES}`);
      assert.match(shown, /\$MDU:nomodel_exec_command\[[0-9a-f]+\]/, `${form}: ${shown}`);
      for (const l of NOTES_LINES) assert.ok(!shown.includes(l), `${form}: no notes line reaches the model in this result`);
      assert.ok(!request.includes(TOKEN), `${form}: the token reaches no model request`);

      const up = await post(r.netPort, "http://api.notion.com/v1/pages", notionBody(), { authorization: `Bearer ${field}` });
      assert.equal(up.status, 200, `${form}: forwarded, not refused: ${up.body}`);
      assert.equal(r.reached.length, 1, `${form}: it reached api.notion.com`);
      assert.ok(r.reached[0]!.includes(`Bearer ${TOKEN}`), `${form}: with the real token in its header`);

      // the oracle: the raw token and the script's credential line, unbound
      const rawToken = await post(r.netPort, "http://httpbin.org/post", JSON.stringify({ t: TOKEN }));
      assert.equal(rawToken.status, 403, rawToken.body);
      assert.match(rawToken.body, /fingerprint tripwire/);
      const credLine = await post(r.netPort, "http://httpbin.org/post", JSON.stringify({ line: "DEPLOY_KEY=ghp_Zq8vT3nLk2Wp9Rx4Hb7Mc1Fd6Gs0Jy5Ua8Ee2" }));
      assert.equal(credLine.status, 403, credLine.body);
      assert.equal(r.reached.length, 1, `${form}: nothing reached httpbin.org`);
    } finally { await r.done(); }
  }
});
