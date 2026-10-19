/**
 * codex-ullm-forwarder — the Codex quarantine (inspect_symbol's U-LLM, a
 * cut-down `codex exec`) through the launcher's U-LLM forwarder
 * (agent-sign-in.md §2.11, 2026-10-04): the REAL forwarder
 * (launcher/src/services/ullm-forwarder.ts, its Codex form), the REAL
 * `CliUllmClient` with its production runner, the real `codex` CLI
 * (self-SKIP without one), a stand-in for the vendor's two upstreams.
 *
 * Under `--landlock-net-strict` the agent's world (the inspect server's
 * included) has no :443, so a Codex quarantine that dials the vendor
 * itself cannot run. The forwarder runs outside that world and relays a
 * model call to the fixed pair:
 *   - on a ChatGPT sign-in (a synthetic one: unsigned JWT-shaped tokens, an
 *     empty refresh token) the turn reaches `/backend-api/codex/responses`
 *     with the sign-in's bearer and account id, verbatim;
 *   - on a saved key, `/v1/responses` with the key;
 *   - the answer comes back to the client; nothing but a model call reached
 *     the stand-in (the forwarder relays nothing else).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { startUllmForwarder } from "../../launcher/src/services/ullm-forwarder.js";
import { CliUllmClient, defaultCliExec } from "../../interceptors/inspect-mcp/src/ullm-client.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the quarantine is a confidentiality-axis tool; nothing here reads an axis

const CODEX = process.env.MANDU_TEST_CODEX_BIN || spawnSync("which", ["codex"], { encoding: "utf8" }).stdout.trim() || null;
const GATE = CODEX ? false : "no codex CLI on PATH (MANDU_TEST_CODEX_BIN names one)";
const ACCOUNT = "acct-synthetic-ullm-0001";

const scratch = mkdtempSync(join(tmpdir(), "codex-ullm-fwd-"));
after(() => rmSync(scratch, { recursive: true, force: true }));

function syntheticSignIn(): { file: string; access: string } {
  const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString("base64url");
  const exp = Math.floor(Date.now() / 1000) + 10 * 24 * 3600;
  const auth = { chatgpt_account_id: ACCOUNT, chatgpt_plan_type: "plus", chatgpt_user_id: "user-synthetic-ullm" };
  const jwt = (claims: Record<string, unknown>): string =>
    `${b64({ alg: "RS256", typ: "JWT" })}.${b64(claims)}.${Buffer.from("synthetic-signature").toString("base64url")}`;
  const access = jwt({ exp, "https://api.openai.com/auth": auth });
  const file = JSON.stringify({
    OPENAI_API_KEY: null,
    tokens: { id_token: jwt({ email: "ci@example.invalid", exp, "https://api.openai.com/auth": auth }), access_token: access, refresh_token: "", account_id: ACCOUNT },
    last_refresh: new Date().toISOString(),
  });
  return { file, access };
}

async function startVendor(): Promise<{ url: string; seen: Array<{ method: string; url: string; headers: Record<string, unknown> }>; close: () => void }> {
  const seen: Array<{ method: string; url: string; headers: Record<string, unknown> }> = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      seen.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers });
      if (!(req.url ?? "").includes("/responses")) { res.writeHead(404); res.end(); return; }
      res.writeHead(200, { "content-type": "text/event-stream" });
      const ev = (o: Record<string, unknown>) => res.write(`event: ${String(o.type)}\ndata: ${JSON.stringify(o)}\n\n`);
      ev({ type: "response.created", response: { id: "r1" } });
      ev({ type: "response.output_item.done", item: { type: "message", role: "assistant", id: "m1", content: [{ type: "output_text", text: "VENDOR-ANSWER" }] } });
      ev({ type: "response.completed", response: { id: "r1", usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } } });
      res.end();
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen, close: () => { server.closeAllConnections(); server.close(); } };
}

async function quarantineCall(codexHome: string, forwarderUrl: string): Promise<string> {
  const saved = process.env.CODEX_HOME;
  process.env.CODEX_HOME = codexHome;
  try {
    const client = new CliUllmClient({ binary: "codex", forwarderUrl, timeoutMs: 90_000, exec: (spec) => defaultCliExec({ ...spec, file: CODEX! }) });
    return (await client.complete({ system: "QUARANTINE: summarize the data.", user: "## Data\nhello" })).text;
  } finally {
    if (saved === undefined) delete process.env.CODEX_HOME;
    else process.env.CODEX_HOME = saved;
  }
}

test("a ChatGPT sign-in: the quarantine's model call reaches the ChatGPT backend's Codex path through the forwarder, the sign-in verbatim; nothing else is relayed", { skip: GATE, timeout: 120_000 }, async () => {
  const vendor = await startVendor();
  const fwd = await startUllmForwarder({ codex: { api: vendor.url, chatgpt: `${vendor.url}/backend-api/codex` } });
  const home = join(scratch, "home-chatgpt");
  mkdirSync(home, { recursive: true });
  const signIn = syntheticSignIn();
  writeFileSync(join(home, "auth.json"), signIn.file, { mode: 0o600 });
  try {
    assert.equal(await quarantineCall(home, fwd.url), "VENDOR-ANSWER");
    const turns = vendor.seen.filter((s) => s.method === "POST");
    assert.ok(turns.length >= 1, JSON.stringify(vendor.seen.map((s) => `${s.method} ${s.url}`)));
    for (const t of turns) {
      assert.equal(t.url, "/backend-api/codex/responses");
      assert.equal(t.headers["authorization"], `Bearer ${signIn.access}`);
      assert.equal(t.headers["chatgpt-account-id"], ACCOUNT);
    }
    for (const s of vendor.seen) {
      assert.ok(/^\/backend-api\/codex\/(responses|models)(\?|$)/.test(s.url), `only a model call is relayed: ${s.method} ${s.url}`);
    }
  } finally {
    await fwd.stop();
    vendor.close();
  }
});

test("a saved key: the quarantine's model call reaches the API origin's /v1/responses through the forwarder, the key verbatim", { skip: GATE, timeout: 120_000 }, async () => {
  const vendor = await startVendor();
  const fwd = await startUllmForwarder({ codex: { api: vendor.url, chatgpt: `${vendor.url}/backend-api/codex` } });
  const home = join(scratch, "home-key");
  mkdirSync(home, { recursive: true });
  writeFileSync(join(home, "auth.json"), JSON.stringify({ OPENAI_API_KEY: "sk-synthetic-ullm-key" }), { mode: 0o600 });
  try {
    assert.equal(await quarantineCall(home, fwd.url), "VENDOR-ANSWER");
    const turns = vendor.seen.filter((s) => s.method === "POST");
    assert.ok(turns.length >= 1);
    for (const t of turns) {
      assert.equal(t.url, "/v1/responses");
      assert.equal(t.headers["authorization"], "Bearer sk-synthetic-ullm-key");
      assert.equal(t.headers["chatgpt-account-id"], undefined);
    }
  } finally {
    await fwd.stop();
    vendor.close();
  }
});
