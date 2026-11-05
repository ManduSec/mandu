/**
 * reply-scope-tripwire.test.ts — the egress tripwire on a REPLY the model
 * wrote (`egressFingerprintScan` `scope: "reply"`, the OpenClaw plugin's
 * message_sending; openclaw-plugin.md §3.5), over the real IPC.
 *
 * A shell result the proxy masked whole, on a host where the path row is not
 * narrowed (no recorder bound its tree: the OpenClaw plugin's Route 1, where
 * the commands run on the Gateway's host), keeps every long line as a piece.
 * For an outbound request that stays (a program may move the output's bytes
 * as they are). For a reply of a `no-model` output it does not: no model saw
 * the output, only its placeholder, so an ordinary line of it in a reply (the meeting title a
 * script printed beside a token: demo-notion-token, live 2026-10-26) is no
 * evidence; the plugin cancelled a harmless reply on it. In a reply such a
 * row counts only by its secrets:
 *   - a registered value still trips (its own row);
 *   - a line of the output with the registered value embedded still trips;
 *   - a credential-shaped line or span of the output still trips (its row);
 *   - the output's whole value still trips;
 *   - an ordinary line of the output no longer trips in a reply, and still
 *     trips in a request;
 *   - only a `no-model` output: an `any-model` one (a model it admits saw
 *     it) keeps every line in a reply too.
 *
 * Mandu-new test. A real ArbiterServer on a temp socket, the real client.
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

// Made-up values (no real credential).
const TOKEN = "secret_ReplyScopeUnit4Kp8Wq2Zx6Ln3Rt7";
const DEPLOY_LINE = "DEPLOY_KEY=ghp_Rq8vT3nLk2Wp9Rx4Hb7Mc1Fd6Gs0Jy5Ua8Ee3";
const TITLE = "Created the page: Team sync, 16 October (14 lines)";
const OUTPUT = `${TITLE}\nposted with token ${TOKEN} to the notes page\n${DEPLOY_LINE}\n`;
const SESSION = "openclaw:d01-reply";

test("a reply counts a whole-masked output only by its secrets; a request still counts every line", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-reply-scope-"));
  const ws = join(dir, "ws");
  mkdirSync(join(ws, "notes-app"), { recursive: true });
  const env = join(ws, "notes-app", ".env");
  writeFileSync(env, `NOTION_TOKEN='${TOKEN}'\n`);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, ["version: 1", "paths:", `  - path: ${env}`, "    level: no-model", "    bindings: [api.notion.com]", ""].join("\n"));
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await server.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock"));
  await c.connect();
  try {
    const reg = await c.registerSecret({ path: env, sessionKey: SESSION });
    assert.ok(typeof reg.symbol === "string", JSON.stringify(reg));
    // the proxy masks the script's whole output (its command names the .env);
    // no recorder bound the call's tree, so the row keeps every line
    const command = "sh notes-app/add-page.sh meetings/sync.md";
    const callId = "call_reply_1";
    await c.callTaint(callId, { command, session: SESSION });
    await c.classify({ tool: "exec", value: OUTPUT, boundary: "model_context", origin: command, params: { command }, sessionKey: SESSION, callId });
    const row = await c.symbolize({
      tool: "exec", value: OUTPUT, origin: command, sessionKey: SESSION, callId,
      confidentiality: "no-model", integrity: "trusted", secretBy: "path-rule",
    });
    assert.match(row, /^\$MDU:nomodel_exec\[/);
    const scan = async (text: string, scope?: "reply"): Promise<string[]> =>
      (await c.egressFingerprintScan({ surfaces: [{ where: "body", text }], destination: "", ...(scope ? { scope } : {}) })).hits.map((h) => h.symbol);

    // the over-cancel: the title the model wrote itself (it read the notes)
    const harmless = `Added the notes to Notion as a new page: **${TITLE}**.`;
    assert.ok((await scan(harmless)).includes(row), "a request: the masked output's ordinary line is a piece (the egress tripwire keeps it)");
    assert.deepEqual(await scan(harmless, "reply"), [], "a reply: an ordinary line of a whole-masked output is no fingerprint");

    // what a reply still trips on
    const reply = async (text: string): Promise<string[]> => scan(text, "reply");
    assert.ok((await reply(`the token is ${TOKEN}`)).includes(reg.symbol!), "a registered value: its own row");
    assert.ok((await reply(`it said: posted with token ${TOKEN} to the notes page`)).length > 0, "a line of the output with the secret embedded");
    assert.ok((await reply(`> ${DEPLOY_LINE}`)).includes(row), "a credential-shaped line of the output");
    assert.ok((await reply("ghp_Rq8vT3nLk2Wp9Rx4Hb7Mc1Fd6Gs0Jy5Ua8Ee3")).includes(row), "its credential span");
    assert.ok((await reply(`x ${OUTPUT} y`)).includes(row), "the output's whole value");

    // a lower level: a model it admits saw the output, so its every line counts
    const seen = "Quarterly figures for the board: revenue up nine percent";
    const callId2 = "call_reply_2";
    const command2 = "cat finance/board-notes.md";
    await c.callTaint(callId2, { command: command2, session: SESSION });
    await c.classify({ tool: "exec", value: `${seen}\nnext steps: hire two\n`, boundary: "model_context", origin: command2, params: { command: command2 }, sessionKey: SESSION, callId: callId2 });
    const row2 = await c.symbolize({
      tool: "exec", value: `${seen}\nnext steps: hire two\n`, origin: command2, sessionKey: SESSION, callId: callId2,
      confidentiality: "any-model", integrity: "trusted", secretBy: "path-rule",
    });
    assert.ok((await reply(`In short: ${seen}.`)).includes(row2), "an any-model output's ordinary line still trips in a reply");
  } finally {
    c.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
