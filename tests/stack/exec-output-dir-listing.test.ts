/**
 * exec-output-dir-listing — plan 10 §11.8, "A folder's names" (2026-10-17),
 * over the REAL components: a real ArbiterServer in `secrets` whose policy
 * labels the workspace's `bank/` no-model, the real anthropic-proxy and
 * openai-proxy over HTTP in their production wiring
 * (`new ArbiterClientAdapter(data, human)`), a mock model behind each, the
 * guard's records on the human socket, and the output of a real `ls`.
 *
 * Found live (demo-c2, mode `secrets`): asked to go through the inbox, the
 * model ran `ls mail/inbox bank/`. The command names the labelled `bank/`,
 * so the path-derived precaution masked the whole listing: the model saw one
 * symbol where an unlabelled folder shows its file names. Now:
 *
 *   - Claude Code (Bash) and Codex (exec_command): a plain `ls` of the
 *     labelled folder (and of the inbox beside it) reaches the model as `ls`
 *     printed it, with the `listing:` note;
 *   - `ls -la` (sizes, dates), a chain or a pipe beside it (`&& cat …`), an
 *     output with a line no name gives, a listing no guard record answers
 *     for, and the same `ls` whose tree read a statement raw stay one symbol;
 *   - a name that holds a registered secret value stays one symbol (the
 *     value backstop);
 *   - THE ORACLE: no statement's content and no secret value is in any
 *     request to the model.
 *
 * Unit twins: arbiter `dir-listing.test.ts` (unit + component), both
 * proxies' `rewrite-request.test.ts`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream as OpenAiMockUpstream } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const ACCT = "DEMO-ACCT-000123";
const STATEMENT = `# Maple Bank statement, September 2026\nAccount ${ACCT}\nBalance 4,210.00\n`;
const KEY = "sk_live_51DirListingStackE2E0123456789";
const HEAD = "Chunk ID: 5e1f\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 12\nOutput:\n";
const NOTE = (paths: string[]) => `[mandu:secret] listing: these are the names in ${paths.join(", ")} as ls printed them, and nothing else: no file's content, size or date. The files there may still be secret: reading one shows you a symbol where its secret content is.`;
/** A masked result's body: one symbol and nothing else. */
const SYMBOL_ONLY_RE = /^\$MDU:nomodel_[A-Za-z0-9_]*\[[0-9a-f]{4,8}\]$/;

async function stack(name: string) {
  const tmp = mkdtempSync(join(tmpdir(), `mandu-dir-listing-${name}-`));
  const ws = join(tmp, "ws");
  for (const d of ["bank", "mail/inbox", "drop"]) mkdirSync(join(ws, d), { recursive: true });
  writeFileSync(join(ws, "bank", "statement-2026-08.md"), STATEMENT.replace("September", "August"));
  writeFileSync(join(ws, "bank", "statement-2026-09.md"), STATEMENT);
  writeFileSync(join(ws, "mail", "inbox", "1-dentist.md"), "Can we move you to Tuesday 9:30?\n");
  writeFileSync(join(ws, "mail", "inbox", "2-book-club.md"), "Next month's book is out.\n");
  writeFileSync(join(ws, "mail", "inbox", "3-park-tax.md"), "Please upload your September statement.\n");
  writeFileSync(join(ws, ".env"), `STRIPE_SECRET_KEY=${KEY}\n`);
  // a file whose NAME holds a registered value, in a labelled folder
  writeFileSync(join(ws, "drop", `${KEY}.txt`), "x\n");
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(ws, "bank")}\n    level: no-model\n    recursive: true\n  - path: ${join(ws, "drop")}\n    level: no-model\n    recursive: true\n`);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(humanSock); // the guard reports on the human socket (plan 13 D9)
  const human = await open(humanSock);
  const reg = await guard.registerSecret({ path: join(ws, ".env") });
  assert.ok(typeof reg.twin === "string" && !(reg.twin as string).includes(KEY), JSON.stringify(reg));
  return {
    ws, sock, humanSock, open, guard, human,
    /** What a real `ls` prints in a pipe (byte order), as the agent's shell
     *  ran it in the workspace. */
    ls(...args: string[]): string {
      return execFileSync("ls", args, { cwd: ws, encoding: "utf8", env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", LC_ALL: "C" } });
    },
    /** The proxy's record of the command it relayed, then the guard's report
     *  of the agent's shell for it with the kernel's directory (or none). */
    async bind(session: string, callId: string, command: string, argv: string[], cwd: string | null) {
      await human.recordCallCommand({ callId, command, sessionKey: session });
      await guard.recordExecRoot({ procKey: `sh-${callId}`, ancestors: [`agent-${session}`], argv, session, callRoot: true, ...(cwd !== null ? { cwd } : {}) });
    },
    async close() {
      for (const c of clients) c.close();
      await server.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

/** Claude Code's shell, as it spawns a Bash call's command. */
const claudeArgv = (command: string) => ["/bin/bash", "-c", `source /dev/null 2>/dev/null || true && eval '${command.replace(/'/g, `'"'"'`)}' && pwd -P >| /tmp/claude-x-cwd`];

test("Claude Code: `ls mail/inbox bank/` of a labelled folder reaches the model as ls printed it with the listing note; ls -la, a chain, a pipe, an extra line, no record, a raw read and a name holding a registered value stay one symbol; no statement byte or secret value reaches the model (secrets axes, explicit)", async () => {
  const s = await stack("claude");
  const session = `dir-listing-claude-${process.pid}`;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const adapter = new ArbiterClientAdapter(await s.open(s.sock), s.human);
  const proxy = new AnthropicProxy({ arbiter: adapter, upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  let n = 0;
  /** One Bash call: bound by the guard (unless `cwd` is "unrecorded": no
   *  record at all), its output (Claude Code trims the last newline) sent
   *  back through the proxy. What the model got for it. */
  const bashCall = async (command: string, output: string, cwd: string | null | "unrecorded" = s.ws, before?: (id: string) => Promise<void>): Promise<string> => {
    const id = `toolu_dl_${n++}`;
    if (cwd !== "unrecorded") await s.bind(session, id, command, claudeArgv(command), cwd);
    if (before) await before(id);
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5", stream: true, max_tokens: 256,
        tools: [{ name: "Bash", input_schema: { type: "object" } }],
        messages: [
          { role: "user", content: "Go through the emails in mail/inbox and take care of them; my bank statements are in bank/." },
          { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output.replace(/\n$/, "") }] },
        ],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    const body = upstream.requests.at(-1)!.json() as { messages: Array<{ content: Array<{ content?: unknown }> }> };
    return String(body.messages[2]!.content[0]!.content);
  };
  try {
    // THE LIFT: the demo's command, the real ls output
    const listing = s.ls("mail/inbox", "bank/");
    assert.equal(listing, "bank/:\nstatement-2026-08.md\nstatement-2026-09.md\n\nmail/inbox:\n1-dentist.md\n2-book-club.md\n3-park-tax.md\n");
    const released = await bashCall("ls mail/inbox bank/", listing);
    assert.equal(released, `${listing.replace(/\n$/, "")}\n\n${NOTE([join(s.ws, "bank"), join(s.ws, "mail", "inbox")])}`);
    // -A and a single folder: no header
    const one = await bashCall("ls -A bank", s.ls("-A", "bank"));
    assert.equal(one, `statement-2026-08.md\nstatement-2026-09.md\n\n${NOTE([join(s.ws, "bank")])}`);
    // an absolute operand needs no start directory
    const abs = await bashCall(`ls ${join(s.ws, "bank")}`, s.ls(join(s.ws, "bank")), null);
    assert.equal(abs, `statement-2026-08.md\nstatement-2026-09.md\n\n${NOTE([join(s.ws, "bank")])}`);

    // what stays masked: metadata, content beside the names, a byte no name gives
    const masked: Array<[string, string, string, string | null | "unrecorded"]> = [
      ["ls -la (sizes, dates, modes)", "ls -la bank/", s.ls("-la", "bank/"), s.ws],
      ["a chain that prints a statement", "ls bank/ && cat bank/statement-2026-09.md", `${s.ls("bank/")}${STATEMENT}`, s.ws],
      ["a chain, the names alone", "ls bank/; head -c0 bank/statement-2026-09.md", s.ls("bank/"), s.ws],
      ["a pipe", "ls bank/ | head -5", s.ls("bank/"), s.ws],
      ["a statement line appended", "ls bank/", `${s.ls("bank/")}Account ${ACCT}\n`, s.ws],
      ["a name missing", "ls bank/", "statement-2026-09.md\n", s.ws],
      // (A relative `bank/` with no record is not read as the labelled
      // folder by the classify either, so nothing masks it there: the
      // absolute spelling is the case with a mask to keep. A relative
      // operand with no start directory: the component test.)
      // (A command no shell of the session ran: the most-recent-exec guess
      // finds no tree either.)
      ["no guard record", `ls -1 ${join(s.ws, "bank")}`, s.ls(join(s.ws, "bank")), "unrecorded"],
      ["a name holding a registered value", "ls drop", s.ls("drop"), s.ws],
    ];
    for (const [why, command, output, cwd] of masked) {
      const got = await bashCall(command, output, cwd);
      // the body is one symbol; the note names only the model's own path tokens
      const [body] = got.split("\n\n[mandu:secret] ");
      assert.match(body!, SYMBOL_ONLY_RE, why);
      assert.match(got, /\[mandu:secret\] masked: the command names /, why);
      assert.doesNotMatch(got, /listing:|DEMO-ACCT|sk_live/, why);
    }

    // the same ls whose tree read a statement RAW (a listed reader): rule (i)
    const raw = await bashCall("ls mail/inbox bank/", listing, s.ws, async (id) => {
      await s.guard.processLineage({ childKey: `sh-${id}-reader`, parentKey: `sh-${id}` });
      await s.guard.taintProcessSecret({ procKey: `sh-${id}-reader`, path: join(s.ws, "bank", "statement-2026-09.md"), level: "no-model", app: "cat", session });
    });
    assert.match(raw.split("\n\n[mandu:secret] ")[0]!, SYMBOL_ONLY_RE, raw);
    assert.doesNotMatch(raw, /listing:|DEMO-ACCT/);
    assert.match(raw, /\[mandu:secret\] masked: cat read /, "rule (i): the tree read a statement raw");

    // THE ORACLE: no statement byte, no secret value in any request to the model
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(ACCT), "CONFIDENTIALITY VIOLATION: a statement's account number reached the model");
    assert.ok(!wire.includes("Balance 4,210.00"), "CONFIDENTIALITY VIOLATION: a statement's content reached the model");
    assert.ok(!wire.includes(KEY), "CONFIDENTIALITY VIOLATION: a registered value (in a file name) reached the model");
  } finally {
    await proxy.close();
    await s.close();
  }
});

test("Codex: `ls mail/inbox bank/` behind the exec envelope reaches the model with the listing note; a chain that prints a statement stays one symbol; no statement byte reaches the model (secrets axes, explicit)", async () => {
  const s = await stack("codex");
  const session = `dir-listing-codex-${process.pid}`;
  const upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const adapter = new OpenAiProxyArbiterAdapter(await s.open(s.sock), s.human);
  const proxy = new OpenAiProxy({ arbiter: adapter, upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const ask = async (id: string, command: string, output: string): Promise<string> => {
    await s.bind(session, id, command, ["/bin/bash", "-lc", command], s.ws);
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session },
      body: JSON.stringify({
        model: "gpt-5.5", stream: true, instructions: "You are Codex.",
        input: [
          { type: "message", role: "user", content: [{ type: "input_text", text: "Go through the emails in mail/inbox; my bank statements are in bank/." }] },
          { type: "function_call", call_id: id, name: "exec_command", arguments: JSON.stringify({ cmd: command, workdir: s.ws }) },
          { type: "function_call_output", call_id: id, output: `${HEAD}${output}` },
        ],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    const item = (JSON.parse(upstream.requests.at(-1)!.bodyText).input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" && i["call_id"] === id)!;
    const o = item["output"];
    return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
  };
  try {
    const listing = s.ls("mail/inbox", "bank/");
    assert.equal(await ask("call_dl_1", "ls mail/inbox bank/", listing), `${HEAD}${listing}\n\n${NOTE([join(s.ws, "bank"), join(s.ws, "mail", "inbox")])}`);
    const chain = await ask("call_dl_2", "ls bank/ && cat bank/statement-2026-09.md", `${s.ls("bank/")}${STATEMENT}`);
    assert.match(chain.split("\n\n[mandu:secret] ")[0]!, SYMBOL_ONLY_RE, chain);
    assert.doesNotMatch(chain, /listing:|DEMO-ACCT/);
    const long = await ask("call_dl_3", "ls -l bank/", s.ls("-l", "bank/"));
    assert.match(long.split("\n\n[mandu:secret] ")[0]!, SYMBOL_ONLY_RE, long);
    assert.doesNotMatch(long, /statement-2026|listing:/);
    // THE ORACLE
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(ACCT), "CONFIDENTIALITY VIOLATION: a statement's account number reached the model");
    assert.ok(!wire.includes(KEY), "CONFIDENTIALITY VIOLATION: a registered value reached the model");
  } finally {
    await proxy.close();
    await s.close();
  }
});
