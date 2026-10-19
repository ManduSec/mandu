/**
 * clean-tree-release — the path-derived mask's clean-tree release
 * (docs/design/confidentiality/clean-tree-release.md), over the REAL
 * components: a real ArbiterServer in `secrets`, the real anthropic-proxy
 * and openai-proxy over HTTP in their production wiring
 * (`new ArbiterClientAdapter(data, human)`), a mock model behind each, the
 * guard's records on the human socket.
 *
 * The shape (demo-git-history-scrub, demo-c4): a repository's `.env`, a
 * registered credential file holding a Stripe key that the first commit
 * hard-coded in `src/checkout.js`. The model scrubs the history with
 * commands that NAME `.env` without printing it. Before, each output was
 * one symbol ("the command names a secret file"), and on Codex, OpenCode,
 * OpenClaw and Goose the demo failed. Now:
 *
 *   1. Claude Code and Codex: git's own output (untracking `.env`, the
 *      rewrite's refusal, a log of `.env`'s commits) reaches the model as git
 *      printed it, and a `git log -p` line holding the key reaches it with
 *      the key as the `.env`'s own field symbol;
 *   2. fail closed, masked whole: the `.env` printed raw by a read the guard
 *      did not record, a base64 copy of the key, a tree that read the `.env`
 *      raw, a document named beside the `.env`, the twin printed beside
 *      git's output;
 *   3. THE ORACLE: no request to the model carries the key in any form this
 *      test knows (verbatim, base64 at each alignment, hex, reversed, any
 *      8-character piece), nor the document's line.
 *
 * Unit twins: arbiter test/unit and test/component clean-tree-release, both
 * proxies' test/unit/clean-tree-release.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
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

const KEY = "sk_test_51CleanTreeE2E7Kq2Xr9Lm4Tz8";
const DOC_LINE = "The acquisition of Northwind closes in March; keep it quiet.";
const HISTORY_LINE = "JWT_SECRET=mysupersecretjwtsigningkey";
const ENV = `STRIPE_SECRET_KEY=${KEY}\nPORT=4242\n`;
const HEAD = "Chunk ID: 5e1f\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 12\nOutput:\n";
const SYMBOL_ONLY_RE = /^\$MDU:nomodel_[A-Za-z0-9_]*\[[0-9a-f]{4,8}\]$/;

const UNTRACK = "(cd storefront && git rm -q --cached .env && printf '.env\\n' >> .gitignore && git add .gitignore && git commit -q -m 'Stop tracking .env' && git status --short --ignored)";
const FILTER = "(cd storefront && FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch --force --index-filter 'git rm -q --cached --ignore-unmatch .env' --prune-empty -- --all 2>&1)";
const LOG_ENV = "cd storefront && git log --all --oneline -- .env";
const LOG_P = "cd storefront && git log --all -p --format='commit %h %s' -- src .env 2>&1";
const LOG_P_OUT = `commit 196115d Initial checkout service\n+const stripe = Stripe("${KEY}");\nerror: unable to read 0d1f2e3c4b5a69788796a5b4c3d2e1f0a9b8c7d6\n`;

/** The forms of the key this test looks for, independent of the arbiter's. */
function keyForms(v: string): string[] {
  const out = [v, Buffer.from(v).toString("hex"), [...v].reverse().join("")];
  for (let pad = 0; pad < 3; pad++) {
    const b64 = Buffer.from("x".repeat(pad) + v).toString("base64").replace(/=+$/, "");
    out.push(b64.slice(pad === 0 ? 0 : pad + 1, b64.length - 1));
  }
  for (let i = 0; i + 8 <= v.length; i++) out.push(v.slice(i, i + 8));
  return out;
}

async function stack(name: string) {
  const tmp = mkdtempSync(join(tmpdir(), `mandu-clean-tree-${name}-`));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "storefront", "src"), { recursive: true });
  mkdirSync(join(ws, "memo"), { recursive: true });
  const env = join(ws, "storefront", ".env");
  writeFileSync(env, ENV);
  writeFileSync(join(ws, "storefront", "src", "checkout.js"), "const stripe = Stripe(process.env.STRIPE_SECRET_KEY);\n");
  const doc = join(ws, "memo", "plan.md");
  writeFileSync(doc, `# Plan\n\n${DOC_LINE}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${doc}\n    level: no-model\n`);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(humanSock); // the guard reports on the human socket (plan 13 D9)
  const human = await open(humanSock);
  // the launcher registers the catalog's .env (no label: the catalog's own)
  const reg = await guard.registerSecret({ path: env });
  assert.ok(typeof reg.twin === "string" && !(reg.twin as string).includes(KEY), JSON.stringify(reg));
  const r2 = await guard.registerSecret({ path: doc });
  assert.ok(r2.symbol, JSON.stringify(r2));
  return {
    ws, env, sock, open, guard, human, twin: reg.twin as string,
    async bind(session: string, callId: string, command: string, argv: string[]) {
      await human.recordCallCommand({ callId, command, sessionKey: session });
      await guard.recordExecRoot({ procKey: `sh-${callId}`, ancestors: [`agent-${session}`], argv, session, callRoot: true, cwd: ws });
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

function oracle(wire: string): void {
  for (const f of keyForms(KEY)) assert.ok(!wire.includes(f), `CONFIDENTIALITY VIOLATION: a form of the key reached the model: ${f}`);
  assert.ok(!wire.includes(DOC_LINE), "CONFIDENTIALITY VIOLATION: the document's content reached the model");
  assert.ok(!wire.includes("mysupersecretjwtsigningkey"), "CONFIDENTIALITY VIOLATION: a history-only secret reached the model");
}

test("Claude Code: git's output naming .env reaches the model as git printed it, a key line with the key as its symbol; an unseen raw read, an encoded copy, a raw tree, a document and a twin beside stay one symbol; the key never reaches the model (secrets axes, explicit)", async () => {
  const s = await stack("claude");
  const session = `clean-tree-claude-${process.pid}`;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const adapter = new ArbiterClientAdapter(await s.open(s.sock), s.human);
  const proxy = new AnthropicProxy({ arbiter: adapter, upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  let n = 0;
  const bashCall = async (command: string, output: string, before?: (id: string) => Promise<void>): Promise<string> => {
    const id = `toolu_ct_${n++}`;
    await s.bind(session, id, command, claudeArgv(command));
    if (before) await before(id);
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5", stream: true, max_tokens: 256,
        tools: [{ name: "Bash", input_schema: { type: "object" } }],
        messages: [
          { role: "user", content: "My Stripe key went into storefront's git history: scrub it." },
          { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
        ],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    const body = upstream.requests.at(-1)!.json() as { messages: Array<{ content: Array<{ content?: unknown }> }> };
    return String(body.messages[2]!.content[0]!.content);
  };
  try {
    // 1. the lift
    for (const [command, out] of [
      [UNTRACK, "!! .env"],
      [FILTER, "Cannot rewrite branches: You have unstaged changes."],
      [LOG_ENV, "ea68b4a Move the Stripe key to .env\n196115d Initial checkout service"],
    ] as const) {
      assert.equal(await bashCall(command, out), out, command);
    }
    const keyLine = await bashCall(LOG_P, LOG_P_OUT);
    const field = /\$MDU:nomodel_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\]\.STRIPE_SECRET_KEY/.exec(s.twin)?.[0];
    assert.ok(field, s.twin);
    assert.equal(keyLine, LOG_P_OUT.replace(KEY, field!), "the key as the .env's own field symbol");

    // 2. fail closed
    const masked: Array<[string, string, string, ((id: string) => Promise<void>)?]> = [
      ["the .env printed raw by a read the guard did not record", "cat storefront/.env", ENV],
      // review round 3, finding 1: a secret file that lives only in git
      // history, its lines in no registry row and of no credential shape
      ["a history-only .env", "git log --all -p -- config/.env.production", `+${HISTORY_LINE}`],
      ["a history-only .env by revision", "cd storefront && git show HEAD~3:old/.env", HISTORY_LINE],
      ["a base64 copy of the key", UNTRACK, `!! .env\n${Buffer.from(KEY).toString("base64")}`],
      ["a document named beside the .env", "git rm -q --cached storefront/.env memo/plan.md && git status --short", "D  memo/plan.md"],
      ["the twin printed beside git's output", "cd storefront && cat .env && git status --short", `${s.twin}?? x`],
      ["a tree that read the .env raw", UNTRACK, "!! .env", async (id) => {
        await s.guard.processLineage({ childKey: `sh-${id}-node`, parentKey: `sh-${id}` });
        await s.guard.taintProcessSecret({ procKey: `sh-${id}-node`, path: s.env, level: "no-model", app: "node", session });
      }],
    ];
    for (const [why, command, output, before] of masked) {
      const got = await bashCall(command, output, before);
      assert.match(got.split("\n\n[mandu:secret] ")[0]!, SYMBOL_ONLY_RE, `${why}: ${got}`);
    }

    // 3. THE ORACLE
    oracle(upstream.requests.map((r) => r.bodyText).join("\n"));
  } finally {
    await proxy.close();
    await s.close();
  }
});

test("Codex: git's output naming .env behind the exec envelope reaches the model as git printed it; the .env printed raw stays one symbol; the key never reaches the model (secrets axes, explicit)", async () => {
  const s = await stack("codex");
  const session = `clean-tree-codex-${process.pid}`;
  const upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const adapter = new OpenAiProxyArbiterAdapter(await s.open(s.sock), s.human);
  const proxy = new OpenAiProxy({ arbiter: adapter, upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const ask = async (id: string, command: string, output: string): Promise<string> => {
    await s.bind(session, id, command, ["/bin/bash", "-lc", command]);
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session },
      body: JSON.stringify({
        model: "gpt-5.5", stream: true, instructions: "You are Codex.",
        input: [
          { type: "message", role: "user", content: [{ type: "input_text", text: "Scrub my Stripe key from storefront's history." }] },
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
    assert.equal(await ask("call_ct_1", UNTRACK, "!! .env\n"), `${HEAD}!! .env\n`);
    assert.equal(await ask("call_ct_2", FILTER, "Cannot rewrite branches: You have unstaged changes.\n"), `${HEAD}Cannot rewrite branches: You have unstaged changes.\n`);
    const raw = await ask("call_ct_3", "cat storefront/.env", ENV);
    assert.ok(!raw.includes("STRIPE_SECRET_KEY="), `the raw .env is masked whole: ${raw}`);
    oracle(upstream.requests.map((r) => r.bodyText).join("\n"));
  } finally {
    await proxy.close();
    await s.close();
  }
});
