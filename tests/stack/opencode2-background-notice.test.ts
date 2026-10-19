/**
 * opencode2-background-notice — OpenCode 2's background-completion notices
 * over the REAL arbiter, its REAL IPC and the PRODUCTION proxy wiring, in the
 * `secrets` mode (supported-agents.md §2.3 item 6;
 * interceptors/anthropic-proxy/src/opencode-background.ts).
 *
 * On OpenCode 2 a shell or subagent the USER moves to the background (the
 * TUI's ctrl+b, `POST /api/session/:id/background`) returns its output later
 * as a USER message `<shell id=… state=… command=…>output</shell>` /
 * `<subagent sessionID=…>answer</subagent>`, re-sent unchanged in every later
 * request. Before this, no tool_result check read it: a moved `cat` of a
 * labelled file reached the model in clear (probed on 2.0.23; the transcript
 * is arbiter/test/fixtures/opencode2-tool-surface-2026-10-05.json
 * `__background_move__`, replayed here verbatim).
 *
 *   ingress     a moved `cat` of the labelled secret, and a moved subagent's
 *               answer carrying a registered secret value, reach the model
 *               only as symbols, inside OpenCode's own header and closing tag;
 *   the capture the real 2.0.23 transcript of a user move, replayed: the
 *               secret it carried is masked;
 *   history     the notice re-sent in the next request forwards byte for byte
 *               the same (the prompt cache stays warm);
 *   unparsed    a notice no call can claim is masked whole;
 *   FAIL-CLOSED the arbiter unreachable: the notice never reaches the model raw.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the built-in default: confidentiality ON, integrity OFF

const here = dirname(fileURLToPath(import.meta.url));
const capture = JSON.parse(readFileSync(join(here, "..", "..", "arbiter", "test", "fixtures", "opencode2-tool-surface-2026-10-05.json"), "utf8")) as {
  __background_move__: { shell: { lastRequestMessages: Message[] }; subagent: { lastRequestMessages: Message[] } };
};
type Message = { role: string; content: string | Array<Record<string, unknown>> };

const API_KEY_BODY = "ACME_API_KEY=sk-live-BGNOTICE-CANARY-4417\n";
const CANARY = "BGNOTICE-CANARY-4417";
const SYMBOL_RE = /\$MDU:[A-Za-z0-9_]+\[[0-9a-f]+\]/;

interface Stack {
  vault: string;
  secretFile: string;
  sessionKey: string;
  real: ArbiterClient;
  admin: ArbiterClient;
  server: ArbiterServer;
  send: (messages: Message[]) => Promise<{ status: number; forwarded: string }>;
}

async function withStack(name: string, fn: (s: Stack) => Promise<void>, extraLabels: string[] = []): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-oc2-bg-"));
  const vault = join(tmp, "home", "vault");
  mkdirSync(vault, { recursive: true });
  const secretFile = join(vault, "api.env");
  writeFileSync(secretFile, API_KEY_BODY);
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [vault, ...extraLabels].map((path) => ({ path, level: "no-model" })) } as never,
  });
  await server.listen();
  const real = new ArbiterClient(socketPath);
  await real.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock"));
  await admin.connect();
  const sessionKey = `oc2-bg-${name}-${process.pid}`;
  assert.equal((await real.setSessionSpec({ sessionKey, spec: "opencode", requestedBy: "opencode2-background-notice e2e" })).bound, "opencode");
  const proxies: AnthropicProxy[] = [];
  try {
    await fn({
      vault, secretFile, sessionKey, real, admin, server,
      send: async (messages) => {
        const up = new MockUpstream({ sse: buildTextSse("ok") });
        const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey, log: () => {} });
        proxies.push(proxy);
        const port = await proxy.listen(0);
        const body = JSON.stringify({ model: "claude-sonnet-4-5", stream: true, tools: [{ name: "shell", input_schema: { type: "object" } }], messages });
        const status = await new Promise<number>((resolve, reject) => {
          const r = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "user-agent": "opencode/latest/2.0.23/cli", "x-mandu-session-id": sessionKey } }, (res) => {
            res.resume();
            res.on("end", () => resolve(res.statusCode ?? 0));
          });
          r.on("error", reject);
          r.end(body);
        });
        return { status, forwarded: up.requests.map((q) => q.bodyText).join("\n") };
      },
    });
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    admin.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
}

/** A user move of a running `cat` (2.0.23's shapes): the call, its "moved"
 *  result, the user's move, and the notice with the output. */
function movedCat(file: string, output: string, id = "sh_10b1e7beb001nTybL5RlJg0o5t"): Message[] {
  const command = `sleep 5; cat ${file}`;
  return [
    { role: "user", content: [{ type: "text", text: "check the key" }] },
    { role: "assistant", content: [{ type: "tool_use", id: "toolu_slow", name: "shell", input: { command } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_slow", content: [{ type: "text", text: `Command moved to the background (shell ID: ${id}).\nOutput is streaming to: /h/.local/share/opencode/shell/x/${id}.out` }, { type: "text", text: "You will be notified automatically when the command finishes." }] }] },
    { role: "user", content: [{ type: "text", text: `User requested that active blocking work be moved to the background.\n\nBackgrounded work:\n- shell: ${command}\n` }] },
    { role: "assistant", content: [{ type: "text", text: "waiting" }] },
    { role: "user", content: [{ type: "text", text: `<shell id="${id}" state="completed" command="${command}">\n${output}\n</shell>`, cache_control: { type: "ephemeral" } }] },
  ];
}

/** The notice text as forwarded (the last user text starting with `<shell` / `<subagent`, or the stand-in's mask). */
function forwardedNotice(forwarded: string, at: number): string {
  const req = JSON.parse(forwarded) as { messages: Message[] };
  const c = req.messages[at]!.content;
  return typeof c === "string" ? c : String((c as Array<{ text?: string }>)[0]!.text);
}

test("ingress: a moved `cat` of the labelled secret reaches the model only as a symbol, inside OpenCode's own header and closing tag", async () => {
  await withStack("cat", async (s) => {
    const r = await s.send(movedCat(s.secretFile, API_KEY_BODY));
    assert.equal(r.status, 200);
    assert.ok(!r.forwarded.includes(CANARY), "INVARIANT: the moved output never reaches the model un-symbolized");
    const notice = forwardedNotice(r.forwarded, 5);
    assert.ok(notice.startsWith(`<shell id="sh_10b1e7beb001nTybL5RlJg0o5t" state="completed" command="sleep 5; cat ${s.secretFile}">\n`), notice);
    assert.ok(notice.endsWith("\n</shell>"), notice);
    assert.match(notice, SYMBOL_RE);
  });
});

test("history: the notice re-sent in the next request forwards byte for byte the same (one symbol, the cache stays warm)", async () => {
  await withStack("history", async (s) => {
    const turn1 = movedCat(s.secretFile, API_KEY_BODY);
    const a = await s.send(turn1);
    const turn2: Message[] = [...structuredClone(turn1),
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_after", name: "shell", input: { command: "echo after" } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_after", content: "after\n" }] }];
    // OpenCode moves cache_control to the newest block
    delete (turn2[5]!.content as Array<Record<string, unknown>>)[0]!["cache_control"];
    const b = await s.send(turn2);
    assert.ok(!a.forwarded.includes(CANARY) && !b.forwarded.includes(CANARY));
    assert.equal(forwardedNotice(b.forwarded, 5), forwardedNotice(a.forwarded, 5));
  });
});

test("the capture: the real 2.0.23 transcript of a user move, replayed verbatim, carries its secret only as a symbol", async () => {
  // The capture's `cat secret.txt` ran in /PROJ; the session's policy labels it.
  await withStack("capture", async (s) => {
    const msgs = structuredClone(capture.__background_move__.shell.lastRequestMessages);
    // make the secret a known one: a labelled read of the same file first
    const pre = await s.send([
      { role: "user", content: "read it" },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_pre", name: "read", input: { path: "/PROJ/secret.txt" } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_pre", content: "Read file /PROJ/secret.txt, lines 1-1\n1: API_KEY=sk-live-MOVED-SECRET-77" }] },
    ]);
    assert.ok(!pre.forwarded.includes("MOVED-SECRET-77"), "the labelled read is masked");
    const r = await s.send(msgs);
    assert.equal(r.status, 200);
    assert.ok(!r.forwarded.includes("MOVED-SECRET-77"), "INVARIANT: the captured moved output is masked");
    assert.match(r.forwarded, /<shell id=\\"sh_ID\\" state=\\"completed\\" command=\\"sleep 5; echo FGOUT-LINE; cat secret.txt\\">\\n\$MDU:/);
  }, ["/PROJ"]);
});

test("ingress: a moved subagent's answer carrying a registered secret value reaches the model only as a symbol", async () => {
  await withStack("subagent", async (s) => {
    // register the value: a labelled read of the file first
    await s.send([
      { role: "user", content: "read it" },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_r", name: "read", input: { path: s.secretFile } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_r", content: `Read file ${s.secretFile}, lines 1-1\n1: ${API_KEY_BODY.trim()}` }] },
    ]);
    const msgs = structuredClone(capture.__background_move__.subagent.lastRequestMessages);
    const notice = msgs.find((m) => m.role === "user" && Array.isArray(m.content) && String((m.content[0] as { text?: string }).text ?? "").startsWith("<subagent "))!;
    const block = (notice.content as Array<{ text: string }>)[0]!;
    block.text = block.text.replace("SUBAGENT-ANSWER sk-live-SUBSECRET-1", `the key is ${API_KEY_BODY.trim()}`);
    const r = await s.send(msgs);
    assert.equal(r.status, 200);
    assert.ok(!r.forwarded.includes(CANARY), "INVARIANT: the subagent's answer is masked");
    assert.match(r.forwarded, /<subagent sessionID=\\"ses_ID\\" state=\\"completed\\" description=\\"slow job\\">\\n\$MDU:/);
  });
});

test("unparsed: a notice no call claims is masked whole, whatever it says", async () => {
  await withStack("unparsed", async (s) => {
    const msgs = movedCat(s.secretFile, "nothing secret here");
    // the "moved" result names another id: no call claims the notice
    (msgs[2]!.content as Array<{ content: Array<{ text: string }> }>)[0]!.content[0]!.text = "Command moved to the background (shell ID: sh_other).";
    const r = await s.send(msgs);
    assert.equal(r.status, 200);
    const notice = forwardedNotice(r.forwarded, 5);
    assert.ok(!notice.includes("nothing secret here") && !notice.startsWith("<shell"), notice);
    assert.match(notice, /^\$MDU:nomodel_/);
  });
});

test("FAIL-CLOSED: the arbiter unreachable, a moved output carrying the secret never reaches the model raw", async () => {
  await withStack("down", async (s) => {
    s.real.close();
    await s.server.close();
    const r = await s.send(movedCat(s.secretFile, API_KEY_BODY));
    assert.ok(!r.forwarded.includes(CANARY), "INVARIANT: nothing carrying the secret was forwarded");
    assert.ok(r.status === 200 || r.status >= 500, `answered or refused (status ${r.status})`);
  });
});
