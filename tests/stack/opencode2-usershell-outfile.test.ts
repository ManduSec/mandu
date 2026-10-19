/**
 * opencode2-usershell-outfile — two more ways OpenCode 2 (2.0.23) puts a
 * program's output in front of the model, over the REAL arbiter, its REAL IPC
 * and the PRODUCTION proxy wiring, in the `secrets` mode (supported-agents.md
 * §2.3 items 7 and 9; interceptors/anthropic-proxy/src/opencode-background.ts,
 * arbiter/policy/session-path-labels.ts).
 *
 *   the user's shell   `POST /api/session/:id/shell` (the TUI's `!cmd`)
 *                      puts "The following shell command was executed by the
 *                      user:" + a `<shell …>output</shell>` notice in the next
 *                      request as a user text: a `cat` of the labelled secret
 *                      reaches the model only as a symbol (it is program
 *                      output, read as a shell result, not the human's text);
 *                      the captured 2.0.23 notice replayed is masked too;
 *   the output file    a moved shell's result names the file its output
 *                      streams to; once the proxy forwarded that result, a
 *                      `read{path}` of the file and a `shell` `cat` of it
 *                      reach the model only as symbols. CONTROL: before the
 *                      result was forwarded, the same read went out raw (the
 *                      gap this closes), for a file no catalog rule knows;
 *   the catalog        §2.3 item 10: an OLD output file in OpenCode's data
 *                      directory (default or another XDG_DATA_HOME) is masked
 *                      on a fresh arbiter with no moved result in sight (the
 *                      real-binary form: tests/sandbox/guard/
 *                      opencode2-shell-output.test.ts).
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

type Message = { role: string; content: string | Array<Record<string, unknown>> };
const here = dirname(fileURLToPath(import.meta.url));
const capture = JSON.parse(readFileSync(join(here, "..", "..", "arbiter", "test", "fixtures", "opencode2-tool-surface-2026-10-05.json"), "utf8")) as {
  __user_shell__: { notices: string[] };
};

const SECRET_LINE = "ACME_API_KEY=sk-live-OUTFILE-CANARY-6620";
const CANARY = "OUTFILE-CANARY-6620";
const US_LINE = "The following shell command was executed by the user:\n";

interface Stack {
  tmp: string;
  secretFile: string;
  sessionKey: string;
  real: ArbiterClient;
  send: (messages: Message[]) => Promise<{ status: number; forwarded: string }>;
}

async function withStack(name: string, fn: (s: Stack) => Promise<void>, extraLabels: string[] = []): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-oc2-outfile-"));
  const vault = join(tmp, "home", "vault");
  mkdirSync(vault, { recursive: true });
  const secretFile = join(vault, "api.env");
  writeFileSync(secretFile, `${SECRET_LINE}\n`);
  const server = new ArbiterServer({
    socketPath: join(tmp, "arbiter.sock"), adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [vault, ...extraLabels].map((path) => ({ path, level: "no-model" })) } as never,
  });
  await server.listen();
  const real = new ArbiterClient(join(tmp, "arbiter.sock"));
  await real.connect();
  const sessionKey = `oc2-outfile-${name}-${process.pid}`;
  assert.equal((await real.setSessionSpec({ sessionKey, spec: "opencode", requestedBy: "opencode2-usershell-outfile e2e" })).bound, "opencode");
  const proxies: AnthropicProxy[] = [];
  try {
    await fn({
      tmp, secretFile, sessionKey, real,
      send: async (messages) => {
        const up = new MockUpstream({ sse: buildTextSse("ok") });
        const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey, log: () => {} });
        proxies.push(proxy);
        const port = await proxy.listen(0);
        const body = JSON.stringify({ model: "claude-sonnet-4-5", stream: true, tools: [{ name: "shell", input_schema: { type: "object" } }, { name: "read", input_schema: { type: "object" } }], messages });
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
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
}

const userShell = (command: string, output: string, id = "sh_10b3955f7001ZS51Eb0iNBKE9V"): string =>
  `${US_LINE}<shell id="${id}" state="completed" command="${command}">\n${output}\n</shell>`;

test("the user's shell: a `!cat` of the labelled secret reaches the model only as a symbol, inside OpenCode's own line and tags", async () => {
  await withStack("usershell", async (s) => {
    const r = await s.send([
      { role: "user", content: [{ type: "text", text: userShell(`cat ${s.secretFile}`, `${SECRET_LINE}\n`) }] },
      { role: "user", content: [{ type: "text", text: "what was that?", cache_control: { type: "ephemeral" } }] },
    ]);
    assert.equal(r.status, 200);
    assert.ok(!r.forwarded.includes(CANARY), "INVARIANT: the user shell's output never reaches the model un-symbolized");
    const sent = JSON.parse(r.forwarded) as { messages: Message[] };
    const text = String((sent.messages[0]!.content as Array<{ text: string }>)[0]!.text);
    assert.ok(text.startsWith(`${US_LINE}<shell id="sh_10b3955f7001ZS51Eb0iNBKE9V" state="completed" command="cat ${s.secretFile}">\n$MDU:`), text);
    assert.ok(text.endsWith("\n</shell>"));
    assert.equal(String((sent.messages[1]!.content as Array<{ text: string }>)[0]!.text), "what was that?", "the human's own text is untouched");
  });
});

test("the user's shell: the captured 2.0.23 notice (`cat secret.txt` in the project), replayed verbatim, is masked once its value is a known secret", async () => {
  await withStack("usershell-capture", async (s) => {
    const notice = capture.__user_shell__.notices[0]!;
    assert.ok(notice.includes("USERSHELL-SECRET-91"));
    // the file the capture read, labelled and read once (the value is registered)
    const pre = await s.send([
      { role: "user", content: "read it" },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_pre", name: "read", input: { path: "/PROJ/secret.txt" } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_pre", content: "Read file /PROJ/secret.txt, lines 1-1\n1: API_KEY=sk-live-USERSHELL-SECRET-91" }] },
    ]);
    assert.ok(!pre.forwarded.includes("USERSHELL-SECRET-91"));
    const r = await s.send([{ role: "user", content: [{ type: "text", text: notice }] }, { role: "user", content: "go" }]);
    assert.equal(r.status, 200);
    assert.ok(!r.forwarded.includes("USERSHELL-SECRET-91"), "INVARIANT: the captured user-shell output is masked");
  }, ["/PROJ"]);
});

/** A moved `cat` (2.0.23's shapes) whose result names `out` as its output file. */
function moved(secretFile: string, out: string): Message[] {
  return [
    { role: "user", content: [{ type: "text", text: "check the key" }] },
    { role: "assistant", content: [{ type: "tool_use", id: "toolu_slow", name: "shell", input: { command: `sleep 30; cat ${secretFile}` } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_slow", content: [
      { type: "text", text: `Command moved to the background (shell ID: sh_10b1e7beb001nTybL5RlJg0o5t).\nOutput is streaming to: ${out}` },
      { type: "text", text: "You will be notified automatically when the command finishes." },
    ] }] },
  ];
}
const readOut = (out: string): Message[] => [
  { role: "assistant", content: [{ type: "tool_use", id: "toolu_read", name: "read", input: { path: out } }] },
  { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_read", content: `Read file ${out}, lines 1-1\n1: ${SECRET_LINE}` }] },
];
const catOut = (out: string): Message[] => [
  { role: "assistant", content: [{ type: "tool_use", id: "toolu_cat", name: "shell", input: { command: `cat ${out}` } }] },
  { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_cat", content: `${SECRET_LINE}\n` }] },
];

test("the session label (item 7): a moved result's output file the catalog does not know is labelled when the result is forwarded; a read{path} and a shell cat of it then reach the model only as symbols; CONTROL: before, the read went out raw", async () => {
  // A place no catalog rule knows (a future layout): only the session label covers it.
  const place = (tmp: string) => join(tmp, "agent-out", "job-17", "output.log");
  await withStack("outfile", async (s) => {
    const out = place(s.tmp);
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, `${SECRET_LINE}\n`);
    const control = await s.send([{ role: "user", content: "read it" }, ...readOut(out)]);
    assert.ok(control.forwarded.includes(CANARY), "control: the unlabelled output file was read raw (the gap)");
    assert.equal((await s.real.pathLevel(out)).level, "public");
  });
  await withStack("outfile-fixed", async (s) => {
    const out = place(s.tmp);
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, `${SECRET_LINE}\n`);
    const first = await s.send(moved(s.secretFile, out));
    assert.equal(first.status, 200);
    assert.equal((await s.real.pathLevel(out)).level, "no-model", "the proxy labelled the file for the session");
    const read = await s.send([...moved(s.secretFile, out), ...readOut(out)]);
    assert.ok(!read.forwarded.includes(CANARY), "INVARIANT: the read of the output file is masked");
    const cat = await s.send([...moved(s.secretFile, out), ...catOut(out)]);
    assert.ok(!cat.forwarded.includes(CANARY), "INVARIANT: a shell cat of the output file is masked");
  });
});

test("the catalog (item 10): an OLD output file in OpenCode's data directory (an earlier run, a fresh arbiter, no moved result in the conversation) reaches the model only masked, via read{path} and via shell cat, at the default location and under another XDG_DATA_HOME", async () => {
  for (const where of ["default", "xdg"] as const) {
    await withStack(`catalog-${where}`, async (s) => {
      const data = where === "default" ? join(s.tmp, "home", ".local", "share", "opencode") : join(s.tmp, "xdg-data", "opencode");
      const out = join(data, "shell", "f2c72c87b7edac3b8b2e41eed399fa7eec2ecc0f", "sh_10b1e8fb1001A0B3HmJH0bzs8n.out");
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, `${SECRET_LINE}\n`);
      assert.equal((await s.real.pathLevel(out)).level, "no-model", `${where}: a catalog location`);
      const read = await s.send([{ role: "user", content: "read it" }, ...readOut(out)]);
      assert.ok(!read.forwarded.includes(CANARY), `INVARIANT (${where}): the read of the old output file is masked`);
      const cat = await s.send([{ role: "user", content: "cat it" }, ...catOut(out)]);
      assert.ok(!cat.forwarded.includes(CANARY), `INVARIANT (${where}): a shell cat of the old output file is masked`);
      const db = join(data, "opencode.db");
      assert.equal((await s.real.pathLevel(db)).level, "no-model", `${where}: the session database too`);
    });
  }
});
