/**
 * twin-comment-credentials — the structured twin's credential belt and its
 * glued-secret lines (plan 10 §2.4, §11.8, 2026-10-17) over the REAL
 * components: a real ArbiterServer in `secrets`, the real anthropic-proxy
 * over HTTP in its production wiring (`new ArbiterClientAdapter(data,
 * human)`), a mock model behind it, and the guard's records on the human
 * socket.
 *
 * Found by an adversarial review (2026-10-17, P0): a `.env` whose comment
 * held an old live key (`# OLD_STRIPE_KEY=sk_live_51Old…`) twinned with the
 * key raw. Every program is served the twin, so a command in a clean tree
 * that does not name the file (`base64 ./.e*`, `cut -c9- ./.e*`) handed the
 * model the key in a form the verbatim value backstop never matched (0 hits
 * for base64, reversed, split across lines, or without its `sk_live_`).
 *
 * THE ORACLE: no request to the model holds the old key in any of those
 * encodings, through Claude Code's Read of the file, `cat` of it, or a
 * command that does not name it; nor does a password in a trailing comment
 * (`PORT=4242 # backup …`, review of !1621). And a short value glued inside another
 * line's word (`MODE=qzxish` beside `DB_PASS2=qzx`) reaches the model through
 * no Read or `cat` of the twin; another line and the key names still do.
 *
 * Unit and component twins: arbiter `twin-comment-credentials.test.ts`.
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
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const OLD = "sk_live_51OldKeyStackE2EAbCdEfGhIjKlMnOp";
const NEW = "sk_live_51NewKeyStackE2EZyXwVuTsRqPoNmLk";
/** A random-looking backup password in a TRAILING comment (review of !1621). */
const BACKUP = "Tq7vZ2pX9kLm4Rw8Hn3B";
const COMMENTED = `# OLD_STRIPE_KEY=${OLD}\nSTRIPE_SECRET_KEY=${NEW}\nPORT=4242 # backup ${BACKUP}\n`;
const GLUED_SECRET = "qzx";
const GLUED = `STRIPE_SECRET_KEY=${NEW}\nDB_PASS2=${GLUED_SECRET}\nMODE=${GLUED_SECRET}ish\nPORT=4242\n`;

/** Claude Code's Read rendering: a right-aligned line number and a tab. */
const claudeRead = (text: string) => text.replace(/\n$/, "").split("\n").map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n");

/** Every form of `secret` the reviewer tried that held it (verbatim, minus
 *  its `sk_live_`, reversed, hex, a 12-character window of its body), found
 *  in `wire` as sent, with its JSON-escaped line breaks and all whitespace
 *  taken out (split across lines), or in any base64 run of it decoded. */
function leaks(wire: string, secret: string): string[] {
  const body = secret.replace(/^sk_live_/, "");
  const forms = [secret, body, [...secret].reverse().join(""), [...body].reverse().join(""), Buffer.from(secret).toString("hex"), body.slice(4, 16)];
  const views = [wire, wire.replace(/\\[nrt]|\s/g, "")];
  for (const m of wire.matchAll(/[A-Za-z0-9+/]{16,}={0,2}/g)) views.push(Buffer.from(m[0], "base64").toString("latin1"));
  return forms.filter((f) => views.some((v) => v.includes(f)));
}

async function stack(name: string, raw: string) {
  const tmp = mkdtempSync(join(tmpdir(), `mandu-twin-belt-${name}-`));
  const ws = join(tmp, "shop-app");
  mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, raw);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(humanSock); // the guard reports on the human socket (plan 13 D9)
  const session = `twin-belt-${name}-${process.pid}`;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), await open(humanSock)), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  let n = 0;
  /** One tool call and its result through the proxy; what the model got. */
  const call = async (tool: "Read" | "Bash", input: Record<string, string>, output: string): Promise<string> => {
    const id = `toolu_tb_${name}_${++n}`;
    if (tool === "Bash") {
      // The guard's record of a clean run: the program opened the file and
      // was served the twin (no raw read), and the call is bound to it.
      const procKey = `tb-${name}-${n}`;
      const d = await guard.decideSecretOpen({ path: env, exe: "/usr/bin/cat", isAgent: false, exeSystem: true, openerEnv: [], procKey, session });
      assert.equal(d.verdict, "twin");
      await guard.recordCallRoot({ callId: id, procKey, session });
    }
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5", stream: true, max_tokens: 256,
        tools: [{ name: tool, input_schema: { type: "object" } }],
        messages: [
          { role: "user", content: "The payments call fails with a 401. What is in the env file?" },
          { role: "assistant", content: [{ type: "tool_use", id, name: tool, input }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
        ],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    const body = upstream.requests.at(-1)!.json() as { messages: Array<{ content: Array<{ content?: unknown }> }> };
    return String(body.messages[2]!.content[0]!.content);
  };
  return {
    env, guard, session, call,
    wire: () => upstream.requests.map((r) => r.bodyText).join("\n"),
    async close() {
      await proxy.close();
      for (const c of clients) c.close();
      await server.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

test("Claude Code: a .env's commented-out old key reaches the model in no encoding, by Read, `cat`, or a command not naming the file (`base64 ./.e*`, `cut -c9- ./.e*`); the twin still reads per key (secrets axes, explicit)", async () => {
  const s = await stack("comment", COMMENTED);
  try {
    const reg = await s.guard.registerSecret({ path: s.env, sessionKey: s.session });
    const twin = reg.twin as string;
    assert.ok(typeof twin === "string", JSON.stringify(reg));
    assert.deepEqual(leaks(twin, OLD), [], `the twin every program is served:\n${twin}`);
    assert.deepEqual(leaks(twin, BACKUP), [], `the twin every program is served:\n${twin}`);

    // Read: the structured read-twin rule, per key.
    const read = await s.call("Read", { file_path: s.env }, claudeRead(twin));
    assert.equal(read, claudeRead(twin), "the Read of the twin reaches the model as it is");
    assert.match(read, /# OLD_STRIPE_KEY=\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.cred\.OLD_STRIPE_KEY/);

    // `cat .env`: the structured exec-twin rule (Claude Code's Bash trims the last newline).
    const cat = await s.call("Bash", { command: `cat ${s.env}` }, twin.replace(/\n$/, ""));
    assert.ok(cat.startsWith(twin.replace(/\n$/, "")), cat);

    // Commands that do not name the file: the program read the twin, the
    // output carries whatever transform of it the program made.
    await s.call("Bash", { command: "cd shop-app && base64 ./.e*" }, Buffer.from(twin).toString("base64"));
    await s.call("Bash", { command: "cd shop-app && cut -c9- ./.e*" }, twin.split("\n").map((l) => l.slice(8)).join("\n"));
    await s.call("Bash", { command: "cd shop-app && rev ./.e*" }, twin.split("\n").map((l) => [...l].reverse().join("")).join("\n"));
    await s.call("Bash", { command: "cd shop-app && fold -w7 ./.e*" }, twin.split("\n").flatMap((l) => l.match(/.{1,7}/g) ?? [""]).join("\n"));

    // THE ORACLE: neither the old key nor the live one, in any form.
    const wire = s.wire();
    assert.deepEqual(leaks(wire, OLD), [], "the model got the old key");
    assert.deepEqual(leaks(wire, BACKUP), [], "the model got the trailing comment's password");
    assert.deepEqual(leaks(wire, NEW), [], "the model got the live key");
  } finally {
    await s.close();
  }
});

test("Claude Code: a short value glued inside another line's word reaches the model through no Read or `cat` of the twin; `grep` of another line and the key names still do (secrets axes, explicit)", async () => {
  const s = await stack("glued", GLUED);
  try {
    const reg = await s.guard.registerSecret({ path: s.env, sessionKey: s.session });
    const twin = reg.twin as string;
    assert.ok(twin.includes(`\nMODE=${GLUED_SECRET}ish\n`), "the twin programs read keeps MODE as written");

    const read = await s.call("Read", { file_path: s.env }, claudeRead(twin));
    assert.match(read, /^\$MDU:nomodel_[A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/, `the Read is masked: ${read}`);
    const cat = await s.call("Bash", { command: `cat ${s.env}` }, twin.replace(/\n$/, ""));
    assert.match(cat, /^\$MDU:nomodel_[A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/, `the cat is masked: ${cat}`);
    const grepMode = await s.call("Bash", { command: `grep MODE ${s.env}` }, `MODE=${GLUED_SECRET}ish`);
    assert.match(grepMode, /^\$MDU:nomodel_[A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/, `grep MODE is masked: ${grepMode}`);

    // Ordinary lines and the key names pass.
    const line = twin.split("\n").find((l) => l.startsWith("STRIPE_SECRET_KEY="))!;
    const grepKey = await s.call("Bash", { command: `grep STRIPE ${s.env}` }, line);
    assert.ok(grepKey.startsWith(line), grepKey);
    const keys = await s.call("Bash", { command: `cut -d= -f1 ${s.env}` }, "STRIPE_SECRET_KEY\nDB_PASS2\nMODE\nPORT");
    assert.ok(keys.startsWith("STRIPE_SECRET_KEY\nDB_PASS2\nMODE\nPORT"), keys);

    // THE ORACLE: the glued value, and the live key, in no request.
    const wire = s.wire();
    assert.ok(!wire.includes(GLUED_SECRET), "the model got the glued value");
    assert.deepEqual(leaks(wire, NEW), [], "the model got the live key");
  } finally {
    await s.close();
  }
});
