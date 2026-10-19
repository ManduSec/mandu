/**
 * agent-read-twin — plan 10 §11.8 over the REAL components: OpenClaw's
 * `read` of a registered secret file reaches the model as the structured
 * twin (keys visible, one symbol per secret value, no raw value), the way
 * Claude Code's `Read` of it does, through the real arbiter, its real IPC and
 * the PRODUCTION proxy wiring (`new ArbiterClientAdapter(new ArbiterClient
 * (sock))`, the proxy fetching the session's gate surface itself).
 *
 * Before (the item 1 VM run, 2026-09-28): the same read was masked whole,
 * one handle. Negatives: the raw file, and a twin with one value put back,
 * still reach the model as one symbol and no raw byte. And Claude Code's
 * `Read` of the twin of a `.env` with a long comment line is per key too
 * (plan 10 §11.8, a twin line is no fingerprint, 2026-10-05).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const STRIPE = "sk_live_read_twin_e2e_0123456789";
const DB_PW = "pg_read_twin_e2e_pw_987654";
const RAW = `PORT=3000\nSTRIPE_KEY=${STRIPE}\nDATABASE_URL=postgres://app:${DB_PW}@db:5432/prod\nLOG_LEVEL=info\n`;
const SYMBOL_RE = /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/g;

function post(port: number, body: string, session: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function readTurn(path: string, content: string, id: string): string {
  return JSON.stringify({
    model: "claude-sonnet-5",
    stream: true,
    messages: [
      { role: "user", content: "which keys are in the env file?" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "read", input: { path } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  });
}

test("OpenClaw `read` of a secret file's twin: keys visible, one symbol per value; the raw file or a tampered twin stays one symbol (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-read-twin-e2e-"));
  const env = join(tmp, ".env");
  writeFileSync(env, RAW);
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const real = new ArbiterClient(socketPath);
  await real.connect();
  const sessionKey = `read-twin-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  try {
    assert.equal((await real.setSessionSpec({ sessionKey, spec: "openclaw-agent", requestedBy: "agent-read-twin e2e" })).bound, "openclaw-agent");
    const reg = await real.registerSecret({ path: env, sessionKey });
    const twin = reg.twin as string;
    assert.ok(typeof twin === "string" && !twin.includes(STRIPE) && !twin.includes(DB_PW), "the twin holds no secret byte");

    const forwarded = async (content: string, id: string): Promise<string> => {
      const up = new MockUpstream({ sse: buildTextSse("ok") });
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey, log: () => {} });
      proxies.push(proxy);
      const r = await post(await proxy.listen(0), readTurn(env, content, id), sessionKey);
      assert.equal(r.status, 200, r.body);
      const sent = up.requests[up.requests.length - 1]!.json() as { messages: Array<{ content: unknown }> };
      const block = (sent.messages[2]!.content as Array<{ content: unknown }>)[0]!.content;
      return typeof block === "string" ? block : JSON.stringify(block);
    };

    // the twin: keys raw, each value its own field symbol
    const got = await forwarded(twin, "tu_rt_1");
    assert.match(got, /^PORT=3000\nSTRIPE_KEY='\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.STRIPE_KEY'\n/, got);
    assert.match(got, /DATABASE_URL='postgres:\/\/app:\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.DATABASE_URL\.password@db:5432\/prod'/, got);
    assert.match(got, /LOG_LEVEL=info/);
    assert.equal((got.match(SYMBOL_RE) ?? []).length, 2, "one symbol per secret value");
    assert.ok(!got.includes(STRIPE) && !got.includes(DB_PW));

    // an offset/limit piece with OpenClaw's continuation notice
    const line = twin.split("\n").find((l) => l.startsWith("STRIPE_KEY="))!;
    const piece = await forwarded(`${line}\n\n[2 more lines in file. Use offset=3 to continue.]`, "tu_rt_2");
    assert.ok(piece.startsWith(`${line}\n`), piece);

    // NEGATIVES: the raw file, and the twin with one value put back: one symbol, no raw byte
    for (const [content, id] of [[RAW, "tu_rt_raw"], [twin.replace(/\$MDU:[^\s']+\.STRIPE_KEY/, STRIPE), "tu_rt_tamper"]] as const) {
      const f = await forwarded(content, id);
      assert.ok(!f.includes(STRIPE) && !f.includes(DB_PW), f);
      assert.ok(!f.includes("PORT=3000"), `masked whole: ${f}`);
      assert.match(f, /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/);
    }
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

// Plan 10 §11.8, a twin line is no fingerprint (2026-10-05): a `.env` with a
// long NON-secret line (the demo's comment) gave that line as a fingerprint
// of the file's row, the twin carries it verbatim, and Claude Code's Read of
// the twin came back as ONE `$MDU:nomodel_Read[…]` instead of per key.
const COMMENT = "# fake values, made up by mandu demo";
const COMMENTED = `${COMMENT}\nSTRIPE_KEY=${STRIPE}\nDEBUG=1\n`;
const claudeRead = (text: string) => text.replace(/\n$/, "").split("\n").map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n");

function claudeReadTurn(path: string, content: string, id: string): string {
  return JSON.stringify({
    model: "claude-sonnet-5",
    stream: true,
    messages: [
      { role: "user", content: "which keys are in the env file?" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "Read", input: { file_path: path } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  });
}

test("Claude Code `Read` of a commented .env's twin: per key, the comment visible; the raw file and the value stay masked (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-read-twin-cm-"));
  const env = join(tmp, ".env");
  writeFileSync(env, COMMENTED);
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const real = new ArbiterClient(socketPath);
  await real.connect();
  const sessionKey = `read-twin-cm-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  try {
    assert.equal((await real.setSessionSpec({ sessionKey, spec: "claude-code", requestedBy: "agent-read-twin e2e" })).bound, "claude-code");
    const twin = (await real.registerSecret({ path: env, sessionKey })).twin as string;
    assert.ok(twin.startsWith(`${COMMENT}\n`) && !twin.includes(STRIPE), twin);

    const forwarded = async (content: string, id: string): Promise<string> => {
      const up = new MockUpstream({ sse: buildTextSse("ok") });
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey, log: () => {} });
      proxies.push(proxy);
      const r = await post(await proxy.listen(0), claudeReadTurn(env, content, id), sessionKey);
      assert.equal(r.status, 200, r.body);
      const sent = up.requests[up.requests.length - 1]!.json() as { messages: Array<{ content: unknown }> };
      const block = (sent.messages[2]!.content as Array<{ content: unknown }>)[0]!.content;
      return typeof block === "string" ? block : JSON.stringify(block);
    };

    const got = await forwarded(claudeRead(twin), "tu_cm_1");
    assert.ok(got.includes(COMMENT), `the comment is visible: ${got}`);
    assert.match(got, /STRIPE_KEY='\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.STRIPE_KEY'/, got);
    assert.match(got, /DEBUG=1/);
    assert.equal((got.match(SYMBOL_RE) ?? []).length, 1, "one symbol, the value's");
    assert.ok(!got.includes(STRIPE));

    // INVARIANT: the raw file, and the twin with the value put back, reach
    // the model masked whole, no raw byte.
    for (const [content, id] of [[claudeRead(COMMENTED), "tu_cm_raw"], [claudeRead(twin.replace(/'\$MDU:[^']+'/, STRIPE)), "tu_cm_tamper"]] as const) {
      const f = await forwarded(content, id);
      assert.ok(!f.includes(STRIPE), f);
      assert.ok(!f.includes("DEBUG=1"), `masked whole: ${f}`);
      assert.match(f, /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/);
    }

    // Review of !1604 (2026-10-17): the masked reads above each minted a
    // proxy `Read` row on the file's path, holding the file's bytes. Its
    // comment line was a line fingerprint (the twin-line exception covered
    // only the registry's base row), so every later Read of the twin hit
    // the value backstop and was masked whole: the file's Reads never
    // recovered (this assertion failed before). Such a row now takes the
    // same exception from the registered file's own twin. (The other half,
    // a proxy row shadowing the registration as the twin's base, is pinned
    // by arbiter's component exec-output-key-listing.test.ts.)
    const again = await forwarded(claudeRead(twin), "tu_cm_again");
    assert.ok(again.includes(COMMENT) && /DEBUG=1/.test(again), `per key after a masked read: ${again}`);
    assert.match(again, /STRIPE_KEY='\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.STRIPE_KEY'/, again);
    assert.ok(!again.includes(STRIPE));
    // and the raw file still comes back masked whole
    const rawAgain = await forwarded(claudeRead(COMMENTED), "tu_cm_raw_again");
    assert.ok(!rawAgain.includes(STRIPE) && !rawAgain.includes("DEBUG=1"), rawAgain);
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

// Plan 10 §2.4 (2026-10-09): a comment that REPEATS the secret value. The
// twin generator replaced only the value's own span, so the twin carried the
// value in the comment and the Read came back masked whole (no leak, no
// per-key view). Now every occurrence is replaced by the value's token.
test("Claude Code `Read` of a .env whose comment repeats the value: per key, the comment carries the token; no raw byte (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-read-twin-dupe-"));
  const env = join(tmp, ".env");
  const DUPE = `# rotated from ${STRIPE} last week`;
  const RAW_DUPE = `${DUPE}\nSTRIPE_KEY=${STRIPE}\nDEBUG=1\n`;
  writeFileSync(env, RAW_DUPE);
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const real = new ArbiterClient(socketPath);
  await real.connect();
  const sessionKey = `read-twin-dupe-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  try {
    assert.equal((await real.setSessionSpec({ sessionKey, spec: "claude-code", requestedBy: "agent-read-twin e2e" })).bound, "claude-code");
    const twin = (await real.registerSecret({ path: env, sessionKey })).twin as string;
    assert.ok(!twin.includes(STRIPE), twin);

    const forwarded = async (content: string, id: string): Promise<string> => {
      const up = new MockUpstream({ sse: buildTextSse("ok") });
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey, log: () => {} });
      proxies.push(proxy);
      const r = await post(await proxy.listen(0), claudeReadTurn(env, content, id), sessionKey);
      assert.equal(r.status, 200, r.body);
      const sent = up.requests[up.requests.length - 1]!.json() as { messages: Array<{ content: unknown }> };
      const block = (sent.messages[2]!.content as Array<{ content: unknown }>)[0]!.content;
      return typeof block === "string" ? block : JSON.stringify(block);
    };

    // INVARIANT: no raw byte of the value reaches the model, and the view is per key.
    const got = await forwarded(claudeRead(twin), "tu_dupe_1");
    assert.ok(!got.includes(STRIPE), got);
    assert.match(got, /# rotated from \$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.STRIPE_KEY last week/, got);
    assert.match(got, /STRIPE_KEY='\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.STRIPE_KEY'/, got);
    assert.match(got, /DEBUG=1/, "per key, not masked whole");

    // The raw file still reaches the model masked whole.
    const raw = await forwarded(claudeRead(RAW_DUPE), "tu_dupe_raw");
    assert.ok(!raw.includes(STRIPE) && !raw.includes("DEBUG=1"), raw);
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

// 2026-10-11, the OpenClaw tour walk: OpenClaw's model reads `.env` by a
// RELATIVE path (`read {path: ".env"}`). The twin was masked whole (one
// handle), so the Stripe key could not be used on its own and the model
// pulled it out of `.env` with a shell command whose output (naming the
// secret file) was masked whole too, Mandu's own "stopped, ask the user"
// answer included. With the launch directory the launcher names the proxy
// (MANDU_AGENT_CWD), the relative read is the same per-key twin as an
// absolute one; without it, or for the raw file, it stays one handle. The
// same walk found the next turn's history cut by OpenClaw's own redaction
// (anthropic-proxy openclaw-redaction.ts): pinned below too.
test("OpenClaw `read` of `.env` by a relative path: per key with the launch directory (and on the next turn, through OpenClaw's history redaction), one handle without it; the raw file stays one handle (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-read-twin-rel-"));
  const env = join(tmp, ".env");
  writeFileSync(env, RAW);
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const real = new ArbiterClient(socketPath);
  await real.connect();
  const sessionKey = `read-twin-rel-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  try {
    assert.equal((await real.setSessionSpec({ sessionKey, spec: "openclaw-agent", requestedBy: "agent-read-twin e2e" })).bound, "openclaw-agent");
    const twin = (await real.registerSecret({ path: env, sessionKey })).twin as string;
    assert.ok(typeof twin === "string" && !twin.includes(STRIPE), twin);

    const forwarded = async (content: string, id: string, agentCwd?: string): Promise<string> => {
      const up = new MockUpstream({ sse: buildTextSse("ok") });
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey, log: () => {}, ...(agentCwd ? { agentCwd } : {}) });
      proxies.push(proxy);
      const r = await post(await proxy.listen(0), readTurn(".env", content, id), sessionKey);
      assert.equal(r.status, 200, r.body);
      const sent = up.requests[up.requests.length - 1]!.json() as { messages: Array<{ content: unknown }> };
      const block = (sent.messages[2]!.content as Array<{ content: unknown }>)[0]!.content;
      return typeof block === "string" ? block : JSON.stringify(block);
    };

    // with the launch directory: keys raw, each value its own field symbol
    const got = await forwarded(twin, "tu_rel_1", tmp);
    assert.match(got, /^PORT=3000\nSTRIPE_KEY='\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.STRIPE_KEY'\n/, got);
    assert.equal((got.match(SYMBOL_RE) ?? []).length, 2, "one symbol per secret value");
    assert.ok(!got.includes(STRIPE) && !got.includes(DB_PW));

    // The next request re-sends that result in the history. OpenClaw keeps
    // tool results through its own redaction (openclaw src/logging/redact.ts
    // `maskToken`: first 6, `…`, last 4), so it comes back with each
    // placeholder cut: live (2026-10-11) the arbiter then masked it whole,
    // "after the fact". The proxy that forwarded it puts it back: still per
    // key. A proxy that never saw it and finds no record of it in the
    // arbiter (these proxies have no human socket, so none was recorded)
    // masks it whole; a relaunch with the record restores it
    // (openclaw-redaction-relaunch.test.ts).
    {
      const maskToken = (v: string): string => (v.length < 18 ? "***" : `${v.slice(0, 6)}…${v.slice(-4)}`);
      const redacted = twin.replace(/\$MDU:[^\s'@]+/g, (t) => maskToken(t));
      assert.ok(redacted !== twin && redacted.includes("$MDU:n…_KEY"), redacted);
      const history = (content: string) => {
        const first = JSON.parse(readTurn(".env", content, "tu_rel_h")) as { messages: unknown[] };
        return { first, second: { ...first, messages: [...first.messages, { role: "assistant", content: "It has PORT, STRIPE_KEY and DATABASE_URL." }, { role: "user", content: "Use the Stripe key to list my customers with curl." }] } };
      };
      const lastResult = (up: MockUpstream): string => {
        const sent = up.requests[up.requests.length - 1]!.json() as { messages: Array<{ content: unknown }> };
        const block = (sent.messages[2]!.content as Array<{ content: unknown }>)[0]!.content;
        return typeof block === "string" ? block : JSON.stringify(block);
      };
      const up = new MockUpstream({ sse: buildTextSse("ok") });
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey, log: () => {}, agentCwd: tmp });
      proxies.push(proxy);
      const port = await proxy.listen(0);
      assert.equal((await post(port, JSON.stringify(history(twin).first), sessionKey)).status, 200);
      assert.equal((await post(port, JSON.stringify(history(redacted).second), sessionKey)).status, 200);
      const again = lastResult(up);
      assert.match(again, /^PORT=3000\nSTRIPE_KEY='\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.STRIPE_KEY'\n/, `the history keeps the per-key twin: ${again}`);
      assert.ok(!again.includes(STRIPE) && !again.includes(DB_PW));

      const up2 = new MockUpstream({ sse: buildTextSse("ok") });
      const fresh = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up2.fetcher, sessionKey, log: () => {}, agentCwd: tmp });
      proxies.push(fresh);
      assert.equal((await post(await fresh.listen(0), JSON.stringify(history(redacted).second), sessionKey)).status, 200);
      const resumed = lastResult(up2);
      assert.ok(!resumed.includes(STRIPE) && !resumed.includes(DB_PW) && !resumed.includes("PORT=3000"), `masked whole: ${resumed}`);
    }

    // INVARIANT: the raw file and a tampered twin by the same relative path,
    // and the twin with no launch directory, reach the model as one handle
    const cases: Array<[string, string, string | undefined]> = [
      [RAW, "tu_rel_raw", tmp],
      [twin.replace(/\$MDU:[^\s']+\.STRIPE_KEY/, STRIPE), "tu_rel_tamper", tmp],
      [twin, "tu_rel_nocwd", undefined],
    ];
    for (const [content, id, cwd] of cases) {
      const f = await forwarded(content, id, cwd);
      assert.ok(!f.includes(STRIPE) && !f.includes(DB_PW), `CONFIDENTIALITY VIOLATION: ${f}`);
      assert.ok(!f.includes("PORT=3000"), `masked whole: ${f}`);
      assert.match(f, /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/);
    }
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
