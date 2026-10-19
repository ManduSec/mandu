/**
 * auth-substitution — an agent's own key file twinned, and its key put back
 * in the auth header at the model proxy (agent-sign-in.md §3), over the REAL
 * components: a real ArbiterServer, the launcher's grant on the human
 * socket, the anthropic-proxy with its PRODUCTION adapter
 * (`new ArbiterClientAdapter(new ArbiterClient(data), new ArbiterClient(human))`)
 * and scripted upstreams (no network). The oracle: the key leaves only in
 * the auth header of a request to the host the launch granted it, on both
 * wires; it never enters a request body (the model's context), and every
 * other case sends the placeholder (the provider would answer 401):
 *
 *   granted        x-api-key to the anthropic upstream, Bearer to the openai
 *                  route: the real key in the header, the body's symbols and
 *                  the shell's read of the twin kept as placeholders;
 *   cross / other  the anthropic key toward the openai host, the extension's
 *                  token (never granted), and an upstream nobody granted;
 *   plain HTTP     an https grant over a plain-HTTP upstream (the scheme rule);
 *   data socket    a grant asked from the agent's world is refused, and binds
 *                  nothing;
 *   arbiter gone   the placeholder is relayed;
 *   restart        an arbiter restarted under the live launch takes its grant
 *                  back from mandu.db (the key keeps working); an ended
 *                  launch's grant is not taken back (§3.2 item 4).
 *
 * Made-up keys. Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiAdapter, type RealArbiterClient as OpenAiRealClient } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { buildTextSse as openAiTextSse } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

interface Seen { origin: string; path: string; headers: Record<string, string | string[] | undefined>; body: string }

/** A scripted upstream: records the request, answers one text turn on the
 *  wire its path names. */
function scripted(origin: string, seen: Seen[]): UpstreamFetcher {
  return async ({ path, headers, body }) => {
    seen.push({ origin, path, headers: { ...headers }, body: body.toString("utf8") });
    const chat = /chat\/completions/.test(path);
    const text = chat
      ? `data: ${JSON.stringify({ id: "c", object: "chat.completion.chunk", created: 1, model: "gpt-4o", choices: [{ index: 0, delta: { content: "ok" }, finish_reason: "stop" }] })}\n\ndata: [DONE]\n\n`
      : /\/messages/.test(path)
        ? [
            ["message_start", { type: "message_start", message: { id: "m", type: "message", role: "assistant", model: "claude-test", content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } } }],
            ["message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } }],
            ["message_stop", { type: "message_stop" }],
          ].map(([e, d]) => `event: ${e}\ndata: ${JSON.stringify(d)}\n\n`).join("")
        : JSON.stringify({ data: [] });
    return { status: 200, headers: { "content-type": chat || /\/messages/.test(path) ? "text/event-stream" : "application/json" }, body: Readable.from([Buffer.from(text)]) };
  };
}

function send(port: number, method: string, path: string, headers: Record<string, string>, body?: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, method, path, headers: { "content-type": "application/json", ...headers } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    r.on("error", reject);
    if (body !== undefined) r.write(body);
    r.end();
  });
}

const fieldOf = (twin: string, field: string): string => {
  const m = new RegExp(`^${field}: (\\$MDU:\\S+)$`, "m").exec(twin);
  assert.ok(m, `${field} in the twin:\n${twin}`);
  return m![1]!;
};

test("the agent's own key leaves only in the auth header to the granted host, on both wires; every other case sends the placeholder", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-auth-subst-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, ".config", "goose"), { recursive: true });
  const file = join(home, ".config", "goose", "secrets.yaml");
  const akey = `sk-ant-api03-${randomBytes(24).toString("hex")}-MANDUFAKE`;
  const okey = `sk-proj-${randomBytes(24).toString("hex")}-MANDUFAKE`;
  const gh = `ghp_${randomBytes(18).toString("hex")}`;
  writeFileSync(file, `ANTHROPIC_API_KEY: ${akey}\nOPENAI_API_KEY: ${okey}\nGITHUB_PERSONAL_ACCESS_TOKEN: ${gh}\n`, { mode: 0o600 });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  let server: ArbiterServer | null = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const launcher = new ArbiterClient(humanPath); await launcher.connect();
  const agentWorld = new ArbiterClient(socketPath); await agentWorld.connect();
  const data: RealArbiterClient = new ArbiterClient(socketPath); await data.connect();
  const human = new ArbiterClient(humanPath); await human.connect();
  const adapter = new ArbiterClientAdapter(data, human);
  const seen: Seen[] = [];
  const proxies: AnthropicProxy[] = [];
  const start = async (origin: string, openai?: string): Promise<number> => {
    const p = new AnthropicProxy({
      arbiter: adapter, sessionKey: "s-auth", log: () => {},
      upstreamOrigin: origin, upstream: scripted(origin, seen),
      ...(openai ? { openaiUpstreams: { openai }, openaiFetcher: () => scripted(openai, seen) } : {}),
    });
    proxies.push(p);
    return p.listen(0);
  };
  try {
    // The launch: the grant first (human plane), then the registration.
    const g = await launcher.registerAuthGrant(file, [
      { field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true },
      { field: "OPENAI_API_KEY", host: "api.openai.com", https: true },
    ]);
    assert.deepEqual(g, { granted: 2 });
    // The agent's world cannot grant: the op is human-plane only.
    await assert.rejects(agentWorld.registerAuthGrant(file, [{ field: "GITHUB_PERSONAL_ACCESS_TOKEN", host: "evil.example", https: true }]), /human-plane/);
    await assert.rejects(agentWorld.registerAuthGrant(file, [{ field: "ANTHROPIC_API_KEY", host: "evil.example", https: true }]), /human-plane/);
    const reg = await launcher.registerSecret({ path: file, home });
    assert.ok(reg.twin, JSON.stringify(reg));
    const twin = reg.twin!;
    for (const v of [akey, okey, gh]) assert.ok(!twin.includes(v), "the twin holds no value");
    const asym = fieldOf(twin, "ANTHROPIC_API_KEY");
    const osym = fieldOf(twin, "OPENAI_API_KEY");
    const gsym = fieldOf(twin, "GITHUB_PERSONAL_ACCESS_TOKEN");

    const port = await start("https://api.anthropic.com", "https://api.openai.com/v1");
    // A turn whose context holds the twin the agent read and the symbol.
    const messages = JSON.stringify({
      model: "claude-test", stream: true,
      messages: [
        { role: "user", content: `use ${asym}` },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_cat", name: "shell", input: { command: "cat ~/.config/goose/secrets.yaml" } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_cat", content: twin }] },
      ],
    });
    assert.equal(await send(port, "POST", "/v1/messages", { "x-api-key": asym }, messages), 200);
    const m = seen.at(-1)!;
    assert.equal(m.origin, "https://api.anthropic.com");
    assert.equal(m.headers["x-api-key"], akey, "the granted key in x-api-key");
    // The openai route: Bearer, its own host.
    const chat = JSON.stringify({ model: "gpt-4o", stream: true, messages: [{ role: "user", content: `key ${osym}` }] });
    assert.equal(await send(port, "POST", "/_mandu/openai/openai/chat/completions", { authorization: `Bearer ${osym}` }, chat), 200);
    assert.equal(seen.at(-1)!.headers["authorization"], `Bearer ${okey}`, "the granted key as Bearer");
    // The relay (GET /models) too.
    await send(port, "GET", "/_mandu/openai/openai/models", { authorization: `Bearer ${osym}` });
    assert.equal(seen.at(-1)!.headers["authorization"], `Bearer ${okey}`);

    // Cross: the anthropic key toward the openai host, the openai key toward
    // the anthropic host, the extension's token anywhere: placeholders.
    await send(port, "POST", "/_mandu/openai/openai/chat/completions", { authorization: `Bearer ${asym}` }, chat);
    assert.equal(seen.at(-1)!.headers["authorization"], `Bearer ${asym}`);
    await send(port, "POST", "/v1/messages", { "x-api-key": osym }, messages);
    assert.equal(seen.at(-1)!.headers["x-api-key"], osym);
    await send(port, "POST", "/v1/messages", { "x-api-key": gsym }, messages);
    assert.equal(seen.at(-1)!.headers["x-api-key"], gsym);
    // Another header, even holding the granted symbol, is relayed as written.
    await send(port, "POST", "/v1/messages", { "x-api-key": asym, "anthropic-beta": asym }, messages);
    assert.equal(seen.at(-1)!.headers["anthropic-beta"], asym);

    // An upstream nobody granted, and the granted host over plain HTTP.
    const other = await start("https://evil.example");
    await send(other, "POST", "/v1/messages", { "x-api-key": asym }, messages);
    assert.equal(seen.at(-1)!.origin, "https://evil.example");
    assert.equal(seen.at(-1)!.headers["x-api-key"], asym, "an ungranted host gets the placeholder");
    const plain = await start("http://api.anthropic.com");
    await send(plain, "GET", "/v1/models", { "x-api-key": asym });
    assert.equal(seen.at(-1)!.headers["x-api-key"], asym, "an https grant is never put back over plain HTTP");

    // THE ORACLE over every request: no body carries any value, and the key
    // appears only in the auth header of a request to its granted host.
    for (const q of seen) {
      for (const v of [akey, okey, gh]) assert.ok(!q.body.includes(v), `INVARIANT: no request body carries a value (${q.origin}${q.path})`);
      for (const [h, v] of Object.entries(q.headers)) {
        const s = Array.isArray(v) ? v.join(",") : String(v ?? "");
        if (s.includes(akey)) assert.ok(h === "x-api-key" && q.origin === "https://api.anthropic.com", `the anthropic key only in x-api-key to api.anthropic.com (${h} ${q.origin})`);
        if (s.includes(okey)) assert.ok(h === "authorization" && q.origin === "https://api.openai.com/v1", `the openai key only as Bearer to api.openai.com (${h} ${q.origin})`);
        assert.ok(!s.includes(gh), "the ungranted token never leaves");
      }
    }
    assert.ok(seen.some((q) => q.body.includes(asym)), "the model's context keeps the symbol");

    // The arbiter gone: the placeholder is relayed (the provider answers 401).
    await server.close();
    server = null;
    await send(port, "GET", "/v1/models", { "x-api-key": asym });
    assert.equal(seen.at(-1)!.headers["x-api-key"], asym, "no arbiter: the placeholder");
  } finally {
    for (const p of proxies) await p.close();
    launcher.close(); agentWorld.close(); (data as unknown as ArbiterClient).close(); human.close();
    if (server) await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("an arbiter restarted under a live launch takes the grant back (the key keeps working); an ended launch's grant is not taken back (§3.2 item 4)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-auth-restart-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, ".config", "goose"), { recursive: true });
  const file = join(home, ".config", "goose", "secrets.yaml");
  const akey = `sk-ant-api03-${randomBytes(24).toString("hex")}-MANDUFAKE`;
  const okey = `sk-proj-${randomBytes(24).toString("hex")}-MANDUFAKE`;
  writeFileSync(file, `ANTHROPIC_API_KEY: ${akey}\nOPENAI_API_KEY: ${okey}\n`, { mode: 0o600 });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  const dbPath = join(tmp, "symbols.sqlite");
  const arbiter = (): ArbiterServer => new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath, dbPath, eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  // A launcher that has already ended: a child that exited (its pid gone).
  const gone = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], { encoding: "utf8" });
  const gonePid = Number(gone.stdout);
  assert.ok(gonePid > 0);
  let server: ArbiterServer | null = arbiter();
  await server.listen();
  const launcher = new ArbiterClient(humanPath); await launcher.connect();
  const data: RealArbiterClient = new ArbiterClient(socketPath); await data.connect();
  const human = new ArbiterClient(humanPath); await human.connect();
  const seen: Seen[] = [];
  const proxy = new AnthropicProxy({
    arbiter: new ArbiterClientAdapter(data, human), sessionKey: "s-restart", log: () => {},
    upstreamOrigin: "https://api.anthropic.com", upstream: scripted("https://api.anthropic.com", seen),
    openaiUpstreams: { openai: "https://api.openai.com/v1" }, openaiFetcher: () => scripted("https://api.openai.com/v1", seen),
  });
  try {
    // The live launch (this process) grants anthropic; an ended one granted openai.
    assert.deepEqual(await launcher.registerAuthGrant(file, [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }], { pid: process.pid }), { granted: 1 });
    // Not visible as alive: never persisted (it would never be taken back anyway).
    assert.deepEqual(await launcher.registerAuthGrant(file, [{ field: "OPENAI_API_KEY", host: "api.openai.com", https: true }], { pid: gonePid }), { granted: 1 });
    const reg = await launcher.registerSecret({ path: file, home });
    const asym = fieldOf(reg.twin!, "ANTHROPIC_API_KEY");
    const osym = fieldOf(reg.twin!, "OPENAI_API_KEY");
    const port = await proxy.listen(0);
    const body = JSON.stringify({ model: "claude-test", stream: true, messages: [{ role: "user", content: `hi ${asym}` }] });
    const chat = JSON.stringify({ model: "gpt-4o", stream: true, messages: [{ role: "user", content: "hi" }] });
    await send(port, "POST", "/v1/messages", { "x-api-key": asym }, body);
    assert.equal(seen.at(-1)!.headers["x-api-key"], akey, "before the restart: the key is put back");
    await send(port, "POST", "/_mandu/openai/openai/chat/completions", { authorization: `Bearer ${osym}` }, chat);
    assert.equal(seen.at(-1)!.headers["authorization"], `Bearer ${okey}`, "before the restart, the in-memory grant serves");

    // The restart, under the live session: same DB, same sockets.
    await server.close();
    server = arbiter();
    await server.listen();
    // The proxy's first request on the connection the old arbiter dropped is
    // refused fail-closed (502, nothing relayed); the agent's retry redials.
    const n = seen.length;
    let st = 0;
    for (let i = 0; i < 3 && seen.length === n; i++) st = await send(port, "POST", "/v1/messages", { "x-api-key": asym }, body);
    assert.equal(seen.length, n + 1, `relayed after the restart (status ${st})`);
    assert.equal(seen.at(-1)!.headers["x-api-key"], akey, "after the restart: the live launch's grant was taken back");
    await send(port, "POST", "/_mandu/openai/openai/chat/completions", { authorization: `Bearer ${osym}` }, chat);
    assert.equal(seen.at(-1)!.headers["authorization"], `Bearer ${osym}`, "the ended launch's grant is not: the placeholder (the provider answers 401)");

    // THE ORACLE: no body carries a key; each key only in its own auth header to its own host.
    for (const q of seen) {
      for (const v of [akey, okey]) assert.ok(!q.body.includes(v), "INVARIANT: no request body carries a key");
      for (const [h, v] of Object.entries(q.headers)) {
        const s = Array.isArray(v) ? v.join(",") : String(v ?? "");
        if (s.includes(akey)) assert.ok(h === "x-api-key" && q.origin === "https://api.anthropic.com");
        if (s.includes(okey)) assert.ok(h === "authorization" && q.origin === "https://api.openai.com/v1");
      }
    }
  } finally {
    await proxy.close();
    launcher.close(); (data as unknown as ArbiterClient).close(); human.close();
    if (server) await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("Claude Code's ANTHROPIC_API_KEY (§3.8): masked only with the launch's env grant, put back only in x-api-key to the granted host, across a restart too", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-auth-env-"));
  const key = `sk-ant-api03-${randomBytes(24).toString("hex")}-MANDUFAKE`;
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  const dbPath = join(tmp, "symbols.sqlite");
  const arbiter = (): ArbiterServer => new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath, dbPath, eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  let server: ArbiterServer | null = arbiter();
  await server.listen();
  const launcher = new ArbiterClient(humanPath); await launcher.connect();
  const agentWorld = new ArbiterClient(socketPath); await agentWorld.connect();
  const data: RealArbiterClient = new ArbiterClient(socketPath); await data.connect();
  const human = new ArbiterClient(humanPath); await human.connect();
  const seen: Seen[] = [];
  const proxies: AnthropicProxy[] = [];
  const start = async (origin: string): Promise<number> => {
    const p = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), sessionKey: "s-env", log: () => {}, upstreamOrigin: origin, upstream: scripted(origin, seen) });
    proxies.push(p);
    return p.listen(0);
  };
  const vars = [{ name: "ANTHROPIC_API_KEY", value: key, agentKey: true }];
  try {
    // No grant yet: the agent's own key variable stays exempt (raw), as before.
    const before = await launcher.registerEnvSecrets({ vars });
    assert.equal(before.vars[0]!.symbol, null, "no grant: not masked (the agent keeps a key it can use)");
    // The agent's world cannot grant (human plane only), nor bind to a host of its own.
    await assert.rejects(agentWorld.registerEnvAuthGrant("ANTHROPIC_API_KEY", [{ field: "ANTHROPIC_API_KEY", host: "evil.example", https: true }]), /human-plane/);
    // A field other than the variable's own name is refused.
    await assert.rejects(launcher.registerEnvAuthGrant("ANTHROPIC_API_KEY", [{ field: "OTHER", host: "api.anthropic.com", https: true }]), /own name/);
    assert.deepEqual(await launcher.registerEnvAuthGrant("ANTHROPIC_API_KEY", [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }], { pid: process.pid }), { granted: 1 });
    const reg = await launcher.registerEnvSecrets({ vars });
    const twin = reg.vars[0]!.twin!;
    assert.match(twin, /^\$MDU:nomodel_Env\[[0-9a-f]+\]\.ANTHROPIC_API_KEY$/, "the agent's environment carries the placeholder");
    assert.ok(!twin.includes(key));

    const port = await start("https://api.anthropic.com");
    const body = JSON.stringify({ model: "claude-test", stream: true, messages: [{ role: "user", content: `my key is ${twin}` }] });
    assert.equal(await send(port, "POST", "/v1/messages", { "x-api-key": twin }, body), 200);
    assert.equal(seen.at(-1)!.headers["x-api-key"], key, "the key put back in x-api-key");
    assert.ok(seen.at(-1)!.body.includes(twin) && !seen.at(-1)!.body.includes(key), "the model's context keeps the symbol");
    // As a Bearer to the same host too (Claude Code sends x-api-key; the shape is the proxy's).
    await send(port, "POST", "/v1/messages", { authorization: `Bearer ${twin}` }, body);
    assert.equal(seen.at(-1)!.headers["authorization"], `Bearer ${key}`);
    // Another upstream nobody granted: the placeholder.
    const other = await start("https://evil.example");
    await send(other, "POST", "/v1/messages", { "x-api-key": twin }, body);
    assert.equal(seen.at(-1)!.headers["x-api-key"], twin);

    // The restart under the live launch: the env grant is taken back.
    await server.close();
    server = arbiter();
    await server.listen();
    const n = seen.length;
    for (let i = 0; i < 3 && seen.length === n; i++) await send(port, "POST", "/v1/messages", { "x-api-key": twin }, body);
    assert.equal(seen.at(-1)!.headers["x-api-key"], key, "after the restart: still put back");

    // THE ORACLE: the key only in an auth header to api.anthropic.com, never in a body.
    for (const q of seen) {
      assert.ok(!q.body.includes(key), "INVARIANT: no request body carries the key");
      for (const [h, v] of Object.entries(q.headers)) {
        const s = Array.isArray(v) ? v.join(",") : String(v ?? "");
        if (s.includes(key)) assert.ok((h === "x-api-key" || h === "authorization") && q.origin === "https://api.anthropic.com", `${h} ${q.origin}`);
      }
    }
  } finally {
    for (const p of proxies) await p.close();
    launcher.close(); agentWorld.close(); (data as unknown as ArbiterClient).close(); human.close();
    if (server) await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("Codex's saved key (§3.9): the twinned auth.json's placeholder is put back as Bearer by the openai-proxy toward the granted API origin only; a ChatGPT sign-in's request is never touched", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-auth-codex-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, ".codex"), { recursive: true });
  const file = join(home, ".codex", "auth.json");
  const key = `sk-proj-${randomBytes(24).toString("hex")}-MANDUFAKE`;
  writeFileSync(file, JSON.stringify({ OPENAI_API_KEY: key, tokens: null, last_refresh: null }, null, 2), { mode: 0o600 });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const launcher = new ArbiterClient(humanPath); await launcher.connect();
  const data: OpenAiRealClient = new ArbiterClient(socketPath); await (data as unknown as ArbiterClient).connect();
  const human: OpenAiRealClient = new ArbiterClient(humanPath); await (human as unknown as ArbiterClient).connect();
  const seen: Seen[] = [];
  const proxies: OpenAiProxy[] = [];
  const start = async (origin: string): Promise<number> => {
    const p = new OpenAiProxy({
      arbiter: new OpenAiAdapter(data, human), sessionKey: "s-codex", log: () => {}, // PRODUCTION wiring
      upstreamOrigin: origin, chatgptOrigin: "https://chatgpt.com/backend-api/codex",
      upstream: async ({ path, headers, body }) => {
        const signedIn = typeof headers["chatgpt-account-id"] === "string";
        seen.push({ origin: signedIn ? "https://chatgpt.com/backend-api/codex" : origin, path, headers: { ...headers }, body: body.toString("utf8") });
        return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(openAiTextSse("ok"))]) };
      },
    });
    proxies.push(p);
    return p.listen(0);
  };
  try {
    assert.deepEqual(await launcher.registerAuthGrant(file, [{ field: "OPENAI_API_KEY", host: "api.openai.com", https: true }], { pid: process.pid }), { granted: 1 });
    const reg = await launcher.registerSecret({ path: file, home });
    const placeholder = (JSON.parse(reg.twin!) as { OPENAI_API_KEY: string }).OPENAI_API_KEY;
    assert.match(placeholder, /^\$MDU:nomodel_Read\[[0-9a-f]+\]\.OPENAI_API_KEY$/);
    assert.ok(!reg.twin!.includes(key), "the twin holds no key");
    const turn = JSON.stringify({ model: "gpt-5.4", stream: true, input: [{ type: "message", role: "user", content: [{ type: "input_text", text: `auth.json: ${reg.twin}` }] }] });
    const port = await start("https://api.openai.com");
    await send(port, "POST", "/v1/responses", { authorization: `Bearer ${placeholder}` }, turn);
    assert.equal(seen.at(-1)!.headers["authorization"], `Bearer ${key}`, "the key, as Bearer, to the API origin");
    assert.ok(seen.at(-1)!.body.includes(placeholder), "the model's context keeps the placeholder");
    // A ChatGPT sign-in's request: relayed as written, never asked about.
    await send(port, "POST", "/v1/responses", { authorization: `Bearer ${placeholder}`, "chatgpt-account-id": "acct-dummy" }, turn);
    assert.equal(seen.at(-1)!.origin, "https://chatgpt.com/backend-api/codex");
    assert.equal(seen.at(-1)!.headers["authorization"], `Bearer ${placeholder}`);
    // An API origin nobody granted: the placeholder.
    const other = await start("https://llm.corp.example");
    await send(other, "POST", "/v1/responses", { authorization: `Bearer ${placeholder}` }, turn);
    assert.equal(seen.at(-1)!.headers["authorization"], `Bearer ${placeholder}`);
    for (const q of seen) {
      assert.ok(!q.body.includes(key), "INVARIANT: no request body carries the key");
      for (const [h, v] of Object.entries(q.headers)) {
        if (String(v ?? "").includes(key)) assert.ok(h === "authorization" && q.origin === "https://api.openai.com", `${h} ${q.origin}`);
      }
    }
  } finally {
    for (const p of proxies) await p.close();
    launcher.close(); (data as unknown as ArbiterClient).close(); (human as unknown as ArbiterClient).close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
