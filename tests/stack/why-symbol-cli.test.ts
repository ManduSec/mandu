/**
 * why-symbol-cli e2e — `mandu why '$MDU:…'` for a prompt finding
 * (confidentiality-plan-15-prompt-filter.md §13.8) on the real path:
 *
 *   a typed prompt ──► the REAL anthropic-proxy (production wiring:
 *       `new ArbiterClientAdapter(new ArbiterClient(sock), new ArbiterClient(humanSock))`)
 *     ──► a scripted fake model, which records what it received;
 *   then `runWhy` with its PRODUCTION deps (`realWhyDeps()`: the launcher's
 *   ndjsonCall, the human socket read from the arbiter's `hello`), only the
 *   resident-arbiter lookup injected, over the same real ArbiterServer.
 *
 * The policy: a pack `acme-dlp` finds a code name, `acme.codename: mask`;
 * the session's environment registers a key. The prompt holds both. Proves:
 *   - the model received neither raw (the oracle);
 *   - `mandu why` on the code name's placeholder says, in plain words, that
 *     part of the person's own message was hidden, by which pack, the
 *     category, the action, the session and the request, the policy now and
 *     the ways out; on the key's placeholder, that it is a secret Mandu holds
 *     (the variable's name) and that the prompt filter never lets it through;
 *   - neither answer (text or --json) carries the value;
 *   - from the agent's side (the data socket, the human socket out of reach)
 *     a claim gets no more than today: `whySymbol` and `events` are refused,
 *     the CLI falls back to `symbolProvenance` and says so, and a forged
 *     `prompt_filter` event on the data socket does not change the answer;
 *   - `--session <id>` finds a finding in a session past the search (24 later
 *     sessions), and with no finding the answer offers the flag.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import type { PolicyFileConfig } from "../../arbiter/policy/load-policy.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { realWhyDeps, runWhy } from "../../launcher/src/why.js";
import type { Layout } from "../../launcher/src/services/layout.js";
import { startScriptedAnthropic } from "../lib/fake-anthropic.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

const KEY = "sk-live-WhyCanary7Hq2Zx9Lw4Rt8Kd";
const CODENAME = "falconridgeproject";
const SESSION = "why-symbol-s1";
const PACK = `pack: acme-dlp
version: 1
description: Acme's data-loss patterns
keywords:
  - category: acme.codename
    words: [${CODENAME}]
    level: local-model
`;
const POLICY: PolicyFileConfig = { version: 1, prompt_filters: { filters: { "acme-dlp": "on" }, actions: { "acme.codename": "mask" } } };

function post(port: number, body: unknown): Promise<{ status: number; body: string }> {
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "content-length": String(data.length), "x-mandu-session-id": SESSION, authorization: "Bearer sk-test-not-real" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(data);
  });
}

async function capture(fn: (out: (s: string) => void) => Promise<number>): Promise<{ code: number; out: string; err: string }> {
  const chunks: string[] = [];
  const err: string[] = [];
  const ew = process.stderr.write.bind(process.stderr);
  (process.stderr as unknown as { write: (s: string) => boolean }).write = (s) => { err.push(String(s)); return true; };
  try {
    const code = await fn((s) => { chunks.push(s); });
    return { code, out: chunks.join(""), err: err.join("") };
  } finally {
    (process.stderr as unknown as { write: typeof ew }).write = ew;
  }
}

async function waitFor<T>(what: string, f: () => Promise<T | undefined>, ms = 10_000): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = await f();
    if (v !== undefined) return v;
    if (Date.now() > until) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

test("mandu why '$MDU:…' explains a prompt finding from the real proxy; a data-plane claim gets no more", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-why-symbol-"));
  const packs = join(tmp, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "acme.yaml"), PACK);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyDocument: POLICY, policyPollMs: 0,
    promptPackDir: packs, adminPromptPackDir: null, adminPolicyDir: null, packDir: null,
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  const human = new ArbiterClient(humanSock);
  const fake = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  let proxy: AnthropicProxy | null = null;
  try {
    await data.connect();
    await human.connect();
    const reg = await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    const keySymbol = reg.vars[0]!.symbol!;
    assert.match(keySymbol, /^\$MDU:/);
    await data.setSessionSpec({ sessionKey: SESSION, spec: "claude-code" });
    proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(new ArbiterClient(sock), new ArbiterClient(humanSock)), upstreamOrigin: fake.origin, sessionKey: SESSION, log: () => {} });
    const port = await proxy.listen(0);
    const res = await post(port, {
      model: "claude-sonnet-4-5", stream: true, max_tokens: 64,
      tools: [{ name: "Read", description: "read", input_schema: { type: "object" } }],
      messages: [{ role: "user", content: [{ type: "text", text: "<system-reminder>\nctx\n</system-reminder>" }, { type: "text", text: `deploy ${CODENAME} with ${KEY}` }] }],
    });
    assert.equal(res.status, 200, res.body);
    const sent = fake.requests.filter((q) => q.body.includes('"tools"')).map((q) => q.body);
    assert.ok(sent.length > 0, "the model received the request");
    for (const b of sent) {
      assert.ok(!b.includes(KEY), "CONFIDENTIALITY VIOLATION: the registered key reached the model raw");
      assert.ok(!b.includes(CODENAME), "the code name reached the model raw under mask");
    }
    // The code name's placeholder, as the person would see it in the transcript.
    const m = /deploy (\$MDU:[A-Za-z0-9_]+\[[0-9a-f]+\](?:\.[A-Za-z0-9_]+)?) with (\$MDU:[A-Za-z0-9_]+\[[0-9a-f]+\](?:\.[A-Za-z0-9_]+)?)/.exec(sent.at(-1)!);
    assert.ok(m, `the model read both placeholders: ${sent.at(-1)}`);
    const codeSymbol = m[1]!;
    assert.equal(m[2], keySymbol, "the key goes as the symbol it has everywhere");
    // The proxy's prompt_filter event lands (best-effort, off the request path).
    await waitFor("the proxy's prompt_filter event", async () => ((await human.whySymbol(codeSymbol)).findings.length > 0 ? true : undefined));

    // A claim from the agent's world: a forged event on the data socket.
    await data.emit({
      id: "forged-1", sessionId: SESSION, ts: new Date().toISOString(), turn: 99, kind: "prompt_filter",
      promptFilter: { agent: "claude-code", segmentId: "x", origin: "human", action: "pass", enforcing: true, skipped: 0, findings: [{ filterId: "forged-pack", category: "forged.cat", action: "mask", symbol: codeSymbol, start: 0, end: 1, let: "session" }], digest: { policy: "p", packs: "k" } },
    });

    const layout = {} as Layout;
    const env = { HOME: join(tmp, "home") };
    const resident = { arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }), cwd: () => tmp };
    const deps = { ...realWhyDeps(), ...resident };

    // 1. The code name: the person asks in their own terminal.
    const w = await capture((out) => runWhy([codeSymbol], env, layout, { ...deps, out }));
    assert.equal(w.code, 0, w.err);
    assert.match(w.out, /what +part of your own message to the AI was hidden from it/);
    assert.match(w.out, /found by +the pack acme-dlp \("Acme's data-loss patterns"\)/);
    assert.match(w.out, /category +acme\.codename/);
    assert.match(w.out, /action +mask: hidden/);
    assert.match(w.out, new RegExp(`session +${SESSION}, model request 1,`));
    assert.match(w.out, /policy now acme\.codename: mask \(your policy\.yaml/);
    assert.match(w.out, /way out +let it through: on the dashboard/);
    assert.match(w.out, /prompt_filters: actions: \{ acme\.codename: log \}/);
    assert.match(w.out, /prompt_filters: exceptions:/);
    assert.doesNotMatch(w.out, /forged/, "a claimed event does not change the answer");
    assert.ok(!w.out.includes(CODENAME) && !w.out.includes(KEY), `CONFIDENTIALITY: mandu why printed a value: ${w.out}`);
    const j = await capture((out) => runWhy([codeSymbol, "--json"], env, layout, { ...deps, out }));
    const a = JSON.parse(j.out) as { source: string; findings: Array<{ category: string; filterId: string; action: string; session: string }> };
    assert.equal(a.source, "prompt-filter");
    assert.deepEqual(a.findings.map((f) => [f.session, f.filterId, f.category, f.action]), [[SESSION, "acme-dlp", "acme.codename", "mask"]]);
    assert.ok(!j.out.includes(CODENAME) && !j.out.includes(KEY), "CONFIDENTIALITY: --json carried a value");

    // 2. The registered key, found in the same message: no way out here.
    const k = await capture((out) => runWhy([keySymbol], env, layout, { ...deps, out }));
    assert.equal(k.code, 0, k.err);
    assert.match(k.out, /a secret Mandu already holds was in your own message to the AI/);
    assert.match(k.out, /secret +the environment variable STRIPE_API_KEY/);
    assert.match(k.out, /found by +the registered-value filter/);
    assert.match(k.out, /never lets a secret Mandu holds through as written/);
    assert.ok(!k.out.includes(KEY), "CONFIDENTIALITY: mandu why printed the key");

    // 3. The agent's side: the human socket out of reach (ENOENT, as under
    // the secret-twins tmpfs), and the data socket's own answers.
    const walled = await capture((out) => runWhy([codeSymbol], env, layout, { ...deps, humanSock: async () => join(tmp, "walled", "h.sock"), out }));
    assert.equal(walled.code, 0, walled.err);
    assert.match(walled.out, /Mandu's prompt filter made it/);
    assert.match(walled.out, /shown only outside the agent/);
    assert.doesNotMatch(walled.out, new RegExp(`acme|${SESSION}`), "no more than the data socket gives today: the minting tool");
    assert.ok(!walled.out.includes(CODENAME));
    await assert.rejects(() => data.whySymbol(codeSymbol), /human-plane/);
    await assert.rejects(() => data.events(SESSION), /human-plane/);

    // 4. `--session` (!422's hint, 2026-10-09). The key's row keeps no
    // session of the prompt (it was registered by the launch), so its
    // finding is found only among the most recent sessions (at most 24).
    // Twenty-four later sessions push SESSION out of the search.
    const later = Date.now() + 1_000;
    for (let i = 0; i < 24; i++) {
      await data.emit({ id: `later-${i}`, sessionId: `why-later-${i}`, ts: new Date(later + i).toISOString(), turn: 0, kind: "model_request" });
    }
    const missed = await capture((out) => runWhy([keySymbol], env, layout, { ...deps, out }));
    assert.equal(missed.code, 0, missed.err);
    assert.doesNotMatch(missed.out, /found by/, `SESSION is past the search: ${missed.out}`);
    assert.match(missed.out, /searched 24 sessions for a message that carried it; for a message in another session, ask again with --session <id>/);
    const named = await capture((out) => runWhy([keySymbol, "--session", SESSION], env, layout, { ...deps, out }));
    assert.equal(named.code, 0, named.err);
    assert.match(named.out, /found by +the registered-value filter/, `the named session is searched: ${named.out}`);
    assert.match(named.out, new RegExp(`session +${SESSION}, model request 1,`));
    assert.doesNotMatch(named.out, /ask again with --session|no finding names/);
    assert.ok(!named.out.includes(KEY) && !missed.out.includes(KEY), "CONFIDENTIALITY: mandu why printed the key");
    const nowhere = await capture((out) => runWhy([keySymbol, "--session", "no-such-session"], env, layout, { ...deps, out }));
    assert.match(nowhere.out, /no finding names this placeholder in session no-such-session/);
  } finally {
    data.close();
    human.close();
    await proxy?.close().catch(() => {});
    await fake.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
});
