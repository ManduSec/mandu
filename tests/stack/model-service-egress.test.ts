/**
 * model-service-egress — a request from a program in the session to a model
 * service it calls itself (agent-sign-in.md §3.12: jev-ultrafast's TypeSafe
 * decision model; net-proxy egress.ts `modelService`), over the PRODUCTION
 * chain: the launcher's `registerProviderKeyGrants` and `applyEnvSecrets` on
 * a real ArbiterServer, a `.env` registered as the launcher does, and a REAL
 * NetProxy on its TLS-inspected leg with the launcher's model-service list,
 * mock-sites routing the service to a loopback HTTPS recorder (the oracle).
 *
 * The page text jev sends carries a page secret's placeholder (what the
 * DevTools relay gave it). At the model service:
 *   - the request goes out: the key in the Authorization header put back,
 *     the page secret's placeholder left as it is, never its value;
 *   - a RAW registered value in the body is still refused (the tripwire);
 *   - the service's own key placeholder outside the header is still refused
 *     (the wire position rule);
 *   - the same placeholder to any other host, and to the service from a
 *     proxy without the list, is refused as before (egress:secret-unbound),
 *     and nothing reaches the host.
 * And under a DevTools relay (devtools-relay.md §6.5) a browser agent's
 * Chat Completions call to OpenRouter reaches it with the real arbiter's
 * handling note first, the key put back, the placeholder as written.
 *
 * And the relay's refusals reach the agent's MODEL (devtools-relay.md
 * §3.4), whatever the agent does with the DevTools error: the real relay
 * (its production adapter) refuses a made-up placeholder, inserted whole
 * and typed a key at a time (browser-use's way, the 2026-10-19 live
 * failure), and the next Chat Completions call through the real proxy, on
 * the same session key, carries one last `user` message naming the typed
 * placeholder and the one the page showed, exactly once; no value in it.
 * A lookalike typed a key at a time (a UUID for the code) is told the same
 * way, naming the page's real placeholder and never the lookalike.
 * A real placeholder typed on a site that may not have it (the live
 * expense-report demo's team chat, 2026-10-19) is told as such: leave it
 * out and go on, ask the user only if they asked for it there; the ask
 * stays open for the person, and nothing of the value reaches the page.
 *
 * Made-up secrets. SKIP without openssl (no session CA). Secrets axes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import { connect as tlsConnect } from "node:tls";
import { connect as netConnect, type AddressInfo } from "node:net";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { MockSites } from "../../interceptors/net-proxy/src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../interceptors/net-proxy/src/ca.js";
import { applyEnvSecrets, ndjsonCall, socketSecretArbiter } from "../../launcher/src/secret-setup.js";
import { PROVIDER_KEY_HOSTS, registerProviderKeyGrants } from "../../launcher/src/agent-key-grant.js";
import { modelNoteOf } from "../../launcher/src/services/net-proxy.js";
import { modelNoteFromEnv } from "../../interceptors/net-proxy/src/model-note.js";
import { emptyMutation } from "../../launcher/src/backend/types.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { stateAxes } from "../lib/axes.js";
import { ArbiterClientAdapter as RelayAdapter, type RealArbiterClient as RelayRealClient } from "../../interceptors/cdp-relay/src/arbiter-client.js";
import { LEAVE_IT_OUT } from "../../interceptors/net-proxy/src/relay-notice.js";
import { CdpRelay } from "../../interceptors/cdp-relay/src/relay.js";
import { FakeChrome } from "../../interceptors/cdp-relay/test/fake-chrome.js";

stateAxes("secrets");

const OPENSSL = opensslAvailable();
const TS_KEY = "tsk_live_ModelServiceStack4Hd8Qz2Lm7";
const STRIPE = "sk_live_51ModelServicePageSecretXq7Rt2Yp9";

interface Got { host: string; url: string; headers: IncomingMessage["headers"]; body: string }

async function httpsRecorder(dir: string, host: string, got: Got[]) {
  const ca = ensureCa(join(dir, `ca-${host}`));
  const leaf = leafForHost(ca, host);
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      got.push({ host, url: req.url ?? "", headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"choice":"1"}');
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { port: (server.address() as AddressInfo).port, caPath: ca.certPath, close: () => server.close() };
}

/** CONNECT host:443, TLS trusting the session CA, one POST. */
function post(proxyPort: number, host: string, sessionCa: string, path: string, headers: Record<string, string>, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const raw = netConnect(proxyPort, "127.0.0.1", () => raw.write(`CONNECT ${host}:443 HTTP/1.1\r\nHost: ${host}:443\r\n\r\n`));
    let head = Buffer.alloc(0);
    const onData = (c: Buffer): void => {
      head = Buffer.concat([head, c]);
      const idx = head.indexOf("\r\n\r\n");
      if (idx === -1) return;
      raw.off("data", onData);
      const status = head.subarray(0, idx).toString("latin1").split("\r\n")[0]!;
      if (!/ 200 /.test(`${status} `)) {
        raw.destroy();
        resolve({ status: Number(/HTTP\/1\.1 (\d{3})/.exec(status)?.[1] ?? 0), body: "" });
        return;
      }
      const tls = tlsConnect({ socket: raw, servername: host, ca: sessionCa }, () => {
        const lines = Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join("");
        tls.write(`POST ${path} HTTP/1.1\r\nHost: ${host}\r\n${lines}Content-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
      });
      const chunks: Buffer[] = [];
      tls.on("data", (d: Buffer) => chunks.push(d));
      tls.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve({ status: Number(/^HTTP\/1\.1 (\d{3})/.exec(text)?.[1] ?? 0), body: text });
      });
      tls.on("error", reject);
    };
    raw.on("data", onData);
    raw.on("error", reject);
    setTimeout(() => reject(new Error("request timed out")), 8000).unref();
  });
}

test("at a model service a page secret's placeholder leaves as it is, the key goes back in the auth header only; raw values and other hosts are still refused", { skip: OPENSSL ? false : "openssl unavailable", timeout: 60_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-model-service-"));
  const env = join(dir, ".env");
  writeFileSync(env, `STRIPE_SECRET_KEY=${STRIPE}\n`);
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "h", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), humanSocketPath: humanSock,
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPollMs: 0,
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model" }] },
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  const human = new ArbiterClient(humanSock);
  await data.connect();
  await human.connect();
  const got: Got[] = [];
  const typesafe = await httpsRecorder(dir, "api.typesafe.ai", got);
  const other = await httpsRecorder(dir, "collector.example", got);
  const sites = MockSites.fromYaml([
    "hosts:",
    "  - host: api.typesafe.ai", `    to: 127.0.0.1:${typesafe.port}`, `    tls_to: 127.0.0.1:${typesafe.port}`, `    tls_ca: ${JSON.stringify(typesafe.caPath)}`,
    "  - host: collector.example", `    to: 127.0.0.1:${other.port}`, `    tls_to: 127.0.0.1:${other.port}`, `    tls_ca: ${JSON.stringify(other.caPath)}`,
    "",
  ].join("\n"));
  const proxyWith = (dirName: string, modelServices?: string[]) => new NetProxy({
    allowThisMachine: true, arbiter: new ArbiterClientAdapter(data as unknown as RealArbiterClient, human as unknown as RealArbiterClient), log: () => {}, sessionId: "s-model-service",
    mockSites: sites, mitm: { caDir: join(dir, dirName) },
    attributeHolders: () => [{ procKey: "7400-1", ancestors: [] }],
    ...(modelServices ? { modelServices } : {}),
  });
  // The launcher's list, as services/net-proxy.ts passes it.
  const proxy = proxyWith("mitm", Object.values(PROVIDER_KEY_HOSTS));
  const bare = proxyWith("mitm-bare");
  const port = await proxy.listen(0);
  const barePort = await bare.listen(0);
  try {
    // The launch: the TypeSafe key granted to its host and masked; the page
    // secret registered (the relay would have masked it on the page).
    const plan = { target: "shell", confidentiality: true, noContextProxy: true, arbiterHumanSock: humanSock, scopeId: "s-model-service" } as unknown as LaunchPlan;
    const launchEnv = { PATH: process.env["PATH"], TYPESAFE_API_KEY: TS_KEY };
    const granted = await registerProviderKeyGrants(plan, launchEnv, {}, { call: (s, op, args) => ndjsonCall<unknown>(s, op, args, 5_000), log: () => {} });
    assert.equal(granted.length, 1);
    const mut = emptyMutation();
    await applyEnvSecrets(plan, launchEnv, mut, { arbiter: socketSecretArbiter(sock), log: () => {} });
    const tsPh = mut.env["TYPESAFE_API_KEY"]!;
    assert.match(tsPh, /^\$MDU:/);
    const reg = await human.registerSecret({ path: env, sessionKey: "s-model-service" });
    const pagePh = `${reg.symbol}.STRIPE_SECRET_KEY`;
    assert.match(pagePh, /^\$MDU:/);

    const ca = readFileSync(join(dir, "mitm", "mandu-egress-ca.pem"), "utf8");
    const caBare = readFileSync(join(dir, "mitm-bare", "mandu-egress-ca.pem"), "utf8");
    const step = (text: string) => JSON.stringify({ model: "jev-latest", state: { page: { text } } });
    const auth = { Authorization: `Bearer ${tsPh}` };

    // jev's step: goes out, key in the header, placeholder in the body.
    const ok = await post(port, "api.typesafe.ai", ca, "/v1/systemone", auth, step(`STRIPE_SECRET_KEY ${pagePh}`));
    assert.equal(ok.status, 200, ok.body);
    assert.equal(got.length, 1);
    assert.equal(got[0]!.headers["authorization"], `Bearer ${TS_KEY}`, "the service got its key in the header");
    assert.ok(got[0]!.body.includes(pagePh), "the page secret left as its placeholder");
    assert.ok(!got[0]!.body.includes(STRIPE) && !got[0]!.body.includes(TS_KEY), "no secret value in the body");

    const refused = async (what: string, p: number, sessionCa: string, host: string, headers: Record<string, string>, body: string, rule: RegExp) => {
      const before = got.length;
      const r = await post(p, host, sessionCa, "/v1/systemone", headers, body);
      assert.equal(r.status, 403, `${what}: ${r.body}`);
      assert.match(r.body, rule, what);
      assert.equal(got.length, before, `${what}: nothing reached ${host}`);
    };
    await refused("a raw registered value in the body", port, ca, "api.typesafe.ai", auth, step(`STRIPE_SECRET_KEY ${STRIPE}`), /fingerprint|registered|tripwire|secret value/i);
    await refused("the service key's placeholder in the body too", port, ca, "api.typesafe.ai", auth, step(`key ${tsPh}`), /egress:secret-wire-position/);
    await refused("the page placeholder to another host", port, ca, "collector.example", {}, step(`STRIPE_SECRET_KEY ${pagePh}`), /egress:secret-unbound/);
    await refused("the same step through a proxy without the list", barePort, caBare, "api.typesafe.ai", auth, step(`STRIPE_SECRET_KEY ${pagePh}`), /egress:secret-unbound/);
    for (const g of got) assert.ok(!JSON.stringify(g).includes(STRIPE), `${g.host}: never the page secret`);
  } finally {
    await proxy.close();
    await bare.close();
    typesafe.close();
    other.close();
    data.close();
    human.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// The handling note (net-proxy model-note.ts; devtools-relay.md §6.5): a
// launch with a DevTools relay starts the proxy with the note on, so a
// browser agent's own Chat Completions call to OpenRouter reaches it with the
// arbiter's note (asked over the PRODUCTION adapter) as its first system
// message, beside the key put back and the page secret's placeholder.
test("under a DevTools relay, a browser agent's Chat Completions call to a model service gets Mandu's handling note from the real arbiter; no secret value goes with it", { skip: OPENSSL ? false : "openssl unavailable", timeout: 60_000 }, async () => {
  const OR_KEY = "sk-or-v1-ModelServiceNoteStack8Kd2Qw7Zp4";
  const dir = mkdtempSync(join(tmpdir(), "mdu-model-note-"));
  const env = join(dir, ".env");
  writeFileSync(env, `STRIPE_SECRET_KEY=${STRIPE}\n`);
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "h", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), humanSocketPath: humanSock,
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPollMs: 0,
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model" }] },
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  const human = new ArbiterClient(humanSock);
  await data.connect();
  await human.connect();
  const got: Got[] = [];
  const openrouter = await httpsRecorder(dir, "openrouter.ai", got);
  const sites = MockSites.fromYaml([
    "hosts:",
    "  - host: openrouter.ai", `    tls_to: 127.0.0.1:${openrouter.port}`, `    tls_ca: ${JSON.stringify(openrouter.caPath)}`,
    "",
  ].join("\n"));
  const proxy = new NetProxy({
    allowThisMachine: true, arbiter: new ArbiterClientAdapter(data as unknown as RealArbiterClient, human as unknown as RealArbiterClient), log: () => {}, sessionId: "s-model-note",
    mockSites: sites, mitm: { caDir: join(dir, "mitm") },
    attributeHolders: () => [{ procKey: "7401-1", ancestors: [] }],
    // The launcher's list and switch, as services/net-proxy.ts passes them
    // for a launch with a relay.
    modelServices: Object.values(PROVIDER_KEY_HOSTS),
    modelNote: modelNoteFromEnv(modelNoteOf({ browserCdp: "http://127.0.0.1:9222" })),
  });
  const port = await proxy.listen(0);
  try {
    const plan = { target: "shell", confidentiality: true, noContextProxy: true, arbiterHumanSock: humanSock, scopeId: "s-model-note" } as unknown as LaunchPlan;
    const launchEnv = { PATH: process.env["PATH"], OPENROUTER_API_KEY: OR_KEY };
    const granted = await registerProviderKeyGrants(plan, launchEnv, {}, { call: (s, op, args) => ndjsonCall<unknown>(s, op, args, 5_000), log: () => {} });
    assert.equal(granted.length, 1);
    const mut = emptyMutation();
    await applyEnvSecrets(plan, launchEnv, mut, { arbiter: socketSecretArbiter(sock), log: () => {} });
    const orPh = mut.env["OPENROUTER_API_KEY"]!;
    assert.match(orPh, /^\$MDU:/);
    const reg = await human.registerSecret({ path: env, sessionKey: "s-model-note" });
    const pagePh = `${reg.symbol}.STRIPE_SECRET_KEY`;

    const ca = readFileSync(join(dir, "mitm", "mandu-egress-ca.pem"), "utf8");
    const messages = [
      { role: "system", content: "You are a browser agent." },
      { role: "user", content: `The page shows: Secret key ${pagePh}. Add it to the deploy host.` },
    ];
    const r = await post(port, "openrouter.ai", ca, "/api/v1/chat/completions", { Authorization: `Bearer ${orPh}` }, JSON.stringify({ model: "google/gemini-2.5-flash", messages }));
    assert.equal(r.status, 200, r.body);
    assert.equal(got.length, 1);
    assert.equal(got[0]!.headers["authorization"], `Bearer ${OR_KEY}`, "the service got its key in the header");
    const sent = JSON.parse(got[0]!.body) as { messages: Array<{ role: string; content: string }> };
    assert.equal(sent.messages.length, 3);
    assert.equal(sent.messages[0]!.role, "system");
    const note = sent.messages[0]!.content;
    assert.equal(note.split("## Web pages").length, 2, "the browser agent's section, once");
    assert.match(note, /The code in its brackets is unique to that secret/, "the confidentiality axis's browser note");
    assert.ok(!note.includes("web_fetch") && !note.includes("inspect_symbol"), "no example code to copy, no tool it lacks");
    assert.match(note, /fill or type the placeholder itself/);
    assert.equal(note, await data.handlingPrompt(undefined, { inspect: false, policyTools: false, exec: false, fsView: false, browser: true }, "s-model-note"), "exactly the arbiter's note");
    assert.deepEqual(sent.messages.slice(1), messages, "the agent's messages, the placeholder as written");
    assert.ok(!got[0]!.body.includes(STRIPE) && !got[0]!.body.includes(OR_KEY), "no secret value in the body");
  } finally {
    await proxy.close();
    openrouter.close();
    data.close();
    human.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

/** A DevTools client over Node's built-in WebSocket (browser-use's role). */
async function devtools(wsUrl: string) {
  const ws = new WebSocket(wsUrl);
  await new Promise<void>((resolve, reject) => {
    ws.addEventListener("open", () => resolve(), { once: true });
    ws.addEventListener("error", () => reject(new Error(`no relay at ${wsUrl}`)), { once: true });
  });
  const waiting = new Map<number, (m: any) => void>();
  ws.addEventListener("message", (ev) => {
    const m = JSON.parse(String(ev.data));
    if (typeof m.id === "number") waiting.get(m.id)?.(m);
  });
  let id = 1;
  const send = (method: string, params: Record<string, unknown> = {}): Promise<any> => {
    const my = id++;
    return new Promise((resolve) => { waiting.set(my, resolve); ws.send(JSON.stringify({ id: my, method, params })); });
  };
  return {
    send,
    /** browser-use's typing: keyDown without text, char, keyUp, per character. */
    /** browser-use's three events per character; every answer. */
    async typeKeys(text: string): Promise<any[]> {
      const answers: any[] = [];
      for (const ch of text) {
        answers.push(await send("Input.dispatchKeyEvent", { type: "keyDown", key: ch }));
        answers.push(await send("Input.dispatchKeyEvent", { type: "char", text: ch, key: ch }));
        answers.push(await send("Input.dispatchKeyEvent", { type: "keyUp", key: ch }));
      }
      return answers;
    },
    close: () => ws.close(),
  };
}

test("a relay refusal reaches the browser agent's model: the next Chat Completions call through the proxy carries it as the last message, once, names only (devtools-relay.md §3.4)", { skip: OPENSSL ? false : "openssl unavailable", timeout: 60_000 }, async () => {
  const KEY = "sk_live_51RelayNoticeStack7Qz2Lm8Kd4";
  const SESSION = "s-relay-notice";
  const dir = mkdtempSync(join(tmpdir(), "mdu-relay-notice-"));
  const env = join(dir, ".env");
  writeFileSync(env, `LEDGERLY_KEY=${KEY}\n`);
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "h", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), humanSocketPath: humanSock,
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPollMs: 0,
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model", bindings: ["ledgerly.localhost"] }] },
  });
  await server.listen();
  // Each component's own clients, as each server-main builds them.
  const relayData = new ArbiterClient(sock);
  const relayHuman = new ArbiterClient(humanSock);
  const proxyData = new ArbiterClient(sock);
  const proxyHuman = new ArbiterClient(humanSock);
  for (const c of [relayData, relayHuman, proxyData, proxyHuman]) await c.connect();
  const reg = await proxyHuman.registerSecret({ path: env, sessionKey: SESSION });
  const shown = `${reg.symbol}.LEDGERLY_KEY`;
  const hash = /\[([0-9a-f]+)\]/.exec(shown)![1]!;
  const madeUp = shown.replace(`[${hash}]`, `[${hash === "8c4f" ? "8c4e" : "8c4f"}]`);

  const chrome = new FakeChrome({ url: "https://ledgerly.localhost/expenses/new", pageText: `API key ${KEY}` });
  await chrome.listen();
  const relay = new CdpRelay({ upstream: chrome.url, arbiter: new RelayAdapter(relayData as unknown as RelayRealClient, relayHuman as unknown as RelayRealClient), session: SESSION });
  const relayAt = await relay.listen();
  const got: Got[] = [];
  const openrouter = await httpsRecorder(dir, "openrouter.ai", got);
  const proxy = new NetProxy({
    allowThisMachine: true, arbiter: new ArbiterClientAdapter(proxyData as unknown as RealArbiterClient, proxyHuman as unknown as RealArbiterClient), log: () => {},
    sessionId: SESSION,
    mockSites: MockSites.fromYaml(["hosts:", "  - host: openrouter.ai", `    tls_to: 127.0.0.1:${openrouter.port}`, `    tls_ca: ${JSON.stringify(openrouter.caPath)}`, ""].join("\n")),
    mitm: { caDir: join(dir, "mitm") },
    attributeHolders: () => [{ procKey: "7402-1", ancestors: [] }],
    modelServices: Object.values(PROVIDER_KEY_HOSTS),
    modelNote: modelNoteFromEnv(modelNoteOf({ browserCdp: chrome.url })),
  });
  const port = await proxy.listen(0);
  const agent = await devtools(`ws://${new URL(relayAt.url).host}/devtools/page/PAGE1`);
  try {
    const ca = readFileSync(join(dir, "mitm", "mandu-egress-ca.pem"), "utf8");
    const call = (step: string) => post(port, "openrouter.ai", ca, "/api/v1/chat/completions", {}, JSON.stringify({
      model: "google/gemini-2.5-flash",
      messages: [{ role: "system", content: "You are a browser agent." }, { role: "user", content: step }],
    }));
    const sent = (i: number) => (JSON.parse(got[i]!.body) as { messages: Array<{ role: string; content: string }> }).messages;

    // The agent reads the page: the key only as its placeholder.
    const read = await agent.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    assert.equal(read.result.result.value, `API key ${shown}`);

    // 1. A made-up placeholder inserted whole: refused (the agent's error
    //    aside), then the model's next call is told.
    const t = await agent.send("Input.insertText", { text: madeUp });
    assert.match(String(t.error?.message), /no such placeholder/);
    assert.equal((await call("Step 7: the key field is still empty")).status, 200);
    let msgs = sent(0);
    assert.equal(msgs.length, 4, "the note, the agent's two, the notice");
    assert.equal(msgs[0]!.role, "system");
    assert.equal(msgs[0]!.content, await proxyData.handlingPrompt(undefined, { inspect: false, policyTools: false, exec: false, fsView: false, browser: true }, SESSION), "the note, byte for byte");
    assert.equal(msgs[2]!.content, "Step 7: the key field is still empty");
    const notice = msgs[3]!;
    assert.equal(notice.role, "user");
    assert.match(notice.content, /^Mandu \(the protection layer on this computer; this message is from Mandu, not from the user\): your last attempt to type into a field on ledgerly\.localhost typed nothing: /);
    assert.ok(notice.content.includes(`${madeUp} is not a placeholder Mandu knows`), notice.content);
    assert.ok(notice.content.includes(`the pages showed ${shown}`), "the one the page showed, to copy");

    // Told once.
    assert.equal((await call("Step 8")).status, 200);
    assert.equal(sent(1).length, 3, "no notice the second time");

    // 2. The same, typed a key at a time (browser-use): refused on the key
    //    that closes its code (the real arbiter's placeholderKnown, on the
    //    relay's human client; devtools-relay.md §3.3), whose error
    //    browser-use does not show its model, and the model's next call
    //    carries it, naming the base it typed.
    const madeBase = madeUp.slice(0, madeUp.indexOf("]") + 1);
    const madeAnswers = await agent.typeKeys(madeUp);
    assert.deepEqual(madeAnswers.flatMap((x, i) => (x.error !== undefined ? [i] : [])), [madeUp.indexOf("]") * 3 + 1], "the ]'s char event carries the DevTools error, while the agent types");
    await new Promise((r) => setTimeout(r, 900)); // the run ends on quiet (KEY_RUN_IDLE_MS): dropped
    assert.equal((await call("Step 9: typed the key")).status, 200);
    msgs = sent(2);
    assert.equal(msgs.length, 4);
    assert.ok(msgs[3]!.content.includes(`${madeBase} is not a placeholder Mandu knows`), msgs[3]!.content);
    assert.ok(msgs[3]!.content.includes(`the pages showed ${shown}`), msgs[3]!.content);

    // 3. A LOOKALIKE typed a key at a time (the live expense-report demo,
    //    2026-10-19: a UUID for the code): refused on the key that closes its
    //    code (devtools-relay.md §3.3), as a placeholder that names nothing,
    //    no arbiter lookup, and the model's next call names the page's real
    //    placeholder, never the lookalike.
    const lookalike = shown.replace(`[${hash}]`, "[e213b2c2-8419-4809-b684-297d264f3319]");
    const keyAnswers = await agent.typeKeys(lookalike);
    const errors = keyAnswers.flatMap((x, i) => (x.error !== undefined ? [i] : []));
    const told = lookalike.indexOf("]") * 3 + 1;
    // step 2's refusal was told on its own key, so only the ]'s char event
    // carries an error here
    assert.deepEqual(errors, [told], "the ]'s char event carries the DevTools error, while the agent types");
    assert.ok(String(keyAnswers[told].error.message).includes(`no such placeholder ${lookalike.slice(0, lookalike.indexOf("]") + 1)}`), keyAnswers[told].error.message);
    await new Promise((r) => setTimeout(r, 900));
    assert.equal((await call("Step 10: typed the card")).status, 200);
    msgs = sent(3);
    assert.equal(msgs.length, 4, "the notice, once");
    assert.equal(msgs[3]!.role, "user");
    assert.ok(msgs[3]!.content.includes("typed nothing: the text typed looks like a placeholder but is not one Mandu made"), msgs[3]!.content);
    assert.ok(msgs[3]!.content.includes(`the pages showed ${shown}`), "the page's real placeholder, to copy");
    assert.ok(!msgs[3]!.content.includes("e213b2c2"), "the lookalike's free-text code is never quoted");
    assert.ok(msgs[3]!.content.includes("ledgerly.localhost"));
    // Told on its key: the agent's next input command (a click) goes as sent.
    const click = await agent.send("Input.dispatchMouseEvent", { type: "mousePressed", x: 1, y: 1, button: "left", clickCount: 1 });
    assert.equal(click.error, undefined, "not told twice");
    assert.ok(!JSON.stringify(chrome.received).includes("e213b2c2"), "none of it reached Chrome");
    assert.equal((await call("Step 11")).status, 200);
    assert.equal(sent(4).length, 3, "told once");

    // Nothing raw anywhere, and Chrome never got the value or a placeholder key.
    for (const g of got) assert.ok(!g.body.includes(KEY), "no value to the model service");
    assert.deepEqual(chrome.typed, []);
    assert.ok(!JSON.stringify(chrome.received).includes(KEY));
  } finally {
    agent.close();
    await relay.close();
    await chrome.close();
    await proxy.close();
    openrouter.close();
    for (const c of [relayData, relayHuman, proxyData, proxyHuman]) c.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a real placeholder on a site that may not have it (the team chat of the live expense-report demo): refused, nothing of it typed, the ask left open for the person, and the model's next call is told to leave it out and go on, asking only if the user asked for it there", { skip: OPENSSL ? false : "openssl unavailable", timeout: 60_000 }, async () => {
  const KEY = "4242424242424242";
  const SESSION = "s-relay-leave-out";
  const dir = mkdtempSync(join(tmpdir(), "mdu-relay-leave-out-"));
  const env = join(dir, ".env");
  writeFileSync(env, `CARD_NUMBER=${KEY}\n`);
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "h", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), humanSocketPath: humanSock,
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPollMs: 0,
    // The card may go to the expense tool, not to the team chat.
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model", bindings: ["ledgerly.localhost"] }] },
  });
  await server.listen();
  const relayData = new ArbiterClient(sock);
  const relayHuman = new ArbiterClient(humanSock);
  const proxyData = new ArbiterClient(sock);
  const proxyHuman = new ArbiterClient(humanSock);
  for (const c of [relayData, relayHuman, proxyData, proxyHuman]) await c.connect();
  const reg = await proxyHuman.registerSecret({ path: env, sessionKey: SESSION });
  const card = `${reg.symbol}.CARD_NUMBER`;

  const chrome = new FakeChrome({ url: "https://huddle.localhost/channel/finance", pageText: "#finance" });
  await chrome.listen();
  const relay = new CdpRelay({ upstream: chrome.url, arbiter: new RelayAdapter(relayData as unknown as RelayRealClient, relayHuman as unknown as RelayRealClient), session: SESSION });
  const relayAt = await relay.listen();
  const got: Got[] = [];
  const openrouter = await httpsRecorder(dir, "openrouter.ai", got);
  const proxy = new NetProxy({
    allowThisMachine: true, arbiter: new ArbiterClientAdapter(proxyData as unknown as RealArbiterClient, proxyHuman as unknown as RealArbiterClient), log: () => {},
    sessionId: SESSION,
    mockSites: MockSites.fromYaml(["hosts:", "  - host: openrouter.ai", `    tls_to: 127.0.0.1:${openrouter.port}`, `    tls_ca: ${JSON.stringify(openrouter.caPath)}`, ""].join("\n")),
    mitm: { caDir: join(dir, "mitm") },
    attributeHolders: () => [{ procKey: "7403-1", ancestors: [] }],
    modelServices: Object.values(PROVIDER_KEY_HOSTS),
    modelNote: modelNoteFromEnv(modelNoteOf({ browserCdp: chrome.url })),
  });
  const port = await proxy.listen(0);
  const agent = await devtools(`ws://${new URL(relayAt.url).host}/devtools/page/PAGE1`);
  try {
    const ca = readFileSync(join(dir, "mitm", "mandu-egress-ca.pem"), "utf8");
    const call = (step: string) => post(port, "openrouter.ai", ca, "/api/v1/chat/completions", {}, JSON.stringify({
      model: "google/gemini-2.5-flash",
      messages: [{ role: "system", content: "You are a browser agent." }, { role: "user", content: step }],
    }));

    // The summary for the team chat, the card's placeholder in it.
    const t = await agent.send("Input.insertText", { text: `Filed the expense. Paid with: company card ${card}` });
    const error = String(t.error?.message);
    assert.ok(error.startsWith(`Mandu: the placeholder was not typed: huddle.localhost may not have ${card} without the person's approval in Mandu; leave it out`), error);
    assert.deepEqual(chrome.typed, [], "nothing of the summary was typed");
    assert.ok(!JSON.stringify(chrome.received).includes(KEY), "no value to the page");

    // The person stays in control: the ask is on the Approvals page.
    const open = await proxyData.egressApprovals("pending");
    assert.ok(open.some((a) => a.symbol === card && a.destination === "huddle.localhost"), JSON.stringify(open.map((a) => [a.symbol, a.destination])));

    // The model's next call is told: leave it out and go on; ask only if
    // the user asked for the card to go there.
    assert.equal((await call("Step 12: the message box is still empty")).status, 200);
    const msgs = (JSON.parse(got[0]!.body) as { messages: Array<{ role: string; content: string }> }).messages;
    assert.equal(msgs.length, 4, "the note, the agent's two, the notice");
    const notice = msgs[3]!;
    assert.equal(notice.role, "user");
    assert.ok(notice.content.includes("your last attempt to type into a field on huddle.localhost typed nothing: "), notice.content);
    assert.ok(notice.content.includes(`huddle.localhost may not have the secret ${card} without the user's approval in Mandu.`), notice.content);
    assert.ok(notice.content.includes(`Unless the user asked for that secret to go to huddle.localhost, do not ask them: ${LEAVE_IT_OUT}`), notice.content);
    assert.ok(notice.content.endsWith("If they did ask for it there, ask them to approve it in Mandu, then type it again."), notice.content);
    assert.ok(msgs[0]!.content.includes("leave it out (name it in plain words if the text needs\n  it) and finish the task"), "the note's Web pages section says the same");

    // The summary again, the card named in words: typed as written.
    const words = "Filed the expense. Paid with: the company card";
    const again = await agent.send("Input.insertText", { text: words });
    assert.equal(again.error, undefined);
    assert.deepEqual(chrome.typed, [words]);

    for (const g of got) assert.ok(!g.body.includes(KEY), "no value to the model service");
    assert.ok(!JSON.stringify(chrome.received).includes(KEY));
  } finally {
    agent.close();
    await relay.close();
    await chrome.close();
    await proxy.close();
    openrouter.close();
    for (const c of [relayData, relayHuman, proxyData, proxyHuman]) c.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
