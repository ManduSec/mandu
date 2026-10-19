/**
 * model-note — a real NetProxy on its TLS-inspected leg adds Mandu's handling
 * note to a browser agent's Chat Completions call to a model service
 * (src/model-note.ts; devtools-relay.md §6.5):
 *   - with the note on, `POST /api/v1/chat/completions` to openrouter.ai
 *     reaches the service with the arbiter's note as its first system
 *     message, the agent's messages and the page's placeholder as written,
 *     asked with a browser agent's capabilities;
 *   - another path, another host, the note off, and an arbiter with no note
 *     each leave the request as written (the last says why in the event);
 *   - a request the gate refuses is refused as before: the note step never
 *     runs and nothing reaches the service;
 *   - the DevTools relay's pending refusals for the proxy's session
 *     (devtools-relay.md §3.4) go in as one last `user` message, once; a
 *     compressed body leaves them pending; an arbiter that cannot give them
 *     sends the call with the note alone.
 * The service is a loopback TLS listener a mock-sites host route sends
 * openrouter.ai to, reached with the real curl through the proxy (the session
 * CA trusted), so nothing leaves the machine. Mandu-new (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile, spawnSync } from "node:child_process";

import { NetProxy } from "../../src/proxy.js";
import { MockArbiter, type MockArbiterOptions } from "../../src/arbiter-client.js";
import { MockSites } from "../../src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../src/ca.js";
import type { ModelNoteKind } from "../../src/model-note.js";
import { LEAVE_IT_OUT, relayNoticeText, type RelayNotice } from "../../src/relay-notice.js";
import { gzipSync } from "node:zlib";

const OPENSSL = opensslAvailable();
const HAS_CURL = spawnSync("curl", ["--version"], { stdio: "ignore" }).status === 0;
const SKIP = !OPENSSL ? "openssl unavailable" : !HAS_CURL ? "curl is not installed" : false;
const NOTE = "## Web pages\n\nfill or type the placeholder itself";
const PLACEHOLDER = "$MDU:nomodel_Read[ab12].STRIPE_SECRET_KEY";
const noop = (): void => {};
const SESSION = "s-model-note";

/** A loopback HTTPS listener for `host`, recording each request. */
async function listener(dir: string, host: string) {
  const ca = ensureCa(join(dir, `ca-${host}`));
  const leaf = leafForHost(ca, host);
  const seen: Array<{ method: string; url: string; body: string }> = [];
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      seen.push({ method: req.method ?? "", url: req.url ?? "", body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"choices":[]}');
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { seen, port: (server.address() as AddressInfo).port, caPath: ca.certPath, close: () => server.close() };
}

function curl(args: string[]): Promise<{ code: string; body: string }> {
  return new Promise((resolve) => {
    execFile("curl", ["-sS", "-w", "\n%{http_code}", "--max-time", "20", ...args], (_e, out) => {
      const i = out.lastIndexOf("\n");
      resolve({ code: out.slice(i + 1).trim(), body: out.slice(0, i) });
    });
  });
}

const request = JSON.stringify({
  model: "google/gemini-2.5-flash",
  messages: [
    { role: "system", content: "You are a browser agent." },
    { role: "user", content: `The page shows: Secret key ${PLACEHOLDER}` },
  ],
});

async function withProxy(
  opts: { modelNote?: ModelNoteKind | null; arbiter?: MockArbiterOptions },
  fn: (ctx: { via: string[]; service: Awaited<ReturnType<typeof listener>>; other: Awaited<ReturnType<typeof listener>>; arbiter: MockArbiter }) => Promise<void>,
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mdu-np-note-"));
  const service = await listener(dir, "openrouter.ai");
  const other = await listener(dir, "api.example.com");
  const sites = MockSites.fromYaml([
    "hosts:",
    "  - host: openrouter.ai", `    tls_to: 127.0.0.1:${service.port}`, `    tls_ca: ${JSON.stringify(service.caPath)}`,
    "  - host: api.example.com", `    tls_to: 127.0.0.1:${other.port}`, `    tls_ca: ${JSON.stringify(other.caPath)}`,
    "",
  ].join("\n"));
  const arbiter = new MockArbiter(opts.arbiter ?? {});
  const caDir = join(dir, "mitm");
  const proxy = new NetProxy({
    arbiter, log: noop, mockSites: sites, mitm: { caDir }, sessionId: SESSION,
    modelServices: ["openrouter.ai"],
    ...(opts.modelNote !== undefined ? { modelNote: opts.modelNote } : {}),
    attributeHolders: () => [{ procKey: "4242-1", ancestors: [] }],
  });
  try {
    const port = await proxy.listen(0);
    await fn({ via: ["-x", `http://127.0.0.1:${port}`, "--cacert", join(caDir, "mandu-egress-ca.pem"), "-H", "content-type: application/json"], service, other, arbiter });
  } finally {
    await proxy.close();
    service.close();
    other.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

const forwarded = (arbiter: MockArbiter): Array<Record<string, unknown>> =>
  (arbiter.emittedEvents as Array<Record<string, unknown>>).filter((e) => e["action"] === "forwarded");

test("the note on: a model service's Chat Completions call gets Mandu's note first, the agent's messages and the placeholder as written", { skip: SKIP, timeout: 60_000 }, async () => {
  await withProxy({ modelNote: "browser", arbiter: { handlingNote: NOTE } }, async ({ via, service, arbiter }) => {
    const r = await curl([...via, "-X", "POST", "--data-binary", request, "https://openrouter.ai/api/v1/chat/completions"]);
    assert.equal(r.code, "200", r.body);
    assert.equal(service.seen.length, 1);
    const sent = JSON.parse(service.seen[0]!.body);
    assert.deepEqual(sent.messages[0], { role: "system", content: NOTE });
    assert.deepEqual(sent.messages.slice(1), JSON.parse(request).messages);
    assert.ok(service.seen[0]!.body.includes(PLACEHOLDER), "the page's placeholder leaves as written (a model service)");
    assert.equal(arbiter.noteCalls.length, 1);
    assert.equal(arbiter.noteCalls[0]!.capabilities.browser, true);
    assert.equal(arbiter.noteCalls[0]!.capabilities.inspect, false);
    assert.equal(forwarded(arbiter)[0]!["modelNote"], "added");
  });
});

test("the note on: another path, another host, a GET leave as written; none asks for the note", { skip: SKIP, timeout: 60_000 }, async () => {
  await withProxy({ modelNote: "browser", arbiter: { handlingNote: NOTE, decisionFn: () => ({ allow: true, reason: "test" }), values: { [PLACEHOLDER]: "sk_live_TESTVALUE" } } }, async ({ via, service, other, arbiter }) => {
    assert.equal((await curl([...via, "-X", "POST", "--data-binary", request, "https://openrouter.ai/api/v1/responses"])).code, "200");
    assert.equal((await curl([...via, "https://openrouter.ai/api/v1/models"])).code, "200");
    const plain = JSON.stringify({ messages: [{ role: "user", content: "hi" }] });
    assert.equal((await curl([...via, "-X", "POST", "--data-binary", plain, "https://api.example.com/v1/chat/completions"])).code, "200");
    assert.deepEqual(service.seen.map((s) => s.body), [request, ""]);
    assert.deepEqual(other.seen.map((s) => s.body), [plain]);
    assert.equal(arbiter.noteCalls.length, 0);
    assert.ok(forwarded(arbiter).every((e) => e["modelNote"] === undefined));
  });
});

test("the note off (no DevTools relay): the call leaves as written and the arbiter is never asked", { skip: SKIP, timeout: 60_000 }, async () => {
  await withProxy({ arbiter: { handlingNote: NOTE } }, async ({ via, service, arbiter }) => {
    assert.equal((await curl([...via, "-X", "POST", "--data-binary", request, "https://openrouter.ai/api/v1/chat/completions"])).code, "200");
    assert.equal(service.seen[0]!.body, request);
    assert.equal(arbiter.noteCalls.length, 0);
  });
});

test("an arbiter that gives no note: the call leaves as written, and the event says why", { skip: SKIP, timeout: 60_000 }, async () => {
  await withProxy({ modelNote: "browser" }, async ({ via, service, arbiter }) => {
    assert.equal((await curl([...via, "-X", "POST", "--data-binary", request, "https://openrouter.ai/api/v1/chat/completions"])).code, "200");
    assert.equal(service.seen[0]!.body, request);
    assert.match(String(forwarded(arbiter)[0]!["modelNote"]), /^not added: the protection service did not give the note/);
  });
});

test("the relay's pending refusals go in as the last message, once, after the agent's latest; names only", { skip: SKIP, timeout: 60_000 }, async () => {
  const notice: RelayNotice = { kind: "unknown", page: "ledgerly.localhost", symbols: ["$MDU:web_fetch[8c4f].text"], shown: [PLACEHOLDER] };
  await withProxy({ modelNote: "browser", arbiter: { handlingNote: NOTE } }, async ({ via, service, arbiter }) => {
    arbiter.pendingNotices.set(SESSION, [notice]);
    arbiter.pendingNotices.set("another-session", [notice]);
    // A compressed body: left as written, the refusals not taken.
    const gz = gzipSync(Buffer.from(request));
    const dir = mkdtempSync(join(tmpdir(), "mdu-np-gz-"));
    const gzPath = join(dir, "body.gz");
    writeFileSync(gzPath, gz);
    assert.equal((await curl([...via, "-H", "content-encoding: gzip", "-X", "POST", "--data-binary", `@${gzPath}`, "https://openrouter.ai/api/v1/chat/completions"])).code, "200");
    rmSync(dir, { recursive: true, force: true });
    assert.deepEqual(arbiter.noticeTakes, [], "not taken for a body the step cannot read");

    assert.equal((await curl([...via, "-X", "POST", "--data-binary", request, "https://openrouter.ai/api/v1/chat/completions"])).code, "200");
    const sent = JSON.parse(service.seen[1]!.body);
    assert.deepEqual(sent.messages[0], { role: "system", content: NOTE }, "the note first, as before");
    assert.deepEqual(sent.messages.slice(1, -1), JSON.parse(request).messages);
    assert.deepEqual(sent.messages.at(-1), { role: "user", content: relayNoticeText([notice]) });
    assert.deepEqual(arbiter.noticeTakes, [SESSION], "the proxy's own session's");
    assert.equal(forwarded(arbiter)[1]!["relayNotices"], 1);

    // Told once: the next call carries the note alone.
    assert.equal((await curl([...via, "-X", "POST", "--data-binary", request, "https://openrouter.ai/api/v1/chat/completions"])).code, "200");
    assert.equal(JSON.parse(service.seen[2]!.body).messages.length, 3);
    assert.equal(forwarded(arbiter)[2]!["relayNotices"], undefined);
    assert.deepEqual(arbiter.pendingNotices.get("another-session"), [notice], "another session's stay");
  });
});

test("a site that may not have the secret (an open ask, an unbound site): the model's next call is told to leave it out and go on, and to ask only if the user asked for it there; names only", { skip: SKIP, timeout: 60_000 }, async () => {
  // Live 2026-10-19 (the expense-report demo): told only to ask, the model
  // stopped before posting a team-chat summary that never needed the card.
  const ask: RelayNotice = { kind: "needs-approval", page: "huddle.localhost", symbols: [PLACEHOLDER] };
  const denied: RelayNotice = { kind: "not-allowed", page: "chat.localhost", symbols: [PLACEHOLDER] };
  await withProxy({ modelNote: "browser", arbiter: { handlingNote: NOTE } }, async ({ via, service, arbiter }) => {
    arbiter.pendingNotices.set(SESSION, [ask]);
    assert.equal((await curl([...via, "-X", "POST", "--data-binary", request, "https://openrouter.ai/api/v1/chat/completions"])).code, "200");
    const told = JSON.parse(service.seen[0]!.body).messages.at(-1) as { role: string; content: string };
    assert.equal(told.role, "user");
    assert.equal(told.content, relayNoticeText([ask]));
    assert.ok(told.content.includes(`huddle.localhost may not have the secret ${PLACEHOLDER} without the user's approval in Mandu.`), told.content);
    assert.ok(told.content.includes(`Unless the user asked for that secret to go to huddle.localhost, do not ask them: ${LEAVE_IT_OUT}`), told.content);
    assert.ok(told.content.endsWith("If they did ask for it there, ask them to approve it in Mandu, then type it again."), told.content);

    arbiter.pendingNotices.set(SESSION, [denied]);
    assert.equal((await curl([...via, "-X", "POST", "--data-binary", request, "https://openrouter.ai/api/v1/chat/completions"])).code, "200");
    const deniedTold = (JSON.parse(service.seen[1]!.body).messages.at(-1) as { content: string }).content;
    assert.ok(deniedTold.includes(`chat.localhost may not have the secret ${PLACEHOLDER}. Do not type it there again: ${LEAVE_IT_OUT}`), deniedTold);
    assert.equal(forwarded(arbiter)[1]!["relayNotices"], 1);
  });
});

test("an arbiter that cannot give the relay's refusals: the call goes with the note alone", { skip: SKIP, timeout: 60_000 }, async () => {
  await withProxy({ modelNote: "browser", arbiter: { handlingNote: NOTE, failRelayNotices: true } }, async ({ via, service, arbiter }) => {
    assert.equal((await curl([...via, "-X", "POST", "--data-binary", request, "https://openrouter.ai/api/v1/chat/completions"])).code, "200");
    const sent = JSON.parse(service.seen[0]!.body);
    assert.equal(sent.messages.length, 3);
    assert.equal(forwarded(arbiter)[0]!["modelNote"], "added");
  });
});

test("a call the gate refuses is refused as before: no note asked for, nothing reaches the service", { skip: SKIP, timeout: 60_000 }, async () => {
  // A raw registered value in the body: the tripwire refuses it at a model
  // service too (agent-sign-in.md §3.12).
  const raw = "sk_live_RAWVALUE_0123456789abcdef";
  await withProxy({ modelNote: "browser", arbiter: { handlingNote: NOTE, fingerprintSecrets: [{ symbol: PLACEHOLDER, value: raw, level: "no-model" }] } }, async ({ via, service, arbiter }) => {
    const body = JSON.stringify({ messages: [{ role: "user", content: `key ${raw}` }] });
    const r = await curl([...via, "-X", "POST", "--data-binary", body, "https://openrouter.ai/api/v1/chat/completions"]);
    assert.equal(r.code, "403", r.body);
    assert.deepEqual(service.seen, []);
    assert.equal(arbiter.noteCalls.length, 0);
  });
});
