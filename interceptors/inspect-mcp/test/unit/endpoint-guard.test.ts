/**
 * endpoint-guard.test: the loopback guard's sanctioned set and the declared
 * endpoint factory (Plan 11 D2/D5).
 *
 * The guard keeps refusing every loopback base URL except the forwarder pin
 * (default U-LLM) and, now, the declared model endpoints the ARBITER listed,
 * minus any whose origin equals the model proxy's or the forwarder's. A
 * declared endpoint at either of those addresses would send local-model bytes
 * to an external vendor, so no client is ever built for it.
 *
 * Axes: none read here (pure transport selection; the arbiter decides levels).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";

import {
  AnthropicUllmClient,
  OpenAiChatUllmClient,
  assertDeclaredEndpointUrl,
  assertNonProxyBaseUrl,
  endpointPlacement,
  sanctionedEndpointOrigins,
} from "../../src/ullm-client.js";
import { buildEndpointUllmClient, endpointApiBase, endpointGuardFromEnv, createEndpointUllmFactory } from "../../src/ullm-config.js";
import type { ModelEndpoint } from "../../src/arbiter-client.js";

const FWD = "http://127.0.0.1:47001";
const PROXY = "http://127.0.0.1:8788";
const OLLAMA: ModelEndpoint = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true };

test("assertNonProxyBaseUrl: the forwarder and sanctioned origins pass; every other loopback stays refused", () => {
  assert.equal(assertNonProxyBaseUrl(`${FWD}/`, FWD), `${FWD}/`);
  assert.equal(assertNonProxyBaseUrl("http://127.0.0.1:11434", undefined, ["http://127.0.0.1:11434"]), "http://127.0.0.1:11434");
  assert.throws(() => assertNonProxyBaseUrl(PROXY, FWD, ["http://127.0.0.1:11434"]), /loopback/);
  assert.throws(() => assertNonProxyBaseUrl("http://localhost:11434", undefined, ["http://127.0.0.1:11434"]), /loopback/,
    "origin match is exact: localhost is not 127.0.0.1");
  assert.equal(assertNonProxyBaseUrl("https://api.anthropic.com"), "https://api.anthropic.com");
});

test("sanctionedEndpointOrigins drops the proxy's and the forwarder's origin, and unparseable urls", () => {
  const eps = [
    OLLAMA,
    { name: "px", url: `${PROXY}/v1`, wire: "anthropic", local: true },
    { name: "fw", url: FWD, wire: "anthropic", local: true },
    { name: "bad", url: "not a url", wire: "openai-chat", local: true },
    { name: "cloud", url: "https://llm.example.com", wire: "anthropic", local: false },
  ] as ModelEndpoint[];
  assert.deepEqual(
    sanctionedEndpointOrigins(eps, { forwarderUrl: FWD, proxyUrls: [PROXY] }),
    ["http://127.0.0.1:11434", "https://llm.example.com"],
  );
});

test("assertDeclaredEndpointUrl refuses the proxy and the forwarder address and non-http urls", () => {
  const guard = { forwarderUrl: FWD, proxyUrls: [PROXY] };
  assert.equal(assertDeclaredEndpointUrl("ollama", OLLAMA.url, guard), OLLAMA.url);
  assert.throws(() => assertDeclaredEndpointUrl("px", `${PROXY}/`, guard), /model proxy's or the U-LLM forwarder's address/);
  assert.throws(() => assertDeclaredEndpointUrl("fw", FWD, guard), /model proxy's or the U-LLM forwarder's address/);
  assert.throws(() => assertDeclaredEndpointUrl("f", "file:///etc/passwd", guard), /no usable http\(s\) url/);
  assert.throws(() => assertDeclaredEndpointUrl("e", "", guard), /no usable/);
});

test("endpointGuardFromEnv: forwarder pin + MANDU_MODEL_PROXY_URL list + host proxies", () => {
  assert.deepEqual(
    endpointGuardFromEnv({ MANDU_ULLM_FORWARDER: FWD, MANDU_MODEL_PROXY_URL: ` ${PROXY} , http://127.0.0.1:8790 ` }, ["http://127.0.0.1:1", undefined]),
    { forwarderUrl: FWD, proxyUrls: [PROXY, "http://127.0.0.1:8790", "http://127.0.0.1:1"] },
  );
  assert.deepEqual(endpointGuardFromEnv({}), { forwarderUrl: undefined, proxyUrls: [] });
});

test("buildEndpointUllmClient: wire picks the client; proxy/forwarder entries and a model-less openai-chat refuse", () => {
  const env = { MANDU_ULLM_FORWARDER: FWD, MANDU_MODEL_PROXY_URL: PROXY };
  const factory = createEndpointUllmFactory(env);
  assert.ok(factory(OLLAMA, [OLLAMA]) instanceof OpenAiChatUllmClient);
  const anth: ModelEndpoint = { name: "lite", url: "http://127.0.0.1:4000", wire: "anthropic", local: true };
  assert.ok(factory(anth, [anth]) instanceof AnthropicUllmClient, "anthropic wire, keyless, loopback accepted as declared");
  assert.throws(() => factory({ ...OLLAMA, url: PROXY }, [{ ...OLLAMA, url: PROXY }]), /model proxy's/);
  assert.throws(() => factory({ ...anth, url: FWD }, [{ ...anth, url: FWD }]), /forwarder's address/);
  assert.throws(() => factory({ ...OLLAMA, model: undefined }, [{ ...OLLAMA, model: undefined }]), /model id is required/);
  assert.throws(
    () => buildEndpointUllmClient({ ...OLLAMA, wire: "grpc" as never }, [OLLAMA], {}, {}),
    /unknown wire/,
  );
});

test("anthropic wire at a declared endpoint: /v1/messages with x-api-key from tokenEnv, none without", async () => {
  const seen: Array<{ url: string; headers: IncomingMessage["headers"]; body: string }> = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      seen.push({ url: req.url ?? "", headers: req.headers, body });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ model: "local-claude", content: [{ type: "text", text: "done" }] }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const ep: ModelEndpoint = { name: "lite", url: base, wire: "anthropic", local: true, tokenEnv: "LITE_KEY" };
    const withKey = buildEndpointUllmClient(ep, [ep], {}, { LITE_KEY: "k-1" });
    assert.deepEqual(await withKey.complete({ system: "S", user: "U" }), { text: "done", model: "local-claude" });
    assert.equal(seen[0].url, "/v1/messages");
    assert.equal(seen[0].headers["x-api-key"], "k-1");
    const body = JSON.parse(seen[0].body) as Record<string, unknown>;
    assert.equal(body.system, "S");
    assert.deepEqual(body.messages, [{ role: "user", content: "U" }]);
    assert.ok(!("tools" in body));

    const keyless = buildEndpointUllmClient({ ...ep, tokenEnv: undefined }, [ep], {}, {});
    await keyless.complete({ system: "S", user: "U" });
    assert.equal(seen[1].headers["x-api-key"], undefined);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("endpointApiBase: one trailing /v1 and trailing slashes go; the origin and any other path stay", () => {
  assert.equal(endpointApiBase("http://127.0.0.1:11434"), "http://127.0.0.1:11434");
  assert.equal(endpointApiBase("http://127.0.0.1:11434/"), "http://127.0.0.1:11434");
  assert.equal(endpointApiBase("http://127.0.0.1:11434/v1"), "http://127.0.0.1:11434");
  assert.equal(endpointApiBase("http://127.0.0.1:11434/v1/"), "http://127.0.0.1:11434");
  assert.equal(endpointApiBase("https://gw.example/openai/v1"), "https://gw.example/openai");
  assert.equal(endpointApiBase("https://gw.example/v1beta"), "https://gw.example/v1beta");
  assert.equal(endpointApiBase("https://gw.example/v1/v1"), "https://gw.example/v1", "one segment only");
});

test("anthropic wire at a declared endpoint whose url ends in /v1 posts to /v1/messages", async () => {
  const seen: string[] = [];
  const server = createServer((req, res) => {
    seen.push(req.url ?? "");
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ model: "local-claude", content: [{ type: "text", text: "done" }] }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const ep: ModelEndpoint = { name: "lite", url: `${base}/v1`, wire: "anthropic", local: true };
    await buildEndpointUllmClient(ep, [ep], {}, {}).complete({ system: "S", user: "U" });
    assert.deepEqual(seen, ["/v1/messages"]);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("anthropic wire at a declared endpoint: error strings never quote the response body", async () => {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      if (req.url === "/v1/messages" && body.includes("E400")) { res.writeHead(400); res.end(`echo ${body}`); return; }
      res.writeHead(200, { "content-type": "text/plain" }); res.end(`echo ${body}`);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const ep: ModelEndpoint = { name: "lite", url: base, wire: "anthropic", local: true };
    const c = buildEndpointUllmClient(ep, [ep], {}, {});
    for (const user of ["E400 LOCAL-SECRET-BYTES", "LOCAL-SECRET-BYTES"]) {
      await assert.rejects(c.complete({ system: "S", user }), (err: Error) => {
        assert.ok(!err.message.includes("LOCAL-SECRET-BYTES"), err.message);
        return true;
      });
    }
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("the default Anthropic client still requires a key (only declared endpoints may be keyless)", () => {
  assert.throws(() => new AnthropicUllmClient({ apiKey: "" }), /apiKey is required/);
});

// ── Plan 12 D1/D2: placement, and plain http to another machine ────────────

test("endpointPlacement: loopback spellings are host; every other host is network (mirror of the arbiter's)", () => {
  for (const u of ["http://127.0.0.1:11434", "http://localhost:1", "http://gpu.localhost", "http://[::1]:1", "http://[::]:1",
    "http://0.0.0.0:1", "http://[::ffff:127.0.0.1]:1", "https://127.9.9.9"]) {
    assert.equal(endpointPlacement(u), "host", u);
  }
  for (const u of ["http://10.0.3.7:8000", "http://[fd00::1]:1", "https://llm.corp.example/v1", "http://localhost.corp.example", "http://8.8.8.8"]) {
    assert.equal(endpointPlacement(u), "network", u);
  }
  assert.equal(endpointPlacement("file:///x"), null);
});

test("assertDeclaredEndpointUrl: plain http to another machine is refused unless the entry opted out; https and loopback pass", () => {
  const guard = { forwarderUrl: FWD, proxyUrls: [PROXY] };
  for (const u of ["http://10.0.3.7:8000", "http://[fd00::7]:8000/v1", "http://llm.corp.example"]) {
    assert.throws(() => assertDeclaredEndpointUrl("lab", u, guard), /'lab' is plain http on another machine, so the data would cross the network unencrypted; refusing \(fail closed\)/, u);
    assert.equal(assertDeclaredEndpointUrl("lab", u, guard, { allowPlainHttp: true }), u, `${u} with the opt-out`);
  }
  assert.equal(assertDeclaredEndpointUrl("corp", "https://10.0.3.7:8443", guard), "https://10.0.3.7:8443");
  assert.equal(assertDeclaredEndpointUrl("tunnel", "http://localhost:18000", guard), "http://localhost:18000");
  // The opt-out never unlocks the proxy's or the forwarder's address.
  assert.throws(() => assertDeclaredEndpointUrl("px", PROXY, guard, { allowPlainHttp: true }), /model proxy's/);
});

test("buildEndpointUllmClient: both wires refuse plain http to another machine without allowPlainHttp, and build with it", () => {
  const factory = createEndpointUllmFactory({});
  const lab: ModelEndpoint = { name: "lab", url: "http://10.0.3.7:8000/v1", wire: "openai-chat", model: "qwen", local: true };
  const anth: ModelEndpoint = { name: "gw", url: "http://10.0.3.8:4000", wire: "anthropic", local: true };
  for (const ep of [lab, anth]) {
    assert.throws(() => factory(ep, [ep]), /plain http on another machine/, ep.wire);
    const opted = { ...ep, allowPlainHttp: true as const };
    assert.ok(factory(opted, [opted]), `${ep.wire} with allowPlainHttp`);
  }
  // Only the literal true counts (a wire value an older or odd arbiter sends).
  const odd = { ...lab, allowPlainHttp: "yes" as never };
  assert.throws(() => factory(odd, [odd]), /plain http on another machine/);
});
