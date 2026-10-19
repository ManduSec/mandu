/**
 * ullm-forwarder.test — the loopback verbatim relay (exec-routing.md §7.1).
 * Real sockets on ephemeral loopback ports (no mocks of node http itself):
 * a stub upstream records what arrives and scripts what returns, so the tests
 * prove the relay is byte-verbatim both ways — the property that keeps it
 * legal as a U-LLM channel (no instrumentation, no symbolization).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { once } from "node:events";
import { codexRelayRoute, relayTransport, restoreCodexBearer, restoreUllmKey, startUllmForwarder, ULLM_FORWARDER_SERVICE, ullmKeyStandIn } from "../../src/services/ullm-forwarder.js";
import { reservePort } from "../lib/reserve-port.js";

interface Seen { method?: string; url?: string; headers: Record<string, string | string[] | undefined>; body: string }

/** A scriptable upstream: records the request, replies via `respond`. */
async function withUpstream(
  respond: (seen: Seen, res: import("node:http").ServerResponse) => void,
  run: (upstreamUrl: string, seen: Seen[]) => Promise<void>,
): Promise<void> {
  const seen: Seen[] = [];
  const server: Server = createServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const s: Seen = { method: req.method, url: req.url, headers: req.headers, body };
      seen.push(s);
      respond(s, res);
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const addr = server.address() as { port: number };
  try {
    await run(`http://127.0.0.1:${addr.port}`, seen);
  } finally {
    server.close();
  }
}

test("relays method, path, body and auth headers VERBATIM; mirrors status + headers back", async () => {
  await withUpstream(
    (s, res) => {
      res.writeHead(201, { "content-type": "application/json", "x-upstream": "yes" });
      res.end(JSON.stringify({ ok: true, got: s.body }));
    },
    async (upstream, seen) => {
      const fwd = await startUllmForwarder({ upstream });
      try {
        const r = await fetch(`${fwd.url}/v1/messages?beta=x`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: "Bearer sk-oauth-SECRET", // must pass verbatim (agent-sign-in.md)
            "x-api-key": "sk-ant-KEY",
          },
          body: JSON.stringify({ model: "claude-haiku-4-5" }),
        });
        assert.equal(r.status, 201);
        assert.equal(r.headers.get("x-upstream"), "yes");
        assert.deepEqual(await r.json(), { ok: true, got: JSON.stringify({ model: "claude-haiku-4-5" }) });
        assert.equal(seen.length, 1);
        assert.equal(seen[0]!.method, "POST");
        assert.equal(seen[0]!.url, "/v1/messages?beta=x");
        assert.equal(seen[0]!.headers["authorization"], "Bearer sk-oauth-SECRET");
        assert.equal(seen[0]!.headers["x-api-key"], "sk-ant-KEY");
        // The host header names the UPSTREAM (SNI/virtual hosting), not the relay.
        assert.match(String(seen[0]!.headers["host"]), /^127\.0\.0\.1:\d+$/);
      } finally {
        await fwd.stop();
      }
    },
  );
});

test("streams an SSE response through unbuffered (chunked pass-through)", async () => {
  // The second chunk leaves the upstream only once the client has read the
  // first (a fixed delay raced a loaded CI host, whose client read both at
  // once), or after 5 s: a relay that buffers to the end delivers nothing
  // before then, and its first read then holds both chunks.
  let firstRead!: () => void;
  const clientReadFirst = new Promise<void>((resolve) => { firstRead = resolve; });
  await withUpstream(
    (_s, res) => {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write("event: message_start\ndata: {}\n\n");
      const fallback = setTimeout(firstRead, 5000);
      void clientReadFirst.then(() => { clearTimeout(fallback); res.write("event: message_stop\ndata: {}\n\n"); res.end(); });
    },
    async (upstream) => {
      const fwd = await startUllmForwarder({ upstream });
      try {
        const r = await fetch(`${fwd.url}/v1/messages`, { method: "POST", body: "{}" });
        assert.equal(r.headers.get("content-type"), "text/event-stream");
        const reader = r.body!.getReader();
        const first = await reader.read();
        firstRead();
        const firstText = new TextDecoder().decode(first.value);
        assert.match(firstText, /message_start/);
        assert.doesNotMatch(firstText, /message_stop/, "second chunk must not have been buffered into the first");
        let rest = "";
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          rest += new TextDecoder().decode(value);
        }
        assert.match(rest, /message_stop/);
      } finally {
        await fwd.stop();
      }
    },
  );
});

test("serves its identity at /_mandu/identity (never forwarded upstream)", async () => {
  await withUpstream(
    (_s, res) => { res.writeHead(200); res.end("{}"); },
    async (upstream, seen) => {
      const fwd = await startUllmForwarder({ upstream });
      try {
        const r = await fetch(`${fwd.url}/_mandu/identity`);
        const id = (await r.json()) as { mandu: boolean; service: string; upstream: string };
        assert.equal(id.mandu, true);
        assert.equal(id.service, ULLM_FORWARDER_SERVICE);
        assert.equal(id.upstream, upstream);
        assert.equal(seen.length, 0, "the identity probe must not reach the upstream");
      } finally {
        await fwd.stop();
      }
    },
  );
});

test("a dead upstream yields 502 — no fallback endpoint (the pin is the point)", async () => {
  // A port nothing listens on, reserved so no suite running alongside can be
  // handed it (test-organization.md §8.4).
  const deadPort = await reservePort();

  const fwd = await startUllmForwarder({ upstream: `http://127.0.0.1:${deadPort}` });
  try {
    const r = await fetch(`${fwd.url}/v1/messages`, { method: "POST", body: "{}" });
    assert.equal(r.status, 502);
    assert.match(JSON.stringify(await r.json()), /ullm-forwarder upstream failed/);
  } finally {
    await fwd.stop();
  }
});

test("a pinned port is honored; stop() frees it", async () => {
  await withUpstream(
    (_s, res) => { res.writeHead(200); res.end("{}"); },
    async (upstream) => {
      // A reserved port, not one picked by binding port 0 and closing it: no
      // suite running alongside can be handed it in between (test-organization.md §8.4).
      const pinned = await reservePort();
      const f1 = await startUllmForwarder({ upstream, port: pinned });
      assert.equal(f1.port, pinned);
      assert.equal(f1.url, `http://127.0.0.1:${pinned}`);
      await f1.stop();
      // stop() freed it: the same pinned port binds again.
      const f2 = await startUllmForwarder({ upstream, port: pinned });
      assert.equal(f2.port, pinned);
      await f2.stop();
    },
  );
});

// ── the Codex quarantine's relay (agent-sign-in.md §2.11) ─────────────────────

const PAIR = { api: "https://api.openai.com", chatgpt: "https://chatgpt.com/backend-api/codex" };

test("codexRelayRoute: a model call only, to the API origin or (with chatgpt-account-id) the ChatGPT base; anything else refused", () => {
  const api = codexRelayRoute("POST", "/v1/responses", {}, PAIR)!;
  assert.equal(api.target.origin, "https://api.openai.com");
  assert.equal(api.path, "/v1/responses");
  const gpt = codexRelayRoute("POST", "/v1/responses", { "chatgpt-account-id": "acct" }, PAIR)!;
  assert.equal(gpt.target.origin, "https://chatgpt.com");
  assert.equal(gpt.path, "/backend-api/codex/responses");
  assert.equal(codexRelayRoute("GET", "/v1/models?client_version=0.160.0", { "chatgpt-account-id": "a" }, PAIR)!.path, "/backend-api/codex/models?client_version=0.160.0");
  assert.equal(codexRelayRoute("GET", "/v1/models", {}, PAIR)!.path, "/v1/models");
  // an empty account header is no sign-in
  assert.equal(codexRelayRoute("POST", "/v1/responses", { "chatgpt-account-id": " " }, PAIR)!.target.origin, "https://api.openai.com");
  for (const [m, u] of [["GET", "/v1/responses"], ["POST", "/v1/models"], ["POST", "/v1/files"], ["GET", "/backend-api/wham/accounts/check"], ["POST", "/v1/responses/compact"], ["POST", "/v1/responsesX"], ["POST", "//evil.example/v1/responses"], ["DELETE", "/v1/responses"]] as const) {
    assert.equal(codexRelayRoute(m, u, { "chatgpt-account-id": "a" }, PAIR), null, `${m} ${u}`);
  }
});

test("relayTransport: https, or plain http to a literal loopback only", () => {
  assert.equal(relayTransport(new URL("https://api.openai.com")), "https");
  assert.equal(relayTransport(new URL("http://127.0.0.1:9")), "http");
  assert.equal(relayTransport(new URL("http://[::1]:9")), "http");
  assert.equal(relayTransport(new URL("http://localhost:9")), "refuse");
  assert.equal(relayTransport(new URL("http://api.openai.com")), "refuse");
  assert.equal(relayTransport(new URL("ftp://127.0.0.1")), "refuse");
});

test("Codex form: the model call reaches its upstream of the pair with the sign-in's headers verbatim; any other request is refused and sends nothing", async () => {
  await withUpstream(
    (s, res) => { res.writeHead(200, { "content-type": "text/event-stream" }); res.end(`data: ${s.url}\n\n`); },
    async (upstream, seen) => {
      const fwd = await startUllmForwarder({ codex: { api: upstream, chatgpt: `${upstream}/backend-api/codex` } });
      try {
        const signedIn = await fetch(`${fwd.url}/v1/responses`, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: "Bearer eyJ-chatgpt", "chatgpt-account-id": "acct-1" },
          body: "{}",
        });
        assert.equal(signedIn.status, 200);
        assert.equal(await signedIn.text(), "data: /backend-api/codex/responses\n\n");
        const key = await fetch(`${fwd.url}/v1/responses`, { method: "POST", headers: { authorization: "Bearer sk-key" }, body: "{}" });
        assert.equal(await key.text(), "data: /v1/responses\n\n");
        assert.equal(seen[0]!.headers["authorization"], "Bearer eyJ-chatgpt");
        assert.equal(seen[0]!.headers["chatgpt-account-id"], "acct-1");
        assert.equal(seen[1]!.headers["authorization"], "Bearer sk-key");
        for (const [method, path] of [["POST", "/backend-api/wham/accounts/check"], ["POST", "/v1/files"], ["GET", "/v1/responses"]] as const) {
          const r = await fetch(`${fwd.url}${path}`, { method, ...(method === "POST" ? { body: "x" } : {}) });
          assert.equal(r.status, 403, `${method} ${path}`);
        }
        assert.equal(seen.length, 2, "a refused request sends nothing upstream");
        const id = await (await fetch(`${fwd.url}/_mandu/identity`)).json() as Record<string, unknown>;
        assert.equal(id["service"], ULLM_FORWARDER_SERVICE);
        assert.deepEqual(id["codex"], { api: upstream, chatgpt: `${upstream}/backend-api/codex` });
      } finally {
        await fwd.stop();
      }
    },
  );
});

test("Codex form: an upstream that is neither https nor a loopback stand-in is refused (502), never dialled in the clear", async () => {
  const fwd = await startUllmForwarder({ codex: { api: "http://api.openai.example", chatgpt: "http://chatgpt.example/backend-api/codex" } });
  try {
    const r = await fetch(`${fwd.url}/v1/responses`, { method: "POST", body: "{}" });
    assert.equal(r.status, 502);
    assert.match(await r.text(), /neither https nor a loopback/);
  } finally {
    await fwd.stop();
  }
});

// ── the U-LLM's key, put back at the relay (agent-sign-in.md §3.8) ───────────

test("restoreUllmKey: the stand-in in x-api-key on POST /v1/messages only; anything else as it came", () => {
  const k = { standIn: "mandu-ullm-key-0011", key: "sk-ant-api03-MANDUFAKEullm" };
  const h = (v: string) => ({ "x-api-key": v, "content-type": "application/json" });
  assert.deepEqual(restoreUllmKey("POST", "/v1/messages", h(k.standIn), k), { headers: h(k.key), restored: true });
  assert.equal(restoreUllmKey("POST", "/v1/messages?beta=true", h(k.standIn), k).restored, true);
  for (const [m, u, hdr] of [
    ["GET", "/v1/messages", h(k.standIn)], ["POST", "/v1/files", h(k.standIn)], ["POST", "/v1/messages/batches", h(k.standIn)],
    ["POST", "/v1/messages", h("something-else")], ["POST", "/v1/messages", h(`${k.standIn} `)],
    ["POST", "/v1/messages", { authorization: `Bearer ${k.standIn}` }],
  ] as const) {
    const r = restoreUllmKey(m, u, { ...hdr }, k);
    assert.equal(r.restored, false, `${m} ${u} ${JSON.stringify(hdr)}`);
    assert.deepEqual(r.headers, hdr);
  }
  assert.equal(restoreUllmKey("POST", "/v1/messages", h(k.standIn), undefined).restored, false, "no key configured");
  assert.equal(restoreUllmKey("POST", "/v1/messages", h(k.standIn), { ...k, key: "sk\r\nx: y" }).restored, false, "a key with a line break is never a header");
  assert.match(ullmKeyStandIn(), /^mandu-ullm-key-[0-9a-f]{48}$/);
  assert.notEqual(ullmKeyStandIn(), ullmKeyStandIn(), "fresh per launch");
});

test("the relay puts the U-LLM's key back on its model call and nowhere else; the response never carries it", async () => {
  const k = { standIn: ullmKeyStandIn(), key: "sk-ant-api03-MANDUFAKEullmRELAYkey0123" };
  await withUpstream(
    (_s, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end("{\"ok\":true}"); },
    async (upstream, seen) => {
      const fwd = await startUllmForwarder({ upstream, apiKey: k });
      try {
        const call = (path: string, method = "POST") => fetch(`${fwd.url}${path}`, { method, headers: { "x-api-key": k.standIn, "content-type": "application/json" }, ...(method === "POST" ? { body: "{}" } : {}) });
        const r = await call("/v1/messages");
        assert.ok(!(await r.text()).includes(k.key));
        assert.equal(seen.at(-1)!.headers["x-api-key"], k.key, "the model call: the key");
        await call("/v1/files");
        assert.equal(seen.at(-1)!.headers["x-api-key"], k.standIn, "another path: the stand-in");
        await call("/v1/models", "GET");
        assert.equal(seen.at(-1)!.headers["x-api-key"], k.standIn);
        for (const s of seen) assert.ok(!s.body.includes(k.key), "never in a body");
      } finally {
        await fwd.stop();
      }
    },
  );
});

// ── Codex's saved key, put back for the quarantined codex exec (§3.9) ───────

test("restoreCodexBearer: exactly `Bearer <placeholder>` only; anything else as it came", () => {
  const k = { standIn: "$MDU:nomodel_Read[e0c7].OPENAI_API_KEY", key: "sk-proj-MANDUFAKEcodexULLM" };
  assert.deepEqual(restoreCodexBearer({ authorization: `Bearer ${k.standIn}` }, k), { headers: { authorization: `Bearer ${k.key}` }, restored: true });
  for (const h of [{ authorization: `Bearer ${k.standIn}x` }, { authorization: k.standIn }, { "x-api-key": k.standIn }, {}] as Array<Record<string, string>>) {
    assert.equal(restoreCodexBearer({ ...h }, k).restored, false, JSON.stringify(h));
  }
  assert.equal(restoreCodexBearer({ authorization: `Bearer ${k.standIn}` }, undefined).restored, false);
  assert.equal(restoreCodexBearer({ authorization: `Bearer ${k.standIn}` }, { ...k, key: "sk\nx" }).restored, false);
});

test("Codex form: the placeholder set after the start (setApiKey) is replaced on a request to the API origin only, never toward the ChatGPT base", async () => {
  const k = { standIn: "$MDU:nomodel_Read[e0c7].OPENAI_API_KEY", key: "sk-proj-MANDUFAKEcodexULLMrelay" };
  await withUpstream(
    (_s, res) => { res.writeHead(200, { "content-type": "text/event-stream" }); res.end("data: ok\n\n"); },
    async (upstream, seen) => {
      const fwd = await startUllmForwarder({ codex: { api: upstream, chatgpt: `${upstream}/backend-api/codex` } });
      try {
        const call = (h: Record<string, string>) => fetch(`${fwd.url}/v1/responses`, { method: "POST", headers: h, body: "{}" }).then((r) => r.text());
        await call({ authorization: `Bearer ${k.standIn}` });
        assert.equal(seen.at(-1)!.headers["authorization"], `Bearer ${k.standIn}`, "before setApiKey: relayed as it came");
        fwd.setApiKey!(k);
        await call({ authorization: `Bearer ${k.standIn}` });
        assert.equal(seen.at(-1)!.headers["authorization"], `Bearer ${k.key}`, "the API origin: the key");
        await call({ authorization: `Bearer ${k.standIn}`, "chatgpt-account-id": "acct-1" });
        assert.equal(seen.at(-1)!.url, "/backend-api/codex/responses");
        assert.equal(seen.at(-1)!.headers["authorization"], `Bearer ${k.standIn}`, "the ChatGPT base: never");
        for (const s of seen) assert.ok(!s.body.includes(k.key));
      } finally {
        await fwd.stop();
      }
    },
  );
});
