/**
 * model-endpoints.test — the launcher's side of policy.yaml `models:`
 * (confidentiality-plan-11 D2/D5): shape checks, origin normalization,
 * loopback-origin equality, the reserved-address refusal, the confine port /
 * guard-spec derivation, and the `modelEndpoints` read over a fake arbiter
 * socket (ok / unknown op / mute / malformed / unreadable local entry).
 * Phase 3 (plan 11 §5): the base-URL → declared-entry match, the proxy
 * upstream it yields (and the plain-http refusal), and the session's main
 * model bind over the same fake socket.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stateAxes } from "../axes.js";
import {
  endpointApiBase,
  helperEndpointName,
  asModelEndpoint,
  assertLocalEndpoints,
  addressReach,
  bindSessionUpstream,
  endpointPlacement,
  hostClass,
  isPlainHttpLocal,
  plainHttpWarnings,
  PlainHttpLocalModelError,
  PerimeterLocalModelError,
  perimeterViolations,
  isLoopbackHost,
  localEndpointConflicts,
  helperEndpointEntry,
  helperEndpointGuardSpecs,
  helperEndpointPorts,
  localModelClientKeys,
  localModelTokens,
  ModelEndpointConflictError,
  parseOrigin,
  readModelEndpoints,
  reservedAddresses,
  sameAddress,
  selectTllmEndpoint,
  tllmUpstream,
  TllmUpstreamError,
  type ModelEndpoint,
} from "../../src/model-endpoints.js";
import { isGuardSpec } from "../../src/net-guard-law.js";

// The level decisions live in the arbiter; this suite exercises the launcher's
// plumbing only, under the mode that has `local-model` in play.
stateAxes("secrets");

const ollama: ModelEndpoint = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true };
const cloud: ModelEndpoint = { name: "cloud", url: "https://api.example.com/llm", wire: "anthropic", local: false };

test("asModelEndpoint: the arbiter's wire shape, strictly; wire defaults to anthropic, local to false", () => {
  assert.deepEqual(asModelEndpoint({ name: "o", url: "http://127.0.0.1:11434" }), { name: "o", url: "http://127.0.0.1:11434", wire: "anthropic", local: false });
  assert.deepEqual(
    asModelEndpoint({ name: "o.1_x-y", url: "http://h:1/p", wire: "openai-chat", model: "m", local: true, tokenEnv: "OLLAMA_TOKEN" }),
    { name: "o.1_x-y", url: "http://h:1/p", wire: "openai-chat", model: "m", local: true, tokenEnv: "OLLAMA_TOKEN" },
  );
  for (const bad of [
    null, 42, {}, { name: "a b", url: "http://h" }, { name: "a", url: "ftp://h" }, { name: "a", url: "not a url" },
    { name: "a", url: "http://h", wire: "grpc" }, { name: "a", url: "http://h", local: "yes" },
    { name: "a", url: "http://h", model: "" }, { name: "a", url: "http://h", tokenEnv: "1BAD" },
  ]) assert.equal(asModelEndpoint(bad), null, JSON.stringify(bad));
});

test("asModelEndpoint: helper: true is kept on a local entry only; a non-boolean helper refuses the entry", () => {
  assert.equal(asModelEndpoint({ name: "o", url: "http://h:1", local: true, helper: true })?.helper, true);
  assert.equal(asModelEndpoint({ name: "o", url: "http://h:1", local: false, helper: true })?.helper, undefined);
  assert.equal("helper" in asModelEndpoint({ name: "o", url: "http://h:1", local: true, helper: false })!, false);
  assert.equal(asModelEndpoint({ name: "o", url: "http://h:1", local: true, helper: "yes" }), null);
});

test("helperEndpointName: the marked local entry, else the first local one, else null (inspect-mcp's rule)", () => {
  const a: ModelEndpoint = { name: "a", url: "http://h:1", wire: "anthropic", local: false };
  const b: ModelEndpoint = { name: "b", url: "http://h:2/v1", wire: "openai-chat", local: true };
  const c: ModelEndpoint = { name: "c", url: "http://h:2", wire: "openai-chat", local: true };
  assert.equal(helperEndpointName([a, b, c]), "b");
  assert.equal(helperEndpointName([a, b, { ...c, helper: true }]), "c");
  assert.equal(helperEndpointName([a]), null);
  assert.equal(helperEndpointName([]), null);
});

test("endpointApiBase: one trailing /v1 and trailing slashes go (inspect-mcp's rule)", () => {
  assert.equal(endpointApiBase("http://127.0.0.1:11434/v1/"), "http://127.0.0.1:11434");
  assert.equal(endpointApiBase("http://127.0.0.1:11434"), "http://127.0.0.1:11434");
  assert.equal(endpointApiBase("https://gw.example/openai/v1"), "https://gw.example/openai");
  assert.equal(endpointApiBase("https://gw.example/v1beta"), "https://gw.example/v1beta");
});

test("parseOrigin: scheme default ports, lowercase host, brackets stripped, IPv4 shorthand and mapped IPv6 canonicalized", () => {
  assert.deepEqual(parseOrigin("http://127.0.0.1:11434"), { scheme: "http", host: "127.0.0.1", port: 11434 });
  assert.deepEqual(parseOrigin("https://API.Example.com/v1"), { scheme: "https", host: "api.example.com", port: 443 });
  assert.deepEqual(parseOrigin("http://gpu.lan"), { scheme: "http", host: "gpu.lan", port: 80 });
  assert.deepEqual(parseOrigin("http://[::1]:8788"), { scheme: "http", host: "::1", port: 8788 });
  assert.deepEqual(parseOrigin("http://127.1:8788"), { scheme: "http", host: "127.0.0.1", port: 8788 });
  assert.deepEqual(parseOrigin("http://0x7f.0.0.1:8788"), { scheme: "http", host: "127.0.0.1", port: 8788 });
  assert.deepEqual(parseOrigin("http://[::ffff:127.0.0.1]:8788"), { scheme: "http", host: "127.0.0.1", port: 8788 });
  assert.deepEqual(parseOrigin("http://localhost.:8788"), { scheme: "http", host: "localhost", port: 8788 });
  for (const bad of ["", "ftp://h", "unix:/x", "http://", "no scheme"]) assert.equal(parseOrigin(bad), null, bad);
});

test("isLoopbackHost / hostClass: loopback spellings, link-local, RFC 1918 + ULA, public, names", () => {
  for (const h of ["localhost", "LOCALHOST", "foo.localhost", "127.0.0.1", "127.0.1.1", "::1", "[::1]", "0.0.0.0", "::"]) assert.ok(isLoopbackHost(h), h);
  for (const h of ["10.0.0.1", "gpu.lan", "::2", "128.0.0.1"]) assert.ok(!isLoopbackHost(h), h);
  assert.equal(hostClass("127.0.0.1"), "loopback");
  assert.equal(hostClass("169.254.3.4"), "link-local");
  assert.equal(hostClass("fe80::1"), "link-local");
  for (const h of ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.5", "fd00::1"]) assert.equal(hostClass(h), "private", h);
  for (const h of ["8.8.8.8", "172.32.0.1", "2001:db8::1"]) assert.equal(hostClass(h), "public", h);
  assert.equal(hostClass("gpu.lan"), "name");
});

test("sameAddress: every loopback spelling is one host, the scheme is not compared, the port always is", () => {
  const proxy = { host: "127.0.0.1", port: 8788 };
  for (const url of ["http://localhost:8788", "https://127.0.0.1:8788", "http://[::1]:8788", "http://127.0.1.1:8788", "http://0.0.0.0:8788", "http://127.1:8788"]) {
    assert.ok(sameAddress(parseOrigin(url)!, proxy), url);
  }
  assert.ok(!sameAddress(parseOrigin("http://localhost:11434")!, proxy), "another port");
  assert.ok(!sameAddress(parseOrigin("http://10.0.0.5:8788")!, proxy), "another host, loopback proxy");
  // A name resolved to loopback, and a proxy bound to the unspecified address
  // answering on this machine's own interface address.
  assert.ok(sameAddress({ host: "devbox", port: 8788 }, proxy, { resolved: new Map([["devbox", ["127.0.1.1"]]]) }));
  assert.ok(sameAddress({ host: "10.0.0.5", port: 8788 }, { host: "0.0.0.0", port: 8788 }, { localAddresses: ["10.0.0.5"] }));
  assert.ok(!sameAddress({ host: "10.0.0.6", port: 8788 }, { host: "0.0.0.0", port: 8788 }, { localAddresses: ["10.0.0.5"] }));
});

test("reservedAddresses: both proxies and the forwarder when their port is adopted; port 0 reserves nothing", () => {
  const r = reservedAddresses({ proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 0 }, ullmForwarder: { host: "127.0.0.1", port: 40001 } });
  assert.deepEqual(r.map((a) => [a.role, a.port]), [["the model proxy (anthropic-proxy)", 8788], ["the U-LLM forwarder", 40001]]);
  assert.deepEqual(reservedAddresses({ proxy: { host: "127.0.0.1", port: 0 }, openaiProxy: { host: "127.0.0.1", port: 0 } }), []);
});

test("localEndpointConflicts: a local entry at the proxy or forwarder address conflicts; an external entry there never does", () => {
  const reserved = reservedAddresses({ proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 0 }, ullmForwarder: { host: "127.0.0.1", port: 40001 } });
  const atProxy: ModelEndpoint = { name: "sneaky", url: "http://localhost:8788", wire: "anthropic", local: true };
  const atFwd: ModelEndpoint = { name: "fwd", url: "http://[::1]:40001/", wire: "anthropic", local: true };
  const extAtProxy: ModelEndpoint = { ...atProxy, name: "ext", local: false };
  const c = localEndpointConflicts([ollama, atProxy, atFwd, extAtProxy, cloud], reserved);
  assert.deepEqual(c.map((x) => [x.endpoint.name, x.reserved.role]), [["sneaky", "the model proxy (anthropic-proxy)"], ["fwd", "the U-LLM forwarder"]]);
  const err = new ModelEndpointConflictError(c);
  assert.match(err.message, /refusing to launch/);
  assert.match(err.message, /models: sneaky \(http:\/\/localhost:8788\) is the model proxy \(anthropic-proxy\) at 127\.0\.0\.1:8788/);
  assert.match(err.message, /remove `local: true`/);
});

test("helperEndpointPorts / helperEndpointGuardSpecs: only the helper's entry, loopback pinned to the loopback pair, others to their host", () => {
  const lan: ModelEndpoint = { name: "lan", url: "http://192.168.1.5:8000", wire: "openai-chat", local: true };
  const v6: ModelEndpoint = { name: "v6", url: "http://[fd00::7]:9000", wire: "openai-chat", local: true };
  const named: ModelEndpoint = { name: "named", url: "http://localhost:11434", wire: "openai-chat", local: true };
  // No helper mark: the FIRST local entry, and nothing for the other local ones.
  assert.deepEqual(helperEndpointPorts([cloud, ollama, lan, named]), [11434]);
  assert.deepEqual(helperEndpointGuardSpecs([cloud, ollama, lan, v6, named]), ["tcp:127.0.0.0/8:11434", "tcp:[::1]:11434"]);
  // The helper mark wins wherever it sits, and only its port opens.
  assert.deepEqual(helperEndpointPorts([ollama, { ...lan, helper: true }, named]), [8000]);
  assert.deepEqual(helperEndpointGuardSpecs([ollama, { ...lan, helper: true }]), ["tcp:192.168.1.5:8000"]);
  assert.deepEqual(helperEndpointGuardSpecs([{ ...v6, helper: true }, ollama]), ["tcp:[fd00::7]:9000"]);
  for (const specs of [helperEndpointGuardSpecs([ollama]), helperEndpointGuardSpecs([lan]), helperEndpointGuardSpecs([v6])]) {
    assert.ok(specs.every(isGuardSpec), "every spec is one the guard accepts");
  }
  // A helper mark on an external entry never counts (the validator refuses
  // one; the confine follows inspect-mcp's rule, fail closed).
  assert.equal(helperEndpointEntry([{ ...cloud, helper: true }, lan])?.name, "lan");
  assert.deepEqual(helperEndpointPorts([cloud]), [], "an external endpoint opens nothing");
  assert.deepEqual(helperEndpointGuardSpecs([cloud]), []);
  assert.deepEqual(helperEndpointPorts([]), []);
  assert.deepEqual(helperEndpointPorts([{ ...lan, url: "not a url" }]), [], "an unparsable helper url opens nothing");
});

function fakeArbiter(answer: (op: string, req: Record<string, unknown>) => unknown): Promise<{ sock: string; close: () => Promise<void> }> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-model-endpoints-"));
  const sock = join(dir, "arbiter.sock");
  const server: Server = createServer((c) => {
    let buf = "";
    c.setEncoding("utf8");
    c.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      const req = JSON.parse(buf.slice(0, nl)) as { id: unknown; op: string };
      buf = buf.slice(nl + 1);
      const a = answer(req.op, req as unknown as Record<string, unknown>);
      if (a === null) return;
      c.write((typeof a === "string" ? a : JSON.stringify({ id: req.id, ...(a as object) })) + "\n");
    });
  });
  return new Promise((resolve) => {
    server.listen(sock, () => resolve({
      sock,
      close: () => new Promise<void>((r) => server.close(() => { rmSync(dir, { recursive: true, force: true }); r(); })),
    }));
  });
}

test("readModelEndpoints: ok (validated, deduped by name), unknown op → unsupported, mute / malformed / absent → unavailable", async () => {
  const good = await fakeArbiter((op) => op === "modelEndpoints"
    ? { ok: true, result: { endpoints: [ollama, { ...ollama, url: "http://dup" }, cloud, { name: "bad", url: "ftp://x", local: true }, { url: "nope" }] } }
    : { ok: false, error: `unknown op: ${op}` });
  try {
    const r = await readModelEndpoints(good.sock, 1000);
    assert.equal(r.status, "ok");
    assert.deepEqual(r.endpoints, [ollama, cloud]);
    assert.deepEqual(r.dropped, ["bad", "(unnamed)"]);
    assert.deepEqual(r.droppedLocal, ["bad"]);
  } finally { await good.close(); }

  const old = await fakeArbiter((op) => ({ ok: false, error: `unknown op: ${op}` }));
  try { assert.deepEqual(await readModelEndpoints(old.sock, 1000), { status: "unsupported", endpoints: [], dropped: [] }); } finally { await old.close(); }

  const mute = await fakeArbiter(() => null);
  try { assert.equal((await readModelEndpoints(mute.sock, 200)).status, "unavailable"); } finally { await mute.close(); }

  const junk = await fakeArbiter(() => "{not json");
  try { assert.equal((await readModelEndpoints(junk.sock, 1000)).status, "unavailable"); } finally { await junk.close(); }

  const shape = await fakeArbiter(() => ({ ok: true, result: { endpoints: "nope" } }));
  try { assert.equal((await readModelEndpoints(shape.sock, 1000)).status, "unavailable"); } finally { await shape.close(); }

  assert.equal((await readModelEndpoints(join(tmpdir(), "definitely-absent-mdu.sock"), 500)).status, "unavailable");
});

test("assertLocalEndpoints: refuses a local entry at a reserved address (by name too), refuses an unreadable local entry, passes otherwise", async () => {
  const reserved = reservedAddresses({ proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 0 } });
  const noNet = { lookup: async () => [] as string[], localAddresses: () => [] as string[] };
  await assertLocalEndpoints({ status: "ok", endpoints: [ollama, cloud], dropped: [] }, reserved, noNet);
  await assert.rejects(
    assertLocalEndpoints({ status: "ok", endpoints: [{ ...ollama, url: "http://localhost:8788" }], dropped: [] }, reserved, noNet),
    ModelEndpointConflictError,
  );
  // A host name that resolves to this machine's loopback: caught by the lookup.
  const looked: string[] = [];
  await assert.rejects(
    assertLocalEndpoints({ status: "ok", endpoints: [{ ...ollama, url: "http://my-box:8788" }], dropped: [] }, reserved, {
      lookup: async (n) => { looked.push(n); return ["127.0.1.1"]; },
      localAddresses: () => [],
    }),
    ModelEndpointConflictError,
  );
  assert.deepEqual(looked, ["my-box"]);
  await assert.rejects(
    assertLocalEndpoints({ status: "ok", endpoints: [], dropped: ["bad"], droppedLocal: ["bad"] }, reserved, noNet),
    /models: bad is declared `local: true` but the launcher cannot read the entry/,
  );
  // Plan 12 D2: a local entry on another machine over plain http refuses (an
  // older arbiter serves it); the opt-out passes, https passes, an outside entry passes.
  const lab: ModelEndpoint = { name: "lab", url: "http://10.0.3.7:8000", wire: "openai-chat", model: "qwen", local: true };
  await assert.rejects(
    assertLocalEndpoints({ status: "ok", endpoints: [ollama, lab], dropped: [] }, reserved, noNet),
    (e: unknown) => e instanceof PlainHttpLocalModelError && /models: lab \(http:\/\/10\.0\.3\.7:8000\)/.test(e.message) &&
      /allow_plain_http: true/.test(e.message) && !/ — /.test(e.message),
  );
  await assertLocalEndpoints({ status: "ok", endpoints: [{ ...lab, allowPlainHttp: true }], dropped: [] }, reserved, noNet);
  await assertLocalEndpoints({ status: "ok", endpoints: [{ ...lab, url: "https://10.0.3.7:8443" }], dropped: [] }, reserved, noNet);
  await assertLocalEndpoints({ status: "ok", endpoints: [{ ...lab, local: false }], dropped: [] }, reserved, noNet);
  // Nothing to check when the arbiter could not say (the caller logs it).
  await assertLocalEndpoints({ status: "unavailable", endpoints: [], dropped: [] }, reserved, noNet);
  await assertLocalEndpoints({ status: "unsupported", endpoints: [], dropped: [] }, reserved, noNet);
});

// ── Phase 3: the main model as a declared endpoint (plan 11 §5) ─────────────

const gpu: ModelEndpoint = { name: "gpu", url: "http://127.0.0.1:8080", wire: "anthropic", local: true };
const gw: ModelEndpoint = { name: "gw", url: "https://gw.example.com/anthropic/", wire: "anthropic", local: false };
const v6: ModelEndpoint = { name: "v6", url: "http://[::1]:9000", wire: "anthropic", local: true };

test("selectTllmEndpoint: normalized url equality over anthropic entries; first wins; openai-chat and query/fragment never match", () => {
  const eps = [ollama, gpu, gw, v6];
  // Trailing slash, explicit default port, host case.
  assert.equal(selectTllmEndpoint("http://127.0.0.1:8080/", eps), gpu);
  assert.equal(selectTllmEndpoint("https://GW.Example.COM:443/anthropic", eps), gw);
  assert.equal(selectTllmEndpoint("https://gw.example.com/anthropic//", eps), gw);
  // IPv6 brackets, spelled either way.
  assert.equal(selectTllmEndpoint("http://[0:0:0:0:0:0:0:1]:9000", eps), v6);
  // The path is part of the identity: a prefix or a sibling path is another URL.
  assert.equal(selectTllmEndpoint("https://gw.example.com", eps), null);
  assert.equal(selectTllmEndpoint("https://gw.example.com/anthropic/v1", eps), null);
  assert.equal(selectTllmEndpoint("https://gw.example.com/other", eps), null);
  // Scheme and port are compared; no DNS (localhost is not 127.0.0.1 here).
  assert.equal(selectTllmEndpoint("https://127.0.0.1:8080", eps), null);
  assert.equal(selectTllmEndpoint("http://127.0.0.1:8081", eps), null);
  assert.equal(selectTllmEndpoint("http://localhost:8080", eps), null);
  // openai-chat never becomes the main model, even at the exact url.
  assert.equal(selectTllmEndpoint("http://127.0.0.1:11434", eps), null);
  // A query or fragment (even an empty one) never matches.
  assert.equal(selectTllmEndpoint("http://127.0.0.1:8080/?x=1", eps), null);
  assert.equal(selectTllmEndpoint("http://127.0.0.1:8080/#top", eps), null);
  assert.equal(selectTllmEndpoint("http://127.0.0.1:8080?", eps), null);
  assert.equal(selectTllmEndpoint("not a url", eps), null);
  assert.equal(selectTllmEndpoint("http://127.0.0.1:8080", []), null);
  // First wins (the file's order, as the arbiter reports it).
  const twin: ModelEndpoint = { ...gpu, name: "gpu-2", local: false };
  assert.equal(selectTllmEndpoint("http://127.0.0.1:8080", [twin, gpu])?.name, "gpu-2");
  assert.equal(selectTllmEndpoint("http://127.0.0.1:8080", [{ ...ollama, url: gpu.url }, gpu])?.name, "gpu", "an openai-chat entry earlier in the list is skipped");
});

test("selectTllmEndpoint for Codex (plan 11 §7.2): the openai wire matches openai-chat entries only, path included", () => {
  const oll: ModelEndpoint = { name: "oll", url: "http://localhost:11434/v1", wire: "openai-chat", local: true };
  const eps = [gpu, { ...gpu, name: "gpu-v1", url: "http://localhost:11434/v1" }, oll];
  assert.equal(selectTllmEndpoint("http://LOCALHOST:11434/v1/", eps, "openai")?.name, "oll", "the anthropic entry at the same url is skipped");
  assert.equal(selectTllmEndpoint("http://localhost:11434/v1", eps, "anthropic")?.name, "gpu-v1", "and the reverse");
  assert.equal(selectTllmEndpoint("http://localhost:11434", eps, "openai"), null, "the base path is part of the identity");
  assert.equal(selectTllmEndpoint("http://127.0.0.1:8080", eps, "openai"), null);
  assert.equal(selectTllmEndpoint("http://127.0.0.1:11434", [ollama], "openai"), ollama);
});

test("tllmUpstream / TllmUpstreamError name the agent's own knob", () => {
  assert.throws(() => tllmUpstream("http://192.168.1.20:8000/v1", "MANDU_OPENAI_BASE_URL"), /\(MANDU_OPENAI_BASE_URL, declared in policy\.yaml models:\)/);
  assert.equal(tllmUpstream("http://localhost:11434/v1/", "MANDU_OPENAI_BASE_URL"), "http://127.0.0.1:11434/v1");
});

test("tllmUpstream: localhost names become the literal 127.0.0.1 (port and path kept); literal loopback and https pass; plain http off this machine throws", () => {
  assert.equal(tllmUpstream("http://localhost:11434/"), "http://127.0.0.1:11434");
  assert.equal(tllmUpstream("http://LOCALHOST:8080/anthropic/"), "http://127.0.0.1:8080/anthropic");
  assert.equal(tllmUpstream("http://model.localhost:8080"), "http://127.0.0.1:8080");
  assert.equal(tllmUpstream("http://127.0.0.2:8080"), "http://127.0.0.2:8080");
  assert.equal(tllmUpstream("http://[::1]:9000/"), "http://[::1]:9000");
  assert.equal(tllmUpstream("http://localhost"), "http://127.0.0.1");
  assert.equal(tllmUpstream("https://192.168.1.20:8443/v1/"), "https://192.168.1.20:8443/v1");
  assert.equal(tllmUpstream("https://gw.example.com:443/anthropic"), "https://gw.example.com/anthropic");
  for (const url of ["http://192.168.1.20:8080", "http://gpu-box:8080", "http://0.0.0.0:8080", "http://[fd00::1]:8080"]) {
    assert.throws(() => tllmUpstream(url), (e: Error) => {
      assert.ok(e instanceof TllmUpstreamError, url);
      assert.equal(e.name, "TllmUpstreamError");
      assert.match(e.message, /^mandu: refusing to launch: /);
      assert.ok(e.message.includes(url), "the message names the url");
      assert.match(e.message, /plain http only to this machine/);
      assert.match(e.message, /Put the model behind https, or run it on this machine/);
      assert.ok(!/ — /.test(e.message), "no em-dash interjection in user-facing copy");
      return true;
    });
  }
});

test("bindSessionUpstream: asks for the clean reporter only when told to, and reads the offer back (§5.3)", async () => {
  const seen: Array<Record<string, unknown>> = [];
  const arb = await fakeArbiter((_op, req) => {
    seen.push(req);
    return { ok: true, result: { sessionKey: req["sessionKey"], endpoint: null, location: "external", bound: true, cleanReporter: req["cleanReporter"] === true } };
  });
  try {
    assert.deepEqual(await bindSessionUpstream(arb.sock, "sid-1", null, 1000, true), { status: "ok", location: "external", cleanReporter: true });
    assert.deepEqual(await bindSessionUpstream(arb.sock, "sid-2", null, 1000), { status: "ok", location: "external" });
    assert.equal(seen[0]!["cleanReporter"], true);
    assert.equal("cleanReporter" in seen[1]!, false, "an old arbiter sees the request it always saw");
  } finally { await arb.close(); }
});

test("bindSessionUpstream: the wire request; ok → location; unknown op → unsupported; refusal → refused; mute / malformed / absent → unavailable", async () => {
  const seen: Array<Record<string, unknown>> = [];
  const good = await fakeArbiter((op, req) => {
    seen.push(req);
    return op === "setSessionUpstream"
      ? { ok: true, result: { sessionKey: req["sessionKey"], endpoint: req["endpoint"], location: req["endpoint"] === "gpu" ? "local" : "external", bound: true } }
      : { ok: false, error: `unknown op: ${op}` };
  });
  try {
    assert.deepEqual(await bindSessionUpstream(good.sock, "sid-1", "gpu", 1000), { status: "ok", location: "local" });
    assert.deepEqual(await bindSessionUpstream(good.sock, "sid-2", null, 1000), { status: "ok", location: "external" });
    assert.deepEqual(seen.map(({ id: _id, ...r }) => r), [
      { op: "setSessionUpstream", sessionKey: "sid-1", endpoint: "gpu", requestedBy: "launcher" },
      { op: "setSessionUpstream", sessionKey: "sid-2", endpoint: null, requestedBy: "launcher" },
    ]);
  } finally { await good.close(); }

  const old = await fakeArbiter((op) => ({ ok: false, error: `unknown op: ${op}` }));
  try {
    const r = await bindSessionUpstream(old.sock, "sid", "gpu", 1000);
    assert.equal(r.status, "unsupported");
  } finally { await old.close(); }

  const refusal = "setSessionUpstream: session already bound to 'cloud' (asked 'gpu'); the main model is bind-once";
  const bound = await fakeArbiter(() => ({ ok: false, error: refusal }));
  try { assert.deepEqual(await bindSessionUpstream(bound.sock, "sid", "gpu", 1000), { status: "refused", error: refusal }); } finally { await bound.close(); }

  const mute = await fakeArbiter(() => null);
  try { assert.equal((await bindSessionUpstream(mute.sock, "sid", null, 200)).status, "unavailable"); } finally { await mute.close(); }
  const junk = await fakeArbiter(() => "{not json");
  try { assert.equal((await bindSessionUpstream(junk.sock, "sid", null, 1000)).status, "unavailable"); } finally { await junk.close(); }
  const shape = await fakeArbiter(() => ({ ok: true, result: { location: "somewhere" } }));
  try { assert.equal((await bindSessionUpstream(shape.sock, "sid", null, 1000)).status, "unavailable"); } finally { await shape.close(); }
  const bare = await fakeArbiter(() => ({ ok: false }));
  try { assert.equal((await bindSessionUpstream(bare.sock, "sid", null, 1000)).status, "unavailable"); } finally { await bare.close(); }
  assert.equal((await bindSessionUpstream(join(tmpdir(), "definitely-absent-mdu.sock"), "sid", null, 500)).status, "unavailable");
});

// ── plan 11 §8 row 2: the undeclared-base-URL warning prints in compact mode ──
import { undeclaredBaseUrlWarning } from "../../src/model-endpoints.js";
import { isAttentionNote } from "../../src/launch-banner.js";

test("undeclaredBaseUrlWarning names the URL and the fix, and the compact display prints it", () => {
  for (const known of [true, false]) {
    const w = undeclaredBaseUrlWarning("http://10.0.0.5:4000", known);
    assert.ok(isAttentionNote(w), "an attention note: shown even without MANDU_VERBOSE");
    assert.match(w, /^WARNING: mandu: /);
    assert.match(w, /ANTHROPIC_BASE_URL \(http:\/\/10\.0\.0\.5:4000\) is not declared in policy\.yaml models:/);
    assert.match(w, /unprotected/);
    assert.match(w, /Declare it under models: with wire: anthropic/);
    assert.equal(/could not say which models are declared/.test(w), !known);
  }
});

test("localModelTokens: only local entries, only set and non-empty values, from the launcher's environment", () => {
  const eps = [
    { name: "own", url: "http://127.0.0.1:11434", wire: "openai-chat" as const, local: true, tokenEnv: "OWN_BEARER" },
    { name: "empty", url: "http://127.0.0.1:11435", wire: "openai-chat" as const, local: true, tokenEnv: "EMPTY_BEARER" },
    { name: "gw", url: "https://gw.example", wire: "anthropic" as const, local: false, tokenEnv: "GW_BEARER" },
    { name: "plain", url: "http://127.0.0.1:11436", wire: "openai-chat" as const, local: true },
  ];
  assert.deepEqual(
    localModelTokens(eps, { OWN_BEARER: "a", EMPTY_BEARER: "", GW_BEARER: "b" }),
    { OWN_BEARER: "a" },
  );
  assert.deepEqual(localModelTokens([], { OWN_BEARER: "a" }), {});
});

test("plan 12 D1/D2: endpointPlacement, isPlainHttpLocal, and the launch warning for an opted-in entry", () => {
  assert.equal(endpointPlacement("http://127.0.0.1:11434"), "host");
  assert.equal(endpointPlacement("http://gpu.localhost:1"), "host");
  assert.equal(endpointPlacement("http://[::1]:1"), "host");
  assert.equal(endpointPlacement("https://llm.corp.example"), "network");
  assert.equal(endpointPlacement("http://10.0.3.7:8000"), "network");
  assert.equal(endpointPlacement("ftp://x"), null);
  const lab: ModelEndpoint = { name: "lab", url: "http://10.0.3.7:8000", wire: "openai-chat", model: "qwen", local: true };
  assert.equal(isPlainHttpLocal(lab), true);
  assert.equal(isPlainHttpLocal({ ...lab, local: false }), false, "an outside entry is never dialed by the helper");
  assert.equal(isPlainHttpLocal({ ...lab, url: "https://10.0.3.7:8443" }), false);
  assert.equal(isPlainHttpLocal(ollama), false);
  assert.deepEqual(plainHttpWarnings([ollama, lab]), [], "no warning without the opt-out (the launch refuses instead)");
  const warned = plainHttpWarnings([ollama, { ...lab, allowPlainHttp: true }]);
  assert.equal(warned.length, 1);
  assert.match(warned[0]!, /^WARNING: mandu: models: lab \(http:\/\/10\.0\.3\.7:8000\) is plain http on another machine; files labeled local-model that the helper sends there cross the network unencrypted/);
  assert.ok(isAttentionNote(warned[0]!), "the compact launch display prints it");
  assert.ok(!/ — /.test(warned[0]!));
});

test("asModelEndpoint: allowPlainHttp kept only when true; a non-boolean refuses the entry", () => {
  const raw = { name: "lab", url: "http://10.0.3.7:8000", wire: "openai-chat", local: true };
  assert.equal(asModelEndpoint({ ...raw, allowPlainHttp: true })?.allowPlainHttp, true);
  assert.equal("allowPlainHttp" in asModelEndpoint({ ...raw, allowPlainHttp: false })!, false);
  assert.equal(asModelEndpoint({ ...raw, allowPlainHttp: "yes" }), null);
});

test("addressReach (plan 12 D6): the worst case over every address; none = unresolved", () => {
  assert.equal(addressReach([]), "unresolved");
  assert.equal(addressReach(["10.0.0.1"]), "private");
  assert.equal(addressReach(["fe80::1", "192.168.1.2"]), "private");
  assert.equal(addressReach(["127.0.1.1"]), "loopback");
  assert.equal(addressReach(["127.0.0.1", "10.0.0.1"]), "private");
  assert.equal(addressReach(["10.0.0.1", "52.1.2.3"]), "public", "one public address makes it public");
  assert.equal(addressReach(["2001:db8::1"]), "public");
});

test("plan 12 D3: asModelEndpoint keeps a well-formed tls, drops the entry on a malformed one; localModelClientKeys reads local entries' keys only", () => {
  const PIN = Buffer.alloc(32, 9).toString("base64");
  const raw = { name: "corp", url: "https://llm.corp.example/v1", wire: "openai-chat", local: true };
  assert.deepEqual(asModelEndpoint({ ...raw, tls: { caFile: "/ca.pem", pinSha256: [PIN] } })?.tls, { caFile: "/ca.pem", pinSha256: [PIN] });
  assert.equal(asModelEndpoint({ ...raw, tls: { caFile: "ca.pem" } }), null, "a relative path drops the entry");
  assert.equal(asModelEndpoint({ ...raw, tls: { clientCert: "/c.pem" } }), null, "half a pair drops the entry");
  assert.equal("tls" in asModelEndpoint({ ...raw, tls: {} })!, false);
  const eps: ModelEndpoint[] = [
    { name: "corp", url: "https://x", wire: "openai-chat", local: true, tls: { clientCert: "/c.pem", clientKey: "/k.pem" } },
    { name: "gone", url: "https://y", wire: "openai-chat", local: true, tls: { clientCert: "/c.pem", clientKey: "/missing.pem" } },
    { name: "outside", url: "https://z", wire: "openai-chat", local: false, tls: { clientCert: "/c.pem", clientKey: "/k.pem" } },
  ];
  const read = (p: string): string => { if (p === "/k.pem") return "KEY"; throw new Error("ENOENT"); };
  assert.deepEqual(localModelClientKeys(eps, read), { corp: "KEY" });
});

test("plan 12 D4: the launch holds a local entry on another machine to its perimeter over the resolver's answer: all inside passes, one outside or an empty answer refuses, a literal is its own answer", async () => {
  const reserved = reservedAddresses({ proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 0 } });
  const nets = ["10.0.0.0/8", "fd00::/8"];
  const corp: ModelEndpoint = { name: "corp", url: "https://llm.corp.example", wire: "openai-chat", model: "qwen", local: true, perimeter: nets };
  const fixture = (answers: Record<string, string[]>) => ({ lookup: async (n: string) => answers[n] ?? [], localAddresses: () => [] as string[] });
  const read = (...endpoints: ModelEndpoint[]) => ({ status: "ok" as const, endpoints, dropped: [] });

  await assertLocalEndpoints(read(corp), reserved, fixture({ "llm.corp.example": ["10.1.2.3", "fd00::7"] }));
  await assert.rejects(
    assertLocalEndpoints(read(corp), reserved, fixture({ "llm.corp.example": ["10.1.2.3", "52.1.2.3"] })),
    (e: unknown) => e instanceof PerimeterLocalModelError && /models: corp \(https:\/\/llm\.corp\.example\) resolves to 52\.1\.2\.3/.test(e.message) &&
      /outside perimeter\.networks/.test(e.message) && !/ — /.test(e.message),
  );
  await assert.rejects(assertLocalEndpoints(read(corp), reserved, fixture({})), /models: corp \(https:\/\/llm\.corp\.example\) does not resolve here/);
  await assert.rejects(assertLocalEndpoints(read({ ...corp, url: "https://203.0.113.9:8443" }), reserved, fixture({})), /resolves to 203\.0\.113\.9/);
  await assertLocalEndpoints(read({ ...corp, url: "https://[fd00::9]:8443" }), reserved, fixture({}));
  // No perimeter on the entry (the arbiter attaches it only where it applies): nothing to check.
  await assertLocalEndpoints(read({ ...corp, perimeter: undefined }), reserved, fixture({ "llm.corp.example": ["52.1.2.3"] }));
  // Pure core: an outside entry is never held.
  assert.deepEqual(perimeterViolations([{ ...corp, local: false }], new Map([["llm.corp.example", ["52.1.2.3"]]])), []);
});

test("asModelEndpoint (plan 12 D4): a perimeter is kept when every item is a network; a malformed one drops the entry; orgDomain only as a boolean", () => {
  const base = { name: "corp", url: "https://llm.corp.example", wire: "openai-chat", local: true };
  assert.deepEqual(asModelEndpoint({ ...base, perimeter: ["10.0.0.0/8"], orgDomain: true })?.perimeter, ["10.0.0.0/8"]);
  assert.equal(asModelEndpoint({ ...base, perimeter: ["10.0.0.0/8"], orgDomain: true })?.orgDomain, true);
  assert.equal(asModelEndpoint({ ...base, perimeter: ["10.0.0.0/33"] }), null);
  assert.equal(asModelEndpoint({ ...base, perimeter: [] }), null);
  assert.equal(asModelEndpoint({ ...base, perimeter: "10.0.0.0/8" }), null);
  assert.equal(asModelEndpoint({ ...base, orgDomain: "yes" }), null);
});

test("plan 12 D5: the administrator's entries keep their file and lock; the layer rides the read; a relative file or a non-boolean lock drops the entry", async () => {
  const base = { name: "corp", url: "https://llm.corp.example", wire: "openai-chat", local: true };
  assert.deepEqual(
    asModelEndpoint({ ...base, adminFile: "/etc/mandu/policy.d/10-corp.yaml", locked: true }),
    { name: "corp", url: "https://llm.corp.example", wire: "openai-chat", local: true, adminFile: "/etc/mandu/policy.d/10-corp.yaml", locked: true },
  );
  assert.equal(asModelEndpoint({ ...base, locked: true })?.locked, undefined, "a lock without a file means nothing");
  assert.equal(asModelEndpoint({ ...base, adminFile: "10-corp.yaml" }), null);
  assert.equal(asModelEndpoint({ ...base, adminFile: "/etc/x.yaml", locked: "yes" }), null);
  const withAdmin = await fakeArbiter((op) => op === "modelEndpoints"
    ? { ok: true, result: { endpoints: [{ ...base, adminFile: "/etc/mandu/policy.d/10-corp.yaml", locked: true }], admin: { files: ["/etc/mandu/policy.d/10-corp.yaml"], locked: true, conflicts: ["models[0]: 'mine' is local: true", 7], refused: "no" } } }
    : { ok: false, error: `unknown op: ${op}` });
  try {
    const r = await readModelEndpoints(withAdmin.sock, 1000);
    assert.deepEqual(r.admin, { files: ["/etc/mandu/policy.d/10-corp.yaml"], locked: true, conflicts: ["models[0]: 'mine' is local: true"], refused: [] }, "only strings survive");
    assert.equal(r.endpoints[0]?.locked, true);
  } finally { await withAdmin.close(); }
});
