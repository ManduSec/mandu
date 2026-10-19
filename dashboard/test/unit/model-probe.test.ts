/**
 * model-probe.test — "Test connection" (dashboard.md §4.25l), pure over fake
 * I/O. The same decisions as `mandu doctor`'s model rows (the case-table
 * parity against doctor itself is tests/stack/model-probe-parity.test.ts).
 *
 * Pins: unreachable stops there (no listing); an openai-chat entry with a
 * model reads the listing (an implied `:latest` matches); a `local: true`
 * entry reads it for cloud-backed models; an anthropic entry that is not
 * local is only connected to; the token from token_env goes to the listing
 * and into no line; the host hint for a `local: true` entry off this machine
 * or a local network; the copy uses the product vocabulary; the real TCP
 * probe answers on a real listener and gives up on a closed port.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";

import { hostClass, needsHostHint, probeModelEndpoint, realProbeTcp, type ProbeDeps, type ProbeEntry } from "../../src/model-probe.js";
import { reservePort } from "./reserve-port.js";

function deps(over: Partial<ProbeDeps> & { ids?: string[] | null; reachable?: boolean } = {}) {
  const calls: string[] = [];
  const d: ProbeDeps = {
    probeTcp: over.probeTcp ?? (async (h, p) => { calls.push(`tcp ${h}:${p}`); return over.reachable ?? true; }),
    listModels: over.listModels ?? (async (u, t) => { calls.push(`list ${u} ${t ?? "-"}`); return over.ids === undefined ? [] : over.ids; }),
    env: over.env ?? {},
    ...(over.lookupHost ? { lookupHost: over.lookupHost } : {}),
  };
  return { d, calls };
}

const OLLAMA: ProbeEntry = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true, tokenEnv: "OLLAMA_TOKEN" };
const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter)\b|\$MDU:/i;

test("unreachable: one bad line, and the listing is never asked for", async () => {
  const { d, calls } = deps({ reachable: false });
  const r = await probeModelEndpoint(OLLAMA, d);
  assert.equal(r.reachable, false);
  assert.equal(r.ok, false);
  assert.deepEqual(calls, ["tcp 127.0.0.1:11434"]);
  assert.deepEqual(r.lines, [{ tone: "bad", text: "Could not connect to 127.0.0.1:11434. Start the model server, or fix the address." }]);
});

test("a name that does not resolve: the connection line says so (not 'start the model server'); with a perimeter, one line says nothing is sent", async () => {
  const corp: ProbeEntry = { name: "corp", url: "https://llm.corp.example/v1", wire: "openai-chat", local: true };
  const r = await probeModelEndpoint(corp, deps({ reachable: false, lookupHost: async () => [] }).d);
  assert.equal(r.lines[0]!.text, "Could not connect to llm.corp.example:443: llm.corp.example does not resolve here. Check the address, or connect to the network it is on.");
  const held = await probeModelEndpoint({ ...corp, perimeter: ["10.0.0.0/8"] }, deps({ reachable: false, lookupHost: async () => [] }).d);
  assert.deepEqual(held.lines.map((l) => l.tone), ["bad", "bad"]);
  assert.equal(held.lines[1]!.text, "Mandu cannot check that llm.corp.example is inside your organization's networks until it resolves. Mandu sends nothing to it, and a launch refuses it.");
  // A name that resolves but refuses the connection keeps the old advice.
  const down = await probeModelEndpoint(corp, deps({ reachable: false, lookupHost: async () => ["10.1.2.3"] }).d);
  assert.equal(down.lines[0]!.text, "Could not connect to llm.corp.example:443. Start the model server, or fix the address.");
});

test("reachable openai-chat entry: the named model is looked up (an implied :latest matches); missing says how to load it", async () => {
  const listed = await probeModelEndpoint(OLLAMA, deps({ ids: ["llama3.2:latest"], env: { OLLAMA_TOKEN: "tok-XYZ" } }).d);
  assert.equal(listed.modelListed, true);
  assert.equal(listed.ok, true);
  assert.deepEqual(listed.lines.map((l) => l.tone), ["ok", "ok"]);
  const missing = await probeModelEndpoint(OLLAMA, deps({ ids: ["qwen2.5"] }).d);
  assert.equal(missing.modelListed, false);
  assert.equal(missing.ok, false);
  assert.match(missing.lines[1]!.text, /llama3\.2 is not in the server's model list \(http:\/\/127\.0\.0\.1:11434\/v1\/models\)\. Load it on the server \(for Ollama: ollama pull llama3\.2\)\./);
  const unread = await probeModelEndpoint(OLLAMA, deps({ ids: null }).d);
  assert.equal(unread.modelListed, null);
  assert.equal(unread.ok, true, "an unread listing is not a failure, as in doctor");
  assert.equal(unread.lines[1]!.tone, "note");
});

test("the token from token_env rides to the listing and into no line; an unset variable is noted", async () => {
  const { d, calls } = deps({ ids: ["llama3.2"], env: { OLLAMA_TOKEN: "tok-XYZ" } });
  const r = await probeModelEndpoint(OLLAMA, d);
  assert.deepEqual(calls, ["tcp 127.0.0.1:11434", "list http://127.0.0.1:11434 tok-XYZ"]);
  assert.doesNotMatch(JSON.stringify(r), /tok-XYZ/);
  const unset = await probeModelEndpoint(OLLAMA, deps({ ids: ["llama3.2"] }).d);
  assert.ok(unset.lines.some((l) => l.text === "OLLAMA_TOKEN is not set where the dashboard runs, so the model list was asked for without a key."));
});

test("a local entry's listing names cloud models; an outside anthropic entry is only connected to", async () => {
  const cloud = await probeModelEndpoint({ ...OLLAMA, tokenEnv: undefined }, deps({ ids: ["llama3.2", "gpt-oss:120b-cloud", "glm-4.6:cloud"] }).d);
  assert.deepEqual(cloud.cloudListed, ["gpt-oss:120b-cloud", "glm-4.6:cloud"]);
  assert.match(cloud.lines.at(-1)!.text, /also offers models that run on the vendor's computers \(gpt-oss:120b-cloud, glm-4\.6:cloud\)/);
  const { d, calls } = deps();
  const outside = await probeModelEndpoint({ name: "gw", url: "https://llm.example.com/v1", wire: "anthropic", local: false }, d);
  assert.deepEqual(calls, ["tcp llm.example.com:443"]);
  assert.equal(outside.ok, true);
  assert.deepEqual(outside.lines, [{ tone: "ok", text: "Connected to llm.example.com:443." }]);
});

test("plan 12 D6 the host hint: graded by where the address really is (names resolved); a private address or this computer gets none", async () => {
  const lookupHost = async (n: string) => (n === "gpu-box" ? ["192.168.7.20"] : n === "llm.example.com" ? ["93.184.216.34"] : []);
  for (const [url, hint] of [
    ["https://127.0.0.1:11434", false], ["https://localhost:11434", false], ["https://192.168.1.20:11434", false], ["https://10.1.2.3:8000", false],
    ["https://[fe80::1]:8000", false], ["https://203.0.113.9:8000", true], ["https://gpu-box:8000", false], ["https://llm.example.com", true],
    ["https://nowhere.example", true],
  ] as const) {
    const r = await probeModelEndpoint({ name: "m", url, wire: "anthropic", local: true }, { ...deps().d, lookupHost });
    assert.equal(r.lines.some((l) => /is a public address|resolves to a public address|does not resolve here/.test(l.text)), hint, url);
    const notLocal = await probeModelEndpoint({ name: "m", url, wire: "anthropic", local: false }, { ...deps().d, lookupHost });
    assert.equal(notLocal.lines.some((l) => /public address|does not resolve/.test(l.text)), false, `${url}: an outside model needs no hint`);
  }
  const noResolver = await probeModelEndpoint({ name: "m", url: "https://gpu-box:8000", wire: "anthropic", local: true }, deps().d);
  assert.equal(noResolver.reach, undefined, "without a resolver a name is not graded");
  // The Approvals card's static check (no resolution) is unchanged.
  for (const [url, hint] of [["http://127.0.0.1:1", false], ["http://10.1.2.3:1", false], ["http://203.0.113.9:1", true], ["http://gpu-box:1", true]] as const) {
    assert.equal(needsHostHint(url), hint, url);
  }
  assert.equal(needsHostHint("not a url"), true, "an address that does not parse is not assumed local");
  assert.equal(hostClass("[::ffff:7f00:1]"), "loopback");
});

test("plan 12 D2: plain http to another machine is a bad line and not ok, with or without the opt-out; https or this computer is fine", async () => {
  const refused = await probeModelEndpoint({ name: "m", url: "http://10.0.3.7:8000", wire: "anthropic", local: true }, deps().d);
  assert.equal(refused.plainHttp, "refused");
  assert.equal(refused.ok, false);
  assert.ok(refused.lines.some((l) => l.tone === "bad" && /plain http address on another computer, so Mandu will not send/.test(l.text)));
  const allowed = await probeModelEndpoint({ name: "m", url: "http://10.0.3.7:8000", wire: "anthropic", local: true, allowPlainHttp: true }, deps().d);
  assert.equal(allowed.plainHttp, "allowed");
  assert.equal(allowed.ok, false);
  assert.ok(allowed.lines.some((l) => l.tone === "bad" && /^Not encrypted: files marked "Your own AI only" cross the network in the clear to 10\.0\.3\.7:8000/.test(l.text)));
  for (const url of ["https://10.0.3.7:8443", "http://127.0.0.1:11434"]) {
    const r = await probeModelEndpoint({ name: "m", url, wire: "anthropic", local: true }, deps().d);
    assert.equal(r.plainHttp, undefined, url);
    assert.equal(r.ok, true, url);
  }
  const outside = await probeModelEndpoint({ name: "m", url: "http://10.0.3.7:8000", wire: "anthropic", local: false }, deps().d);
  assert.equal(outside.plainHttp, undefined, "an outside model is never sent local-model files");
});

test("an address that does not parse is one bad line and no I/O", async () => {
  const { d, calls } = deps();
  const r = await probeModelEndpoint({ name: "m", url: "ftp://x", wire: "anthropic", local: false }, d);
  assert.equal(r.ok, false);
  assert.deepEqual(calls, []);
});

test("every line is product copy (the §4.18 sweep)", async () => {
  const all = [
    await probeModelEndpoint(OLLAMA, deps({ reachable: false }).d),
    await probeModelEndpoint(OLLAMA, deps({ ids: ["x", "a:cloud"] }).d),
    await probeModelEndpoint({ ...OLLAMA, url: "http://gpu-box:1", model: "a-cloud" }, deps({ ids: null }).d),
  ];
  for (const r of all) for (const l of r.lines) assert.doesNotMatch(l.text, FORBIDDEN, l.text);
});

test("the real TCP probe: a listener answers, a closed port does not", async () => {
  // A reserved port, not port 0: once the listener closes, no suite running
  // alongside can be handed it before the second probe (test-organization.md §8.4).
  const port = await reservePort();
  const srv = createServer((s) => s.end());
  await new Promise<void>((r) => srv.listen(port, "127.0.0.1", () => r()));
  assert.equal(await realProbeTcp("127.0.0.1", port, 3000), true);
  await new Promise<void>((r) => srv.close(() => r()));
  assert.equal(await realProbeTcp("127.0.0.1", port, 3000), false);
});

test("plan 12 D3/D6: a reachable https entry with tls (or local on another machine) gets one handshake; ✓ names the checks, a refusal is a bad line and not ok", async () => {
  const PIN = Buffer.alloc(32, 9).toString("base64");
  const probed: string[] = [];
  const probeTls = async (h: string, p: number, m: unknown) => {
    probed.push(`${h}:${p} ${JSON.stringify(m)}`);
    return h === "10.0.3.7" ? { ok: false as const, reason: "the server's key is not one of the pinned keys (tls.pin_sha256)" } : { ok: true as const };
  };
  const ok = await probeModelEndpoint({ name: "corp", url: "https://llm.corp.example/v1", wire: "anthropic", local: true, tls: { pinSha256: [PIN] } }, { ...deps().d, probeTls, lookupHost: async () => ["10.1.2.3"] });
  assert.deepEqual(ok.tls, { checks: ["a pinned key"], ok: true });
  assert.ok(ok.lines.some((l) => l.tone === "ok" && l.text === "TLS checked with a pinned key."));
  assert.equal(ok.ok, true);
  const bad = await probeModelEndpoint({ name: "lan", url: "https://10.0.3.7:8443", wire: "anthropic", local: true, tls: { pinSha256: [PIN] } }, { ...deps().d, probeTls });
  assert.equal(bad.ok, false);
  assert.ok(bad.lines.some((l) => l.tone === "bad" && /^TLS refused: the server's key is not one of the pinned keys \(tls\.pin_sha256\)\. Nothing is sent to this model until it passes\.$/.test(l.text)));
  const home = await probeModelEndpoint({ name: "home", url: "https://127.0.0.1:8443", wire: "anthropic", local: true }, { ...deps().d, probeTls });
  assert.equal(home.tls, undefined, "this computer, no tls config: no handshake");
  assert.deepEqual(probed.map((p) => p.split(" ")[0]), ["llm.corp.example:443", "10.0.3.7:8443"]);
});
