/**
 * model-probe-parity.test.ts — the dashboard's "Test connection" and
 * `mandu doctor` decide the same things about a declared model
 * (dashboard.md §4.25l; confidentiality-plan-11 D6, §7.3).
 *
 * The dashboard cannot import the launcher (each package typechecks alone),
 * so dashboard/src/model-probe.ts carries copies of doctor's model checks and
 * of the launcher's host rules. This runs ONE case table through both:
 *   - doctor's `gatherModels` (launcher/src/doctor.ts) with fake arbiter,
 *     TCP and listing deps, and
 *   - the dashboard's `probeModelEndpoint` with the same fake TCP and listing,
 * and asserts the facts agree: reachable, model listed, cloud models listed,
 * host class, and that the same entries get the host hint and the same token
 * rides to the listing. Then the host classes themselves over a table of
 * spellings (loopback forms, mapped IPv6, private, link-local, public, names).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { gatherModels, modelRows } from "../../launcher/src/doctor.js";
import { hostClass as launcherHostClass, type ModelEndpoint } from "../../launcher/src/model-endpoints.js";
import { hostClass as dashboardHostClass, probeModelEndpoint } from "../../dashboard/src/model-probe.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the declared models serve local-model data (the confidentiality axis); no axis is read here

interface Case {
  entry: ModelEndpoint;
  reachable: boolean;
  ids: string[] | null;
}

const CASES: Case[] = [
  { entry: { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true, tokenEnv: "OLLAMA_TOKEN" }, reachable: true, ids: ["llama3.2:latest", "gpt-oss:120b-cloud"] },
  { entry: { name: "missing", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "qwen2.5", local: true }, reachable: true, ids: ["llama3.2"] },
  { entry: { name: "unread", url: "http://localhost:8000/v1", wire: "openai-chat", model: "qwen2.5", local: false }, reachable: true, ids: null },
  { entry: { name: "down", url: "http://127.0.0.1:1", wire: "openai-chat", model: "x", local: true }, reachable: false, ids: ["x"] },
  { entry: { name: "gw", url: "https://llm.example.com", wire: "anthropic", local: false }, reachable: true, ids: ["ignored"] },
  { entry: { name: "far", url: "http://203.0.113.9:8000", wire: "anthropic", local: true }, reachable: true, ids: ["m", "m:cloud"] },
  { entry: { name: "named", url: "http://gpu-box:8000", wire: "openai-chat", model: "m", local: true }, reachable: true, ids: ["m"] },
  { entry: { name: "lan", url: "http://192.168.1.20:8000", wire: "anthropic", local: true }, reachable: true, ids: [] },
  // Plan 12: the opt-out, https on another machine, a name resolving inside
  // and outside the organization, and a name that does not resolve.
  { entry: { name: "lab", url: "http://10.0.3.7:8000", wire: "anthropic", local: true, allowPlainHttp: true }, reachable: true, ids: [] },
  { entry: { name: "corp", url: "https://llm.corp.example/v1", wire: "openai-chat", model: "m", local: true }, reachable: true, ids: ["m"] },
  { entry: { name: "pl", url: "https://pl.corp.example", wire: "anthropic", local: true }, reachable: true, ids: [] },
  { entry: { name: "gone", url: "https://gone.corp.example", wire: "anthropic", local: true }, reachable: false, ids: null },
  { entry: { name: "tls-lan", url: "https://10.0.3.7:8443", wire: "anthropic", local: true }, reachable: true, ids: [] },
  { entry: { name: "pinned", url: "https://llm.corp.example/v1", wire: "openai-chat", model: "m", local: true, tls: { pinSha256: [Buffer.alloc(32, 9).toString("base64")] } }, reachable: true, ids: ["m"] },
  { entry: { name: "badpin", url: "https://10.0.3.9:8443", wire: "anthropic", local: false, tls: { pinSha256: [Buffer.alloc(32, 8).toString("base64")] } }, reachable: true, ids: [] },
  // Plan 12 D4: an entry held to perimeter.networks, resolving inside,
  // outside (no handshake then), not at all, and a literal outside.
  { entry: { name: "p-in", url: "https://llm.corp.example/v1", wire: "openai-chat", model: "m", local: true, perimeter: ["10.0.0.0/8"], orgDomain: true }, reachable: true, ids: ["m"] },
  { entry: { name: "p-out", url: "https://pl.corp.example", wire: "anthropic", local: true, perimeter: ["10.0.0.0/8"] }, reachable: true, ids: [] },
  { entry: { name: "p-gone", url: "https://gone.corp.example", wire: "anthropic", local: true, perimeter: ["10.0.0.0/8"] }, reachable: false, ids: null },
  { entry: { name: "p-lit", url: "https://203.0.113.9:8443", wire: "anthropic", local: true, perimeter: ["10.0.0.0/8"] }, reachable: true, ids: [] },
];

/** One fake handshake for both sides: refuses the host 10.0.3.9 and 10.0.3.7. */
const PROBE_TLS = async (h: string): Promise<{ ok: true } | { ok: false; reason: string }> =>
  h === "10.0.3.9" || h === "10.0.3.7" ? { ok: false, reason: "the server's key is not one of the pinned keys (tls.pin_sha256)" } : { ok: true };

/** One fake resolver for both sides. */
const LOOKUP = async (n: string): Promise<string[]> =>
  n === "llm.corp.example" ? ["10.1.2.3"] : n === "pl.corp.example" ? ["52.1.2.3"] : n === "gpu-box" ? ["192.168.7.20"] : n === "llm.example.com" ? ["93.184.216.34"] : [];

const ENV = { OLLAMA_TOKEN: "tok-parity", MANDU_POLICY_FILE: "/dev/null/none.yaml" };

test("doctor and the dashboard probe agree on every case: reachable, listed, cloud models, host class, token, hint", async () => {
  for (const c of CASES) {
    const seenDoctor: string[] = [];
    const seenDash: string[] = [];
    const facts = await gatherModels(ENV, {
      readKnob: () => null,
      modelEndpoints: async () => ({ status: "ok", endpoints: [c.entry], dropped: [] }),
      probeTcp: async (h, p) => { seenDoctor.push(`tcp ${h}:${p}`); return c.reachable; },
      listModels: async (u, t) => { seenDoctor.push(`list ${u} ${t ?? "-"}`); return c.ids; },
      lookupHost: LOOKUP,
      probeTls: PROBE_TLS,
    }, "/nonexistent.sock", true);
    const d = facts.endpoints[0]!;
    const r = await probeModelEndpoint(c.entry, {
      probeTcp: async (h, p) => { seenDash.push(`tcp ${h}:${p}`); return c.reachable; },
      listModels: async (u, t) => { seenDash.push(`list ${u} ${t ?? "-"}`); return c.ids; },
      lookupHost: LOOKUP,
      probeTls: PROBE_TLS,
      env: ENV,
    });
    const at = c.entry.name;
    assert.deepEqual(seenDash, seenDoctor, `${at}: the same I/O, the same token`);
    assert.equal(r.reachable, d.reachable, `${at}: reachable`);
    assert.equal(r.modelListed, d.modelListed, `${at}: model listed`);
    assert.deepEqual(r.cloudListed, d.cloudListed ?? [], `${at}: cloud models listed`);
    assert.equal(r.hostClass, d.hostClass, `${at}: host class`);
    assert.equal(r.placement, d.placement, `${at}: placement`);
    assert.deepEqual(r.addresses ?? null, d.addresses ?? null, `${at}: resolved addresses`);
    assert.equal(r.reach ?? null, d.reach ?? null, `${at}: where the addresses are`);
    assert.equal(r.plainHttp ?? null, d.plainHttp ?? null, `${at}: plain http`);
    assert.deepEqual(r.tls ?? null, d.tls ?? null, `${at}: the TLS handshake fact`);
    assert.deepEqual(r.perimeter ?? null, d.perimeter ?? null, `${at}: the perimeter fact`);
    const doctorHint = modelRows(facts).some((row) => row.includes("hint:"));
    const dashHint = r.lines.some((l) => l.tone === "note" && /is a public address|resolves to a public address|does not resolve here/.test(l.text));
    assert.equal(dashHint, doctorHint, `${at}: the host hint`);
    const doctorBad = modelRows(facts).some((row) => row.includes("✗") || /not reachable|is not listed/.test(row));
    assert.equal(!r.ok, doctorBad, `${at}: a failure in one is a failure in the other`);
  }
});

test("the launcher's and the dashboard's host classes agree on every spelling", () => {
  for (const h of [
    "127.0.0.1", "127.0.1.1", "localhost", "LOCALHOST.", "api.localhost", "::1", "[::1]", "::", "0.0.0.0", "::ffff:7f00:1", "::ffff:127.0.0.1",
    "10.0.0.5", "172.16.0.1", "172.31.255.255", "172.32.0.1", "192.168.1.20", "169.254.1.1", "fe80::1", "fd12:3456::1",
    "8.8.8.8", "203.0.113.9", "2001:db8::1", "gpu-box", "llm.example.com", "::ffff:c0a8:114",
  ]) {
    assert.equal(dashboardHostClass(h), launcherHostClass(h), h);
  }
});
