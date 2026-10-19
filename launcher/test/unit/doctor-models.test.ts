/**
 * doctor-models.test — `mandu doctor`'s policy.yaml `models:` rows
 * (confidentiality-plan-11 D6): one row per declared endpoint with injected
 * reachability and model-listing probes (no network), the non-private-host
 * hint for a `local: true` endpoint, and the "files labeled local-model are
 * read by no model" row when no model is declared.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { gatherModels, modelListedIn, modelRows, renderDoctor, tlsChecksWords, type DoctorDeps, type DoctorFacts, type ModelsFacts } from "../../src/doctor.js";
import type { ModelEndpoint, ModelEndpointsRead } from "../../src/model-endpoints.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // local-model matters under the confidentiality axis; doctor reads no axis itself

const POLICY = "/cfg/mandu/policy.yaml";
const env = { MANDU_POLICY_FILE: POLICY, OLLAMA_TOKEN: "tok-123" };
const ollama: ModelEndpoint = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true, tokenEnv: "OLLAMA_TOKEN" };

function deps(over: {
  file?: string | null;
  read?: ModelEndpointsRead;
  reachable?: (host: string, port: number) => boolean;
  ids?: string[] | null;
  seen?: Array<{ url: string; token: string | undefined }>;
} = {}): Pick<DoctorDeps, "readKnob" | "modelEndpoints" | "probeTcp" | "listModels"> {
  return {
    readKnob: (p) => (p === POLICY ? (over.file ?? null) : null),
    modelEndpoints: async () => over.read ?? { status: "ok", endpoints: [], dropped: [] },
    probeTcp: async (h, p) => (over.reachable ? over.reachable(h, p) : true),
    listModels: async (url, token) => { over.seen?.push({ url, token }); return over.ids === undefined ? ["llama3.2:latest"] : over.ids; },
  };
}

test("modelListedIn: exact, or with Ollama's implied :latest either way", () => {
  assert.ok(modelListedIn(["llama3.2:latest"], "llama3.2"));
  assert.ok(modelListedIn(["llama3.2"], "llama3.2:latest"));
  assert.ok(modelListedIn(["qwen2.5:7b"], "qwen2.5:7b"));
  assert.ok(!modelListedIn(["qwen2.5:7b"], "qwen2.5"));
  assert.ok(!modelListedIn([], "llama3.2"));
});

test("gatherModels: one row per declared endpoint, probed through the injected deps; the endpoint's own token rides the listing", async () => {
  const seen: Array<{ url: string; token: string | undefined }> = [];
  const cloud: ModelEndpoint = { name: "cloud", url: "https://llm.example.com", wire: "anthropic", local: false };
  const m = await gatherModels(env, deps({ read: { status: "ok", endpoints: [ollama, cloud], dropped: [] }, seen }), "/s.sock", true);
  assert.equal(m.source, "arbiter");
  assert.deepEqual(m.endpoints.map((e) => [e.name, e.reachable, e.modelListed, e.hostClass]), [
    ["ollama", true, true, "loopback"],
    ["cloud", true, null, "name"], // anthropic wire: no listing checked
  ]);
  assert.deepEqual(seen, [{ url: "http://127.0.0.1:11434", token: "tok-123" }]);
});

test("gatherModels: an unreachable endpoint is not listed; no probe deps → not checked; arbiter down → file line scan only", async () => {
  const down = await gatherModels(env, deps({ read: { status: "ok", endpoints: [ollama], dropped: [] }, reachable: () => false }), "/s.sock", true);
  assert.deepEqual([down.endpoints[0]!.reachable, down.endpoints[0]!.modelListed], [false, null]);

  const bare = await gatherModels(env, { readKnob: () => null, modelEndpoints: async () => ({ status: "ok", endpoints: [ollama], dropped: [] }) }, "/s.sock", true);
  assert.deepEqual([bare.endpoints[0]!.reachable, bare.endpoints[0]!.modelListed], [null, null]);

  const file = "paths:\n  - path: ~/notes\n    level: local-model\nmodels:\n  - name: ollama\n    url: http://127.0.0.1:11434\n";
  let asked = false;
  const offline = await gatherModels(env, { ...deps({ file }), modelEndpoints: async () => { asked = true; return { status: "ok", endpoints: [], dropped: [] }; } }, "/s.sock", false);
  assert.equal(asked, false, "an unreachable arbiter is not asked");
  assert.deepEqual({ ...offline }, { source: "file", endpoints: [], declaredInFile: true, localModelLines: [3], policyPath: POLICY });
});

const base = (over: Partial<ModelsFacts>): ModelsFacts => ({ source: "arbiter", endpoints: [], declaredInFile: false, localModelLines: [], policyPath: POLICY, ...over });
const row = (over: Partial<ModelsFacts["endpoints"][number]>): ModelsFacts["endpoints"][number] => ({
  name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true, host: "127.0.0.1", hostClass: "loopback", placement: "host", reachable: true, modelListed: true, ...over,
});

test("modelRows: reachable + listed ✓, unreachable ✗, reachable but not listed ✗ with the pull hint, not checked ·", () => {
  assert.deepEqual(modelRows(base({ endpoints: [row({})] })), [
    "  ✓ ollama: http://127.0.0.1:11434 (openai-chat, model llama3.2, your own model, on this computer): reachable, llama3.2 is listed",
  ]);
  assert.match(modelRows(base({ endpoints: [row({ reachable: false, modelListed: null })] }))[0]!, /^  ✗ ollama: .*: not reachable; start the model server, or fix the url in policy\.yaml$/);
  assert.match(modelRows(base({ endpoints: [row({ modelListed: false })] }))[0]!, /✗ .*reachable, but llama3\.2 is not listed at http:\/\/127\.0\.0\.1:11434\/v1\/models; .*ollama pull llama3\.2/);
  assert.match(modelRows(base({ endpoints: [row({ reachable: null, modelListed: null })] }))[0]!, /^  · ollama: .*reachability not checked$/);
  // Plan 12: a name with no address was never dialed; an administrator's entry is fixed in their file.
  const corp = { name: "corp", url: "https://llm.corp.example/v1", host: "llm.corp.example", placement: "network" as const, reachable: false, modelListed: null };
  assert.match(modelRows(base({ endpoints: [row({ ...corp, reach: "unresolved" })] }))[0]!, /: not reachable: llm\.corp\.example does not resolve here; check the address, or connect to the network it is on$/);
  assert.match(modelRows(base({ endpoints: [row({ ...corp, reach: "unresolved", adminFile: "/etc/mandu/policy.d/10-corp.yaml" })] }))[0]!, /does not resolve here; check the address, or connect to the network it is on, or ask your administrator \(\/etc\/mandu\/policy\.d\/10-corp\.yaml\)$/);
  assert.match(modelRows(base({ endpoints: [row({ ...corp, reach: "private", adminFile: "/etc/mandu/policy.d/10-corp.yaml" })] }))[0]!, /: not reachable; start the model server, or ask your administrator \(\/etc\/mandu\/policy\.d\/10-corp\.yaml\)$/);
});

test("gatherModels + modelRows: the helper's entry is named; with helper: true it is the marked one, not the first local", async () => {
  const codex: ModelEndpoint = { name: "codex-main", url: "http://127.0.0.1:11434/v1", wire: "openai-chat", model: "gpt-oss:20b", local: true };
  const first = await gatherModels(env, deps({ read: { status: "ok", endpoints: [codex, ollama], dropped: [] } }), "/s.sock", true);
  assert.deepEqual(first.endpoints.map((e) => [e.name, e.helper ?? false]), [["codex-main", true], ["ollama", false]]);
  const marked = await gatherModels(env, deps({ read: { status: "ok", endpoints: [codex, { ...ollama, helper: true }], dropped: [] } }), "/s.sock", true);
  assert.deepEqual(marked.endpoints.map((e) => [e.name, e.helper ?? false]), [["codex-main", false], ["ollama", true]]);
  assert.match(modelRows(marked).join("\n"), /ollama: .*\(openai-chat, model llama3\.2, your own model, on this computer, the helper uses it\)/);
  assert.doesNotMatch(modelRows(marked).find((r) => r.includes("codex-main"))!, /helper/);
});

test("modelRows: a url ending in /v1 names …/v1/models once, not /v1/v1", () => {
  assert.match(
    modelRows(base({ endpoints: [row({ url: "http://127.0.0.1:11434/v1", modelListed: false })] }))[0]!,
    /not listed at http:\/\/127\.0\.0\.1:11434\/v1\/models;/,
  );
});

test("modelRows (plan 12 D6): graded by where the address really is: a public address or a name resolving to one gets the hint, an unresolved name its own; private, link-local, this computer or an outside model none", () => {
  const net = { placement: "network" as const, url: "https://x" };
  const hint = (over: Partial<ModelsFacts["endpoints"][number]>): string[] => modelRows(base({ endpoints: [row({ ...net, ...over })] })).filter((l) => l.includes("hint:"));
  assert.match(hint({ host: "8.8.8.8", hostClass: "public", addresses: ["8.8.8.8"], reach: "public" })[0]!,
    /hint: 8\.8\.8\.8 is a public address; if it is your organization's private-link endpoint, list its network under perimeter: networks in policy\.yaml; otherwise make sure your organization controls that server\. Mandu proves the data went to the address you named, not what that server does with it next/);
  assert.match(hint({ host: "llm.corp.example", hostClass: "name", addresses: ["10.1.2.3", "52.1.2.3"], reach: "public" })[0]!,
    /hint: llm\.corp\.example resolves to a public address \(52\.1\.2\.3\); if it is your organization's private-link endpoint/);
  assert.match(hint({ host: "gone.corp.example", hostClass: "name", addresses: [], reach: "unresolved" })[0]!, /hint: gone\.corp\.example does not resolve on this machine; check the name in policy\.yaml/);
  assert.deepEqual(hint({ host: "llm.corp.example", hostClass: "name", addresses: ["10.1.2.3"], reach: "private" }), [], "a name on your network: no hint");
  assert.deepEqual(hint({ host: "llm.corp.example", hostClass: "name" }), [], "not resolved (no resolver): no hint");
  for (const hc of ["link-local", "private"] as const) assert.deepEqual(hint({ hostClass: hc, reach: "private" }), [], hc);
  assert.deepEqual(hint({ placement: "host", reach: undefined }), [], "this computer");
  assert.deepEqual(hint({ host: "8.8.8.8", hostClass: "public", addresses: ["8.8.8.8"], reach: "public", local: false }), [], "an outside model is external anyway");
  assert.match(modelRows(base({ endpoints: [row({ ...net, host: "10.1.2.3", reach: "private" })] }))[0]!, /\(openai-chat, model llama3\.2, your own model, on your network\)/);
  assert.ok(!/ — /.test(hint({ host: "8.8.8.8", reach: "public", addresses: ["8.8.8.8"] })[0]!));
});

test("gatherModels (plan 12 D6): placement from the url; a name is resolved through the injected lookup, a literal is itself, this computer never", async () => {
  const looked: string[] = [];
  const eps: ModelEndpoint[] = [
    ollama,
    { name: "corp", url: "https://llm.corp.example/v1", wire: "openai-chat", model: "q", local: true },
    { name: "lab", url: "https://10.0.3.7:8443", wire: "openai-chat", model: "q", local: true },
    { name: "pl", url: "https://pl.corp.example", wire: "anthropic", local: true },
  ];
  const facts = await gatherModels(env, {
    readKnob: () => null,
    modelEndpoints: async () => ({ status: "ok", endpoints: eps, dropped: [] }),
    lookupHost: async (n) => { looked.push(n); return n === "llm.corp.example" ? ["10.1.2.3"] : ["52.1.2.3"]; },
  }, "/s.sock", true);
  assert.deepEqual(facts.endpoints.map((e) => [e.name, e.placement, e.addresses ?? null, e.reach ?? null]), [
    ["ollama", "host", null, null],
    ["corp", "network", ["10.1.2.3"], "private"],
    ["lab", "network", ["10.0.3.7"], "private"],
    ["pl", "network", ["52.1.2.3"], "public"],
  ]);
  assert.deepEqual(looked, ["llm.corp.example", "pl.corp.example"], "only names are resolved");
});

test("modelRows: local-model labels with no model declared → the D6 sentence with the lines; a declared model or no label → silent", () => {
  const rows = modelRows(base({ localModelLines: [3, 9] }));
  assert.deepEqual(rows, [
    `  ✗ files labeled local-model are read by no model until you declare your own model in policy.yaml (${POLICY}, lines 3, 9; add a models: entry with local: true)`,
  ]);
  assert.deepEqual(modelRows(base({ localModelLines: [3], endpoints: [row({})] })).filter((l) => l.includes("read by no model")), []);
  assert.deepEqual(modelRows(base({})), []);
  // Arbiter down: the file decides whether a section exists.
  assert.ok(modelRows(base({ source: "file", localModelLines: [3], declaredInFile: false }))[0]!.includes("read by no model"));
  assert.deepEqual(modelRows(base({ source: "file", localModelLines: [3], declaredInFile: true })), [
    `  · ${POLICY} declares models: start Mandu (any launch starts it) and run mandu doctor again to check them`,
  ]);
});

test("renderDoctor: the models section appears only with something to say", () => {
  const facts: DoctorFacts = {
    node: { version: "22.22.1", ok: true }, git: "2.50.1", agents: { claude: true, codex: false },
    layout: { mode: "installed", root: "/opt/mandu" }, arbiter: { sock: "/s.sock", reachable: true },
    kernel: { "net-supervisor": false, "fs-supervisor": false, "exec-supervisor": false },
    confinement: { posture: "confined" }, claudeSandbox: null,
  };
  assert.doesNotMatch(renderDoctor(facts), /Your own models/);
  assert.doesNotMatch(renderDoctor({ ...facts, models: base({}) }), /Your own models/);
  const out = renderDoctor({ ...facts, models: base({ endpoints: [row({})] }) });
  assert.match(out, /Your own models \(policy\.yaml models:\)\n  ✓ ollama: http:\/\/127\.0\.0\.1:11434/);
});

// ── ANTHROPIC_BASE_URL against models: (plan 11 §5, phase 3) ────────────────

test("gatherModels: a set ANTHROPIC_BASE_URL is matched with the launch's own rule; unset adds nothing; arbiter down → unknown", async () => {
  const gpu: ModelEndpoint = { name: "gpu", url: "http://localhost:8080/", wire: "anthropic", local: true };
  const lan: ModelEndpoint = { name: "lan", url: "http://192.168.1.20:8080", wire: "anthropic", local: true };
  const read: ModelEndpointsRead = { status: "ok", endpoints: [ollama, gpu, lan], dropped: [] };
  const hit = await gatherModels({ ...env, ANTHROPIC_BASE_URL: "http://LOCALHOST:8080" }, deps({ read }), "/s.sock", true);
  assert.deepEqual(hit.anthropicBaseUrl, { url: "http://LOCALHOST:8080", match: { name: "gpu", local: true } });
  const refused = await gatherModels({ ...env, ANTHROPIC_BASE_URL: "http://192.168.1.20:8080/" }, deps({ read }), "/s.sock", true);
  assert.deepEqual(refused.anthropicBaseUrl, { url: "http://192.168.1.20:8080/", match: { name: "lan", local: true }, refused: true });
  const miss = await gatherModels({ ...env, ANTHROPIC_BASE_URL: "http://127.0.0.1:11434" }, deps({ read }), "/s.sock", true);
  assert.deepEqual(miss.anthropicBaseUrl, { url: "http://127.0.0.1:11434", match: null }, "an openai-chat entry is never the main model");
  const unset = await gatherModels(env, deps({ read }), "/s.sock", true);
  assert.equal("anthropicBaseUrl" in unset, false, "no key without the variable (older fixtures keep their shape)");
  const offline = await gatherModels({ ...env, ANTHROPIC_BASE_URL: "http://localhost:8080" }, deps({ read }), "/s.sock", false);
  assert.equal(offline.source, "file");
  assert.deepEqual(offline.anthropicBaseUrl, { url: "http://localhost:8080", match: null });
});

test("modelRows: the ANTHROPIC_BASE_URL row: declared ✓ (own / outside), plain http off this machine ✗, undeclared ✗ with the fix, unknown ·", () => {
  const rows = (b: ModelsFacts["anthropicBaseUrl"], over: Partial<ModelsFacts> = {}): string[] =>
    modelRows(base({ anthropicBaseUrl: b, ...over })).filter((l) => l.includes("ANTHROPIC_BASE_URL"));
  assert.deepEqual(rows({ url: "http://localhost:8080", match: { name: "gpu", local: true } }), [
    "  ✓ ANTHROPIC_BASE_URL is models: gpu (your own model); the model proxy stays in front of it",
  ]);
  assert.deepEqual(rows({ url: "https://gw.example.com", match: { name: "gw", local: false } }), [
    "  ✓ ANTHROPIC_BASE_URL is models: gw (an outside model); the model proxy stays in front of it",
  ]);
  assert.match(rows({ url: "http://192.168.1.20:8080", match: { name: "lan", local: true }, refused: true })[0]!,
    /^  ✗ ANTHROPIC_BASE_URL is models: lan, but a launch refuses it: .*plain http only to this machine; put the model behind https or run it on this machine$/);
  assert.deepEqual(rows({ url: "http://127.0.0.1:9999", match: null }), [
    "  ✗ ANTHROPIC_BASE_URL (http://127.0.0.1:9999) is not declared under models:, so a launch skips the model proxy for it and the model " +
      "reads file contents unprotected; declare it under models: with wire: anthropic (local: true if it is your own model)",
  ]);
  assert.deepEqual(rows({ url: "http://127.0.0.1:9999", match: null }, { source: "file" }), [
    "  · ANTHROPIC_BASE_URL is set (http://127.0.0.1:9999): start Mandu and run mandu doctor again to check it against models:",
  ]);
  assert.deepEqual(rows(undefined), []);
  for (const l of [...rows({ url: "u", match: null }), ...rows({ url: "u", match: { name: "n", local: true }, refused: true })]) {
    assert.ok(!/ — /.test(l), `no em-dash interjection: ${l}`);
  }
});

test("renderDoctor: a set ANTHROPIC_BASE_URL alone opens the models section", () => {
  const facts: DoctorFacts = {
    node: { version: "22.22.1", ok: true }, git: "2.50.1", agents: { claude: true, codex: false },
    layout: { mode: "installed", root: "/opt/mandu" }, arbiter: { sock: "/s.sock", reachable: true },
    kernel: { "net-supervisor": false, "fs-supervisor": false, "exec-supervisor": false },
    confinement: { posture: "confined" }, claudeSandbox: null,
  };
  const out = renderDoctor({ ...facts, models: base({ anthropicBaseUrl: { url: "http://x:1", match: null } }) });
  assert.match(out, /Your own models \(policy\.yaml models:\)\n  ✗ ANTHROPIC_BASE_URL \(http:\/\/x:1\) is not declared under models:/);
});

// ── MANDU_OPENAI_BASE_URL (Codex) against models: (plan 11 §7.2) ────────────

test("gatherModels: a set MANDU_OPENAI_BASE_URL is matched against openai-chat entries only", async () => {
  const oll: ModelEndpoint = { name: "oll", url: "http://localhost:11434/v1", wire: "openai-chat", local: true };
  const gpu: ModelEndpoint = { name: "gpu", url: "http://127.0.0.1:8080/v1", wire: "anthropic", local: true };
  const read: ModelEndpointsRead = { status: "ok", endpoints: [gpu, oll], dropped: [] };
  const hit = await gatherModels({ ...env, MANDU_OPENAI_BASE_URL: "http://LOCALHOST:11434/v1/" }, deps({ read }), "/s.sock", true);
  assert.deepEqual(hit.openaiBaseUrl, { url: "http://LOCALHOST:11434/v1/", match: { name: "oll", local: true } });
  const miss = await gatherModels({ ...env, MANDU_OPENAI_BASE_URL: "http://127.0.0.1:8080/v1" }, deps({ read }), "/s.sock", true);
  assert.deepEqual(miss.openaiBaseUrl, { url: "http://127.0.0.1:8080/v1", match: null }, "an anthropic entry is never Codex's main model");
  const both = await gatherModels({ ...env, ANTHROPIC_BASE_URL: "http://127.0.0.1:8080/v1", MANDU_OPENAI_BASE_URL: "http://localhost:11434/v1" }, deps({ read }), "/s.sock", true);
  assert.equal(both.anthropicBaseUrl?.match?.name, "gpu");
  assert.equal(both.openaiBaseUrl?.match?.name, "oll");
  const unset = await gatherModels(env, deps({ read }), "/s.sock", true);
  assert.equal("openaiBaseUrl" in unset, false);
});

test("modelRows: the MANDU_OPENAI_BASE_URL row names the Codex knob and wire: openai-chat", () => {
  const rows = (b: ModelsFacts["openaiBaseUrl"]): string[] =>
    modelRows(base({ openaiBaseUrl: b })).filter((l) => l.includes("MANDU_OPENAI_BASE_URL"));
  assert.deepEqual(rows({ url: "http://localhost:11434/v1", match: { name: "oll", local: true } }), [
    "  ✓ MANDU_OPENAI_BASE_URL is models: oll (your own model); the model proxy stays in front of it",
  ]);
  assert.deepEqual(rows({ url: "http://127.0.0.1:9999/v1", match: null }), [
    "  ✗ MANDU_OPENAI_BASE_URL (http://127.0.0.1:9999/v1) is not declared under models:, so a launch skips the model proxy for it and the model " +
      "reads file contents unprotected; declare it under models: with wire: openai-chat (local: true if it is your own model)",
  ]);
  assert.deepEqual(rows(undefined), []);
});

test("modelRows: an outside model alone reads no local-model file (D2); Rules-page labels the line scan cannot see are named too", () => {
  const outside = row({ name: "gw", url: "https://gw.example", wire: "anthropic", model: undefined, local: false, host: "gw.example", hostClass: "name" });
  const lines = modelRows(base({ localModelLines: [3], endpoints: [outside] })).filter((l) => l.includes("read by no model"));
  assert.equal(lines.length, 1, "a declared outside model does not silence the row");
  assert.deepEqual(modelRows(base({ localModelLabels: ["/h/a.md", "/h/b.md"] })).filter((l) => l.includes("read by no model")), [
    "  ✗ files labeled local-model are read by no model until you declare your own model in policy.yaml (labeled on the Rules page: /h/a.md, /h/b.md; add a models: entry with local: true)",
  ]);
  assert.match(
    modelRows(base({ localModelLines: [3], localModelLabels: ["/1", "/2", "/3", "/4", "/5"] })).join("\n"),
    new RegExp(`\\(${POLICY.replace(/[.]/g, "\\.")}, line 3; labeled on the Rules page: /1, /2, /3 and 2 more; add`),
  );
  assert.deepEqual(modelRows(base({ localModelLabels: ["/h/a.md"], endpoints: [row({})] })).filter((l) => l.includes("read by no model")), [], "your own model declared: silent");
});

test("gatherModels: the arbiter's non-file local-model labels ride the facts; absent dep or a failed read adds nothing", async () => {
  const deps = { readKnob: () => null, modelEndpoints: async () => ({ status: "ok" as const, endpoints: [], dropped: [] }) };
  const withLabels = await gatherModels({}, { ...deps, localModelLabels: async () => ["/h/x.md"] }, "/s", true);
  assert.deepEqual(withLabels.localModelLabels, ["/h/x.md"]);
  assert.equal((await gatherModels({}, { ...deps, localModelLabels: async () => null }, "/s", true)).localModelLabels, undefined);
  assert.equal((await gatherModels({}, deps, "/s", true)).localModelLabels, undefined);
});

test("modelRows (plan 12 D2): an opted-in plain-http entry is a ✗ row naming the opt-out; an unopted one names the refusal; https is silent", () => {
  const rows = modelRows(base({ endpoints: [
    row({ name: "lab", url: "http://10.0.3.7:8000", host: "10.0.3.7", hostClass: "private", reachable: true, modelListed: null, plainHttp: "allowed" }),
    row({ name: "old", url: "http://10.0.3.8:8000", host: "10.0.3.8", hostClass: "private", reachable: true, modelListed: null, plainHttp: "refused" }),
    row({ name: "corp", url: "https://10.0.3.9:8443", host: "10.0.3.9", hostClass: "private", reachable: true, modelListed: null }),
  ] })).join("\n");
  assert.match(rows, /✗ lab: plain http to another machine, allowed by allow_plain_http: files labeled local-model the helper sends there cross the network unencrypted/);
  assert.match(rows, /✗ old: plain http to another machine: the helper and a launch refuse this entry/);
  assert.doesNotMatch(rows, /corp: plain http/);
  assert.ok(!/ — /.test(rows));
});

test("gatherModels (plan 12 D2): plainHttp is derived from the entry, allowed only with allowPlainHttp", async () => {
  const lab: ModelEndpoint = { name: "lab", url: "http://10.0.3.7:8000", wire: "openai-chat", model: "qwen", local: true };
  const read: ModelEndpointsRead = { status: "ok", endpoints: [lab, { ...lab, name: "lab2", allowPlainHttp: true }, ollama], dropped: [] };
  const facts = await gatherModels(env, { readKnob: () => null, modelEndpoints: async () => read }, "/s.sock", true);
  assert.deepEqual(facts.endpoints.map((e) => [e.name, e.plainHttp ?? null]), [["lab", "refused"], ["lab2", "allowed"], ["ollama", null]]);
});

test("plan 12 D3/D6: one TLS handshake with the entry's checks for a reachable https entry; ✓ names the checks, ✗ the reason", async () => {
  const PIN = Buffer.alloc(32, 9).toString("base64");
  const eps: ModelEndpoint[] = [
    { name: "corp", url: "https://llm.corp.example/v1", wire: "openai-chat", model: "q", local: true, tls: { pinSha256: [PIN] } },
    { name: "lan", url: "https://10.0.3.7:8443", wire: "anthropic", local: true },
    { name: "home", url: "https://127.0.0.1:8443", wire: "anthropic", local: true },
    { name: "http", url: "http://127.0.0.1:11434", wire: "anthropic", local: true },
  ];
  const probed: string[] = [];
  const facts = await gatherModels(env, {
    readKnob: () => null,
    modelEndpoints: async () => ({ status: "ok", endpoints: eps, dropped: [] }),
    probeTcp: async () => true,
    lookupHost: async () => ["10.1.2.3"],
    probeTls: async (h, p, m) => { probed.push(`${h}:${p} ${JSON.stringify(m)}`); return h === "10.0.3.7" ? { ok: false, reason: "the server's certificate is not trusted (add your organization's CA as tls.ca_file)" } : { ok: true }; },
  }, "/s.sock", true);
  assert.deepEqual(probed, [`llm.corp.example:443 {"pins":["${PIN}"]}`, "10.0.3.7:8443 {}"], "tls configured, or local on another machine; this computer and http are not probed");
  const rows = modelRows(facts).join("\n");
  assert.match(rows, /✓ corp: TLS checked \(a pinned key\)/);
  assert.match(rows, /✗ lan: TLS refused: the server's certificate is not trusted \(add your organization's CA as tls\.ca_file\); nothing is sent to this model until it passes/);
  assert.doesNotMatch(rows, /home: TLS|http: TLS/);
  assert.deepEqual(tlsChecksWords({ caFile: "/a", pinSha256: [PIN], clientCert: "/c", clientKey: "/k" }), ["your CA", "a pinned key", "a client certificate"]);
  assert.deepEqual(tlsChecksWords(undefined), []);
});

test("plan 12 D4: an entry with a perimeter is graded against it from the addresses doctor resolved; outside ✗ (no TLS probe to it), inside ✓, unresolved ✗; the public hint gives way to it", async () => {
  const nets = ["10.0.0.0/8"];
  const eps: ModelEndpoint[] = [
    { name: "in", url: "https://llm.corp.example", wire: "anthropic", local: true, perimeter: nets, orgDomain: true },
    { name: "out", url: "https://drift.corp.example", wire: "anthropic", local: true, perimeter: nets },
    { name: "lit", url: "https://203.0.113.9:8443", wire: "anthropic", local: true, perimeter: nets },
    { name: "gone", url: "https://gone.corp.example", wire: "anthropic", local: true, perimeter: nets },
  ];
  const answers: Record<string, string[]> = { "llm.corp.example": ["10.1.2.3"], "drift.corp.example": ["10.1.2.4", "52.1.2.3"], "gone.corp.example": [] };
  const probed: string[] = [];
  const facts = await gatherModels(env, {
    readKnob: () => null,
    modelEndpoints: async () => ({ status: "ok", endpoints: eps, dropped: [] }),
    probeTcp: async () => true,
    lookupHost: async (h) => answers[h] ?? [],
    probeTls: async (h) => { probed.push(h); return { ok: true }; },
  }, "/s.sock", true);
  assert.deepEqual(facts.endpoints.map((e) => [e.name, e.perimeter?.ok, e.perimeter?.outside ?? null]), [
    ["in", true, null], ["out", false, "52.1.2.3"], ["lit", false, "203.0.113.9"], ["gone", false, null],
  ]);
  assert.deepEqual(probed, ["llm.corp.example"], "no handshake with an address outside the perimeter");
  const rows = modelRows(facts).join("\n");
  assert.match(rows, /in: https:\/\/llm\.corp\.example \(anthropic, your own model, on your organization's network, the helper uses it\)/);
  assert.match(rows, /✓ in: every address \(10\.1\.2\.3\) is inside perimeter\.networks/);
  assert.match(rows, /✗ out: resolves to 52\.1\.2\.3, outside perimeter\.networks \(10\.0\.0\.0\/8\); a launch refuses this entry and nothing is sent to it/);
  assert.match(rows, /✗ lit: is at 203\.0\.113\.9, outside perimeter\.networks/);
  assert.match(rows, /✗ gone: does not resolve here, so it cannot be checked against perimeter\.networks/);
  assert.doesNotMatch(rows, /hint:/, "the perimeter rows replace the address hints");
});

test("plan 12 D5: doctor names the administrator's files and the lock, and marks their entries", async () => {
  const corp: ModelEndpoint = { name: "corp", url: "https://llm.corp.example", wire: "anthropic", local: true, adminFile: "/etc/mandu/policy.d/10-corp.yaml", locked: true };
  const facts = await gatherModels(env, {
    readKnob: () => null,
    modelEndpoints: async () => ({ status: "ok", endpoints: [corp], dropped: [], admin: { files: ["/etc/mandu/policy.d/10-corp.yaml"], locked: true, conflicts: [], refused: [] } }),
  }, "/s.sock", true);
  const rows = modelRows(facts);
  assert.equal(rows[0], "  · your administrator's policy: /etc/mandu/policy.d/10-corp.yaml; your own models are locked: you can remove one of theirs or add an outside model, not add or change your own");
  assert.match(rows.join("\n"), /corp: https:\/\/llm\.corp\.example \(anthropic, your own model, on your network, the helper uses it, set by your administrator\)/);
  const open = modelRows({ ...facts, admin: { files: ["/etc/mandu/policy.d/10-corp.yaml"], locked: false } });
  assert.match(open[0]!, /not locked: an entry of the same name in policy\.yaml changes one of theirs/);
  assert.ok(!modelRows({ ...facts, admin: undefined }).some((r) => r.includes("administrator's policy")));
});

test("plan 12 D5: doctor names the user's entries the administrator's layer keeps out of force, and a refused re-read", () => {
  const rows = modelRows({
    source: "arbiter", endpoints: [], localModelLines: [],
    admin: {
      files: ["/etc/mandu/policy.d/10-corp.yaml"], locked: true,
      conflicts: ["models[0]: 'mine' is local: true, and your own models are set by your administrator (/etc/mandu/policy.d/10-corp.yaml): you can add outside models only (local: true is refused)"],
      refused: ["/etc/mandu/policy.d/20-bad.yaml: 'paths' cannot be set here"],
    },
  } as never);
  assert.match(rows.join("\n"), /✗ not in force, your administrator's policy wins: 'mine' is local: true.*; change policy\.yaml to match/);
  assert.match(rows.join("\n"), /✗ your administrator's policy changed and cannot be used, so the one read before stays in force: .*20-bad\.yaml: 'paths' cannot be set here/);
  // A refused layer with no file in force: no files row.
  const gone = modelRows({ source: "arbiter", endpoints: [], localModelLines: [], admin: { files: [], locked: false, conflicts: [], refused: ["x"] } } as never);
  assert.ok(!gone.some((r) => r.includes("your administrator's policy:")));
});
