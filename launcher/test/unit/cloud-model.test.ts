/**
 * cloud-model.test — plan 11 §8 item 3 on the launcher's side: a
 * cloud-backed model name (Ollama's `:cloud` / `-cloud` tags run on the
 * vendor's servers behind the same loopback API) is never the operator's own
 * model.
 *
 * Pins the launcher's mirror of `isCloudBackedModel` (the three copies are
 * pinned to one table by tests/stack/cloud-model-parity.test.ts),
 * the launch refusal for a `local: true` entry naming one (a belt for an
 * arbiter older than the load rule), the policy-file line scan doctor uses,
 * and the two doctor rows: ✗ for such an entry (from the arbiter or the
 * file), · for a local server whose listing names cloud models.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { assertLocalEndpoints, isCloudBackedModel, type ModelEndpoint, type ModelEndpointsRead } from "../../src/model-endpoints.js";
import { cloudLocalModelEntries } from "../../src/policy-level-spelling.js";
import { gatherModels, modelRows, type DoctorDeps, type ModelsFacts } from "../../src/doctor.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // local-model matters under the confidentiality axis; none of this reads an axis itself

test("isCloudBackedModel: cloud tags and names yes; local models and near misses no", () => {
  for (const n of ["gpt-oss:120b-cloud", "qwen3-coder:480b-cloud", "deepseek-v3.1:671b-cloud", "glm-4.6:cloud", "KIMI-K2:1T-CLOUD", "deepseek-v3.1-cloud", "x:480b-cloud-q4"]) {
    assert.equal(isCloudBackedModel(n), true, n);
  }
  for (const n of ["llama3.2", "gpt-oss:20b", "wordcloud:7b", "cloud-llama:7b", "claude-haiku-4-5", "registry:5000/team/model", ""]) {
    assert.equal(isCloudBackedModel(n), false, n);
  }
});

const noNet = { lookup: async () => [], localAddresses: () => [] };

test("assertLocalEndpoints: a local: true entry with a cloud model refuses the launch; a non-local one does not", async () => {
  const cloudLocal: ModelEndpoint = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "gpt-oss:120b-cloud", local: true };
  await assert.rejects(assertLocalEndpoints({ status: "ok", endpoints: [cloudLocal], dropped: [] }, [], noNet), (e: Error) => {
    assert.equal(e.name, "CloudLocalModelError");
    assert.match(e.message, /models: ollama \(model gpt-oss:120b-cloud, http:\/\/127\.0\.0\.1:11434\)/);
    assert.match(e.message, /Name a model that runs on your own servers, or remove `local: true`, then launch again\.$/);
    assert.ok(!/ — /.test(e.message), "no em-dash interjection");
    return true;
  });
  await assertLocalEndpoints({ status: "ok", endpoints: [{ ...cloudLocal, local: false }, { ...cloudLocal, name: "own", model: "gpt-oss:20b" }], dropped: [] }, [], noNet);
});

test("cloudLocalModelEntries: block and flow style, local: true only, comments skipped, stops at the next top-level key", () => {
  const block = [
    "version: 1",               // 1
    "models:",                  // 2
    "  - name: ollama",         // 3
    "    url: http://127.0.0.1:11434",
    "    model: \"gpt-oss:120b-cloud\"", // 5
    "    local: true",
    "  - name: own",            // 7
    "    model: gpt-oss:20b",
    "    local: true",
    "  - name: relay",          // 10
    "    model: glm-4.6:cloud", // 11
    "    local: false",
    "- name: col0",             // 13 (a block list at the key's column)
    "  local: true   # mine",
    "  model: minimax-m2:cloud", // 15
    "paths:",
    "  - path: ~/x",
    "    model: gpt-oss:120b-cloud",
    "    local: true",
  ].join("\n");
  assert.deepEqual(cloudLocalModelEntries(block), [
    { line: 5, name: "ollama", model: "gpt-oss:120b-cloud" },
    { line: 15, name: "col0", model: "minimax-m2:cloud" },
  ]);
  assert.deepEqual(cloudLocalModelEntries("models: [{ name: a, model: 'kimi-k2:1t-cloud', local: true }, { name: b, model: x:cloud }]\n"), [
    { line: 1, name: "a", model: "kimi-k2:1t-cloud" },
  ]);
  assert.deepEqual(cloudLocalModelEntries("models:\n  - name: c\n    # model: gpt-oss:120b-cloud\n    local: true\n"), []);
  assert.deepEqual(cloudLocalModelEntries("paths: []\n"), []);
});

const POLICY = "/cfg/mandu/policy.yaml";
const env = { MANDU_POLICY_FILE: POLICY };
const ollama: ModelEndpoint = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "gpt-oss:20b", local: true };

function deps(over: { file?: string | null; read?: ModelEndpointsRead; ids?: string[] | null; seen?: string[] } = {}): Pick<DoctorDeps, "readKnob" | "modelEndpoints" | "probeTcp" | "listModels"> {
  return {
    readKnob: (p) => (p === POLICY ? (over.file ?? null) : null),
    modelEndpoints: async () => over.read ?? { status: "ok", endpoints: [], dropped: [] },
    probeTcp: async () => true,
    listModels: async (url) => { over.seen?.push(url); return over.ids === undefined ? ["gpt-oss:20b"] : over.ids; },
  };
}

test("gatherModels: a local endpoint's listing is read for cloud models (any wire), once; an outside one is not", async () => {
  const seen: string[] = [];
  const gpu: ModelEndpoint = { name: "gpu", url: "http://127.0.0.1:8080", wire: "anthropic", local: true };
  const outside: ModelEndpoint = { name: "gw", url: "https://gw.example", wire: "anthropic", local: false };
  const ids = ["gpt-oss:20b", "gpt-oss:120b-cloud", "llama3.2:latest", "glm-4.6:cloud"];
  const m = await gatherModels(env, deps({ read: { status: "ok", endpoints: [ollama, gpu, outside], dropped: [] }, ids, seen }), "/s.sock", true);
  assert.deepEqual(seen, ["http://127.0.0.1:11434", "http://127.0.0.1:8080"]);
  assert.deepEqual(m.endpoints.map((e) => [e.name, e.modelListed, e.cloudListed ?? null]), [
    ["ollama", true, ["gpt-oss:120b-cloud", "glm-4.6:cloud"]],
    ["gpu", null, ["gpt-oss:120b-cloud", "glm-4.6:cloud"]], // anthropic wire: no "is it loaded" check, still the cloud check
    ["gw", null, null],
  ]);
  const clean = await gatherModels(env, deps({ read: { status: "ok", endpoints: [ollama], dropped: [] } }), "/s.sock", true);
  assert.equal("cloudListed" in clean.endpoints[0]!, false, "no key when no cloud model is listed");
  assert.equal("cloudLocalInFile" in clean, false, "no key without such an entry in the file");
});

test("gatherModels: the file is scanned for a cloud local entry with the arbiter up (a refused reload) and down", async () => {
  const file = "models:\n  - name: ollama\n    url: http://127.0.0.1:11434\n    model: gpt-oss:120b-cloud\n    local: true\n";
  const up = await gatherModels(env, deps({ file, read: { status: "ok", endpoints: [ollama], dropped: [] } }), "/s.sock", true);
  assert.deepEqual(up.cloudLocalInFile, [{ line: 4, name: "ollama", model: "gpt-oss:120b-cloud" }]);
  const down = await gatherModels(env, deps({ file }), "/s.sock", false);
  assert.equal(down.source, "file");
  assert.deepEqual(down.cloudLocalInFile, [{ line: 4, name: "ollama", model: "gpt-oss:120b-cloud" }]);
});

const base = (over: Partial<ModelsFacts>): ModelsFacts => ({ source: "arbiter", endpoints: [], declaredInFile: true, localModelLines: [], policyPath: POLICY, ...over });
const row = (over: Partial<ModelsFacts["endpoints"][number]>): ModelsFacts["endpoints"][number] => ({
  name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "gpt-oss:20b", local: true, host: "127.0.0.1", hostClass: "loopback", placement: "host", reachable: true, modelListed: true, ...over,
});

test("modelRows: ✗ for a local entry naming a cloud model (arbiter or file, once), · for a local server listing cloud models", () => {
  const fromArbiter = modelRows(base({ endpoints: [row({ model: "gpt-oss:120b-cloud" })] }));
  assert.ok(fromArbiter.includes(
    "  ✗ ollama: model gpt-oss:120b-cloud runs on the vendor's servers (a cloud model), so this entry cannot be local: true; name a model that runs on your own machine, or remove local: true",
  ), fromArbiter.join("\n"));
  // The same entry also in the file: reported once, not twice.
  const both = modelRows(base({ endpoints: [row({ model: "gpt-oss:120b-cloud" })], cloudLocalInFile: [{ line: 4, name: "ollama", model: "gpt-oss:120b-cloud" }] }));
  assert.equal(both.filter((l) => l.includes("runs on the vendor's servers")).length, 1, both.join("\n"));
  // Only in the file (the arbiter refused the reload and kept the old law, or is not running).
  for (const source of ["arbiter", "file"] as const) {
    const onlyFile = modelRows(base({ source, endpoints: source === "arbiter" ? [row({})] : [], cloudLocalInFile: [{ line: 4, name: "ollama", model: "gpt-oss:120b-cloud" }] }));
    assert.ok(onlyFile.includes(
      `  ✗ ${POLICY} line 4: models: ollama says local: true, but its model gpt-oss:120b-cloud runs on the vendor's servers (a cloud model); ` +
        "Mandu refuses this file until the entry names a model that runs on your own machine or drops local: true",
    ), `${source}:\n${onlyFile.join("\n")}`);
  }
  // An outside entry may name a cloud model: no row.
  assert.deepEqual(modelRows(base({ endpoints: [row({ model: "gpt-oss:120b-cloud", local: false })] })).filter((l) => l.includes("vendor's servers")), []);

  const listed = modelRows(base({ endpoints: [row({ cloudListed: ["gpt-oss:120b-cloud", "glm-4.6:cloud"] })] }));
  assert.ok(listed.includes(
    "  · ollama also serves models that run on the vendor's servers (gpt-oss:120b-cloud, glm-4.6:cloud); requests for them leave this machine, " +
      "so never choose one as your main model or as this entry's model",
  ), listed.join("\n"));
  const many = modelRows(base({ endpoints: [row({ cloudListed: ["a:cloud", "b:cloud", "c:cloud", "d:cloud", "e:cloud", "f:cloud", "g:cloud"] })] }));
  assert.ok(many.some((l) => l.includes("(a:cloud, b:cloud, c:cloud, d:cloud, e:cloud and 2 more)")), many.join("\n"));
  for (const l of [...fromArbiter, ...listed]) assert.ok(!/ — /.test(l), `no em-dash interjection: ${l}`);
});
