/**
 * cloud-model.test — plan 11 §8 item 3: a cloud-backed model name is never
 * the operator's own model.
 *
 * Pins `isCloudBackedModel` (policy/cloud-model.ts) on Ollama's published
 * cloud tags and the near misses, and the policy load refusal in
 * `validatePolicyDocument`: a `local: true` entry naming a cloud model is a
 * problem that names the entry; the same model on a non-local entry is fine.
 * The cross-package mirrors are pinned together by
 * tests/stack/cloud-model-parity.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { isCloudBackedModel } from "../../policy/cloud-model.js";
import { validatePolicyDocument } from "../../policy/policy-file-validate.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // local-model is a confidentiality level; the validator itself reads no axis

test("isCloudBackedModel: Ollama's cloud tags and names are cloud-backed", () => {
  for (const name of [
    "gpt-oss:120b-cloud", "gpt-oss:20b-cloud", "qwen3-coder:480b-cloud", "deepseek-v3.1:671b-cloud",
    "kimi-k2:1t-cloud", "glm-4.6:cloud", "minimax-m2:cloud", "GPT-OSS:120B-CLOUD", "  glm-4.6:cloud  ",
    "deepseek-v3.1-cloud", "foo_cloud:latest", "cloud", "ollama.com/library/gpt-oss:120b-cloud",
    "qwen3-coder:480b-cloud-q4", "gpt-oss:120b-cloud@sha256:abc123", "registry:5000/team/model-cloud",
  ]) {
    assert.equal(isCloudBackedModel(name), true, name);
  }
});

test("isCloudBackedModel: local models and near misses are not", () => {
  for (const name of [
    "llama3.2", "llama3.2:latest", "qwen2.5-coder:7b", "gpt-oss:20b", "hf.co/bartowski/x-GGUF:Q4_K_M",
    "wordcloud:7b", "soundcloud-embed:latest", "cloudy:1b", "cloud-llama:7b", "claude-haiku-4-5",
    "registry:5000/team/model", "", "   ", "@sha256:cloud",
  ]) {
    assert.equal(isCloudBackedModel(name), false, JSON.stringify(name));
  }
});

test("policy load refuses a local: true entry whose model is cloud-backed, naming the entry", () => {
  const problems = validatePolicyDocument({ version: 1, models: [
    { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "gpt-oss:120b-cloud", local: true },
  ] });
  assert.equal(problems.length, 1, problems.join("\n"));
  assert.match(problems[0]!, /^models\[0\]\.model: 'gpt-oss:120b-cloud' runs on the vendor's servers \(a cloud model\), so 'ollama' cannot be local: true; /);
  assert.ok(!/ — /.test(problems[0]!), "no em-dash interjection");
});

test("policy load accepts the same cloud model on a non-local entry, and a local entry with a local model", () => {
  assert.deepEqual(validatePolicyDocument({ version: 1, models: [
    { name: "ollama-cloud", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "gpt-oss:120b-cloud", local: false },
    { name: "ollama-cloud-2", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "glm-4.6:cloud" },
    { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "gpt-oss:20b", local: true },
    { name: "gpu", url: "http://127.0.0.1:8080", wire: "anthropic", local: true }, // no model: nothing to check
  ] }), []);
});
