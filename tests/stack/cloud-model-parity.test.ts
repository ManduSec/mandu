/**
 * cloud-model-parity.test.ts — ONE cloud-model rule in five packages
 * (model-endpoints.md §1.8 item 3).
 *
 * "Is this model name one the server runs on the vendor's machine?" is
 * decided in five places that ship standalone and cannot import each other:
 *   - arbiter/policy/cloud-model.ts            refuses a `local: true`
 *                                               `models:` entry at policy load
 *   - launcher/src/model-endpoints.ts          refuses the launch (older
 *                                               arbiter) and drives doctor rows
 *   - interceptors/anthropic-proxy/src/cloud-model.ts  refuses a request for
 *                                               such a model at a declared
 *                                               local main model
 *   - interceptors/openai-proxy/src/cloud-model.ts     the same, for Codex
 *                                               (plan 11 §7.2)
 *   - dashboard/src/model-probe.ts             Settings › Models "Test
 *                                               connection" (dashboard.md §4.25l)
 * A drift would let a name through one door that another refuses. This runs
 * all five over one table (Ollama's published cloud tags, spelling variants,
 * and the near misses) and asserts they agree with the expected answer.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { isCloudBackedModel as arbiterRule } from "../../arbiter/policy/cloud-model.js";
import { isCloudBackedModel as launcherRule } from "../../launcher/src/model-endpoints.js";
import { isCloudBackedModel as proxyRule } from "../../interceptors/anthropic-proxy/src/cloud-model.js";
import { isCloudBackedModel as openaiProxyRule } from "../../interceptors/openai-proxy/src/cloud-model.js";
import { isCloudBackedModel as dashboardRule } from "../../dashboard/src/model-probe.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the rule protects local-model data (the confidentiality axis); it reads no axis itself

const TABLE: ReadonlyArray<readonly [string, boolean]> = [
  // Ollama's cloud catalog shapes.
  ["gpt-oss:120b-cloud", true],
  ["gpt-oss:20b-cloud", true],
  ["qwen3-coder:480b-cloud", true],
  ["deepseek-v3.1:671b-cloud", true],
  ["kimi-k2:1t-cloud", true],
  ["glm-4.6:cloud", true],
  ["minimax-m2:cloud", true],
  ["qwen3-vl:235b-cloud", true],
  // Spelling variants the servers accept.
  ["GPT-OSS:120B-CLOUD", true],
  ["  glm-4.6:cloud\t", true],
  ["ollama.com/library/gpt-oss:120b-cloud", true],
  ["gpt-oss:120b-cloud@sha256:0123abcd", true],
  ["qwen3-coder:480b-cloud-q4", true],
  ["qwen3-coder:480b_cloud", true],
  ["deepseek-v3.1-cloud", true],
  ["foo_cloud:latest", true],
  ["cloud", true],
  ["registry:5000/team/model-cloud", true],
  // Local models and near misses.
  ["gpt-oss:20b", false],
  ["gpt-oss", false],
  ["llama3.2", false],
  ["llama3.2:latest", false],
  ["qwen2.5-coder:7b-instruct-q4_K_M", false],
  ["hf.co/bartowski/Qwen2.5-GGUF:Q4_K_M", false],
  ["registry:5000/team/model", false],
  ["wordcloud:7b", false],
  ["soundcloud-embed:latest", false],
  ["cloudy:1b", false],
  ["cloud-llama:7b", false],
  ["cloudflare/llama:8b", false],
  ["claude-haiku-4-5", false],
  ["claude-sonnet-4-5-20250929", false],
  ["", false],
  ["   ", false],
  ["@sha256:cloud", false],
];

test("the arbiter, the launcher, both model proxies and the dashboard agree on every name in the table", () => {
  for (const [name, want] of TABLE) {
    assert.equal(arbiterRule(name), want, `arbiter: ${JSON.stringify(name)}`);
    assert.equal(launcherRule(name), want, `launcher: ${JSON.stringify(name)}`);
    assert.equal(proxyRule(name), want, `anthropic-proxy: ${JSON.stringify(name)}`);
    assert.equal(openaiProxyRule(name), want, `openai-proxy: ${JSON.stringify(name)}`);
    assert.equal(dashboardRule(name), want, `dashboard: ${JSON.stringify(name)}`);
  }
});
