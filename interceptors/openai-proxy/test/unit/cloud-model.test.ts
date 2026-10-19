/**
 * cloud-model.test.ts — the openai-proxy's copy of the cloud-model rule
 * (plan 11 §8 item 3, §7.2). The full table, and agreement with the other
 * three copies, is tests/stack/cloud-model-parity.test.ts;
 * this pins the package on its own.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { isCloudBackedModel } from "../../src/cloud-model.js";

// Axes: none (a pure name predicate).

test("isCloudBackedModel: cloud tags and names are cloud; local models and near misses are not", () => {
  for (const n of ["gpt-oss:120b-cloud", "glm-4.6:cloud", "GPT-OSS:120B-CLOUD", "deepseek-v3.1-cloud", "gpt-oss:120b-cloud@sha256:ab"]) {
    assert.equal(isCloudBackedModel(n), true, n);
  }
  for (const n of ["gpt-oss:20b", "llama3.2", "wordcloud:7b", "cloud-llama:7b", "gpt-5.4", "", "@sha256:cloud"]) {
    assert.equal(isCloudBackedModel(n), false, n);
  }
});
