/**
 * model-placement.test — plan 12 D1/D2: where a declared model sits, and the
 * policy load rule that a `local: true` entry on another machine is reached
 * over https unless it opts out with `allow_plain_http: true`.
 *
 * Pins `endpointPlacement` / `isPlainHttpToNetwork` (policy/model-placement.ts)
 * on every loopback spelling and the remote shapes, the load refusal and its
 * opt-out in `validatePolicyDocument`, and the compiled field the
 * `modelEndpoints` op carries. The cross-package mirrors are pinned together
 * by tests/stack/model-placement-parity.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { endpointPlacement, isLoopbackHost, isPlainHttpToNetwork } from "../../policy/model-placement.js";
import { validatePolicyDocument } from "../../policy/policy-file-validate.js";
import { compilePolicy } from "../../policy/compiled-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // local-model is a confidentiality level; placement reads no axis

test("placement: every loopback spelling is host; private, public and named hosts are network", () => {
  for (const u of [
    "http://127.0.0.1:11434", "http://127.1.2.3", "http://localhost:8080", "http://LOCALHOST.", "http://gpu.localhost:1",
    "http://[::1]:8000", "http://[::]:1", "http://0.0.0.0:1", "http://[::ffff:127.0.0.1]:1", "http://0x7f000001:1",
    "https://127.0.0.1:8443",
  ]) {
    assert.equal(endpointPlacement(u), "host", u);
  }
  for (const u of [
    "http://10.0.3.7:8000", "http://192.168.1.2", "http://[fd00::1]:8000", "http://169.254.1.1", "http://8.8.8.8",
    "https://llm.ml.corp.example/v1", "http://localhost.corp.example", "http://127.0.0.1.nip.io", "http://[::ffff:10.0.0.1]:1",
  ]) {
    assert.equal(endpointPlacement(u), "network", u);
  }
  assert.equal(endpointPlacement("ftp://127.0.0.1"), null);
  assert.equal(endpointPlacement("not a url"), null);
  assert.equal(isLoopbackHost("127.0.0.256"), false, "not an address");
});

test("isPlainHttpToNetwork: only http to a network placement", () => {
  assert.equal(isPlainHttpToNetwork("http://10.0.3.7:8000"), true);
  assert.equal(isPlainHttpToNetwork("http://llm.corp.example"), true);
  assert.equal(isPlainHttpToNetwork("https://10.0.3.7:8443"), false);
  assert.equal(isPlainHttpToNetwork("http://127.0.0.1:11434"), false);
  assert.equal(isPlainHttpToNetwork("http://localhost:11434"), false);
  assert.equal(isPlainHttpToNetwork("garbage"), false);
});

test("policy load refuses a local: true entry on another machine over plain http, naming it and the fixes", () => {
  for (const url of ["http://10.0.3.7:8000", "http://[fd00::7]:8000", "http://llm.corp.example/v1", "http://8.8.8.8"]) {
    const problems = validatePolicyDocument({ version: 1, models: [{ name: "lab", url, wire: "openai-chat", model: "qwen", local: true }] });
    assert.equal(problems.length, 1, `${url}: ${problems.join("\n")}`);
    assert.match(problems[0]!, /^models\[0\]\.url: 'lab' is on another machine and would receive local-model files in the clear; use https, reach it through a loopback tunnel \(ssh -L\), or add allow_plain_http: true to accept that$/);
    assert.ok(!/ — /.test(problems[0]!), "no em-dash interjection");
  }
});

test("policy load accepts https, loopback http, a non-local http entry, and the explicit opt-out", () => {
  assert.deepEqual(validatePolicyDocument({ version: 1, models: [
    { name: "corp", url: "https://llm.corp.example/v1", wire: "openai-chat", model: "qwen", local: true },
    { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true },
    { name: "tunnel", url: "http://localhost:18000", local: true },
    { name: "outside", url: "http://10.0.3.8:8000" },
    { name: "lab", url: "http://10.0.3.7:8000", wire: "openai-chat", model: "qwen", local: true, allow_plain_http: true },
    { name: "lab2", url: "http://10.0.3.9:8000", local: true, allow_plain_http: true, helper: true },
  ] }), []);
});

test("allow_plain_http: must be a boolean, and is refused on an https url as meaningless", () => {
  const bad = validatePolicyDocument({ version: 1, models: [
    { name: "a", url: "https://llm.corp.example", local: true, allow_plain_http: true },
    { name: "b", url: "http://10.0.3.7:8000", local: true, allow_plain_http: "yes" },
  ] }).join("\n");
  assert.match(bad, /models\[0\]\.allow_plain_http: the url is already https, so there is nothing to allow; remove allow_plain_http/);
  assert.match(bad, /models\[1\]\.allow_plain_http: must be true or false/);
  assert.match(bad, /models\[1\]\.url: 'b' is on another machine/, "a non-boolean is no opt-out");
  assert.deepEqual(validatePolicyDocument({ version: 1, models: [
    { name: "c", url: "http://10.0.3.7:8000", local: true, allow_plain_http: false },
  ] }).length, 1, "allow_plain_http: false is the default spelled out: still refused");
});

test("the compiled list carries allowPlainHttp only when true (the modelEndpoints wire)", () => {
  const models = compilePolicy({ specId: "claude-code", document: { version: 1, models: [
    { name: "lab", url: "http://10.0.3.7:8000", local: true, allow_plain_http: true },
    { name: "ollama", url: "http://127.0.0.1:11434", local: true, allow_plain_http: false },
    { name: "corp", url: "https://llm.corp.example", local: true },
  ] } }).models;
  assert.equal(models.find((m) => m.name === "lab")?.allowPlainHttp, true);
  assert.equal("allowPlainHttp" in models.find((m) => m.name === "ollama")!, false);
  assert.equal("allowPlainHttp" in models.find((m) => m.name === "corp")!, false);
});
