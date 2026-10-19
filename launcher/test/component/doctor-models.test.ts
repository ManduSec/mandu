/**
 * doctor-models e2e — `mandu doctor` through the real CLI entry (a child
 * process with the REAL probes) reports policy.yaml `models:`
 * (confidentiality-plan-11 D6): the endpoints come from a stand-in arbiter's
 * `modelEndpoints` op, the reachability probe dials a loopback model server
 * this test runs (and a closed port), the `/v1/models` listing is read from
 * it with the endpoint's own bearer token; with no arbiter and a policy file
 * that labels a path `local-model` but declares no model, the D6 sentence
 * prints.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createNetServer, type Server } from "node:net";
import { createServer as createHttpServer } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { runCli } from "../lib/run-cli.js";
import { reservePort } from "../lib/reserve-port.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // local-model matters under the confidentiality axis; doctor itself reads no axis

async function modelsArbiter(sock: string, endpoints: unknown[], labels: unknown[] = []): Promise<Server> {
  const srv = createNetServer((s) => {
    let buf = "";
    s.setEncoding("utf8");
    s.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const req = JSON.parse(buf.slice(0, nl)) as { id: unknown; op: string };
        buf = buf.slice(nl + 1);
        s.write(JSON.stringify(req.op === "modelEndpoints"
          ? { id: req.id, ok: true, result: { endpoints } }
          : req.op === "pathLabels"
            ? { id: req.id, ok: true, result: { labels } }
            : { id: req.id, ok: false, error: `unknown op: ${req.op}` }) + "\n");
      }
    });
  });
  srv.listen(sock);
  await once(srv, "listening");
  return srv;
}

test("mandu doctor: one row per declared model (reachable + listed, reachable + not listed, unreachable) and the non-private hint", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-doctor-models-"));
  const home = join(dir, "home");
  mkdirSync(home);
  const auth: string[] = [];
  const modelServer = createHttpServer((req, res) => {
    auth.push(String(req.headers["authorization"] ?? ""));
    if (req.url === "/v1/models") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ object: "list", data: [{ id: "llama3.2:latest", object: "model" }] }));
    } else { res.writeHead(404); res.end(); }
  });
  modelServer.listen(0, "127.0.0.1");
  await once(modelServer, "listening");
  const port = (modelServer.address() as AddressInfo).port;
  // A port nothing listens on, reserved so no suite running alongside can be
  // handed it (test-organization.md §8.4).
  const deadPort = await reservePort();

  const sock = join(dir, "arbiter.sock");
  const arb = await modelsArbiter(sock, [
    { name: "ollama", url: `http://127.0.0.1:${port}`, wire: "openai-chat", model: "llama3.2", local: true, tokenEnv: "DOCTOR_E2E_TOKEN" },
    { name: "other", url: `http://localhost:${port}`, wire: "openai-chat", model: "qwen2.5:7b", local: true },
    { name: "gone", url: `http://127.0.0.1:${deadPort}`, wire: "anthropic", local: true },
  ]);
  try {
    const r = await runCli(["doctor"], {
      HOME: home, MANDU_HOME: join(dir, "mandu-home"), XDG_RUNTIME_DIR: dir, MANDU_ARBITER_SOCK: sock,
      MANDU_POLICY_FILE: join(dir, "absent-policy.yaml"), DOCTOR_E2E_TOKEN: "tok-DOCTOR-E2E",
    });
    assert.equal(r.code, 0, r.stderr);
    const out = r.stdout;
    assert.match(out, /Your own models \(policy\.yaml models:\)/);
    assert.match(out, new RegExp(`✓ ollama: http://127\\.0\\.0\\.1:${port} \\(openai-chat, model llama3\\.2, your own model, on this computer, the helper uses it\\): reachable, llama3\\.2 is listed`));
    assert.match(out, new RegExp(`✗ other: http://localhost:${port} .*reachable, but qwen2\\.5:7b is not listed at http://localhost:${port}/v1/models`));
    assert.match(out, new RegExp(`✗ gone: http://127\\.0\\.0\\.1:${deadPort} \\(anthropic, your own model, on this computer\\): not reachable`));
    assert.doesNotMatch(out, /hint:/, "loopback endpoints get no hint");
    assert.ok(auth.includes("Bearer tok-DOCTOR-E2E"), `the endpoint's own token rode the listing: ${JSON.stringify(auth)}`);
    assert.ok(auth.includes(""), "an endpoint without token_env sends none");
    assert.doesNotMatch(out, /tok-DOCTOR-E2E/, "the token is never printed");
  } finally {
    arb.close();
    modelServer.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("mandu doctor with no arbiter: a policy file labeling local-model with no models: section prints the D6 sentence with the line", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-doctor-models-"));
  const home = join(dir, "home");
  mkdirSync(home);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "paths:\n  - path: ~/notes/contract.md\n    level: local-model\n");
  try {
    const r = await runCli(["doctor"], {
      HOME: home, MANDU_HOME: join(dir, "mandu-home"), XDG_RUNTIME_DIR: dir, MANDU_ARBITER_SOCK: join(dir, "absent.sock"), MANDU_POLICY_FILE: policy,
    });
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /✗ files labeled local-model are read by no model until you declare your own model in policy\.yaml/);
    assert.match(r.stdout, new RegExp(`\\(${policy.replace(/[.]/g, "\\.")}, line 3; add a models: entry with local: true\\)`));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("mandu doctor: a set ANTHROPIC_BASE_URL is checked against models: (plan 11 phase 3): declared ✓, undeclared ✗ with the fix", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-doctor-models-"));
  const home = join(dir, "home");
  mkdirSync(home);
  const sock = join(dir, "arbiter.sock");
  const arb = await modelsArbiter(sock, [
    { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true },
    { name: "gpu", url: "http://localhost:18080/", wire: "anthropic", local: true },
  ]);
  const base = { HOME: home, MANDU_HOME: join(dir, "mandu-home"), XDG_RUNTIME_DIR: dir, MANDU_ARBITER_SOCK: sock, MANDU_POLICY_FILE: join(dir, "absent-policy.yaml") };
  try {
    const hit = await runCli(["doctor"], { ...base, ANTHROPIC_BASE_URL: "http://localhost:18080" });
    assert.equal(hit.code, 0, hit.stderr);
    assert.match(hit.stdout, /✓ ANTHROPIC_BASE_URL is models: gpu \(your own model\); the model proxy stays in front of it/);

    // The openai-chat entry's exact url is still not a main model.
    const miss = await runCli(["doctor"], { ...base, ANTHROPIC_BASE_URL: "http://127.0.0.1:11434" });
    assert.equal(miss.code, 0, miss.stderr);
    assert.match(miss.stdout, /✗ ANTHROPIC_BASE_URL \(http:\/\/127\.0\.0\.1:11434\) is not declared under models:, so a launch skips the model proxy for it .*declare it under models: with wire: anthropic/);

    const unset = await runCli(["doctor"], base);
    assert.doesNotMatch(unset.stdout, /ANTHROPIC_BASE_URL/, "no row without the variable");
  } finally {
    arb.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("mandu doctor: a local-model label made on the Rules page (not a policy file line) and only an outside model declared prints the D6 sentence naming the label", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-doctor-models-"));
  const home = join(dir, "home");
  mkdirSync(home);
  const sock = join(dir, "arbiter.sock");
  const arb = await modelsArbiter(sock, [
    { name: "gw", url: "https://gw.example", wire: "anthropic", local: false },
  ], [
    { path: "/h/notes/contract.md", level: "local-model", source: "user" },
    { path: "/h/notes/in-file.md", level: "local-model", source: "policy-file" },
    { path: "/h/notes/memo.md", level: "any-model", source: "user" },
  ]);
  try {
    const r = await runCli(["doctor"], {
      HOME: home, MANDU_HOME: join(dir, "mandu-home"), XDG_RUNTIME_DIR: dir, MANDU_ARBITER_SOCK: sock, MANDU_POLICY_FILE: join(dir, "absent-policy.yaml"),
    });
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /✗ files labeled local-model are read by no model until you declare your own model in policy\.yaml \(labeled on the Rules page: \/h\/notes\/contract\.md; add a models: entry with local: true\)/);
    assert.doesNotMatch(r.stdout, /in-file\.md|memo\.md/, "policy file lines come from the line scan; other levels are not listed");
  } finally {
    arb.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
