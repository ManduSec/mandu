/**
 * network-model.test.ts — confidentiality plan 12 §6 "live (gated)",
 * run on one host: the declared local model is a REAL model server (the
 * Ollama on this host) reached as if it were on the organization's network.
 *
 * Two network namespaces (tests/lib/netns.ts) stand in for two machines. The
 * peer runs an https relay with the test CA's certificate on 10.77.0.2
 * (inside `perimeter.networks`) and 203.0.113.9 (outside), and reaches this
 * host's Ollama through slirp4netns (10.0.2.2 → 127.0.0.1:11434). This side
 * runs the production wiring of the launch check and the helper
 * (tests/fixtures/perimeter-scenario.fixture.ts) against a real ArbiterServer
 * whose policy declares the relay `local: true` with `tls.ca_file` and a
 * `perimeter`. It asserts:
 *   - corp (→ 10.77.0.2): the launch passes; the helper's local-model call
 *     crosses the namespace boundary over TLS, the real model answers, the
 *     answer comes back as `$MDU:localmodel_…` and resolves (for that model)
 *     to real text; the document reached the relay on 10.77.0.2 only;
 *   - drift (→ 203.0.113.9): refused at launch and by the helper, zero
 *     requests to the relay.
 * What this does not cover: the T-LLM side of the full drill
 * (local-model.test.ts, which runs the real launcher and `claude -p`).
 *
 * GATED: MANDU_LIVE_NETWORK_MODEL=1 npm run test:env:network-model
 *   MANDU_LIVE_OLLAMA_URL   the host's Ollama (default http://127.0.0.1:11434)
 *   MANDU_LIVE_OLLAMA_MODEL the model (default llama3.2)
 * Self-SKIP without user/network namespaces, slirp4netns, openssl, or a
 * reachable Ollama. No vendor budget is spent.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { mintTlsFixtures } from "../../interceptors/inspect-mcp/test/helpers/tls-fixtures.js";
import { HOST_FROM_PEER, runTwoHostNet, slirpUnavailable, twoHostNetUnavailable, TWO_HOST } from "../lib/netns.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // local-model is a confidentiality level

const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), ".."); // tests/, the package root
const TSX = join(PKG_ROOT, "node_modules", ".bin", "tsx");
const OLLAMA = new URL(process.env["MANDU_LIVE_OLLAMA_URL"] ?? "http://127.0.0.1:11434");
const MODEL = process.env["MANDU_LIVE_OLLAMA_MODEL"] ?? "llama3.2";

async function ollamaUnavailable(): Promise<string | null> {
  try {
    const r = await fetch(new URL("/api/tags", OLLAMA), { signal: AbortSignal.timeout(3000) });
    const tags = (await r.json()) as { models?: Array<{ name: string }> };
    return (tags.models ?? []).some((m) => m.name === MODEL || m.name === `${MODEL}:latest`) ? null : `the model ${MODEL} is not pulled on ${OLLAMA.origin}`;
  } catch {
    return `no Ollama answers at ${OLLAMA.origin}`;
  }
}

const gate = process.env["MANDU_LIVE_NETWORK_MODEL"] === "1" ? null : "set MANDU_LIVE_NETWORK_MODEL=1 to run the live network-model leg";
const skip = gate ?? twoHostNetUnavailable() ?? slirpUnavailable() ?? (await ollamaUnavailable());

test("a real model on 'another machine': served inside the perimeter over TLS with a real answer; outside refused with zero requests", { skip: skip ?? false, timeout: 600_000 }, async () => {
  const fx = mintTlsFixtures({ serverSans: ["DNS:corp.corp.example", "DNS:drift.corp.example", `IP:${TWO_HOST.inside}`, `IP:${TWO_HOST.outside}`] });
  if (fx === null) return; // openssl missing: nothing to mint the relay's certificate with
  const dir = mkdtempSync(join(tmpdir(), "mandu-network-model-live-"));
  try {
    const log = join(dir, "model.log");
    const ready = join(dir, "ready");
    const r = await runTwoHostNet({
      hosts: { "corp.corp.example": [TWO_HOST.inside], "drift.corp.example": [TWO_HOST.outside] },
      peer: [TSX, join(PKG_ROOT, "fixtures", "netns-model-server.fixture.ts")],
      peerReady: ready,
      peerHostLoopback: true,
      main: [TSX, join(PKG_ROOT, "fixtures", "perimeter-scenario.fixture.ts")],
      env: {
        ...process.env,
        MODEL_CERT: fx.serverCert, MODEL_KEY: fx.serverKey, MODEL_PORT: "8443", MODEL_LOG: log, MODEL_READY: ready,
        MODEL_UPSTREAM: `http://${HOST_FROM_PEER}:${OLLAMA.port || "80"}`,
        FX_CA: fx.caCert, PERIMETER: TWO_HOST.network,
        LEGS: "corp,drift", MODEL_NAME: MODEL, NO_PROXY_LEG: "1", ANSWER: "1", MANDU_ULLM_ENDPOINT_TIMEOUT_MS: "300000",
      },
      timeoutMs: 580_000,
    });
    assert.equal(r.status, 0, `scenario failed:\n${r.stderr}\n${r.stdout}`);
    const out = JSON.parse(r.stdout.trim().split("\n").pop()!) as Record<string, { launch: string; helper: { ok: boolean; error?: string; resultSymbol?: string }; helperRequests: number; answer?: string | null }>;
    const corp = out["corp"]!;
    assert.equal(corp.launch, "ok");
    assert.equal(corp.helper.ok, true, corp.helper.error);
    assert.match(corp.helper.resultSymbol ?? "", /^\$MDU:localmodel_/);
    assert.ok(typeof corp.answer === "string" && corp.answer.trim().length > 0, "the real model wrote an answer");
    assert.ok(!/A summary from the model on the other machine/.test(corp.answer!), "not the stand-in's canned text");
    console.log(`[network-model live] ${MODEL} answered: ${corp.answer!.slice(0, 160).replace(/\s+/g, " ")}`);
    const drift = out["drift"]!;
    assert.match(drift.launch, /outside perimeter\.networks/);
    assert.equal(drift.helper.ok, false);
    assert.equal(drift.helperRequests, 0);
    assert.ok(existsSync(log));
    const seen = readFileSync(log, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { local: string; body: string });
    assert.ok(seen.some((s) => s.body.includes("NETNS_CANARY_CORP")), "the document crossed to the model");
    assert.deepEqual([...new Set(seen.map((s) => s.local.replace(/^::ffff:/, "")))], [TWO_HOST.inside]);
    assert.ok(seen.every((s) => !s.body.includes("NETNS_CANARY_DRIFT")));
  } finally {
    fx.cleanup();
    rmSync(dir, { recursive: true, force: true });
  }
});
