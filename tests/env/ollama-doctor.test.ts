/**
 * ollama-doctor.test.ts — `mandu doctor`'s `models:` rows against a REAL
 * Ollama (docs/design/confidentiality/model-endpoints.md §1 D6,
 * §8 item 3).
 *
 * The offline suites pin the rows over a stubbed listing; this reads the
 * server's own `GET /v1/models` through doctor's real deps (the TCP probe and
 * the listing fetch), with the law served by a real in-process ArbiterServer:
 *   - a declared `local: true` entry whose model is loaded reads ✓ "is listed";
 *   - one whose model is not loaded reads ✗ with the pull hint;
 *   - the cloud-backed models doctor reports for a local server are exactly
 *     the listing's cloud-named ids (none on a host with no cloud tag, which
 *     is this check's usual answer: it never pulls a model to make one).
 * Read-only toward the server: two GETs, no model pulled, nothing generated.
 *
 * Run (in tests/):
 *   MANDU_LIVE_OLLAMA=1 npx tsx --test tests/env/ollama-doctor.test.ts
 * Optional: MANDU_LIVE_OLLAMA_URL (default http://127.0.0.1:11434),
 * MANDU_LIVE_OLLAMA_MODEL (default llama3.2, must be pulled already).
 * Self-SKIPs without the env var or when the server does not answer.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { gatherModels, modelRows, realDoctorDeps } from "../../launcher/src/doctor.js";
import { isCloudBackedModel } from "../../launcher/src/model-endpoints.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // local-model is a confidentiality level (the default mode's axis)

const URL_ = (process.env["MANDU_LIVE_OLLAMA_URL"] ?? "http://127.0.0.1:11434").replace(/\/+$/, "");
const MODEL = process.env["MANDU_LIVE_OLLAMA_MODEL"] ?? "llama3.2";
const MISSING = "mandu-never-pulled-model";

async function listing(): Promise<string[] | null> {
  try {
    const r = await fetch(`${URL_}/v1/models`, { signal: AbortSignal.timeout(3000) });
    if (!r.ok) return null;
    const body = (await r.json()) as { data?: Array<{ id?: unknown }> };
    return (body.data ?? []).map((d) => d.id).filter((id): id is string => typeof id === "string");
  } catch {
    return null;
  }
}

test("doctor over a real Ollama: a loaded model is listed, a missing one is not, cloud models are reported as the server lists them", async (t) => {
  if (process.env["MANDU_LIVE_OLLAMA"] !== "1") { t.skip("set MANDU_LIVE_OLLAMA=1 to run against the Ollama on this host"); return; }
  const ids = await listing();
  if (ids === null) { t.skip(`no OpenAI-compatible listing at ${URL_}/v1/models`); return; }
  if (!ids.some((id) => id === MODEL || id.startsWith(`${MODEL}:`))) { t.skip(`${MODEL} is not pulled on this server (this check never pulls one)`); return; }

  const dir = mkdtempSync(join(tmpdir(), "mandu-ollama-doctor-"));
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
    policyDocument: {
      version: 1,
      models: [
        { name: "ollama", url: URL_, wire: "openai-chat", model: MODEL, local: true },
        { name: "missing", url: URL_, wire: "openai-chat", model: MISSING, local: true },
      ],
    },
  });
  await server.listen();
  try {
    const facts = await gatherModels(
      { MANDU_POLICY_FILE: join(dir, "no-policy.yaml") },
      { readKnob: () => null, modelEndpoints: realDoctorDeps.modelEndpoints, probeTcp: realDoctorDeps.probeTcp, listModels: realDoctorDeps.listModels },
      sock,
      true,
    );
    assert.equal(facts.source, "arbiter", "doctor read the law from the running arbiter");
    const byName = new Map(facts.endpoints.map((e) => [e.name, e]));
    const own = byName.get("ollama")!;
    assert.equal(own.reachable, true);
    assert.equal(own.modelListed, true, `${MODEL} is loaded: ${ids.join(", ")}`);
    assert.equal(byName.get("missing")!.modelListed, false);

    const cloud = ids.filter(isCloudBackedModel);
    assert.deepEqual(own.cloudListed ?? [], cloud, "the cloud-backed ids doctor reports are the listing's");

    const rows = modelRows(facts);
    assert.ok(rows.some((r) => r.includes(`ollama: ${URL_}`) && r.includes(`${MODEL} is listed`)), rows.join("\n"));
    assert.ok(rows.some((r) => r.includes(`missing: ${URL_}`) && r.includes(`ollama pull ${MISSING}`)), rows.join("\n"));
    const cloudRow = rows.some((r) => /also serves models that run on the vendor's servers/.test(r));
    assert.equal(cloudRow, cloud.length > 0, "the cloud row appears exactly when the server lists a cloud model");
    t.diagnostic(`listing: ${ids.join(", ")}; cloud-backed: ${cloud.length === 0 ? "none" : cloud.join(", ")}`);
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
