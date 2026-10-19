/**
 * perimeter-netns.test.ts — confidentiality plan 12 D4 across a real network
 * boundary, on this host with no root (tests/lib/netns.ts): the declared model
 * runs on "another machine" (a peer network namespace answering on
 * 10.77.0.2, inside `perimeter.networks`, and on 203.0.113.9, outside it),
 * and the names the policy declares get their DNS answers from a hosts file.
 *
 * The scenario (tests/fixtures/perimeter-scenario.fixture.ts) meets three
 * declared names with the production wiring of the launch check, the helper
 * (`new ArbiterClientAdapter(new ArbiterClient(sock))`) and the model proxy:
 *   - corp → 10.77.0.2: the launch passes, the helper's local-model call is
 *     served ON 10.77.0.2 and answers `$MDU:localmodel_`, the proxy is served;
 *   - drift → 203.0.113.9: the launch refuses naming the address, the helper
 *     and the proxy are refused with ZERO requests to the peer;
 *   - mixed → both: refused the same way (every address counts, not the first).
 * The peer's own log is the oracle: no request ever arrives on 203.0.113.9,
 * and the canary of a refused leg never appears in it.
 *
 * Self-SKIP where unprivileged user and network namespaces are refused, or
 * without openssl.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { mintTlsFixtures } from "../../interceptors/inspect-mcp/test/helpers/tls-fixtures.js";
import { runTwoHostNet, twoHostNetUnavailable, TWO_HOST } from "../lib/netns.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the built-in default: confidentiality ON (local-model is its level)

const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const TSX = join(PKG_ROOT, "node_modules", ".bin", "tsx");
const unavailable = twoHostNetUnavailable();
const fx = unavailable ? null : mintTlsFixtures({
  serverSans: ["DNS:corp.corp.example", "DNS:drift.corp.example", "DNS:mixed.corp.example", `IP:${TWO_HOST.inside}`, `IP:${TWO_HOST.outside}`],
});
const skip = unavailable ?? (fx === null ? "openssl is not on PATH" : false);
process.on("exit", () => fx?.cleanup());

interface Leg {
  launch: string;
  helper: { ok: boolean; error?: string; resultSymbol?: string };
  helperRequests: number;
  proxyStatus: number;
  proxyRequests: number;
  endpoint: { perimeter?: string[]; orgDomain?: boolean } | null;
}

test("perimeter across a network boundary: inside is served on the inside address; an answer outside, or one address outside, is refused by the launch, the helper and the model proxy with zero requests", { skip, timeout: 180_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-perimeter-netns-"));
  try {
    const log = join(dir, "model.log");
    const ready = join(dir, "ready");
    const env = {
      ...process.env,
      MODEL_CERT: fx!.serverCert, MODEL_KEY: fx!.serverKey, MODEL_PORT: "8443", MODEL_LOG: log, MODEL_READY: ready,
      FX_CA: fx!.caCert, PERIMETER: TWO_HOST.network,
    };
    const r = await runTwoHostNet({
      hosts: {
        "corp.corp.example": [TWO_HOST.inside],
        "drift.corp.example": [TWO_HOST.outside],
        "mixed.corp.example": [TWO_HOST.inside, TWO_HOST.outside],
      },
      peer: [TSX, join(PKG_ROOT, "fixtures", "netns-model-server.fixture.ts")],
      peerReady: ready,
      main: [TSX, join(PKG_ROOT, "fixtures", "perimeter-scenario.fixture.ts")],
      env,
    });
    assert.equal(r.status, 0, `scenario failed:\n${r.stderr}\n${r.stdout}`);
    const out = JSON.parse(r.stdout.trim().split("\n").pop()!) as Record<"corp" | "drift" | "mixed", Leg>;

    // What the arbiter handed out: the perimeter on each (a local entry on
    // another machine), and the domain match.
    for (const leg of Object.values(out)) {
      assert.deepEqual(leg.endpoint?.perimeter, [TWO_HOST.network]);
      assert.equal(leg.endpoint?.orgDomain, true);
    }

    // corp: inside, served.
    assert.equal(out.corp.launch, "ok");
    assert.equal(out.corp.helper.ok, true, out.corp.helper.error);
    assert.match(out.corp.helper.resultSymbol ?? "", /^\$MDU:localmodel_/, "the answer goes back to the conversation as a local-model symbol");
    assert.ok(out.corp.helperRequests >= 1);
    assert.equal(out.corp.proxyStatus, 200);
    assert.equal(out.corp.proxyRequests, 1);

    // drift and mixed: refused everywhere, nothing sent.
    for (const [name, addr] of [["drift", TWO_HOST.outside], ["mixed", TWO_HOST.outside]] as const) {
      const leg = out[name];
      assert.match(leg.launch, new RegExp(`refusing to launch: .*outside perimeter\\.networks[\\s\\S]*models: ${name} \\(https://${name}\\.corp\\.example:8443/v1\\) resolves to ${addr.replace(/\./g, "\\.")}`), name);
      assert.equal(leg.helper.ok, false, name);
      assert.match(leg.helper.error ?? "", new RegExp(`${name}\\.corp\\.example resolves to ${addr.replace(/\./g, "\\.")}, outside perimeter\\.networks`), name);
      assert.ok(!(leg.helper.error ?? "").includes("NETNS_CANARY"), "no document byte in the error");
      assert.equal(leg.helperRequests, 0, `${name}: zero requests from the helper`);
      assert.equal(leg.proxyStatus, 502, name);
      assert.equal(leg.proxyRequests, 0, `${name}: zero requests from the proxy`);
    }

    // The peer's own log: every request arrived on the inside address, and
    // only corp's canary is in it.
    assert.ok(existsSync(log));
    const seen = readFileSync(log, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { local: string; host: string; body: string });
    assert.ok(seen.length >= 2);
    assert.deepEqual([...new Set(seen.map((s) => s.local.replace(/^::ffff:/, "")))], [TWO_HOST.inside], "nothing ever reached 203.0.113.9");
    assert.ok(seen.some((s) => s.body.includes("NETNS_CANARY_CORP")));
    assert.ok(seen.every((s) => !s.body.includes("NETNS_CANARY_DRIFT") && !s.body.includes("NETNS_CANARY_MIXED")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
