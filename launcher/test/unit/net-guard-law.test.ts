/**
 * net-guard-law.test — the launcher's read of the law's connect allowances
 * (policy-surface.md §2.3, stage 4b): the `netConnectAllow` op over
 * a fake arbiter socket; fail-SOFT toward tighter (unreachable / unknown op /
 * malformed / slow ⇒ []), strict spec filtering, dedupe.
 *
 * Plus the endpoint case (confidentiality-plan-11 D5, §4 launcher row): the
 * guard set a launch builds from the two reads run.ts makes of the same
 * arbiter, the law's allowances and policy.yaml `models:`. A `local: true`
 * endpoint's port joins pinned to its host; a declared external endpoint adds
 * nothing, so `models:` never becomes a second way to open egress.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { isGuardSpec, readConnectAllowances } from "../../src/net-guard-law.js";
import { readModelEndpoints } from "../../src/model-endpoints.js";
import { applyNetGuard } from "../../src/net-guard-setup.js";
import { emptyMutation } from "../../src/backend/types.js";
import type { LaunchPlan } from "../../src/types.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the endpoint case runs under a mode with local-model in play; the law read itself reads no axis

function fakeArbiter(answer: (op: string) => { ok: boolean; result?: unknown; error?: string } | null): Promise<{ sock: string; close: () => Promise<void> }> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-net-guard-law-"));
  const sock = join(dir, "arbiter.sock");
  const server: Server = createServer((c) => {
    let buf = "";
    c.setEncoding("utf8");
    c.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      const req = JSON.parse(buf.slice(0, nl)) as { id: unknown; op: string };
      buf = buf.slice(nl + 1);
      const a = answer(req.op);
      if (a === null) return; // never answers → the deadline decides
      c.write(JSON.stringify({ id: req.id, ...a }) + "\n");
    });
  });
  return new Promise((resolve) => {
    server.listen(sock, () => resolve({
      sock,
      close: () => new Promise<void>((r) => server.close(() => { rmSync(dir, { recursive: true, force: true }); r(); })),
    }));
  });
}

test("isGuardSpec: proto:host:port only — tcp/udp, port 1–65535 or *, no whitespace/quotes", () => {
  for (const ok of ["tcp:registry.npmjs.org:443", "udp:*:53", "tcp:10.0.0.0/8:*", "tcp:[::1]:8788", "tcp:*.internal.example:8443"]) assert.ok(isGuardSpec(ok), ok);
  for (const bad of ["registry.npmjs.org:443", "sctp:a:1", "tcp:a:0", "tcp:a:70000", "tcp:a b:443", "tcp:a\":443", "", 42, null]) assert.ok(!isGuardSpec(bad), String(bad));
});

test("readConnectAllowances: the op's specs come back filtered + deduped", async () => {
  const a = await fakeArbiter((op) => op === "netConnectAllow"
    ? { ok: true, result: { specs: ["tcp:registry.npmjs.org:443", "tcp:registry.npmjs.org:443", "bogus", 7, "udp:10.0.0.0/8:*"] } }
    : { ok: false, error: "unexpected op" });
  try {
    assert.deepEqual(await readConnectAllowances(a.sock), ["tcp:registry.npmjs.org:443", "udp:10.0.0.0/8:*"]);
  } finally {
    await a.close();
  }
});

test("readConnectAllowances: fail-SOFT toward tighter — unknown op / malformed / silent / unreachable ⇒ []", async () => {
  const unknown = await fakeArbiter(() => ({ ok: false, error: "unknown op netConnectAllow" }));
  try { assert.deepEqual(await readConnectAllowances(unknown.sock), []); } finally { await unknown.close(); }
  const malformed = await fakeArbiter(() => ({ ok: true, result: { specs: "tcp:a:443" } }));
  try { assert.deepEqual(await readConnectAllowances(malformed.sock), []); } finally { await malformed.close(); }
  const silent = await fakeArbiter(() => null);
  try { assert.deepEqual(await readConnectAllowances(silent.sock, 150), []); } finally { await silent.close(); }
  assert.deepEqual(await readConnectAllowances("/nonexistent/mandu.sock", 500), []);
});

test("the guard law with policy.yaml models: the helper's entry is pinned to its host; another local entry and a declared external endpoint add nothing", async () => {
  const a = await fakeArbiter((op) => {
    if (op === "netConnectAllow") return { ok: true, result: { specs: ["tcp:registry.npmjs.org:443"] } };
    if (op === "modelEndpoints") {
      return {
        ok: true,
        result: {
          endpoints: [
            { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true },
            // The helper mark rides the arbiter read (readModelEndpoints keeps it).
            { name: "gpu", url: "http://192.168.7.20:8000/v1", wire: "openai-chat", local: true, helper: true },
            { name: "gateway", url: "https://llm.corp.example:4000", wire: "anthropic", local: false },
          ],
        },
      };
    }
    return { ok: false, error: `unknown op ${op}` };
  });
  try {
    // The two reads run.ts makes before any wrap is decided.
    const lawAllow = await readConnectAllowances(a.sock);
    const models = await readModelEndpoints(a.sock);
    assert.equal(models.status, "ok");
    assert.ok(!lawAllow.some((s) => /11434|8000|llm\.corp\.example/.test(s)), "models: is not in the law's connect allowances");

    const p: LaunchPlan = {
      target: "claude", argv: ["claude"], scopeId: "sid", tenant: "live", arbiterSock: a.sock, arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu", eventDir: "/e",
      cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin",
      proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
      openaiProviderName: "mandu", noProxyExtra: [],
      requested: { netProxy: false, netProxyMitm: false, execWrap: false },
      execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
      noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, netGuard: true,
      // Strict: no :443 / :22 fallback, so every admitted destination is named.
      landlockNetStrict: true, netGuardGitRemotes: false,
      modelEndpoints: models.endpoints,
    };
    const r = applyNetGuard(p, emptyMutation(), { resolveBin: () => "/bin/g", staleNote: () => null, log: () => {}, lawAllow });
    assert.ok(r);
    assert.ok(r.specs.includes("tcp:192.168.7.20:8000"), `the helper's entry in ${JSON.stringify(r.specs)}`);
    assert.ok(!r.specs.some((s) => s.endsWith(":11434")), `the local entry that is not the helper opens nothing: ${JSON.stringify(r.specs)}`);
    assert.ok(!r.specs.some((s) => /^tcp:\*:(11434|8000)$/.test(s)), "an endpoint port is never opened to every host");
    assert.ok(!r.specs.some((s) => s.includes("llm.corp.example") || s.endsWith(":4000")), "the declared external endpoint adds nothing");
    assert.ok(r.specs.includes("tcp:registry.npmjs.org:443"), "the law's own allowance is still there");
  } finally {
    await a.close();
  }
});
