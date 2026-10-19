/**
 * subscription-real.test.ts — LIVE end-to-end against the REAL Anthropic API
 * on the subscription, asserting the REAL model produced meaningful output.
 *
 * Mandu (tests/). The sibling `subscription.test.ts` proves the
 * credential RELAY + §9 invariant against a FAKE upstream — so its "LLM output" is
 * scripted, not generated. This test closes that gap: it points the proxy at the
 * REAL `https://api.anthropic.com`, so a subscription-authenticated `claude -p`
 * gets a genuine model response, and we FAIL unless that real response carries the
 * exact token we asked the model to echo.
 *
 *     claude -p  (real SUBSCRIPTION, no api key)
 *        │   ANTHROPIC_BASE_URL → real ArbiterServer + real AnthropicProxy
 *        ▼   ── upstream ──► REAL api.anthropic.com  (real model, real tokens)
 *
 * "No meaningful LLM output → the test fails": the assertion is on the model's
 * actual stdout, not just the process exit code.
 *
 * It runs in `secrets`, the product's default (test-organization.md §7.3): its
 * checks (the real model's echo, the relayed subscription credential) are the
 * relay's mechanics and hold in any mode; it pinned integrity ON only
 * incidentally. The confidentiality form of the invariant over the
 * subscription is subscription.test.ts check (3).
 *
 * GATED + COSTS REAL BUDGET: runs only when `claude` is on PATH AND
 * `MANDU_E2E_SUBSCRIPTION_LIVE=1` is set. It makes a real (cheap, single-turn,
 * Haiku) model call on your subscription. Run with:
 *     MANDU_E2E_SUBSCRIPTION_LIVE=1 npx tsx --test env/subscription-real.test.ts   # in tests/
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Readable } from "node:stream";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import type { UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as AnthropicProxyArbiterAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";

import { runChildToExit } from "../lib/child-run.js";
import { installExitGuard } from "../lib/exit-guard.js";
import { stateAxes } from "../lib/axes.js";

// Exit-guard backstop (tests/lib/exit-guard.ts): if a leaked handle still
// holds this runner's event loop after the tests complete, dump it to stderr
// and force-exit instead of hanging the suite forever.
installExitGuard("subscription-real");

// This suite STATES its axes (protection-modes.md §4): `secrets`, the
// built-in default. The arbiter below also takes the pair explicitly.
stateAxes("secrets");

/** Forward upstream to the REAL Anthropic (http or https), recording the auth header. */
function realCapturingForwarder(
  origin: string,
  sink: Array<{ authorization?: string; apiKey?: string }>,
): UpstreamFetcher {
  const url = new URL(origin);
  const isHttps = url.protocol === "https:";
  return async ({ method, path, headers, body }) => {
    const one = (v: string | string[] | undefined): string | undefined =>
      Array.isArray(v) ? v[0] : v;
    sink.push({ authorization: one(headers.authorization), apiKey: one(headers["x-api-key"]) });
    const mod = isHttps ? await import("node:https") : await import("node:http");
    return new Promise((resolve, reject) => {
      const r = mod.request(
        {
          protocol: url.protocol,
          hostname: url.hostname,
          port: url.port ? Number(url.port) : isHttps ? 443 : 80,
          method,
          path,
          headers: { ...headers, host: url.host },
        },
        (up) => resolve({ status: up.statusCode ?? 502, headers: up.headers, body: up as unknown as Readable }),
      );
      r.on("error", reject);
      r.end(body);
    });
  };
}

const CLAUDE_AVAILABLE = (() => {
  try {
    return spawnSync("claude", ["--version"], { encoding: "utf8", timeout: 15000 }).status === 0;
  } catch {
    return false;
  }
})();

const SKIP_REASON: string | false = !CLAUDE_AVAILABLE
  ? "`claude` binary not on PATH — run where Claude Code is installed"
  : process.env["MANDU_E2E_SUBSCRIPTION_LIVE"] !== "1"
    ? "set MANDU_E2E_SUBSCRIPTION_LIVE=1 to run — hits the REAL Anthropic API and spends a little subscription budget"
    : false;

const REAL_UPSTREAM = "https://api.anthropic.com";
// A distinctive token only the model could emit in response to our echo prompt.
const ECHO_TOKEN = "MDUPONG_NINE_DELTA_42";

function credShape(c: { authorization?: string; apiKey?: string }): string {
  if (c.authorization) return c.authorization.startsWith("Bearer ") ? "Bearer …" : "auth:other";
  if (c.apiKey) return c.apiKey.startsWith("sk-ant-oat") ? "x-api-key:oat…" : `x-api-key:${c.apiKey.slice(0, 10)}…`;
  return "none";
}

test(
  "LIVE(real upstream): subscription → proxy → REAL model returns meaningful output (echoes our token)",
  { skip: SKIP_REASON, timeout: 120_000 },
  async () => {
    const tmp = mkdtempSync(join(tmpdir(), "mandu-sub-real-"));
    const socketPath = join(tmp, "arbiter.sock");

    const arbiter = new ArbiterServer({
      socketPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
      integrity: false, confidentiality: true, // `secrets`, stated explicitly
    });
    await arbiter.listen();
    const proxyClient = new ArbiterClient(socketPath);
    await proxyClient.connect();

    const forwardedCreds: Array<{ authorization?: string; apiKey?: string }> = [];
    const proxy = new AnthropicProxy({
      // The PRODUCTION wiring (CONTRIBUTING.md arbiter-client pattern): the adapter
      // over the real IPC client, no test bridge.
      arbiter: new AnthropicProxyArbiterAdapter(proxyClient),
      upstream: realCapturingForwarder(REAL_UPSTREAM, forwardedCreds),
      log: () => {},
    });
    const proxyPort = await proxy.listen(0);

    try {
      // runChildToExit SIGKILLs the whole process group and rejects on timeout.
      const { code, stdout, stderr } = await runChildToExit(
        "claude",
        [
          "-p",
          `Reply with exactly this token and nothing else, no preamble: ${ECHO_TOKEN}`,
          "--model", "claude-haiku-4-5",
          "--output-format", "text",
          "--permission-mode", "bypassPermissions",
          "--setting-sources", "project,local", // exclude user apiKeyHelper → force subscription
        ],
        {
          cwd: tmp,
          env: {
            HOME: process.env["HOME"] ?? tmp,
            PATH: process.env["PATH"] ?? "",
            ANTHROPIC_BASE_URL: `http://127.0.0.1:${proxyPort}`,
            // NO ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN — force the subscription.
          },
          timeoutMs: 110_000,
          label: "claude",
        },
      );

      // (1) The turn completed against the REAL API on the subscription.
      assert.equal(code, 0, `claude exited ${code} (stderr=${JSON.stringify(stderr.slice(0, 600))})`);

      // (2) THE MEANINGFUL-OUTPUT CHECK: the REAL model actually produced a
      //     response, and it is the token we asked it to echo. An empty/garbled
      //     output (auth silently degraded, model returned nothing) FAILS here.
      assert.ok(
        stdout.includes(ECHO_TOKEN),
        `expected the real model to echo ${ECHO_TOKEN}; got stdout=${JSON.stringify(stdout.slice(0, 300))}`,
      );

      // (3) And it got there on a SUBSCRIPTION credential (relayed by the proxy).
      assert.ok(forwardedCreds.length > 0, "the proxy forwarded ≥1 request upstream");
      assert.ok(
        forwardedCreds.some((c) => c.authorization?.startsWith("Bearer ") || c.apiKey?.startsWith("sk-ant-oat")),
        `expected a subscription OAuth credential relayed upstream; saw shapes=${JSON.stringify(forwardedCreds.map(credShape))}`,
      );
    } finally {
      await proxy.close();
      proxyClient.close();
      await arbiter.close();
      rmSync(tmp, { recursive: true, force: true });
    }
  },
);
