/**
 * subscription.test.ts — LIVE end-to-end test proving the proxy works with
 * Claude Code's real SUBSCRIPTION (OAuth, no API key).
 *
 * Mandu (tests/). The sibling `claude-code.test.ts` spawns a real
 * `claude -p` but with a DUMMY api key + an isolated CLAUDE_CONFIG_DIR — so it
 * deliberately does NOT exercise subscription auth. This test fills that gap:
 *
 *     claude -p  (real logged-in SUBSCRIPTION, NO api key)
 *        │   ANTHROPIC_BASE_URL → real ArbiterServer + real AnthropicProxy
 *        ▼   ── upstream ──► fake Anthropic (stands in for api.anthropic.com)
 *
 * It proves the §3.1 relay property (docs/design/agents/agent-sign-in.md §1) against the
 * REAL client: a subscription-authenticated `claude` forwards its OAuth credential
 * to the proxy base URL (finding F1), and the proxy relays it upstream UNCHANGED.
 * The fake upstream accepts anything, so NO real Anthropic budget is spent and no
 * network call to api.anthropic.com is made — only the user's loopback proxy sees
 * the credential.
 *
 * It runs in `secrets` mode (test-organization.md §7.3): subscription auth must
 * not weaken the CONFIDENTIALITY invariant. The file claude reads is LABELLED
 * secret (admin `setPathLabel`, as a user does), and check (3) asserts the model
 * saw it only as its `$MDU:nomodel_…` symbol while the human can still reveal
 * it. The integrity form of check (3) (a poisoned file reaching the model only
 * as a symbol) is frozen: tests/integrity/subscription.test.ts.
 *
 * To force the SUBSCRIPTION (not a stray key/apiKeyHelper) we dogfood the same
 * hardening the U-LLM uses: spawn with NO ANTHROPIC_API_KEY and
 * `--setting-sources project,local` (excludes user settings, where apiKeyHelper
 * lives; the credential store is read independently of settings).
 *
 * GATED: runs only when `claude` is on PATH AND `MANDU_E2E_SUBSCRIPTION=1` is set
 * (it uses your real logged-in subscription). Otherwise it SKIPS. Run it with:
 *     MANDU_E2E_SUBSCRIPTION=1 npx tsx --test env/subscription.test.ts   # in tests/
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Readable } from "node:stream";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import type { UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as AnthropicProxyArbiterAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";

import { startFakeAnthropic } from "../lib/fake-anthropic.js";
import { runChildToExit } from "../lib/child-run.js";
import {
  NOMODEL_SYMBOL_RE, confCanary, humanReveal, labelSecret, modelSawCanary, secretFileBody, toolResultSpan,
} from "../lib/conf-exfil.js";
import { installExitGuard } from "../lib/exit-guard.js";
import { stateAxes } from "../lib/axes.js";

// Exit-guard backstop (tests/lib/exit-guard.ts): if a leaked handle still
// holds this runner's event loop after the tests complete, dump it to stderr
// and force-exit instead of hanging the suite forever.
installExitGuard("subscription");

// This suite STATES its axes (protection-modes.md §4): `secrets`, the
// built-in default. The arbiter below also takes the pair explicitly.
stateAxes("secrets");

/** Forward upstream over HTTP to the fake Anthropic, recording the auth header. */
function capturingForwarder(
  origin: string,
  sink: Array<{ authorization?: string; apiKey?: string }>,
): UpstreamFetcher {
  const url = new URL(origin);
  return async ({ method, path, headers, body }) => {
    const one = (v: string | string[] | undefined): string | undefined =>
      Array.isArray(v) ? v[0] : v;
    sink.push({ authorization: one(headers.authorization), apiKey: one(headers["x-api-key"]) });
    const http = await import("node:http");
    return new Promise((resolve, reject) => {
      const r = http.request(
        { protocol: url.protocol, hostname: url.hostname, port: url.port, method, path, headers: { ...headers, host: url.host } },
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
  : process.env["MANDU_E2E_SUBSCRIPTION"] !== "1"
    ? "set MANDU_E2E_SUBSCRIPTION=1 to run — uses your real logged-in subscription"
    : false;

/** The Read tool_use id startFakeAnthropic scripts (lib/fake-anthropic.ts). */
const READ_ID = "toolu_mdu_live_1";
const PROMPT_MARKER = "MDU_SUB_MARKER_4K2P";
const FINAL_TEXT = "MDU_SUB_DONE_QZ7";

/** Redact a captured credential to its shape only — never log the token. */
function credShape(c: { authorization?: string; apiKey?: string }): string {
  if (c.authorization) return c.authorization.startsWith("Bearer ") ? "Bearer …" : "auth:other";
  if (c.apiKey) return c.apiKey.startsWith("sk-ant-oat") ? "x-api-key:oat…" : `x-api-key:${c.apiKey.slice(0, 10)}…`;
  return "none";
}

test(
  "LIVE: real `claude -p` on a SUBSCRIPTION (no api key) flows through the proxy; OAuth credential relayed",
  { skip: SKIP_REASON, timeout: 120_000 },
  async () => {
    const tmp = mkdtempSync(join(tmpdir(), "mandu-sub-live-"));
    const workspace = join(tmp, "workspace");
    // Not a default-secret catalog name: the label, and nothing else, makes it secret.
    const notes = join(workspace, "partner-token.md");
    const socketPath = join(tmp, "arbiter.sock");
    const adminSock = join(tmp, "admin.sock");
    const canary = confCanary("SUB");
    mkdirSync(workspace, { recursive: true });
    writeFileSync(notes, secretFileBody(canary));

    const arbiter = new ArbiterServer({
      socketPath, adminSocketPath: adminSock,
      dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
      integrity: false, confidentiality: true, // `secrets`, stated explicitly
    });
    await arbiter.listen();
    await labelSecret(adminSock, notes);
    const proxyClient = new ArbiterClient(socketPath);
    await proxyClient.connect();

    const fake = await startFakeAnthropic({ readFilePath: notes, promptMarker: PROMPT_MARKER, finalText: FINAL_TEXT });
    const forwardedCreds: Array<{ authorization?: string; apiKey?: string }> = [];
    const proxy = new AnthropicProxy({
      // The PRODUCTION wiring (CONTRIBUTING.md arbiter-client pattern): the adapter
      // over the real IPC client, no test bridge.
      arbiter: new AnthropicProxyArbiterAdapter(proxyClient),
      upstream: capturingForwarder(fake.origin, forwardedCreds),
      log: () => {},
    });
    const proxyPort = await proxy.listen(0);

    try {
      // Spawn the REAL claude on the user's SUBSCRIPTION:
      //   - NO ANTHROPIC_API_KEY (so it falls through to the OAuth/keychain login),
      //   - real HOME (so the credential store ~/.claude/.credentials.json is read),
      //   - `--setting-sources project,local` to exclude USER settings (apiKeyHelper),
      //   - pointed at our loopback proxy.
      // runChildToExit SIGKILLs the whole process group and rejects on timeout.
      const { code, stdout, stderr } = await runChildToExit(
        "claude",
        [
          "-p",
          `${PROMPT_MARKER} Read the file ${notes} and reply with its first line.`,
          "--model", "claude-haiku-4-5",
          "--output-format", "text",
          "--permission-mode", "bypassPermissions",
          "--setting-sources", "project,local",
        ],
        {
          cwd: workspace,
          env: {
            HOME: process.env["HOME"] ?? tmp,
            PATH: process.env["PATH"] ?? "",
            ANTHROPIC_BASE_URL: `http://127.0.0.1:${proxyPort}`,
            // Deliberately NO ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN — force the subscription.
          },
          timeoutMs: 110_000,
          label: "claude",
        },
      );

      // (1) claude authenticated via the subscription and completed a turn through
      //     the proxy. A non-zero exit here usually means auth failed (e.g. the
      //     client wanted an API key) — surface stderr to diagnose.
      assert.equal(code, 0, `claude exited ${code} (stderr=${JSON.stringify(stderr.slice(0, 600))})`);
      // claude actually PRINTED the final assistant turn — the round-trip
      // (claude → proxy → upstream → claude) produced output, not an empty exit.
      // NOTE: the upstream is FAKED here, so this verifies the PIPELINE, not the
      // real model's content. The real-model output check is in
      // subscription-real.test.ts.
      assert.ok(
        stdout.includes(FINAL_TEXT),
        `claude printed the final model turn (stdout=${JSON.stringify(stdout.slice(0, 300))})`,
      );
      assert.ok(forwardedCreds.length > 0, "the proxy forwarded at least one request upstream");

      // (2) THE RELAY PROPERTY: a SUBSCRIPTION (OAuth) credential was forwarded
      //     through the proxy — an Authorization: Bearer, or an x-api-key OAuth
      //     token (sk-ant-oat*) for client versions that use that transport (F4).
      //     We assert the *shape* only; the token value is never logged.
      const sawSubscriptionCred = forwardedCreds.some(
        (c) => c.authorization?.startsWith("Bearer ") || c.apiKey?.startsWith("sk-ant-oat"),
      );
      assert.ok(
        sawSubscriptionCred,
        `expected a subscription OAuth credential relayed upstream; saw shapes=${JSON.stringify(forwardedCreds.map(credShape))}`,
      );

      // (3) THE CONFIDENTIALITY INVARIANT still holds: the labelled file
      //     reached the model ONLY as its no-model symbol — subscription auth
      //     does not weaken symbolization. Positive oracle first: without the
      //     Read's tool_result the wire scan below is vacuous.
      assert.ok(fake.requests.length > 0, "the proxy forwarded ≥1 request to the (fake) model");
      const span = fake.requests.map((r) => toolResultSpan(r.body, READ_ID)).find((x) => x !== null) ?? null;
      assert.ok(span !== null, "claude ran Read and its tool_result was forwarded to the model");
      assert.ok(!modelSawCanary(fake.requests, canary), "CONFIDENTIALITY VIOLATION: the labelled secret's bytes reached the model");
      assert.ok(!fake.requests.some((r) => r.body.includes("sk-live-")), "no fragment of the credential reached the model");
      assert.match(span!, NOMODEL_SYMBOL_RE, `the Read result reached the model as ONE no-model symbol, got ${JSON.stringify(span)}`);
      // The human still owns the value: the arbiter reveals it on the admin channel.
      assert.ok((await humanReveal(adminSock, span!)).includes(canary), "HumanView reveal returns the original");
    } finally {
      await proxy.close();
      proxyClient.close();
      await fake.close();
      await arbiter.close();
      rmSync(tmp, { recursive: true, force: true });
    }
  },
);
