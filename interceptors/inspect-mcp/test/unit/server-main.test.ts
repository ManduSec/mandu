/**
 * server-main selection tests — the PURE U-LLM transport selector
 * (src/server-main.ts `selectUllmConfig` / `buildUllmClient`).
 *
 * Mandu M4 (interceptors/inspect-mcp). server-main wiring is I/O-only, but the
 * api-vs-cli DECISION is extracted into `selectUllmConfig` so it is unit-testable
 * with NO key, NO real claude, and NO arbiter. The `cliAvailable` PATH probe is
 * injected. Asserts:
 *   - a key → the api client; no key + a present CLI binary → the cli client;
 *     neither → fail closed.
 *   - explicit modes (api / cli) honored + fail closed when their requirement is
 *     unmet.
 *   - buildUllmClient maps each config to the right concrete client.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  selectUllmConfig,
  buildUllmClient,
  type UllmEnv,
} from "../../src/server-main.js";
import { AnthropicUllmClient, CliUllmClient } from "../../src/ullm-client.js";

const ALWAYS = () => true;
const NEVER = () => false;
/** A probe that reports only the named binary as present. */
const only = (present: "claude" | "codex") => (b: "claude" | "codex") => b === present;

// ── auto mode ─────────────────────────────────────────────────────────────────

test("auto: a key present selects the api client", () => {
  const env: UllmEnv = { ANTHROPIC_API_KEY: "sk-test", MANDU_ULLM_MODEL: "claude-haiku-4-5" };
  const cfg = selectUllmConfig(env, NEVER);
  assert.equal(cfg.mode, "api");
  if (cfg.mode !== "api") return;
  assert.equal(cfg.apiKey, "sk-test");
  assert.equal(cfg.model, "claude-haiku-4-5");
});

test("auto: no key + a present CLI binary selects the cli client (no key needed)", () => {
  const env: UllmEnv = {}; // no key
  const cfg = selectUllmConfig(env, ALWAYS);
  assert.equal(cfg.mode, "cli");
  if (cfg.mode !== "cli") return;
  assert.equal(cfg.binary, "auto");
});

test("auto: no key and NO CLI binary fails closed with a clear message", () => {
  assert.throws(
    () => selectUllmConfig({}, NEVER),
    /no ANTHROPIC_API_KEY and no claude\/codex CLI on PATH/i,
  );
});

test("auto: an empty/whitespace key is treated as no key (falls through to cli)", () => {
  const cfg = selectUllmConfig({ ANTHROPIC_API_KEY: "   " }, ALWAYS);
  assert.equal(cfg.mode, "cli");
});

test("auto: a codex model probes for codex, and a codex-only PATH still resolves to cli", () => {
  const cfg = selectUllmConfig({ MANDU_ULLM_MODEL: "gpt-5.4-mini" }, only("codex"));
  assert.equal(cfg.mode, "cli");
});

test("auto: claude-model probe falls back to the OTHER binary when only it is installed", () => {
  // model implies claude, but only codex is present → still resolves to cli.
  const cfg = selectUllmConfig({ MANDU_ULLM_MODEL: "claude-haiku-4-5" }, only("codex"));
  assert.equal(cfg.mode, "cli");
  if (cfg.mode !== "cli") return;
  assert.equal(cfg.binary, "codex");
});

// ── explicit api mode ─────────────────────────────────────────────────────────

test("api mode: requires a key (current behavior); present → api client", () => {
  const cfg = selectUllmConfig({ MANDU_ULLM_MODE: "api", ANTHROPIC_API_KEY: "sk-x" }, NEVER);
  assert.equal(cfg.mode, "api");
});

test("api mode: no key fails closed (preserves the original required-key behavior)", () => {
  assert.throws(
    () => selectUllmConfig({ MANDU_ULLM_MODE: "api" }, ALWAYS),
    /MANDU_ULLM_MODE=api but ANTHROPIC_API_KEY is not set/i,
  );
});

test("SECURITY: api mode REFUSES a loopback ANTHROPIC_BASE_URL (the anthropic-proxy) — fail closed", () => {
  // The Mandu anthropic-proxy lives on loopback (e.g. 127.0.0.1:8788). Routing the
  // quarantined U-LLM through it loops untrusted data back through T-LLM's
  // instrumented path — the core invariant violation. api mode must NOT use it.
  for (const url of [
    "http://127.0.0.1:8788",
    "http://localhost:8788",
    "http://[::1]:8788",
    "https://127.0.0.1",
    "http://localhost",
  ]) {
    assert.throws(
      () => selectUllmConfig({ MANDU_ULLM_MODE: "api", ANTHROPIC_API_KEY: "sk-x", ANTHROPIC_BASE_URL: url }, NEVER),
      /loopback|proxy|127\.0\.0\.1|localhost/i,
      `api mode must refuse loopback base URL ${url}`,
    );
  }
});

test("SECURITY: auto mode (key present → api) also REFUSES a loopback ANTHROPIC_BASE_URL", () => {
  assert.throws(
    () => selectUllmConfig({ ANTHROPIC_API_KEY: "sk-x", ANTHROPIC_BASE_URL: "http://127.0.0.1:8788" }, NEVER),
    /loopback|proxy|127\.0\.0\.1|localhost/i,
  );
});

test("api mode: a REAL (non-loopback) ANTHROPIC_BASE_URL passes through unchanged", () => {
  const cfg = selectUllmConfig(
    { MANDU_ULLM_MODE: "api", ANTHROPIC_API_KEY: "sk-x", ANTHROPIC_BASE_URL: "https://api.anthropic.com" },
    NEVER,
  );
  assert.equal(cfg.mode, "api");
  if (cfg.mode !== "api") return;
  assert.equal(cfg.baseUrl, "https://api.anthropic.com");
});

test("SECURITY: AnthropicUllmClient constructor REFUSES a loopback baseUrl (defense in depth)", () => {
  assert.throws(
    () => new AnthropicUllmClient({ apiKey: "sk-x", baseUrl: "http://127.0.0.1:8788" }),
    /loopback|proxy|127\.0\.0\.1|localhost/i,
  );
  // The real endpoint (and the default) are accepted.
  assert.doesNotThrow(() => new AnthropicUllmClient({ apiKey: "sk-x", baseUrl: "https://api.anthropic.com" }));
  assert.doesNotThrow(() => new AnthropicUllmClient({ apiKey: "sk-x" }));
});

// ── the launcher-pinned loopback forwarder (the ONE sanctioned loopback) ──────

test("SECURITY: the MANDU_ULLM_FORWARDER pin admits EXACTLY that loopback origin — nothing else", () => {
  const PIN = "http://127.0.0.1:8791";
  // api mode with the pinned relay as base URL: accepted.
  const cfg = selectUllmConfig(
    { MANDU_ULLM_MODE: "api", ANTHROPIC_API_KEY: "sk-x", ANTHROPIC_BASE_URL: PIN, MANDU_ULLM_FORWARDER: PIN },
    NEVER,
  );
  assert.equal(cfg.mode, "api");
  if (cfg.mode !== "api") return;
  assert.equal(cfg.baseUrl, PIN);
  assert.equal(cfg.forwarderUrl, PIN);

  // A DIFFERENT loopback (above all the instrumented proxy on 8788) stays refused
  // even with the pin present — the pin names one origin, not a loopback class.
  for (const other of ["http://127.0.0.1:8788", "http://localhost:8791", "http://127.0.0.1:9999"]) {
    assert.throws(
      () => selectUllmConfig(
        { MANDU_ULLM_MODE: "api", ANTHROPIC_API_KEY: "sk-x", ANTHROPIC_BASE_URL: other, MANDU_ULLM_FORWARDER: PIN },
        NEVER,
      ),
      /loopback/i,
      `pin must not admit ${other}`,
    );
  }
});

test("SECURITY: cli mode now guards the base URL too (it reaches the child's ANTHROPIC_BASE_URL)", () => {
  // Loopback without the pin: refused (this closes the previously-unguarded cli path).
  assert.throws(
    () => selectUllmConfig({ MANDU_ULLM_MODE: "cli", ANTHROPIC_BASE_URL: "http://127.0.0.1:8788" }, ALWAYS),
    /loopback/i,
  );
  // The pinned forwarder: accepted, and carried on the config for the child env.
  const PIN = "http://127.0.0.1:8791";
  const cfg = selectUllmConfig(
    { MANDU_ULLM_MODE: "cli", ANTHROPIC_BASE_URL: PIN, MANDU_ULLM_FORWARDER: PIN },
    ALWAYS,
  );
  assert.equal(cfg.mode, "cli");
  if (cfg.mode !== "cli") return;
  assert.equal(cfg.baseUrl, PIN);
});

test("SECURITY: AnthropicUllmClient accepts the pinned forwarder as baseUrl (and only it)", () => {
  const PIN = "http://127.0.0.1:8791";
  assert.doesNotThrow(() => new AnthropicUllmClient({ apiKey: "sk-x", baseUrl: PIN, forwarderUrl: PIN }));
  assert.throws(
    () => new AnthropicUllmClient({ apiKey: "sk-x", baseUrl: "http://127.0.0.1:8788", forwarderUrl: PIN }),
    /loopback/i,
  );
});

// ── explicit cli mode ─────────────────────────────────────────────────────────

test("cli mode: no key needed; a present binary → cli client", () => {
  const cfg = selectUllmConfig({ MANDU_ULLM_MODE: "cli" }, ALWAYS);
  assert.equal(cfg.mode, "cli");
  if (cfg.mode !== "cli") return;
  assert.equal(cfg.binary, "auto");
});

test("cli mode: honors the MANDU_ULLM_BINARY hint", () => {
  const cfg = selectUllmConfig({ MANDU_ULLM_MODE: "cli", MANDU_ULLM_BINARY: "claude" }, ALWAYS);
  assert.equal(cfg.mode, "cli");
  if (cfg.mode !== "cli") return;
  assert.equal(cfg.binary, "claude");
});

test("cli mode: the binary not on PATH fails closed", () => {
  assert.throws(
    () => selectUllmConfig({ MANDU_ULLM_MODE: "cli", MANDU_ULLM_BINARY: "claude" }, NEVER),
    /the 'claude' CLI is not on PATH/i,
  );
});

test("cli mode: a key is IGNORED (cli does not need or use it)", () => {
  const cfg = selectUllmConfig({ MANDU_ULLM_MODE: "cli", ANTHROPIC_API_KEY: "sk-x" }, ALWAYS);
  assert.equal(cfg.mode, "cli");
});

// ── base-url / model passthrough ──────────────────────────────────────────────

test("baseUrl + model pass through to the cli config (real endpoint, never the proxy)", () => {
  const cfg = selectUllmConfig(
    { MANDU_ULLM_MODE: "cli", ANTHROPIC_BASE_URL: "https://api.anthropic.com", MANDU_ULLM_MODEL: "claude-haiku-4-5" },
    ALWAYS,
  );
  assert.equal(cfg.mode, "cli");
  if (cfg.mode !== "cli") return;
  assert.equal(cfg.baseUrl, "https://api.anthropic.com");
  assert.equal(cfg.model, "claude-haiku-4-5");
});

test("an unrecognized MANDU_ULLM_MODE falls back to auto", () => {
  const cfg = selectUllmConfig({ MANDU_ULLM_MODE: "weird", ANTHROPIC_API_KEY: "sk-x" }, NEVER);
  assert.equal(cfg.mode, "api"); // auto resolved to api because a key is present
});

// ── buildUllmClient ───────────────────────────────────────────────────────────

test("buildUllmClient: api config → AnthropicUllmClient; cli config → CliUllmClient", () => {
  const api = buildUllmClient({ mode: "api", apiKey: "sk-x" });
  assert.ok(api instanceof AnthropicUllmClient);
  const cli = buildUllmClient({ mode: "cli", binary: "auto" });
  assert.ok(cli instanceof CliUllmClient);
});
