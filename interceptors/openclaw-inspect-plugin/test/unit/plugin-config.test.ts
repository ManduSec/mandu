/**
 * plugin-config tests — config/env resolution + the fail-loud arbiter
 * requirement + the two DELIBERATE env divergences (host ANTHROPIC_* must
 * never leak into the quarantined channel's selection).
 *
 * Mandu (interceptors/openclaw-inspect-plugin). No OpenClaw, no network,
 * no arbiter.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { resolvePluginConfig } from "../../src/plugin-config.js";

const SOCK = "/tmp/mandu-test/arbiter.sock";

test("config values win over env fallbacks", () => {
  const cfg = resolvePluginConfig(
    {
      arbiterSock: SOCK,
      scopeId: "scope-cfg",
      ullmMode: "cli",
      ullmBinary: "claude",
      ullmModel: "claude-haiku-4-5",
      ullmBaseUrl: "https://api.anthropic.com",
      ullmForwarder: "http://127.0.0.1:9999",
      ullmApiKey: "sk-cfg",
    },
    {
      MANDU_ARBITER_SOCK: "/env/other.sock",
      MANDU_SCOPE_ID: "scope-env",
      MANDU_ULLM_MODE: "api",
      MANDU_ULLM_BINARY: "codex",
      MANDU_ULLM_MODEL: "env-model",
      MANDU_ULLM_BASE_URL: "https://env.example",
      MANDU_ULLM_FORWARDER: "http://127.0.0.1:1111",
      MANDU_ULLM_API_KEY: "sk-env",
    },
  );
  assert.equal(cfg.arbiterSock, SOCK);
  assert.equal(cfg.scopeId, "scope-cfg");
  assert.equal(cfg.ullmEnv.MANDU_ULLM_MODE, "cli");
  assert.equal(cfg.ullmEnv.MANDU_ULLM_BINARY, "claude");
  assert.equal(cfg.ullmEnv.MANDU_ULLM_MODEL, "claude-haiku-4-5");
  assert.equal(cfg.ullmEnv.ANTHROPIC_BASE_URL, "https://api.anthropic.com");
  assert.equal(cfg.ullmEnv.MANDU_ULLM_FORWARDER, "http://127.0.0.1:9999");
  assert.equal(cfg.ullmEnv.ANTHROPIC_API_KEY, "sk-cfg");
});

test("env fallbacks apply when config is absent", () => {
  const cfg = resolvePluginConfig(undefined, {
    MANDU_ARBITER_SOCK: SOCK,
    MANDU_SCOPE_ID: "scope-env",
    MANDU_ULLM_MODE: "api",
    MANDU_ULLM_MODEL: "env-model",
    MANDU_ULLM_BASE_URL: "https://env.example",
    MANDU_ULLM_API_KEY: "sk-env",
  });
  assert.equal(cfg.arbiterSock, SOCK);
  assert.equal(cfg.scopeId, "scope-env");
  assert.equal(cfg.ullmEnv.MANDU_ULLM_MODE, "api");
  assert.equal(cfg.ullmEnv.MANDU_ULLM_MODEL, "env-model");
  assert.equal(cfg.ullmEnv.ANTHROPIC_BASE_URL, "https://env.example");
  assert.equal(cfg.ullmEnv.ANTHROPIC_API_KEY, "sk-env");
});

test("FAIL LOUD: missing arbiter socket throws with a clear message", () => {
  assert.throws(
    () => resolvePluginConfig({}, {}),
    /arbiterSock|MANDU_ARBITER_SOCK/,
  );
});

test("empty-string arbiter socket counts as absent (still throws)", () => {
  assert.throws(() => resolvePluginConfig({ arbiterSock: "  " }, { MANDU_ARBITER_SOCK: "" }));
});

// ── The deliberate divergences: host ANTHROPIC_* never leaks in ──────────────
// In a Mandu-wrapped OpenClaw run the HOST process env has
// ANTHROPIC_BASE_URL = the instrumented anthropic-proxy and
// ANTHROPIC_API_KEY = the T-LLM path's credential (a dummy in the live
// harness). Neither may reach the quarantined channel's transport selection.

test("host ANTHROPIC_BASE_URL (the instrumented proxy) is IGNORED", () => {
  const cfg = resolvePluginConfig(
    { arbiterSock: SOCK },
    {
      ANTHROPIC_BASE_URL: "http://127.0.0.1:8788", // the proxy — must not leak
    },
  );
  assert.equal(cfg.ullmEnv.ANTHROPIC_BASE_URL, undefined);
});

test("host ANTHROPIC_API_KEY (the T-LLM credential) is IGNORED", () => {
  const cfg = resolvePluginConfig(
    { arbiterSock: SOCK },
    {
      ANTHROPIC_API_KEY: "dummy-tllm-key", // must not select api mode
    },
  );
  assert.equal(cfg.ullmEnv.ANTHROPIC_API_KEY, undefined);
});

test("only the dedicated MANDU_ULLM_* names feed the U-LLM slice", () => {
  const cfg = resolvePluginConfig(
    { arbiterSock: SOCK },
    {
      ANTHROPIC_BASE_URL: "http://127.0.0.1:8788",
      ANTHROPIC_API_KEY: "dummy-tllm-key",
      MANDU_ULLM_BASE_URL: "https://api.anthropic.com",
      MANDU_ULLM_API_KEY: "sk-quarantine",
    },
  );
  assert.equal(cfg.ullmEnv.ANTHROPIC_BASE_URL, "https://api.anthropic.com");
  assert.equal(cfg.ullmEnv.ANTHROPIC_API_KEY, "sk-quarantine");
});
