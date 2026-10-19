/**
 * codex-auth-lib.test.ts — the real-model Codex suites' credential switch
 * (tests/lib/codex-auth.ts; agent-sign-in.md §2.7,
 * continuous-integration.md §9.8), offline: no model, no network.
 *
 * Pins: the mode and its skip reasons; the ChatGPT form writes a REDUCED
 * sign-in (refresh token emptied, no API key, the source untouched) into the
 * suite's own CODEX_HOME and refuses a source that is not a ChatGPT sign-in
 * without printing a value; the provider is the launcher's own shape per
 * mode; the key reaches Codex only in the key mode; the model pin applies
 * only to the key mode.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  codexAuthMode, codexAuthSkip, codexCredentialEnv, codexModelArgs, codexProvider, writeReducedSignIn,
} from "../lib/codex-auth.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("off"); // no protection decision here: the credential plumbing only

const SIGN_IN = {
  OPENAI_API_KEY: null,
  tokens: { id_token: "eyJ.id.DUMMY", access_token: "eyJ.access.DUMMY", refresh_token: "REFRESH-DUMMY-NEVER-COPIED", account_id: "acct-dummy" },
  last_refresh: "2026-09-01T00:00:00Z",
};

test("the mode, and why each cannot run", () => {
  assert.equal(codexAuthMode({}), "key");
  assert.equal(codexAuthMode({ MANDU_CODEX_AUTH: "chatgpt" }), "chatgpt");
  assert.equal(codexAuthMode({ MANDU_CODEX_AUTH: "anything" }), "key");
  assert.match(String(codexAuthSkip("key", {})), /no OPENAI_API_KEY/);
  assert.equal(codexAuthSkip("key", { OPENAI_API_KEY: "sk-x" }), false);
  assert.match(String(codexAuthSkip("chatgpt", { OPENAI_API_KEY: "sk-x" })), /no MANDU_CI_CODEX_AUTH/, "a key does not stand in for a sign-in");
  assert.match(String(codexAuthSkip("chatgpt", { MANDU_CI_CODEX_AUTH: "/nonexistent/auth.json" })), /does not exist/);
});

test("the ChatGPT form writes a reduced copy: no refresh token, no key, the source untouched", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-codex-auth-lib-"));
  try {
    const src = join(dir, "source-auth.json");
    const srcText = JSON.stringify(SIGN_IN);
    writeFileSync(src, srcText);
    const home = join(dir, "home");
    mkdirSync(home);
    const env = { MANDU_CI_CODEX_AUTH: src };
    assert.equal(codexAuthSkip("chatgpt", env), false);
    writeReducedSignIn(home, env);
    const out = readFileSync(join(home, "auth.json"), "utf8");
    const doc = JSON.parse(out) as { OPENAI_API_KEY: unknown; tokens: Record<string, string>; last_refresh: string };
    assert.equal(doc.OPENAI_API_KEY, null);
    assert.equal(doc.tokens["refresh_token"], "", "the field stays (Codex requires it), empty");
    assert.equal(doc.tokens["access_token"], SIGN_IN.tokens.access_token);
    assert.equal(doc.tokens["account_id"], SIGN_IN.tokens.account_id);
    assert.ok(!out.includes("REFRESH-DUMMY-NEVER-COPIED"));
    assert.ok(Date.parse(doc.last_refresh) > Date.parse(SIGN_IN.last_refresh), "last_refresh is now: no proactive refresh");
    assert.equal(statSync(join(home, "auth.json")).mode & 0o777, 0o600);
    assert.equal(readFileSync(src, "utf8"), srcText, "the source is never written");

    // Not a ChatGPT sign-in (a saved key): refused, no value in the message.
    writeFileSync(src, JSON.stringify({ OPENAI_API_KEY: "sk-SAVED-DUMMY", tokens: null }));
    assert.throws(() => writeReducedSignIn(home, env), (e: Error) => /not a ChatGPT sign-in/.test(e.message) && !e.message.includes("sk-SAVED-DUMMY"));
    writeFileSync(src, "not json SECRET-ish");
    assert.throws(() => writeReducedSignIn(home, env), (e: Error) => /is not JSON/.test(e.message) && !e.message.includes("SECRET-ish"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the provider, the credential env and the model per mode", () => {
  assert.match(codexProvider("key", 4100), /base_url="http:\/\/127\.0\.0\.1:4100\/v1".*env_key="OPENAI_API_KEY"\}$/);
  const signIn = codexProvider("chatgpt", 4100);
  assert.match(signIn, /requires_openai_auth=true,supports_websockets=false\}$/);
  assert.doesNotMatch(signIn, /env_key/);
  assert.deepEqual(codexCredentialEnv("key", { OPENAI_API_KEY: "sk-x" }), { OPENAI_API_KEY: "sk-x" });
  assert.deepEqual(codexCredentialEnv("chatgpt", { OPENAI_API_KEY: "sk-x" }), {}, "a sign-in run never hands Codex a key");
  assert.deepEqual(codexModelArgs("key", "gpt-5.4", {}), ["-c", "model=gpt-5.4"]);
  assert.deepEqual(codexModelArgs("chatgpt", "gpt-5.4", {}), [], "the backend's own default");
  assert.deepEqual(codexModelArgs("chatgpt", "gpt-5.4", { MANDU_CODEX_MODEL: "m" }), ["-c", "model=m"]);
});
