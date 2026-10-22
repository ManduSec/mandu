// Unit tests for scripts/matrix/lib/reduce-codex-auth.mjs
// (docs/design/testing/os-test-matrix.md §10.18): the npm-release guest gets
// a Codex sign-in that can never refresh, so it never rotates the host's.
// Run: node --test <this file>.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { tmpDir } from "./lib/tmp-dir.mjs";
import { reduce } from "../matrix/lib/reduce-codex-auth.mjs";

const NOW = 1_000_000_000_000;
const jwt = (expMs) => `h.${Buffer.from(JSON.stringify({ exp: Math.floor(expMs / 1000) })).toString("base64url")}.AT-secret-sig`;
const signIn = (over = {}, tokens = {}) => JSON.stringify({
  auth_mode: "chatgpt", OPENAI_API_KEY: null, last_refresh: "2026-01-01T00:00:00Z",
  tokens: { id_token: "ID-tok", access_token: jwt(NOW + 3600_000), refresh_token: "RT-secret", account_id: "acct", ...tokens },
  ...over,
});

test("a sign-in keeps the access token, drops the refresh token, and says it was just refreshed", () => {
  const r = reduce(signIn(), NOW, 600);
  assert.ok(r.ok); assert.equal(r.kind, "sign-in");
  assert.ok(!r.json.includes("RT-secret"));
  const j = JSON.parse(r.json);
  assert.equal(j.tokens.refresh_token, "");
  assert.equal(j.tokens.access_token, jwt(NOW + 3600_000));
  assert.equal(j.tokens.account_id, "acct");
  assert.equal(j.last_refresh, new Date(NOW).toISOString());
});

test("allow-list: an unknown field, top level or in tokens, does not ride along", () => {
  const r = reduce(signIn({ some_new_refresh: "X-secret" }, { another: "Y-secret" }), NOW, 600);
  assert.ok(r.ok && !r.json.includes("X-secret") && !r.json.includes("Y-secret"));
});

test("a saved API key is copied as the key alone", () => {
  const r = reduce(JSON.stringify({ OPENAI_API_KEY: "sk-key", tokens: { refresh_token: "RT-secret" } }), NOW, 600);
  assert.ok(r.ok); assert.equal(r.kind, "key");
  assert.deepEqual(JSON.parse(r.json), { OPENAI_API_KEY: "sk-key" });
});

test("too little lifetime left is refused and marked stale", () => {
  const r = reduce(signIn({}, { access_token: jwt(NOW + 60_000) }), NOW, 600);
  assert.equal(r.ok, false); assert.equal(r.stale, true);
});

test("garbage, no token, and a token with no exp are refused", () => {
  assert.equal(reduce("{nope", NOW, 1).ok, false);
  assert.equal(reduce("{}", NOW, 1).ok, false);
  assert.equal(reduce(signIn({}, { access_token: "" }), NOW, 1).ok, false);
  assert.equal(reduce(signIn({}, { access_token: "not-a-jwt" }), NOW, 1).ok, false);
});

test("CLI: writes 0600 into an existing dir, never prints a token, refuses a missing dir", () => {
  const cli = join(dirname(fileURLToPath(import.meta.url)), "..", "matrix", "lib", "reduce-codex-auth.mjs");
  const d = tmpDir("redcodex-");
  const src = join(d, "auth.json");
  writeFileSync(src, JSON.stringify({ auth_mode: "chatgpt", tokens: { access_token: jwt(Date.now() + 3600_000), refresh_token: "RT-secret" } }));
  const out = join(d, "out");
  const miss = spawnSync("node", [cli, src, out, "60"], { encoding: "utf8" });
  assert.equal(miss.status, 3); assert.ok(!existsSync(out));
  const ok = spawnSync("node", [cli, src, d, "60"], { encoding: "utf8" });
  assert.equal(ok.status, 0, ok.stderr);
  assert.ok(!(ok.stdout + ok.stderr).includes("secret"));
  const f = join(d, "codex-auth.json");
  assert.equal(statSync(f).mode & 0o777, 0o600);
  assert.ok(!readFileSync(f, "utf8").includes("RT-secret"));
});
