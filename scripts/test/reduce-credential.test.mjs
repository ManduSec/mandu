// Unit tests for scripts/matrix/lib/reduce-credential.mjs
// (docs/design/testing/os-test-matrix.md §10.3.5). Run: node --test <this file>.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { tmpDir } from "./lib/tmp-dir.mjs";
import { reduce } from "../matrix/lib/reduce-credential.mjs";

const NOW = 1_000_000_000_000;
const full = (over = {}) => JSON.stringify({ claudeAiOauth: {
  accessToken: "AT-secret", refreshToken: "RT-secret", expiresAt: NOW + 3600_000,
  refreshTokenExpiresAt: NOW + 9e9, scopes: ["user:inference"], subscriptionType: "max", rateLimitTier: "t", ...over } });

test("the refresh token (and its expiry) never survives", () => {
  const r = reduce(full(), NOW, 600);
  assert.ok(r.ok);
  assert.ok(!r.json.includes("RT-secret"));
  assert.ok(!r.json.includes("refreshToken"));
  assert.equal(JSON.parse(r.json).claudeAiOauth.accessToken, "AT-secret");
});

test("allow-list: an unknown future field does not ride along", () => {
  const r = reduce(full({ someNewRefreshThing: "X-secret" }), NOW, 600);
  assert.ok(r.ok && !r.json.includes("X-secret"));
});

test("too little lifetime left is refused and marked stale", () => {
  const r = reduce(full({ expiresAt: NOW + 60_000 }), NOW, 600);
  assert.equal(r.ok, false); assert.equal(r.stale, true);
});

test("garbage, a missing token, and a missing expiry are refused", () => {
  assert.equal(reduce("{nope", NOW, 1).ok, false);
  assert.equal(reduce("{}", NOW, 1).ok, false);
  assert.equal(reduce(full({ accessToken: "" }), NOW, 1).ok, false);
  assert.equal(reduce(full({ expiresAt: undefined }), NOW, 1).ok, false);
});

test("CLI: writes 0600 into an existing dir, never prints a token, refuses a missing dir", () => {
  const cli = join(dirname(fileURLToPath(import.meta.url)), "..", "matrix", "lib", "reduce-credential.mjs");
  const d = tmpDir("redcred-");
  const src = join(d, "src.json");
  writeFileSync(src, full({ expiresAt: Date.now() + 3600_000 }));
  const out = join(d, "out"); 
  const miss = spawnSync("node", [cli, src, out, "60"], { encoding: "utf8" });
  assert.equal(miss.status, 3); assert.ok(!existsSync(out));
  const ok = spawnSync("node", [cli, src, d, "60"], { encoding: "utf8" });
  assert.equal(ok.status, 0, ok.stderr);
  assert.ok(!(ok.stdout + ok.stderr).includes("secret"));
  const f = join(d, ".credentials.json");
  assert.equal(statSync(f).mode & 0o777, 0o600);
  assert.ok(!readFileSync(f, "utf8").includes("RT-secret"));
});

// ── scripts/ci/credential.mjs: the nightly's credential and its canary ─────
// (docs/design/testing/continuous-integration.md §9). The same rule as above, for the one
// automatic run that holds a credential: the guest gets an access token only,
// and the token never comes back in a log or an artifact.
import { parseClaude, installShape, checkFile, credentialTar, needles, scan, defaultPath } from "../ci/credential.mjs";
import { chmodSync, mkdirSync, symlinkSync, readdirSync } from "node:fs";
import { randomBytes } from "node:crypto";

const CRED_CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "ci", "credential.mjs");
const tok = () => `sk-ant-oat01-TEST${randomBytes(66).toString("base64url")}`;
const run = (args, opts = {}) => spawnSync("node", [CRED_CLI, ...args], { encoding: "utf8", ...opts });

test("credential: a token is installed as the reduced JSON, 0600, with its expiry and the plan", () => {
  const t = tok();
  const r = installShape(t, { nowMs: NOW, subscription: "max" });
  assert.ok(r.ok);
  const o = JSON.parse(r.json).claudeAiOauth;
  assert.deepEqual(Object.keys(o).sort(), ["accessToken", "expiresAt", "scopes", "subscriptionType"]);
  assert.equal(o.accessToken, t); assert.equal(o.expiresAt, NOW + 365 * 86400_000);
  assert.deepEqual(o.scopes, ["user:inference"]); assert.equal(o.subscriptionType, "max");
  assert.equal(installShape(t, { subscription: "free" }).ok, false);
});

test("credential: refresh tokens, API keys, garbage and a full login are refused in every form", () => {
  const rt = "sk-ant-ort01-" + "x".repeat(40);
  assert.equal(installShape(rt).ok, false);
  assert.match(installShape(rt).reason, /REFRESH/);
  assert.equal(installShape("sk-ant-api03-" + "k".repeat(40)).ok, false);
  assert.equal(installShape("sk-ant-usr01-" + "k".repeat(40)).ok, false, "a newer-form API key is no subscription token either");
  assert.equal(installShape("hello").ok, false);
  assert.equal(parseClaude(rt, NOW).ok, false);
  assert.equal(parseClaude("sk-ant-api03-" + "k".repeat(40), NOW).ok, false);
  assert.equal(parseClaude("", NOW).ok, false);
  assert.equal(parseClaude("two words", NOW).ok, false);
  // The whole login (with its refresh token) is refused, not reduced on the fly:
  // the runner host must not keep a refresh token either.
  const login = JSON.stringify({ claudeAiOauth: { accessToken: tok(), refreshToken: rt, expiresAt: NOW + 3600_000 } });
  assert.match(parseClaude(login, NOW).reason, /refresh/i);
  const sneaky = JSON.stringify({ claudeAiOauth: { accessToken: tok(), expiresAt: NOW + 3600_000, refresh_token_v2: "z" } });
  assert.equal(parseClaude(sneaky, NOW).ok, false);
});

test("credential: the reduced JSON keeps an allow-list, and a token that dies before the run ends is refused", () => {
  const t = tok();
  const j = JSON.stringify({ claudeAiOauth: { accessToken: t, expiresAt: NOW + 7200_000, scopes: ["user:inference"], subscriptionType: "max", extra: "E-secret" } });
  const r = parseClaude(j, NOW, 600);
  assert.ok(r.ok);
  assert.ok(!r.json.includes("E-secret"));
  assert.equal(JSON.parse(r.json).claudeAiOauth.subscriptionType, "max");
  const short = parseClaude(j, NOW, 3 * 3600);
  assert.equal(short.ok, false); assert.match(short.reason, /needs 10800s/);
  const bare = parseClaude(t + "\n", NOW);
  assert.ok(bare.ok); assert.equal(JSON.parse(bare.json).claudeAiOauth.expiresAt, NOW + 24 * 3600_000);
});

test("credential: the host file must be a regular 0600 file of this account", () => {
  const d = tmpDir("cicred-");
  const f = join(d, "c.json");
  assert.equal(checkFile(f).absent, true);
  writeFileSync(f, "x"); chmodSync(f, 0o644);
  assert.match(checkFile(f).reason, /chmod 600/);
  chmodSync(f, 0o600);
  assert.equal(checkFile(f).ok, true);
  assert.match(checkFile(f, { uid: 424242 }).reason, /not owned/);
  symlinkSync(f, join(d, "link"));
  assert.match(checkFile(join(d, "link")).reason, /symlink/);
});

test("credential: the default path is under the passwd home, not $HOME, unless overridden", () => {
  const p = defaultPath("claude", { HOME: "/somewhere/else" });
  assert.ok(p.endsWith("/.config/mandu-ci/claude-credential.json"));
  assert.ok(!p.startsWith("/somewhere/else"));
  assert.equal(defaultPath("claude", { MANDU_CI_CLAUDE_CREDENTIAL: "/x/y" }), "/x/y");
  assert.equal(defaultPath("gemini", {}), null);
});

test("credential: the disk is a tar tar(1) reads, holding claude/.credentials.json 0600 and nothing else", () => {
  const d = tmpDir("cicred-");
  const json = parseClaude(tok(), NOW).json;
  writeFileSync(join(d, "c.tar"), credentialTar(json));
  const list = spawnSync("tar", ["-tvf", join(d, "c.tar")], { encoding: "utf8" });
  assert.equal(list.status, 0, list.stderr);
  const lines = list.stdout.trim().split("\n");
  assert.equal(lines.length, 2);
  assert.match(lines[0], /^drwx------ .* claude\/$/);
  assert.match(lines[1], /^-rw------- .* claude\/\.credentials\.json$/);
  const body = spawnSync("tar", ["-xOf", join(d, "c.tar"), "claude/.credentials.json"], { encoding: "utf8" });
  assert.equal(body.stdout, json);
  assert.equal(statSync(join(d, "c.tar")).size % 512, 0);
});

test("credential canary: the whole token or any 19 characters of it are found, in nested files and across read chunks", () => {
  const t = tok();
  const secret = t.slice("sk-ant-oat01-".length);
  assert.ok(needles(t).length >= Math.floor(secret.length / 16));
  const d = tmpDir("cicanary-");
  mkdirSync(join(d, "logs", "deep"), { recursive: true });
  writeFileSync(join(d, "summary.json"), '{"result":"pass"}');
  writeFileSync(join(d, "logs", "a.log"), "nothing here\n");
  assert.deepEqual(scan(t, [d]).found, []);
  writeFileSync(join(d, "logs", "deep", "b.log"), `header ${secret.slice(20, 40)} trailer`);
  assert.deepEqual(scan(t, [d]).found, [join(d, "logs", "deep", "b.log")]);
  // A token straddling the 4 MiB read boundary is still found.
  const big = Buffer.alloc(4 * 1024 * 1024 + 100, 0x2e);
  big.write(t, 4 * 1024 * 1024 - 30);
  writeFileSync(join(d, "big.raw"), big);
  assert.ok(scan(t, [join(d, "big.raw")]).found.length === 1);
  // A symlink out of the tree is not followed.
  const d2 = tmpDir("cicanary-");
  symlinkSync(join(d, "logs"), join(d2, "l"));
  assert.deepEqual(scan(t, [d2]).found, []);
});

test("credential CLI: install (stdin), check, prepare, scan; the token is never printed", () => {
  const d = tmpDir("cicli-");
  const f = join(d, "sub", "claude-credential.json");
  const t = tok();
  const inst = run(["install", "claude", "--dest", f, "--subscription", "max"], { input: t + "\n" });
  assert.equal(inst.status, 0, inst.stderr);
  assert.equal(statSync(f).mode & 0o777, 0o600);
  assert.equal(statSync(dirname(f)).mode & 0o777, 0o700);
  const chk = run(["check", "claude", "--src", f, "--min-seconds", "28800"]);
  assert.equal(chk.status, 0, chk.stderr);
  const miss = run(["check", "claude", "--src", join(d, "absent.json")]);
  assert.equal(miss.status, 3);
  assert.match(miss.stderr, /claude setup-token/);
  assert.match(miss.stderr, /credential\.mjs install claude/);
  const tar = join(d, "c.tar");
  const prep = run(["prepare", "claude", "--src", f, "--out", tar]);
  assert.equal(prep.status, 0, prep.stderr);
  assert.equal(statSync(tar).mode & 0o777, 0o600);
  assert.equal(run(["prepare", "claude", "--src", f, "--out", tar]).status !== 0, true, "prepare never overwrites");
  const out = join(d, "out"); mkdirSync(out);
  writeFileSync(join(out, "clean.log"), "ok\n");
  assert.equal(run(["scan", "--src", f, out]).status, 0);
  writeFileSync(join(out, "leak.log"), `Authorization: Bearer ${t}\n`);
  const hit = run(["scan", "--src", f, out]);
  assert.equal(hit.status, 1);
  assert.match(hit.stderr, /leak\.log/);
  for (const r of [inst, chk, miss, prep, hit]) {
    for (const n of needles(t)) assert.ok(!(r.stdout + r.stderr).includes(n.toString()), "no piece of the token on stdout/stderr");
  }
  chmodSync(f, 0o640);
  assert.equal(run(["check", "claude", "--src", f]).status, 3, "a group-readable file is refused");
  assert.deepEqual(readdirSync(dirname(f)).sort(), ["claude-credential.json"], "install leaves no temp file");
});

test("credential CLI: install refuses without --subscription max|pro (the eval runners and `claude auth status` read the plan from the file)", () => {
  const d = tmpDir("cicli-");
  const f = join(d, "c.json");
  for (const extra of [[], ["--subscription", "free"]]) {
    const r = run(["install", "claude", "--dest", f, ...extra], { input: tok() + "\n" });
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, /--subscription max\|pro/);
    assert.ok(!existsSync(f));
  }
});

test("credential: the installed shape is a login the eval runners accept (a Pro/Max subscriptionType, an access token)", () => {
  // eval/lib/paired/paired-subscription.ts isolatedSubscriptionLogin's rule;
  // `claude auth status` on this shape says loggedIn, claude.ai, the plan
  // (checked on 2.1.273 and 2.1.283 with a synthetic token, 2026-09-29).
  for (const plan of ["max", "pro"]) {
    const o = JSON.parse(installShape(tok(), { subscription: plan }).json).claudeAiOauth;
    assert.equal(typeof o.accessToken, "string");
    assert.ok(["max", "pro"].includes(String(o.subscriptionType)));
  }
});

// ── the api kind: the nightly's API lane (continuous-integration.md §9.8) ──────
import { parseApi, installApi, refusedKey, TAR_PATH } from "../ci/credential.mjs";
const antKey = () => `sk-ant-api03-TEST${randomBytes(60).toString("base64url")}`;
const oaiKey = () => `sk-proj-TEST${randomBytes(60).toString("base64url")}`;

test("credential api: an Anthropic and an OpenAI key are installed one at a time into one file, the other kept", () => {
  const a = antKey(), o = oaiKey();
  const one = installApi("", "anthropic", a);
  assert.ok(one.ok);
  const both = installApi(one.json, "openai", o);
  assert.ok(both.ok);
  assert.deepEqual(JSON.parse(both.json), { anthropic: a, openai: o });
  const again = installApi(both.json, "anthropic", antKey());
  assert.equal(JSON.parse(again.json).openai, o, "replacing one key keeps the other");
  const r = parseApi(both.json);
  assert.ok(r.ok);
  assert.deepEqual(r.providers, ["anthropic", "openai"]);
  assert.deepEqual(r.tokens.sort(), [a, o].sort());
  assert.equal(r.secondsLeft, null);
});

test("credential api: OAuth tokens, admin keys, the wrong vendor's key, extra fields and an empty file are refused", () => {
  assert.match(refusedKey("anthropic", "sk-ant-oat01-" + "x".repeat(40)), /subscription lane/);
  assert.match(refusedKey("anthropic", "sk-ant-ort01-" + "x".repeat(40)), /subscription lane/);
  assert.match(refusedKey("anthropic", "sk-ant-admin01-" + "x".repeat(40)), /admin/);
  assert.match(refusedKey("openai", "sk-admin-" + "x".repeat(40)), /admin/);
  assert.match(refusedKey("openai", antKey()), /Anthropic key/);
  assert.match(refusedKey("anthropic", oaiKey()), /not an Anthropic API key/);
  assert.match(refusedKey("openai", "hello"), /not an OpenAI API key/);
  assert.match(refusedKey("gemini", "k"), /unknown provider/);
  assert.equal(refusedKey("openai", `sk-${"a".repeat(48)}`), null, "a legacy user key");
  assert.equal(refusedKey("anthropic", "sk-ant-usr01-" + "u".repeat(90)), null, "the Console's newer sk-ant-usr key");
  assert.match(refusedKey("openai", "sk-ant-usr01-" + "u".repeat(90)), /Anthropic key/);
  assert.equal(parseApi("").ok, false);
  assert.equal(parseApi("{}").ok, false);
  assert.equal(parseApi("[]").ok, false);
  assert.match(parseApi(JSON.stringify({ anthropic: antKey(), refresh: "z" })).reason, /fields other than/);
  assert.match(parseApi(JSON.stringify({ openai: "sk-ant-api03-" + "k".repeat(40) })).reason, /^openai: /);
  assert.equal(installApi("not json", "openai", oaiKey()).ok, false, "an unusable existing file is not silently replaced");
});

test("credential api: the default path, the disk and the canary cover every key", () => {
  assert.ok(defaultPath("api", { HOME: "/x" }).endsWith("/.config/mandu-ci/api-keys.json"));
  assert.equal(defaultPath("api", { MANDU_CI_API_CREDENTIAL: "/k/f" }), "/k/f");
  assert.notEqual(defaultPath("api", { MANDU_CI_CLAUDE_CREDENTIAL: "/k/f" }), "/k/f", "the claude override is the claude kind's");
  const a = antKey(), o = oaiKey();
  const r = parseApi(JSON.stringify({ anthropic: a, openai: o }));
  const d = tmpDir("ciapi-");
  writeFileSync(join(d, "c.tar"), credentialTar(r.json, "api"));
  const lines = spawnSync("tar", ["-tvf", join(d, "c.tar")], { encoding: "utf8" }).stdout.trim().split("\n");
  assert.deepEqual(TAR_PATH.api, ["api/", "api/keys.json"]);
  assert.match(lines[0], /^drwx------ .* api\/$/);
  assert.match(lines[1], /^-rw------- .* api\/keys\.json$/);
  assert.equal(spawnSync("tar", ["-xOf", join(d, "c.tar"), "api/keys.json"], { encoding: "utf8" }).stdout, r.json);
  // The canary strips each vendor's prefix and finds 19 characters of EITHER key.
  const out = join(d, "out"); mkdirSync(out);
  writeFileSync(join(out, "a.log"), "clean\n");
  assert.deepEqual(scan(r.tokens, [out]).found, []);
  writeFileSync(join(out, "b.log"), `x ${o.slice(20, 40)} y`);
  assert.deepEqual(scan(r.tokens, [out]).found, [join(out, "b.log")]);
  assert.ok(needles(o).slice(1).every((n) => !n.toString().startsWith("proj-")), "the sk-proj- prefix is not part of a piece");
});

test("credential api CLI: install per provider (stdin), check, prepare, scan api; no key is ever printed", () => {
  const d = tmpDir("ciapicli-");
  const f = join(d, "sub", "api-keys.json");
  const a = antKey(), o = oaiKey();
  const i1 = run(["install", "api", "--provider", "anthropic", "--dest", f], { input: a + "\n" });
  assert.equal(i1.status, 0, i1.stderr);
  const i2 = run(["install", "api", "--provider", "openai", "--dest", f], { input: o + "\n" });
  assert.equal(i2.status, 0, i2.stderr);
  assert.match(i2.stderr, /keys: anthropic, openai/);
  assert.equal(statSync(f).mode & 0o777, 0o600);
  assert.equal(run(["install", "api", "--dest", f], { input: a + "\n" }).status, 2, "--provider is required");
  assert.equal(run(["install", "api", "--provider", "openai", "--dest", f], { input: a + "\n" }).status, 3, "an Anthropic key as openai is refused");
  const chk = run(["check", "api", "--src", f, "--min-seconds", "99999999"]);
  assert.equal(chk.status, 0, chk.stderr);
  assert.match(chk.stderr, /API keys \(anthropic, openai\); usable/);
  const miss = run(["check", "api", "--src", join(d, "absent.json")]);
  assert.equal(miss.status, 3);
  assert.match(miss.stderr, /credential\.mjs install api --provider anthropic/);
  const prep = run(["prepare", "api", "--src", f, "--out", join(d, "c.tar")]);
  assert.equal(prep.status, 0, prep.stderr);
  const out = join(d, "out"); mkdirSync(out);
  writeFileSync(join(out, "leak.log"), `OPENAI_API_KEY=${o}\n`);
  const hit = run(["scan", "api", "--src", f, out]);
  assert.equal(hit.status, 1);
  assert.equal(run(["scan", "--src", f, out]).status, 2, "without the kind, scan reads the file as claude's and refuses it");
  for (const r of [i1, i2, chk, miss, prep, hit]) {
    for (const k of [a, o]) for (const n of needles(k)) assert.ok(!(r.stdout + r.stderr).includes(n.toString()), "no piece of a key on stdout/stderr");
  }
});

// ── the codex kind (continuous-integration.md §9.8 "The Codex sign-in") ─────────
// The subscription lane's Codex sign-in: the host keeps the DEDICATED CI
// account's full sign-in and refreshes it; the guest gets the id and access
// token only (refresh_token ""), and every one of the host's tokens, the
// refresh token included, is a canary needle.
import { parseCodex, reduceCodex, parseKinds, refreshCodex, codexRefreshUrl, codexNeedsRefresh, jwtExp, CODEX_CLIENT_ID } from "../ci/credential.mjs";
import { createServer } from "node:http";
import { spawn } from "node:child_process";

const b64j = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (expS, sig = randomBytes(96).toString("base64url")) =>
  `${b64j({ alg: "RS256", typ: "JWT" })}.${b64j({ exp: expS, "https://api.openai.com/auth": { chatgpt_account_id: "acct-test" } })}.TEST${sig}`;
const rtok = () => `rt_TEST${randomBytes(48).toString("base64url")}`;
const NOW_S = Math.floor(NOW / 1000);
const signIn = (over = {}, tokOver = {}) => ({
  OPENAI_API_KEY: null,
  tokens: { id_token: jwt(NOW_S + 240 * 3600), access_token: jwt(NOW_S + 240 * 3600), refresh_token: rtok(), account_id: "acct-test", ...tokOver },
  last_refresh: new Date(NOW).toISOString(), ...over,
});
const writeSecret = (f, o) => { mkdirSync(dirname(f), { recursive: true, mode: 0o700 }); writeFileSync(f, typeof o === "string" ? o : JSON.stringify(o), { mode: 0o600 }); chmodSync(f, 0o600); };
const allTokens = (a) => [a.tokens.access_token, a.tokens.id_token, a.tokens.refresh_token];
const noTokenIn = (text, tokens) => { for (const t of tokens) for (const n of needles(t)) assert.ok(!text.includes(n.toString()), "no piece of a token printed"); };

test("credential kinds: the subscription kinds combine, api stands alone", () => {
  for (const s of ["claude", "codex", "api", "claude,codex", "codex,claude"]) assert.ok(parseKinds(s).ok, s);
  assert.match(parseKinds("claude,api").reason, /api does not combine/);
  assert.match(parseKinds("api,codex").reason, /api does not combine/);
  assert.match(parseKinds("claude,claude").reason, /twice/);
  assert.match(parseKinds("gemini").reason, /unknown credential kind/);
  assert.equal(parseKinds("").ok, false);
  assert.equal(parseKinds("claude,").ok, false);
  assert.ok(defaultPath("codex", { HOME: "/x" }).endsWith("/.config/mandu-ci/codex-auth.json"));
  assert.equal(defaultPath("codex", { MANDU_CI_CODEX_CREDENTIAL: "/c/f" }), "/c/f");
});

test("credential codex: the host file is a full ChatGPT sign-in; the guest's copy has no refresh token", () => {
  const a = signIn({}, { future_field: "X-secret" });
  const p = parseCodex(JSON.stringify(a));
  assert.ok(p.ok, p.reason);
  assert.equal(p.exp, NOW_S + 240 * 3600);
  assert.deepEqual(p.tokens, allTokens(a));
  assert.ok(!JSON.stringify(p.auth.tokens).includes("X-secret"), "unknown token fields are not kept");
  const r = reduceCodex(p, NOW + 3600_000, 9 * 3600);
  assert.ok(r.ok, r.reason);
  const g = JSON.parse(r.json);
  assert.deepEqual(Object.keys(g).sort(), ["OPENAI_API_KEY", "last_refresh", "tokens"]);
  assert.deepEqual(g.tokens, { id_token: a.tokens.id_token, access_token: a.tokens.access_token, refresh_token: "", account_id: "acct-test" });
  assert.equal(g.last_refresh, new Date(NOW + 3600_000).toISOString(), "last_refresh is the copy time: Codex's own refresh never comes due in a run");
  assert.ok(!r.json.includes(a.tokens.refresh_token));
  assert.equal(r.secondsLeft, 239 * 3600);
  // Refusals.
  assert.match(parseCodex(JSON.stringify(signIn({ OPENAI_API_KEY: "sk-proj-x" }))).reason, /saved API key/);
  assert.match(parseCodex(JSON.stringify(signIn({}, { refresh_token: "" }))).reason, /no refresh token/);
  assert.match(parseCodex(JSON.stringify(signIn({}, { refresh_token: undefined }))).reason, /no refresh token/);
  assert.match(parseCodex(JSON.stringify(signIn({}, { access_token: "sk-proj-abc" }))).reason, /access_token is not a JWT/);
  assert.match(parseCodex(JSON.stringify(signIn({}, { id_token: undefined }))).reason, /id_token is not a JWT/);
  assert.match(parseCodex(JSON.stringify(signIn({}, { access_token: `${b64j({ alg: "none" })}.${b64j({ sub: "x" })}.sigsigsig` }))).reason, /no expiry/);
  assert.match(parseCodex(JSON.stringify({ OPENAI_API_KEY: null })).reason, /no tokens object/);
  assert.equal(parseCodex("[]").ok, false);
  assert.equal(parseCodex("").ok, false);
  assert.match(reduceCodex(p, NOW + 239 * 3600_000, 9 * 3600).reason, /has 3600s left, the run needs 32400s.*refresh codex/);
  assert.equal(jwtExp("a.b.c"), null);
});

test("credential codex: the refresh endpoint is https, or http to a literal loopback address", () => {
  assert.equal(codexRefreshUrl({}).url, "https://auth.openai.com/oauth/token");
  assert.ok(codexRefreshUrl({ MANDU_CI_CODEX_REFRESH_URL: "http://127.0.0.1:9/t" }).ok);
  assert.ok(codexRefreshUrl({ MANDU_CI_CODEX_REFRESH_URL: "http://[::1]:9/t" }).ok);
  for (const u of ["http://localhost:9/t", "http://10.0.0.1/t", "ftp://127.0.0.1/t", "not a url"]) {
    assert.equal(codexRefreshUrl({ MANDU_CI_CODEX_REFRESH_URL: u }).ok, false, u);
  }
  const p = parseCodex(JSON.stringify(signIn()));
  assert.equal(codexNeedsRefresh(p, NOW, undefined), true, "without --min-seconds, always");
  assert.equal(codexNeedsRefresh(p, NOW, 3600), false, "fresh and recent");
  assert.equal(codexNeedsRefresh(p, NOW, 241 * 3600), true, "too little left");
  assert.equal(codexNeedsRefresh(p, NOW + 8 * 86400_000, 0), true, "a week since the last refresh");
});

/** A stand-in token endpoint that rotates: each refresh token works once. */
async function tokenStub({ delayMs = 0, fail = null } = {}) {
  const seen = [];
  let current = null;
  const srv = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => setTimeout(() => {
      const j = JSON.parse(body);
      seen.push({ method: req.method, url: req.url, ctype: req.headers["content-type"], body: j });
      const send = (st, o) => { res.writeHead(st, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
      if (fail) return send(fail.status, fail.body);
      if (current !== null && j.refresh_token !== current) return send(401, { error: { code: "refresh_token_reused", message: "detail with a token-like string rt_LEAKY" } });
      current = rtok();
      send(200, { id_token: jwt(Math.floor(Date.now() / 1000) + 240 * 3600), access_token: jwt(Math.floor(Date.now() / 1000) + 240 * 3600), refresh_token: current });
    }, delayMs));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}/oauth/token`, seen, setCurrent: (t) => { current = t; }, close: () => new Promise((r) => srv.close(r)) };
}

test("credential codex: refresh posts what Codex posts, writes the rotated sign-in back (0600), and a refusal leaves the file as it was", async () => {
  const d = tmpDir("cicodex-");
  const f = join(d, "codex-auth.json");
  const a = signIn({ last_refresh: new Date(Date.now() - 86400_000).toISOString() }, {
    access_token: jwt(Math.floor(Date.now() / 1000) + 3600), id_token: jwt(Math.floor(Date.now() / 1000) + 3600) });
  writeSecret(f, a);
  const stub = await tokenStub();
  stub.setCurrent(a.tokens.refresh_token);
  try {
    const env = { MANDU_CI_CODEX_REFRESH_URL: stub.url };
    const skip = await refreshCodex(f, { env, minSeconds: 60 });
    assert.deepEqual([skip.ok, skip.refreshed], [true, false], "fresh enough: nothing sent");
    assert.equal(stub.seen.length, 0);
    const r = await refreshCodex(f, { env, minSeconds: 7200 });
    assert.ok(r.ok, r.reason);
    assert.equal(r.refreshed, true);
    assert.deepEqual(stub.seen[0], { method: "POST", url: "/oauth/token", ctype: "application/json",
      body: { client_id: CODEX_CLIENT_ID, grant_type: "refresh_token", refresh_token: a.tokens.refresh_token } });
    const after = JSON.parse(readFileSync(f, "utf8"));
    assert.notEqual(after.tokens.refresh_token, a.tokens.refresh_token, "the rotated refresh token is written back");
    assert.notEqual(after.tokens.access_token, a.tokens.access_token);
    assert.equal(after.tokens.account_id, "acct-test", "fields the answer leaves out are kept");
    assert.ok(Date.now() - Date.parse(after.last_refresh) < 60_000);
    assert.equal(statSync(f).mode & 0o777, 0o600);
    assert.deepEqual(readdirSync(d), ["codex-auth.json"], "no temporary file left");
    // A refused refresh (the token was spent elsewhere): the file is untouched,
    // and only the error CODE is reported, never the vendor's text.
    stub.setCurrent("rt_someone-else-refreshed");
    const before = readFileSync(f);
    const bad = await refreshCodex(f, { env });
    assert.equal(bad.ok, false);
    assert.match(bad.reason, /already used.*install codex/);
    assert.ok(!bad.reason.includes("rt_LEAKY"));
    assert.ok(readFileSync(f).equals(before), "a failed refresh leaves the file as it was");
  } finally { await stub.close(); }
  // Unreachable endpoint and a malformed answer: unchanged too.
  const before = readFileSync(f);
  const down = await refreshCodex(f, { env: { MANDU_CI_CODEX_REFRESH_URL: "http://127.0.0.1:1/t" } });
  assert.match(down.reason, /request failed.*unchanged/);
  const junk = await tokenStub({ fail: { status: 200, body: { access_token: "not-a-jwt" } } });
  try {
    const r = await refreshCodex(f, { env: { MANDU_CI_CODEX_REFRESH_URL: junk.url } });
    assert.match(r.reason, /not usable.*unchanged/);
  } finally { await junk.close(); }
  assert.ok(readFileSync(f).equals(before));
  assert.match((await refreshCodex(f, { env: { MANDU_CI_CODEX_REFRESH_URL: "http://10.1.1.1/t" } })).reason, /literal loopback/);
});

const runAsync = (args, env) => new Promise((resolve) => {
  const c = spawn("node", [CRED_CLI, ...args], { env: { ...process.env, ...env } });
  let out = "";
  c.stdout.on("data", (b) => (out += b)); c.stderr.on("data", (b) => (out += b));
  c.on("close", (status) => resolve({ status, out }));
});

test("credential codex CLI: two refreshes at once are serialized by the lock (the second presents the rotated token)", async () => {
  const d = tmpDir("cicodexlock-");
  const f = join(d, "codex-auth.json");
  const a = signIn();
  writeSecret(f, a);
  const stub = await tokenStub({ delayMs: 300 });
  stub.setCurrent(a.tokens.refresh_token);
  try {
    const env = { MANDU_CI_CODEX_REFRESH_URL: stub.url, MANDU_CI_CODEX_CREDENTIAL: f, MANDU_CI_CODEX_LOCKED: "" };
    const [r1, r2] = await Promise.all([runAsync(["refresh", "codex"], env), runAsync(["refresh", "codex"], env)]);
    assert.equal(r1.status, 0, r1.out);
    assert.equal(r2.status, 0, r2.out);
    assert.equal(stub.seen.length, 2);
    assert.notEqual(stub.seen[0].body.refresh_token, stub.seen[1].body.refresh_token, "the second refresh used the first one's rotated token");
    const final = JSON.parse(readFileSync(f, "utf8"));
    noTokenIn(r1.out + r2.out, [...allTokens(a), ...allTokens(final)]);
    assert.match(r1.out, /codex: refreshed; the access token has \d+ h left/);
    // A refusal exits 3 with the reason.
    stub.setCurrent("rt_elsewhere");
    const bad = await runAsync(["refresh", "codex"], env);
    assert.equal(bad.status, 3, bad.out);
    assert.match(bad.out, /not refreshed: the refresh was refused/);
  } finally { await stub.close(); }
});

test("credential codex CLI: install refuses a personal sign-in and a key; check, prepare (with claude) and scan cover every token", () => {
  const d = tmpDir("cicodexcli-");
  const home = join(d, "home");
  const own = join(home, ".codex", "auth.json");
  const a = signIn({}, { access_token: jwt(Math.floor(Date.now() / 1000) + 240 * 3600), id_token: jwt(Math.floor(Date.now() / 1000) + 240 * 3600) });
  writeSecret(own, a);
  const dest = join(d, "cfg", "codex-auth.json");
  const env = { ...process.env, HOME: home, CODEX_HOME: "" };
  const mine = run(["install", "codex", "--from", own, "--dest", dest], { env });
  assert.equal(mine.status, 3);
  assert.match(mine.stderr, /this account's own Codex sign-in.*DEDICATED CI account/);
  const other = join(d, "throwaway", "auth.json");
  writeSecret(other, a);
  const viaCodexHome = run(["install", "codex", "--from", other, "--dest", dest], { env: { ...env, CODEX_HOME: dirname(other) } });
  assert.equal(viaCodexHome.status, 3, "the sign-in CODEX_HOME points at is personal too");
  writeSecret(join(d, "key.json"), signIn({ OPENAI_API_KEY: "sk-proj-abcdefghijklmnopqrstuvwxyz" }));
  assert.equal(run(["install", "codex", "--from", join(d, "key.json"), "--dest", dest], { env }).status, 3);
  assert.equal(run(["install", "codex", "--dest", dest], { env }).status, 2, "--from is required");
  const inst = run(["install", "codex", "--from", other, "--dest", dest], { env });
  assert.equal(inst.status, 0, inst.stderr);
  assert.equal(statSync(dest).mode & 0o777, 0o600);
  assert.equal(JSON.parse(readFileSync(dest, "utf8")).tokens.refresh_token, a.tokens.refresh_token, "the host keeps the full sign-in");
  // check / prepare with both subscription kinds, each from its own path.
  const cf = join(d, "cfg", "claude-credential.json");
  const t = tok();
  assert.equal(run(["install", "claude", "--dest", cf, "--subscription", "max"], { input: t + "\n" }).status, 0);
  const kenv = { ...process.env, MANDU_CI_CODEX_CREDENTIAL: dest, MANDU_CI_CLAUDE_CREDENTIAL: cf };
  const chk = run(["check", "claude,codex", "--min-seconds", "28800"], { env: kenv });
  assert.equal(chk.status, 0, chk.stderr);
  assert.match(chk.stderr, /codex: Codex ChatGPT sign-in \(reduced: no refresh token\), \d+ days left; usable/);
  assert.equal(run(["check", "codex", "--min-seconds", String(241 * 3600)], { env: kenv }).status, 3, "too little left for the run");
  assert.equal(run(["check", "claude,api"], { env: kenv }).status, 2);
  assert.equal(run(["check", "claude,codex", "--src", dest], { env: kenv }).status, 2, "--src names one kind's file");
  const tar = join(d, "c.tar");
  const prep = run(["prepare", "claude,codex", "--out", tar, "--min-seconds", "28800"], { env: kenv });
  assert.equal(prep.status, 0, prep.stderr);
  const lines = spawnSync("tar", ["-tvf", tar], { encoding: "utf8" }).stdout.trim().split("\n");
  assert.deepEqual(lines.map((l) => l.split(/\s+/).pop()), ["claude/", "claude/.credentials.json", "codex/", "codex/auth.json"]);
  assert.match(lines[3], /^-rw------- /);
  const g = JSON.parse(spawnSync("tar", ["-xOf", tar, "codex/auth.json"], { encoding: "utf8" }).stdout);
  assert.equal(g.tokens.refresh_token, "");
  assert.equal(g.tokens.access_token, a.tokens.access_token);
  assert.ok(!readFileSync(tar).includes(Buffer.from(a.tokens.refresh_token)), "the refresh token never reaches the disk");
  // The canary: 19 characters of the access or id token's signature, of the
  // refresh token the guest never had, or of the claude token, are each found.
  const out = join(d, "out"); mkdirSync(out);
  writeFileSync(join(out, "clean.log"), `ok; another JWT with the same header and claims: ${jwt(NOW_S)}\n`);
  assert.equal(run(["scan", "claude,codex", out], { env: kenv }).status, 0, "a JWT's shared header and claims are not needles");
  for (const [name, leak] of [["access", a.tokens.access_token.slice(-40, -20)], ["id", a.tokens.id_token.slice(-30, -10)],
                              ["refresh", a.tokens.refresh_token.slice(10, 30)], ["claude", t.slice(30, 50)]]) {
    const dir = join(d, `leak-${name}`); mkdirSync(dir);
    writeFileSync(join(dir, "x.log"), `.. ${leak} ..\n`);
    assert.equal(run(["scan", "claude,codex", dir], { env: kenv }).status, 1, `the ${name} token is found`);
  }
  for (const r of [mine, inst, chk, prep]) noTokenIn(r.stdout + r.stderr, [...allTokens(a), t]);
});

// ── the tool kinds (continuous-integration.md §9.8 "Tool credentials") ──────
// A Docker personal access token (with the account's username) and a
// GitGuardian API token: tool credentials the subscription lane carries
// beside claude, each in its own host file, never in api-keys.json.
import { refusedTool, refusedDockerUser, parseTool, dockerUser, dockerUserFile, TOOL_KINDS, API_TOOL_KINDS } from "../ci/credential.mjs";
const dckTok = () => `dckr_pat_TEST${randomBytes(20).toString("base64url")}`;
const ggTok = () => `TEST${randomBytes(30).toString("hex")}`;
const toolTokenIn = (text, tokens) => { for (const t of tokens) for (const n of needles(t)) assert.ok(!text.includes(n.toString()), "no piece of a tool token printed"); };

test("credential tool kinds: they combine with the subscription kinds; docker alone also with api", () => {
  assert.deepEqual(TOOL_KINDS, ["docker", "gitguardian"]);
  assert.deepEqual(API_TOOL_KINDS, ["docker"]);
  for (const s of ["docker", "gitguardian", "claude,docker,gitguardian", "codex,gitguardian", "claude,codex,docker"]) assert.ok(parseKinds(s).ok, s);
  // the API lane's Docker Sandboxes side (2026-10-19): api with docker, either order
  for (const s of ["api,docker", "docker,api"]) assert.deepEqual(parseKinds(s), { ok: true, kinds: s.split(",") }, s);
  assert.match(parseKinds("api,gitguardian").reason, /api does not combine with gitguardian/);
  assert.match(parseKinds("api,docker,gitguardian").reason, /api does not combine with gitguardian/);
  assert.match(parseKinds("api,docker,claude").reason, /api does not combine with claude/);
  assert.match(parseKinds("api,api").reason, /twice/);
  assert.match(parseKinds("docker,docker").reason, /twice/);
  assert.ok(defaultPath("docker", { HOME: "/x" }).endsWith("/.config/mandu-ci/docker-token"));
  assert.ok(defaultPath("gitguardian", { HOME: "/x" }).endsWith("/.config/mandu-ci/gitguardian-token"));
  assert.equal(defaultPath("docker", { MANDU_CI_DOCKER_CREDENTIAL: "/d/t" }), "/d/t");
  assert.equal(defaultPath("gitguardian", { MANDU_CI_GITGUARDIAN_CREDENTIAL: "/g/t" }), "/g/t");
  assert.equal(dockerUserFile("/d/docker-token"), "/d/docker-user");
});

test("credential tool kinds: the shapes; another vendor's token, a model key and an inner space are refused, never quoted", () => {
  const d = dckTok(), g = ggTok();
  assert.equal(refusedTool("docker", d), null);
  assert.equal(refusedTool("gitguardian", g), null);
  assert.match(refusedTool("docker", "dckr_oat_" + "x".repeat(30)), /not a personal access token/);
  assert.match(refusedTool("docker", "x".repeat(40)), /not a Docker personal access token/);
  assert.match(refusedTool("docker", antKey()), /model credential/);
  assert.match(refusedTool("gitguardian", antKey()), /model credential/);
  assert.match(refusedTool("gitguardian", d), /another vendor's token/);
  assert.match(refusedTool("gitguardian", "ghp_" + "a".repeat(36)), /another vendor's token/);
  assert.match(refusedTool("gitguardian", "ggtt-v-abcdefghij"), /test token/);
  assert.match(refusedTool("gitguardian", "short"), /32-128/);
  assert.match(refusedTool("gitguardian", `${g.slice(0, 20)} ${g.slice(20)}`), /one word/);
  assert.match(refusedTool("slack", g), /unknown tool credential/);
  for (const why of [refusedTool("docker", "dckr_oat_" + "x".repeat(30)), refusedTool("gitguardian", d)]) assert.ok(!why.includes("x".repeat(16)) && !why.includes(d.slice(9)));
  assert.equal(refusedDockerUser("ci-user"), null);
  assert.match(refusedDockerUser("ci@example.test"), /email; sbx login takes the Docker ID/, "sbx refuses an email login");
  assert.match(refusedDockerUser(""), /no Docker username/);
  assert.match(refusedDockerUser("two words"), /one word/);
  assert.match(refusedDockerUser(d), /looks like a token/);
});

test("credential tool kinds: the guest's JSON, the username from env or the file beside, the disk and the canary", () => {
  const d = dckTok(), g = ggTok();
  assert.deepEqual(JSON.parse(parseTool("docker", d + "\n", "ci-user").json), { username: "ci-user", token: d });
  assert.deepEqual(JSON.parse(parseTool("gitguardian", g).json), { token: g });
  assert.equal(parseTool("docker", "", "u").ok, false);
  const dir = tmpDir("citool-");
  const tf = join(dir, "docker-token");
  writeFileSync(tf, d, { mode: 0o600 });
  assert.match(dockerUser(tf, {}).reason, /no Docker username/);
  assert.equal(dockerUser(tf, {}).absent, true);
  assert.equal(dockerUser(tf, { MANDU_CI_DOCKER_USER: "env-user" }).user, "env-user");
  writeFileSync(join(dir, "docker-user"), "file-user\n");
  assert.equal(dockerUser(tf, {}).user, "file-user");
  assert.equal(dockerUser(tf, { MANDU_CI_DOCKER_USER: "env-user" }).user, "env-user", "the variable wins over the file");
  writeFileSync(join(dir, "c.tar"), credentialTar([{ kind: "docker", json: parseTool("docker", d, "file-user").json }, { kind: "gitguardian", json: parseTool("gitguardian", g).json }]));
  const lines = spawnSync("tar", ["-tvf", join(dir, "c.tar")], { encoding: "utf8" }).stdout.trim().split("\n");
  assert.deepEqual(lines.map((l) => l.split(/\s+/).pop()), ["docker/", "docker/auth.json", "gitguardian/", "gitguardian/key.json"]);
  assert.deepEqual(TAR_PATH.docker, ["docker/", "docker/auth.json"]);
  assert.match(lines[1], /^-rw------- /);
  const out = join(dir, "out"); mkdirSync(out);
  writeFileSync(join(out, "clean.log"), "dckr_pat_ and a username file-user are not secrets\n");
  assert.deepEqual(scan([d, g], [out]).found, []);
  writeFileSync(join(out, "d.log"), `x ${d.slice(-19)} y`);
  writeFileSync(join(out, "g.log"), `Token ${g.slice(7, 26)}`);
  assert.deepEqual(scan([d, g], [out]).found.sort(), [join(out, "d.log"), join(out, "g.log")]);
  assert.ok(needles(d).slice(1).every((n) => !n.toString().startsWith("dckr_pat_")), "the dckr_pat_ prefix is not part of a piece");
});

test("credential tool CLI: `install api --provider docker|gitguardian` and `install docker|gitguardian` write their own files, bare, 0600; never api-keys.json; no token printed", () => {
  const dir = tmpDir("citoolcli-");
  const cfg = join(dir, "cfg");
  const tf = join(cfg, "docker-token"), gf = join(cfg, "gitguardian-token"), af = join(cfg, "api-keys.json");
  const d = dckTok(), g = ggTok();
  const env = { ...process.env, MANDU_CI_DOCKER_USER: "" };
  // Docker: the token, then the username on the next line (the terminal's echoed prompt).
  const i1 = run(["install", "api", "--provider", "docker", "--dest", tf], { input: `${d}\nci-user\n`, env });
  assert.equal(i1.status, 0, i1.stderr);
  assert.equal(readFileSync(tf, "utf8"), d, "the bare token, no newline");
  assert.equal(readFileSync(join(cfg, "docker-user"), "utf8"), "ci-user");
  assert.equal(statSync(tf).mode & 0o777, 0o600);
  assert.equal(statSync(join(cfg, "docker-user")).mode & 0o777, 0o600);
  assert.ok(!existsSync(af), "never into api-keys.json");
  // A second install keeps the username file and asks nothing more.
  const d2 = dckTok();
  const i2 = run(["install", "docker", "--dest", tf], { input: `${d2}\n`, env });
  assert.equal(i2.status, 0, i2.stderr);
  assert.match(i2.stderr, /username ci-user from /);
  assert.equal(readFileSync(tf, "utf8"), d2);
  // GitGuardian, both forms; no newline in the input either.
  const i3 = run(["install", "api", "--provider", "gitguardian", "--dest", gf], { input: g });
  assert.equal(i3.status, 0, i3.stderr);
  assert.equal(readFileSync(gf, "utf8"), g);
  assert.equal(statSync(gf).mode & 0o777, 0o600);
  const i4 = run(["install", "gitguardian", "--dest", gf], { input: `${g}\n` });
  assert.equal(i4.status, 0, i4.stderr);
  assert.ok(!existsSync(af));
  // Refusals: the wrong tool's token, a model key, no --provider.
  const bad1 = run(["install", "gitguardian", "--dest", gf], { input: `${d}\n` });
  assert.equal(bad1.status, 3);
  const bad2 = run(["install", "api", "--provider", "docker", "--dest", join(dir, "other")], { input: `${antKey()}\nu\n`, env });
  assert.equal(bad2.status, 3);
  assert.ok(!existsSync(join(dir, "other")));
  const noprov = run(["install", "api", "--dest", af], { input: "" });
  assert.equal(noprov.status, 2);
  assert.match(noprov.stderr, /--provider anthropic\|openai .* or docker\|gitguardian/);
  // check, prepare, scan.
  const kenv = { ...env, MANDU_CI_DOCKER_CREDENTIAL: tf, MANDU_CI_GITGUARDIAN_CREDENTIAL: gf };
  const chk = run(["check", "docker,gitguardian"], { env: kenv });
  assert.equal(chk.status, 0, chk.stderr);
  assert.match(chk.stderr, /docker: Docker personal access token \(user ci-user\); usable/);
  assert.match(chk.stderr, /gitguardian: GitGuardian API token; usable/);
  const tar = join(dir, "c.tar");
  const prep = run(["prepare", "docker,gitguardian", "--out", tar], { env: kenv });
  assert.equal(prep.status, 0, prep.stderr);
  assert.deepEqual(JSON.parse(spawnSync("tar", ["-xOf", tar, "docker/auth.json"], { encoding: "utf8" }).stdout), { username: "ci-user", token: d2 });
  // The username missing: check says what to add, and `install docker-user` adds it.
  const lone = join(dir, "lone", "docker-token");
  mkdirSync(dirname(lone), { mode: 0o700 }); writeFileSync(lone, d, { mode: 0o600 });
  const nouser = run(["check", "docker", "--src", lone], { env });
  assert.equal(nouser.status, 3);
  assert.match(nouser.stderr, /no Docker username/);
  assert.match(nouser.stderr, /install docker-user/);
  const addu = run(["install", "docker-user", "--dest", lone], { input: "lone-user\n" });
  assert.equal(addu.status, 0, addu.stderr);
  assert.equal(run(["check", "docker", "--src", lone], { env }).status, 0);
  const gone = run(["check", "gitguardian", "--src", join(dir, "absent")]);
  assert.equal(gone.status, 3);
  assert.match(gone.stderr, /credential\.mjs install gitguardian/);
  // The canary: scan needs no username.
  const out = join(dir, "out"); mkdirSync(out);
  writeFileSync(join(out, "leak.log"), `GITGUARDIAN_API_KEY=${g}\n`);
  assert.equal(run(["scan", "gitguardian", "--src", gf, out]).status, 1);
  assert.equal(run(["scan", "docker", "--src", lone, out], { env: { ...env, MANDU_CI_DOCKER_USER: "" } }).status, 0, "scan reads the token only");
  for (const r of [i1, i2, i3, i4, bad1, bad2, chk, prep, nouser, addu, gone]) toolTokenIn(r.stdout + r.stderr, [d, d2, g]);
});
