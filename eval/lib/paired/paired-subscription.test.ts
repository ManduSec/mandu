import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PAID_MODEL, summarizeUsage } from "./paired-budget.js";
import { SubscriptionBudget, SUBSCRIPTION_LIMITS, subscriptionHeaders, isolatedSubscriptionLogin, checkSubscriptionLogin } from "./paired-subscription.js";
import { launchSpec } from "./paired-config.js";
import { reviewPacket } from "./paired-runner.js";

const body = { model: PAID_MODEL, max_tokens: 4096 };
test("subscription limits cover both channels, count requests, and deadline", () => {
  let now = 0;
  const budget = new SubscriptionBudget(() => {}, () => now);
  for (let i = 0; i < SUBSCRIPTION_LIMITS.maxRequests; i++) budget.reserve("leg", i % 2 ? "inspection" : "model", body, i % 3 === 0);
  assert.throws(() => budget.reserve("leg", "model", body, false), /request limit/);
  const expired = new SubscriptionBudget(() => {}, () => now);
  now += SUBSCRIPTION_LIMITS.maxBatchMs;
  assert.throws(() => expired.reserve("leg", "model", body, false), /deadline/);
  const fresh = new SubscriptionBudget();
  assert.throws(() => fresh.reserve("leg", "model", { ...body, model: "other" }, false), /pinned/);
  assert.throws(() => fresh.reserve("leg", "model", { ...body, max_tokens: 4097 }, false), /allowance/);
  assert.equal(fresh.snapshot().requests.length, 0);
});

test("observed subscription usage stays separate from count estimates and unknown replies", () => {
  const b = new SubscriptionBudget();
  const id = b.reserve("leg", "model", body, false);
  b.settle(id, { input_tokens: 7, output_tokens: 0, cache_read_input_tokens: 10 }, 200);
  const count = b.reserve("leg", "model", body, true);
  b.settle(count, { input_tokens: 999 }, 200);
  const incomplete = b.reserve("leg", "model", body, false);
  assert.throws(() => b.settle(incomplete, {}, 200), /missing/);
  b.uncertain(incomplete, 429);
  const usage = summarizeUsage(b.snapshot(), "leg", "model");
  assert.equal(usage.status, "partial");
  assert.equal(usage.countRequests, 1);
  assert.equal(usage.observedResponses, 1);
  assert.deepEqual(usage.observedTokens, { uncachedInput: 7, cacheWrite: 0, cacheRead: 10, output: 0 });
  assert.throws(() => b.reserve("leg", "inspection", body, false), /stopped/);
});

test("native auth and beta headers survive; API-key fallback is refused", () => {
  assert.deepEqual(subscriptionHeaders({ authorization: "Bearer fake", "anthropic-beta": "native-beta", host: "local", connection: "close" }), { authorization: "Bearer fake", "anthropic-beta": "native-beta" });
  assert.throws(() => subscriptionHeaders({ "x-api-key": "fake" }), /API keys refused/);
  assert.throws(() => subscriptionHeaders({ authorization: "Bearer fake", "x-api-key": "fake" }), /API keys refused/);
});

test("disposable login copies only OAuth, removes secrets, and excludes user settings", () => {
  const source = mkdtempSync(join(tmpdir(), "paired-auth-test-"));
  try {
    writeFileSync(join(source, ".credentials.json"), JSON.stringify({ claudeAiOauth: { accessToken: "fake-private-token", subscriptionType: "max" }, apiKey: "unwanted" }));
    writeFileSync(join(source, "settings.json"), '{"apiKeyHelper":"unwanted"}');
    const login = isolatedSubscriptionLogin(source);
    assert.equal(statSync(join(login.configDir, ".credentials.json")).mode & 0o777, 0o600);
    assert.doesNotMatch(readFileSync(join(login.configDir, ".credentials.json"), "utf8"), /unwanted/);
    assert.equal(existsSync(join(login.configDir, "settings.json")), false);
    login.close(); assert.equal(existsSync(login.configDir), false);
    writeFileSync(join(source, ".credentials.json"), "{}");
    assert.throws(() => isolatedSubscriptionLogin(source), /login is required/);
  } finally { rmSync(source, { recursive: true, force: true }); }
});

test("subscription paired launch selects CLI quarantine without leaking ambient credentials", () => {
  const config = { model: PAID_MODEL, inspectionModel: PAID_MODEL, agentBinary: "claude", repoRoot: "/repo", timeoutMs: 180000, subscription: true };
  const w = "/tmp/mdu-e-x";
  const paths = { root: "/run", work: w, workspace: `${w}/workspace`, home: `${w}/home`, manduHome: `${w}/mandu-home`, runtime: `${w}/runtime`, tmp: `${w}/tmp`, sock: `${w}/a.sock` };
  for (const side of ["unwrapped", "wrapped-default"] as const) {
    const spec = launchSpec(config, side, paths, "task", { model: "https://127.0.0.1:1", inspection: "https://127.0.0.1:2", arbiterSock: paths.sock }, { ANTHROPIC_API_KEY: "ambient-secret", ANTHROPIC_AUTH_TOKEN: "ambient-secret", CLAUDE_CODE_OAUTH_TOKEN: "ambient-secret" });
    assert.equal(spec.env.ANTHROPIC_API_KEY, undefined);
    assert.equal(spec.env.MANDU_ULLM_API_KEY, undefined);
    assert.equal(spec.env.CLAUDE_CODE_MAX_OUTPUT_TOKENS, "4096");
    assert.doesNotMatch(JSON.stringify(spec), /ambient-secret/);
  }
  assert.doesNotMatch(reviewPacket(config), /UNAPPROVED|\$5|Before paid/);
  assert.match(reviewPacket(config), /After execution/);
});

// The nightly's credential (the shape scripts/ci/credential.mjs install
// writes: an access token, no refresh token, the plan in the file) is a login
// these runners accept. The agent's auth status reads that file only (no
// network); the stub below answers as it does (continuous-integration.md §9.7).
test("the nightly's reduced credential passes the isolated login and the auth-status check", () => {
  const source = mkdtempSync(join(tmpdir(), "paired-nightly-cred-"));
  try {
    const oauth = { accessToken: "sk-ant-oat01-synthetic", expiresAt: Date.now() + 365 * 86400_000, scopes: ["user:inference"], subscriptionType: "max" };
    writeFileSync(join(source, ".credentials.json"), JSON.stringify({ claudeAiOauth: oauth }));
    const login = isolatedSubscriptionLogin(source);
    assert.deepEqual(JSON.parse(readFileSync(join(login.configDir, ".credentials.json"), "utf8")), { claudeAiOauth: oauth });
    const observed = { loggedIn: true, authMethod: "claude.ai", apiProvider: "firstParty", email: null, orgId: null, orgName: null, subscriptionType: "max" };
    const stub = join(source, "claude-stub");
    writeFileSync(stub, `#!/bin/sh\n[ "$1 $2" = "auth status" ] && printf '%s' '${JSON.stringify(observed)}'\n`, { mode: 0o755 });
    assert.doesNotThrow(() => checkSubscriptionLogin(stub, { PATH: process.env.PATH ?? "" }, source));
    login.close();
    // Without the plan in the file, auth status reports none and the runners
    // refuse, which is why credential.mjs install requires it.
    writeFileSync(join(source, ".credentials.json"), JSON.stringify({ claudeAiOauth: { ...oauth, subscriptionType: undefined } }));
    assert.throws(() => isolatedSubscriptionLogin(source), /Pro\/Max CLI login is required/);
    writeFileSync(stub, `#!/bin/sh\nprintf '%s' '${JSON.stringify({ ...observed, subscriptionType: null })}'\n`, { mode: 0o755 });
    assert.throws(() => checkSubscriptionLogin(stub, { PATH: process.env.PATH ?? "" }, source), /not using a Pro\/Max subscription/);
  } finally { rmSync(source, { recursive: true, force: true }); }
});
