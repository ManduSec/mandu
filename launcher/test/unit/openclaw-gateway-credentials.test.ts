/**
 * openclaw-gateway-credentials — OpenClaw's Gateway token and password in the
 * run config carry the placeholder the environment does
 * (src/openclaw-gateway-credentials.ts; confidentiality-plan-10 §11.4).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  openclawArgvCredentials, openclawGatewayCredentials, pinArgvGatewayCredentials, pinOpenclawGatewayCredentials, pinRunConfigGatewayCredentials,
  type CredentialArbiter,
} from "../../src/openclaw-gateway-credentials.js";

const doc = () => ({
  gateway: {
    port: 18789,
    auth: { mode: "token", token: "tok-real-1", password: "pw-real" },
    remote: { token: "tok-real-1", password: "${OPENCLAW_GATEWAY_PASSWORD}" },
  },
  models: { providers: {} },
});

test("the literal Gateway credentials of a config are found; an environment reference, an empty value and a placeholder are not", () => {
  assert.deepEqual(openclawGatewayCredentials(doc()), [
    { field: "gateway.auth.token", kind: "token", value: "tok-real-1" },
    { field: "gateway.auth.password", kind: "password", value: "pw-real" },
    { field: "gateway.remote.token", kind: "token", value: "tok-real-1" },
  ]);
  assert.deepEqual(openclawGatewayCredentials({ gateway: { auth: { token: "" }, remote: { token: "$MDU:nomodel_Env[1a2b].OPENCLAW_GATEWAY_TOKEN" } } }), []);
  assert.deepEqual(openclawGatewayCredentials({ models: {} }), []);
});

test("pinning puts each value's placeholder in every field that holds it, and leaves the rest of the config", () => {
  const d = doc();
  const placeholders = new Map([["tok-real-1", "$MDU:nomodel_Env[aaaa].OPENCLAW_GATEWAY_TOKEN"]]);
  const { doc: out, pinned } = pinOpenclawGatewayCredentials(d, placeholders);
  assert.deepEqual(pinned, ["gateway.auth.token", "gateway.remote.token"]);
  const gw = (out as { gateway: { auth: Record<string, unknown>; remote: Record<string, unknown>; port: number } }).gateway;
  assert.equal(gw.auth["token"], "$MDU:nomodel_Env[aaaa].OPENCLAW_GATEWAY_TOKEN");
  assert.equal(gw.remote["token"], "$MDU:nomodel_Env[aaaa].OPENCLAW_GATEWAY_TOKEN");
  assert.equal(gw.auth["password"], "pw-real", "a value with no placeholder is left");
  assert.equal(gw.remote["password"], "${OPENCLAW_GATEWAY_PASSWORD}", "a reference is left: OpenClaw resolves it from the masked environment");
  assert.equal(gw.port, 18789);
  assert.equal(d.gateway.auth.token, "tok-real-1", "the input is not changed");
});

/** A fake arbiter that mints like the real one: one random-looking name per
 *  (variable, value), the same on every call. */
function fakeArbiter(seen: Array<{ name: string; value: string }>): CredentialArbiter {
  const minted = new Map<string, string>();
  return {
    async registerEnvSecrets(vars) {
      seen.push(...vars);
      return {
        vars: vars.map((v) => {
          const k = `${v.name}\u0000${v.value}`;
          if (!minted.has(k)) minted.set(k, `$MDU:nomodel_Env[${(minted.size + 0xa1).toString(16)}].${v.name}`);
          return { name: v.name, symbol: minted.get(k)!, twin: minted.get(k)!, reason: "registered" };
        }),
      };
    },
  };
}

test("the run config is rewritten in place with the placeholders: each distinct value registered once under its kind's variable, the file's mode kept", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-ocgwcred-"));
  try {
    const path = join(dir, "openclaw.json");
    writeFileSync(path, JSON.stringify(doc()), { mode: 0o600 });
    const seen: Array<{ name: string; value: string }> = [];
    const logs: string[] = [];
    const r = await pinRunConfigGatewayCredentials(path, { arbiter: fakeArbiter(seen), log: (m) => logs.push(m) });
    assert.deepEqual(r.pinned, ["gateway.auth.token", "gateway.auth.password", "gateway.remote.token"]);
    assert.deepEqual(seen, [{ name: "OPENCLAW_GATEWAY_TOKEN", value: "tok-real-1" }, { name: "OPENCLAW_GATEWAY_PASSWORD", value: "pw-real" }]);
    const text = readFileSync(path, "utf8");
    assert.ok(!text.includes("tok-real-1") && !text.includes("pw-real"), `no real credential is left in the run config: ${text}`);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.ok(logs.some((l) => /Gateway credential .* is its placeholder in the run config/.test(l)), logs.join("\n"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an arbiter that cannot register leaves the run config as written and says so; a config with no credential is left alone", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-ocgwcred-"));
  try {
    const path = join(dir, "openclaw.json");
    writeFileSync(path, JSON.stringify(doc()));
    const before = readFileSync(path, "utf8");
    const logs: string[] = [];
    const r = await pinRunConfigGatewayCredentials(path, { arbiter: { registerEnvSecrets: async () => { throw new Error("down"); } }, log: (m) => logs.push(m) });
    assert.deepEqual(r.pinned, []);
    assert.match(r.status, /^error: down/);
    assert.equal(readFileSync(path, "utf8"), before);
    assert.ok(logs.some((l) => /WARNING: mandu: OpenClaw's Gateway credential in its config NOT masked/.test(l)));
    writeFileSync(path, JSON.stringify({ gateway: { port: 1 } }));
    assert.match((await pinRunConfigGatewayCredentials(path, { arbiter: fakeArbiter([]), log: () => {} })).status, /no literal Gateway credential/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the command line's Gateway credentials, both spellings: `--token <v>` and `--token=<v>`, `--password`; a reference, a placeholder and what follows `--` are left", () => {
  const argv = ["openclaw", "gateway", "run", "--port", "18789", "--token", "tok-a", "--password=pw-b", "--auth", "token"];
  assert.deepEqual(openclawArgvCredentials(argv), [
    { index: 6, flag: "--token", kind: "token", value: "tok-a", form: "split" },
    { index: 7, flag: "--password", kind: "password", value: "pw-b", form: "eq" },
  ]);
  assert.deepEqual(openclawArgvCredentials(["openclaw", "tui", "--token=tok-a"]).map((c) => c.form), ["eq"]);
  assert.deepEqual(openclawArgvCredentials(["openclaw", "gateway", "--token", "${OPENCLAW_GATEWAY_TOKEN}", "--password=$MDU:nomodel_Env[1a2b].OPENCLAW_GATEWAY_PASSWORD"]), []);
  assert.deepEqual(openclawArgvCredentials(["openclaw", "agent", "--", "--token", "tok-a"]), [], "after `--`: the program's own words");
  assert.deepEqual(openclawArgvCredentials(["openclaw", "gateway", "--token"]), [], "a flag with no value: OpenClaw's to refuse");
});

test("the launch's argv carries the placeholder in each spelling: the same one for the same value, the config's and the environment's", async () => {
  const seen: Array<{ name: string; value: string }> = [];
  const arb = fakeArbiter(seen);
  const logs: string[] = [];
  const out = await pinArgvGatewayCredentials(["openclaw", "gateway", "run", "--token", "tok-real-1", "--password=pw-real"], { arbiter: arb, log: (m) => logs.push(m) });
  const tok = out[4]!;
  assert.match(tok, /^\$MDU:nomodel_Env\[[0-9a-f]+\]\.OPENCLAW_GATEWAY_TOKEN$/);
  assert.match(out[5]!, /^--password=\$MDU:nomodel_Env\[[0-9a-f]+\]\.OPENCLAW_GATEWAY_PASSWORD$/);
  assert.ok(!out.join(" ").includes("tok-real-1") && !out.join(" ").includes("pw-real"), out.join(" "));
  assert.deepEqual(seen, [{ name: "OPENCLAW_GATEWAY_TOKEN", value: "tok-real-1" }, { name: "OPENCLAW_GATEWAY_PASSWORD", value: "pw-real" }]);
  // A client's `--token=` spelling of the same value: the same placeholder.
  const client = await pinArgvGatewayCredentials(["openclaw", "tui", "--token=tok-real-1"], { arbiter: arb, log: () => {} });
  assert.equal(client[2], `--token=${tok}`);
  assert.ok(logs.some((l) => /Gateway --token and --password on the command line is its placeholder/.test(l)), logs.join("\n"));
  // No credential: unchanged.
  assert.deepEqual(await pinArgvGatewayCredentials(["openclaw", "chat"], { arbiter: arb, log: () => {} }), ["openclaw", "chat"]);
});

test("a command-line credential the arbiter cannot register refuses the launch, naming the environment variable and the config key", async () => {
  await assert.rejects(
    pinArgvGatewayCredentials(["openclaw", "gateway", "run", "--token=tok-real-1"], { arbiter: { registerEnvSecrets: async () => { throw new Error("down"); } }, log: () => {} }),
    (e: Error) => /refusing to launch openclaw with its Gateway --token on the command line: the arbiter could not register it \(down\)/.test(e.message)
      && /OPENCLAW_GATEWAY_TOKEN/.test(e.message) && /gateway\.auth\.token/.test(e.message) && !e.message.includes("tok-real-1"),
  );
  await assert.rejects(pinArgvGatewayCredentials(["openclaw", "gateway", "--password", "pw"], { arbiter: {}, log: () => {} }), /cannot register it/);
  await assert.rejects(
    pinArgvGatewayCredentials(["openclaw", "gateway", "--token", "tok"], { arbiter: { registerEnvSecrets: async (vars) => ({ vars: vars.map((v) => ({ name: v.name, symbol: null, reason: "not a secret" })) }) }, log: () => {} }),
    /could not mint its placeholder/,
  );
});
