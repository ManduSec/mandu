/**
 * config.test — ~/.mandu/config.toml (packaging.md §7): the TOML subset
 * parser, the friendly-key → MANDU_* mapping, and the precedence contract
 * (flags > env > config > defaults). Reads are injected — no real filesystem.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseToml, configPath, loadConfigEnv, applyConfigDefaults, DEFAULT_CONFIG_TOML } from "../../src/config.js";
import { parse as parseIn } from "../../src/parse.js";
import { hermetic } from "../lib/test-runtime.js";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** parse with this file's own runtime dir when the env names none (test-runtime.ts). */
const parse = hermetic(parseIn, 1);

test("parseToml: bools / ints / quoted strings / inline comments; sections + junk ignored", () => {
  const t = parseToml([
    "# a comment",
    "[section]            # headers are ignored (flat namespace)",
    "reply-filter = false",
    "proxy-port = 8788",
    'arbiter-sock = "/run/a.sock"',
    "ullm-model = 'claude-haiku-4-5'",
    "net-proxy = true   # inline comment stripped",
    "garbage line without eq",
  ].join("\n"));
  assert.equal(t["reply-filter"], false);
  assert.equal(t["proxy-port"], 8788);
  assert.equal(t["arbiter-sock"], "/run/a.sock");
  assert.equal(t["ullm-model"], "claude-haiku-4-5");
  assert.equal(t["net-proxy"], true);
  assert.ok(!("garbage line without eq" in t));
});

test("configPath: <home>/config.toml, the home MANDU_HOME else ~/.mandu; null when none", () => {
  assert.equal(configPath({ MANDU_HOME: "/mh" }), "/mh/config.toml");
  assert.equal(configPath({ HOME: "/home/u" }), "/home/u/.mandu/config.toml");
  assert.equal(configPath({}), null);
  // Empty values count as unset (on-disk-layout.md §5).
  assert.equal(configPath({ MANDU_HOME: "", HOME: "" }), null);
  assert.equal(configPath({ MANDU_HOME: "", HOME: "/home/u" }), "/home/u/.mandu/config.toml");
  // The one home (phase 3c): XDG_CONFIG_HOME no longer places it.
  assert.equal(configPath({ XDG_CONFIG_HOME: "/cfg/", HOME: "/home/u" }), "/home/u/.mandu/config.toml");
  assert.equal(configPath({ XDG_CONFIG_HOME: "/cfg" }), null);
});

test("loadConfigEnv: friendly keys map to MANDU_* with coercion", () => {
  const read = (): string =>
    ["reply-filter = false", "net-proxy = true", "proxy-port = 9000", 'ullm-model = "m1"'].join("\n");
  const e = loadConfigEnv({ HOME: "/home/u" }, read);
  assert.equal(e["MANDU_REPLY_FILTER"], "0"); // bool false → "0"
  assert.equal(e["MANDU_NET_PROXY"], "1"); // bool true → "1"
  assert.equal(e["MANDU_PROXY_PORT"], "9000"); // num → string
  assert.equal(e["MANDU_ULLM_MODEL"], "m1");
  assert.ok(!("MANDU_FS_SYNC" in e)); // absent key → not emitted
});

test("preview-notice = false seeds MANDU_PREVIEW_NOTICE=0, which hides a preview agent's launch line; the template documents it commented-out", async () => {
  const { launchPreviewNotice } = await import("../../src/agent-versions.js");
  const e = loadConfigEnv({ HOME: "/home/u" }, () => "preview-notice = false\n");
  assert.equal(e["MANDU_PREVIEW_NOTICE"], "0");
  assert.equal(launchPreviewNotice("goose", ["goose"], null, e), null);
  assert.match(DEFAULT_CONFIG_TOML, /^# preview-notice = true$/m);
  assert.deepEqual(parseToml(DEFAULT_CONFIG_TOML), {}, "everything in the template stays commented out");
});

test("other-agent-logins = \"raw\" seeds MANDU_OTHER_AGENT_LOGINS=raw, the opt-out for another agent's login (secret-discovery.md §1.10); the template documents it commented-out", async () => {
  const { otherAgentLoginsRaw } = await import("../../src/agent-login.js");
  const e = loadConfigEnv({ HOME: "/home/u" }, () => 'other-agent-logins = "raw"\n');
  assert.equal(e["MANDU_OTHER_AGENT_LOGINS"], "raw");
  assert.equal(otherAgentLoginsRaw(e), true);
  assert.equal(otherAgentLoginsRaw(loadConfigEnv({ HOME: "/home/u" }, () => 'other-agent-logins = "twin"\n')), false);
  assert.match(DEFAULT_CONFIG_TOML, /^# other-agent-logins = "twin"$/m);
  assert.deepEqual(parseToml(DEFAULT_CONFIG_TOML), {});
});

test("MANDU_CONFIG is retired: it neither moves the config nor stands in for a home (on-disk-layout.md §5)", () => {
  assert.equal(configPath({ MANDU_CONFIG: "/x/c.toml", HOME: "/home/u" }), "/home/u/.mandu/config.toml");
  assert.equal(configPath({ MANDU_CONFIG: "/x/c.toml", MANDU_HOME: "/mh" }), "/mh/config.toml");
  assert.equal(configPath({ MANDU_CONFIG: "/x/c.toml" }), null);
  const asked: string[] = [];
  loadConfigEnv({ MANDU_CONFIG: "/x/c.toml", MANDU_HOME: "/mh" }, (p) => { asked.push(p); return null; });
  assert.deepEqual(asked, ["/mh/config.toml"]);
});

test("the view-state key is gone: an old config naming it is read like any unknown key (ignored)", () => {
  const e = loadConfigEnv({ HOME: "/home/u" }, () => `view-state = "/elsewhere"\nfs-sync = false\n`);
  assert.deepEqual(e, { MANDU_FS_SYNC: "0" });
  assert.ok(!Object.keys(e).some((k) => k.includes("VIEW_STATE")));
  assert.doesNotMatch(DEFAULT_CONFIG_TOML, /view-state/);
});

test("the real reader: a home under a non-directory (ENOTDIR, the test home /dev/null/...) reads as no config", () => {
  assert.deepEqual(loadConfigEnv({ MANDU_HOME: "/dev/null/mandu-test-home" }), {});
  const home = mkdtempSync(join(tmpdir(), "mandu-cfg-"));
  try {
    assert.deepEqual(loadConfigEnv({ MANDU_HOME: home }), {}, "absent (ENOENT) → empty");
    writeFileSync(join(home, "config.toml"), "reply-filter = false\n");
    assert.deepEqual(loadConfigEnv({ MANDU_HOME: home }), { MANDU_REPLY_FILTER: "0" });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("loadConfigEnv: missing/empty config → empty map", () => {
  assert.deepEqual(loadConfigEnv({ HOME: "/home/u" }, () => null), {});
  assert.deepEqual(loadConfigEnv({}, () => "reply-filter = false"), {}); // no path → empty
});

test("applyConfigDefaults: fills UNSET env, never overrides a SET env (env > config)", () => {
  const read = (): string => ["net-proxy = true", "reply-filter = false"].join("\n");
  const env: Record<string, string | undefined> = { HOME: "/home/u", MANDU_NET_PROXY: "0" }; // env set
  applyConfigDefaults(env, read);
  assert.equal(env["MANDU_NET_PROXY"], "0"); // env value preserved (env wins)
  assert.equal(env["MANDU_REPLY_FILTER"], "0"); // config filled the unset one
});

test("precedence end-to-end: config seeds the plan; a set env overrides config", () => {
  const read = (): string => ["net-proxy = true", "reply-filter = false"].join("\n");

  // config only → plan reflects config
  const e1: Record<string, string | undefined> = { HOME: "/h", PWD: "/w", XDG_RUNTIME_DIR: "/run" };
  applyConfigDefaults(e1, read);
  const p1 = parse(["claude"], e1);
  assert.equal(p1.requested.netProxy, true, "config net-proxy=true reached the plan");
  assert.equal(p1.replyFilter, false, "config reply-filter=false reached the plan");

  // env overrides config
  const e2: Record<string, string | undefined> = { HOME: "/h", PWD: "/w", XDG_RUNTIME_DIR: "/run", MANDU_NET_PROXY: "0" };
  applyConfigDefaults(e2, read);
  assert.equal(parse(["claude"], e2).requested.netProxy, false, "env MANDU_NET_PROXY=0 overrode config");

  // flag overrides config
  assert.equal(parse(["--no-reply-filter", "claude"], e1).replyFilter, false);
  assert.equal(parse(["--reply-filter", "claude"], e1).replyFilter, true, "flag overrode config reply-filter=false");
});

test("config no-kernel=true seeds MANDU_NO_KERNEL → the plan drops the kernel rungs", () => {
  const read = (): string => "no-kernel = true";
  assert.equal(loadConfigEnv({ HOME: "/h" }, read)["MANDU_NO_KERNEL"], "1");
  const e: Record<string, string | undefined> = { HOME: "/h", PWD: "/w", XDG_RUNTIME_DIR: "/run" };
  applyConfigDefaults(e, read);
  const p = parse(["claude"], e);
  assert.equal(p.execBox, false);
  assert.equal(p.landlockNet, false);
});

test("policy-file → MANDU_POLICY_FILE (the arbiter's data-law document; env wins; §2.1)", () => {
  const read = (): string => 'policy-file = "~/.config/mandu/policy.yaml"';
  const env: Record<string, string | undefined> = { HOME: "/home/u" };
  applyConfigDefaults(env, read);
  assert.equal(env["MANDU_POLICY_FILE"], "~/.config/mandu/policy.yaml", "the arbiter expands ~ itself");
  const pinned: Record<string, string | undefined> = { HOME: "/home/u", MANDU_POLICY_FILE: "/etc/mandu/law.yaml" };
  applyConfigDefaults(pinned, read);
  assert.equal(pinned["MANDU_POLICY_FILE"], "/etc/mandu/law.yaml");
});

test("require-confinement maps to MANDU_REQUIRE_CONFINEMENT and the template documents it commented-out", () => {
  const seeded = loadConfigEnv({ MANDU_HOME: "/x" }, () => "require-confinement = true\n");
  assert.equal(seeded["MANDU_REQUIRE_CONFINEMENT"], "1");
  assert.equal(parse(["claude"], { ...seeded, HOME: "/home/u" }).requireConfinement, true);
  assert.match(DEFAULT_CONFIG_TOML, /^# require-confinement = false$/m);
});

// ── `mode` key (protection-modes.md §3.2) ────────────────────────────────────

test("config `mode` seeds MANDU_MODE and resolves through parse like any level", () => {
  const env: Record<string, string | undefined> = { MANDU_HOME: "/x" };
  applyConfigDefaults(env, () => `mode = "secrets"\n`);
  assert.equal(env["MANDU_MODE"], "secrets");
  const p = parse(["claude"], env);
  assert.deepEqual([p.mode, p.integrity, p.confidentiality], ["secrets", false, true]);
});

test("`mode` and axis keys both present is resolved, never an error: the axis key wins its axis", () => {
  // The resolved pair is the frozen `injection`: the opt-in lets it parse
  // (docs/design/architecture/protection-modes.md §10); the precedence is what is pinned here.
  const env: Record<string, string | undefined> = { MANDU_HOME: "/x", MANDU_EXPERIMENTAL_INTEGRITY: "1" };
  applyConfigDefaults(env, () => `mode = "full"\nconfidentiality = false\n`);
  const p = parse(["claude"], env);
  assert.deepEqual([p.mode, p.integrity, p.confidentiality], ["injection", true, false]);
});

test("an exported MANDU_MODE beats the file's axis keys (env level > config level)", () => {
  const env: Record<string, string | undefined> = { MANDU_HOME: "/x", MANDU_MODE: "full", MANDU_EXPERIMENTAL_INTEGRITY: "1" };
  applyConfigDefaults(env, () => `integrity = false\nconfidentiality = false\nproxy-port = 0\n`);
  assert.equal(env["MANDU_INTEGRITY"], undefined, "the lower level's axis keys are not folded in beside an env mode");
  assert.equal(env["MANDU_PROXY_PORT"], "0", "unrelated keys still are");
  assert.equal(parse(["claude"], env).mode, "full");
});

test("an exported axis beats the file's mode for that axis; the file's mode fills the other", () => {
  const env: Record<string, string | undefined> = { MANDU_HOME: "/x", MANDU_INTEGRITY: "0" };
  applyConfigDefaults(env, () => `mode = "full"\n`);
  const p = parse(["claude"], env);
  assert.deepEqual([p.mode, p.integrity, p.confidentiality], ["secrets", false, true]);
});

test("the init template documents the mode key, commented out", () => {
  assert.match(DEFAULT_CONFIG_TOML, /^# mode = "/m);
  assert.equal(Object.keys(parseToml(DEFAULT_CONFIG_TOML)).length, 0);
  // Only the product modes are offered; the frozen pair is named with its opt-in.
  assert.match(DEFAULT_CONFIG_TOML, /^#   secrets /m);
  assert.match(DEFAULT_CONFIG_TOML, /^#   off /m);
  assert.doesNotMatch(DEFAULT_CONFIG_TOML, /^#   (injection|full) /m);
  assert.match(DEFAULT_CONFIG_TOML, /injection and full are frozen: they need MANDU_EXPERIMENTAL_INTEGRITY=1/);
});

test("frozen integrity: a config.toml `mode = \"full\"` (or `integrity = true`) is refused at launch without the opt-in, naming config.toml", () => {
  for (const toml of [`mode = "full"\n`, `mode = "injection"\n`, `integrity = true\n`]) {
    const env: Record<string, string | undefined> = { MANDU_HOME: "/x" };
    applyConfigDefaults(env, () => toml);
    assert.throws(() => parse(["claude"], env), /config\.toml\) is frozen.*MANDU_EXPERIMENTAL_INTEGRITY=1/s, toml);
    assert.equal(parse(["claude"], { ...env, MANDU_EXPERIMENTAL_INTEGRITY: "1" }).integrity, true, toml);
  }
  // The opt-in is an env switch only: the file cannot grant it to itself.
  const env: Record<string, string | undefined> = { MANDU_HOME: "/x" };
  applyConfigDefaults(env, () => `mode = "full"\n`);
  assert.equal(env["MANDU_EXPERIMENTAL_INTEGRITY"], undefined);
});
