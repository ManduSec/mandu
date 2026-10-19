/**
 * policy-file-validate.test — the strict data-law document check the daemon
 * runs at boot (policy-surface.md §2.1, stage 2).
 *
 * Pins: the documented shapes validate clean (new + legacy origin keys,
 * command entries, tool inbound schemas with markers/__items, outbound maps);
 * every malformed shape names its path; the semantic contradictions the engine
 * would ignore silently are errors; the file loader distinguishes missing
 * (fine) from unparseable/invalid (throws with every problem); the path
 * resolution honors MANDU_POLICY_FILE (with `~`), else the config dir.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  defaultPolicyFilePath,
  dispositionableRuleIds,
  loadPolicyFileStrict,
  PolicyFileError,
  resolvePolicyFilePath,
  policyWarnings,
  validatePolicyDocument,
} from "../../policy/policy-file-validate.js";

const VALID = {
  inbound: {
    url: { default: "UNTRUSTED", trustedList: ["https://docs.python.org/"] },
    dir: { default: "TRUSTED", untrustedList: ["~/Downloads"] },
    "channel-trust": { untrustedChannels: ["#random"] },
    command: [
      { id: "git", aliases: ["/usr/bin/git"], trustHelp: true, subcommands: { status: { schema: { stdout: "TRUSTED" } } } },
    ],
  },
  tools: {
    WebFetch: { inbound: { url: "TRUSTED", text: { category: "URL", role: "data", keyField: "url" } }, outbound: { url: "resolve" } },
    Grep: { inbound: { __items: { path: { category: "DIR", role: "key" }, line: "UNTRUSTED" } } },
    my_tool: { inbound: "UNTRUSTED", outbound: "not_resolve" },
  },
};

test("validatePolicyDocument: the documented shapes are clean; an empty document is a valid no-op", () => {
  assert.deepEqual(validatePolicyDocument(VALID), []);
  assert.deepEqual(validatePolicyDocument(null), []);
  assert.deepEqual(validatePolicyDocument({}), []);
});

test("validatePolicyDocument: every malformed shape is named by path", () => {
  const problems = validatePolicyDocument({
    inbound: {
      url: { default: "MAYBE", trustedList: "docs.python.org" },
      dir: { default: "TRUSTED", trustedList: ["~/x"] },
      channel: { default: "UNTRUSTED", untrustedList: ["#a"], extra: 1 },
      command: [{ aliases: "git" }, "ls"],
      "dir-trust": { untrustedDirs: [1] },
    },
    tools: {
      Read: {},
      Bash: { inbound: "SOMETIMES", outbound: { command: "maybe" } },
      Glob: { inbound: { path: { category: "DIR", role: "owner" } }, outbound: 42 },
      Edit: { inbound: { __items: "TRUSTED", also: "UNTRUSTED" } },
    },
    extra: true,
  });
  const has = (re: RegExp) => assert.ok(problems.some((p) => re.test(p)), `expected a problem matching ${re}\n${problems.join("\n")}`);
  has(/^policy: unknown key 'extra'/);
  has(/^inbound\.url\.default: must be TRUSTED or UNTRUSTED/);
  has(/^inbound\.url\.trustedList: must be a list of strings/);
  has(/^inbound\.dir: 'trustedList' has no effect under default TRUSTED/);
  has(/^inbound\.channel: 'untrustedList' has no effect under default UNTRUSTED/);
  has(/^inbound\.channel: unknown key 'extra'/);
  has(/^inbound\.command\[0\]\.id: must be the command's canonical name/);
  has(/^inbound\.command\[0\]\.aliases: must be a list of strings/);
  has(/^inbound\.command\[1\]: must be a mapping/);
  has(/^inbound\.dir-trust\.untrustedDirs\[0\]: must be a non-empty string/);
  has(/^tools\.Read: needs 'inbound' and\/or 'outbound'/);
  has(/^tools\.Bash\.inbound: a leaf must be TRUSTED or UNTRUSTED/);
  has(/^tools\.Bash\.outbound\.command: must be resolve \| not_resolve \| no_symbols_expected/);
  has(/^tools\.Glob\.inbound\.path\.role: must be "key" or "data"/);
  has(/^tools\.Glob\.outbound: must be "resolve", "not_resolve", or a mapping/);
  has(/^tools\.Edit\.inbound: unknown key 'also'/);
  assert.equal(validatePolicyDocument("just a string").length, 1);
  assert.match(validatePolicyDocument("just a string")[0]!, /must be a mapping/);
});

test("loadPolicyFileStrict: missing → found:false; valid → config; YAML garbage and invalid docs THROW with every problem", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-policy-file-"));
  try {
    assert.deepEqual(loadPolicyFileStrict(join(dir, "none.yaml")), { path: join(dir, "none.yaml"), found: false, config: null });

    const ok = join(dir, "ok.yaml");
    writeFileSync(ok, "inbound:\n  url:\n    default: UNTRUSTED\n    trustedList: [\"https://docs.python.org/\"]\ntools:\n  Read:\n    outbound: not_resolve\n");
    const loaded = loadPolicyFileStrict(ok);
    assert.equal(loaded.found, true);
    assert.deepEqual(loaded.config?.inbound?.url, { default: "UNTRUSTED", trustedList: ["https://docs.python.org/"] });

    const empty = join(dir, "empty.yaml");
    writeFileSync(empty, "# nothing yet\n");
    assert.deepEqual(loadPolicyFileStrict(empty), { path: empty, found: true, config: {} });

    const garbage = join(dir, "garbage.yaml");
    writeFileSync(garbage, "inbound: [unclosed\n  url: {\n");
    assert.throws(
      () => loadPolicyFileStrict(garbage),
      (err: Error) => err instanceof PolicyFileError && /YAML parse error/.test(err.message) && /refuses to start/.test(err.message),
    );

    const invalid = join(dir, "invalid.yaml");
    writeFileSync(invalid, "inbound:\n  url:\n    default: SOMETIMES\ntools:\n  Read: {}\n");
    assert.throws(
      () => loadPolicyFileStrict(invalid),
      (err: Error) =>
        err instanceof PolicyFileError &&
        err.problems.length === 2 &&
        /inbound\.url\.default/.test(err.problems[0]!) &&
        /tools\.Read/.test(err.problems[1]!),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("paths: patterns — gitignore-style entries validate clean; a pattern that would mean something else than written is refused WITH the reason", () => {
  assert.deepEqual(validatePolicyDocument({
    paths: [
      { path: "**/*.pem", level: "no-model" },
      { path: "~/work/*/contracts/**", level: "any-model", bindings: ["example.com"] },
      { path: "/srv/keys/id_[rd]sa", level: "no-model", recursive: false },
      { path: "/srv/odd/a\\*b.txt", level: "public" },
    ],
  }), []);
  const errs = validatePolicyDocument({
    paths: [
      { path: "*.pem", level: "no-model" },
      { path: "/ws/a**b", level: "public" },
      { path: "/ws/[abc", level: "public" },
      { path: "**", level: "public" },
    ],
  });
  const has = (re: RegExp): void => assert.ok(errs.some((e) => re.test(e)), `missing ${re} in:\n${errs.join("\n")}`);
  has(/^paths\[0\]\.path: pattern "\*\.pem": a pattern is anchored/);
  has(/^paths\[1\]\.path: pattern .*whole path segment/);
  has(/^paths\[2\]\.path: pattern .*never closed/);
  has(/^paths\[3\]\.path: pattern .*every path on the machine/);
});

test("resolvePolicyFilePath: MANDU_POLICY_FILE (with ~ and relative paths) else <home>/policy.yaml", () => {
  assert.equal(resolvePolicyFilePath({ MANDU_POLICY_FILE: "/etc/mandu/law.yaml" }), "/etc/mandu/law.yaml");
  assert.equal(resolvePolicyFilePath({ MANDU_POLICY_FILE: "~/law.yaml", HOME: "/home/u" }), "/home/u/law.yaml");
  assert.equal(resolvePolicyFilePath({ MANDU_POLICY_FILE: "rel/law.yaml" }, "/cwd"), "/cwd/rel/law.yaml");
  assert.equal(resolvePolicyFilePath({ MANDU_POLICY_FILE: "", HOME: "/home/u" }), "/home/u/.mandu/policy.yaml", "empty = unset");
  assert.equal(defaultPolicyFilePath({ HOME: "/home/u" }), "/home/u/.mandu/policy.yaml");
  // The one home (on-disk-layout.md §3): MANDU_HOME moves it, XDG_CONFIG_HOME no longer does.
  assert.equal(defaultPolicyFilePath({ HOME: "/home/u", MANDU_HOME: "/mh" }), "/mh/policy.yaml");
  assert.equal(defaultPolicyFilePath({ HOME: "/home/u", XDG_CONFIG_HOME: "/xdg" }), "/home/u/.mandu/policy.yaml");
  // The path table's `policy` entry: empty variables count as unset.
  assert.equal(defaultPolicyFilePath({ HOME: "/home/u", MANDU_HOME: "" }), "/home/u/.mandu/policy.yaml");
});

test("the retired MANDU_CONFIG no longer moves the policy file: it is MANDU_POLICY_FILE, else <home>/policy.yaml", () => {
  assert.equal(defaultPolicyFilePath({ HOME: "/home/u", MANDU_CONFIG: "/srv/mandu/config.toml" }), "/home/u/.mandu/policy.yaml");
  assert.equal(defaultPolicyFilePath({ HOME: "/home/u", MANDU_HOME: "/mh", MANDU_CONFIG: "/srv/mandu/config.toml" }), "/mh/policy.yaml");
  assert.equal(resolvePolicyFilePath({ HOME: "/home/u", MANDU_CONFIG: "/srv/mandu/config.toml" }), "/home/u/.mandu/policy.yaml");
  assert.equal(resolvePolicyFilePath({ HOME: "/home/u", MANDU_CONFIG: "/srv/mandu/config.toml", MANDU_POLICY_FILE: "/etc/law.yaml" }), "/etc/law.yaml");
});

test("stage 4 keys: version / lists / paths / rules / user_rules validate clean and name every problem", () => {
  const ok = validatePolicyDocument({
    version: 1,
    lists: { "trusted-docs": ["https://docs.python.org/"], "my-services": ["api.github.com", "*.internal.example"] },
    inbound: { url: { default: "UNTRUSTED", trustedList: ["@trusted-docs"] } },
    paths: [
      { path: "~/.ssh", level: "no-model" },
      { path: "/home/u/notes", level: "any-model", bindings: ["api.anthropic.com"], recursive: false },
    ],
    rules: { "egress:untrusted-destination": { mode: "block" } },
    user_rules: [
      { id: "r-1", kind: "release", from: { host: "docs.python.org" }, to: { host: "@my-services" }, mode: "allow", reason: "docs → my api", expires: "2027-01-01T00:00:00Z" },
      { id: "r-2", kind: "release", to: { host: "*.pastebin.com" }, mode: "block" },
      { id: "r-3", kind: "release", to: { host: "*" }, mode: "audit", expires: null },
    ],
  });
  assert.deepEqual(ok, []);

  const problems = validatePolicyDocument({
    version: 2,
    lists: { "bad name!": ["x"], good: "not-a-list" },
    inbound: { url: { default: "UNTRUSTED", trustedList: ["@missing"] } },
    paths: [{ path: "relative/dir", level: "secret" }, "nope", { path: "/x", level: "public", recursive: "yes", extra: 1 }],
    rules: { "egress:trusted-destination": { mode: "block" }, "egress:untrusted-destination": { mode: "maybe" }, "fs:sensitive-path": { mode: "block" } },
    user_rules: [
      { id: "dup", kind: "release", to: { host: "a" }, mode: "allow" },
      { id: "dup", kind: "deny", from: "docs", to: { host: "@missing" }, mode: "sometimes", expires: "yesterday", audit: true },
      { kind: "release", mode: "allow" },
    ],
  });
  const has = (re: RegExp) => assert.ok(problems.some((p) => re.test(p)), `expected ${re}\n${problems.join("\n")}`);
  has(/^policy\.version: must be 1/);
  has(/^lists\.bad name!: names are letters/);
  has(/^lists\.good: must be a list of strings/);
  has(/^inbound\.url\.trustedList\[0\]: references list '@missing'/);
  has(/^paths\[0\]\.path: must be an absolute path or ~/);
  has(/^paths\[0\]\.level: must be public \| any-model \| local-model \| no-model/);
  has(/^paths\[1\]: must be a mapping/);
  has(/^paths\[2\]\.recursive: must be true or false/);
  has(/^paths\[2\]: unknown key 'extra'/);
  has(/^rules\.egress:trusted-destination: not a built-in rule that asks by default/);
  has(/^rules\.egress:untrusted-destination\.mode: must be ask or block/);
  has(/^rules\.fs:sensitive-path: not a built-in rule that asks by default/);
  has(/^user_rules\[1\]\.id: duplicate id 'dup'/);
  has(/^user_rules\[1\]\.kind: must be "release"/);
  has(/^user_rules\[1\]\.from: must be \{ host \}/);
  has(/^user_rules\[1\]\.to\.host: references list '@missing'/);
  has(/^user_rules\[1\]\.mode: must be allow \| block \| audit \| off/);
  has(/^user_rules\[1\]\.expires: must be an ISO date\/time or null/);
  has(/^user_rules\[1\]\.audit: use mode: audit instead/);
  has(/^user_rules\[2\]\.id: must be a non-empty string/);
  has(/^user_rules\[2\]\.to: must be \{ host \}/);
});

test("dispositionableRuleIds: exactly the egress rules that ask by default", () => {
  const ids = dispositionableRuleIds();
  assert.ok(ids.includes("egress:untrusted-destination"));
  assert.ok(ids.includes("egress:symbol-as-command"));
  assert.ok(!ids.includes("egress:trusted-destination"), "an allow has nothing to tighten into a block");
  assert.ok(!ids.includes("egress:secret-model-context"), "a deny is already a block");
  assert.ok(ids.every((id) => id.startsWith("egress:")));
});

// ── plan 10: readers, others, apps ───────────────────────────────────────────
test("paths[].readers / others and the apps section validate; an interpreter may only be `secret`", () => {
  const ok = validatePolicyDocument({
    version: 1,
    paths: [{ path: "~/.pgpass", level: "no-model", readers: ["psql", { app: "pg_dump", path: "/usr/bin/pg_dump", sha256: "0".repeat(64) }], others: "twin" }],
    apps: [{ app: "psql", output: "clear" }, { app: "aws", output: "mask", mask: ["AKIA[0-9A-Z]{16}"] }, { app: "bash", output: "secret" }],
  });
  assert.deepEqual(ok, []);
  const bad = validatePolicyDocument({
    version: 1,
    paths: [{ path: "~/.pgpass", level: "no-model", readers: ["/usr/bin/psql", { app: "x", sha256: "zz" }] }, { path: "~/.netrc", level: "no-model", others: "deny" }],
    apps: [{ app: "bash", output: "clear" }, { app: "aws", output: "mask" }, { app: "gh", output: "loud" }, { app: "psql", output: "secret", mask: ["x"] }],
  });
  const text = bad.join("\n");
  assert.match(text, /readers\[0\]: a bare reader is a program name/);
  assert.match(text, /readers\[1\]\.sha256/);
  assert.match(text, /others: only meaningful with a readers list/);
  assert.match(text, /apps\[0\]: bash is an interpreter/);
  assert.match(text, /apps\[1\]\.mask: a mask rule needs at least one regex/);
  assert.match(text, /apps\[2\]\.output/);
  assert.match(text, /apps\[3\]\.mask: only meaningful/);
});

// Plan 13 D8: a reader that runs any code is valid, and warned about.
test("plan 13 D3: a reader entry carries its own output rule; a code-running reader may only be secret; ssh_agent readers carry none", () => {
  assert.deepEqual(validatePolicyDocument({
    version: 1,
    paths: [{ path: "~/.pgpass", level: "no-model", readers: [
      { app: "psql", output: "clear" },
      { app: "aws", output: "mask", mask: ["AKIA[0-9A-Z]{16}"] },
      { app: "pg_dump", path: "/usr/bin/pg_dump", sha256: "0".repeat(64), output: "secret" },
      { app: "python3", output: "secret" },
    ] }],
  }), []);
  const bad = validatePolicyDocument({
    version: 1,
    paths: [{ path: "~/.pgpass", level: "no-model", readers: [
      { app: "python3", output: "clear" },
      { app: "awk", output: "mask", mask: ["x"] },
      { app: "psql", output: "loud" },
      { app: "aws", output: "mask" },
      { app: "gh", output: "clear", mask: ["x"] },
      { app: "jq", output: "mask", mask: ["("] },
    ] }],
    ssh_agent: { readers: [{ app: "ssh", output: "clear" }] },
  });
  const text = bad.join("\n");
  assert.match(text, /readers\[0\]: python3 runs any code/);
  assert.match(text, /readers\[1\]: awk runs any code/);
  assert.match(text, /readers\[2\]\.output: must be secret, clear or mask/);
  assert.match(text, /readers\[3\]\.mask: a mask rule needs at least one regex/);
  assert.match(text, /readers\[4\]\.mask: only meaningful with output: mask/);
  assert.match(text, /readers\[5\]\.mask\[0\]: invalid regex/);
  assert.match(text, /ssh_agent\.readers\[0\]: unknown key 'output'/);
});

test("plan 13 D3: a program-wide apps: output rule is deprecated: it still validates, clears nothing, and earns a warning naming the reader-entry form", () => {
  const doc = { version: 1, apps: [{ app: "psql", output: "clear" }, { app: "aws", output: "mask", mask: ["AKIA.*"] }, { app: "jq", output: "secret" }] };
  assert.deepEqual(validatePolicyDocument(doc), []);
  const w = policyWarnings(doc);
  assert.equal(w.length, 2, w.join("\n"));
  assert.match(w[0]!, /^apps\[0\]: .*no longer clears.*psql.*readers: \[\{ app: psql, output: clear \}\]/);
  assert.match(w[1]!, /^apps\[1\]: .*aws/);
});

test("policyWarnings: a shell, an interpreter or a launcher on a reader list is a warning (the document still validates); a leaf program is not", () => {
  const doc = {
    version: 1,
    paths: [
      { path: "~/ws/app/.env", level: "no-model", readers: ["bash", "ssh-add", { app: "node", from: "make" }, { app: "python3.12", path: "/usr/bin/python3.12" }] },
      { path: "~/.pgpass", level: "no-model", readers: ["ssh-add", "ssh"] },
    ],
    ssh_agent: { readers: ["ssh-add", "env"] },
  };
  assert.deepEqual(validatePolicyDocument(doc), [], "a warning never refuses the start");
  const w = policyWarnings(doc);
  assert.equal(w.length, 4, w.join("\n"));
  assert.match(w[0]!, /^paths\[0\]\.readers\[0\]: bash runs any code it is given .* ~\/ws\/app\/\.env raw/);
  // Plan 13 §8 decision (b): the entry is inert, and the warning says so and
  // names the script pin for an interpreter that can carry one
  assert.match(w[0]!, /so this entry admits nothing: no bash reads .*inline code \(bash -c …\) included/);
  assert.match(w[0]!, /\{ app: bash, script: \/absolute\/path\/of\/the\/script, prints: nothing \}/);
  assert.match(w[1]!, /^paths\[0\]\.readers\[2\]: node /);
  assert.match(w[2]!, /^paths\[0\]\.readers\[3\]: python3\.12 /);
  assert.match(w[3]!, /^ssh_agent\.readers\[1\]: env .* your ssh-agent raw/);
  assert.doesNotMatch(w[3]!, /script:/, "the socket's readers have no script pin");
  assert.deepEqual(policyWarnings({ version: 1, paths: [{ path: "~/.pgpass", level: "no-model", readers: ["ssh-add"] }] }), []);
  // psql prints a file (plan 13 D8 (12)'s correction): a printer's warning
  assert.match(policyWarnings({ version: 1, paths: [{ path: "~/.pgpass", level: "no-model", readers: ["psql"] }] }).join("\n"), /psql prints or copies/);
  assert.deepEqual(policyWarnings(null), []);
});

// ── plan 10 §11.4: the env section ───────────────────────────────────────────
test("env: { secrets, exempt } validates names and PREFIX_* patterns; a bare '*', a bad name and a name in both lists are refused", () => {
  assert.deepEqual(validatePolicyDocument({ version: 1, env: { secrets: ["MYCO_*", "DEPLOY_CRED"], exempt: ["GH_TOKEN", "PUBLIC_*"] } }), []);
  assert.deepEqual(validatePolicyDocument({ version: 1, env: {} }), []);
  const bad = validatePolicyDocument({ version: 1, env: { secrets: ["*", "bad-name", "DUP"], exempt: ["DUP"], other: 1 } }).join("\n");
  assert.match(bad, /env\.secrets\[0\]: '\*' alone would mask every variable/);
  assert.match(bad, /env\.secrets\[1\]: must be a variable name or PREFIX_\* pattern/);
  assert.match(bad, /env: "DUP" is in both secrets and exempt/);
  assert.match(bad, /env: unknown key 'other'/);
  assert.match(validatePolicyDocument({ version: 1, env: ["X"] }).join("\n"), /env: must be a mapping/);
  assert.match(validatePolicyDocument({ version: 1, env: { exempt: "GH_TOKEN" } }).join("\n"), /env\.exempt: must be a list/);
});

test("env.sources: name, a known source scheme and host bindings; duplicates and unknown schemes are refused", () => {
  assert.deepEqual(validatePolicyDocument({ version: 1, env: { sources: [
    { name: "GH_TOKEN", source: "cmd:gh auth token", bindings: ["api.github.com"] },
    { name: "OP_KEY", source: "op://Dev/Stripe/key" },
    { name: "KR_KEY", source: "keyring:github/me", bindings: ["*.example.com"] },
  ] } }), []);
  const bad = validatePolicyDocument({ version: 1, env: { sources: [
    { name: "A", source: "file:/etc/passwd" },
    { name: "A", source: "cmd:true" },
    { name: "1BAD", source: "cmd:true" },
    { name: "B", source: "cmd:true", bindings: ["not a host"] },
    { name: "C", source: "cmd:true", extra: 1 },
  ] } });
  assert.ok(bad.some((p) => /sources\[0\]\.source: must be cmd:/.test(p)), bad.join("\n"));
  assert.ok(bad.some((p) => /sources\[1\]\.name: A has two sources/.test(p)));
  assert.ok(bad.some((p) => /sources\[2\]\.name: must be a variable name/.test(p)));
  assert.ok(bad.some((p) => /sources\[3\]\.bindings: must be a list of host names/.test(p)));
  assert.ok(bad.some((p) => /sources\[4\]/.test(p) && /extra/.test(p)));
});

test("readers[].from names the program that starts the reader; a path or an empty name is refused", () => {
  assert.deepEqual(validatePolicyDocument({ version: 1, paths: [{ path: "/h/.ssh/id_ed25519", level: "no-model", readers: [{ app: "ssh", from: "git" }] }] }), []);
  const bad = validatePolicyDocument({ version: 1, paths: [{ path: "/h/.ssh/id_ed25519", level: "no-model", readers: [{ app: "ssh", from: "/usr/bin/git" }, { app: "ssh", from: "" }] }] });
  assert.equal(bad.filter((p) => /\.from: must be the program name/.test(p)).length, 2, bad.join("\n"));
});

test("ssh_agent: { readers } takes the same reader entries as paths[].readers; readers is required", () => {
  assert.deepEqual(validatePolicyDocument({ version: 1, ssh_agent: { readers: ["ssh-add", { app: "ssh", from: "git" }] } }), []);
  assert.ok(validatePolicyDocument({ version: 1, ssh_agent: {} }).some((p) => /ssh_agent\.readers: required/.test(p)));
  assert.ok(validatePolicyDocument({ version: 1, ssh_agent: { readers: [{ app: "ssh", from: "/usr/bin/git" }] } }).some((p) => /ssh_agent\.readers\[0\]\.from/.test(p)));
});

test("protect: absolute or ~/ paths; / and ~ alone are refused", () => {
  assert.deepEqual(validatePolicyDocument({ version: 1, protect: ["~/Documents", "/srv/data"] }), []);
  const bad = validatePolicyDocument({ version: 1, protect: ["Documents", "/", "~"] });
  assert.equal(bad.filter((p) => /^protect\[\d\]/.test(p)).length, 3, bad.join("\n"));
});

test("plan 11 D2: models: is a list of named endpoints; local-model is a level", () => {
  assert.deepEqual(validatePolicyDocument({ version: 1,
    models: [
      { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true },
      { name: "gateway", url: "https://llm.corp.example/v1", token_env: "GATEWAY_TOKEN" },
    ],
    paths: [{ path: "~/notes/contract.md", level: "local-model" }],
  }), []);
  const bad = validatePolicyDocument({ version: 1, models: [
    { name: "a b", url: "http://x" },                                   // name charset
    { name: "dup", url: "ftp://x" },                                    // scheme
    { name: "dup", url: "http://user:pw@x" },                           // twice + credentials in the URL
    { name: "w", url: "http://x", wire: "grpc", local: "yes", model: "" }, // wire, local, model
    { name: "t", url: "http://x", token_env: "sk-live-123" },            // a token, not a name
    { name: "k", url: "http://x", extra: 1 },                            // unknown key
    "ollama",
  ] }).join("\n");
  for (const re of [/models\[0\]\.name/, /models\[1\]\.url/, /models\[2\]\.name: 'dup' is declared twice/, /models\[2\]\.url/,
    /models\[3\]\.wire/, /models\[3\]\.local/, /models\[3\]\.model/, /models\[4\]\.token_env: must be an environment variable NAME/,
    /models\[5\]/, /models\[6\]: must be a mapping/]) {
    assert.match(bad, re);
  }
  assert.match(validatePolicyDocument({ version: 1, models: {} }).join("\n"), /models: must be a list/);
});

test("models: helper: true names the helper's model: one entry at most, and only a local: true one", () => {
  const two = [
    { name: "codex-main", url: "http://127.0.0.1:11434/v1", wire: "openai-chat", model: "gpt-oss:20b", local: true },
    { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true, helper: true },
  ];
  assert.deepEqual(validatePolicyDocument({ version: 1, models: two }), []);
  assert.deepEqual(validatePolicyDocument({ version: 1, models: [{ ...two[0], helper: false }] }), [], "helper: false is the default spelled out");
  const bad = validatePolicyDocument({ version: 1, models: [
    { ...two[0], helper: true },
    { ...two[1] },                                                   // a second helper
    { name: "gw", url: "https://llm.example.com", helper: true },   // not local
    { name: "y", url: "http://127.0.0.1:1", local: true, helper: "yes" },
  ] }).join("\n");
  assert.match(bad, /models\[1\]\.helper: only one model can be the helper's \('codex-main' already is\)/);
  assert.match(bad, /models\[2\]\.helper: 'gw' is not local: true/);
  assert.match(bad, /models\[3\]\.helper: must be true or false/);
  assert.doesNotMatch(bad, /models\[0\]\.helper/);
});
