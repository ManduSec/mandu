/**
 * found-labels — the default catalog's CONTENT tier (secret-discovery.md
 * §2.6, 2026-10-19): which config files the launch walk reads, which of
 * them it labels (a credential under a credential-named key, or a vendor
 * key anywhere), how a found label composes with the human's labels, and
 * that the walk lists, clears and keeps them.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import {
  CONTENT_RULE, FoundLabelStore, contentProbeCandidate, credentialInDataFile, credentialName, readCandidate, referenceValue,
} from "../../policy/found-labels.js";
import { composedLabel, foundLabel, guardLabelRoots, labelRoots, type LabelSnapshot } from "../../policy/label-lookup.js";
import { confidentialityForOrigin, pathConfidentiality } from "../../policy/secret-catalog.js";
import { discoverSecretsReport } from "../../policy/secret-discovery.js";
import { extractSecretSpans, renderStructuredTwin } from "../../policy/secret-extract.js";
import type { PathLabel } from "../../policy/path-labels.js";
import type { DerivedLabel } from "../../policy/derived-labels.js";

/** A password and a token the value tests take as credentials. */
const PW = "Garden-Lamp-QXT4-6180";
const TOKEN = "ldk_7Hq2Lp9Xw3Rt5Vb8Nc1Mz6Ks4Jd0Fg2A";
const VENDOR = "sk-ant-api03-q8Zr2LwT9xVb4NcK7mHs1JdP6fYg3RtE0aUo5WiQ";

// ── which files the walk reads ──────────────────────────────────────────────

test("contentProbeCandidate: config files of a workspace, a tool's dot-directory in HOME, never test data or an agent's config", () => {
  const ws = (p: string): boolean => contentProbeCandidate(p.split("/"), "workspace");
  const home = (p: string): boolean => contentProbeCandidate(p.split("/"), "home");
  for (const p of ["accounts/brightgrid.yaml", "config.json", "deploy/prod.yml", "infra/settings.toml", ".launchdeck/config.json", "app/config/database.yml"]) {
    assert.ok(ws(p), `${p} is read in a workspace`);
  }
  for (const p of [
    "README.md", "notes.txt", ".env", "app/main.py",                           // not JSON, YAML or TOML
    "package.json", "package-lock.json", "tsconfig.json", "tsconfig.build.json", "Cargo.toml", "pyproject.toml", "pnpm-lock.yaml",
    "config.example.yaml", "secrets.sample.json", "app.template.yml",          // templates
    "refunds-svc/test/fixtures/refund.json", "tests/login.json", "spec/cassettes/login.yml", "__mocks__/api.json",
    "docs/config.yaml", "examples/settings.json", "src/__snapshots__/x.json",  // test data, examples, docs
    ".mcp.json", "mcp.json", ".vscode/settings.json", ".claude/settings.local.json", ".cursor/mcp.json", "opencode.json",
    ".config/opencode/config.json", ".config/goose/config.yaml",               // an agent's or editor's own
  ]) {
    assert.ok(!ws(p), `${p} is not read`);
  }
  // HOME: a file in a tool's own dot-directory, one level of subfolder at most
  for (const p of [".railway/config.json", ".config/turso/settings.json", ".doppler/.doppler.yaml", ".twilio-cli/config.json"]) assert.ok(home(p), p);
  for (const p of ["proj/config.yaml", "config.json", ".config/a/b/c.json", ".vscode/settings.json", ".config/Code/settings.json"]) assert.ok(!home(p), p);
  // the walk root is what the dirs are judged below: a workspace under ~/tests/ is read
  assert.ok(contentProbeCandidate(["accounts", "power.yaml"], "workspace"));
});

test("credentialName and referenceValue: a credential's name and value, not a name or value ABOUT one", () => {
  for (const n of ["password", "PASSWORD", "db_password", "passwd", "token", "access_token", "accessToken", "api_key", "apiKey", "client_secret", "secret", "private_key", "passphrase", "auth_key", "credential", "pw", "db_pw", "SMTP_PASS", "PGPASSWORD", "pin", "card_pin", "passcode", "access_code"]) {
    assert.ok(credentialName(n), n);
  }
  for (const n of ["adminPasswordKey", "tokenKey", "token_url", "tokenUri", "token_endpoint", "secret_name", "secretName", "password_file", "passwordFile", "api_key_id", "secretKeyRef", "token_type", "password_hint", "user", "email", "site", "key", "auth", "tokenizer_class", "led_pin", "first_pass", "status_code", "pw_hash"]) {
    assert.ok(!credentialName(n), n);
  }
  for (const v of ["https://oauth2.googleapis.com/token", "/run/secrets/db_password2", "./keys/prod2.pem", "~/secrets/x1.txt", "ENC[AES256_GCM,data:Zm9vYmFy1,iv:abc]", "arn:aws:secretsmanager:us-east-1:123456789012:secret:db", "op://vault/item/password1", "use the one in 1Password 2024"]) {
    assert.ok(referenceValue(v), v);
  }
  for (const v of [PW, TOKEN]) assert.ok(!referenceValue(v), v);
});

test("credentialInDataFile: a credential under a credential-named key, or a vendor key anywhere, labels the file", () => {
  const yes: Array<[string, string, string]> = [
    ["accounts/brightgrid.yaml", `# BrightGrid Energy: my online account\nsite: https://my.brightgrid.test\nemail: alex@mail.test\npassword: ${PW}\n`, "password"],
    [".launchdeck/auth.json", `${JSON.stringify({ token: TOKEN }, null, 2)}\n`, "token"],
    ["api/http-client.private.env.json", JSON.stringify({ staging: { user: "ops-admin", password: PW } }), "password"],
    ["deploy/prod.toml", `[db]\nhost = "db.internal"\npassword = "${PW}"\n`, "db.password"],
    ["config/app.yaml", `database:\n  url: postgres://app:${PW}@db.internal:5432/app\n`, "database.url.password"],
    // a vendor key under a name that says nothing, in a file whose keys gave
    // the extractor a span (the credential belt's reach): its own field
    ["config/ci.json", JSON.stringify({ smtp: { password: "changeme" }, notify: { webhook_value: VENDOR } }), "*"],
    ["k8s/secret.yaml", "apiVersion: v1\nkind: Secret\ndata:\n  password: c3VwZXItc2VjcmV0LXBhc3N3b3JkLTIwMjY=\n", "data.password"],
  ];
  for (const [path, text, field] of yes) {
    const got = credentialInDataFile(`/ws/${path}`, text);
    if (field === "*") assert.ok(got !== null && got !== "password", `${path}: ${got}`);
    else assert.equal(got, field, path);
    // the twin keeps the file and hides the value (the structured twin by construction)
    const x = extractSecretSpans(`/ws/${path}`, text);
    const twin = renderStructuredTwin(text, x.spans, () => "$MDU:nomodel_T[0]");
    for (const v of [PW, TOKEN, VENDOR]) assert.ok(!twin.includes(v), `${path}: ${twin}`);
  }
  const no: Array<[string, string]> = [
    // a vendor key alone under a name that says nothing: the extractor finds
    // no keyed span, the file would be one whole-file placeholder, so the
    // tier leaves it to the launch scan's suggestion (secret-discovery.md §2.6)
    ["config/ci.json", JSON.stringify({ notify: { webhook_value: VENDOR } })],
    ["config/database.yml", "production:\n  password: ${DB_PASSWORD}\n"],
    ["config/database.yml", "production:\n  password: <%= ENV['DB_PASSWORD'] %>\n"],
    ["config/app.yaml", "password: changeme\n"],
    ["config/app.yaml", "password: hunter2\n"],                               // a famous example (credential-names.ts COMMON_PASSWORDS)
    ["config/app.yaml", "password: \"\"\ntoken: null\n"],
    ["locales/en/auth.json", JSON.stringify({ password: "Password", forgotPassword: "Forgot your password?", token_expired: "Your session expired" })],
    ["config/oauth.json", JSON.stringify({ token_uri: "https://oauth2.googleapis.com/token", client_id: "123-abc.apps.googleusercontent.com" })],
    ["config/secrets.yaml.lock", "x"],
    ["chart/values.yaml", "auth:\n  existingSecret: my-db-secret\n  secretKeys:\n    adminPasswordKey: postgres-password2\n"],
    ["docker-compose.yml", "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: postgres\n      DATABASE_URL: postgres://postgres:postgres@db:5432/app\n"],
    [".github/workflows/ci.yml", "steps:\n  - uses: x\n    with:\n      token: ${{ secrets.GITHUB_TOKEN }}\n"],
    ["infra/secrets.enc.yaml", "password: ENC[AES256_GCM,data:9dkW3,iv:Zm9vYmFyYmF6cXV4,tag:abc==,type:str]\n"],
    ["openapi.yaml", "components:\n  securitySchemes:\n    bearerAuth:\n      type: http\n      scheme: bearer\n      bearerFormat: JWT\n"],
    ["tokenizer_config.json", JSON.stringify({ bos_token: "<s>", pad_token: "<pad>", tokenizer_class: "PreTrainedTokenizerFast" })],
    ["schema/user.json", JSON.stringify({ properties: { password: { type: "string", minLength: 12 } } })],
    ["config/app.yaml", `# an old one: password: ${PW}\nsite: x\n`],    // a comment's non-vendor token
  ];
  for (const [path, text] of no) assert.equal(credentialInDataFile(`/ws/${path}`, text), null, `${path}: ${text}`);
});

test("readCandidate: a regular file of at most the cap, as text; never a symlink, a FIFO-like path or a binary", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-found-read-"));
  try {
    writeFileSync(join(dir, "a.yaml"), `password: ${PW}\n`);
    writeFileSync(join(dir, "big.json"), `{"x":"${"a".repeat(70 * 1024)}"}`);
    writeFileSync(join(dir, "bin.json"), Buffer.from([0x7b, 0x00, 0x7d]));
    assert.equal(readCandidate(join(dir, "a.yaml")), `password: ${PW}\n`);
    assert.equal(readCandidate(join(dir, "big.json")), null, "over the cap");
    assert.equal(readCandidate(join(dir, "bin.json")), null, "not text");
    assert.equal(readCandidate(join(dir, "missing.json")), null);
    assert.equal(readCandidate(dir), null, "a directory");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── how a found label composes ──────────────────────────────────────────────

const human = (path: string, confidentiality: PathLabel["confidentiality"], recursive = false): PathLabel =>
  ({ path, confidentiality, bindings: [], recursive, createdAt: 0, updatedAt: 0 } as unknown as PathLabel);
const snap = (o: { human?: PathLabel[]; derived?: DerivedLabel[]; found?: string[] }): LabelSnapshot => ({
  human: new Map((o.human ?? []).map((l) => [l.path, l])),
  derived: new Map((o.derived ?? []).map((d) => [d.path, d])),
  clientKeys: [],
  found: new Map((o.found ?? []).map((p) => [p, { path: p }])),
});

test("a found label is no-model, bound nowhere, rule content:secret-key; a human label on the file or above it decides instead", () => {
  const f = "/home/u/ws/accounts/power.yaml";
  const lookup = (s: LabelSnapshot) => (p: string) => composedLabel(p, s);
  assert.deepEqual(pathConfidentiality(f, "/home/u", lookup(snap({ found: [f] }))), { level: "no-model", bindings: [], rule: CONTENT_RULE });
  assert.deepEqual(foundLabel(f, snap({ found: [f] })), { level: "no-model", bindings: [], via: f, origin: "found" });
  assert.equal(pathConfidentiality("/home/u/ws/accounts/other.yaml", "/home/u", lookup(snap({ found: [f] }))).level, "public", "exact path only");
  // a human `public` label, on the file or on a folder above it, releases it (as it releases a catalog file)
  assert.equal(pathConfidentiality(f, "/home/u", lookup(snap({ found: [f], human: [human(f, "public")] }))).rule, `label:${f}`);
  assert.equal(pathConfidentiality(f, "/home/u", lookup(snap({ found: [f], human: [human("/home/u/ws/accounts", "public", true)] }))).level, "public");
  // a human label that binds it decides its level and bindings
  assert.equal(pathConfidentiality(f, "/home/u", lookup(snap({ found: [f], human: [human(f, "local-model")] }))).level, "local-model");
  // a catalog path rule on the same file keeps its own name
  const ld = "/home/u/ws/.launchdeck/auth.json";
  assert.equal(pathConfidentiality(ld, "/home/u", lookup(snap({ found: [ld] }))).rule, "shape:tool-login-file");
  // a derived row adds nothing over it (it is the strictest a machine gives)
  const d: DerivedLabel = { path: f, confidentiality: "local-model", bindings: [], sessionKey: "s", tool: "Write", sources: null, createdAt: 0, updatedAt: 0 };
  assert.deepEqual(pathConfidentiality(f, "/home/u", lookup(snap({ found: [f], derived: [d] }))), { level: "no-model", bindings: [], rule: CONTENT_RULE });
  // the text scan reads a command that names it, relative to where it runs
  const s = snap({ found: [f] });
  const withRoots = Object.assign((p: string) => composedLabel(p, s), { roots: () => labelRoots(s) });
  assert.equal(confidentialityForOrigin("cat accounts/power.yaml", "/home/u", withRoots, "/home/u/ws").level, "no-model");
  assert.equal(confidentialityForOrigin(`base64 ${f}`, "/home/u", withRoots).level, "no-model");
  // the guard gates it at the open (its own root)
  assert.ok(guardLabelRoots(new Map(), [], "/home/u", [f]).some((r) => r.path === f && r.shape === undefined));
  assert.ok(labelRoots(s).some((r) => r.path === f && r.level === "no-model"));
});

test("FoundLabelStore: written through, kept across a reopen, dropped on purpose; each change moves the generation", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-found-store-"));
  const db = join(dir, "symbols.sqlite");
  try {
    const a = new FoundLabelStore({ dbPath: db });
    assert.equal(a.add("relative/x.yaml", "password"), null, "an absolute path only");
    const g0 = a.generation();
    const row = a.add("/w/accounts/power.yaml", "password");
    assert.ok(row && row.field === "password");
    assert.ok(a.generation() > g0);
    const g1 = a.generation();
    assert.equal(a.add("/w/accounts/power.yaml", "password"), row, "the same verdict changes nothing");
    assert.equal(a.generation(), g1);
    a.add("/w/.cli/config.json", "user.token");
    a.close();
    const b = new FoundLabelStore({ dbPath: db });
    assert.deepEqual([...b.map().keys()].sort(), ["/w/.cli/config.json", "/w/accounts/power.yaml"], "kept across a restart");
    assert.equal(b.map().get("/w/.cli/config.json")!.field, "user.token");
    assert.ok(b.drop("/w/accounts/power.yaml"));
    assert.ok(!b.drop("/w/accounts/power.yaml"), "dropped once");
    b.close();
    const c = new FoundLabelStore({ dbPath: db });
    assert.deepEqual([...c.map().keys()], ["/w/.cli/config.json"]);
    c.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── the walk ────────────────────────────────────────────────────────────────

function tree(files: Record<string, string>): { dir: string; home: string; ws: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mdu-found-walk-"));
  const home = join(dir, "home");
  const ws = join(dir, "work", "proj");
  mkdirSync(home, { recursive: true });
  mkdirSync(ws, { recursive: true });
  for (const [rel, text] of Object.entries(files)) {
    const p = rel.startsWith("~/") ? join(home, rel.slice(2)) : join(ws, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, text);
  }
  return { dir, home, ws, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("the walk reads the candidates, lists a config file holding a credential (rule content:secret-key) and reports it found, never a value", () => {
  const t = tree({
    "accounts/power.yaml": `site: https://my.power.test\nemail: a@mail.test\npassword: ${PW}\n`,
    "config/app.yaml": "password: ${DB_PASSWORD}\n",
    "test/fixtures/login.json": JSON.stringify({ password: PW }),
    ".mcp.json": JSON.stringify({ mcpServers: { x: { env: { API_TOKEN: TOKEN } } } }),
    "~/.railway/config.json": JSON.stringify({ user: { token: TOKEN } }),
    "~/proj-elsewhere/config.yaml": `password: ${PW}\n`,
  });
  try {
    const r = discoverSecretsReport([t.home, t.ws], t.home);
    assert.ok(!JSON.stringify(r).includes(PW) && !JSON.stringify(r).includes(TOKEN), "paths and fields, never a value");
    const listed = new Map(r.files.map((f) => [f.path, f.rule]));
    assert.equal(listed.get(join(t.ws, "accounts/power.yaml")), CONTENT_RULE);
    assert.equal(listed.get(join(t.home, ".railway/config.json")), CONTENT_RULE, "a tool's dot-directory in HOME");
    for (const p of [join(t.ws, "config/app.yaml"), join(t.ws, "test/fixtures/login.json"), join(t.ws, ".mcp.json"), join(t.home, "proj-elsewhere/config.yaml")]) {
      assert.ok(!listed.has(p), `${p} is not listed`);
    }
    assert.deepEqual(r.found!.map((f) => [f.path, f.field]).sort(), [[join(t.home, ".railway/config.json"), "token"], [join(t.ws, "accounts/power.yaml"), "password"]].sort());
    assert.deepEqual(r.cleared, []);
    assert.ok(r.content!.read >= 3 && r.content!.capped === 0, JSON.stringify(r.content));
    // names only, on request
    const names = discoverSecretsReport([t.home, t.ws], t.home, undefined, { contentTier: false });
    assert.ok(!names.files.some((f) => f.rule === CONTENT_RULE) && (names.found ?? []).length === 0);
  } finally {
    t.cleanup();
  }
});

test("the walk clears a found label whose file it reads clean, keeps one it does not reach, and lists a found file outside its roots", () => {
  const t = tree({ "accounts/power.yaml": "site: https://my.power.test\npassword: ${POWER_PASSWORD}\n" });
  const elsewhere = join(t.dir, "other", ".cli", "config.json");
  mkdirSync(dirname(elsewhere), { recursive: true });
  writeFileSync(elsewhere, JSON.stringify({ token: TOKEN }));
  try {
    const power = join(t.ws, "accounts/power.yaml");
    const s = snap({ found: [power, elsewhere] });
    const lookup = (p: string) => composedLabel(p, s);
    const r = discoverSecretsReport([t.home, t.ws], t.home, lookup, { foundPaths: [power, elsewhere] });
    assert.deepEqual(r.cleared, [power], "read again, no credential: its label goes");
    const listed = new Map(r.files.map((f) => [f.path, f.rule]));
    assert.ok(!listed.has(power), "and it is not listed");
    assert.equal(listed.get(elsewhere), CONTENT_RULE, "a found file the walk does not reach is a candidate of its own (kept)");
  } finally {
    t.cleanup();
  }
});

// ── INI-family files, credential files by name, short passwords (§2.9) ─────

/** A short password the short-value rule takes: 6 characters. */
const SHORT_PW = "Tr0ub4";

test("contentProbeCandidate (§2.9): INI-family files and credential files by name; never a tool's own INI manifest or a template", () => {
  const ws = (p: string): boolean => contentProbeCandidate(p.split("/"), "workspace");
  const home = (p: string): boolean => contentProbeCandidate(p.split("/"), "home");
  for (const p of ["config.ini", "app.conf", "etc/my.cnf", "deploy/settings.cfg", "gradle.properties", "app/src/main/resources/application.properties", ".npmrc", ".pgpass", ".netrc", ".pypirc", "db/pg_service.conf", "pip.conf"]) {
    assert.ok(ws(p), `${p} is read in a workspace`);
  }
  for (const p of ["setup.cfg", "tox.ini", "pytest.ini", "mypy.ini", "gradle/wrapper/gradle-wrapper.properties", "config.example.ini", "app.sample.conf", "tests/fixtures/db.ini", "docs/my.cnf", ".vscode/x.ini", ".pg_service.conf.bak", ".wgetrc"]) {
    assert.ok(!ws(p), `${p} is not read`);
  }
  // HOME: its own .pg_service.conf, and INI files in a tool's dot-directory
  for (const p of [".pg_service.conf", ".odbc.ini", ".wakatime.cfg", ".config/myapp/app.conf", ".mytool/config.ini"]) assert.ok(home(p), p);
  for (const p of ["app.ini", "proj/config.ini", ".npmrc", "proj/.pg_service.conf"]) assert.ok(!home(p), p);
});

test("credentialInDataFile (§2.9): a password in an INI, .conf, .cnf or .properties file, a credential file by name, and a short or oddly named password", () => {
  const yes: Array<[string, string, string]> = [
    ["config.ini", `[database]\nhost = db.internal\nport = 5432\nuser = app\npassword = ${SHORT_PW}\n`, "database.password"],
    ["app.conf", "[db]\nhost=db\ndb_pw = k9z!q2x\n", "db.db_pw"],
    ["etc/my.cnf", "[client]\nuser=root\npassword=S3cret-77\n", "client.password"],
    ["gradle.properties", "org.gradle.jvmargs=-Xmx2048m\nsigning.password=Tr0ub4dor&3\n", "signing.password"],
    ["application.properties", `spring.datasource.url=jdbc:postgresql://db/app\nspring.datasource.password=${SHORT_PW}\n`, "spring.datasource.password"],
    ["mail.conf", `SMTP_HOST=smtp.mail.test\nSMTP_PASS=${SHORT_PW}\n`, "SMTP_PASS"],
    ["alembic.ini", `[alembic]\nsqlalchemy.url = postgresql://app:${SHORT_PW}@db/app\n`, "alembic.sqlalchemy.url.password"],
    [".pgpass", `db.internal:5432:app:app:${SHORT_PW}\n`, "app.password"],
    [".netrc", `machine api.example.com login me password ${SHORT_PW}\n`, "api.example.com.password"],
    [".npmrc", "registry=https://npm.pkg.example.com/\n//npm.pkg.example.com/:_authToken=Zq8xV2mN4bL7kP9wR3tY6uJ1\n", "npm.pkg.example.com._authToken"],
    [".pypirc", "[pypi]\nusername = __token__\npassword = pypi-AgEIcHlwaS5vcmcCJGQ4ZjE2YjI4LTNmNWQtNDk0Zi1hZTEwLWUwZDk3\n", "pypi.password"],
    ["pip.conf", "[global]\nindex-url = https://user:Tr0ub4x@pypi.example.com/simple\n", "global.pypi.example.com.password"],
    ["db/pg_service.conf", `[prod]\nhost=db\nuser=app\npassword=${SHORT_PW}\n`, "prod.password"],
    ["svc.yaml", `PGPASSWORD: ${SHORT_PW}\n`, "PGPASSWORD"],
    ["svc.yaml", `smtp:\n  pass: ${SHORT_PW}\n`, "smtp.pass"],
    ["home/alarm.yaml", "door:\n  access_code: 4821\n", "door.access_code"],
    ["bank.toml", "card_pin = \"4821\"\n", "card_pin"],
    ["registry.ini", "[a]\n_auth = dXNlcjpUcjB1YjRkb3IxMjM0\n", "a._auth"],
  ];
  for (const [path, text, field] of yes) {
    assert.equal(credentialInDataFile(`/ws/${path}`, text), field, `${path}: ${text}`);
    // the twin keeps the file and hides the value
    const x = extractSecretSpans(`/ws/${path}`, text);
    const twin = renderStructuredTwin(text, x.spans, () => "$MDU:nomodel_T[0]");
    for (const v of [SHORT_PW, "k9z!q2x", "S3cret-77", "Tr0ub4dor&3", "4821", "Zq8xV2mN4bL7kP9wR3tY6uJ1"]) {
      if (text.includes(v)) assert.ok(!twin.includes(v), `${path}: the twin hides ${v}:\n${twin}`);
    }
  }
  const no: Array<[string, string]> = [
    // ordinary config values stay public
    ["settings.ini", "[server]\nport = 5432\ndebug = true\nname = admin\nworkers = 4\n"],
    ["app.conf", "[auth]\nauth = basic\nauth_type = ldap\nuser = admin\n"],
    ["db.ini", "[db]\npassword = postgres\n"],                                 // a public default
    ["db.ini", "[db]\npassword = changeit\n"],
    ["db.ini", "[db]\npassword = ${DB_PASSWORD}\n"],                            // a reference
    ["db.ini", "[db]\npassword = %(db_pw)s\n"],
    ["db.ini", "[db]\npassword = DB_PASSWORD\n"],                               // an env variable's name
    ["db.ini", "[db]\npassword = keyring\n"],                                   // a mode
    ["db.ini", "[db]\npassword_file = /run/secrets/db\n"],                      // about a password
    ["db.ini", "; password = Tr0ub4\n[db]\nhost = db\n"],                       // a comment
    ["gpio.ini", "[pins]\nled_pin = 4821\npin = 17\n"],                        // hardware pins
    ["app.properties", "app.name=Shop\nlogin.password.label=Password\nlogin.pw.hint=Your password\n"],
    ["i18n/es.properties", "password=Contraseña\npw=Clave\n"],
    ["nginx.conf", "server {\n  listen 80;\n  auth_basic_user_file /etc/nginx/htpasswd;\n}\n"],
    ["my.cnf", "[mysqld]\nport=3306\nsocket=/var/run/mysqld/mysqld.sock\n"],
    [".npmrc", "engine-strict=true\nsave-exact=true\n"],
    ["svc.yaml", "password: hunter2\n"],
  ];
  for (const [path, text] of no) assert.equal(credentialInDataFile(`/ws/${path}`, text), null, `${path}: ${text}`);
});

test("the walk (§2.9): an INI file with a short password in a workspace and HOME's .pg_service.conf are found; a plain .conf is read clean", () => {
  const t = tree({
    "config.ini": `[database]\nhost = db.internal\nport = 5432\npassword = ${SHORT_PW}\n`,
    "nginx/site.conf": "server {\n  listen 80;\n}\n",
    "tests/fixtures/db.ini": `[db]\npassword = ${SHORT_PW}\n`,
    "~/.pg_service.conf": `[prod]\nhost=db\nuser=app\npassword=${SHORT_PW}\n`,
    "~/.mytool/config.ini": "[x]\nport = 1\n",
  });
  try {
    const r = discoverSecretsReport([t.home, t.ws], t.home);
    assert.ok(!JSON.stringify(r).includes(SHORT_PW), "paths and fields, never a value");
    const listed = new Map(r.files.map((f) => [f.path, f.rule]));
    assert.equal(listed.get(join(t.ws, "config.ini")), CONTENT_RULE);
    assert.equal(listed.get(join(t.home, ".pg_service.conf")), CONTENT_RULE);
    for (const p of [join(t.ws, "nginx/site.conf"), join(t.ws, "tests/fixtures/db.ini"), join(t.home, ".mytool/config.ini")]) assert.ok(!listed.has(p), `${p} is not listed`);
    assert.deepEqual(r.found!.map((f) => [f.path, f.field]).sort(), [[join(t.home, ".pg_service.conf"), "prod.password"], [join(t.ws, "config.ini"), "database.password"]].sort());
  } finally {
    t.cleanup();
  }
});
