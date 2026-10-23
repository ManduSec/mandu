/**
 * twin-comment-credentials.test.ts — the structured twin's CREDENTIAL BELT
 * and its glued-secret lines (plan 10 §2.4 and §11.8, 2026-10-17;
 * secret-extract.ts `withCredentialBelt`, egress-fingerprint.ts
 * `holdsSecretText`, claude-code-inbound.ts `isStructuredTwinText` and
 * `keyListingForms`).
 *
 * Found by an adversarial review (2026-10-17, P0): a `.env` with a
 * commented-out old key (`# OLD_STRIPE_KEY=sk_live_51Old…`) twinned with the
 * key RAW. The twin is what every program is served and Read shows, and the
 * value backstop matches verbatim bytes only, so `base64 ./.e*` or
 * `cut -c9- ./.e*` in a clean tree (a command not naming the file) handed the
 * model the key in a form nothing recognized. The fingerprint layer already
 * held it as a piece of the file; the generator did not mask it. Second: a
 * short secret value glued inside a longer word (`DB_PASS2=owl` beside
 * `MODE=owlish`) left a twin line under the 24-character line floor that
 * the structured rules and a Read released raw.
 *
 * Now, for every structured shape (dotenv, JSON, YAML, INI, TOML, .npmrc,
 * pgpass, netrc): every credential-shaped span the value backstop's
 * detectors find anywhere (comments included), and every bare token that
 * reads as a credential in a comment line, is a field of the file; a
 * comment's field is bound nowhere unless a label's `values:` names it; a
 * twin line still holding a secret text is a piece of the file whatever its
 * length; a key listing's form never reaches into a secret text nor holds a
 * piece.
 *
 * Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { extractSecretSpans, renderStructuredTwin } from "../../policy/secret-extract.js";
import { holdsSecretText, valueFingerprints, locateBareSecretTokens, bareSecretTokens } from "../../policy/egress-fingerprint.js";
import { isStructuredTwinText, structuredTwinExecOutputPath, structuredTwinKeyListingPath, type KeyListingTwin } from "../../policy/claude-code-inbound.js";
import { loadSymbolMap } from "../../symbol-table/symbol-table.js";
import { registerSecret, structuredTwinWithSecretsFor, wireServableTwin } from "../../secret-registry/registry.js";
import { syncRegisteredBindings } from "../../secret-registry/current-bindings.js";
import { compileValueRules } from "../../policy/value-bindings.js";
import type { LabelLookup } from "../../policy/secret-catalog.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis: what the twin may show

const OLD = "sk_" + "live_51OldKeyAbCdEfGhIjKlMnOpQrStUv";
const NEW = "sk_" + "live_51NewKeyZyXwVuTsRqPoNmLkJiHg";
const GHP = "ghp_R4nd0mT0k3nV4lu3F0rT3st1ngPurp0s3sXy";
const AKIA = "AKIAZ7Q2W3E4R5T6Y7U8";
const BARE = "Tq7vZ2pX9kLm4Rw8";

/** Every form of `secret` the reviewer tried (verbatim, minus its vendor
 *  prefix, reversed, base64 at each byte alignment, hex) and a stable
 *  12-character window of its body: none may be in a text the model sees. */
function encodings(secret: string): string[] {
  const body = secret.replace(/^(?:sk_live_|ghp_)/, "");
  const out = [secret, body, [...secret].reverse().join(""), [...body].reverse().join(""), Buffer.from(secret).toString("hex"), body.slice(2, 14)];
  for (let k = 0; k < 3; k++) {
    const b = Buffer.from("x".repeat(k) + secret).toString("base64");
    out.push(b.slice(4, -4));
  }
  return out;
}
const holdsAny = (text: string, secret: string): string | null => encodings(secret).find((e) => text.includes(e)) ?? null;

/** The twin as the generator renders it, each span its own named token. */
function twinOf(path: string, content: string): { twin: string; keys: string[]; shape: string | null } {
  const x = extractSecretSpans(path, content);
  const twin = x.shape === null ? "<whole-file>" : renderStructuredTwin(content, x.spans, (s) => `$MDU:nomodel_Read[abcd].${s.key}`);
  return { twin, keys: x.spans.flatMap((s) => [s.key, ...(s.parts ?? []).map((p) => p.key)]), shape: x.shape };
}

const SHAPES: Array<{ name: string; path: string; content: string; oldIn: string }> = [
  { name: "dotenv", path: "/w/app/.env", content: `# OLD_STRIPE_KEY=${OLD}\nSTRIPE_SECRET_KEY=${NEW}\nPORT=3000\n`, oldIn: "comment" },
  { name: "JSON (JSONC comment)", path: "/w/app/config.json", content: `{\n  // old: ${OLD}\n  "api_key": "${NEW}",\n  "port": 3000\n}\n`, oldIn: "comment" },
  { name: "JSON (a non-secret key's value)", path: "/w/app/settings.json", content: `{\n  "api_key": "${NEW}",\n  "description": "rotated from ${OLD} in March"\n}\n`, oldIn: "value" },
  { name: "YAML", path: "/w/app/secrets.yml", content: `# previous: ${OLD}\napi_key: ${NEW}\nregion: us-east-1\n`, oldIn: "comment" },
  { name: "YAML (a non-secret key's value)", path: "/w/app/app.yaml", content: `api_key: ${NEW}\nnotes: was ${GHP} until rotation\n`, oldIn: "value" },
  { name: "INI (; comment)", path: "/w/app/settings.ini", content: `[stripe]\n; old_key = ${OLD}\napi_key = ${NEW}\nmode = live\n`, oldIn: "comment" },
  { name: "TOML", path: "/w/app/wrangler.toml", content: `# old token ${OLD}\napi_token = "${NEW}"\nname = "worker"\n`, oldIn: "comment" },
  { name: ".npmrc", path: "/w/app/.npmrc", content: `# //registry.npmjs.org/:_authToken=${OLD}\n//registry.npmjs.org/:_authToken=${NEW}\nsave-exact=true\n`, oldIn: "comment" },
  { name: "pgpass", path: "/w/app/.pgpass", content: `# old: ${OLD}\ndb:5432:app:alice:${NEW}\n`, oldIn: "comment" },
  { name: "netrc", path: "/w/app/.netrc", content: `# old ${OLD}\nmachine api.example password ${NEW}\n`, oldIn: "comment" },
];

for (const s of SHAPES) {
  test(`${s.name}: a credential the shape rules left raw (in a ${s.oldIn}) is a field of the twin, in none of the reviewer's encodings`, () => {
    const t = twinOf(s.path, s.content);
    assert.notEqual(t.shape, null, "a structured twin");
    const secret = s.content.includes(OLD) ? OLD : GHP;
    assert.equal(holdsAny(t.twin, secret), null, `${t.twin}`);
    assert.equal(holdsAny(t.twin, NEW), null, "the shape's own secret stays masked");
    assert.ok(t.keys.some((k) => /^cred\.[A-Za-z0-9_]+$/.test(k)), `a belt field: ${t.keys.join(", ")}`);
    const span = extractSecretSpans(s.path, s.content).spans.find((x) => x.key.startsWith("cred."))!;
    assert.equal(span.value, secret, "the field stands for the credential itself");
    assert.equal(span.comment === true, s.oldIn === "comment", "a comment line's span says so");
  });
}

test("dotenv: the comment keeps its name readable (`OLD_STRIPE_KEY=` is no secret once the key is masked), and `. ./.env` still works", () => {
  const raw = `# OLD_STRIPE_KEY=${OLD}\nSTRIPE_SECRET_KEY=${NEW}\nPORT=3000\n`;
  const t = twinOf("/w/app/.env", raw);
  assert.equal(t.twin.split("\n")[0], "# OLD_STRIPE_KEY=$MDU:nomodel_Read[abcd].cred.OLD_STRIPE_KEY");
  // The "no migration" behaviour: a shell sourcing the twin reads every
  // value as the twin writes it, and the comment line stays inert.
  const dir = mkdtempSync(join(tmpdir(), "mandu-twin-belt-"));
  try {
    writeFileSync(join(dir, ".env"), t.twin);
    const out = execFileSync("bash", ["-c", "set -a; . ./.env; printf '%s|%s|%s' \"$STRIPE_SECRET_KEY\" \"$PORT\" \"${OLD_STRIPE_KEY-unset}\""], { cwd: dir, encoding: "utf8" });
    assert.equal(out, "$MDU:nomodel_Read[abcd].STRIPE_SECRET_KEY|3000|unset");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("dotenv: a key in a known format inside a value the value rules keep raw (a URL with no password) masks the whole value, single-quoted", () => {
  const raw = `STRIPE_URL=https://api.stripe.com/v1?key=${NEW}\nDEBUG=1\n`;
  const x = extractSecretSpans("/w/app/.env", raw);
  assert.equal(x.spans.length, 1);
  assert.equal(x.spans[0]!.value, `https://api.stripe.com/v1?key=${NEW}`);
  const twin = renderStructuredTwin(raw, x.spans, () => "$MDU:nomodel_Read[abcd].STRIPE_URL");
  assert.equal(twin, "STRIPE_URL='$MDU:nomodel_Read[abcd].STRIPE_URL'\nDEBUG=1\n");
});

test("a comment's bare token that reads as a credential (no vendor shape) is masked too; prose, URLs and words in a comment stay", () => {
  const raw = `# backup password ${BARE} (rotated)\n# see https://docs.stripe.com/keys for details\nSTRIPE_SECRET_KEY=${NEW}\n`;
  const t = twinOf("/w/app/.env", raw);
  assert.ok(!t.twin.includes(BARE), t.twin);
  assert.ok(t.twin.includes("# backup password $MDU:nomodel_Read[abcd].cred.token (rotated)"), t.twin);
  assert.ok(t.twin.includes("# see https://docs.stripe.com/keys for details"), "a comment with no credential is kept as written");
  // The belt's tokens are the fingerprint layer's own (one detector).
  assert.deepEqual(locateBareSecretTokens(`password ${BARE}.`).map((s) => `password ${BARE}.`.slice(s.start, s.end)), bareSecretTokens(`password ${BARE}.`));
});

test("the belt never turns a whole-file twin structured: a YAML with no secret key but a credential in a comment stays one placeholder", () => {
  const x = extractSecretSpans("/w/app/notes.yml", `# old: ${OLD}\nregion: us-east-1\n`);
  assert.equal(x.spans.length, 0, "no span: the shape found no secret value (whole-file twin, as before)");
});

test("the twin carries no piece the value backstop holds for the file: every credential span and comment token of the base row is masked", () => {
  const raw = `# OLD_STRIPE_KEY=${OLD}\n# aws ${AKIA} and ${GHP}\n# backup ${BARE}\nSTRIPE_SECRET_KEY=${NEW}\nPORT=3000\n`;
  const t = twinOf("/w/app/.env", raw);
  for (const p of valueFingerprints(raw, 0, { bareTokens: true })) {
    if (p.includes("\n")) continue; // the whole value without its final newline
    assert.ok(!t.twin.includes(p), `the twin holds the piece ${JSON.stringify(p)}:\n${t.twin}`);
  }
});

test("a file of many comment tokens is extracted in linear time (an agent-written file; `mandu why` runs it on demand)", () => {
  const lines = Array.from({ length: 40_000 }, (_, i) => `# k${i} ${BARE}${i}`);
  const raw = `${lines.join("\n")}\nSTRIPE_SECRET_KEY=${NEW}\n`;
  // CPU time, not the wall clock: a loaded CI host stretches the wall clock
  // with the same work, and a quadratic walk is far past the bound either way.
  const c0 = process.cpuUsage();
  const x = extractSecretSpans("/w/app/.env", raw);
  const c = process.cpuUsage(c0);
  const ms = Math.round((c.user + c.system) / 1000);
  assert.equal(x.spans.length, 40_001);
  assert.ok(ms < 10_000, `took ${ms} ms of CPU`);
});

test("more detector hits than the belt counts: the whole-file twin (fail-closed)", () => {
  const raw = `${Array.from({ length: 1001 }, (_, i) => `# ${GHP.slice(0, -4)}${String(i).padStart(4, "0")}`).join("\n")}\nSTRIPE_SECRET_KEY=${NEW}\n`;
  assert.equal(extractSecretSpans("/w/app/.env", raw).shape, null);
});

// ── registry: rows, bindings, npm ────────────────────────────────────────

function registered(name: string, content: string, label?: LabelLookup) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-twin-belt-reg-"));
  mkdirSync(join(dir, "app"));
  const path = join(dir, "app", name);
  writeFileSync(path, content);
  const dbPath = join(dir, "db.sqlite");
  const map = loadSymbolMap(dbPath);
  const r = registerSecret(map, { path, home: dir, ...(label ? { resolveLabel: label } : {}) }, dbPath);
  return { dir, path, dbPath, map, r, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("registry: the comment's key gets a field row of the file (the value backstop holds it), bound nowhere though the file is bound", () => {
  const label: LabelLookup = (p) => p.endsWith("/app/.env") ? { level: "no-model", bindings: ["api.stripe.com"], via: p } : null;
  const f = registered(".env", `# OLD_STRIPE_KEY=${OLD}\nSTRIPE_SECRET_KEY=${NEW}\n`, label);
  try {
    assert.ok(f.r.twin && !f.r.twin.includes(OLD), JSON.stringify(f.r));
    const rows = [...f.map.symbols.entries()].filter(([, e]) => e.origin === f.path && e.field !== null);
    const old = rows.find(([, e]) => e.value === OLD);
    const cur = rows.find(([, e]) => e.value === NEW);
    assert.ok(old && cur, rows.map(([n]) => n).join(", "));
    assert.equal(old![1].field, "cred.OLD_STRIPE_KEY", "named by the assignment before it, not by its line");
    assert.deepEqual(old![1].bindings ?? [], [], "an old key in a comment: bound nowhere");
    assert.deepEqual(cur![1].bindings, ["api.stripe.com"], "the value programs read: the file's bindings");
    // The sync (rule 1) keeps it so.
    syncRegisteredBindings(f.map, { resolveLabel: label, paths: [f.path] }, f.dbPath);
    assert.deepEqual(old![1].bindings ?? [], []);
    // The twin and its secret texts, re-rendered from the table.
    const t = structuredTwinWithSecretsFor(f.map, f.path, { resolveLabel: label })!;
    assert.equal(t.text, f.r.twin);
    assert.ok(t.secrets.includes(OLD));
  } finally {
    f.cleanup();
  }
});

test("registry: a label's `values:` entry naming the comment's field binds it (and only it)", () => {
  // The whole file's bindings are the intersection (none here); a value
  // with no entry takes the file's own (`fileBindings`).
  const label: LabelLookup = (p) => p.endsWith("/app/.env")
    ? { level: "no-model", bindings: [], fileBindings: ["api.stripe.com"], values: compileValueRules({ "cred.*": { bindings: ["old.example"] } })!, via: p }
    : null;
  const f = registered(".env", `# OLD_STRIPE_KEY=${OLD}\nSTRIPE_SECRET_KEY=${NEW}\n`, label);
  try {
    const rows = [...f.map.symbols.values()].filter((e) => e.origin === f.path && e.field !== null);
    assert.deepEqual(rows.find((e) => e.value === OLD)!.bindings, ["old.example"]);
    assert.deepEqual(rows.find((e) => e.value === NEW)!.bindings, ["api.stripe.com"]);
  } finally {
    f.cleanup();
  }
});

test("second review of !1621: a labelled INI's raw `api_note=<32 hex>` (a KNOWN LIMIT value) stays a piece of the file, so a Read of the twin is still masked; `port=5432` is not", () => {
  const HEX = "9f3c2a7b4e1d8f6a0c5b3e2d7a9f1c4e";
  const label: LabelLookup = (p) => p.endsWith("/app/svc.ini") ? { level: "no-model", bindings: [], via: p } : null;
  const f = registered("svc.ini", `[svc]\napi_key=${NEW}\napi_note=${HEX}\nport=5432\n`, label);
  try {
    const t = structuredTwinWithSecretsFor(f.map, f.path, { resolveLabel: label })!;
    assert.ok(t.text.includes(`api_note=${HEX}`), "raw in the twin: the KNOWN LIMIT");
    const base = [...f.map.symbols.values()].find((e) => e.origin === f.path && e.field === null)!;
    const pieces = valueFingerprints(base.value, 0, { bareTokens: true, twin: t });
    assert.ok(pieces.some((p) => t.text.includes(p) && p.includes(HEX)), pieces.join(" | "));
    assert.ok(!pieces.includes("port=5432"), pieces.join(" | "));
  } finally {
    f.cleanup();
  }
});

test("registry: the launch HOME's .npmrc with a commented-out old token is still served to npm as its twin (npm never reads a comment)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-twin-belt-npm-"));
  try {
    const path = join(dir, ".npmrc");
    writeFileSync(path, `# //registry.npmjs.org/:_authToken=npm_${"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"}\n//registry.npmjs.org/:_authToken=${NEW}\n`);
    const dbPath = join(dir, "db.sqlite");
    const map = loadSymbolMap(dbPath);
    const r = registerSecret(map, { path, home: dir }, dbPath);
    assert.ok(r.twin && !r.twin.includes("A1b2C3d4E5f6G7h8I9j0"), JSON.stringify(r));
    const w = wireServableTwin(map, path);
    assert.equal(w.servable, true, w.why);
    assert.deepEqual(w.hosts, ["registry.npmjs.org"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── the glued short secret ───────────────────────────────────────────────

const GLUED_RAW = `STRIPE_SECRET_KEY=${NEW}\nDB_PASS2=owl\nMODE=owlish\nPORT=3000\n`;

test("glued: the generator keeps `MODE=owlish` as written (a program reads MODE right); the twin's release rules refuse a rendering carrying it, and the line is no piece of the file", () => {
  const t = twinOf("/w/app/.env", GLUED_RAW);
  assert.ok(t.twin.includes("\nMODE=owlish\n"), "the twin is unchanged for programs");
  const twin = { text: t.twin, secrets: [NEW, "owl"] };
  // Not a GLOBAL piece (review of !1621): `NODE_ENV=development` beside
  // `DB_PASS=dev` masked every package.json and env dump holding it.
  const pieces = valueFingerprints(GLUED_RAW, 0, { bareTokens: true, twin });
  assert.ok(!pieces.includes("MODE=owlish"), pieces.join(" | "));
  // The twin's own release rules refuse it instead.
  const alloc = (tok: string) => tok.startsWith("$MDU:nomodel_Read[abcd].");
  assert.equal(isStructuredTwinText(t.twin, twin, alloc), false, "the whole twin carries the glued line");
  assert.equal(isStructuredTwinText(t.twin.split("\n").slice(0, 2).join("\n"), twin, alloc), true, "the lines around it do not");
  assert.equal(isStructuredTwinText(t.twin, t.twin, alloc), true, "(the text alone, as before, cannot tell)");
  const twinFor = () => ({ path: "/w/app/.env", ...twin });
  assert.equal(structuredTwinExecOutputPath(t.twin, twinFor), null, "`cat .env`");
  assert.equal(structuredTwinExecOutputPath(t.twin.split("\n")[0]!, twinFor), "/w/app/.env", "`grep STRIPE .env`");
});

test("glued: a short value that only a twin token's hash or field spells is no occurrence", () => {
  assert.equal(holdsSecretText("DB_PASS='$MDU:nomodel_Read[4e2a].DB_PASS'", ["PASS"]), true, "the key name holds PASS");
  assert.equal(holdsSecretText("X='$MDU:nomodel_Read[4e2a].X'", ["4e2a"]), false, "the hash alone");
});

test("a bare token the twin shows as it is (`DATABASE_PORT=5432`) is no piece of the file, so a Read of the twin is not masked whole; one holding a secret text still is", () => {
  const raw = `STRIPE_SECRET_KEY=${NEW}\nDATABASE_PORT=5432\nREDIS_URL=redis://localhost:6379\nexport DB_POOL_SIZE_2=10\n`;
  const t = twinOf("/w/app/.env", raw);
  const twin = { text: t.twin, secrets: [NEW] };
  const pieces = valueFingerprints(raw, 0, { bareTokens: true, twin });
  assert.ok(!pieces.includes("DATABASE_PORT=5432") && !pieces.includes("DB_POOL_SIZE_2=10"), pieces.join(" | "));
  // second review of !1621: a value part that reads as a credential keeps the token a piece
  assert.ok(pieces.includes("REDIS_URL=redis://localhost:6379"), pieces.join(" | "));
  // a token that is only part of a twin line stays a piece (YAML's value)
  const yaml = valueFingerprints(`api_key: ${NEW}\nnotes: ${BARE}\n`, 0, { bareTokens: true, twin: { text: `api_key: '$MDU:x'\nnotes: ${BARE}\n`, secrets: [NEW] } });
  assert.ok(yaml.includes(BARE), yaml.join(" | "));
  assert.ok(pieces.includes(NEW), "the secret itself stays a piece");
  assert.ok(pieces.every((p) => p === "REDIS_URL=redis://localhost:6379" || !t.twin.includes(p)), "no other piece is in the twin");
  // a twin token that holds a glued secret text stays a piece
  const glued = valueFingerprints("DB_PASS=k9z\nSERVICE_ID=k9z48172635\n", 0, { bareTokens: true, twin: { text: "DB_PASS='$MDU:nomodel_Read[abcd].DB_PASS'\nSERVICE_ID=k9z48172635\n", secrets: ["k9z"] } });
  assert.ok(glued.includes("SERVICE_ID=k9z48172635"), glued.join(" | "));
});

test("trailing comments: a credential-looking token after a value's comment marker is masked in every shape that has inline comments; a BOM does not hide a first-line comment", () => {
  const cases: Array<[string, string]> = [
    ["/w/app/.env", `DEBUG=1 # backup ${BARE}\nSTRIPE_SECRET_KEY=${NEW}\n`],
    ["/w/app/.env", `\uFEFF# backup ${BARE}\nSTRIPE_SECRET_KEY=${NEW}\n`],
    ["/w/app/a.yml", `host: db.internal # old ${BARE}\napi_key: ${NEW}\n`],
    ["/w/app/a.ini", `[s]\nhost = db ; old ${BARE}\napi_key = ${NEW}\n`],
    ["/w/app/a.toml", `host = "db"# old ${BARE}\napi_token = "${NEW}"\n`],
    ["/w/app/config.json", `{\n  "host": "db", // old ${BARE}\n  "api_key": "${NEW}"\n}\n`],
    ["/w/app/.npmrc", `save-exact=true ; old ${BARE}\n//registry.npmjs.org/:_authToken=${NEW}\n`],
  ];
  for (const [path, raw] of cases) {
    const t = twinOf(path, raw);
    assert.ok(!t.twin.includes(BARE) && t.twin.includes("cred.token"), `${path}:\n${t.twin}`);
    const span = extractSecretSpans(path, raw).spans.find((x) => x.value === BARE)!;
    assert.equal(span.comment, true, path);
  }
});

test("second review of !1621: a quote still open at the line's end is read both ways, so a comment after it is masked (dotenv, YAML, INI)", () => {
  const cases: Array<[string, string]> = [
    ["/w/app/.env", `NOTE= "abc # old ${BARE}\nSTRIPE_SECRET_KEY=${NEW}\n`],
    ["/w/app/a.yml", `note: "abc # old ${BARE}\napi_key: ${NEW}\n`],
    ["/w/app/a.ini", `[s]\nnote = 'abc ; old ${BARE}\napi_key = ${NEW}\n`],
  ];
  for (const [path, raw] of cases) {
    const t = twinOf(path, raw);
    assert.ok(!t.twin.includes(BARE), `${path}:\n${t.twin}`);
  }
});

test("JSONC block comments outside strings: a token inside one is masked, on one line or across lines; inside a string it is not a comment", () => {
  for (const raw of [
    `{\n  /* old: ${BARE} */ "api_key": "${NEW}"\n}\n`,
    `{\n  /*\n   * rotated, was ${BARE}\n   */\n  "api_key": "${NEW}"\n}\n`,
  ]) {
    const t = twinOf("/w/app/config.json", raw);
    assert.ok(!t.twin.includes(BARE) && t.twin.includes("*/"), t.twin);
  }
  const s = extractSecretSpans("/w/app/config.json", `{\n  "glob": "/* ${BARE} */",\n  "api_key": "${NEW}"\n}\n`).spans.find((x) => x.value === BARE && x.comment);
  assert.equal(s, undefined);
});

test("not a comment: a `#` inside quotes, glued to a dotenv or YAML value, or on a YAML block scalar's line is data, and a token there is left to the value rules", () => {
  const cases: Array<[string, string]> = [
    ["/w/app/.env", `NOTE="see # ${BARE}"\nSTRIPE_SECRET_KEY=${NEW}\n`],
    ["/w/app/a.yml", `note: 'it''s # ${BARE}'\napi_key: ${NEW}\n`],
    ["/w/app/a.yml", `script: |\n  echo hi\n  # ${BARE}\napi_key: ${NEW}\n`],
    ["/w/app/a.yml", `tag: v1#${BARE}\napi_key: ${NEW}\n`],
  ];
  for (const [path, raw] of cases) {
    const span = extractSecretSpans(path, raw).spans.find((x) => x.value === BARE && x.comment);
    assert.equal(span, undefined, `${path}: ${raw}`);
  }
  // after a block scalar ends, a comment is a comment again
  const after = extractSecretSpans("/w/app/a.yml", `script: |\n  echo hi\n# old ${BARE}\napi_key: ${NEW}\n`).spans.find((x) => x.value === BARE);
  assert.equal(after?.comment, true);
});

test("key listing: a glued line still stands as its key name when the name holds no secret text; never as itself", () => {
  const twin: KeyListingTwin = { path: "/w/app/.env", text: `STRIPE_SECRET_KEY='$MDU:nomodel_Read[abcd].STRIPE_SECRET_KEY'\nDB_PASS2='$MDU:nomodel_Read[abcd].DB_PASS2'\nMODE=owlish\nPORT=3000\n`, secrets: [NEW, "owl"] };
  const one = (out: string) => structuredTwinKeyListingPath(out, () => [[twin.path]], (p) => (p === twin.path ? twin : null));
  assert.equal(one("STRIPE_SECRET_KEY\nDB_PASS2\nMODE\nPORT"), twin.path, "cut -d= -f1 .env");
  assert.equal(one("STRIPE_SECRET_KEY=\nDB_PASS2=\nMODE=\nPORT="), twin.path, "grep -o '^[^=]*='");
  assert.equal(one("STRIPE_SECRET_KEY\nDB_PASS2\nMODE=owlish\nPORT"), null, "the glued line verbatim shows the value");
  assert.equal(one("STRIPE_SECRET_KEY\nDB_PASS2\nMODE=owl\nPORT"), null, "nor any prefix reaching into it");
});

test("key listing: a comment line holding a belt token can be skipped (it has no key part), and stands as its key part when it has one", () => {
  const twin: KeyListingTwin = { path: "/w/app/.env", text: `# backup password $MDU:nomodel_Read[abcd].cred.token\n# OLD_KEY=$MDU:nomodel_Read[abcd].cred.OLD_KEY\nSTRIPE_SECRET_KEY='$MDU:nomodel_Read[abcd].STRIPE_SECRET_KEY'\nPORT=3000\n`, secrets: [NEW, BARE] };
  const one = (out: string) => structuredTwinKeyListingPath(out, () => [[twin.path]], (p) => (p === twin.path ? twin : null));
  assert.equal(one("STRIPE_SECRET_KEY\nPORT"), twin.path, "grep -v '^#' | cut -d= -f1");
  assert.equal(one("# OLD_KEY\nSTRIPE_SECRET_KEY\nPORT"), twin.path, "the commented assignment's key part");
  assert.equal(one("PORT"), null, "a listing naming no secret key still fails");
});

test("key listing (review of !1604, hardening): a form holding one of the base row's pieces is refused; a piece running past the key name does not refuse it", () => {
  const text = `api_key: '$MDU:nomodel_Read[abcd].api_key'\n${BARE}: true\nport: 5432\n`;
  const pieces = valueFingerprints(`api_key: ${NEW}\n${BARE}: true\nport: 5432\n`, 0, { bareTokens: true });
  assert.ok(pieces.includes(BARE), pieces.join(" | "));
  const twin: KeyListingTwin = { path: "/w/app/a.yml", text, secrets: [NEW], pieces };
  const one = (out: string) => structuredTwinKeyListingPath(out, () => [[twin.path]], (p) => (p === twin.path ? twin : null));
  assert.equal(one(`api_key\n${BARE}\nport`), null, "a random key name that is a piece of the file");
  assert.equal(one("api_key\nport"), twin.path, "that token-free line skipped");
  const env: KeyListingTwin = { path: "/w/app/.env", text: `STRIPE_SECRET_KEY='$MDU:nomodel_Read[abcd].STRIPE_SECRET_KEY'\nDATABASE_PORT=5432\n`, secrets: [NEW], pieces: ["DATABASE_PORT=5432"] };
  assert.equal(structuredTwinKeyListingPath("STRIPE_SECRET_KEY\nDATABASE_PORT", () => [[env.path]], (p) => (p === env.path ? env : null)), env.path, "the bare token `DATABASE_PORT=5432` runs past the key name");
  assert.equal(structuredTwinKeyListingPath("STRIPE_SECRET_KEY\nDATABASE_PORT=5432", () => [[env.path]], (p) => (p === env.path ? env : null)), null, "the line verbatim holds the piece");
});
