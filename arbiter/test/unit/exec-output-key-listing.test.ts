/**
 * exec-output-key-listing.test.ts — "A key listing" (plan 10 §11.8,
 * 2026-10-16; claude-code-inbound.ts structuredTwinKeyListingPath): a shell
 * result holding NO token that is a strict in-order projection of ONE
 * registered file's structured twin (each line exactly a key part, or a
 * token-free twin line verbatim; token-free twin lines may be skipped,
 * token-bearing ones may not) names that file, when the command names it.
 * Anything else (a value, a reordered or partial listing of the secret lines,
 * two files, a token, a byte the twin does not give) does not, and the
 * path-derived mask stands.
 *
 * Found live (2026-10-16, demo-api-401-debug, Claude Code + Sonnet): the
 * model ran `cd shop-app && sed 's/=.*$//' .env` to see the variable names
 * without the values, and the output `STRIPE_SECRET_KEY\nPORT` was masked
 * whole because the command names `.env`. The review of !1604 added the
 * exact-bytes rule (no whitespace channel), the glued short secret, and the
 * candidates the command names.
 *
 * Mandu-new test. Pure: the candidates are lists.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { keyListingCandidates, keyListingLines, structuredTwinExecOutputPath, structuredTwinKeyListingPath, KEY_LISTING_OUTPUT_MAX, type KeyListingTwin } from "../../policy/claude-code-inbound.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the rule serves the confidentiality axis

const ENV = "/home/u/shop-app/.env";
const DEMO = "/home/u/demo/.env";
const NPMRC = "/home/u/.npmrc";
const AWS = "/home/u/.aws/credentials";
const T1 = "$MDU:nomodel_Read[9bbd].STRIPE_SECRET_KEY";
const T2 = "$MDU:nomodel_Read[9bbd].DATABASE_URL.password";
/** The demo's file as the guard serves it (the twin renders a value quoted). */
const DEMO_TWIN = `STRIPE_SECRET_KEY='${T1}'\nPORT=4242\n`;
/** A commented `.env` with an `export` line and a value inside a URL. */
const ENV_TWIN = `# fake values, made up by mandu demo\nexport STRIPE_SECRET_KEY='${T1}'\nPORT=4242\n\nDATABASE_URL='postgres://app:${T2}@db:5432/prod'\nLOG_LEVEL=info\n`;
const NPMRC_TWIN = "//registry.npmjs.org/:_authToken=$MDU:nomodel_Read[a1b2].registry.npmjs.org._authToken\nsave-exact=true\n";
const AWS_TWIN = "[default]\naws_access_key_id = $MDU:nomodel_Read[c3d4].default.aws_access_key_id\naws_secret_access_key = $MDU:nomodel_Read[c3d4].default.aws_secret_access_key\n";
const TWINS: KeyListingTwin[] = [
  { path: AWS, text: AWS_TWIN },
  { path: DEMO, text: DEMO_TWIN },
  { path: NPMRC, text: NPMRC_TWIN },
  { path: ENV, text: ENV_TWIN },
];
const byPath = (twins: readonly KeyListingTwin[]) => (p: string) => twins.find((t) => t.path === p) ?? null;
/** Every twin in one tier: the content rule alone (a match must be unique). */
const of = (out: string, codexHead = false): string | null => structuredTwinKeyListingPath(out, () => [TWINS.map((t) => t.path)], byPath(TWINS), { codexHead });

test("the live demo's command: `sed 's/=.*//' .env` printed `STRIPE_SECRET_KEY\\nPORT`, the keys of the file's twin", () => {
  assert.equal(of("STRIPE_SECRET_KEY\nPORT"), DEMO);
  assert.equal(of("STRIPE_SECRET_KEY\nPORT\n"), DEMO, "ONE final newline is framing");
  assert.equal(of("STRIPE_SECRET_KEY=\nPORT="), DEMO, "grep -o '^[A-Z_]*=': the key with its separator");
  assert.equal(of("STRIPE_SECRET_KEY\nPORT=4242"), DEMO, "a token-free line verbatim (sed leaving PORT as it is)");
});

test("a commented .env with `export` lines: sed, cut, awk and grep -o all pass, and a skipped comment or blank line too", () => {
  const keys = "# fake values, made up by mandu demo\nexport STRIPE_SECRET_KEY\nPORT\n\nDATABASE_URL\nLOG_LEVEL";
  assert.equal(of(keys), ENV, "sed 's/=.*//' / cut -d= -f1 / awk -F= '{print $1}' / grep -o '^[^=]*'");
  assert.equal(of("export STRIPE_SECRET_KEY\nPORT\nDATABASE_URL\nLOG_LEVEL"), ENV, "grep -v '^#' | grep -v '^$' | cut -d= -f1");
  assert.equal(of("export STRIPE_SECRET_KEY\nDATABASE_URL"), ENV, "only the secret keys: every token-free line skipped");
  assert.equal(of("export STRIPE_SECRET_KEY=\nDATABASE_URL="), ENV);
  assert.equal(of("export STRIPE_SECRET_KEY\nDATABASE_URL='postgres"), ENV, "cut -d: -f1 stops at the first `:`, before the token");
});

test("other shapes: an .npmrc (both `cut -d= -f1` and `cut -d: -f1`) and an INI file, each form exactly as a program prints it", () => {
  assert.equal(of("//registry.npmjs.org/:_authToken\nsave-exact"), NPMRC);
  assert.equal(of("//registry.npmjs.org/\nsave-exact=true"), NPMRC);
  assert.equal(of("[default]\naws_access_key_id\naws_secret_access_key"), AWS, "awk -F' = ' '{print $1}': the blank before the separator trimmed");
  assert.equal(of("[default]\naws_access_key_id \naws_secret_access_key "), AWS, "cut -d= -f1 keeps the blank, as the twin has it");
  assert.equal(of("aws_access_key_id =\naws_secret_access_key ="), AWS, "grep -o '^[^=]*='");
});

test("Codex: the exec envelope, and a script cell's printed result object (canonical JSON only), are looked through", () => {
  const head = "Chunk ID: 3f2a\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 4\nOutput:\n";
  assert.equal(of(`${head}STRIPE_SECRET_KEY\nPORT\n`, true), DEMO);
  const cell = "Script completed\nWall time 0.2 seconds\nOutput:\n";
  const obj = { chunk_id: "3ec25a", wall_time_seconds: 0.01, exit_code: 0, output: "STRIPE_SECRET_KEY\nPORT\n" };
  assert.equal(of(cell + JSON.stringify(obj), true), DEMO);
  assert.equal(of(cell + JSON.stringify(obj, null, 2) + "\n", true), DEMO, "a 2-space indent and one final newline");
  assert.equal(of(cell + JSON.stringify(obj).replace(",", " ,"), true), null, "a byte of whitespace JSON.parse takes but no canonical print has");
  assert.equal(of(cell + JSON.stringify(obj, null, 3), true), null, "another indent");
  assert.equal(of(cell + JSON.stringify({ chunk_id: "3ec25a", note: "x", output: "STRIPE_SECRET_KEY\nPORT\n" }), true), null, "an unknown key: tested as it is, fails");
  // Review of !1604: the head is looked through only on Codex, once, with
  // bounded digits; a program's own head (the key spelled as digits) is body.
  const digits = [...Buffer.from("sk_test_51abcDEFghiJKLmnoPQRstuvw")].map((b) => String(b).padStart(3, "0")).join("");
  const forged = `Chunk ID: 3f2a\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: ${digits}\nOutput:\n`;
  assert.equal(of(`${head}STRIPE_SECRET_KEY\nPORT\n`), null, "a well-formed head on another agent: the program printed it");
  assert.equal(of(`${forged}STRIPE_SECRET_KEY\nPORT\n`), null, "the probe on Claude Code");
  assert.equal(of(`${forged}STRIPE_SECRET_KEY\nPORT\n`, true), null, "the probe's digit run is past Codex's bound");
  assert.equal(of(`${head}${head}STRIPE_SECRET_KEY\nPORT\n`, true), null, "a second head after Codex's own");
});

test("review of !1604, the whitespace channel: only the twin's own bytes and one final newline pass; spaces, tabs, U+00A0, U+2003, trailing blank lines or a stray \\r do not", () => {
  for (const [why, out] of [
    ["a trailing space on a key", "STRIPE_SECRET_KEY \nPORT"],
    ["a trailing tab", "STRIPE_SECRET_KEY\t\nPORT"],
    ["U+00A0", "STRIPE_SECRET_KEY \nPORT"],
    ["U+2003 on the last line", "STRIPE_SECRET_KEY\nPORT "],
    ["two final newlines", "STRIPE_SECRET_KEY\nPORT\n\n"],
    ["a trailing blank line of spaces", "STRIPE_SECRET_KEY\nPORT\n  \n"],
    ["a \\r on an LF file", "STRIPE_SECRET_KEY\r\nPORT"],
    ["a space after the separator", "STRIPE_SECRET_KEY= \nPORT"],
  ] as const) {
    assert.equal(of(out), null, why);
  }
  // A CRLF file: the `\r` the twin line ends in, and nothing else
  const crlf: KeyListingTwin = { path: "/x/.env", text: `# note\r\nSTRIPE_SECRET_KEY='${T1}'\r\nPORT=4242\r\n` };
  const one = (out: string) => structuredTwinKeyListingPath(out, () => [["/x/.env"]], byPath([crlf]));
  assert.equal(one("# note\r\nSTRIPE_SECRET_KEY\nPORT"), "/x/.env", "cut -d= -f1: the comment keeps its \\r, the keys have none");
  assert.equal(one("# note\r\nSTRIPE_SECRET_KEY\r\nPORT\r\n"), "/x/.env");
  assert.equal(one("# note\r\r\nSTRIPE_SECRET_KEY\nPORT"), null, "a second \\r");
  // the parse alone
  assert.deepEqual(keyListingLines("A\nB\n"), ["A", "B"]);
  assert.equal(keyListingLines(""), null);
  assert.equal(keyListingLines("\n"), null);
});

test("review of !1604, the same channel in the structured rule: one final newline is framing, other trailing whitespace is not", () => {
  const lookup = (t: string) => (t === T1 ? { path: DEMO, text: DEMO_TWIN } : null);
  assert.equal(structuredTwinExecOutputPath(`STRIPE_SECRET_KEY='${T1}'\n`, lookup), DEMO);
  assert.equal(structuredTwinExecOutputPath(`STRIPE_SECRET_KEY='${T1}'`, lookup), DEMO);
  assert.equal(structuredTwinExecOutputPath(`STRIPE_SECRET_KEY='${T1}'\n\n`, lookup), DEMO, "the line's own newline is the twin's, then the framing one");
  assert.equal(structuredTwinExecOutputPath(`STRIPE_SECRET_KEY='${T1}'\n\n\n`, lookup), null);
  assert.equal(structuredTwinExecOutputPath(`STRIPE_SECRET_KEY='${T1}'  `, lookup), null);
  assert.equal(structuredTwinExecOutputPath(`STRIPE_SECRET_KEY='${T1}' \n`, lookup), null);
  assert.equal(structuredTwinExecOutputPath(`STRIPE_SECRET_KEY='${T1}'\n \t\n`, lookup), null);
});

test("review of !1604, the glued short secret: a twin line holding a secret text stands as nothing (skippable if token-free; a listing that needs it fails)", () => {
  // `DB_PASSWORD=x9k2q`: the generator leaves the short value glued inside
  // the longer word of another line (registry secrets: the value).
  const glued: KeyListingTwin = { path: "/x/.env", text: "DB_PASSWORD='$MDU:nomodel_Read[eeee].DB_PASSWORD'\nMY_x9k2q_SERVICE_ENDPOINT_URL=https://svc.example.com\n", secrets: ["x9k2q"] };
  const one = (t: KeyListingTwin) => (out: string) => structuredTwinKeyListingPath(out, () => [[t.path]], byPath([t]));
  assert.equal(one(glued)("DB_PASSWORD\nMY_x9k2q_SERVICE_ENDPOINT_URL"), null, "the glued key part would show the value");
  assert.equal(one(glued)("DB_PASSWORD\nMY_x9k2q_SERVICE_ENDPOINT_URL=https://svc.example.com"), null, "nor verbatim");
  assert.equal(one(glued)("DB_PASSWORD"), "/x/.env", "the token-free glued line skipped: no secret text printed");
  // the glued value on a token-bearing line: that line cannot stand, so no listing passes
  const gluedToken: KeyListingTwin = { path: "/x/.env", text: "API_KEY_x9k2q='$MDU:nomodel_Read[eeee].API_KEY_x9k2q'\nDB_PASSWORD='$MDU:nomodel_Read[eeee].DB_PASSWORD'\n", secrets: ["x9k2q"] };
  assert.equal(one(gluedToken)("API_KEY_x9k2q\nDB_PASSWORD"), null);
  assert.equal(one(gluedToken)("DB_PASSWORD"), null);
});

test("a value, a cut key, a reordered or partial listing of the secret lines, or any extra byte: no file (the mask stands)", () => {
  assert.equal(of("STRIPE_SECRET_KEY=sk_test_51abcDEF\nPORT"), null, "a raw value");
  assert.equal(of("STRIPE_SECRET_KEY='\nPORT"), null, "a cut past the separator");
  assert.equal(of("STRIPE_SEC\nPORT"), null, "a cut key");
  assert.equal(of("PORT\nSTRIPE_SECRET_KEY"), null, "sort: out of order");
  assert.equal(of("DATABASE_URL\nexport STRIPE_SECRET_KEY\nLOG_LEVEL\nPORT"), null, "sort on the commented file");
  assert.equal(of("export STRIPE_SECRET_KEY\nPORT"), null, "head -3 | cut: a token-bearing line (DATABASE_URL) left out");
  assert.equal(of("DATABASE_URL"), null, "grep DATABASE | cut: the STRIPE line left out");
  assert.equal(of("PORT"), null, "no secret key at all");
  assert.equal(of("# fake values, made up by mandu demo"), null, "a comment alone names no secret key");
  assert.equal(of("STRIPE_SECRET_KEY\nPORT\ndone"), null, "an extra line");
  assert.equal(of("STRIPE_SECRET_KEYx\nPORT"), null, "an extra byte");
  assert.equal(of(" STRIPE_SECRET_KEY\nPORT"), null, "a leading space");
  assert.equal(of("STRIPE_SECRET_KEY\nSTRIPE_SECRET_KEY\nPORT"), null, "a line twice");
  assert.equal(of("1 STRIPE_SECRET_KEY\n2 PORT"), null, "a gutter (cat -n)");
  assert.equal(of(""), null);
  assert.equal(of("\n \n"), null, "whitespace only");
});

test("a token, an encoded token, or two files in one output: no file", () => {
  assert.equal(of(`STRIPE_SECRET_KEY='${T1}'\nPORT`), null, "a token: the structured rule's case, not this one");
  assert.equal(of("STRIPE_SECRET_KEY\nPORT\n$MDU:nomodel_Read[9bbd]"), null);
  assert.equal(of("STRIPE_SECRET_KEY\n%24MDU%3Anomodel_Read%5B9bbd%5D.STRIPE_SECRET_KEY"), null, "percent-encoded");
  const b64 = Buffer.from(T1).toString("base64");
  assert.equal(of(`STRIPE_SECRET_KEY\n${b64}`), null, "base64");
  assert.equal(of("STRIPE_SECRET_KEY\nPORT\n[default]\naws_access_key_id\naws_secret_access_key"), null, "cut -d= -f1 .env credentials");
  assert.equal(of("[default]\naws_access_key_id\naws_secret_access_key\nSTRIPE_SECRET_KEY\nPORT"), null);
});

test("bounds: an oversized output is never examined, nor are the candidates asked; no candidate, or a twin with no token line, names nothing", () => {
  let asked = false;
  const big = `STRIPE_SECRET_KEY\nPORT\n${"x".repeat(KEY_LISTING_OUTPUT_MAX)}`;
  assert.equal(structuredTwinKeyListingPath(big, () => { asked = true; return [[DEMO]]; }, byPath(TWINS)), null);
  assert.equal(asked, false, "the result is no listing: the registry is not read");
  assert.equal(structuredTwinKeyListingPath("STRIPE_SECRET_KEY\nPORT", () => [], byPath(TWINS)), null);
  const flat: KeyListingTwin = { path: "/x/.env", text: "PORT=4242\nLOG_LEVEL=info\n" };
  assert.equal(structuredTwinKeyListingPath("PORT\nLOG_LEVEL", () => [["/x/.env"]], byPath([flat])), null, "a twin with no token is no structured twin");
});

test("the in-order walk is not greedy: a comment that reads like a key does not take the key's place", () => {
  const t: KeyListingTwin = { path: "/x/.env", text: `KEY\nKEY='$MDU:nomodel_Read[eeee].KEY'\n` };
  const one = (out: string) => structuredTwinKeyListingPath(out, () => [["/x/.env"]], byPath([t]));
  assert.equal(one("KEY"), "/x/.env");
  assert.equal(one("KEY\nKEY"), "/x/.env");
  assert.equal(one("KEY\nKEY\nKEY"), null);
});

test("review of !1604, the file named: only files the command names, in tiers; a tier with two matches names nothing", () => {
  const HOME_ENV = "/home/u/.env";
  const SHOP = "/home/u/proj/shop-app/.env";
  const OTHER = "/home/u/proj/other/.env";
  const reg = [HOME_ENV, OTHER, SHOP, "/home/u/.aws/credentials"];
  // the start directory known: words resolve where the shell read them, no suffix guess
  assert.deepEqual(keyListingCandidates("cd shop-app && sed 's/=.*//' .env", reg, { startDir: "/home/u/proj", home: "/home/u" }), [[SHOP]]);
  assert.deepEqual(keyListingCandidates("sed 's/=.*//' shop-app/.env", reg, { startDir: "/home/u/proj", home: "/home/u" }), [[SHOP]]);
  assert.deepEqual(keyListingCandidates("cut -d= -f1 .env", reg, { startDir: "/home/u/proj", home: "/home/u" }), [], "proj/.env is not registered: the home-wide .env is not guessed");
  assert.deepEqual(keyListingCandidates("cut -d= -f1 ~/.env", reg, { startDir: "/home/u/proj", home: "/home/u" }), [[HOME_ENV]]);
  assert.deepEqual(keyListingCandidates(`cut -d= -f1 ${SHOP}`, reg, {}), [[SHOP]], "an absolute word");
  // the start directory unknown: a word read after a cd is joined to it; one
  // read where the command started is a bare suffix
  assert.deepEqual(keyListingCandidates("cd shop-app && sed 's/=.*//' .env", reg, { home: "/home/u" }), [[SHOP]], "read in shop-app only");
  assert.deepEqual(keyListingCandidates("cut -d= -f1 .env", reg, {}), [[HOME_ENV, OTHER, SHOP]]);
  assert.deepEqual(keyListingCandidates("cut -d= -f1 notes.txt", reg, {}), [], "a command that names no registered file names no candidate");
  assert.deepEqual(keyListingCandidates("", reg, {}), []);

  // through the rule: the home-wide .env with the same keys never wins over the named one
  const twin = `STRIPE_SECRET_KEY='${T1}'\nPORT=4242\n`;
  const twins: KeyListingTwin[] = [HOME_ENV, OTHER, SHOP].map((path) => ({ path, text: twin }));
  const rule = (command: string, startDir?: string) =>
    structuredTwinKeyListingPath("STRIPE_SECRET_KEY\nPORT", () => keyListingCandidates(command, reg, { ...(startDir ? { startDir } : {}), home: "/home/u" }), byPath(twins));
  assert.equal(rule("cd shop-app && sed 's/=.*//' .env", "/home/u/proj"), SHOP);
  assert.equal(rule("cd shop-app && sed 's/=.*//' .env"), SHOP, "no start dir: the cd-joined tier");
  assert.equal(rule("cut -d= -f1 .env"), null, "no start dir, three files match `.env`: ambiguous, none named");
  assert.equal(rule("cut -d= -f1 .env", "/home/u/proj"), null, "the word resolves to no registered file");
  assert.equal(rule("echo STRIPE_SECRET_KEY PORT"), null, "a command that names no file");
});

test("review of !1604, second pass: a word is read in the directory the command is in AT THAT POINT (cd tracked in order, subshells, pipelines, `||`)", () => {
  const P = "/home/u/proj";
  const TOP = `${P}/.env`;
  const SHOP = `${P}/shop-app/.env`;
  const reg = [TOP, SHOP];
  const c = (command: string, startDir: string | null = P) => keyListingCandidates(command, reg, { ...(startDir ? { startDir } : {}), home: "/home/u" });
  // the reviewer's case: both ./.env and ./shop-app/.env registered
  assert.deepEqual(c("cd shop-app && sed 's/=.*//' .env"), [[SHOP]], "after the cd, .env is shop-app's only");
  assert.deepEqual(c("cut -d= -f1 .env && cd shop-app"), [[TOP]], "a cd after the word does not move it");
  assert.deepEqual(c("cd shop-app; cd ..; cut -d= -f1 .env"), [[TOP]]);
  assert.deepEqual(c('cd "shop-app" && cut -d= -f1 .env'), [[SHOP]], "a quoted target");
  // a subshell's cd ends with it
  assert.deepEqual(c("(cd shop-app && cut -d= -f1 .env)"), [[SHOP]]);
  assert.deepEqual(c("(cd shop-app) && cut -d= -f1 .env"), [[TOP]], "the subshell's cd is gone");
  assert.deepEqual(c("(cd shop-app && cut -d= -f1 .env); cut -d= -f1 .env"), [[TOP, SHOP]], "both words name a file; the content decides");
  // a cd in a pipeline element or a background job changes nothing after it
  assert.deepEqual(c("cd shop-app | true; cut -d= -f1 .env"), [[TOP]]);
  assert.deepEqual(c("cd shop-app & cut -d= -f1 .env"), [[TOP]]);
  // a cd that may not have happened, or goes somewhere unknown: no word after it names a file
  assert.deepEqual(c("cd shop-app || exit 1; cut -d= -f1 .env"), []);
  assert.deepEqual(c("cd $DIR && cut -d= -f1 .env"), []);
  assert.deepEqual(c("cd && cut -d= -f1 .env"), []);
  assert.deepEqual(c("cd - && cut -d= -f1 .env"), []);
  // absolute and ~ words do not depend on the directory
  assert.deepEqual(c(`cd $DIR && cut -d= -f1 ${SHOP}`), [[SHOP]]);
  // start directory unknown: the same order, by suffix
  assert.deepEqual(c("cd shop-app && cut -d= -f1 .env", null), [[SHOP]]);
  assert.deepEqual(c("(cd shop-app) && cut -d= -f1 .env", null), [[TOP, SHOP]], "read where the command started: a bare suffix, both match it");
  // a word holding an expansion is no path word
  assert.deepEqual(c("cut -d= -f1 $HOME/proj/.env"), []);
});
