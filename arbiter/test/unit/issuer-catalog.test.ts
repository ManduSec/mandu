/**
 * issuer-catalog — the issuer bindings' table as data (confidentiality.md
 * §2.3, "Where the table lives, and what checks a file"): one JSON file per
 * issuer, checked and compiled by issuer-catalog.ts into `ISSUERS`.
 *
 *   1. THE PIN: the table compiled from the files is, row for row and in
 *      order, the `ISSUERS` array it replaced (each field, each format's
 *      `source` and `flags`), so the move changed no release;
 *   2. the shipped files pass every check, the directory and the index
 *      name the same files, and each file's examples name its issuer;
 *   3. every check refuses what it exists to refuse, and a file that fails
 *      one is LEFT OUT WHOLE (fail-closed: its keys ask), never matched
 *      more loosely; a clash between files leaves out both sides.
 *
 * Pure (a temp directory for the directory check). Mandu-new test. Axes
 * stated: `secrets` (the issuer bindings are a confidentiality rule).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ISSUERS, ISSUER_CATALOG_PROBLEMS, ISSUER_SAMPLES, issuerOfValue } from "../../policy/issuer-bindings.js";
import {
  checkIssuerFile, expandSample, formatProblems, issuerDocProblem, issuerHostProblem, literalPrefixes, loadIssuerCatalog,
  type Issuer,
} from "../../policy/issuer-catalog.js";
import { ISSUER_FILES } from "../../policy/issuers/index.js";
import { isPlaceholder } from "../../policy/secret-detectors.js";
import { checkIssuerDir, ISSUER_DIR } from "../../scripts/check-issuers.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

// ── 1. the pin ──────────────────────────────────────────────────────────────

/** `ISSUERS` as it was written in issuer-bindings.ts before the move to
 *  files (2026-10-19 to 2026-10-24), copied verbatim. A change to one of
 *  these rows is a change to what is released without asking: it updates
 *  this copy on purpose, with the issuer's docs. */
const TABLE_2026_10_19: readonly Issuer[] = [
  {
    id: "stripe", name: "Stripe",
    formats: [/^(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,247}$/],
    shapes: ["sk_live_…", "sk_test_…", "rk_live_…", "rk_test_…"],
    hosts: ["api.stripe.com", "files.stripe.com"],
    docs: ["https://docs.stripe.com/api", "https://docs.stripe.com/api/files/create"],
  },
  {
    id: "github", name: "GitHub",
    formats: [/^gh[pous]_[0-9A-Za-z]{36,251}$/, /^github_pat_[0-9A-Za-z_]{50,244}$/],
    shapes: ["ghp_…", "gho_…", "ghu_…", "ghs_…", "github_pat_…"],
    hosts: ["api.github.com", "uploads.github.com"],
    docs: ["https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api", "https://docs.github.com/en/rest/releases/assets#upload-a-release-asset"],
  },
  {
    id: "notion", name: "Notion",
    formats: [/^ntn_[0-9A-Za-z]{40,64}$/],
    shapes: ["ntn_…"],
    hosts: ["api.notion.com"],
    docs: ["https://developers.notion.com/reference/authentication"],
  },
  {
    id: "openai", name: "OpenAI",
    formats: [/^sk-(?:proj|svcacct|admin)-[0-9A-Za-z_-]{20,250}$/],
    shapes: ["sk-proj-…", "sk-svcacct-…", "sk-admin-…"],
    hosts: ["api.openai.com"],
    docs: ["https://platform.openai.com/docs/api-reference/authentication"],
  },
  {
    id: "slack", name: "Slack",
    formats: [/^xox[bp]-[0-9A-Za-z-]{20,250}$/],
    shapes: ["xoxb-…", "xoxp-…"],
    hosts: ["slack.com"],
    docs: ["https://docs.slack.dev/apis/web-api/"],
  },
  {
    id: "npm", name: "npm",
    formats: [/^npm_[0-9A-Za-z]{36}$/],
    shapes: ["npm_…"],
    hosts: ["registry.npmjs.org"],
    docs: ["https://docs.npmjs.com/cli/using-npm/registry"],
  },
  {
    id: "pypi", name: "PyPI",
    formats: [/^pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,2000}$/],
    shapes: ["pypi-AgEIcHlwaS5vcmc…"],
    hosts: ["upload.pypi.org"],
    docs: ["https://docs.pypi.org/api/upload/", "https://pypi.org/help/#apitoken"],
  },
  {
    id: "huggingface", name: "Hugging Face",
    formats: [/^hf_[0-9A-Za-z]{34}$/],
    shapes: ["hf_…"],
    hosts: ["huggingface.co", "router.huggingface.co"],
    docs: ["https://huggingface.co/docs/hub/security-tokens", "https://huggingface.co/docs/inference-providers/index"],
  },
  {
    id: "sendgrid", name: "SendGrid",
    formats: [/^SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}$/],
    shapes: ["SG.….…"],
    hosts: ["api.sendgrid.com"],
    docs: ["https://www.twilio.com/docs/sendgrid/api-reference/how-to-use-the-sendgrid-v3-api/authentication"],
  },
];

const plain = (i: Issuer) => ({
  keys: Object.keys(i),
  id: i.id, name: i.name,
  formats: i.formats.map((f) => ({ source: f.source, flags: f.flags })),
  shapes: [...i.shapes], hosts: [...i.hosts], docs: [...i.docs],
});

test("the pin: the files compile to the table they replaced, field for field, format for format, in order", () => {
  assert.deepEqual(ISSUER_CATALOG_PROBLEMS, [], "no shipped file is left out");
  assert.deepEqual(
    ISSUERS.slice(0, TABLE_2026_10_19.length).map(plain),
    TABLE_2026_10_19.map(plain),
    "a row of the 2026-10-19 table changed: a host, a format or a name released without asking changed with it",
  );
  // New issuers are appended (the order is printed); none replaces a row.
  assert.deepEqual(ISSUERS.slice(0, TABLE_2026_10_19.length).map((i) => i.id), TABLE_2026_10_19.map((i) => i.id));
});

test("the pin holds for values too: each old row's formats accept and refuse exactly what they did", () => {
  const values = [...ISSUER_SAMPLES.values()].flatMap((s) => [...s.examples, ...s.nonExamples]);
  for (const old of TABLE_2026_10_19) {
    const now = ISSUERS.find((i) => i.id === old.id)!;
    for (const v of values) {
      assert.equal(now.formats.some((f) => f.test(v)), old.formats.some((f) => f.test(v)), `${old.id}: ${v.slice(0, 24)}…`);
    }
  }
});

// ── 2. the shipped files ────────────────────────────────────────────────────

test("the shipped files: every check passes, the directory is the index, and the index holds the files' own bytes", () => {
  const dir = checkIssuerDir();
  assert.deepEqual(dir.problems, []);
  assert.deepEqual(dir.issuers.map((i) => i.id), ISSUERS.map((i) => i.id));
  assert.equal(ISSUERS.length, ISSUER_FILES.length, "every file compiled");
  for (const f of ISSUER_FILES) {
    assert.deepEqual(JSON.parse(readFileSync(join(ISSUER_DIR, f.file), "utf8")), f.data, f.file);
  }
});

test("every issuer's examples name it (and only it); its non-examples do not; every example is a stand-in", () => {
  for (const i of ISSUERS) {
    const s = ISSUER_SAMPLES.get(i.id)!;
    assert.ok(s.examples.length > 0, i.id);
    for (const v of s.examples) {
      assert.equal(issuerOfValue(v)?.id, i.id, `${i.id}: ${v.slice(0, 24)}…`);
      assert.ok(isPlaceholder(v), `${i.id}: an example is a stand-in by Mandu's own test`);
    }
    for (const v of s.nonExamples) assert.notEqual(issuerOfValue(v)?.id, i.id, `${i.id} non-example: ${v.slice(0, 24)}…`);
  }
});

// ── 3. the checks ───────────────────────────────────────────────────────────

const STRIPE = ISSUER_FILES.find((f) => f.file === "stripe.json")!.data as Record<string, unknown>;
const withStripe = (patch: Record<string, unknown>, drop: string[] = []): Record<string, unknown> => {
  const o: Record<string, unknown> = { ...STRIPE, ...patch };
  for (const k of drop) delete o[k];
  return o;
};
/** A format and the shapes and examples that fit it, for format cases. */
const fmt = (source: string, shape = "abc_…", example = "abc_{x*24}") => withStripe({ formats: [source], shapes: [shape], examples: [example], non_examples: [] });
const refused = (file: string, data: unknown, why: RegExp): void => {
  const c = checkIssuerFile(file, data);
  assert.equal(c.issuer, null, `${file} ${JSON.stringify(data).slice(0, 160)} must be refused`);
  assert.ok(c.problems.some((p) => why.test(p)), `${JSON.stringify(c.problems)} should match ${why}`);
  // …and loading it leaves it out whole: the rest still load, it does not.
  const others = ISSUER_FILES.filter((f) => f.file !== file.toLowerCase());
  const cat = loadIssuerCatalog([{ file, data }, ...others]);
  assert.deepEqual(cat.issuers.map((i) => `${i.id}.json`), others.map((f) => f.file), "left out, the rest loaded");
  assert.ok(cat.problems.length > 0, "and reported");
};

test("a file that is not an object, or whose fields are wrong, is refused", () => {
  for (const d of [null, "stripe", [STRIPE], 7]) refused("stripe.json", d, /must be a JSON object/);
  refused("stripe.json", withStripe({ wildcard_hosts: ["*.stripe.com"] }), /unknown field 'wildcard_hosts'/);
  for (const k of ["id", "name", "formats", "shapes", "hosts", "docs", "examples"]) refused("stripe.json", withStripe({}, [k]), new RegExp(`missing field '${k}'`));
  refused("stripe.json", withStripe({ hosts: [] }), /hosts: must be a non-empty list/);
  refused("stripe.json", withStripe({ hosts: "api.stripe.com" }), /hosts: must be a non-empty list/);
  refused("stripe.json", withStripe({ hosts: ["api.stripe.com", "api.stripe.com"] }), /hosts: has a repeated entry/);
  refused("stripe.json", withStripe({ docs: [7] }), /docs: every entry must be a string/);
  refused("stripe.json", withStripe({ name: "" }), /name:/);
});

test("the id is the file name, in lower case", () => {
  refused("stripe.json", withStripe({ id: "stripe2" }), /must equal the file name/);
  refused("Stripe.json", withStripe({ id: "Stripe" }), /id: must be lower-case/);
  refused("stripe.json", withStripe({ id: "../stripe" }), /id: must be lower-case/);
});

test("a format must compile, be anchored over the whole value, and begin with a fixed prefix of 3 or more", () => {
  refused("stripe.json", fmt("^abc_[0-9A-Za-z{20,247}$"), /does not compile/);
  refused("stripe.json", fmt("abc_[0-9A-Za-z]{20,247}$"), /must start with \^/);
  refused("stripe.json", fmt("^abc_[0-9A-Za-z]{20,247}"), /must end with \$/);
  refused("stripe.json", fmt("^abc_[0-9A-Za-z]{20,247}\\$"), /escaped \$/);
  refused("stripe.json", fmt("^abc_[0-9A-Za-z]{20}|[0-9A-Za-z]{20,247}$"), /top-level \|/);
  refused("stripe.json", fmt("^abc_(x+)[0-9A-Za-z]{20,247}$"), /\(\?: … \) groups only/);
  refused("stripe.json", fmt("^abc_(?=x)[0-9A-Za-z]{20,247}$"), /\(\?: … \) groups only/);
  refused("stripe.json", fmt("^abc_(?:x)\\1[0-9A-Za-z]{20,247}$"), /backreference/);
  refused("stripe.json", fmt("^abc_(?:[0-9A-Za-z]+)+$"), /repeats a group that itself repeats/);
  refused("stripe.json", fmt("^abc_(?:(?:x+)y)*[0-9A-Za-z]{20}$"), /repeats a group that itself repeats/);
  refused("stripe.json", fmt("^abc_x^[0-9A-Za-z]{20}$"), /has \^ inside/);
  // No fixed prefix, or one too short to name anyone.
  refused("stripe.json", fmt("^[0-9A-Za-z]{24,247}$", "…", "{x*24}"), /fixed literal prefix/);
  refused("stripe.json", fmt("^.{3}_[0-9A-Za-z]{20}$", "…", "abc_{x*20}"), /fixed literal prefix/);
  refused("stripe.json", fmt("^ab[0-9A-Za-z]{20,247}$", "ab…", "ab{x*24}"), /fixed literal prefix/);
  refused("stripe.json", fmt("^ab?c_[0-9A-Za-z]{20,247}$", "a…", "abc_{x*24}"), /fixed literal prefix/);
  refused("stripe.json", fmt("^(?:abc|d)_[0-9A-Za-z]{20,247}$", "abc_…", "abc_{x*24}"), /fixed literal prefix/);
});

test("literalPrefixes reads literal characters, small sets and choices of literals, and stops at anything repeated", () => {
  const cases: Array<[string, string[]]> = [
    ["^(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,247}$", ["sk_live_", "sk_test_", "rk_live_", "rk_test_"]],
    ["^gh[pous]_[0-9A-Za-z]{36,251}$", ["ghp_", "gho_", "ghu_", "ghs_"]],
    ["^SG\\.[0-9A-Za-z_-]{22}\\.[0-9A-Za-z_-]{43}$", ["SG."]],
    ["^pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,2000}$", ["pypi-AgEIcHlwaS5vcmc"]],
    ["^abc+d$", ["ab"]],
    ["^abc(?:de)?f$", ["abc"]],
    ["^ab[a-z]c$", ["ab"]],
    ["^ab\\dc$", ["ab"]],
    ["^ab.c$", ["ab"]],
    ["^abc$", ["abc"]],
    ["abc$", []],
  ];
  for (const [src, want] of cases) assert.deepEqual(literalPrefixes(src).sort(), want.sort(), src);
  assert.deepEqual(formatProblems("^(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,247}$"), []);
});

test("the shapes in words are exactly the formats' prefixes, each followed by …", () => {
  refused("stripe.json", withStripe({ shapes: ["sk_live_…", "sk_test_…", "rk_live_…"] }), /shapes: must name exactly/);
  refused("stripe.json", withStripe({ shapes: ["sk_live_…", "sk_test_…", "rk_live_…", "rk_test_…", "pk_live_…"] }), /shapes: must name exactly/);
  refused("stripe.json", withStripe({ shapes: ["sk_live_", "sk_test_…", "rk_live_…", "rk_test_…"] }), /must show the prefix followed by …/);
});

test("a host is a lower-case DNS name of two labels or more: no scheme, port, path, wildcard, address, suffix or shared host", () => {
  const bad: Array<[string, RegExp]> = [
    ["API.stripe.com", /lower-case DNS name/], ["https://api.stripe.com", /lower-case DNS name/],
    ["api.stripe.com:443", /lower-case DNS name/], ["api.stripe.com/v1", /lower-case DNS name/],
    ["*.stripe.com", /lower-case DNS name/], ["api.stripe.com.", /lower-case DNS name/],
    ["10.0.0.7", /lower-case DNS name/], ["[::1]", /lower-case DNS name/], ["localhost", /lower-case DNS name/],
    ["com", /lower-case DNS name/], [" api.stripe.com", /lower-case DNS name/], ["user@api.stripe.com", /lower-case DNS name/],
    ["co.uk", /public suffix/], ["com.au", /public suffix/],
    ["stripe.github.io", /under github\.io/], ["api-stripe.vercel.app", /under vercel\.app/], ["x.y.amazonaws.com", /under amazonaws\.com/],
  ];
  for (const [h, why] of bad) {
    assert.match(issuerHostProblem(h) ?? "", why, h);
    refused("stripe.json", withStripe({ hosts: ["api.stripe.com", h] }), why);
  }
  for (const h of ["api.stripe.com", "slack.com", "huggingface.co", "api.example.co.uk"]) assert.equal(issuerHostProblem(h), null, h);
});

test("a doc is an https:// URL with no user name", () => {
  for (const d of ["http://docs.stripe.com/api", "docs.stripe.com/api", "https://user:pw@docs.stripe.com/api", "ftp://docs.stripe.com", "https://10.0.0.1/docs"]) {
    assert.notEqual(issuerDocProblem(d), null, d);
    refused("stripe.json", withStripe({ docs: [d] }), /docs:/);
  }
  assert.equal(issuerDocProblem("https://docs.stripe.com/api#auth"), null);
});

test("examples: written with a run of x, each matching the issuer, every format covered; no non-example matches", () => {
  assert.deepEqual(expandSample("sk_live_{x*3}{y*2}"), { value: "sk_live_xxxyy", runs: 2 });
  assert.ok("problem" in expandSample("sk_live_{x*}"));
  assert.ok("problem" in expandSample("sk_live_{x*0}"));
  assert.ok("problem" in expandSample(`sk_live_{x*5000}`));
  // A real-looking key, written whole, is refused: no run, not a stand-in
  // (built here so this file holds no key-shaped literal either).
  const realLooking = ["sk", "live", "51Hq8f2KZvT9rWmN3pLxYcB7eDaUo4sG"].join("_");
  refused("stripe.json", withStripe({ examples: [realLooking] }), /run of x/);
  refused("stripe.json", withStripe({ examples: ["sk_live_{a*24}"] }), /run of x/); // a run, but not a stand-in
  refused("stripe.json", withStripe({ examples: ["sk_live_{x*24}}"] }), /not a \{c\*n\} run/);
  refused("stripe.json", withStripe({ examples: ["sk_live_{x*5}"] }), /examples\[0\]: does not match/);
  refused("stripe.json", withStripe({ examples: [] }), /examples: must be a non-empty list/);
  refused("github.json", { ...(ISSUER_FILES.find((f) => f.file === "github.json")!.data as object), examples: ["ghp_{x*36}"] }, /formats\[1\]: no example matches it/);
  refused("stripe.json", withStripe({ non_examples: ["sk_live_{x*24}"] }), /non_examples\[0\]: matches this issuer's format/);
});

// ── 3b. across files ───────────────────────────────────────────────────────

/** A well-formed issuer file around one format. */
const issuer = (id: string, source: string, prefix: string, host: string, example = `${prefix}{x*20}`) => ({
  file: `${id}.json`,
  data: { id, name: id, formats: [source], shapes: [`${prefix}…`], hosts: [host], docs: [`https://${host}/docs`], examples: [example] },
});

test("a clash between files leaves out both sides, and the rest load in order", () => {
  const rest = ISSUER_FILES.filter((f) => f.file !== "stripe.json");
  const ids = (files: Array<{ file: string; data: unknown }>) => loadIssuerCatalog(files).issuers.map((i) => i.id);
  // A new issuer claiming a prefix Stripe's prefixes extend (sk_…): a
  // Stripe key would match both, so neither releases it.
  const greedy = issuer("acme", "^sk_[0-9A-Za-z]{10,40}$", "sk_", "api.acme-payments.com");
  let cat = loadIssuerCatalog([...ISSUER_FILES, greedy]);
  assert.ok(!cat.issuers.some((i) => i.id === "stripe" || i.id === "acme"));
  assert.match(cat.problems.join("\n"), /stripe\.json and acme\.json: .*prefixes overlap \(sk_live_… and sk_…\)/);
  // …and one claiming a LONGER prefix inside Stripe's namespace.
  cat = loadIssuerCatalog([...ISSUER_FILES, issuer("acme", "^sk_live_acme_[0-9A-Za-z]{20}$", "sk_live_acme_", "api.acme-payments.com")]);
  assert.ok(!cat.issuers.some((i) => i.id === "stripe" || i.id === "acme"));
  // The same host twice.
  cat = loadIssuerCatalog([...ISSUER_FILES, issuer("acme", "^acme_[0-9A-Za-z]{20}$", "acme_", "api.stripe.com")]);
  assert.match(cat.problems.join("\n"), /both name host api\.stripe\.com/);
  assert.ok(!cat.issuers.some((i) => i.id === "stripe" || i.id === "acme"));
  // The same id twice (two files, one named for another).
  cat = loadIssuerCatalog([...ISSUER_FILES, { file: "stripe.json", data: issuer("stripe", "^zzz_[0-9A-Za-z]{20}$", "zzz_", "api.zzz-pay.com").data }]);
  assert.match(cat.problems.join("\n"), /both have id 'stripe'/);
  assert.ok(!cat.issuers.some((i) => i.id === "stripe"));
  // A file that does not clash is appended, the rest untouched and in order.
  const fine = issuer("acme", "^acme_[0-9A-Za-z]{20}$", "acme_", "api.acme-payments.com");
  assert.deepEqual(ids([...ISSUER_FILES, fine]), [...ISSUERS.map((i) => i.id), "acme"]);
  assert.deepEqual(ids([...rest, fine]), [...rest.map((f) => f.file.replace(/\.json$/, "")), "acme"]);
});

test("fail-closed: with Stripe's file broken, a Stripe key matches NO issuer (no looser match anywhere)", () => {
  const broken = withStripe({ hosts: ["api.stripe.com", "*.stripe.com"] });
  const cat = loadIssuerCatalog([{ file: "stripe.json", data: broken }, ...ISSUER_FILES.filter((f) => f.file !== "stripe.json")]);
  assert.ok(!cat.issuers.some((i) => i.id === "stripe"));
  assert.match(cat.problems.join("\n"), /^stripe\.json: hosts: "\*\.stripe\.com"/m);
  for (const v of ISSUER_SAMPLES.get("stripe")!.examples) {
    assert.deepEqual(cat.issuers.filter((i) => i.formats.some((f) => f.test(v))), [], "no other issuer takes a Stripe key");
  }
});

test("the directory check: a file the index does not import, an index line with no file, a file that is not JSON", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-issuers-"));
  try {
    for (const f of ISSUER_FILES) writeFileSync(join(dir, f.file), JSON.stringify(f.data));
    assert.deepEqual(checkIssuerDir(dir).problems, []);
    writeFileSync(join(dir, "acme.json"), JSON.stringify(issuer("acme", "^acme_[0-9A-Za-z]{20}$", "acme_", "api.acme-payments.com").data));
    writeFileSync(join(dir, "zeta.json"), '{"id": "zeta", ');
    rmSync(join(dir, "npm.json"));
    const r = checkIssuerDir(dir);
    assert.match(r.problems.join("\n"), /acme\.json: not imported by issuers\/index\.ts/);
    assert.match(r.problems.join("\n"), /issuers\/index\.ts: names npm\.json, which is not in/);
    assert.match(r.problems.join("\n"), /zeta\.json: is not valid JSON/);
    assert.ok(r.issuers.some((i) => i.id === "acme"), "a valid unlisted file still checks (so a contributor sees its result)");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
