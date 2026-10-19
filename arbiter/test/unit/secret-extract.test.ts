/**
 * secret-extract — the secret SPANS of a credential file, so the structured
 * twin keeps the keys and masks the values
 * (confidentiality-plan-10-flow-taint.md §2.4).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { crc32 } from "node:zlib";
import {
  envNameMatches,
  envSecretSpan,
  extractSecretSpans,
  renderStructuredTwin,
  secretFileShape,
  type SecretSpan,
  envSecretExempt,
  envSecretNameMatches,
  shapeIsExhaustive,
  npmrcProxyBypassKeys,
  npmrcRegistryHost,
  indexWireHost,
  withheldCommandMessage,
  withheldCommandTwin,
  withheldCommands,
  withheldFileName,
  decodeBase64Text,
  percentDecodeText,
  encodeToken,
  npmrcHttpRegistryHosts,
} from "../../policy/secret-extract.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const tok = (s: SecretSpan) => `<${s.key}>`;
/** The twin's refusal command for a withheld ssh command (plan 10 §11.13.3). */
const refusal = (line: number, keyword: string, token: string, quote = false) =>
  withheldCommandTwin({ file: "~/.ssh/config", line, keyword, ...(quote ? { quote } : {}) }, token);
const twin = (path: string, content: string, extract?: string) => {
  const x = extractSecretSpans(path, content, extract ? { extract } : {});
  return { x, text: renderStructuredTwin(content, x.spans, tok) };
};

test("dotenv: values are masked, keys and benign values stay, comments untouched", () => {
  const raw = [
    "# app config",
    "PORT=3000",
    "NODE_ENV=production",
    "STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc",
    'DB_PASSWORD="hunter2"',
    "export API_TOKEN='abc def' # trailing",
    "EMPTY=",
    "PLAIN=hello world",
    "",
  ].join("\n");
  const { x, text } = twin("/ws/app/.env", raw);
  assert.equal(x.shape, "dotenv");
  assert.deepEqual(x.spans.map((s) => [s.key, s.value]), [
    ["STRIPE_KEY", "sk_live_4eC39HqLyjWDarjtT1zdp7dc"],
    ["DB_PASSWORD", "hunter2"],
    ["API_TOKEN", "abc def"],
    ["PLAIN", "hello world"],
  ]);
  assert.equal(
    text,
    [
      "# app config",
      "PORT=3000",
      "NODE_ENV=production",
      "STRIPE_KEY='<STRIPE_KEY>'",
      "DB_PASSWORD='<DB_PASSWORD>'",
      "export API_TOKEN='<API_TOKEN>' # trailing",
      "EMPTY=",
      "PLAIN='<PLAIN>'",
      "",
    ].join("\n"),
  );
  // the twin never contains a secret byte
  for (const s of x.spans) assert.ok(!text.includes(s.value), s.key);
});

test("URL with a password: only the password is masked, in dotenv and INI", () => {
  const raw = "DATABASE_URL=postgres://app:s3cr3t-pw@db.internal:5432/prod\nAPI_URL=http://localhost:3000\n";
  const { x, text } = twin("/ws/.env", raw);
  assert.deepEqual(x.spans.map((s) => [s.key, s.value]), [["DATABASE_URL.password", "s3cr3t-pw"]]);
  assert.equal(text, "DATABASE_URL='postgres://app:<DATABASE_URL.password>@db.internal:5432/prod'\nAPI_URL=http://localhost:3000\n");
});

test("INI (aws credentials): secret-looking keys per section, region stays raw", () => {
  const raw = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG\nregion = us-east-1\n\n[prod]\naws_secret_access_key = other/secret\n";
  const { x, text } = twin("/home/u/.aws/credentials", raw);
  assert.equal(x.shape, "ini");
  assert.deepEqual(x.spans.map((s) => s.key), [
    "default.aws_access_key_id", "default.aws_secret_access_key", "prod.aws_secret_access_key",
  ]);
  assert.ok(text.includes("region = us-east-1"));
  assert.ok(text.includes("aws_secret_access_key = <default.aws_secret_access_key>"));
  assert.ok(!text.includes("wJalrXUtnFEMI"));
});

test("pgpass: the last field, escaped colons respected", () => {
  const raw = "# comment\ndb.internal:5432:prod:app:pa\\:ss\nlocalhost:*:*:me:xyz\n";
  const { x, text } = twin("/home/u/.pgpass", raw);
  assert.equal(x.shape, "pgpass");
  assert.deepEqual(x.spans.map((s) => [s.key, s.value]), [["app.password", "pa\\:ss"], ["me.password", "xyz"]]);
  assert.equal(text, "# comment\ndb.internal:5432:prod:app:<app.password>\nlocalhost:*:*:me:<me.password>\n");
});

test("netrc and npmrc", () => {
  const n = twin("/home/u/.netrc", "machine api.github.com login me password ghp_abc123\ndefault login x password zzz\n");
  assert.deepEqual(n.x.spans.map((s) => [s.key, s.value]), [["api.github.com.password", "ghp_abc123"], ["default.password", "zzz"]]);
  assert.ok(!n.text.includes("ghp_abc123") && n.text.includes("login me password <api.github.com.password>"));
  const p = twin("/home/u/.npmrc", "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_TOKEN123\nemail=me@x\n");
  assert.deepEqual(p.x.spans.map((s) => [s.key, s.value]), [["registry.npmjs.org._authToken", "npm_TOKEN123"]]);
  assert.ok(p.text.includes("registry=https://registry.npmjs.org/") && !p.text.includes("npm_TOKEN123"));
});

// Plan 10 §11.13.1: which .npmrc values npm sends verbatim to the registry
// their own key names (the session proxy can put them back there).
test("npmrc: a scoped _authToken / _auth / _password is marked for the wire with its registry's host; unscoped keys are not", () => {
  const raw = [
    "//registry.npmjs.org/:_authToken=npm_A",
    "//npm.pkg.github.com/acme/:_authToken=ghp_B",
    "//LocalHost:4873/:_auth=dXNlcjpwYXNz",
    // The file declares this one registry over plain http: its credential
    // may be put back in plain HTTP; every other one is https only.
    "@local:registry=http://localhost:4873/",
    "//corp.example/npm/:username=me",
    "//corp.example/npm/:_password=cGFzcw==",
    "_authToken=npm_UNSCOPED",
    "_password=cGFzcw==",
    "//user@evil.example/:_authToken=npm_C",
    "//user@evil.example/:_password=cGFzcw==",
    "",
  ].join("\n");
  const x = extractSecretSpans("/home/u/.npmrc", raw);
  assert.deepEqual(x.spans.map((s) => [s.value, s.wire ?? null, s.encoded ?? null]), [
    ["npm_A", { host: "registry.npmjs.org", scheme: "bearer", httpsOnly: true }, null],
    ["ghp_B", { host: "npm.pkg.github.com", scheme: "bearer", httpsOnly: true }, null],
    ["dXNlcjpwYXNz", { host: "localhost:4873", scheme: "basic", httpsOnly: false }, null],
    // Since 2026-10-03 (§11.13.1): the decoded password, base64 in the twin.
    ["pass", { host: "corp.example", scheme: "basic", httpsOnly: true }, "base64"],
    ["npm_UNSCOPED", null, null],
    ["cGFzcw==", null, null],
    ["npm_C", null, null],
    ["cGFzcw==", null, null],
  ]);
  // The span still covers the file's base64 text; the twin holds the base64
  // of the token, which npm decodes back into the token.
  const pw = x.spans[3]!;
  assert.equal(raw.slice(pw.start, pw.end), "cGFzcw==");
  const text = renderStructuredTwin(raw, x.spans, tok);
  assert.ok(text.includes(`//corp.example/npm/:_password=${Buffer.from("<corp.example/npm._password>").toString("base64")}\n`), text);
  assert.ok(text.includes("//corp.example/npm/:username=me\n"), text);
  assert.equal(npmrcRegistryHost("registry.npmjs.org"), "registry.npmjs.org");
  assert.equal(npmrcRegistryHost("npm.pkg.github.com/OWNER"), "npm.pkg.github.com");
  assert.equal(npmrcRegistryHost(""), null);
  assert.equal(npmrcRegistryHost("*.example"), null);
});

test("npmrc: a _password that is not clean base64 of printable UTF-8 is never marked (nothing could put it back)", () => {
  const bad = [
    "not base64!",                                   // not the alphabet
    "cGFzcw",                                        // fine unpadded...
    "cGFzcx==",                                      // ...but non-canonical trailing bits
    Buffer.from([0xff, 0xfe, 0x00]).toString("base64"), // not UTF-8
    Buffer.from("pa\nss").toString("base64"),        // a control character
  ];
  const marks = bad.map((v) => {
    const s = extractSecretSpans("/home/u/.npmrc", `//r.example/:username=me\n//r.example/:_password=${v}\n`).spans[0]!;
    return [s.value === v, s.encoded ?? null, s.wire ? "wire" : null];
  });
  assert.deepEqual(marks, [
    [true, null, null],
    [false, "base64", "wire"],
    [true, null, null],
    [true, null, null],
    [true, null, null],
  ]);
  assert.equal(decodeBase64Text("cGFzcw=="), "pass");
  assert.equal(decodeBase64Text(Buffer.from("pässwörd:x").toString("base64")), "pässwörd:x");
  assert.equal(decodeBase64Text(""), null);
});

test("encodings: percent-decoding is pip's unquote; a token survives its own encoding", () => {
  assert.equal(percentDecodeText("plain"), "plain");
  assert.equal(percentDecodeText("p%40ss%3Aw%C3%B6rd"), "p@ss:wörd");
  assert.equal(percentDecodeText("100%zz%"), "100%zz%", "a % that is no escape stays, as Python's unquote keeps it");
  assert.equal(percentDecodeText("%ff%fe"), null, "not UTF-8 once decoded");
  const token = "$MDU:nomodel_Read[1a2b].global.pypi.corp.example.password";
  assert.equal(encodeToken(token, undefined), token);
  assert.equal(encodeToken(token, "percent"), "%24MDU%3Anomodel_Read%5B1a2b%5D.global.pypi.corp.example.password");
  assert.equal(percentDecodeText(encodeToken(token, "percent")), token);
  assert.equal(decodeBase64Text(encodeToken(token, "base64")), token);
});

test("pip.conf: an index URL's user and password are percent-encoded in the twin and marked for the wire to its host; other URLs are encoded, not marked", () => {
  const raw = [
    "[global]",
    "index-url = https://alice:s3cret%40Pw@PyPI.Corp.Example/simple",
    "extra-index-url =",
    "    https://ghp_PIPUSERTOKEN2abcdef@pkgs.example:8443/simple",
    "    ftp://bob:FTPPW_9@ftp.example/simple",
    "    https://carol:CAROLPW_8@[::1]/simple",
    "    https://erin:ERINPW_7@[fe80::1%25eth0]/simple",
    "    https://frank:FRANKPW_6@2001:db8::1/simple",
    "[install]",
    "proxy = http://proxyuser:PIPPROXY_4@proxy.example:3128",
    "find-links = https://dave:DAVEPW_5@links.example/",
    "",
  ].join("\n");
  const x = extractSecretSpans("/home/u/.config/pip/pip.conf", raw);
  const by = (needle: string) => x.spans.find((s) => raw.slice(s.start, s.end) === needle)!;
  assert.deepEqual({ ...by("s3cret%40Pw") }, {
    key: "global.PyPI.Corp.Example.password", start: raw.indexOf("s3cret%40Pw"), end: raw.indexOf("s3cret%40Pw") + 11,
    value: "s3cret@Pw", encoded: "percent", wire: { host: "pypi.corp.example", scheme: "basic", httpsOnly: true },
  });
  assert.deepEqual(by("ghp_PIPUSERTOKEN2abcdef").wire, { host: "pkgs.example:8443", scheme: "basic", httpsOnly: true }, "a token as the user is sent in Basic too");
  // 2026-10-17: a bracketed IPv6 literal is a wire host too (indexWireHost).
  assert.deepEqual(by("CAROLPW_8").wire, { host: "[::1]", scheme: "basic", httpsOnly: true }, "an IPv6 literal index");
  for (const [needle, why] of [["FTPPW_9", "not http(s)"], ["ERINPW_7", "an IPv6 zone id"], ["FRANKPW_6", "an IPv6 address without brackets"], ["PIPPROXY_4", "not an index URL"], ["DAVEPW_5", "not an index URL"]] as const) {
    const s = by(needle);
    assert.equal(s.wire, undefined, `${needle}: ${why}`);
    assert.equal(s.encoded, "percent", `${needle}: still percent-encoded in the twin`);
  }
  const text = renderStructuredTwin(raw, x.spans, (s) => `$MDU:nomodel_Read[1a2b].${s.key}`);
  assert.ok(text.includes("index-url = https://alice:%24MDU%3Anomodel_Read%5B1a2b%5D.global.PyPI.Corp.Example.password@PyPI.Corp.Example/simple\n"), text);
  for (const secret of ["s3cret", "ghp_PIPUSERTOKEN2abcdef", "FTPPW_9", "CAROLPW_8", "ERINPW_7", "FRANKPW_6", "PIPPROXY_4", "DAVEPW_5"]) assert.ok(!text.includes(secret), `${secret}:\n${text}`);
});

test("indexWireHost (2026-10-17): a name as npmrcRegistryHost reads it, or a bracketed IPv6 literal in its canonical text; a zone id, a bare IPv6 address or a bad port is none", () => {
  const cases: Array<[string, string | null]> = [
    ["pypi.corp.example", "pypi.corp.example"],
    ["PyPI.Corp.Example:8443", "pypi.corp.example:8443"],
    ["10.1.2.3:8080", "10.1.2.3:8080"],
    ["[2001:db8::1]", "[2001:db8::1]"],
    ["[2001:DB8::1]", "[2001:db8::1]"],
    ["[2001:db8:0::1]:8443", "[2001:db8::1]:8443"],
    ["[2001:0db8:0000:0000:0000:0000:0000:0001]:08443", "[2001:db8::1]:8443"],
    ["[::1]", "[::1]"],
    ["[::ffff:10.1.2.3]", "[::ffff:a01:203]"],
    ["[fe80::1%25eth0]", null],
    ["[fe80::1%eth0]", null],
    ["2001:db8::1", null],
    ["[2001:db8::1", null],
    ["[2001:db8::1]x", null],
    ["[2001:db8::1]:0", null],
    ["[2001:db8::1]:70000", null],
    ["[not:an:address:g]", null],
    ["[10.1.2.3]", null],
    ["[]", null],
  ];
  for (const [hp, want] of cases) assert.equal(indexWireHost(hp), want, hp);
});

test("pip, IPv6-literal index hosts (2026-10-17): pip.conf and PIP_INDEX_URL mark the password for the wire to the canonical address; a zone id is not marked", () => {
  const raw = "[global]\nindex-url = https://builder:V6PW_A1@[2001:DB8:0::1]:8443/simple\nextra-index-url = http://user:V6PW_B2@[::1]/simple\n";
  const x = extractSecretSpans("/home/u/.config/pip/pip.conf", raw);
  const by = (needle: string) => x.spans.find((s) => raw.slice(s.start, s.end) === needle)!;
  assert.deepEqual(by("V6PW_A1").wire, { host: "[2001:db8::1]:8443", scheme: "basic", httpsOnly: true });
  assert.deepEqual(by("V6PW_B2").wire, { host: "[::1]", scheme: "basic", httpsOnly: false }, "an http:// index: plain HTTP too");
  const env = envSecretSpan("PIP_INDEX_URL", "https://me:p%40ss@[2001:db8::1]:8443/simple")!;
  assert.deepEqual({ ...env }, { key: "PIP_INDEX_URL.password", start: 11, end: 17, value: "p@ss", encoded: "percent", wire: { host: "[2001:db8::1]:8443", scheme: "basic", httpsOnly: true } });
  const http = envSecretSpan("PIP_EXTRA_INDEX_URL", "http://user:pass@[::1]/simple")!;
  assert.deepEqual(http.wire, { host: "[::1]", scheme: "basic", httpsOnly: false });
  assert.equal(http.key, "PIP_EXTRA_INDEX_URL.password_http");
  const zone = envSecretSpan("PIP_INDEX_URL", "https://me:pw@[fe80::1%25eth0]/simple")!;
  assert.equal(zone.wire, undefined, "a zone id: masked, never put back");
  assert.equal(zone.value, "pw");
});

test("pip env: PIP_INDEX_URL's password is percent-decoded, percent-encoded in the twin, and marked for the wire; another URL variable is unchanged", () => {
  const s = envSecretSpan("PIP_INDEX_URL", "https://alice:p%40ss@pypi.corp.example:8080/simple")!;
  assert.deepEqual({ ...s }, { key: "PIP_INDEX_URL.password", start: 14, end: 20, value: "p@ss", encoded: "percent", wire: { host: "pypi.corp.example:8080", scheme: "basic", httpsOnly: true } });
  assert.equal(renderStructuredTwin("https://alice:p%40ss@pypi.corp.example:8080/simple", [s], () => "$MDU:env[aa11].PIP_INDEX_URL.password"),
    "https://alice:%24MDU%3Aenv%5Baa11%5D.PIP_INDEX_URL.password@pypi.corp.example:8080/simple");
  assert.equal(envSecretSpan("PIP_EXTRA_INDEX_URL", "https://u:pw@x.example/simple")!.wire?.host, "x.example");
  const db = envSecretSpan("DATABASE_URL", "postgres://u:pw@db.example/app")!;
  assert.equal(db.encoded, undefined);
  assert.equal(db.wire, undefined);
});

test("https only (2026-10-03): a wire credential is httpsOnly unless its own declared URL or registry is http://", () => {
  // npm: a nerf-dart names no scheme; only an http registry line for that host lifts it.
  assert.deepEqual([...npmrcHttpRegistryHosts("registry=http://r.example:8080/\n@a:registry = \"http://Other.Example/x/\"\nregistry=https://s.example/\nregistry=not a url\n")].sort(),
    ["other.example", "r.example:8080"]);
  const npm = (extra: string) => extractSecretSpans("/h/.npmrc", `${extra}//r.example/:_authToken=npm_T\n`).spans[0]!.wire!.httpsOnly;
  assert.equal(npm(""), true, "no registry line: https");
  assert.equal(npm("registry=https://r.example/\n"), true);
  assert.equal(npm("registry=http://r.example/\n"), false);
  assert.equal(npm("registry=http://elsewhere.example/\n"), true, "an http registry for ANOTHER host lifts nothing");
  assert.equal(npm("registry=http://r.example:8080/\n"), true, "nor one on another port");
  // pip.conf: the index URL's own scheme.
  const pip = (url: string) => extractSecretSpans("/h/.config/pip/pip.conf", `[global]\nindex-url = ${url}\n`).spans[0]!.wire;
  assert.deepEqual(pip("https://u:PW_1@pypi.corp.example/simple"), { host: "pypi.corp.example", scheme: "basic", httpsOnly: true });
  assert.deepEqual(pip("http://u:PW_1@pypi.corp.example/simple"), { host: "pypi.corp.example", scheme: "basic", httpsOnly: false });
  // PIP_INDEX_URL: the same, and an http index's field says so (the env row keeps no URL).
  const https = envSecretSpan("PIP_INDEX_URL", "https://u:PW_2@pypi.corp.example/simple")!;
  assert.equal(https.key, "PIP_INDEX_URL.password");
  assert.equal(https.wire!.httpsOnly, true);
  const http = envSecretSpan("PIP_INDEX_URL", "http://u:PW_2@pypi.corp.example/simple")!;
  assert.equal(http.key, "PIP_INDEX_URL.password_http");
  assert.equal(http.wire!.httpsOnly, false);
});

test("env: a URL password that is not at the start of the value (a list of URLs) masks the whole value (it used to reach the agent raw)", () => {
  const v = "https://a.example/simple https://user:PASS_LIST_1@b.example/simple";
  assert.deepEqual(envSecretSpan("PIP_EXTRA_INDEX_URL", v), { key: "PIP_EXTRA_INDEX_URL", start: 0, end: v.length, value: v });
  assert.equal(envSecretSpan("SOME_URLS", "--index https://u:PW_2@x.example")?.value, "--index https://u:PW_2@x.example");
  assert.equal(envSecretSpan("SOME_URLS", "https://a.example https://b.example"), null, "no password, no mask");
  assert.equal(envSecretSpan("ANTHROPIC_API_KEY", "x https://u:p@h"), null, "the exemptions still hold");
});

test("npmrc: the keys that send npm around the session proxy are found, scoped or not", () => {
  assert.deepEqual(npmrcProxyBypassKeys("//registry.npmjs.org/:_authToken=x\nregistry=https://r/\n"), []);
  assert.deepEqual(
    npmrcProxyBypassKeys("https-proxy=http://corp:3128\nproxy = http://corp:3128\nnoproxy=.corp\ncafile=/c.pem\nca[]=---\n//r/:certfile=/a\n//r/:keyfile=/b\n"),
    ["https-proxy", "proxy", "noproxy", "cafile", "ca[]", "certfile", "keyfile"],
  );
  assert.deepEqual(npmrcProxyBypassKeys("ca=\"-----BEGIN\"\n"), ["ca"]);
  assert.deepEqual(npmrcProxyBypassKeys("cache=/tmp/x\ncafile-x=1\n"), [], "only the exact key names");
});

test("yaml by key name (gh hosts.yml) and json by key name", () => {
  const y = twin("/home/u/.config/gh/hosts.yml", "github.com:\n    oauth_token: gho_abcdef\n    user: me\n    git_protocol: https\n");
  assert.equal(y.x.shape, "yaml-keys");
  assert.deepEqual(y.x.spans.map((s) => [s.key, s.value]), [["github.com.oauth_token", "gho_abcdef"]]);
  assert.ok(y.text.includes("user: me") && y.text.includes("oauth_token: <github.com.oauth_token>"));
  const j = twin("/ws/secrets.json", '{"name":"svc","api_key":"k-123456","nested":{"password":"p\\"q"},"url":"https://u:pw@h/"}');
  assert.equal(j.x.shape, "json-keys");
  assert.deepEqual(j.x.spans.map((s) => [s.key, s.value]), [["api_key", "k-123456"], ["password", 'p\\"q'], ["url.password", "pw"]]);
  assert.ok(j.text.includes('"name":"svc"') && !j.text.includes("k-123456") && !j.text.includes('p\\"q'));
});

test("duplicate keys get unique field names", () => {
  const { x } = twin("/ws/.env", "TOKEN=a1b2c3d4\nTOKEN=e5f6g7h8\n");
  assert.deepEqual(x.spans.map((s) => s.key), ["TOKEN", "TOKEN__2"]);
});

test("a user extract regex overrides the shape; no match keeps the whole file masked", () => {
  const raw = "oauth: tok_ABC\nother: x\n";
  const a = twin("/x/custom.conf", raw, "oauth: (\\S+)");
  assert.equal(a.x.shape, "extract");
  assert.equal(a.text, "oauth: <extract_1>\nother: x\n");
  const b = twin("/x/custom.conf", raw, "nothing: (\\S+)");
  assert.equal(b.x.shape, null);
  assert.equal(b.x.spans.length, 0);
  const c = twin("/x/custom.conf", raw, "(unbalanced");
  assert.equal(c.x.shape, null);
});

test("unknown shape, binary, oversize and empty content stay whole-file", () => {
  assert.equal(extractSecretSpans("/home/u/.ssh/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n").shape, null);
  assert.equal(extractSecretSpans("/ws/.env", "A=\u0000b").shape, null);
  assert.equal(extractSecretSpans("/ws/.env", "").shape, null);
  assert.equal(extractSecretSpans("/ws/.env", "A=" + "x".repeat(9 * 1024 * 1024)).shape, null);
  assert.equal(secretFileShape("/home/u/.ssh/id_ed25519"), null);
  assert.equal(secretFileShape("/home/u/.aws/config"), "ini");
  assert.equal(secretFileShape("/ws/credentials.json"), "json-keys");
});

test("renderStructuredTwin is exact around spans, and single-quotes a wrapped value", () => {
  const content = "A=1\nB=xy\n";
  const spans: SecretSpan[] = [{ key: "B", start: 6, end: 8, value: "xy" }];
  assert.equal(renderStructuredTwin(content, spans, () => "T"), "A=1\nB=T\n");
  const wrapped: SecretSpan[] = [{ key: "B", start: 6, end: 8, value: "y", wrap: { prefix: "x", suffix: "" } }];
  assert.equal(renderStructuredTwin(content, wrapped, () => "T"), "A=1\nB='xT'\n");
});

test("dotenv twin survives being SOURCED by a shell: masked values are single-quoted, whatever the original quoting", () => {
  const raw = 'A=sk_live_abc123\nB="sk_live_def456"\nC=\'sk_live_ghi789\' # note\nU=postgres://u:pw-1234@h/db\n';
  const { text } = twin("/ws/.env", raw);
  assert.equal(text, "A='<A>'\nB='<B>'\nC='<C>' # note\nU='postgres://u:<U.password>@h/db'\n");
});

test("env-var mask, the law's env: section (plan 10 §11.4): secrets ADD names or PREFIX_* patterns, exempt REMOVES them, the agent's own key stays exempt", () => {
  const rules = { secrets: ["MYCO_*", "DEPLOY_CRED"], exempt: ["GH_TOKEN", "PUBLIC_*"] };
  // added: a name no built-in shape would catch, whole value
  assert.deepEqual(envSecretSpan("MYCO_THING", "abc", rules), { key: "MYCO_THING", start: 0, end: 3, value: "abc" });
  assert.equal(envSecretSpan("DEPLOY_CRED", "xyz", rules)?.value, "xyz");
  assert.equal(envSecretSpan("MYCO_THING", "abc"), null, "without the rule the name is not a secret");
  // exempted: a built-in shape hit that the law releases
  assert.equal(envSecretSpan("GH_TOKEN", "ghp_1234", rules), null);
  assert.equal(envSecretSpan("PUBLIC_API_KEY", "pk_live_1", rules), null);
  assert.ok(envSecretSpan("GH_TOKEN", "ghp_1234"), "the built-in shape still holds without the exemption");
  // the built-in exemptions win over an added name
  assert.equal(envSecretSpan("ANTHROPIC_API_KEY", "sk-ant-1", { secrets: ["ANTHROPIC_API_KEY"] }), null);
  assert.equal(envSecretSpan("MANDU_MODE", "secrets", { secrets: ["MANDU_*"] }), null);
  // an exempted URL variable is left whole, password included
  assert.equal(envSecretSpan("DATABASE_URL", "postgres://a:pw@h/db", { exempt: ["DATABASE_URL"] }), null);
  // the glob helper
  assert.ok(envNameMatches("MYCO_*", "MYCO_X") && envNameMatches("*_PIN", "CARD_PIN") && envNameMatches("A*B", "AxyB"));
  assert.ok(!envNameMatches("MYCO_*", "MYCO") && !envNameMatches("MYCO_*", "XMYCO_A") && !envNameMatches("A.B", "AxB"));
});

test("envSecretNameMatches: the names-only half of envSecretSpan (the dry run): shapes, the agent's own credential exempt, the law's names and exemptions", () => {
  assert.equal(envSecretNameMatches("GH_TOKEN"), true);
  assert.equal(envSecretNameMatches("DB_PASSWORD"), true);
  assert.equal(envSecretNameMatches("AWS_SECRET_ACCESS_KEY"), true);
  assert.equal(envSecretNameMatches("HOME"), false);
  assert.equal(envSecretNameMatches("ANTHROPIC_API_KEY"), false, "the agent's own credential is never masked");
  assert.equal(envSecretNameMatches("MANDU_ARBITER_SOCK"), false);
  assert.equal(envSecretNameMatches("MYCO_PIN", { secrets: ["MYCO_*"] }), true);
  assert.equal(envSecretNameMatches("GH_TOKEN", { exempt: ["GH_TOKEN"] }), false);
  assert.equal(envSecretNameMatches("STRIPE_KEY"), false, "not a shape: a URL-password VALUE could still mask it, which the dry run cannot see");
});

// ── shapes added by the catalog recall audit (secret-discovery.md §2) ──

test("toml: quoted values masked in place, quotes kept; non-secret keys raw", () => {
  const c = `[registry]\ntoken = "tok-abc123"\nregion = "us"\n`;
  const x = extractSecretSpans("/h/.cargo/credentials.toml", c);
  assert.equal(x.shape, "toml");
  assert.deepEqual(x.spans.map((s) => s.value), ["tok-abc123"]);
  assert.equal(renderStructuredTwin(c, x.spans, () => "SYM"), `[registry]\ntoken = "SYM"\nregion = "us"\n`);
});

test("toml: an inline table or a multi-line string makes the whole file the twin", () => {
  assert.equal(extractSecretSpans("/h/a.toml", `creds = { token = "x1" }\n`).shape, null);
  assert.equal(extractSecretSpans("/h/a.toml", `key = """\nabc\n"""\n`).shape, null);
});

test("xml: maven <password>, NuGet key/value pairs and secret-named attributes", () => {
  const m = `<settings><servers><server><id>r</id><username>me</username><password> pw-1 </password></server></servers></settings>`;
  const x = extractSecretSpans("/h/.m2/settings.xml", m);
  assert.equal(x.shape, "xml-keys");
  assert.deepEqual(x.spans.map((s) => s.value), ["pw-1"]);
  assert.ok(!renderStructuredTwin(m, x.spans, () => "SYM").includes("pw-1"));
  const n = `<configuration><f><add key="Username" value="me" /><add key="ClearTextPassword" value="pw-2" /></f><x password="pw-3" name="n"/></configuration>`;
  const y = extractSecretSpans("/h/.nuget/NuGet/NuGet.Config", n);
  assert.deepEqual(y.spans.map((s) => s.value).sort(), ["pw-2", "pw-3"]);
  assert.ok(renderStructuredTwin(n, y.spans, () => "SYM").includes(`value="me"`), "non-secret pairs stay raw");
});

test("kubeconfig is YAML: token and client-key-data masked, server raw", () => {
  const c = `clusters:\n- cluster:\n    server: https://k8s.example.com\nusers:\n- name: a\n  user:\n    token: kt-1\n    client-key-data: LS0tkey\n`;
  const x = extractSecretSpans("/h/.kube/config", c);
  assert.equal(x.shape, "yaml-keys");
  assert.deepEqual(x.spans.map((s) => s.value), ["kt-1", "LS0tkey"]);
});

test("dotenv by suffix and direnv's .envrc; INI for .my.cnf and .properties; JSON keys for .tfstate", () => {
  assert.equal(extractSecretSpans("/h/w/prod.env", "API_TOKEN=t1\n").shape, "dotenv");
  const e = extractSecretSpans("/h/w/.envrc", "export AWS_SECRET_ACCESS_KEY=s1\n");
  assert.equal(e.shape, "dotenv");
  assert.deepEqual(e.spans.map((s) => s.value), ["s1"]);
  assert.deepEqual(extractSecretSpans("/h/.my.cnf", "[client]\npassword = p1\n").spans.map((s) => s.value), ["p1"]);
  assert.deepEqual(extractSecretSpans("/h/.gradle/gradle.properties", "org.gradle.jvmargs=-Xmx2g\nossrhPassword=p2\n").spans.map((s) => s.value), ["p2"]);
  assert.deepEqual(extractSecretSpans("/h/w/terraform.tfstate", `{"attributes":{"password":"p3","name":"db"}}`).spans.map((s) => s.value), ["p3"]);
});

// Release checklist d9 (2026-09-26): every CLAUDE_* / CODEX_* name used to be
// exempt, so CLAUDE_CODE_MESSAGING_TOKEN (the credential for an outer Claude
// Code session's local messaging socket) reached the agent raw. Now only the
// agent's own login credentials are exempt by name; the agents' config
// switches stay exempt unless they end in a credential suffix.
test("env-var mask exemptions (d9): the agent's own credentials yes, CLAUDE_CODE_MESSAGING_TOKEN no, config switches yes", () => {
  for (const own of ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "OPENAI_API_KEY", "CODEX_API_KEY"]) {
    assert.equal(envSecretExempt(own), true, own);
    assert.equal(envSecretSpan(own, "value-1"), null, own);
  }
  assert.equal(envSecretExempt("CLAUDE_CODE_MESSAGING_TOKEN"), false);
  assert.equal(envSecretNameMatches("CLAUDE_CODE_MESSAGING_TOKEN"), true, "the dry run lists it");
  assert.deepEqual(envSecretSpan("CLAUDE_CODE_MESSAGING_TOKEN", "3d6aa8f0c1"), {
    key: "CLAUDE_CODE_MESSAGING_TOKEN", start: 0, end: 10, value: "3d6aa8f0c1",
  });
  // A hypothetical future agent secret under the prefix is masked too.
  assert.ok(envSecretSpan("CODEX_SESSION_SECRET", "s"), "CODEX_* with a credential suffix is masked");
  // Switches that merely look secret-shaped (`*_AUTH`) stay raw: masking "1"
  // would change the agent's behaviour, and there is no secret in it.
  assert.equal(envSecretExempt("CLAUDE_CODE_SKIP_BEDROCK_AUTH"), true);
  assert.equal(envSecretSpan("CLAUDE_CODE_SKIP_BEDROCK_AUTH", "1"), null);
  assert.equal(envSecretSpan("CLAUDE_CODE_SKIP_VERTEX_AUTH", "1"), null);
  // Non-secret CLAUDE_* names are not shapes anyway, and stay exempt.
  assert.equal(envSecretExempt("CLAUDE_CODE_MESSAGING_SOCKET"), true);
  assert.equal(envSecretSpan("CLAUDE_CODE_MAX_OUTPUT_TOKENS", "8000"), null);
  // The law cannot add a mask to the agent's own credential.
  assert.equal(envSecretSpan("CODEX_API_KEY", "sk-x", { secrets: ["CODEX_*"] }), null);
});

// ── env names and key formats (plan 10 §11.4, 2026-10-09) ───────────────────
// PGPASSWORD, MYSQL_PWD, GITHUB_PAT, Terraform's TF_TOKEN_<host> and webhook
// URLs reached the agent raw (the name list wanted `_PASSWORD`, had no `_PWD`,
// `_PAT`, `TF_TOKEN_` or webhook rule), and so did a key in a known format
// under a name no shape matched. Keys are built at run time: this file holds
// no token-shaped literal.

/** A deterministic alphanumeric run. */
function alnum(n: number, seed: number): string {
  const A = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  let x = seed >>> 0;
  let out = "";
  for (let i = 0; i < n; i++) {
    x = (Math.imul(x, 1103515245) + 12345) >>> 0;
    out += A[(x >>> 16) % 62]!;
  }
  return out;
}
/** A GitHub classic token whose checksum holds (GitHub's CRC-32, base62). */
function githubClassic(random30: string): string {
  const B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  let n = crc32(random30);
  let sum = "";
  for (let i = 0; i < 6; i++) { sum = B62[n % 62]! + sum; n = Math.floor(n / 62); }
  return "gh" + "p_" + random30 + sum;
}
const AWS_ID = "AK" + "IA" + alnum(16, 10).toUpperCase();
const AWS_SECRET = alnum(38, 11) + "/+";
const KEYS: Record<string, string> = {
  "GitHub classic token": githubClassic(alnum(30, 1)),
  "GitHub fine-grained token": "github" + "_pat_" + alnum(22, 2) + "_" + alnum(59, 3),
  "GitLab token": "glp" + "at-" + alnum(20, 4),
  "Stripe live key": "sk" + "_live_" + alnum(24, 5),
  "Slack bot token": "xo" + "xb-" + "1234567890-" + alnum(24, 6),
  "Anthropic key": "sk-" + "ant-api03-" + alnum(40, 7),
  "OpenAI project key": "sk-" + "proj-" + alnum(40, 8),
  "npm token": "np" + "m_" + alnum(36, 9),
  "AWS key pair": `${AWS_ID}:${AWS_SECRET}`,
  "AWS key pair (JSON)": JSON.stringify({ AccessKeyId: AWS_ID, SecretAccessKey: AWS_SECRET }),
  "AWS secret key, named": "aws_secret_access_key=" + alnum(40, 19),
  "private key block": "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n" + alnum(64, 12) + "\n-----END OPENSSH PRIVATE KEY-----\n",
  // 2026-10-10: the key-block rule wanted real line breaks after the header.
  "private key in a JSON string (a service-account key)": JSON.stringify({
    type: "service_account", project_id: "demo", private_key_id: alnum(12, 20),
    private_key: "-----BEGIN " + "PRIVATE KEY-----\n" + alnum(64, 21) + "\n" + alnum(64, 22) + "\n-----END PRIVATE KEY-----\n",
    client_email: "svc@demo.iam.gserviceaccount.com",
  }),
  "private key in a JSON string with escaped slashes": JSON.stringify({
    private_key: "-----BEGIN " + "RSA PRIVATE KEY-----\n" + alnum(30, 23) + "/" + alnum(33, 24) + "\n-----END RSA PRIVATE KEY-----\n",
  }).replace(/\//g, "\\/"),
  "private key on one line": "-----BEGIN " + "OPENSSH PRIVATE KEY----- " + alnum(70, 25) + " " + alnum(70, 26) + " -----END OPENSSH PRIVATE KEY-----",
  "encrypted private key on one line": "-----BEGIN " + "RSA PRIVATE KEY----- Proc-Type: 4,ENCRYPTED DEK-Info: AES-128-CBC," + alnum(32, 27).toUpperCase() + " " + alnum(64, 28) + " -----END RSA PRIVATE KEY-----",
};

test("env names (2026-10-09): PGPASSWORD, MYSQL_PWD, *_PAT, TF_TOKEN_<host> and *_WEBHOOK_URL are masked whole", () => {
  const whole = (name: string, value: string) => assert.deepEqual(envSecretSpan(name, value), { key: name, start: 0, end: value.length, value }, name);
  for (const [name, value] of [
    ["PGPASSWORD", "fakePgPw_Q7x91"],
    ["MYSQL_PWD", "fakeMyPw_R2k44"],
    ["SNOWSQL_PWD", "pw"],
    ["GITHUB_PAT", "pat-value-1"],
    ["GITLAB_PAT", "pat-value-2"],
    ["AZURE_DEVOPS_EXT_PAT", "pat-value-3"],
    ["TF_TOKEN_app_terraform_io", "tf.atlasv1.value"],
    ["TF_TOKEN_tfe_corp_example", "tf-token-value"],
    // still masked, as before
    ["DB_PASSWORD", "pw"], ["PASSWORD", "pw"], ["password", "pw"], ["MYSQL_ROOT_PASSWORD", "pw"],
  ] as const) {
    whole(name, value);
    assert.equal(envSecretNameMatches(name), true, `${name}: the dry run lists it`);
  }
  // A webhook URL carries its secret in the path: masked whole, though any
  // other URL with no password stays raw.
  whole("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T0000/B0000/" + alnum(24, 13));
  whole("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1234567890/" + alnum(60, 14));
  whole("ALERTS_WEBHOOK_URL", "https://u:pw@hooks.example/x");
  assert.equal(envSecretNameMatches("SLACK_WEBHOOK_URL"), true);
  // 2026-10-10: the names CI actions read have no `_URL`.
  whole("SLACK_WEBHOOK", "https://hooks.slack.com/services/T0000/B0000/" + alnum(24, 29));
  whole("DISCORD_WEBHOOK", "https://discord.com/api/webhooks/1234567890/" + alnum(60, 30));
  assert.equal(envSecretNameMatches("SLACK_WEBHOOK"), true);
  assert.equal(envSecretNameMatches("DISCORD_WEBHOOK"), true);
  assert.equal(envSecretSpan("SOME_URL", "https://hooks.slack.com/services/T0000/B0000/x"), null, "by name only: no URL is a secret for its host");
});

test("env names that stay raw: the shell's and the tools' everyday variables, value checks included", () => {
  const raw: Record<string, string> = {
    PWD: "/home/u/proj", OLDPWD: "/home/u", HOME: "/home/u", PATH: "/usr/local/bin:/usr/bin:/bin",
    LD_LIBRARY_PATH: "/opt/lib", MANPATH: "/usr/share/man", CDPATH: ".:~", SHELL: "/bin/bash", USER: "u",
    LOGNAME: "u", LANG: "en_US.UTF-8", TERM: "xterm-256color", DISPLAY: ":0", EDITOR: "vim", PAGER: "less",
    SHLVL: "1", TMUX: "/tmp/tmux-1000/default,1234,0", XDG_RUNTIME_DIR: "/run/user/1000",
    SSH_AUTH_SOCK: "/run/user/1000/ssh-agent.sock", SSH_ASKPASS: "/usr/lib/ssh/ssh-askpass",
    GIT_ASKPASS: "/usr/lib/git-core/git-gui--askpass", SUDO_ASKPASS: "/usr/bin/ssh-askpass",
    PASSWORD_STORE_DIR: "/home/u/.password-store", PGPASSFILE: "/home/u/.pgpass", PGHOST: "db.internal", PGUSER: "app",
    POSTGRES_PASSWORD_FILE: "/run/secrets/pg", KUBECONFIG: "/home/u/.kube/config", AWS_PROFILE: "dev", AWS_REGION: "eu-west-1",
    TF_DATA_DIR: "/home/u/.terraform.d", TF_LOG: "INFO", TF_CLI_CONFIG_FILE: "/home/u/.terraformrc",
    SENTRY_DSN: "https://0123456789abcdef0123456789abcdef@o0.ingest.sentry.io/42",
    DATABASE_URL: "postgres://app@db.internal/app", HTTPS_PROXY: "http://proxy.internal:3128",
    NODE_OPTIONS: "--max-old-space-size=4096", INIT_CWD: "/home/u/proj", VIRTUAL_ENV: "/home/u/proj/.venv",
    LS_COLORS: "rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:*.tar=01;31",
    // values a key check must not take
    HOSTNAME: "sk-" + "production-cluster-0001.internal",
    GIT_COMMIT: "3f1c2a9b8e7d6c5b4a3928170f6e5d4c3b2a1908",
    BUILD_ID: "123e4567-e89b-12d3-a456-426614174000",
    FIXTURE_GH_STRING: "gh" + "p_" + alnum(36, 15), // no valid checksum: a stand-in, not a token
    STRIPE_SAMPLE: "sk" + "_live_" + "EXAMPLE" + alnum(20, 16),
    AWS_DOC_PAIR: "AK" + "IA" + "IOSFODNN7" + "EXAMPLE" + ":" + "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
    AWS_ID_ALONE: AWS_ID,
    AWS_ID_AND_HASH: `${AWS_ID} 3f1c2a9b8e7d6c5b4a3928170f6e5d4c3b2a1908`,
    MANDU_ARBITER_SOCK: "/run/user/1000/mandu/arbiter.sock", CLAUDE_CODE_SKIP_BEDROCK_AUTH: "1",
  };
  for (const [name, value] of Object.entries(raw)) {
    assert.equal(envSecretNameMatches(name), false, `${name}: not a secret name`);
    assert.equal(envSecretSpan(name, value), null, `${name}=${value} stays raw`);
  }
  // 2026-10-10: a `*_PWD` a script set to a directory (docker-compose's
  // HOST_PWD, ORIG_PWD, CALLER_PWD) is no password. The dry run, which sees
  // names only, lists it; the launch, which sees the value, leaves it.
  const dirs: Record<string, string> = {
    HOST_PWD: "/home/u/proj", ORIG_PWD: "/srv/build area/x-1.2", CALLER_PWD: "/home/u/프로젝트", BUILD_PWD: "/",
  };
  for (const [name, value] of Object.entries(dirs)) {
    assert.equal(envSecretNameMatches(name), true, `${name}: the dry run lists the name`);
    assert.equal(envSecretSpan(name, value), null, `${name}=${value} stays raw`);
  }
});

test("env names (2026-10-10): a `*_PWD` stays masked unless it holds a directory and says secret only by its `_PWD`; MySQL's is masked whatever it holds", () => {
  const whole = (name: string, value: string) => assert.deepEqual(envSecretSpan(name, value), { key: name, start: 0, end: value.length, value }, `${name}=${value}`);
  whole("MYSQL_PWD", "/home/u");
  whole("SNOWSQL_PWD", "/pw");
  whole("DB_PWD", "/x9F!k$2");                 // punctuation no directory has
  whole("HOST_PWD", "relative/dir");           // not absolute
  whole("HOST_PWD", "hunter2");
  whole("DB_SECRET_PWD", "/home/u");           // `_SECRET_` says secret without the `_PWD`
  whole("API_TOKEN_PWD", "/home/u");
  whole("HOST_PWD", "/home/u\n/etc");          // one line only
  // The value check runs first: a key inside a path-like value still masks it.
  const gh = KEYS["GitHub classic token"]!;
  whole("HOST_PWD", `/home/u/${gh}`);
});

test("env values (2026-10-09): a key in a known format is masked whole under any name; never by the entropy rule", () => {
  for (const [what, value] of Object.entries(KEYS)) {
    assert.deepEqual(envSecretSpan("BUILD_HELPER_CONFIG", value), { key: "BUILD_HELPER_CONFIG", start: 0, end: value.length, value }, what);
    assert.deepEqual(envSecretSpan("BUILD_HELPER_CONFIG", `--auth ${value} --verbose`)?.start, 0, `${what} inside a longer value: the whole value`);
  }
  assert.equal(envSecretNameMatches("BUILD_HELPER_CONFIG"), false, "the dry run cannot see values (and says so)");
  // A long random value with no format: raw (no entropy test on env values).
  assert.equal(envSecretSpan("BUILD_HELPER_CONFIG", alnum(48, 17)), null);
  assert.equal(envSecretSpan("BUILD_HELPER_CONFIG", "api_token=" + alnum(40, 18)), null, "a credential-looking assignment is the entropy rule's, not a format");
  // A URL password stays the only span unless a key sits elsewhere in the URL.
  const gh = KEYS["GitHub classic token"]!;
  const clone = `https://x-access-token:${gh}@github.com/o/r.git`;
  assert.deepEqual(envSecretSpan("REPO_REMOTE", clone), { key: "REPO_REMOTE.password", start: 23, end: 23 + gh.length, value: gh });
  const hook = `https://u:pw-9@api.internal/hook?key=${KEYS["Stripe live key"]}`;
  assert.deepEqual(envSecretSpan("REPORT_TARGET", hook), { key: "REPORT_TARGET", start: 0, end: hook.length, value: hook });
});

test("env values: the agent's own credential, Mandu's routing and the law's exempt win over the value check; a config switch does not", () => {
  assert.equal(envSecretSpan("ANTHROPIC_API_KEY", KEYS["Anthropic key"]!), null);
  assert.equal(envSecretSpan("ANTHROPIC_AUTH_TOKEN", KEYS["Anthropic key"]!), null);
  assert.equal(envSecretSpan("OPENAI_API_KEY", KEYS["OpenAI project key"]!), null);
  assert.equal(envSecretSpan("CODEX_API_KEY", KEYS["OpenAI project key"]!), null);
  assert.equal(envSecretSpan("MANDU_ULLM_API_KEY", KEYS["Anthropic key"]!), null, "Mandu's own (the helper model's key)");
  const gh = KEYS["GitHub classic token"]!;
  assert.equal(envSecretSpan("CI_HELPER", gh, { exempt: ["CI_HELPER"] }), null, "the law's exempt, by name");
  assert.equal(envSecretSpan("CI_HELPER", gh, { exempt: ["CI_*"] }), null, "and by pattern");
  assert.ok(envSecretSpan("CI_HELPER", gh), "without it, masked");
  // A config switch is exempt from the name shapes, not from the value check.
  assert.equal(envSecretExempt("CLAUDE_CODE_EXTRA_HEADER_VALUE"), true);
  assert.equal(envSecretNameMatches("CLAUDE_CODE_EXTRA_HEADER_VALUE"), false);
  assert.deepEqual(envSecretSpan("CLAUDE_CODE_EXTRA_HEADER_VALUE", gh), { key: "CLAUDE_CODE_EXTRA_HEADER_VALUE", start: 0, end: gh.length, value: gh });
  assert.equal(envSecretSpan("CLAUDE_CODE_EXTRA_HEADER_VALUE", "https://u:pw@h.example/"), null, "a switch's URL is still the switch's");
  // The new suffixes make a CLAUDE_* / CODEX_* name a credential, as _TOKEN does.
  for (const name of ["CLAUDE_X_PAT", "CODEX_DB_PWD", "CLAUDE_PGPASSWORD", "CODEX_ALERTS_WEBHOOK_URL", "CLAUDE_ALERTS_WEBHOOK"]) {
    assert.equal(envSecretExempt(name), false, name);
    assert.ok(envSecretSpan(name, "v-1"), name);
  }
  assert.ok(envSecretSpan("CODEX_ALERTS_WEBHOOK_URL", "https://hooks.example/x/y"), "a webhook URL, whole");
});

test("env values (2026-10-10): a value longer than the detector's 10,000-character line is checked too, a key at any offset", () => {
  // locateSecretShapes skips a line over 10,000 characters; a one-line value
  // (a JSON config blob) used to pass the value check unread.
  const gh = KEYS["GitHub classic token"]!;
  // Words, not one long run: the URL-password rules before the value check
  // are slow over a long run of letters, which this test does not measure.
  const pad = (n: number): string => "lorem ipsum dolor ".repeat(Math.ceil(n / 18) + 1).slice(0, n);
  for (const at of [0, 5_000, 8_975, 8_976, 9_970, 9_999, 10_001, 17_951, 17_952, 25_000]) {
    const v = pad(at) + " " + gh + " " + pad(30_000 - at);
    assert.equal(envSecretSpan("BUILD_HELPER_CONFIG", v)?.end, v.length, `a key at ${at}: the whole value`);
  }
  const blob = JSON.stringify({ pad: "lorem ipsum ".repeat(2_000), stripe: KEYS["Stripe live key"], note: "dolor ".repeat(2_000) });
  assert.ok(blob.length > 20_000 && !blob.includes("\n"));
  assert.equal(envSecretSpan("APP_CONFIG_JSON", blob)?.end, blob.length);
  assert.equal(envSecretSpan("APP_CONFIG_JSON", "lorem ipsum ".repeat(5_000)), null, "a long value with no key stays raw");
  // A window's cut edge fakes no boundary: a token glued to a letter is no
  // token in a short value, nor where a window starts right after the letter.
  assert.equal(envSecretSpan("BUILD_HELPER_CONFIG", "A" + gh), null);
  const glued = pad(8_975) + "A" + gh + " " + pad(20_000);
  assert.equal(envSecretSpan("BUILD_HELPER_CONFIG", glued), null);
});

test("env values (2026-10-10): a private-key header alone, or with no key material after it, is no key", () => {
  assert.equal(envSecretSpan("DOC_SNIPPET", "-----BEGIN " + "PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----"), null);
  assert.equal(envSecretSpan("DOC_SNIPPET", "paste your -----BEGIN " + "PRIVATE KEY----- here"), null);
  assert.equal(envSecretSpan("DOC_SNIPPET", "-----BEGIN " + "PRIVATE KEY----- -----END PRIVATE KEY----- " + alnum(64, 31)), null, "material after the END line is not the block's");
});

// ── exhaustive configuration shapes (plan 10 §11.13, 2026-10-02) ────────────

test("shape dispatch: ssh config (and config.d), pip.conf / pip.ini, git's credential stores; only these three are exhaustive", () => {
  assert.equal(secretFileShape("/home/u/.ssh/config"), "ssh-config");
  assert.equal(secretFileShape("/home/u/.ssh/config.d/work"), "ssh-config");
  assert.equal(secretFileShape("/home/u/.ssh/conf.d/work.conf"), "ssh-config");
  assert.equal(secretFileShape("/home/u/.ssh/id_ed25519"), null, "a private key is whole-file");
  assert.equal(secretFileShape("/home/u/.config/pip/pip.conf"), "pip-conf");
  assert.equal(secretFileShape("/home/u/.pip/pip.conf"), "pip-conf");
  assert.equal(secretFileShape("/home/u/AppData/Roaming/pip/pip.ini"), "pip-conf");
  assert.equal(secretFileShape("/home/u/.git-credentials"), "git-credentials");
  assert.equal(secretFileShape("/home/u/.config/git/credentials"), "git-credentials");
  assert.equal(secretFileShape("/home/u/.aws/credentials"), "ini", "aws keeps its INI shape");
  for (const s of ["ssh-config", "pip-conf", "git-credentials"]) assert.equal(shapeIsExhaustive(s), true, s);
  for (const s of ["dotenv", "ini", "toml", "json-keys", "yaml-keys", "xml-keys", "pgpass", "netrc", "npmrc", "extract", null]) {
    assert.equal(shapeIsExhaustive(s), false, String(s));
  }
});

test("ssh config: no keyword is judged by name, so a config with no secret extracts nothing (its twin is its own text)", () => {
  const raw = [
    "# work hosts",
    "Host bastion",
    "  HostName 10.9.8.7",
    "  User deploy",
    "  PubkeyAuthentication yes",
    "  PasswordAuthentication=no",
    "  IdentityFile ~/.ssh/id_work",
    "  CertificateFile ~/.ssh/id_work-cert.pub",
    "",
    "Host *.internal",
    "\tProxyJump bastion",
    "\tProxyCommand ssh -W %h:%p bastion",
    "Include config.d/*",
    "",
  ].join("\n");
  const { x, text } = twin("/home/u/.ssh/config", raw.replace("# work hosts\n", ""));
  assert.equal(x.shape, "ssh-config");
  assert.deepEqual(x.spans, []);
  assert.equal(text, raw.replace("# work hosts\n", ""));
  // Since §11.13.2 a comment's text is masked (no program reads it; a note
  // may hold anything), its marker kept; a bare rule line stays.
  const commented = twin("/home/u/.ssh/config", raw.replace("# work hosts", "# work hosts, old pw hunter2\n#####"));
  assert.ok(commented.text.startsWith("# <global.comment>\n#####\nHost bastion\n"), commented.text);
});

test("ssh config: SetEnv values, a ProxyCommand off the relay grammar (env prefix, sshpass), a LocalCommand and an unreadable line are masked; the rest stays", () => {
  const raw = [
    "Host db",
    "  SetEnv LANG=C API_TOKEN=tok_SSHSETENV_1 GIT_DIR=/srv",
    "  ProxyCommand env DB_PASSWORD='pw SSHENV 2' nc %h %p",
    "Host legacy",
    "  ProxyCommand sshpass -e -pSSHPASS_3 ssh -W %h:%p jump",
    "  LocalCommand curl -s https://me:SSHURL_4@hooks.example.com/ping?private_token=SSHQ_5",
    "  this is not ssh_config SSHGARBAGE_6",
    "  SetEnv HOME_TOKEN=$HOME_TOKEN",
  ].join("\n");
  const { text } = twin("/home/u/.ssh/config", raw);
  for (const secret of ["tok_SSHSETENV_1", "pw SSHENV 2", "SSHPASS_3", "SSHURL_4", "SSHQ_5", "SSHGARBAGE_6"]) {
    assert.ok(!text.includes(secret), `${secret} must not survive the twin:\n${text}`);
  }
  // Since §11.13.2 every SetEnv value is a symbol, and a command no grammar
  // vouches for is withheld: Mandu's refusal command in its place (§11.13.3).
  assert.ok(text.includes("SetEnv LANG=<db.LANG> API_TOKEN=<db.API_TOKEN> GIT_DIR=<db.GIT_DIR>"), text);
  assert.ok(text.includes(`  ProxyCommand ${refusal(3, "ProxyCommand", "<db.ProxyCommand>")}\n`), text);
  assert.ok(text.includes(`  ProxyCommand ${refusal(5, "ProxyCommand", "<legacy.ProxyCommand>")}\n  LocalCommand ${refusal(6, "LocalCommand", "<legacy.LocalCommand>")}\n`), text);
  assert.ok(text.includes("SetEnv HOME_TOKEN=$HOME_TOKEN"), "an environment reference is not a secret");
  assert.ok(text.includes("Host legacy"));
});

test("pip.conf: URL credentials (password, a token as the user, a token parameter) on any line, continuation lines too; cert paths and plain URLs stay", () => {
  const raw = [
    "[global]",
    "index-url = https://__token__:PIPPW_1@pypi.corp.example/simple",
    "extra-index-url =",
    "    https://pypi.org/simple",
    "    https://ghp_PIPUSERTOKEN2@pkgs.example/simple",
    "    https://gitlab.example/api/v4/projects/1/packages/pypi/simple?private_token=PIPQ_3",
    "    https://${PIP_USER}:${PIP_PASSWORD}@env.example/simple",
    "cert = /etc/ssl/corp.pem",
    "timeout = 60",
    "trusted-host = pypi.corp.example",
    "[install]",
    "find-links = file:///srv/wheels",
    "proxy = http://proxyuser:PIPPROXY_4@proxy.example:3128",
    "",
  ].join("\n");
  const { x, text } = twin("/home/u/.config/pip/pip.conf", raw);
  assert.equal(x.shape, "pip-conf");
  for (const secret of ["PIPPW_1", "ghp_PIPUSERTOKEN2", "PIPQ_3", "PIPPROXY_4"]) assert.ok(!text.includes(secret), `${secret}:\n${text}`);
  for (const kept of ["https://__token__:", "    https://pypi.org/simple", "cert = /etc/ssl/corp.pem", "timeout = 60",
    "trusted-host = pypi.corp.example", "find-links = file:///srv/wheels", "https://${PIP_USER}:${PIP_PASSWORD}@env.example/simple",
    "http://proxyuser:"]) {
    assert.ok(text.includes(kept), `${kept} stays:\n${text}`);
  }
  // A pip.conf with no credential is its own twin.
  const plain = "[global]\nindex-url = https://pypi.org/simple\ntimeout = 60\n";
  assert.deepEqual(extractSecretSpans("/home/u/.config/pip/pip.conf", plain), { shape: "pip-conf", spans: [] });
});

test("pip.conf: a secret-named key masks its value and its continuation lines; an unparseable line is masked whole", () => {
  const raw = "[global]\nmy_api_key = PIPKEY_1\n  PIPKEY_CONT_2\nnot a config line PIPJUNK_3\n";
  const { text } = twin("/home/u/.pip/pip.conf", raw);
  for (const secret of ["PIPKEY_1", "PIPKEY_CONT_2", "PIPJUNK_3"]) assert.ok(!text.includes(secret), `${secret}:\n${text}`);
});

test("git-credentials: the password (and a token as the user) per line; the user and host stay; a non-URL line is masked", () => {
  const raw = [
    "https://alice:GITPW_1@github.com",
    "https://oauth2:GITPW_2@gitlab.example.com",
    "https://ghp_GITUSERTOKEN3@github.example",
    "https://github.com",
    "GITGARBAGE_4",
    "",
  ].join("\n");
  const { x, text } = twin("/home/u/.git-credentials", raw);
  assert.equal(x.shape, "git-credentials");
  for (const secret of ["GITPW_1", "GITPW_2", "ghp_GITUSERTOKEN3", "GITGARBAGE_4"]) assert.ok(!text.includes(secret), `${secret}:\n${text}`);
  assert.ok(text.startsWith("https://alice:<git.github.com.password>@github.com\n"), text);
  assert.ok(text.includes("\nhttps://github.com\n"));
  assert.equal(extractSecretSpans("/home/u/.config/git/credentials", "https://u:XDGPW@gitlab.com\n").spans[0]!.value, "XDGPW");
});

// ── exhaustive shapes fail closed (plan 10 §11.13.2, 2026-10-02) ────────────
// The own-text twin trusted the extractor: a value it did not classify as a
// secret stayed raw. Each case below sat raw in the twin before the change.

/** No secret byte survives, in the twin's text or in a field name. */
function assertMasked(path: string, raw: string, secrets: readonly string[]): string {
  const { text, x } = twin(path, raw);
  for (const s of secrets) {
    assert.ok(!text.includes(s), `${s} must not survive the twin:\n${text}`);
    for (const span of x.spans) assert.ok(!span.key.includes(s), `${s} leaked into the field name ${span.key}`);
  }
  return text;
}

test("ssh config fails closed: a command no grammar vouches for is masked whole, whatever it holds", () => {
  const raw = [
    "Host db",
    "  ProxyCommand mysql -phunter2 -h %h",
    "  LocalCommand curl -H 'Authorization: Bearer abcLOCALCMD' https://hooks.example/%n",
    "  RemoteCommand psql postgresql://db/app?password=REMOTEPW1",
    "  KnownHostsCommand /usr/local/bin/hosts --key KHCKEY77",
    "Host web",
    "  ProxyCommand nc -x proxy:1080 -P PROXYUSER9 %h %p",
    "Match exec \"vault login TOKENinMATCH5 && true\" host x",
    "Match host y exec MATCHBARE6",
  ].join("\n");
  const text = assertMasked("/home/u/.ssh/config", raw,
    ["hunter2", "abcLOCALCMD", "REMOTEPW1", "KHCKEY77", "PROXYUSER9", "TOKENinMATCH5", "MATCHBARE6", "mysql", "vault"]);
  // A withheld command is Mandu's refusal command (§11.13.3), the field
  // symbol riding along; a Match exec word is one double-quoted word.
  assert.ok(text.includes(`  ProxyCommand ${refusal(2, "ProxyCommand", "<db.ProxyCommand>")}\n`), text);
  assert.ok(text.includes(`  RemoteCommand ${refusal(4, "RemoteCommand", "<db.RemoteCommand>")}\n`), text);
  assert.ok(text.includes(`  KnownHostsCommand ${refusal(5, "KnownHostsCommand", "<db.KnownHostsCommand>")}\n`), text);
  assert.ok(text.includes(`Match exec ${refusal(8, "Match exec", "<x.exec>", true)} host x`), text);
  assert.ok(text.endsWith(`Match host y exec ${refusal(9, "Match exec", "<y.exec>", true)}`), text);
});

// ── a withheld command says where, why and the way out (§11.13.3) ──────────
// Before: the twin held `ProxyCommand '$MDU…'`, and the agent saw only
// `sh: 1: $MDU:…: not found` and `Connection closed by UNKNOWN port 65535`.

const WITHHELD_RAW = [
  "# hosts",                                                        // 1
  "Host db",                                                        // 2
  "  ProxyCommand mysql -phunter2SECRET -h %h",                     // 3
  "",                                                               // 4
  "Host hooks",                                                     // 5
  "  PermitLocalCommand yes",                                       // 6
  "  LocalCommand curl -H 'Authorization: Bearer LOCALtok9' https://hooks.example/%n", // 7
  "  RemoteCommand psql postgresql://db/app?password=REMOTEpw3",    // 8
  "  KnownHostsCommand /usr/local/bin/hosts --key KHkey77",         // 9
  "Match host x exec \"vault login MATCHtok5 && true\"",            // 10
  "Host jump",                                                      // 11
  "  ProxyCommand ssh -W %h:%p bastion",                            // 12
].join("\n");
const WITHHELD_SECRETS = ["hunter2SECRET", "LOCALtok9", "REMOTEpw3", "KHkey77", "MATCHtok5", "mysql", "curl", "psql", "vault", "Bearer"];

test("withheld ssh command: the message names the file, the right line and the keyword, and carries none of the command's text", () => {
  for (const content of [WITHHELD_RAW, WITHHELD_RAW.replace(/\n/g, "\r\n")]) {
    const found = withheldCommands("/home/alice/.ssh/config", content);
    assert.deepEqual(found, [
      { line: 3, keyword: "ProxyCommand" },
      { line: 7, keyword: "LocalCommand" },
      { line: 8, keyword: "RemoteCommand" },
      { line: 9, keyword: "KnownHostsCommand" },
      { line: 10, keyword: "Match exec" },
    ], "a vetted jump command (line 12) is not withheld; CRLF counts the same lines");
    const x = extractSecretSpans("/home/alice/.ssh/config", content);
    for (const s of x.spans.filter((sp) => sp.withheld)) {
      const lines = withheldCommandMessage(s.withheld!);
      const text = lines.join("\n");
      assert.match(lines[0]!, new RegExp(`^mandu: ~/\\.ssh/config line ${s.withheld!.line}: ${s.withheld!.keyword} withheld`));
      assert.match(text, /would run code holding one/, "why");
      assert.match(text, /ProxyJump/);
      assert.match(text, /script Mandu can pin/, "the way out names the pin");
      assert.match(text, /run this ssh outside the agent/);
      assert.match(text, /mandu why ~\/\.ssh\/config/);
      // No secret value, no word of the command, no user name.
      for (const secret of [...WITHHELD_SECRETS, "alice"]) assert.ok(!text.includes(secret), `${secret} in the message:\n${text}`);
      // The rendered twin carries the token, never the withheld text.
      const cmd = withheldCommandTwin(s.withheld!, "<tok>");
      for (const secret of [...WITHHELD_SECRETS, "alice"]) assert.ok(!cmd.includes(secret), `${secret} in the refusal command:\n${cmd}`);
      // Shell- and ssh-inert: each line is a single-quoted argument printed
      // through an unquoted expansion, and ssh %-expands the command.
      for (const l of lines) assert.match(l, /^[^'"$`\\*?[%]+$/, `not inert: ${l}`);
    }
    const { text } = twin("/home/alice/.ssh/config", content);
    for (const secret of WITHHELD_SECRETS) assert.ok(!text.includes(secret), `${secret} survived the twin:\n${text}`);
    assert.ok(text.includes("  ProxyCommand ssh -W %h:%p bastion"), "the vetted command stays");
  }
});

test("withheld ssh command: the effect follows the keyword, the file name is shell-inert and keeps no user name, other shapes withhold nothing", () => {
  const effect = (keyword: string) => withheldCommandMessage({ file: "~/.ssh/config", line: 1, keyword })[0]!;
  assert.match(effect("ProxyCommand"), /cannot reach this host/);
  assert.match(effect("RemoteCommand"), /session to this host ends at once/);
  assert.match(effect("LocalCommand"), /runs this notice in its place/);
  assert.match(effect("KnownHostsCommand"), /cannot check the key of this host/);
  assert.match(effect("Match exec"), /this Match block is skipped/);
  assert.equal(withheldFileName("/home/alice/.ssh/config"), "~/.ssh/config");
  assert.equal(withheldFileName("/home/alice/.ssh/config.d/work"), "~/.ssh/config.d/work");
  assert.equal(withheldFileName("/tmp/h/.ssh/config.d/it's $(x) %h"), "~/.ssh/config.d/it_s___x___h");
  // An Include'd file is named as itself.
  const inc = withheldCommands("/home/alice/.ssh/config.d/work", "Host w\n  RemoteCommand tmux attach\n");
  assert.deepEqual(inc, [{ line: 2, keyword: "RemoteCommand" }]);
  assert.match(twin("/home/alice/.ssh/config.d/work", "Host w\n  RemoteCommand tmux attach\n").text, /'mandu: ~\/\.ssh\/config\.d\/work line 2: RemoteCommand withheld/);
  assert.deepEqual(withheldCommands("/home/alice/.env", "ProxyCommand=evil\n"), []);
  // A token with a quote cannot break the quoting (symbols have none; belt).
  assert.ok(!withheldCommandTwin({ file: "~/.ssh/config", line: 1, keyword: "ProxyCommand" }, "a'b").includes("a'b"));
});

test("ssh config: the known-safe command grammar keeps ordinary jump commands raw", () => {
  const kept = [
    "Host a",
    "  ProxyCommand ssh -W %h:%p bastion",
    "  ProxyCommand exec ssh -q -o StrictHostKeyChecking=no -p 2222 -i ~/.ssh/id_jump -W %h:%p deploy@bastion.example.com",
    "  ProxyCommand ssh bastion nc %h %p",
    "  ProxyCommand nc -X 5 -x proxy.corp:1080 %h %p",
    "  ProxyCommand /usr/bin/ncat --proxy proxy.corp:3128 --proxy-type http %h %p",
    "  ProxyCommand socat - PROXY:proxy.corp:%h:%p,proxyport=3128",
    "  ProxyCommand connect-proxy -H proxy.corp:3128 %h %p",
    "  ProxyCommand corkscrew proxy.corp 3128 %h %p",
    "  ProxyCommand cloudflared access ssh --hostname %h",
    "  ProxyCommand aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p' --region eu-west-1",
    "  ProxyCommand gcloud compute start-iap-tunnel %h %p --listen-on-stdin --project=my-proj --zone=europe-west1-b",
    "  ProxyCommand none",
    "  LocalCommand none",
    "Match exec \"nc -z bastion 22\" host *.internal",
    "  ProxyJump bastion",
  ].join("\n");
  const { x, text } = twin("/home/u/.ssh/config", kept);
  assert.deepEqual(x.spans, [], text);
  // Off the grammar: each of these is masked.
  for (const cmd of [
    "nc -x proxy:1080 %h %p | tee /tmp/x",                // a pipe
    "ssh -W %h:%p $(cat ~/.token)",                       // a substitution
    "ssh -o ProxyCommand=evil -W %h:%p bastion",          // -o with a command keyword
    "ssh -W %h:%p bastion extra args here",               // a remote command off the grammar
    "socat - PROXY:proxy:%h:%p,proxyauth=user:SOCATPW",   // proxy credentials
    "ncat --proxy proxy:3128 --proxy-auth u:NCATPW %h %p",
    "cloudflared access ssh --hostname %h --service-token-secret CFSECRET",
    "nc %h %p 3f2a1b4c9d8e7f6a5b4c",                      // a credential-shaped argument
  ]) {
    const raw = `Host b\n  ProxyCommand ${cmd}\n`;
    const t = twin("/home/u/.ssh/config", raw).text;
    assert.equal(t, `Host b\n  ProxyCommand ${refusal(2, "ProxyCommand", "<b.ProxyCommand>")}\n`, `${cmd}\n${t}`);
  }
});

test("ssh config fails closed: every SetEnv value is masked, an unknown keyword's name too, and Match keeps no command in a field name", () => {
  const raw = [
    "Host ci",
    "  SetEnv LANG=C FOO=hunter3 \"QUOTED=a b\" HOME_TOKEN=$HOME_TOKEN NOEQUALS7",
    "  hunter4secret99 somevalue",
    "  User ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
  ].join("\n");
  const text = assertMasked("/home/u/.ssh/config", raw, ["hunter3", "a b", "NOEQUALS7", "hunter4secret99", "somevalue", "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"]);
  assert.ok(text.includes("SetEnv LANG=<ci.LANG> FOO=<ci.FOO> \"QUOTED=<ci.QUOTED>\" HOME_TOKEN=$HOME_TOKEN <ci.SetEnv>"), text);
  assert.ok(text.includes("  <ci.line>\n"), "an unknown line with a credential-shaped keyword is masked whole");
});

test("pip.conf fails closed: an unknown key's value, a token in an index URL's path or query, a scheme-less proxy, a token user with a dummy password", () => {
  const raw = [
    "[global]",
    "index-url = https://dl.cloudsmith.io/AbCd1234EfGh5678/acme/repo/python/simple/",
    "extra-index-url = https://pypi.fury.io/1a2B3c4D5e6F7g8H9i0J/acme/",
    "    https://pkgs.example/simple?auth=QUERYTOK1234abcd",
    "    https://ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567:x-oauth-basic@github.com/simple",
    "proxy = proxyuser:SCHEMELESSPW@proxy.corp:3128",
    "my-plugin-setting = PLUGINVALUE",
    "  PLUGINCONT",
    "hunter5secret99 = xyz",
    "[my-section]",
    "anything = SECTIONVALUE",
  ].join("\n");
  const text = assertMasked("/home/u/.config/pip/pip.conf", raw,
    ["AbCd1234EfGh5678", "1a2B3c4D5e6F7g8H9i0J", "QUERYTOK1234abcd", "aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567", "SCHEMELESSPW", "PLUGINVALUE", "PLUGINCONT", "hunter5secret99", "SECTIONVALUE"]);
  for (const kept of ["https://dl.cloudsmith.io/", "/acme/repo/python/simple/", "https://pypi.fury.io/", "my-plugin-setting = ", "proxyuser:", "@proxy.corp:3128"]) {
    assert.ok(text.includes(kept), `${kept} stays:\n${text}`);
  }
});

test("pip.conf: realistic index URLs and settings stay their own text (the utility the rule keeps)", () => {
  const raw = [
    "[global]",
    "index-url = https://pypi.org/simple",
    "extra-index-url =",
    "    https://pkgs.dev.azure.com/acme/_packaging/feed/pypi/simple/",
    "    https://acme.jfrog.io/artifactory/api/pypi/pypi-virtual/simple",
    "    https://nexus.acme.example/repository/pypi-group/simple",
    "    https://gitlab.example.com/api/v4/projects/1234/packages/pypi/simple",
    "    https://${PIP_USER}:${PIP_PASSWORD}@env.example/simple",
    "    https://alice@keyring.example/simple",
    "trusted-host = pypi.corp.example d111111abcdef8.cloudfront.net",
    "timeout = 60",
    "cert = /etc/ssl/corp.pem",
    "cache-dir = /home/u/.cache/pip",
    "keyring_provider = subprocess",
    "[install]",
    "find-links = file:///srv/wheels",
    "no-binary = :all:",
    "upgrade-strategy = only-if-needed",
    "",
  ].join("\n");
  const { x, text } = twin("/home/u/.config/pip/pip.conf", raw);
  assert.deepEqual(x.spans, [], text);
});

test("git-credentials fails closed: a token user with a dummy password, a token in the path or query, a URL line with trailing text", () => {
  const raw = [
    "https://ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789:x-oauth-basic@github.com",
    "https://bob:GITPW_9@git.example.com/AbCd1234EfGh5678IjKl/repo.git?token=QTOKEN42xyz123",
    "https://carol:GITPW_8@git.example.com trailing TRAILJUNK",
    "# a comment COMMENTJUNK",
  ].join("\n");
  const text = assertMasked("/home/u/.git-credentials", raw,
    ["aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "x-oauth-basic", "GITPW_9", "AbCd1234EfGh5678IjKl", "QTOKEN42xyz123", "GITPW_8", "TRAILJUNK", "COMMENTJUNK"]);
  assert.ok(text.includes("https://bob:<git.git.example.com.password>@git.example.com/"), text);
  assert.ok(text.includes("/repo.git?token="), text);
});

test("exhaustive shapes: a credential shape the detector knows is masked wherever it sits raw (the detection belt)", () => {
  const ssh = assertMasked("/home/u/.ssh/config", "Host x\n  HostName sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ012345\n", ["aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"]);
  assert.ok(ssh.includes("HostName <x.anthropic-key>"), ssh);
  assertMasked("/home/u/.config/pip/pip.conf", "[global]\nlog = /tmp/glpat-AbCdEfGhIj1234567890\n", ["AbCdEfGhIj1234567890"]);
});
