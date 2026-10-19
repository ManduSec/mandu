/**
 * secret-extract, list items (2026-10-09): the string items of a JSON array,
 * a YAML sequence and a TOML array are masked when Mandu recognizes a secret
 * in them, in a file whose keys already gave a secret span.
 *
 * Before: the key-name rule saw only `"key": "string"` pairs, so in a
 * labelled `.mcp.json` with an `env` block every `args` value stayed raw in
 * the twin (`"--api-key", "…"`, `"--token=…"`, a database URL's password).
 * The rules (`listItemSpans`): a URL's password; a credential format the
 * content detector knows; the item after a secret-named flag; the value of a
 * secret-named `--flag=…`, `NAME=…` or `Header: …`; every item of a list
 * under a secret-looking key. Field names `<list>.<index>`, scanner-safe.
 * And `twinFormOf`, what `mandu why` reports: the twin the registration
 * makes of the file as it is, not the shape its path suggests.
 *
 * 2026-10-10 (review): `--auth`, `--pat` and `user:password` after `--user`
 * / `-u`; a flag after a secret flag is not its value; a placeholder in a
 * plain YAML flow item is quoted (the twin parses with js-yaml); a block
 * scalar's text is no YAML; a list that never closes or nests too deep
 * hides the file whole; rules (b) and (d) in YAML and TOML; and every walk
 * is linear (adversarial 256 KB inputs finish within 5 s on a loaded guest,
 * and one that takes over 1 s grows about 2x, not 4x, from half size).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import yaml from "js-yaml";
import { extractSecretSpans, renderStructuredTwin, type SecretSpan } from "../../policy/secret-extract.js";
import { twinFormOf } from "../../secret-registry/registry.js";
import { canonicalSymbolField } from "../../symbol-table/symbol-format.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // pure extraction; the twin is the confidentiality axis's

// Credential-format fixtures, built at run time so no source line is token-shaped.
const STRIPE = ["sk", "live", "4eC39HqLyjWDarjtT1zdp7dc"].join("_");
const GITLAB = `glpat-${"Xq7Rz2Lm9Tb4Wc8Vn3Kp"}`;
const PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7";
const PEM = `-----BEGIN ${"PRIVATE"} KEY-----\n${PEM_BODY}\n-----END ${"PRIVATE"} KEY-----\n`;

const pairs = (spans: readonly SecretSpan[]) => spans.map((s) => [s.key, s.value]);
const token = (s: SecretSpan) => `$MDU:nomodel_Read[abcd].${s.key}`;
const twin = (path: string, content: string) => {
  const x = extractSecretSpans(path, content);
  return { x, text: renderStructuredTwin(content, x.spans, token) };
};
/** Field names stay as written in the token (no hex encoding, no brackets). */
const scannerSafe = (spans: readonly SecretSpan[]) => {
  for (const s of spans) {
    assert.equal(canonicalSymbolField(s.key), s.key, `field ${s.key} is scanner-complete as written`);
    assert.ok(!/[[\]]/.test(s.key), `field ${s.key} has no brackets`);
  }
};

/** A multi-server MCP config: an env block (a keyed secret) beside args. */
const MCP = JSON.stringify({
  mcpServers: {
    brave: {
      command: "npx",
      args: ["-y", "@brave/brave-search-mcp-server", "--api-key", "hunter42", "--token=swordfish", "postgresql://app:tiger@db.internal:5432/prod"],
      env: { BRAVE_API_KEY: "BSAenvKEY0123456789abcdef" },
    },
    github: {
      command: "docker",
      args: ["run", "-i", "--rm", "-p", "8080:80", "-e", "GITHUB_TOKEN", "-e", "LOG_LEVEL=debug", "ghcr.io/github/github-mcp-server:v1.2.3", "--toolsets", "repos,issues"],
    },
    files: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/home/u/projects/app2", "--verbose", "--read-only"] },
  },
}, null, 2);

test("json: an MCP config's args are masked by the four rules, its env by key; the rest stays as written and the twin still parses", () => {
  const { x, text } = twin("/home/u/proj/.mcp.json", MCP);
  assert.equal(x.shape, "json-keys");
  assert.deepEqual(pairs(x.spans), [
    ["args.3", "hunter42"],
    ["args.4", "swordfish"],
    ["args.5.password", "tiger"],
    ["BRAVE_API_KEY", "BSAenvKEY0123456789abcdef"],
  ]);
  for (const raw of ["hunter42", "swordfish", "tiger", "BSAenvKEY0123456789abcdef"]) assert.ok(!text.includes(raw), raw);
  const parsed = JSON.parse(text) as { mcpServers: Record<string, { args: string[]; env?: Record<string, string> }> };
  assert.deepEqual(parsed.mcpServers.brave!.args, [
    "-y", "@brave/brave-search-mcp-server", "--api-key", "$MDU:nomodel_Read[abcd].args.3", "--token=$MDU:nomodel_Read[abcd].args.4",
    "postgresql://app:$MDU:nomodel_Read[abcd].args.5.password@db.internal:5432/prod",
  ]);
  // NOT masked: commands, package names, paths, ports, image names, flags with no secret.
  assert.deepEqual(parsed.mcpServers.github!.args, JSON.parse(MCP).mcpServers.github.args);
  assert.deepEqual(parsed.mcpServers.files!.args, JSON.parse(MCP).mcpServers.files.args);
  scannerSafe(x.spans);
});

test("json, rule (a): a URL's password anywhere in an item, only the password", () => {
  const c = JSON.stringify({ token: "t-1", args: ["--db=postgres://u:pw1@h/db", "see mysql://root:pw2@10.0.0.5:3306/x and more", "https://h.example/path:8080"] });
  const { x } = twin("/w/a.json", c);
  assert.deepEqual(pairs(x.spans), [["token", "t-1"], ["args.0.password", "pw1"], ["args.1.password", "pw2"]]);
});

test("json, rule (b): a credential format the content detector knows, wherever it sits in an item; a private key's escapes are masked with it", () => {
  const c = JSON.stringify({ password: "p", args: [STRIPE, `--header=X-Key ${GITLAB}`, PEM, "plain"] });
  const { x, text } = twin("/w/b.json", c);
  assert.deepEqual(x.spans.map((s) => s.key), ["password", "args.0", "args.1", "args.2"]);
  assert.equal(x.spans[1]!.value, STRIPE);
  assert.equal(x.spans[2]!.value, GITLAB);
  // The span is on the file's text: the key block's `\n` escapes are inside it.
  assert.ok(x.spans[3]!.value.startsWith("-----BEGIN") && x.spans[3]!.value.includes("\\n") && x.spans[3]!.value.includes(PEM_BODY));
  for (const raw of [STRIPE, GITLAB, PEM_BODY]) assert.ok(!text.includes(raw));
  assert.deepEqual((JSON.parse(text) as { args: string[] }).args, [
    "$MDU:nomodel_Read[abcd].args.0", "--header=X-Key $MDU:nomodel_Read[abcd].args.1", "$MDU:nomodel_Read[abcd].args.2\n", "plain",
  ]);
});

test("json, rule (c): the item after a secret-named flag; the flag list is exact", () => {
  const secretFlags = [
    "--api-key", "--token", "--password", "--secret", "--key", "--apikey", "--api_key", "--client-secret", "--db-password",
    "--access-token", "--passphrase", "--pw", "--authtoken", "--secretkey", "-token", "-password", "-api-key",
    // 2026-10-10: the auth family and a personal access token.
    "--auth", "--basic-auth", "--http-auth", "--proxy-auth", "--pat", "--gitlab-pat",
  ];
  const plainFlags = [
    "--key-file", "--token-path", "--password-stdin", "--no-password", "--keyboard", "--monkey", "--hotkey", "--author", "-k", "-p", "-t", "--port", "-ptoken",
    "--oauth", "--auth-file", "--auth-type", "--no-auth", "--path", "--compat",
    // 2026-10-10 (review): a switch that ends in `auth`, a pattern that ends in `pat`.
    "--skip-auth", "--disable-auth", "--disable-basic-auth", "--require-auth", "--exclude-pat", "--include-pat", "--file-pat",
    // `--user` / `-u` take `user:password` (rule e); a bare user is no secret.
    "--user", "-u",
  ];
  const args: string[] = [];
  for (const f of [...secretFlags, ...plainFlags]) args.push(f, `v${args.length}`);
  const { x } = twin("/w/c.json", JSON.stringify({ secret: "s", args }));
  const masked = new Set(x.spans.filter((s) => s.key.startsWith("args.")).map((s) => s.value));
  secretFlags.forEach((f, i) => assert.ok(masked.has(`v${2 * i}`), `${f} takes a secret`));
  plainFlags.forEach((f, i) => assert.ok(!masked.has(`v${2 * (secretFlags.length + i)}`), `${f} does not`));
});

test("json, rule (c): a one-letter flag counts only for the programs that take a password with it (sshpass -p, mysql -p glued, redis-cli -a), named in the list or as the command beside it", () => {
  const c = JSON.stringify({
    token: "t",
    docker: { command: "docker", args: ["run", "-p", "8080:80", "img"] },
    npx: { command: "npx", args: ["-p", "@scope/pkg", "tool"] },
    ssh: { args: ["-p", "sshpw1", "ssh", "host"], command: "/usr/bin/sshpass" },
    inline: { args: ["sshpass", "-psshpw2", "ssh", "host"] },
    mysql: { command: "mysql", args: ["-u", "root", "-pmypw3", "-p", "mydb"] },
    redis: { command: "redis-cli", args: ["-a", "rdpw4", "-p", "6379"] },
  });
  const { x } = twin("/w/d.json", c);
  assert.deepEqual(x.spans.filter((s) => s.key !== "token").map((s) => s.value), ["sshpw1", "sshpw2", "mypw3", "rdpw4"]);
});

test("json, rule (d): the value of a secret-named --flag=, NAME= or Header: item; a `${…}` reference stays, a `$NAME` no shell expands does not", () => {
  const c = JSON.stringify({
    password: "p",
    args: [
      "--token=tk1", "--api-key=ak2", "--log-level=debug", "-e", "API_KEY=ek3", "PLAIN=hello", "DB_PASSWORD=dp4",
      "--header", "Authorization: Bearer bt5", "X-API-Key: xk6", "Content-Type: application/json",
      "--token=${TOKEN}", "--api-key", "${input:brave_key}", "--secret", "$SECRET", "--token", "${X:-default7}",
    ],
  });
  const { x } = twin("/w/e.json", c);
  // 2026-10-10 (fourth review): an item reaches the program as written (the
  // MCP client expands `${…}` only), so `$SECRET` is a value, as a
  // password `$ecretPass99` would be.
  assert.deepEqual(x.spans.filter((s) => s.key !== "password").map((s) => s.value), ["tk1", "ak2", "ek3", "dp4", "bt5", "xk6", "$SECRET", "${X:-default7}"]);
});

test("json: an item that is a command line (`sh -c …`) gets the same flags and names for the words inside it", () => {
  const c = JSON.stringify({
    token: "t",
    command: "sh",
    args: ["-c", 'exec env API_KEY=ck1 node server.js --token ck2 --password="ck3 x" --log-level info', "sshpass -p ck4 ssh host", "run --token-file /x --key-path /y --verbose"],
  });
  const { x, text } = twin("/w/g.json", c);
  // `sshpass -p` inside an item is a flag of the program named before it (args.2), as it is as items.
  assert.deepEqual(pairs(x.spans.filter((s) => s.key !== "token")), [
    ["args.1.API_KEY", "ck1"], ["args.1", "ck2"], ["args.1__2", "ck3 x"], ["args.2", "ck4"],
  ]);
  assert.equal((JSON.parse(text) as { args: string[] }).args[3], "run --token-file /x --key-path /y --verbose", "file and path flags stay");
});

test("json: every string item of a list under a secret-looking key, a URL keeping all but its password; nested lists named by place", () => {
  const c = JSON.stringify({ password: "p0", api_keys: ["k-one", "https://h.example/x", "https://u:kpw@h/x", 42, ["nested-k"]], matrix: [["--token", "mt"]] });
  const { x } = twin("/w/f.json", c);
  assert.deepEqual(pairs(x.spans), [["password", "p0"], ["api_keys.0", "k-one"], ["api_keys.2.password", "kpw"], ["api_keys.4.0", "nested-k"], ["matrix.0.1", "mt"]]);
  scannerSafe(x.spans);
});

test("json: list items only add to a file whose keys gave a secret; a list-only file stays the whole-file twin, as before", () => {
  const pgOnly = JSON.stringify({ mcpServers: { pg: { command: "npx", args: ["-y", "@modelcontextprotocol/server-postgres", "postgresql://u:pw@h/db"] } } });
  assert.deepEqual(extractSecretSpans("/w/.mcp.json", pgOnly), { shape: "json-keys", spans: [] });
  assert.deepEqual(extractSecretSpans("/w/x.json", JSON.stringify({ args: ["--token", "t"] })).spans, []);
});

test("json: keyed values are judged as before; IDs under ordinary keys and in ordinary lists stay (tfstate)", () => {
  const tf = JSON.stringify({
    resources: [{ type: "aws_instance", instances: [{ attributes: {
      id: "i-0abc123def4567890", password: "p3", vpc_security_group_ids: ["sg-0123456789abcdef0"], tags_all: { Name: "web" },
      arn: "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def4567890", subnet_ids: ["subnet-0a1b2c3d4e5f67890"],
    } }] }],
  });
  assert.deepEqual(pairs(extractSecretSpans("/w/terraform.tfstate", tf).spans), [["password", "p3"]]);
});

test("json: comments (JSONC), escapes and broken structure do not misplace a span", () => {
  const c = `{
  // "--token", "not-an-item"
  "token": "t", /* ["--password", "nope"] */
  "args": ["--token", "a\\"b\\u0041c", 1, {"k": "v"}, "--key"],
  "broken": ["--password", "unclosed
}`;
  const { x, text } = twin("/w/.vscode/mcp.json", c);
  assert.deepEqual(pairs(x.spans), [["token", "t"], ["args.1", 'a\\"b\\u0041c'], ["broken.1", "unclosed"]]);
  assert.ok(text.includes('"$MDU:nomodel_Read[abcd].args.1"'), text);
  assert.ok(text.includes('"not-an-item"') && text.includes('"nope"'), "comments are not lists");
});

const YAML = `mcpServers:
  - name: sqlite
    command: sshpass
    args:
      - "-p"
      - 'it''s'
      - --api-key
      - hunter42 # rotate monthly
      - postgresql://u:ypw@h/db
      - -y
      - "@scope/server"
  - name: other
    args: [-p, "8080", "--token=yt1", [nested, --key, ynk]]
    env:
      API_KEY: zzz
extensions:
  github:
    args:
    - --password
    - ypw2
    - /home/u/repo
    tokens:
      - ytk3
`;

test("yaml: block and flow sequences by the four rules, names by their keys' path; `-p` counts for the item whose command is sshpass, not the next", () => {
  const { x, text } = twin("/home/u/.continue/config.yaml", YAML);
  assert.equal(x.shape, "yaml-keys");
  assert.deepEqual(pairs(x.spans), [
    ["mcpServers.args.1", "it''s"],
    ["mcpServers.args.3", "hunter42"],
    ["mcpServers.args.4.password", "ypw"],
    ["mcpServers.args.2", "yt1"],
    ["mcpServers.args.3.2", "ynk"],
    ["mcpServers.env.API_KEY", "zzz"],
    ["extensions.github.args.1", "ypw2"],
    ["extensions.github.tokens.0", "ytk3"],
  ]);
  assert.ok(text.includes("      - $MDU:nomodel_Read[abcd].mcpServers.args.3 # rotate monthly\n"), text);
  assert.ok(text.includes("      - '$MDU:nomodel_Read[abcd].mcpServers.args.1'\n"), "a quoted item keeps its quotes");
  for (const kept of ['- "-p"', "- -y", '- "@scope/server"', '[-p, "8080", ', "- /home/u/repo", "- --password"]) assert.ok(text.includes(kept), kept);
  scannerSafe(x.spans);
});

test("yaml: a list-only file stays whole-file; key-name spans are as before", () => {
  assert.deepEqual(extractSecretSpans("/w/a.yaml", "args:\n  - --token\n  - t1\n"), { shape: "yaml-keys", spans: [] });
  assert.deepEqual(pairs(extractSecretSpans("/home/u/.config/gh/hosts.yml", "github.com:\n    oauth_token: gho_abcdef\n    user: me\n").spans), [["github.com.oauth_token", "gho_abcdef"]]);
});

const TOML = `[mcp_servers.brave]
command = "npx"
args = ["-y", "pkg", "--api-key", "thunter42", 'postgresql://u:tpw@h/db']

[mcp_servers.multi]
args = [
  "--token", # the next item is the token
  "tt1",
  1, true, 2026-10-09,
  ["--key", "tnk"],
  "-p", "tsp",
]
command = 'sshpass'

[mcp_servers.multi.env]
BRAVE_API_KEY = "tbk"
`;

test("toml: one-line and multi-line arrays by the four rules, named <table>.<key>.<index>; a table's command applies after it; numbers are no items", () => {
  const { x, text } = twin("/home/u/.codex/config.toml", TOML);
  assert.equal(x.shape, "toml");
  assert.deepEqual(pairs(x.spans), [
    ["mcp_servers.brave.args.3", "thunter42"],
    ["mcp_servers.brave.args.4.password", "tpw"],
    ["mcp_servers.multi.args.1", "tt1"],
    ["mcp_servers.multi.args.5.1", "tnk"],
    ["mcp_servers.multi.args.7", "tsp"],
    ["mcp_servers.multi.env.BRAVE_API_KEY", "tbk"],
  ]);
  assert.ok(text.includes(`args = ["-y", "pkg", "--api-key", "$MDU:nomodel_Read[abcd].mcp_servers.brave.args.3", 'postgresql://u:$MDU:nomodel_Read[abcd].mcp_servers.brave.args.4.password@h/db']`), text);
  assert.ok(text.includes('  "--token", # the next item is the token\n'), "the comment stays");
  scannerSafe(x.spans);
});

test("toml: an inline table or a multi-line string is still the whole-file twin; a list-only file too", () => {
  assert.equal(extractSecretSpans("/h/a.toml", `[x]\nenv = { TOKEN = "x1" }\nargs = ["--token", "t"]\n`).shape, null);
  assert.deepEqual(extractSecretSpans("/h/a.toml", `[x]\nargs = ["--token", "t"]\n`), { shape: "toml", spans: [] });
});

test("twinFormOf: the twin a registration makes of the text, not the shape its path suggests (mandu why)", () => {
  const label = { rule: "label:/w/.mcp.json" };
  assert.deepEqual(twinFormOf("/w/.mcp.json", MCP, label), { form: "structured", shape: "json-keys", fields: 4 });
  const pgOnly = JSON.stringify({ args: ["postgresql://u:pw@h/db"] });
  assert.deepEqual(twinFormOf("/w/.mcp.json", pgOnly, label), { form: "whole-file", shape: "json-keys", fields: 0 });
  assert.deepEqual(twinFormOf("/w/notes.md", "token t\n", { rule: "label:/w/notes.md" }), { form: "whole-file", shape: null, fields: 0 });
  // A TOML with an inline table cannot be masked in place: whole, no shape to blame.
  assert.deepEqual(twinFormOf("/w/c.toml", `[x]\nenv = { TOKEN = "x1" }\n`, { rule: "label:/w/c.toml" }), { form: "whole-file", shape: null, fields: 0 });
  // An exhaustive shape with no secret: its own text on the catalog's word, whole under a label.
  assert.deepEqual(twinFormOf("/h/.ssh/config", "Host a\n  HostName 10.0.0.1\n", { rule: "prefix:~/.ssh" }), { form: "own-text", shape: "ssh-config", fields: 0 });
  assert.deepEqual(twinFormOf("/h/.ssh/config", "Host a\n  HostName 10.0.0.1\n", { rule: "label:/h/.ssh/config" }), { form: "whole-file", shape: "ssh-config", fields: 0 });
  // A label's extract regex decides the spans.
  assert.deepEqual(twinFormOf("/w/notes.md", "pin: 1234\n", { rule: "label:/w/notes.md", extract: "pin: (\\d+)" }), { form: "structured", shape: "extract", fields: 1 });
});

// ── 2026-10-10: the review's findings ───────────────────────────────────────

test("json, rule (e): the password of `user:password` after --user, -u or --proxy-user; not docker's uid:gid, a bare user or a reference", () => {
  const c = JSON.stringify({
    token: "t",
    curl: { command: "curl", args: ["-u", "admin:cpw1", "--user=bob:cpw2", "-ucarol:cpw3", "--proxy-user", "px:cpw4", "--user", "dave", "-u", "apiuser42:", "https://h.example"] },
    docker: { command: "docker", args: ["run", "-u", "1000:1000", "--user", "app:app", "img", "curl", "-u", "eve:cpw5"] },
    plain: { args: ["-u", "1000:1000", "--user", "${USER}:${PASS}", "-u", "x:${input:pw}"] },
    sh: { command: "sh", args: ["-c", "docker run -u app:grp img && curl -u frank:cpw6 https://h"] },
  });
  const { x, text } = twin("/w/u.json", c);
  // Only the password; with an empty password (`-u KEY:`) the user part is the key.
  assert.deepEqual(x.spans.filter((s) => s.key !== "token").map((s) => s.value), ["cpw1", "cpw2", "cpw3", "cpw4", "apiuser42", "cpw5", "cpw6"]);
  const parsed = JSON.parse(text) as Record<string, { args: string[] }>;
  const tok = (k: string) => `$MDU:nomodel_Read[abcd].${k}`;
  assert.deepEqual(parsed.curl!.args, [
    "-u", `admin:${tok("args.1.password")}`, `--user=bob:${tok("args.2.password")}`, `-ucarol:${tok("args.3.password")}`,
    "--proxy-user", `px:${tok("args.5.password")}`, "--user", "dave", "-u", `${tok("args.9")}:`, "https://h.example",
  ]);
  assert.deepEqual(parsed.docker!.args.slice(0, 7), ["run", "-u", "1000:1000", "--user", "app:app", "img", "curl"], "docker's -u is a user and group");
  assert.deepEqual(parsed.plain!.args, JSON.parse(c).plain.args, "a numeric uid:gid and a reference stay");
  assert.ok(parsed.sh!.args[1]!.startsWith("docker run -u app:grp img && curl -u frank:$MDU:"), parsed.sh!.args[1]);
  scannerSafe(x.spans);
});

test("json, rule (c): a secret flag followed by a flag takes no value from it (that flag is no placeholder, here or elsewhere in the file)", () => {
  const c = JSON.stringify({ token: "t", args: ["--token", "--verbose", "--api-key", "--", "x1", "--password", "--log-level=debug", "--secret", "sv1"], other: ["--verbose"] });
  const { x, text } = twin("/w/v.json", c);
  assert.deepEqual(x.spans.filter((s) => s.key !== "token").map((s) => s.value), ["sv1"]);
  assert.equal(text.split('"--verbose"').length - 1, 2, `--verbose stays as written, here and in the other list:\n${text}`);
  assert.ok(text.includes('"--log-level=debug"') && text.includes('"x1"'), text);
});

test("yaml: a placeholder in a plain item of a flow sequence is single-quoted, so the twin parses (js-yaml) to the same structure", () => {
  const c = `token: abc
args: [-y, --api-key, hunter2, --token=tok12, plain, "dq --token=q1", 'sq']
multi: [
  --password, mpw1,
  --token=mt2 ]
cmd: [sh -c env API_KEY=k1 tool --token k2, it's --token=k3]
`;
  const { x, text } = twin("/w/flow.yaml", c);
  for (const raw of ["hunter2", "tok12", "q1", "mpw1", "mt2", "k1", "k2", "k3"]) assert.ok(!text.includes(raw), `${raw}:\n${text}`);
  const tok = (k: string) => `$MDU:nomodel_Read[abcd].${k}`;
  assert.deepEqual(yaml.load(text), {
    token: tok("token"),
    args: ["-y", "--api-key", tok("args.2"), `--token=${tok("args.3")}`, "plain", `dq --token=${tok("args.5")}`, "sq"],
    multi: ["--password", tok("multi.1"), `--token=${tok("multi.2")}`],
    // Two placeholders in one plain item are one (the words between them hidden too);
    // an item whose own text holds a quote is one placeholder whole.
    cmd: [`sh -c env API_KEY=${tok("cmd.0.API_KEY")}`, tok("cmd.1")],
  });
  assert.ok(text.includes(`args: [-y, --api-key, '${tok("args.2")}', '--token=${tok("args.3")}', plain, "dq --token=${tok("args.5")}", 'sq']`), text);
  // The span keeps the secret as its value: the quotes are the twin's, not the value's.
  assert.deepEqual(x.spans.find((s) => s.key === "args.3")?.value, "tok12");
  // The earlier fixture (block sequences, a nested flow list, quoted items) parses too.
  const block = twin("/home/u/.continue/config.yaml", YAML).text;
  const parsed = yaml.load(block) as { mcpServers: Array<{ args: unknown[] }> };
  assert.deepEqual(parsed.mcpServers[1]!.args, ["-p", "8080", `--token=${tok("mcpServers.args.2")}`, ["nested", "--key", tok("mcpServers.args.3.2")]]);
  assert.equal(parsed.mcpServers[0]!.args[3], tok("mcpServers.args.3"));
});

test("yaml and toml, rules (b) and (d): a credential format, --flag=, NAME= and Header: items, in block and flow lists", () => {
  const y = `password: p
servers:
  a:
    args:
      - ${STRIPE}
      - --token=yd1
      - API_KEY=yd2
      - "Authorization: Bearer yd3"
      - "X-API-Key: yd4"
    flow: [${GITLAB}, --token=yd5, "DB_PASSWORD=yd6", 'Authorization: token yd7']
`;
  const { x: xy, text: ty } = twin("/w/b.yaml", y);
  assert.deepEqual(pairs(xy.spans), [
    ["password", "p"],
    ["servers.a.args.0", STRIPE],
    ["servers.a.args.1", "yd1"],
    ["servers.a.args.2", "yd2"],
    ["servers.a.args.3", "yd3"],
    ["servers.a.args.4", "yd4"],
    ["servers.a.flow.0", GITLAB],
    ["servers.a.flow.1", "yd5"],
    ["servers.a.flow.2", "yd6"],
    ["servers.a.flow.3", "yd7"],
  ]);
  for (const raw of [STRIPE, GITLAB, "yd1", "yd2", "yd3", "yd4", "yd5", "yd6", "yd7"]) assert.ok(!ty.includes(raw), `${raw}:\n${ty}`);
  const tok = (k: string) => `$MDU:nomodel_Read[abcd].${k}`;
  assert.deepEqual(yaml.load(ty), {
    password: tok("password"),
    servers: { a: {
      args: [tok("servers.a.args.0"), `--token=${tok("servers.a.args.1")}`, `API_KEY=${tok("servers.a.args.2")}`, `Authorization: Bearer ${tok("servers.a.args.3")}`, `X-API-Key: ${tok("servers.a.args.4")}`],
      flow: [tok("servers.a.flow.0"), `--token=${tok("servers.a.flow.1")}`, `DB_PASSWORD=${tok("servers.a.flow.2")}`, `Authorization: token ${tok("servers.a.flow.3")}`],
    } },
  });
  scannerSafe(xy.spans);

  const t = `password = "p"
[srv]
args = ["${STRIPE}", "--token=td1", "API_KEY=td2", "Authorization: Bearer td3", 'X-API-Key: td4', "${GITLAB}"]
`;
  const { x: xt, text: tt } = twin("/w/b.toml", t);
  assert.deepEqual(pairs(xt.spans), [
    ["password", "p"],
    ["srv.args.0", STRIPE],
    ["srv.args.1", "td1"],
    ["srv.args.2", "td2"],
    ["srv.args.3", "td3"],
    ["srv.args.4", "td4"],
    ["srv.args.5", GITLAB],
  ]);
  for (const raw of [STRIPE, GITLAB, "td1", "td2", "td3", "td4"]) assert.ok(!tt.includes(raw), `${raw}:\n${tt}`);
  assert.ok(tt.includes(`args = ["${tok("srv.args.0")}", "--token=${tok("srv.args.1")}", "API_KEY=${tok("srv.args.2")}", "Authorization: Bearer ${tok("srv.args.3")}", 'X-API-Key: ${tok("srv.args.4")}', "${tok("srv.args.5")}"]`), tt);
  scannerSafe(xt.spans);
});

test("yaml: a block scalar's text is no YAML: a `key: [` in it opens no list, so the lists after it are read; a `- |` item is no string item", () => {
  const c = `token: abc
script: |
  args: [unclosed
  - --api-key
mcp:
  args:
    - --api-key
    - hunter2
    - |
      --token blk1
    - --password
    - hunter3
`;
  // Before: the `[` in the script opened a list that ran to the end of the file, so hunter2 and hunter3 stayed raw.
  assert.deepEqual(pairs(extractSecretSpans("/w/s.yaml", c).spans), [["token", "abc"], ["mcp.args.1", "hunter2"], ["mcp.args.4", "hunter3"]]);
});

test("yaml and toml: a flow list that never closes hides the file whole (it used to swallow the rest of the file)", () => {
  assert.equal(extractSecretSpans("/w/u.yaml", "token: abc\nargs: [--api-key, x1\nother:\n  - --token\n  - x2\n").shape, null);
  assert.equal(extractSecretSpans("/w/u.toml", `password = "p"\nargs = ["--token", "x"\n`).shape, null);
  assert.deepEqual(twinFormOf("/w/u.yaml", "token: abc\nargs: [--api-key, x1\n", { rule: "label:/w/u.yaml" }), { form: "whole-file", shape: null, fields: 0 });
});

test("json, yaml and toml: lists nested deeper than 64 hide the file whole; 10 deep are read", () => {
  const deep = (n: number) => `${"[".repeat(n)}"--token", "x"${"]".repeat(n)}`;
  assert.equal(extractSecretSpans("/w/d.json", `{"password": "p", "a": ${deep(65)}}`).shape, null);
  assert.deepEqual(pairs(extractSecretSpans("/w/d.json", `{"password": "p", "a": ${deep(10)}}`).spans), [["password", "p"], [`a${".0".repeat(9)}.1`, "x"]]);
  assert.equal(extractSecretSpans("/w/d.yaml", `password: p\nargs: ${deep(65)}\n`).shape, null);
  assert.deepEqual(pairs(extractSecretSpans("/w/d.yaml", `password: p\nargs: ${deep(10)}\n`).spans), [["password", "p"], [`args${".0".repeat(9)}.1`, "x"]]);
  assert.equal(extractSecretSpans("/w/d.toml", `password = "p"\nargs = ${deep(65)}\n`).shape, null);
  assert.equal(extractSecretSpans("/w/d.yaml", `password: p\nargs:\n  ${"- ".repeat(65)}x\n`).shape, null);
});

test("rule (a) finds what the old URL regex found, on random items (now a linear scan by `@`)", () => {
  const OLD = /(?<![A-Za-z0-9+.-])[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:([^\s@]+)@/gi;
  const alphabet = ["a", "B", "1", "+", ".", "-", ":", "/", "@", " ", "x"];
  const chunks = ["://", ":", "@", "a://u:"];
  let seed = 7;
  const rand = (n: number): number => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
  for (let iter = 0; iter < 3000; iter++) {
    let item = "";
    const len = 1 + rand(24);
    for (let k = 0; k < len; k++) item += rand(4) === 0 ? chunks[rand(chunks.length)]! : alphabet[rand(alphabet.length)]!;
    const want: string[] = [];
    OLD.lastIndex = 0;
    for (let m = OLD.exec(item); m !== null; m = OLD.exec(item)) want.push(m[1]!);
    const got = extractSecretSpans("/w/r.json", JSON.stringify({ token: "t", args: [item] })).spans
      .filter((s) => /^args\.0\.password(?:__\d+)?$/.test(s.key)).map((s) => s.value);
    assert.deepEqual(got, want, JSON.stringify(item));
  }
});

test("every walk is linear: adversarial 256 KB inputs an agent could write finish within 5 s each, and one past 1 s grows about 4x from quarter size", () => {
  // Load-tolerant bound. Under the CI guest's parallel stage these ran ~12x
  // slower: pipeline 10158 failed a linear case at 1492 ms against the old
  // 1000 ms bound (126 ms on an idle host). Each regression guarded here took
  // 5 s to minutes at these sizes on an idle host, so 5000 ms still catches
  // it; and a case past 1 s is also run at quarter size, where a linear walk
  // grows ~4x to full size and a quadratic one ~16x, so the bound of 8 leaves
  // 2x of noise either way. Half size (~2x against ~4x, bound 3) failed a
  // linear case at x3.3 under load (pipeline 10247). Each size counts its
  // fastest of three runs, taken alternately so a load spike hits both, in
  // CPU time, which waiting for a CPU does not inflate. A round over the
  // bound is measured again, up to three rounds: a quadratic walk fails
  // every round, while the CI guest once ran the 6 MB "JSON keys" case at
  // x14.4 (604 ms against 42 ms, pipeline 10293), linear at x3.7-4.9 here
  // idle, loaded and on a small heap, so likely its full input falling out
  // of a contended cache for a while.
  // Each builder takes `f` (1 full size, 0.25 quarter) and scales the part a
  // quadratic walk would square.
  const K = 1024;
  const n = (f: number, m: number) => Math.round(f * m);
  const cases: Array<[string, string, (f: number) => string, (x: ReturnType<typeof extractSecretSpans>) => void]> = [
    // The URL regex tried each `x://u:` start and scanned the rest of the item for an `@`: 9.7 s at 256 KB.
    ["URL starts with no @", "/w/a.json", (f) => JSON.stringify({ password: "p", args: ["a://b:c,".repeat(n(f, 32 * K))] }), (x) => assert.equal(x.spans.length, 1)],
    ["URL starts, then one @", "/w/a.json", (f) => JSON.stringify({ password: "p", args: [`${"a://b:".repeat(n(f, 43 * K))}x@h`] }), (x) => assert.equal(x.spans.length, 2)],
    // The keyed JSON scan started at each escaped quote of a long string: 0.7 s at 64 KB.
    ["a JSON string of escaped quotes", "/w/b.json", (f) => JSON.stringify({ password: "p", args: [' -a "x'.repeat(n(f, 37 * K))] }), (x) => assert.equal(x.spans[0]?.key, "password")],
    // The YAML key regex's blank run before the `:`: 0.4 s at 16 KB.
    ["a YAML line of blanks", "/w/c.yaml", (f) => `password: p\nx${" ".repeat(n(f, 256 * K))}y\n`, (x) => assert.equal(x.spans.length, 1)],
    // One walk down the stack per closer: 5 s for 50 000 each.
    ["JSON { then ] with no list open", "/w/d.json", (f) => `{"password":"p","a":${"{".repeat(60)}${"]".repeat(n(f, 256 * K))}}`, (x) => assert.equal(x.shape, "json-keys")],
    ["JSON { x 128 K then ] x 128 K", "/w/d.json", (f) => `{"password":"p","a":${"{".repeat(n(f, 128 * K))}${"]".repeat(n(f, 128 * K))}}`, (x) => assert.equal(x.shape, null)],
    // Recursion: `[` x 100 000 overflowed the stack.
    ["YAML [ x 256 K", "/w/e.yaml", (f) => `password: p\nargs: ${"[".repeat(n(f, 256 * K))}\n`, (x) => assert.equal(x.shape, null)],
    ["TOML [ x 256 K", "/w/f.toml", (f) => `password = "p"\nargs = ${"[".repeat(n(f, 256 * K))}\n`, (x) => assert.equal(x.shape, null)],
    ["YAML - x 128 K", "/w/g.yaml", (f) => `password: p\n${"- ".repeat(n(f, 128 * K))}--token=x\n`, (x) => assert.equal(x.shape, null)],
    // Field names past 16 383 characters hash alike in V8: the dedupe map went
    // quadratic (137 s for this 156 KB file). Past MAX_FIELD_NAME the file is whole.
    ["YAML lines under a 20 000-character key", "/w/h.yaml", (f) => `${"k".repeat(20000)}:\n${"  password: x\n".repeat(n(f, 10000))}`, (x) => assert.deepEqual(x.spans, [])],
    ["JSON keys of 20 000 characters", "/w/i.json", (f) => `{${Array.from({ length: n(f, 300) }, () => `"${"a".repeat(20000)}_password": "x"`).join(",")}}`, (x) => assert.equal(x.shape, null)],
  ];
  const time = (path: string, content: string) => {
    const t0 = performance.now();
    const x = extractSecretSpans(path, content);
    return { x, ms: performance.now() - t0 };
  };
  const cpuMs = (path: string, content: string) => {
    const c0 = process.cpuUsage();
    const x = extractSecretSpans(path, content);
    const c = process.cpuUsage(c0);
    return { x, ms: (c.user + c.system) / 1000 };
  };
  for (const [what, path, build, check] of cases) {
    const full = build(1);
    const { x, ms } = time(path, full);
    check(x);
    assert.ok(ms < 5000, `${what}: ${Math.round(ms)} ms`);
    if (ms > 1000) {
      const quarter = build(0.25);
      const rounds: string[] = [];
      for (let round = 0; round < 3; round++) {
        let best = Infinity;
        let bestQuarter = Infinity;
        for (let i = 0; i < 3; i++) {
          const q = cpuMs(path, quarter);
          check(q.x);
          bestQuarter = Math.min(bestQuarter, q.ms);
          best = Math.min(best, cpuMs(path, full).ms);
        }
        if (best / bestQuarter < 8) break;
        rounds.push(`${Math.round(best)} ms at full size, ${Math.round(bestQuarter)} ms at quarter (x${(best / bestQuarter).toFixed(1)})`);
      }
      assert.ok(rounds.length < 3, `${what}, CPU time in each round: ${rounds.join("; ")}; linear is ~4`);
    }
  }
});

// ── 2026-10-10, second review: a merged placeholder keeps each secret ─────────

/** The part of `x`'s spans whose value is `value`, and the span holding it. */
const partOf = (spans: readonly SecretSpan[], value: string) => {
  for (const s of spans) for (const p of s.parts ?? []) if (p.value === value) return { span: s, part: p };
  return null;
};

test("yaml: a flow item that becomes one placeholder (two secrets, or the whole item) keeps each secret as a part: a copy of it elsewhere in the file is masked, and the twin parses (js-yaml)", () => {
  const A = "Sup3rSecretA99";
  const B = "Sup3rSecretB99";
  const C = "Sup3rSecretC99";
  // The reviewer's repro, a copy of each secret under an ordinary key and in
  // a comment, and an item whose text holds a backslash (one placeholder whole).
  const c = `token: abcdefgh1234
note: ${B}
other: ${A} # and ${C} again
args: [sh, -c, env API_KEY=${A} tool --token ${B}]
odd: [a\\b --token ${C}, plain]
`;
  const { x, text } = twin("/w/merged.yaml", c);
  for (const raw of [A, B, C]) assert.ok(!text.includes(raw), `CONFIDENTIALITY VIOLATION: ${raw} stays raw in the twin:\n${text}`);
  scannerSafe(x.spans);
  // The merged span: its value is the covered text, its parts the secrets.
  const merged = x.spans.find((s) => s.key === "args.2")!;
  assert.equal(merged.value, `${A} tool --token ${B}`);
  assert.deepEqual(merged.parts!.map((p) => p.value).sort(), [A, B]);
  // The whole-item span: the item's text, and its secret.
  const whole = x.spans.find((s) => s.key === "odd.0")!;
  assert.equal(whole.value, `a\\b --token ${C}`);
  assert.deepEqual(whole.parts!.map((p) => p.value), [C]);
  // Part names are unique among every span and part, and keep the earlier names.
  const names = [...x.spans.map((s) => s.key), ...x.spans.flatMap((s) => (s.parts ?? []).map((p) => p.key))];
  assert.equal(new Set(names).size, names.length, names.join(" "));
  assert.equal(partOf(x.spans, B)!.part.key, "args.2__2", "the name the reviewed commit gave B's placeholder");
  for (const p of [...merged.parts!, ...whole.parts!]) scannerSafe([p]);
  const tok = (k: string) => `$MDU:nomodel_Read[abcd].${k}`;
  assert.deepEqual(yaml.load(text), {
    token: tok("token"),
    note: tok(partOf(x.spans, B)!.part.key),
    other: tok(partOf(x.spans, A)!.part.key),
    args: ["sh", "-c", `env API_KEY=${tok("args.2")}`],
    odd: [tok("odd.0"), "plain"],
  });
  assert.ok(text.includes(`# and ${tok(partOf(x.spans, C)!.part.key)} again`), text);
  // A block-sequence form of the same file masked it all along (no merge).
  const block = twin("/w/block.yaml", `token: abcdefgh1234\nnote: ${B}\nargs:\n  - sh\n  - -c\n  - env API_KEY=${A} tool --token ${B}\n`).text;
  for (const raw of [A, B]) assert.ok(!block.includes(raw), block);
});

test("json and yaml: an overlap union (finishMerged) keeps each secret it covers as a part: `--api-key key=https://u:PW@h` masks a copy of PW elsewhere", () => {
  const PW = "PW1234567xyz";
  // The flag's value is masked whole (it is no URL) and holds a URL's password:
  // two rules claim one place. (`--token=https://u:PW@h` was the example until the
  // third review; the command-line reader now reads that value as a URL, its password only.)
  const json = JSON.stringify({ token: "t0k3nvalue", note: PW, args: ["--api-key", `key=https://u:${PW}@h.example`] }, null, 2);
  const j = twin("/w/u.json", json);
  assert.ok(!j.text.includes(PW), `CONFIDENTIALITY VIOLATION: the URL password stays raw under "note":\n${j.text}`);
  const hit = partOf(j.x.spans, PW)!;
  assert.ok(hit, "the URL's password is a part of the union");
  assert.equal(hit.span.value, `key=https://u:${PW}@h.example`, "the union masks the whole value in place");
  const parsed = JSON.parse(j.text) as { note: string; args: string[] };
  assert.equal(parsed.note, `$MDU:nomodel_Read[abcd].${hit.part.key}`);
  const url = twin("/w/v.json", JSON.stringify({ token: "t0k3nvalue", args: [`--token=https://u:${PW}@h.example`] })).text;
  assert.equal((JSON.parse(url) as { args: string[] }).args[0], "--token=https://u:$MDU:nomodel_Read[abcd].args.0.password@h.example", "a URL value keeps all but its password");
  const y = twin("/w/u.yaml", `token: t0k3nvalue\nnote: ${PW}\nargs: [--api-key, key=https://u:${PW}@h.example]\n`);
  assert.ok(!y.text.includes(PW), y.text);
  assert.equal((yaml.load(y.text) as { note: string }).note, `$MDU:nomodel_Read[abcd].${partOf(y.x.spans, PW)!.part.key}`);
  // A part that is the span's own secret is left out: one secret, one name.
  const single = extractSecretSpans("/w/s.json", JSON.stringify({ token: "t", args: ["--token", "lonesecret1"] })).spans;
  assert.ok(single.every((s) => s.parts === undefined), JSON.stringify(single));
});

test("json keys: the regex and the string walk together find everything the old regex found, on generated valid documents; the escaped-quote fix stays", () => {
  // The regex before 2026-10-10: it could start at any quote, and on valid
  // JSON lost track of the strings after an escaped quote or a `"C:\\"`.
  const OLD = /"((?:[^"\\]|\\.)*)"\s*:\s*"((?:[^"\\]|\\.)*)"/g;
  /** The spans the old regex's pairs gave, judged by the production rule on
   *  a one-pair document and placed back on `doc`. */
  const oldSpans = (doc: string) => {
    const out: Array<{ start: number; end: number; value: string }> = [];
    OLD.lastIndex = 0;
    for (let m = OLD.exec(doc); m !== null; m = OLD.exec(doc)) {
      const [key, value] = [m[1]!, m[2]!];
      if (value === "") continue;
      const vAt = m.index + m[0].length - value.length - 1;
      const base = 2 + key.length + 4; // `{"` key `": "`
      for (const s of extractSecretSpans("/w/one.json", `{"${key}": "${value}"}`).spans) out.push({ start: s.start - base + vAt, end: s.end - base + vAt, value: s.value });
    }
    return out;
  };
  /** Masked in place, and still a secret value of its own (a span's or a part's). */
  const covered = (got: readonly SecretSpan[], o: { start: number; end: number; value: string }) =>
    got.some((n) => n.start <= o.start && o.end <= n.end && (n.value === o.value || (n.parts ?? []).some((p) => p.value === o.value)));
  // Pinned: the old regex found `token` here only after losing track; the
  // lookbehind alone lost it (the review's 1 in 300 000), the string walk finds it.
  const lost = '{"b": [":", {"x\\"token": "v4lue"}]}';
  assert.deepEqual(oldSpans(lost).map((o) => o.value), ["v4lue"]);
  assert.ok(covered(extractSecretSpans("/w/p.json", lost).spans, oldSpans(lost)[0]!), "the pair the old regex found");
  // And one master missed: the string walk does not lose track at all.
  assert.deepEqual(pairs(extractSecretSpans("/w/p.json", '["C:\\\\", ":", {"password": "x9"}]').spans), [["password", "x9"]]);
  const KEYS = ["password", "api_key", "token", "name", "url", "C:\\", ":", 'x"token', "a\\", '\\"', "note", "db", "key", ": "];
  const STRS = ["hunter2", "C:\\", ":", '"', "\\", 'x\\"y', "https://u:pw1@h.example", "postgres://app:tiger@db:5432/x", " : ", '", "', "{", "[", "--token", 'a"b"c', "", "\\\\", '\\":'];
  let seed = 12345;
  const rand = (n: number): number => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
  const ws = (): string => ["", "", " ", "\n  ", "\t"][rand(5)]!;
  const value = (d: number): string => {
    const r = rand(d > 3 ? 3 : 6);
    if (r <= 1) return JSON.stringify(STRS[rand(STRS.length)]!);
    if (r === 2) return ["1", "-2.5e3", "true", "false", "null"][rand(5)]!;
    const n = rand(5);
    if (r === 3) return `[${ws()}${Array.from({ length: n }, () => value(d + 1)).join(`${ws()},${ws()}`)}${ws()}]`;
    return `{${ws()}${Array.from({ length: n }, () => `${JSON.stringify(KEYS[rand(KEYS.length)]!)}${ws()}:${ws()}${value(d + 1)}`).join(`${ws()},${ws()}`)}${ws()}}`;
  };
  let found = 0;
  for (let i = 0; i < 20000; i++) {
    const doc = value(0);
    JSON.parse(doc); // valid JSON only
    const olds = oldSpans(doc);
    found += olds.length;
    if (olds.length === 0) continue;
    const got = extractSecretSpans("/w/p.json", doc).spans;
    for (const o of olds) assert.ok(covered(got, o), `lost ${JSON.stringify(o)} of ${JSON.stringify(doc)}`);
  }
  assert.ok(found > 3000, `the documents hold secret pairs (${found})`);
});

test("json, yaml: a switch ending in `auth` and a pattern ending in `pat` take no value, as an item or in a command line; --auth and --pat still do", () => {
  const { x } = twin("/w/f.json", JSON.stringify({
    token: "t",
    args: ["--skip-auth", "server.js", "--exclude-pat", "*.log", "--include-pat=src/**", "--auth", "authval1", "--gitlab-pat", "patval2", "run --disable-auth app.py --pat patval3"],
  }));
  assert.deepEqual(pairs(x.spans).filter(([k]) => k !== "token").map(([, v]) => v), ["authval1", "patval2", "patval3"]);
  const y = twin("/w/f.yaml", "token: t\nargs: [--skip-auth, server.js, --include-pat, '*.ts', --pat, patval4]\n");
  assert.deepEqual(pairs(y.x.spans).filter(([k]) => k !== "token").map(([, v]) => v), ["patval4"]);
});
