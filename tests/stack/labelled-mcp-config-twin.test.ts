/**
 * labelled-mcp-config-twin — a labelled `.mcp.json` over the REAL
 * components (2026-10-09): its twin, Claude Code's `Read` of that twin
 * through the PRODUCTION proxy wiring (`new ArbiterClientAdapter(new
 * ArbiterClient(sock))`), and `mandu why` on it through the launcher's own
 * call path, all against a real ArbiterServer in `secrets`.
 *
 * Before: the structured twin masked only `"key": "string"` pairs whose key
 * looks secret. A labelled MCP config with an `env` block kept every `args`
 * value raw: `"--api-key", "<value>"`, `"--token=<value>"` and a database
 * URL's password reached every program that read the twin, and, being short
 * and word-like (no fingerprint holds them, and their lines are the twin's
 * own), Claude Code's Read of the twin carried them to the model. `mandu
 * why` said "each value is a placeholder" of that file, and called a
 * labelled `.json` it hid whole a copy that keeps its structure.
 * Now each such list item is a placeholder of its own (`args.3`), the Read
 * is per key with no raw value, and `mandu why` says what the registration
 * made: how many values it masks, or that it hides the file whole.
 * 2026-10-10 (review): a labelled YAML config's `--auth`, `--pat` and
 * `-u user:password` values are placeholders too, a placeholder in a plain
 * flow item is quoted, and a block scalar's text is no YAML; `mandu why`
 * on a labelled path that is a FIFO answers at once (the arbiter used to
 * block on it for good), with the words of an answer that has no twin.
 * Second review: a flow item that is one placeholder keeps each secret in
 * it, so a copy of one under another key is masked too (step 7).
 * Third review: a command line inside one item is read word by word, so a
 * valueless switch before a secret flag (`curl -s -u admin:pw`, `tool
 * --verbose --auth S`) no longer swallows it, and `-H "Authorization:
 * Bearer …"`, `docker login -p` and `PGPASSWORD=` inside it are masked
 * (step 8; before, those values reached the model with Claude Code's Read).
 * Fourth review: a word that only names psql, mysql, docker or podman (a
 * path, an image, a flag's value) no longer makes `--password VALUE` a
 * prompt or `-u user:password` a user and group; only the command itself
 * does, and a `$`-led value nothing expands is a value (step 9; before,
 * those passwords reached the model). The exceptions still hold for `psql
 * --password <db>` and `docker run -u <user>:<group>` as the command.
 * Unit twins: arbiter `secret-extract-lists.test.ts`,
 * `secret-extract-command-lines.test.ts` (the table of real command lines),
 * launcher `why.test.ts`; component: arbiter `why.test.ts`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { loadPolicyFileStrict } from "../../arbiter/policy/policy-file-validate.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { runWhy, realWhyDeps } from "../../launcher/src/why.js";
import type { Layout } from "../../launcher/src/services/layout.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

// Short, word-like values: no credential format, no fingerprint piece.
const API_KEY = "hunter42x";
const TOKEN = "swordfishq";
const PG_PW = "tigerlily";
const ENV_KEY = "BSAenvKEYmcpE2E0123456789";
const RAWS = [API_KEY, TOKEN, PG_PW, ENV_KEY];

const MCP = `${JSON.stringify({
  mcpServers: {
    brave: { command: "npx", args: ["-y", "@brave/brave-search-mcp-server", "--api-key", API_KEY, `--token=${TOKEN}`], env: { BRAVE_API_KEY: ENV_KEY } },
    postgres: { command: "npx", args: ["-y", "@modelcontextprotocol/server-postgres", `postgresql://app:${PG_PW}@db/prod`] },
  },
}, null, 2)}\n`;
/** A labelled YAML config (Continue-style): `-u user:password` for curl,
 *  `--auth`, `--pat`, plain flow items, and a block scalar whose text holds
 *  an unclosed `[` (it used to swallow the rest of the file). */
const Y_PW = "yamlpw1x";
const Y_AUTH = "yamlauth2x";
const Y_PAT = "yamlpat3x";
const Y_ENV = "yamlenvTOKEN0123456789";
const Y_RAWS = [Y_PW, Y_AUTH, Y_PAT, Y_ENV];
const YAML_CONFIG = `mcpServers:
  - name: fetch
    command: curl
    args: [-s, -u, "deploy:${Y_PW}", --auth, ${Y_AUTH}, https://api.example/x]
    env:
      API_TOKEN: ${Y_ENV}
  - name: run
    command: sh
    script: |
      args: [this is text, not YAML
    args:
      - --pat
      - ${Y_PAT}
`;
/** 2026-10-10 (second review): a plain flow item that becomes ONE
 *  placeholder (two secrets in it, or a backslash beside the secret), and
 *  a copy of each secret under an ordinary key. The merged placeholder's
 *  value used to be the covered text, so the copies stayed raw in the twin
 *  and reached the model with Claude Code's Read. */
const M_A = "mergedA0secret9";
const M_B = "mergedB0secret9";
const M_C = "mergedC0secret9";
const M_RAWS = [M_A, M_B, M_C];
const MERGED_YAML = `token: abcdefgh1234
note: ${M_B}
other: ${M_C}
args: [sh, -c, env API_KEY=${M_A} tool --token ${M_B}]
odd: [a\\b --token ${M_C}]
`;
/** 2026-10-10 (third review): command lines in one item each, with
 *  valueless switches before, between and after the secret flags. The
 *  values are short and word-like: only the command-line reader finds them. */
const C_PW = "cmdcurlpw1x";
const C_AUTH = "cmdauthval2x";
const C_BEARER = "cmdbearer3x";
const C_DOCKER = "cmddockpw4x";
const C_PG = "cmdpgpw5x";
const C_PAT = "cmdpatval6x";
const C_ENV = "cmdenvTOKEN0123456789";
const C_RAWS = [C_PW, C_AUTH, C_BEARER, C_DOCKER, C_PG, C_PAT, C_ENV];
const COMMAND_LINES = `${JSON.stringify({
  mcpServers: {
    fetch: { command: "sh", args: ["-c", `curl -s -u admin:${C_PW} -H "Authorization: Bearer ${C_BEARER}" --fail https://api.example.com/v1/x`] },
    tool: { command: "bash", args: ["-lc", `tool --verbose --auth ${C_AUTH} --dry-run && tool -q --pat ${C_PAT} -v`] },
    deploy: { command: "sh", args: ["-c", `docker login -u deploy -p ${C_DOCKER} registry.example.com; PGPASSWORD=${C_PG} psql -h db.internal -U app prod`] },
  },
  env: { API_TOKEN: C_ENV },
}, null, 2)}\n`;
/** 2026-10-10 (fourth review): a word that only names a program before a
 *  secret flag (a path, an image, another flag's value), in JSON and in a
 *  YAML config with plain items; and the commands whose exceptions hold. */
const N_IMAGE = "progimgpw1x";
const N_DATADIR = "progdirpw2x";
const N_DBTYPE = "progdbtpw3x";
const N_RUNTIME = "progrunpw4x";
const N_SCRIPT = "progshpw5x";
const N_LITERAL = "$ecretPass99";
const N_ENV = "progenvTOKEN0123456789";
const N_RAWS = [N_IMAGE, N_DATADIR, N_DBTYPE, N_RUNTIME, N_SCRIPT, N_LITERAL, N_ENV];
const PROGRAM_WORDS = `${JSON.stringify({
  mcpServers: {
    mysql: { command: "docker", args: ["run", "-i", "--rm", "mcp/mysql", "--password", N_IMAGE] },
    backup: { command: "backup-tool", args: ["--datadir", "/var/lib/mysql", "--user", "root", "--password", N_DATADIR] },
    db: { command: "db-mcp", args: ["--db-type", "mysql", "--host", "db", "--password", N_DBTYPE] },
    runner: { command: "runner", args: ["--runtime", "docker", "--user", `admin:${N_RUNTIME}`] },
    nightly: { command: "sh", args: ["-c", `backup-tool --datadir /var/lib/mysql --password ${N_SCRIPT}`] },
    literal: { command: "tool", args: ["--password", N_LITERAL] },
    pg: { command: "psql", args: ["-h", "db.internal", "--password", "proddb"] },
    web: { command: "docker", args: ["run", "-u", "app:staff", "nginx"] },
  },
  env: { API_TOKEN: N_ENV },
}, null, 2)}\n`;
const Y_IMAGE = "yprogimgpw6x";
const Y_DATADIR = "yprogdirpw7x";
const Y_PROG_RAWS = [Y_IMAGE, Y_DATADIR, "yprogTOKEN0123456789"];
const PROGRAM_WORDS_YAML = `token: yprogTOKEN0123456789
servers:
  - command: docker
    args:
      - run
      - --rm
      - mcp/mysql
      - --password
      - ${Y_IMAGE}
  - command: backup-tool
    args: [--datadir, /var/lib/mysql, --password, ${Y_DATADIR}]
  - command: psql
    args: [-h, db.internal, --password, proddb]
`;
/** The official Postgres server's config alone: its only secret is in a list. */
const PG_ONLY = `${JSON.stringify({ mcpServers: { postgres: { command: "npx", args: ["-y", "@modelcontextprotocol/server-postgres", "postgresql://app:pgonlypw@db/prod"] } } }, null, 2)}\n`;
const SYMBOL_RE = /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/g;

function post(port: number, body: string, session: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/** Claude Code's Read output: numbered lines. */
const claudeRead = (text: string) => text.replace(/\n$/, "").split("\n").map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n");

function claudeReadTurn(path: string, content: string, id: string): string {
  return JSON.stringify({
    model: "claude-sonnet-5",
    stream: true,
    messages: [
      { role: "user", content: "which MCP servers are configured?" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "Read", input: { file_path: path } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  });
}

test("a labelled .mcp.json: its args' secrets are placeholders in the twin, Claude Code's Read of the twin holds no raw value, and mandu why says what was made (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-mcp-twin-"));
  const home = join(dir, "home");
  const proj = join(home, "proj");
  mkdirSync(join(proj, "pg"), { recursive: true });
  const mcp = join(proj, ".mcp.json");
  const pgOnly = join(proj, "pg", ".mcp.json");
  const yamlConfig = join(proj, ".continue", "config.yaml");
  const fifo = join(proj, "fifo", "servers.json");
  const merged = join(proj, ".continue", "merged.yaml");
  const commandLines = join(proj, "cmd", ".mcp.json");
  const programWords = join(proj, "prog", ".mcp.json");
  const programWordsYaml = join(proj, "prog", "servers.yaml");
  mkdirSync(join(proj, ".continue"), { recursive: true });
  mkdirSync(join(proj, "fifo"), { recursive: true });
  mkdirSync(join(proj, "cmd"), { recursive: true });
  mkdirSync(join(proj, "prog"), { recursive: true });
  writeFileSync(commandLines, COMMAND_LINES);
  writeFileSync(programWords, PROGRAM_WORDS);
  writeFileSync(programWordsYaml, PROGRAM_WORDS_YAML);
  writeFileSync(mcp, MCP);
  writeFileSync(pgOnly, PG_ONLY);
  writeFileSync(yamlConfig, YAML_CONFIG);
  writeFileSync(merged, MERGED_YAML);
  execFileSync("mkfifo", [fifo]);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n${[mcp, pgOnly, yamlConfig, fifo, merged, commandLines, programWords, programWordsYaml].map((p) => `  - path: ${p}\n    level: no-model\n`).join("")}`);
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0, policyDocument: loadPolicyFileStrict(policy).config,
  });
  await server.listen();
  const real = new ArbiterClient(sock);
  await real.connect();
  const sessionKey = `mcp-twin-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  let watchdog: ChildProcess | undefined;
  try {
    // 1. The launcher registers the labelled file: the twin it materializes.
    const reg = await real.registerSecret({ path: mcp, sessionKey });
    assert.ok(reg.symbol, reg.reason);
    const twin = reg.twin as string;
    assert.equal(typeof twin, "string", `a structured twin: ${reg.reason}`);
    for (const raw of RAWS) assert.ok(!twin.includes(raw), `CONFIDENTIALITY VIOLATION: ${raw} is in the twin programs read:\n${twin}`);
    assert.equal(reg.fields, 4, reg.reason);
    const parsed = JSON.parse(twin) as { mcpServers: Record<string, { command: string; args: string[] }> };
    const brave = parsed.mcpServers.brave!.args;
    assert.deepEqual(brave.slice(0, 3), ["-y", "@brave/brave-search-mcp-server", "--api-key"], "the rest stays as written");
    assert.match(brave[3]!, /^\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.args\.3$/);
    assert.match(brave[4]!, /^--token=\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.args\.4$/);
    assert.match(parsed.mcpServers.postgres!.args[2]!, /^postgresql:\/\/app:\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.args\.2\.password@db\/prod$/);

    // 2. Claude Code's Read of the twin, through the real proxy and arbiter.
    assert.equal((await real.setSessionSpec({ sessionKey, spec: "claude-code", requestedBy: "labelled-mcp-config-twin e2e" })).bound, "claude-code");
    const forwarded = async (content: string, id: string, path = mcp): Promise<string> => {
      const up = new MockUpstream({ sse: buildTextSse("ok") });
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey, log: () => {} });
      proxies.push(proxy);
      const r = await post(await proxy.listen(0), claudeReadTurn(path, content, id), sessionKey);
      assert.equal(r.status, 200, r.body);
      const sent = up.requests[up.requests.length - 1]!.json() as { messages: Array<{ content: unknown }> };
      const block = (sent.messages[2]!.content as Array<{ content: unknown }>)[0]!.content;
      return typeof block === "string" ? block : JSON.stringify(block);
    };
    const got = await forwarded(claudeRead(twin), "tu_mcp_1");
    for (const raw of RAWS) assert.ok(!got.includes(raw), `CONFIDENTIALITY VIOLATION: ${raw} reached the model:\n${got}`);
    assert.match(got, /"command": "npx"/, `per key, not masked whole: ${got}`);
    assert.match(got, /"--token=\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.args\.4"/, got);
    assert.equal((got.match(SYMBOL_RE) ?? []).length, 4, "one placeholder per secret value");
    // The raw file still reaches the model masked whole.
    const raw = await forwarded(claudeRead(MCP), "tu_mcp_raw");
    for (const v of RAWS) assert.ok(!raw.includes(v), raw);
    assert.doesNotMatch(raw, /"command": "npx"/, `masked whole: ${raw}`);

    // 3. A labelled file whose only secret sits in a list is still hidden whole.
    const pgReg = await real.registerSecret({ path: pgOnly, sessionKey });
    assert.ok(pgReg.symbol, pgReg.reason);
    assert.equal(pgReg.twin, undefined, `a whole-file twin: ${pgReg.reason}`);

    // 4. `mandu why` over the launcher's own call path says what was made.
    const deps = { ...realWhyDeps(), arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }), cwd: () => proj };
    const why = async (arg: string): Promise<string> => {
      const chunks: string[] = [];
      const code = await runWhy([arg], { HOME: home }, {} as Layout, { ...deps, out: (s: string) => { chunks.push(s); } });
      const out = chunks.join("");
      assert.equal(code, 0, out);
      for (const v of [...RAWS, "pgonlypw"]) assert.ok(!out.includes(v), `never a value: ${out}`);
      assert.doesNotMatch(out, /each value is a placeholder/, out);
      return out;
    };
    assert.match(await why(".mcp.json"), /the AI +sees a placeholder copy that keeps the file's structure \(json-keys\); each secret value Mandu recognizes is a placeholder \(4 in the file now\)/);
    // Its URL password IS recognized (a list item), but list items only add to
    // a file whose keys gave a secret: hidden whole, and the words say so truly.
    const pgWhy = await why("pg/.mcp.json");
    assert.match(pgWhy, /the AI +sees a whole-file placeholder \(one placeholder for the whole file\): Mandu finds no secret value it can hide in place in this json-keys file/);
    assert.doesNotMatch(pgWhy, /recognizes no secret value/, "its URL password is recognized; the file is hidden whole for another reason");

    // 5. A labelled YAML config: `-u user:password`, `--auth`, `--pat` values
    //    are placeholders; a placeholder in a plain flow item is quoted; the
    //    block scalar's `[` opens no list (else the file would be hidden whole).
    const yReg = await real.registerSecret({ path: yamlConfig, sessionKey });
    assert.ok(yReg.symbol, yReg.reason);
    const yTwin = yReg.twin as string;
    assert.equal(typeof yTwin, "string", `a structured twin: ${yReg.reason}`);
    for (const raw of Y_RAWS) assert.ok(!yTwin.includes(raw), `CONFIDENTIALITY VIOLATION: ${raw} is in the twin programs read:\n${yTwin}`);
    assert.equal(yReg.fields, 4, yReg.reason);
    assert.match(yTwin, /args: \[-s, -u, "deploy:\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.mcpServers\.args\.2\.password", --auth, '\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.mcpServers\.args\.4', https:\/\/api\.example\/x\]/, yTwin);
    assert.ok(yTwin.includes("      args: [this is text, not YAML\n"), "the block scalar's text is as written");
    const yGot = await forwarded(claudeRead(yTwin), "tu_yaml_1", yamlConfig);
    for (const raw of Y_RAWS) assert.ok(!yGot.includes(raw), `CONFIDENTIALITY VIOLATION: ${raw} reached the model:\n${yGot}`);
    assert.match(yGot, /command: curl/, `per key, not masked whole: ${yGot}`);

    // 6. `mandu why` on a labelled path that is a FIFO: the answer comes at
    //    once, with no twin (the hedged words), and the arbiter keeps
    //    answering. A writer frees a blocked arbiter after 3 s (it runs in
    //    this process), so a regression fails on the time, not by hanging.
    watchdog = spawn("sh", ["-c", 'sleep 3; (echo x > "$1") & wait', "_", fifo], { stdio: "ignore", detached: true });
    const t0 = Date.now();
    const fifoWhy = await why("fifo/servers.json");
    assert.ok(Date.now() - t0 < 2000, `mandu why took ${Date.now() - t0} ms: the arbiter blocked on a FIFO`);
    assert.match(fifoWhy, /the AI +sees a placeholder copy that keeps the file's structure \(json-keys\) when Mandu recognizes a secret value in it/, fifoWhy);
    assert.match(await why(".mcp.json"), /\(4 in the file now\)/, "still answering");

    // 7. A flow item that is one placeholder keeps each secret in it: a copy
    //    of it under another key is that secret's own placeholder, in the
    //    twin programs read and in Claude Code's Read of it.
    const mReg = await real.registerSecret({ path: merged, sessionKey });
    assert.ok(mReg.symbol, mReg.reason);
    const mTwin = mReg.twin as string;
    assert.equal(typeof mTwin, "string", `a structured twin: ${mReg.reason}`);
    for (const raw of M_RAWS) assert.ok(!mTwin.includes(raw), `CONFIDENTIALITY VIOLATION: ${raw} is in the twin programs read:\n${mTwin}`);
    assert.match(mTwin, /^note: \$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.args\.2__2$/m, mTwin);
    assert.match(mTwin, /^args: \[sh, -c, 'env API_KEY=\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.args\.2'\]$/m, mTwin);
    assert.match(mTwin, /^odd: \['\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.odd\.0'\]$/m, mTwin);
    const mGot = await forwarded(claudeRead(mTwin), "tu_merged_1", merged);
    for (const raw of M_RAWS) assert.ok(!mGot.includes(raw), `CONFIDENTIALITY VIOLATION: ${raw} reached the model:\n${mGot}`);
    assert.match(mGot, /note: \$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.args\.2__2/, `per key, not masked whole: ${mGot}`);

    // 8. Command lines in one item: every word is read, so a switch before a
    //    secret flag hides nothing, and a header, `docker login -p` and
    //    `PGPASSWORD=` inside the line are placeholders; the rest is as written.
    const cReg = await real.registerSecret({ path: commandLines, sessionKey });
    assert.ok(cReg.symbol, cReg.reason);
    const cTwin = cReg.twin as string;
    assert.equal(typeof cTwin, "string", `a structured twin: ${cReg.reason}`);
    for (const raw of C_RAWS) assert.ok(!cTwin.includes(raw), `CONFIDENTIALITY VIOLATION: ${raw} is in the twin programs read:\n${cTwin}`);
    assert.equal(cReg.fields, C_RAWS.length, cReg.reason);
    const cArgs = (JSON.parse(cTwin) as { mcpServers: Record<string, { args: string[] }> }).mcpServers;
    const P = "\\$MDU:nomodel_Read\\[[0-9a-f]{4,8}\\]";
    assert.match(cArgs.fetch!.args[1]!, new RegExp(`^curl -s -u admin:${P}\\.args\\.1\\.password -H "Authorization: Bearer ${P}\\.args\\.1(?:__\\d+)?" --fail https://api\\.example\\.com/v1/x$`));
    assert.match(cArgs.tool!.args[1]!, new RegExp(`^tool --verbose --auth ${P}\\S+ --dry-run && tool -q --pat ${P}\\S+ -v$`));
    assert.match(cArgs.deploy!.args[1]!, new RegExp(`^docker login -u deploy -p ${P}\\S+ registry\\.example\\.com; PGPASSWORD=${P}\\S+ psql -h db\\.internal -U app prod$`));
    const cGot = await forwarded(claudeRead(cTwin), "tu_cmd_1", commandLines);
    for (const raw of C_RAWS) assert.ok(!cGot.includes(raw), `CONFIDENTIALITY VIOLATION: ${raw} reached the model:\n${cGot}`);
    assert.match(cGot, /curl -s -u admin:\$MDU:/, `per value, not masked whole: ${cGot}`);
    assert.match(cGot, /psql -h db\.internal -U app prod/, `the rest of the line as written: ${cGot}`);
    assert.match(await why("cmd/.mcp.json"), new RegExp(`\\(${C_RAWS.length} in the file now\\)`));

    // 9. A word that only names psql, mysql, docker or podman (an image, a
    //    path, a flag's value) leaves `--password` and `-u` their values:
    //    placeholders in the twin and in Claude Code's Read of it. Where the
    //    program is the command, psql's database and docker's user and group
    //    stay as written. A `$`-led value no shell expands is a value too.
    const nTwins: string[] = [];
    for (const [path, raws, fields] of [[programWords, N_RAWS, N_RAWS.length], [programWordsYaml, Y_PROG_RAWS, Y_PROG_RAWS.length]] as const) {
      const nReg = await real.registerSecret({ path, sessionKey });
      assert.ok(nReg.symbol, nReg.reason);
      const nTwin = nReg.twin as string;
      assert.equal(typeof nTwin, "string", `a structured twin: ${nReg.reason}`);
      nTwins.push(nTwin);
      for (const raw of raws) assert.ok(!nTwin.includes(raw), `CONFIDENTIALITY VIOLATION: ${raw} is in the twin programs read:\n${nTwin}`);
      assert.equal(nReg.fields, fields, nReg.reason);
      assert.ok(nTwin.includes("proddb"), `psql's --password takes no value when psql is the command: ${nTwin}`);
      const nGot = await forwarded(claudeRead(nTwin), `tu_prog_${fields}`, path);
      for (const raw of raws) assert.ok(!nGot.includes(raw), `CONFIDENTIALITY VIOLATION: ${raw} reached the model:\n${nGot}`);
      assert.match(nGot, /mcp\/mysql/, `per value, not masked whole: ${nGot}`);
    }
    const nArgs = (JSON.parse(nTwins[0]!) as { mcpServers: Record<string, { args: string[] }> }).mcpServers;
    assert.deepEqual(nArgs.mysql!.args.slice(0, 5), ["run", "-i", "--rm", "mcp/mysql", "--password"]);
    assert.match(nArgs.mysql!.args[5]!, new RegExp(`^${P}\\.args\\.5$`));
    assert.match(nArgs.runner!.args[3]!, new RegExp(`^admin:${P}\\.args\\.3\\.password$`));
    assert.match(nArgs.nightly!.args[1]!, new RegExp(`^backup-tool --datadir /var/lib/mysql --password ${P}\\S+$`));
    assert.deepEqual(nArgs.pg!.args, ["-h", "db.internal", "--password", "proddb"]);
    assert.deepEqual(nArgs.web!.args, ["run", "-u", "app:staff", "nginx"]);
    assert.match(await why("prog/.mcp.json"), new RegExp(`\\(${N_RAWS.length} in the file now\\)`));
  } finally {
    if (watchdog?.pid !== undefined) try { process.kill(-watchdog.pid, "SIGKILL"); } catch { /* already gone */ }
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
