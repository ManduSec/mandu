/**
 * labelled-data-file-twin — a KNOWN LIMIT, pinned (2026-10-16). This is NOT
 * a passing security oracle: it asserts that values of a labelled file DO
 * reach the model today, so that the fix must flip it deliberately.
 *
 * The limit (guarantees.md §3, "A value Mandu does not recognize in a
 * structured file"; secret-discovery.md §2.5; plan 10 §2.4; plan 16 §1.2):
 * a JSON, YAML, TOML, INI or XML file a PERSON labelled `no-model`, with one
 * secret-looking key, gets the per-key copy. Only the value under that key
 * is a placeholder; every other value (`ssn`, `wages`) stays as written in
 * the copy programs read, and reaches the model through Claude Code's Read
 * of the copy and through a shell command that does not name the file
 * (`cat ./ret*`). A command that names the file is masked whole. A
 * labelled dotenv masks by value but keeps integers and plain words. The
 * planned fix is plan 16's document twin
 * (confidentiality-plan-16-document-twins-writeback.md §1.2, §3): every
 * value of a labelled data file a symbol. When it lands, the KNOWN LIMIT
 * assertions below must be turned into their negation.
 *
 * Also pinned: the workarounds the user docs give for today, over the same
 * components. An `extract:` pattern that matches every value masks every
 * value; the same data in a file of no known shape (`return.txt`) is one
 * placeholder; and `mandu why` says which form each file gets.
 *
 * Real ArbiterServer, PRODUCTION proxy wiring (`new ArbiterClientAdapter(new
 * ArbiterClient(sock))`), `registerSecret` as the launcher calls it, and
 * `mandu why` over the launcher's own call path.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
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

const SSN = "123-45-6789";
const WAGES = "81234";
const PW = "hunter2pw";
/** Values under keys Mandu does not recognize as secret. */
const UNRECOGNIZED = [["ssn", SSN], ["wages", WAGES]] as const;
const YAML = `ssn: ${SSN}\nwages: ${WAGES}\npassword: ${PW}\n`;
const FORMATS: Record<string, string> = {
  "return.yaml": YAML,
  "return.json": `${JSON.stringify({ ssn: SSN, wages: WAGES, password: PW }, null, 2)}\n`,
  "return.toml": `ssn = "${SSN}"\nwages = "${WAGES}"\npassword = "${PW}"\n`,
  "return.ini": `[return]\nssn = ${SSN}\nwages = ${WAGES}\npassword = ${PW}\n`,
  "return.xml": `<return>\n  <ssn>${SSN}</ssn>\n  <wages>${WAGES}</wages>\n  <password>${PW}</password>\n</return>\n`,
};

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

function turn(input: { file_path: string } | { command: string }, content: string, id: string): string {
  return JSON.stringify({
    model: "claude-sonnet-5",
    stream: true,
    messages: [
      { role: "user", content: "what is in last year's return?" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "file_path" in input ? "Read" : "Bash", input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  });
}

test("KNOWN LIMIT (plan 16 §1.2): a person-labelled JSON/YAML/TOML/INI/XML file gets the per-key copy, and its unrecognized values reach the model as written; the documented workarounds hold (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-data-twin-"));
  const home = join(dir, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  for (const [name, text] of Object.entries(FORMATS)) writeFileSync(join(proj, name), text);
  const dotenv = join(proj, "return.env");
  writeFileSync(dotenv, `SSN=${SSN}\nWAGES=${WAGES}\nFILING=joint\nPASSWORD=${PW}\n`);
  const extracted = join(proj, "extracted.yaml");
  const plain = join(proj, "return.txt");
  writeFileSync(extracted, YAML);
  writeFileSync(plain, YAML);
  const labelled = Object.keys(FORMATS).map((n) => join(proj, n));
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n${[...labelled, plain, dotenv].map((p) => `  - path: ${p}\n    level: no-model\n`).join("")}` +
    `  - path: ${extracted}\n    level: no-model\n    extract: ':[ \\t]*(.+)'\n`);
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0, policyDocument: loadPolicyFileStrict(policy).config,
  });
  await server.listen();
  const real = new ArbiterClient(sock);
  await real.connect();
  const sessionKey = `data-twin-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  let n = 0;
  try {
    assert.equal((await real.setSessionSpec({ sessionKey, spec: "claude-code", requestedBy: "labelled-data-file-twin e2e" })).bound, "claude-code");
    /** The tool_result the model-facing request carries. */
    const forwarded = async (input: { file_path: string } | { command: string }, content: string): Promise<string> => {
      const up = new MockUpstream({ sse: buildTextSse("ok") });
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey, log: () => {} });
      proxies.push(proxy);
      const r = await post(await proxy.listen(0), turn(input, content, `tu_${n++}`), sessionKey);
      assert.equal(r.status, 200, r.body);
      const sent = up.requests[up.requests.length - 1]!.json() as { messages: Array<{ content: unknown }> };
      const block = (sent.messages[2]!.content as Array<{ content: unknown }>)[0]!.content;
      return typeof block === "string" ? block : JSON.stringify(block);
    };
    const twinOf = async (path: string): Promise<{ twin: string; structured: boolean }> => {
      const reg = await real.registerSecret({ path, sessionKey });
      assert.ok(reg.symbol, reg.reason);
      return typeof reg.twin === "string" ? { twin: reg.twin, structured: true } : { twin: `${reg.symbol}\n`, structured: false };
    };

    // 1. The limit, in each format.
    for (const path of labelled) {
      const { twin, structured } = await twinOf(path);
      assert.ok(structured, `${path}: the per-key copy`);
      assert.ok(!twin.includes(PW), `the recognized key's value is a placeholder:\n${twin}`);
      assert.match(twin, /\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.\S*password/, twin);
      const read = await forwarded({ file_path: path }, claudeRead(twin));
      const glob = await forwarded({ command: "cat ./ret*" }, twin);
      const named = await forwarded({ command: `cat ${path}` }, twin);
      for (const out of [read, glob, named]) assert.ok(!out.includes(PW), `the recognized value never reaches the model:\n${out}`);
      for (const [key, v] of UNRECOGNIZED) {
        assert.ok(twin.includes(v), `KNOWN LIMIT flipped? ${key} is no longer raw in the copy of ${path}; update the docs and this test (plan 16 §3)`);
        assert.ok(read.includes(v), `KNOWN LIMIT flipped? ${key} no longer reaches the model by Read of ${path}:\n${read}`);
        assert.ok(glob.includes(v), `KNOWN LIMIT flipped? ${key} no longer reaches the model by a command that does not name ${path}:\n${glob}`);
        assert.ok(!named.includes(v), `a command that names the file is masked whole:\n${named}`);
      }
    }

    // 1b. A dotenv masks every value but an integer or a plain word, under
    //     any key: there `wages` and `joint` stay as written.
    const env = await twinOf(dotenv);
    assert.ok(env.structured, "the per-key copy");
    for (const v of [SSN, PW]) assert.ok(!env.twin.includes(v), env.twin);
    assert.ok(env.twin.includes(`WAGES=${WAGES}\n`) && env.twin.includes("FILING=joint\n"), `KNOWN LIMIT flipped? ${env.twin}`);

    // 2. Workaround: an `extract:` pattern that matches every value.
    const ex = await twinOf(extracted);
    assert.ok(ex.structured, "the person's pattern keeps the structure");
    assert.match(ex.twin, /^ssn: \$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.extract_1\nwages: \$MDU:/, ex.twin);
    const exRead = await forwarded({ file_path: extracted }, claudeRead(ex.twin));
    for (const v of [SSN, WAGES, PW]) {
      assert.ok(!ex.twin.includes(v), `CONFIDENTIALITY VIOLATION: ${v} in the extract: copy:\n${ex.twin}`);
      assert.ok(!exRead.includes(v), `CONFIDENTIALITY VIOLATION: ${v} reached the model:\n${exRead}`);
    }

    // 3. Workaround: the same data in a file of no known shape is one placeholder.
    const txt = await twinOf(plain);
    assert.ok(!txt.structured, "a .txt gets the whole-file placeholder");
    const txtRead = await forwarded({ file_path: plain }, claudeRead(txt.twin));
    for (const v of [SSN, WAGES, PW]) assert.ok(!txtRead.includes(v), `CONFIDENTIALITY VIOLATION: ${v} reached the model:\n${txtRead}`);

    // 4. `mandu why` tells the two forms apart.
    const deps = { ...realWhyDeps(), arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }), cwd: () => proj };
    const why = async (arg: string): Promise<string> => {
      const chunks: string[] = [];
      const code = await runWhy([arg], { HOME: home }, {} as Layout, { ...deps, out: (s: string) => { chunks.push(s); } });
      const out = chunks.join("");
      assert.equal(code, 0, out);
      for (const v of [SSN, WAGES, PW]) assert.ok(!out.includes(v), `never a value: ${out}`);
      return out;
    };
    assert.match(await why("return.yaml"), /keeps the file's structure \(yaml-keys\); each secret value Mandu recognizes is a placeholder \(1 in the file now\)/);
    assert.match(await why("extracted.yaml"), /keeps the file's structure \(extract\); each secret value Mandu recognizes is a placeholder \(3 in the file now\)/);
    assert.match(await why("return.txt"), /a whole-file placeholder \(one placeholder for the whole file\)/);
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
