/**
 * e2e — a labeled file committed to the workspace's OWN git repository does not
 * reach the model through git (confidentiality-plan-11 §8 row 1: found by the
 * live local-model drill, 2026-09-27). Production wiring of the model proxy
 * (`new ArbiterClientAdapter(new ArbiterClient(sock))`) over a real
 * ArbiterServer in `secrets` mode (integrity OFF, the product default, where
 * the Bash result classifies TRUSTED), with REAL `git diff` / `git show`
 * output from a real repository.
 *
 * Why it leaked: `git` reads the committed copy out of .git/objects, an open
 * the guard never sees as an open of the labeled file, so the process tree
 * held no taint and the value backstop never ran; and a diff prefixes every
 * line, so the whole document never appears verbatim. The backstop now runs
 * for every exec result and matches a multi-line secret line by line.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { request as httpRequest } from "node:http";
import { chmodSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as ProxyAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { planSecretTwins, withObjectTwins } from "../../launcher/src/secret-twins.js";
import { prepareGitObjectTwins } from "../../launcher/src/git-object-twins.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4): the product default

const CANARY = "GIT_OBJECTS_CANARY_7731";
const DOC = [
  "# Board minutes (confidential)",
  `The Acme acquisition closes at 4,200,000 USD, reference ${CANARY}.`,
  "The board approved the budget for the next fiscal year unanimously.",
  "",
].join("\n");

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd, encoding: "utf8",
    env: { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x", GIT_CONFIG_GLOBAL: "/dev/null" },
  });
}

function bashTurn(command: string, output: string, id: string): string {
  return JSON.stringify({
    model: "claude-opus-4",
    stream: true,
    messages: [
      { role: "user", content: "What changed?" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
    ],
  });
}

function readTurn(path: string, content: string, id: string): string {
  return JSON.stringify({
    model: "claude-opus-4",
    stream: true,
    messages: [
      { role: "user", content: "Read it." },
      { role: "assistant", content: [{ type: "tool_use", id, name: "Read", input: { file_path: path } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  });
}

function post(port: number, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } },
      (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); },
    );
    r.on("error", reject);
    r.end(body);
  });
}

test("git diff / git show of a committed local-model file, and a copy read back, reach the model masked; an unrelated diff passes", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-git-label-"));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "notes"), { recursive: true });
  const minutes = join(ws, "notes", "minutes.md");
  writeFileSync(minutes, DOC);
  writeFileSync(join(ws, "README.md"), "hello\n");
  git(ws, "init", "-q");
  git(ws, "add", ".");
  git(ws, "commit", "-qm", "init");
  writeFileSync(minutes, "(redacted)\n");
  writeFileSync(join(ws, "README.md"), "hello world\n");
  const diff = git(ws, "diff");
  const show = git(ws, "show", "HEAD:notes/minutes.md");
  const readmeDiff = git(ws, "diff", "README.md");
  assert.ok(diff.includes(CANARY) && show.includes(CANARY), "precondition: git itself prints the committed bytes");

  const sock = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: minutes, level: "local-model" }] } as never,
  });
  await arbiter.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  const real = new ArbiterClient(sock);
  await real.connect();
  const up = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ProxyAdapter(real), upstream: up.fetcher, sessionKey: "g", log: () => {} });
  const port = await proxy.listen(0);
  try {
    // The launcher registers the labeled file at launch (secret-setup); the
    // working copy now differs, as after an edit, so only git has the bytes.
    writeFileSync(minutes, DOC);
    const reg = await data.registerSecret({ path: minutes, sessionKey: "g", home: tmp });
    assert.ok(reg.symbol, `registered (${reg.reason})`);
    writeFileSync(minutes, "(redacted)\n");

    assert.equal(await post(port, bashTurn("git diff", diff, "tu_d")), 200);
    assert.equal(await post(port, bashTurn("git show HEAD:notes/minutes.md", show, "tu_s")), 200);
    assert.equal(await post(port, bashTurn("git diff README.md", readmeDiff, "tu_r")), 200);
    // The copy route: `git show … > out.txt`, then the Read tool on the copy
    // (an unlabeled path, and no exec output for the command check to see).
    const copy = join(ws, "out.txt");
    writeFileSync(copy, show);
    assert.equal(await post(port, readTurn(copy, show, "tu_c")), 200);
    const fwd = up.requests.map((r) => r.bodyText);
    assert.ok(!fwd[0]!.includes(CANARY), "git diff: the committed document's lines do not reach the model");
    assert.ok(!fwd[0]!.includes("board approved the budget"), "no line of it does");
    assert.ok(!fwd[1]!.includes(CANARY), "git show: masked");
    assert.match(fwd[0]!, /\$MDU:localmodel_Bash\[[0-9a-f]+\]/, "masked at the document's own level");
    assert.match(fwd[2]!, /hello world/, "an unrelated diff reaches the model as before");
    assert.ok(!fwd[3]!.includes(CANARY), "a copy read back with the Read tool: masked at the model door");
  } finally {
    await proxy.close();
    data.close();
    real.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("under the launch's twins, git itself never prints the committed bytes: the raw canary is ABSENT from the agent's world, and the model still sees none", async (t) => {
  if (spawnSync("bwrap", ["--dev-bind", "/", "/", "--cap-drop", "ALL", "--", "true"], { stdio: "ignore", timeout: 10_000 }).status !== 0) {
    t.skip("bwrap cannot start here (the guard-only posture is proven in net-supervisor's guard_integration.rs)");
    return;
  }
  const tmp = mkdtempSync(join(tmpdir(), "mandu-git-twin-"));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "notes"), { recursive: true });
  const minutes = join(ws, "notes", "minutes.md");
  writeFileSync(minutes, DOC);
  writeFileSync(join(ws, "README.md"), "hello\n");
  git(ws, "init", "-q");
  git(ws, "add", ".");
  git(ws, "commit", "-qm", "init");
  writeFileSync(join(ws, "README.md"), "hello world\n");

  const sock = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: minutes, level: "local-model" }] } as never,
  });
  await arbiter.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  const real = new ArbiterClient(sock);
  await real.connect();
  const up = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ProxyAdapter(real), upstream: up.fetcher, sessionKey: "g2", log: () => {} });
  const port = await proxy.listen(0);
  try {
    // What the launcher does (secret-setup.ts): register the file, twin it,
    // and twin the object store holding its committed bytes.
    const reg = await data.registerSecret({ path: minutes, sessionKey: "g2", home: tmp });
    assert.ok(reg.symbol, `registered (${reg.reason})`);
    const twinDir = join(tmp, "twins");
    mkdirSync(twinDir);
    const denyFile = join(twinDir, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    const plan = planSecretTwins([{ path: minutes, symbol: reg.symbol!, ...(reg.twin !== undefined ? { twin: reg.twin } : {}) }], twinDir, "bwrap");
    for (const f of plan.files) writeFileSync(f.twinPath, f.content, { mode: 0o600 });
    const objects = await prepareGitObjectTwins([minutes], { cacheDir: join(tmp, "cache"), denyFile });
    assert.ok(objects.twins.length > 0, "the committed document's pack or loose object is twinned");
    const wrap = withObjectTwins(plan.wrapArgv, objects.twins, []);
    const inWrap = (cmd: string) => {
      const r = spawnSync(wrap[0]!, [...wrap.slice(1), "sh", "-c", cmd], { cwd: ws, encoding: "utf8", timeout: 60_000, env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null" } });
      return `${r.stdout}${r.stderr}`;
    };
    const outputs = {
      diff: inWrap("git diff"),
      show: inWrap("git show HEAD:notes/minutes.md"),
      logp: inWrap("git log -p"),
      all: inWrap("git cat-file --batch-all-objects --batch"),
      cat: inWrap("cat notes/minutes.md"),
      readme: inWrap("git diff README.md"),
    };
    for (const [name, out] of Object.entries(outputs)) {
      assert.ok(!out.includes(CANARY), `${name}: the raw canary is absent from what git printed in the agent's world`);
      assert.ok(!out.includes("board approved the budget"), `${name}: no line of the document either`);
    }
    assert.match(outputs.readme, /hello world/, "an unrelated diff still works under the twins");
    assert.ok(outputs.cat.includes("$MDU:"), "the working copy is its twin");

    let n = 0;
    for (const [name, out] of Object.entries(outputs)) {
      assert.equal(await post(port, bashTurn(name === "cat" ? "cat notes/minutes.md" : `git ${name}`, out, `tu_w${n++}`)), 200);
    }
    for (const r of up.requests) assert.ok(!r.bodyText.includes(CANARY), "no request to the model carries the canary");
  } finally {
    await proxy.close();
    data.close();
    real.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
