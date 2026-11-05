/**
 * git-locked-object-report — git's own report on a history rewrite and on an
 * object Mandu locked reaches the model; no byte of the locked file does
 * (confidentiality.md §7.1, "git's report on a history rewrite", 2026-10-26).
 *
 * Live on the Claude subscription drills of 2026-10-26 (demo-git-history-
 * scrub, Haiku 4.5): `git log -p` stopped at the locked `.env` version with
 * "unable to read <id>", and every filter-branch that named `.env` came back
 * as one placeholder, so the model could not check its rewrite and told the
 * person the history was clean when the hard-coded key was still in it.
 *
 * Real git in a scratch repository whose `.env` version is locked (a
 * `blobs:` lock in the policy, its loose copy made unreadable as the object
 * twins make it), a real ArbiterServer, and the PRODUCTION proxy wiring (`new
 * ArbiterClientAdapter(new ArbiterClient(sock))`) in front of a mock upstream:
 * what the upstream receives is what the model would. Asserted: git's
 * report of the unreadable object reaches the model with Mandu's one-line
 * note naming it; filter-branch's report on `.env` (banner, progress, `rm
 * '.env'`, the rewritten ref) reaches it as git printed it; the same output
 * with a line of the file in it stays masked; the key is in no request.
 *
 * The Codex wire too (2026-10-27): the openai-proxy carries the same note
 * (locked-object-note.ts, one module in both proxies). Live, Codex got git's
 * EACCES on the locked `.env` version with nothing beside it, ran filter-repo
 * with `--replace-text` and `--invert-paths` in one pass (which reads every
 * blob and fails), took the repository for broken and replaced its history
 * with one new commit. And every claim the note makes is pinned on real git
 * with a locked version (two filter-repo passes work where one fails,
 * filter-branch's index filter works, `log --name-status` works where
 * `log --stat` fails); filter-repo's half self-SKIPs where it is not
 * installed.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { LOCKED_NOTE_MARKER, lockedObjectNote, protectedCopyNote } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import * as openaiNote from "../../interceptors/openai-proxy/src/locked-object-note.js";
import { MockUpstream as OpenAiMockUpstream } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

const KEY = "sk_test_LOCKEDREPORT_" + "q".repeat(24);
const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "seed", GIT_AUTHOR_EMAIL: "seed@example.invalid", GIT_COMMITTER_NAME: "seed", GIT_COMMITTER_EMAIL: "seed@example.invalid",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", FILTER_BRANCH_SQUELCH_WARNING: "1", LC_ALL: "C",
};
/** A command's output as Claude Code's Bash returns it: stdout then stderr, and `Exit code N` first on a failure. */
function bash(cwd: string, command: string): string {
  const r = spawnSync("bash", ["-c", command], { cwd, env: ENV, encoding: "utf8" });
  const out = `${r.stdout}${r.stderr}`.replace(/\n+$/, "");
  return r.status === 0 ? out : `Exit code ${r.status}\n${out}`;
}
const git = (cwd: string, ...a: string[]): string => {
  const r = spawnSync("git", a, { cwd, env: ENV, encoding: "utf8" });
  assert.equal(r.status, 0, `git ${a.join(" ")}: ${r.stderr}`);
  return r.stdout.trim();
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

test("git's report on a rewrite and on a locked object reaches the model; the locked file's bytes never do (secrets axes)", { skip: typeof process.getuid === "function" && process.getuid() === 0 ? "root reads a mode-000 file" : false }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-git-locked-"));
  const repo = join(dir, "storefront");
  mkdirSync(join(repo, "src"), { recursive: true });
  git(repo, "init", "-q", "-b", "main");
  writeFileSync(join(repo, "src", "checkout.js"), "const stripe = Stripe(process.env.STRIPE_SECRET_KEY);\n");
  writeFileSync(join(repo, ".env"), `STRIPE_SECRET_KEY=${KEY}\n`);
  git(repo, "add", ".");
  git(repo, "commit", "-q", "-m", "Move the Stripe key to .env");
  writeFileSync(join(repo, "src", "checkout.js"), "const stripe = Stripe(process.env.STRIPE_SECRET_KEY); // retry\n");
  git(repo, "commit", "-q", "-am", "Retry a declined charge once");
  const blob = git(repo, "rev-parse", "HEAD:.env");
  // the object twins make a locked version's loose copy unreadable
  chmodSync(join(repo, ".git", "objects", blob.slice(0, 2), blob.slice(2)), 0o000);

  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"), adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
    policyDocument: { blobs: [{ id: `sha1:${blob}`, level: "no-model" }] },
  });
  await server.listen();
  const client = new ArbiterClient(join(dir, "arbiter.sock"));
  await client.connect();
  const sessionKey = `git-locked-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  let n = 0;
  try {
    assert.equal((await client.setSessionSpec({ sessionKey, spec: "claude-code", requestedBy: "git-locked-object-report e2e" })).bound, "claude-code");
    const locks = await client.gitHistoryLocks();
    assert.ok(locks.lockedSet.sha1.includes(blob), `the blob lock is in the locked set: ${JSON.stringify(locks.lockedSet)}`);
    const forwarded = async (command: string, content: string): Promise<string> => {
      const up = new MockUpstream({ sse: buildTextSse("ok") });
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client), upstream: up.fetcher, sessionKey, log: () => {} });
      proxies.push(proxy);
      const id = `tu_${n++}`;
      const r = await post(await proxy.listen(0), JSON.stringify({
        model: "claude-haiku-4-5", stream: true,
        messages: [
          { role: "user", content: "scrub my Stripe key from storefront's whole history" },
          { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
        ],
      }), sessionKey);
      assert.equal(r.status, 200, r.body);
      const b: unknown = up.requests[up.requests.length - 1]!.body;
      const sent = Buffer.isBuffer(b) ? b.toString("utf8") : String(b);
      assert.ok(!sent.includes(KEY), `CONFIDENTIALITY VIOLATION: the key reached the model through ${command}:\n${sent.slice(0, 2000)}`);
      return sent;
    };
    const quoted = (s: string) => JSON.stringify(s).slice(1, -1);

    // 1. git log -p stops at the locked version: the error, then Mandu's note
    const logCmd = "git log -p --all";
    const logOut = bash(repo, logCmd);
    assert.match(logOut, new RegExp(`unable to (?:open loose object|read) ${blob}`), logOut);
    const errLines = logOut.split("\n").filter((l) => l.includes(blob)).join("\n");
    const sentErr = await forwarded(logCmd, `Exit code 128\n${errLines}`);
    assert.ok(sentErr.includes(quoted(errLines)), `the model reads git's error:\n${sentErr.slice(0, 1500)}`);
    assert.ok(sentErr.includes(LOCKED_NOTE_MARKER) && sentErr.includes(blob.slice(0, 12)), `and Mandu's note names the object:\n${sentErr.slice(0, 2500)}`);

    // 2. filter-branch removing .env: its report as git printed it
    const fbCmd = "git filter-branch --index-filter 'git rm --cached --ignore-unmatch .env' -- --all";
    const fbOut = bash(repo, fbCmd);
    assert.match(fbOut, /rm '\.env'/, fbOut);
    assert.match(fbOut, /Ref 'refs\/heads\/main' was rewritten/, fbOut);
    const sentFb = await forwarded(fbCmd, fbOut);
    assert.ok(sentFb.includes("was rewritten") && sentFb.includes("rm '.env'"), `the model reads filter-branch's report:\n${sentFb.slice(0, 2500)}`);
    assert.ok(!/\$MDU:nomodel_Bash\[/.test(sentFb), "not masked");

    // 3. the same report with a line of the file in it: masked whole
    const sentLeak = await forwarded(fbCmd, `${fbOut}\n+STRIPE_SECRET_KEY=${KEY}`);
    assert.match(sentLeak, /\$MDU:nomodel_/, "masked");
    assert.ok(!sentLeak.includes(LOCKED_NOTE_MARKER), "no note on a masked result");
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    client.close();
    await server.close();
    try { chmodSync(join(repo, ".git", "objects"), 0o755); } catch { /* best effort */ }
    spawnSync("chmod", ["-R", "u+rwX", dir]);
    rmSync(dir, { recursive: true, force: true });
  }
});

// The note's replacement recipe, on real git with the hard-coded version
// unreadable (live 2026-10-26, demo-git-history-scrub on OpenClaw: told only
// to remove the versions, the model removed checkout.js from every commit and
// its rewrite dropped "Retry a declined charge once"). Putting a clean blob in
// place of the locked one in an --index-filter reads no locked object, keeps
// every commit and leaves the key in none.
test("the [mandu:locked] note's replacement keeps every commit and reads no locked object (real git)", { skip: typeof process.getuid === "function" && process.getuid() === 0 ? "root reads a mode-000 file" : false }, () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-git-locked-swap-"));
  const repo = join(dir, "storefront");
  mkdirSync(join(repo, "src"), { recursive: true });
  try {
    git(repo, "init", "-q", "-b", "main");
    writeFileSync(join(repo, "src", "checkout.js"), `const stripe = Stripe("${KEY}");\n`);
    git(repo, "add", ".");
    git(repo, "commit", "-q", "-m", "Initial checkout service");
    writeFileSync(join(repo, "src", "checkout.js"), "const stripe = Stripe(process.env.STRIPE_SECRET_KEY);\n");
    git(repo, "commit", "-q", "-am", "Move the Stripe key to .env");
    writeFileSync(join(repo, "src", "checkout.js"), "const stripe = Stripe(process.env.STRIPE_SECRET_KEY); // retry\n");
    git(repo, "commit", "-q", "-am", "Retry a declined charge once");
    const locked = git(repo, "rev-parse", "HEAD~2:src/checkout.js");
    const clean = git(repo, "rev-parse", "HEAD~1:src/checkout.js");
    chmodSync(join(repo, ".git", "objects", locked.slice(0, 2), locked.slice(2)), 0o000);
    assert.match(bash(repo, "git show HEAD~2:src/checkout.js"), /Exit code 128[\s\S]*(Permission denied|unable to)/, "the version is unreadable");

    // the recipe as the note words it
    const filter = `if [ "$(git ls-files -s src/checkout.js | cut -d' ' -f2)" = ${locked} ]; then git update-index --cacheinfo 100644,${clean},src/checkout.js; fi`;
    const out = bash(repo, `git filter-branch --index-filter '${filter.replace(/'/g, "'\\''")}' -- --all`);
    assert.doesNotMatch(out, /^Exit code/, out);
    assert.match(out, /Ref 'refs\/heads\/main' was rewritten/, out);
    git(repo, "update-ref", "-d", "refs/original/refs/heads/main");
    const subjects = git(repo, "log", "--format=%s", "main").split("\n");
    assert.deepEqual(subjects, ["Retry a declined charge once", "Move the Stripe key to .env", "Initial checkout service"], "every commit kept");
    for (const c of git(repo, "rev-list", "main").split("\n")) {
      assert.notEqual(git(repo, "rev-parse", `${c}:src/checkout.js`), locked, `commit ${c} no longer holds the locked version`);
    }
    assert.equal(bash(repo, `git grep -l -F '${KEY}' $(git rev-list main) || true`), "", "the key is in no commit");
  } finally {
    spawnSync("chmod", ["-R", "u+rwX", dir]);
    rmSync(dir, { recursive: true, force: true });
  }
});

// The twin of a protected file is read-only in the agent's working tree, so
// git cannot remove it (live 2026-10-27, demo-git-history-scrub on Haiku
// 4.5: filter-branch's checkout of the rewritten head said "warning: unable
// to unlink '.env': Permission denied", and the whole report came back
// masked). Simulated by a read-only repository root (filter-branch's temp
// directory elsewhere): git's report reaches the model with the note on the
// protected copy; the same report with a line of the file stays masked.
test("git's EACCES on removing a protected file's read-only copy reaches the model with the note; a value beside it never does (real git, secrets axes)", { skip: typeof process.getuid === "function" && process.getuid() === 0 ? "root writes a mode-555 directory" : false }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-git-unlink-"));
  const repo = join(dir, "storefront");
  mkdirSync(join(repo, "src"), { recursive: true });
  git(repo, "init", "-q", "-b", "main");
  writeFileSync(join(repo, "src", "checkout.js"), "const stripe = Stripe(process.env.STRIPE_SECRET_KEY);\n");
  writeFileSync(join(repo, ".env"), `STRIPE_SECRET_KEY=${KEY}\n`);
  git(repo, "add", ".");
  git(repo, "commit", "-q", "-m", "Move the Stripe key to .env");
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"), adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  const client = new ArbiterClient(join(dir, "arbiter.sock"));
  await client.connect();
  const sessionKey = `git-unlink-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  try {
    await client.setSessionSpec({ sessionKey, spec: "claude-code", requestedBy: "git-locked-object-report e2e" });
    const forwarded = async (command: string, content: string): Promise<string> => {
      const up = new MockUpstream({ sse: buildTextSse("ok") });
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client), upstream: up.fetcher, sessionKey, log: () => {} });
      proxies.push(proxy);
      const r = await post(await proxy.listen(0), JSON.stringify({
        model: "claude-haiku-4-5", stream: true,
        messages: [
          { role: "user", content: "scrub my Stripe key from storefront's whole history" },
          { role: "assistant", content: [{ type: "tool_use", id: "tu_unlink", name: "Bash", input: { command } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_unlink", content }] },
        ],
      }), sessionKey);
      assert.equal(r.status, 200, r.body);
      const b: unknown = up.requests[up.requests.length - 1]!.body;
      const sent = Buffer.isBuffer(b) ? b.toString("utf8") : String(b);
      assert.ok(!sent.includes(KEY), `CONFIDENTIALITY VIOLATION: the key reached the model through ${command}:\n${sent.slice(0, 2000)}`);
      return sent;
    };
    const fbCmd = `git filter-branch -d ${join(dir, "fb-tmp")} --index-filter "git update-index --remove .env" --prune-empty -- --all`;
    chmodSync(repo, 0o555); // the work tree's files cannot be removed (the twin's read-only copy)
    const out = bash(repo, fbCmd);
    chmodSync(repo, 0o755);
    assert.match(out, /warning: unable to unlink '\.env': Permission denied/, out);
    const sent = await forwarded(fbCmd, out);
    assert.ok(sent.includes("unable to unlink '.env': Permission denied") && sent.includes("was rewritten"), `git's report reaches the model:\n${sent.slice(0, 2500)}`);
    assert.ok(sent.includes(`${LOCKED_NOTE_MARKER} git could not remove '.env'`) && sent.includes("--index-filter"), `with the note:\n${sent.slice(0, 3000)}`);
    const leak = await forwarded(fbCmd, `${out}\n+STRIPE_SECRET_KEY=${KEY}`);
    assert.match(leak, /\$MDU:nomodel_/, "the report with a line of the file: masked");
    assert.ok(!leak.includes(LOCKED_NOTE_MARKER), "no note on a masked result");
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    client.close();
    await server.close();
    spawnSync("chmod", ["-R", "u+rwX", dir]);
    rmSync(dir, { recursive: true, force: true });
  }
});

const rootReads = typeof process.getuid === "function" && process.getuid() === 0 ? "root reads a mode-000 file" : false;
const hasFilterRepo = spawnSync("git", ["filter-repo", "--version"], { env: ENV, encoding: "utf8" }).status === 0;
const SUBJECTS = ["Retry a declined charge once", "Move the Stripe key to .env", "Initial checkout service"];

/** The drill's storefront shape under `dir`: (with `hardCoded`) the key in
 *  checkout.js first, then moved to .env, then one more change; the .env
 *  version locked as the object twins lock it (its loose copy unreadable). */
function lockedStorefront(dir: string, hardCoded: boolean): { repo: string; envBlob: string } {
  const repo = join(dir, "storefront");
  mkdirSync(join(repo, "src"), { recursive: true });
  git(repo, "init", "-q", "-b", "main");
  if (hardCoded) {
    writeFileSync(join(repo, "src", "checkout.js"), `const stripe = Stripe("${KEY}");\n`);
    git(repo, "add", ".");
    git(repo, "commit", "-q", "-m", "Initial checkout service");
  }
  writeFileSync(join(repo, "src", "checkout.js"), "const stripe = Stripe(process.env.STRIPE_SECRET_KEY);\n");
  writeFileSync(join(repo, ".env"), `STRIPE_SECRET_KEY=${KEY}\n`);
  git(repo, "add", ".");
  git(repo, "commit", "-q", "-m", "Move the Stripe key to .env");
  writeFileSync(join(repo, "src", "checkout.js"), "const stripe = Stripe(process.env.STRIPE_SECRET_KEY); // retry\n");
  git(repo, "commit", "-q", "-am", "Retry a declined charge once");
  const envBlob = git(repo, "rev-parse", "HEAD:.env");
  chmodSync(join(repo, ".git", "objects", envBlob.slice(0, 2), envBlob.slice(2)), 0o000);
  return { repo, envBlob };
}

// Codex's two wires (an exec_command output, a code-mode script cell's
// parts), the real arbiter, the PRODUCTION openai-proxy wiring (2026-10-27).
test("Codex: git's report on a locked object reaches the model with the same [mandu:locked] note as Claude's; the locked file's bytes never do (secrets axes)", { skip: rootReads }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-git-locked-codex-"));
  // the key only ever in .env, whose one version is locked: nothing git
  // prints here holds it
  const { envBlob: blob } = lockedStorefront(dir, false);
  const human = join(dir, "human", "h.sock");
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"), humanSocketPath: human, adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
    policyDocument: { blobs: [{ id: `sha1:${blob}`, level: "no-model" }] },
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const session = `git-locked-codex-${process.pid}`;
  const upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const proxy = new OpenAiProxy({ arbiter: new OpenAiArbiterAdapter(await open(join(dir, "arbiter.sock")), await open(human)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const head = (code: number) => `Chunk ID: 7a1f\nWall time: 0.0312 seconds\nProcess exited with code ${code}\nOriginal token count: 40\nOutput:\n`;
  const CELL_HEAD = "Script completed\nWall time 0.8 seconds\nOutput:\n";
  const send = async (...items: unknown[]): Promise<string> => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session },
      body: JSON.stringify({ model: "gpt-5.5", stream: true, instructions: "You are Codex.", input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "scrub my Stripe key from storefront's whole history" }] }, ...items] }),
    });
    assert.equal(res.status, 200, await res.text());
    const sent = upstream.requests.at(-1)!.bodyText;
    assert.ok(!sent.includes(KEY), `CONFIDENTIALITY VIOLATION: the key reached the model on the Codex wire:\n${sent.slice(0, 2000)}`);
    return sent;
  };
  const itemOf = (body: string, callId: string): Record<string, unknown> =>
    (JSON.parse(body).input as Array<Record<string, unknown>>).find((i) => String(i["type"]).endsWith("_output") && i["call_id"] === callId)!;
  const textOf = (item: Record<string, unknown>): string => {
    const o = item["output"];
    return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
  };
  const raw = (command: string): { code: number; out: string } => {
    const r = spawnSync("bash", ["-c", command], { cwd: dir, env: ENV, encoding: "utf8" });
    return { code: r.status ?? 1, out: `${r.stdout}${r.stderr}` };
  };
  try {
    // 1. exec_command: git log -p stops at the locked version; its report, then the note
    const logCmd = "git -C storefront log -p --all";
    const log = raw(logCmd);
    assert.match(log.out, new RegExp(`unable to (?:open loose object|read) ${blob}`), log.out);
    const sent1 = await send(
      { type: "function_call", call_id: "c_log", name: "exec_command", arguments: JSON.stringify({ cmd: logCmd, workdir: dir }) },
      { type: "function_call_output", call_id: "c_log", output: `${head(log.code)}${log.out}` },
    );
    const o1 = textOf(itemOf(sent1, "c_log"));
    assert.equal(o1, `${head(log.code)}${log.out}\n\n${lockedObjectNote([blob])}`, "git's report as it printed it, then the Claude proxy's note");

    // 2. a script cell (Codex's code mode, as live 2026-10-27): the one-pass
    // filter-repo that reads every blob (else `log --stat`, which reads it
    // too), with the path built at run time as the model built it; the
    // cell's parts kept, the note one more
    writeFileSync(join(dir, "redact.txt"), "Stripe==>REDACTED\n");
    const cellCmd = hasFilterRepo
      ? `f=.; f="\${f}env"; git -C storefront filter-repo --force --replace-text ${join(dir, "redact.txt")} --path "$f" --invert-paths`
      : "git -C storefront log --all --stat";
    const cell = raw(cellCmd);
    assert.notEqual(cell.code, 0, `the command reads the locked version and fails:\n${cell.out}`);
    assert.match(cell.out, new RegExp(blob), cell.out);
    const sent2 = await send(
      { type: "custom_tool_call", call_id: "c_cell", name: "exec", input: `const r = await tools.exec_command({cmd:${JSON.stringify(cellCmd)}}); text(r.output);` },
      { type: "custom_tool_call_output", call_id: "c_cell", output: [{ type: "input_text", text: CELL_HEAD }, { type: "input_text", text: cell.out }] },
    );
    assert.deepEqual(itemOf(sent2, "c_cell")["output"], [
      { type: "input_text", text: CELL_HEAD },
      { type: "input_text", text: cell.out },
      { type: "input_text", text: `\n\n${lockedObjectNote([blob])}` },
    ], "the cell's parts as Codex wrote them, then the note");
    assert.equal(git(join(dir, "storefront"), "log", "--format=%s", "main"), "Retry a declined charge once\nMove the Stripe key to .env", "the failed run left the history as it was");

    // 3. the same report with a line of the file, from a command naming .env: masked, no note
    const errLines = log.out.split("\n").filter((l) => l.includes(blob)).join("\n");
    const sent3 = await send(
      { type: "function_call", call_id: "c_leak", name: "exec_command", arguments: JSON.stringify({ cmd: "git -C storefront log -p --all -- .env", workdir: dir }) },
      { type: "function_call_output", call_id: "c_leak", output: `${head(128)}${errLines}\n+STRIPE_SECRET_KEY=${KEY}\n` },
    );
    const o3 = textOf(itemOf(sent3, "c_leak"));
    assert.match(o3, /\$MDU:nomodel_/, `masked:\n${o3}`);
    assert.ok(!o3.includes(LOCKED_NOTE_MARKER), "no note on a masked output");

    // THE ORACLE over every request this test sent
    for (const r of upstream.requests) assert.ok(!r.bodyText.includes(KEY), "CONFIDENTIALITY VIOLATION: the key is in a request to the model");
  } finally {
    await proxy.close();
    for (const c of clients) c.close();
    await server.close();
    spawnSync("chmod", ["-R", "u+rwX", dir]);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the [mandu:locked] note's text is one module in both proxies", () => {
  const ids = ["7c72b0c959f112730dc47da675a590979839a25e", "a".repeat(64)];
  assert.equal(openaiNote.LOCKED_NOTE_MARKER, LOCKED_NOTE_MARKER);
  assert.equal(openaiNote.lockedObjectNote(ids), lockedObjectNote(ids));
  assert.equal(openaiNote.protectedCopyNote([".env", "config/prod.env"]), protectedCopyNote([".env", "config/prod.env"]));
});

// Every command the note recommends, and the ones it warns against, on real
// git with the .env version locked (confidentiality.md §7.2a, "Why not
// rewrite the objects": the table of what git does with a locked version).
test("the note's claims on real git: log --name-status and log -- <path> work, log --stat and show fail; filter-branch's index filter keeps every commit", { skip: rootReads }, () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-git-locked-claims-"));
  try {
    const { repo, envBlob } = lockedStorefront(dir, true);
    assert.match(lockedObjectNote([envBlob])!, /git show, log -p, log --stat and a tree filter fail on a locked version, so check a rewrite with git log --all --name-status or git log --all -- <path>/);
    assert.match(bash(repo, "git log --all --stat"), /^Exit code 128[\s\S]*(Permission denied|unable to read)/, "--stat reads the locked version");
    assert.match(bash(repo, "git show HEAD~1:.env"), /^Exit code 128/, "git show of the version fails");
    const ns = bash(repo, "git log --all --name-status --format=%s");
    assert.doesNotMatch(ns, /^Exit code/, ns);
    assert.match(ns, /^A\t\.env$/m, ns);
    assert.equal(bash(repo, "git log --all --format=%s -- .env"), "Move the Stripe key to .env");

    const fb = bash(repo, "git filter-branch --index-filter 'git rm -q --cached --ignore-unmatch .env' -- --all");
    assert.doesNotMatch(fb, /^Exit code/, fb);
    assert.deepEqual(git(repo, "log", "--format=%s", "main").split("\n"), SUBJECTS, "every commit kept");
    assert.equal(bash(repo, "git log --format=%s main -- .env"), "", ".env is in no commit of main");
  } finally {
    spawnSync("chmod", ["-R", "u+rwX", dir]);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the note's filter-repo advice on real git: one pass with --replace-text fails, --invert-paths then --replace-text works and keeps every commit", { skip: rootReads || (hasFilterRepo ? false : "git filter-repo is not installed") }, () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-git-locked-filter-repo-"));
  try {
    const redact = join(dir, "redact.txt");
    writeFileSync(redact, `${KEY}==>REDACTED\n`);
    const one = lockedStorefront(join(dir, "one"), true);
    const onePass = bash(one.repo, `git filter-repo --force --replace-text ${redact} --path .env --invert-paths`);
    assert.match(onePass, /^Exit code [1-9][\s\S]*fast-export failed/, `one pass reads the locked version and fails:\n${onePass}`);
    assert.ok(onePass.includes(one.envBlob), onePass);

    const two = lockedStorefront(join(dir, "two"), true);
    const first = bash(two.repo, "git filter-repo --force --path .env --invert-paths");
    assert.doesNotMatch(first, /^Exit code/, `the first pass reads no content:\n${first}`);
    const second = bash(two.repo, `git filter-repo --force --replace-text ${redact}`);
    assert.doesNotMatch(second, /^Exit code/, `the second pass reads what is left:\n${second}`);
    assert.deepEqual(git(two.repo, "log", "--format=%s", "main").split("\n"), SUBJECTS, "every commit kept");
    const patches = bash(two.repo, "git log --all -p");
    assert.doesNotMatch(patches, /^Exit code/, patches);
    assert.ok(!patches.includes(KEY), "the key is in no version");
    assert.match(patches, /Stripe\("REDACTED"\)/, "the hard-coded copy is replaced");
    assert.equal(bash(two.repo, "git log --all --format=%s -- .env"), "", ".env is in no commit");
  } finally {
    spawnSync("chmod", ["-R", "u+rwX", dir]);
    rmSync(dir, { recursive: true, force: true });
  }
});
