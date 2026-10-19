/**
 * The C17 oracle (confidentiality-plan-14-policy-suggestions.md §9 "C17
 * closed" and "Inline key"; test-organization.md §7.2), across the REAL
 * components in `secrets` mode: the launcher's main(), a REAL ArbiterServer
 * with its admin channel, the host's REAL bwrap (and the guard where it is
 * built), a real repository, and the production model proxy
 * (`new ProxyAdapter(new ArbiterClient(sock))`) in front of a mock upstream.
 * The "agent" is /bin/sh running git in the confined launch.
 *
 *   K1 a deploy key committed and then DELETED (no file on disk, no label, no
 *      registry entry). Before: `git show <c>:deploy/id_rsa` and `git log -p`
 *      inside the confined launch print the key, and the proxy forwards it
 *      raw: the boundary of `secrets` mode, asserted as such. The human
 *      applies `lock-path` on the gone path through the admin channel; on
 *      relaunch `git show` fails with "bad object", `git log -p` holds no
 *      key, README.md reads as before, and no request to the model holds
 *      the key's bytes.
 *   K2 a key once INLINE in config.py, which is public now, beside a catalog
 *      credential in HOME (so the launch confines a file too). After
 *      `lock-blob` on the old version: `git show <c>:config.py` fails, the
 *      current config.py reads normally (file and HEAD), `git log -p` holds
 *      no key, and no model request does.
 *   K3 K1's key applied from the TERMINAL (plan 14 §5.3, §9): `mandu policy
 *      suggest` scans through the arbiter, a scripted `a` applies the
 *      suggestion on the DATA socket (a `tighten` change proposed by
 *      `mandu:scan`), and the relaunch hides the key as in K1.
 *   K12 the WORKSPACE scan (plan 14 §13.7): a token in `deploy/staging.tfvars`,
 *      on disk and never committed (a file the default catalog misses: no
 *      name rule, and the content tier reads no `.tfvars`; a `.conf` it has
 *      read since 2026-10-19, secret-discovery.md §2.9). Before: the
 *      confined launch reads it and the proxy forwards it raw (the boundary,
 *      asserted as such), and the launch's own scan prints "1 possible key
 *      in this project". `mandu policy suggest` applies the workspace
 *      suggestion on the DATA socket (the law shows its `lock-path`); on
 *      relaunch the file is confined, no request to the model holds the
 *      token's bytes and no suggestion line prints.
 *   K13 SENSITIVITY LABELS (plan 14 §14.1): an Office document with a
 *      Purview label the person mapped to no-model, its text stored
 *      uncompressed. Before: the confined launch reads the text and the
 *      proxy forwards it raw (the boundary), and the launch's scan prints "1
 *      labelled document in this project". `mandu policy suggest` applies
 *      its suggestion on the DATA socket; on relaunch the document reads as
 *      one `$MDU:` placeholder and no request to the model holds its text.
 *   K4/K5 K1 and K2 after the lock, in the GUARD-ONLY posture
 *      (`--no-secret-bind`: no bind, the REAL mandu-net-guard serves every
 *      twin by descriptor; confidentiality.md §7.2a). Until 2026-09-30 git
 *      there stat'ed the real pack by path, read the sanitized one by
 *      descriptor, found the sizes differ ("packfile … size changed") and
 *      dropped the whole pack: every other object was unreadable too. Now
 *      the guard answers the stat with the twin's metadata: the other
 *      objects and the log read, the protected version is a bad object,
 *      `stat -L` of the pack and of the credential says the twin's size,
 *      and no model request holds the key.
 *
 *   K6/K7 the guard's BACKSTOP (plan 14 §11.1 R4): a key locked by id in a
 *      repository the launch did not prepare (not the workspace, no confined
 *      file or labelled path in it), and in a fork of it: `git log -p` and a
 *      `cat` of the pack are refused (no sanitized copy exists), a repository
 *      with nothing locked reads, the end-of-session notice names both
 *      repositories once, the event names the repository, and no model
 *      request holds the key. K6 with the guard alone, K7 with the bind up.
 *   K8 a PLANTED PACK (plan 14 §11.2): after K1's lock and one launch, the
 *      REAL pack's bytes (the key inside) are written over the sanitized
 *      copy in Mandu's cache, its clean `.idx` kept (the old `.idx` check
 *      passed exactly that). The relaunch does not serve it: the seal does
 *      not match (a confined first launch left one; an unconfined one left
 *      none), the pack is rebuilt, `git show` is a bad object and a raw
 *      read of the pack inflates no byte of the key. The arbiter here has
 *      its human socket, which carries the seals.
 *   K9/K10 COPIES PREPARED AHEAD OF TIME (plan 14 §11.1 R3): K6's
 *      repositories with the arbiter preparing sanitized copies. The first
 *      launch in B is refused in A and the fork (no copy yet; both are
 *      registered); the arbiter prepares and seals their copies; the second
 *      launch runs `git -C A log -p` and the fork's, the locked version is
 *      a bad object, a `cat` of A's pack is served the copy and its raw
 *      bytes, inflated, hold no key. K9 with the guard alone, K10 with the
 *      bind up. K11: the cycle cap at 0 prepares nothing (the arbiter says
 *      the repositories are capped) and the second launch is refused too.
 *   K14 ALTERNATES TWO LINKS DEEP (confidentiality.md §7.2a): A <- B <- C,
 *      each a `clone --shared` of the one before (C reaches A's pack only
 *      through B's alternates file), locked versions in each pack, C
 *      registered alone. The arbiter prepares a copy of every pack C reads,
 *      A's keyed by the union of the locked versions it holds; under the
 *      wrap git in C reads its log and files, no locked version from any
 *      pack, and A's pack read raw is the copy.
 *   K16 A HISTORY REWRITE (guard-file-identity.md §1, a history rewrite under
 *      the guard): the agent rewrites the key out of history and runs `git
 *      gc --prune=now`; the gc succeeds, every file created right after is
 *      made (none taken for the removed twinned pack by its reused inode
 *      number), the old index goes with its pack, no notice prints, and the
 *      locked version stays unreadable. K16a guard only, K16b with the bind.
 *   K17 AN INDEX STAYS ANCHORED beside any pack: in a clone hard-linked to
 *      the workspace's twinned pack and in a copied clone, removing the
 *      `.idx` is refused; once the `.pack` is gone it runs. K17a/K17b.
 *
 * K1-K3, K12, K13 and K8 self-SKIP where bwrap cannot create a user namespace (no bwrap,
 * Ubuntu's AppArmor restriction without a grant, a container; K8 runs with
 * the guard where it is built, and then asserts the seal it left); K4/K5/K6,
 * K9 and K11 where the guard is not built (scripts/build-native.sh); K7,
 * K10 and K14 on either.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { request as httpRequest } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as ProxyAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { ndjsonCall } from "../../launcher/src/secret-setup.js";
import { resolveWrapBwrap } from "../../launcher/src/bwrap-grant.js";
import { realPolicySuggestDeps, runPolicySuggest } from "../../launcher/src/policy-suggest.js";
import type { Layout } from "../../launcher/src/services/layout.js";
import { stateAxes } from "../lib/axes.js";
import { pickGuard } from "../lib/native-guard.js";
import { buildOfficeFile } from "../../arbiter/test/helpers/office-zip.js";
import { idxLookupFile, rebuildKey } from "../../arbiter/policy/prepared-copies.js";

stateAxes("secrets"); // the product default: integrity OFF, so a Bash result reaches the model unmasked unless the law hides it

const BWRAP = (process.platform === "linux" ? resolveWrapBwrap() : null) ?? "bwrap";
const BWRAP_RUNS = process.platform === "linux" && spawnSync(BWRAP, ["--ro-bind", "/", "/", "--", "true"], { stdio: "ignore", timeout: 10_000 }).status === 0;
const skip = BWRAP_RUNS ? false : "bwrap cannot create a user namespace on this host (the confined launch cannot start)";
const PICK = pickGuard(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "interceptors", "target"));
const GUARD = PICK.path;
const skipGuard = process.platform !== "linux" || !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)" : false;

/** Key-shaped canaries assembled at run time (no key literal in this file). */
const DEPLOY_KEY = ["C17", "DEPLOY", "KEY", "7731", "Zq".repeat(16)].join("_");
const INLINE_KEY = ["C17", "INLINE", "KEY", "7731", "Wp".repeat(16)].join("_");
const RAW_CRED = ["AKIA", "C17", "CATALOG", "CRED", "MUST", "NOT", "BE", "READ"].join("_");

const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...a: string[]): string => execFileSync("git", a, { cwd, encoding: "utf8", env: GIT_ENV });

interface Stack { dir: string; home: string; ws: string; sock: string; server: ArbiterServer; admin: ArbiterClient; close: () => Promise<void> }

async function stack(prefix: string, opts: { human?: boolean; prepared?: { cycleMB?: number } } = {}): Promise<Stack> {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const home = join(dir, "home");
  const ws = join(dir, "ws");
  mkdirSync(home, { recursive: true });
  git(dir, "init", "-q", ws);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  const sock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
    // K8: the human plane, which carries the caches' seals (plan 14 §11.2).
    ...(opts.human ? { humanSocketPath: join(dir, "human", "h.sock") } : {}),
    // K9-K11: the copies prepared ahead of time (plan 14 §11.1 R3), into the
    // object-twin cache the launch reads (MANDU_HOME below), on demand.
    ...(opts.prepared ? {
      lockResolution: { home: join(dir, "no-home"), selfDir: null },
      preparedCopies: {
        cacheDir: join(home, ".mandu", "cache", "object-twins"),
        ...(opts.prepared.cycleMB !== undefined ? { limits: { cycleBytes: opts.prepared.cycleMB * 1048576 } } : {}),
      },
    } : {}),
  });
  await server.listen();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  return {
    dir, home, ws, sock, server, admin,
    close: async () => { admin.close(); await server.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

/** One confined launch of /bin/sh running `reads` (name → shell command) in
 *  the workspace; each output (stdout + stderr) and its exit status. */
async function launch(s: Stack, reads: Record<string, string>, opts: { guardOnly?: boolean; guard?: boolean; env?: Record<string, string> } = {}): Promise<{ log: string; out: Record<string, { text: string; status: number }> }> {
  const outDir = mkdtempSync(join(s.dir, "out-"));
  const script = [
    "export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_PAGER=cat",
    `cd '${s.ws}'`,
    ...Object.entries(reads).map(([name, cmd]) => `${cmd} > '${outDir}/${name}' 2>&1; echo $? > '${outDir}/${name}.status'`),
  ].join("\n");
  const lines: string[] = [];
  const orig = console.error;
  const saved = { HOME: process.env["HOME"], MANDU_HOME: process.env["MANDU_HOME"], MANDU_NET_GUARD_BIN: process.env["MANDU_NET_GUARD_BIN"] };
  const cwd = process.cwd();
  let code: number | null = null;
  let err: Error | null = null;
  try {
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["HOME"] = s.home;
    process.env["MANDU_HOME"] = join(s.home, ".mandu");
    if (opts.guardOnly || opts.guard) process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    // The workspace is the launch's cwd (run.ts: workspaceRoots), which is
    // how a blob lock reaches its repository.
    process.chdir(s.ws);
    try {
      code = await main(
        ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", ...(opts.guardOnly ? ["--no-secret-bind"] : []), "--", "/bin/sh", "-c", script],
        {
          HOME: s.home, PWD: s.ws, MANDU_ARBITER_SOCK: s.sock, PATH: process.env["PATH"],
          MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(s.home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: s.dir, MANDU_VERBOSE: "1", ...opts.env,
        },
      );
    } catch (e) {
      err = e as Error;
    }
  } finally {
    console.error = orig;
    process.chdir(cwd);
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
  const log = lines.join("\n");
  assert.equal(err, null, `${err?.message}\n${log}`);
  assert.equal(code, 0, log);
  const out: Record<string, { text: string; status: number }> = {};
  for (const name of Object.keys(reads)) {
    const f = join(outDir, name);
    assert.ok(existsSync(f), `the confined launch ran ${name}\n${log}`);
    out[name] = { text: readFileSync(f, "utf8"), status: Number(readFileSync(`${f}.status`, "utf8").trim()) };
  }
  return { log, out };
}

function bashTurn(command: string, output: string, id: string): string {
  return JSON.stringify({
    model: "claude-opus-4", stream: true,
    messages: [
      { role: "user", content: "Look at the history." },
      { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
    ],
  });
}

/** Every output as a Bash tool result through the production model proxy;
 *  what the upstream (the model) received. */
async function toModel(s: Stack, outputs: Record<string, string>): Promise<string[]> {
  const real = new ArbiterClient(s.sock);
  await real.connect();
  const up = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ProxyAdapter(real), upstream: up.fetcher, sessionKey: `c17-${Date.now()}`, log: () => {} });
  const port = await proxy.listen(0);
  try {
    let n = 0;
    for (const [name, text] of Object.entries(outputs)) {
      const status = await new Promise<number>((resolve, reject) => {
        const r = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } },
          (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
        r.on("error", reject);
        r.end(bashTurn(name, text, `tu_${n++}`));
      });
      assert.equal(status, 200);
    }
    return up.requests.map((r) => r.bodyText);
  } finally {
    await proxy.close();
    real.close();
  }
}

const texts = (o: Record<string, { text: string }>): Record<string, string> => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, v.text]));

test("K1 (C17 closed): a deploy key committed then deleted reaches the model before; after lock-path on the gone path, git show is a bad object and no request holds the key", { skip, timeout: 300_000 }, async () => {
  const s = await stack("mandu-c17-gone-");
  try {
    writeFileSync(join(s.ws, "README.md"), "project readme\n");
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "init");
    mkdirSync(join(s.ws, "deploy"));
    writeFileSync(join(s.ws, "deploy", "id_rsa"), `${DEPLOY_KEY}\n`);
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "add deploy key");
    const added = git(s.ws, "rev-parse", "HEAD").trim();
    git(s.ws, "rm", "-rq", "deploy");
    git(s.ws, "commit", "-qm", "oops, remove it");
    git(s.ws, "repack", "-adq");
    const reads = {
      show: `git show ${added}:deploy/id_rsa`,
      log: "git log -p",
      head: "git show HEAD:README.md",
      cat: "cat README.md",
    };

    // Before: the boundary of `secrets` mode, asserted as such.
    const before = await launch(s, reads);
    assert.ok(before.out.show!.text.includes(DEPLOY_KEY), `boundary: the confined launch reads the key from history\n${before.out.show!.text}`);
    assert.ok(before.out.log!.text.includes(DEPLOY_KEY));
    const fwdBefore = await toModel(s, texts(before.out));
    assert.ok(fwdBefore.some((b) => b.includes(DEPLOY_KEY)), "boundary: with no rule the key reaches the model raw");

    // The human locks the gone path (the suggestion's edit) on the admin channel.
    const r = await s.admin.policyPropose({ edits: [{ op: "lock-path", path: join(s.ws, "deploy", "id_rsa"), level: "no-model" }], reason: "C17", requestedBy: "dashboard" });
    assert.equal((r as { applied?: boolean }).applied, true, JSON.stringify(r));

    const after = await launch(s, reads);
    assert.notEqual(after.out.show!.status, 0, "git show of the deleted key fails");
    assert.match(after.out.show!.text, /bad object/, after.out.show!.text);
    for (const [name, o] of Object.entries(after.out)) assert.ok(!o.text.includes(DEPLOY_KEY), `${name}: the key is absent from the agent's world`);
    assert.match(after.out.log!.text, /oops, remove it/, "the log itself still runs");
    assert.equal(after.out.head!.text, "project readme\n", "every other object reads as before");
    assert.equal(after.out.cat!.text, "project readme\n");
    assert.match(after.log, /git history: \d+ committed version\(s\) of protected files in 1 repository hidden/, after.log);
    for (const b of await toModel(s, texts(after.out))) assert.ok(!b.includes(DEPLOY_KEY), "no request to the model holds the key's bytes");
  } finally {
    await s.close();
  }
});

test("K2 (inline key): after lock-blob on the old version, git show of it fails while the current public file reads normally; no request holds the key", { skip, timeout: 300_000 }, async () => {
  const s = await stack("mandu-c17-inline-");
  try {
    // A catalog credential in HOME: this launch confines a file too, so the
    // blob lock rides beside a confined file's twins.
    mkdirSync(join(s.home, ".aws"), { recursive: true });
    writeFileSync(join(s.home, ".aws", "credentials"), `[default]\naws_secret_access_key=${RAW_CRED}\n`);
    writeFileSync(join(s.ws, "config.py"), `API_KEY = "${INLINE_KEY}"\n`);
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "inline key");
    const first = git(s.ws, "rev-parse", "HEAD").trim();
    const oldBlob = git(s.ws, "rev-parse", "HEAD:config.py").trim();
    writeFileSync(join(s.ws, "config.py"), "API_KEY = os.environ[\"API_KEY\"]\n");
    git(s.ws, "commit", "-qam", "read it from the environment");
    git(s.ws, "repack", "-adq");
    const reads = {
      show: `git show ${first}:config.py`,
      log: "git log -p",
      head: "git show HEAD:config.py",
      cat: "cat config.py",
      cred: `cat '${join(s.home, ".aws", "credentials")}'`,
    };

    const before = await launch(s, reads);
    assert.ok(before.out.show!.text.includes(INLINE_KEY), "boundary: the old version holds the key");
    assert.ok(!before.out.cred!.text.includes(RAW_CRED), "the catalog credential is confined in both launches");
    assert.ok((await toModel(s, texts(before.out))).some((b) => b.includes(INLINE_KEY)), "boundary: with no rule it reaches the model raw");

    const r = await s.admin.policyPropose({ edits: [{ op: "lock-blob", blob: `sha1:${oldBlob}`, level: "no-model", note: "found in history: config.py" }], reason: "inline key", requestedBy: "dashboard" });
    assert.equal((r as { applied?: boolean }).applied, true, JSON.stringify(r));

    const after = await launch(s, reads);
    assert.notEqual(after.out.show!.status, 0);
    assert.match(after.out.show!.text, /bad object/, after.out.show!.text);
    for (const [name, o] of Object.entries(after.out)) assert.ok(!o.text.includes(INLINE_KEY), `${name}: the old version is gone from every read`);
    assert.equal(after.out.head!.text, "API_KEY = os.environ[\"API_KEY\"]\n", "the current file's version reads normally");
    assert.equal(after.out.cat!.text, "API_KEY = os.environ[\"API_KEY\"]\n", "and so does the file");
    assert.ok(!after.out.cred!.text.includes(RAW_CRED));
    for (const b of await toModel(s, texts(after.out))) {
      assert.ok(!b.includes(INLINE_KEY), "no request to the model holds the inline key");
      assert.ok(!b.includes(RAW_CRED), "nor the confined credential");
    }
  } finally {
    await s.close();
  }
});

test("K3 (C17 closed from the terminal): the scan files the deleted key; `mandu policy suggest` applies it on the data socket; on relaunch git show is a bad object and no request holds the key", { skip, timeout: 300_000 }, async () => {
  const s = await stack("mandu-c17-term-");
  // A key-shaped body (assembled: no key literal here) at a credential file's name.
  const body = ["C17", "TERMINAL", "KEY", "7731", "Kx".repeat(20)].join("");
  const pem = "-----BEGIN OPENSSH " + `PRIVATE KEY-----\n${body}\n-----END OPENSSH ` + "PRIVATE KEY-----\n";
  try {
    writeFileSync(join(s.ws, "README.md"), "project readme\n");
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "init");
    mkdirSync(join(s.ws, "deploy"));
    writeFileSync(join(s.ws, "deploy", "id_rsa"), pem);
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "add deploy key");
    const added = git(s.ws, "rev-parse", "HEAD").trim();
    git(s.ws, "rm", "-rq", "deploy");
    git(s.ws, "commit", "-qm", "oops, remove it");
    git(s.ws, "repack", "-adq");
    const reads = { show: `git show ${added}:deploy/id_rsa`, log: "git log -p", cat: "cat README.md" };

    const before = await launch(s, reads);
    assert.ok(before.out.show!.text.includes(body), "boundary: the confined launch reads the key from history");

    // The person runs `mandu policy suggest` in a terminal and presses `a`:
    // the production deps (suggestPolicy and applySuggestion over the DATA
    // socket), only the arbiter lookup and the keys injected.
    const out: string[] = [];
    const keys = ["a"];
    const code = await runPolicySuggest([], { HOME: s.home, NO_COLOR: "1" }, {} as Layout, {
      ...realPolicySuggestDeps(),
      arbiter: async () => ({ sock: s.sock, kind: "resident" as const, axisOn: true, stop: async () => {} }),
      cwd: () => s.ws,
      isTTY: () => true,
      readKey: async () => keys.shift() ?? "",
      readLine: async () => "",
      out: (t) => out.push(t),
      err: (t) => out.push(t),
    });
    const screen = out.join("");
    assert.equal(code, 0, screen);
    assert.match(screen, /\[1\/1\] Make .*deploy\/id_rsa a secret no AI may read \(only in git history\)/, screen);
    assert.match(screen, /Applied \(change pc-\d+;/, screen);
    assert.ok(!screen.includes(body) && !screen.includes(body.slice(8, 16)), "the terminal shows no byte of the key");
    const change = (await s.admin.policyChanges(1)).changes[0]!;
    assert.equal(change.via, "agent-tighten", "applied on the data socket (the agent's channel), as a tightening");
    assert.equal(change.proposedBy, "mandu:scan");

    const after = await launch(s, reads);
    assert.notEqual(after.out.show!.status, 0, "git show of the deleted key fails");
    assert.match(after.out.show!.text, /bad object/, after.out.show!.text);
    for (const [name, o] of Object.entries(after.out)) assert.ok(!o.text.includes(body), `${name}: the key is absent from the agent's world`);
    assert.equal(after.out.cat!.text, "project readme\n");
    assert.doesNotMatch(after.log, /possible keys? in this project/, "nothing waits: the launch prints no suggestion line");
    for (const b of await toModel(s, texts(after.out))) assert.ok(!b.includes(body), "no request to the model holds the key's bytes");
  } finally {
    await s.close();
  }
});

test("K12 (the workspace scan, plan 14 §13.7): a token in deploy/staging.tfvars reaches the model before; `mandu policy suggest` applies the workspace suggestion on the data socket; on relaunch the file is confined, no request holds the token and no notice prints", { skip, timeout: 300_000 }, async () => {
  const s = await stack("mandu-ws-scan-");
  // A GitHub-token shape (assembled: no token literal here) in a file the
  // catalog misses (`.env.staging` would be the catalog's, `shape:.env*`;
  // a `.conf` the content tier's, secret-discovery.md §2.9).
  const body = ["K12", "WORKSPACE", "TOKEN", "7731", "Hv9q".repeat(5)].join("");
  const token = "gh" + "p_" + body;
  const file = join(s.ws, "deploy", "staging.tfvars");
  try {
    writeFileSync(join(s.ws, "README.md"), "project readme\n");
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "init");
    // On disk, never committed: only the workspace scan can find it.
    mkdirSync(join(s.ws, "deploy"));
    writeFileSync(file, `api_token = "${token}"\n`);
    const reads = { conf: "cat deploy/staging.tfvars", cat: "cat README.md", status: "git status --porcelain" };
    // A budget the scan finishes within, so the notice is deterministic here.
    const env = { MANDU_SUGGEST_WAIT_MS: "20000" };

    // Before: the boundary of `secrets` mode, asserted as such.
    const before = await launch(s, reads, { env });
    assert.ok(before.out.conf!.text.includes(token), `boundary: the confined launch reads the token from the file\n${before.out.conf!.text}`);
    assert.ok((await toModel(s, texts(before.out))).some((b) => b.includes(body)), "boundary: with no rule the token reaches the model raw");
    // The launch's own scan (no `sources`: both run) filed it, and said so.
    assert.match(before.log, /^mandu: 1 possible key in this project is not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard$/m, before.log);
    assert.ok(!before.log.includes(body), "the launch's log holds no byte of the token");

    // The person runs `mandu policy suggest` in a terminal and presses `a`:
    // the production deps (suggestPolicy and applySuggestion over the DATA
    // socket), only the arbiter lookup and the keys injected.
    const out: string[] = [];
    const keys = ["a"];
    const code = await runPolicySuggest([], { HOME: s.home, NO_COLOR: "1" }, {} as Layout, {
      ...realPolicySuggestDeps(),
      arbiter: async () => ({ sock: s.sock, kind: "resident" as const, axisOn: true, stop: async () => {} }),
      cwd: () => s.ws,
      isTTY: () => true,
      readKey: async () => keys.shift() ?? "",
      readLine: async () => "",
      out: (t) => out.push(t),
      err: (t) => out.push(t),
    });
    const screen = out.join("");
    assert.equal(code, 0, screen);
    assert.match(screen, /\[1\/1\] Make .*deploy\/staging\.tfvars a secret no AI may read\n/, screen);
    assert.match(screen, /looks like a GitHub token · ghp_… \(line 1\)\n {6}hides: this file, from the next launch\n {6}If an AI session read this file before, rotate the key\.\n/, screen);
    assert.match(screen, /Applied \(change pc-\d+;/, screen);
    assert.ok(!screen.includes(body) && !screen.includes(body.slice(8, 16)), "the terminal shows no byte of the token");
    const change = (await s.admin.policyChanges(1)).changes[0]!;
    assert.equal(change.via, "agent-tighten", "applied on the data socket (the agent's channel), as a tightening");
    assert.equal(change.proposedBy, "mandu:scan");
    const law = (await s.admin.policyDocument()).inForce as { paths?: Array<{ path: string; level: string }> };
    assert.deepEqual(law.paths?.find((p) => p.path === file), { path: file, level: "no-model" }, "the law shows the workspace file's lock-path");

    const after = await launch(s, reads, { env });
    for (const [name, o] of Object.entries(after.out)) assert.ok(!o.text.includes(body), `${name}: the token is absent from the agent's world`);
    assert.match(after.out.conf!.text, /^api_token = "\$MDU:\S+"\n$/,`the file reads with a placeholder in the token's place\n${after.out.conf!.text}`);
    assert.equal(after.out.cat!.text, "project readme\n", "every other file reads as before");
    assert.doesNotMatch(after.log, /possible keys? in this project/, "nothing waits: the launch prints no suggestion line");
    assert.ok(!after.log.includes(body), "the launch's log holds no byte of the token");
    for (const b of await toModel(s, texts(after.out))) assert.ok(!b.includes(body), "no request to the model holds the token's bytes");
    assert.equal(readFileSync(file, "utf8"), `api_token = "${token}"\n`, "the person's file is unchanged on disk");
  } finally {
    await s.close();
  }
});

test("K13 (sensitivity labels, plan 14 §14.1): a labelled document's text reaches the model before; with the label mapped to no-model, `mandu policy suggest` applies its suggestion on the data socket; on relaunch the document reads as a placeholder and no request holds its text", { skip, timeout: 300_000 }, async () => {
  const s = await stack("mandu-labels-");
  const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
  const TENANT = "5b3c2d4e-1111-4222-8333-444455556666";
  // The document's text: a canary stored uncompressed, so a raw read shows it.
  const body = ["K13", "BOARD", "MINUTES", "7731", "Qd4r".repeat(5)].join("");
  const file = join(s.ws, "board", "q3-board.docx");
  try {
    writeFileSync(join(s.ws, "README.md"), "project readme\n");
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "init");
    mkdirSync(join(s.ws, "board"));
    writeFileSync(file, buildOfficeFile({ labelInfo: [{ id: HC, site: TENANT }], body, stored: true }));
    // The person maps the tenant's label (a new mapping above public: a tightening).
    const mapped = await s.admin.policyPropose({ edits: [{ op: "map-sensitivity-label", id: HC, site: TENANT, name: "Highly Confidential", level: "no-model" }], reason: "K13" });
    assert.equal(mapped.applied, true, JSON.stringify(mapped));
    const reads = { doc: "cat board/q3-board.docx", cat: "cat README.md" };
    const env = { MANDU_SUGGEST_WAIT_MS: "20000" };

    // Before: the boundary of `secrets` mode, asserted as such.
    const before = await launch(s, reads, { env });
    assert.ok(before.out.doc!.text.includes(body), "boundary: the confined launch reads the document's text");
    assert.ok((await toModel(s, texts(before.out))).some((b) => b.includes(body)), "boundary: with no rule the text reaches the model raw");
    assert.match(before.log, /^mandu: 1 labelled document in this project is not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard$/m, before.log);
    assert.ok(!before.log.includes(body), "the launch's log holds no byte of the document");

    const out: string[] = [];
    const keys = ["a"];
    const code = await runPolicySuggest([], { HOME: s.home, NO_COLOR: "1" }, {} as Layout, {
      ...realPolicySuggestDeps(),
      arbiter: async () => ({ sock: s.sock, kind: "resident" as const, axisOn: true, stop: async () => {} }),
      cwd: () => s.ws,
      isTTY: () => true,
      readKey: async () => keys.shift() ?? "",
      readLine: async () => "",
      out: (t) => out.push(t),
      err: (t) => out.push(t),
    });
    const screen = out.join("");
    assert.equal(code, 0, screen);
    assert.match(screen, /\[1\/1\] Make .*board\/q3-board\.docx a secret no AI may read: its sensitivity label is Highly Confidential\n/, screen);
    assert.match(screen, /Applied \(change pc-\d+;/, screen);
    assert.ok(!screen.includes(body), "the terminal shows no byte of the document");
    const change = (await s.admin.policyChanges(1)).changes[0]!;
    assert.equal(change.via, "agent-tighten", "applied on the data socket (the agent's channel), as a tightening");
    assert.equal(change.proposedBy, "mandu:scan");

    const after = await launch(s, reads, { env });
    for (const [name, o] of Object.entries(after.out)) assert.ok(!o.text.includes(body), `${name}: the document's text is absent from the agent's world`);
    assert.match(after.out.doc!.text, /^\$MDU:\S+\s*$/, `the document reads as one placeholder\n${after.out.doc!.text.slice(0, 200)}`);
    assert.equal(after.out.cat!.text, "project readme\n", "every other file reads as before");
    assert.doesNotMatch(after.log, /labelled documents? in this project/, "nothing waits: the launch prints no suggestion line");
    for (const b of await toModel(s, texts(after.out))) assert.ok(!b.includes(body), "no request to the model holds the document's text");
  } finally {
    await s.close();
  }
});

/** The object store's pack(s) of the workspace, for `stat -L` checks. */
const packsOf = (ws: string): string => git(ws, "rev-parse", "--git-path", "objects/pack").trim();

test("K4 (guard only, §7.2a): after lock-path, with no bind the guard answers a stat of the twinned pack with the twin's size, so git reads every other object and the log; the gone key is a bad object and reaches no model", { skip: skipGuard, timeout: 300_000 }, async () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const s = await stack("mandu-c17-gone-guard-");
  try {
    writeFileSync(join(s.ws, "README.md"), "project readme\n");
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "init");
    mkdirSync(join(s.ws, "deploy"));
    writeFileSync(join(s.ws, "deploy", "id_rsa"), `${DEPLOY_KEY}\n`);
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "add deploy key");
    const added = git(s.ws, "rev-parse", "HEAD").trim();
    git(s.ws, "rm", "-rq", "deploy");
    git(s.ws, "commit", "-qm", "oops, remove it");
    git(s.ws, "repack", "-adq");
    const r = await s.admin.policyPropose({ edits: [{ op: "lock-path", path: join(s.ws, "deploy", "id_rsa"), level: "no-model" }], reason: "C17", requestedBy: "dashboard" });
    assert.equal((r as { applied?: boolean }).applied, true, JSON.stringify(r));
    const pack = `${packsOf(s.ws)}/*.pack`;
    const after = await launch(s, {
      show: `git show ${added}:deploy/id_rsa`,
      log: "git log -p",
      oneline: "git log --oneline",
      head: "git show HEAD:README.md",
      cat: "cat README.md",
      // A reader's stat (following links) and the bytes it reads agree.
      size: `for p in ${pack}; do echo "$(stat -L -c %s "$p") $(wc -c < "$p")"; done`,
    }, { guardOnly: true });
    assert.match(after.log, /bind mount SKIPPED \(--no-secret-bind\)/, `the guard-only posture: ${after.log}`);
    assert.notEqual(after.out.show!.status, 0, "git show of the deleted key fails");
    assert.match(after.out.show!.text, /bad object/, after.out.show!.text);
    for (const [name, o] of Object.entries(after.out)) {
      assert.ok(!o.text.includes(DEPLOY_KEY), `${name}: the key is absent from the agent's world`);
      assert.doesNotMatch(o.text, /size changed/, `${name}: git keeps the sanitized pack\n${o.text}`);
    }
    assert.equal(after.out.oneline!.status, 0, after.out.oneline!.text);
    assert.equal(after.out.oneline!.text.trim().split("\n").length, 3, `every commit reads: ${after.out.oneline!.text}`);
    assert.match(after.out.log!.text, /oops, remove it/, "the log itself still runs");
    assert.equal(after.out.head!.text, "project readme\n", "every other object of the pack reads");
    assert.equal(after.out.cat!.text, "project readme\n");
    const sizes = after.out.size!.text.trim().split("\n");
    assert.ok(sizes.length >= 1 && sizes.every((l) => { const [a, b] = l.split(" "); return a === b; }), `stat -L and the bytes read agree: ${after.out.size!.text}`);
    for (const b of await toModel(s, texts(after.out))) assert.ok(!b.includes(DEPLOY_KEY), "no request to the model holds the key's bytes");
  } finally {
    await s.close();
  }
});

test("K5 (guard only, §7.2a): after lock-blob beside a confined credential, with no bind the current file and HEAD read, the old version is a bad object, and a stat of the credential and of the pack says its twin's size", { skip: skipGuard, timeout: 300_000 }, async () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const s = await stack("mandu-c17-inline-guard-");
  try {
    const cred = join(s.home, ".aws", "credentials");
    mkdirSync(join(s.home, ".aws"), { recursive: true });
    writeFileSync(cred, `[default]\naws_secret_access_key=${RAW_CRED}\n`);
    writeFileSync(join(s.ws, "config.py"), `API_KEY = "${INLINE_KEY}"\n`);
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "inline key");
    const first = git(s.ws, "rev-parse", "HEAD").trim();
    const oldBlob = git(s.ws, "rev-parse", "HEAD:config.py").trim();
    writeFileSync(join(s.ws, "config.py"), "API_KEY = os.environ[\"API_KEY\"]\n");
    git(s.ws, "commit", "-qam", "read it from the environment");
    git(s.ws, "repack", "-adq");
    const r = await s.admin.policyPropose({ edits: [{ op: "lock-blob", blob: `sha1:${oldBlob}`, level: "no-model", note: "found in history: config.py" }], reason: "inline key", requestedBy: "dashboard" });
    assert.equal((r as { applied?: boolean }).applied, true, JSON.stringify(r));
    const pack = `${packsOf(s.ws)}/*.pack`;
    const after = await launch(s, {
      show: `git show ${first}:config.py`,
      log: "git log -p",
      head: "git show HEAD:config.py",
      cat: "cat config.py",
      cred: `cat '${cred}'`,
      credSize: `echo "$(stat -L -c %s '${cred}') $(wc -c < '${cred}')"`,
      size: `for p in ${pack}; do echo "$(stat -L -c %s "$p") $(wc -c < "$p")"; done`,
    }, { guardOnly: true });
    assert.match(after.log, /bind mount SKIPPED \(--no-secret-bind\)/, `the guard-only posture: ${after.log}`);
    assert.notEqual(after.out.show!.status, 0);
    assert.match(after.out.show!.text, /bad object/, after.out.show!.text);
    for (const [name, o] of Object.entries(after.out)) {
      assert.ok(!o.text.includes(INLINE_KEY), `${name}: the old version is gone from every read`);
      assert.ok(!o.text.includes(RAW_CRED), `${name}: the credential's real bytes are never read`);
      assert.doesNotMatch(o.text, /size changed/, `${name}\n${o.text}`);
    }
    assert.equal(after.out.head!.text, "API_KEY = os.environ[\"API_KEY\"]\n", "the current file's version reads normally");
    assert.equal(after.out.cat!.text, "API_KEY = os.environ[\"API_KEY\"]\n");
    const [statSize, readSize] = after.out.credSize!.text.trim().split(" ");
    assert.equal(statSize, readSize, `a stat of the credential says the placeholder copy's size: ${after.out.credSize!.text}`);
    assert.notEqual(Number(statSize), readFileSync(cred).length, "and not the real file's");
    assert.ok(after.out.size!.text.trim().split("\n").every((l) => { const [a, b] = l.split(" "); return a === b; }), after.out.size!.text);
    for (const b of await toModel(s, texts(after.out))) {
      assert.ok(!b.includes(INLINE_KEY), "no request to the model holds the inline key");
      assert.ok(!b.includes(RAW_CRED), "nor the confined credential");
    }
  } finally {
    await s.close();
  }
});

// ── Plan 14 §11.1 R4: the guard's backstop in a repository the launch did not prepare ──

/** Every event line under the arbiter's event dir that mentions `needle`. */
function eventLines(s: Stack, needle: string): string[] {
  const evDir = join(s.dir, "events");
  if (!existsSync(evDir)) return [];
  const out: string[] = [];
  for (const f of readdirSync(evDir, { recursive: true }) as string[]) {
    if (!f.endsWith(".ndjson")) continue;
    for (const l of readFileSync(join(evDir, f), "utf8").split("\n")) if (l.includes(needle)) out.push(l);
  }
  return out;
}

/**
 * K6/K7: a key committed to repository A and deleted, locked by id
 * (`lock-blob`); the launch is in B, the workspace, which holds nothing
 * locked. A is none of the repositories the launch prepares (not the
 * workspace, no confined file, no labelled path in it), so it has no
 * sanitized copy: the guard refuses its object files. A fork of A (a clone
 * with its own pack) the same; a third repository with nothing locked reads
 * as before. The notice names A and the fork once each, the dashboard's
 * event names A, and no request to the model holds the key.
 */
async function backstop(posture: "guard-only" | "bind"): Promise<string> {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const s = await stack(`mandu-r4-${posture}-`);
  const key = ["R4", "BACKSTOP", "KEY", "7731", "Qv".repeat(16)].join("_");
  try {
    // A catalog credential in HOME: the launch confines a file, so the bind
    // posture has a twin to bind (the guard serves it in the other).
    mkdirSync(join(s.home, ".aws"), { recursive: true });
    writeFileSync(join(s.home, ".aws", "credentials"), `[default]\naws_secret_access_key=${RAW_CRED}\n`);
    writeFileSync(join(s.ws, "README.md"), "workspace readme\n");
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "workspace");
    const a = join(realpathSync(s.dir), "a");
    git(s.dir, "init", "-q", a);
    writeFileSync(join(a, "README.md"), "readme of a\n");
    writeFileSync(join(a, "id_rsa"), `${key}\n`);
    git(a, "add", ".");
    git(a, "commit", "-qm", "add a key");
    const blob = git(a, "rev-parse", "HEAD:id_rsa").trim();
    git(a, "rm", "-q", "id_rsa");
    git(a, "commit", "-qm", "oops, remove it");
    git(a, "repack", "-adq");
    const fork = join(realpathSync(s.dir), "fork");
    git(s.dir, "clone", "-q", "--no-local", a, fork);
    const clean = join(realpathSync(s.dir), "clean");
    git(s.dir, "init", "-q", clean);
    writeFileSync(join(clean, "notes.txt"), "nothing locked here\n");
    git(clean, "add", ".");
    git(clean, "commit", "-qm", "clean");
    git(clean, "repack", "-adq");
    // An agent's own git store holding the key: OpenCode's snapshot history
    // (a bare repository per project under ~/.local/share/opencode/snapshot),
    // as the first-session tour met it. Refused like A, but said apart.
    const snap = join(s.home, ".local", "share", "opencode", "snapshot", "global", "0a1b2c3d");
    mkdirSync(join(snap, ".."), { recursive: true });
    git(s.dir, "clone", "-q", "--bare", "--no-local", a, snap);
    // Git's files of objects being written by a program outside the session
    // (2026-10-17): a `git gc` the person runs in A writes every object,
    // the locked one included, as `tmp_pack_*` before it has an index; a
    // loose write is `tmp_obj_*`. Planted as such a writer leaves them.
    const tmpPack = join(a, ".git", "objects", "pack", "tmp_pack_Ab12Cd");
    const aPack = readdirSync(join(a, ".git", "objects", "pack")).find((n) => n.endsWith(".pack"))!;
    writeFileSync(tmpPack, readFileSync(join(a, ".git", "objects", "pack", aPack)));
    const keyBody = Buffer.from(`${key}\n`);
    mkdirSync(join(a, ".git", "objects", blob.slice(0, 2)), { recursive: true });
    const tmpObj = join(a, ".git", "objects", blob.slice(0, 2), "tmp_obj_Zz99Yy");
    writeFileSync(tmpObj, deflateSync(Buffer.concat([Buffer.from(`blob ${keyBody.length}\0`), keyBody])));
    // Not vacuous: read raw outside the session, both hold the key.
    for (const f of [tmpPack, tmpObj]) assert.ok(execFileSync("sh", ["-c", `${INFLATE_FILE} '${f}'`], { encoding: "latin1" }).includes(key), f);
    const r = await s.admin.policyPropose({ edits: [{ op: "lock-blob", blob: `sha1:${blob}`, level: "no-model", note: "found in history: a/id_rsa" }], reason: "R4", requestedBy: "dashboard" });
    assert.equal((r as { applied?: boolean }).applied, true, JSON.stringify(r));

    const run = await launch(s, {
      alog: `git -C '${a}' log -p`,
      ashow: `git -C '${a}' cat-file -p ${blob}`,
      acat: `cat '${a}'/.git/objects/pack/*.pack`,
      flog: `git -C '${fork}' log -p`,
      fcat: `cat '${fork}'/.git/objects/pack/*.pack`,
      slog: `git --git-dir='${snap}' log -p`,
      clog: `git -C '${clean}' log -p`,
      wlog: "git log -p",
      cred: `cat '${join(s.home, ".aws", "credentials")}'`,
      // After A's first refusal (the notice tells each repository's first):
      // git's files in progress, read raw and inflated: refused, no byte of
      // the key.
      tpack: `${INFLATE_FILE} '${tmpPack}'`,
      tobj: `${INFLATE_FILE} '${tmpObj}'`,
      tcat: `cat '${tmpPack}'`,
      // The session's own git writes and reads its temporary files under
      // the lock: a clone (index-pack), a fetch unpacked loose, a loose write.
      own: `git clone -q --no-local '${clean}' '${s.ws}/own-clone' && git -C '${s.ws}/own-clone' log -p`,
      ownfetch: `git init -q '${s.ws}/own-fetch' && git -C '${s.ws}/own-fetch' -c fetch.unpackLimit=100000 fetch -q '${clean}' HEAD && git -C '${s.ws}/own-fetch' log -p FETCH_HEAD`,
      ownobj: `echo own-object | git -C '${s.ws}/own-fetch' hash-object -w --stdin | xargs git -C '${s.ws}/own-fetch' cat-file -p`,
    }, posture === "guard-only" ? { guardOnly: true } : { guard: true });
    if (posture === "guard-only") assert.match(run.log, /bind mount SKIPPED \(--no-secret-bind\)/, run.log);
    else assert.doesNotMatch(run.log, /--no-secret-bind/, run.log);
    const all = Object.entries(run.out).map(([n, o]) => `${n} [${o.status}]: ${o.text.slice(0, 300)}`).join("\n");
    for (const [name, o] of Object.entries(run.out)) {
      assert.ok(!o.text.includes(key), `${name}: the locked key is absent from the agent's world\n${all}`);
      assert.ok(!o.text.includes(RAW_CRED), `${name}: the confined credential too`);
    }
    for (const n of ["alog", "ashow", "acat", "flog", "fcat", "slog", "tpack", "tobj", "tcat"]) assert.notEqual(run.out[n]!.status, 0, `${n}: refused\n${all}`);
    assert.match(run.out.acat!.text, /Permission denied/, all);
    assert.match(run.out.fcat!.text, /Permission denied/, all);
    assert.match(run.out.tcat!.text, /Permission denied/, all);
    assert.ok(!run.out.tcat!.text.startsWith("PACK"), all);
    for (const n of ["own", "ownfetch", "ownobj"]) assert.equal(run.out[n]!.status, 0, `${n}: the session's own git works under the lock\n${all}`);
    assert.match(run.out.own!.text, /nothing locked here/, all);
    assert.match(run.out.ownfetch!.text, /nothing locked here/, all);
    assert.match(run.out.ownobj!.text, /own-object/, all);
    // What holds nothing locked is untouched.
    assert.equal(run.out.clog!.status, 0, all);
    assert.match(run.out.clog!.text, /nothing locked here/, all);
    assert.equal(run.out.wlog!.status, 0, all);
    assert.match(run.out.wlog!.text, /workspace readme/, all);
    // The person is told, once per repository, after the session.
    assert.match(run.log, /git was refused in these 2 repositories for the session/, run.log);
    assert.equal(run.log.split("\n").filter((l) => l === `  ${a}`).length, 1, run.log);
    assert.equal(run.log.split("\n").filter((l) => l === `  ${fork}`).length, 1, run.log);
    assert.ok(!run.log.includes(`  ${clean}`), run.log);
    // OpenCode's snapshot store is said apart: what it is, nothing to do,
    // never the repository advice (it is not one of the person's).
    assert.match(run.log, /mandu: OpenCode's own snapshot history \(the copy of your files it keeps for undo\) holds a file you marked secret/, run.log);
    assert.equal(run.log.split("\n").filter((l) => /^ {2}\S*\/opencode\/snapshot\/global\/0a1b2c3d$/.test(l)).length, 1, run.log);
    assert.match(run.log, /Nothing needs doing: it is OpenCode's own store/, run.log);
    assert.ok(!run.log.includes(`  ${snap}\n  To work in one`), run.log);
    assert.ok(!run.log.includes(key), "the notice holds no byte of the key");
    // The dashboard's event names A (the repository and the file, never a byte).
    const ev = eventLines(s, "git-lock");
    assert.ok(ev.some((l) => l.includes(a) && !l.includes(key)), `an event names ${a}: ${ev.join("\n")}`);
    for (const b of await toModel(s, texts(run.out))) assert.ok(!b.includes(key), "no request to the model holds the key's bytes");
    // R1: the refusal registered A (and the fork) with the arbiter's known
    // repositories: asking again adds nothing; the clean one was never named.
    const again = (root: string) => ndjsonCall<{ added: boolean; root: string | null }>(s.sock, "registerRepository", { root }, 10_000);
    assert.equal((await again(a)).added, false, "the guard or the launcher registered A");
    assert.equal((await again(fork)).added, false, "and the fork");
    assert.equal((await again(clean)).added, true, "a repository nothing refused was not registered");
    return run.log;
  } finally {
    await s.close();
  }
}

test("K6 (plan 14 §11.1 R4, guard only): a key locked by id in a repository the launch did not prepare, and in a fork of it, is refused by the guard; a clean repository reads; the notice and the event name the repository", { skip: skipGuard, timeout: 300_000 }, async () => {
  await backstop("guard-only");
});

test("K7 (plan 14 §11.1 R4, guard and bind): the same with the mount layer up beside the guard", { skip: skipGuard || skip, timeout: 300_000 }, async (t) => {
  const log = await backstop("bind");
  // A host whose bubblewrap forbids nesting runs the guard alone (the
  // launcher's own choice, rootless-confinement §12.3): said, not failed.
  if (/the mount layer is off/.test(log)) t.diagnostic("this host's bubblewrap forbids nesting: the launch ran guard-only");
  else assert.match(log, /confined via symbolized twins/, log);
});

/** Every zlib stream in the object-store packs, inflated: what a program
 *  that reads a pack's raw bytes (not through git) gets. Run inside the
 *  confined launch. */
const INFLATE_PACKS = `python3 -c 'import glob,sys,zlib
for p in glob.glob(".git/objects/pack/*.pack"):
    b=open(p,"rb").read()
    for i in range(12,len(b)-2):
        if b[i]!=0x78: continue
        try: sys.stdout.write(zlib.decompressobj().decompress(b[i:]).decode("latin1")+"\\n")
        except Exception: pass'`;

/** Every zlib stream in ONE file (its path the argument), inflated: a pack
 *  or a loose object read raw, not through git. */
const INFLATE_FILE = `python3 -c 'import sys,zlib
b=open(sys.argv[1],"rb").read()
for i in range(0,len(b)-2):
    if b[i]!=0x78: continue
    try: sys.stdout.write(zlib.decompressobj().decompress(b[i:]).decode("latin1")+"\\n")
    except Exception: pass'`;

test("K8 (plan 14 §11.2, a planted pack): the real pack's bytes planted under the sanitized copy's clean .idx are never served; the relaunch rebuilds, git show is a bad object and the raw pack holds no key", { skip, timeout: 300_000 }, async (t) => {
  const s = await stack("mandu-c17-planted-", { human: true });
  try {
    writeFileSync(join(s.ws, "README.md"), "project readme\n");
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "init");
    mkdirSync(join(s.ws, "deploy"));
    writeFileSync(join(s.ws, "deploy", "id_rsa"), `${DEPLOY_KEY}\n`);
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "add deploy key");
    const added = git(s.ws, "rev-parse", "HEAD").trim();
    git(s.ws, "rm", "-rq", "deploy");
    git(s.ws, "commit", "-qm", "oops, remove it");
    git(s.ws, "repack", "-adq");
    const r = await s.admin.policyPropose({ edits: [{ op: "lock-path", path: join(s.ws, "deploy", "id_rsa"), level: "no-model" }], reason: "C17", requestedBy: "dashboard" });
    assert.equal((r as { applied?: boolean }).applied, true, JSON.stringify(r));
    const reads = { show: `git show ${added}:deploy/id_rsa`, log: "git log -p", head: "git show HEAD:README.md", raw: INFLATE_PACKS };

    const first = await launch(s, reads, { guard: true });
    assert.match(first.out.show!.text, /bad object/, first.out.show!.text);
    for (const [name, o] of Object.entries(first.out)) assert.ok(!o.text.includes(DEPLOY_KEY), `${name}: hidden in the first launch`);
    assert.ok(first.out.raw!.text.includes("project readme"), `the raw read does inflate the pack (the probe works): ${first.out.raw!.text.slice(0, 400)}`);

    // What the first launch left in the cache, and whether its seals stand
    // (a confined launch leaves them; an unconfined one voids them at its end).
    const cacheRoot = join(s.home, ".mandu", "cache", "object-twins");
    const keyDir = readdirSync(cacheRoot).find((n) => !n.startsWith("."))!;
    const packName = readdirSync(join(cacheRoot, keyDir)).find((n) => n.endsWith(".pack"))!;
    const sealKey = `${keyDir}/${packName}`;
    const sealed = (await s.admin.cacheSeals("object-twin", [sealKey])).seals.length === 1;
    t.diagnostic(`the first launch left its seal: ${sealed} (a confined launch does; confined needs the guard)`);
    // With a fresh guard the launch is confined (secrets, the guard, write
    // protection): its seal stands, and the planted pack must FAIL it.
    if (GUARD && PICK.stale === null) assert.equal(sealed, true, `a confined launch leaves its seal: ${first.log}`);

    // An unconfined writer plants the REAL pack (it holds the key) under the
    // sanitized name, keeping the sanitized .idx, which lists no protected
    // version: before the seals, the relaunch served it.
    const realDir = join(s.ws, ".git", "objects", "pack");
    const real = join(realDir, readdirSync(realDir).find((n) => n.endsWith(".pack"))!);
    const planted = join(cacheRoot, keyDir, packName);
    rmSync(planted);
    writeFileSync(planted, readFileSync(real));

    const second = await launch(s, reads, { guard: true });
    assert.match(second.out.show!.text, /bad object/, second.out.show!.text);
    for (const [name, o] of Object.entries(second.out)) assert.ok(!o.text.includes(DEPLOY_KEY), `${name}: the planted pack is not served`);
    assert.equal(second.out.head!.text, "project readme\n", "every other object reads");
    assert.ok(second.out.raw!.text.includes("project readme"), "the raw read inflates the pack served");
    assert.match(second.log, /pack\(s\) sanitized/, `the relaunch rebuilt the pack: ${second.log}`);
    if (sealed) {
      assert.match(second.log, /did not match its seal and was rebuilt/, `a confined first launch left a seal, which the planted pack fails: ${second.log}`);
      const events = await s.admin.events("arbiter-admin");
      assert.ok(events.some((e) => JSON.stringify(e).includes("\"reason\":\"mismatch\"") && JSON.stringify(e).includes(sealKey)), "the arbiter names the entry");
    }
    for (const b of await toModel(s, texts(second.out))) assert.ok(!b.includes(DEPLOY_KEY), "no request to the model holds the key's bytes");
  } finally {
    await s.close();
  }
});

/** K9-K11: every zlib stream of one repository's packs, inflated, read
 *  inside the confined launch (what a program reading the pack's raw bytes,
 *  not through git, gets). */
const inflateRepo = (repo: string): string => INFLATE_PACKS.replace('glob.glob(".git/objects/pack/*.pack")', `glob.glob("${repo}/.git/objects/pack/*.pack")`);

/**
 * K9-K11 (plan 14 §11.1 R3): K6's repositories (a key locked by id in A, a
 * fork of A, a clean repository; the launch in B, the workspace), with the
 * arbiter preparing sanitized copies in the background. The first launch is
 * refused in A and the fork as in K6 (no copy yet); the guard and the
 * launcher register both. The arbiter then prepares and seals their copies.
 * The second launch in B serves them: `git -C A log -p` reads the history,
 * the locked version is a bad object, a `cat` of A's pack succeeds and its
 * raw bytes, inflated, hold no byte of the key; the same in the fork; no
 * notice; no model request holds the key. With the cycle cap at 0 (K11)
 * nothing is prepared, the arbiter says the repositories are capped, and
 * the second launch is refused exactly as the first.
 */
async function preparedCopies(posture: "guard-only" | "bind", cycleMB?: number): Promise<string> {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const s = await stack(`mandu-r3-${posture}-`, { human: true, prepared: cycleMB !== undefined ? { cycleMB } : {} });
  const key = ["R3", "PREPARED", "KEY", "7731", "Kp".repeat(16)].join("_");
  try {
    writeFileSync(join(s.ws, "README.md"), "workspace readme\n");
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "workspace");
    const a = join(realpathSync(s.dir), "a");
    git(s.dir, "init", "-q", a);
    writeFileSync(join(a, "README.md"), "readme of a\n");
    writeFileSync(join(a, "id_rsa"), `${key}\n`);
    git(a, "add", ".");
    git(a, "commit", "-qm", "add a key");
    const blob = git(a, "rev-parse", "HEAD:id_rsa").trim();
    git(a, "rm", "-q", "id_rsa");
    git(a, "commit", "-qm", "oops, remove it");
    git(a, "repack", "-adq");
    const fork = join(realpathSync(s.dir), "fork");
    git(s.dir, "clone", "-q", "--no-local", a, fork);
    const clean = join(realpathSync(s.dir), "clean");
    git(s.dir, "init", "-q", clean);
    writeFileSync(join(clean, "notes.txt"), "nothing locked here\n");
    git(clean, "add", ".");
    git(clean, "commit", "-qm", "clean");
    const r = await s.admin.policyPropose({ edits: [{ op: "lock-blob", blob: `sha1:${blob}`, level: "no-model", note: "found in history: a/id_rsa" }], reason: "R3", requestedBy: "dashboard" });
    assert.equal((r as { applied?: boolean }).applied, true, JSON.stringify(r));
    const reads = {
      alog: `git -C '${a}' log`,
      aread: `git -C '${a}' show HEAD:README.md`,
      // The patch of the commit that deleted the key needs the locked
      // version: git stops there ("unable to read"), with no byte of it.
      alogp: `git -C '${a}' log -p`,
      ashow: `git -C '${a}' cat-file -p ${blob}`,
      acat: `cat '${a}'/.git/objects/pack/*.pack > /dev/null`,
      araw: inflateRepo(a),
      flog: `git -C '${fork}' log`,
      fraw: inflateRepo(fork),
      clog: `git -C '${clean}' log -p`,
      wlog: "git log -p",
    };
    const opts = posture === "guard-only" ? { guardOnly: true } : { guard: true };
    const check = (run: { out: Record<string, { text: string; status: number }> }): string => {
      const all = Object.entries(run.out).map(([n, o]) => `${n} [${o.status}]: ${o.text.slice(0, 300)}`).join("\n");
      for (const [name, o] of Object.entries(run.out)) assert.ok(!o.text.includes(key), `${name}: the locked key is absent from the agent's world\n${all}`);
      assert.equal(run.out.clog!.status, 0, all);
      assert.equal(run.out.wlog!.status, 0, all);
      return all;
    };

    // Before preparation: refused, as K6.
    const first = await launch(s, reads, opts);
    const all1 = check(first);
    for (const n of ["alog", "aread", "ashow", "acat", "flog"]) assert.notEqual(first.out[n]!.status, 0, `${n}: refused before preparation\n${all1}`);
    assert.match(first.log, /git was refused in these 2 repositories for the session/, first.log);

    // The arbiter prepares in the background (here, awaited).
    await s.server.prepareCopiesNow();
    const answer = await ndjsonCall<{ prepared?: Array<{ root: string }>; preparation?: { capped: Array<{ root: string }> } }>(s.sock, "gitHistoryLocks", {}, 10_000);
    if (cycleMB === 0) {
      assert.deepEqual(answer.prepared, [], "the cycle cap at 0 prepares nothing");
      assert.deepEqual(answer.preparation?.capped.map((c) => c.root).sort(), [a, fork].sort(), "and says so");
    } else {
      assert.deepEqual((answer.prepared ?? []).map((p) => p.root).sort(), [a, fork].sort(), JSON.stringify(answer));
    }

    const second = await launch(s, reads, opts);
    const all2 = check(second);
    for (const b of await toModel(s, texts({ ...first.out, ...second.out }))) assert.ok(!b.includes(key), "no request to the model holds the key's bytes");
    if (cycleMB === 0) {
      for (const n of ["alog", "aread", "ashow", "acat", "flog"]) assert.notEqual(second.out[n]!.status, 0, `${n}: still refused with nothing prepared\n${all2}`);
      assert.match(second.log, /git was refused in these 2 repositories for the session/, second.log);
      return second.log;
    }
    assert.equal(second.out.alog!.status, 0, `git in A works with its prepared copy\n${all2}\n${second.log}`);
    assert.match(second.out.alog!.text, /oops, remove it/, all2);
    assert.match(second.out.alog!.text, /add a key/, all2);
    assert.equal(second.out.aread!.status, 0, all2);
    assert.equal(second.out.aread!.text, "readme of a\n", all2);
    assert.match(second.out.alogp!.text, /oops, remove it/, `the log with patches reads up to the locked version\n${all2}`);
    assert.notEqual(second.out.ashow!.status, 0, all2);
    assert.match(second.out.ashow!.text, /bad object|could not get object info|not a valid object|fatal/i, all2);
    assert.equal(second.out.acat!.status, 0, `a cat of A's pack is served the copy, not refused\n${all2}`);
    assert.match(second.out.araw!.text, /readme of a/, `the raw read inflates the copy served (the probe works)\n${all2}`);
    assert.equal(second.out.flog!.status, 0, `the fork too\n${all2}`);
    assert.match(second.out.fraw!.text, /readme of a/, all2);
    assert.match(second.log, /prepared ahead of time served for 2 other repositories/, second.log);
    assert.doesNotMatch(second.log, /git was refused in/, second.log);
    return second.log;
  } finally {
    await s.close();
  }
}

test("K9 (plan 14 §11.1 R3, guard only): after the arbiter prepared sealed copies, a launch in B runs git in A and its fork; the locked version is a bad object and A's raw pack holds no key; before, it was refused", { skip: skipGuard, timeout: 300_000 }, async () => {
  await preparedCopies("guard-only");
});

test("K10 (plan 14 §11.1 R3, guard and bind): the same with the mount layer binding the prepared copies", { skip: skipGuard || skip, timeout: 300_000 }, async (t) => {
  const log = await preparedCopies("bind");
  if (/the mount layer is off/.test(log)) t.diagnostic("this host's bubblewrap forbids nesting: the launch ran guard-only");
});

test("K11 (plan 14 §11.1 R3, the cycle cap at 0): nothing is prepared, the arbiter says the repositories are capped, and git there stays refused as R4", { skip: skipGuard, timeout: 300_000 }, async () => {
  await preparedCopies("guard-only", 0);
});

test("K14 (plan 14 §11.1 R3, alternates two links deep, confidentiality.md §7.2a): C, a clone --shared of B, itself one of A, registered alone; the arbiter prepares every pack C reads, A's excluding the union; under the wrap git in C works and reads no locked version from any pack", { skip: skipGuard || skip, timeout: 300_000 }, async (t) => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const s = await stack("mandu-r3-chain-", { human: true, prepared: {} });
  const keys = ["X", "W", "Y", "Z"].map((n) => ["K14", n, "CHAIN", "KEY", "7731", "Kc".repeat(14)].join("_"));
  const [keyX, keyW, keyY, keyZ] = keys as [string, string, string, string];
  const commitKey = (root: string, file: string, key: string): string => {
    writeFileSync(join(root, file), `${key}\n`);
    git(root, "add", "."); git(root, "commit", "-qm", `add ${file}`);
    const id = git(root, "rev-parse", `HEAD:${file}`).trim();
    git(root, "rm", "-q", file); git(root, "commit", "-qm", `remove ${file}`);
    return id;
  };
  const packOf = (root: string): string => {
    const d = join(root, ".git", "objects", "pack");
    const n = readdirSync(d).filter((x) => x.endsWith(".pack"));
    assert.equal(n.length, 1, root);
    return join(d, n[0]!.slice(0, -5));
  };
  try {
    writeFileSync(join(s.ws, "README.md"), "workspace readme\n");
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "workspace");
    const top = realpathSync(s.dir);
    // A ← B ← C: each a `clone --shared` of the one before, repacked LOCAL,
    // so A's versions stay in A's pack and C reaches them only through B's
    // alternates file. A's pack holds two locked versions (X, W).
    const a = join(top, "a");
    git(top, "init", "-q", a);
    writeFileSync(join(a, "README"), "readme of a\n");
    git(a, "add", "."); git(a, "commit", "-qm", "readme");
    const x = commitKey(a, "id_rsa", keyX);
    const w = commitKey(a, "staging.env", keyW);
    git(a, "repack", "-adq");
    const b = join(top, "b");
    git(top, "clone", "-q", "--shared", a, b);
    const y = commitKey(b, "id_b", keyY);
    git(b, "repack", "-adlq");
    const c = join(top, "c");
    git(top, "clone", "-q", "--shared", b, c);
    const z = commitKey(c, "id_c", keyZ);
    git(c, "repack", "-adlq");
    assert.equal(readFileSync(join(c, ".git", "objects", "info", "alternates"), "utf8").trim(), join(b, ".git", "objects"), "C names B only");
    const ids = [x, w, y, z];
    const r = await s.admin.policyPropose({
      edits: ids.map((id, i) => ({ op: "lock-blob" as const, blob: `sha1:${id}`, level: "no-model", note: `K14 ${i}` })), reason: "K14", requestedBy: "dashboard",
    });
    assert.equal((r as { applied?: boolean }).applied, true, JSON.stringify(r));
    // C alone is known (A and B are not): before the closure followed an
    // alternate's alternates, A's pack got no copy and git in C fell to the
    // backstop.
    const data = new ArbiterClient(s.sock);
    await data.connect();
    try { assert.equal((await data.registerRepository(c)).added, true); } finally { data.close(); }
    await s.server.prepareCopiesNow();
    const answer = await ndjsonCall<{ prepared?: Array<{ root: string }> }>(s.sock, "gitHistoryLocks", {}, 10_000);
    assert.deepEqual((answer.prepared ?? []).map((p) => p.root), [c], JSON.stringify(answer));
    // A's copy: keyed by the union of the locked versions its pack holds, and
    // its index lists none of them.
    const cacheDir = join(s.home, ".mandu", "cache", "object-twins");
    const aKey = rebuildKey(packOf(a), [x, w]);
    // Run red on the code before the closure (2026-10-17, confidentiality.md
    // §7.2a): A's key directory was never made, so this reads as a missing
    // copy (and, past it, git in C was refused for the session).
    const aIdx = existsSync(join(cacheDir, aKey)) ? readdirSync(join(cacheDir, aKey)).find((n) => n.endsWith(".idx")) : undefined;
    assert.ok(aIdx, `A's pack has its copy under the union key: ${readdirSync(cacheDir).join(", ")}`);
    assert.deepEqual(idxLookupFile(join(cacheDir, aKey, aIdx!), ids), [], "the copy's index lists no locked id");

    const reads = {
      clog: `git -C '${c}' log --format=%s`,
      cread: `git -C '${c}' show HEAD:README`,
      clogp: `git -C '${c}' log -p`,
      cx: `git -C '${c}' cat-file -p ${x}`,
      cw: `git -C '${c}' cat-file -p ${w}`,
      cy: `git -C '${c}' cat-file -p ${y}`,
      cz: `git -C '${c}' cat-file -p ${z}`,
      araw: inflateRepo(a),
      braw: inflateRepo(b),
      craw: inflateRepo(c),
      wlog: "git log -p",
    };
    const run = await launch(s, reads, { guard: true });
    const all = Object.entries(run.out).map(([n, o]) => `${n} [${o.status}]: ${o.text.slice(0, 300)}`).join("\n");
    for (const [name, o] of Object.entries(run.out)) for (const k of keys) assert.ok(!o.text.includes(k), `${name}: no locked version in the agent's world\n${all}`);
    assert.equal(run.out.clog!.status, 0, `git in C works with the copies prepared two links deep\n${all}\n${run.log}`);
    assert.match(run.out.clog!.text, /remove id_c/, all);
    assert.match(run.out.clog!.text, /remove staging\.env/, "A's history, read through B, reads");
    assert.equal(run.out.cread!.status, 0, all);
    assert.equal(run.out.cread!.text, "readme of a\n", all);
    for (const n of ["cx", "cw", "cy", "cz"]) assert.notEqual(run.out[n]!.status, 0, `${n}: a locked version is read from no pack\n${all}`);
    assert.match(run.out.araw!.text, /readme of a/, `A's pack, read raw, is the copy (the probe works)\n${all}`);
    assert.equal(run.out.wlog!.status, 0, all);
    assert.match(run.log, /prepared ahead of time served for 1 other repository/, run.log);
    assert.doesNotMatch(run.log, /git was refused in/, run.log);
    if (/the mount layer is off/.test(run.log)) t.diagnostic("this host's bubblewrap forbids nesting: the launch ran guard-only");
    for (const body of await toModel(s, texts(run.out))) for (const k of keys) assert.ok(!body.includes(k), "no request to the model holds a locked version");
  } finally {
    await s.close();
  }
});

/**
 * K15 (OpenCode's snapshot store, 2026-10-11): OpenCode keeps a git history
 * of the files it works on (for undo) in its own data folder: a git
 * directory per project under ~/.local/share/opencode/snapshot, its work
 * tree the project, objects written by `add` + `write-tree` and never
 * referenced (1.18.13's Snapshot service). A copy taken BEFORE the person
 * labelled a file holds the file's real version. This drives that store as
 * OpenCode does, in two launches after the label, with its objects LOOSE
 * (as a short session leaves them) and PACKED (after OpenCode's own `gc`),
 * and pins what happens (confidentiality.md §7.2a "An agent's own git
 * store"):
 *   - the old version never reaches the agent's world; tracking the work
 *     tree (`add` + `write-tree`, which reads the placeholder) works while
 *     the store is loose;
 *   - what reads the older history is refused: the old version's content
 *     (a full diff, `cat-file`) and OpenCode's `gc`; once packed, every read
 *     of the pack: the change list against an older snapshot, and tracking
 *     too (`write-tree` checks that each file's version is in the store, and
 *     an unchanged file's version is only in the refused pack);
 *   - the store is not a work tree, so the arbiter does not register it and
 *     nothing prepares a copy: the exit notice comes back in the second
 *     launch, saying so and how to stop it;
 *   - removed (outside Mandu) and started again by OpenCode, the store holds
 *     only the placeholder: every command works and no notice prints.
 */
async function openCodeSnapshot(packed: boolean): Promise<void> {
  const s = await stack(`mandu-oc-snap-${packed ? "packed" : "loose"}-`);
  const body = ["K15", "SNAPSHOT", "TOKEN", "7731", "Rt4w".repeat(5)].join("");
  const token = "gh" + "p_" + body;
  const file = join(s.ws, "deploy", "staging.conf");
  try {
    writeFileSync(join(s.ws, "README.md"), "project readme\n");
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "init");
    // The unchanged file is older than the store's index, as in a real
    // session. Written in the same second as that index, git takes it for
    // "racily clean" (its racy check is by whole seconds) and hashes it
    // again in the launch's `add`, writing its version loose: tracking a
    // packed store then passed or failed on whether a second boundary fell
    // between this write and the store's first `add` (a CI flake,
    // 2026-10-11).
    const past = new Date(Date.now() - 3_600_000);
    utimesSync(join(s.ws, "README.md"), past, past);
    mkdirSync(join(s.ws, "deploy"));
    writeFileSync(file, `[api]\nAPI_TOKEN=${token}\n`);
    // The store as OpenCode 1.18.13 creates it, outside Mandu (session 1,
    // before the label): `git init` with GIT_DIR and GIT_WORK_TREE, then
    // `add` and `write-tree`.
    const snap = join(s.home, ".local", "share", "opencode", "snapshot", "0123456789abcdef", "fedcba9876543210");
    mkdirSync(snap, { recursive: true });
    const init = `GIT_DIR='${snap}' GIT_WORK_TREE='${s.ws}' git init -q`;
    execFileSync("sh", ["-c", init], { cwd: s.ws, env: GIT_ENV });
    const sg = (...a: string[]): string => git(s.ws, "-c", "core.autocrlf=false", "--git-dir", snap, "--work-tree", s.ws, ...a);
    sg("add", "--all", ".");
    const t0 = sg("write-tree").trim();
    const blob = sg("rev-parse", `${t0}:deploy/staging.conf`).trim();
    if (packed) sg("gc", "-q", "--prune=7.days");
    const r = await s.admin.policyPropose({ edits: [{ op: "lock-path", path: file, level: "no-model" }], reason: "K15", requestedBy: "dashboard" });
    assert.equal((r as { applied?: boolean }).applied, true, JSON.stringify(r));

    const g = `git -c core.autocrlf=false --git-dir='${snap}' --work-tree='${s.ws}'`;
    const reads = {
      // what OpenCode runs at each step, and its change list since t0
      track: `${g} add --all . && ${g} write-tree`,
      names: `${g} diff --cached --no-ext-diff --name-only ${t0} -- .`,
      // the changes with their content: the old version's bytes
      full: `${g} diff --cached --no-ext-diff ${t0} -- .`,
      blob: `${g} cat-file -p ${blob}`,
      // OpenCode's own cleanup
      gc: `${g} gc -q --prune=7.days`,
    };
    const show = (run: { log: string; out: Record<string, { text: string; status: number }> }): string =>
      Object.entries(run.out).map(([n, o]) => `${n} [${o.status}]: ${o.text.slice(0, 300)}`).join("\n") + `\n${run.log}`;
    const notice = (log: string): string[] => log.split("\n").filter((l) => /git was refused|snapshot history|opencode\/snapshot|Nothing needs doing|To work in one/.test(l));
    for (const n of [1, 2]) {
      const run = await launch(s, reads, { guard: true });
      const all = show(run);
      for (const [name, o] of Object.entries(run.out)) assert.ok(!o.text.includes(body), `launch ${n}, ${name}: the token is absent from the agent's world\n${all}`);
      assert.ok(!run.log.includes(body), "the launch's log holds no byte of the token");
      if (!packed) {
        assert.equal(run.out.track!.status, 0, `launch ${n}: tracking the work tree works (it reads the placeholder)\n${all}`);
        assert.equal(run.out.names!.status, 0, `launch ${n}: a loose store's change list reads trees only\n${all}`);
      } else {
        // The unchanged README's version is only in the refused pack.
        assert.notEqual(run.out.track!.status, 0, `launch ${n}: tracking a packed store checks the refused pack\n${all}`);
        assert.match(run.out.track!.text, /invalid object \d+ [0-9a-f]+ for 'README\.md'/, all);
        assert.notEqual(run.out.names!.status, 0, `launch ${n}: a packed store's change list reads the refused pack\n${all}`);
      }
      for (const k of ["full", "blob", "gc"]) assert.notEqual(run.out[k]!.status, 0, `launch ${n}: ${k} reads the old version: refused\n${all}`);
      if (!packed) assert.match(run.out.blob!.text, /Permission denied/, all);
      // The notice, in BOTH launches: nothing prepared a copy in between.
      const lines = notice(run.log);
      assert.match(lines[0] ?? "", /^mandu: OpenCode's own snapshot history \(the copy of your files it keeps for undo\) holds a file you marked secret/, `launch ${n}\n${run.log}`);
      assert.ok(lines.some((l) => /\/opencode\/snapshot\/0123456789abcdef\/fedcba9876543210$/.test(l)), run.log);
      assert.ok(lines.some((l) => /comes back in each session .* To stop it, remove that folder/.test(l)), run.log);
      assert.ok(!lines.some((l) => /git was refused|To work in one/.test(l)), `never the repository advice\n${run.log}`);
      for (const b of await toModel(s, texts(run.out))) assert.ok(!b.includes(body), "no request to the model holds the token's bytes");
    }
    // Why it comes back: the store is not a work tree, so the arbiter does
    // not take it as a known repository, and nothing prepares its copy.
    await assert.rejects(
      ndjsonCall(s.sock, "registerRepository", { root: snap }, 10_000),
      /not a git work tree the arbiter can read/,
    );
    // The way out the notice names: the folder removed outside Mandu,
    // OpenCode starts a new history (inside the launch, as it would), which
    // holds only the placeholder; every command works, no notice prints.
    rmSync(snap, { recursive: true, force: true });
    const fresh = await launch(s, {
      init: `mkdir -p '${snap}' && ${init}`,
      track: `${g} add --all . && ${g} write-tree`,
      show: `${g} show :deploy/staging.conf`,
      gc: `${g} gc -q --prune=7.days`,
    }, { guard: true });
    const all = show(fresh);
    for (const [name, o] of Object.entries(fresh.out)) {
      assert.equal(o.status, 0, `the new history: ${name} works\n${all}`);
      assert.ok(!o.text.includes(body), `${name}: no token\n${all}`);
    }
    assert.match(fresh.out.show!.text, /^\[api\]\nAPI_TOKEN=\$MDU:\S+\n$/, `the new history holds the placeholder\n${all}`);
    assert.deepEqual(notice(fresh.log), [], fresh.log);
  } finally {
    await s.close();
  }
}

test("K15a (OpenCode's snapshot store, loose): after the label its older history is refused in every launch, the notice says so and how to stop it; a new store works", { skip: skipGuard || skip, timeout: 300_000 }, async () => {
  await openCodeSnapshot(false);
});

test("K15b (OpenCode's snapshot store, packed by its gc): the same, and the change list against an older snapshot is refused too", { skip: skipGuard || skip, timeout: 300_000 }, async () => {
  await openCodeSnapshot(true);
});

/**
 * K16 (2026-10-16, a history rewrite under the guard; guard-file-identity.md
 * §1): the agent removes a locked key from history
 * the way a person asks it to (rewrite every ref, drop the backups and the
 * reflog, `git gc --prune=now`). git's repack then removes the twinned
 * pack and its companions. Two guard defects showed there:
 *
 *   - the guard's identity list of registered files (re-`stat`ed every 2 s)
 *     still held the removed pack's inode NUMBER, and the next file the
 *     agent created could get that number: it was taken for the pack and
 *     its create refused (EACCES, "cannot create …: Permission denied" for
 *     the first one or two creates after the rewrite);
 *   - the repack unlinks the old `.idx` before its `.pack` (refused: the
 *     index anchors its pack), and `git prune`'s removal of the index left
 *     without its pack was refused too, so an orphan index stayed, and the
 *     first refusal named the repository in the end-of-session notice.
 *
 * Now every create right after the rewrite succeeds (in the pack directory,
 * where the freed numbers are reused first, in the work tree and in HOME)
 * and reads back its own bytes, the prune removes the orphan index (its
 * pack is gone), the repack's refused unlink is not told (an anchor refusal
 * stops nothing git needs), the notice names no repository, and the locked
 * version stays unreadable
 * before and after, reaching no model. The agent's command runs `git
 * filter-branch` (git's own; `git filter-repo` is not in every image) with
 * an index filter, which rewrites trees without reading a blob.
 */
async function historyRewrite(posture: "guard-only" | "bind"): Promise<void> {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const s = await stack(`mandu-k16-${posture}-`);
  try {
    writeFileSync(join(s.ws, "README.md"), "project readme\n");
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "init");
    mkdirSync(join(s.ws, "deploy"));
    writeFileSync(join(s.ws, "deploy", "id_rsa"), `${DEPLOY_KEY}\n`);
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "add deploy key");
    const added = git(s.ws, "rev-parse", "HEAD").trim();
    const blob = git(s.ws, "rev-parse", "HEAD:deploy/id_rsa").trim();
    writeFileSync(join(s.ws, "README.md"), "project readme\n\nmore\n");
    git(s.ws, "rm", "-rq", "deploy");
    git(s.ws, "commit", "-qam", "remove it");
    git(s.ws, "repack", "-adq");
    const r = await s.admin.policyPropose({ edits: [{ op: "lock-path", path: join(s.ws, "deploy", "id_rsa"), level: "no-model" }], reason: "K16", requestedBy: "dashboard" });
    assert.equal((r as { applied?: boolean }).applied, true, JSON.stringify(r));
    const packDir = join(s.ws, packsOf(s.ws));
    const oldPack = readdirSync(packDir);
    const oldInodes = new Set(oldPack.map((f) => execFileSync("stat", ["-c", "%i", join(packDir, f)], { encoding: "utf8" }).trim()));
    const N = 24;
    const run = await launch(s, {
      before: `git cat-file -p ${blob}`,
      rewrite: "FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch --force --index-filter 'git rm -rq --cached --ignore-unmatch deploy' --prune-empty -- --all",
      clean: "( rm -rf .git/refs/original && git reflog expire --expire=now --all && git gc -q --prune=now )",
      // At once after the repack removed the twinned pack: the freed inode
      // numbers go first to new files in the same directory.
      creates: `( f=0; for i in $(seq 1 ${N}); do for d in .git/objects/pack . "$HOME"; do echo "hi $i" > "$d/new-$i" || f=$((f+1)); done; done; echo "failed=$f"; stat -c %i .git/objects/pack/new-* ./new-* "$HOME"/new-* | tr '\\n' ' ' )`,
      readback: `( for i in $(seq 1 ${N}); do for d in .git/objects/pack . "$HOME"; do [ "$(cat "$d/new-$i")" = "hi $i" ] || echo "MISMATCH $d/new-$i"; done; done; echo checked )`,
      packs: "ls .git/objects/pack | grep -v '^new-'",
      after: `( git cat-file -p ${blob}; git show ${added}:deploy/id_rsa )`,
      log: "git log --oneline --all",
    }, posture === "guard-only" ? { guardOnly: true } : { guard: true });
    const all = Object.entries(run.out).map(([k, v]) => `--- ${k} (exit ${v.status})\n${v.text}`).join("\n");
    if (posture === "guard-only") assert.match(run.log, /bind mount SKIPPED \(--no-secret-bind\)/, run.log);
    // The locked version is unreadable before the rewrite.
    assert.notEqual(run.out.before!.status, 0, all);
    // The rewrite and its cleanup ran, and git removed the old index too.
    assert.equal(run.out.rewrite!.status, 0, all);
    assert.equal(run.out.clean!.status, 0, all);
    assert.doesNotMatch(run.out.clean!.text, /unable to unlink/, `the repack removes the old pack's index with it\n${all}`);
    // Every create right after the repack: made, and its own bytes read back.
    assert.match(run.out.creates!.text, /^failed=0$/m, `no create is refused after the rewrite\n${all}`);
    assert.equal(run.out.readback!.text.trim(), "checked", all);
    const created = new Set(run.out.creates!.text.split("\n").slice(1).join(" ").trim().split(/\s+/).filter(Boolean));
    const reused = [...oldInodes].filter((i) => created.has(i));
    // Only a filesystem that hands a freed inode number out again (ext4,
    // the CI guest's) reproduces the first defect; tmpfs never does.
    const fsType = execFileSync("stat", ["-f", "-c", "%T", packDir], { encoding: "utf8" }).trim();
    console.log(`K16 ${posture}: ${fsType}: ${reused.length} of the removed pack's inode numbers reused by the new files`);
    // No orphan index: only the new pack's files are left.
    const left = run.out.packs!.text.trim().split("\n").filter(Boolean);
    for (const b of new Set(left.map((f) => f.replace(/\.[a-z]+$/, "")))) {
      assert.ok(left.includes(`${b}.pack`) && left.includes(`${b}.idx`), `every index has its pack: ${left.join(" ")}\n${all}`);
    }
    assert.ok(!left.some((f) => oldPack.includes(f)), `the old pack is gone, its index too: ${left.join(" ")}\n${all}`);
    // The locked version is still unreadable, and the history has no key.
    assert.notEqual(run.out.after!.status, 0, all);
    assert.match(run.out.log!.text, /remove it/, all);
    assert.doesNotMatch(run.out.log!.text, /add deploy key/, `the rewrite dropped the commit that only added the key\n${all}`);
    // The notice names no repository: nothing was refused.
    assert.doesNotMatch(run.log, /git was refused/, run.log);
    for (const [name, o] of Object.entries(run.out)) assert.ok(!o.text.includes(DEPLOY_KEY), `${name}: the key is absent from the agent's world\n${all}`);
    for (const b of await toModel(s, texts(run.out))) assert.ok(!b.includes(DEPLOY_KEY), "no request to the model holds the key's bytes");
    // Host truth: the repository holds no object with the key any more.
    const objects = spawnSync("git", ["cat-file", "--batch-all-objects", "--batch"], { cwd: s.ws, env: GIT_ENV, maxBuffer: 1 << 26 }).stdout.toString("latin1");
    assert.ok(!objects.includes(DEPLOY_KEY), "the rewrite removed the key from the repository");
  } finally {
    await s.close();
  }
}

/**
 * K17 (2026-10-16, the negative side of K16's orphan index): an index stays
 * anchored while ANY pack is beside it. Two clones of K16's repository made
 * before the session, outside the workspace (so the launch prepares
 * neither): `clone-linked` by `git clone --local`, whose pack is a hard link
 * to the workspace's twinned pack (the guard knows that inode as the twin's
 * entry by identity only), and `clone-copy` by `--no-hardlinks`, an
 * untwinned pack whose index lists the locked id. Removing either index is
 * refused (the backstop judges `clone-linked`'s pack by that index once the
 * workspace's name for it is gone); removing `clone-copy`'s pack first and
 * then its index runs. Anchor refusals are not told in the notice.
 */
async function anchoredIndex(posture: "guard-only" | "bind"): Promise<void> {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
  const s = await stack(`mandu-k17-${posture}-`);
  try {
    writeFileSync(join(s.ws, "README.md"), "project readme\n");
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "init");
    mkdirSync(join(s.ws, "deploy"));
    writeFileSync(join(s.ws, "deploy", "id_rsa"), `${DEPLOY_KEY}\n`);
    git(s.ws, "add", ".");
    git(s.ws, "commit", "-qm", "add deploy key");
    git(s.ws, "rm", "-rq", "deploy");
    git(s.ws, "commit", "-qm", "remove it");
    git(s.ws, "repack", "-adq");
    const linked = join(s.dir, "clone-linked");
    const copy = join(s.dir, "clone-copy");
    git(s.dir, "clone", "-q", "--local", s.ws, linked);
    git(s.dir, "clone", "-q", "--no-hardlinks", s.ws, copy);
    const packDir = (repo: string): string => join(repo, ".git", "objects", "pack");
    const wsPack = readdirSync(packDir(s.ws)).find((f) => f.endsWith(".pack"))!;
    assert.ok(wsPack, "the workspace has one pack");
    const nlink = (p: string): number => Number(execFileSync("stat", ["-c", "%h", p], { encoding: "utf8" }).trim());
    assert.ok(nlink(join(packDir(linked), wsPack)) >= 2, "clone --local hard-linked the pack (one filesystem)");
    assert.equal(nlink(join(packDir(copy), wsPack)), 1, "clone --no-hardlinks copied it");
    const r = await s.admin.policyPropose({ edits: [{ op: "lock-path", path: join(s.ws, "deploy", "id_rsa"), level: "no-model" }], reason: "K17", requestedBy: "dashboard" });
    assert.equal((r as { applied?: boolean }).applied, true, JSON.stringify(r));
    const idx = wsPack.replace(/\.pack$/, ".idx");
    const run = await launch(s, {
      linked: `rm '${join(packDir(linked), idx)}'`,
      copy: `rm '${join(packDir(copy), idx)}'`,
      orphan: `( rm '${join(packDir(copy), wsPack)}' && rm '${join(packDir(copy), idx)}' )`,
    }, posture === "guard-only" ? { guardOnly: true } : { guard: true });
    const all = Object.entries(run.out).map(([k, v]) => `--- ${k} (exit ${v.status})\n${v.text}`).join("\n");
    assert.notEqual(run.out.linked!.status, 0, `an index beside a pack twinned only by identity stays\n${all}`);
    assert.match(run.out.linked!.text, /Permission denied/, all);
    assert.ok(existsSync(join(packDir(linked), idx)), "clone-linked's index is still there");
    assert.notEqual(run.out.copy!.status, 0, `an index beside an untwinned locked pack stays\n${all}`);
    assert.match(run.out.copy!.text, /Permission denied/, all);
    assert.equal(run.out.orphan!.status, 0, `the pack first, then its orphan index\n${all}`);
    assert.deepEqual(readdirSync(packDir(copy)).filter((f) => f.startsWith(wsPack.replace(/\.pack$/, "")) && /\.(pack|idx)$/.test(f)), [], all);
    assert.doesNotMatch(run.log, /git was refused/, `a refused index removal is not told as git refused\n${run.log}`);
    // ...but each refused change of an anchoring index is recorded.
    const eventsDir = join(s.dir, "events");
    const events = existsSync(eventsDir) ? readdirSync(eventsDir).map((f) => { try { return readFileSync(join(eventsDir, f), "utf8"); } catch { return ""; } }).join("\n") : "";
    for (const repo of [linked, copy]) {
      const want = `change of ${join(realpathSync(packDir(repo)), idx)} — REFUSED (git-index:`;
      assert.ok(events.includes(want), `a refused index change is an event: ${want}\n${events.split("\n").filter((l) => /git-index|git-lock/.test(l)).join("\n")}`);
    }
    assert.ok(!/REFUSED \(git-lock:/.test(events), "no refused read was recorded");
  } finally {
    await s.close();
  }
}

test("K17a (guard only, §7.2a): an index beside a pack (twinned only by identity, or untwinned and locked) cannot be removed; once its pack is gone it can", { skip: skipGuard, timeout: 300_000 }, async () => {
  await anchoredIndex("guard-only");
});

test("K17b (guard and bind, §7.2a): the same with the mount layer up beside the guard", { skip: skipGuard || skip, timeout: 300_000 }, async () => {
  await anchoredIndex("bind");
});

test("K16a (guard only, §7.2a, a history rewrite): after the agent's rewrite and gc, every file it creates at once is made (none taken for the removed pack by a reused inode number), the old index goes with its pack, no notice, and the locked version stays unreadable", { skip: skipGuard, timeout: 300_000 }, async () => {
  await historyRewrite("guard-only");
});

test("K16b (guard and bind, §7.2a, a history rewrite): the same with the mount layer up beside the guard", { skip: skipGuard || skip, timeout: 300_000 }, async () => {
  await historyRewrite("bind");
});
