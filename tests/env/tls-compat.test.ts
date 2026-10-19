/**
 * tls-compat.live.test — the TLS-inspection compatibility matrix, measured
 * (docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md §10). A real net-proxy with inspection on,
 * the launcher's own trust variables (`mitmTrustEnv`, `writeCaBundle`) and
 * proxy variables, and every client installed on this host fetching a public
 * HTTPS page. Each client lands in one cell:
 *
 *   SERVED   the request went through the inspecting proxy and the client
 *            trusted the session CA: a placeholder it sends is put back;
 *   BYPASS   the client never used the proxy (the wire release cannot help;
 *            nothing leaks either: it only ever held a placeholder);
 *   REFUSED  the client reached the proxy and rejected its certificate.
 *
 * The expected cell per client is the matrix; a change in any of them fails
 * here and the doc must change with it. A few cells depend on the installed
 * client, not on Mandu (Node's version for NODE_USE_ENV_PROXY, the TLS
 * library wget or cargo's libcurl was built with): those rows derive their
 * expectation from the client's own version text (tests/lib/tls-compat-cells.ts),
 * and a build the helper cannot place is declared build-dependent (SERVED or
 * REFUSED both pass; BYPASS still fails). A row whose only event is
 * `forward_error` (the upstream was unreachable: transport, not a cell) is
 * retried once. Opt-in (MANDU_LIVE_TLS_COMPAT=1); a missing client, or no
 * network, skips (no API budget either way).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { lookup } from "node:dns/promises";

import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { MockArbiter } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { writeCaBundle } from "../../launcher/src/services/net-proxy.js";
import { mitmTrustEnv } from "../../launcher/src/env-compose.js";
import { tmpDir } from "../lib/tmp-dir.js";
import {
  type Cell, cargoNoCainfoCell, cellOf, nodeEnvProxyCell, transportOnly, wgetCell,
} from "../lib/tls-compat-cells.js";

const TARGET = process.env["MANDU_TLS_COMPAT_TARGET"] ?? "https://example.com";
const has = (bin: string): boolean => spawnSync("sh", ["-c", `command -v ${bin}`]).status === 0;

/** A row's expectation: a fixed cell, or one derived from the client's
 *  version text (null: build-dependent, SERVED or REFUSED). */
type Expect = Cell | ((versionText: string) => { cell: Cell | null; why: string });

interface Client {
  name: string;
  bins: string[];
  expect: Expect;
  /** argv printing the client's version (default `<bins[0]> --version`). */
  version?: string[];
  argv: (url: string, work: string) => string[];
  /** Extra environment on top of the launcher's (to show what a cell depends on). */
  env?: Record<string, string>;
  /** Build step (compile a probe) run once when the client is present. */
  build?: (work: string) => boolean;
}

/** The three Node rows for one `node` binary: fetch and https with the
 *  launcher's NODE_USE_ENV_PROXY=1 (the cell follows the version: Node's docs
 *  date the variable v24.0.0/v22.21.0 for fetch, v24.5.0/v22.21.0 for
 *  http/https), and fetch without it (BYPASS on every version). */
function nodeRows(node: string, label: string): Client[] {
  const derive = (api: "fetch" | "https") => (v: string) => ({
    cell: nodeEnvProxyCell(v.trim(), api),
    why: `Node ${v.trim()} ${nodeEnvProxyCell(v.trim(), api) === "SERVED" ? "honours" : "ignores"} NODE_USE_ENV_PROXY for ${api}`,
  });
  return [
    { name: `${label} fetch`, bins: [node], version: [node, "--version"], expect: derive("fetch"), argv: (u) => [node, "-e", `fetch("${u}").then(r=>r.text()).catch(e=>{console.error(e.cause??e);process.exit(3)})`] },
    { name: `${label} https`, bins: [node], version: [node, "--version"], expect: derive("https"), argv: (u) => [node, "-e", `require("https").get("${u}",r=>r.resume()).on("error",e=>{console.error(e);process.exit(3)})`] },
    { name: `${label} fetch, no NODE_USE_ENV_PROXY`, bins: [node], version: [node, "--version"], expect: "BYPASS", env: { NODE_USE_ENV_PROXY: "" }, argv: (u) => [node, "-e", `fetch("${u}").then(r=>r.text()).catch(()=>process.exit(3))`] },
  ];
}

// The node a session's programs run is the one on PATH (in the CI guest,
// Mandu's floor, scripts/ci/pins.env NODE_VERSION). The guest image also
// carries a newer node for the agent CLIs whose engine floor is above
// Mandu's (AGENT_NODE_VERSION, /opt/agent-node): measured too, so the SERVED
// Node cell is measured even where the PATH node predates NODE_USE_ENV_PROXY.
const AGENT_NODE = "/opt/agent-node/bin/node";

const CLIENTS: Client[] = [
  { name: "curl", bins: ["curl"], expect: "SERVED", argv: (u) => ["curl", "-sS", "-o", "/dev/null", "--max-time", "15", u] },
  {
    name: "wget", bins: ["wget"],
    // An OpenSSL build (Ubuntu 24.04's) reads SSL_CERT_FILE; a GnuTLS build
    // (Ubuntu 26.04's) reads only the system store.
    expect: (v) => ({ cell: wgetCell(v), why: `wget built with ${/\+ssl\/\w+/.exec(v)?.[0] ?? "an unnamed TLS library"}` }),
    argv: (u) => ["wget", "-q", "-O", "/dev/null", "-T", "15", "-t", "1", u],
  },
  { name: "python urllib", bins: ["python3"], expect: "SERVED", argv: (u) => ["python3", "-c", `import urllib.request;urllib.request.urlopen("${u}",timeout=15).read()`] },
  { name: "python requests", bins: ["python3"], expect: "SERVED", version: ["python3", "-c", "import requests,sys;print('requests',requests.__version__,sys.version.split()[0])"], argv: (u) => ["python3", "-c", `import requests;requests.get("${u}",timeout=15)`], build: () => spawnSync("python3", ["-c", "import requests"]).status === 0 },
  ...nodeRows("node", "node"),
  ...(existsSync(AGENT_NODE) ? nodeRows(AGENT_NODE, "agent node") : []),
  { name: "bun fetch", bins: ["bun"], expect: "SERVED", argv: (u) => ["bun", "-e", `await (await fetch("${u}")).text()`] },
  { name: "ruby Net::HTTP", bins: ["ruby"], expect: "SERVED", argv: (u) => ["ruby", "-rnet/http", "-e", `Net::HTTP.get(URI("${u}"))`] },
  { name: "git", bins: ["git"], expect: "SERVED", argv: (u) => ["git", "ls-remote", `${u}/mandu-tls-compat.git`] },
  { name: "pip", bins: ["pip3"], expect: "SERVED", argv: (u, w) => ["pip3", "download", "--no-deps", "-d", w, "--index-url", `${u}/simple`, "mandu-tls-compat", "--timeout", "15", "--retries", "0"] },
  { name: "npm", bins: ["npm"], expect: "SERVED", argv: (u) => ["npm", "view", "mandu-tls-compat", "--registry", `${u}/`, "--fetch-retries=0"] },
  { name: "cargo", bins: ["cargo"], expect: "SERVED", version: ["cargo", "-vV"], argv: (u) => ["cargo", "search", "mandu-tls-compat", "--index", `sparse+${u}/`] },
  {
    // Without CARGO_HTTP_CAINFO only SSL_CERT_FILE names the session CA: read
    // by rustup's cargo (a vendored libcurl over OpenSSL), not by a cargo
    // linked to a libcurl that ignores it.
    name: "cargo, no CARGO_HTTP_CAINFO", bins: ["cargo"], version: ["cargo", "-vV"],
    expect: (v) => ({ cell: cargoNoCainfoCell(v), why: `cargo's ${/^libcurl:.*$/m.exec(v)?.[0] ?? "libcurl (not named by cargo -vV)"}` }),
    env: { CARGO_HTTP_CAINFO: "" }, argv: (u) => ["cargo", "search", "mandu-tls-compat", "--index", `sparse+${u}/`],
  },
  {
    name: "go net/http", bins: ["go"], expect: "SERVED", version: ["go", "version"], argv: (u, w) => [join(w, "gofetch"), u],
    build: (w) => {
      writeFileSync(join(w, "gofetch.go"), 'package main\nimport ("net/http";"os")\nfunc main(){ r,err:=http.Get(os.Args[1]); if err!=nil{os.Stderr.WriteString(err.Error());os.Exit(3)}; r.Body.Close() }\n');
      return spawnSync("go", ["build", "-o", join(w, "gofetch"), join(w, "gofetch.go")], { cwd: w, env: { ...process.env, GOCACHE: join(w, "gocache"), GO111MODULE: "off" } }).status === 0;
    },
  },
  {
    // Java reads none of the variables: no proxy, its own trust store.
    name: "java HttpClient", bins: ["java", "javac"], expect: "BYPASS", version: ["java", "-version"], argv: (u, w) => ["java", "-cp", w, "JFetch", u],
    build: (w) => {
      writeFileSync(join(w, "JFetch.java"), "import java.net.http.*; import java.net.URI;\npublic class JFetch { public static void main(String[] a) throws Exception { HttpClient.newBuilder().proxy(java.net.ProxySelector.getDefault()).build().send(HttpRequest.newBuilder(URI.create(a[0])).build(), HttpResponse.BodyHandlers.discarding()); } }\n");
      return spawnSync("javac", [join(w, "JFetch.java")], { cwd: w }).status === 0;
    },
  },
];

function run(argv: string[], env: NodeJS.ProcessEnv, cwd: string): Promise<{ code: number | null; out: string }> {
  return new Promise((resolve) => {
    // Async on purpose: the proxy lives on this event loop (spawnSync would starve it).
    const c = spawn(argv[0]!, argv.slice(1), { env, cwd });
    let out = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (out += d));
    const t = setTimeout(() => c.kill("SIGKILL"), 60_000);
    c.on("close", (code) => { clearTimeout(t); resolve({ code, out }); });
    c.on("error", (e) => { clearTimeout(t); resolve({ code: -1, out: String(e) }); });
  });
}

/** The client's version text (stdout + stderr: `java -version` prints to
 *  stderr). Run before the request, while the proxy is idle. */
function versionText(argv: string[], env: NodeJS.ProcessEnv, cwd: string): string {
  const r = spawnSync(argv[0]!, argv.slice(1), { env, cwd, encoding: "utf8", timeout: 20_000 });
  return `${r.stdout ?? ""}${r.stderr ?? ""}`.trim() || `(no version: ${r.error?.message ?? `exit ${r.status}`})`;
}

// Opt-in like every other live suite (test-organization.md §8.2): it reaches
// the public internet, so a bare run of the env suites skips it.
const OPTED_IN = process.env["MANDU_LIVE_TLS_COMPAT"] === "1";
const online = OPTED_IN && await lookup(new URL(TARGET).hostname).then(() => true, () => false);
const SKIP = !OPTED_IN
  ? "set MANDU_LIVE_TLS_COMPAT=1 to run: every installed HTTPS client fetches a public page through the inspecting proxy"
  : !online && `no DNS for ${TARGET}`;

test("TLS-inspection compatibility matrix: each installed client lands in its documented cell", { skip: SKIP }, async (t) => {
  const work = tmpDir("mdu-tls-compat-");
  const arbiter = new MockArbiter();
  // The proxy's log goes into each row's diagnostics and failure message.
  const proxyLog: string[] = [];
  const proxy = new NetProxy({ arbiter, log: (m) => { proxyLog.push(m); }, mitm: { caDir: join(work, "ca") } });
  const port = await proxy.listen(0);
  const ca = proxy.mitmCaCertPath!;
  const bundle = writeCaBundle(join(work, "ca"), ca);
  const url = `http://127.0.0.1:${port}`;
  // The launcher's composition (env-compose.ts): proxy variables, the trust
  // variables, and NODE_USE_ENV_PROXY.
  const base: NodeJS.ProcessEnv = {
    ...process.env,
    HTTP_PROXY: url, http_proxy: url, HTTPS_PROXY: url, https_proxy: url,
    NO_PROXY: "127.0.0.1,localhost,::1", no_proxy: "127.0.0.1,localhost,::1",
    NODE_USE_ENV_PROXY: "1",
    ...mitmTrustEnv(ca, bundle),
    // cargo writes its index cache under CARGO_HOME; keep the user's clean.
    CARGO_HOME: join(work, "cargo"),
  };
  // The CI guest runs its whole pipeline with cargo offline (boot.sh), which
  // a session does not: offline cargo never dials, and reads as BYPASS.
  delete base["CARGO_NET_OFFLINE"];
  try {
    for (const c of CLIENTS) {
      await t.test(c.name, async (st) => {
        if (!c.bins.every(has)) return st.skip(`${c.bins.join("/")} not installed`);
        if (c.build && !c.build(work)) return st.skip("probe did not build");
        const env = { ...base, ...c.env };
        for (const [k, v] of Object.entries(c.env ?? {})) if (v === "") delete env[k];
        const version = versionText(c.version ?? [c.bins[0]!, "--version"], env, work);
        const derived = typeof c.expect === "string" ? { cell: c.expect, why: "the documented row" } : c.expect(version);
        const attempt = async () => {
          const before = arbiter.emittedEvents.length;
          const logBefore = proxyLog.length;
          const r = await run(c.argv(TARGET, work), env, work);
          await new Promise((res) => setTimeout(res, 100));
          const events = arbiter.emittedEvents.slice(before) as Array<{ action?: string; reason?: string }>;
          return { r, events, actions: events.map((e) => e.action ?? "?"), log: proxyLog.slice(logBefore) };
        };
        let a = await attempt();
        if (transportOnly(a.actions)) {
          st.diagnostic(`only forward_error (${a.events.map((e) => e.reason).join("; ")}): transport, retrying once`);
          a = await attempt();
        }
        const cell = cellOf(a.actions);
        const shown = a.events.map((e) => `${e.action}${e.reason ? ` (${e.reason})` : ""}`).join(", ") || "none";
        const what =
          `${c.name} [${version.split("\n")[0]}]: ${cell}, expected ${derived.cell ?? "SERVED or REFUSED (build-dependent)"} (${derived.why}); ` +
          `exit ${a.r.code}; events: ${shown}; proxy log: ${a.log.slice(-8).join(" | ") || "none"}; output: ${a.r.out.slice(0, 300)}`;
        st.diagnostic(what);
        if (derived.cell === null) assert.notEqual(cell, "BYPASS", what);
        else assert.equal(cell, derived.cell, what);
      });
    }
  } finally {
    await proxy.close();
  }
});
