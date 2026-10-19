/**
 * bundle-smoke — the packaging.md §5 anti-drift oracle (caveat §10.1): the test
 * is source, but its SUBJECT is the BUILT dist/ bundles. It rebuilds from the
 * current source, then proves the shipped artifacts actually run:
 *   1. every manifest entry produced a non-empty dist/<name>.mjs;
 *   2. the bundled arbiter (node:sqlite, no native addon) boots and serves IPC;
 *   3. the bundled arbiter-client (the interceptors' MANDU_ARBITER_CLIENT_MODULE
 *      target) connects to it and round-trips symbolize → desymbolize —
 *      exactly the installed-mode path a bundled proxy takes;
 *   4. the bundled arbiter walks `discoverSecrets` on its worker thread
 *      (dist/secret-discovery-worker.mjs beside dist/arbiter.mjs), not
 *      in-process (runtime-instances.md §14.2 item 7);
 *   5. the package ships the reference prompt classifier
 *      (dist/prompt-filters/): the installed `mandu policy classifier-pack`
 *      pins the shipped copy, and that copy answers the plugin protocol;
 *   6. the SDK route preload ships with the permission-mode rule it
 *      requires beside it, and loads from dist/.
 *
 * This is the mechanism that keeps `dist/` from silently rotting away from
 * source; the fuller wrapper-parity-against-dist axis is layered on top later.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { axesEnv, stateAxes } from "../axes.js";
import { waitForPaths } from "../lib/arbiter-ready.js";
import { ownArbiterBuild } from "../../src/arbiter-version.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const manifest = JSON.parse(readFileSync(join(pkgRoot, "bundle-manifest.json"), "utf8")) as {
  services: Record<string, string>;
  modules: Record<string, string>;
};
const allNames = [...Object.keys(manifest.services), ...Object.keys(manifest.modules)];

let tmp: string;
let distDir: string;

before(() => {
  // Rebuild from CURRENT source so the bundle under test can't drift from HEAD.
  // Build into a PRIVATE dir (not the shared launcher/dist) so parallel test
  // files — npm-pack rebuilds launcher/dist via prepack — can't race us.
  tmp = mkdtempSync(join(tmpdir(), "mandu-bundle-smoke-"));
  distDir = join(tmp, "dist");
  const r = spawnSync("node", [join(pkgRoot, "scripts", "build-bundle.mjs"), `--outdir=${distDir}`], {
    cwd: pkgRoot,
    encoding: "utf8",
  });
  assert.equal(r.status, 0, `build-bundle failed:\n${r.stdout}\n${r.stderr}`);
  // The installed layout: the package's manifest beside dist/, where the
  // bundles read the release from (runtime-instances.md §4.1).
  copyFileSync(join(pkgRoot, "package.json"), join(tmp, "package.json"));
});

after(() => {
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

test("every manifest entry produced a non-empty dist bundle", () => {
  for (const name of allNames) {
    const p = join(distDir, `${name}.mjs`);
    assert.ok(existsSync(p), `missing bundle: ${name}.mjs`);
    assert.ok(statSync(p).size > 0, `empty bundle: ${name}.mjs`);
  }
});

test("the bundle carries the product page beside dashboard.mjs (dashboard.md §4.25)", () => {
  const idx = join(distDir, "dashboard", "public", "index.html");
  assert.ok(existsSync(idx), "public/index.html shipped");
  assert.match(readFileSync(idx, "utf8"), /name="mandu-app"/, "the product page");
  assert.ok(existsSync(join(distDir, "dashboard", "public", "js", "home.js")));
});

test("the developer view is in the bundle exactly when its source is in the tree (dashboard.md §4.25ac)", () => {
  const optional = (manifest as { optionalModules?: Record<string, string>; optionalAssetDirs?: Record<string, string> });
  const repoRoot = join(pkgRoot, "..");
  const src = optional.optionalModules?.["dashboard-dev"];
  const pages = optional.optionalAssetDirs?.["dashboard/dev"];
  if (!src && !pages) {
    // The public tree's manifest names no developer view: its bundle has none.
    assert.equal(existsSync(join(distDir, "dashboard-dev.mjs")), false, "no module");
    assert.equal(existsSync(join(distDir, "dashboard", "dev")), false, "no pages");
    return;
  }
  assert.ok(src && pages, "the manifest names both the developer view's module and its pages");
  const here = existsSync(join(repoRoot, src)) && existsSync(join(repoRoot, pages));
  assert.equal(existsSync(join(distDir, "dashboard-dev.mjs")), existsSync(join(repoRoot, src)), "its module");
  assert.equal(existsSync(join(distDir, "dashboard", "dev", "index.html")), existsSync(join(repoRoot, pages)), "its pages");
  if (here) {
    assert.match(readFileSync(join(distDir, "dashboard", "dev", "index.html"), "utf8"), /Mandu · Developer view/);
    assert.ok(existsSync(join(distDir, "dashboard", "dev", "js", "app.js")));
    assert.ok(existsSync(join(distDir, "dashboard", "dev", "vendor", "asciinema-player", "asciinema-player.min.js")));
  }
});

test("bundled arbiter boots and the bundled arbiter-client round-trips over IPC", async () => {
  const sock = join(tmp, "arb.sock");
  // A private Mandu home (its symbol DB and events): symbolize dedups by
  // value, so on the user's real ~/.mandu a pre-existing row would return its
  // stored (possibly stale-format) token instead of a fresh mint.
  const manduHome = join(tmp, "mandu-home");
  let arb: ChildProcess | undefined;
  let client: { close: () => void } | undefined;
  let human: { close: () => void } | undefined;
  try {
    arb = spawn(
      "node",
      ["--no-warnings=ExperimentalWarning", join(distDir, "arbiter.mjs")],
      {
        // A private runtime base: the human-plane socket binds under it.
        env: { ...process.env, MANDU_ARBITER_SOCK: sock, MANDU_HOME: manduHome, MANDU_RUNTIME_DIR: join(tmp, "rt") },
        stdio: ["ignore", "ignore", "pipe"],
      },
    );
    let stderr = "";
    arb.stderr?.on("data", (c) => (stderr += c));

    // Wait for the socket the daemon creates on listen.
    await waitForPaths(sock, { what: "the bundled arbiter", child: arb, output: () => stderr });

    // Drive the BUNDLED client (installed-mode MANDU_ARBITER_CLIENT_MODULE target).
    const mod = (await import(join(distDir, "arbiter-client.mjs"))) as {
      ArbiterClient: new (sock: string) => {
        connect(): Promise<void>;
        ping(): Promise<unknown>;
        symbolize(a: { tool: string; value: string }): Promise<string>;
        desymbolize(t: string): Promise<string>;
        hello(): Promise<{ humanSock?: string | null; version?: string; build?: { bundle: string | null; rev: string | null } }>;
        close(): void;
      };
    };
    const c = new mod.ArbiterClient(sock);
    client = c;
    await c.connect();
    await c.ping(); // liveness

    const secret = "TOP-SECRET-UNTRUSTED-VALUE";
    const sym = await c.symbolize({ tool: "web_fetch", value: secret });
    assert.match(sym, /^\$MDU:/, `symbolize returned a non-symbol: ${sym}`);
    assert.notEqual(sym, secret);
    // Originals come back only over the HUMAN plane (arbiter-human-plane.md):
    // the data socket refuses, the socket hello names answers.
    await assert.rejects(c.desymbolize(sym), /human-plane/, "the data socket must refuse desymbolize");
    const hello = await c.hello();
    // The release the launcher compares with its own (runtime-instances.md
    // §4.1): read beside the bundle, it must be the package's version, or
    // every launch would refuse the arbiter it started.
    const pkgVersion = (JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8")) as { version: string }).version;
    assert.equal(hello.version, pkgVersion, "the bundled arbiter reports the package's release");
    // Which build of it (build-identity.ts): the hash of the bundle file it
    // runs, no rev for an install. The launcher computes the same for the
    // bundle it would start, so a launch from this package matches it.
    const sha16 = createHash("sha256").update(readFileSync(join(distDir, "arbiter.mjs"))).digest("hex").slice(0, 16);
    assert.deepEqual(hello.build, { bundle: sha16, rev: null }, "the bundled arbiter reports its own hash");
    assert.deepEqual(ownArbiterBuild({ mode: "installed", bundled: true, pkgRoot: tmp, repoRoot: tmp }, { revOf: () => "nogit" }), hello.build);
    const humanSock = hello.humanSock;
    assert.ok(typeof humanSock === "string" && humanSock.startsWith(join(tmp, "rt", "human")), `hello names the human socket: ${humanSock}`);
    const h = new mod.ArbiterClient(humanSock);
    human = h;
    const back = await h.desymbolize(sym);
    assert.equal(back, secret, "desymbolize did not recover the original through the bundle");
  } finally {
    try { client?.close(); } catch { /* best-effort */ }
    try { human?.close(); } catch { /* best-effort */ }
    if (arb) { arb.kill("SIGTERM"); await once(arb, "exit", 5000); }
  }
});

test("the bundled arbiter walks discoverSecrets on its worker thread (runtime-instances.md §14.2 item 7)", async () => {
  assert.ok(existsSync(join(distDir, "secret-discovery-worker.mjs")), "the worker ships beside arbiter.mjs");
  const sock = join(tmp, "arb-disc.sock");
  const home = join(tmp, "disc-home");
  mkdirSync(join(home, "proj"), { recursive: true });
  writeFileSync(join(home, "proj", ".env"), "A=AKIA_BUNDLE_DISC\n");
  let arb: ChildProcess | undefined;
  let client: { close: () => void } | undefined;
  let stderr = "";
  try {
    arb = spawn(
      "node",
      ["--no-warnings=ExperimentalWarning", join(distDir, "arbiter.mjs")],
      {
        // Confidentiality ON for this daemon: discovery walks only then.
        env: {
          ...process.env, ...axesEnv("secrets"),
          MANDU_ARBITER_SOCK: sock, MANDU_HOME: join(tmp, "mandu-home-disc"), MANDU_RUNTIME_DIR: join(tmp, "rt-disc"),
        },
        stdio: ["ignore", "ignore", "pipe"],
      },
    );
    arb.stderr?.on("data", (c) => (stderr += c));
    await waitForPaths(sock, { what: "the bundled arbiter", child: arb, output: () => stderr });
    const mod = (await import(join(distDir, "arbiter-client.mjs"))) as {
      ArbiterClient: new (sock: string) => {
        connect(): Promise<void>;
        discoverSecretsReport(roots: string[], home?: string): Promise<{ files: Array<{ path: string }> }>;
        close(): void;
      };
    };
    const c = new mod.ArbiterClient(sock);
    client = c;
    await c.connect();
    const r = await c.discoverSecretsReport([home], home);
    assert.deepEqual(r.files.map((f) => f.path), [join(home, "proj", ".env")]);
    assert.doesNotMatch(stderr, /walking in-process/, "the bundled arbiter found and ran its worker");
  } finally {
    try { client?.close(); } catch { /* best-effort */ }
    if (arb) { arb.kill("SIGTERM"); await once(arb, "exit", 5000); }
  }
});

// The preload requires the permission-mode rule from beside itself
// (claude-permission-rule.cjs, supported-agents.md §2): a package without it
// would fail every SDK host and every `claude` PATH shim at start.
test("the package ships the SDK route preload with its permission-mode rule beside it: dist/sdk-route-preload.cjs loads and applies the rule", () => {
  const preload = join(distDir, "sdk-route-preload.cjs");
  assert.ok(existsSync(join(distDir, "claude-permission-rule.cjs")), "dist/claude-permission-rule.cjs ships");
  const mode = { cwd: tmp, configDir: join(tmp, "cfg"), scopes: [] };
  const r = spawnSync(process.execPath, ["-e",
    `const p = require(${JSON.stringify(preload)}); process.stdout.write(JSON.stringify(p.claudeModeArgs(["-p", "x"], ${JSON.stringify(mode)}, ${JSON.stringify(tmp)}, { CLAUDE_CONFIG_DIR: ${JSON.stringify(mode.configDir)} })));`,
  ], { encoding: "utf8", env: { PATH: process.env["PATH"] ?? "" } });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), ["--permission-mode", "default", "-p", "x"]);
});

// P0 item 13 (c): releases left the reference classifier out, so an
// installed user could not write its pack (the documented command named a
// checkout path) and the classifier did nothing.
test("the package ships the reference classifier: `mandu policy classifier-pack` pins the shipped copy, which answers the protocol (confidentiality-plan-15 §13.5 item 15)", async () => {
  const shipped = join(distDir, "prompt-filters", "local-classifier.mjs");
  assert.ok(existsSync(shipped), "dist/prompt-filters/local-classifier.mjs ships");
  assert.ok(existsSync(join(distDir, "prompt-filters", "local-classifier-pack.mjs")), "and its pack writer");
  // The installed layout (dist/ with no src/run.ts beside it).
  const r = spawnSync("node", [join(distDir, "mandu.mjs"), "policy", "classifier-pack", "--id", "acme-cls", "--categories", "acme.codename"], {
    encoding: "utf8", env: { ...process.env, HOME: join(tmp, "cls-home"), MANDU_HOME: join(tmp, "cls-home", ".mandu") },
  });
  assert.equal(r.status, 0, `mandu policy classifier-pack failed:\n${r.stdout}\n${r.stderr}`);
  const sha = createHash("sha256").update(readFileSync(shipped)).digest("hex");
  assert.match(r.stdout, new RegExp(`^  script: ${realpathSync(shipped).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"), r.stdout);
  assert.match(r.stdout, new RegExp(`^  script_sha256: "${sha}"$`, "m"));
  assert.match(r.stdout, /^  endpoint: required$/m);
  // The shipped classifier runs as the arbiter runs it (a program: one
  // request on stdin) against a fake local model, and reads long text in
  // overlapping chunks: a phrase the first cut falls inside is found.
  const phrase = "Project Heron";
  const text = `${"lorem ips ".repeat(599)}${phrase} ${"tail word ".repeat(400)}`;
  const model = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ findings: body.includes(phrase) ? [{ category: "acme.codename", text: phrase }] : [] }) } }] }));
    });
  });
  await new Promise<void>((ok) => model.listen(0, "127.0.0.1", ok));
  try {
    const port = (model.address() as AddressInfo).port;
    const request = JSON.stringify({
      protocol: "mandu-prompt-filter/1", filter: "acme-cls", deadlineMs: 10000, categories: ["acme.codename"],
      endpoint: { name: "ollama", url: `http://127.0.0.1:${port}`, wire: "openai-chat", model: "x" },
      segments: [{ id: "h", origin: "human", text }],
    });
    const child = spawn("node", [shipped], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout!.on("data", (c) => (out += c));
    child.stderr!.on("data", (c) => (err += c));
    child.stdin!.end(request);
    const code = await new Promise<number | null>((ok) => child.on("close", ok));
    assert.equal(code, 0, err);
    const at = text.indexOf(phrase);
    assert.deepEqual(JSON.parse(out), { findings: [{ segment: "h", start: at, end: at + phrase.length, category: "acme.codename" }] });
  } finally {
    model.close();
  }
});

function once(cp: ChildProcess, ev: string, timeoutMs: number): Promise<void> {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, timeoutMs);
    cp.once(ev, () => { clearTimeout(t); resolve(); });
  });
}
