/**
 * npm-pack — the packaging.md §5 "self-contained artifact" oracle: `npm pack`
 * the package (prepack's bundle build, run into a private stage by
 * test/lib/pack-private.ts so a parallel test file never races the shared
 * launcher/dist), install the tarball into a throwaway
 * dir, and run the installed `mandu` with PLAIN node. The dependency install
 * pulls NO devDeps (no tsx), so if `mandu` runs at all it MUST be from the
 * bundle — proving `npm install -g @mandusec/mandu` needs neither a repo checkout
 * nor tsx nor a native build.
 *
 * Heavyweight (pack + install); it exercises the real shipped path, not a mock.
 * Every npm call uses a cache inside the test's tmp dir (npmEnv), never the
 * real `~/.npm` (test-organization.md §8.4).
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createServer } from "node:http";
import { checkoutCommits } from "../lib/checkout-commits.js";
import { once } from "node:events";
import { PKG_ROOT, npmCacheDir, npmEnv, packPrivate } from "../lib/pack-private.js";

let tmp: string;
let tarball: string;
let installed: string;

before(() => {
  tmp = mkdtempSync(join(tmpdir(), "mandu-npm-pack-"));
  tarball = packPrivate(tmp);

  // Install the tarball into a fresh project (no devDeps → no tsx available).
  installed = join(tmp, "consumer");
  mkdirSync(installed, { recursive: true });
  const nm = join(installed, "node_modules");
  const env = npmEnv(tmp);
  assert.equal(spawnSync("npm", ["init", "-y"], { cwd: installed, stdio: "ignore", env }).status, 0);
  const inst = spawnSync("npm", ["install", "--silent", "--no-audit", "--no-fund", "--offline", tarball], {
    cwd: installed, encoding: "utf8", timeout: 180_000, env,
  });
  // --offline can fail if npm wants to touch the registry for metadata; retry online.
  if (inst.status !== 0) {
    const online = spawnSync("npm", ["install", "--silent", "--no-audit", "--no-fund", tarball], {
      cwd: installed, encoding: "utf8", timeout: 180_000, env,
    });
    assert.equal(online.status, 0, `npm install failed:\n${online.stdout}\n${online.stderr}`);
  }
  assert.ok(existsSync(join(nm, ".bin", "mandu")), "the mandu bin was not installed");
  // The pack and the install filled the private cache, not the real ~/.npm.
  assert.ok(existsSync(npmCacheDir(tmp)), "npm used the test's private cache");
});

after(() => {
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

test("the tarball ships the bin + all bundles, and NO source/tests", () => {
  const list = spawnSync("tar", ["tzf", tarball], { encoding: "utf8" }).stdout
    .split("\n").map((l) => l.replace(/^package\//, "")).filter(Boolean);
  assert.ok(list.includes("bin/mandu.mjs"), "bin/mandu.mjs missing from tarball");
  const bundles = list.filter((l) => /^dist\/.*\.mjs$/.test(l));
  assert.ok(bundles.length >= 10, `expected ≥10 dist bundles, got ${bundles.length}: ${bundles.join(",")}`);
  assert.ok(bundles.includes("dist/mandu.mjs") && bundles.includes("dist/arbiter.mjs"));
  // Lean: no source or tests shipped.
  assert.ok(!list.some((l) => l.startsWith("src/")), "src/ leaked into the tarball");
  // The build record is a checkout's (packaging.md §5.1): it names the build
  // machine's paths and means nothing in an install.
  assert.ok(!list.includes("dist/.bundle-stamp.json"), "the build record leaked into the tarball");
  assert.ok(!list.some((l) => l.startsWith("dist/.build.lock")), "the build lock leaked into the tarball");
  assert.ok(!list.some((l) => l.startsWith("test/")), "test/ leaked into the tarball");
});

test("the tarball ships the npm README, and the installed copy is the in-tree one", () => {
  // Release checklist d7: without a README the npm page is blank.
  const list = spawnSync("tar", ["tzf", tarball], { encoding: "utf8" }).stdout
    .split("\n").map((l) => l.replace(/^package\//, "")).filter(Boolean);
  assert.ok(list.includes("README.md"), `README.md missing from tarball: ${list.filter((l) => !l.startsWith("dist/")).join(",")}`);
  const shipped = readFileSync(join(installed, "node_modules", "@mandusec", "mandu", "README.md"), "utf8");
  assert.equal(shipped, readFileSync(join(PKG_ROOT, "README.md"), "utf8"));
});

test("the tarball ships LICENSE and NOTICE (Apache-2.0 §4(d)), the in-tree copies", () => {
  const list = spawnSync("tar", ["tzf", tarball], { encoding: "utf8" }).stdout
    .split("\n").map((l) => l.replace(/^package\//, "")).filter(Boolean);
  for (const f of ["LICENSE", "NOTICE"]) {
    assert.ok(list.includes(f), `${f} missing from tarball`);
    const shipped = readFileSync(join(installed, "node_modules", "@mandusec", "mandu", f), "utf8");
    assert.equal(shipped, readFileSync(join(PKG_ROOT, f), "utf8"), f);
  }
});

test("npm-installed doctor recommends the exact npm release from the public release list", async () => {
  const server = createServer((_req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify([{ tag_name: "v99.0.0", draft: false, body: "" }]));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const child = spawn(join(installed, "node_modules/.bin/mandu"), ["doctor"], {
      cwd: installed, env: npmEnv(tmp, {
        HOME: tmp, MANDU_HOME: join(tmp, "update-home"), MANDU_MODE: "off",
        MANDU_UPDATE_CHECK: "1", MANDU_UPDATE_CHECK_URL: `http://127.0.0.1:${address.port}/releases`,
      }), stdio: ["ignore", "pipe", "pipe"], timeout: 60_000,
    });
    let stdout = "", stderr = "";
    child.stdout.on("data", (part) => { stdout += part; });
    child.stderr.on("data", (part) => { stderr += part; });
    const [code] = await once(child, "close");
    assert.equal(code, 0, stderr);
    assert.match(stdout, /to update: npm install -g @mandusec\/mandu@99\.0\.0/);
    assert.doesNotMatch(stdout, /to update: curl/);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("the installed `mandu` runs from the bundle with plain node (no tsx, no repo)", () => {
  // No tsx in a dependency install; if it runs, it's the bundle. status is
  // read-only and exits 0 regardless of what's running.
  const bin = join(installed, "node_modules", ".bin", "mandu");
  const r = spawnSync(bin, ["status"], {
    cwd: installed,
    encoding: "utf8",
    timeout: 30_000,
    // Its own runtime dir: never the caller's, nor the shared /tmp/mandu (test-runtime.ts).
    env: { ...process.env, MANDU_ARBITER_SOCK: join(tmp, "nope.sock"), MANDU_RUNTIME_DIR: join(tmp, "rt") },
  });
  assert.equal(r.status, 0, `mandu status failed:\n${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout, /^  arbiter:   (running|not running) \(/m, "status did not print the arbiter line");
  // No tsx was consulted (it isn't installed) — sanity that the consumer is bundle-only.
  assert.ok(!existsSync(join(installed, "node_modules", "tsx")), "tsx unexpectedly present in the consumer install");
});

test("the tarball records its commit, and the installed `mandu version` reports it, its own install and its problems", () => {
  // packaging.md §11.7: an install has no git, so the build records the
  // commit in dist/build-info.json; `mandu version` reads it back.
  const info = JSON.parse(spawnSync("tar", ["-xzOf", tarball, "package/dist/build-info.json"], { encoding: "utf8" }).stdout) as Record<string, unknown>;
  // Public snapshots name the internal source in their commit trailer;
  // their own HEAD is the public commit. A git-less release pack names both.
  const commits = checkoutCommits(join(PKG_ROOT, ".."));
  const source = process.env["MANDU_BUILD_SOURCE_COMMIT"]?.trim().toLowerCase() || commits.source;
  const publicCommit = process.env["MANDU_BUILD_PUBLIC_COMMIT"]?.trim().toLowerCase() || commits.public;
  assert.equal(info["sourceCommit"], source, "the source commit is the build override, snapshot trailer, or source HEAD");
  assert.equal(info["publicCommit"], publicCommit, "the public commit is the build override or public HEAD");
  assert.equal(info["version"], JSON.parse(readFileSync(join(PKG_ROOT, "package.json"), "utf8")).version);

  const bin = join(installed, "node_modules", ".bin");
  const pkg = join(installed, "node_modules", "@mandusec", "mandu");
  const env = {
    // This install's bin first; node's own dir for the shebang. No other mandu.
    PATH: `${bin}:${dirname(process.execPath)}`,
    HOME: join(tmp, "home"),
    MANDU_RUNTIME_DIR: join(tmp, "rt-version"),
    MANDU_ARBITER_SOCK: join(tmp, "nope.sock"),
    // The global npm folder is a private prefix, never this host's.
    npm_config_prefix: join(tmp, "npm-global"),
    npm_config_cache: npmCacheDir(tmp),
  };
  const r = spawnSync(join(bin, "mandu"), ["version", "--json"], { cwd: installed, encoding: "utf8", timeout: 60_000, env });
  assert.equal(r.status, 0, `mandu version failed:\n${r.stdout}\n${r.stderr}`);
  const rep = JSON.parse(r.stdout) as {
    self: { kind: string; root: string; invoked: string; commitsFrom: string; sourceCommit: string | null; publicCommit: string | null };
    path: Array<{ path: string; kind: string; running: boolean }>;
    services: { running: boolean } | null;
    problems: Array<{ id: string }>;
  };
  assert.equal(rep.self.kind, "npm");
  assert.equal(realpathSync(rep.self.root), realpathSync(pkg));
  assert.equal(rep.self.invoked, join(bin, "mandu"));
  assert.equal(rep.self.commitsFrom, "build-info");
  assert.equal(rep.self.sourceCommit, source);
  assert.equal(rep.self.publicCommit, publicCommit);
  assert.deepEqual(rep.path.map((e) => [e.path, e.kind, e.running]), [[join(bin, "mandu"), "npm", true]]);
  assert.equal(rep.services?.running, false);
  assert.deepEqual(rep.problems, [], JSON.stringify(rep.problems));

  // The text form, and `--version` is still the one line.
  const text = spawnSync(join(bin, "mandu"), ["version"], { cwd: installed, encoding: "utf8", timeout: 60_000, env });
  assert.match(text.stdout, new RegExp(`commit: +source ${source?.slice(0, 12)}`));
  const one = spawnSync(join(bin, "mandu"), ["--version"], { cwd: installed, encoding: "utf8", timeout: 30_000, env });
  assert.equal(one.stdout, `mandu ${String(info["version"])}\n`);

  // MANDU_DEV_REPO left in a shell from a source install points this npm
  // mandu's services at that tree: named, with its fix.
  const forced = spawnSync(join(bin, "mandu"), ["version", "--json"], {
    cwd: installed, encoding: "utf8", timeout: 60_000, env: { ...env, MANDU_DEV_REPO: join(tmp, "old-checkout") },
  });
  const ids = (JSON.parse(forced.stdout) as { problems: Array<{ id: string }> }).problems.map((p) => p.id);
  assert.deepEqual(ids, ["forced-dev-layout"]);
});

test("the tarball ships Mandu's bubblewrap profile and the installed `mandu setup --print` emits it byte for byte", () => {
  // rootless-confinement-ubuntu-2404.md §3.2, §12.3: an npm-installed user has
  // no scripts/ directory; the fix command must work from the package alone.
  const list = spawnSync("tar", ["tzf", tarball], { encoding: "utf8" }).stdout
    .split("\n").map((l) => l.replace(/^package\//, "")).filter(Boolean);
  const bin = join(installed, "node_modules", ".bin", "mandu");
  const r = spawnSync(bin, ["setup", "--print"], { cwd: installed, encoding: "utf8", timeout: 30_000 });
  assert.equal(r.status, 0, `mandu setup --print failed:\n${r.stdout}\n${r.stderr}`);
  assert.ok(list.includes("dist/apparmor/mandu-bwrap"), "dist/apparmor/mandu-bwrap missing from tarball");
  for (const old of ["bwrap", "unshare"]) assert.ok(!list.includes(`dist/apparmor/${old}`), `the old ${old} grant is still shipped`);
  const inTree = readFileSync(join(PKG_ROOT, "..", "scripts", "apparmor", "mandu-bwrap"), "utf8");
  const shipped = readFileSync(join(installed, "node_modules", "@mandusec", "mandu", "dist", "apparmor", "mandu-bwrap"), "utf8");
  assert.equal(shipped, inTree, "the shipped profile differs from scripts/apparmor/mandu-bwrap");
  assert.ok(r.stdout.includes(inTree.replace(/\n$/, "")), "--print is not the in-tree profile verbatim");
  // The printed install command names the INSTALLED asset, not a checkout path.
  assert.match(r.stdout, /sudo install .*node_modules\/@mandusec\/mandu\/dist\/apparmor\/mandu-bwrap \/etc\/apparmor\.d\/mandu-bwrap/);
  assert.match(r.stdout, /sudo install -m 0755 -o root -g root \/usr\/bin\/bwrap \/usr\/lib\/mandu\/bin\/bwrap/);
});
