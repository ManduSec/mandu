/**
 * install-sh e2e — the `curl | sh` installer (scripts/install.sh) over the
 * REAL artifact: `npm pack` the package (prepack's bundle build, run into a
 * private stage by test/lib/pack-private.ts so a parallel test file never races
 * the shared launcher/dist), run the
 * installer with `--package <tarball>` into a throwaway prefix and bin dir,
 * then run the installed `mandu`. The Node on PATH meets the floor (the
 * test host's), so this is the no-download branch; the download branch is
 * covered offline by test/unit/install-sh.test.ts.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PKG_ROOT, packPrivate } from "../lib/pack-private.js";

const INSTALL = join(PKG_ROOT, "..", "scripts", "install.sh");
const VERSION = (JSON.parse(readFileSync(join(PKG_ROOT, "package.json"), "utf8")) as { version: string }).version;

let tmp: string;
let tarball: string;

before(() => {
  tmp = mkdtempSync(join(tmpdir(), "mandu-install-e2e-"));
  tarball = packPrivate(tmp);
});

after(() => {
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

test("install.sh --package <tarball> installs a working `mandu` for the user, no sudo, own prefix", () => {
  const prefix = join(tmp, "prefix");
  const binDir = join(tmp, "bin");
  const r = spawnSync("sh", [INSTALL, "--package", tarball, "--prefix", prefix, "--bin-dir", binDir], {
    encoding: "utf8", timeout: 300_000, env: { ...process.env, HOME: tmp, npm_config_cache: join(tmp, "npm-cache") },
  });
  const out = r.stdout + r.stderr;
  assert.equal(r.status, 0, out);
  assert.match(out, /using Node v\d+/, "the host's Node meets the floor: no download");
  assert.match(out, new RegExp(`installed mandu ${VERSION.replace(/\./g, "\\.")}`));
  const mandu = join(binDir, "mandu");
  const v = spawnSync(mandu, ["--version"], { encoding: "utf8" });
  assert.equal(v.status, 0, v.stderr);
  assert.equal(v.stdout.trim(), `mandu ${VERSION}`);
  // A read-only command runs from the installed bundle with a nonexistent arbiter.
  const s = spawnSync(mandu, ["status"], { encoding: "utf8", timeout: 30_000, env: { ...process.env, MANDU_ARBITER_SOCK: join(tmp, "nope.sock"), MANDU_RUNTIME_DIR: join(tmp, "rt") } });
  assert.equal(s.status, 0, s.stdout + s.stderr);
  // The package lives in the installer's own prefix, not the system npm's.
  assert.ok(existsSync(join(prefix, "pkg", "lib", "node_modules", "@mandusec", "mandu", "bin", "mandu.mjs")));
});

// The release one-liner (packaging.md §11.4): a release's install.sh names its
// tarball URL and SHA-256 as the default, and installs that file or nothing.
// Over the REAL tarball, served as a file:// URL.
test("a release's install.sh installs its own verified tarball by URL, and refuses a different one", () => {
  const sum = createHash("sha256").update(readFileSync(tarball)).digest("hex");
  const copy = join(tmp, "release-install.sh");
  writeFileSync(copy, readFileSync(INSTALL, "utf8")
    .replace(/^PACKAGE_DEFAULT=".*"$/m, `PACKAGE_DEFAULT="file://${tarball}"`)
    .replace(/^PACKAGE_DEFAULT_SHA256=".*"$/m, `PACKAGE_DEFAULT_SHA256="${sum}"`));
  const env = { ...process.env, HOME: tmp, npm_config_cache: join(tmp, "npm-cache") };
  const prefix = join(tmp, "rel-prefix");
  const binDir = join(tmp, "rel-bin");
  const r = spawnSync("sh", [copy, "--prefix", prefix, "--bin-dir", binDir], { encoding: "utf8", timeout: 300_000, env });
  const out = r.stdout + r.stderr;
  assert.equal(r.status, 0, out);
  assert.match(out, new RegExp(`verified file://.* \\(sha256 ${sum}\\)`));
  assert.equal(spawnSync(join(binDir, "mandu"), ["--version"], { encoding: "utf8" }).stdout.trim(), `mandu ${VERSION}`);

  // The same script pointed at a tampered copy under the release's hash installs nothing.
  const bad = join(tmp, "tampered.tgz");
  writeFileSync(bad, Buffer.concat([readFileSync(tarball), Buffer.from("x")]));
  const t = spawnSync("sh", [copy, "--package", `file://${bad}`, "--sha256", sum, "--prefix", join(tmp, "bad-prefix"), "--bin-dir", join(tmp, "bad-bin")],
    { encoding: "utf8", timeout: 300_000, env });
  assert.notEqual(t.status, 0);
  assert.match(t.stdout + t.stderr, /checksum mismatch .* not installing/);
  assert.ok(!existsSync(join(tmp, "bad-bin", "mandu")));
});

// Release review, first run (2026-09-26): a fresh
// install into the installer's DEFAULT prefix (~/.local/share/mandu) put
// pkg/bin and pkg/lib at depth 5 under HOME, so every launch and every
// `mandu doctor --secrets` warned "secrets NOT covered by the walk" about
// Mandu's own files. The walk now prunes Mandu's own install trees
// (arbiter/policy/secret-discovery.ts `manduInstallTrees`). Proven here over
// the REAL installed artifact: the installed `mandu doctor --secrets` runs
// its throwaway arbiter from the installed bundle, over a HOME that holds the
// install plus a real-shaped secret elsewhere.
test("installed Mandu is not 'not covered': doctor --secrets over a HOME holding the default-prefix install prunes it (mandu-install), no depth WARNING, and a secret elsewhere is still found", () => {
  const home = join(tmp, "fresh-home");
  mkdirSync(home, { recursive: true });
  // The test runner may itself run under Mandu: no MANDU_* / XDG_* leaks in.
  const baseEnv: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (!k.startsWith("MANDU_") && !k.startsWith("XDG_")) baseEnv[k] = v;
  }
  // A runtime dir of its own: without one the installed mandu would use the
  // host's shared /tmp/mandu (test-runtime.ts).
  const env = { ...baseEnv, HOME: home, npm_config_cache: join(tmp, "npm-cache"), MANDU_RUNTIME_DIR: join(tmp, "rt") };
  const r = spawnSync("sh", [INSTALL, "--package", tarball], { encoding: "utf8", timeout: 300_000, env });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const prefix = join(home, ".local", "share", "mandu");
  assert.ok(existsSync(join(prefix, "pkg", "bin")), "the default prefix holds the npm prefix");

  mkdirSync(join(home, ".aws"), { recursive: true });
  writeFileSync(join(home, ".aws", "credentials"), "[default]\naws_access_key_id=AKIAFRESHUSER\n");
  const ws = join(home, "proj");
  mkdirSync(ws);
  const d = spawnSync(join(home, ".local", "bin", "mandu"), ["doctor", "--secrets", "--json"], {
    encoding: "utf8", timeout: 120_000, cwd: ws,
    env: { ...env, MANDU_ARBITER_SOCK: join(tmp, "no-arbiter.sock") },
  });
  const out = d.stdout + d.stderr;
  // --json prints the report first, then the rendered text: the JSON object is
  // the first balanced top-level block.
  const report = JSON.parse(firstJsonObject(d.stdout)) as {
    arbiter: { kind: string } | null;
    files: Array<{ path: string }>;
    notCovered: { counts: Record<string, number>; skipped: Array<{ path: string; reason: string }> };
  };
  assert.equal(report.arbiter?.kind, "throwaway", `the installed bundle's own arbiter answered: ${out}`);
  const depth = report.notCovered.skipped.filter((s) => s.reason === "depth").map((s) => s.path);
  assert.deepEqual(depth.filter((p) => p.startsWith(prefix)), [], `no depth record under the install: ${depth}`);
  assert.equal(report.notCovered.counts["depth"] ?? 0, 0, out);
  assert.ok(
    report.notCovered.skipped.some((s) => s.reason === "mandu-install" && s.path === join(prefix, "pkg")),
    `the install is pruned by name: ${JSON.stringify(report.notCovered.skipped)}`,
  );
  assert.ok(report.files.some((f) => f.path === join(home, ".aws", "credentials")), `the secret elsewhere is found: ${out}`);
  assert.doesNotMatch(out, /NOT covered/);
  assert.doesNotMatch(out, /AKIAFRESHUSER/, "the dry run never carries a secret's content");
});

/** The first top-level `{…}` block of `s` (string-aware brace matching). */
function firstJsonObject(s: string): string {
  const start = s.indexOf("{");
  if (start < 0) throw new Error(`no JSON object in: ${s.slice(0, 500)}`);
  let depth = 0;
  let inStr = false;
  for (let i = start; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (c === "\\") i++;
      else if (c === '"') inStr = false;
    } else if (c === '"') inStr = true;
    else if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return s.slice(start, i + 1);
  }
  throw new Error(`unbalanced JSON in: ${s.slice(0, 500)}`);
}
