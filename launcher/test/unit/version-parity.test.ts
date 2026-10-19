/**
 * version-parity.test — Mandu releases as ONE product with ONE version
 * (docs/design/distribution/packaging.md §11.2). There is no root package.json/workspace, so
 * nothing else keeps the 15 npm manifests and the Cargo workspace in step;
 * this test does. Bump with scripts/set-version.sh, never by hand.
 *
 * Also pins the two places that print the version: `mandu --version` reads
 * the launcher's package.json (run.ts launcherVersion), and the inspect-mcp
 * server announces its own package.json version in `initialize`.
 *
 * Pure repo-hygiene: no protection axis is involved (no arbiter, no agent).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const read = (rel: string) => readFileSync(join(REPO, rel), "utf8");

const SEMVER = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;

function packageJsonPaths(): string[] {
  const out: string[] = [];
  for (const parent of ["", "interceptors", "tests"]) {
    const dir = join(REPO, parent);
    for (const name of readdirSync(dir)) {
      const pj = join(dir, name, "package.json");
      if (name !== "node_modules" && existsSync(pj) && statSync(pj).isFile()) {
        out.push(join(parent, name, "package.json"));
      }
    }
  }
  return out.sort();
}

const launcherVersion = (): string => (JSON.parse(read("launcher/package.json")) as { version: string }).version;

test("the release version is a real semver, not a 0.0.0-<tag> placeholder", () => {
  const v = launcherVersion();
  assert.match(v, SEMVER, v);
  assert.doesNotMatch(v, /^0\.0\.0-/, "placeholder versions ended with 0.1.0 (2026-09-25)");
});

test("every package.json carries the launcher's version", () => {
  const want = launcherVersion();
  const pkgs = packageJsonPaths();
  assert.ok(pkgs.length >= 15, `found ${pkgs.length} package.json files`);
  for (const rel of pkgs) {
    const pj = JSON.parse(read(rel)) as { name: string; version: string };
    assert.equal(pj.version, want, `${rel} (${pj.name})`);
  }
});

test("the Cargo workspace carries the same version, and every crate inherits it", () => {
  const want = launcherVersion();
  const ws = read("interceptors/Cargo.toml");
  const m = /\[workspace\.package\][^[]*?\nversion = "([^"]+)"/.exec(ws);
  assert.ok(m, "[workspace.package] version");
  assert.equal(m![1], want, "interceptors/Cargo.toml [workspace.package].version");
  const crates = readdirSync(join(REPO, "interceptors")).filter((d) =>
    existsSync(join(REPO, "interceptors", d, "Cargo.toml")),
  );
  assert.ok(crates.length >= 5, `found ${crates.length} crates`);
  for (const c of crates) {
    const toml = read(join("interceptors", c, "Cargo.toml"));
    assert.match(toml, /^version\.workspace = true$/m, `${c}/Cargo.toml inherits the workspace version`);
  }
});

test("the MCP servers (inspect-mcp, policy-mcp) announce the same version (a constant the bundle can carry)", () => {
  for (const pkg of ["inspect-mcp", "policy-mcp"]) {
    const src = read(`interceptors/${pkg}/src/mcp-server.ts`);
    const m = /^const SERVER_VERSION = "([^"]+)";/m.exec(src);
    assert.ok(m, `${pkg} SERVER_VERSION constant`);
    assert.equal(m![1], launcherVersion(), pkg);
  }
});

test("package-lock.json files agree with their package.json", () => {
  for (const rel of packageJsonPaths()) {
    const lock = rel.replace(/package\.json$/, "package-lock.json");
    if (!existsSync(join(REPO, lock))) continue;
    const want = (JSON.parse(read(rel)) as { version: string }).version;
    const lj = JSON.parse(read(lock)) as { version?: string; packages?: Record<string, { version?: string }> };
    if (lj.version !== undefined) assert.equal(lj.version, want, `${lock} version`);
    const root = lj.packages?.[""];
    if (root?.version !== undefined) assert.equal(root.version, want, `${lock} packages[""].version`);
  }
});

test("scripts/set-version.sh is the bump path and mentions the tag step", () => {
  const src = read("scripts/set-version.sh");
  assert.match(src, /version-parity\.test\.ts/);
  assert.match(src, /git tag v/);
});
