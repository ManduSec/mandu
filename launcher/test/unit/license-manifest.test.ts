/**
 * license-manifest.test — the repo's licensing manifest cannot drift
 * (docs/design/distribution/licensing.md §7, decisions 2026-09-24 and 2026-10-09).
 *
 * Pins: the root LICENSE is the canonical Apache-2.0 text; the published npm
 * package (this one) carries identical LICENSE/NOTICE copies; every package.json
 * and Cargo manifest declares the license the open-core line assigns it; the
 * enterprise-side directories carry their own LICENSE; and every source file
 * that names the DualView reference (adfi-openclaw) is accounted for in NOTICE,
 * so a newly copied module cannot land without its attribution.
 *
 * Pure repo-hygiene: no protection axis is involved (no arbiter, no agent).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const read = (rel: string) => readFileSync(join(REPO, rel), "utf8");

/** sha256 of https://www.apache.org/licenses/LICENSE-2.0.txt as fetched 2026-10-09. */
const APACHE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30";

const CORE_LICENSE = "Apache-2.0";
const NO_PRIVATE = !existsSync(join(REPO, "private"))
  && "no private/ here (a public checkout: the enterprise components are not in it)";
/** Enterprise side of the open-core line (licensing.md §6): each is a
 *  directory directly under private/ that carries its own LICENSE (the
 *  rule, not a list, so no enterprise component is named in a public file).
 *  private/ is left out of the public export, so a public checkout has none. */
function enterpriseDirs(): string[] {
  const priv = join(REPO, "private");
  if (!existsSync(priv)) return [];
  return readdirSync(priv, { withFileTypes: true })
    .filter((e) => e.isDirectory() && existsSync(join(priv, e.name, "LICENSE")))
    .map((e) => `private/${e.name}`)
    .sort();
}
const ENTERPRISE_DIRS = enterpriseDirs();
const ENTERPRISE_PKG_LICENSE = "SEE LICENSE IN LICENSE";
/** The arbiter client crate: Apache-2.0 before the rest of the tree was, so it
 *  declares the license itself and carries its own copy of the text. */
const CLIENT_CRATE = "interceptors/mandu-arbiter";

function packageJsonPaths(): string[] {
  const out: string[] = [];
  for (const parent of ["", "interceptors", "tests", "private"]) {
    const dir = join(REPO, parent);
    if (!existsSync(dir)) continue;
    for (const name of readdirSync(dir)) {
      const pj = join(dir, name, "package.json");
      if (name !== "node_modules" && existsSync(pj) && statSync(pj).isFile()) {
        out.push(join(parent, name, "package.json"));
      }
    }
  }
  return out.sort();
}

test("root LICENSE is the canonical Apache-2.0 text and the npm package ships identical copies", () => {
  const root = read("LICENSE");
  assert.equal(createHash("sha256").update(root).digest("hex"), APACHE_SHA256);
  assert.match(root, /Apache License\s+Version 2\.0, January 2004/);
  assert.equal(read("launcher/LICENSE"), root, "launcher/LICENSE must equal the root LICENSE");
  assert.equal(read("launcher/NOTICE"), read("NOTICE"), "launcher/NOTICE must equal the root NOTICE");
});

test("every package.json declares the license the open-core line assigns it", () => {
  const paths = packageJsonPaths();
  assert.ok(paths.length >= 15, `expected the 15 TS packages, found ${paths.length}`);
  for (const rel of paths) {
    const pkg = JSON.parse(read(rel)) as { license?: string; private?: boolean };
    const enterprise = ENTERPRISE_DIRS.some((d) => rel.startsWith(d + "/"));
    assert.equal(pkg.license, enterprise ? ENTERPRISE_PKG_LICENSE : CORE_LICENSE, rel);
    if (enterprise) assert.equal(pkg.private, true, `${rel}: enterprise packages stay private`);
  }
});

test("Cargo workspace is Apache-2.0; the mandu-arbiter client crate declares it too, with its own LICENSE", () => {
  const ws = read("interceptors/Cargo.toml");
  assert.match(ws, /^license = "Apache-2\.0"$/m);
  const crate = read(`${CLIENT_CRATE}/Cargo.toml`);
  assert.match(crate, /^license = "Apache-2\.0"$/m);
  assert.equal(read(`${CLIENT_CRATE}/LICENSE`), read("LICENSE"), `${CLIENT_CRATE}/LICENSE must equal the root LICENSE`);
  // Every other crate inherits the workspace license.
  for (const name of readdirSync(join(REPO, "interceptors"))) {
    const p = join("interceptors", name, "Cargo.toml");
    if (!existsSync(join(REPO, p)) || p.startsWith(CLIENT_CRATE)) continue;
    assert.match(read(p), /^license\.workspace = true$/m, p);
  }
});

test("NOTICE names the enterprise side of the open-core line", () => {
  const notice = read("NOTICE");
  assert.match(notice, /SIEM integration/);
  assert.match(notice, /not covered by the root LICENSE/);
});

test("enterprise-side directories carry their own LICENSE", { skip: NO_PRIVATE }, () => {
  assert.ok(ENTERPRISE_DIRS.length > 0, "private/ holds the enterprise components: none carries a LICENSE");
  for (const d of ENTERPRISE_DIRS) {
    const lic = read(`${d}/LICENSE`);
    assert.match(lic, /NOT licensed under the Apache-2\.0/, `${d}/LICENSE`);
  }
});

// The OS test matrix copies the tree into its VM guests WITHOUT .git (on
// purpose: suites must not depend on repo git state), so there is nothing to
// list there. Skip with the reason; every checkout, CI included, runs it.
const NO_GIT = !existsSync(join(REPO, ".git"))
  && "no git checkout here (the OS test matrix copies the tree without .git)";

test("every source file that names the DualView reference is listed in NOTICE", { skip: NO_GIT }, () => {
  const notice = read("NOTICE");
  const tracked = execFileSync(
    "git",
    ["ls-files", "-z", "--", "*.ts", "*.js", "*.rs", "*.py"],
    { cwd: REPO, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  )
    .split("\0")
    .filter((p) => p && !p.includes("/node_modules/") && !p.includes("/vendor/"));
  assert.ok(tracked.length > 100, "git ls-files returned suspiciously few files");
  const missing: string[] = [];
  for (const rel of tracked) {
    const abs = join(REPO, rel);
    if (!existsSync(abs)) continue; // deleted in the working tree
    if (!readFileSync(abs, "utf8").includes("adfi-openclaw")) continue;
    // A file of a private package with a NOTICE of its own is listed there,
    // by its path in the package: the public NOTICE names no private file.
    const own = /^(private\/[^/]+)\/(.+)$/.exec(rel);
    if (own && existsSync(join(REPO, own[1]!, "NOTICE"))) {
      if (!read(`${own[1]}/NOTICE`).includes(`\n  ${own[2]}\n`)) missing.push(rel);
      continue;
    }
    if (!notice.includes(`\n  ${rel}\n`)) missing.push(rel);
  }
  assert.deepEqual(missing, [], `files naming adfi-openclaw but absent from NOTICE:\n${missing.join("\n")}`);
});

test("the licensing design doc records the decision", () => {
  assert.match(read("docs/design/distribution/licensing.md"), /Status: DECIDED/);
});
