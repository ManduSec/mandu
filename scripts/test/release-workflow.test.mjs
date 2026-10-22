// release-workflow.test.mjs — the release path (.github/workflows/release.yml,
// scripts/ci/release-pack.sh; packaging.md §11.3, continuous-integration.md
// §12): what may publish, with which credential, after which gates, and from
// which tree. There is no GitHub here to run the workflow on, so the file's
// structure is the contract this pins; release-pack.sh's refusals run for real
// in a throwaway tree. Offline, no privilege.
//
// Run: node --test scripts/test/release-workflow.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { tmpDir } from "./lib/tmp-dir.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const read = (p) => readFileSync(join(REPO, p), "utf8");
/** pins.env's KEY=value lines (ci-pins.test.mjs checks their form). */
const pins = () => Object.fromEntries(read("scripts/ci/pins.env").split("\n")
  .map((l) => /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(l)).filter(Boolean).map((m) => [m[1], m[2]]));

const NO_PYYAML = (() => { try { execFileSync("python3", ["-c", "import yaml"], { stdio: "ignore" }); return false; } catch { return "needs python3 with PyYAML"; } })();
const workflow = () => JSON.parse(execFileSync("python3", ["-c",
  "import json, sys, yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1])), default=str))",
  join(REPO, ".github", "workflows", "release.yml")], { encoding: "utf8" }));
const runs = (job) => (job.steps ?? []).map((s) => s.run ?? "").join("\n");

test("release.yml: a v* tag only; read-only by default; only the publish job can write or mint an OIDC token", { skip: NO_PYYAML }, () => {
  const doc = workflow();
  assert.deepEqual(doc.on ?? doc.true, { push: { tags: ["v*"] } });
  assert.deepEqual(doc.permissions, { contents: "read" });
  assert.equal(doc.concurrency["cancel-in-progress"], false, "a release in flight is never cancelled half-published");
  for (const [name, job] of Object.entries(doc.jobs)) {
    const perms = job.permissions ?? {};
    if (name === "publish") {
      assert.deepEqual(perms, { contents: "write", "id-token": "write" });
    } else {
      assert.ok(!Object.values(perms).includes("write"), `${name} writes nothing`);
    }
  }
});

test("release.yml: publish waits for the CI check, the pack and a maintainer's approval of the `release` environment", { skip: NO_PYYAML }, () => {
  const { jobs } = workflow();
  assert.equal(jobs.check.uses, "./.github/workflows/ci.yml", "the check is the CI workflow itself");
  assert.deepEqual([jobs.publish.needs].flat().sort(), ["check", "pack"]);
  assert.equal(jobs.publish.environment, "release");
  assert.ok(!("environment" in jobs.pack) && !("environment" in jobs.check), "nothing else runs in the publishing environment");
});

test("release.yml: no stored publish credential anywhere; npm publishes by trusted publishing with provenance, scripts off", { skip: NO_PYYAML }, () => {
  const text = read(".github/workflows/release.yml");
  assert.ok(!/\bsecrets\./.test(text), "no repository secret is read");
  assert.ok(!/NPM_TOKEN|NODE_AUTH_TOKEN/.test(text), "no npm token");
  const pub = runs(workflow().jobs.publish);
  const line = pub.split("\n").find((l) => /^\s*npm publish /.test(l));
  assert.ok(line, "the publish job runs npm publish");
  assert.ok(!/\bnpm dist-tag\b/.test(pub), "no dist-tag change beyond the publish's own --tag (the trusted publisher does not allow it)");
  for (const flag of ["--provenance", "--ignore-scripts", "--access public", "--tag latest"]) assert.ok(line.includes(flag), `npm publish ${flag}`);
  assert.match(line, /"\.\/\$TARBALL"/, "it publishes the downloaded tarball, never a pack of its own");
  assert.match(pub, /sha256sum -c SHA256SUMS/, "the bytes are checked against pack's sums first");
  assert.match(pub, /needs >= 11\.5\.1/, "the npm floor for trusted publishing is checked");
  assert.match(pub, /npm install -g --ignore-scripts [^\n]*"npm@\$PUBLISH_NPM_VERSION"/, "the npm that stages is a pinned one");
  assert.match(workflow().env.PUBLISH_NPM_VERSION, /^11\.\d+\.\d+$/, "a pinned npm 11");
  assert.ok(!/registry-url/.test(text), "no .npmrc with a placeholder token (setup-node's registry-url)");
  assert.ok(pub.indexOf("sha256sum -c") < pub.indexOf("gh release") && pub.indexOf("gh release") < pub.indexOf("npm publish"));
  assert.ok(!(workflow().jobs.publish.steps ?? []).some((s) => /actions\/checkout/.test(s.uses ?? "")),
    "the publish job checks out no code: nothing from the commit runs where the credential is");
});

test("release.yml: pack refuses a private repository, a lightweight tag, a commit that is not a snapshot on main", { skip: NO_PYYAML }, () => {
  const { pack } = workflow().jobs;
  const first = pack.steps.find((s) => s.id === "snapshot");
  assert.ok(first && pack.steps.indexOf(first) === 1, "right after the checkout");
  assert.match(first.run, /REPO_PRIVATE" = false/);
  assert.match(first.run, /Mandu-Snapshot: \[0-9a-f\]\{40\}/);
  assert.match(first.run, /object\.type <<<"\$ref"\)" = tag/);
  assert.match(first.run, /merge-base --is-ancestor HEAD FETCH_HEAD/);
  const all = runs(pack);
  assert.match(all, /bash scripts\/ci\/release-pack\.sh "\$TAG"/);
  assert.match(all, /node scripts\/ci\/release-assets\.mjs --dir release/);
  for (const s of pack.steps.filter((x) => /actions\/checkout/.test(x.uses ?? ""))) assert.equal(s.with?.["persist-credentials"], false);
});

test("release.yml: pack installs every package the bundle builds from", { skip: NO_PYYAML }, () => {
  const step = workflow().jobs.pack.steps.find((s) => /npm ci/.test(s.name ?? ""));
  const listed = new Set(step.run.split(/[\s;\\]+/).filter((w) => /^(arbiter|dashboard|fs-sync|launcher|interceptors\/[\w-]+)$/.test(w)));
  const m = JSON.parse(read("launcher/bundle-manifest.json"));
  for (const entry of [...Object.values(m.services ?? {}), ...Object.values(m.modules ?? {})]) {
    const pkg = entry.startsWith("interceptors/") ? entry.split("/").slice(0, 2).join("/") : entry.split("/")[0];
    assert.ok(listed.has(pkg), `${entry}: its package ${pkg} is installed before the pack`);
  }
});

test("release.yml builds at pins.env's node and rust, and publishes with a node whose npm can use trusted publishing", { skip: NO_PYYAML }, () => {
  const p = pins();
  const { env } = workflow();
  assert.equal(env.NODE_VERSION, p.NODE_VERSION);
  assert.equal(env.RUSTUP_TOOLCHAIN, p.RUST_VERSION);
  assert.ok(Number(env.PUBLISH_NODE_VERSION.split(".")[0]) >= 24, "node 24 bundles npm 11");
});

// ── release-pack.sh refuses what is not the public tree, before any build ──

function packTree({ privateFlag }) {
  const t = tmpDir("release-pack-");
  mkdirSync(join(t, "scripts", "ci"), { recursive: true });
  mkdirSync(join(t, "launcher", "scripts"), { recursive: true });
  copyFileSync(join(REPO, "scripts/ci/release-pack.sh"), join(t, "scripts/ci/release-pack.sh"));
  copyFileSync(join(REPO, "launcher/scripts/build-info.mjs"), join(t, "launcher/scripts/build-info.mjs"));
  writeFileSync(join(t, "launcher/package.json"), JSON.stringify({ name: "@mandusec/mandu", version: "9.9.9", ...(privateFlag ? { private: true } : {}) }));
  return t;
}

function pack(t, env = {}) {
  const clean = { ...process.env, MANDU_BUILD_PUBLIC_COMMIT: "", MANDU_BUILD_SOURCE_COMMIT: "", ...env };
  return spawnSync("bash", [join(t, "scripts/ci/release-pack.sh"), "v9.9.9"], { cwd: t, encoding: "utf8", env: clean });
}

test("release-pack.sh: a tree whose launcher is private (this repository's own) is refused with the reason", () => {
  const r = pack(packTree({ privateFlag: true }));
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stderr, /`private: true`: this is not the public tree/);
});

test("release-pack.sh: a public tree that cannot name its public commit is refused", () => {
  const r = pack(packTree({ privateFlag: false }));
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stderr, /no public commit to record/);
});

test("release-pack.sh: a tag that is not the manifests' version is refused first", () => {
  const t = packTree({ privateFlag: false });
  const r = spawnSync("bash", [join(t, "scripts/ci/release-pack.sh"), "v1.0.0"], { cwd: t, encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /tag 'v1\.0\.0' does not match the manifests' version '9\.9\.9'/);
});
