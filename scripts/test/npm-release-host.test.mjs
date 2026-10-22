// npm-release-host.test.mjs — the npm-release VM suite's host prep
// (scripts/matrix/suites/npm-release.host.sh; docs/design/testing/os-test-matrix.md
// §10.18) decides what the guest installs: one exact registry version for
// every target, or the candidate tarball; the version an existing user
// upgrades from; and which credentials go into ephemeral/ (none unless the
// live legs are asked for).
//
// The host script runs in a throwaway tree with npm stubbed (a fixed
// registry answer: versions 0.0.0-stage, 0.2.0-beta.6, 0.2.0-beta.7), so
// nothing is fetched.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { tmpDir } from "./lib/tmp-dir.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

const NPM_STUB = `#!/bin/sh
# npm view <spec> <field> — a fixed registry.
[ "$1" = view ] || exit 1
case "$2 $3" in
  "@mandusec/mandu@latest version"|"@mandusec/mandu@0.2.0-beta.7 version") echo 0.2.0-beta.7 ;;
  "@mandusec/mandu@0.2.0-beta.6 version") echo 0.2.0-beta.6 ;;
  "@mandusec/mandu@^0.2.0-beta.0 version") printf "%s\\n" "@mandusec/mandu@0.2.0-beta.6 '0.2.0-beta.6'" "@mandusec/mandu@0.2.0-beta.7 '0.2.0-beta.7'" ;;
  "@mandusec/mandu@0.2.0-beta.7 dist.shasum") echo sha-b7 ;;
  "@mandusec/mandu@0.2.0-beta.6 dist.shasum") echo sha-b6 ;;
  "@mandusec/mandu versions") echo '["0.0.0-stage","0.2.0-beta.6","0.2.0-beta.7"]' ;;
  *) exit 1 ;;
esac
`;

function tree() {
  const t = tmpDir("npm-release-host-");
  const put = (rel, text, mode) => {
    mkdirSync(dirname(join(t, rel)), { recursive: true });
    writeFileSync(join(t, rel), text);
    if (mode) chmodSync(join(t, rel), mode);
  };
  const copy = (rel) => { mkdirSync(dirname(join(t, rel)), { recursive: true }); copyFileSync(join(REPO, rel), join(t, rel)); };
  copy("scripts/matrix/suites/npm-release.host.sh");
  copy("scripts/matrix/lib/reduce-credential.mjs");
  copy("scripts/matrix/lib/reduce-codex-auth.mjs");
  copy("launcher/src/agent-versions.ts");
  for (const f of ["fake-model.mjs", "agent-leg.sh", "env-twin-check.mjs"]) put(`scripts/matrix/suites/fresh-agents/${f}`, "");
  put("scripts/matrix/suites/npm-release/timing-leg.sh", "");
  put("bin/npm", NPM_STUB, 0o755);
  mkdirSync(join(t, "art")); mkdirSync(join(t, "home"));
  return t;
}

function prep(t, env = {}) {
  return spawnSync("bash", [join(t, "scripts/matrix/suites/npm-release.host.sh")], {
    encoding: "utf8",
    env: {
      PATH: `${join(t, "bin")}:${process.env.PATH}`, HOME: join(t, "home"), MANDU_HOME: join(t, "home", ".mandu"),
      ARTIFACT_DIR: join(t, "art"), REPO_ROOT: t, ...env,
    },
  });
}
const art = (t, f) => readFileSync(join(t, "art", f), "utf8").trim();

test("default: @mandusec/mandu@latest, resolved to one exact version, with its registry sha1", () => {
  const t = tree();
  const r = prep(t);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(art(t, "PACKAGE"), "registry @mandusec/mandu@0.2.0-beta.7");
  assert.equal(art(t, "EXPECT_VERSION"), "0.2.0-beta.7");
  assert.equal(art(t, "EXPECT_SHASUM"), "sha-b7");
  assert.equal(art(t, "COMMIT"), "npm:0.2.0-beta.7");
  for (const f of ["fake-model.mjs", "agent-leg.sh", "env-twin-check.mjs", "timing-leg.sh"]) assert.ok(existsSync(join(t, "art", f)), f);
});

test("a range resolves to its highest match, so every target tests the same version", () => {
  const t = tree();
  const r = prep(t, { NPM_RELEASE_PACKAGE: "@mandusec/mandu@^0.2.0-beta.0" });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(art(t, "EXPECT_VERSION"), "0.2.0-beta.7");
});

test("upgrade-from auto: the published version before the one under test; stage builds never count", () => {
  const t = tree();
  prep(t);
  assert.equal(art(t, "UPGRADE_FROM"), "0.2.0-beta.6");
  const t2 = tree();
  prep(t2, { NPM_RELEASE_PACKAGE: "@mandusec/mandu@0.2.0-beta.6" });
  assert.equal(art(t2, "UPGRADE_FROM"), "none");
  const t3 = tree();
  prep(t3, { NPM_RELEASE_UPGRADE_FROM: "none" });
  assert.equal(art(t3, "UPGRADE_FROM"), "none");
});

test("a candidate tarball: copied in, its own version, its sha1, and the upgrade is from what npm serves", () => {
  const t = tree();
  const pkg = join(t, "pkgsrc", "package");
  mkdirSync(pkg, { recursive: true });
  writeFileSync(join(pkg, "package.json"), JSON.stringify({ name: "@mandusec/mandu", version: "0.2.0-beta.8" }));
  const tgz = join(t, "mandusec-mandu-0.2.0-beta.8.tgz");
  assert.equal(spawnSync("tar", ["-czf", tgz, "-C", join(t, "pkgsrc"), "package"]).status, 0);
  const r = prep(t, { NPM_RELEASE_PACKAGE: tgz });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(art(t, "PACKAGE"), "file mandusec-mandu-0.2.0-beta.8.tgz");
  assert.equal(art(t, "EXPECT_VERSION"), "0.2.0-beta.8");
  assert.ok(existsSync(join(t, "art", "mandusec-mandu-0.2.0-beta.8.tgz")));
  assert.match(art(t, "EXPECT_SHASUM"), /^[0-9a-f]{40}$/);
  assert.equal(art(t, "UPGRADE_FROM"), "0.2.0-beta.7");
  assert.equal(prep(tree(), { NPM_RELEASE_PACKAGE: join(t, "missing.tgz") }).status, 1);
});

test("agents: latest by default, the launcher's tested max on request", () => {
  const t = tree();
  prep(t);
  assert.equal(art(t, "AGENT_VERSIONS"), "claude=latest\ncodex=latest");
  const t2 = tree();
  const r = prep(t2, { NPM_RELEASE_AGENT_VERSIONS: "tested" });
  assert.equal(r.status, 0, r.stderr);
  for (const l of art(t2, "AGENT_VERSIONS").split("\n")) assert.match(l, /^(claude|codex)=\d+\.\d+\.\d+/);
});

test("no live legs asked for: no ephemeral/ and no credential anywhere in the share", () => {
  const t = tree();
  mkdirSync(join(t, "home", ".mandu"), { recursive: true });
  writeFileSync(join(t, "home", ".mandu", "secrets.json"), JSON.stringify({ anthropic_api_key: "sk-ant-api-SECRET", openai_api_key: "sk-OPENAI-SECRET" }));
  assert.equal(prep(t).status, 0);
  assert.ok(!existsSync(join(t, "art", "ephemeral")));
  const all = spawnSync("grep", ["-r", "SECRET", join(t, "art")], { encoding: "utf8" });
  assert.equal(all.stdout, "");
});

test("live: the API keys go into ephemeral/ only, 0600; with no OpenAI key, the reduced codex login", () => {
  const t = tree();
  mkdirSync(join(t, "home", ".mandu"), { recursive: true });
  writeFileSync(join(t, "home", ".mandu", "secrets.json"), JSON.stringify({ anthropic_api_key: "sk-ant-api-SECRET", openai_api_key: "sk-OPENAI-SECRET" }));
  assert.equal(prep(t, { NPM_RELEASE_LIVE: "1" }).status, 0);
  assert.equal(readFileSync(join(t, "art", "ephemeral", "anthropic.key"), "utf8"), "sk-ant-api-SECRET");
  assert.equal(readFileSync(join(t, "art", "ephemeral", "openai.key"), "utf8"), "sk-OPENAI-SECRET");
  for (const f of ["anthropic.key", "openai.key"]) assert.equal(statSync(join(t, "art", "ephemeral", f)).mode & 0o777, 0o600);

  const t2 = tree();
  mkdirSync(join(t2, "home", ".codex"), { recursive: true });
  const exp = Math.floor(Date.now() / 1000) + 7200;
  const at = `h.${Buffer.from(JSON.stringify({ exp })).toString("base64url")}.s`;
  writeFileSync(join(t2, "home", ".codex", "auth.json"), JSON.stringify({ auth_mode: "chatgpt", tokens: { access_token: at, refresh_token: "RT-SECRET" } }));
  const r = prep(t2, { NPM_RELEASE_LIVE: "1" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /live Claude legs will SKIP/);
  const auth = readFileSync(join(t2, "art", "ephemeral", "codex-auth.json"), "utf8");
  assert.ok(auth.includes(at) && !auth.includes("RT-SECRET"));
});
