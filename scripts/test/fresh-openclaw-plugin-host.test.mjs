// fresh-openclaw-plugin-host.test.mjs — the fresh-openclaw-plugin VM suite's
// host prep (scripts/matrix/suites/fresh-openclaw-plugin.host.sh;
// docs/design/testing/os-test-matrix.md §10.20): it hands the guest the scripted
// model, the OpenClaw version (the launcher's tested max by default, `latest`,
// or a version given), the Node major and the commit, and NEVER a packed
// tarball (the guest installs Mandu from its copy of the checkout).
//
// The host script runs in a throwaway tree: the real script, the launcher's
// tested-version table and the Node-major parser, with npm and curl stubbed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

// A nodejs.org release index: one current release per candidate major.
const INDEX = JSON.stringify([{ version: "v26.1.0" }, { version: "v24.16.0" }, { version: "v22.20.0" }]);

function tree({ engines = "", index = false } = {}) {
  const t = mkdtempSync(join(tmpdir(), "fresh-openclaw-plugin-host-"));
  const put = (rel, text, mode) => {
    mkdirSync(dirname(join(t, rel)), { recursive: true });
    writeFileSync(join(t, rel), text);
    if (mode) chmodSync(join(t, rel), mode);
  };
  const copy = (rel) => { mkdirSync(dirname(join(t, rel)), { recursive: true }); copyFileSync(join(REPO, rel), join(t, rel)); };
  copy("scripts/matrix/suites/fresh-openclaw-plugin.host.sh");
  copy("scripts/matrix/suites/fresh-agents/fake-model.mjs");
  copy("scripts/matrix/lib/node-major.mjs");
  copy("launcher/src/agent-versions.ts");
  // npm answers `view openclaw@<v> engines.node` with the range given (and
  // records what it was asked); curl writes the index to its -o file, or
  // has no network.
  put("bin/npm", `#!/bin/sh\necho "$*" >> "${t}/npm.log"\n${engines ? `echo '${engines}'` : "exit 1"}\n`, 0o755);
  put("index.json", INDEX);
  put("bin/curl", index
    ? `#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && cp "${t}/index.json" "$2"; shift; done\n`
    : "#!/bin/sh\nexit 1\n", 0o755);
  mkdirSync(join(t, "art"));
  return t;
}

function prep(t, env = {}) {
  return spawnSync("bash", [join(t, "scripts/matrix/suites/fresh-openclaw-plugin.host.sh")], {
    encoding: "utf8",
    env: { ...process.env, PATH: `${join(t, "bin")}:${process.env.PATH}`, ARTIFACT_DIR: join(t, "art"), REPO_ROOT: t, FRESH_OPENCLAW_VERSION: "", ...env },
  });
}
const art = (t, f) => readFileSync(join(t, "art", f), "utf8").trim();

test("tested (the default): OpenClaw at the launcher's tested max, the scripted model, no tarball", () => {
  const t = tree();
  try {
    const r = prep(t);
    assert.equal(r.status, 0, r.stderr);
    const v = art(t, "OPENCLAW_VERSION");
    const table = readFileSync(join(REPO, "launcher/src/agent-versions.ts"), "utf8");
    assert.ok(new RegExp(`openclaw:\\s*\\{[^}]*?max:\\s*"${v.replace(/\./g, "\\.")}"`).test(table), `${v} is OpenClaw's tested max`);
    assert.equal(readFileSync(join(t, "art", "fake-model.mjs"), "utf8"), readFileSync(join(REPO, "scripts/matrix/suites/fresh-agents/fake-model.mjs"), "utf8"));
    assert.ok(!readdirSync(join(t, "art")).some((f) => f.endsWith(".tgz")), "nothing is packed");
    assert.match(readFileSync(join(t, "npm.log"), "utf8"), new RegExp(`^view openclaw@${v.replace(/\./g, "\\.")} engines\\.node$`, "m"));
    assert.ok(art(t, "COMMIT").length > 0);
  } finally { rmSync(t, { recursive: true, force: true }); }
});

test("latest, or a version given: passed through as the guest's npm spec", () => {
  for (const want of ["latest", "2026.10.7"]) {
    const t = tree();
    try {
      const r = prep(t, { FRESH_OPENCLAW_VERSION: want });
      assert.equal(r.status, 0, r.stderr);
      assert.equal(art(t, "OPENCLAW_VERSION"), want);
    } finally { rmSync(t, { recursive: true, force: true }); }
  }
});

test("the Node major follows OpenClaw's engines; with nothing to read, the README's 22", () => {
  const t = tree({ engines: ">=24.16.0 <25 || >=26.1.0", index: true });
  try {
    const r = prep(t);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(art(t, "NODE_MAJOR"), "24", "OpenClaw 2026.9.x does not run on Node 22: the lowest major that does");
  } finally { rmSync(t, { recursive: true, force: true }); }
  const t2 = tree();
  try {
    assert.equal(prep(t2).status, 0);
    assert.equal(art(t2, "NODE_MAJOR"), "22", "no range read (npm unreachable): the README's 22");
  } finally { rmSync(t2, { recursive: true, force: true }); }
});
