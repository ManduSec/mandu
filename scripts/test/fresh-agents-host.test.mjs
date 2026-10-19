// fresh-agents-host.test.mjs — the fresh-agents VM suite's host prep
// (scripts/matrix/suites/fresh-agents.host.sh; docs/design/testing/os-test-matrix.md
// §10.14) picks its agents from the agent registry
// (scripts/agents/agent-registry.mjs NPM_AGENTS; supported-agents.md §5.7),
// never from a list of its own, and the guest's npm package table names each
// of them by the registry's package.
//
// The host script runs in a throwaway tree: the real script, the registry and
// the launcher's tested-version table, with fresh-install's prep, the guest's
// files, npm and curl stubbed (nothing is packed, fetched or installed).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { NPM_AGENTS, AGENTS, lineOf } from "../agents/agent-registry.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SUITES = join(REPO, "scripts", "matrix", "suites");

/** A tree holding the host script and what it reads; `registry: false`
 *  leaves the registry out. */
function tree({ registry = true } = {}) {
  const t = mkdtempSync(join(tmpdir(), "fresh-agents-host-"));
  const put = (rel, text, mode) => {
    mkdirSync(dirname(join(t, rel)), { recursive: true });
    writeFileSync(join(t, rel), text);
    if (mode) chmodSync(join(t, rel), mode);
  };
  const copy = (rel) => { mkdirSync(dirname(join(t, rel)), { recursive: true }); copyFileSync(join(REPO, rel), join(t, rel)); };
  copy("scripts/matrix/suites/fresh-agents.host.sh");
  copy("scripts/matrix/lib/node-major.mjs");
  copy("launcher/src/agent-versions.ts");
  if (registry) copy("scripts/agents/agent-registry.mjs");
  put("scripts/matrix/suites/fresh-install.host.sh", "exit 0\n");
  for (const f of ["fake-model.mjs", "agent-leg.sh", "env-twin-check.mjs"]) put(`scripts/matrix/suites/fresh-agents/${f}`, "");
  put("bin/npm", "#!/bin/sh\nexit 1\n", 0o755);
  put("bin/curl", "#!/bin/sh\nexit 1\n", 0o755);
  mkdirSync(join(t, "art"));
  return t;
}

function prep(t, env = {}) {
  return spawnSync("bash", [join(t, "scripts/matrix/suites/fresh-agents.host.sh")], {
    encoding: "utf8",
    env: { ...process.env, PATH: `${join(t, "bin")}:${process.env.PATH}`, ARTIFACT_DIR: join(t, "art"), REPO_ROOT: t, FRESH_AGENTS_LIVE: "0", ...env },
  });
}

const versions = (t) => readFileSync(join(t, "art", "AGENT_VERSIONS"), "utf8").trim().split("\n").map((l) => l.split("="));

test("the registry's npm agents are claude, codex, openclaw and opencode; Goose (a release binary) is not one", () => {
  assert.deepEqual([...NPM_AGENTS], ["claude", "codex", "openclaw", "opencode"]);
  assert.ok(AGENTS.includes("goose") && lineOf("goose").npm === undefined);
});

test("tested (the default): each npm agent at the launcher's tested max, in the registry's order", () => {
  const t = tree();
  try {
    const r = prep(t);
    assert.equal(r.status, 0, r.stderr);
    const got = versions(t);
    assert.deepEqual(got.map(([a]) => a), [...NPM_AGENTS]);
    const table = readFileSync(join(REPO, "launcher/src/agent-versions.ts"), "utf8");
    for (const [a, v] of got) {
      assert.match(v, /^\d+\.\d+\.\d+/, `${a}=${v}`);
      assert.ok(new RegExp(`${a}:\\s*\\{[^}]*?max:\\s*"${v.replace(/\./g, "\\.")}"`).test(table), `${a}: ${v} is its tested max`);
    }
    assert.equal(readFileSync(join(t, "art", "NODE_MAJOR"), "utf8").trim(), "22", "no engines range read (npm stubbed): Node 22");
  } finally { rmSync(t, { recursive: true, force: true }); }
});

test("latest: each npm agent at npm's latest, in the registry's order", () => {
  const t = tree();
  try {
    const r = prep(t, { FRESH_AGENTS_VERSIONS: "latest" });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(versions(t), NPM_AGENTS.map((a) => [a, "latest"]));
  } finally { rmSync(t, { recursive: true, force: true }); }
});

test("no registry: the prep stops with the reason, writing no agent versions", () => {
  const t = tree({ registry: false });
  try {
    const r = prep(t);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /cannot read the agents/);
    assert.throws(() => readFileSync(join(t, "art", "AGENT_VERSIONS")));
  } finally { rmSync(t, { recursive: true, force: true }); }
});

test("the guest installs each npm agent from the registry's package, as its own command", () => {
  const guest = readFileSync(join(SUITES, "fresh-agents.sh"), "utf8");
  const table = (name) => {
    const m = new RegExp(`declare -A ${name}=\\(([^)]*)\\)`).exec(guest);
    assert.ok(m, `fresh-agents.sh declares ${name}`);
    return Object.fromEntries([...m[1].matchAll(/\[([a-z0-9]+)\]=(\S+)/g)].map((x) => [x[1], x[2]]));
  };
  const pkg = table("PKG"), bin = table("BIN");
  assert.deepEqual(Object.keys(pkg).sort(), [...NPM_AGENTS].sort());
  for (const a of NPM_AGENTS) {
    assert.equal(pkg[a], lineOf(a).npm, `${a}: the registry's npm package`);
    assert.equal(bin[a], a, `${a}: its command is its id`);
  }
});
