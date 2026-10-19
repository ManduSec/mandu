/**
 * opencode-data-catalog — OpenCode's data directory is a persistent built-in
 * `no-model` location (supported-agents.md §2.3 item 10; secret-catalog.ts
 * SECRET_PREFIXES `~/.local/share/opencode` and OPENCODE_DATA_SHAPE_RE), and
 * a classification only: secret discovery never registers or twins it
 * (secret-discovery.ts AGENT_STORES / isAgentAuthPath), so OpenCode keeps
 * reading and writing its own files. Its login (`auth.json`, the provider
 * keys) is keyed per launch (AGENT_LOGIN_FILES, secret-discovery.md §1.10):
 * raw under `mandu opencode`, a twinned catalog secret under every other
 * agent.
 *
 * Why (measured on OpenCode 2.0.23): every shell command's output, a
 * foreground one's too, is written to `shell/<40 hex>/sh_<id>.out` and kept
 * after the run, so a masked result left its raw output on disk for a later
 * `read` or `cat`; OpenCode 1.18.13 keeps tool outputs in `opencode.db`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { OPENCODE_DATA_SHAPE_RE, SECRET_PREFIXES, findSecretPathsInText, secretPathConfidentiality } from "../../policy/secret-catalog.js";
import { AGENT_LOGIN_FILES, AGENT_STORES, discoverSecretsReport, isAgentAuthPath } from "../../policy/secret-discovery.js";
import { decideFsPath } from "../../policy/fs-outbound.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the catalog serves the confidentiality axis

const HOME = "/home/u";
const HASH = "f2c72c87b7edac3b8b2e41eed399fa7eec2ecc0f";

test("the default data directory: shell outputs, the session database and the provider keys classify no-model", () => {
  assert.ok(SECRET_PREFIXES.includes("~/.local/share/opencode"));
  for (const p of [
    `${HOME}/.local/share/opencode/shell/${HASH}/sh_10b1e7beb001nTybL5RlJg0o5t.out`,
    `${HOME}/.local/share/opencode/opencode.db`,
    `${HOME}/.local/share/opencode/opencode.db-wal`,
    `${HOME}/.local/share/opencode/auth.json`,
    "~/.local/share/opencode/shell",
  ]) {
    const m = secretPathConfidentiality(p, HOME);
    assert.equal(m.level, "no-model", p);
    assert.equal(m.rule, "prefix:~/.local/share/opencode", p);
  }
});

test("another XDG_DATA_HOME: the shell output files and the session database classify no-model by shape", () => {
  for (const p of [
    `/data/xdg/opencode/shell/${HASH}/sh_A.out`,
    `/tmp/run/home/.local/share/opencode/shell/${HASH}/sh_A.out`.replace("/home/", "/h/"),
    "/srv/share/opencode/shell",
    "/srv/share/opencode/shell/anything",
    "/data/xdg/opencode/opencode.db",
    "/data/xdg/opencode/opencode.db-shm",
  ]) {
    assert.equal(secretPathConfidentiality(p, HOME).level, "no-model", p);
  }
  // near misses stay public: a project's own folders of those names
  for (const p of [
    "/src/opencode/shell/README.md",
    "/src/opencode/shell/abc/x.ts",
    "/src/app/opencode.db",
    "/src/opencode/shellcheck.yml",
  ]) {
    assert.equal(secretPathConfidentiality(p, HOME).level, "public", p);
    assert.equal(OPENCODE_DATA_SHAPE_RE.test(p), false, p);
  }
});

test("a shell command naming an output file (a glob too) carries the file's level", () => {
  const hits = (cmd: string) => findSecretPathsInText(cmd, HOME).map((h) => h.level);
  assert.deepEqual(hits(`cat ~/.local/share/opencode/shell/${HASH}/sh_A.out`), ["no-model"]);
  assert.deepEqual(hits("tail -n 50 ~/.local/share/opencode/shell/*/sh_*.out"), ["no-model"]);
  assert.deepEqual(hits(`grep KEY /data/xdg/opencode/shell/${HASH}/sh_A.out`), ["no-model"]);
});

test("the same posture as ~/.claude and ~/.codex (Claude Code's and Codex's transcripts): a tool's read of the data directory asks (the path gate)", () => {
  for (const p of [
    `${HOME}/.local/share/opencode/shell/${HASH}/sh_A.out`,
    `${HOME}/.local/share/opencode/opencode.db`,
    `${HOME}/.claude/projects/p/s.jsonl`,
    `${HOME}/.codex/sessions/2026/10/05/r.jsonl`,
  ]) {
    const d = decideFsPath({ path: p, mode: "read", tool: "read", workspaceRoots: [`${HOME}/proj`] }, { home: HOME });
    assert.equal(d.allow, false, p);
    assert.equal(d.requiresApproval, true, p);
  }
});

test("never twinned: the data directory is the agent's own (agent-auth), any spelling the shape matches too", () => {
  assert.ok(AGENT_STORES.opencode.includes("~/.local/share/opencode"));
  assert.ok(AGENT_LOGIN_FILES.opencode.includes("~/.local/share/opencode/auth.json"), "its login is keyed per launch");
  assert.equal(isAgentAuthPath(`${HOME}/.local/share/opencode/auth.json`, HOME), true);
  assert.equal(isAgentAuthPath(`/data/xdg/opencode/shell/${HASH}/sh_A.out`, HOME), true);
  assert.equal(isAgentAuthPath("/data/xdg/opencode/opencode.db", HOME), true);
  assert.equal(isAgentAuthPath(`${HOME}/.aws/credentials`, HOME), false);
});

test("discovery walks past the data directory: nothing in it is registered or twinned (counted as agent-auth); its login only under another agent", () => {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "mandu-oc-data-")));
  try {
    const data = join(home, ".local", "share", "opencode");
    mkdirSync(join(data, "shell", HASH), { recursive: true });
    writeFileSync(join(data, "auth.json"), '{"anthropic":{"type":"api","key":"sk-ant-x"}}');
    writeFileSync(join(data, "opencode.db"), "SQLite format 3\0");
    writeFileSync(join(data, "shell", HASH, "sh_A.out"), "API_KEY=sk-live-x\n");
    mkdirSync(join(home, ".aws"), { recursive: true });
    writeFileSync(join(home, ".aws", "credentials"), "[default]\naws_secret_access_key=x\n");
    for (const target of ["opencode", undefined]) {
      const r = discoverSecretsReport([home], home, undefined, target === undefined ? {} : { target });
      const found = r.files.map((f) => f.path);
      assert.ok(found.includes(join(home, ".aws", "credentials")), "a credential is still found");
      assert.ok(!found.some((p) => p.startsWith(data)), `nothing under OpenCode's data directory (${target}): ${found.join(", ")}`);
      assert.ok(r.counts["agent-auth"] >= 1, JSON.stringify(r.counts));
      assert.ok(r.skipped.some((s) => s.reason === "agent-login" && s.path === join(data, "auth.json")), "its login is kept raw");
    }
    // Under another agent the login is a catalog secret like any other; the
    // session store and the shell outputs still stay raw.
    const other = discoverSecretsReport([home], home, undefined, { target: "claude" });
    const login = other.files.find((f) => f.path === join(data, "auth.json"));
    assert.ok(login, `OpenCode's login is discovered under mandu claude: ${other.files.map((f) => f.path).join(", ")}`);
    assert.equal(login!.agentLogin, "opencode");
    assert.deepEqual(other.files.filter((f) => f.path.startsWith(data)).map((f) => f.path), [join(data, "auth.json")], "nothing else in the store");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
