/**
 * goose-data-catalog — Goose's data and state directories are persistent
 * built-in `no-model` locations (supported-agents.md §5.6.2; fs-outbound.ts
 * SENSITIVE_PATHS `~/.local/share/goose` and `~/.local/state/goose`,
 * secret-catalog.ts GOOSE_DATA_SHAPE_RE), and a classification only: secret
 * discovery never registers or twins them, in any launch (secret-discovery.ts
 * AGENT_STORES / isAgentAuthPath), so Goose keeps reading and writing its own
 * files.
 *
 * Why (goose 1.53.0): the session store `sessions/sessions.db` keeps every
 * message and tool output as Goose built it, and the CLI writes the last ten
 * model requests WHOLE to `logs/llm_request.{0..9}.jsonl` (providers/utils.rs)
 * before the model proxy symbolizes them, so a masked result's raw text sits
 * on disk for a later `cat`. The same posture as OpenCode's data directory
 * (opencode-data-catalog.test.ts) and ~/.claude, ~/.codex.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { GOOSE_DATA_SHAPE_RE, SECRET_PREFIXES, findSecretPathsInText, secretPathConfidentiality } from "../../policy/secret-catalog.js";
import { AGENT_STORES, discoverSecretsReport, isAgentAuthPath } from "../../policy/secret-discovery.js";
import { SENSITIVE_PATHS, decideFsPath } from "../../policy/fs-outbound.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the catalog serves the confidentiality axis

const HOME = "/home/u";
const UUID = "5f0c2a8e-8a8b-4c1e-9d3e-2b7f4e1a9c00";

test("the default directories: the session store, the request log, the history and the CLI logs classify no-model", () => {
  assert.ok(SENSITIVE_PATHS.includes("~/.local/share/goose"));
  assert.ok(SENSITIVE_PATHS.includes("~/.local/state/goose"));
  assert.ok(SECRET_PREFIXES.includes("~/.local/share/goose"));
  for (const [p, rule] of [
    [`${HOME}/.local/share/goose/sessions/sessions.db`, "prefix:~/.local/share/goose"],
    [`${HOME}/.local/share/goose/sessions/sessions.db-wal`, "prefix:~/.local/share/goose"],
    [`${HOME}/.local/state/goose/logs/llm_request.0.jsonl`, "prefix:~/.local/state/goose"],
    [`${HOME}/.local/state/goose/logs/llm_request.${UUID}.jsonl`, "prefix:~/.local/state/goose"],
    [`${HOME}/.local/state/goose/history.txt`, "prefix:~/.local/state/goose"],
    [`${HOME}/.local/state/goose/logs/cli/2026-10-07/20261007_1.log`, "prefix:~/.local/state/goose"],
    ["~/.local/state/goose/logs", "prefix:~/.local/state/goose"],
  ] as const) {
    const m = secretPathConfidentiality(p, HOME);
    assert.equal(m.level, "no-model", p);
    assert.equal(m.rule, rule, p);
  }
});

test("another XDG_DATA_HOME / XDG_STATE_HOME, a GOOSE_PATH_ROOT, macOS: the same files classify no-model by shape", () => {
  for (const p of [
    "/data/xdg/goose/sessions/sessions.db",
    "/data/xdg/goose/sessions/sessions.db-shm",
    "/data/xdg/goose/sessions/sessions.db-journal",
    "/data/xdg/goose/sessions/20250101_1.jsonl",
    "/state/xdg/goose/logs/llm_request.3.jsonl",
    `/state/xdg/goose/logs/llm_request.${UUID}.jsonl`,
    "/state/xdg/goose/logs/cli",
    "/state/xdg/goose/logs/cli/2026-10-07/x.log",
    "/state/xdg/goose/history.txt",
    // GOOSE_PATH_ROOT=/srv/g: <root>/data and <root>/state, no goose segment
    "/srv/g/data/sessions/sessions.db",
    "/srv/g/state/logs/llm_request.0.jsonl",
    // macOS Application Support (the directory name ends in goose)
    "/Users/u/Library/Application Support/Block.goose/sessions/sessions.db",
    "/Users/u/Library/Application Support/Block.goose/logs/llm_request.1.jsonl",
  ]) {
    assert.equal(secretPathConfidentiality(p, HOME).level, "no-model", p);
    assert.equal(GOOSE_DATA_SHAPE_RE.test(p), true, p);
  }
  // near misses stay public: a project's own files of those names
  for (const p of [
    "/src/app/sessions/sessions.db",
    "/src/app/data/sessions/sessions.sqlite",
    "/src/goose/README.md",
    "/src/app/logs/llm_request.0.jsonl",
    "/src/app/history.txt",
    "/src/app/logs/cli/x.log",
  ]) {
    assert.equal(secretPathConfidentiality(p, HOME).level, "public", p);
    assert.equal(GOOSE_DATA_SHAPE_RE.test(p), false, p);
  }
});

test("a shell command naming the store or the request log (a glob too) carries the file's level", () => {
  const hits = (cmd: string) => findSecretPathsInText(cmd, HOME).map((h) => h.level);
  assert.deepEqual(hits("cat ~/.local/state/goose/logs/llm_request.0.jsonl"), ["no-model"]);
  assert.deepEqual(hits("tail -n 50 ~/.local/state/goose/logs/llm_request.*.jsonl"), ["no-model"]);
  assert.deepEqual(hits("sqlite3 ~/.local/share/goose/sessions/sessions.db 'select * from messages'"), ["no-model"]);
  assert.deepEqual(hits("grep KEY /state/xdg/goose/logs/llm_request.2.jsonl"), ["no-model"]);
});

test("the same posture as ~/.local/share/opencode: a tool's read of either directory asks (the path gate)", () => {
  for (const p of [
    `${HOME}/.local/share/goose/sessions/sessions.db`,
    `${HOME}/.local/state/goose/logs/llm_request.0.jsonl`,
    `${HOME}/.local/state/goose/history.txt`,
  ]) {
    const d = decideFsPath({ path: p, mode: "read", tool: "read", workspaceRoots: [`${HOME}/proj`] }, { home: HOME });
    assert.equal(d.allow, false, p);
    assert.equal(d.requiresApproval, true, p);
  }
});

test("never twinned: Goose's own data and state (agent-auth), any spelling the shape matches too", () => {
  assert.ok(AGENT_STORES.goose.includes("~/.local/share/goose"));
  assert.ok(AGENT_STORES.goose.includes("~/.local/state/goose"));
  assert.equal(isAgentAuthPath(`${HOME}/.local/share/goose/sessions/sessions.db`, HOME), true);
  assert.equal(isAgentAuthPath(`${HOME}/.local/state/goose/logs/llm_request.0.jsonl`, HOME), true);
  assert.equal(isAgentAuthPath("/srv/g/state/logs/llm_request.0.jsonl", HOME), true);
  assert.equal(isAgentAuthPath("/data/xdg/goose/sessions/sessions.db", HOME), true);
  assert.equal(isAgentAuthPath(`${HOME}/.aws/credentials`, HOME), false);
  // Goose's key file stays a twinned catalog secret under other agents
  assert.equal(isAgentAuthPath(`${HOME}/.config/goose/secrets.yaml`, HOME), false);
});

test("discovery walks past both directories: nothing in them is registered or twinned (counted as agent-auth)", () => {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "mandu-goose-data-")));
  try {
    const data = join(home, ".local", "share", "goose");
    const state = join(home, ".local", "state", "goose");
    mkdirSync(join(data, "sessions"), { recursive: true });
    mkdirSync(join(state, "logs"), { recursive: true });
    writeFileSync(join(data, "sessions", "sessions.db"), "SQLite format 3\0API_KEY=sk-live-x\n");
    writeFileSync(join(state, "logs", "llm_request.0.jsonl"), '{"messages":[{"content":"API_KEY=sk-live-x"}]}\n');
    writeFileSync(join(state, "logs", "secrets.env"), "API_KEY=sk-live-x\n");
    mkdirSync(join(home, ".aws"), { recursive: true });
    writeFileSync(join(home, ".aws", "credentials"), "[default]\naws_secret_access_key=x\n");
    // In every launch, whichever agent it runs (the stores are not keyed).
    for (const target of [undefined, "goose", "claude", "codex"]) {
      const r = discoverSecretsReport([home], home, undefined, target === undefined ? {} : { target });
      const found = r.files.map((f) => f.path);
      assert.ok(found.includes(join(home, ".aws", "credentials")), "a credential is still found");
      assert.ok(!found.some((p) => p.startsWith(data) || p.startsWith(state)), `nothing under Goose's directories (${target}): ${found.join(", ")}`);
      assert.ok(r.counts["agent-auth"] >= 1, JSON.stringify(r.counts));
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
