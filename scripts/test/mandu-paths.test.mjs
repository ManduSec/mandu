// Unit tests for scripts/paths/mandu-paths.mjs, the one path table
// (docs/design/architecture/on-disk-layout.md §5), and THE parity test for its generated
// copies: it fails when any copy differs from what the table generates.
// It pins the one Mandu home (phase 3c) and the migration's moves out of the
// layout before it (§6).
// Run: node --test scripts/test/mandu-paths.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";

import {
  BASES, COPIES, FIXTURES, PATHS, expectedCopies, resolveBase, resolvePath, staleCopies, tableProblems,
} from "../paths/mandu-paths.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SCRIPT = join(ROOT, "scripts", "paths", "mandu-paths.mjs");

test("the table is sound", () => {
  assert.deepEqual(tableProblems(), []);
});

test("every generated copy matches the table (run `node scripts/paths/mandu-paths.mjs generate`)", () => {
  assert.deepEqual(staleCopies(), []);
  const r = spawnSync(process.execPath, [SCRIPT, "check"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
});

test("check names a stale or missing copy and exits 1", () => {
  const scratch = mkdtempSync(join(tmpdir(), "mandu-paths-"));
  try {
    for (const c of expectedCopies()) {
      mkdirSync(dirname(join(scratch, c.path)), { recursive: true });
      writeFileSync(join(scratch, c.path), c.text);
    }
    assert.deepEqual(staleCopies(scratch), []);
    const edited = COPIES[0].path;
    writeFileSync(join(scratch, edited), readFileSync(join(scratch, edited), "utf8").replace('".mandu"', '".mandu2"'));
    rmSync(join(scratch, COPIES[COPIES.length - 1].path));
    assert.deepEqual(staleCopies(scratch), [edited, COPIES[COPIES.length - 1].path]);
    // The CLI checks the real repo; copy the script into the scratch tree to
    // see it refuse there.
    mkdirSync(join(scratch, "scripts", "paths"), { recursive: true });
    cpSync(SCRIPT, join(scratch, "scripts", "paths", "mandu-paths.mjs"));
    const r = spawnSync(process.execPath, [join(scratch, "scripts", "paths", "mandu-paths.mjs"), "check"], { encoding: "utf8" });
    assert.equal(r.status, 1);
    assert.match(r.stderr, new RegExp(edited.replace(/[./]/g, "\\$&")));
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("each TS package's copy is the same text; the Rust crate and the shell copy differ only by language", () => {
  const texts = expectedCopies();
  const ts = new Set(texts.filter((c) => c.lang === "ts").map((c) => c.text));
  assert.equal(ts.size, 1);
  assert.deepEqual(COPIES.map((c) => c.path).sort(), [
    "arbiter/src/generated/mandu-paths.ts",
    "dashboard/src/generated/mandu-paths.ts",
    "eval/lib/generated/mandu-paths.ts",
    "fs-sync/src/generated/mandu-paths.ts",
    "interceptors/mandu-paths/src/lib.rs",
    "launcher/src/generated/mandu-paths.ts",
    "scripts/paths/mandu-paths.sh",
  ]);
});

test("the shell copy resolves every entry and base like the table, on every fixture (env -i: the host's variables stay out)", () => {
  const sh = join(ROOT, "scripts", "paths", "mandu-paths.sh");
  const names = PATHS.map((e) => e.name);
  const bases = Object.keys(BASES);
  const script = `source "$1"; for b in ${bases.join(" ")}; do mandu_base "$b" "$MP_HOME"; done; ` +
    'for n in "${MANDU_PATH_NAMES[@]}"; do mandu_path "$n" "$MP_HOME"; done';
  for (const [label, env, home] of FIXTURES) {
    const vars = Object.entries({ ...env, MP_HOME: home }).map(([k, v]) => `${k}=${v}`);
    const r = spawnSync("env", ["-i", ...vars, "bash", "-c", script, "sh", sh], { encoding: "utf8" });
    assert.equal(r.status, 0, `${label}: ${r.stderr}`);
    const want = [...bases.map((b) => resolveBase(b, env, home)), ...names.map((n) => resolvePath(n, env, home))];
    assert.deepEqual(r.stdout.split("\n").slice(0, -1), want, label);
  }
  // Path shapes the fixtures do not reach: node's normalize on dot segments.
  const shapes = ["/a/./b/../c/", "a/../../b", "", "/", "//x//y", "./", "../", "/.."];
  const norm = spawnSync("bash", ["-c", 'source "$1"; shift; for p in "$@"; do _mandu_normalize "$p"; done', "sh", sh, ...shapes], { encoding: "utf8" });
  assert.deepEqual(norm.stdout.split("\n").slice(0, -1), shapes.map((x) => posix.normalize(x)));
  const bad = spawnSync("bash", ["-c", 'source "$1"; mandu_path nope', "sh", sh], { encoding: "utf8" });
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /unknown path nope/);
});

test("phase 3c: every store sits in the one Mandu home", () => {
  const h = "/home/u";
  const at = (name, env = {}) => resolvePath(name, env, h);
  assert.equal(at("mandu-home"), "/home/u/.mandu");
  assert.equal(at("config-root"), "/home/u/.mandu");
  assert.equal(at("config-toml"), "/home/u/.mandu/config.toml");
  assert.equal(at("policy"), "/home/u/.mandu/policy.yaml");
  assert.equal(at("packs"), "/home/u/.mandu/packs");
  assert.equal(at("pack-keys"), "/home/u/.mandu/pack-keys");
  assert.equal(at("secrets-json"), "/home/u/.mandu/secrets.json");
  assert.equal(at("dashboard-env"), "/home/u/.mandu/dashboard.env");
  assert.equal(at("state-root"), "/home/u/.mandu/state");
  assert.equal(at("symbol-db"), "/home/u/.mandu/state/mandu.db");
  assert.equal(at("symbol-db-test"), "/home/u/.mandu/state/mandu-test.db");
  assert.equal(at("view-state"), "/home/u/.mandu/state");
  assert.equal(at("workspaces"), "/home/u/.mandu/state/workspaces");
  assert.equal(at("object-walks"), "/home/u/.mandu/state/object-walks");
  assert.equal(at("paired-approvals"), "/home/u/.mandu/state/paired-approvals");
  assert.equal(at("events"), "/home/u/.mandu/events");
  assert.equal(at("events-test"), "/home/u/.mandu/events/test");
  assert.equal(at("runs-root"), "/home/u/.mandu/runs");
  assert.equal(at("test-runs"), "/home/u/.mandu/runs/test-runs.json");
  assert.equal(at("test-run-results"), "/home/u/.mandu/runs/test-runs");
  assert.equal(at("live-drill-runs"), "/home/u/.mandu/runs/drills/live");
  assert.equal(at("ci-runs"), "/home/u/.mandu/runs/ci");
  assert.equal(at("matrix-results"), "/home/u/.mandu/runs/matrix");
  assert.equal(at("eval-runs"), "/home/u/.mandu/runs/eval");
  assert.equal(at("replay-drill-runs"), "/home/u/.mandu/runs/drills/replay");
  assert.equal(at("drill-baselines"), "/home/u/.mandu/runs/drills/baselines");
  assert.equal(at("dev-root"), "/home/u/.mandu/dev");
  assert.equal(at("docker-e2e-home"), "/home/u/.mandu/dev/docker-e2e-home");
  assert.equal(at("cache-root"), "/home/u/.mandu/cache");
  assert.equal(at("object-twins"), "/home/u/.mandu/cache/object-twins");
  assert.equal(at("exec-box-cache"), "/home/u/.local/share/mandu/exec-box");
  assert.equal(at("ci-cache"), "/home/u/.mandu/cache/ci");
  assert.equal(at("ci-host-out"), "/home/u/.mandu/cache/ci/host-out");
  assert.equal(at("dashboard-cache"), "/home/u/.mandu/cache/dashboard");
  assert.equal(at("update-check"), "/home/u/.mandu/cache/update-check.json");
  assert.equal(at("runtime-dir"), "/tmp/mandu");
  assert.equal(at("runtime-dir", { XDG_RUNTIME_DIR: "/run/user/1000" }), "/run/user/1000/mandu");
  assert.equal(at("runtime-dir", { TMPDIR: "/var/tmp" }), "/var/tmp/mandu");
  assert.equal(at("install-prefix"), "/home/u/.local/share/mandu");
  assert.equal(at("bin-dir"), "/home/u/.local/bin");
});

test("MANDU_HOME moves every store in the home; XDG roots move none; overrides are verbatim; empty counts as unset", () => {
  for (const e of PATHS) {
    const plain = resolvePath(e.name, {}, "/h");
    const moved = plain.startsWith("/h/.mandu") ? plain.replace("/h/.mandu", "/m") : plain;
    assert.equal(resolvePath(e.name, { MANDU_HOME: "/m" }, "/h"), moved, e.name);
  }
  const xdg = { XDG_STATE_HOME: "/s", XDG_CONFIG_HOME: "/c", XDG_CACHE_HOME: "/k" };
  for (const name of ["events", "config-toml", "ci-cache", "symbol-db"]) {
    assert.equal(resolvePath(name, xdg, "/h"), resolvePath(name, {}, "/h"), `${name}: XDG roots do not move it`);
  }
  assert.equal(resolvePath("runtime-dir", { MANDU_RUNTIME_DIR: "/pinned/", MANDU_HOME: "/m" }, "/h"), "/pinned/");
  assert.equal(resolvePath("events", { MANDU_HOME: "" }, "/h"), "/h/.mandu/events");
  // Phase 4 (§9 1): nothing in the home has its own override any more.
  for (const e of PATHS) {
    if (resolvePath(e.name, {}, "/h").startsWith("/h/.mandu")) assert.equal(e.env, null, `${e.name} has no override`);
  }
  assert.equal(resolvePath("events", { MANDU_EVENT_DIR: "/e" }, "/h"), "/h/.mandu/events", "MANDU_EVENT_DIR is retired");
  assert.equal(resolvePath("workspaces", { MANDU_VIEW_STATE: "/v" }, "/h"), "/h/.mandu/state/workspaces", "MANDU_VIEW_STATE is retired");
  assert.equal(resolveBase("runtime", { XDG_RUNTIME_DIR: "", TMPDIR: "" }, "/h"), "/tmp");
});

test("unknown names throw", () => {
  assert.throws(() => resolvePath("no-such-path", {}, "/h"), /unknown path/);
  assert.throws(() => resolveBase("no-such-base", {}, "/h"), /unknown base/);
});

test("every store the agent may not read is owner-only; bases name no entry", () => {
  for (const e of PATHS) {
    if (e.agentReadable) continue;
    assert.ok(e.mode !== null && (e.mode & 0o077) === 0, `${e.name}: mode ${e.mode?.toString(8)}`);
    assert.equal(e.mode, e.kind === "dir" ? 0o700 : 0o600, e.name);
  }
  for (const name of Object.keys(BASES)) assert.ok(!PATHS.some((e) => e.name === name), name);
});

test("the fixtures exercise every variable the table reads, set and unset", () => {
  const vars = new Set([...Object.values(BASES).flatMap((b) => b.chain), ...PATHS.flatMap((e) => (e.env ? [e.env] : []))]);
  for (const v of vars) {
    assert.ok(FIXTURES.some(([, env]) => env[v]), `${v} set somewhere`);
    assert.ok(FIXTURES.some(([, env]) => env[v] === ""), `${v} empty somewhere`);
  }
});
