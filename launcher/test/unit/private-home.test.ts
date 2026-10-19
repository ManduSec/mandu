/**
 * private-home — the test helper that keeps an in-process launch off the real
 * HOME (test-organization.md §8.4). Importing it points this process's npm
 * cache, the Mandu home an autostarted arbiter opens, and the claude / codex
 * config dirs the trust carry-over rewrites at a fresh temp dir, removed when
 * the process exits. The tripwire below fails any launcher test that runs a
 * launch (imports src/run.js, or test/lib/launch-in-dir.ts) without it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  PRIVATE_CLAUDE_CONFIG_DIR, PRIVATE_CODEX_HOME, PRIVATE_HOME_DIR, PRIVATE_MANDU_HOME, PRIVATE_NPM_CACHE,
} from "../lib/private-home.js";
import { manduPath } from "../../src/generated/mandu-paths.js";
import { stateAxes } from "../axes.js";

stateAxes("off"); // this suite states its axes (protection-modes.md §4); no arbiter is involved

const HERE = dirname(fileURLToPath(import.meta.url));
const TEST_ROOT = join(HERE, "..");
const TSX = join(HERE, "..", "..", "node_modules", ".bin", "tsx");

test("importing it pins the npm cache, the Mandu home and both agent config dirs under a temp dir", () => {
  assert.ok(PRIVATE_HOME_DIR.startsWith(realpathSync(tmpdir())), `under the temp dir (canonical), got ${PRIVATE_HOME_DIR}`);
  assert.ok(!PRIVATE_HOME_DIR.startsWith(homedir() + "/"), "not inside the real HOME");
  assert.ok(existsSync(PRIVATE_HOME_DIR));
  const pinned: Array<[string, string]> = [
    ["npm_config_cache", PRIVATE_NPM_CACHE],
    ["MANDU_HOME", PRIVATE_MANDU_HOME],
    ["CLAUDE_CONFIG_DIR", PRIVATE_CLAUDE_CONFIG_DIR],
    ["CODEX_HOME", PRIVATE_CODEX_HOME],
  ];
  for (const [k, v] of pinned) {
    assert.equal(process.env[k], v, k);
    assert.ok(v.startsWith(PRIVATE_HOME_DIR + "/"), `${k} is inside the private dir`);
  }
});

test("the arbiter's symbol-DB resolution lands in the private dir, not ~/.mandu", () => {
  // The path table the arbiter resolves its DB through (symbol-table.ts
  // getSymbolDbPath), fed this process's env as an autostarted daemon is.
  assert.equal(manduPath("symbol-db", process.env, homedir()), join(PRIVATE_MANDU_HOME, "state", "mandu.db"));
});

test("the trust carry-over still reads these variables from process.env (else this guard misses it)", () => {
  // manager.ts resolves both config dirs from process.env, not from the env
  // handed to main(); the guard pins exactly those. If this changes, move the
  // pin with it.
  const src = readFileSync(join(HERE, "..", "..", "src", "services", "manager.ts"), "utf8");
  assert.match(src, /configDir: process\.env\["CLAUDE_CONFIG_DIR"\] \|\| homedir\(\)/);
  assert.match(src, /codexHome: process\.env\["CODEX_HOME"\] \|\| join\(homedir\(\), "\.codex"\)/);
});

test("tripwire: every unit/component/kernel file that runs a launch in-process imports it", () => {
  const missing: string[] = [];
  for (const dir of ["unit", "component", "kernel"]) {
    for (const f of readdirSync(join(TEST_ROOT, dir)).filter((n) => n.endsWith(".test.ts"))) {
      const src = readFileSync(join(TEST_ROOT, dir, f), "utf8");
      if (!/from "\.\.\/(\.\.\/src\/run|lib\/launch-in-dir)\.js"/.test(src)) continue;
      if (!src.includes('import "../lib/private-home.js";')) missing.push(`test/${dir}/${f}`);
    }
  }
  assert.deepEqual(missing, [], "these files launch without test/lib/private-home.ts (test-organization.md §8.4)");
});

test("an npm child resolves its cache, and writes its logs, there", () => {
  const r = spawnSync("npm", ["config", "get", "cache"], { encoding: "utf8", timeout: 60_000 });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), PRIVATE_NPM_CACHE);
  // A failing npm command always leaves a debug log in <cache>/_logs.
  spawnSync("npm", ["run", "--silent", "no-such-script-mandu"], { cwd: PRIVATE_HOME_DIR, encoding: "utf8", timeout: 60_000 });
  const logs = existsSync(join(PRIVATE_NPM_CACHE, "_logs")) ? readdirSync(join(PRIVATE_NPM_CACHE, "_logs")) : [];
  assert.ok(logs.length > 0, "npm wrote its debug log into the private cache");
});

test("the dir is removed when the importing process exits", () => {
  const r = spawnSync(TSX, ["-e", `import("${join(HERE, "..", "lib", "private-home.ts")}").then((m) => console.log(m.PRIVATE_HOME_DIR))`], {
    encoding: "utf8", timeout: 60_000,
  });
  assert.equal(r.status, 0, r.stderr);
  const dir = r.stdout.trim();
  assert.ok(dir.startsWith(realpathSync(tmpdir())), `the child reported its dir, got '${dir}'`);
  assert.ok(!existsSync(dir), `${dir} outlived its process`);
});
