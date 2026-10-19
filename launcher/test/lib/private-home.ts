/**
 * private-home — import this for its side effect in every launcher test that
 * runs a launch in-process (`main()` from src/run.ts): it points the paths the
 * launch resolves from THIS process's env, rather than from the env handed to
 * `main()`, at a per-file temp dir, so no launch can write the real HOME
 * (test-organization.md §8.4). Node's runner gives each file its own process;
 * the dir is removed when the process exits. A unit test
 * (test/unit/private-home.test.ts) fails any file that imports src/run.js
 * without this.
 *
 * - `npm_config_cache`: in the dev layout every daemon is spawned as
 *   `npm run --silent serve` (src/services/layout.ts), and each such npm
 *   writes `_logs/<ts>-debug-0.log` and `_update-notifier-last-checked` into
 *   its cache dir, the real `~/.npm` by default. The daemons' env is built
 *   from `process.env`.
 * - `MANDU_HOME`: an arbiter the launch autostarts at a pinned socket
 *   (src/arbiter.ts startArbiter) gets `process.env`, and without this it
 *   opens `~/.mandu/state/mandu.db`. The dir is not created here (the arbiter
 *   makes it 0700), so it holds no config.toml: pass PRIVATE_MANDU_HOME as
 *   MANDU_HOME in the env handed to `main()` for a launch that reads no
 *   config. A test that sets its own afterwards still wins.
 * - `CLAUDE_CONFIG_DIR` / `CODEX_HOME`: the fs rung's trust carry-over
 *   (src/services/manager.ts → claude-trust.ts / codex-trust.ts) reads them
 *   from `process.env` and otherwise rewrites `~/.claude.json` /
 *   `~/.codex/config.toml` when the launch's folder is already trusted there
 *   (a launch in the repo checkout would be). Nothing in the launcher passes
 *   either to the agent from `process.env`: an agent's config dir comes from
 *   the env handed to `main()`.
 *
 * Each is set unconditionally: a value exported in the developer's shell
 * names their real files.
 */
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** The temp dir holding everything below. Canonical: on macOS the temp dir
 *  is reached through a link (/tmp → /private/tmp, /var → /private/var),
 *  and a Mandu home spelled through one misses the realpaths the launch
 *  compares against it (the frozen modes' AgentView seed then stays raw). */
export const PRIVATE_HOME_DIR = realpathSync(mkdtempSync(join(tmpdir(), "mandu-test-home-")));
/** The npm cache every npm child of this test process uses. */
export const PRIVATE_NPM_CACHE = join(PRIVATE_HOME_DIR, "npm-cache");
/** The Mandu home an autostarted arbiter (and a launch handed it) uses. */
export const PRIVATE_MANDU_HOME = join(PRIVATE_HOME_DIR, "mandu");
/** Where the claude trust carry-over looks for `.claude.json`. */
export const PRIVATE_CLAUDE_CONFIG_DIR = join(PRIVATE_HOME_DIR, "claude-config");
/** Where the codex trust carry-over looks for `config.toml`. */
export const PRIVATE_CODEX_HOME = join(PRIVATE_HOME_DIR, "codex-home");

process.env["npm_config_cache"] = PRIVATE_NPM_CACHE;
process.env["MANDU_HOME"] = PRIVATE_MANDU_HOME;
process.env["CLAUDE_CONFIG_DIR"] = PRIVATE_CLAUDE_CONFIG_DIR;
process.env["CODEX_HOME"] = PRIVATE_CODEX_HOME;
process.on("exit", () => {
  try { rmSync(PRIVATE_HOME_DIR, { recursive: true, force: true }); } catch { /* best effort */ }
});
