/**
 * package-cache-env-parity.test.ts — ONE list of the variables that move a
 * package cache, in two packages (secret-discovery.md §1.9 G).
 *
 * The arbiter's secret walk records a too-deep directory inside a package
 * cache as the quiet `package-cache` instead of the counted `depth`; a cache
 * moved by `CARGO_HOME`, `GOMODCACHE`, … is found from the LAUNCH's values
 * of those variables, which the launcher sends (the arbiter is shared and
 * cannot read the session's environment). The two packages ship standalone
 * and cannot import each other:
 *   - arbiter/policy/secret-discovery.ts   PACKAGE_CACHE_ENV (from
 *                                           RELOCATED_PACKAGE_CACHES), and
 *                                           `pickPackageCacheEnv`, which
 *                                           drops any other name on the wire
 *   - launcher/src/secret-setup.ts         PACKAGE_CACHE_ENV, and
 *                                           `packageCacheEnv`, which picks
 *                                           what it sends
 * A name only the launcher lists would be dropped by the arbiter (the cache
 * stays counted); a name only the arbiter lists would never be sent. This
 * pins the lists equal and runs both pickers over one environment.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { PACKAGE_CACHE_ENV as arbiterNames, pickPackageCacheEnv } from "../../arbiter/policy/secret-discovery.js";
import { PACKAGE_CACHE_ENV as launcherNames, packageCacheEnv } from "../../launcher/src/secret-setup.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the walk runs only with confidentiality ON; the lists read no axis themselves

test("the launcher sends exactly the variables the arbiter reads", () => {
  assert.deepEqual([...launcherNames].sort(), [...arbiterNames].sort());
  assert.equal(new Set(launcherNames).size, launcherNames.length, "no name twice");
});

test("what the launcher picks from an environment is what the arbiter keeps", () => {
  const env: Record<string, string> = { HOME: "/home/u", PATH: "/bin", ANTHROPIC_API_KEY: "sk-ant-x", GH_TOKEN: "ghp_x" };
  for (const [i, name] of arbiterNames.entries()) env[name] = `/moved/${i}`;
  const sent = packageCacheEnv(env);
  assert.deepEqual(pickPackageCacheEnv(sent), sent);
  assert.deepEqual(Object.keys(sent).sort(), [...arbiterNames].sort());
  assert.ok(!("ANTHROPIC_API_KEY" in sent) && !("GH_TOKEN" in sent), "nothing else leaves the launcher");
});
