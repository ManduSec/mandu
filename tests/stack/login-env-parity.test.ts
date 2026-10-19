/**
 * login-env-parity.test.ts — ONE list of the variables that move an AI
 * agent's login file, in two packages (secret-discovery.md §1.10).
 *
 * The arbiter's secret walk leaves the logins a launch runs on raw and
 * discovers every other agent's; where `CLAUDE_CONFIG_DIR`, `CODEX_HOME` or
 * `XDG_DATA_HOME` move them, it learns that from the LAUNCH's values, which
 * the launcher sends (the arbiter is shared and cannot read the session's
 * environment). The two packages ship standalone and cannot import each
 * other:
 *   - arbiter/policy/secret-discovery.ts   LOGIN_ENV, and `pickLoginEnv`,
 *                                           which drops any other name on
 *                                           the wire
 *   - launcher/src/secret-setup.ts         LOGIN_ENV, and `loginEnvOf`,
 *                                           which picks what it sends
 * A name only the launcher lists would be dropped by the arbiter (a moved
 * login of the launched agent would be twinned, and it could not log in); a
 * name only the arbiter lists would never be sent. This pins the lists
 * equal and runs both pickers over one environment.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { LOGIN_ENV as arbiterNames, agentLoginPaths, pickLoginEnv } from "../../arbiter/policy/secret-discovery.js";
import { LOGIN_ENV as launcherNames, loginEnvOf } from "../../launcher/src/secret-setup.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the walk runs only with confidentiality ON; the lists read no axis themselves

test("the launcher sends exactly the login variables the arbiter reads", () => {
  assert.deepEqual([...launcherNames].sort(), [...arbiterNames].sort());
  assert.equal(new Set(launcherNames).size, launcherNames.length, "no name twice");
});

test("what the launcher picks from an environment is what the arbiter keeps, and each variable moves a login the arbiter knows", () => {
  const env: Record<string, string> = { HOME: "/home/u", PATH: "/bin", OPENAI_API_KEY: "sk-x", ANTHROPIC_API_KEY: "sk-ant-x" };
  for (const [i, name] of arbiterNames.entries()) env[name] = `/moved/${i}`;
  const sent = loginEnvOf(env);
  assert.deepEqual(pickLoginEnv(sent), sent);
  assert.deepEqual(Object.keys(sent).sort(), [...arbiterNames].sort());
  assert.ok(!("OPENAI_API_KEY" in sent) && !("ANTHROPIC_API_KEY" in sent), "nothing else leaves the launcher");
  const every = (["claude", "codex", "opencode"] as const).flatMap((o) => agentLoginPaths(o, "/home/u", sent));
  for (const name of arbiterNames) {
    assert.ok(every.some((p) => p.startsWith(`${sent[name]}/`)), `${name} moves a login file: ${every.join(", ")}`);
  }
});
