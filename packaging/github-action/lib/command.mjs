// @ts-check
/**
 * command — the launch a CI run makes, and its environment (pure).
 *
 *   mandu --no-reply-filter [--require-confinement] [--verbose] claude -p <prompt> <agent-args…>
 *   mandu --no-reply-filter [--require-confinement] [--verbose] codex exec <agent-args…> <prompt>
 *
 * Why each piece (docs/design/distribution/github-action.md §4, §5):
 *   - `--no-reply-filter`: the reply filter puts real values back in what a
 *     person at the terminal reads. In CI the "terminal" is the job log, which
 *     anyone with read access to the repository can open (everyone, on a
 *     public one) and GitHub masks only the values it was told about. So the
 *     log keeps the placeholders.
 *   - `--require-confinement` (input, default on): the run refuses a `gated`
 *     posture, where a program the agent runs could read a secret file raw.
 *   - MANDU_MODE=secrets: the product default, stated, so a config file on a
 *     self-hosted runner cannot turn protection off.
 *   - MANDU_EGRESS_HOLD_MS=0 and MANDU_SECRETS_ASK_TIMEOUT=1: nobody answers
 *     an approval in CI. A send that would wait for one is refused at once,
 *     and so is a reader or a protected-file change that would wait.
 *   - MANDU_HOME under the runner's temp folder: the run's own policy, symbol
 *     table and event log, none of it in the workspace the agent edits.
 *   - MANDU_RUNTIME_DIR a short fresh dir under /tmp (runtimeDirTemplate):
 *     the run's own services, whose socket paths must stay short.
 *
 * Mandu-new (no reference origin).
 */

/**
 * @param {import("./inputs.mjs").ActionConfig} c
 * @returns {string[]} the argv after `mandu`
 */
export function launchArgv(c) {
  const flags = ["--no-reply-filter"];
  if (c.requireConfinement) flags.push("--require-confinement");
  if (c.verbose) flags.push("--verbose");
  if (c.agent === "codex") return [...flags, "codex", "exec", ...c.agentArgs, c.prompt];
  return [...flags, "claude", "-p", c.prompt, ...c.agentArgs];
}

/** The agents' login variables action.yml sets from its inputs. */
export const AGENT_LOGIN_VARS = ["ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "OPENAI_API_KEY"];

/**
 * The environment the launch runs with: the job's own, plus the run's fixed
 * settings, which nothing in the job's environment can override.
 * @param {Record<string, string | undefined>} env
 * @param {{ manduHome: string, runtimeDir: string | null }} o
 */
export function launchEnv(env, o) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined || k.startsWith("MANDU_ACTION_")) continue;
    // action.yml maps each login input to its variable, empty when not
    // given: an empty login variable is no login, so it is left out.
    if (v === "" && AGENT_LOGIN_VARS.includes(k)) continue;
    out[k] = v;
  }
  out.MANDU_HOME = o.manduHome;
  out.MANDU_POLICY_FILE = `${o.manduHome}/policy.yaml`;
  out.MANDU_MODE = "secrets";
  out.MANDU_EGRESS_HOLD_MS = "0";
  out.MANDU_SECRETS_ASK_TIMEOUT = "1";
  out.MANDU_REPLY_FILTER = "0";
  out.CI = env.CI && env.CI !== "false" ? env.CI : "true";
  if (o.runtimeDir) out.MANDU_RUNTIME_DIR = o.runtimeDir;
  return out;
}

/**
 * The longest runtime dir the launcher accepts (launcher/src/runtime-base.ts
 * instanceBaseProblem): the arbiter's instance socket
 * `<dir>/instances/<id>/arbiter.sock` adds up to INSTANCE_SOCK_SUFFIX_MAX (63)
 * bytes, and a Unix socket path holds 107 on Linux. The e2e pins this
 * against the launcher's own constants (tests/stack/github-action.test.ts).
 */
export const RUNTIME_DIR_MAX = 107 - 63;

/**
 * Where the run's runtime dir (the services' sockets) is made: a fresh
 * `mkdtemp` under /tmp with a short prefix, never under $RUNNER_TEMP or
 * $TMPDIR, which on a runner (`/home/runner/work/_temp/…`) or a self-hosted
 * one with a deep work dir would put the sockets past the limit. The run's
 * MANDU_HOME (its policy, store and event log; no socket) stays under
 * $RUNNER_TEMP. The env is taken and ignored on purpose.
 * @param {Record<string, string | undefined>} [_env]
 */
export function runtimeDirTemplate(_env = {}) {
  return "/tmp/mdu-gha-";
}

/** Why `dir` cannot be the runtime dir, or null. */
export function runtimeDirProblem(dir) {
  const bytes = Buffer.byteLength(dir, "utf8");
  return bytes <= RUNTIME_DIR_MAX ? null
    : `the runtime dir ${dir} is ${bytes} bytes; Mandu's sockets need one of at most ${RUNTIME_DIR_MAX} bytes`;
}

/**
 * Whether to run `mandu setup` (Mandu's own bubblewrap and its AppArmor
 * profile; rootless-confinement-ubuntu-2404.md §0.3) before the launch.
 * `auto` runs it for Codex only, whose own command sandbox is a bubblewrap
 * that Ubuntu 24.04 refuses without it; Claude Code is confined by the
 * whole-agent guard alone. It needs passwordless sudo, which GitHub's hosted
 * runners have; where there is none, `auto` skips it and says so, and `true`
 * refuses.
 * @param {"auto" | "true" | "false"} setting
 * @param {{ agent: "claude" | "codex", platform: string, sudo: boolean }} host
 * @returns {{ run: boolean, problem?: string, note?: string }}
 */
export function setupDecision(setting, host) {
  if (setting === "false") return { run: false };
  if (host.platform !== "linux") {
    return setting === "true" ? { run: false, problem: "setup: true needs a Linux runner" } : { run: false };
  }
  const wanted = setting === "true" || host.agent === "codex";
  if (!wanted) return { run: false };
  if (!host.sudo) {
    return setting === "true"
      ? { run: false, problem: "setup: true needs passwordless sudo on the runner (GitHub's hosted runners have it)" }
      : { run: false, note: "no passwordless sudo here, so Mandu's own bubblewrap is not installed: Codex's own command sandbox may fail on Ubuntu 24.04 (Mandu's guard still keeps the secrets)" };
  }
  return { run: true };
}

/**
 * The step's exit status: the agent's when it failed (or the launch was
 * refused); else 1 when a send was blocked and `fail-on-blocked` is on;
 * else 0.
 * @param {number} agentExit
 * @param {number} blockedSends
 * @param {boolean} failOnBlocked
 */
export function stepStatus(agentExit, blockedSends, failOnBlocked) {
  if (agentExit !== 0) return agentExit;
  return blockedSends > 0 && failOnBlocked ? 1 : 0;
}
