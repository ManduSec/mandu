/**
 * serve-secrets — the secret registration an attachment session needs when no
 * launch ever runs (docs/design/agents/openclaw-plugin.md §3.2, "Secrets
 * without a launch"; the pluggable plan's "registering secrets without a
 * file view").
 *
 * A launch discovers the secret files under HOME and its workspace and asks
 * the arbiter to register each one (secret-setup.ts applySecretTwins: the
 * arbiter's `discoverSecrets`, then `registerSecret` per file). The registry
 * is account-wide, so a proxy of any session masks what any launch
 * registered; but a user who runs OpenClaw only as a resident Gateway may
 * never launch, and the pool proxy would then have nothing to swap. So the
 * service runs the same two ops, through the same arbiter adapter
 * (`socketSecretArbiter`) and with the options a launch of OpenClaw would
 * walk with (`launchDiscoverOptions`, target `openclaw`), over HOME plus the
 * OpenClaw agent's workspace, before it registers the attachment and starts
 * its proxy, and again on a timer and at every start of the service.
 *
 * What it does NOT do, unlike a launch: no twin is made or mounted (nothing
 * here confines a file: the Gateway's programs read the real ones, which is
 * the attachment's gap), and no environment variable is registered (the
 * Gateway's environment is not the service's; a variable it holds is masked
 * only once a launch or the user registers its value).
 *
 * The pool (dashboard/src/supervisor/attachment-pool.ts) runs it as
 * `mandu serve register-secrets --agent <id> --json`, a launcher process,
 * since the dashboard does not import the launcher. Fail closed there: a
 * failed walk or registration keeps the session's proxy from serving.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";

import { resolveArbiterSock } from "./arbiter-sock.js";
import { normalizeAgentId } from "./attachment-contract.js";
import { asDiscoveryReport, launchDiscoverOptions, ndjsonCall, notCoveredNotice, socketSecretArbiter, type SecretArbiter } from "./secret-setup.js";
import { parseAgentConfigText, userConfigPath } from "./services/agent-config.js";
import { resolveOpenclawIncludes } from "./services/openclaw-include.js";

type Env = Record<string, string | undefined>;
type Json = Record<string, unknown>;

function obj(v: unknown): Json | undefined {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Json) : undefined;
}

/** The workspace an OpenClaw agent works in, from its effective config: the
 *  agent's own `agents.list[].workspace`, else `agents.defaults.workspace`,
 *  else OpenClaw's default (`<state dir>/workspace`). A relative path is
 *  taken against the config's folder. Pure. */
export function openclawWorkspace(effective: Json | null, agentId: string, ctx: { configPath: string; stateDir: string }): string {
  const agents = obj(effective?.["agents"]);
  const id = normalizeAgentId(agentId);
  const own = Array.isArray(agents?.["list"])
    ? (agents!["list"] as unknown[]).map(obj).find((a) => typeof a?.["id"] === "string" && normalizeAgentId(a["id"] as string) === id)
    : undefined;
  const ws = own?.["workspace"] ?? obj(agents?.["defaults"])?.["workspace"];
  if (typeof ws === "string" && ws.trim() !== "") {
    const t = ws.trim();
    return isAbsolute(t) ? t : resolve(dirname(ctx.configPath), t);
  }
  return join(ctx.stateDir, "workspace");
}

/** The roots the service walks for an agent: HOME, and the agent's
 *  workspace when it is a folder outside HOME (inside, HOME's walk covers
 *  it). An unreadable config walks HOME alone. */
export function attachmentSecretRoots(env: Env, agentId: string): { home: string; roots: string[]; workspace: string | null } {
  const home = env["HOME"] || homedir();
  const configPath = userConfigPath("openclaw", env, home);
  const stateDir = env["OPENCLAW_STATE_DIR"] || join(home, ".openclaw");
  let effective: Json | null = null;
  try {
    const raw = parseAgentConfigText(readFileSync(configPath, "utf8"));
    effective = resolveOpenclawIncludes(raw, configPath, { env }) as Json;
  } catch { /* no config, or unreadable: OpenClaw's default workspace */ }
  const workspace = openclawWorkspace(effective, agentId, { configPath, stateDir });
  let isDir = false;
  try { isDir = statSync(workspace).isDirectory(); } catch { /* absent */ }
  const inside = workspace === home || workspace.startsWith(home.replace(/\/+$/, "") + "/");
  return { home, roots: isDir && !inside ? [home, workspace] : [home], workspace: isDir ? workspace : null };
}

/** What one registration run did (the `--json` answer; the pool records the
 *  counts for `mandu serve status`). */
export interface SecretRegistration {
  ok: boolean;
  roots: string[];
  /** Files the walk found. */
  found: number;
  /** Of them, registered (the arbiter minted a placeholder for the value). */
  registered: number;
  /** Found but not registered (unreadable, empty), with the arbiter's reason. */
  notRegistered: Array<{ path: string; reason: string }>;
  /** The walk's "not covered" lines (secret-setup.ts notCoveredNotice). */
  notCovered: string[];
  /** The agent's workspace (absolute, an existing folder) or null: where the
   *  agent's relative tool paths start, which the pool hands the session's
   *  proxy as MANDU_AGENT_CWD (openclaw-plugin.md §3.2, 2026-10-26). */
  workspace: string | null;
  /** Why it failed (ok false). */
  error?: string;
}

/** Discover and register an attachment session's secret files. Never throws:
 *  a failed walk or a failed registration is `ok: false` (the caller keeps
 *  the proxy from serving). */
export async function registerAttachmentSecrets(env: Env, agentId: string, arbiter: SecretArbiter): Promise<SecretRegistration> {
  const { home, roots, workspace } = attachmentSecretRoots(env, agentId);
  const base: SecretRegistration = { ok: false, roots, found: 0, registered: 0, notRegistered: [], notCovered: [], workspace };
  let files;
  let notCovered: string[] = [];
  try {
    const report = asDiscoveryReport(await arbiter.discoverSecrets(roots, home, launchDiscoverOptions(env, home, { target: "openclaw" })));
    files = report.files;
    notCovered = notCoveredNotice(report, 3, home);
  } catch (e) {
    return { ...base, error: `the arbiter could not discover secrets (${(e as Error).message})` };
  }
  const loginEnv = launchDiscoverOptions(env, home, { target: "openclaw" }).loginEnv;
  let registered = 0;
  const notRegistered: SecretRegistration["notRegistered"] = [];
  for (const f of files) {
    let reg;
    try {
      reg = (f.agentLogin !== undefined || f.agentConfig !== undefined) && loginEnv !== undefined
        ? await arbiter.registerSecret(f.path, home, loginEnv)
        : await arbiter.registerSecret(f.path, home);
    } catch (e) {
      return { ...base, found: files.length, registered, notRegistered, notCovered, error: `the arbiter could not register ${f.path} (${(e as Error).message})` };
    }
    if (reg.symbol === null) notRegistered.push({ path: f.path, reason: reg.reason });
    else registered++;
  }
  return { ok: true, roots, found: files.length, registered, notRegistered, notCovered, workspace };
}

/** The arbiter a registration run talks to: the account's rendezvous, the
 *  registration over its human socket (secret-setup.ts socketSecretArbiter:
 *  only there does a file earn its wire grant). Throws when none answers. */
export async function serviceSecretArbiter(env: Env): Promise<SecretArbiter> {
  const { sock } = resolveArbiterSock(env);
  if (!existsSync(sock)) throw new Error(`no arbiter answers at ${sock}`);
  const hello = await ndjsonCall<{ humanSock?: unknown }>(sock, "hello", {}, 5_000);
  const human = typeof hello?.humanSock === "string" && hello.humanSock !== "" ? hello.humanSock : null;
  return socketSecretArbiter(sock, { humanSock: human });
}

/** `mandu serve register-secrets --agent <id> [--json]` (the pool runs it):
 *  exit 0 registered, 1 failed, 2 usage. */
export async function runRegisterSecrets(
  rest: readonly string[],
  env: Env,
  deps: { arbiter?: (env: Env) => Promise<SecretArbiter>; out(s: string): void; err(s: string): void },
): Promise<number> {
  let agent = "main";
  let json = false;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a === "--json") json = true;
    else if (a === "--agent") agent = rest[++i] ?? "";
    else if (a.startsWith("--agent=")) agent = a.slice("--agent=".length);
    else { deps.err(`mandu serve register-secrets: unknown option '${a}'\n`); return 2; }
  }
  if (agent.trim() === "") { deps.err("mandu serve register-secrets: --agent needs an OpenClaw agent id\n"); return 2; }
  let r: SecretRegistration;
  try {
    r = await registerAttachmentSecrets(env, agent, await (deps.arbiter ?? serviceSecretArbiter)(env));
  } catch (e) {
    r = { ok: false, roots: [], found: 0, registered: 0, notRegistered: [], notCovered: [], workspace: null, error: (e as Error).message };
  }
  if (json) deps.out(JSON.stringify(r) + "\n");
  else if (r.ok) {
    deps.out(`mandu serve: ${r.registered} of ${r.found} secret file${r.found === 1 ? "" : "s"} registered (walked ${r.roots.join(", ")})\n`);
    for (const n of r.notRegistered) deps.out(`  not registered: ${n.path} (${n.reason})\n`);
    for (const l of r.notCovered) deps.out(`${l}\n`);
  } else {
    deps.err(`mandu serve: secrets not registered: ${r.error ?? "unknown"}\n`);
  }
  return r.ok ? 0 : 1;
}
