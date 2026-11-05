/**
 * openclaw-sandbox — the confined-commands tier of `mandu openclaw install`
 * (`--sandbox`): what it writes into `openclaw.json` and what uninstall puts
 * back (docs/design/agents/openclaw-plugin.md §10). PURE: the I/O is
 * openclaw-install-command.ts's. What the doctor, the install's post-check
 * and the service's route check judge (sandboxTierProblems) and what the
 * declaration records (DeclaredSandbox) live in attachment-contract.ts,
 * shared with the pool. Mandu-new (no reference origin).
 *
 * The tier makes Mandu OpenClaw's sandbox backend: with
 * `agents.defaults.sandbox: {mode: "all", backend: "mandu", scope: "agent",
 * workspaceAccess: "rw"}` OpenClaw hands every command and file tool to the
 * plugin's `mandu` backend, which runs it in a Mandu-confined box. Install
 * also writes:
 *   - `tools.sandbox.tools.alsoAllow`: a sandboxed session gets OpenClaw's
 *     fixed tool allowlist, which leaves out the chat tool, the web tools and
 *     every plugin tool (Mandu's inspect_symbol among them); without these
 *     the agent goes quiet on its chat. The host-side tools OpenClaw's default
 *     sandbox policy denies (browser, canvas, nodes, the Gateway tool,
 *     automations) stay denied: they run outside any box;
 *   - `tools.elevated.enabled: false`, and no `tools.exec.host` of `gateway`
 *     or `node`: both run a command on a host instead of the sandbox;
 *   - the plugin's `sandbox` block (the launcher argv, the paths the box may
 *     not change, the status file).
 * Every value it replaces is recorded (the declaration's `sandbox.original`),
 * and uninstall puts each back as it was, the user's Docker settings
 * included.
 */
import { join } from "node:path";

import { SANDBOX_ALSO_ALLOW, SANDBOX_BACKEND_ID, type SandboxOriginal } from "./attachment-contract.js";

type Json = Record<string, unknown>;

export { SANDBOX_ALSO_ALLOW, SANDBOX_BACKEND_ID, type SandboxOriginal };

export interface SandboxPlanInput {
  /** The absolute argv that runs the launcher. */
  launcher: string[];
  /** Paths the box may not change. */
  writeProtect: string[];
  /** The plugin's status file. */
  statusFile: string;
}

function isObj(v: unknown): v is Json {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function ensureObj(o: Json, key: string): Json {
  const v = o[key];
  if (isObj(v)) return v;
  const fresh: Json = {};
  o[key] = fresh;
  return fresh;
}

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

/** The values install replaces in `doc` (the main file), before it does. Pure. */
export function sandboxOriginal(doc: Json): SandboxOriginal {
  const agents = isObj(doc["agents"]) ? doc["agents"] : {};
  const defaults = isObj(agents["defaults"]) ? agents["defaults"] : {};
  const tools = isObj(doc["tools"]) ? doc["tools"] : {};
  const sb = isObj(tools["sandbox"]) ? tools["sandbox"] : {};
  const sbTools = isObj(sb["tools"]) ? sb["tools"] : {};
  const exec = isObj(tools["exec"]) ? tools["exec"] : {};
  return {
    sandbox: isObj(defaults["sandbox"]) ? clone(defaults["sandbox"]) : null,
    alsoAllow: Array.isArray(sbTools["alsoAllow"]) ? clone(sbTools["alsoAllow"] as unknown[]) : null,
    elevated: isObj(tools["elevated"]) ? clone(tools["elevated"]) : null,
    execHost: typeof exec["host"] === "string" ? exec["host"] : null,
  };
}

/** Does `pluginConfig` (the plugin entry's config) carry the tier? Pure. */
export function hasSandboxBlock(pluginConfig: unknown): boolean {
  return isObj(pluginConfig) && pluginConfig["sandbox"] !== undefined;
}

/**
 * Write the tier into `doc` (mutated in place; the main file, not an
 * include). `pluginConfig` is the plugin entry's config object install
 * already wrote. Returns what changed, in words.
 */
export function applySandboxInstall(doc: Json, pluginConfig: Json, input: SandboxPlanInput): string[] {
  const changes: string[] = [];
  const agents = ensureObj(doc, "agents");
  const defaults = ensureObj(agents, "defaults");
  const prior = isObj(defaults["sandbox"]) ? defaults["sandbox"] : {};
  // The backend, mode, scope and workspace access are the tier's; anything
  // else the user set (Docker images, the browser, prune) stays, for
  // uninstall to find as it was (OpenClaw ignores it under another backend).
  const sandbox: Json = { ...prior, mode: "all", backend: SANDBOX_BACKEND_ID, scope: "agent", workspaceAccess: "rw" };
  if (JSON.stringify(sandbox) !== JSON.stringify(prior)) {
    defaults["sandbox"] = sandbox;
    changes.push(`agents.defaults.sandbox: mode all, backend ${SANDBOX_BACKEND_ID}, scope agent, workspaceAccess rw`);
  }
  const tools = ensureObj(doc, "tools");
  const sbTools = ensureObj(ensureObj(tools, "sandbox"), "tools");
  const also = Array.isArray(sbTools["alsoAllow"]) ? [...sbTools["alsoAllow"] as unknown[]] : [];
  const added = SANDBOX_ALSO_ALLOW.filter((t) => !also.includes(t));
  if (added.length > 0) {
    sbTools["alsoAllow"] = [...also, ...added];
    changes.push(`tools.sandbox.tools.alsoAllow: + ${added.join(", ")}`);
  }
  const elevated = ensureObj(tools, "elevated");
  if (elevated["enabled"] !== false) {
    elevated["enabled"] = false;
    changes.push("tools.elevated.enabled: false");
  }
  const exec = isObj(tools["exec"]) ? tools["exec"] : null;
  if (exec && (exec["host"] === "gateway" || exec["host"] === "node")) {
    changes.push(`tools.exec.host: ${String(exec["host"])} removed (commands run in the sandbox)`);
    delete exec["host"];
  }
  const block = { launcher: [...input.launcher], writeProtect: [...input.writeProtect], statusFile: input.statusFile };
  if (JSON.stringify(pluginConfig["sandbox"]) !== JSON.stringify(block)) {
    pluginConfig["sandbox"] = block;
    changes.push("the plugin's sandbox backend (mandu)");
  }
  return changes;
}

/**
 * Take the tier out of `doc` (mutated): each value install replaced goes
 * back to `original` (absent where it was absent). A sandbox block the user
 * moved to another backend since is left as the user's. `pluginConfig` (null:
 * the entry is gone with the rest of uninstall) loses its `sandbox` block.
 * With no `original` (no record), Mandu's own values are removed and nothing
 * else is touched; elevated stays off. Returns what changed. Pure.
 */
export function applySandboxUninstall(doc: Json, pluginConfig: Json | null, original: SandboxOriginal | null): string[] {
  const changes: string[] = [];
  const agents = isObj(doc["agents"]) ? doc["agents"] : null;
  const defaults = agents && isObj(agents["defaults"]) ? agents["defaults"] : null;
  const cur = defaults && isObj(defaults["sandbox"]) ? defaults["sandbox"] : null;
  if (defaults && cur && cur["backend"] === SANDBOX_BACKEND_ID) {
    if (original?.sandbox) defaults["sandbox"] = clone(original.sandbox);
    else if (original) delete defaults["sandbox"];
    else {
      const { mode: _m, backend: _b, scope: _s, workspaceAccess: _w, ...rest } = cur;
      if (Object.keys(rest).length > 0) defaults["sandbox"] = rest;
      else delete defaults["sandbox"];
    }
    changes.push(original?.sandbox ? "agents.defaults.sandbox: back to your own settings" : "agents.defaults.sandbox: Mandu's backend removed");
  }
  const tools = isObj(doc["tools"]) ? doc["tools"] : null;
  const sbObj = tools && isObj(tools["sandbox"]) ? tools["sandbox"] : null;
  const sbTools = sbObj && isObj(sbObj["tools"]) ? sbObj["tools"] : null;
  if (sbObj && sbTools && Array.isArray(sbTools["alsoAllow"])) {
    const before = sbTools["alsoAllow"] as unknown[];
    const kept = original?.alsoAllow ?? [];
    const next = before.filter((t) => !SANDBOX_ALSO_ALLOW.includes(t as string) || kept.includes(t));
    if (next.length !== before.length) {
      if (next.length === 0 && (original === null || original.alsoAllow === null)) delete sbTools["alsoAllow"];
      else sbTools["alsoAllow"] = next;
      if (Object.keys(sbTools).length === 0) delete sbObj["tools"];
      if (Object.keys(sbObj).length === 0) delete tools!["sandbox"];
      changes.push("tools.sandbox.tools.alsoAllow: Mandu's entries removed");
    }
  }
  if (tools && original !== null && isObj(tools["elevated"]) && tools["elevated"]["enabled"] === false) {
    const was = JSON.stringify(original.elevated);
    if (original.elevated) tools["elevated"] = clone(original.elevated);
    else delete tools["elevated"];
    if (was !== JSON.stringify({ enabled: false })) changes.push(original.elevated ? "tools.elevated: back to your own settings" : "tools.elevated: Mandu's switch removed");
  }
  if (tools && (original?.execHost === "gateway" || original?.execHost === "node")) {
    const exec = ensureObj(tools, "exec");
    if (exec["host"] === undefined) {
      exec["host"] = original.execHost;
      changes.push(`tools.exec.host: back to ${original.execHost}`);
    }
  }
  if (tools && Object.keys(tools).length === 0) delete doc["tools"];
  if (pluginConfig && pluginConfig["sandbox"] !== undefined) {
    delete pluginConfig["sandbox"];
    changes.push("the plugin's sandbox backend removed");
  }
  return changes;
}

/** The paths the box may not change: the OpenClaw config (and the file it
 *  links to), the files it includes, the state folder's plugins, Mandu's
 *  plugin. Pure. */
export function sandboxWriteProtect(o: { configPath: string; configTarget: string; includes: readonly string[]; stateDir: string; pluginDir: string }): string[] {
  return [...new Set([o.configPath, o.configTarget, ...o.includes, join(o.stateDir, "extensions"), o.pluginDir])];
}

/** Why the tier cannot be installed here (null: it can). Linux with
 *  unprivileged user namespaces only: fail closed elsewhere. Pure. */
export function sandboxTierRefusal(platform: string, usernsOk: boolean, usernsHint: string): string | null {
  if (platform !== "linux") {
    return `the confined-commands tier (--sandbox) runs on Linux only: it confines each command with user namespaces, seccomp and Landlock, which ${platform === "darwin" ? "macOS" : platform} does not offer. Install without --sandbox to keep Mandu's other protections`;
  }
  if (!usernsOk) {
    return `the confined-commands tier (--sandbox) needs unprivileged user namespaces, which this host does not allow (${usernsHint}). Install without --sandbox, or allow them first (mandu doctor says how)`;
  }
  return null;
}
