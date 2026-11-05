/**
 * backend — Mandu as an OpenClaw sandbox backend: the plugin's opt-in
 * "confined commands" tier (docs/design/agents/openclaw-plugin.md §10).
 * Mandu-new (no reference origin); the handle's shape is OpenClaw's
 * (`SandboxBackendHandle`, 2026.7 to 2026.10), modelled on its Docker backend
 * and NVIDIA OpenShell's plugin backend.
 *
 * With `agents.defaults.sandbox: {mode: "all", backend: "mandu"}` OpenClaw
 * hands every command the agent runs, and every file its tools touch, to the
 * backend this module registers as `mandu`:
 *   - buildExecSpec: the command is prepared with the box (box.ts, a Mandu
 *     launch confining box/host.mjs) and OpenClaw spawns the exec relay
 *     (box/relay.mjs) in its place; the relay streams the command run IN THE
 *     BOX. OpenClaw spawns exactly the argv returned (background runs too).
 *   - runShellCommand: OpenClaw's own small scripts (process cleanup, probes)
 *     run in the box too.
 *   - createFsBridge: read, write, edit, ls… through the box (fs-bridge.ts).
 * One box per workspace, started on first use and kept for the Gateway's
 * life (its stdin is its lifeline). FAIL CLOSED: Linux only; no box, a box
 * that is not confined, an arbiter that is down at its start: the factory or
 * the call throws, OpenClaw reports the tool failed, and nothing runs on the
 * host instead.
 *
 * OpenClaw's registry is last-writer-wins: another plugin registering
 * `mandu` after this one would take the commands. The plugin checks, every
 * 30 s, that the factory OpenClaw holds for `mandu` is this one, logs loudly
 * when it is not, and writes the answer to a status file the service's route
 * check and `mandu doctor` read (a claim from the Gateway, like everything it
 * writes; §10.6).
 *
 * The SDK seam (`openclaw/plugin-sdk/sandbox`) does not exist before
 * OpenClaw 2026.7: it is imported dynamically, after the synchronous
 * registrar returns, so the plugin's hooks and tools still load where it is
 * missing; the tier then logs why it is off, and OpenClaw's own config check
 * refuses `sandbox.backend` on such a release.
 */
import { createHash } from "node:crypto";
import { mkdirSync, realpathSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { PluginLogger } from "../openclaw-api.js";
import { ManduBox, type BoxLaunchSpec } from "./box.js";
import { ManduFsBridge, type BridgeSandboxContext } from "./fs-bridge.js";

/** The backend id the installer writes into `agents.defaults.sandbox.backend`. */
export const SANDBOX_BACKEND_ID = "mandu";
/** The SDK module the backend registers through. */
export const SANDBOX_SDK = "openclaw/plugin-sdk/sandbox";
/** How often the plugin checks that OpenClaw's `mandu` backend is still its own. */
export const SELF_CHECK_MS = 30_000;

const HERE = dirname(fileURLToPath(import.meta.url));
/** box/host.mjs and box/relay.mjs, beside the plugin's sources. */
export const HOST_SCRIPT = resolve(HERE, "..", "..", "box", "host.mjs");
export const RELAY_SCRIPT = resolve(HERE, "..", "..", "box", "relay.mjs");

/** The plugin config's `sandbox` block (written by `mandu openclaw install --sandbox`). */
export interface SandboxTierConfig {
  /** The argv that runs the Mandu launcher. */
  launcher: string[];
  /** Paths the box may not change (the OpenClaw config, the plugin). */
  writeProtect: string[];
  /** Where the plugin records which backend OpenClaw holds for `mandu`. */
  statusFile?: string;
}

/** The part of OpenClaw's SDK the tier uses. */
export interface SandboxSdk {
  registerSandboxBackend(id: string, registration: { factory: (params: FactoryParams) => Promise<unknown> }): () => void;
  getSandboxBackendFactory?(id: string): unknown;
}

/** What OpenClaw passes the factory (subset). */
export interface FactoryParams {
  sessionKey?: string;
  scopeKey?: string;
  workspaceDir: string;
  agentWorkspaceDir?: string;
  cfg?: { workspaceAccess?: string };
}

export interface SandboxTierDeps {
  env: NodeJS.ProcessEnv;
  arbiterSock: string;
  logger: PluginLogger;
  /** Loads the SDK; default: the dynamic import of SANDBOX_SDK. */
  loadSdk?: () => Promise<SandboxSdk>;
  platform?: NodeJS.Platform;
  /** Builds a box (tests pass a fake). */
  makeBox?: (spec: BoxLaunchSpec) => Pick<ManduBox, "ready" | "stop">;
  nodePath?: string;
  /** Writes the status file (tests capture it). */
  writeStatus?: (path: string, text: string) => void;
  now?: () => Date;
}

/** The status the plugin records (§10.6). */
export interface SandboxStatus {
  version: 1;
  pid: number;
  checkedAt: string;
  /** Whether the SDK seam exists on this OpenClaw. */
  sdk: boolean;
  /** Whether this plugin registered `mandu`. */
  registered: boolean;
  /** Whether OpenClaw's `mandu` factory is this plugin's (null: cannot tell). */
  ours: boolean | null;
  platform: string;
  error?: string;
}

/** The handle's runtime id for a workspace. Pure. */
export function runtimeIdFor(workspaceDir: string): string {
  return `mandu-${createHash("sha256").update(workspaceDir).digest("hex").slice(0, 12)}`;
}

/** The env the exec relay runs with on the Gateway's side: enough to find node's own needs, nothing of the Gateway's. Pure. */
export function relayEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of ["PATH", "HOME", "LANG", "TERM", "TZ"]) {
    const v = env[k];
    if (typeof v === "string") out[k] = v;
  }
  return out;
}

const defaultLoadSdk = async (): Promise<SandboxSdk> => {
  const spec: string = SANDBOX_SDK;
  return (await import(spec)) as SandboxSdk;
};

const defaultWriteStatus = (path: string, text: string): void => {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, text, { mode: 0o600 });
  renameSync(tmp, path);
};

/**
 * Register the `mandu` sandbox backend (asynchronously: the SDK import
 * resolves after the registrar returns). Returns a stop function (the
 * self-check timer, every box).
 */
export function registerSandboxTier(tier: SandboxTierConfig, deps: SandboxTierDeps): { stop: () => void; ready: Promise<void> } {
  const log = deps.logger;
  const platform = deps.platform ?? process.platform;
  const nodePath = deps.nodePath ?? process.execPath;
  const manduHome = deps.env["MANDU_HOME"] || join(deps.env["HOME"] || "/", ".mandu");
  const boxes = new Map<string, Pick<ManduBox, "ready" | "stop">>();
  let timer: NodeJS.Timeout | null = null;
  let sdk: SandboxSdk | null = null;
  let registered = false;
  let lastOurs: boolean | null = null;

  const boxFor = (workspaceDir: string): Pick<ManduBox, "ready" | "stop"> => {
    let real = workspaceDir;
    try { real = realpathSync(workspaceDir); } catch { /* not there yet: as given */ }
    let box = boxes.get(real);
    if (!box) {
      const spec: BoxLaunchSpec = {
        launcher: tier.launcher, nodePath, hostScript: HOST_SCRIPT, workspaceDir: real,
        env: deps.env, arbiterSock: deps.arbiterSock, manduHome, writeProtect: tier.writeProtect,
      };
      box = deps.makeBox ? deps.makeBox(spec) : new ManduBox(spec, {
        log: (level, msg) => (level === "error" ? log.error(msg) : level === "warn" ? log.warn(msg) : log.info(msg)),
      });
      boxes.set(real, box);
    }
    return box;
  };

  const factory = async (params: FactoryParams): Promise<unknown> => {
    if (platform !== "linux") {
      throw new Error(
        "Mandu's confined-commands tier runs on Linux only (it confines each command with user namespaces, seccomp and Landlock); " +
          "remove `agents.defaults.sandbox.backend: \"mandu\"` (mandu openclaw install without --sandbox) to run commands on this host as before",
      );
    }
    const access = params.cfg?.workspaceAccess;
    if (access !== undefined && access !== "rw") {
      throw new Error(`Mandu's confined-commands tier needs agents.defaults.sandbox.workspaceAccess "rw" (got ${JSON.stringify(access)}): run mandu openclaw install --sandbox again`);
    }
    const workspaceDir = params.workspaceDir;
    const box = boxFor(workspaceDir);
    const handle = {
      id: SANDBOX_BACKEND_ID,
      runtimeId: runtimeIdFor(workspaceDir),
      runtimeLabel: "Mandu box",
      workdir: workspaceDir,
      configLabel: "Mandu (confined commands)",
      configLabelKind: "Backend",
      capabilities: { browser: false },
      async buildExecSpec(p: { command: string; workdir?: string; env: Record<string, string>; usePty: boolean }) {
        const client = await box.ready();
        const ticket = await client.prepare({ command: p.command, cwd: p.workdir ?? workspaceDir, env: p.env ?? {}, pty: p.usePty === true });
        return {
          argv: [nodePath, RELAY_SCRIPT, client.socketPath, ticket],
          env: relayEnv(deps.env),
          cwd: workspaceDir,
          stdinMode: p.usePty ? "pipe-open" : "pipe-closed",
        };
      },
      async finalizeExec(): Promise<void> { /* nothing held per command */ },
      async runShellCommand(p: { script: string; args?: string[]; stdin?: Buffer | string; allowFailure?: boolean; signal?: AbortSignal }) {
        const client = await box.ready();
        const r = await client.shell({ script: p.script, args: p.args ?? [], ...(p.stdin !== undefined ? { stdin: p.stdin } : {}), cwd: workspaceDir, ...(p.signal ? { signal: p.signal } : {}) });
        if (r.code !== 0 && p.allowFailure !== true) {
          throw Object.assign(new Error(r.stderr.toString("utf8").trim() || `the script in Mandu's box exited ${r.code}`), { code: r.code, stdout: r.stdout, stderr: r.stderr });
        }
        return r;
      },
      createFsBridge: ({ sandbox }: { sandbox: BridgeSandboxContext }) =>
        new ManduFsBridge(sandbox, () => box.ready(), {
          log: (level, msg) => (level === "error" ? log.error(msg) : level === "warn" ? log.warn(msg) : log.info(msg)),
        }),
    };
    return handle;
  };

  const status = (error?: string): SandboxStatus => {
    let ours: boolean | null = null;
    if (sdk && registered && typeof sdk.getSandboxBackendFactory === "function") {
      try { ours = sdk.getSandboxBackendFactory(SANDBOX_BACKEND_ID) === factory; } catch { ours = null; }
    }
    return {
      version: 1, pid: process.pid, checkedAt: (deps.now ?? (() => new Date()))().toISOString(),
      sdk: sdk !== null, registered, ours, platform, ...(error ? { error } : {}),
    };
  };
  const record = (error?: string): void => {
    const s = status(error);
    if (s.ours === false && lastOurs !== false) {
      log.error(
        `[mandu-inspect] OpenClaw's sandbox backend "${SANDBOX_BACKEND_ID}" is no longer Mandu's: another plugin registered the same id after this one, ` +
          "so commands may run outside Mandu's box. Remove or disable that plugin, then restart the Gateway (openclaw gateway restart).",
      );
    } else if (s.ours === true && lastOurs === false) {
      log.info(`[mandu-inspect] OpenClaw's sandbox backend "${SANDBOX_BACKEND_ID}" is Mandu's again`);
    }
    lastOurs = s.ours;
    if (!tier.statusFile) return;
    try { (deps.writeStatus ?? defaultWriteStatus)(tier.statusFile, `${JSON.stringify(s)}\n`); } catch (e) {
      log.warn(`[mandu-inspect] could not write the sandbox status file ${tier.statusFile} (${(e as Error).message})`);
    }
  };

  const ready = (deps.loadSdk ?? defaultLoadSdk)().then(
    (mod) => {
      if (typeof mod?.registerSandboxBackend !== "function") throw new Error(`${SANDBOX_SDK} has no registerSandboxBackend`);
      sdk = mod;
      mod.registerSandboxBackend(SANDBOX_BACKEND_ID, { factory });
      registered = true;
      log.info(
        `[mandu-inspect] sandbox backend "${SANDBOX_BACKEND_ID}" registered: commands and file tools run in Mandu's confined box` +
          (platform === "linux" ? "" : ` (refused on ${platform}: Linux only)`),
      );
      record();
      timer = setInterval(() => record(), SELF_CHECK_MS);
      timer.unref?.();
    },
    (err: unknown) => {
      const why = err instanceof Error ? err.message : String(err);
      log.error(
        `[mandu-inspect] the confined-commands tier is OFF: this OpenClaw has no sandbox backend seam (${SANDBOX_SDK}: ${why}). ` +
          "It needs OpenClaw 2026.7 or later; with sandbox.backend \"mandu\" set, OpenClaw refuses to run commands.",
      );
      record(why);
    },
  );

  const stopAll = (): void => {
    if (timer) clearInterval(timer);
    for (const b of boxes.values()) b.stop();
    boxes.clear();
  };
  process.once("exit", stopAll);
  return { stop: stopAll, ready };
}
