/**
 * box — one confined-commands box: the Mandu launch that confines the box
 * host, started by the plugin inside the Gateway (docs/design/agents/
 * openclaw-plugin.md §10.2). Mandu-new (no reference origin).
 *
 * The box is a `mandu --target shell` launch whose program is box/host.mjs,
 * so the launcher's own machinery confines it, exactly as it confines any
 * program it runs on the `secrets` axes: the secret twins (labelled files
 * read as placeholder copies), the network guard and the egress proxy (a
 * connection reaches only the proxy, which puts a value back only at a
 * bound host), Mandu's own folder hidden and its runtime registries
 * write-protected, no root. The plugin adds:
 *   --no-reply-filter           the command's output goes to the model, which
 *                               must see placeholders (the reply filter would
 *                               put the values back for a person);
 *   --require-own-confinement   the launch refuses where it cannot confine
 *                               (no guard, no user namespace), instead of the
 *                               default `gated` degrade; the attachment beside
 *                               it only warns;
 *   --write-protect <path>      the OpenClaw config (and the files beside it)
 *                               and the plugin itself, read-only in the box.
 *
 * Ready only when the host's first line arrives AND the facts it reports
 * show a confined world (box/policy.mjs boxFactsProblems). Anything else (the
 * launch refused, exited, or took longer than `readyTimeoutMs`; a box that
 * reports itself unconfined) is an error the caller turns into "the command
 * did not run": never a command run on the host (fail closed).
 *
 * The launch's environment is a short allowlist of the Gateway's, not all of
 * it: the Gateway's own variables (its provider keys, its channel tokens) do
 * not belong to the commands, as they do not reach a Docker sandbox either.
 */
import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { boxFactsProblems, type BoxFacts } from "../../box/policy.mjs";
import { BoxClient } from "./box-client.js";

/** What starts a box. */
export interface BoxLaunchSpec {
  /** The argv that runs the Mandu launcher (the installer's, plugin config `sandbox.launcher`). */
  launcher: readonly string[];
  /** The node that runs box/host.mjs (the Gateway's own). */
  nodePath: string;
  /** Absolute path of box/host.mjs. */
  hostScript: string;
  /** The folder the launch runs in (its project: the agent's workspace). */
  workspaceDir: string;
  /** The Gateway's environment (the allowlist below is taken from it). */
  env: NodeJS.ProcessEnv;
  /** The arbiter the plugin and the attachment share (the launch's too). */
  arbiterSock: string;
  /** Mandu's home, for the host's "is it hidden" probe. */
  manduHome: string;
  /** Paths the box may not change (`--write-protect`). */
  writeProtect: readonly string[];
  /** How long the launch may take to come up. Default 120 s. */
  readyTimeoutMs?: number;
  /** Where the socket's private folder is made. Default os.tmpdir(). */
  socketParent?: string;
}

export interface BoxDeps {
  spawn?: (cmd: string, args: readonly string[], opts: SpawnOptions) => ChildProcess;
  log?: (level: "info" | "warn" | "error", msg: string) => void;
  now?: () => number;
}

/** Gateway variables the launch inherits (the rest stay in the Gateway).
 *  Of Mandu's own, only where things are and which build runs: never a
 *  mode or an opt-out switch (`MANDU_MODE`, `MANDU_NET_GUARD=0`,
 *  `MANDU_WRITE_PROTECT=0`, …), which would weaken the box a launch would
 *  otherwise give. `MANDU_NET_PROXY_MOCK_SITES` is the operator's host
 *  routes (the test lanes'): a route only says where an allowed request is
 *  dialed, after the gate. */
const ENV_KEEP = new Set([
  "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LANGUAGE", "TERM", "TZ", "TMPDIR", "COLORTERM", "NO_COLOR",
  "MANDU_HOME", "MANDU_RUNTIME_DIR", "MANDU_TENANT", "MANDU_POLICY_FILE", "MANDU_LAYOUT", "MANDU_DEV_REPO", "MANDU_FROM_SOURCE",
  "MANDU_NET_GUARD_BIN", "MANDU_EXEC_BOX_BIN", "MANDU_LANDLOCK_APPLY", "MANDU_NET_PROXY_MOCK_SITES", "MANDU_VERBOSE",
]);
const ENV_KEEP_PREFIX = ["LC_", "XDG_"];

/** The launch's environment: the Gateway's allowlisted variables, the
 *  arbiter the attachment uses, and no arbiter of its own: the service
 *  supervises that one, and with it down the launch refuses (the box does
 *  not come up: fail closed) instead of starting a second stack. Pure. */
export function boxLaunchEnv(env: NodeJS.ProcessEnv, arbiterSock: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) {
    if (typeof v !== "string") continue;
    if (ENV_KEEP.has(k) || ENV_KEEP_PREFIX.some((p) => k.startsWith(p))) out[k] = v;
  }
  out["MANDU_ARBITER_SOCK"] = arbiterSock;
  out["MANDU_NO_ARBITER_AUTOSTART"] = "1";
  return out;
}

/** The launch's argv. Pure. */
export function boxLaunchArgv(spec: Pick<BoxLaunchSpec, "launcher" | "nodePath" | "hostScript" | "writeProtect">, socketPath: string, probeFile: string | null): string[] {
  return [
    ...spec.launcher.slice(1),
    "--target", "shell",
    "--no-reply-filter",
    "--require-own-confinement",
    ...spec.writeProtect.flatMap((p) => ["--write-protect", p]),
    "--",
    spec.nodePath, spec.hostScript, "--socket", socketPath,
    ...(probeFile ? ["--probe-file", probeFile] : []),
  ];
}

/** A regular file inside Mandu's home the host tries to open (it must
 *  fail inside the box), or null when the home holds none. */
export function probeFileIn(manduHome: string, read: (p: string) => string[] = (p) => readdirSync(p), isFile: (p: string) => boolean = (p) => statSync(p).isFile()): string | null {
  const queue = [manduHome];
  for (let depth = 0; depth < 3 && queue.length > 0; depth++) {
    const next: string[] = [];
    for (const dir of queue) {
      let names: string[] = [];
      try { names = read(dir).sort(); } catch { continue; }
      for (const n of names) {
        const p = join(dir, n);
        try { if (isFile(p)) return p; } catch { continue; }
        next.push(p);
      }
    }
    queue.splice(0, queue.length, ...next);
  }
  return null;
}

type State =
  | { kind: "idle" }
  | { kind: "starting"; promise: Promise<BoxClient> }
  | { kind: "ready"; client: BoxClient; child: ChildProcess }
  | { kind: "failed"; error: Error; at: number };

/** After a failed start, the next one waits this long (a refusal is not retried in a loop). */
const RETRY_AFTER_MS = 5_000;

export class ManduBox {
  private state: State = { kind: "idle" };
  private child: ChildProcess | null = null;
  private sockDir: string | null = null;
  private readonly log: NonNullable<BoxDeps["log"]>;
  private readonly now: () => number;

  constructor(private readonly spec: BoxLaunchSpec, private readonly deps: BoxDeps = {}) {
    this.log = deps.log ?? (() => {});
    this.now = deps.now ?? Date.now;
  }

  /** The box's client once it is up and confined; starts it on first use. */
  ready(): Promise<BoxClient> {
    const s = this.state;
    if (s.kind === "ready") return Promise.resolve(s.client);
    if (s.kind === "starting") return s.promise;
    if (s.kind === "failed" && this.now() - s.at < RETRY_AFTER_MS) return Promise.reject(s.error);
    const promise = this.start();
    this.state = { kind: "starting", promise };
    promise.then(
      (client) => { if (this.state.kind === "starting" && this.child) this.state = { kind: "ready", client, child: this.child }; },
      (error: Error) => { this.state = { kind: "failed", error, at: this.now() }; },
    );
    return promise;
  }

  /** Whether a launch is up and answering. */
  get running(): boolean {
    return this.state.kind === "ready";
  }

  private start(): Promise<BoxClient> {
    const sockDir = mkdtempSync(join(this.spec.socketParent ?? tmpdir(), "mandu-ocbox-"));
    this.sockDir = sockDir;
    const socketPath = join(sockDir, "box.sock");
    const probe = probeFileIn(this.spec.manduHome);
    const [cmd] = this.spec.launcher;
    if (!cmd) return Promise.reject(new Error("no Mandu launcher configured (plugins.entries.mandu-inspect.config.sandbox.launcher)"));
    const argv = boxLaunchArgv(this.spec, socketPath, probe);
    const child = (this.deps.spawn ?? spawn)(cmd, argv, {
      cwd: this.spec.workspaceDir,
      env: boxLaunchEnv(this.spec.env, this.spec.arbiterSock),
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child = child;
    child.unref?.();
    for (const s of [child.stdin, child.stdout, child.stderr]) (s as unknown as { unref?: () => void } | null)?.unref?.();
    this.log("info", `[mandu-inspect] starting the confined-commands box for ${this.spec.workspaceDir}`);
    return new Promise<BoxClient>((resolve, reject) => {
      let settled = false;
      let out = "";
      let err = "";
      const finish = (e: Error | null, client?: BoxClient): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (e) {
          this.stopChild(child);
          reject(e);
        } else resolve(client!);
      };
      const timer = setTimeout(() => finish(new Error(`the box did not come up within ${Math.round((this.spec.readyTimeoutMs ?? 120_000) / 1000)} s${tailOf(err)}`)), this.spec.readyTimeoutMs ?? 120_000);
      timer.unref?.();
      child.stderr?.on("data", (d: Buffer) => { err = (err + d.toString("utf8")).slice(-8_000); });
      child.stdout?.on("data", (d: Buffer) => {
        out += d.toString("utf8");
        let nl: number;
        while ((nl = out.indexOf("\n")) >= 0) {
          const line = out.slice(0, nl);
          out = out.slice(nl + 1);
          let j: { manduBox?: number; ready?: boolean; socket?: string; facts?: BoxFacts } | null = null;
          try { j = JSON.parse(line); } catch { continue; }
          if (j?.manduBox !== 1 || j.ready !== true) continue;
          const problems = boxFactsProblems(j.facts);
          if (problems.length > 0) {
            finish(new Error(`the box is not confined: ${problems.join("; ")}`));
            return;
          }
          this.log("info", `[mandu-inspect] confined-commands box ready (${JSON.stringify(j.facts)})`);
          finish(null, new BoxClient(socketPath));
        }
      });
      child.once("error", (e) => finish(new Error(`the Mandu launcher could not be started (${e.message})`)));
      child.once("exit", (code, signal) => {
        if (!settled) {
          finish(new Error(`the Mandu launch that confines the box ended before it was ready (exit ${code ?? signal})${tailOf(err)}`));
          return;
        }
        if (this.child === child) {
          this.log("warn", `[mandu-inspect] the confined-commands box ended (exit ${code ?? signal}); the next command starts a new one${tailOf(err)}`);
          this.child = null;
          this.state = { kind: "idle" };
          this.cleanupSockDir(sockDir);
        }
      });
    });
  }

  private stopChild(child: ChildProcess): void {
    try { child.stdin?.end(); } catch { /* closed */ }
    const t = setTimeout(() => { try { child.kill("SIGTERM"); } catch { /* gone */ } }, 3_000);
    t.unref?.();
  }

  private cleanupSockDir(dir: string): void {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }

  /** End the box (the Gateway stopping): its lifeline first, then SIGTERM. */
  stop(): void {
    const c = this.child;
    this.child = null;
    this.state = { kind: "idle" };
    if (c) {
      try { c.stdin?.end(); } catch { /* closed */ }
      try { c.kill("SIGTERM"); } catch { /* gone */ }
    }
    if (this.sockDir) this.cleanupSockDir(this.sockDir);
  }
}

/** The last lines the launcher printed, for an error message. */
function tailOf(stderr: string): string {
  const lines = stderr.trim().split("\n").filter(Boolean).slice(-6);
  return lines.length > 0 ? `: ${lines.join(" | ")}` : "";
}
