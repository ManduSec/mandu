/**
 * services/layout — the packaging.md §5 layout resolver: the one place that
 * knows HOW to run each shipped service in each layout.
 *
 *   installed — the npm package: `node <pkgRoot>/dist/<name>.mjs`, with
 *               MANDU_ARBITER_CLIENT_MODULE pointed at the co-located
 *               dist/arbiter-client.mjs (the interceptors' dynamic-import target,
 *               §5). One node process per service, carrying its own ps title.
 *   dev       — a source checkout, in one of two forms (§5.1), the same form the
 *               launcher itself runs in:
 *                 bundled: the launcher runs from the checkout's own fresh
 *                   launcher/dist (launcher/mandu-run.sh checked the build
 *                   record), so every service runs from that same dist exactly
 *                   as installed does, the resident dashboard included (it
 *                   knows a checkout's build and keeps the checkout's paths);
 *                 source: the launcher runs through tsx (MANDU_FROM_SOURCE=1, a
 *                   stale bundle that could not be rebuilt, the tests), so every
 *                   service runs its TypeScript entry through the package-local
 *                   tsx as ONE node process: `node --import <tsx ESM entry>
 *                   <entry.ts>`, never `npm run serve` (npm, then sh, then the
 *                   tsx binary re-spawning node: three extra processes and
 *                   about a second per daemon on the launch's critical path).
 *               Auto-detected from where the launcher runs, or forced with
 *               MANDU_DEV_REPO / MANDU_LAYOUT.
 *
 * The service names match bundle-manifest.json (the SAME map build-bundle.mjs
 * consumes), so the built set and the spawned set cannot drift; SERVICE_SOURCES
 * mirrors its `services` (test/unit/layout.test.ts holds them equal).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code. Generalizes the
 * `repoRoot` string that was threaded through every services/*.ts into a
 * layout-aware resolver.
 */
import { existsSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export type LayoutMode = "installed" | "dev";

/** node flags every bundle is spawned with (suppress the node:sqlite
 *  ExperimentalWarning the arbiter bundle emits on first import). */
const NODE_FLAGS = ["--no-warnings=ExperimentalWarning"];

/** Each spawned service's TypeScript entry, relative to the repo root. MUST
 *  mirror bundle-manifest.json `services` (test/unit/layout.test.ts). */
export const SERVICE_SOURCES = {
  "arbiter": "arbiter/ipc/server-main.ts",
  "anthropic-proxy": "interceptors/anthropic-proxy/src/server-main.ts",
  "openai-proxy": "interceptors/openai-proxy/src/server-main.ts",
  "net-proxy": "interceptors/net-proxy/src/server-main.ts",
  "cdp-relay": "interceptors/cdp-relay/src/server-main.ts",
  "inspect-mcp": "interceptors/inspect-mcp/src/server-main.ts",
  "policy-classifier": "interceptors/inspect-mcp/src/classify-main.ts",
  "policy-mcp": "interceptors/policy-mcp/src/server-main.ts",
  "dashboard": "dashboard/src/server-main.ts",
  "reply-filter": "interceptors/reply-filter/src/run.ts",
  "fs-sync-cli": "fs-sync/src/fs-sync-cli.ts",
  "exec-shim": "interceptors/exec-wrap/src/wrap.ts",
  "mandu": "launcher/src/run.ts",
} as const;
export type ServiceName = keyof typeof SERVICE_SOURCES;

/**
 * Source form: run a package's TypeScript entry through tsx WITHOUT the tsx
 * binary. `node_modules/.bin/tsx` re-spawns node with `--require
 * <preflight.cjs>`, and a CJS preload makes node parse the CWD's package.json
 * — which, in an AgentView worktree under an integrity-ON mode, is a
 * whole-file symbol twin, not JSON: `ERR_INVALID_PACKAGE_CONFIG`, and every
 * helper that inherits the agent's cwd (the reply filter, the exec-wrap shim,
 * inspect-mcp) died at launch in ANY Node workspace (found 2026-09-24 booting
 * a drill workspace; the installed layout's bundles were never affected).
 * `--import <file URL of tsx's ESM entry>` registers the same hooks and
 * resolves nothing from the cwd (verified from such a cwd on node 22).
 */
function devTsx(pkgDir: string): { cmd: string; args: string[]; entry: string } {
  const entry = join(pkgDir, "node_modules", "tsx", "dist", "esm", "index.mjs");
  return { cmd: "node", args: ["--import", pathToFileURL(entry).href], entry };
}

/**
 * Is `distDir` a source checkout's own build (`launcher/dist` beside
 * `launcher/src`) rather than an installed package's dist (which ships no
 * src/)? The bundled launcher and native-bins.ts both ask: a checkout's build
 * is a dev layout, and its native bins come from interceptors/target.
 */
export function isCheckoutBuild(distDir: string, exists: (p: string) => boolean = existsSync): boolean {
  return basename(distDir) === "dist" && exists(join(distDir, "..", "src", "run.ts"));
}

/** How to start a resident daemon (arbiter / proxies / net-proxy / dashboard):
 *  deps.startDetachedCmd(cmd, args, { cwd, env: {...base, ...env} }). */
export interface DaemonSpec {
  cmd: string;
  args: string[];
  cwd: string;
  env: Record<string, string>;
}

/** A `cmd + baseArgs` prefix the caller appends subcommand args to (fs-sync CLI,
 *  exec-wrap wrapper). */
export interface CmdPrefix {
  cmd: string;
  baseArgs: string[];
  cwd: string;
  env: Record<string, string>;
}

/** Asset key → source path relative to the repo root. MUST mirror
 *  bundle-manifest.json `assets` (test/unit/layout.test.ts holds them equal). */
export const ASSET_SOURCES: Record<string, string> = {
  "apparmor/mandu-bwrap": "scripts/apparmor/mandu-bwrap",
  "sdk-route-preload.cjs": "launcher/src/sdk-route-preload.cjs",
  "claude-permission-rule.cjs": "launcher/src/claude-permission-rule.cjs",
  "sdk-route-python/sitecustomize.py": "launcher/src/sdk-route-python/sitecustomize.py",
  "prompt-filters/local-classifier.mjs": "arbiter/prompt-filter/plugins/local-classifier.mjs",
  "prompt-filters/local-classifier-pack.mjs": "arbiter/prompt-filter/plugins/local-classifier-pack.mjs",
};

export class Layout {
  private constructor(
    readonly mode: LayoutMode,
    /** Source-tree root (dev). In installed mode this equals pkgRoot and is unused. */
    readonly repoRoot: string,
    /** The @mandusec/mandu package root — where dist/ lives. */
    readonly pkgRoot: string,
    /** Services run from `<pkgRoot>/dist/<name>.mjs`: always when installed;
     *  in dev, when the launcher itself runs from the checkout's fresh build. */
    readonly bundled: boolean,
  ) {}

  static dev(repoRoot: string, pkgRoot = repoRoot, opts: { bundled?: boolean } = {}): Layout {
    return new Layout("dev", repoRoot, pkgRoot, opts.bundled === true);
  }
  static installed(pkgRoot: string): Layout {
    return new Layout("installed", pkgRoot, pkgRoot, true);
  }

  /**
   * Resolve the layout from the running launcher module:
   *   - from `src/` (tsx) → dev, source form;
   *   - from a checkout's `launcher/dist` (isCheckoutBuild) → dev, bundled;
   *   - from any other `dist/` → installed.
   * MANDU_LAYOUT=installed forces installed; MANDU_LAYOUT=dev or
   * MANDU_DEV_REPO forces the dev source form (MANDU_DEV_REPO may name another
   * tree, whose services this launcher's bundles were not built from).
   */
  static detect(
    moduleUrl: string,
    env: Record<string, string | undefined> = process.env,
    exists: (p: string) => boolean = existsSync,
  ): Layout {
    const selfDir = dirname(fileURLToPath(moduleUrl));
    const pkgRoot = resolve(selfDir, ".."); // parent of src/ (dev) or dist/ (bundle)
    const forced = env["MANDU_LAYOUT"];
    if (forced === "installed") return Layout.installed(pkgRoot);
    if (forced === "dev" || env["MANDU_DEV_REPO"]) {
      return Layout.dev(env["MANDU_DEV_REPO"] ?? resolve(pkgRoot, ".."), pkgRoot);
    }
    if (basename(selfDir) === "dist") {
      return isCheckoutBuild(selfDir, exists)
        ? Layout.dev(resolve(pkgRoot, ".."), pkgRoot, { bundled: true })
        : Layout.installed(pkgRoot);
    }
    return Layout.dev(resolve(pkgRoot, ".."), pkgRoot);
  }

  /** Absolute path to a bundle. */
  private bundle(name: string): string {
    return join(this.pkgRoot, "dist", `${name}.mjs`);
  }

  /** A service's TypeScript entry in the source tree (dev, source form). */
  private source(name: ServiceName): string {
    return join(this.repoRoot, SERVICE_SOURCES[name]);
  }

  /**
   * A static asset shipped with the package (bundle-manifest.json `assets`):
   * `dist/<key>` when installed, the source file in a checkout. Today: the
   * AppArmor userns grants `mandu setup` installs, and the SDK route's Node
   * preload (sdk-route.ts).
   */
  asset(key: string): string {
    if (this.mode === "installed") return join(this.pkgRoot, "dist", key);
    const src = ASSET_SOURCES[key];
    if (src === undefined) throw new Error(`mandu: unknown asset '${key}'`);
    return join(this.repoRoot, src);
  }

  /** Env the arbiter-client consumers need when bundled (empty from source). */
  private clientEnv(): Record<string, string> {
    return this.bundled
      ? { MANDU_ARBITER_CLIENT_MODULE: this.bundle("arbiter-client") }
      : {};
  }

  /**
   * A resident daemon. `name` is the bundle/service name; `pkgSubdir` is its
   * source package relative to repoRoot (the source form's cwd and tsx).
   * `needsClient` adds MANDU_ARBITER_CLIENT_MODULE when bundled (false for the
   * arbiter, which never imports its own client).
   */
  daemon(name: ServiceName, pkgSubdir: string, needsClient = true): DaemonSpec {
    // A checkout's resident dashboard follows the launch too: started from
    // the build this launch just checked, it knows itself for a checkout's
    // build (dashboard/src/server-main.ts, a dist/ beside src/run.ts), so it
    // keeps the checkout's paths and front-ends, and its supervisor checks
    // the build again before every service it starts (packaging.md §5.1).
    if (this.bundled) {
      return {
        cmd: "node",
        args: [...NODE_FLAGS, this.bundle(name)],
        cwd: this.pkgRoot,
        env: {
          ...(needsClient ? this.clientEnv() : {}),
          // The dashboard's "Describe what you want" box (policy-surface.md §8
          // §5.2) imports the U-LLM selector + client at runtime.
          ...(name === "dashboard" ? { MANDU_ULLM_MODULE: this.bundle("ullm-client") } : {}),
        },
      };
    }
    const dir = join(this.repoRoot, pkgSubdir);
    const t = devTsx(dir);
    return { cmd: t.cmd, args: [...t.args, this.source(name)], cwd: dir, env: {} };
  }

  /** inspect-mcp entry for .mcp.json (spawned by the agent, not the launcher). */
  inspectMcp(): { command: string; args: string[]; env: Record<string, string> } {
    if (this.bundled) {
      return { command: "node", args: [...NODE_FLAGS, this.bundle("inspect-mcp")], env: this.clientEnv() };
    }
    const t = devTsx(join(this.repoRoot, "interceptors", "inspect-mcp"));
    return { command: t.cmd, args: [...t.args, this.source("inspect-mcp")], env: {} };
  }

  /**
   * The policy classifier's argv (confidentiality-plan-14 §14.3): the arbiter
   * runs it once per names-only model run, and learns it from its launch
   * arguments (`--classifier`, arbiter/ipc/server-args.ts), never from the
   * environment. Absolute node (this process's), then the bundle or tsx + the
   * source. Null when its runtime is missing (a checkout whose inspect-mcp has
   * no node_modules): the arbiter then answers "not available in this install".
   */
  policyClassifier(exists: (p: string) => boolean = existsSync): string[] | null {
    if (this.bundled) {
      const b = this.bundle("policy-classifier");
      return exists(b) ? [process.execPath, ...NODE_FLAGS, b] : null;
    }
    const t = devTsx(join(this.repoRoot, "interceptors", "inspect-mcp"));
    return exists(t.entry) ? [process.execPath, ...t.args, this.source("policy-classifier")] : null;
  }

  /** policy-mcp entry for the MCP config (spawned by the agent, not the launcher;
   *  policy-surface.md §8.5.1). Same split as inspectMcp. */
  policyMcp(): { command: string; args: string[]; env: Record<string, string> } {
    if (this.bundled) {
      return { command: "node", args: [...NODE_FLAGS, this.bundle("policy-mcp")], env: this.clientEnv() };
    }
    const t = devTsx(join(this.repoRoot, "interceptors", "policy-mcp"));
    return { command: t.cmd, args: [...t.args, this.source("policy-mcp")], env: {} };
  }

  /** fs-sync CLI one-shot base (init/sync); caller appends the subcommand + args. */
  fsSyncCli(): CmdPrefix {
    if (this.bundled) {
      return { cmd: "node", baseArgs: [...NODE_FLAGS, this.bundle("fs-sync-cli")], cwd: this.pkgRoot, env: this.clientEnv() };
    }
    const dir = join(this.repoRoot, "fs-sync");
    const t = devTsx(dir);
    return { cmd: t.cmd, baseArgs: [...t.args, this.source("fs-sync-cli")], cwd: dir, env: {} };
  }

  /**
   * fs-sync eager watcher base. The source form uses `node --import <tsx>`
   * (not the tsx binary) so SIGTERM reaches the real node process the launcher
   * waits on; a bundle is already a single node process.
   */
  fsSyncWatch(): CmdPrefix {
    return this.fsSyncCli();
  }

  /**
   * The exec-wrap shim's inner command. The generated bash shim runs
   * `exec -a <cmd> <tokens…> "$@"`; `env` are extra `export`s the shim needs
   * (MANDU_ARBITER_CLIENT_MODULE when bundled).
   */
  execShim(): { tokens: string[]; env: Record<string, string> } {
    if (this.bundled) {
      return { tokens: ["node", ...NODE_FLAGS, this.bundle("exec-shim")], env: this.clientEnv() };
    }
    const t = devTsx(join(this.repoRoot, "interceptors", "exec-wrap"));
    return { tokens: [t.cmd, ...t.args, this.source("exec-shim")], env: {} };
  }

  /**
   * The user-reply egress filter wrapper (packaging.md §5): the launcher
   * prepends `<tokens> -- <agent argv>` so the agent's stdout is desymbolized for
   * the human. `requiredFile` is the path whose absence means the runtime is
   * unavailable — the launcher then degrades to no wrapper (utility-only).
   */
  replyFilter(): { tokens: string[]; env: Record<string, string>; requiredFile: string } {
    if (this.bundled) {
      const bundle = this.bundle("reply-filter");
      return { tokens: ["node", ...NODE_FLAGS, bundle], env: this.clientEnv(), requiredFile: bundle };
    }
    const t = devTsx(join(this.repoRoot, "interceptors", "reply-filter"));
    return { tokens: [t.cmd, ...t.args, this.source("reply-filter")], env: {}, requiredFile: t.entry };
  }
}
