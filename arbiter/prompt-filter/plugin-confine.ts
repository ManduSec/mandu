/**
 * plugin-confine — the confinement a prompt filter plugin runs under
 * (confidentiality-plan-15-prompt-filter.md §4.3, §12 2026-10-03; the
 * non-root principle of privilege-model.md §0). Mandu-new (no reference
 * origin). The planning is pure; the probe runs the real tools once.
 *
 * THE LEGS, outermost first:
 *
 *   [bwrap --unshare-pid --unshare-ipc --unshare-uts … --]    namespaces (probe-gated)
 *   mandu-net-guard [--allow tcp:<cleared endpoint>] --        REQUIRED: the network
 *   mandu-landlock-apply --clean --seccomp-deny                 by address; Landlock FS
 *       --read <roots> --rw <scratch> --                        (+ all TCP denied in-kernel)
 *                                                               and the seccomp deny
 *   <the verified copy of the plugin> [script] [args]           filter (probe-gated)
 *
 * - The NETWORK GUARD is required (§12): `mandu-net-guard` traps every
 *   connect and send and decides it by DESTINATION address, connecting an
 *   allowed one itself on the plugin's behalf (TOCTOU-safe). Its allow list
 *   is the cleared endpoint only (a `local: true` entry: its literal address,
 *   `localhost` as both loopbacks, or the perimeter's networks for a name
 *   inside them); a plugin that needs no model gets an EMPTY list, which
 *   denies every connect. Without a working guard a plugin does not run, and
 *   the policy's `on_error` applies.
 * - LANDLOCK (clean mode): reads only under `/usr`, `/lib*`, `/bin`, `/sbin`,
 *   `/etc` and the plugin's verified private copies (never the directory it
 *   was installed in: what it loads from there must be pinned, plugin-pin.ts
 *   `modules:`, and is read from the copy); writes only to
 *   one fresh scratch directory per run; no home; and every TCP connect or
 *   bind denied in-kernel (the guard's own connect for an allowed address is
 *   made outside it). The SECCOMP DENY FILTER (the AgentShell's,
 *   `--seccomp-deny`) rides the same applier; `--seccomp-only` keeps it on a
 *   kernel without Landlock. Both are probe-gated: a leg the host cannot
 *   enact is dropped with a note (§12), never silently.
 * - NAMESPACES (PID, IPC, UTS, cgroup; a new session; capabilities dropped)
 *   come from bubblewrap, outermost, where it is installed and the composed
 *   probe shows the guard still connects for the plugin inside it (the
 *   guard then runs inside the namespaces with the plugin). A host where it
 *   does not (a bubblewrap whose security profile stops the guard from
 *   taking the plugin's socket) drops the namespaces with a note: the guard
 *   is the leg that must hold. `no_new_privs` comes from the guard (seccomp
 *   needs it) and the new session from the spawn (`detached`).
 * - ENVIRONMENT: an allowlist (`pluginEnv`): a fixed `PATH`, `LANG`,
 *   `LC_ALL`, `HOME` = `TMPDIR` = the scratch directory, the endpoint's URL
 *   (`MANDU_PROMPT_FILTER_ENDPOINT`) and the cleared entry's token variable.
 *   No pack may add a path or a variable.
 */
import { isIP } from "node:net";

import type { ModelEndpoint } from "../policy/compiled-policy.js";

/** The read-only system roots every plugin may read (§12, 2026-10-03). */
export const PLUGIN_READ_ROOTS: readonly string[] = ["/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin", "/etc"];

/** A fixed PATH (the system's directories only). */
export const PLUGIN_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

export const PLUGIN_ENDPOINT_ENV = "MANDU_PROMPT_FILTER_ENDPOINT";

/** The confinement tools' absolute paths (null: not installed). */
export interface ConfineTools {
  netGuard: string | null;
  landlockApply: string | null;
  bwrap: string | null;
}

/** Which legs the probe found working on this host. */
export interface ConfineLegs {
  /** The address guard: REQUIRED for any plugin to run. */
  guard: boolean;
  /** Landlock filesystem (and TCP) confinement. */
  landlock: boolean;
  /** The seccomp deny filter. */
  seccomp: boolean;
  /** PID/IPC/UTS/cgroup namespaces through bubblewrap. */
  namespaces: boolean;
  /** Why a leg is off (one line each). */
  notes: string[];
}

export const NO_LEGS: ConfineLegs = { guard: false, landlock: false, seccomp: false, namespaces: false, notes: [] };

/** The guard's allow specs for a cleared endpoint, or why there are none. Pure. */
export function endpointAllowSpecs(e: Pick<ModelEndpoint, "url" | "perimeter">): { specs: string[] } | { why: string } {
  let u: URL;
  try {
    u = new URL(e.url);
  } catch {
    return { why: `its URL (${e.url}) does not parse` };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return { why: `its URL is not http or https (${u.protocol})` };
  const port = u.port !== "" ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
  const host = u.hostname.replace(/^\[(.*)\]$/, "$1");
  const fmt = (h: string): string => (isIP(h) === 6 ? `tcp:[${h}]:${port}` : `tcp:${h}:${port}`);
  if (isIP(host) !== 0) return { specs: [fmt(host)] };
  if (host === "localhost") return { specs: [fmt("127.0.0.1"), fmt("::1")] };
  // A name: only inside the perimeter's networks (Plan 12 D4), whose
  // addresses the guard checks at every connect.
  if (e.perimeter && e.perimeter.length > 0) return { specs: e.perimeter.map((net) => (net.includes(":") ? `tcp:[${net.split("/")[0]}]${net.includes("/") ? `/${net.split("/")[1]}` : ""}:${port}` : `tcp:${net}:${port}`)) };
  return { why: `its host ${host} is a name outside any perimeter network; name it by address, as localhost, or inside your organization's perimeter` };
}

/** The plugin's environment (an allowlist, §12). Pure. */
export function pluginEnv(o: { scratch: string; hostEnv: NodeJS.ProcessEnv; endpointUrl?: string; tokenEnv?: string }): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    PATH: PLUGIN_PATH,
    HOME: o.scratch,
    TMPDIR: o.scratch,
    LANG: o.hostEnv.LANG && /^[A-Za-z0-9_.@-]{1,64}$/.test(o.hostEnv.LANG) ? o.hostEnv.LANG : "C.UTF-8",
  };
  if (o.hostEnv.LC_ALL && /^[A-Za-z0-9_.@-]{1,64}$/.test(o.hostEnv.LC_ALL)) env.LC_ALL = o.hostEnv.LC_ALL;
  if (o.endpointUrl) env[PLUGIN_ENDPOINT_ENV] = o.endpointUrl;
  if (o.tokenEnv && /^[A-Za-z_][A-Za-z0-9_]*$/.test(o.tokenEnv) && typeof o.hostEnv[o.tokenEnv] === "string") env[o.tokenEnv] = o.hostEnv[o.tokenEnv];
  return env;
}

export interface PlanInput {
  legs: ConfineLegs;
  tools: ConfineTools;
  /** The guard's allow specs (empty: no network at all). */
  allow: readonly string[];
  /** Directories the plugin may read besides the system roots: its
   *  verified copies only (plugin-pin.ts `copyDirs`). */
  readDirs: readonly string[];
  /** The fresh scratch directory (read-write). */
  scratch: string;
  /** The program and its arguments (the verified copies). */
  target: readonly string[];
}

/**
 * The argv that runs `target` under the legs the probe found. Throws when
 * the guard is not available (the plugin must not run). Pure.
 */
export function planPluginArgv(p: PlanInput): string[] {
  if (!p.legs.guard || p.tools.netGuard === null) throw new Error("the network guard (mandu-net-guard) is not available");
  const reads = [...PLUGIN_READ_ROOTS, ...p.readDirs];
  const inner: string[] = [];
  if (p.tools.landlockApply !== null && p.legs.landlock) {
    inner.push(p.tools.landlockApply, "--clean", ...(p.legs.seccomp ? ["--seccomp-deny"] : []));
    for (const r of reads) inner.push("--read", r);
    inner.push("--rw", p.scratch, "--");
  } else if (p.tools.landlockApply !== null && p.legs.seccomp) {
    inner.push(p.tools.landlockApply, "--seccomp-only", "--");
  }
  const guard = [p.tools.netGuard, ...p.allow.flatMap((s) => ["--allow", s]), "--"];
  const out: string[] = [];
  if (p.tools.bwrap !== null && p.legs.namespaces) {
    out.push(p.tools.bwrap);
    for (const r of reads) out.push("--ro-bind-try", r, r);
    for (const t of [p.tools.netGuard, p.tools.landlockApply]) if (t !== null) out.push("--ro-bind", t, t);
    out.push(
      "--bind", p.scratch, p.scratch, "--dev", "/dev", "--proc", "/proc",
      "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try",
      "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--chdir", p.scratch, "--",
    );
  }
  out.push(...guard, ...inner, ...p.target);
  return out;
}

/** The probe's program: connect to the allowed port (must work) and to the
 *  denied one (must fail); exit 0 only when both hold. */
export const PROBE_SCRIPT = [
  "const net=require('net');",
  "const t=(p)=>new Promise((r)=>{const s=net.connect(+p,'127.0.0.1');s.on('connect',()=>{s.destroy();r(true)});s.on('error',()=>r(false));setTimeout(()=>{s.destroy();r(false)},3000)});",
  "Promise.all([t(process.argv[1]),t(process.argv[2])]).then(([a,b])=>process.exit(a&&!b?0:3));",
].join("");
