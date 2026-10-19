/**
 * exec-box-setup — establish the --exec-box shim dir for a launch
 * (docs/design/integrity/exec-routing.md §7).
 *
 * Mirrors applySecretTwins / applyLandlockNet: resolve the committed
 * `mandu-exec-box` bin, probe that the box can actually run here, and — when
 * everything is present — write one PATH-shadow shim per curated command and
 * record the dir on `plan.execBoxShimDir` (env-compose then prepends it to the
 * agent PATH). ON BY DEFAULT (the non-root principle), UTILITY-CLASS graceful
 * degrade: any unmet precondition (bin not built, no bwrap / user namespaces,
 * arbiter socket absent) WARNS and proceeds WITHOUT boxing — the listed
 * commands then run normally — rather than failing the launch. Boxing a
 * command whose box would fail (exit 71/78) would be WORSE than not boxing it,
 * so the probe is the honest choice.
 *
 * VIEW WIRING (fs-view co-design, §7.2): runs AFTER startServices, so when
 * fs-view produced a HumanView↔AgentView pair (plan.viewMap) the shims bake it
 * and the box gains the writable AgentView binds (identity + over-workspace);
 * boxed writes land in the AgentView worktree and ride the existing fs-sync
 * path. Without a pair the box stays RO-root + /tmp, and the shims name the
 * launch directory as the project so one under /tmp is re-bound read-only
 * over the box's fresh /tmp (exec-routing.md §4, checklist a7).
 *
 * Mandu-new (no reference origin).
 */
import { chmodSync, closeSync, copyFileSync, existsSync, fstatSync, mkdirSync, openSync, readSync, realpathSync, renameSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { cleanHostEnv, cleanHostSocket } from "./clean-host.js";
import { manduPath, type ManduPathEnv } from "./generated/mandu-paths.js";
import { writeExecBoxShims, type ExecBoxView } from "./services/exec-box-shims.js";
import { nativeBinBuildHint, resolveNativeBin, staleNativeBinNote, type NativeBinName } from "./services/native-bins.js";
import type { LaunchPlan } from "./types.js";
import { probeUserns, usernsGapHint } from "./userns.js";
import { commandAvailable } from "./bwrap-grant.js";
import { systemBwrapBin } from "./bwrap-path.js";
import { cachedProbe } from "./probe-cache.js";

export interface ExecBoxDeps {
  resolveBin?: (name: NativeBinName) => string | null;
  /** The stale-bin WARNING for a resolved bin (services/native-bins
   *  `staleNativeBinNote`; null = fresh or unjudgeable). Injectable. */
  staleNote?: (name: NativeBinName, path: string) => string | null;
  /** Is a command on PATH (bwrap)? */
  commandExists?: (cmd: string) => boolean;
  /** Can we create an unprivileged user + mount namespace? (bubblewrap backend.) */
  usernsOk?: () => boolean;
  /** WHY the namespace is unavailable (src/userns.ts `usernsGapHint`): the
   *  cause + fix appended to the degrade line when `usernsOk` says no. */
  usernsHint?: () => string;
  /** Does the arbiter socket exist? (the box fails closed without it.) */
  arbiterSockExists?: (sock: string) => boolean;
  writeShims?: (
    cmds: string[], boxBin: string, sock: string, scopeRunDir: string,
    view?: ExecBoxView, landlockApply?: string, cleanBox?: boolean, projectRoot?: string, cleanSock?: string,
    workspaceWritable?: boolean, bwrapDisableUsernsSha256?: string,
  ) => string;
  /** The launch's own environment: what the guard-hosted clean box inherits
   *  of it (clean-host.ts CLEAN_HOST_PASS_ENV). */
  hostEnv?: Record<string, string | undefined>;
  /** Copy a bin into destDir (throws on failure); returns the staged path. */
  stageBin?: (srcPath: string, destDir: string) => string;
  log?: (msg: string) => void;
  /** The host platform (run.ts passes `platform.id`). The box is bubblewrap
   *  + seccomp + Landlock, Linux only: elsewhere ONE informational line says
   *  so, never the "not built" degrade (exec-routing.md §7.2). Absent: the
   *  Linux path. */
  platform?: "linux" | "darwin" | "win32";
  /** The kept `bwrap --help` answer the shims bake (keptBwrapDisableUserns):
   *  the sha256 of the box's bubblewrap when it supports `--disable-userns`,
   *  else undefined. Injectable; default probes the real one. */
  bwrapKept?: (bwrapDir: string | undefined) => string | undefined;
}

// ── The box's `bwrap --help`, asked once per launch ─────────────────────────

/** A bubblewrap larger than this is not hashed (exec-supervisor
 *  `sandbox::BWRAP_HASH_MAX_BYTES`): nothing is baked, the box probes. */
export const BWRAP_HASH_MAX_BYTES = 64 * 1024 * 1024;

/** PURE: does a `bwrap --help` text advertise `flag`? Whitespace-token-exact,
 *  as exec-supervisor `kernel::bwrap_help_supports` (bwrap ≥ 0.8's
 *  `--assert-userns-disabled` is not `--disable-userns`). */
export function bwrapHelpSupports(helpText: string, flag: string): boolean {
  return helpText.split(/\s+/).includes(flag);
}

/** sha256 hex of a regular file's bytes (at most BWRAP_HASH_MAX_BYTES), or
 *  null. One open: the bytes hashed are the bytes of the file that was opened. */
export function fileSha256(path: string): string | null {
  let fd: number;
  try { fd = openSync(path, "r"); } catch { return null; }
  try {
    const s = fstatSync(fd);
    if (!s.isFile() || s.size > BWRAP_HASH_MAX_BYTES) return null;
    const h = createHash("sha256");
    const buf = Buffer.alloc(Math.min(Math.max(s.size, 1), 1 << 20));
    let total = 0;
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      total += n;
      if (total > BWRAP_HASH_MAX_BYTES) return null;
      h.update(buf.subarray(0, n));
    }
    return h.digest("hex");
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
}

export interface KeptBwrapDeps {
  /** The distribution's bubblewrap (bwrap-path.ts systemBwrapBin). */
  system?: () => string | null;
  realpath?: (p: string) => string;
  sha256?: (p: string) => string | null;
  /** `bwrap --help`'s output (stdout + stderr), or null when it did not run. */
  help?: (bin: string) => string | null;
}

const realHelp = (bin: string): string | null => {
  const r = spawnSync(bin, ["--help"], { encoding: "utf8", timeout: 5_000 });
  return r.error ? null : `${r.stdout ?? ""}\n${r.stderr ?? ""}`;
};

/**
 * The box's `bwrap --help` probe, asked once for the launch instead of once
 * per boxed command (exec-routing.md §4, "The bwrap probe, kept by content").
 * The bubblewrap is the one the box resolves: `bwrapDir`'s (Mandu's own copy
 * or an administrator's `bwrap_path`, first on the agent's PATH), else the
 * distribution's (bwrap-path.ts). Returns the sha256 of its bytes when it
 * advertises `--disable-userns`, else undefined (nothing baked: the box
 * probes for itself, as before). The box honors the hash only for a
 * bubblewrap with exactly those bytes, and only a positive answer exists, so
 * a wrong one can only make an old bwrap reject the box's argv: the command
 * fails, it never runs less confined. The probe itself is kept for the boot
 * (probe-cache.ts, "bwrap-help").
 */
export function keptBwrapDisableUserns(bwrapDir: string | undefined, deps: KeptBwrapDeps = {}): string | undefined {
  const bin = bwrapDir ? join(bwrapDir, "bwrap") : (deps.system ?? systemBwrapBin)();
  if (bin === null) return undefined;
  let real: string;
  try { real = (deps.realpath ?? realpathSync)(bin); } catch { return undefined; }
  const sha = (deps.sha256 ?? fileSha256)(real);
  if (sha === null || !/^[0-9a-f]{64}$/.test(sha)) return undefined;
  const help = deps.help ?? realHelp;
  const ok = cachedProbe("bwrap-help", () => ({ bins: [real], argv: ["--help"] }), () => {
    const text = help(real);
    return text !== null && bwrapHelpSupports(text, "--disable-userns");
  });
  return ok ? sha : undefined;
}

/** The one line a non-Linux launch prints for the box (informational). */
export const EXEC_BOX_LINUX_ONLY_NOTE =
  "mandu: exec-box (the per-command box for a curated read-only command set) is Linux only; on macOS those " +
  "commands run under the whole-agent Seatbelt profile like every other program the agent starts";

/** `bwrap` is the distribution's outside the current directory, the one the
 *  box resolves too (bwrap-path.ts; exec-supervisor `resolve_bwrap`). */
const defaultCommandExists = commandAvailable;
const defaultUsernsOk = (): boolean => probeUserns();
const defaultStageBin = (srcPath: string, destDir: string): string => {
  mkdirSync(destDir, { recursive: true });
  const dest = join(destDir, basename(srcPath));
  // Copy-then-rename: a concurrent launch re-staging the same slot must never
  // leave a half-written binary where an in-flight box could exec it.
  const tmp = `${dest}.staging-${process.pid}`;
  copyFileSync(srcPath, tmp);
  chmodSync(tmp, 0o755);
  renameSync(tmp, dest);
  return dest;
};

/** The box mounts a fresh tmpfs over /tmp (sandbox.rs AgentShell plan), so a
 *  staged copy under a /tmp-fallback run dir (parse.ts: MANDU_RUNTIME_DIR, else
 *  XDG_RUNTIME_DIR → TMPDIR → /tmp) would be exactly as invisible in-box as the
 *  workspace path it replaces — those hosts stage into the path table's
 *  `exec-box-cache` instead, under the install prefix (on-disk-layout.md §4,
 *  §5): readable to the agent that runs it, write-protected, and outside the
 *  Mandu home the agent may not open. */
export function stagingDirFor(scopeRunDir: string, env: ManduPathEnv, home: string): string {
  const dir = join(scopeRunDir, "bin");
  return isUnderDir(dir, "/tmp") ? join(manduPath("exec-box-cache", env, home), "bin") : dir;
}

/** `p`'s realpath, or `p` itself when it does not resolve (undefined stays undefined). */
function realOr(p: string | undefined): string | undefined {
  if (!p) return undefined;
  try { return realpathSync(p); } catch { return p; }
}

/** Is `p` at or under `root`? Realpaths both sides the same way (the workspace
 *  pair comes from git — resolved — while the bin path is module-derived and
 *  may ride a symlink). A path that does not exist YET (a run dir about to be
 *  created) resolves its deepest existing ancestor and keeps the rest, so
 *  `/tmp/mandu-1000/sid/bin` still lands under `/tmp` where /tmp is a symlink
 *  (darwin: → /private/tmp); nothing resolvable → the literal path. Exported
 *  for tests. */
export function isUnderDir(p: string, root: string): boolean {
  const real = (x: string): string => {
    let head = x;
    let rest = "";
    for (;;) {
      try { return join(realpathSync(head), rest); } catch { /* not there yet: walk up */ }
      const cut = head.lastIndexOf("/");
      if (cut < 0 || head === "/") return x;
      rest = join(head.slice(cut + 1), rest);
      head = cut === 0 ? "/" : head.slice(0, cut);
    }
  };
  const rp = real(p);
  const rr = real(root);
  return rp === rr || rp.startsWith(rr.endsWith("/") ? rr : rr + "/");
}

/**
 * May the box write the launch's project directly (exec-routing.md §7.2,
 * "The workspace without an AgentView")? Only when ALL hold:
 *   - there is NO view pair: with one, boxed writes land in the AgentView and
 *     sync back (the integrity co-design), never in the HumanView;
 *   - the session's EFFECTIVE integrity axis is OFF (`secrets`, `off`): the
 *     agent then has one view, the HumanView, and already writes it unboxed,
 *     so a boxed `sed -i` gains nothing the agent lacks. An unknown axis
 *     (no preflight result) keeps the old read-only box;
 *   - the project is known (`projectRoot`).
 * What the box enforces for reads and egress is unchanged: net off, and the
 * workspace bind is the agent's own mount namespace's tree (secret twins
 * included, the guard's open/write rules inherited). PURE.
 */
export function boxWorkspaceWritable(plan: Pick<LaunchPlan, "effectiveAxes">, view: ExecBoxView | undefined, projectRoot: string | undefined): boolean {
  return view === undefined && projectRoot !== undefined && plan.effectiveAxes?.integrity === false;
}

/**
 * Write the exec-box shim dir and set `plan.execBoxShimDir`. No-ops when
 * `plan.execBox` is false (explicit opt-out); undefined = default-on. Returns
 * the shim dir on success, or null when off / degraded.
 */
export function applyExecBox(plan: LaunchPlan, scopeRunDir: string, deps: ExecBoxDeps = {}): string | null {
  if (plan.execBox === false) return null;
  const log = deps.log ?? ((m: string) => console.error(m));
  if (deps.platform !== undefined && deps.platform !== "linux") {
    if (deps.platform === "darwin") log(EXEC_BOX_LINUX_ONLY_NOTE);
    return null;
  }
  if (plan.target === "codex" && plan.execBox !== true) {
    // Codex runs every tool command inside ITS OWN sandbox (seccomp +
    // Landlock, workspace-write by default), and a nested bwrap cannot set up
    // its net namespace there — measured live 2026-09-05 with the developer's
    // real config: every boxed command (`cat README.md` first) failed with
    // `bwrap: loopback: Failed to create NETLINK_ROUTE socket`, the model
    // relayed the error, nothing else worked. Codex's sandbox already gives
    // the AgentShell's containment for those commands (net off, filesystem
    // confined to the workspace = the AgentView cwd), so the box is OFF by
    // default for codex; --exec-box forces it (danger-full-access users).
    log(
      "mandu: exec-box OFF for codex by default — codex boxes each command in its own sandbox " +
      "(seccomp + Landlock, workspace-write, net off), where a nested bwrap cannot create its net " +
      "namespace (`bwrap: loopback: Failed to create NETLINK_ROUTE socket`); --exec-box forces it " +
      "for a danger-full-access codex.",
    );
    return null;
  }
  const resolveBin = deps.resolveBin ?? resolveNativeBin;
  const commandExists = deps.commandExists ?? defaultCommandExists;
  const usernsOk = deps.usernsOk ?? defaultUsernsOk;
  const usernsHint = deps.usernsHint ?? usernsGapHint;
  const arbiterSockExists = deps.arbiterSockExists ?? existsSync;
  const writeShims = deps.writeShims ?? writeExecBoxShims;
  const stageBin = deps.stageBin ?? defaultStageBin;

  const cmds = plan.execBoxCmds ?? [];
  // Explicit --exec-box vs the default-on posture degrade identically (the box
  // is additive hardening); only the wording differs — a default must not claim
  // the user "asked" for it.
  const asked = plan.execBox === true ? "--exec-box asked to box a command set" : "exec-box is on by default";
  const degrade = (why: string): null => {
    log(`mandu: ${asked}, but ${why} — proceeding WITHOUT it (the listed commands run normally; --no-exec-box silences this).`);
    return null;
  };

  const boxBin = resolveBin("mandu-exec-box");
  if (!boxBin) return degrade(`the mandu-exec-box bin is not built. ${nativeBinBuildHint()}`);
  // A bin older than its source silently runs OLD code for every boxed
  // command (2026-09-17: a session-long bwrap flag error). Warn, then proceed.
  const staleNote = deps.staleNote ?? staleNativeBinNote;
  const boxStale = staleNote("mandu-exec-box", boxBin);
  if (boxStale) log(boxStale);
  if (!commandExists("bwrap")) return degrade("`bwrap` (bubblewrap) is not installed, so the box cannot run");
  if (!usernsOk()) return degrade(`unprivileged user namespaces are unavailable (${usernsHint()}), so the box cannot run`);
  if (!arbiterSockExists(plan.arbiterSock)) return degrade(`the arbiter socket ${plan.arbiterSock} is absent (the box cannot gate without it)`);
  if (cmds.length === 0) return degrade("no commands were given to shadow");

  // fs-view co-design: bake the session view pair so the box RW-binds the
  // AgentView (identity + over-workspace). viewMap is at most one pair today
  // (manager.ts fs-sync block).
  const pair = plan.viewMap?.[0];
  const view: ExecBoxView | undefined = pair
    ? { agentViewRoot: pair.agent, workspace: pair.human }
    : undefined;

  // The Landlock applier is the ONE bin execed INSIDE the box's mount ns
  // (sandbox.rs interposes it after the AgentView bind). Resolve it here and
  // pin it via env — the box bin's own sibling-of-exe fallback probes existence
  // on the HOST and cannot see in-box shadowing. When the resolved path sits
  // UNDER the workspace the AgentView is bound over (dev layout with the
  // workspace = this repo: target/ is gitignored AND on fs-sync's deny list
  // of heavy directories, so it is ABSENT from the worktree; the other
  // ignored files enter it only as symbolized twins, never as runnable
  // bytes, fs-sync.md §3.4.1), every boxed exec would die at
  // bwrap's execvp — stage a copy into the scope run dir and pin THAT instead.
  let landlockApply = resolveBin("mandu-landlock-apply") ?? undefined;
  if (landlockApply !== undefined) {
    const applyStale = staleNote("mandu-landlock-apply", landlockApply);
    if (applyStale) log(applyStale);
  }
  if (landlockApply !== undefined && view !== undefined && isUnderDir(landlockApply, view.workspace)) {
    try {
      landlockApply = stageBin(landlockApply, stagingDirFor(scopeRunDir, deps.hostEnv ?? process.env, homedir()));
    } catch (e) {
      // A shadowed applier that cannot be staged would break EVERY boxed
      // command (bwrap execvp ENOENT inside the box) — degrading the whole box
      // is the only honest option.
      return degrade(
        `the Landlock applier at ${landlockApply} is inside the workspace (the AgentView bind would ` +
        `shadow it in-box) and staging a copy failed: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  }

  // The clean-box posture (exec-routing.md §8.5). The arbiter honors
  // only a verdict the session's GUARD reports (§5.3, sandbox-security-review
  // finding 4): when the arbiter offered this session a reporter, the guard
  // hosts the attempt and the clean box is ON by default; otherwise it is
  // opt-in (the in-tree attempt un-masks nothing, its rerun only costs).
  // Baked HARD so ambient env cannot flip a session's posture.
  const hosted = plan.cleanReporterOffered === true && plan.execCleanBox !== false;
  const cleanBox = plan.execCleanBox === true || hosted;
  // No view pair: name the launch's project (realpath, so a symlinked cwd
  // into /tmp still matches in-box) for the box's /tmp re-bind (checklist a7).
  const projectRoot = view === undefined ? realOr(plan.humanCwd) : undefined;
  const cleanSock = hosted ? cleanHostSocket(scopeRunDir) : undefined;
  const workspaceWritable = boxWorkspaceWritable(plan, view, projectRoot);
  // The box's `bwrap --help`, asked here once instead of by every boxed
  // command (exec-routing.md §4, "The bwrap probe, kept by content").
  const bwrapKept = (deps.bwrapKept ?? ((d) => keptBwrapDisableUserns(d)))(plan.bwrapDir);
  const shimDir = writeShims(
    cmds, boxBin, plan.arbiterSock, scopeRunDir, view, landlockApply, cleanBox, projectRoot, cleanSock, workspaceWritable,
    bwrapKept,
  );
  plan.execBoxShimDir = shimDir;
  if (cleanSock !== undefined) {
    plan.cleanHost = {
      socket: cleanSock,
      boxBin,
      env: cleanHostEnv({
        arbiterSock: plan.arbiterSock, hostEnv: deps.hostEnv ?? process.env, view, projectRoot, landlockApply,
        ...(plan.bwrapDir ? { bwrapDir: plan.bwrapDir } : {}),
      }),
    };
  }
  log(
    `mandu: exec-box LIVE — boxing [${cmds.join(", ")}] in the net-off AgentShell (seccomp` +
    (view
      ? `; RW = the AgentView worktree at its own path + over the workspace — boxed writes land in the AgentView and sync back)`
      : workspaceWritable
        // exec-routing.md §7.2: the agent's own /tmp (its sockets masked),
        // not a fresh one, so a boxed reader sees what the agent wrote there.
        ? `; RW = the project directory and the agent's own /tmp (its sockets masked), the rest read-only — integrity is off, so boxed writes land where the agent's own do)`
        : `; RO root, only a fresh private /tmp writable — no AgentView pair on this launch)`),
  );
  if (cleanBox) {
    log(
      "mandu: exec-box CLEAN BOX first — each boxed command is tried under the clean " +
      "ruleset (reads only under system roots; the AgentView write-only) so a benign " +
      "output reaches the AI UN-masked; a command the clean box refuses reruns in the " +
      "ordinary box (its output masked as before). Cost: that rerun repeats the attempt's " +
      "pre-failure side effects — the default read-only set fails at its first denied " +
      "read, before any write. " +
      (hosted
        ? "The session's guard runs the attempt and vouches for it, outside the agent's process tree."
        : "Without the session's guard hosting it, the arbiter does not honor the box's verdict, " +
          "so no output is un-masked by it."),
    );
  }
  return shimDir;
}
