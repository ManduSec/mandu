/**
 * seatbelt-setup — apply the ONE whole-agent Seatbelt profile of a macOS
 * launch (seatbelt-profile.ts renders it; confidentiality.md §7.3).
 *
 * run.ts gathers each component from the rung that owns it on Linux:
 *
 *   1. the credential files        secret-setup.ts (result.seatbelt)
 *   2. Mandu's own state           here (`manduStatePaths`), `secrets` mode
 *   3. the write-protect list      write-protect.ts (platform "darwin")
 *   4. the network confine         landlock-net-setup.ts (`planSeatbeltNet`)
 *   5. the Unix-socket list        unix-policy.ts (platform "darwin")
 *   6. the host-service programs   seatbelt-profile.ts, with 5's switch
 *   and the arbiter's human plane  plan.humanPlaneDirs (human-plane.ts; the
 *                                  guard's always-deny `unixDeny` on Linux)
 *   and Mandu's runtime registries runtime-registry.ts, under
 *                                  plan.arbiterRuntimeBase and the account's
 *                                  default base and rendezvous
 *
 * then this appends `/usr/bin/sandbox-exec -p <profile text>` to the launch
 * prefix: INSIDE the reply filter (prepended later), around the agent and
 * everything it starts. The binary is named by path (seatbelt-profile.ts
 * `SANDBOX_EXEC`), never looked up on the agent's PATH, and `available` is
 * the check of that same path. The text rides the argv, never a file read
 * back by path: the runtime base stays writable to the agent of another
 * session, which could otherwise swap this session's profile file between
 * its write and sandbox-exec's read (review 2026-09-30). A copy for the
 * person to read is written beside the session (`<scope run
 * dir>/seatbelt/agent.sb`, 0600, in a fresh 0700 directory, created
 * O_EXCL|O_NOFOLLOW); nothing reads it back, so a copy that cannot be
 * written costs one note and no protection.
 *
 * Fail-closed: a runtime registry entry that holds what the agent must keep
 * writable (its workspace, the runtime base, its scope dir) refuses the
 * launch, never drops the rule (parse.ts already refuses a scope id that
 * names one).
 *
 * The result also says whether the profile SEALS THE MANDU HOME
 * (`homeSealed`, `profileSealsHome`): every direct read and write of it
 * denied to everything under the profile, the fact the history caches'
 * seals rest on (confidentiality-plan-14 §11.2, §11.3). run.ts sends it with
 * the launch record, and the arbiter counts a `read-blocked` launch as
 * confined only with it. Code a system service runs for the agent outside
 * the profile (confidentiality.md §7.3) stays a residual, accepted for the
 * caches on macOS (plan 14 §12).
 *
 * Mandu-new (no reference origin).
 */
import { closeSync, constants, mkdirSync, openSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import {
  canonicalPath, normalizeAbs, renderSeatbeltProfile, seatbeltSpellings, seatbeltWrapArgvInline,
  type SeatbeltNet, type SeatbeltRuntime, type SeatbeltUnix,
} from "./seatbelt-profile.js";
import { humanPlaneDir } from "./human-plane.js";
import { runtimeRegistryPaths } from "./runtime-registry.js";
import { manduHomes, SecretConfinementError } from "./secret-setup.js";
import type { LaunchMutation, LaunchPlan } from "./types.js";
import { darwinUnixRefuse, UNIX_EXTRA_LABELS, type UnixPolicy } from "./unix-policy.js";
import { ownFiles, type WriteProtectEntry } from "./write-protect.js";
import { manduPath } from "./generated/mandu-paths.js";
import { accountHome, pathAndDefault } from "./own-paths.js";

export interface SeatbeltSetupInput {
  plan: Pick<LaunchPlan, "eventDir" | "arbiterSock" | "arbiterRuntimeBase" | "humanCwd" | "cwd">;
  env: Record<string, string | undefined>;
  scopeRunDir: string;
  /** Component 1 (secret-setup.ts result.seatbelt); absent: none. Its
   *  `ownStores` (secret-setup.ts `ownStoresHidden`: the symbol DB, the event
   *  log, the CA key, the shadow repositories) join component 2 whatever the
   *  axes, as the Linux guard hides them, and its `carveOuts` (the home's
   *  AgentView and repo.git in the integrity modes) are allowed back. */
  secrets?: { secrets: string[]; noDelete: string[]; ownStores?: string[]; carveOuts?: string[] };
  /** The arbiter's human-plane directories (run.ts plan.humanPlaneDirs,
   *  human-plane.ts): no connect, no read or write, no rename above them —
   *  in every mode that renders a profile (arbiter-human-plane.md §5). */
  humanDirs?: readonly string[];
  /** Write-deny Mandu's runtime registries (runtime-registry.ts) under
   *  plan.arbiterRuntimeBase and `registryBases`: run.ts sets it in every
   *  mode but `off`, with the human plane. No opt-out: nothing the agent does
   *  needs to write them. */
  runtimeRegistry: boolean;
  /** Further runtime bases whose registries are write-denied too: the
   *  account's default base and its rendezvous (runtime-base.ts
   *  `defaultRuntimeBaseOf`, `accountRendezvous`), where the user's resident
   *  arbiter and dashboards live when this launch uses a base of its own
   *  (MANDU_RUNTIME_DIR). Relative entries and repeats are ignored. */
  registryBases?: readonly string[];
  /** Component 2: seal Mandu's own state (confidentiality ON, integrity
   *  OFF: no AgentView lives under ~/.mandu then). */
  sealState: boolean;
  /** Component 3; null: off (mode `off`, MANDU_WRITE_PROTECT=0). */
  writeProtect: WriteProtectEntry[] | null;
  /** Component 4; null: off (--no-landlock-net) or not planned. */
  net: SeatbeltNet | null;
  /** Components 5 and 6; null: off (confidentiality OFF,
   *  MANDU_UNIX_POLICY=0). */
  unix: UnixPolicy | null;
  /** Is /usr/bin/sandbox-exec there (seatbelt-profile.ts
   *  `sandboxExecAvailable`)? Without it nothing can be applied. */
  available: boolean;
}

export interface SeatbeltSetupDeps {
  log: (m: string) => void;
  /** realpath, null when the path does not resolve. Default: realpathSync. */
  realpath?: (p: string) => string | null;
  /** Write the profile's copy for the person to read (mode 0600). Default:
   *  `writeProfileCopy`. A test knob. */
  writeProfile?: (dir: string, path: string, text: string) => void;
  /** The launching user's uid (the host tmux socket dir). Default: this
   *  process's. */
  uid?: number;
  /** The account's passwd home, whose `~/.mandu` the home seal must cover
   *  too (secret-setup.ts `manduHomes`; default `accountHome()`); null:
   *  none beyond the launch's own. A test knob. */
  accountHome?: string | null;
}

export interface SeatbeltSetupResult {
  /** The copy for the person to read (the wrap carries the text itself). */
  profilePath: string;
  profile: string;
  /** The components the profile carries, for the launch note and tests. */
  components: string[];
  /** The profile denies every direct read and write of the Mandu home to
   *  the agent's tree, for the history caches' purpose (plan 14 §11.2,
   *  §11.3; `profileSealsHome`, which also says what it does not cover):
   *  the launch record's `homeSealed` claim (cache-epoch.ts). */
  homeSealed: boolean;
  /** Every human-plane directory requested by the launch is denied in
   *  this applied profile, independently of the home/cache seal. */
  humanPlaneWalled: boolean;
}

const realOrNull = (p: string): string | null => {
  try { return realpathSync(p); } catch { return null; }
};

/** Mandu's secret-bearing state (component 2; on-disk-layout.md §4): the
 *  Mandu home (MANDU_HOME, else ~/.mandu: the symbol DB, the event store,
 *  the shadow repositories, config and policy, one rule) and the session's
 *  event directory; and, write only, the install directory (the path
 *  table's `install-prefix`, MANDU_PREFIX and its default) and an explicit
 *  MANDU_POLICY_FILE. Pure. */
export function manduStatePaths(
  plan: Pick<LaunchPlan, "eventDir">,
  env: Record<string, string | undefined>,
  home: string,
): { dirs: string[]; files: string[]; writeOnly: string[] } {
  const dirs = [manduPath("mandu-home", env, home), plan.eventDir].filter((d): d is string => !!d);
  const writeOnly = pathAndDefault("install-prefix", env, home);
  if (env["MANDU_POLICY_FILE"]) writeOnly.push(env["MANDU_POLICY_FILE"]!);
  return { dirs: [...new Set(dirs)], files: [], writeOnly: [...new Set(writeOnly)] };
}

/** Is `inner` the same as `outer`, or under it? (Both canonical.) */
function within(inner: string, outer: string): boolean {
  return inner === outer || inner.startsWith(outer.endsWith("/") ? outer : `${outer}/`);
}

/** What `profileSealsHome` judges: the lists the profile is rendered from,
 *  after every drop, as given to `renderSeatbeltProfile`. The judgment spells
 *  them exactly as the renderer does (`seatbeltSpellings`: normalized, both
 *  spellings, a non-absolute entry dropped), so it sees what is rendered. */
export interface HomeSealFacts {
  /** Every Mandu home a launch hides (secret-setup.ts `manduHomes`). */
  homes: readonly string[];
  /** Component 2's read-and-write denies (the state and own-store dirs). */
  stateDirs: readonly string[];
  /** Component 2's carve-outs, allowed back after those denies (the
   *  renderer emits them only beside a state deny). */
  carveOuts: readonly string[];
  /** Component 3's write denies, and its exceptions. */
  writeProtect: readonly string[];
  writeExcept: readonly string[];
  /** The human-plane directories the profile walls off. */
  humanDirs: readonly string[];
  /** Components 5 and 6: the Unix-socket list and the host services. */
  unixAndHostServices: boolean;
  /** The canonical spelling of a path (seatbelt-profile.ts `canonicalPath`
   *  over the host); default identity. */
  canonical?: (p: string) => string;
}

/** A key under which two spellings may name the same file on the default
 *  macOS volume, which ignores case and Unicode normalization. Seatbelt's
 *  path match does too there: a deny spelled `.MANDU` holds for `.mandu`,
 *  and an allow spelled `.MANDU/cache` re-allows `.mandu/cache` (both
 *  measured on macOS 26.5, 2026-09-30). */
function sameFileKey(p: string): string {
  return p.toUpperCase().toLowerCase().normalize("NFD");
}

/**
 * Does the profile seal the Mandu home, for the history caches' purpose
 * (confidentiality-plan-14 §11.2, §11.3)? Those caches (the sanitized
 * packs, the history walks, the history-scan cache) and mandu.db's seal and
 * lock rows are trusted only while nothing the agent runs has written them.
 * This answers true only when ALL of these hold for the profile as
 * rendered (fail closed):
 *
 *   1. every Mandu home is absolute and read- AND write-denied (component
 *      2: a rendered `subpath` deny covering its canonical spelling exactly;
 *      a home the renderer would drop, a relative MANDU_HOME, is not);
 *   2. no carve-out re-allows an enforcement store: a carve-out that could
 *      name a path in a home (any spelling, case and normalization
 *      ignored) lies strictly inside its `state/workspaces/` (the only place
 *      own-paths.ts `homeCarveOuts` puts one), apart from `cache/`,
 *      `state/object-walks/` and `state/mandu.db`; the same for the
 *      write-protect exceptions;
 *   3. every home is write-protected too (component 3);
 *   4. the human plane is walled off (the seal and launch ops live there,
 *      arbiter-human-plane.md §3);
 *   5. the Unix-socket list and the six-program host-service deny are on
 *      (components 5 and 6): they refuse docker and its kin, a host tmux
 *      server, `open`, `osascript`, `launchctl`, `crontab`, `at`, `batch`
 *      and Apple Events, the known ways to have a service run code outside
 *      the profile.
 *
 * What true means, and does not: the profile denies every direct read and
 * write of the home to everything that runs UNDER it, by any spelling (the
 * darwin live test tries the path as given, other cases, the
 * `/System/Volumes/Data` firmlink, `..` components, `/.vol/<dev>/<inode>`
 * and a symlink). It does not stop code a system service runs for the agent
 * OUTSIDE the profile beyond those programs (a copied `launchctl`, a direct
 * XPC client: confidentiality.md §7.3, guarantees.md §3 "Services reached
 * over Mach or XPC"). Such code is S3's same-uid process outside Mandu,
 * which the session-end rotation never bounded either (it outlives the
 * session and can forge the seal rows themselves); plan 14 §11.2
 * "Residuals" (e) and §12 record why the caches accept it on macOS.
 *
 * Pure.
 */
export function profileSealsHome(f: HomeSealFacts): boolean {
  const canon = f.canonical ?? ((p: string): string => p);
  const spell = (xs: readonly string[]): string[] => seatbeltSpellings(xs, canon);
  // 1's precondition: a home the renderer cannot spell is not sealed.
  const homes: string[] = [];
  for (const h of f.homes) {
    const abs = normalizeAbs(h);
    const c = abs === null ? null : normalizeAbs(canon(abs));
    if (abs === null || abs === "/" || c === null || c === "/") return false;
    homes.push(c);
  }
  if (homes.length === 0) return false;
  const stateDirs = spell(f.stateDirs);
  const carveOuts = stateDirs.length > 0 ? spell(f.carveOuts) : [];
  const writeProtect = spell(f.writeProtect);
  const writeExcept = spell(f.writeExcept);
  // Every spelling of every home, for 2 (an allow in any of them counts).
  const homeKeys = spell(f.homes).map(sameFileKey);
  const reachesNoStore = (x: string): boolean => {
    const k = sameFileKey(x);
    return homeKeys.every((h) => {
      if (!within(k, h) && !within(h, k)) return true;
      return k.startsWith(`${sameFileKey(manduPath("workspaces", { MANDU_HOME: h }, "/"))}/`);
    });
  };
  return homes.every((h) => stateDirs.some((d) => within(h, d)) && writeProtect.some((w) => within(h, w)))
    && carveOuts.every(reachesNoStore)
    && writeExcept.every(reachesNoStore)
    && spell(f.humanDirs).length > 0
    && f.unixAndHostServices;
}

/** The registry entries under one runtime base (runtime-registry.ts). */
export { runtimeRegistryPaths };

/**
 * Write the profile's copy for the person to read, never through something
 * planted: `seatbelt/` is made afresh (whatever stood at the name is removed
 * first, a link itself and never what it names; then a non-recursive mkdir,
 * 0700), and the file is created O_CREAT|O_EXCL|O_NOFOLLOW (0600), so the
 * bytes only ever land in a file this call created. Nothing reads it back:
 * the wrap carries the text (`-p`).
 */
export function writeProfileCopy(dir: string, path: string, text: string): void {
  mkdirSync(dirname(dir), { recursive: true, mode: 0o700 });
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { mode: 0o700 });
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    writeFileSync(fd, text);
  } finally {
    closeSync(fd);
  }
}

/**
 * Render and apply the profile. Returns null (and wraps nothing) when there
 * is nothing to apply or `sandbox-exec` is missing.
 */
export function applySeatbelt(input: SeatbeltSetupInput, mut: LaunchMutation, deps: SeatbeltSetupDeps): SeatbeltSetupResult | null {
  if (!input.available) return null;
  const real = deps.realpath ?? realOrNull;
  const canonical = (p: string): string => canonicalPath(p, real);
  const env = input.env;
  const home = env["HOME"] || homedir();
  const cwd = input.plan.humanCwd || input.plan.cwd;
  // What the agent must keep: its working directory, Mandu's runtime
  // directory (the arbiter socket) and this session's run directory.
  const keep = [cwd, input.plan.arbiterRuntimeBase, input.scopeRunDir].filter((k): k is string => !!k).map(canonical);

  // Component 2, minus any directory that holds one of those. Said, never
  // silent.
  let stateDirs: string[] = [];
  let stateFiles: string[] = [];
  let stateWrite: string[] = [];
  if (input.sealState) {
    const st = manduStatePaths(input.plan, env, home);
    const kept = (p: string): boolean => {
      const c = canonical(p);
      const hit = keep.find((k) => within(k, c));
      if (hit === undefined) return true;
      deps.log(`WARNING: mandu: ${p} (Mandu's own state) stays readable to the agent: ${hit} is inside it`);
      return false;
    };
    stateDirs = st.dirs.filter(kept);
    stateFiles = st.files;
    stateWrite = st.writeOnly.filter(kept);
  }
  // Mandu's own stores of originals (secret-setup.ts `ownStoresHidden`),
  // sealed in every mode the secret setup hides them, integrity on included
  // (it already leaves out a state base that holds the workspace).
  const ownStores = (input.secrets?.ownStores ?? []).filter((p) => {
    const hit = keep.find((k) => within(k, canonical(p)));
    if (hit === undefined) return true;
    deps.log(`WARNING: mandu: ${p} (Mandu's own store) stays readable to the agent: ${hit} is inside it`);
    return false;
  });
  stateDirs = [...new Set([...stateDirs, ...ownStores])];

  // Component 3. The arbiter socket's own entries (the socket and the links
  // on its way, `current`, and on macOS `/tmp` and `/var` themselves) name
  // the file or link ITSELF: following `/tmp` would seal all of
  // /private/tmp. And an entry that covers what the agent must keep writable
  // (its workspace, Mandu's runtime or session directory) is left out, said.
  const sock = input.plan.arbiterSock;
  const sockReal = sock ? real(sock) : null;
  const own = new Set(ownFiles(env).map((e) => e.path));
  /** The socket, its real path, or a directory (a link) on its way. */
  const onSockWay = (p: string): boolean =>
    !own.has(p) && !!sock && (p === sock || p === sockReal || sock.startsWith(p.endsWith("/") ? p : `${p}/`));
  const wpPaths: string[] = [];
  const wpLinks: string[] = [];
  const wpExcept: string[] = [];
  for (const e of input.writeProtect ?? []) {
    if (onSockWay(e.path)) { wpLinks.push(e.path); continue; }
    const hit = keep.find((k) => within(k, canonical(e.path)));
    if (hit !== undefined) {
      deps.log(`WARNING: mandu: write-protect entry ${e.path} is not applied on macOS: ${hit} is inside it and must stay writable`);
      continue;
    }
    wpPaths.push(e.path);
    wpExcept.push(...(e.except ?? []));
  }

  // Mandu's runtime registries under this launch's base and the account's
  // default one (runtime-registry.ts). One that holds what the agent must
  // keep writable REFUSES the launch: dropping the rule would reopen the
  // registry (parse.ts refuses a scope id that names one, so only a
  // workspace or a MANDU_RUNTIME_DIR inside a registry gets here). Compared
  // with case and Unicode folded (`sameFileKey`): the default macOS volume
  // and Seatbelt's match both ignore them, so `<base>/Logs` IS `logs/`.
  const bases = [input.plan.arbiterRuntimeBase, ...(input.registryBases ?? [])].filter((b): b is string => !!b && b.startsWith("/"));
  let runtime: SeatbeltRuntime | null = null;
  if (input.runtimeRegistry && bases.length > 0) {
    runtime = { dirs: [], names: [], prefixes: [] };
    const seen = new Set<string>();
    /** An entry named ITSELF: only its parent resolved (`current` is a link). */
    const ownSpelling = (p: string): string => `${canonical(dirname(p)).replace(/\/$/, "")}/${p.slice(p.lastIndexOf("/") + 1)}`;
    for (const b of bases) {
      const cb = canonical(b);
      if (seen.has(cb)) continue;
      seen.add(cb);
      const r = runtimeRegistryPaths(b);
      const refuse = (p: string, hit: string): never => {
        throw new Error(
          `mandu: refusing to launch: ${hit} lies in ${p}, one of Mandu's runtime registries, which the agent may never write ` +
            "(runtime-instances.md §2). Launch from another folder, or point MANDU_RUNTIME_DIR somewhere else.",
        );
      };
      for (const p of r.dirs) {
        const c = sameFileKey(canonical(p));
        const hit = keep.find((k) => within(sameFileKey(k), c));
        if (hit !== undefined) refuse(p, hit);
      }
      for (const p of r.names) {
        const c = sameFileKey(ownSpelling(p));
        const hit = keep.find((k) => within(sameFileKey(k), c));
        if (hit !== undefined) refuse(p, hit);
      }
      for (const p of r.prefixes) {
        const c = sameFileKey(ownSpelling(p));
        const hit = keep.find((k) => sameFileKey(k).startsWith(c));
        if (hit !== undefined) refuse(`${p}*`, hit);
      }
      runtime.dirs.push(...r.dirs);
      runtime.names.push(...r.names);
      runtime.prefixes.push(...r.prefixes);
    }
  }
  const runtimeEntries = runtime === null ? 0 : runtime.dirs.length + runtime.names.length + runtime.prefixes.length;

  const unix: SeatbeltUnix | null = input.unix === null ? null : {
    allow: input.unix.allow.filter((a) => !UNIX_EXTRA_LABELS.includes(a.label)).map((a) => a.path),
    refuse: darwinUnixRefuse(env, deps.uid ?? process.getuid?.()),
    extra: input.unix.allow.filter((a) => UNIX_EXTRA_LABELS.includes(a.label)).map((a) => a.path),
  };
  const profileDir = join(input.scopeRunDir, "seatbelt");
  const profilePath = join(profileDir, "agent.sb");
  const components: string[] = [];
  if ((input.secrets?.secrets.length ?? 0) > 0) components.push("credential files");
  if (stateDirs.length + stateFiles.length + stateWrite.length > 0) components.push("Mandu's state");
  if ((input.writeProtect?.length ?? 0) > 0) components.push("write-protect");
  if (input.net !== null) components.push("network");
  if (unix !== null) components.push("unix sockets", "host services");
  // The human plane under EVERY registry base, not only the launch's own:
  // a launch with its own MANDU_RUNTIME_DIR must not reach the resident
  // stack's `human/` under the account's default base either
  // (arbiter-human-plane.md §5). Deduplicated by canonical path.
  const humanDirs: string[] = [];
  const humanSeen = new Set<string>();
  for (const d of [...(input.humanDirs ?? []), ...(input.runtimeRegistry ? bases.map(humanPlaneDir) : [])]) {
    if (!d.startsWith("/") || humanSeen.has(canonical(d))) continue;
    humanSeen.add(canonical(d));
    humanDirs.push(d);
  }
  if (humanDirs.length > 0) components.push("human plane");
  if (runtimeEntries > 0) components.push("runtime registry");
  if (components.length === 0) return null;
  const profile = renderSeatbeltProfile({
    secrets: input.secrets?.secrets ?? [],
    noDelete: input.secrets?.noDelete ?? [],
    stateDirs,
    stateCarveOuts: input.secrets?.carveOuts ?? [],
    stateFiles,
    // The profile's copy: the agent cannot make it say something else than
    // what runs (the wrap carries the text, and the running profile is
    // already compiled).
    stateWriteOnly: [...stateWrite, profilePath],
    writeProtect: wpPaths,
    writeProtectLinks: wpLinks,
    writeProtectExcept: wpExcept,
    net: input.net,
    unix,
    hostServices: unix !== null,
    humanDirs,
    runtime,
    canonical,
  })!;

  // The text rides the argv (`-p`): nothing is read back by path.
  mut.launchPrefix = [...mut.launchPrefix, ...seatbeltWrapArgvInline(profile)];
  let copy = `copy: ${profilePath}`;
  try {
    (deps.writeProfile ?? writeProfileCopy)(profileDir, profilePath, profile);
  } catch (e) {
    copy = `its copy could not be written: ${(e as Error).message}`;
  }

  // Plan 14 §11.2, §11.3: what the launch record may claim about the home,
  // judged on exactly what the renderer was given above (after the drops),
  // spelled as it spells them.
  const homeSealed = profileSealsHome({
    homes: manduHomes(env, home, deps.accountHome === undefined ? accountHome() : deps.accountHome),
    stateDirs,
    carveOuts: input.secrets?.carveOuts ?? [],
    writeProtect: wpPaths,
    writeExcept: wpExcept,
    humanDirs,
    unixAndHostServices: unix !== null,
    canonical,
  });

  deps.log(`mandu: seatbelt LIVE — the macOS profile around the whole agent: ${components.join(", ")} (${copy})`);
  if (stateDirs.length + stateFiles.length > 0) {
    deps.log("mandu: Mandu's own state (the symbol store, the event log, the shadow repositories) is unreadable to the agent");
  }
  if (input.writeProtect !== null && input.writeProtect.length > 0) {
    const later = input.writeProtect.filter((e) => e.answer === "ask").length;
    deps.log(
      `mandu: write-protect — Mandu's own files are read-only to the agent; ${later} file(s) that run later ` +
        "(shell startup, launchd agents, ssh and git settings, repo hooks) are REFUSED on macOS: the Seatbelt " +
        "profile cannot hold a change for your OK in the Inbox (MANDU_WRITE_PROTECT=0 opts out)",
    );
  }
  if (unix !== null) {
    deps.log(
      "mandu: unix sockets — the agent's programs reach only Mandu, name service, logging, the ssh and gpg agents, " +
        "the display and sockets under the workspace (host services such as docker are refused)",
    );
    deps.log(
      "mandu: host services — open, osascript, launchctl, crontab, at and batch cannot run and Apple Events are " +
        "refused (each runs code outside the profile); the Keychain stays reachable",
    );
  }
  const requestedHuman = input.humanDirs ?? [];
  const humanPlaneWalled = requestedHuman.length > 0 && requestedHuman.every((d) =>
    d.startsWith("/") && humanSeen.has(canonical(d)));
  return { profilePath, profile, components, homeSealed, humanPlaneWalled };
}
