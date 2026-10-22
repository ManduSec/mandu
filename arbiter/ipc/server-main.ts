#!/usr/bin/env tsx
/**
 * server-main — arbiter daemon entrypoint (Mandu-new, no reference origin).
 *
 * SOCKET SELECTION (docs/design/architecture/runtime-instances.md):
 *   - EXPLICIT path (the first plain argument or $MANDU_ARBITER_SOCK) → bind it verbatim, as
 *     before. listen() refuses to clobber a LIVE listener (no squatting) and
 *     reclaims a stale file. Tests and pinned deployments use this. Since
 *     2026-07-15 a pinned arbiter STILL registers a (registry-only) instance
 *     dir + manifest under the runtime base — no arbiter process is invisible
 *     to `mandu status`/`reap`. Scope MANDU_RUNTIME_DIR in tests.
 *   - DEFAULT (no explicit path) → INSTANCE MODE: bind
 *       ${runtimeBase}/instances/<utc>-<gitrev>-p<pid>/arbiter.sock
 *     (runtimeBase: runtime-base.ts; when it is the /tmp/mandu-<uid>
 *     fallback it must be a private 0700 dir of this uid, created so when
 *     absent — else the start is refused; a base directly in a shared sticky
 *     dir, such as $TMPDIR/mandu-<uid> with TMPDIR=/var/tmp, must be ours and writable by nobody else,
 *     runtime-instances.md §3b)
 *     write manifest.json (identity: pid/rev/startedAt/paths), and — only when
 *     $MANDU_PROMOTE is truthy — atomically repoint ${runtimeBase}/current at
 *     this instance. A hand-started arbiter therefore CANNOT steal the
 *     deployment rendezvous by accident (the 2026-07-05 blackhole); the
 *     dashboard supervisor / launcher autostart pass MANDU_PROMOTE=1.
 *     Dead instances (manifest pid gone) are swept at startup.
 *
 * HUMAN PLANE (docs/design/architecture/arbiter-human-plane.md): BOTH modes also bind the
 * human-plane socket at ${runtimeBase}/human/<instanceId>.sock (dir 0700,
 * ours — verified, or the start is refused), outside every instance and scope
 * dir. The ops that return originals are served only there (and on the admin
 * channel). It is recorded in the manifest, answered by `hello`, and unlinked
 * on a graceful shutdown (a crashed instance's is swept with its dir).
 *
 * STORES (server-args.ts; on-disk-layout.md §3, §5): the symbol DB is
 * `--symbol-db <path>` and the event dir `--event-dir <path>`, defaulting to
 * the path table's `${MANDU_HOME:-~/.mandu}/state/mandu.db` and `…/events`.
 * Only Mandu's own spawners pass the flags; no environment variable moves a
 * single store. Both are DURABLE, shared across instances AND across host
 * reboots; only the runtime identity is instance-scoped. The event store prunes sessions idle longer than
 * $MANDU_EVENT_RETENTION_DAYS (default 90; 0 disables) — the reserved
 * `arbiter-admin` audit stream is never pruned.
 *
 * Run: npm run serve                          # instance mode, un-promoted
 *      MANDU_PROMOTE=1 npm run serve        # instance mode + promotion
 *      tsx ipc/server-main.ts /path/to.sock   # explicit path (verbatim)
 *      npm run --silent serve -- --symbol-db X --event-dir Y   # pinned stores
 */

import { existsSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "./server.js";
import { DAEMON_SCHEDULE } from "../policy/lock-resolution.js";
import { prepLimitsFromEnv, preparedCopiesOff } from "../policy/prepared-copies.js";
import { manduPath } from "../src/generated/mandu-paths.js";
import { homedir } from "node:os";
import { armLifeline } from "./lifeline.js";
import { armTestOwnerWatch } from "./test-owner.js";
import { arbiterBuild } from "./build-identity.js";
import {
  createInstanceDir,
  gitRevOf,
  humanSockPath,
  instanceId,
  promoteInstance,
  foreignHomePromotion,
  resolveOwnerPid,
  runtimeBase,
  sweepDeadInstances,
  writeManifest,
  type InstancePaths,
} from "./instance.js";
import { parseServerArgs, resolveStorePaths } from "./server-args.js";
import { ensurePrivateIfFallback } from "./runtime-base.js";
import { storeLinkProblems, storeLinkRefusal } from "../db/store-links.js";
import { seedStoreFrom } from "../db/store-seed.js";
import { eventRetentionDaysFromEnv } from "../events/event-store.js";
import { setActiveInboundSpec, isInboundSpecId } from "../policy/tool-inbound.js";
import { setActiveOutboundSpec } from "../policy/tool-outbound.js";
import { resolveConfidentialityEnabled } from "../policy/confidentiality-flag.js";
import { assertIntegrityAllowed, resolveIntegrityEnabled } from "../policy/integrity-flag.js";
import { modeOf } from "../policy/protection-mode.js";
import { installAdminLayer, loadPolicyFileStrict, policyWarnings, resolvePolicyFilePath, type StrictPolicyFile } from "../policy/policy-file-validate.js";
import { refreshProgramHashes } from "../policy/program-hashes.js";
import { adminBwrap } from "../src/bwrap-path.js";

// Canonical process title (runtime-instances.md §7): every Mandu daemon names
// itself `mandu-<service>` so ps/top/pgrep/ss -xlp identify it directly,
// instead of the anonymous `node …/tsx server-main.ts` soup that made stale
// daemons a /proc forensics job. This one is exactly 15 chars — the kernel comm
// limit — so even bare `pgrep mandu-arbiter` matches.
process.title = "mandu-arbiter";

// arbiter/ipc → the repo root (for the git rev of the code this daemon loads).
const REPO_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** The prompt filter plugins' bubblewrap: an administrator's trusted
 *  `bwrap_path`, else the distribution's at its fixed path (never a PATH
 *  lookup); none when the administrator's cannot be used. */
function pluginBwrap(): string | null {
  const admin = adminBwrap();
  if (admin.kind === "path") return admin.path;
  if (admin.kind === "refused") return null;
  return ["/usr/bin/bwrap", "/bin/bwrap"].find((p) => existsSync(p)) ?? null;
}

function promoteRequested(): boolean {
  const v = (process.env.MANDU_PROMOTE ?? "").toLowerCase();
  return ["1", "true", "yes", "on"].includes(v);
}

/**
 * Select the inbound trust spec from $MANDU_INBOUND_SPEC (default: claude-code).
 * Used by the AgentDojo eval to load the "agentdojo" / "fail-closed" specs
 * (docs/design/testing/evaluation.md §2.5). An unknown value fails closed to the
 * conservative "fail-closed" spec (every tool UNTRUSTED) rather than silently
 * running the permissive default.
 */
function applyInboundSpecFromEnv(): void {
  const raw = process.env.MANDU_INBOUND_SPEC;
  if (!raw) return;
  // Switch inbound AND outbound together (both are keyed off the same
  // InboundSpecId — see tool-outbound.ts) so trust classification and egress
  // desymbolization stay coherent. Known ids come from the spec registry
  // itself (isInboundSpecId) — no hand-kept twin list to drift.
  if (isInboundSpecId(raw)) {
    setActiveInboundSpec(raw);
    setActiveOutboundSpec(raw);
    console.error(`[arbiter] inbound spec: ${raw}`);
  } else {
    console.error(`[arbiter] unknown MANDU_INBOUND_SPEC="${raw}" — using fail-closed`);
    setActiveInboundSpec("fail-closed");
    setActiveOutboundSpec("fail-closed");
  }
}

async function main(): Promise<void> {
  // The integrity axis is frozen (docs/design/architecture/protection-modes.md §10): refuse an
  // integrity-ON start without the opt-in BEFORE anything is registered.
  assertIntegrityAllowed(resolveIntegrityEnabled());
  applyInboundSpecFromEnv();

  const args = parseServerArgs(process.argv.slice(2));
  const stores = resolveStorePaths(args);
  // Plan 14 §11.2 residual (c): a store inside the home that resolves outside
  // it (a planted symlink or hard link) is behind none of the layers that
  // keep a confined agent out of it, so every original stored from now on
  // would be readable there. Refuse to start (store-links.ts).
  const linkProblems = storeLinkProblems(process.env, process.env.HOME || homedir());
  if (linkProblems.length > 0) throw new Error(storeLinkRefusal(linkProblems, "refusing to start"));
  const explicitSock = args.socketPath ?? process.env.MANDU_ARBITER_SOCK;
  // `mandu why` with no Mandu running (comparisons.md §3.2): its temporary
  // arbiter starts on a copy of what the resident one keeps, read from that
  // store READ-ONLY (db/store-seed.ts). Only a pinned, unpromoted start is
  // seeded; a failed seed refuses the start, and the launcher then asks an
  // unseeded one, as before.
  if (args.seedFrom !== undefined) {
    if (!explicitSock || promoteRequested()) throw new Error("--seed-from seeds only a pinned, unpromoted arbiter (mandu why's temporary one)");
    const seeded = seedStoreFrom({
      from: args.seedFrom, to: stores.symbolDb,
      ...(args.seedPolicy !== undefined ? { policy: { from: args.seedPolicy, to: resolvePolicyFilePath(process.env) } } : {}),
    });
    if (!seeded.ok) throw new Error(`--seed-from: ${seeded.why}`);
    console.error(`[arbiter] store seeded read-only from ${args.seedFrom}: ${Object.entries(seeded.rows).map(([t, n]) => `${t} ${n}`).join(", ")}`);
  }
  const { rev, dirty } = gitRevOf(REPO_DIR);
  // The build this process loaded (build-identity.ts): hashed now, before a
  // rebuild could rename another bundle over this file.
  const build = arbiterBuild(rev);

  // BOTH modes register an instance dir (runtime-instances.md §10): a pinned
  // arbiter binds the caller's path but still writes a manifest, so NO arbiter
  // process is invisible to `mandu status`/`reap` — the 17h-orphan class was
  // exactly pinned ad-hoc spawns nothing could enumerate or safely kill.
  const base = runtimeBase();
  // The shared-/tmp fallback base must be ours alone BEFORE anything under it
  // is read (the sweep) or created (the instance dir): a dir another user made
  // first could hand clients an impostor `current` (runtime-instances.md §3b).
  // Any other base directly in a shared sticky dir ($TMPDIR/mandu-<uid> with TMPDIR=/var/tmp) must be ours
  // and writable by nobody else, for the same reason. Every remaining base
  // ($XDG_RUNTIME_DIR/mandu, the service unit's %t/mandu) is created 0700, not
  // with the umask's mode, and tightened to 0700 when only we could reach it.
  // Throws an actionable refusal → `[arbiter] fatal:` → exit 1.
  ensurePrivateIfFallback(base);
  const swept = sweepDeadInstances(base);
  if (swept.length) console.error(`[arbiter] swept ${swept.length} dead instance(s): ${swept.join(", ")}`);

  const mode: "instance" | "pinned" = explicitSock ? "pinned" : "instance";
  const id = instanceId(new Date(), rev, process.pid);

  // The graceful shutdown is armed BEFORE the instance dir exists: a SIGTERM
  // any time after the dir appears (a spawner stopping a daemon it just saw
  // register, under load) must tidy it, never take the default action and
  // leave the dir for the next start's sweep (runtime-instances.md §10, the
  // instance-mode flake). Arming it right after the mkdir still left a window
  // a descheduled daemon could lose on a loaded CI guest (gl-7602).
  let server: ArbiterServer | null = null;
  let shuttingDown = false;
  let instanceDir: string | null = null;
  const shutdown = async (sig: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.error(`[arbiter] received ${sig}, shutting down`);
    if (server) await server.close();
    // Tidy OUR instance dir on graceful exit; a dangling `current` simply stops
    // resolving (clients fall back / the next promotion repoints it). Crashed
    // instances are reaped by the next start's sweep instead.
    if (instanceDir) try { rmSync(instanceDir, { recursive: true, force: true }); } catch { /* best-effort */ }
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  // A daemon a test started dies with that test's process (test-owner.ts,
  // runtime-instances.md §8a); no production start has an owner here.
  const testOwner = armTestOwnerWatch((owner) => void shutdown(`test owner pid ${owner} gone`));
  if (testOwner) console.error(`[arbiter] test owner pid ${testOwner.owner}: this instance exits when that process does`);

  const paths = createInstanceDir(base, id);
  instanceDir = paths.dir;
  const instance: { id: string; paths: InstancePaths; base: string } = { id, paths, base };

  // Pinned: the caller owns the socket path; the instance dir is registry-only.
  const socketPath: string = explicitSock || paths.sockPath;
  // The human plane is never caller-pinned: it lives under the runtime base's
  // private `human/` dir in both modes, so no MANDU_ARBITER_SOCK a test or an
  // agent chose can move it next to the data socket.
  const humanSocketPath = humanSockPath(base, id);

  // Event store: the on-disk default unless the spawner passed --event-dir.
  const eventDir = stores.eventDir;
  const retentionDays = eventRetentionDaysFromEnv();
  console.error(
    `[arbiter] event store: ${eventDir} (retention: ${retentionDays > 0 ? `${retentionDays}d` : "off"})`,
  );
  console.error(`[arbiter] symbol DB: ${stores.symbolDb}`);

  // Admin channel (policy-surface.md §2.6): the supervisor that spawned
  // us passes one end of a socketpair as an inherited fd and names it here.
  // Human-decision ops (approvals, labels, posture, session deletion) are
  // accepted only on that channel. MANDU_ADMIN_SOCK is the dev/test-only
  // path variant (loud warning at start; never for a stack an agent runs on).
  const adminFdRaw = process.env.MANDU_ADMIN_FD;
  let adminFd: number | undefined;
  if (adminFdRaw !== undefined && adminFdRaw !== "") {
    adminFd = Number.parseInt(adminFdRaw, 10);
    if (!Number.isInteger(adminFd) || adminFd < 3) {
      throw new Error(`MANDU_ADMIN_FD must be an inherited fd number ≥ 3 (got ${JSON.stringify(adminFdRaw)})`);
    }
  }
  const adminSocketPath = process.env.MANDU_ADMIN_SOCK || undefined;

  // The data-law document (policy-surface.md §2.1, stage 2):
  // MANDU_POLICY_FILE, else <home>/policy.yaml. A MISSING file means
  // the built-ins are the whole law (the law source says so, naming the path
  // it looked for). A PRESENT file must validate, or the daemon refuses to
  // start with every problem listed — never "warn and run the built-ins",
  // because a user file may tighten the law and a typo must not silently
  // loosen it. Always passed to the server so `lawSource` is truthful.
  const policyPath = resolvePolicyFilePath(process.env);
  let policyStatus: StrictPolicyFile;
  try {
    // Plan 12 D5: the administrator's layer first, so the user's file is
    // judged against its lock (a layer that cannot be used refuses the start).
    const admin = installAdminLayer();
    if (admin.files.length > 0) {
      console.error(`[arbiter] administrator's policy: ${admin.files.join(", ")}${admin.locked ? " (models locked)" : ""}`);
    }
    policyStatus = loadPolicyFileStrict(policyPath);
  } catch (err) {
    // A refused start must not leave a half-created instance dir behind.
    try { rmSync(instance.paths.dir, { recursive: true, force: true }); } catch { /* best-effort */ }
    throw err;
  }
  if (policyStatus.found) {
    const c = policyStatus.config ?? {};
    const inbound = c.inbound ?? {};
    console.error(
      `[arbiter] policy file: ${policyPath} (url:${inbound.url || inbound["url-trust"] ? "set" : "-"} ` +
        `channel:${inbound.channel || inbound["channel-trust"] ? "set" : "-"} dir:${inbound.dir || inbound["dir-trust"] ? "set" : "-"} ` +
        `commands:${inbound.command?.length ?? 0} tools:${Object.keys(c.tools ?? {}).length})`,
    );
    // Plan 13 D8: a valid law can still name a reader that runs any code,
    // or a printer (a copy of either by its hash: the host's are hashed first).
    refreshProgramHashes({ minIntervalMs: 0 });
    for (const w of policyWarnings(c)) console.error(`[arbiter] policy warning: ${w}`);
  } else {
    console.error(`[arbiter] policy file: none at ${policyPath} — the built-in policy is the whole law`);
  }

  const prepOff = preparedCopiesOff(process.env);
  server = new ArbiterServer({
    socketPath,
    identity: { instanceId: instance.id, gitRev: rev, gitDirty: dirty, build },
    dbPath: stores.symbolDb,
    eventDir,
    eventRetentionMs: retentionDays * 86_400_000,
    adminFd,
    adminSocketPath,
    humanSocketPath,
    policyPath,
    warmDiscoveryWorker: true,
    // Plan 14 §14.3: the policy classifier for a names-only model run, from
    // the flags only Mandu's own spawners pass (server-args.ts).
    policyClassifier: args.classifier ? { argv: args.classifier, landlockApply: args.landlockApply ?? null } : null,
    // Plan 15 §4.3: the prompt filter plugins' confinement: the address guard
    // (required), the Landlock applier and the system's bubblewrap (each
    // probe-gated, plugin-probe.ts). The bubblewrap is the distribution's at
    // its fixed path, never a PATH lookup, or an administrator's `bwrap_path`
    // (src/bwrap-path.ts); one set but unusable means none.
    promptPlugins: {
      netGuard: args.netGuard ?? null,
      landlockApply: args.landlockApply ?? null,
      bwrap: pluginBwrap(),
    },
    // Plan 14 §11.1: the known-repository registry is filled by a HOME walk
    // and every lock resolved to blob ids in the background.
    // MANDU_LOCK_RESOLUTION=on-demand keeps only the on-demand part (the
    // roots a launch or a registration names).
    lockResolution: process.env.MANDU_LOCK_RESOLUTION === "on-demand" ? {} : { schedule: DAEMON_SCHEDULE },
    // Plan 14 §11.1 R3: every known repository holding a locked object gets
    // sanitized copies prepared after each resolution cycle, into the
    // launcher's object-twin cache, sealed in the current epoch. Caps:
    // MANDU_GIT_PREP_CYCLE_MB (default MANDU_GIT_TWIN_MAX_MB, else 1024; 0
    // builds nothing) and MANDU_GIT_PREP_TOTAL_MB (default 4096). Off with
    // MANDU_GIT_PREPARE=0, and off on every host but Linux, the only one
    // whose launch uses a copy (preparedCopiesOff says why).
    preparedCopies: prepOff !== null
      ? null
      : { cacheDir: manduPath("object-twins", process.env, process.env.HOME || homedir()), limits: prepLimitsFromEnv(process.env) },
  });
  // Said only where the copies could have run: with the confidentiality
  // axis OFF there is no resolver, so nothing to prepare on any host.
  if (prepOff !== null && resolveConfidentialityEnabled()) {
    console.error(`[arbiter] git copies prepared ahead of time (plan 14 §11.1 R3): off: ${prepOff}`);
  }
  // One line per run so every session transcript records which mode ran
  // (confidentiality.md §11: the switch is a deliberate, visible state).
  console.error(
    `[arbiter] confidentiality axis: ${resolveConfidentialityEnabled() ? "ON" : "OFF"}`,
  );
  // The named mode over the two axes (docs/design/architecture/protection-modes.md).
  {
    const axes = { integrity: resolveIntegrityEnabled(), confidentiality: resolveConfidentialityEnabled() };
    console.error(
      `[arbiter] protection mode: ${modeOf(axes)} (integrity ${axes.integrity ? "ON" : "OFF"}, ` +
        `confidentiality ${axes.confidentiality ? "ON" : "OFF"})`,
    );
  }
  // Tenant (policy-surface.md §2.7): explicit → refuses the other
  // tenant's events and stamps its own; unset → untenanted (legacy).
  console.error(
    `[arbiter] tenant: ${server.tenant ?? "untenanted (MANDU_TENANT unset — accepts sessions of any tenant, stamps none)"}`,
  );
  try {
    await server.listen();
  } catch (e) {
    if (shuttingDown) return; // a signal closed the server mid-listen; shutdown owns the exit
    // A refused start (live-socket theft, symbol DB owned by a live writer)
    // must not leave a half-created instance dir for the sweeper to age out.
    try { rmSync(instance.paths.dir, { recursive: true, force: true }); } catch { /* best-effort */ }
    throw e;
  }
  if (shuttingDown) return;

  writeManifest(instance.paths, {
    instanceId: instance.id,
    role: "arbiter",
    pid: process.pid,
    startedAt: new Date().toISOString(),
    gitRev: rev,
    gitDirty: dirty,
    sockPath: socketPath,
    humanSockPath: humanSocketPath,
    eventDir: server.eventDirectory,
    symbolDb: stores.symbolDb,
    mode,
    ownerPid: resolveOwnerPid(),
  });
  if (mode === "pinned") {
    // Promotion is meaningless for a caller-owned path (current/<sock> would
    // not resolve inside this registry-only dir) — never repoint the rendezvous.
    console.error(
      `[arbiter] pinned socket ${socketPath} — registered as instance ${instance.id} (registry-only)`,
    );
  } else if (promoteRequested() && foreignHomePromotion(instance.base) !== null) {
    // runtime-instances.md §13: a scratch-HOME arbiter never becomes the
    // account's rendezvous. It keeps serving its own instance socket (a caller
    // that knows the path can use it); `current` is left alone.
    console.error(
      `[arbiter] instance ${instance.id} NOT promoted: ${foreignHomePromotion(instance.base)}. ` +
        "Start the stack from this account's real HOME, or give this run its own MANDU_RUNTIME_DIR.",
    );
  } else if (promoteRequested()) {
    promoteInstance(instance.base, instance.id);
    console.error(`[arbiter] instance ${instance.id} PROMOTED → ${join(instance.base, "current")}`);
  } else {
    console.error(
      `[arbiter] instance ${instance.id} (un-promoted — clients keep resolving the previous ` +
        `'current'; set MANDU_PROMOTE=1 to make this the deployment rendezvous)`,
    );
  }

  // Lifeline (lifeline.ts): a spawner that passed MANDU_LIFELINE=stdin owns
  // this daemon's lifetime — stdin EOF means it died (even by SIGKILL), so run
  // the same graceful shutdown as SIGTERM. NOT set by the launcher's arbiter
  // autostart (the shared stack outlives launches); test harnesses set it.
  if (armLifeline(() => void shutdown("lifeline EOF (spawner gone)"))) {
    console.error("[arbiter] lifeline armed — this instance exits when its spawner dies");
  }
}

main().catch((err) => {
  console.error(`[arbiter] fatal: ${(err as Error).message}`);
  process.exit(1);
});
