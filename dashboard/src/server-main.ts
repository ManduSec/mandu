#!/usr/bin/env npx tsx
/**
 * server-main — CLI entry for the Mandu dashboard server.
 *
 * Mandu-new (NO reference origin); the arg/env wiring style mirrors
 * arbiter/ipc/server-main.ts. Selects the EventSource:
 *   - MANDU_ARBITER_SOCK (or legacy MANDU_ARBITER_SOCKET) set →
 *       ArbiterEventSource — live sessions/events/subscribe over the arbiter
 *       Unix socket. This is the production path.
 *   - else → FileEventSource over MANDU_EVENTS_DIR (default ./fixtures), the
 *       local + demo / test fallback.
 *
 * Env:
 *   DASHBOARD_PORT        Port to listen on (default 4500; 0 = kernel-assigned,
 *                         published via MANDU_PORT_FILE).
 *   MANDU_PORT_FILE     When set, the BOUND port is published here via atomic
 *                         tmp+rename (runtime-instances.md §8 — the same
 *                         rendezvous the proxies use, so concurrent stacks
 *                         need no fixed ports).
 *   DASHBOARD_HOST        Bind address (default 127.0.0.1). A non-loopback bind
 *                         (0.0.0.0, for a reverse proxy on another host) needs
 *                         an authenticator or it is refused; the server's
 *                         source-IP gate stays fail-closed: only loopback and
 *                         DASHBOARD_ALLOW_HOSTS peers get anything but 403.
 *   DASHBOARD_ALLOW_HOSTS Comma-separated hostnames/IPs additionally allowed to
 *                         connect, ON TOP of loopback (always). Empty by
 *                         default. Hostnames resolve ONCE at startup (a DNS
 *                         change needs a restart); an unresolvable name grants
 *                         nothing.
 *                         Each entry is also a Host name the dashboard
 *                         answers to (the Host check, dashboard.md §6).
 *   DASHBOARD_SERVER_NAMES Comma-separated Host names (optionally name:port)
 *                         the dashboard answers to besides loopback at its
 *                         port: the name a reverse proxy or tunnel forwards
 *                         (e.g. dash.example.org). Every other Host is 421
 *                         (DNS rebinding, dashboard.md §6).
 *   DASHBOARD_PASSWORD    No longer used (2026-10-22): the dashboard signs in
 *                         with its account; a value set is ignored, with a
 *                         NOTICE.
 *   DASHBOARD_BASIC_AUTH  "user:password" — moved, once, into the Mandu
 *                         dashboard account (state/dashboard-account.json,
 *                         a scrypt hash; `mandu dashboard --set-password`
 *                         sets it directly), whose sign-in page and Basic
 *                         header guard every request (dashboard.md §6.z).
 *                         Ignored once an account exists.
 *   DASHBOARD_BASE_PATH   Reverse-proxy URL prefix (default "", none). Set it
 *                         to the proxy's mount (e.g. /mandu) when the
 *                         dashboard is served under a sub-path; it must match
 *                         the mount exactly. Unprefixed URLs keep working.
 *   MANDU_SLIDES_DIR    Directory of HTML slide decks served at /slides/<file>
 *                         for the inspector's Settings links (unset = no decks:
 *                         the route 404s and the links are hidden).
 *   MANDU_EVENTS_DIR    NDJSON event-log dir (default ./fixtures for demo).
 *   MANDU_HOME          The one Mandu home (default ~/.mandu). Every store the
 *                         dashboard reads or its supervised arbiters write is a
 *                         path-table entry under it (on-disk-layout.md §5):
 *                         the live event dir and DB, the test tenant's
 *                         (state/mandu-test.db, events/test), runs/ci (the CI
 *                         tab), runs/matrix, runs/drills/live, runs/test-runs.json.
 *   MANDU_ARBITER_SOCK   Arbiter socket → use ArbiterEventSource (the arbiter
 *                         daemon's socket; same var name as arbiter/ipc/server-main).
 */

import { publishPortFile } from "./port-file.js";
import { join, basename } from "node:path";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { randomBytes } from "node:crypto";

import { DashboardServer, isCheckoutBuildDir, resolveStaticDir } from "./server.js";
import { loadExtensions } from "./extension-loader.js";
import { makeApprovalsArbiter, type AdminTarget } from "./arbiter-adapter.js";
import { FileEventSource, ArbiterEventSource, type EventSource } from "./event-source.js";
import { adminUnavailableError } from "./server/http-util.js";
import { DashboardSelf, gitShortRev } from "./self-status.js";
import { registerDashboard, resolveOwnerPid, rewriteDashboardEntry, sweepDeadDashboards, unregisterDashboard } from "./registry.js";
import { Supervisor } from "./supervisor/supervisor.js";
import { armTestOwnerWatch } from "./test-owner.js";
import { startTimeoutFromEnv, testTenantPaths } from "./supervisor/supervisor-defs.js";
import { ensurePrivateIfFallback, resolveRuntimeBase } from "./runtime-base.js";
import { serveSignInChannel, signInDepsFor, signInSockPath, sweepDeadSignInSocks } from "./sign-in.js";
import { manduNotRunning } from "./mandu-running.js";
import { defaultEventDir } from "./event-dir.js";
import { AccountFile, makeAccount, readAccount, writeAccount } from "./account.js";
import { manduPath } from "./generated/mandu-paths.js";
import { homeOf } from "./data-locations.js";

/** How often a dashboard started with no arbiter looks for one (below). */
const ARBITER_JOIN_POLL_MS = 2_000;

function pidAliveHere(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

// Canonical process title (runtime-instances.md §7): ps/pgrep-visible identity.
process.title = "mandu-dashboard";
const PORT = Number(process.env.DASHBOARD_PORT ?? "4500");
// LOOPBACK by default (2026-09-25, dashboard.md §6): the
// dashboard reveals symbol→original, so the shipped default is the one that
// exposes nothing to the network. Every entry point agrees — this server, the
// launcher's stack autostart (arbiter.ts passes no host, so it inherits this
// default) and `mandu dashboard` (subcommands.ts, which pins 127.0.0.1).
// A remote deployment is EXPLICIT: DASHBOARD_HOST=0.0.0.0 plus an allowlist
// (DASHBOARD_ALLOW_HOSTS) plus the dashboard account (`mandu dashboard
// --set-password`, or a DASHBOARD_BASIC_AUTH it is made from) — a wide bind
// without one is refused below.
const HOST = process.env.DASHBOARD_HOST ?? "127.0.0.1";
// No baked-in remote peers: the shipped default allowlist is EMPTY. Loopback
// is always allowed by the server's gate; every other source IP is answered
// 403 (fail-closed) unless DASHBOARD_ALLOW_HOSTS names it. (Until 2026-09-25
// a development deployment's reverse proxy was admitted by default; a
// deployment's peer has no place in a product default, so it names its peer
// in its own env file instead.)
const DEFAULT_ALLOW_IPS: string[] = [];
const ALLOW_HOSTS = (process.env.DASHBOARD_ALLOW_HOSTS ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
// The Host names this dashboard answers to besides loopback at its port
// (server/read-gate.ts hostAllowed): the operator's allow-hosts and the
// names a front forwards.
const SERVER_NAMES = [
  ...ALLOW_HOSTS,
  ...(process.env.DASHBOARD_SERVER_NAMES ?? "").split(",").map((s) => s.trim()).filter(Boolean),
];
// DASHBOARD_PASSWORD is gone (2026-10-22, dashboard.md §6.z): one account
// for every dashboard. A value still set is ignored, said once below.
const PASSWORD_SET = (process.env.DASHBOARD_PASSWORD ?? "") !== "";
// DASHBOARD_BASIC_AUTH="user:password" (the first ':' splits — a password may
// contain ':'). Malformed (no ':' or empty user) is a startup error, not a
// silent no-auth: exposing originals by typo is the failure to rule out.
const BASIC_AUTH = parseBasicAuth(process.env.DASHBOARD_BASIC_AUTH);
function parseBasicAuth(raw: string | undefined): { user: string; password: string } | undefined {
  if (raw === undefined || raw === "") return undefined;
  const i = raw.indexOf(":");
  if (i <= 0) {
    console.error('[dashboard] DASHBOARD_BASIC_AUTH must be "user:password" (non-empty user)');
    process.exit(2);
  }
  return { user: raw.slice(0, i), password: raw.slice(i + 1) };
}
// The admin token: a TEST SEAM since the account (dashboard.md §6.z). A
// random per-boot token nobody is told, unless DASHBOARD_ADMIN_TOKEN pins it
// (the suites do): then its `/login?token=` and its cookie pass the sign-in
// gate. Readable via /proc environ by any same-uid process, so a deployment
// never sets it (the log says so when it is set).
// DASHBOARD_TRUST_FRONT=1 lets allowlisted NON-loopback clients (an
// authenticating reverse proxy) act as the admin once past the sign-in.
const PINNED_ADMIN_TOKEN = (process.env.DASHBOARD_ADMIN_TOKEN ?? "") !== "";
const ADMIN_TOKEN = process.env.DASHBOARD_ADMIN_TOKEN || randomBytes(16).toString("hex");
const TRUST_FRONT = process.env.DASHBOARD_TRUST_FRONT === "1";
// Base path: none by default (2026-09-26; until then it defaulted to the
// /mandu mount of a development deployment, which now sets it in its env
// file). Behind a proxy that mounts the dashboard under a prefix, set
// DASHBOARD_BASE_PATH to that prefix: the injected <meta name="base-path">
// makes the client fetch <prefix>/api/..., and it MUST match the proxy mount
// exactly (a /mandu vs /mandu mismatch loads the shell but leaves the
// data lanes empty). handle() only STRIPS the prefix when present, so
// unprefixed URLs route as-is.
const BASE_PATH = process.env.DASHBOARD_BASE_PATH ?? "";

function isLoopbackHost(host: string): boolean {
  return host === "localhost" || host === "::1" || host.startsWith("127.");
}

/**
 * Resolve DASHBOARD_ALLOW_HOSTS entries (hostnames or IP literals) into the IP
 * allowlist the server enforces per request (server.ts clientAllowed). Names
 * resolve ONCE at startup so the admitted set is deterministic; a name that
 * fails to resolve is logged and skipped — fail-closed, it grants nothing.
 */
async function resolveAllowHosts(hosts: string[]): Promise<string[]> {
  const ips: string[] = [];
  for (const host of hosts) {
    if (isIP(host)) {
      ips.push(host);
      continue;
    }
    try {
      const addrs = await lookup(host, { all: true });
      ips.push(...addrs.map((a) => a.address));
      console.error(`[dashboard] allow-host ${host} → ${addrs.map((a) => a.address).join(", ")}`);
    } catch (err) {
      console.error(
        `[dashboard] WARNING: allow-host '${host}' did not resolve (${(err as Error).message}) — it stays blocked`,
      );
    }
  }
  return ips;
}

// dashboard/src → up two levels to the repo root (the dir holding launcher/ +
// arbiter/). server-main runs as <repoRoot>/dashboard/src/server-main.ts in a
// checkout. INSTALLED (packaging.md §5): the launcher spawns the esbuild bundle
// `<pkgRoot>/dist/dashboard.mjs`, where there is no checkout at all — the
// services are the sibling bundles and the launcher is `bin/mandu.mjs`
// (os-test-matrix.md §10.11 finding 2: the checkout cwds made every
// service spawn fail with ENOENT from an npm install).
// A CHECKOUT'S BUILD (packaging.md §5.1): `<repo>/launcher/dist/dashboard.mjs`,
// a `dist/` beside `src/run.ts` (the launcher's isCheckoutBuild), which a
// bundled launch of a checkout starts. That is the dev layout, run from the
// build: the repo root is two levels up as from source, and the supervisor
// keeps its checkout definitions (each service from that build while it is
// fresh, else from source).
const SELF_DIR = fileURLToPath(new URL(".", import.meta.url)).replace(/\/$/, "");
const CHECKOUT_BUILD = isCheckoutBuildDir(SELF_DIR);
const INSTALLED = basename(SELF_DIR) === "dist" && !CHECKOUT_BUILD;
const PKG_ROOT = join(SELF_DIR, "..");
const REPO_ROOT = INSTALLED ? PKG_ROOT : join(SELF_DIR, "..", "..");
const LAYOUT = INSTALLED ? ({ mode: "installed", pkgRoot: PKG_ROOT } as const) : undefined;
if (INSTALLED) console.error(`[dashboard] layout: installed (bundles under ${PKG_ROOT}/dist)`);
if (CHECKOUT_BUILD) console.error(`[dashboard] layout: a checkout's build (${SELF_DIR}); the checkout is ${REPO_ROOT}`);

// Arbiter socket the control plane will manage and the dashboard's own event
// source attaches to (runtime-instances.md; mirrors arbiter/ipc/instance.ts
// resolveArbiterSock — duplicated here so this package stays standalone):
//   - explicit $MANDU_ARBITER_SOCK → verbatim; the supervisor pins the spawned
//     arbiter to that exact path (legacy / test deployments).
//   - default → the `${runtimeBase}/current/arbiter.sock` RENDEZVOUS: the
//     supervisor spawns the arbiter in INSTANCE MODE (it binds its own
//     instances/<id>/arbiter.sock and atomically promotes itself to `current`),
//     so this spelling resolves through the promotion symlink and a stale
//     legacy daemon at the old fixed path can never be silently adopted.
// The base is the path table's `runtime-dir` (on-disk-layout.md §5) under
// the one rule (runtime-base.ts, runtime-instances.md §3b): MANDU_RUNTIME_DIR,
// else XDG_RUNTIME_DIR/mandu, else TMPDIR/mandu when an instance socket fits,
// else the private /tmp/mandu-<uid> — checked in main() before anything under
// it is trusted or created.
const RUNTIME_BASE = resolveRuntimeBase(process.env).base;
const EXPLICIT_SOCK = process.env.MANDU_ARBITER_SOCK;
const ARBITER_SOCK = EXPLICIT_SOCK ?? join(RUNTIME_BASE, "current", "arbiter.sock");
// Point the dashboard's own EventSource at the arbiter the supervisor manages, so
// the live trace populates once that arbiter is started. (Set before
// makeSource() reads MANDU_ARBITER_SOCK below.)
if (!process.env.MANDU_ARBITER_SOCK) process.env.MANDU_ARBITER_SOCK = ARBITER_SOCK;

function makeSource(): EventSource {
  // Arbiter mode: live stream from the arbiter daemon. MANDU_ARBITER_SOCK matches
  // arbiter/ipc/server-main.ts; MANDU_ARBITER_SOCKET is accepted as a legacy alias.
  const arbiterSocket = process.env.MANDU_ARBITER_SOCK ?? process.env.MANDU_ARBITER_SOCKET;
  if (arbiterSocket) {
    console.error(`[dashboard] source: arbiter @ ${arbiterSocket}`);
    // The human plane (arbiter-human-plane.md): sessions/events/reveals ride
    // the human socket — explicit from $MANDU_ARBITER_HUMAN_SOCK, else
    // discovered per instance from the arbiter's `hello`.
    const humanSocketPath = process.env.MANDU_ARBITER_HUMAN_SOCK || undefined;
    return new ArbiterEventSource({ socketPath: arbiterSocket, ...(humanSocketPath ? { humanSocketPath } : {}) });
  }
  const dir =
    process.env.MANDU_EVENTS_DIR ??
    join(fileURLToPath(new URL(".", import.meta.url)), "..", "fixtures");
  console.error(`[dashboard] source: file @ ${dir}`);
  return new FileEventSource(dir);
}


async function main(): Promise<void> {
  // A dashboard a test started dies with that test's process (test-owner.ts,
  // runtime-instances.md §8a). Read first, while the chain of parents that
  // names the test is still there; the owner it finds is written back into
  // this env, so the arbiter this dashboard starts dies with the test too.
  // Until `bye` exists below there is nothing of ours to stop.
  let onTestOwnerGone = (_owner: number): void => { process.exit(0); };
  const testOwner = armTestOwnerWatch((owner) => onTestOwnerGone(owner));
  if (testOwner) console.error(`[dashboard] test owner pid ${testOwner.owner}: this dashboard exits when that process does`);
  // The shared-/tmp fallback base must be a private 0700 dir of this uid
  // BEFORE the event source dials `current/arbiter.sock` under it, the
  // registry writes there or the supervisor starts an arbiter in it: a dir
  // another user made first could hold an impostor arbiter
  // (runtime-instances.md §3b). Any other base directly in a shared sticky
  // dir ($TMPDIR/mandu-<uid> with TMPDIR=/var/tmp) must be ours and writable by nobody else. Created when
  // absent; refused otherwise. Every remaining base (the service unit's %t/mandu)
  // is created 0700, and tightened to 0700 when only we could reach it.
  try {
    ensurePrivateIfFallback(RUNTIME_BASE);
  } catch (err) {
    console.error(`[dashboard] fatal: ${(err as Error).message}`);
    process.exit(1);
  }
  // makeSource() reads MANDU_ARBITER_SOCK (set above) — keep it before this.
  const source = makeSource();

  // Control plane: enabled unless DASHBOARD_CONTROL=0. It lets the privileged
  // HumanView (the dashboard) start/stop the arbiter + Track-A proxies and launch
  // monitored agent runs. Every store path comes from the path table under
  // MANDU_HOME: the supervised live arbiter gets no store flags (its defaults
  // are the table's), and runs join it over its socket.
  // The TEST tenant's paths (policy-surface.md §2.7 1b): the same
  // function the supervisor uses for its `test-arbiter` service, so the
  // test-runner, the test event source and the service agree.
  const TEST_PATHS = testTenantPaths({
    arbiterSock: ARBITER_SOCK,
    arbiterInstanceBase: EXPLICIT_SOCK ? undefined : RUNTIME_BASE,
  });
  let supervisor: Supervisor | undefined;
  // What a supervised service's crash does; set by the autostart below.
  let onServiceCrash = (_id: string, _reason: string): void => {};
  if (process.env.DASHBOARD_CONTROL !== "0") {
    // Optional offline web mock: if MANDU_NET_PROXY_MOCK_SITES is set, the
    // supervised net-proxy serves canned responses for the configured URLs so a
    // real-agent run/demo is deterministic + offline.
    const mockSitesPath = process.env.MANDU_NET_PROXY_MOCK_SITES || undefined;
    const startTimeoutMs = startTimeoutFromEnv(process.env);
    supervisor = new Supervisor({
      ...(startTimeoutMs !== undefined ? { startTimeoutMs } : {}),
      repoRoot: REPO_ROOT,
      ...(LAYOUT ? { layout: LAYOUT } : {}),
      arbiterSock: ARBITER_SOCK,
      // Instance mode only for the DEFAULT rendezvous; an explicit socket stays
      // pinned exactly where the caller said.
      arbiterInstanceBase: EXPLICIT_SOCK ? undefined : RUNTIME_BASE,
      mockSitesPath,
      onCrash: (id, reason) => onServiceCrash(id, reason),
    });
    console.error("[dashboard] control plane enabled");
  } else {
    console.error("[dashboard] control plane disabled (DASHBOARD_CONTROL=0)");
  }

  // Egress-approval queue: connect a arbiter client when a socket is configured
  // (the dashboard already resolves ARBITER_SOCK above and points its EventSource
  // at it). When the arbiter is unreachable this is undefined → the routes answer
  // 404 "arbiter not connected" — and on a SUPERVISED cold boot that is the
  // NORMAL state (the supervisor's own arbiter cannot exist before autostart),
  // so the autostart success handler below retries and late-binds the surfaces
  // (server.attachArbiterSurfaces). `let`, not const, for exactly that.
  // The admin channel: our supervisor's parent end of the arbiter's socketpair
  // (only when WE spawned it), else the dev-only MANDU_ADMIN_SOCK path, else
  // none (adopted arbiter → human-decision writes answer 503 with the remedy).
  const adminTarget = (): AdminTarget | undefined => {
    const socket = supervisor?.adminChannel("arbiter");
    if (socket) return { socket };
    const devPath = process.env.MANDU_ADMIN_SOCK;
    if (devPath) return { socketPath: devPath };
    return undefined;
  };
  let approvals = await makeApprovalsArbiter(ARBITER_SOCK, adminTarget);
  // Session deletion is admin-only too: the event source dials the data socket,
  // so it delegates the act to the (late-bound) admin surface.
  if (source instanceof ArbiterEventSource) {
    source.setAdminDeleter(async (sessionId) => {
      if (!approvals) throw adminUnavailableError("arbiter not connected");
      await approvals.deleteSession(sessionId);
    });
  }

  // The TEST tenant (§2.7 1c): a second event source + surfaces over the
  // test-arbiter, only when the control plane runs it (no supervisor → no test
  // arbiter → the dashboard advertises the live tenant alone). Same lazy admin
  // resolution, same late-bind after autostart.
  const testAdminTarget = (): AdminTarget | undefined => {
    const socket = supervisor?.adminChannel("test-arbiter");
    return socket ? { socket } : undefined;
  };
  const testSource = supervisor ? new ArbiterEventSource({ socketPath: TEST_PATHS.sock }) : undefined;
  let testApprovals = supervisor ? await makeApprovalsArbiter(TEST_PATHS.sock, testAdminTarget) : undefined;
  testSource?.setAdminDeleter(async (sessionId) => {
    if (!testApprovals) throw adminUnavailableError("test-tenant arbiter not connected");
    await testApprovals.deleteSession(sessionId);
  });

  // Self control (self-status.ts): the dashboard's own identity/staleness for
  // the control panel, plus the restart trigger behind
  // POST /api/control/dashboard/restart.
  const dashboardDir = join(REPO_ROOT, "dashboard");
  const self = new DashboardSelf({ repoRoot: REPO_ROOT, packageDir: dashboardDir });
  // This dashboard's runtime-registry entry (registry.ts) — written after
  // listen() (the manifest carries the BOUND port), removed on every deliberate
  // exit path below. A SIGKILL leaves it for the next boot's sweep / reap.
  let registryEntry: string | null = null;
  // The sign-in socket (bound after listen, below); closed on every
  // deliberate exit, like the registry entry.
  let signIn: { path: string; close: () => Promise<void> } | null = null;
  let restarting = false; // a second POST while we're already dying must not spawn a second successor
  const selfControl = {
    status: () => self.status(),
    restart: (): void => {
      if (restarting) return;
      restarting = true;
      console.error(
        "[dashboard] self-restart: reaping spawned services, spawning a successor, exiting " +
          "(the successor's autostart respawns them; externally-started adopted instances stay up)",
      );
      void (async () => {
        // Reap the services THIS process spawned before exiting. Their
        // stdout/stderr are pipes into THIS process (supervisor launch()), so
        // leaving them running hands the successor a stack that dies with
        // EPIPE on its next log line. shutdownAll() by design skips ADOPTED
        // instances (no child pid) — anything started outside this dashboard
        // survives and is re-adopted by the successor.
        try {
          await supervisor?.shutdownAll();
        } catch (err) {
          console.error(`[dashboard] self-restart: shutdown error (continuing): ${(err as Error).message}`);
        }
        // The successor sleeps past our exit so the port is free when it binds.
        // stdio "inherit" hands it the SAME stdout/stderr this process was
        // launched with (the daemon log file, or the user's terminal).
        //
        // Env: do NOT leak the MANDU_ARBITER_SOCK this process DERIVED and
        // self-assigned (the rendezvous default, set above for our EventSource
        // and children). The successor would read it as an EXPLICIT socket and
        // pin its supervisor to legacy mode — its spawned arbiter then tries to
        // mkdir the `current` promotion symlink and dies. Only pass it through
        // when the operator explicitly set it for THIS process.
        const successorEnv = { ...process.env };
        if (!EXPLICIT_SOCK) delete successorEnv.MANDU_ARBITER_SOCK;
        // Deliberate exit → drop our registry entry; the successor writes its own.
        // (An EXPLICIT MANDU_OWNER_PID rides successorEnv unchanged, so a
        // chain of self-restarts keeps the original owner.)
        if (registryEntry) unregisterDashboard(registryEntry);
        await signIn?.close();
        spawn("sh", ["-c", "sleep 0.6; exec npm run --silent serve"], {
          cwd: dashboardDir,
          detached: true,
          stdio: "inherit",
          env: successorEnv,
        }).unref();
        // Exit WITHOUT server.close(): it would re-run shutdownAll and then
        // wait on open SSE responses (they only drain when the browser
        // leaves). The 250ms grace lets the 202 response and log line flush.
        setTimeout(() => process.exit(0), 250);
      })();
    },
  };

  const allowedClientIps = [
    ...new Set([...DEFAULT_ALLOW_IPS, ...(await resolveAllowHosts(ALLOW_HOSTS))]),
  ];
  // The Mandu dashboard account (account.ts, dashboard.md §6.z): one
  // username and password for every page, set by `mandu dashboard
  // --set-password`. A DASHBOARD_BASIC_AUTH pair with no account yet becomes
  // the account, once: hashed into the file (the pair is never printed), so
  // the env entry can go. A home that cannot hold the file (a test's
  // /dev/null home) keeps the pair in memory, as before.
  const accountPath = manduPath("dashboard-account", process.env, homeOf(process.env));
  let basicAuthInMemory = BASIC_AUTH;
  let atStart = readAccount(accountPath);
  if (BASIC_AUTH && atStart.kind === "none") {
    try {
      writeAccount(accountPath, await makeAccount(BASIC_AUTH.user, BASIC_AUTH.password, new Date(), { minPassword: false }));
      basicAuthInMemory = undefined;
      atStart = readAccount(accountPath);
      console.error(
        `[dashboard] DASHBOARD_BASIC_AUTH moved into the dashboard account (${accountPath}, a password hash only); ` +
          `sign in with the same username and password. You can now remove DASHBOARD_BASIC_AUTH from where it is set (such as ~/.mandu/dashboard.env).`,
      );
    } catch (err) {
      console.error(`[dashboard] could not write the dashboard account (${(err as Error).message}); DASHBOARD_BASIC_AUTH stays in use from the environment`);
    }
  } else if (BASIC_AUTH) {
    basicAuthInMemory = undefined;
    console.error("[dashboard] DASHBOARD_BASIC_AUTH is ignored: the dashboard account is set (`mandu dashboard --set-password` changes it); you can remove the entry");
  }
  if (atStart.kind === "unsafe") {
    console.error(`[dashboard] NOTICE: the dashboard account cannot be used: ${atStart.why}. Nobody can sign in until \`mandu dashboard --set-password\` writes it again.`);
  }
  const accountSet = atStart.kind !== "none";
  // Made after the migration, so the file as it now stands is the baseline
  // (the server's first read), and only a later change is reported.
  // A change also rewrites the registry entry's `signInMode` (below), so
  // the launcher and `mandu scan` say what the dashboard does now.
  let onAccountChange: () => void = () => {};
  const account = new AccountFile(accountPath, {
    onChange: (what) => {
      console.error(`[dashboard] NOTICE: the dashboard account file ${accountPath} changed (${what}); every sign-in session ended. If you did not run \`mandu dashboard --set-password\`, run it now.`);
      onAccountChange();
    },
  });

  if (PASSWORD_SET) {
    console.error("[dashboard] NOTICE: DASHBOARD_PASSWORD is no longer used and is ignored: the dashboard signs in with its account (`mandu dashboard --set-password`); you can remove the entry");
  }
  if (!accountSet && !basicAuthInMemory) {
    console.error("[dashboard] NOTICE: no dashboard account yet, so the dashboard serves nothing but a page that says to run `mandu dashboard --set-password`");
  }

  // A non-loopback bind without an account is a startup REFUSAL, not a
  // warning: the source-IP allowlist says which hosts may connect, not who is
  // at the keyboard. (With no account the pages would serve nothing anyway;
  // the refusal says what to do instead of starting a dashboard nobody can
  // use.)
  if (!isLoopbackHost(HOST) && !basicAuthInMemory && !accountSet) {
    console.error(
      `[dashboard] refusing to bind ${HOST}: a non-loopback bind needs the dashboard account — ` +
        `run \`mandu dashboard --set-password\` first (and name the proxy or tunnel host in DASHBOARD_ALLOW_HOSTS). ` +
        `Unset DASHBOARD_HOST for loopback-only.`,
    );
    process.exit(2);
  }

  // The developer view, where this build carries it (extension-loader.ts,
  // dashboard.md §4.25ac): its runners and run stores come with it.
  const extensions = await loadExtensions(SELF_DIR, {
    repoRoot: REPO_ROOT,
    ...(INSTALLED ? { installedLauncher: join(PKG_ROOT, "bin", "mandu.mjs") } : {}),
    arbiterSock: ARBITER_SOCK,
    testArbiterSock: TEST_PATHS.sock,
    testEventDir: TEST_PATHS.eventDir,
    supervisor,
    selfControl,
    publicDir: resolveStaticDir(SELF_DIR, "public"),
    env: process.env,
    log: (m) => console.error(`[dashboard] ${m}`),
  });

  const server = new DashboardServer({
    source,
    basicAuth: basicAuthInMemory,
    account,
    adminToken: ADMIN_TOKEN,
    pinnedAdminToken: PINNED_ADMIN_TOKEN,
    trustFront: TRUST_FRONT,
    basePath: BASE_PATH,
    allowedClientIps,
    allowedHosts: SERVER_NAMES,
    supervisor,
    extensions,
    approvalsArbiter: approvals?.arbiter,
    secretsArbiter: approvals?.secrets,
    postureArbiter: approvals?.posture,
    auditArbiter: approvals?.audit,
    policyDocArbiter: approvals?.policyDoc,
    // Home tells "nothing of Mandu's runs" (protection off) from "an arbiter
    // that does not answer" (Not connected) over these paths (§4.25).
    manduNotRunning: () => manduNotRunning({ arbiterSock: ARBITER_SOCK, runtimeBase: RUNTIME_BASE, eventDir: defaultEventDir(process.env) }),
    ...(testSource
      ? {
          testTenant: {
            source: testSource,
            approvalsArbiter: testApprovals?.arbiter,
            secretsArbiter: testApprovals?.secrets,
            postureArbiter: testApprovals?.posture,
            auditArbiter: testApprovals?.audit,
            policyDocArbiter: testApprovals?.policyDoc,
          },
        }
      : {}),
  });
  const port = await server.listen(PORT, HOST);
  // The human-plane socket (sign-in.ts, policy-surface.md §2.6 "Signing
  // in"): in the arbiter's human-plane directory, behind the walls the
  // launcher builds around it. It tells the launcher's dashboard line and
  // `mandu dashboard` how this dashboard signs a person in (it mints no link
  // since the account), and answers the end-of-session line. Bound before
  // the port file and the registry entry, so whoever finds this dashboard
  // finds it up. Best-effort: without it the dashboard still serves.
  try {
    sweepDeadSignInSocks(join(RUNTIME_BASE, "human"), pidAliveHere);
    signIn = await serveSignInChannel(signInSockPath(RUNTIME_BASE), signInDepsFor(server));
    console.error(`[dashboard] human-plane socket: served on ${signIn.path} (reachable only outside an agent's sandbox)`);
  } catch (err) {
    console.error(`[dashboard] human-plane socket unavailable (${(err as Error).message}); the launcher will not say how to sign in`);
  }
  // Ephemeral-port discovery (mirror of anthropic-proxy/server-main): with
  // DASHBOARD_PORT=0 the kernel picks; publish the bound port atomically so a
  // supervisor's waitForFile never reads a half-written value, and never
  // through a link planted at the temp name (port-file.ts).
  const portFile = process.env.MANDU_PORT_FILE;
  if (portFile) publishPortFile(portFile, port);
  console.error(`[dashboard] up on http://${HOST}:${port}${BASE_PATH}/`);
  // How a person signs in (dashboard.md §6.z). No admin link is printed any
  // more: the account is the way in, and the admin token a test seam.
  const signedWith = account.read();
  if (signedWith.kind === "ok") {
    console.error(`[dashboard] sign-in: the dashboard account (user ${signedWith.account.user}) on the sign-in page, or as a Basic header; the session is the admin session`);
  } else if (signedWith.kind === "unsafe") {
    console.error("[dashboard] sign-in: the dashboard account is set but cannot be used, so nobody can sign in (see above)");
  } else if (basicAuthInMemory) {
    console.error(`[dashboard] HTTP Basic auth enabled (user ${basicAuthInMemory.user}) on the sign-in page, or as a Basic header; the session is the admin session`);
  } else {
    console.error("[dashboard] sign-in: no account yet; run `mandu dashboard --set-password` in your own terminal (a running dashboard picks it up at once)");
  }
  if (PINNED_ADMIN_TOKEN) {
    console.error("[dashboard] DASHBOARD_ADMIN_TOKEN is pinned (a test seam): its /login?token= link passes the sign-in; never set it on a deployment");
  }

  // Runtime-registry entry (registry.ts, runtime-instances.md §10): make this
  // dashboard enumerable (`mandu status`) and collectable (`mandu reap`) —
  // dashboards used to be the one Mandu daemon invisible to the registry,
  // which is how five of them ended up serving side by side unnoticed
  // (2026-07-19). Best-effort: a registry failure never blocks serving.
  try {
    const swept = sweepDeadDashboards(RUNTIME_BASE);
    if (swept.length > 0) {
      console.error(`[dashboard] registry: swept ${swept.length} dead entr${swept.length === 1 ? "y" : "ies"} (${swept.join(", ")})`);
    }
    const ownerPid = resolveOwnerPid();
    const manifest = {
      pid: process.pid,
      port,
      host: HOST,
      startedAt: new Date().toISOString(),
      gitRev: gitShortRev(REPO_ROOT),
      ownerPid,
      repoRoot: REPO_ROOT,
      basePath: BASE_PATH,
      ...(signIn ? { signInSock: signIn.path } : {}),
      signInMode: server.signInMode(),
    };
    const reg = registerDashboard(RUNTIME_BASE, manifest);
    registryEntry = reg.path;
    // The account made (or changed) while this dashboard runs: the entry
    // says the new way in. Checked every 2 s too, so a reader of the
    // registry (`mandu scan`'s line) need not wait for a page request.
    onAccountChange = () => {
      try {
        rewriteDashboardEntry(reg.path, { ...manifest, signInMode: server.signInMode() });
      } catch (err) {
        console.error(`[dashboard] registry: could not record the new sign-in mode (${(err as Error).message})`);
      }
    };
    setInterval(() => { account.read(); }, 2_000).unref();
    console.error(`[dashboard] registry: ${reg.id} (owner ${ownerPid ?? "none"})`);
  } catch (err) {
    console.error(`[dashboard] registry (best-effort) failed: ${(err as Error).message}`);
  }
  if (!isLoopbackHost(HOST)) {
    console.error(
      `[dashboard] non-loopback bind: remote clients limited to ${
        allowedClientIps.length
          ? allowedClientIps.join(", ")
          : "(none — every remote client is denied; set DASHBOARD_ALLOW_HOSTS)"
      }`,
    );
    if (TRUST_FRONT) {
      console.error(
        "[dashboard] DASHBOARD_TRUST_FRONT=1: an allowlisted front's requests are the admin once past the sign-in",
      );
    }
  }

  // Auto-start the stack on boot (arbiter + Track-A proxies) so the dashboard comes
  // up "ready to run" without a manual Start all. Fire-and-forget: the server is
  // already listening; services go stopped→running in the background and the
  // Control panel reflects it. Opt out with DASHBOARD_AUTOSTART=0 (or off/none).
  // `arbiter` (stage 0b, policy-surface.md §2.6): ONLY the arbiter —
  // the launcher's autostart path spawns this supervisor instead of a bare
  // arbiter, so the human-decision channel exists from the first launch; the
  // proxies are the launcher's own per-session services there.
  const autostart = (process.env.DASHBOARD_AUTOSTART ?? "all").toLowerCase();
  if (supervisor && !["0", "off", "none", "false"].includes(autostart)) {
    const arbiterOnly = autostart === "arbiter";
    // A dashboard started to supervise the arbiter (a launch's stack
    // autostart, or a service that runs it so) is that arbiter's: once its
    // arbiter exits on its own (crashed, or replaced by another dashboard
    // that found it stale, runtime-instances.md §4.1b) it exits too, so the
    // next launch or the service manager starts the stack whole instead of
    // a second dashboard beside one that supervises nothing (the 2026-10-21
    // orphan: a launch's dashboard outlived its role for four days).
    if (arbiterOnly) {
      onServiceCrash = (id, reason) => {
        if (id !== "arbiter") return;
        console.error(`[dashboard] the arbiter this dashboard supervises exited (${reason.split("\n")[0]}); exiting with it`);
        void bye(1);
      };
    }
    console.error(arbiterOnly
      ? "[dashboard] autostart: bringing up the arbiter only (DASHBOARD_AUTOSTART=arbiter)…"
      : "[dashboard] autostart: bringing up arbiter + proxies (DASHBOARD_AUTOSTART=0 to disable)…");
    const bringUp = arbiterOnly
      ? supervisor.start("arbiter").then(() => supervisor.status())
      : supervisor.startAll();
    void bringUp.then(
      async (st) => {
        const up = st.filter((s) => s.state === "running").length;
        console.error(`[dashboard] autostart: ${up}/${st.length} services running`);
        // The approvals/secrets connect above necessarily FAILED on a
        // supervised cold boot (no arbiter existed yet); now that autostart
        // brought one up, retry and late-bind the surfaces. A few spaced
        // attempts: "running" means the process is up, its socket file can
        // trail by a beat. Best-effort like autostart itself — every attempt
        // failing just leaves the routes 404 (the pre-existing behavior).
        for (let attempt = 0; !approvals && attempt < 5; attempt++) {
          await new Promise((r) => setTimeout(r, 1000));
          approvals = await makeApprovalsArbiter(ARBITER_SOCK, adminTarget);
        }
        if (approvals) {
          server.attachArbiterSurfaces(
            approvals.arbiter, approvals.secrets, approvals.posture, approvals.audit,
          );
          server.attachPolicyDocSurface(approvals.policyDoc);
          console.error("[dashboard] egress approvals: connected after autostart");
        }
        for (let attempt = 0; testSource && !testApprovals && attempt < 5; attempt++) {
          await new Promise((r) => setTimeout(r, 1000));
          testApprovals = await makeApprovalsArbiter(TEST_PATHS.sock, testAdminTarget);
        }
        if (testApprovals) {
          server.attachArbiterSurfaces(
            testApprovals.arbiter, testApprovals.secrets, testApprovals.posture, testApprovals.audit, "test",
          );
          server.attachPolicyDocSurface(testApprovals.policyDoc, "test");
          console.error("[dashboard] test tenant: surfaces connected after autostart");
        }
      },
      (err: unknown) => {
        console.error(`[dashboard] autostart (best-effort) failed: ${(err as Error).message}`);
        // DASHBOARD_AUTOSTART=arbiter is the launcher's stack autostart: it
        // waits for THIS arbiter to promote, and a supervisor that serves
        // without one only delays the launcher's own fallback arbiter until it
        // stops us (runtime-instances.md §10). Exit, so it falls back at once.
        if (arbiterOnly) {
          console.error("[dashboard] autostart: the arbiter did not come up; exiting so the launcher starts one itself");
          void bye(1);
        }
      },
    );
  } else if (!approvals) {
    // No autostart and no arbiter at boot: `mandu dashboard` opened while
    // Mandu was not running (the person ran only `mandu scan`, plan 17 §3
    // item 12). The first `mandu claude` then starts an arbiter at the
    // rendezvous; join it when it appears, as the autostart path does, so
    // this page stops saying protection is off once an agent runs under
    // Mandu (dashboard.md §4.25, *Protection is off when nothing runs*). A
    // stat per tick until then; the timer never holds the process up.
    let joining = false;
    const joinTimer = setInterval(() => {
      if (approvals) { clearInterval(joinTimer); return; }
      if (joining || !existsSync(ARBITER_SOCK)) return;
      joining = true;
      void makeApprovalsArbiter(ARBITER_SOCK, adminTarget).then((a) => {
        joining = false;
        if (!a || approvals) { a?.close(); return; }
        approvals = a;
        clearInterval(joinTimer);
        server.attachArbiterSurfaces(a.arbiter, a.secrets, a.posture, a.audit);
        server.attachPolicyDocSurface(a.policyDoc);
        console.error("[dashboard] egress approvals: connected to the arbiter that started after this dashboard");
      }, () => { joining = false; });
    }, ARBITER_JOIN_POLL_MS);
    joinTimer.unref();
  }

  // server.close() reaps the supervised children (shutdownAll) + cancels runs
  // (cancelAll), so exit cleanly on a signal instead of orphaning the arbiter.
  const bye = async (code = 0): Promise<void> => {
    if (registryEntry) unregisterDashboard(registryEntry);
    await signIn?.close();
    await server.close();
    approvals?.close();
    testApprovals?.close();
    process.exit(code);
  };
  process.on("SIGINT", () => void bye());
  process.on("SIGTERM", () => void bye());
  onTestOwnerGone = (owner) => {
    console.error(`[dashboard] test owner pid ${owner} is gone; shutting down`);
    void bye();
  };
}

void main();
