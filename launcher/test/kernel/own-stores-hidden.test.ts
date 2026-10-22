/**
 * own-stores-hidden.test — E2E oracle: the agent can neither read nor write
 * the Mandu home from inside its wrap (docs/design/architecture/on-disk-layout.md §4, the
 * one deny rule; §7 phases 1 and 4).
 *
 * WHY: the symbol DB (`symbols.value`) and the event log (`DualRepr.original`)
 * hold the original behind every `$MDU:` placeholder. Until 2026-09-29 the
 * whole-agent wrap (`--dev-bind / /`) and the guard hid only the shadow
 * repositories, so `sqlite3 ~/.mandu/mandu.db 'select value from symbols'`
 * inside a launch printed every secret Mandu had ever confined. Phase 1 hid
 * a LIST of the home's parts; a stray file an older layout left at the top
 * of the home (`~/.mandu/mandu.db`) and any new file the agent created there
 * fell between the parts. Phase 4 hides the whole home, one rule.
 *
 * Real components: the arbiter daemon (subprocess, confidentiality ON) with
 * its DB at the default `<home>/state/mandu.db` of a scratch MANDU_HOME,
 * registering a real credential through the production socket adapter;
 * `applySecretTwins` building the production wrap (`ownStoresHidden` +
 * `homeMaskOps` + `withObjectTwins`) with the bubblewrap the launcher would
 * run (`resolveWrapBwrap`); the resulting launch prefix run for real. The
 * one stand-in: the git object twins (`gitObjectTwins`), a sanitized pack
 * whose cache file sits INSIDE the masked home, which proves bwrap still
 * binds it at the repository's own pack path (bind sources come from the
 * host, not the masked view). The guard's half (the deny prefix with its
 * carve-outs, the refused create) is proven by net-supervisor's
 * guard_integration `the_whole_home_is_hidden_and_unwritable_but_its_carve_out_is_the_agents`.
 *
 * The dashboard account (`state/dashboard-account.json`, dashboard.md §6.z:
 * the hash every dashboard page's sign-in checks) is one of the probed
 * stores: a confined agent can neither read it (an offline guess at the
 * password) nor replace it (a password of its own), and its overwrite
 * lands on the tmpfs.
 *
 * Three launches: `secrets` mode (the whole home masked, nothing carved
 * out); the `full` canary (protection-modes.md §10: the home masked, the
 * AgentView and its repo.git bound back and writable); and a launch with no
 * secret found and no guard, which before 2026-09-29's follow-up started no
 * wrap and so hid nothing. In each, a file the agent creates in `<home>/` or
 * `<home>/state/` lands on the wrap's throwaway tmpfs, never in the real
 * home.
 */
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { applySecretTwins, socketSecretArbiter, type SecretSetupResult } from "../../src/secret-setup.js";
import { resolveWrapBwrap } from "../../src/bwrap-grant.js";
import { emptyMutation } from "../../src/backend/types.js";
import type { LaunchPlan } from "../../src/types.js";
import { axesEnv, stateAxes, type ProtectionMode } from "../axes.js";
import { removeDir, stopGroup, tmpDir } from "../lib/tmp-dir.js";
import { sourceArbiterArgs, waitForPaths } from "../lib/arbiter-ready.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF (protection-modes.md §4);
// the `full` canary pins its own arbiter's axes (axesEnv("full"), which carries
// MANDU_EXPERIMENTAL_INTEGRITY=1) and its plan's.

const HERE = dirname(fileURLToPath(import.meta.url));
const ARBITER_DIR = join(resolve(HERE, "..", "..", ".."), "arbiter");
const ARBITER_TSX = join(ARBITER_DIR, "node_modules", ".bin", "tsx");
const CANARY = "OWNSTORE-RAW-7c3e19";

const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

interface Scenario {
  tmp: string;
  home: string;
  base: string;
  db: string;
  stray: string;
  /** The dashboard account (dashboard.md §6.z). */
  account: string;
  events: string;
  record: string;
  cred: string;
  ws: string;
  pack: string;
  sanitized: string;
  agentview: string;
  repoGit: string;
  sock: string;
  bwrap: string;
}

/** A scratch HOME with a credential, an event record and a stray top-level
 *  DB holding the canary, a workspace's AgentView and shadow repo under the
 *  home, a real arbiter (`mode`'s axes) with its DB at the default
 *  `<home>/state/mandu.db`, and a sanitized pack cached INSIDE the home,
 *  served at the repo's own path. */
async function setUp(mode: ProtectionMode, bwrap: string, arbiters: ChildProcess[]): Promise<Scenario> {
  // A short prefix: the arbiter's human socket lands at <tmp>/mandu/human/<id>.sock
  // (107-byte sun_path; a suite's TMPDIR is longer than /tmp, test-organization.md §8.5).
  const tmp = realpathSync(tmpDir("mdu-os-"));
  const home = join(tmp, "home", "u");
  const base = join(home, ".mandu");
  const db = join(base, "state", "mandu.db");
  const events = join(base, "events");
  mkdirSync(join(home, ".aws"), { recursive: true });
  mkdirSync(events, { recursive: true });
  const cred = join(home, ".aws", "credentials");
  writeFileSync(cred, `[default]\naws_secret_access_key=${CANARY}\n`, { mode: 0o600 });
  // An event record as the arbiter writes one: the original travels with it.
  const record = join(events, "s1.ndjson");
  writeFileSync(record, JSON.stringify({ sessionId: "s1", seq: 1, input: { symbolized: "$MDU:x", original: CANARY } }) + "\n");
  // The pre-one-home DB location, left behind at the top of the home.
  const stray = join(base, "mandu.db");
  writeFileSync(stray, `SQLite format 3 ${CANARY}\n`, { mode: 0o600 });
  // The dashboard account, as `mandu dashboard --set-password` writes it.
  mkdirSync(join(base, "state"), { recursive: true });
  const account = join(base, "state", "dashboard-account.json");
  writeFileSync(account, JSON.stringify({ version: 1, user: "alice", kdf: "scrypt", salt: CANARY, hash: CANARY }) + "\n", { mode: 0o600 });
  // A workspace's AgentView and shadow repo (fs-sync layout.ts).
  const wsDir = join(base, "state", "workspaces", "ws-0123456789ab");
  const agentview = join(wsDir, "agentview");
  const repoGit = join(wsDir, "repo.git");
  mkdirSync(agentview, { recursive: true });
  mkdirSync(repoGit, { recursive: true });
  writeFileSync(join(agentview, "main.rs"), "AGENTVIEW-SOURCE\n");
  writeFileSync(join(repoGit, "HEAD"), "ref: refs/heads/mdu-main\n");

  const sock = join(tmp, "arbiter.sock");
  const logFd = openSync(join(tmp, "arbiter.log"), "a");
  const arbiter = spawn(process.execPath, sourceArbiterArgs(sock), {
    cwd: ARBITER_DIR,
    env: {
      ...process.env, ...axesEnv(mode), HOME: home, MANDU_HOME: base,
      MANDU_ARBITER_SOCK: sock, MANDU_RUNTIME_DIR: join(tmp, "mandu"),
    },
    stdio: ["ignore", logFd, logFd], detached: true,
  });
  arbiters.push(arbiter);
  closeSync(logFd);
  // The shared readiness budget (launcher/test/lib/arbiter-ready.ts): load- and
  // CI-aware, ended at once by an exit; a start that does not come up FAILS
  // with the log's last lines.
  await waitForPaths(sock, { what: "the arbiter", child: arbiter, logPath: join(tmp, "arbiter.log") });

  const ws = join(tmp, "ws");
  const packDir = join(ws, ".git", "objects", "pack");
  mkdirSync(packDir, { recursive: true });
  const pack = join(packDir, "pack-1.pack");
  writeFileSync(pack, `REAL-PACK ${CANARY}\n`);
  const twinCache = join(base, "cache", "object-twins", "k1");
  mkdirSync(twinCache, { recursive: true });
  const sanitized = join(twinCache, "pack-1.pack");
  writeFileSync(sanitized, "SANITIZED-PACK\n");
  return { tmp, home, base, db, stray, account, events, record, cred, ws, pack, sanitized, agentview, repoGit, sock, bwrap };
}

/** One launch's `applySecretTwins` as the launcher runs it without a guard
 *  (the wrap alone hides the home: the guard's half is guard_integration).
 *  `full` runs in the AgentView, as fs-view points the agent there. */
async function launch(sc: Scenario, integrity: boolean, runName: string): Promise<{ r: SecretSetupResult; prefix: string[]; logs: string[] }> {
  const plan = {
    confidentiality: true, integrity, bestEffort: false,
    cwd: integrity ? sc.agentview : sc.ws, humanCwd: sc.ws, eventDir: join(sc.tmp, runName, "events"), scopeId: "own-stores",
  } as unknown as LaunchPlan;
  const runDir = join(sc.tmp, runName);
  mkdirSync(runDir);
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = await applySecretTwins(plan, runDir, mut, {
    arbiter: socketSecretArbiter(sc.sock), commandExists: () => true, usernsOk: () => true, platform: "linux",
    log: (m) => logs.push(m), home: sc.home, workspaceRoots: [], onWsl: false,
    guardServesTwins: false, nestingOk: () => true, wrapBwrap: sc.bwrap, env: { MANDU_HOME: sc.base },
    symlinkProbe: (b) => ({ bwrap: b, verdict: "unknown" }),
    gitObjectTwins: async () => ({
      twins: [{ targetPath: sc.pack, twinPath: sc.sanitized, kind: "object" as const }],
      repos: 1, blobs: 1, packsRebuilt: 1, cacheHits: 0, walks: { hit: 0, incremental: 0, full: 1 },
    }),
  });
  return { r, prefix: mut.launchPrefix, logs };
}

/** Control: outside the wrap the canary IS in the DB (so a probe cannot pass
 *  because the store was empty). */
function assertCanaryOnDisk(sc: Scenario): void {
  const onDisk = ["", "-wal"].map((s) => (existsSync(sc.db + s) ? readFileSync(sc.db + s).toString("latin1") : "")).join("");
  assert.ok(onDisk.includes(CANARY), "the registered credential's original is in the symbol DB on disk");
}

const NEW_TOP = "agent-new-top";
/** What the agent tries to put in place of the dashboard account. */
const FORGED = "AGENT-FORGED-ACCOUNT";
const NEW_STATE = "agent-new-state";

/** The agent's view: every way to the originals, and a create at the top of
 *  the home and under state/, run inside the prefix. */
function probeInside(sc: Scenario, prefix: string[], extra: string[] = []): string {
  const probe = [
    `for f in '${sc.db}' '${sc.db}-wal' '${sc.stray}' '${sc.account}' '${sc.record}' '${sc.sanitized}'; do if [ -e "$f" ]; then echo "PRESENT $f"; cat "$f" 2>/dev/null; else echo "ABSENT $f"; fi; done`,
    `ls -a '${sc.base}' '${sc.events}' 2>&1`,
    `echo "PACK=$(cat '${sc.pack}')"`,
    `echo "CRED=$(cat '${sc.cred}' 2>&1)"`,
    `grep -ra '${CANARY}' '${sc.base}' '${sc.events}' 2>/dev/null && echo LEAK-GREP || true`,
    `(echo x > '${sc.base}/${NEW_TOP}') 2>/dev/null; (echo x > '${sc.base}/state/${NEW_STATE}') 2>/dev/null; true`,
    `(echo '${FORGED}' > '${sc.account}') 2>/dev/null; true`,
    ...extra,
  ].join("; ");
  const inside = spawnSync("sh", ["-c", '"$@"', "sh", ...prefix, "sh", "-c", probe], { encoding: "utf8" });
  const out = `${inside.stdout}\n${inside.stderr}`;
  assert.equal(inside.status, 0, `the wrap ran: ${out}`);
  assert.ok(!out.includes(CANARY), `no original from Mandu's home reaches the agent:\n${out}`);
  for (const f of [sc.db, sc.stray, sc.account, sc.record, sc.sanitized]) {
    assert.match(out, new RegExp(`ABSENT ${esc(f)}\\n`), `${f} is not there:\n${out}`);
  }
  assert.match(out, /PACK=SANITIZED-PACK/, `the twin cached under the masked home still binds at the pack's own path:\n${out}`);
  assert.match(out, /CRED=[\s\S]*?\$MDU:/, `the credential reads as its placeholder:\n${out}`);
  // Every `--tmpfs` target: the launch's home, and the account's own
  // `~/.mandu` besides (the fixture's HOME is a scratch one).
  const masked = prefix.flatMap((a, i) => (a === "--tmpfs" ? [prefix[i + 1]] : []));
  assert.ok(masked.includes(sc.base), `the wrap masks the whole home: ${prefix.join(" ")}`);
  return out;
}

/** Outside, nothing was touched: we masked a view, not the disk, and what
 *  the agent wrote into the home went to the wrap's tmpfs. */
function assertDiskUntouched(sc: Scenario): void {
  assert.ok(readFileSync(sc.record, "utf8").includes(CANARY));
  assert.ok(readFileSync(sc.stray, "utf8").includes(CANARY));
  assert.ok(!existsSync(join(sc.base, NEW_TOP)), "no new file at the top of the real home");
  assert.ok(!existsSync(join(sc.base, "state", NEW_STATE)), "no new file under the real home's state/");
  const account = readFileSync(sc.account, "utf8");
  assert.ok(account.includes(CANARY) && !account.includes(FORGED), "the dashboard account was not replaced");
}

function preconditions(t: TestContext): string | null {
  if (process.platform !== "linux") { t.skip("Linux only"); return null; }
  if (!existsSync(ARBITER_TSX)) { t.skip("arbiter dependencies not installed (cd arbiter && npm install)"); return null; }
  const bwrap = resolveWrapBwrap() ?? "bwrap";
  if (spawnSync(bwrap, ["--dev-bind", "/", "/", "--", "true"]).status !== 0) {
    t.skip(`${bwrap} cannot start a sandbox here (unprivileged user namespaces barred; \`mandu setup\` installs one that can)`);
    return null;
  }
  return bwrap;
}

async function tearDown(arbiters: ChildProcess[], sc: Scenario | undefined): Promise<void> {
  // The arbiters first (they write into the scenario's dir), then the dir.
  // A setUp that failed half-way left no Scenario: its dir goes when the
  // process exits (tmpDir).
  for (const a of arbiters) await stopGroup(a);
  if (sc !== undefined) removeDir(sc.tmp);
}

test("secrets mode: inside the agent's wrap the whole home is gone (the DB, a stray top-level DB, the event log, the twin cache by its own path), a new file there never reaches the disk, the credential reads as its placeholder, and a twin cached in the home still binds", async (t) => {
  const bwrap = preconditions(t);
  if (bwrap === null) return;
  const arbiters: ChildProcess[] = [];
  let sc: Scenario | undefined;
  try {
    sc = await setUp("secrets", bwrap, arbiters);
    const { r, prefix, logs } = await launch(sc, false, "run");
    assert.equal(r.confined.length, 1, `the credential is confined (${logs.join(" | ")})`);
    assertCanaryOnDisk(sc);
    const out = probeInside(sc, prefix, [`ls '${sc.agentview}' 2>&1 || true`]);
    assert.ok(!out.includes("main.rs"), `no AgentView carve-out in secrets mode:\n${out}`);
    assert.ok(!prefix.some((a, i) => a === "--bind" && prefix[i + 1] === sc!.agentview), "nothing bound back into the home");
    assertDiskUntouched(sc);
    assert.ok(readFileSync(sc.cred, "utf8").includes(CANARY));
  } finally {
    await tearDown(arbiters, sc);
  }
});

test("full mode canary: the whole home is masked, the AgentView and its repo.git are bound back, readable and writable; the stores and the stray DB stay gone", async (t) => {
  const bwrap = preconditions(t);
  if (bwrap === null) return;
  const arbiters: ChildProcess[] = [];
  let sc: Scenario | undefined;
  try {
    sc = await setUp("full", bwrap, arbiters);
    const { r, prefix, logs } = await launch(sc, true, "run");
    assert.equal(r.confined.length, 1, `the credential is confined (${logs.join(" | ")})`);
    assertCanaryOnDisk(sc);
    const out = probeInside(sc, prefix, [
      `echo "AV=$(cat '${sc.agentview}/main.rs')"`,
      `echo "HEAD=$(cat '${sc.repoGit}/HEAD')"`,
      `echo AGENT-WROTE > '${sc.agentview}/new.rs' && echo AV-WRITE-OK`,
      `echo x > '${sc.repoGit}/agent-note' && echo REPO-WRITE-OK`,
    ]);
    assert.match(out, /AV=AGENTVIEW-SOURCE/, `the AgentView reads:\n${out}`);
    assert.match(out, /HEAD=ref: refs\/heads\/mdu-main/, `full mode: its repo.git reads:\n${out}`);
    assert.match(out, /AV-WRITE-OK/, `the AgentView takes writes:\n${out}`);
    assert.match(out, /REPO-WRITE-OK/, `full mode: its repo.git takes writes:\n${out}`);
    assert.equal(readFileSync(join(sc.agentview, "new.rs"), "utf8"), "AGENT-WROTE\n", "the AgentView write reached the real worktree");
    assertDiskUntouched(sc);
  } finally {
    await tearDown(arbiters, sc);
  }
});

test("no secret found and no guard: the wrap still starts, for the home alone (the originals of every earlier launch stay hidden)", async (t) => {
  const bwrap = preconditions(t);
  if (bwrap === null) return;
  const arbiters: ChildProcess[] = [];
  let sc: Scenario | undefined;
  try {
    sc = await setUp("secrets", bwrap, arbiters);
    // An earlier launch confined the credential: its original is in the DB.
    const first = await launch(sc, false, "run-1");
    assert.equal(first.r.confined.length, 1, first.logs.join(" | "));
    assertCanaryOnDisk(sc);
    // This launch finds nothing (the file is gone), so no secret is bound,
    // and no history is sanitized either: the fixture pack drops its canary.
    rmSync(sc.cred);
    writeFileSync(sc.pack, "REAL-PACK\n");
    const { r, prefix, logs } = await launch(sc, false, "run-2");
    assert.equal(r.confined.length, 0);
    assert.match(r.status, /no secrets found to confine \(Mandu's own stores .* hidden\)/, logs.join(" | "));
    assert.equal(prefix[0], bwrap, `a wrap for the home alone: ${prefix.join(" ")}`);
    const probe = [
      `for f in '${sc.db}' '${sc.stray}' '${sc.account}' '${sc.record}'; do if [ -e "$f" ]; then echo "PRESENT $f"; cat "$f" 2>/dev/null; else echo "ABSENT $f"; fi; done`,
      `(echo x > '${sc.base}/${NEW_TOP}') 2>/dev/null; (echo x > '${sc.base}/state/${NEW_STATE}') 2>/dev/null; true`,
      `(echo '${FORGED}' > '${sc.account}') 2>/dev/null; true`,
    ].join("; ");
    const inside = spawnSync("sh", ["-c", '"$@"', "sh", ...prefix, "sh", "-c", probe], { encoding: "utf8" });
    const out = `${inside.stdout}\n${inside.stderr}`;
    assert.equal(inside.status, 0, out);
    assert.ok(!out.includes(CANARY), out);
    for (const f of [sc.db, sc.stray, sc.account, sc.record]) assert.match(out, new RegExp(`ABSENT ${esc(f)}\\n`), `${f}:\n${out}`);
    assertDiskUntouched(sc);
  } finally {
    await tearDown(arbiters, sc);
  }
});
