/**
 * launcher-fixture-homes.test.ts — the FIXTURE-HOME TABLE
 * (docs/design/confidentiality/secret-discovery.md §1.4): one launch per HOME shape
 * that has bricked, or could brick, the secret walk and the twin bind, each
 * asserting the same contract:
 *
 *   L1 the launch SUCCEEDS (exit 0) — never a refused first launch;
 *   L2 every discovered secret reads back as a twin under EVERY spelling;
 *   L3 what the walk deliberately leaves out is REPORTED (the launch WARNING);
 *      a catalog file below its depth cap or past its file cap is gated at
 *      the open by the guard all the same (confidentiality.md §6, "A catalog
 *      file the launch did not register", 2026-10-17): it reads back as its
 *      placeholder, not raw;
 *   L4 `mandu doctor --secrets --json` (the dry run) AGREES with the launch:
 *      the same files, the same ledger, the same verdict (§7).
 *
 * Every launch also reports the fs rung off BY MODE, the proof the table ran
 * in `secrets` rather than an axis gone quiet.
 *
 * Same gate and plumbing as launcher-real-home.test.ts: Linux + bwrap +
 * an unprivileged userns, a private in-process arbiter in `secrets` (the
 * built-in default mode; test-organization.md §7.1) with withStack's
 * throwaway HOME, `--no-reply-filter` so stdout is what the AGENT sees,
 * absolute `/bin/cat` past the exec-box shims. Zero API budget.
 *
 * In `secrets` there is no AgentView worktree (the fs rung is off by mode), so
 * the rows about the walk reaching the AgentView copies through the view map
 * (secret-discovery.md §1.9 D) are restated: the depth-5 workspace
 * `.env` is reported under its one spelling, and a view state base under HOME
 * is pruned from the walk AND hidden from the agent whole (ownStoresHidden in
 * launcher/src/secret-setup.ts: the shadow repositories hold raw bytes of
 * protected files, fs-sync.md §3.8), asserted with a raw canary
 * planted there. The integrity form of the table is frozen:
 * tests/integrity/launcher-fixture-homes.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, linkSync, mkdirSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { basename, join } from "node:path";

import { withStack, runLauncher, probeKernelTier, hardeningBanners } from "../../lib/launcher-live.js";
import { installExitGuard } from "../../lib/exit-guard.js";
import { shardOf } from "../../lib/shard.js";
import { stateAxes } from "../../lib/axes.js";
import { doctorSecretsReport } from "../../lib/doctor-secrets-report.js";

installExitGuard("launcher-fixture-homes");

// This suite STATES its axes (protection-modes.md §4): `secrets`. withStack
// brings its private arbiter up in the same mode.
stateAxes("secrets");

const probe = process.platform === "linux" ? probeKernelTier() : null;
const GATE = process.platform !== "linux"
  ? "Linux only (bwrap secret twins)"
  : !probe!.bwrap
    ? "`bwrap` not installed"
    : !probe!.userns
      ? "unprivileged user namespaces unavailable"
      : process.getuid?.() === 0
        ? "runs as root: the unreadable-file shapes cannot be built"
        : false;

const KEY = (tag: string): string => `REAL_SECRET_${tag}_NEVER_IN_AGENT_WORLD`;
const PEM = (tag: string): string => `-----BEGIN OPENSSH PRIVATE KEY-----\n${KEY(tag)}\n`;

interface Fixture {
  name: string;
  /** Build the HOME (and anything outside it) — returns the shell reads to run inside the launch. */
  build: (home: string, outside: string, workspace: string) => string[];
  /** Raw strings that must NOT appear in the agent's world. */
  rawAbsent: string[];
  /** Raw strings that MUST appear (documented gaps, non-secrets). */
  rawPresent?: string[];
  /** Minimum number of `$MDU:nomodel_Read` twins the reads must yield. */
  twins: number;
  /** Launch-output regexes that must (not) appear. */
  outMatch?: RegExp[];
  outNoMatch?: RegExp[];
  /** The dry run's ledger must agree: (counts) and truncation. `extra` pins further reasons by name. */
  ledger?: { depth?: number; count?: number; unreadable?: number; truncated?: boolean; files?: number; extra?: Record<string, number> };
  /** A workspace symlink case: the cwd the launch runs in (default: the real workspace). */
  cwd?: (workspace: string, home: string) => string;
  /** Environment overrides for the launch AND the dry run (a state-base case). */
  env?: (home: string, tmp: string) => Record<string, string>;
  /** Extra assertions over the launch output. */
  check?: (out: string) => void;
}

const F: Fixture[] = [
  {
    name: "broken symlink named like a secret (~/.aws/credentials → /nonexistent): skipped loudly, launch succeeds",
    build: (home) => { mkdirSync(join(home, ".aws"), { recursive: true }); symlinkSync("/nonexistent/creds", join(home, ".aws", "credentials")); return [`/bin/cat ${join(home, ".aws", "credentials")} || echo DANGLING`]; },
    rawAbsent: [], rawPresent: ["DANGLING"], twins: 0, ledger: { files: 0 },
  },
  {
    name: "symlink loops (a → b → a; a directory loop): no hang, no crash, other secrets still twinned",
    build: (home) => {
      mkdirSync(join(home, ".ssh"), { recursive: true });
      symlinkSync(join(home, ".ssh", "id_b"), join(home, ".ssh", "id_a"));
      symlinkSync(join(home, ".ssh", "id_a"), join(home, ".ssh", "id_b"));
      mkdirSync(join(home, "loop"), { recursive: true });
      symlinkSync(join(home, "loop"), join(home, "loop", "self"));
      writeFileSync(join(home, ".ssh", "id_real"), PEM("LOOP"));
      return [`/bin/cat ${join(home, ".ssh", "id_real")}`];
    },
    rawAbsent: [KEY("LOOP")], twins: 1, ledger: { files: 1 },
  },
  {
    name: "secret symlinked to an unreadable target (→ /etc/shadow): not masked, launch succeeds",
    build: (home) => { mkdirSync(join(home, ".aws"), { recursive: true }); symlinkSync("/etc/shadow", join(home, ".aws", "credentials")); return [`/bin/cat ${join(home, ".aws", "credentials")} 2>&1 || echo UNREADABLE_TARGET`]; },
    rawAbsent: [], rawPresent: ["UNREADABLE_TARGET"], twins: 0, ledger: { files: 0 },
  },
  {
    name: "an unreadable directory (chmod 000) on the walk path: skipped, launch succeeds, the readable secret beside it is twinned",
    build: (home) => {
      mkdirSync(join(home, "locked"), { recursive: true }); chmodSync(join(home, "locked"), 0o000);
      mkdirSync(join(home, ".aws"), { recursive: true }); writeFileSync(join(home, ".aws", "credentials"), `[default]\naws_secret_access_key=${KEY("LOCKEDDIR")}\n`);
      return [`/bin/cat ${join(home, ".aws", "credentials")}`];
    },
    rawAbsent: [KEY("LOCKEDDIR")], twins: 1, ledger: { files: 1 },
  },
  {
    name: "secret files at mode 0400 and 0600 are masked; an unreadable (0000) candidate is REPORTED and stays where it is",
    build: (home) => {
      mkdirSync(join(home, ".ssh"), { recursive: true });
      writeFileSync(join(home, ".ssh", "id_ro"), PEM("RO")); chmodSync(join(home, ".ssh", "id_ro"), 0o400);
      writeFileSync(join(home, ".ssh", "id_rw"), PEM("RW")); chmodSync(join(home, ".ssh", "id_rw"), 0o600);
      writeFileSync(join(home, ".ssh", "id_none"), PEM("NONE")); chmodSync(join(home, ".ssh", "id_none"), 0o000);
      return [`/bin/cat ${join(home, ".ssh", "id_ro")}`, `/bin/cat ${join(home, ".ssh", "id_rw")}`, `/bin/cat ${join(home, ".ssh", "id_none")} 2>&1 || true`];
    },
    rawAbsent: [KEY("RO"), KEY("RW"), KEY("NONE")], twins: 2,
    outMatch: [/secrets NOT covered by the walk/, /1 unreadable candidate: .*id_none/],
    ledger: { unreadable: 1, files: 2 },
  },
  {
    name: "two spellings of one file (a hard link; a symlink chain of length 3): one bind per real file, EVERY spelling masked",
    build: (home) => {
      mkdirSync(join(home, ".ssh"), { recursive: true });
      writeFileSync(join(home, ".ssh", "id_base"), PEM("MULTI"));
      linkSync(join(home, ".ssh", "id_base"), join(home, ".ssh", "id_hard"));
      symlinkSync(join(home, ".ssh", "id_base"), join(home, ".ssh", "id_l1"));
      symlinkSync(join(home, ".ssh", "id_l1"), join(home, ".ssh", "id_l2"));
      symlinkSync(join(home, ".ssh", "id_l2"), join(home, ".ssh", "id_l3"));
      return ["id_base", "id_hard", "id_l1", "id_l2", "id_l3"].map((n) => `/bin/cat ${join(home, ".ssh", n)}`);
    },
    rawAbsent: [KEY("MULTI")], twins: 5, outMatch: [/same file as .*id_/],
  },
  {
    name: "a path with spaces, a leading dash and a very long name: the bind argv survives, masked",
    build: (home) => {
      const dir = join(home, "my projects", "-dashed", "x".repeat(120));
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, ".env"), `API_KEY=${KEY("SPACES")}\n`);
      return [`/bin/cat "${join(dir, ".env")}"`];
    },
    rawAbsent: [KEY("SPACES")], twins: 1, ledger: { files: 1 },
  },
  {
    name: "a secret inside the workspace which is itself under HOME (overlapping roots): deduplicated, one twin",
    build: (home, _o, ws) => { writeFileSync(join(ws, ".env"), `TOKEN=${KEY("OVERLAP")}\n`); return [`/bin/cat ${join(ws, ".env")}`]; },
    rawAbsent: [KEY("OVERLAP")], twins: 1, outNoMatch: [/same file as/], ledger: { files: 1 },
  },
  {
    name: "a workspace that is itself a symlink: masked under the path the agent uses",
    build: (home, outside) => {
      mkdirSync(outside, { recursive: true });
      writeFileSync(join(outside, ".env"), `TOKEN=${KEY("WSLINK")}\n`);
      symlinkSync(outside, join(home, "ws-link"));
      return [`/bin/cat ${join(home, "ws-link", ".env")}`, `/bin/cat ${join(outside, ".env")}`];
    },
    cwd: (_ws, home) => join(home, "ws-link"),
    rawAbsent: [KEY("WSLINK")], twins: 2,
  },
  {
    // secret-discovery.md §1.9 F: a special file, listed by the dry run, never an "unreadable candidate".
    name: "a FIFO named like a secret is ignored (regular files only), listed as a special file and never the launch WARNING; launch succeeds",
    build: (home) => { mkdirSync(join(home, ".aws"), { recursive: true }); spawnSync("mkfifo", [join(home, ".aws", "credentials")]); return ["echo FIFO_OK"]; },
    rawAbsent: [], rawPresent: ["FIFO_OK"], twins: 0,
    outNoMatch: [/secrets NOT covered by the walk/, /not searched for secrets/],
    ledger: { files: 0, unreadable: 0, extra: { "special-file": 1 } },
  },
  {
    // secret-discovery.md §1.9 F: the launch notice counts what may hold a USER's secret, not
    // the package managers' downloaded trees nor the ssh-agent's socket; the dry run lists both.
    name: "package caches below the depth cap (~/.cargo/registry/src/…, ~/go/pkg/mod/…, OpenCode's ~/.local/share/opentui/tree-sitter/…) and the ssh-agent socket under ~/.ssh: listed by the dry run (package-cache, special-file), never the launch WARNING; the key beside them is twinned",
    build: (home) => {
      mkdirSync(join(home, ".cargo", "registry", "src", "index.crates.io-x", "serde-1.0.0", "src"), { recursive: true });
      mkdirSync(join(home, "go", "pkg", "mod", "github.com", "x", "y@v1"), { recursive: true });
      // OpenCode's TUI library, as its first run leaves it (live 2026-10-11)
      mkdirSync(join(home, ".local", "share", "opentui", "tree-sitter", "languages"), { recursive: true });
      mkdirSync(join(home, ".ssh", "agent"), { recursive: true });
      // A listening socket's file outlives the process that bound it (no close, no unlink).
      const sock = join(home, ".ssh", "agent", "s.x");
      const made = spawnSync(process.execPath, ["-e", `require("net").createServer().listen(${JSON.stringify(sock)}, () => process.exit(0))`]);
      assert.equal(made.status, 0, `could not bind ${sock}: ${String(made.stderr)}`);
      writeFileSync(join(home, ".ssh", "id_ed25519"), PEM("BESIDECACHE"));
      return [`/bin/cat ${join(home, ".ssh", "id_ed25519")}`];
    },
    rawAbsent: [KEY("BESIDECACHE")], twins: 1,
    outNoMatch: [/secrets NOT covered by the walk/, /not searched for secrets/],
    ledger: { depth: 0, unreadable: 0, files: 1, extra: { "package-cache": 3, "special-file": 1 } },
  },
  {
    // secret-discovery.md §1.9 G: a cache an environment variable MOVES is still a cache. The
    // launcher sends the launch's CARGO_HOME / GOMODCACHE; the walk records the deep folders
    // inside them as package-cache (still walked, never counted), as it does the defaults.
    name: "caches moved by CARGO_HOME and GOMODCACHE (under HOME, below the depth cap): listed by the dry run as package-cache, never the launch WARNING; the key beside them is twinned",
    build: (home) => {
      mkdirSync(join(home, "dev", "cargo", "registry", "src", "index.crates.io-x", "serde-1.0.0"), { recursive: true });
      mkdirSync(join(home, "dev", "gomod", "github.com", "x", "y@v1", "pkg"), { recursive: true });
      mkdirSync(join(home, ".ssh"), { recursive: true });
      writeFileSync(join(home, ".ssh", "id_ed25519"), PEM("MOVEDCACHE"));
      return [`/bin/cat ${join(home, ".ssh", "id_ed25519")}`];
    },
    env: (home) => ({ CARGO_HOME: join(home, "dev", "cargo"), GOMODCACHE: join(home, "dev", "gomod") }),
    rawAbsent: [KEY("MOVEDCACHE")], twins: 1,
    outNoMatch: [/secrets NOT covered by the walk/, /not searched for secrets/],
    ledger: { depth: 0, unreadable: 0, files: 1, extra: { "package-cache": 2 } },
  },
  {
    // secret-discovery.md §1.9 G: a launch from HOME sends the roots [home, home]; each root is
    // walked once, so the one deep folder is ONE directory in the WARNING and the dry run.
    name: "a launch from HOME itself (the workspace IS HOME): walked once, the depth-5 folder reported ONCE by the launch WARNING and the dry run; the key twinned",
    build: (home) => {
      mkdirSync(join(home, "a", "b", "c", "d", "e"), { recursive: true });
      mkdirSync(join(home, ".aws"), { recursive: true });
      writeFileSync(join(home, ".aws", "credentials"), `[default]\naws_secret_access_key=${KEY("FROMHOME")}\n`);
      return [`/bin/cat ${join(home, ".aws", "credentials")}`];
    },
    cwd: (_ws, home) => home,
    rawAbsent: [KEY("FROMHOME")], twins: 1,
    outMatch: [/secrets NOT covered by the walk/, /1 directory below depth 4 not searched, in ~\/a\/b \(1\)$/m],
    ledger: { depth: 1, unreadable: 0, files: 1 },
  },
  {
    name: "300 catalog matches: the file cap TRUNCATES the walk, the launch succeeds and SAYS so, and the guard masks the keys past the cap at the open",
    build: (home) => {
      mkdirSync(join(home, ".ssh"), { recursive: true });
      for (let i = 0; i < 300; i++) writeFileSync(join(home, ".ssh", `id_k${String(i).padStart(3, "0")}`), PEM(`K${i}`));
      // readdir order (not name order) decides WHICH 256 are masked: read them all
      return [`for f in ${join(home, ".ssh")}/id_k*; do /bin/cat "$f"; done`];
    },
    rawAbsent: [], twins: 256,
    outMatch: [/secrets NOT covered by the walk/, /beyond the 256-file cap/, /the walk stopped at the 256-file cap/],
    check: (out) => {
      const raw = out.match(/REAL_SECRET_K\d+_NEVER_IN_AGENT_WORLD/g) ?? [];
      assert.equal(new Set(raw).size, 0, `no key beyond the cap reads back raw: the guard gates it at the open (saw ${new Set(raw).size})`);
      assert.ok(!/Permission denied/.test(out), "a key past the cap is served its placeholder, never refused");
      const twins = out.match(/\$MDU:nomodel_Read\[[0-9a-f]+\]/g) ?? [];
      assert.ok(twins.length >= 300, `every key reads as a placeholder (saw ${twins.length})`);
    },
    ledger: { truncated: true, files: 256 },
  },
  {
    name: "a secret at depth 5: the depth cap is REPORTED, and the guard masks the file at the open",
    build: (home) => {
      const deep = join(home, "a", "b", "c", "d", "e"); mkdirSync(deep, { recursive: true });
      writeFileSync(join(deep, ".env"), `TOKEN=${KEY("DEEP")}\n`);
      mkdirSync(join(home, ".aws"), { recursive: true }); writeFileSync(join(home, ".aws", "credentials"), `[default]\naws_secret_access_key=${KEY("SHALLOW")}\n`);
      return [`/bin/cat ${join(deep, ".env")}`, `/bin/cat ${join(home, ".aws", "credentials")}`];
    },
    rawAbsent: [KEY("SHALLOW"), KEY("DEEP")], twins: 2,
    outMatch: [/secrets NOT covered by the walk/, /1 directory below depth 4 not searched, in ~\/a\/b \(1\)$/m],
    ledger: { depth: 1, files: 1 },
  },
  {
    name: "catalog recall (secret-discovery.md): ~/.pgpass, ~/.npmrc, a TOML CLI config, maven settings.xml and the token under the pruned ~/.cache read back as twins",
    build: (home) => {
      const put = (rel: string, body: string): string => { const p = join(home, rel); mkdirSync(join(p, ".."), { recursive: true }); writeFileSync(p, body); return p; };
      const files = [
        put(".pgpass", `db.internal:5432:app:app:${KEY("PGPASS")}\n`),
        put(".npmrc", `//registry.npmjs.org/:_authToken=${KEY("NPMRC")}\n`),
        put(".config/stripe/config.toml", `[default]\ntest_mode_api_key = "${KEY("STRIPE")}"\n`),
        put(".m2/settings.xml", `<settings><servers><server><id>r</id><password>${KEY("MAVEN")}</password></server></servers></settings>\n`),
        put(".cache/huggingface/token", `${KEY("HF")}\n`),
      ];
      return files.map((f) => `/bin/cat ${f}`);
    },
    rawAbsent: ["PGPASS", "NPMRC", "STRIPE", "MAVEN", "HF"].map(KEY), twins: 5, ledger: { files: 5 },
    // the structure survives: the non-secret parts read back raw
    rawPresent: ["db.internal:5432:app:app:", "test_mode_api_key = \"", "<password>"],
  },
  {
    name: "an empty HOME: launch succeeds with zero twins",
    build: () => ["echo EMPTY_OK"],
    rawAbsent: [], rawPresent: ["EMPTY_OK"], twins: 0, ledger: { files: 0 },
  },
  {
    // secret-discovery.md §1.10: only the launched agent's login stays raw
    // (these launches are `--target claude`); another agent's is masked.
    name: "the agents' logins (~/.claude.json, ~/.codex/auth.json) are present: the launched agent's never masked, the agent still starts; another agent's is a placeholder copy",
    build: (home) => {
      writeFileSync(join(home, ".claude.json"), `{"oauth":"${KEY("AGENTAUTH")}"}`);
      mkdirSync(join(home, ".codex"), { recursive: true }); writeFileSync(join(home, ".codex", "auth.json"), `{"t":"${KEY("CODEXAUTH")}"}`);
      return [`/bin/cat ${join(home, ".claude.json")}`, `/bin/cat ${join(home, ".codex", "auth.json")}`];
    },
    rawAbsent: [KEY("CODEXAUTH")], rawPresent: [KEY("AGENTAUTH")], twins: 1, ledger: { files: 1, extra: { "agent-login": 1 } },
  },
  {
    name: ".env files at several depths in the workspace: depth ≤ 4 masked by the walk, depth 5 reported and masked by the guard at the open",
    build: (_h, _o, ws) => {
      const d3 = join(ws, "p", "q", "r"); mkdirSync(d3, { recursive: true }); writeFileSync(join(d3, ".env"), `A=${KEY("D3")}\n`);
      const d5 = join(ws, "p", "q", "r", "s", "t"); mkdirSync(d5, { recursive: true }); writeFileSync(join(d5, ".env"), `A=${KEY("D5")}\n`);
      return [`/bin/cat ${join(d3, ".env")}`, `/bin/cat ${join(d5, ".env")}`];
    },
    // depth: 1 in `secrets`: no AgentView worktree mirrors the workspace (the fs rung is off by mode), so
    // the depth-5 directory has one spelling. The integrity form reports 2 (the view-map walk, §9 D).
    rawAbsent: [KEY("D3"), KEY("D5")], twins: 2, ledger: { depth: 1 },
  },
  {
    // secret-discovery.md §1.9 D, restated for `secrets` and the one home: the
    // Mandu home (and so its state base) is five levels down, where the HOME walk never
    // reaches. No AgentView copy exists to cover (the integrity form reads them back
    // symbolic); what the state base still holds is a shadow repository from an earlier
    // integrity session, raw bytes of tracked files (fs-sync.md §3.8). The walk
    // prunes it and the launch hides it whole.
    name: "the Mandu home lives DEEP under HOME (below the depth cap): pruned from the walk (mandu-state, never the depth ledger), hidden from the agent whole (the raw shadow bytes never read back), the workspace's secrets twinned",
    build: (home, _o, ws) => {
      writeFileSync(join(ws, ".env"), `A=${KEY("AV")}
`);
      const nested = join(ws, "svc", "cfg"); mkdirSync(nested, { recursive: true }); writeFileSync(join(nested, ".env"), `B=${KEY("AVN")}
`);
      const shadow = join(deepHome(home), "state", "workspaces", wsId(ws), "shadow.git");
      mkdirSync(shadow, { recursive: true }); writeFileSync(join(shadow, "raw-blob"), `A=${KEY("SHADOWDEEP")}\n`);
      return [`/bin/cat ${join(ws, ".env")}`, `/bin/cat ${join(nested, ".env")}`, `/bin/cat ${join(shadow, "raw-blob")} 2>&1 || echo STATE_HIDDEN`];
    },
    env: (home) => ({ MANDU_HOME: deepHome(home) }),
    rawAbsent: [KEY("AV"), KEY("AVN"), KEY("SHADOWDEEP")], rawPresent: ["STATE_HIDDEN"], twins: 2,
    // One prune: the deep Mandu home, which holds the state base (and the
    // DB and event log the launch creates).
    ledger: { depth: 0, files: 2, extra: { "mandu-state": 1, "agentview-symbolized": 0 } },
  },
  {
    // The same for the DEFAULT state base, restated for `secrets` (see the row above): no
    // AgentView copy of this workspace exists; a stale workspace's symbolic copy and this
    // workspace's raw shadow bytes are both hidden from the agent.
    name: "the DEFAULT state base (~/.mandu) under HOME: pruned from the walk (mandu-state), hidden from the agent whole (a stale workspace's copy and the raw shadow bytes never read back), the workspace's secret twinned",
    build: (home, _o, ws) => {
      writeFileSync(join(ws, ".env"), `A=${KEY("DEF")}
`);
      // a stale tracked workspace of some past session, with a symbolic copy of its own
      const stale = join(home, ".mandu", "state", "workspaces", "old-ws-0123456789ab");
      mkdirSync(join(stale, "agentview"), { recursive: true });
      writeFileSync(join(stale, "workspace.json"), JSON.stringify({ schemaVersion: 1, workspacePath: "/somewhere/old", workspaceId: "old-ws-0123456789ab" }));
      writeFileSync(join(stale, "agentview", ".env"), "$MDU:nomodel_Read[0badf00d].env\n");
      const shadow = join(home, ".mandu", "state", "workspaces", wsId(ws), "shadow.git");
      mkdirSync(shadow, { recursive: true }); writeFileSync(join(shadow, "raw-blob"), `A=${KEY("SHADOWDEF")}\n`);
      return [
        `/bin/cat ${join(ws, ".env")}`,
        `/bin/cat ${join(stale, "agentview", ".env")} 2>&1 || echo STALE_HIDDEN`,
        `/bin/cat ${join(shadow, "raw-blob")} 2>&1 || echo STATE_HIDDEN`,
      ];
    },
    // The default home, `$HOME/.mandu` (every fixture's; spelled for the reader).
    env: (home) => ({ MANDU_HOME: join(home, ".mandu") }),
    rawAbsent: [KEY("DEF"), KEY("SHADOWDEF"), "0badf00d"], rawPresent: ["STALE_HIDDEN", "STATE_HIDDEN"], twins: 1,
    ledger: { depth: 0, files: 1, extra: { "mandu-state": 1, "agentview-symbolized": 0 } },
  },
];

/** A Mandu home five levels under `home`, below the HOME walk's depth cap. */
function deepHome(home: string): string {
  return join(home, ".local", "state", "mandu", "x", "mandu-home");
}

/** fs-sync's workspace id for a path (fs-sync/src/layout.ts `workspaceIdFor`). */
function wsId(ws: string): string {
  const c = realpathSync(ws);
  return `${basename(c).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 40)}-${createHash("sha256").update(c).digest("hex").slice(0, 12)}`;
}

// MANDU_FIXTURE_SHARD=k/n runs every n-th fixture from the k-th: the per-push
// CI runs the table as shards side by side (tests/suites.mjs).
for (const f of shardOf(F, process.env["MANDU_FIXTURE_SHARD"])) {
  test(`LIVE fixture home: ${f.name}`, { skip: GATE, timeout: 150_000 }, async () => {
    await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
      const outside = join(tmp, "outside");
      const reads = f.build(home, outside, workspace);
      const cwd = f.cwd ? f.cwd(workspace, home) : workspace;
      // The Mandu home at its default under the fixture HOME, as a real
      // install has it (the throwaway HOME holds no config.toml).
      const env: Record<string, string | undefined> = {
        ...launcherEnv("https://127.0.0.1:1", 0), HOME: home, MANDU_HOME: join(home, ".mandu"), ...(f.env?.(home, tmp) ?? {}),
      };
      const r = await runLauncher(
        ["--no-scope", "--no-mcp", "--no-reply-filter", "--confidentiality", "--target", "claude", "--", "/bin/sh", "-c", reads.join("; ")],
        env, cwd,
      );
      // Forensics: MANDU_FIXTURE_DUMP=<dir> keeps every launch's full output.
      const dump = process.env["MANDU_FIXTURE_DUMP"];
      if (dump) writeFileSync(join(dump, `${f.name.replace(/[^a-z0-9]+/gi, "-").slice(0, 60)}.out`), r.out);
      // L1
      assert.equal(r.code, 0, `launch exited ${r.code}:\n${r.out.slice(-2000)}`);
      assert.ok(!/Can't mkdir parents/.test(r.out), "the bwrap symlinked-parent failure must not recur");
      // The posture is `secrets` (integrity off ⇒ the fs rung off by mode), never an axis gone quiet.
      assert.ok(hardeningBanners(r.out).fsRungOffByMode, `the fs rung did not report off-by-mode in \`secrets\`:\n${r.out.slice(-1500)}`);
      // L2
      for (const raw of f.rawAbsent) assert.ok(!r.out.includes(raw), `raw secret ${raw} leaked into the agent's world:\n${r.out.slice(-1500)}`);
      const twins = r.out.match(/\$MDU:nomodel_Read\[[0-9a-f]+\]/g) ?? [];
      assert.ok(twins.length >= f.twins, `expected ≥${f.twins} twin reads, saw ${twins.length}:\n${r.out.slice(-1500)}`);
      // L3
      for (const raw of f.rawPresent ?? []) assert.ok(r.out.includes(raw), `expected ${raw} to read back raw:\n${r.out.slice(-1500)}`);
      for (const re of f.outMatch ?? []) assert.match(r.out, re);
      for (const re of f.outNoMatch ?? []) assert.doesNotMatch(r.out, re);
      f.check?.(r.out);
      // L4 — the dry run agrees with the launch (asked for the same agent:
      // its login stays raw, another agent's is masked; secret-discovery.md §1.10)
      const d = await runLauncher(["doctor", "--secrets", "--json", "--target", "claude"], env, cwd);
      const rep = doctorSecretsReport(d.out);
      assert.equal(rep.launch.ok, true, "the dry run must not predict a refusal for a launch that succeeded");
      assert.equal(d.code, 0);
      if (f.ledger?.files !== undefined) assert.equal(rep.files.length, f.ledger.files, `dry run inventory: ${JSON.stringify(rep.files)}`);
      if (f.ledger?.depth !== undefined) assert.equal(rep.notCovered.counts["depth"], f.ledger.depth);
      if (f.ledger?.count !== undefined) assert.equal(rep.notCovered.counts["count"], f.ledger.count);
      if (f.ledger?.unreadable !== undefined) assert.equal(rep.notCovered.counts["unreadable"], f.ledger.unreadable);
      if (f.ledger?.truncated !== undefined) assert.equal(rep.notCovered.truncated, f.ledger.truncated);
      for (const [reason, n] of Object.entries(f.ledger?.extra ?? {})) assert.equal(rep.notCovered.counts[reason] ?? 0, n, `ledger[${reason}]: ${JSON.stringify(rep.notCovered.counts)}`);
      // never a secret in the dry run
      for (const raw of [...f.rawAbsent, ...(f.rawPresent ?? [])]) assert.ok(!d.out.includes(raw), "the dry run printed a value");
    }, { mode: "secrets" });
  });
}
