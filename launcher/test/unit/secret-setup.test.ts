import { test } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, existsSync, mkdtempSync, mkdirSync, readdirSync, writeFileSync, rmSync, readFileSync, symlinkSync, realpathSync, statSync, linkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Socket } from "node:net";
import { once } from "node:events";
import { execFileSync, spawnSync } from "node:child_process";
import {
  GUARD_STAT_TWINS_ENV,
  fileLinkCount,
  linkedSecretFiles,
  asGitHistoryLocks,
  applySecretTwins,
  launchHomeCarveOuts,
  lockedHistoryRepos,
  ownStoresHidden,
  gitHistoryNotice,
  socketSecretArbiter,
  SecretConfinementError,
  resolveSecretTarget,
  trackedSecretRepos,
  type GitHistoryLocksWire,
  type LockedHistoryLaunch,
  type SecretArbiter,
  type SecretSetupDeps,
} from "../../src/secret-setup.js";
import { emptyMutation } from "../../src/backend/types.js";
import { seatbeltSecretProfile } from "../../src/secret-twins.js";
import { TWIN_SNAPSHOT_FILE, discardedWrites, parseTwinSnapshots } from "../../src/twin-writes.js";
import { cleanTwinsInIndex, endTwinIndexSession } from "../../src/twin-index-stat.js";
import type { GitSession } from "../../src/git-session.js";
import type { GitRunner } from "../../src/git-object-twins.js";
import { ownFiles } from "../../src/write-protect.js";
import { manduPath } from "../../src/generated/mandu-paths.js";
import type { TwinSource, WatchedRepo } from "../../src/placeholder-commits.js";
import type { LaunchPlan } from "../../src/types.js";

const SECRET = "/home/u/.aws/credentials";
const SYM = "$MDU:nomodel_Read[aaaa]";

function mockArbiter(over: Partial<SecretArbiter> = {}): SecretArbiter {
  return {
    discoverSecrets: async () => [{ path: SECRET }],
    registerSecret: async () => ({ symbol: SYM, reason: "registered" }),
    ...over,
  };
}

function deps(over: Partial<SecretSetupDeps> = {}): SecretSetupDeps {
  return {
    arbiter: mockArbiter(),
    commandExists: () => true,
    usernsOk: () => true,
    platform: "linux",
    log: () => {},
    home: "/home/u",
    workspaceRoots: [],
    // The mock paths do not exist on disk: identity instead of realpath. The
    // symlinked-spelling test below passes the REAL resolver explicitly.
    resolveTarget: (p) => p,
    // Pinned: the host's own WSL-ness must not change the wrap under test.
    onWsl: false,
    // Pinned: the host's own bwrap must not decide whether the bind is used.
    nestingOk: () => true,
    // Pinned: the host's own bwrap must not decide the CVE-2026-87766 warning.
    symlinkProbe: (bwrap) => ({ bwrap, verdict: "unknown" }),
    // Pinned: one link (the mock paths do not exist; P0 4c's test sets it).
    linkCount: () => 1,
    // Pinned: whether `mandu setup` installed Mandu's own bubblewrap on this
    // host must not change the wrap under test (the plain PATH bwrap).
    wrapBwrap: "bwrap",
    // Pinned: the launcher's own MANDU_HOME must not decide which home the
    // agent is denied.
    env: {},
    // Pinned: a unit test never creates the (mock) home on disk.
    makeHome: () => {},
    accountHome: null,
    ...over,
  };
}

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return { confidentiality: true, bestEffort: false, ...over } as LaunchPlan;
}

function runDir(): { dir: string; cleanup: () => void } {
  // realpath: on macOS /tmp and /var are links to /private/…, and the stores'
  // paths are resolved (secret-setup.ts ownStoresHidden).
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mandu-run-")));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("linux: twins are materialized with the SYMBOL as content and the wrap is recorded", async () => {
  const { dir, cleanup } = runDir();
  try {
    const mut = emptyMutation();
    const res = await applySecretTwins(plan(), dir, mut, deps({ guardServesTwins: true }));

    assert.equal(res.confined.length, 1);
    assert.equal(res.confined[0]!.symbol, SYM);
    assert.equal(res.posture, "confined");

    // The twin file holds the symbol — never the secret (which this process
    // never even saw: the ARBITER read the file).
    const twinDir = join(dir, "secret-twins");
    const twin = join(twinDir, "000-credentials");
    assert.equal(readFileSync(twin, "utf8"), `${SYM}\n`);

    // The wrap binds it over the real path.
    assert.equal(mut.launchPrefix[0], "bwrap");
    const i = mut.launchPrefix.indexOf(twin);
    assert.ok(i > 0);
    assert.equal(mut.launchPrefix[i - 1], "--bind");
    assert.equal(mut.launchPrefix[i + 1], SECRET);
  } finally {
    cleanup();
  }
});

test("plan 10 §4.1: each twin is watched as written, in the bind and guard-only postures, so a write to it is named at the end; no twin, no watch", async () => {
  const { dir, cleanup } = runDir();
  try {
    const twin = join(dir, "secret-twins", "000-credentials");
    for (const [what, p, d] of [
      ["bind + guard", plan(), deps({ guardServesTwins: true })],
      ["bind only (gated)", plan(), deps()],
      ["guard only", plan({ secretBind: false }), deps({ guardServesTwins: true })],
    ] as const) {
      const res = await applySecretTwins(p, dir, emptyMutation(), d);
      const watch = res.twinWatch!;
      assert.equal(watch.twins.length, 1, what);
      assert.equal(watch.twins[0]!.targetPath, SECRET, what);
      assert.equal(watch.twins[0]!.twinPath, twin, what);
      // The snapshots are left beside the twins for `mandu reap`.
      assert.equal(watch.file, join(dir, "secret-twins", TWIN_SNAPSHOT_FILE), what);
      assert.deepEqual(parseTwinSnapshots(JSON.parse(readFileSync(watch.file!, "utf8"))), watch.twins, what);
      // The mock secret is not on disk: its real file is unknown, never "unchanged".
      assert.equal(watch.real.get(SECRET), null, what);
      assert.deepEqual(discardedWrites(watch), [], `${what}: nothing written yet`);
      appendFileSync(twin, "region=eu-west-1\n");
      assert.deepEqual(discardedWrites(watch), [{ path: SECRET, real: "unknown" }], `${what}: a write to the copy is named`);
    }
    // No twin is written: gated by a host gap, macOS, nothing to confine.
    const gated = await applySecretTwins(plan(), dir, emptyMutation(), deps({ usernsOk: () => false }));
    assert.equal(gated.posture, "gated");
    assert.equal(gated.twinWatch, undefined);
    const mac = await applySecretTwins(plan(), dir, emptyMutation(), deps({ platform: "darwin", gitTracked: async () => [] }));
    assert.equal(mac.posture, "read-blocked");
    assert.equal(mac.twinWatch, undefined);
    const none = await applySecretTwins(plan(), dir, emptyMutation(), deps({ arbiter: mockArbiter({ discoverSecrets: async () => [] }) }));
    assert.equal(none.twinWatch, undefined);
  } finally {
    cleanup();
  }
});

test("plan 10 §4.1: the real file is marked at launch in memory only, so the end of the session says whether it changed too", async () => {
  const { dir, cleanup } = runDir();
  try {
    const real = join(dir, "proj", ".env");
    mkdirSync(join(dir, "proj"));
    const bytes = "STRIPE_SECRET_KEY=sk_" + "live_CANARYsecretSETUPwatch01234\n";
    writeFileSync(real, bytes, { mode: 0o600 });
    const arbiter = mockArbiter({ discoverSecrets: async () => [{ path: real }] });
    const res = await applySecretTwins(plan(), dir, emptyMutation(), deps({ arbiter, guardServesTwins: true }));
    const watch = res.twinWatch!;
    assert.equal(watch.twins[0]!.targetPath, real);
    const mark = watch.real.get(real);
    assert.ok(mark !== null && mark !== undefined && mark.sha256 !== undefined, "the real file was read at launch");
    const onDisk = readFileSync(watch.file!, "utf8");
    assert.ok(!onDisk.includes(mark.sha256) && !onDisk.includes("sk_live_"), "nothing of the real file is written down");

    appendFileSync(watch.twins[0]!.twinPath, "FEATURE_X=1\n");
    assert.deepEqual(discardedWrites(watch), [{ path: real, real: "unchanged" }]);
    appendFileSync(real, "EDITED=1\n");
    assert.deepEqual(discardedWrites(watch), [{ path: real, real: "changed" }]);
  } finally {
    cleanup();
  }
});

test("the agent's own key file (agentOwnFiles): registered, but neither twinned nor bound; every other secret still is (supported-agents.md §5.6.1)", async () => {
  const { dir, cleanup } = runDir();
  try {
    const GOOSE_KEYS = "/home/u/.config/goose/secrets.yaml";
    const registered: string[] = [];
    const logs: string[] = [];
    const mut = emptyMutation();
    const arbiter = mockArbiter({
      discoverSecrets: async () => [{ path: SECRET }, { path: GOOSE_KEYS }],
      registerSecret: async (p) => { registered.push(p); return { symbol: SYM, reason: "registered" }; },
    });
    const res = await applySecretTwins(plan(), dir, mut, deps({ arbiter, agentOwnFiles: [GOOSE_KEYS], guardServesTwins: true, log: (m) => logs.push(m) }));
    assert.deepEqual(registered, [SECRET, GOOSE_KEYS], "both registered: the key file's values are masked in what reaches the model");
    assert.deepEqual(res.confined.map((c) => c.path), [SECRET], "only the other secret is confined");
    assert.ok(!mut.launchPrefix.includes(GOOSE_KEYS), "no bind over the agent's own key file");
    assert.ok(mut.launchPrefix.includes(SECRET), "the other secret keeps its bind");
    assert.ok(logs.some((l) => l.includes(GOOSE_KEYS) && /agent's own key file/.test(l)), logs.join("\n"));
    // Without the list (another agent's launch) the same file is twinned like any secret.
    const mut2 = emptyMutation();
    const res2 = await applySecretTwins(plan(), dir, mut2, deps({ arbiter, guardServesTwins: true }));
    assert.deepEqual(res2.confined.map((c) => c.path).sort(), [GOOSE_KEYS, SECRET].sort());
    assert.ok(mut2.launchPrefix.includes(GOOSE_KEYS));
  } finally {
    cleanup();
  }
});

test("the launched agent's own MCP config (agentConfig, secret-discovery.md §2.10): registered, left readable (no bind, no twin), and said; another MCP config is twinned", async () => {
  const { dir, cleanup } = runDir();
  try {
    const OWN = "/w/proj/.mcp.json";
    const OTHER = "/home/u/.cursor/mcp.json";
    const registered: string[] = [];
    const logs: string[] = [];
    const mut = emptyMutation();
    const arbiter = mockArbiter({
      discoverSecrets: async () => ({ files: [{ path: SECRET }, { path: OWN, level: "no-model", rule: "content:secret-key", agentConfig: "claude" }, { path: OTHER, level: "no-model", rule: "content:secret-key" }] }),
      registerSecret: async (p) => { registered.push(p); return { symbol: SYM, reason: "registered" }; },
    });
    const res = await applySecretTwins(plan(), dir, mut, deps({ arbiter, guardServesTwins: true, log: (m) => logs.push(m) }));
    assert.deepEqual(registered, [SECRET, OWN, OTHER], "all registered: the agent's config's values are known to the model gates and the tripwire");
    assert.deepEqual(res.confined.map((c) => c.path).sort(), [OTHER, SECRET].sort(), "the agent's own config is not confined");
    assert.ok(!mut.launchPrefix.includes(OWN), "no bind over it: the agent starts its servers from the real values");
    assert.ok(mut.launchPrefix.includes(OTHER), "another MCP config keeps its bind");
    assert.ok(logs.some((l) => l.includes(OWN) && /Claude Code's MCP config: left readable to it, so its MCP servers start with their real values/.test(l)), logs.join("\n"));
  } finally {
    cleanup();
  }
});

test("another agent's login (secret-discovery.md §1.10): the walk is asked with the launch's agent, the login is twinned and named; MANDU_OTHER_AGENT_LOGINS=raw registers it but leaves it readable", async () => {
  const { dir, cleanup } = runDir();
  try {
    const CODEX_AUTH = "/home/u/.codex/auth.json";
    const asked: Array<Record<string, unknown> | undefined> = [];
    const registered: string[] = [];
    const arbiter = mockArbiter({
      discoverSecrets: async (_roots, _home, opts) => {
        asked.push(opts as Record<string, unknown> | undefined);
        return { files: [{ path: SECRET, level: "no-model" }, { path: CODEX_AUTH, level: "no-model", agentLogin: "codex" }] };
      },
      registerSecret: async (p, _home, loginEnv) => { registered.push(p); regEnv.push(loginEnv); return { symbol: SYM, reason: "registered" }; },
    });
    const regEnv: Array<Record<string, string> | undefined> = [];
    const claudePlan = plan({ target: "claude", writeMcp: true, ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" } } as Partial<LaunchPlan>);
    const env = { CODEX_HOME: "/home/u/.codex", OPENAI_API_KEY: "sk-not-sent" };

    // Default: a placeholder copy, said in one line naming the file and the agent.
    const logs: string[] = [];
    const mut = emptyMutation();
    const res = await applySecretTwins(claudePlan, dir, mut, deps({ arbiter, env, guardServesTwins: true, log: (m) => logs.push(m) }));
    assert.equal(asked[0]?.["target"], "claude", "the walk knows which agent this launch runs");
    assert.equal(asked[0]?.["ullmBinary"], "claude", "and the AI helper's CLI");
    assert.deepEqual(asked[0]?.["loginEnv"], { CODEX_HOME: "/home/u/.codex" }, "the login variables, and nothing else from the environment");
    assert.deepEqual(res.confined.map((c) => c.path).sort(), [CODEX_AUTH, SECRET].sort(), "Codex's login is confined like any secret");
    assert.ok(mut.launchPrefix.includes(CODEX_AUTH));
    const note = logs.find((l) => l.includes(CODEX_AUTH) && /Codex's login/.test(l));
    assert.ok(note, logs.join("\n"));
    assert.match(note!, /a placeholder copy in this session, which does not run Codex \(MANDU_OTHER_AGENT_LOGINS=raw leaves it readable\)/);
    // Another agent's login is registered with the login variables (a login
    // CODEX_HOME moved is no catalog path); an ordinary secret without them.
    assert.deepEqual(regEnv, [undefined, { CODEX_HOME: "/home/u/.codex" }]);
    regEnv.length = 0;

    // The opt-out: registered (values masked, known to the egress gate), not twinned.
    registered.length = 0;
    const logs2: string[] = [];
    const mut2 = emptyMutation();
    const res2 = await applySecretTwins(claudePlan, dir, mut2, deps({ arbiter, env: { ...env, MANDU_OTHER_AGENT_LOGINS: "raw" }, guardServesTwins: true, log: (m) => logs2.push(m) }));
    assert.deepEqual(registered, [SECRET, CODEX_AUTH], "both registered");
    assert.deepEqual(res2.confined.map((c) => c.path), [SECRET], "the other agent's login is left readable");
    assert.ok(!mut2.launchPrefix.includes(CODEX_AUTH));
    assert.ok(logs2.some((l) => l.includes(CODEX_AUTH) && /Codex's login: left readable \(MANDU_OTHER_AGENT_LOGINS=raw\), so Codex started in this session can use it/.test(l)), logs2.join("\n"));

    // An unknown value is the default, said once.
    const logs3: string[] = [];
    const res3 = await applySecretTwins(claudePlan, dir, emptyMutation(), deps({ arbiter, env: { MANDU_OTHER_AGENT_LOGINS: "yes" }, guardServesTwins: true, log: (m) => logs3.push(m) }));
    assert.ok(res3.confined.some((c) => c.path === CODEX_AUTH), "fails toward the placeholder copy");
    assert.ok(logs3.some((l) => /MANDU_OTHER_AGENT_LOGINS=yes is not `raw` or `twin`/.test(l)), logs3.join("\n"));
  } finally {
    cleanup();
  }
});

test("off / unset: a complete no-op (no wrap, no twin dir)", async () => {
  const { dir, cleanup } = runDir();
  try {
    for (const c of [false, undefined]) {
      const mut = emptyMutation();
      const res = await applySecretTwins(plan({ confidentiality: c }), dir, mut, deps());
      assert.deepEqual(mut.launchPrefix, []);
      assert.equal(res.confined.length, 0);
      assert.equal(res.status, "off");
      assert.equal(res.posture, "off");
    }
  } finally {
    cleanup();
  }
});

// ── root stays optional: a HOST gap degrades to `gated`; strictness is opt-in ──
// (docs/design/confidentiality/rootless-confinement-ubuntu-2404.md §3.1)

test("DEFAULT: no userns ⇒ the launch PROCEEDS gated, with the loud notice, NO wrap, and secrets still registered", async () => {
  const { dir, cleanup } = runDir();
  try {
    const logs: string[] = [];
    const registered: string[] = [];
    const mut = emptyMutation();
    const res = await applySecretTwins(plan(), dir, mut, deps({
      usernsOk: () => false,
      apparmorRestricted: () => true,
      arbiter: mockArbiter({ registerSecret: async (p) => { registered.push(p); return { symbol: SYM, reason: "registered" }; } }),
      log: (m) => logs.push(m),
    }));
    assert.equal(res.posture, "gated");
    assert.equal(res.gap, "apparmor-userns");
    assert.deepEqual(res.confined, [], "gated never reports a confined secret");
    assert.deepEqual(mut.launchPrefix, [], "no wrap");
    assert.ok(!existsSync(join(dir, "secret-twins")), "no twin is materialized");
    assert.deepEqual(registered, [SECRET], "pre-registration still feeds Track A masking");
    const notice = logs.find((l) => l.startsWith("mandu: secrets are GATED, not confined"));
    assert.ok(notice, "the notice is printed");
    assert.match(notice!, /can still read your credential files/);
    assert.match(notice!, /One-time upgrade: {2}mandu setup/);
    assert.match(notice!, /mandu doctor/);
    // gated must never borrow the confined claim
    assert.ok(!logs.some((l) => /absent from the agent's world|secret\(s\) confined via/.test(l)));
    assert.ok(logs.some((l) => /1 secret\(s\) registered for masking, NONE confined/.test(l)));
  } finally {
    cleanup();
  }
});

test("DEFAULT: no bwrap ⇒ gated with the apt fix (dnf and the Ubuntu AppArmor step in the cause), never the setup offer as the fix; a non-AppArmor userns gap offers no fix", async () => {
  const { dir, cleanup } = runDir();
  try {
    const logs: string[] = [];
    const res = await applySecretTwins(plan(), dir, emptyMutation(), deps({ commandExists: () => false, log: (m) => logs.push(m) }));
    assert.equal(res.gap, "no-bwrap");
    assert.ok(logs.some((l) => /One-time upgrade: {2}sudo apt install bubblewrap\n/.test(l)), logs.join("\n"));
    // `mandu setup` cannot install bubblewrap: it is never the fix line, only
    // the step after it on Ubuntu 24.04 and later (decision A: the
    // distribution's bubblewrap, rootless-confinement-ubuntu-2404.md §0.7).
    assert.ok(!logs.some((l) => /One-time upgrade: +mandu setup/.test(l)));
    assert.ok(logs.some((l) => /Fedora: sudo dnf install bubblewrap\. Ubuntu 24\.04 and later: after installing it, mandu setup adds the AppArmor grant\./.test(l)));
    assert.ok(logs.some((l) => /never one inside the working directory/.test(l)));
    const logs2: string[] = [];
    const res2 = await applySecretTwins(plan(), dir, emptyMutation(), deps({ usernsOk: () => false, apparmorRestricted: () => false, log: (m) => logs2.push(m) }));
    assert.equal(res2.gap, "userns-off");
    assert.ok(!logs2.some((l) => /One-time upgrade/.test(l)));
  } finally {
    cleanup();
  }
});

test("--best-effort is a synonym for the default on a host gap", async () => {
  const { dir, cleanup } = runDir();
  try {
    const res = await applySecretTwins(plan({ bestEffort: true }), dir, emptyMutation(), deps({ usernsOk: () => false }));
    assert.equal(res.posture, "gated");
  } finally {
    cleanup();
  }
});

test("--require-confinement: a host gap REFUSES with the cause + the fix command, and wins over --best-effort", async () => {
  const { dir, cleanup } = runDir();
  try {
    for (const bestEffort of [false, true]) {
      const mut = emptyMutation();
      await assert.rejects(
        () => applySecretTwins(plan({ requireConfinement: true, bestEffort }), dir, mut,
          deps({ usernsOk: () => false, apparmorRestricted: () => true, usernsHint: () => "HINT: knob X is shut" })),
        (e: unknown) => {
          assert.ok(e instanceof SecretConfinementError);
          assert.match(e.message, /--require-confinement is set/);
          assert.match(e.message, /unprivileged user namespaces are unavailable \(HINT: knob X is shut\)/);
          assert.match(e.message, /Fix it \(mandu setup\)/);
          assert.match(e.message, /drop --require-confinement to launch GATED/);
          return true;
        },
      );
      assert.deepEqual(mut.launchPrefix, [], "no half-applied wrap");
    }
    await assert.rejects(
      () => applySecretTwins(plan({ requireConfinement: true }), dir, emptyMutation(), deps({ commandExists: () => false })),
      /bubblewrap.*[\s\S]*sudo apt install bubblewrap/,
    );
  } finally {
    cleanup();
  }
});

// ── an ARBITER failure is an incident, not a host condition: still fail-closed ──

test("FAIL-CLOSED: an arbiter failure on a host that COULD confine refuses; --best-effort degrades it loudly; --require-confinement wins", async () => {
  const { dir, cleanup } = runDir();
  try {
    const broken = mockArbiter({ discoverSecrets: async () => { throw new Error("boom"); } });
    await assert.rejects(
      () => applySecretTwins(plan(), dir, emptyMutation(), deps({ arbiter: broken })),
      (e: unknown) => {
        assert.ok(e instanceof SecretConfinementError);
        assert.match(e.message, /could not discover secrets \(boom\)/);
        assert.match(e.message, /Fix it, or re-run with --best-effort to proceed GATED/);
        return true;
      },
    );
    const warnings: string[] = [];
    const res = await applySecretTwins(plan({ bestEffort: true }), dir, emptyMutation(), deps({ arbiter: broken, log: (m) => warnings.push(m) }));
    assert.equal(res.posture, "gated");
    assert.equal(res.gap, "arbiter");
    assert.ok(warnings.some((w) => /^WARNING: mandu: secrets are GATED, not confined/.test(w)));
    await assert.rejects(
      () => applySecretTwins(plan({ bestEffort: true, requireConfinement: true }), dir, emptyMutation(), deps({ arbiter: broken })),
      SecretConfinementError,
    );
  } finally {
    cleanup();
  }
});

test("an arbiter failure on an ALREADY gated host only warns: there is no confinement left to lose", async () => {
  const { dir, cleanup } = runDir();
  try {
    const logs: string[] = [];
    const res = await applySecretTwins(plan(), dir, emptyMutation(), deps({
      usernsOk: () => false,
      arbiter: mockArbiter({ discoverSecrets: async () => { throw new Error("boom"); } }),
      log: (m) => logs.push(m),
    }));
    assert.equal(res.posture, "gated");
    assert.ok(logs.some((l) => /secrets stay GATED/.test(l)));
  } finally {
    cleanup();
  }
});

test("a secret that cannot be registered is reported, not silently left unconfined", async () => {
  const { dir, cleanup } = runDir();
  try {
    const logs: string[] = [];
    const mut = emptyMutation();
    const res = await applySecretTwins(plan(), dir, mut, deps({
      arbiter: mockArbiter({
        registerSecret: async () => ({ symbol: null, reason: "unreadable" }),
      }),
      log: (m) => logs.push(m),
    }));
    assert.equal(res.confined.length, 0);
    assert.ok(logs.some((l) => l.includes("NOT confined")), "the hole is announced");
    assert.deepEqual(mut.launchPrefix, [], "no wrapper for zero confined secrets");
  } finally {
    cleanup();
  }
});

test("no secrets on the machine ⇒ no wrapper (never pay for a sandbox we do not need)", async () => {
  const { dir, cleanup } = runDir();
  try {
    const mut = emptyMutation();
    const res = await applySecretTwins(plan(), dir, mut, deps({
      arbiter: mockArbiter({ discoverSecrets: async () => [] }),
    }));
    assert.deepEqual(mut.launchPrefix, []);
    assert.match(res.status, /no secrets found/);
  } finally {
    cleanup();
  }
});

test("FAIL-CLOSED: a wedged arbiter (accepting but never replying) times out — never hangs the launch", async () => {
  // A real unix socket that accepts and then stays SILENT — the wedge that used
  // to hang applySecretTwins forever (ndjsonCall had no client deadline; found
  // 2026-07-14 when a silent test mock hung the e2e suite for an hour).
  const dir = mkdtempSync(join(tmpdir(), "mandu-wedge-"));
  const sockPath = join(dir, "arbiter.sock");
  const conns = new Set<Socket>();
  const srv = createServer((s) => {
    conns.add(s);
    s.on("close", () => conns.delete(s));
  });
  srv.listen(sockPath);
  await once(srv, "listening");
  try {
    const arbiter = socketSecretArbiter(sockPath, { requestTimeoutMs: 150 });
    // Both ops carry the deadline…
    await assert.rejects(
      arbiter.registerSecret(SECRET),
      /registerSecret timed out after 150ms — fail closed/,
    );
    // …and through applySecretTwins the timeout becomes the fail-closed refusal
    // (never a hang: this test completing at all is the point).
    await assert.rejects(
      () => applySecretTwins(plan(), dir, emptyMutation(), deps({ arbiter })),
      (e: Error) => {
        assert.ok(e instanceof SecretConfinementError);
        assert.match(e.message, /discoverSecrets timed out after 150ms/);
        return true;
      },
    );
  } finally {
    srv.close();
    for (const s of conns) s.destroy();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("macOS: the deny set is recorded for the ONE Seatbelt profile (both spellings, policy.yaml protect:); read-blocked, said so; no readers", async () => {
  const { dir, cleanup } = runDir();
  try {
    const mut = emptyMutation();
    const logs: string[] = [];
    const res = await applySecretTwins(plan(), dir, mut, deps({
      platform: "darwin",
      log: (m) => logs.push(m),
      resolveTarget: (p) => (p === SECRET ? "/private/home/u/.aws/credentials" : p),
      gitTracked: async () => [],
      arbiter: mockArbiter({
        // An arbiter that counts pinned readers (a Linux policy) pins none on macOS.
        registerSecret: async () => ({ symbol: SYM, reason: "registered", readers: { named: 2, pinned: 2 } }),
        protectPaths: async () => ({ paths: ["~/keep"] }),
      }),
    }));
    assert.equal(res.confined.length, 1);
    assert.equal(res.posture, "read-blocked");
    // The secret setup no longer wraps on macOS: seatbelt-setup.ts renders the
    // whole profile once the other components are known (run.ts).
    assert.deepEqual(mut.launchPrefix, []);
    assert.deepEqual(res.seatbelt?.secrets, ["/home/u/.aws/credentials", "/private/home/u/.aws/credentials"]);
    assert.deepEqual(res.seatbelt?.noDelete, ["/home/u/keep"]);
    assert.equal(res.readersPinned, undefined, "no reader is ever handed the real file under read-blocked");
    assert.match(res.status, /^on: 1 read-blocked \(the Seatbelt profile\)$/);
    assert.ok(logs.some((l) => /1 credential file\(s\) unreadable \(read-blocked by the Seatbelt profile/.test(l)), logs.join("\n"));
    assert.ok(!logs.some((l) => /confined via|masked/.test(l)), "macOS never claims confined or masked");
    assert.deepEqual(existsSync(join(dir, "secret-twins")) ? readdirSync(join(dir, "secret-twins")) : [], [], "no twin file on macOS (nothing to substitute)");
    // Upstream's own stores of originals ride in the same ONE profile
    // (seatbelt-setup.ts), never a second sandbox-exec wrap.
    assert.ok((res.seatbelt?.ownStores ?? []).includes("/home/u/.mandu"), "and the whole Mandu home");
    assert.ok((res.ownStoresHidden ?? []).includes("/home/u/.mandu"));
  } finally {
    cleanup();
  }
});

test("macOS: a protected file committed to git ⇒ ONE warning naming the repositories (the history stays readable there)", async () => {
  const { dir, cleanup } = runDir();
  try {
    const logs: string[] = [];
    const seen: string[][] = [];
    const res = await applySecretTwins(plan(), dir, emptyMutation(), deps({
      platform: "darwin",
      log: (m) => logs.push(m),
      gitTracked: async (ps) => { seen.push(ps); return [{ root: "/w/repo", checked: true }, { root: "/w/slow", checked: false }]; },
    }));
    assert.deepEqual(seen, [[SECRET]], "asked with the real paths");
    const warn = logs.filter((l) => l.startsWith("WARNING: mandu: a protected file is committed to git"));
    assert.equal(warn.length, 1, logs.join("\n"));
    assert.match(warn[0]!, /in \/w\/repo, \/w\/slow \(git did not answer; assumed committed\): on macOS/);
    assert.deepEqual(res.gitTrackedRepos, ["/w/repo", "/w/slow"]);
    assert.equal(gitHistoryNotice([]), null);
  } finally {
    cleanup();
  }
});

test("macOS: trackedSecretRepos — staged or committed counts, ignored does not, a failing git errs loud", async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "mandu-git-")));
  try {
    const git = (args: string[]) => spawnSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", ...args], { cwd: root, encoding: "utf8" });
    git(["init", "-q"]);
    writeFileSync(join(root, ".env"), "SECRET=1\n");
    writeFileSync(join(root, "ignored.env"), "SECRET=2\n");
    assert.deepEqual(await trackedSecretRepos([join(root, "ignored.env")]), [], "an untracked file in a repository with no commit");
    git(["add", ".env"]);
    assert.deepEqual(await trackedSecretRepos([join(root, ".env"), join(root, "ignored.env")]), [{ root, checked: true }], "staged: the blob is in the object store");
    git(["commit", "-qm", "x"]);
    git(["rm", "-q", "--cached", ".env"]);
    git(["commit", "-qm", "drop"]);
    assert.deepEqual(await trackedSecretRepos([join(root, ".env")]), [{ root, checked: true }], "removed from the index but still in the history");
    assert.deepEqual(await trackedSecretRepos([join(tmpdir(), "no-repo-here", ".env")], { exists: () => false }), [], "outside any repository");
    const broken = await trackedSecretRepos([join(root, ".env")], { git: async () => ({ code: 128, stdout: "", stderr: "boom" }) });
    assert.deepEqual(broken, [{ root, checked: false }]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("linux: a secret registered under a SYMLINKED spelling is bound on its REAL path (the bricked-launch shape)", async () => {
  const { dir, cleanup } = runDir();
  const home = mkdtempSync(join(tmpdir(), "mandu-home-"));
  const outside = mkdtempSync(join(tmpdir(), "mandu-outside-"));
  try {
    // ~/tools/linux → <outside>; the registry holds the spelling THROUGH the link.
    mkdirSync(join(outside, "Documentation", "security"), { recursive: true });
    const real = join(outside, "Documentation", "security", "credentials.rst");
    writeFileSync(real, "kernel doc\n");
    mkdirSync(join(home, "tools"), { recursive: true });
    symlinkSync(outside, join(home, "tools", "linux"));
    const seen = join(home, "tools", "linux", "Documentation", "security", "credentials.rst");
    const gone = join(home, ".aws", "credentials"); // registered, but vanished since

    const logs: string[] = [];
    const mut = emptyMutation();
    const res = await applySecretTwins(plan(), dir, mut, deps({
      home,
      resolveTarget: resolveSecretTarget, // the production resolver (realpath)
      log: (m) => logs.push(m),
      arbiter: mockArbiter({
        discoverSecrets: async () => [{ path: seen }, { path: gone }],
        registerSecret: async (p) => ({ symbol: p === seen ? "$MDU:nomodel_Read[5555]" : "$MDU:nomodel_Read[6666]", reason: "registered" }),
      }),
    }));

    const i = mut.launchPrefix.indexOf("--bind");
    assert.ok(i > 0, "a bind was planned");
    assert.equal(mut.launchPrefix[i + 2], realpathSync(real), "the bind lands on the REAL path, not the symlinked spelling");
    assert.ok(!mut.launchPrefix.includes(seen), "no bind through the symlinked parent (bwrap cannot mkdir it)");
    assert.equal(res.confined.length, 1, "only the file that exists counts as confined");
    assert.ok(logs.some((l) => l.includes(gone) && /no longer exists/.test(l)), "the vanished file is reported, not silently dropped");
  } finally {
    cleanup();
    rmSync(home, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

// ── plan 10: structured twins and the environment half ───────────────────────
import { applyEnvSecrets } from "../../src/secret-setup.js";

test("linux: a structured twin from the arbiter is what lands in the twin file, and the count is reported", async () => {
  const { dir, cleanup } = runDir();
  try {
    const twin = "[default]\naws_access_key_id = $MDU:nomodel_Read[aaaa].default.aws_access_key_id\nregion = us-east-1\n";
    const mut = emptyMutation();
    const res = await applySecretTwins(plan(), dir, mut, deps({
      arbiter: mockArbiter({ registerSecret: async () => ({ symbol: SYM, reason: "registered", twin, fields: 1 }) }),
    }));
    assert.equal(res.confined.length, 1);
    assert.equal(res.structured, 1);
    assert.match(res.status, /1 structured/);
    assert.equal(readFileSync(join(dir, "secret-twins", "000-credentials"), "utf8"), twin);
  } finally {
    cleanup();
  }
});

function envArbiter(over: Partial<SecretArbiter> = {}): SecretArbiter {
  return mockArbiter({
    registerEnvSecrets: async (vars) => ({
      vars: vars.map((v) =>
        v.name === "GH_TOKEN"
          ? { name: v.name, symbol: "$MDU:nomodel_Env[1111].GH_TOKEN", twin: "$MDU:nomodel_Env[1111].GH_TOKEN", reason: "registered" }
          : v.name === "DATABASE_URL"
            ? { name: v.name, symbol: "$MDU:nomodel_Env[2222].DATABASE_URL.password", twin: "postgres://app:$MDU:nomodel_Env[2222].DATABASE_URL.password@db/prod", reason: "registered" }
            : { name: v.name, symbol: null, reason: "not a secret variable" }),
    }),
    ...over,
  });
}

test("applyEnvSecrets: masked variables reach mut.env (both spawn paths); launcher-set and empty variables are never sent", async () => {
  const mut = emptyMutation();
  mut.env["ANTHROPIC_BASE_URL"] = "http://127.0.0.1:1/";
  const sent: string[] = [];
  const arb = envArbiter({
    registerEnvSecrets: async (vars) => {
      sent.push(...vars.map((v) => v.name));
      return envArbiter().registerEnvSecrets!(vars);
    },
  });
  const env = { GH_TOKEN: "ghp_x", DATABASE_URL: "postgres://app:pw@db/prod", PATH: "/usr/bin", EMPTY: "", ANTHROPIC_BASE_URL: "https://real" };
  const logs: string[] = [];
  const res = await applyEnvSecrets(plan(), env, mut, { arbiter: arb, log: (m) => logs.push(m) });
  assert.deepEqual(res.masked, ["DATABASE_URL", "GH_TOKEN"]);
  assert.equal(mut.env["GH_TOKEN"], "$MDU:nomodel_Env[1111].GH_TOKEN");
  assert.equal(mut.env["DATABASE_URL"], "postgres://app:$MDU:nomodel_Env[2222].DATABASE_URL.password@db/prod");
  assert.equal(mut.env["PATH"], undefined, "an unmasked variable is left to the ambient env");
  assert.ok(!sent.includes("EMPTY") && !sent.includes("ANTHROPIC_BASE_URL"), sent.join(","));
  assert.ok(logs.some((l) => /2 secret variables masked \(DATABASE_URL, GH_TOKEN\)/.test(l)), logs.join("\n"));
});

test("applyEnvSecrets under `mandu goose`: the key of the Chat Completions provider the launch routes is the agent's own, never sent; another provider's key is", async () => {
  const sent: string[] = [];
  const arb = envArbiter({ registerEnvSecrets: async (vars) => { sent.push(...vars.map((v) => v.name)); return envArbiter().registerEnvSecrets!(vars); } });
  const env = { OPENROUTER_API_KEY: "sk-or-x", XAI_API_KEY: "xai-x", GH_TOKEN: "ghp_x" };
  const gooseRouting = { provider: "openrouter", subagentProvider: "openrouter", openai: null, compat: [{ provider: "openrouter", upstream: "https://openrouter.ai" }] } as LaunchPlan["gooseRouting"];
  await applyEnvSecrets(plan({ target: "goose", gooseRouting }), env, emptyMutation(), { arbiter: arb, log: () => {} });
  assert.deepEqual(sent.sort(), ["GH_TOKEN", "XAI_API_KEY"], "OPENROUTER_API_KEY stays the agent's own; xAI is not routed by this launch");
  sent.length = 0;
  await applyEnvSecrets(plan({ target: "opencode", gooseRouting }), env, emptyMutation(), { arbiter: arb, log: () => {} });
  assert.ok(sent.includes("OPENROUTER_API_KEY"), "only a goose launch");
});

test("applyEnvSecrets: off with the axis off or --no-env-secrets; fail-soft on an arbiter error (and says so)", async () => {
  const env = { GH_TOKEN: "ghp_x" };
  let mut = emptyMutation();
  assert.match((await applyEnvSecrets(plan({ confidentiality: false }), env, mut, { arbiter: envArbiter(), log: () => {} })).status, /^off/);
  assert.equal(mut.env["GH_TOKEN"], undefined);
  mut = emptyMutation();
  assert.match((await applyEnvSecrets(plan({ envSecrets: false }), env, mut, { arbiter: envArbiter(), log: () => {} })).status, /no-env-secrets/);
  assert.equal(mut.env["GH_TOKEN"], undefined);
  mut = emptyMutation();
  const logs: string[] = [];
  const r = await applyEnvSecrets(plan(), env, mut, {
    arbiter: envArbiter({ registerEnvSecrets: async () => { throw new Error("socket gone"); } }),
    log: (m) => logs.push(m),
  });
  assert.match(r.status, /^error/);
  assert.equal(mut.env["GH_TOKEN"], undefined);
  assert.ok(logs.some((l) => /WARNING.*NOT masked.*socket gone/.test(l)), logs.join("\n"));
});


// ── plan 10 §4.1: the interposer's policy file ───────────────────────────────
import { npmWrappedNative, resolveAgentExe } from "../../src/secret-setup.js";

test("linux: the guard's secret policy file is written beside the twins and named in the env", async () => {
  const { dir, cleanup } = runDir();
  try {
    const mut = emptyMutation();
    const res = await applySecretTwins(plan({ argv: ["sh"], basePath: "/bin:/usr/bin", scopeId: "sid-7", secretsAsk: "always" } as Partial<LaunchPlan>), dir, mut, deps());
    assert.equal(res.confined.length, 1);
    const policyPath = mut.env["MANDU_NET_GUARD_SECRETS"];
    assert.ok(policyPath && policyPath.startsWith(join(dir, "secret-twins")), policyPath);
    const doc = JSON.parse(readFileSync(policyPath!, "utf8"));
    assert.equal(doc.ask, "always");
    assert.equal(doc.session, "sid-7");
    assert.ok(doc.agentExe.endsWith("/sh") || doc.agentExe.endsWith("/dash") || doc.agentExe.endsWith("/bash"), doc.agentExe);
    assert.deepEqual(doc.secrets.map((s: { path: string; level: string }) => [s.path, s.level]), [[SECRET, "no-model"]]);
    assert.equal(doc.secrets[0].twin, join(dir, "secret-twins", "000-credentials"));
  } finally {
    cleanup();
  }
});

test("resolveAgentExe: a PATH lookup on the launch basePath, realpath'd; empty when unresolvable", () => {
  assert.ok(resolveAgentExe({ argv: ["sh"], basePath: "/bin:/usr/bin" } as LaunchPlan).endsWith("sh"));
  assert.equal(resolveAgentExe({ argv: ["no-such-agent-xyz"], basePath: "/bin" } as LaunchPlan), "");
  assert.equal(resolveAgentExe({ argv: [] } as unknown as LaunchPlan), "");
});

test("resolveAgentExe: npm's codex script names the native Codex it runs (sibling and nested platform package, the package's own vendor); anything else, or a missing native, is unchanged", () => {
  const { dir, cleanup } = runDir();
  try {
    const layout = (root: string, native: string[] | null): { bin: string; script: string; native: string | null } => {
      const pkg = join(root, "lib", "node_modules", "@openai", "codex");
      mkdirSync(join(pkg, "bin"), { recursive: true });
      const script = join(pkg, "bin", "codex.js");
      writeFileSync(script, "#!/usr/bin/env node\n");
      mkdirSync(join(root, "bin"), { recursive: true });
      const bin = join(root, "bin", "codex");
      symlinkSync(script, bin);
      let nat: string | null = null;
      if (native) {
        nat = join(root, ...native);
        mkdirSync(join(nat, ".."), { recursive: true });
        writeFileSync(nat, "\x7fELF");
      }
      return { bin, script: realpathSync(script), native: nat ? realpathSync(nat) : null };
    };
    const triple = process.arch === "arm64" ? "aarch64-unknown-linux-musl" : "x86_64-unknown-linux-musl";
    const plat = `codex-linux-${process.arch}`;
    if (process.platform === "linux" && (process.arch === "x64" || process.arch === "arm64")) {
      // npm -g: the platform package beside the script's package (0.144.1, 0.162.0)
      const sib = layout(join(dir, "sib"), ["lib", "node_modules", "@openai", plat, "vendor", triple, "bin", "codex"]);
      assert.equal(resolveAgentExe({ argv: [sib.bin] } as LaunchPlan), sib.native, "the sibling platform package's binary");
      assert.equal(resolveAgentExe({ argv: ["codex"], basePath: join(dir, "sib", "bin") } as LaunchPlan), sib.native, "by PATH too");
      // nested under the script's package
      const nest = layout(join(dir, "nest"), ["lib", "node_modules", "@openai", "codex", "node_modules", "@openai", plat, "vendor", triple, "bin", "codex"]);
      assert.equal(resolveAgentExe({ argv: [nest.bin] } as LaunchPlan), nest.native);
      // the package's own vendor/, the codex/codex spelling
      const own = layout(join(dir, "own"), ["lib", "node_modules", "@openai", "codex", "vendor", triple, "codex", "codex"]);
      assert.equal(resolveAgentExe({ argv: [own.bin] } as LaunchPlan), own.native);
      // no native where the script looks: the script, as before
      const none = layout(join(dir, "none"), null);
      assert.equal(resolveAgentExe({ argv: [none.bin] } as LaunchPlan), none.script);
    }
    // not a known wrapper: as before
    const other = join(dir, "other.js");
    writeFileSync(other, "");
    assert.equal(resolveAgentExe({ argv: [other] } as LaunchPlan), realpathSync(other));
    assert.equal(npmWrappedNative("/x/node_modules/@openai/codex/bin/codex.js", "freebsd", "x64"), null, "an unsupported platform: no guess");
    assert.equal(npmWrappedNative("/x/node_modules/@anthropic-ai/claude-code/cli.js"), null, "an agent that is its own script is not a wrapper");
  } finally {
    cleanup();
  }
});

test("plan 10 §12.5: the pinned readers the arbiter reports are summed into the result and the status", async () => {
  const { dir, cleanup } = runDir();
  try {
    const mut = emptyMutation();
    const res = await applySecretTwins(plan(), dir, mut, deps({
      arbiter: mockArbiter({ registerSecret: async () => ({ symbol: SYM, reason: "registered", readers: { named: 3, pinned: 2 } }) }),
    }));
    assert.equal(res.readersPinned, 2);
    assert.match(res.status, /2 readers pinned/);
    // no list at all: zero, and the status stays quiet about it
    const res2 = await applySecretTwins(plan(), dir, emptyMutation(), deps());
    assert.equal(res2.readersPinned, 0);
    assert.doesNotMatch(res2.status, /pinned/);
  } finally {
    cleanup();
  }
});

test("phase 6 soak switch: --no-secret-bind on a host that COULD bind runs guard-only (no bwrap, twins + policy file); without a guard it is refused loudly and the bind stays", async () => {
  const { dir, cleanup } = runDir();
  try {
    const mut = emptyMutation();
    const logs: string[] = [];
    const res = await applySecretTwins(plan({ secretBind: false }), dir, mut, deps({ guardServesTwins: true, log: (m) => logs.push(m) }));
    assert.equal(res.posture, "confined");
    assert.match(res.status, /by the guard, no bind/);
    assert.ok(!mut.launchPrefix.includes("bwrap"), "no bind mount");
    assert.ok(mut.env["MANDU_NET_GUARD_SECRETS"]);
    assert.equal(mut.env[GUARD_STAT_TWINS_ENV], "1", "no bind: the guard answers a stat of a twinned path too (§7.2a)");
    assert.ok(logs.some((l) => /bind mount SKIPPED \(--no-secret-bind\)/.test(l)));
    // no guard: the request cannot be honored; the bind stays and a WARNING says so
    const mut2 = emptyMutation();
    const logs2: string[] = [];
    const res2 = await applySecretTwins(plan({ secretBind: false }), dir, mut2, deps({ log: (m) => logs2.push(m) }));
    // bind-only since finding 7 (2026-09-28): gated, the bind still up
    assert.deepEqual({ posture: res2.posture, gap: res2.gap }, { posture: "gated", gap: "no-guard" });
    assert.ok(mut2.launchPrefix.includes("bwrap"), "the bind stays");
    assert.equal(mut2.env[GUARD_STAT_TWINS_ENV], undefined, "under the bind the path is the twin already");
    assert.ok(logs2.some((l) => /WARNING: mandu: --no-secret-bind ignored/.test(l)));
  } finally {
    cleanup();
  }
});

test("§14.1 item 6: where the bind would stop nested sandboxes (Ubuntu 26.04), the guard alone serves the twins; without a guard the bind stays and a WARNING says what breaks", async () => {
  const { dir, cleanup } = runDir();
  try {
    const probed: string[][] = [];
    const nestingOk = (argv: string[]): boolean => { probed.push(argv); return false; };
    const mut = emptyMutation();
    const logs: string[] = [];
    const res = await applySecretTwins(plan(), dir, mut, deps({ guardServesTwins: true, nestingOk, log: (m) => logs.push(m) }));
    assert.equal(res.posture, "confined");
    assert.equal(res.bindGap, "bwrap-nesting");
    assert.match(res.status, /by the guard, no bind/);
    assert.ok(!mut.launchPrefix.includes("bwrap"), "no bind mount");
    assert.equal(readFileSync(join(dir, "secret-twins", "000-credentials"), "utf8"), `${SYM}\n`, "the twin is still written: the guard serves it");
    assert.ok(mut.env["MANDU_NET_GUARD_SECRETS"], "the guard's policy file is named");
    assert.equal(mut.env[GUARD_STAT_TWINS_ENV], "1", "and the guard answers a stat of a twinned path with the twin's metadata");
    assert.equal(logs.filter((l) => /mount layer is off/.test(l)).length, 1, "one launch line says so");
    assert.ok(!logs.some((l) => /WARNING|GATED/.test(l)), "not a degradation: the posture is still confined");
    // the probe ran the wrap the launch would run, around a nested bwrap
    assert.equal(probed.length, 1);
    assert.deepEqual(probed[0]!.slice(0, 4), ["bwrap", "--dev-bind", "/", "/"]);
    assert.ok(probed[0]!.includes("--unshare-user"));

    // no guard: the bind stays (raw bytes out beats a working shell), and says what breaks
    const mut2 = emptyMutation();
    const logs2: string[] = [];
    const res2 = await applySecretTwins(plan(), dir, mut2, deps({ nestingOk: () => false, log: (m) => logs2.push(m) }));
    assert.equal(res2.posture, "gated", "bind-only is gated (finding 7)");
    assert.equal(res2.bindGap, undefined);
    assert.ok(mut2.launchPrefix.includes("bwrap"), "the bind stays");
    assert.ok(logs2.some((l) => /^WARNING: mandu: .*Codex's shell and Mandu's command box will fail/.test(l)));

    // nesting works: the bind is used, nothing is said
    const mut3 = emptyMutation();
    const logs3: string[] = [];
    const res3 = await applySecretTwins(plan(), dir, mut3, deps({ guardServesTwins: true, nestingOk: () => true, log: (m) => logs3.push(m) }));
    assert.equal(res3.bindGap, undefined);
    assert.ok(mut3.launchPrefix.includes("bwrap"));
    assert.equal(mut3.env[GUARD_STAT_TWINS_ENV], undefined, "the bind answers the stat: no trap, no cost");
    assert.ok(!logs3.some((l) => /mount layer/.test(l)));

    // guard-only already (--no-secret-bind): the probe is not even run
    let asked = 0;
    await applySecretTwins(plan({ secretBind: false }), dir, emptyMutation(), deps({ guardServesTwins: true, nestingOk: () => { asked++; return false; } }));
    assert.equal(asked, 0);
  } finally {
    cleanup();
  }
});

test("P0 4c: linkedSecretFiles names the protected files with another hard link; an unreadable count is linked (fail-closed)", () => {
  const counts: Record<string, number | null> = { "/h/.env": 1, "/h/.aws/credentials": 2, "/h/gone": null };
  assert.deepEqual(linkedSecretFiles(["/h/.env"], (p) => counts[p]!), [], "one link: the bind covers the only name");
  assert.deepEqual(linkedSecretFiles(["/h/.env", "/h/.aws/credentials", "/h/gone"], (p) => counts[p]!), ["/h/.aws/credentials", "/h/gone"]);
  assert.deepEqual(linkedSecretFiles([], () => 9), []);
  // The default reads st_nlink, following a symlink; null when absent.
  const { dir, cleanup } = runDir();
  try {
    const f = join(dir, ".env");
    writeFileSync(f, "TOKEN=x\n");
    symlinkSync(f, join(dir, "sym"));
    assert.equal(fileLinkCount(f), 1);
    assert.equal(fileLinkCount(join(dir, "sym")), 1, "a symlink is not a second link: the bind covers what it resolves to");
    linkSync(f, join(dir, "innocent"));
    assert.equal(fileLinkCount(f), 2);
    assert.equal(fileLinkCount(join(dir, "missing")), null);
  } finally {
    cleanup();
  }
});

test("P0 4c: under the bind, a protected file with another hard link turns the guard's stat trap on; one link, or no guard, leaves it off", async () => {
  const { dir, cleanup } = runDir();
  try {
    // A hard link made before the launch: the trap on, the bind kept, one line.
    const mut = emptyMutation();
    const logs: string[] = [];
    const asked: string[] = [];
    const res = await applySecretTwins(plan(), dir, mut, deps({ guardServesTwins: true, linkCount: (p) => { asked.push(p); return 2; }, log: (m) => logs.push(m) }));
    assert.equal(res.posture, "confined");
    assert.ok(mut.launchPrefix.includes("bwrap"), "the bind stays");
    assert.deepEqual(asked, [SECRET], "the protected file's resolved target is asked");
    assert.equal(mut.env[GUARD_STAT_TWINS_ENV], "1", "the guard answers a stat of every name with the twin's metadata");
    assert.equal(mut.env["MANDU_NET_GUARD_LSTAT_TWINS"], undefined, "the lstat trap takes the guard's default (cwd-relative)");
    assert.equal(logs.filter((l) => /another name on disk \(a hard link\).*slower this session/.test(l)).length, 1, `one launch line: ${logs.join(" | ")}`);
    assert.ok(logs.some((l) => l.includes(SECRET)), "it names the file");

    // One link (the common case): nothing trapped, nothing said.
    const mut2 = emptyMutation();
    const logs2: string[] = [];
    await applySecretTwins(plan(), dir, mut2, deps({ guardServesTwins: true, linkCount: () => 1, log: (m) => logs2.push(m) }));
    assert.equal(mut2.env[GUARD_STAT_TWINS_ENV], undefined, "one link: the bind answers every stat, no trap, no cost");
    assert.ok(!logs2.some((l) => /hard link/.test(l)));

    // A count the launcher cannot read: fail-closed, the trap on.
    const mut3 = emptyMutation();
    await applySecretTwins(plan(), dir, mut3, deps({ guardServesTwins: true, linkCount: () => null }));
    assert.equal(mut3.env[GUARD_STAT_TWINS_ENV], "1");

    // No guard around the launch: nobody to answer, the variable stays unset.
    const mut4 = emptyMutation();
    await applySecretTwins(plan(), dir, mut4, deps({ linkCount: () => 2 }));
    assert.ok(mut4.launchPrefix.includes("bwrap"));
    assert.equal(mut4.env[GUARD_STAT_TWINS_ENV], undefined);
  } finally {
    cleanup();
  }
});

test("phase 6: with the guard around the launch, a host without a user namespace is still CONFINED (twins + policy file, no bind)", async () => {
  const { dir, cleanup } = runDir();
  try {
    const mut = emptyMutation();
    const logs: string[] = [];
    const res = await applySecretTwins(plan(), dir, mut, deps({ usernsOk: () => false, guardServesTwins: true, log: (m) => logs.push(m) }));
    assert.equal(res.posture, "confined");
    assert.equal(res.confined.length, 1);
    assert.match(res.status, /by the guard, no bind/);
    assert.ok(!mut.launchPrefix.includes("bwrap"), "no bind mount");
    assert.equal(readFileSync(join(dir, "secret-twins", "000-credentials"), "utf8"), `${SYM}\n`);
    assert.ok(mut.env["MANDU_NET_GUARD_SECRETS"]);
    assert.equal(mut.env[GUARD_STAT_TWINS_ENV], "1");
    assert.ok(logs.some((l) => /serves the secret twins by descriptor/.test(l)));
    // without the guard the same host is gated, as before
    const mut2 = emptyMutation();
    const gated = await applySecretTwins(plan(), dir, mut2, deps({ usernsOk: () => false }));
    assert.equal(gated.posture, "gated");
  } finally {
    cleanup();
  }
});


// ── secret-discovery.md §1.2 gap 1: what the walk left RAW is never silent ──
test("the discovery REPORT's consequential skips are logged as a WARNING at launch; the bare array of an older arbiter/mock warns nothing", async () => {
  const { dir, cleanup } = runDir();
  try {
    const logs: string[] = [];
    const reportArbiter = mockArbiter({
      discoverSecrets: async () => ({
        files: [{ path: SECRET }],
        skipped: [{ path: "/home/u/deep/a/b/c/d", reason: "depth" }, { path: "/home/u/.claude.json", reason: "agent-auth" }],
        counts: { depth: 1, count: 0, unreadable: 0, "agent-auth": 1 },
        limits: { maxDepth: 4, maxFiles: 256 },
        truncated: false,
      }),
    });
    const res = await applySecretTwins(plan(), dir, emptyMutation(), deps({ arbiter: reportArbiter, log: (m) => logs.push(m) }));
    assert.equal(res.confined.length, 1, "the files half is unchanged by the ledger");
    const warn = logs.find((l) => l.startsWith("WARNING: mandu: secrets NOT covered"));
    assert.ok(warn, logs.join("\n"));
    assert.match(warn!, /1 directory below depth 4 not searched: \/home\/u\/deep\/a\/b\/c\/d/);
    assert.match(warn!, /mandu doctor --secrets/);
    assert.ok(!/agent-auth/.test(warn!), "expected skips are not a launch warning");

    const quiet: string[] = [];
    await applySecretTwins(plan(), dir, emptyMutation(), deps({ log: (m) => quiet.push(m) })); // the array-shaped mock
    assert.ok(!quiet.some((l) => l.includes("NOT covered")));
  } finally {
    cleanup();
  }
});

test("the socket adapter sends the launch's HOME with discoverSecrets and registerSecret (the catalog's ~/ rules resolve against the session, not the arbiter)", async () => {
  const { dir, cleanup } = runDir();
  const sockPath = join(dir, "arbiter.sock");
  const seen: Array<Record<string, unknown>> = [];
  const conns = new Set<Socket>();
  const srv = createServer((s) => {
    conns.add(s);
    s.on("close", () => conns.delete(s));
    s.on("data", (chunk) => {
      const req = JSON.parse(chunk.toString().split("\n")[0]!) as Record<string, unknown>;
      seen.push(req);
      const result = req["op"] === "discoverSecrets"
        ? { files: [{ path: SECRET }], skipped: [], counts: {}, limits: { maxDepth: 4, maxFiles: 256 }, truncated: false }
        : req["op"] === "gitHistoryLocks" ? { axis: true, blobs: [], labels: [] }
        : { symbol: SYM, reason: "registered" };
      s.write(JSON.stringify({ id: req["id"], ok: true, result }) + "\n");
    });
  });
  srv.listen(sockPath);
  await once(srv, "listening");
  try {
    const arbiter = socketSecretArbiter(sockPath);
    const res = await applySecretTwins(plan(), dir, emptyMutation(), deps({ arbiter, home: "/session/home" }));
    assert.equal(res.confined.length, 1);
    const disc = seen.find((r) => r["op"] === "discoverSecrets")!;
    assert.deepEqual(disc["roots"], ["/session/home"]);
    assert.equal(disc["home"], "/session/home");
    // The home's state base rides along (the path table's `view-state`, the
    // value run.ts prefetches with), so the walk prunes it and reads the view
    // map it holds (secret-discovery.md §1.9).
    assert.equal(disc["stateBase"], "/session/home/.mandu/state");
    const reg = seen.find((r) => r["op"] === "registerSecret")!;
    assert.equal(reg["home"], "/session/home");
    // MANDU_HOME moves it with the whole home.
    seen.length = 0;
    await applySecretTwins(plan(), dir, emptyMutation(), deps({ arbiter, home: "/session/home", env: { MANDU_HOME: "/session/mh" } }));
    assert.equal(seen.find((r) => r["op"] === "discoverSecrets")!["stateBase"], "/session/mh/state");
    // The package caches the session's environment moves ride along, by
    // those names only (secret-discovery.md §1.9 G): never the rest of the
    // environment, which can hold keys.
    assert.equal("cacheEnv" in disc, false, "no moved cache: no field");
    seen.length = 0;
    await applySecretTwins(plan(), dir, emptyMutation(), deps({
      arbiter, home: "/session/home",
      env: { CARGO_HOME: "/data/cargo", GOMODCACHE: "/data/gomod", ANTHROPIC_API_KEY: "sk-ant-NEVER-SENT", XDG_CACHE_HOME: "" },
    }));
    const moved = seen.find((r) => r["op"] === "discoverSecrets")!;
    assert.deepEqual(moved["cacheEnv"], { CARGO_HOME: "/data/cargo", GOMODCACHE: "/data/gomod" });
    assert.ok(!JSON.stringify(seen).includes("sk-ant-NEVER-SENT"), "no other variable reaches the arbiter");
  } finally {
    srv.close();
    for (const s of conns) s.destroy();
    cleanup();
  }
});

// ── env.sources (comparisons.md §3.4) ──

import { envSourceCommand } from "../../src/env-sources.js";

test("envSourceCommand: cmd, 1Password and the platform keyring; unknown schemes refused", () => {
  assert.deepEqual(envSourceCommand("cmd:gh auth token"), ["sh", "-c", "gh auth token"]);
  assert.deepEqual(envSourceCommand("op://Dev/GitHub/token"), ["op", "read", "op://Dev/GitHub/token"]);
  assert.deepEqual(envSourceCommand("keyring:github/me", "linux"), ["secret-tool", "lookup", "service", "github", "account", "me"]);
  assert.deepEqual(envSourceCommand("keyring:github/me", "darwin"), ["security", "find-generic-password", "-s", "github", "-a", "me", "-w"]);
  assert.equal(envSourceCommand("file:/etc/passwd"), null);
});

test("applyEnvSecrets: a sourced variable is fetched, registered, and reaches the agent only as its placeholder (over the shell's own value)", async () => {
  const mut = emptyMutation();
  const sent: Array<{ name: string; value: string }> = [];
  const arb = envArbiter({
    envSources: async () => ({ sources: [{ name: "GH_TOKEN", source: "cmd:gh auth token", bindings: ["api.github.com"] }] }),
    registerEnvSecrets: async (vars) => { sent.push(...vars); return envArbiter().registerEnvSecrets!(vars); },
  });
  const res = await applyEnvSecrets(plan(), { GH_TOKEN: "stale_shell_value" }, mut, {
    arbiter: arb, log: () => {}, resolveSource: (s) => (s === "cmd:gh auth token" ? { value: "gho_from_source" } : { error: "?" }),
  });
  assert.deepEqual(sent, [{ name: "GH_TOKEN", value: "gho_from_source" }], "the source's value, not the shell's");
  assert.equal(mut.env["GH_TOKEN"], "$MDU:nomodel_Env[1111].GH_TOKEN");
  assert.deepEqual(res.masked, ["GH_TOKEN"]);
});

test("applyEnvSecrets: a failed source falls back to the shell's value, masked; a value the arbiter declines is emptied, never raw", async () => {
  const logs: string[] = [];
  let mut = emptyMutation();
  const failing = envArbiter({ envSources: async () => ({ sources: [{ name: "GH_TOKEN", source: "op://x/y/z", bindings: [] }] }) });
  await applyEnvSecrets(plan(), { GH_TOKEN: "ghp_shell" }, mut, { arbiter: failing, log: (m) => logs.push(m), resolveSource: () => ({ error: "op is not installed" }) });
  assert.equal(mut.env["GH_TOKEN"], "$MDU:nomodel_Env[1111].GH_TOKEN", "the shell's value went through registration and is masked");
  assert.ok(logs.some((l) => /GH_TOKEN: its source \(op\) failed \(op is not installed\); using the shell's value, masked/.test(l)), logs.join("\n"));

  mut = emptyMutation();
  const declined = envArbiter({ envSources: async () => ({ sources: [{ name: "PLAIN_NAME", source: "cmd:echo x", bindings: [] }] }) });
  await applyEnvSecrets(plan(), { PLAIN_NAME: "shell_raw" }, mut, { arbiter: declined, log: (m) => logs.push(m), resolveSource: () => ({ value: "from_source_raw" }) });
  assert.equal(mut.env["PLAIN_NAME"], "", "neither the sourced value nor the shell's reaches the agent");
});

// ── ssh_agent (comparisons.md §3.5) ──

import { sshAgentSockets } from "../../src/secret-setup.js";

test("sshAgentSockets: a policy ssh_agent section names the socket for the guard; no section, no agent or an error leaves it ungated", async () => {
  const readers = [{ app: "ssh", from: "git" }];
  const logs: string[] = [];
  const arb = mockArbiter({ sshAgentPolicy: async () => ({ readers }) });
  assert.deepEqual(await sshAgentSockets({ arbiter: arb, log: (m) => logs.push(m) }, "/run/user/1/ssh.sock"), [{ path: "/run/user/1/ssh.sock", label: "ssh-agent", readers }]);
  assert.ok(logs.some((l) => /ssh-agent: only ssh from git may use it/.test(l)), logs.join("\n"));
  assert.deepEqual(await sshAgentSockets({ arbiter: arb, log: () => {} }, undefined), [], "no agent running");
  assert.deepEqual(await sshAgentSockets({ arbiter: mockArbiter({ sshAgentPolicy: async () => ({ readers: null }) }), log: () => {} }, "/s"), [], "no section");
  const warn: string[] = [];
  assert.deepEqual(await sshAgentSockets({ arbiter: mockArbiter({ sshAgentPolicy: async () => { throw new Error("down"); } }), log: (m) => warn.push(m) }, "/s"), []);
  assert.match(warn.join(""), /ssh-agent is not gated/);
});

import { protectedPaths } from "../../src/secret-setup.js";

test("protectedPaths: ~ expands against the launching HOME; an error protects nothing and says so", async () => {
  const logs: string[] = [];
  assert.deepEqual(await protectedPaths({ arbiter: mockArbiter({ protectPaths: async () => ({ paths: ["~/Documents", "/srv/x"] }) }), log: (m) => logs.push(m) }, "/home/u"), ["/home/u/Documents", "/srv/x"]);
  assert.ok(logs.some((l) => /protected from deletion: \/home\/u\/Documents, \/srv\/x/.test(l)));
  const warn: string[] = [];
  assert.deepEqual(await protectedPaths({ arbiter: mockArbiter({ protectPaths: async () => { throw new Error("down"); } }), log: (m) => warn.push(m) }, "/h"), []);
  assert.match(warn.join(""), /nothing is protected from deletion/);
});

import { announceConsumerPacks } from "../../src/secret-setup.js";

test("announceConsumerPacks: the banner names each pack by version and key, and warns about a refused one", async () => {
  const logs: string[] = [];
  await announceConsumerPacks({ arbiter: mockArbiter({ consumerPacks: async () => ({ packs: [{ name: "acme/cli", version: "1", keyId: "acme", consumers: 2 }], refused: ["evil.json: unsigned (no evil.json.sig): refused"] }) }), log: (m) => logs.push(m) });
  assert.ok(logs.some((l) => l === "mandu: consumer packs: acme/cli 1 (key acme)"), logs.join("\n"));
  assert.ok(logs.some((l) => /WARNING: mandu: consumer pack refused: evil\.json/.test(l)));
});

test("linux on WSL: the twin wrap also hides the Windows interop socket and /init, before the binds", async () => {
  const { dir, cleanup } = runDir();
  try {
    const mut = emptyMutation();
    await applySecretTwins(plan(), dir, mut, deps({ onWsl: true, pathExists: (p) => p === "/run/WSL" || p === "/init" }));
    const argv = mut.launchPrefix;
    const at = (...seq: string[]): number => argv.findIndex((_, i) => seq.every((t, j) => argv[i + j] === t));
    const bind = argv.indexOf("--bind");
    assert.ok(at("--dev-bind", "/", "/") >= 0 && bind > 0);
    for (const seq of [["--tmpfs", "/run/WSL"], ["--ro-bind", "/dev/null", "/init"], ["--unsetenv", "WSL_INTEROP"]]) {
      const i = at(...seq);
      assert.ok(i > 0 && i < bind, `${seq.join(" ")} before the twin binds: ${argv.join(" ")}`);
    }
    // Off WSL the same launch adds none of it.
    const plain = emptyMutation();
    await applySecretTwins(plan(), dir, plain, deps({ onWsl: false, pathExists: () => true }));
    assert.ok(!plain.launchPrefix.includes("/run/WSL") && !plain.launchPrefix.includes("WSL_INTEROP"));
  } finally {
    cleanup();
  }
});

test("linux on WSL: each Windows profile is discovered as its own home, and its files register against that home", async () => {
  const { dir, cleanup } = runDir();
  try {
    const calls: Array<{ roots: string[]; home?: string }> = [];
    const registered: Array<{ path: string; home?: string }> = [];
    const winCred = "/mnt/c/Users/alice/.aws/credentials";
    const arbiter = mockArbiter({
      discoverSecrets: async (roots, home) => {
        calls.push({ roots, home });
        return home === "/mnt/c/Users/alice" ? [{ path: winCred }, { path: SECRET }] : [{ path: SECRET }];
      },
      registerSecret: async (path, home) => { registered.push({ path, home }); return { symbol: SYM, reason: "registered" }; },
    });
    const mut = emptyMutation();
    const r = await applySecretTwins(plan(), dir, mut, deps({ arbiter, onWsl: true, pathExists: () => false, windowsProfiles: ["/mnt/c/Users/alice"], guardServesTwins: true }));
    assert.equal(calls.length, 2);
    assert.equal(calls[1]!.home, "/mnt/c/Users/alice");
    assert.ok(calls[1]!.roots.includes("/mnt/c/Users/alice/.aws") && calls[1]!.roots.includes("/mnt/c/Users/alice/_netrc"));
    assert.ok(!calls[1]!.roots.includes("/mnt/c/Users/alice"), "never the whole profile (a 9p walk)");
    // The Linux file is registered once, against the Linux HOME; the Windows
    // one against its profile (the arbiter re-classifies with that home).
    assert.deepEqual(registered, [{ path: SECRET, home: "/home/u" }, { path: winCred, home: "/mnt/c/Users/alice" }]);
    assert.deepEqual(r.confined.map((c) => c.path), [SECRET, winCred]);
    const argv = mut.launchPrefix.join(" ");
    assert.match(argv, /--bind \S+ \/mnt\/c\/Users\/alice\/\.aws\/credentials/, "the Windows credential is bound over by its twin");
  } finally { cleanup(); }
});

test("off WSL the Windows profiles are never consulted", async () => {
  const { dir, cleanup } = runDir();
  try {
    let calls = 0;
    const arbiter = mockArbiter({ discoverSecrets: async () => { calls++; return [{ path: SECRET }]; } });
    await applySecretTwins(plan(), dir, emptyMutation(), deps({ arbiter, onWsl: false, windowsProfiles: ["/mnt/c/Users/alice"] }));
    assert.equal(calls, 1);
  } finally { cleanup(); }
});

test("linux on WSL without the guard: Windows credentials refuse the launch (another spelling would miss the bind), --best-effort proceeds with a warning", async () => {
  const { dir, cleanup } = runDir();
  try {
    const winCred = "/mnt/c/Users/alice/.aws/credentials";
    const arbiter = () => mockArbiter({
      discoverSecrets: async (_roots, home) => (home === "/mnt/c/Users/alice" ? [{ path: winCred }] : [{ path: SECRET }]),
      registerSecret: async () => ({ symbol: SYM, reason: "registered" }),
    });
    const wsl = { onWsl: true, pathExists: () => false, windowsProfiles: ["/mnt/c/Users/alice"] };
    await assert.rejects(
      applySecretTwins(plan(), dir, emptyMutation(), deps({ ...wsl, arbiter: arbiter() })),
      (e: Error) => e instanceof SecretConfinementError && /1 Windows credential file\(s\) \(\/mnt\/c\/Users\/alice\/\.aws\/credentials\)/.test(e.message) && /--best-effort/.test(e.message),
    );
    const logs: string[] = [];
    const mut = emptyMutation();
    const r = await applySecretTwins(plan({ bestEffort: true }), dir, mut, deps({ ...wsl, arbiter: arbiter(), log: (m) => logs.push(m) }));
    assert.deepEqual(r.confined.map((c) => c.path), [SECRET, winCred], "the exact spellings stay protected");
    assert.ok(logs.some((l) => /^WARNING: .*only their exact spellings are protected/.test(l)), logs.join("\n"));
    // Linux-only secrets without the guard: nothing to refuse over.
    const linux = await applySecretTwins(plan(), dir, emptyMutation(), deps({ onWsl: true, pathExists: () => false, windowsProfiles: [] }));
    assert.equal(linux.confined.length, 1);
    assert.equal(linux.posture, "gated", "bind-only is gated (finding 7), and it launches");
  } finally { cleanup(); }
});

// ── confidentiality-plan-11 D5: the guard's secret index carries the real level ──
import { secretLevel } from "../../src/secret-setup.js";
import { stateAxes } from "../axes.js";
stateAxes("secrets"); // the confidentiality axis is what confines secrets; this suite's cases assume it (plan() also pins confidentiality: true)

test("secretLevel: the discovered level first, else the symbol's marker, else no-model", () => {
  assert.equal(secretLevel("local-model", "$MDU:nomodel_Read[1]"), "local-model");
  assert.equal(secretLevel("any-model", null), "any-model");
  // A retired name (2026-09-27) is an unknown level: the strictest, not its old meaning.
  assert.equal(secretLevel(["secret", "strict"].join("-"), null), "no-model");
  assert.equal(secretLevel(["secret", "model-ok"].join("-"), null), "no-model");
  assert.equal(secretLevel(undefined, "$MDU:localmodel_Read[1]"), "local-model");
  assert.equal(secretLevel(undefined, "$MDU:anymodel_Read[1].password"), "any-model");
  assert.equal(secretLevel("bogus", "$MDU:weird_Read[1]"), "no-model");
  assert.equal(secretLevel(undefined, null), "no-model");
});

test("linux: secret-policy.json records each file's LABELED level (local-model, any-model), not the strictest for all", async () => {
  const { dir, cleanup } = runDir();
  try {
    const mut = emptyMutation();
    const A = "/home/u/notes/contract.md";
    const B = "/home/u/.aws/credentials";
    const C = "/home/u/.pgpass";
    const res = await applySecretTwins(plan({ argv: ["sh"], basePath: "/bin:/usr/bin", scopeId: "sid-11" } as Partial<LaunchPlan>), dir, mut, deps({
      arbiter: mockArbiter({
        discoverSecrets: async () => ({
          files: [
            { path: A, level: "local-model", rule: "label:paths[0]" },
            { path: B, level: "no-model", rule: "catalog:aws" },
            { path: C, rule: "catalog:pgpass" } as { path: string; level?: string; rule?: string },
          ],
        }),
        registerSecret: async (p) => ({ symbol: p === C ? "$MDU:anymodel_Read[cccc]" : SYM, reason: "registered" }),
      }),
    }));
    assert.equal(res.confined.length, 3);
    const doc = JSON.parse(readFileSync(mut.env["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
    const byPath = Object.fromEntries(doc.secrets.map((s: { path: string; level: string }) => [s.path, s.level]));
    assert.deepEqual(byPath, { [A]: "local-model", [B]: "no-model", [C]: "any-model" });
  } finally {
    cleanup();
  }
});

// ── The committed bytes: object-store twins + the shadow-repo mask ───────────

const PACK = "/w/dotgit/objects/pack/pack-1.pack";
const LOOSE = "/w/dotgit/objects/ab/cd";

test("linux: object-store twins join the wrap and the guard's policy (object / deny kinds); the deny source is unreadable", async () => {
  const { dir, cleanup } = runDir();
  try {
    const mut = emptyMutation();
    let asked: string[] = [];
    let walkCacheDir: string | undefined;
    const res = await applySecretTwins(plan(), dir, mut, deps({
      gitObjectTwins: async (paths, opts) => {
        asked = paths;
        walkCacheDir = opts.walkCacheDir;
        return {
          twins: [
            { targetPath: PACK, twinPath: "/cache/p.pack", kind: "object" },
            { targetPath: LOOSE, twinPath: opts.denyFile, kind: "deny" },
          ],
          repos: 1, blobs: 2, packsRebuilt: 1, cacheHits: 0, walks: { hit: 0, incremental: 0, full: 1 },
        };
      },
    }));
    assert.deepEqual(asked, [SECRET], "asked with the confined files' real paths");
    // The walk cache must be one the agent cannot write (an entry with a
    // version left out would leave it readable next launch): inside
    // write-protect's own-files set, like policy.yaml.
    const own = ownFiles({ HOME: "/home/u", XDG_STATE_HOME: process.env["XDG_STATE_HOME"] }, [], null);
    assert.ok(walkCacheDir !== undefined && own.some((e) => walkCacheDir === e.path || walkCacheDir!.startsWith(`${e.path}/`)), `walk cache ${walkCacheDir} is write-protected`);
    assert.deepEqual(res.gitObjects, { repos: 1, blobs: 2, files: 2, packsRebuilt: 1, cacheHits: 0 });
    const deny = join(dir, "secret-twins", "git-object-denied");
    assert.equal(statSync(deny).mode & 0o777, 0, "the deny source is mode 000");
    const i = mut.launchPrefix.indexOf(PACK);
    assert.equal(mut.launchPrefix[i - 2], "--bind");
    assert.equal(mut.launchPrefix[i - 1], "/cache/p.pack");
    assert.equal(mut.launchPrefix[mut.launchPrefix.indexOf(LOOSE) - 1], deny);
    assert.equal(mut.launchPrefix[mut.launchPrefix.length - 1], "--");
    const doc = JSON.parse(readFileSync(mut.env["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
    const kinds = Object.fromEntries(doc.secrets.map((s: { path: string; kind?: string }) => [s.path, s.kind ?? "file"]));
    assert.deepEqual(kinds, { [SECRET]: "file", [PACK]: "object", [LOOSE]: "deny" });
  } finally {
    cleanup();
  }
});

test("FAIL-CLOSED: history that cannot be hidden refuses the launch; --best-effort proceeds loudly; --require-confinement wins", async () => {
  const boom = async (): Promise<never> => { throw new Error("pack too big"); };
  for (const [p, refuses] of [
    [plan(), true],
    [plan({ bestEffort: true }), false],
    [plan({ bestEffort: true, requireConfinement: true } as Partial<LaunchPlan>), true],
  ] as const) {
    const { dir, cleanup } = runDir();
    const logs: string[] = [];
    try {
      const run = applySecretTwins(p, dir, emptyMutation(), deps({ guardServesTwins: true, gitObjectTwins: boom, log: (m) => logs.push(m) }));
      if (refuses) {
        await assert.rejects(run, (e: Error) => e instanceof SecretConfinementError && /history.*pack too big/.test(e.message) && /committed bytes/.test(e.message));
      } else {
        const res = await run;
        assert.equal(res.posture, "confined", "the files themselves stay confined");
        assert.ok(logs.some((l) => /WARNING: .*history.*stay readable/.test(l)), logs.join("\n"));
      }
    } finally {
      cleanup();
    }
  }
});

test("--best-effort: a repository whose history cannot be hidden is named; the others keep their twins (never all-or-nothing)", async () => {
  for (const [p, wantContinue] of [[plan(), false], [plan({ bestEffort: true }), true]] as const) {
    const { dir, cleanup } = runDir();
    const logs: string[] = [];
    let asked: boolean | undefined;
    const partial = async (_paths: readonly string[], opts: { continueOnFailure?: boolean }) => {
      asked = opts.continueOnFailure;
      return { twins: [{ targetPath: "/w/.git/objects/pack/p.pack", twinPath: "/c/p.pack", kind: "object" as const }], repos: 1, blobs: 1, packsRebuilt: 0, cacheHits: 1, walks: { hit: 1, incremental: 0, full: 0 },
        failed: [{ root: "/home/u/linux", reason: "/home/u/linux: sanitizing its git history needs 5637 MiB of packs rebuilt, over the 1024 MiB cap (MANDU_GIT_TWIN_MAX_MB)" }] };
    };
    try {
      await applySecretTwins(p, dir, emptyMutation(), deps({ guardServesTwins: true, gitObjectTwins: partial as never, log: (m) => logs.push(m) }));
      assert.equal(asked, wantContinue, "only --best-effort keeps going past a repository");
      if (wantContinue) {
        assert.ok(logs.some((l) => /WARNING: .*could not be hidden .*5637 MiB.*the committed bytes in \/home\/u\/linux stay readable.*Every other repository's history stays hidden/.test(l)), logs.join("\n"));
      }
    } finally {
      cleanup();
    }
  }
});

/** A scratch HOME with a one-home layout: a workspace's AgentView and shadow
 *  repo, the event log, the DB, and a stray pre-one-home `mandu.db` at the
 *  top of the home. */
function oneHome(): { home: string; h: string; mh: string; av: string; repo: string; ws: string; cleanup: () => void } {
  const home = mkdtempSync(join(tmpdir(), "mandu-home-"));
  const mh = join(home, ".mandu");
  const wsDir = join(mh, "state", "workspaces", "proj-0123456789ab");
  mkdirSync(join(wsDir, "agentview"), { recursive: true });
  mkdirSync(join(wsDir, "repo.git"), { recursive: true });
  mkdirSync(join(mh, "events"), { recursive: true });
  writeFileSync(join(mh, "state", "mandu.db"), "");
  writeFileSync(join(mh, "mandu.db"), "");
  const h = realpathSync(home);
  return {
    home, h, mh: `${h}/.mandu`,
    av: `${h}/.mandu/state/workspaces/proj-0123456789ab/agentview`,
    repo: `${h}/.mandu/state/workspaces/proj-0123456789ab/repo.git`,
    ws: `${h}/.mandu/state/workspaces`,
    cleanup: () => rmSync(home, { recursive: true, force: true }),
  };
}

/** The head line of the SBPL rule whose filter list names `filter` (the
 *  renderer writes one filter per line), and that filter line's index; -1
 *  and null when absent. */
function sbRule(profile: string, filter: string): { head: string | null; at: number } {
  const lines = profile.split("\n");
  const at = lines.findIndex((l) => l.trim() === filter || l.trim() === `${filter})`);
  if (at < 0) return { head: null, at: -1 };
  let h = at;
  while (h > 0 && lines[h]!.startsWith("  ")) h--;
  return { head: lines[h]!, at };
}

const tmpfsOf = (argv: string[]): string[] => argv.flatMap((a, i) => (a === "--tmpfs" ? [argv[i + 1]!] : []));
const bindsOf = (argv: string[]): Array<[string, string]> => argv.flatMap((a, i) => (a === "--bind" ? [[argv[i + 1]!, argv[i + 2]!] as [string, string]] : []));
const noTwins = async () => ({ twins: [], repos: 0, blobs: 0, packsRebuilt: 0, cacheHits: 0, walks: { hit: 0, incremental: 0, full: 0 } });

test("the one home rule (on-disk-layout.md §4), `secrets` mode: the wrap masks the whole home, the guard denies it, nothing is carved out", async () => {
  const t = oneHome();
  const { dir, cleanup } = runDir();
  try {
    const mut = emptyMutation();
    const res = await applySecretTwins(plan({ integrity: false, cwd: "/w", humanCwd: "/w" }), dir, mut, deps({ home: t.home, gitObjectTwins: noTwins }));
    const doc = JSON.parse(readFileSync(mut.env["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
    const d = realpathSync(dir);
    assert.deepEqual(doc.denyPrefixes, [t.mh, `${d}/egress-mitm-ca/mandu-egress-ca.key`, `${d}/events`].sort(),
      "ONE prefix for the home (not its parts), the launch's own event dir, its CA key");
    assert.deepEqual(doc.denyExcept, [], "no carve-out in `secrets` mode");
    assert.deepEqual(res.ownStoresHidden, doc.denyPrefixes);
    assert.deepEqual(tmpfsOf(mut.launchPrefix), [t.mh], "the whole home masked (the event dir does not exist yet)");
    assert.ok(!bindsOf(mut.launchPrefix).some(([, to]) => to.startsWith(`${t.mh}/`)), "nothing bound back into the home");
    assert.equal(res.shadowMasked, t.ws);
    // The mask comes before the secret's bind (a twin is never under a later tmpfs).
    assert.ok(mut.launchPrefix.indexOf("--tmpfs") < mut.launchPrefix.indexOf(SECRET));
  } finally {
    cleanup();
    t.cleanup();
  }
});

test("the one home rule, `full` canary: the AgentView and its repo.git are bound back over the masked home and excepted from the guard's deny", async () => {
  const t = oneHome();
  try {
    for (const how of ["cwd", "viewMap"] as const) {
      const { dir, cleanup } = runDir();
      try {
        const mut = emptyMutation();
        const p = how === "cwd"
          ? plan({ integrity: true, cwd: t.av, humanCwd: "/w" })
          : plan({ integrity: true, cwd: "/w", humanCwd: "/w", viewMap: [{ human: "/w", agent: t.av }] });
        const res = await applySecretTwins(p, dir, mut, deps({ home: t.home, gitObjectTwins: noTwins }));
        const doc = JSON.parse(readFileSync(mut.env["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
        assert.ok(doc.denyPrefixes.includes(t.mh), `${how}: the home is still ONE deny prefix`);
        assert.deepEqual(doc.denyExcept, [t.av, t.repo], `${how}: the carve-outs, for the guard`);
        assert.deepEqual(tmpfsOf(mut.launchPrefix), [t.mh], `${how}: the whole home masked`);
        const argv = mut.launchPrefix;
        const at = (dst: string): number => argv.findIndex((a, i) => a === "--bind" && argv[i + 1] === dst && argv[i + 2] === dst);
        assert.ok(at(t.av) > argv.indexOf("--tmpfs") && at(t.repo) > argv.indexOf("--tmpfs"), `${how}: both bound back at their own path, after the mask: ${argv.join(" ")}`);
        assert.ok(at(t.av) < argv.indexOf(SECRET), `${how}: and before every secret-twin bind`);
        assert.ok(!bindsOf(argv).some(([, to]) => to === `${t.mh}/state/mandu.db` || to === `${t.mh}/mandu.db`), "no DB bind needed: it is under the mask");
        assert.equal(res.shadowMasked, undefined, "integrity on: no shadow notice");
      } finally {
        cleanup();
      }
    }
  } finally {
    t.cleanup();
  }
});

test("the one home rule: with no secret the guard alone denies the home; without a guard the wrap starts for it alone; macOS denies it by subpath with the carve-outs allowed after", async () => {
  const t = oneHome();
  try {
    {
      const { dir, cleanup } = runDir();
      try {
        const mut = emptyMutation();
        const res = await applySecretTwins(plan({ integrity: false, cwd: "/w", humanCwd: "/w" }), dir, mut, deps({
          home: t.home, arbiter: mockArbiter({ discoverSecrets: async () => [] }), guardServesTwins: true,
        }));
        assert.deepEqual(mut.launchPrefix, [], "no wrap for this alone");
        const doc = JSON.parse(readFileSync(mut.env["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
        assert.deepEqual(doc.secrets, []);
        assert.ok(doc.denyPrefixes.includes(t.mh));
        assert.deepEqual(doc.denyExcept, []);
        assert.match(res.status, /own stores \(its whole home: the placeholder table, the event log\) hidden/);
      } finally {
        cleanup();
      }
    }
    for (const integrity of [false, true]) {
      const r2 = runDir();
      try {
        const mut = emptyMutation();
        const res = await applySecretTwins(plan({ integrity, cwd: integrity ? t.av : "/w", humanCwd: "/w" }), r2.dir, mut, deps({
          home: t.home, arbiter: mockArbiter({ discoverSecrets: async () => [] }), guardServesTwins: false,
        }));
        assert.equal(mut.launchPrefix[0], "bwrap", "a wrap for the home alone");
        assert.equal(mut.launchPrefix.at(-1), "--");
        assert.deepEqual(tmpfsOf(mut.launchPrefix), [t.mh]);
        const back = bindsOf(mut.launchPrefix).filter(([from, to]) => from === to).map(([, to]) => to);
        assert.deepEqual(back, integrity ? [t.av, t.repo] : [], integrity ? "full: the carve-outs come back" : "secrets: nothing comes back");
        assert.equal(mut.env["MANDU_NET_GUARD_SECRETS"], undefined, "no guard to hand a policy to");
        assert.match(res.status, /^on: no secrets found to confine \(Mandu's own stores .* hidden\)$/);
        assert.equal(res.posture, "gated", "bind-only is still gated");
      } finally {
        r2.cleanup();
      }
    }
    for (const integrity of [false, true]) {
      const r3 = runDir();
      try {
        const mut = emptyMutation();
        const res = await applySecretTwins(plan({ integrity, cwd: integrity ? t.av : "/w", humanCwd: "/w" }), r3.dir, mut, deps({
          home: t.home, platform: "darwin", arbiter: mockArbiter({ discoverSecrets: async () => [] }),
        }));
        // The secret setup wraps nothing on macOS: the home and its carve-outs
        // ride in the ONE whole-agent profile (seatbelt-setup.ts).
        assert.deepEqual(mut.launchPrefix, []);
        assert.ok((res.seatbelt?.ownStores ?? []).includes(t.mh), JSON.stringify(res.seatbelt));
        assert.deepEqual(res.seatbelt?.carveOuts ?? [], integrity ? [t.av, t.repo] : []);
        const profile = seatbeltSecretProfile([], res.seatbelt?.ownStores ?? [], res.seatbelt?.carveOuts ?? [])!;
        const deny = sbRule(profile, `(subpath "${t.mh}")`);
        assert.equal(deny.head, "(deny file-read* file-write*", profile);
        const allow = sbRule(profile, `(subpath "${t.av}")`);
        if (integrity) assert.ok(allow.head === "(allow file-read* file-write*" && allow.at > deny.at, `full: the AgentView allowed after the deny:\n${profile}`);
        else assert.equal(allow.at, -1, "secrets: no carve-out");
      } finally {
        r3.cleanup();
      }
    }
    // An arbiter failure under --best-effort: the home needs no arbiter.
    const r4 = runDir();
    try {
      const mut = emptyMutation();
      const res = await applySecretTwins(plan({ integrity: false, bestEffort: true, cwd: "/w", humanCwd: "/w" }), r4.dir, mut, deps({
        home: t.home, guardServesTwins: true, arbiter: mockArbiter({ discoverSecrets: async () => { throw new Error("boom"); } }),
      }));
      assert.equal(res.posture, "gated");
      assert.equal(res.gap, "arbiter");
      const doc = JSON.parse(readFileSync(mut.env["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
      assert.ok(doc.denyPrefixes.includes(t.mh));
      assert.deepEqual(res.ownStoresHidden, doc.denyPrefixes);
    } finally {
      r4.cleanup();
    }
  } finally {
    t.cleanup();
  }
});

test("the one home rule: a launch whose working directory is inside the home, outside the carve-outs, is REFUSED (fail-closed)", async () => {
  const t = oneHome();
  try {
    const refused: Array<[string, Partial<LaunchPlan>]> = [
      ["the home itself", { integrity: false, cwd: t.mh, humanCwd: t.mh }],
      ["state/", { integrity: false, cwd: `${t.mh}/state`, humanCwd: `${t.mh}/state` }],
      ["the AgentView in `secrets` mode (no carve-out there)", { integrity: false, cwd: t.av, humanCwd: "/w" }],
      ["the launch's own directory in the home, the agent's elsewhere", { integrity: true, cwd: t.av, humanCwd: `${t.mh}/events` }],
    ];
    for (const [what, over] of refused) {
      const { dir, cleanup } = runDir();
      try {
        const mut = emptyMutation();
        await assert.rejects(
          applySecretTwins(plan(over), dir, mut, deps({ home: t.home, gitObjectTwins: noTwins })),
          (e: unknown) => e instanceof SecretConfinementError && /inside Mandu's home/.test(e.message) && /Launch from another directory/.test(e.message),
          what,
        );
        assert.deepEqual(mut.launchPrefix, [], `${what}: nothing launched`);
      } finally {
        cleanup();
      }
    }
    // A symlink into the home is the home.
    const link = join(t.h, "shortcut");
    symlinkSync(join(t.mh, "state"), link);
    assert.throws(() => ownStoresHidden(plan({ integrity: false, cwd: link, humanCwd: link }), t.home, {}, "/run/x", existsSync, undefined, null), SecretConfinementError);
    // The AgentView in `full`: the agent's own cwd, allowed.
    const own = ownStoresHidden(plan({ integrity: true, cwd: t.av, humanCwd: "/w" }), t.home, {}, "/run/x", existsSync, undefined, null);
    assert.deepEqual(own.carveOuts, [t.av, t.repo]);
  } finally {
    t.cleanup();
  }
});

test("ownStoresHidden: the home (MANDU_HOME and the default one), the launch's own event dir, the CA key; the retired overrides move nothing", () => {
  const t = oneHome();
  const scope = mkdtempSync(join(tmpdir(), "mandu-scope-"));
  try {
    mkdirSync(join(scope, "events"), { recursive: true });
    const s = realpathSync(scope);
    // The canonical spelling (t.h): on macOS the temp dir is a link, and the
    // CA dir does not exist yet, so it cannot be resolved.
    const env = { MANDU_NET_PROXY_MITM_CA_DIR: join(t.h, "ca") };
    const p = plan({ integrity: false, eventDir: join(scope, "events"), cwd: "/w", humanCwd: "/w" });
    const own = ownStoresHidden(p, t.home, env, scope, existsSync, undefined, null);
    assert.deepEqual(own.guard, [`${t.h}/ca/mandu-egress-ca.key`, t.mh, `${s}/events`].sort());
    assert.ok(!own.guard.some((g) => g.endsWith(".pem")), "the agent reads the certificate");
    assert.deepEqual(own.wrap, [t.mh, `${s}/events`].sort(), "only existing dirs are masked");
    assert.deepEqual(own.files, [], "no store file outside a mask yet");
    assert.deepEqual(own.carveOuts, []);
    // The stray pre-one-home DB at the top of the home and the object-twin
    // cache are under the one prefix; nothing names them apart.
    for (const q of [`${t.mh}/mandu.db`, `${t.mh}/state/mandu.db-wal`, `${t.mh}/cache/object-twins/k/p.pack`, `${t.mh}/new-file`]) {
      assert.ok(own.guard.some((g) => q.startsWith(`${g}/`)), q);
    }
    mkdirSync(join(t.home, "ca"));
    writeFileSync(join(t.home, "ca", "mandu-egress-ca.key"), "");
    assert.deepEqual(ownStoresHidden(p, t.home, env, scope, existsSync, undefined, null).files, [`${t.h}/ca/mandu-egress-ca.key`], "the CA key gets the unreadable bind");
    // The retired per-path overrides name nothing.
    const retired = { ...env, MANDU_SYMBOL_DB: "/o/arb.db", MANDU_EVENT_DIR: "/o/events", MANDU_VIEW_STATE: "/o/vs", MANDU_CONFIG: "/o/c.toml" };
    assert.deepEqual(ownStoresHidden(p, t.home, retired, scope, existsSync, undefined, null).guard, ownStoresHidden(p, t.home, env, scope, existsSync, undefined, null).guard);
    // MANDU_HOME moves the home; the default ~/.mandu stays hidden too.
    const moved = ownStoresHidden(p, "/home/u", { MANDU_HOME: "/data/mh" }, "/run/u/mandu/sid", () => false, (x) => x, null);
    assert.ok(moved.guard.includes("/data/mh") && moved.guard.includes("/home/u/.mandu"), moved.guard.join(" "));
  } finally {
    t.cleanup();
    rmSync(scope, { recursive: true, force: true });
  }
});

test("ownStoresHidden: nothing outside the one home, the CA key and the launch's own event dir (no old XDG place)", () => {
  const env = { XDG_CONFIG_HOME: "/x/config", XDG_STATE_HOME: "/x/state", XDG_CACHE_HOME: "/x/cache" };
  const allowed = (q: string): boolean =>
    q === "/home/u/.mandu" || q === "/run/u/mandu/sid/events" || q === "/run/u/mandu/sid/egress-mitm-ca/mandu-egress-ca.key";
  for (const integrity of [false, true]) {
    for (const e of [{}, env]) {
      const p = plan({ integrity, eventDir: "/run/u/mandu/sid/events", cwd: "/w", humanCwd: "/w" });
      const own = ownStoresHidden(p, "/home/u", e, "/run/u/mandu/sid", () => true, (x) => x, null);
      for (const q of [...own.guard, ...own.wrap, ...own.files]) assert.ok(allowed(q), `${q} is not a one-home location`);
    }
  }
});

test("the missing home is made 0700 before the launch hides it (the agent cannot make it)", async () => {
  const home = mkdtempSync(join(tmpdir(), "mandu-home-"));
  const { dir, cleanup } = runDir();
  try {
    const made: string[] = [];
    await applySecretTwins(plan({ cwd: "/w", humanCwd: "/w" }), dir, emptyMutation(), deps({ home, gitObjectTwins: noTwins, makeHome: (d) => made.push(d) }));
    assert.deepEqual(made, [join(home, ".mandu")]);
    made.length = 0;
    await applySecretTwins(plan({ cwd: "/w", humanCwd: "/w" }), dir, emptyMutation(), deps({ home, env: { MANDU_HOME: join(home, "mh") }, gitObjectTwins: noTwins, makeHome: (d) => made.push(d) }));
    assert.deepEqual(made, [join(home, "mh")], "the effective home");
    // The production default, for real.
    const mut = emptyMutation();
    await applySecretTwins(plan({ cwd: "/w", humanCwd: "/w" }), dir, mut, deps({ home, gitObjectTwins: noTwins, makeHome: undefined }));
    assert.equal(statSync(join(home, ".mandu")).mode & 0o777, 0o700);
    assert.deepEqual(tmpfsOf(mut.launchPrefix), [realpathSync(join(home, ".mandu"))], "and masked at once");
  } finally {
    cleanup();
    rmSync(home, { recursive: true, force: true });
  }
});

test("plan 14 §11.2 (c): a store in the home swapped for a symlink outside it, or a hard-linked symbol DB, REFUSES the launch (nothing launched); a sound home launches", async () => {
  const root = mkdtempSync(join(tmpdir(), "mandu-links-"));
  const home = join(root, "h");
  const mh = join(home, ".mandu");
  const planted = join(root, "planted");
  mkdirSync(join(mh, "state"), { recursive: true, mode: 0o700 });
  mkdirSync(planted, { mode: 0o700 });
  const { dir, cleanup } = runDir();
  const attempt = async (): Promise<{ mut: ReturnType<typeof emptyMutation>; err: unknown }> => {
    const mut = emptyMutation();
    try {
      await applySecretTwins(plan({ cwd: "/w", humanCwd: "/w" }), dir, mut, deps({ home, gitObjectTwins: noTwins }));
      return { mut, err: null };
    } catch (e) {
      return { mut, err: e };
    }
  };
  try {
    assert.equal((await attempt()).err, null, "a sound home launches");
    // the event log swapped for a symlink to a directory of the planter's
    symlinkSync(planted, join(mh, "events"));
    const a = await attempt();
    // MASTER: launched, with the guard and the wrap denying only the home
    assert.ok(a.err instanceof SecretConfinementError, String(a.err));
    assert.match((a.err as Error).message, /refusing to launch: Mandu's stores must lie inside its home/);
    assert.match((a.err as Error).message, /events resolves to .*planted/);
    assert.deepEqual(a.mut.launchPrefix, [], "nothing launched");
    rmSync(join(mh, "events"));
    // the symbol DB with a second name outside the home
    writeFileSync(join(mh, "state", "mandu.db"), "");
    linkSync(join(mh, "state", "mandu.db"), join(planted, "alias.db"));
    const b = await attempt();
    assert.ok(b.err instanceof SecretConfinementError && /mandu\.db has 2 hard links/.test(b.err.message), String(b.err));
  } finally {
    cleanup();
    rmSync(root, { recursive: true, force: true });
  }
});

test("write-protect takes the launch's carve-outs (launchHomeCarveOuts): `injection` keeps the AgentView writable, `full` its repo.git too, `secrets` nothing", () => {
  const t = oneHome();
  try {
    const cases: Array<[string, { confidentiality: boolean; integrity: boolean }, string[]]> = [
      ["secrets", { confidentiality: true, integrity: false }, []],
      ["injection", { confidentiality: false, integrity: true }, [t.av]],
      ["full", { confidentiality: true, integrity: true }, [t.av, t.repo]],
    ];
    for (const [mode, axes, want] of cases) {
      const p = plan({ ...axes, effectiveAxes: axes, cwd: t.av, humanCwd: "/w" } as Partial<LaunchPlan>);
      const carve = launchHomeCarveOuts(p, t.home, {});
      assert.deepEqual(carve, want, mode);
      const home = ownFiles({ HOME: t.home }, carve, null)[0]!;
      assert.equal(home.path, join(t.home, ".mandu"));
      assert.deepEqual(home.except ?? [], want, `${mode}: the write-protect home entry spares exactly these`);
    }
    // A carve-out that does not exist is not named (nothing to bind or open).
    rmSync(t.repo, { recursive: true });
    assert.deepEqual(launchHomeCarveOuts(plan({ confidentiality: true, integrity: true, cwd: t.av }), t.home, {}), [t.av]);
  } finally {
    t.cleanup();
  }
});

// ── sandbox-security-review-2026-09-28 finding 7: the bind alone is `gated` ──
test("finding 7: bwrap + userns but no guard ⇒ GATED (no-guard) with the bind STILL up; --require-confinement refuses; --no-net-guard names guard-off", async () => {
  const { dir, cleanup } = runDir();
  try {
    const logs: string[] = [];
    const mut = emptyMutation();
    const res = await applySecretTwins(plan(), dir, mut, deps({ log: (m) => logs.push(m) }));
    assert.deepEqual({ posture: res.posture, gap: res.gap }, { posture: "gated", gap: "no-guard" });
    assert.equal(res.confined.length, 1, "the partial layer covers the file found at launch");
    assert.equal(mut.launchPrefix[0], "bwrap", "the bind mount still goes up");
    assert.match(res.status, /^gated: 1 behind placeholders \(mount layer only, no guard\)/);
    const notice = logs.find((l) => l.startsWith("mandu: secrets are GATED, not confined"));
    assert.ok(notice, logs.join("\n"));
    assert.match(notice!, /file guard \(mandu-net-guard\) is not available/);
    assert.match(notice!, /mount layer still puts a placeholder/);
    assert.ok(!logs.some((l) => /absent from the agent's world/.test(l)), "gated never borrows the confined claim");

    // the user turned the guard off: same posture, the gap says so
    const off = await applySecretTwins(plan({ netGuard: false }), dir, emptyMutation(), deps());
    assert.deepEqual({ posture: off.posture, gap: off.gap }, { posture: "gated", gap: "guard-off" });

    // strict: refuses before anything is registered or bound
    for (const netGuard of [undefined, false]) {
      let registered = 0;
      const m = emptyMutation();
      await assert.rejects(
        applySecretTwins(plan({ requireConfinement: true, netGuard } as Partial<LaunchPlan>), dir, m, deps({
          arbiter: mockArbiter({ registerSecret: async () => { registered++; return { symbol: SYM, reason: "registered" }; } }),
        })),
        (e: Error) => e instanceof SecretConfinementError && /--require-confinement is set/.test(e.message) &&
          (netGuard === false ? /turned off/ : /not available/).test(e.message) && /replaces while the agent runs/.test(e.message),
      );
      assert.equal(registered, 0);
      assert.deepEqual(m.launchPrefix, []);
    }
    // with the guard: confined, as before
    const both = await applySecretTwins(plan({ requireConfinement: true } as Partial<LaunchPlan>), dir, emptyMutation(), deps({ guardServesTwins: true }));
    assert.equal(both.posture, "confined");
    assert.equal(both.gap, undefined);
  } finally {
    cleanup();
  }
});

// ── finding 14: CVE-2026-87766 probe, WARN ONLY ──
test("finding 14: a bwrap that follows a symlinked mount destination is one WARNING line when the bind is used; never a refusal, never a posture change", async () => {
  const { dir, cleanup } = runDir();
  try {
    for (const verdict of ["vulnerable", "fixed", "unknown", "version-affected"] as const) {
      for (const guard of [true, false]) {
        const logs: string[] = [];
        const asked: string[] = [];
        const mut = emptyMutation();
        const res = await applySecretTwins(plan(), dir, mut, deps({
          guardServesTwins: guard,
          wrapBwrap: "/usr/lib/mandu/bin/bwrap",
          symlinkProbe: (bwrap) => { asked.push(bwrap); return { bwrap, verdict, ...(verdict === "fixed" ? {} : { version: "0.11.1" }) }; },
          log: (m) => logs.push(m),
        }));
        assert.deepEqual(asked, ["/usr/lib/mandu/bin/bwrap"], "the wrap's own bwrap is probed, once");
        assert.equal(res.posture, guard ? "confined" : "gated", "the probe never changes the posture");
        const warns = logs.filter((l) => /CVE-2026-87766/.test(l));
        assert.equal(warns.length, verdict === "vulnerable" || verdict === "version-affected" ? 1 : 0, `${verdict}: ${logs.join("\n")}`);
        if (verdict === "vulnerable") assert.match(warns[0]!, /^WARNING: mandu: bubblewrap on this host follows symlinks while it sets up a sandbox \(CVE-2026-87766\) \(\/usr\/lib\/mandu\/bin\/bwrap, version 0\.11\.1\)/);
        if (verdict === "version-affected") assert.match(warns[0]!, /^WARNING: mandu: bubblewrap 0\.11\.1 \(\/usr\/lib\/mandu\/bin\/bwrap\) reports a version older than 0\.12\.0, the first upstream release with the fix for CVE-2026-87766/);
        // Mandu's own copy: the fix names mandu setup (the copy does not follow the package)
        if (warns.length === 1) assert.match(warns[0]!, /then run mandu setup/);
      }
    }
    // no bind (guard only): the probe is not run
    let asked = 0;
    await applySecretTwins(plan({ secretBind: false }), dir, emptyMutation(), deps({ guardServesTwins: true, symlinkProbe: (b) => { asked++; return { bwrap: b, verdict: "vulnerable" }; } }));
    await applySecretTwins(plan(), dir, emptyMutation(), deps({ usernsOk: () => false, guardServesTwins: true, symlinkProbe: (b) => { asked++; return { bwrap: b, verdict: "vulnerable" }; } }));
    assert.equal(asked, 0);
  } finally {
    cleanup();
  }
});

// ── The discovery prefetch (launch time, 2026-09-28) ────────────────────────

import { prefetchDiscovery, withPrefetchedDiscovery } from "../../src/secret-setup.js";

test("withPrefetchedDiscovery serves the FIRST call with the prefetch's exact arguments once; every other call asks the arbiter", async () => {
  const live: string[][] = [];
  const inner = mockArbiter({ discoverSecrets: async (roots: string[]) => { live.push(roots); return [{ path: `/live/${roots.join("+")}` }]; } });
  const prefetch = prefetchDiscovery(inner, ["/h", "/w"], "/h", { stateBase: "/s" });
  assert.equal(live.length, 1, "the prefetch asked once, up front");
  const a = withPrefetchedDiscovery(inner, prefetch);
  assert.deepEqual(await a.discoverSecrets(["/h", "/w"], "/h", { stateBase: "/s" }), [{ path: "/live//h+/w" }]);
  assert.equal(live.length, 1, "served from the prefetch");
  await a.discoverSecrets(["/h", "/w"], "/h", { stateBase: "/s" });
  assert.equal(live.length, 2, "a second identical call asks live");
  await a.discoverSecrets(["/h"], "/h", { stateBase: "/s" });
  await a.discoverSecrets(["/h", "/w"], "/h", { stateBase: "/other" });
  assert.equal(live.length, 4, "other roots or another state base ask live");
  // The moved caches are part of the key: a prefetch made under another
  // CARGO_HOME is not served for this one.
  const withCache = withPrefetchedDiscovery(inner, prefetchDiscovery(inner, ["/h"], "/h", { stateBase: "/s", cacheEnv: { CARGO_HOME: "/c" } }));
  await withCache.discoverSecrets(["/h"], "/h", { stateBase: "/s", cacheEnv: { CARGO_HOME: "/other" } });
  assert.equal(live.length, 6, "another moved cache asks live");
  await withCache.discoverSecrets(["/h"], "/h", { stateBase: "/s", cacheEnv: { CARGO_HOME: "/c" } });
  assert.equal(live.length, 6, "the same moved cache is served from the prefetch");
  assert.equal(withPrefetchedDiscovery(inner, undefined), inner, "no prefetch: the arbiter itself");
  // The login keying is part of the key too (secret-discovery.md §1.10): a
  // walk asked for another agent keeps other logins raw.
  const asClaude = withPrefetchedDiscovery(inner, prefetchDiscovery(inner, ["/h"], "/h", { stateBase: "/s", target: "claude", ullmBinary: "claude" }));
  await asClaude.discoverSecrets(["/h"], "/h", { stateBase: "/s", target: "codex", ullmBinary: "codex" });
  assert.equal(live.length, 8, "another agent asks live");
  await asClaude.discoverSecrets(["/h"], "/h", { stateBase: "/s", target: "claude", ullmBinary: "claude" });
  assert.equal(live.length, 8, "the same agent is served from the prefetch");
});

import { launchDiscoverOptions, loginEnvOf, LOGIN_ENV } from "../../src/secret-setup.js";

test("launchDiscoverOptions carries the launch's agent, the AI helper's CLI and the login variables (absolute paths only); discoverWireOpts sends them", () => {
  const env = { HOME: "/home/u", CODEX_HOME: "/data/codex", CLAUDE_CONFIG_DIR: "rel/dir", XDG_DATA_HOME: "", OPENAI_API_KEY: "sk-x", MANDU_HOME: "/home/u/.mandu" };
  assert.deepEqual([...LOGIN_ENV].sort(), ["CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_DATA_HOME"]);
  assert.deepEqual(loginEnvOf(env), { CODEX_HOME: "/data/codex" });
  const o = launchDiscoverOptions(env, "/home/u", { target: "opencode", ullmBinary: "claude" });
  assert.equal(o.target, "opencode");
  assert.equal(o.ullmBinary, "claude");
  assert.deepEqual(o.loginEnv, { CODEX_HOME: "/data/codex" });
  const wire = discoverWireOpts(o);
  assert.equal(wire["target"], "opencode");
  assert.equal(wire["ullmBinary"], "claude");
  assert.deepEqual(wire["loginEnv"], { CODEX_HOME: "/data/codex" });
  assert.ok(!JSON.stringify(wire).includes("sk-x"), "no key leaves the launcher");
  // No launch named (a caller that is no launch): no keying on the wire, so
  // the arbiter keeps every agent's login raw, as before.
  const none = launchDiscoverOptions({ HOME: "/home/u" }, "/home/u");
  assert.equal(none.target, undefined);
  assert.equal(discoverWireOpts(none)["target"], undefined);
  assert.equal(launchDiscoverOptions({}, "/home/u", { target: "codex" }).ullmBinary, undefined, "API mode: no helper CLI");
});

test("withPrefetchedDiscovery forwards every other method, a class's prototype methods included", async () => {
  class ClassArbiter implements SecretArbiter {
    private readonly tag = "class";
    async discoverSecrets() { return [{ path: "/x" }]; }
    async registerSecret(path: string) { return { symbol: `${this.tag}:${path}`, reason: "registered" }; }
    async protectPaths() { return { paths: [this.tag] }; }
  }
  const inner = new ClassArbiter();
  const a = withPrefetchedDiscovery(inner, prefetchDiscovery(inner, ["/h"], "/h", {}));
  assert.deepEqual(await a.registerSecret("/p"), { symbol: "class:/p", reason: "registered" });
  assert.deepEqual(await a.protectPaths!(), { paths: ["class"] });
});

test("a prefetch that fails is held for whoever awaits it: no unhandled rejection, and the secret setup refuses (fail-closed)", async () => {
  const unhandled: unknown[] = [];
  const on = (e: unknown) => { unhandled.push(e); };
  process.on("unhandledRejection", on);
  const { dir, cleanup } = runDir();
  try {
    const inner = mockArbiter({ discoverSecrets: async () => { throw new Error("arbiter gone"); } });
    const prefetch = prefetchDiscovery(inner, ["/home/u"], "/home/u", {});
    await new Promise((r) => setTimeout(r, 10));
    await assert.rejects(
      applySecretTwins(plan(), dir, emptyMutation(), deps({ arbiter: withPrefetchedDiscovery(inner, prefetch) })),
      /could not discover secrets \(arbiter gone\)/,
    );
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(unhandled, []);
  } finally {
    process.off("unhandledRejection", on);
    cleanup();
  }
});

// ── protection-modes.md §8: the refusals speak the mode vocabulary ──

test("every secret-setup refusal names `--mode off` as the way out, never the --[no-]confidentiality axis flag", async () => {
  const broken = mockArbiter({ discoverSecrets: async () => { throw new Error("boom"); } });
  const boom = async (): Promise<never> => { throw new Error("pack too big"); };
  const winCred = "/mnt/c/Users/alice/.aws/credentials";
  const wslArbiter = mockArbiter({
    discoverSecrets: async (_roots, home) => (home === "/mnt/c/Users/alice" ? [{ path: winCred }] : [{ path: SECRET }]),
  });
  // One case per SecretConfinementError throw site in applySecretTwins.
  const cases: Array<[string, Partial<LaunchPlan>, Partial<SecretSetupDeps>]> = [
    ["host gap, --require-confinement", { requireConfinement: true }, { usernsOk: () => false }],
    ["no guard, --require-confinement", { requireConfinement: true }, {}],
    ["arbiter failure", {}, { arbiter: broken }],
    ["arbiter failure, --require-confinement", { requireConfinement: true }, { arbiter: broken, guardServesTwins: true }],
    ["WSL credentials without the guard", {}, { onWsl: true, pathExists: () => false, windowsProfiles: ["/mnt/c/Users/alice"], arbiter: wslArbiter }],
    ["history cannot be hidden", {}, { guardServesTwins: true, gitObjectTwins: boom }],
    ["history cannot be hidden, --require-confinement", { requireConfinement: true }, { guardServesTwins: true, gitObjectTwins: boom }],
  ];
  for (const [name, p, d] of cases) {
    const { dir, cleanup } = runDir();
    try {
      await assert.rejects(applySecretTwins(plan(p), dir, emptyMutation(), deps(d)), (e: unknown) => {
        assert.ok(e instanceof SecretConfinementError, name);
        assert.match(e.message, /turn secret protection off\s+for this launch(: | \()--mode off\b/, `${name}: ${e.message}`);
        assert.doesNotMatch(e.message, /--(no-)?confidentiality/, `${name}: ${e.message}`);
        return true;
      }, name);
    } finally {
      cleanup();
    }
  }
});

test("the arbiter-failure refusal names the modes that protect secrets, not the axis flag", async () => {
  const { dir, cleanup } = runDir();
  try {
    const broken = mockArbiter({ discoverSecrets: async () => { throw new Error("boom"); } });
    await assert.rejects(applySecretTwins(plan(), dir, emptyMutation(), deps({ arbiter: broken })),
      /mandu: this mode protects your secrets \(modes secrets and full\), but /);
  } finally {
    cleanup();
  }
});

test("ownStoresHidden: a scratch HOME still hides the account's own ~/.mandu", () => {
  const own = ownStoresHidden(plan({ cwd: "/w", humanCwd: "/w" }), "/tmp/leg/home", {}, "/run/u/mandu/sid", () => true, (x) => x, "/home/real");
  assert.ok(own.guard.includes("/tmp/leg/home/.mandu"), JSON.stringify(own.guard));
  assert.ok(own.guard.includes("/home/real/.mandu"), "the account's own home is denied too");
  assert.ok(own.wrap.includes("/home/real/.mandu"), "and masked");
});

// ── The arbiter's human plane (arbiter-human-plane.md §5) ────────────────────

test("human plane, linux: the twin wrap puts a tmpfs over each existing human-plane dir, after the home mask and before every secret bind", async () => {
  const t = oneHome();
  const { dir, cleanup } = runDir();
  const human = mkdtempSync(join(tmpdir(), "mandu-human-"));
  try {
    const mut = emptyMutation();
    await applySecretTwins(
      plan({ integrity: false, cwd: "/w", humanCwd: "/w", humanPlaneDirs: [human, "/nonexistent/mandu/human"] }),
      dir, mut, deps({ home: t.home, gitObjectTwins: noTwins }),
    );
    const real = realpathSync(human);
    assert.deepEqual(tmpfsOf(mut.launchPrefix), [t.mh, real], "the home, then the human plane (an absent dir gets no mount point)");
    const at = mut.launchPrefix.findIndex((a, i) => a === "--tmpfs" && mut.launchPrefix[i + 1] === real);
    assert.ok(at > mut.launchPrefix.indexOf("--tmpfs"), "after the home mask");
    assert.ok(!bindsOf(mut.launchPrefix).some(([, to]) => to === real || to.startsWith(`${real}/`)), "nothing is ever bound into it");
    assert.ok(at < mut.launchPrefix.indexOf(SECRET), "before the secret's twin bind");
  } finally {
    cleanup();
    t.cleanup();
    rmSync(human, { recursive: true, force: true });
  }
});

test("human plane, linux: no humanPlaneDirs on the plan → the wrap is unchanged", async () => {
  const t = oneHome();
  const { dir, cleanup } = runDir();
  try {
    const mut = emptyMutation();
    await applySecretTwins(plan({ integrity: false, cwd: "/w", humanCwd: "/w" }), dir, mut, deps({ home: t.home, gitObjectTwins: noTwins }));
    assert.deepEqual(tmpfsOf(mut.launchPrefix), [t.mh]);
  } finally {
    cleanup();
    t.cleanup();
  }
});

test("human plane, macOS: the secret setup wraps nothing; the profile of its record denies connect and reads under each human-plane dir, after every allow", async () => {
  const { dir, cleanup } = runDir();
  try {
    const mut = emptyMutation();
    const res = await applySecretTwins(plan({ humanPlaneDirs: ["/nonexistent-mandu-x/human"] }), dir, mut, deps({ platform: "darwin" }));
    // The human plane reaches the ONE profile from the plan (run.ts →
    // seatbelt-setup.ts), not through the secret setup.
    assert.deepEqual(mut.launchPrefix, []);
    const profile = seatbeltSecretProfile(res.confined, res.seatbelt?.ownStores ?? [], res.seatbelt?.carveOuts ?? [], ["/nonexistent-mandu-x/human"])!;
    const lines = profile.trim().split("\n");
    const net = lines.findIndex((l) => l.includes('(remote unix-socket (subpath "/nonexistent-mandu-x/human"))'));
    assert.ok(net > 0, profile);
    assert.ok(lines.some((l) => l.includes('(subpath "/nonexistent-mandu-x/human")') && lines[lines.indexOf(l) - 1]?.startsWith("(deny file-read* file-write*")), profile);
    assert.ok(!lines.slice(net).some((l) => l.startsWith("(allow")), "no allow after the human-plane denies (last match wins)");
  } finally {
    cleanup();
  }
});

// ── Plan 14 §8.1/§8.2: labelled paths gone from the work tree, blob locks ────

const LOCKS = {
  axis: true,
  blobs: [{ id: `sha1:${"a".repeat(40)}`, level: "no-model" }],
  labels: [{ path: "/w/repo/deploy/id_rsa", level: "no-model", recursive: true }, { path: "/w/repo/README.md", level: "public", recursive: true }],
};

test("no file to confine, but the law locks history: the object twins get the labels, the blob locks and the workspace, and join the guard's policy or the wrap", async () => {
  for (const guard of [true, false]) {
    const { dir, cleanup } = runDir();
    try {
      const mut = emptyMutation();
      let seen: { paths: string[]; labels?: unknown; blobLocks?: unknown; repoHints?: unknown } | undefined;
      const res = await applySecretTwins(plan(), dir, mut, deps({
        guardServesTwins: guard,
        workspaceRoots: ["/w/repo"],
        arbiter: mockArbiter({ discoverSecrets: async () => [], gitHistoryLocks: async () => LOCKS }),
        gitObjectTwins: async (paths, opts) => {
          seen = { paths, labels: opts.labels, blobLocks: opts.blobLocks, repoHints: opts.repoHints };
          return { twins: [{ targetPath: PACK, twinPath: "/cache/p.pack", kind: "object" }, { targetPath: LOOSE, twinPath: opts.denyFile, kind: "deny" }], repos: 1, blobs: 2, packsRebuilt: 1, cacheHits: 0, walks: { hit: 0, incremental: 0, full: 1 } };
        },
      }));
      assert.deepEqual(seen, { paths: [], labels: LOCKS.labels, blobLocks: [LOCKS.blobs[0]!.id], repoHints: ["/w/repo"] });
      assert.deepEqual(res.gitObjects, { repos: 1, blobs: 2, files: 2, packsRebuilt: 1, cacheHits: 0 });
      assert.match(res.status, /^on: no secrets found to confine \(.*git history hidden in 1 repo\)$/);
      if (guard) {
        const doc = JSON.parse(readFileSync(mut.env["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
        assert.deepEqual(doc.secrets.map((s: { path: string; kind: string }) => [s.path, s.kind]), [[PACK, "object"], [LOOSE, "deny"]]);
        // Both layers where the host can bind: under the guard alone git
        // rejects the twinned pack (its stat size is the real one's).
        const i = mut.launchPrefix.indexOf(PACK);
        assert.deepEqual(mut.launchPrefix.slice(i - 2, i), ["--bind", "/cache/p.pack"], "the mount layer binds the twin too");
        assert.equal(mut.env[GUARD_STAT_TWINS_ENV], undefined, "the bind answers a stat of the pack: no stat trap");
      } else {
        assert.equal(mut.launchPrefix[0], "bwrap", "the wrap starts for the history alone");
        const i = mut.launchPrefix.indexOf(PACK);
        assert.deepEqual(mut.launchPrefix.slice(i - 2, i), ["--bind", "/cache/p.pack"]);
        assert.equal(mut.launchPrefix[mut.launchPrefix.indexOf(LOOSE) - 1], join(dir, "secret-twins", "git-object-denied"));
      }
    } finally {
      cleanup();
    }
  }
});

test("plan 14 §11.1: the launch names its workspace to gitHistoryLocks and hands the arbiter's resolved repositories to the object twins; a malformed entry is dropped (walked here)", async () => {
  const { dir, cleanup } = runDir();
  try {
    const good = { root: "/w/repo", format: "sha1" as const, key: "k".repeat(64), blobs: ["b".repeat(40)] };
    const answer = {
      ...LOCKS,
      lockedSet: { sha1: ["a".repeat(40), "b".repeat(40)], sha256: [] }, complete: true, pending: [],
      repos: [good, { root: "/w/bad", format: "sha1", key: "x", blobs: ["not-hex"] }, { root: "rel", format: "sha1", key: "x", blobs: [] }],
    };
    let asked: readonly string[] | undefined;
    let resolved: ReadonlyMap<string, { key: string; blobs: readonly string[] }> | undefined;
    await applySecretTwins(plan(), dir, emptyMutation(), deps({
      guardServesTwins: true,
      workspaceRoots: ["/w/repo"],
      arbiter: mockArbiter({ discoverSecrets: async () => [], gitHistoryLocks: async (roots?: readonly string[]) => { asked = roots; return answer as never; } }),
      gitObjectTwins: async (_paths, opts) => { resolved = opts.resolved; return { twins: [], repos: 0, blobs: 0, packsRebuilt: 0, cacheHits: 0, walks: { hit: 0, incremental: 0, full: 0 } }; },
    }));
    assert.deepEqual(asked, ["/w/repo"], "the workspace is registered with the arbiter");
    assert.deepEqual([...(resolved ?? new Map())], [["/w/repo", { key: good.key, blobs: good.blobs }]], "only the well-formed entry stands in for a walk");
    assert.deepEqual(asGitHistoryLocks(LOCKS), LOCKS, "an older arbiter's answer (no repos) reads as before");
  } finally {
    cleanup();
  }
});

test("plan 14 §11.1 R3: the arbiter's prepared repositories go to preparedCopyTwins with the guard's set, the launch's own roots skipped; their twins join the guard's policy; the global set reaches the launch's own twins", async () => {
  const { dir, cleanup } = runDir();
  try {
    const OTHER_PACK = "/o/repo/.git/objects/pack/pack-1.pack";
    const answer = {
      ...LOCKS,
      lockedSet: { sha1: ["a".repeat(40), "b".repeat(40)], sha256: [] }, complete: true, pending: [], repos: [],
      prepared: [{ root: "/o/repo", format: "sha1" }, { root: "rel", format: "sha1" }, { root: "/x", format: "md5" }, null],
    };
    let globalLocked: readonly string[] | undefined;
    let asked: { repos: unknown; lockedIds: readonly string[]; skipRoots: string[]; skipTargets: string[] } | undefined;
    const logs: string[] = [];
    const mut = emptyMutation();
    const res = await applySecretTwins(plan(), dir, mut, deps({
      guardServesTwins: true, nestingOk: () => false, log: (m) => logs.push(m),
      workspaceRoots: ["/w/repo"],
      arbiter: mockArbiter({ discoverSecrets: async () => [], gitHistoryLocks: async () => answer as never }),
      gitObjectTwins: async (_paths, opts) => {
        globalLocked = opts.globalLocked;
        return { twins: [{ targetPath: PACK, twinPath: "/cache/p.pack", kind: "object" }], repos: 1, blobs: 1, packsRebuilt: 0, cacheHits: 1, walks: { hit: 0, incremental: 0, full: 0 }, roots: ["/w/repo"], lockedIds: [] };
      },
      preparedCopies: async (repos, opts) => {
        asked = { repos, lockedIds: opts.lockedIds, skipRoots: [...(opts.skipRoots ?? [])], skipTargets: [...(opts.skipTargets ?? [])] };
        return { twins: [{ targetPath: OTHER_PACK, twinPath: "/cache/k/p.pack", kind: "object" }], bound: ["/o/repo"], notReady: [{ root: "/n/repo", reason: "its sanitized copies are not prepared yet" }], overCap: [] };
      },
    }));
    assert.deepEqual(globalLocked, [`sha1:${"a".repeat(40)}`, `sha1:${"b".repeat(40)}`], "the launch's own twins exclude the global set too");
    assert.deepEqual(asked, {
      repos: [{ root: "/o/repo", format: "sha1" }],
      lockedIds: [`sha1:${"a".repeat(40)}`, `sha1:${"b".repeat(40)}`],
      skipRoots: ["/w/repo"], skipTargets: [PACK],
    }, "only the well-formed prepared entries, the guard's set, the launch's own repositories skipped");
    const doc = JSON.parse(readFileSync(mut.env["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
    assert.deepEqual(doc.secrets.map((s: { path: string; kind: string }) => [s.path, s.kind]), [[PACK, "object"], [OTHER_PACK, "object"]], "the guard sees the prepared copy as prepared");
    assert.equal(mut.env[GUARD_STAT_TWINS_ENV], "1");
    assert.deepEqual(res.gitObjects, { repos: 2, blobs: 1, files: 2, packsRebuilt: 0, cacheHits: 1 });
    assert.ok(logs.some((l) => /prepared ahead of time served for 1 other repository/.test(l)), logs.join("\n"));
    assert.ok(logs.some((l) => /1 repository holding a locked key has no ready copy this launch/.test(l)), logs.join("\n"));
  } finally {
    cleanup();
  }
});

test("the same locks beside a confined file: asked once, with the confined file's real path", async () => {
  const { dir, cleanup } = runDir();
  try {
    let seen: { paths: string[]; blobLocks?: readonly string[] } | undefined;
    await applySecretTwins(plan(), dir, emptyMutation(), deps({
      guardServesTwins: true,
      arbiter: mockArbiter({ gitHistoryLocks: async () => LOCKS }),
      gitObjectTwins: async (paths, opts) => { seen = { paths, blobLocks: opts.blobLocks }; return { twins: [], repos: 0, blobs: 0, packsRebuilt: 0, cacheHits: 0, walks: { hit: 0, incremental: 0, full: 0 } }; },
    }));
    assert.deepEqual(seen, { paths: [SECRET], blobLocks: [LOCKS.blobs[0]!.id] });
  } finally {
    cleanup();
  }
});

test("FAIL-CLOSED: history locks the arbiter cannot tell refuse the launch; --best-effort still hides the confined files' history; an older arbiter is said and proceeds; a malformed answer refuses", async () => {
  const cases: Array<[string, Partial<LaunchPlan>, () => Promise<unknown>, "refuse" | "warn" | "old"]> = [
    ["timeout", {}, async () => { throw new Error("arbiter gitHistoryLocks timed out after 5000ms — fail closed"); }, "refuse"],
    ["timeout, --best-effort", { bestEffort: true }, async () => { throw new Error("arbiter gitHistoryLocks timed out"); }, "warn"],
    ["malformed", {}, async () => ({ symbol: SYM, reason: "registered" }), "refuse"],
    ["older arbiter", {}, async () => { throw new Error("unknown op: gitHistoryLocks"); }, "old"],
  ];
  for (const [name, over, locks, want] of cases) {
    const { dir, cleanup } = runDir();
    const logs: string[] = [];
    let asked: readonly string[] | undefined;
    try {
      const run = applySecretTwins(plan(over), dir, emptyMutation(), deps({
        guardServesTwins: true, log: (m) => logs.push(m),
        arbiter: mockArbiter({ gitHistoryLocks: locks as never }),
        gitObjectTwins: async (paths, opts) => { asked = [...paths, ...(opts.blobLocks ?? [])]; return { twins: [], repos: 0, blobs: 0, packsRebuilt: 0, cacheHits: 0, walks: { hit: 0, incremental: 0, full: 0 } }; },
      }));
      if (want === "refuse") {
        await assert.rejects(run, (e: Error) => e instanceof SecretConfinementError && /could not tell which git history to hide/.test(e.message), name);
        continue;
      }
      await run;
      assert.deepEqual(asked, [SECRET], `${name}: the confined file's history is still hidden, with no lock`);
      assert.ok(logs.some((l) => (want === "old" ? /predates git-history locks/ : /WARNING: .*could not tell which git history to hide/).test(l)), `${name}: ${logs.join("\n")}`);
    } finally {
      cleanup();
    }
  }
});

test("no file to confine, history locked, a host whose bubblewrap forbids nesting: the guard alone serves the object twins (no wrap)", async () => {
  const { dir, cleanup } = runDir();
  try {
    const mut = emptyMutation();
    await applySecretTwins(plan(), dir, mut, deps({
      guardServesTwins: true, nestingOk: () => false,
      arbiter: mockArbiter({ discoverSecrets: async () => [], gitHistoryLocks: async () => LOCKS }),
      gitObjectTwins: async (_paths, opts) => ({ twins: [{ targetPath: PACK, twinPath: "/cache/p.pack", kind: "object" }, { targetPath: LOOSE, twinPath: opts.denyFile, kind: "deny" }], repos: 1, blobs: 2, packsRebuilt: 0, cacheHits: 1, walks: { hit: 1, incremental: 0, full: 0 } }),
    }));
    assert.deepEqual(mut.launchPrefix, [], "no wrap the agent's own sandboxes could not nest in");
    const doc = JSON.parse(readFileSync(mut.env["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
    assert.deepEqual(doc.secrets.map((s: { path: string }) => s.path), [PACK, LOOSE]);
    // §7.2a: git stats the real pack by path; the guard answers the twin's
    // size, or git drops the whole sanitized pack.
    assert.equal(mut.env[GUARD_STAT_TWINS_ENV], "1");
  } finally {
    cleanup();
  }
});

test("§7.2a: the stat trap goes on exactly where the guard serves twins with no bind over them", async () => {
  const objectTwins = async (_paths: readonly string[], opts: { denyFile: string }) => ({ twins: [{ targetPath: PACK, twinPath: "/cache/p.pack", kind: "object" as const }, { targetPath: LOOSE, twinPath: opts.denyFile, kind: "deny" as const }], repos: 1, blobs: 2, packsRebuilt: 0, cacheHits: 1, walks: { hit: 1, incremental: 0, full: 0 } });
  const none = async () => ({ twins: [], repos: 0, blobs: 0, packsRebuilt: 0, cacheHits: 0, walks: { hit: 0, incremental: 0, full: 0 } });
  const noFile = mockArbiter({ discoverSecrets: async () => [], gitHistoryLocks: async () => LOCKS });
  const cases: Array<[string, Partial<LaunchPlan>, Record<string, unknown>, "1" | undefined]> = [
    ["history only, --no-secret-bind", { secretBind: false }, { arbiter: noFile, gitObjectTwins: objectTwins }, "1"],
    ["history only, bwrap forbids nesting", {}, { arbiter: noFile, gitObjectTwins: objectTwins, nestingOk: () => false }, "1"],
    ["history only, the bind is up", {}, { arbiter: noFile, gitObjectTwins: objectTwins, nestingOk: () => true }, undefined],
    ["nothing twinned at all", { secretBind: false }, { arbiter: noFile, gitObjectTwins: none }, undefined],
    ["a confined file, --no-secret-bind", { secretBind: false }, { gitObjectTwins: none }, "1"],
    ["a confined file, the bind is up", {}, { gitObjectTwins: none, nestingOk: () => true }, undefined],
  ];
  for (const [name, over, extra, want] of cases) {
    const { dir, cleanup } = runDir();
    try {
      const mut = emptyMutation();
      await applySecretTwins(plan(over), dir, mut, deps({ guardServesTwins: true, ...extra } as never));
      assert.equal(mut.env[GUARD_STAT_TWINS_ENV], want, name);
    } finally {
      cleanup();
    }
  }
});

// ── Plan 14 §11.1 R4: the locked set for the guard's backstop ─────────────────

test("R4: the guard's policy carries the locked set (blob locks above public, the walks' resolved ids, the arbiter's global set) and traps the rename family, with or without a confined file", async () => {
  const resolved = `sha1:${"b".repeat(40)}`;
  const global = `sha256:${"c".repeat(64)}`;
  const withPublic = { ...LOCKS, blobs: [...LOCKS.blobs, { id: `sha1:${"d".repeat(40)}`, level: "public" }], lockedSet: { sha1: [], sha256: [global.slice("sha256:".length)] } };
  const twins = async () => ({ twins: [], repos: 0, blobs: 0, packsRebuilt: 0, cacheHits: 0, walks: { hit: 0, incremental: 0, full: 0 }, lockedIds: [resolved] });
  for (const [name, arbiter] of [
    ["beside a confined file", mockArbiter({ gitHistoryLocks: async () => withPublic })],
    ["no file to confine", mockArbiter({ discoverSecrets: async () => [], gitHistoryLocks: async () => withPublic })],
  ] as const) {
    const { dir, cleanup } = runDir();
    try {
      const mut = emptyMutation();
      await applySecretTwins(plan(), dir, mut, deps({ guardServesTwins: true, arbiter, gitObjectTwins: twins }));
      const doc = JSON.parse(readFileSync(mut.env["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
      assert.deepEqual(doc.gitLocks, { ids: [LOCKS.blobs[0]!.id, resolved, global].sort(), noticeFile: join(dir, "git-lock-refusals") }, `${name}: a public lock is no lock`);
      assert.equal(mut.env["MANDU_NET_GUARD_PROTECT"], "1", `${name}: a locked object must not leave its checked name`);
    } finally {
      cleanup();
    }
  }
});

test("R4: no lock at all, no gitLocks field (the guard checks nothing); a history that cannot be hidden under --best-effort still hands the blob locks over", async () => {
  {
    const { dir, cleanup } = runDir();
    try {
      const mut = emptyMutation();
      await applySecretTwins(plan(), dir, mut, deps({ guardServesTwins: true, arbiter: mockArbiter({ gitHistoryLocks: async () => ({ axis: true, blobs: [], labels: [] }) }), gitObjectTwins: noTwins }));
      const doc = JSON.parse(readFileSync(mut.env["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
      assert.equal(doc.gitLocks, undefined);
    } finally {
      cleanup();
    }
  }
  const { dir, cleanup } = runDir();
  try {
    const mut = emptyMutation();
    await applySecretTwins(plan({ bestEffort: true }), dir, mut, deps({
      guardServesTwins: true, log: () => {},
      arbiter: mockArbiter({ gitHistoryLocks: async () => LOCKS }),
      gitObjectTwins: async () => { throw new Error("pack too big"); },
    }));
    const doc = JSON.parse(readFileSync(mut.env["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
    assert.deepEqual(doc.gitLocks.ids, [LOCKS.blobs[0]!.id], "the backstop still refuses the locked blob elsewhere");
  } finally {
    cleanup();
  }
});

test("R4: the arbiter's global locked set (lockedSet, bare hex per format) is checked like the rest of the answer", async () => {
  const cases: Array<[unknown, boolean]> = [
    [{ sha1: ["e".repeat(40)], sha256: ["f".repeat(64)] }, true],
    [{ sha1: [], sha256: [] }, true],
    [{ sha1: ["XYZ"], sha256: [] }, false],
    [{ sha1: ["f".repeat(64)], sha256: [] }, false],
    [{ sha1: [] }, false],
    [[`sha1:${"e".repeat(40)}`], false],
    ["not a set", false],
  ];
  for (const [bad, ok] of cases) {
    const { dir, cleanup } = runDir();
    try {
      const run = applySecretTwins(plan(), dir, emptyMutation(), deps({ guardServesTwins: true, arbiter: mockArbiter({ gitHistoryLocks: async () => ({ ...LOCKS, lockedSet: bad }) as never }), gitObjectTwins: noTwins }));
      if (ok) await run;
      else await assert.rejects(run, (e: Error) => e instanceof SecretConfinementError && /could not tell which git history/.test(e.message));
    } finally {
      cleanup();
    }
  }
});

// ── macOS: the one Seatbelt profile's record, and honesty about the locks ────

test("macOS: an arbiter failure under --best-effort still hands the Mandu home to the one Seatbelt profile (the record every other own-store path gives); Linux unchanged", async () => {
  const t = oneHome();
  try {
    for (const integrity of [false, true]) {
      const r = runDir();
      try {
        const res = await applySecretTwins(plan({ integrity, bestEffort: true, cwd: integrity ? t.av : "/w", humanCwd: "/w" }), r.dir, emptyMutation(), deps({
          home: t.home, platform: "darwin", arbiter: mockArbiter({ discoverSecrets: async () => { throw new Error("boom"); } }),
        }));
        assert.equal(res.posture, "gated");
        assert.equal(res.gap, "arbiter");
        assert.ok((res.ownStoresHidden ?? []).includes(t.mh));
        assert.deepEqual(res.seatbelt?.secrets, [], "no credential file: the arbiter could not name one");
        assert.deepEqual(res.seatbelt?.noDelete, []);
        assert.ok((res.seatbelt?.ownStores ?? []).includes(t.mh), `the home rides in the profile (integrity ${integrity}): ${JSON.stringify(res.seatbelt)}`);
        assert.deepEqual(res.seatbelt?.carveOuts ?? [], integrity ? [t.av, t.repo] : []);
      } finally {
        r.cleanup();
      }
    }
    const r = runDir();
    try {
      const linux = await applySecretTwins(plan({ integrity: false, bestEffort: true, cwd: "/w", humanCwd: "/w" }), r.dir, emptyMutation(), deps({
        home: t.home, guardServesTwins: true, arbiter: mockArbiter({ discoverSecrets: async () => { throw new Error("boom"); } }),
      }));
      assert.equal(linux.seatbelt, undefined, "Linux hides the stores through the guard, no Seatbelt record");
    } finally {
      r.cleanup();
    }
  } finally {
    t.cleanup();
  }
});

test("gitHistoryNotice: one line for committed files, for locks, or for both; unchecked repositories are said", () => {
  assert.equal(gitHistoryNotice([], []), null);
  const locks = gitHistoryNotice([], [{ root: "/w/a", checked: true }, { root: "/w/b", checked: false }])!;
  assert.match(locks, /^WARNING: mandu: a history lock \(policy\.yaml `blobs:`, or a labelled path's earlier versions\) covers committed versions in \/w\/a, \/w\/b \(not checked; assumed\): on macOS they stay readable to programs the agent runs \(git show, git log -p\); only Linux hides locked git history\./);
  const both = gitHistoryNotice([{ root: "/w/a", checked: true }], [{ root: "/w/c", checked: true }])!;
  assert.match(both, /^WARNING: mandu: a protected file is committed to git in \/w\/a, and a history lock .* covers committed versions in \/w\/c: on macOS those committed bytes stay readable/);
  assert.equal(both.split("WARNING").length - 1, 1, "one warning");
  assert.equal(
    gitHistoryNotice([{ root: "/w/a", checked: true }]),
    "WARNING: mandu: a protected file is committed to git in /w/a: on macOS its committed bytes stay readable to programs the agent runs (git show, git log -p); only Linux hides a protected file's git history. Remove it from the history, or rotate the secret.",
    "the committed-file notice alone is unchanged",
  );
});

test("macOS: the history locks are asked as the Linux launch asks (the workspace joins the registry, R1), and those reaching the launch's repositories join the committed-file notice in ONE warning", async () => {
  const { dir, cleanup } = runDir();
  try {
    const logs: string[] = [];
    let asked: readonly string[] | undefined;
    let seen: { launch: LockedHistoryLaunch; locks: GitHistoryLocksWire } | undefined;
    const mut = emptyMutation();
    const res = await applySecretTwins(plan(), dir, mut, deps({
      platform: "darwin", log: (m) => logs.push(m), workspaceRoots: ["/w/repo"],
      gitTracked: async () => [{ root: "/w/repo", checked: true }],
      gitLocked: async (launch, locks) => { seen = { launch, locks }; return [{ root: "/w/repo", checked: true }, { root: "/w/other", checked: false }]; },
      arbiter: mockArbiter({ gitHistoryLocks: async (roots?: readonly string[]) => { asked = roots; return LOCKS; } }),
    }));
    assert.deepEqual(asked, ["/w/repo"], "registered as on Linux");
    assert.deepEqual(seen?.launch, { workspaceRoots: ["/w/repo"], realPaths: [SECRET] });
    assert.deepEqual(seen?.locks.blobs, LOCKS.blobs);
    const warnings = logs.filter((l) => l.startsWith("WARNING: mandu:"));
    assert.equal(warnings.length, 1, logs.join("\n"));
    assert.match(warnings[0]!, /a protected file is committed to git in \/w\/repo, and a history lock .* covers committed versions in \/w\/repo, \/w\/other \(not checked; assumed\): on macOS/);
    assert.deepEqual(res.gitTrackedRepos, ["/w/repo"]);
    assert.deepEqual(res.gitLockedRepos, ["/w/repo", "/w/other"]);
    assert.equal(res.posture, "read-blocked");
    assert.deepEqual(mut.launchPrefix, [], "nothing enforced here: no wrap, no twin");
    assert.equal(mut.env["MANDU_NET_GUARD_SECRETS"], undefined);
    assert.ok(!logs.some((l) => /git history: .*hidden from the agent/.test(l)), "macOS never claims hidden history");
  } finally {
    cleanup();
  }
});

test("macOS, no file to confine: the locks still reach the launch and are said; an older arbiter, a missing op or no lock says nothing; a failure is said, never a refusal", async () => {
  const cases: Array<[string, Partial<SecretArbiter>, Array<{ root: string; checked: boolean }> | Error, RegExp | null, boolean]> = [
    ["locked", { gitHistoryLocks: async () => LOCKS }, [{ root: "/w/repo", checked: true }], /^WARNING: mandu: a history lock .* covers committed versions in \/w\/repo: on macOS they stay readable/, true],
    ["nothing reached", { gitHistoryLocks: async () => LOCKS }, [], null, true],
    ["older arbiter", { gitHistoryLocks: async () => { throw new Error("unknown op: gitHistoryLocks"); } }, [], null, false],
    ["no op on the adapter", {}, [], null, false],
    ["timeout", { gitHistoryLocks: async () => { throw new Error("arbiter gitHistoryLocks timed out after 5000ms — fail closed"); } }, [], /^WARNING: mandu: the history locks could not be read \(arbiter gitHistoryLocks timed out/, false],
    ["malformed", { gitHistoryLocks: async () => ({ nope: 1 }) as never }, [], /^WARNING: mandu: the history locks could not be read \(gitHistoryLocks: the arbiter's answer is not/, false],
    ["lookup failed", { gitHistoryLocks: async () => LOCKS }, new Error("EACCES"), /^WARNING: mandu: which repositories hold a locked version was not checked \(EACCES\)/, true],
  ];
  for (const [name, arb, looked, want, called] of cases) {
    const { dir, cleanup } = runDir();
    try {
      const logs: string[] = [];
      let lookups = 0;
      const res = await applySecretTwins(plan(), dir, emptyMutation(), deps({
        platform: "darwin", log: (m) => logs.push(m), workspaceRoots: ["/w/repo"],
        arbiter: mockArbiter({ discoverSecrets: async () => [], ...arb }),
        gitLocked: async () => { lookups++; if (looked instanceof Error) throw looked; return looked; },
      }));
      assert.equal(res.posture, "read-blocked", name);
      assert.equal(lookups, called ? 1 : 0, `${name}: looked up`);
      const warnings = logs.filter((l) => l.startsWith("WARNING:"));
      if (want === null) assert.deepEqual(warnings, [], `${name}: ${logs.join("\n")}`);
      else { assert.equal(warnings.length, 1, name); assert.match(warnings[0]!, want, name); }
      assert.deepEqual(res.gitLockedRepos, Array.isArray(looked) && looked.length > 0 ? looked.map((r) => r.root) : undefined, name);
    } finally {
      cleanup();
    }
  }
});

test("Linux never runs the macOS lock notice: the history is hidden instead", async () => {
  const { dir, cleanup } = runDir();
  try {
    const logs: string[] = [];
    await applySecretTwins(plan(), dir, emptyMutation(), deps({
      guardServesTwins: true, log: (m) => logs.push(m), workspaceRoots: ["/w/repo"],
      arbiter: mockArbiter({ discoverSecrets: async () => [], gitHistoryLocks: async () => LOCKS }),
      gitObjectTwins: noTwins,
      gitLocked: async () => { throw new Error("must not be asked on Linux"); },
    }));
    assert.ok(!logs.some((l) => /history lock .* covers committed versions/.test(l)), logs.join("\n"));
  } finally {
    cleanup();
  }
});

/** A real repository with a key committed then deleted (its blob stays in
 *  the history), and git as the launcher runs it. */
function lockedRepo(): { root: string; blob: string; git: (...a: string[]) => string; cleanup: () => void } {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "mandu-locked-")));
  const env = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x" };
  const git = (...a: string[]): string => {
    const r = spawnSync("git", a, { cwd: root, encoding: "utf8", env });
    if (r.status !== 0) throw new Error(`git ${a.join(" ")}: ${r.stderr}`);
    return r.stdout;
  };
  git("init", "-q");
  mkdirSync(join(root, "deploy"));
  writeFileSync(join(root, "deploy", "key"), "LOCKED-KEY-V1-7c1e\n");
  writeFileSync(join(root, "README"), "hi\n");
  git("add", ".");
  git("commit", "-qm", "1");
  git("rm", "-q", "deploy/key");
  git("commit", "-qm", "2");
  const blob = spawnSync("git", ["hash-object", "--stdin"], { cwd: root, input: "LOCKED-KEY-V1-7c1e\n", encoding: "utf8", env }).stdout.trim();
  return { root, blob, git, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("lockedHistoryRepos (real git): a locked version held loose or packed is found by name; an unrelated or public lock is not; the global set and the arbiter's resolved versions count", async () => {
  const f = lockedRepo();
  try {
    const launch = { workspaceRoots: [join(f.root, "deploy")], realPaths: [] };
    const lock = (id: string, level = "no-model"): GitHistoryLocksWire => ({ axis: true, blobs: [{ id, level }], labels: [] });
    assert.deepEqual(await lockedHistoryRepos(launch, lock(`sha1:${f.blob}`)), [{ root: f.root, checked: true }], "loose, from a subdirectory of the work tree");
    f.git("gc", "-q", "--prune=now");
    assert.deepEqual(await lockedHistoryRepos(launch, lock(`sha1:${f.blob}`)), [{ root: f.root, checked: true }], "packed (the .idx looked up)");
    assert.deepEqual(await lockedHistoryRepos(launch, lock(`sha1:${"e".repeat(40)}`)), [], "an id the repository does not hold");
    assert.deepEqual(await lockedHistoryRepos(launch, lock(`sha1:${f.blob}`, "public")), [], "a public lock hides nothing");
    assert.deepEqual(await lockedHistoryRepos(launch, lock(`sha256:${"a".repeat(64)}`)), [], "another object format");
    assert.deepEqual(await lockedHistoryRepos(launch, { axis: true, blobs: [], labels: [], lockedSet: { sha1: [f.blob], sha256: [] } }), [{ root: f.root, checked: true }], "the global set: a clone or fork holds the same blob");
    assert.deepEqual(
      await lockedHistoryRepos(launch, { axis: true, blobs: [], labels: [], repos: [{ root: "/elsewhere", format: "sha1", key: "k", blobs: [f.blob] }] }),
      [{ root: f.root, checked: true }], "another repository's resolved version, held here too",
    );
    assert.deepEqual(await lockedHistoryRepos(launch, { ...lock(`sha1:${f.blob}`), axis: false }), [], "the axis off: nothing is locked");
    assert.deepEqual(await lockedHistoryRepos({ workspaceRoots: [tmpdir()], realPaths: [] }, lock(`sha1:${f.blob}`)), [], "no repository in the launch");
  } finally {
    f.cleanup();
  }
});

test("lockedHistoryRepos: a labelled path the arbiter has not resolved yet in the workspace, or an object store git cannot name, is said as not checked", async () => {
  const f = lockedRepo();
  try {
    const launch = { workspaceRoots: [f.root], realPaths: [] };
    const labelled: GitHistoryLocksWire = { axis: true, blobs: [], labels: [{ path: join(f.root, "deploy", "key"), level: "no-model", recursive: true }] };
    assert.deepEqual(await lockedHistoryRepos(launch, labelled), [{ root: f.root, checked: false }], "pending: its gone path is not resolved yet");
    assert.deepEqual(
      await lockedHistoryRepos(launch, { ...labelled, repos: [{ root: f.root, format: "sha1", key: "k", blobs: [f.blob] }] }),
      [{ root: f.root, checked: true }], "resolved: its gone path's version is held",
    );
    assert.deepEqual(await lockedHistoryRepos(launch, { ...labelled, repos: [{ root: f.root, format: "sha1", key: "k", blobs: [] }] }), [], "resolved with nothing labelled");
    const publicOnly: GitHistoryLocksWire = { axis: true, blobs: [], labels: [{ path: join(f.root, "deploy", "key"), level: "public", recursive: true }] };
    assert.deepEqual(await lockedHistoryRepos(launch, publicOnly), [], "a public label locks nothing");
    const broken = async () => ({ code: 128, stdout: "", stderr: "not a git repository" });
    assert.deepEqual(
      await lockedHistoryRepos(launch, { axis: true, blobs: [{ id: `sha1:${f.blob}`, level: "no-model" }], labels: [] }, { git: broken }),
      [{ root: f.root, checked: false }], "git could not name the object store: counted (a notice errs loud)",
    );
    // A confined file's repository counts too, found from its real path.
    const other = lockedRepo();
    try {
      writeFileSync(join(other.root, ".env"), "X=1\n");
      const both = await lockedHistoryRepos({ workspaceRoots: [], realPaths: [join(other.root, ".env")] }, { axis: true, blobs: [{ id: `sha1:${other.blob}`, level: "no-model" }], labels: [] });
      assert.deepEqual(both, [{ root: other.root, checked: true }]);
    } finally {
      other.cleanup();
    }
  } finally {
    f.cleanup();
  }
});

// ── The moved package caches (secret-discovery.md §1.9 G) ───────────────────

import { discoverWireOpts, packageCacheEnv, PACKAGE_CACHE_ENV } from "../../src/secret-setup.js";

test("packageCacheEnv: only the package-cache variables, set and non-empty; discoverWireOpts leaves out what is absent", () => {
  assert.deepEqual(packageCacheEnv({}), {});
  assert.deepEqual(
    packageCacheEnv({ CARGO_HOME: "/c", GOPATH: "/g1:/g2", PIP_CACHE_DIR: "", HOME: "/h", AWS_SECRET_ACCESS_KEY: "x", GOMODCACHE: undefined }),
    { CARGO_HOME: "/c", GOPATH: "/g1:/g2" },
  );
  assert.ok(PACKAGE_CACHE_ENV.includes("CARGO_HOME") && PACKAGE_CACHE_ENV.includes("GOMODCACHE"));
  assert.deepEqual(discoverWireOpts(undefined), {});
  assert.deepEqual(discoverWireOpts({ stateBase: "/s", cacheEnv: {} }), { stateBase: "/s" });
  assert.deepEqual(discoverWireOpts({ cacheEnv: { CARGO_HOME: "/c" } }), { cacheEnv: { CARGO_HOME: "/c" } });
});

// ── The placeholder watch (placeholder-commits.ts; confidentiality.md §7.2a
//    "A placeholder in your repository") ──────────────────────────────────

const WATCHED: WatchedRepo = { root: "/w", tips: ["a".repeat(40)], paths: [{ rel: ".env", ids: ["b".repeat(40)], index: ["c".repeat(40)] }] };

test("linux: the twinned files go to the placeholder watch with their twin's content; what it watches comes back as placeholderWatch, and nothing watched leaves it out", async () => {
  const a = runDir();
  const b = runDir();
  try {
    let got: TwinSource[] = [];
    const res = await applySecretTwins(plan(), a.dir, emptyMutation(), deps({
      guardServesTwins: true,
      placeholderWatch: async (files) => { got = files; return [WATCHED]; },
    }));
    assert.equal(res.posture, "confined");
    assert.deepEqual(got, [{ targetPath: SECRET, content: `${SYM}\n`, twinPath: join(a.dir, "secret-twins", "000-credentials") }],
      "the real path, the twin's bytes (what git in the agent's world reads) and the twin file");
    assert.deepEqual(res.placeholderWatch, [WATCHED]);
    const none = await applySecretTwins(plan(), b.dir, emptyMutation(), deps({ guardServesTwins: true, placeholderWatch: async () => [] }));
    assert.equal(none.posture, "confined");
    assert.equal("placeholderWatch" in none, false, "no repository to watch: no field (the caller writes no record)");
  } finally {
    a.cleanup();
    b.cleanup();
  }
});

test("linux: what the watch found goes to the index patch (twin-index-stat.ts) after the twins are written; what it patched comes back as twinIndex; a failing patch never refuses the launch", async () => {
  const CLEANED = { root: "/w", indexPath: "/w/.git/index", hashBytes: 20 as const, entries: [] };
  for (const how of ["ok", "rejects", "throws"] as const) {
    const { dir, cleanup } = runDir();
    try {
      let got: WatchedRepo[] | null = null;
      let twinWritten = false;
      const res = await applySecretTwins(plan({ requireConfinement: true }), dir, emptyMutation(), deps({
        guardServesTwins: true,
        workspaceRoots: ["/w"],
        placeholderWatch: async () => [WATCHED],
        twinIndex: (async (repos: WatchedRepo[]) => {
          got = repos;
          twinWritten = existsSync(join(dir, "secret-twins", "000-credentials"));
          if (how === "rejects") throw new Error("index exploded");
          return [CLEANED];
        }) as SecretSetupDeps["twinIndex"],
        ...(how === "throws" ? { twinIndex: (() => { throw new Error("sync boom"); }) as unknown as SecretSetupDeps["twinIndex"] } : {}),
      }));
      assert.equal(res.posture, "confined", `${how}: the launch goes on`);
      if (how === "ok") {
        assert.deepEqual(got, [WATCHED]);
        assert.equal(twinWritten, true, "the twin exists when its stat is taken");
        assert.deepEqual(res.twinIndex, [CLEANED]);
      } else {
        assert.equal("twinIndex" in res, false, `${how}: nothing patched`);
      }
    } finally {
      cleanup();
    }
  }
});

test("linux: only the launch's own repositories go to the index patch; the placeholder watch still covers every repository it found (the backstop for the rest)", async () => {
  const top = mkdtempSync(join(tmpdir(), "secret-setup-scope-"));
  const own = join(top, "own");
  const other = join(top, "other");
  const plainDir = join(top, "plain");
  for (const d of [join(own, ".git"), join(own, "sub"), join(other, ".git"), plainDir]) mkdirSync(d, { recursive: true });
  const ownRepo: WatchedRepo = { ...WATCHED, root: own };
  const otherRepo: WatchedRepo = { ...WATCHED, root: other };
  try {
    for (const [name, ws, patched] of [
      ["from a subdir of one repository", [join(own, "sub")], [own]],
      ["from above both", [top], [own, other]],
      ["from a plain dir", [plainDir], null],
    ] as Array<[string, string[], string[] | null]>) {
      const { dir, cleanup } = runDir();
      try {
        let got: WatchedRepo[] | null = null;
        const res = await applySecretTwins(plan(), dir, emptyMutation(), deps({
          guardServesTwins: true,
          workspaceRoots: ws,
          placeholderWatch: async () => [ownRepo, otherRepo],
          twinIndex: async (repos) => { got = repos; return []; },
        }));
        assert.equal(res.posture, "confined", name);
        assert.deepEqual(res.placeholderWatch, [ownRepo, otherRepo], `${name}: the watch keeps every repository`);
        assert.deepEqual((got as WatchedRepo[] | null)?.map((r) => r.root) ?? null, patched, `${name}: patched`);
      } finally {
        cleanup();
      }
    }
  } finally {
    rmSync(top, { recursive: true, force: true });
  }
});

test("linux: the index patch takes each work tree's index file from the history step's facts (no rev-parse of its own), and records in the HOME's store whatever MANDU_HOME says", async () => {
  const GIT_ENV = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
  const top = mkdtempSync(join(tmpdir(), "secret-setup-facts-"));
  const repo = join(top, "repo");
  mkdirSync(repo);
  const g = (...a: string[]): string => execFileSync("git", a, { cwd: repo, encoding: "utf8", env: GIT_ENV });
  g("init", "-q");
  writeFileSync(join(repo, ".env"), "K=real\n");
  g("add", ".env");
  g("commit", "-qm", "c");
  const oid = g("rev-parse", "HEAD:.env").trim();
  const twin = join(top, "twin");
  writeFileSync(twin, "K=$MDU:x\n");
  const index = g("rev-parse", "--path-format=absolute", "--git-path", "index").trim();
  try {
    for (const [name, indexPaths, revParses] of [
      ["the step read this work tree", { [repo]: index }, 0],
      ["the step did not read it", {}, 1],
    ] as Array<[string, Record<string, string>, number]>) {
      g("update-index", "-q", "--really-refresh");
      const calls: string[][] = [];
      const counting: GitRunner = async (args, o) => {
        calls.push(args);
        const r = spawnSync("git", args, { cwd: o.cwd, encoding: "utf8", env: GIT_ENV });
        return { code: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
      };
      const { dir, cleanup } = runDir();
      try {
        const res = await applySecretTwins(plan({ scopeId: "facts-test" } as Partial<LaunchPlan>), dir, emptyMutation(), deps({
          guardServesTwins: true,
          home: top,
          env: { ...process.env, MANDU_HOME: join(top, "scratch-home") },
          workspaceRoots: [repo],
          gitSession: { runner: () => counting } as unknown as GitSession,
          gitObjectTwins: (async () => ({ twins: [], repos: 0, blobs: 0, packsRebuilt: 0, cacheHits: 0, walks: { hit: 0, incremental: 0, full: 0 }, indexPaths })) as unknown as SecretSetupDeps["gitObjectTwins"],
          placeholderWatch: async () => [{ root: repo, tips: null, paths: [{ rel: ".env", ids: [], index: [oid], twin }] }],
        }));
        assert.equal(res.twinIndex?.length, 1, `${name}: patched`);
        assert.equal(res.twinIndex![0]!.indexPath, index);
        assert.equal(calls.filter((a) => a[0] === "rev-parse" && a.includes("index")).length, revParses, `${name}: rev-parse calls for the index`);
        assert.ok(res.twinIndexRecorder?.file?.startsWith(join(top, ".mandu", "state", "object-walks", "twin-index") + "/"), `${name}: the record in the HOME's store, not MANDU_HOME's`);
        endTwinIndexSession(res.twinIndex, res.twinIndexRecorder);
      } finally {
        cleanup();
      }
    }
  } finally {
    rmSync(top, { recursive: true, force: true });
  }
});

test("linux, bind-only (no guard serves the twins, posture gated): the index is NEVER patched (a human's git stash or reset there would replace the real file and detach the bind; review of !1642 M1)", async () => {
  for (const guard of [false, undefined]) {
    const { dir, cleanup } = runDir();
    try {
      let called = false;
      const res = await applySecretTwins(plan(), dir, emptyMutation(), deps({
        ...(guard !== undefined ? { guardServesTwins: guard } : {}),
        placeholderWatch: async () => [WATCHED],
        twinIndex: async () => { called = true; return []; },
      }));
      assert.equal(res.posture, "gated", "bind-only");
      assert.equal(called, false, "no index patch without the guard");
      assert.equal("twinIndex" in res, false);
    } finally {
      cleanup();
    }
  }
});

test("a setup that throws AFTER the index patch puts the real stat back before it throws (review of !1642 L2)", async () => {
  const GIT_ENV = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
  const repo = mkdtempSync(join(tmpdir(), "secret-setup-index-"));
  const g = (...a: string[]): string => execFileSync("git", a, { cwd: repo, encoding: "utf8", env: GIT_ENV });
  g("init", "-q");
  writeFileSync(join(repo, ".env"), "K=real\n");
  g("add", ".env");
  g("commit", "-qm", "c");
  const oid = g("rev-parse", "HEAD:.env").trim();
  const launch = readFileSync(join(repo, ".git", "index"));
  const twin = join(repo, "twin");
  writeFileSync(twin, "K=$MDU:x\n");
  const runner: GitRunner = async (args, o) => {
    const r = spawnSync("git", args, { cwd: o.cwd, encoding: "utf8", env: GIT_ENV });
    return { code: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
  };
  const { dir, cleanup } = runDir();
  try {
    let patched = false;
    await assert.rejects(applySecretTwins(plan(), dir, emptyMutation(), deps({
      guardServesTwins: true,
      workspaceRoots: [repo],
      placeholderWatch: async () => [{ root: repo, tips: null, paths: [{ rel: ".env", ids: [], index: [oid], twin }] }],
      twinIndex: async (rs) => {
        const got = await cleanTwinsInIndex(rs, { git: runner, readReal: () => Buffer.from("K=real\n") });
        patched = got.length === 1 && !readFileSync(join(repo, ".git", "index")).equals(launch);
        return got;
      },
      // The step after the patch fails.
      symlinkProbe: () => { throw new Error("probe exploded"); },
    })), /probe exploded/);
    assert.equal(patched, true, "precondition: the index was patched");
    assert.ok(readFileSync(join(repo, ".git", "index")).equals(launch), "the launch's index, byte for byte");
  } finally {
    cleanup();
    rmSync(repo, { recursive: true, force: true });
  }
});

test("a placeholder watch that fails never refuses the launch (rejected or thrown, --require-confinement too): confined, no placeholderWatch", async () => {
  const failing: Array<[string, SecretSetupDeps["placeholderWatch"]]> = [
    ["rejects", async () => { throw new Error("git exploded"); }],
    ["throws", (() => { throw new Error("sync boom"); }) as unknown as SecretSetupDeps["placeholderWatch"]],
  ];
  for (const [how, placeholderWatch] of failing) {
    for (const p of [plan(), plan({ requireConfinement: true })]) {
      const { dir, cleanup } = runDir();
      try {
        const res = await applySecretTwins(p, dir, emptyMutation(), deps({ guardServesTwins: true, placeholderWatch }));
        assert.equal(res.posture, "confined", `${how}: the launch goes on`);
        assert.equal(res.confined.length, 1);
        assert.equal("placeholderWatch" in res, false, `${how}: nothing watched`);
      } finally {
        cleanup();
      }
    }
  }
});

test("applyEnvSecrets: an agent key the launch granted (agentKeys) is sent with agentKey; every other variable without it (agent-sign-in.md §3.8)", async () => {
  const sent: Array<{ name: string; agentKey?: boolean }> = [];
  const arb = envArbiter({
    registerEnvSecrets: async (vars) => {
      sent.push(...vars.map((v) => ({ name: v.name, ...(v.agentKey ? { agentKey: v.agentKey } : {}) })));
      return { vars: vars.map((v) => v.name === "ANTHROPIC_API_KEY" && v.agentKey
        ? { name: v.name, symbol: "$MDU:nomodel_Env[3333].ANTHROPIC_API_KEY", twin: "$MDU:nomodel_Env[3333].ANTHROPIC_API_KEY", reason: "registered" }
        : { name: v.name, symbol: null, reason: "not a secret variable" }) };
    },
  });
  const env = { ANTHROPIC_API_KEY: "sk-ant-api03-MANDUFAKE", PATH: "/usr/bin" };
  const mut = emptyMutation();
  const res = await applyEnvSecrets(plan({ target: "claude" }), env, mut, { arbiter: arb, log: () => {}, agentKeys: ["ANTHROPIC_API_KEY"] });
  assert.deepEqual(res.masked, ["ANTHROPIC_API_KEY"]);
  assert.equal(mut.env["ANTHROPIC_API_KEY"], "$MDU:nomodel_Env[3333].ANTHROPIC_API_KEY", "the agent's environment carries the placeholder");
  assert.deepEqual(sent.find((v) => v.name === "ANTHROPIC_API_KEY"), { name: "ANTHROPIC_API_KEY", agentKey: true });
  assert.deepEqual(sent.find((v) => v.name === "PATH"), { name: "PATH" });
  // Without the grant the variable is sent plain, and the arbiter's exemption keeps it raw.
  sent.length = 0;
  const mut2 = emptyMutation();
  await applyEnvSecrets(plan({ target: "claude" }), env, mut2, { arbiter: arb, log: () => {} });
  assert.deepEqual(sent.find((v) => v.name === "ANTHROPIC_API_KEY"), { name: "ANTHROPIC_API_KEY" });
  assert.equal(mut2.env["ANTHROPIC_API_KEY"], undefined, "left to the ambient env: raw, as before");
});

test("grantedLoginFiles (agent-sign-in.md §3.9): the launched agent's own login a grant covers is registered and twinned although the walk leaves it out; a missing file is skipped", async () => {
  const { dir, cleanup } = runDir();
  try {
    const CODEX_AUTH = "/home/u/.codex/auth.json";
    const registered: string[] = [];
    const arbiter = mockArbiter({
      discoverSecrets: async () => [{ path: SECRET }],
      registerSecret: async (p) => { registered.push(p); return { symbol: SYM, reason: "registered", ...(p === CODEX_AUTH ? { twin: '{"OPENAI_API_KEY": "$MDU:nomodel_Read[e0c7].OPENAI_API_KEY"}', fields: 1 } : {}) }; },
    });
    const mut = emptyMutation();
    const res = await applySecretTwins(plan(), dir, mut, deps({ arbiter, grantedLoginFiles: [CODEX_AUTH], guardServesTwins: true, pathExists: (p) => p === CODEX_AUTH || p === SECRET }));
    assert.deepEqual(registered, [SECRET, CODEX_AUTH]);
    assert.deepEqual(res.confined.map((c) => c.path), [SECRET, CODEX_AUTH], "twinned like any secret");
    assert.ok(mut.launchPrefix.includes(CODEX_AUTH), "bound");
    registered.length = 0;
    await applySecretTwins(plan(), dir, emptyMutation(), deps({ arbiter, grantedLoginFiles: [CODEX_AUTH], guardServesTwins: true, pathExists: (p) => p === SECRET }));
    assert.deepEqual(registered, [SECRET], "no such file: nothing to twin");
  } finally {
    cleanup();
  }
});

test("applyEnvSecrets under `mandu goose` (§3.10): a routed provider's key variable the launch granted is sent (masked, put back at the proxy); an ungranted one stays the agent's own", async () => {
  const sent: string[] = [];
  const arb = envArbiter({ registerEnvSecrets: async (vars) => { sent.push(...vars.map((v) => `${v.name}${v.agentKey ? "+agentKey" : ""}`)); return envArbiter().registerEnvSecrets!(vars); } });
  const env = { OPENROUTER_API_KEY: "sk-or-x", LITELLM_API_KEY: "sk-lite-x" };
  const gooseRouting = { provider: "openrouter", subagentProvider: "litellm", openai: null, compat: [
    { provider: "openrouter", upstream: "https://openrouter.ai" }, { provider: "litellm", upstream: "https://litellm.corp.example" },
  ] } as LaunchPlan["gooseRouting"];
  await applyEnvSecrets(plan({ target: "goose", gooseRouting }), env, emptyMutation(), { arbiter: arb, log: () => {}, agentKeys: ["OPENROUTER_API_KEY"] });
  assert.deepEqual(sent, ["OPENROUTER_API_KEY+agentKey"], "LITELLM_API_KEY (a remote LiteLLM: no grant) stays the agent's own");
});

test("socketSecretArbiter: registerEnvSecrets and registerSecret go over the human socket when the arbiter reported one (only there do they earn a wire grant, confidentiality.md §2.1), else over the data socket", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-envsock-"));
  const ops: Record<string, string[]> = { data: [], human: [] };
  const listen = async (which: "data" | "human") => {
    const path = join(dir, `${which}.sock`);
    const srv = createServer((s) => {
      s.on("data", (chunk) => {
        const req = JSON.parse(chunk.toString().split("\n")[0]!) as Record<string, unknown>;
        ops[which]!.push(String(req["op"]));
        s.write(JSON.stringify({ id: req["id"], ok: true, result: { vars: [] } }) + "\n");
      });
    });
    srv.listen(path);
    await once(srv, "listening");
    return { path, srv };
  };
  const data = await listen("data");
  const human = await listen("human");
  try {
    await socketSecretArbiter(data.path, { humanSock: human.path }).registerEnvSecrets!([{ name: "PIP_INDEX_URL", value: "https://u:p@x.example/" }]);
    assert.deepEqual(ops, { data: [], human: ["registerEnvSecrets"] });
    await socketSecretArbiter(data.path).registerEnvSecrets!([{ name: "PIP_INDEX_URL", value: "https://u:p@x.example/" }]);
    assert.deepEqual(ops, { data: ["registerEnvSecrets"], human: ["registerEnvSecrets"] }, "no human socket: the data socket, as before");
    ops["data"]!.length = 0; ops["human"]!.length = 0;
    // The launch HOME's files too: only a human-plane registration earns their wire grant.
    await socketSecretArbiter(data.path, { humanSock: human.path }).registerSecret("/h/.npmrc", "/h");
    assert.deepEqual(ops, { data: [], human: ["registerSecret"] });
    await socketSecretArbiter(data.path).registerSecret("/h/.npmrc", "/h");
    assert.deepEqual(ops, { data: ["registerSecret"], human: ["registerSecret"] }, "no human socket: the data socket, as before");
  } finally {
    data.srv.close(); human.srv.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
