/**
 * human-plane.test — the launcher's half of the arbiter's human plane
 * (docs/design/architecture/arbiter-human-plane.md): where the human socket comes from,
 * who gets it (the reply filter, fs-sync, net-proxy; never the agent), and
 * the walls around its directory (the guard's always-deny list, the Unix
 * allow-list, Claude Code's sandbox overlay).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  HUMAN_SOCK_ENV,
  applyHumanPlaneDeny,
  humanPlaneDir,
  humanPlaneDirs,
  humanPlaneWalled,
  humanSockEnv,
  readArbiterHumanSock,
  touchesHumanPlane,
  withoutHumanSock,
} from "../../src/human-plane.js";
import { applyUnixPolicy, unixPolicy } from "../../src/unix-policy.js";
import { assessClaudeSandbox, type ClaudeSandboxView } from "../../src/claude-sandbox.js";
import { applyReplyFilter } from "../../src/reply-filter.js";
import { composeLaunch } from "../../src/env-compose.js";
import { emptyMutation } from "../../src/backend/types.js";
import { Layout } from "../../src/services/layout.js";
import type { LaunchPlan } from "../../src/types.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const BASE = "/run/user/7/mandu";
const HUMAN = `${BASE}/human`;
const HSOCK = `${HUMAN}/20260930-1200-abc-p1.sock`;

test("the human-plane dirs: the reported socket's dir and this launch's runtime base, deduplicated", () => {
  assert.equal(humanPlaneDir(`${BASE}/`), HUMAN);
  assert.deepEqual(humanPlaneDirs(HSOCK, BASE), [HUMAN], "the usual deployment: one directory");
  assert.deepEqual(humanPlaneDirs("/tmp/other/mandu/human/x.sock", BASE), ["/tmp/other/mandu/human", HUMAN], "a pinned arbiter elsewhere: both");
  assert.deepEqual(humanPlaneDirs(null, BASE), [HUMAN], "none reported: the runtime base's is still walled");
});

test("touchesHumanPlane: equal, inside and every ancestor touch it; look-alikes and siblings do not", () => {
  for (const p of [HUMAN, `${HUMAN}/`, HSOCK, BASE, "/run/user/7", "/run", "/"]) assert.ok(touchesHumanPlane(p, [HUMAN]), p);
  for (const p of [`${BASE}/human-evil`, `${BASE}/current/arbiter.sock`, `${BASE}/instances`, "/run/user/7/gnupg/S.gpg-agent", "relative/human"]) {
    assert.ok(!touchesHumanPlane(p, [HUMAN]), p);
  }
});

test("readArbiterHumanSock: hello's humanSock; anything else (absent, null, relative, an error) is null — never the data socket", async () => {
  assert.equal(await readArbiterHumanSock("/d.sock", async () => ({ humanSock: HSOCK, sockPath: "/d.sock" })), HSOCK);
  assert.equal(await readArbiterHumanSock("/d.sock", async () => ({ sockPath: "/d.sock" })), null, "a pre-human-plane arbiter");
  assert.equal(await readArbiterHumanSock("/d.sock", async () => ({ humanSock: null })), null);
  assert.equal(await readArbiterHumanSock("/d.sock", async () => ({ humanSock: "rel.sock" })), null);
  assert.equal(await readArbiterHumanSock("/d.sock", async () => { throw new Error("ECONNREFUSED"); }), null);
});

test("readArbiterHumanSock over a real socket (the production NDJSON call)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-hp-"));
  const sock = join(dir, "a.sock");
  const srv = createServer((c) => {
    c.setEncoding("utf8");
    c.on("data", (line: string) => {
      const req = JSON.parse(line.trim()) as { id: unknown; op: string };
      c.write(JSON.stringify({ id: req.id, ok: true, result: req.op === "hello" ? { humanSock: HSOCK, sockPath: sock } : {} }) + "\n");
    });
  });
  srv.listen(sock);
  await once(srv, "listening");
  try {
    assert.equal(await readArbiterHumanSock(sock), HSOCK);
  } finally {
    srv.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the agent env: composeLaunch never emits the human socket; withoutHumanSock drops an ambient one; human-facing children get it explicitly or explicitly unset", () => {
  const plan = {
    target: "claude", argv: ["claude"], scopeId: "s", tenant: "live", arbiterSock: "/d.sock", arbiterSockMode: "pinned",
    arbiterRuntimeBase: BASE, arbiterHumanSock: HSOCK, humanPlaneDirs: [HUMAN],
    eventDir: "/run/s/events", cwd: "/w", humanCwd: "/w", basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 1 }, openaiProxy: { host: "127.0.0.1", port: 2 },
    openaiProviderName: "mandu", noProxyExtra: [], requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noContextProxy: false, noScope: false, writeMcp: true, bestEffort: false, replyFilter: true,
  } as unknown as LaunchPlan;
  const composed = composeLaunch(plan);
  assert.ok(!(HUMAN_SOCK_ENV in composed.env), "the composed agent env never names the human plane");
  assert.equal(composed.env["MANDU_ARBITER_SOCK"], "/d.sock");
  const ambient: Record<string, string | undefined> = { PATH: "/usr/bin", [HUMAN_SOCK_ENV]: "/stale/human.sock" };
  const agent = withoutHumanSock(ambient);
  assert.ok(!(HUMAN_SOCK_ENV in agent));
  assert.equal(agent.PATH, "/usr/bin");
  assert.equal(ambient[HUMAN_SOCK_ENV], "/stale/human.sock", "the caller's env is not mutated");
  assert.deepEqual(humanSockEnv(HSOCK), { [HUMAN_SOCK_ENV]: HSOCK });
  assert.deepEqual(humanSockEnv(null), { [HUMAN_SOCK_ENV]: undefined }, "none: an explicit unset, not the data socket");
});

test("the reply filter gets the human socket through the launch env (and removes it for its child); none reported → none set", () => {
  const base = { argv: ["claude"], replyFilter: true, arbiterSock: "/d.sock" } as unknown as LaunchPlan;
  const on = emptyMutation();
  applyReplyFilter({ ...base, arbiterHumanSock: HSOCK } as LaunchPlan, Layout.dev("/repo"), on, () => true, () => {});
  assert.equal(on.env[HUMAN_SOCK_ENV], HSOCK);
  const none = emptyMutation();
  applyReplyFilter({ ...base, arbiterHumanSock: null } as LaunchPlan, Layout.dev("/repo"), none, () => true, () => {});
  assert.ok(!(HUMAN_SOCK_ENV in none.env));
  const off = emptyMutation();
  applyReplyFilter({ ...base, replyFilter: false, arbiterHumanSock: HSOCK } as LaunchPlan, Layout.dev("/repo"), off, () => true, () => {});
  assert.ok(!(HUMAN_SOCK_ENV in off.env), "no filter, no human socket in the launch env");
});

test("unix allow-list: an entry equal to, inside, or an ancestor of the human dir is dropped and reported, from every source", () => {
  const refused: string[] = [];
  const p = unixPolicy(
    { HOME: "/h", XDG_RUNTIME_DIR: "/run/user/7", MANDU_UNIX_ALLOW: `${HUMAN}:/srv/app.sock:${BASE}` },
    {
      arbiterSock: `${BASE}/current/arbiter.sock`,
      scopeRunDir: "/run/user/7",
      extra: [HSOCK, "/run", "@abstract-ok", "/srv/db.sock"],
      humanDirs: [HUMAN],
      onRefused: (path) => refused.push(path),
    },
  );
  const paths = p.allow.map((a) => a.path);
  assert.ok(paths.includes(`${BASE}/current/arbiter.sock`), "the data socket stays listed");
  assert.ok(paths.includes("/srv/app.sock") && paths.includes("/srv/db.sock"));
  for (const bad of [HUMAN, HSOCK, BASE, "/run/user/7", "/run"]) {
    assert.ok(!paths.includes(bad), `${bad} would reach the human plane`);
    assert.ok(refused.includes(bad), `${bad} reported`);
  }
  assert.ok(!paths.some((q) => touchesHumanPlane(q, [HUMAN])), "nothing on the list reaches it");
  assert.ok(p.abstractAllow.includes("abstract-ok"), "abstract names are unaffected");
});

test("the guard's always-deny list: written on its own (MANDU_UNIX_POLICY=0), and kept when the allow-list joins the same file in either order", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-hp-"));
  const deps = { scopeRunDir: dir, agentExe: "/usr/bin/claude", session: "s", log: () => {} };
  try {
    // Alone: the allow-list opted out, the deny list stands.
    const alone: Record<string, string> = {};
    applyHumanPlaneDeny([HUMAN], alone, deps);
    const doc1 = JSON.parse(readFileSync(alone["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
    assert.deepEqual(doc1.unixDeny, [HUMAN]);
    assert.equal(doc1.unixPolicy, undefined, "no allow-list was asked for");
    // With the allow-list, both orders.
    rmSync(join(dir, "guard-policy.json"), { force: true });
    const a: Record<string, string> = {};
    applyUnixPolicy(unixPolicy({}, { humanDirs: [HUMAN] }), a, deps);
    applyHumanPlaneDeny([HUMAN], a, deps);
    const doc2 = JSON.parse(readFileSync(a["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
    assert.deepEqual(doc2.unixDeny, [HUMAN]);
    assert.ok(doc2.unixPolicy);
    rmSync(join(dir, "guard-policy.json"), { force: true });
    const b: Record<string, string> = {};
    applyHumanPlaneDeny([HUMAN], b, deps);
    applyUnixPolicy(unixPolicy({}, { humanDirs: [HUMAN] }), b, deps);
    const doc3 = JSON.parse(readFileSync(b["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
    assert.deepEqual(doc3.unixDeny, [HUMAN]);
    assert.ok(doc3.unixPolicy);
    // Nothing to deny → no file.
    const empty: Record<string, string> = {};
    applyHumanPlaneDeny([], empty, deps);
    assert.equal(empty["MANDU_NET_GUARD_SECRETS"], undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Claude Code's sandbox overlay never carries a human-plane path, and a user entry naming one is warned about", () => {
  const view: ClaudeSandboxView = {
    enabled: true, enabledBy: ["~/.claude/settings.json"], files: [], envVars: [],
    allowUnixSockets: ["/run/a.sock", HSOCK], sources: [], errors: [],
  };
  const a = assessClaudeSandbox(view, { confined: [], maskedEnv: [], arbiterSock: `${BASE}/current/arbiter.sock`, humanDirs: [HUMAN] });
  const overlay = (a.settingsOverlay as { sandbox: { network: { allowUnixSockets: string[] } } }).sandbox.network.allowUnixSockets;
  assert.deepEqual(overlay, ["/run/a.sock", `${BASE}/current/arbiter.sock`]);
  assert.ok(a.notes.some((n) => n.includes("human-plane") && n.includes(HSOCK)));
  // Even an arbiter socket spelled inside the human dir is left out.
  const b = assessClaudeSandbox({ ...view, allowUnixSockets: [] }, { confined: [], maskedEnv: [], arbiterSock: HSOCK, humanDirs: [HUMAN] });
  assert.deepEqual((b.settingsOverlay as { sandbox: { network: { allowUnixSockets: string[] } } }).sandbox.network.allowUnixSockets, []);
});

test("humanPlaneWalled (plan 13 D9 leftovers): the guard's deny entry, or a tmpfs over every existing human dir, or Seatbelt; anything else is unwalled", () => {
  const exists = (p: string): boolean => p === HUMAN || p === "/tmp/other/mandu/human";
  const real = (p: string): string => (p === HUMAN ? "/real/human" : p);
  const base = { dirs: [HUMAN], guardDeny: false, launchPrefix: [] as string[], platform: "linux", exists, realpath: real };
  assert.equal(humanPlaneWalled({ ...base, guardDeny: true }), true, "the guard's always-deny entry");
  assert.equal(humanPlaneWalled(base), false, "no guard, no wrap: the gated posture with neither, or off");
  const wrap = ["bwrap", "--dev-bind", "/", "/", "--tmpfs", "/home/u/.mandu", "--tmpfs", "/real/human", "--"];
  assert.equal(humanPlaneWalled({ ...base, launchPrefix: wrap }), true, "the wrap masks the human dir (by its real path)");
  assert.equal(humanPlaneWalled({ ...base, launchPrefix: ["bwrap", "--tmpfs", `${HUMAN}/`, "--"] }), true, "by its spelling, trailing slash");
  assert.equal(humanPlaneWalled({ ...base, launchPrefix: ["bwrap", "--tmpfs", "/home/u/.mandu", "--"] }), false, "a wrap that masks only the home");
  assert.equal(humanPlaneWalled({ ...base, dirs: [HUMAN, "/tmp/other/mandu/human"], launchPrefix: wrap }), false, "every directory must be masked");
  assert.equal(humanPlaneWalled({ ...base, exists: () => false, launchPrefix: wrap }), false, "a directory that does not exist yet is not masked");
  assert.equal(humanPlaneWalled({ ...base, dirs: [] }), false, "no human directory known");
  assert.equal(humanPlaneWalled({ ...base, platform: "darwin", launchPrefix: ["/usr/bin/sandbox-exec", "-p", "(version 1)"], seatbeltHumanDenied: true }), true, "the applied Seatbelt profile denies every human directory");
  assert.equal(humanPlaneWalled({ ...base, platform: "darwin" }), false);
  assert.equal(humanPlaneWalled({ ...base, platform: "darwin", launchPrefix: ["sandbox-exec", "-f", "/unrelated.sb"] }), false, "a sandbox command name alone does not prove the human-plane deny");
});
