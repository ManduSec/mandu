/**
 * net-guard.test — the PURE allow-spec set + wrap-argv plan, and applyNetGuard's
 * prepend / degrade / banner behavior (docs/design/integrity/exec-routing.md §7.5).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  computeNetGuardSpecs,
  gitRemoteSpecs,
  gitRemoteToSpec,
  planNetGuard,
  specsAdmitAnyHttps,
} from "../../src/net-guard.js";
import { applyNetGuard, NET_GUARD_BOX_SOCKETS_ENV, NET_GUARD_OWN_SERVER_ENV, NET_GUARD_SESSION_ENV, netGuardStatusFile } from "../../src/net-guard-setup.js";
import { NET_GUARD_PROXY_PORTS_ENV, sessionProxyPorts } from "../../src/net-guard.js";
import { NET_GUARD_STATUS_ENV } from "../../src/guard-death.js";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { emptyMutation } from "../../src/backend/types.js";
import type { LaunchPlan } from "../../src/types.js";

// ── planNetGuard: argv shape ─────────────────────────────────────────────────

test("planNetGuard: one --allow pair per spec, --skip-unsupported + trailing -- always present", () => {
  const { wrapArgv } = planNetGuard({ binPath: "/bin/net-guard", specs: ["tcp:127.0.0.1:8788", "udp:*:53"] });
  assert.deepEqual(wrapArgv, [
    "/bin/net-guard",
    "--allow", "tcp:127.0.0.1:8788",
    "--allow", "udp:*:53",
    "--skip-unsupported", "--",
  ]);
  assert.equal(wrapArgv.at(-1), "--", "the target argv follows the separator");
  assert.equal(wrapArgv.at(-2), "--skip-unsupported", "always degrade-capable");
});

test("planNetGuard: empty specs is valid (whole-agent connect deny-all)", () => {
  const { wrapArgv } = planNetGuard({ binPath: "g", specs: [] });
  assert.deepEqual(wrapArgv, ["g", "--skip-unsupported", "--"]);
});

test("planNetGuard: `required` (OpenCode 2 with confidentiality on) drops the degrade: a guard that cannot start fails the launch", () => {
  const { wrapArgv } = planNetGuard({ binPath: "g", specs: ["tcp:127.0.0.1:1"], required: true });
  assert.deepEqual(wrapArgv, ["g", "--allow", "tcp:127.0.0.1:1", "--"]);
  assert.ok(planNetGuard({ binPath: "g", specs: [], required: false }).wrapArgv.includes("--skip-unsupported"));
});

// ── computeNetGuardSpecs: the allow-set policy ───────────────────────────────

const base = {
  targetProxyPort: 8788,
  netProxyPort: null,
  ullmForwarderPort: null,
  apiHost: "api.anthropic.com",
};

test("computeNetGuardSpecs: default (non-strict) = loopback svc + DNS + API host + permissive *:443/*:22", () => {
  const specs = computeNetGuardSpecs({ ...base, strict: false });
  // Loopback service (both v4 range + v6 localhost) for the proxy port.
  assert.ok(specs.includes("tcp:127.0.0.0/8:8788"));
  assert.ok(specs.includes("tcp:[::1]:8788"));
  // DNS.
  assert.ok(specs.includes("udp:*:53") && specs.includes("tcp:*:53"));
  // The model API host on 443.
  assert.ok(specs.includes("tcp:api.anthropic.com:443"));
  // The permissive fallback keeps arbitrary HTTPS + git-ssh working.
  assert.ok(specs.includes("tcp:*:443") && specs.includes("tcp:*:22"));
  assert.ok(specsAdmitAnyHttps(specs));
});

test("computeNetGuardSpecs: strict DROPS the *:443/*:22 fallback (IP/domain-precise)", () => {
  const specs = computeNetGuardSpecs({ ...base, strict: true });
  assert.ok(!specs.includes("tcp:*:443"), "no any-host :443 in strict");
  assert.ok(!specs.includes("tcp:*:22"));
  assert.ok(!specsAdmitAnyHttps(specs));
  // …but the API host + loopback + DNS remain so the agent still works.
  assert.ok(specs.includes("tcp:api.anthropic.com:443"));
  assert.ok(specs.includes("tcp:127.0.0.0/8:8788"));
  assert.ok(specs.includes("udp:*:53"));
});

test("computeNetGuardSpecs: an explicit allow-list appends verbatim and drops the fallback", () => {
  const specs = computeNetGuardSpecs({
    ...base,
    strict: false,
    explicitAllow: ["10.0.0.0/8:*", " registry.npmjs.org:443 "],
  });
  assert.ok(specs.includes("10.0.0.0/8:*"));
  assert.ok(specs.includes("registry.npmjs.org:443"), "trimmed");
  assert.ok(!specsAdmitAnyHttps(specs), "curated ⇒ the permissive fallback is dropped");
  // Baseline rules still present.
  assert.ok(specs.includes("tcp:api.anthropic.com:443"));
  assert.ok(specs.includes("udp:*:53"));
});

test("computeNetGuardSpecs: net-proxy + ullm-forwarder loopback rules included IFF live", () => {
  const specs = computeNetGuardSpecs({ ...base, netProxyPort: 8790, ullmForwarderPort: 8791, strict: true });
  assert.ok(specs.includes("tcp:127.0.0.0/8:8790"));
  assert.ok(specs.includes("tcp:127.0.0.0/8:8791"));
  assert.ok(specs.includes("tcp:[::1]:8790"));
});

test("computeNetGuardSpecs: empty explicit allow-list = curated-but-empty (baseline only, no fallback)", () => {
  const specs = computeNetGuardSpecs({ ...base, strict: false, explicitAllow: [] });
  assert.ok(!specsAdmitAnyHttps(specs));
  assert.ok(specs.includes("tcp:api.anthropic.com:443"));
});

// ── git-remote → spec parsing ────────────────────────────────────────────────

test("gitRemoteToSpec: https/http/ssh-url/git/scp-shorthand → host:port; local → null", () => {
  assert.equal(gitRemoteToSpec("https://github.com/o/r.git"), "tcp:github.com:443");
  assert.equal(gitRemoteToSpec("http://host.example/o/r"), "tcp:host.example:80");
  assert.equal(gitRemoteToSpec("git://git.example/o/r"), "tcp:git.example:9418");
  // scp-like ssh shorthand.
  assert.equal(gitRemoteToSpec("git@github.com:o/r.git"), "tcp:github.com:22");
  // ssh URL with an explicit port + credentials stripped.
  assert.equal(gitRemoteToSpec("ssh://git@code.example:2222/o/r.git"), "tcp:code.example:2222");
  // https with credentials + explicit port.
  assert.equal(gitRemoteToSpec("https://user:tok@registry.example:8443/o/r"), "tcp:registry.example:8443");
  // IPv6 host stays bracketed so it re-parses as a spec.
  assert.equal(gitRemoteToSpec("ssh://git@[2001:db8::1]/o/r"), "tcp:[2001:db8::1]:22");
  assert.equal(gitRemoteToSpec("git@[2001:db8::1]:o/r"), "tcp:[2001:db8::1]:22");
  // Local / file paths → no network host.
  assert.equal(gitRemoteToSpec("/srv/git/r.git"), null);
  assert.equal(gitRemoteToSpec("file:///srv/git/r.git"), null);
  assert.equal(gitRemoteToSpec("../relative/r.git"), null);
  assert.equal(gitRemoteToSpec(""), null);
});

test("gitRemoteSpecs: maps + dedupes + drops local", () => {
  assert.deepEqual(
    gitRemoteSpecs([
      "https://github.com/o/r.git",
      "git@github.com:o/r.git",
      "https://github.com/o/r.git", // dup of the first
      "/local/path",
    ]),
    ["tcp:github.com:443", "tcp:github.com:22"],
  );
});

test("computeNetGuardSpecs: git-remote specs included when narrowed, omitted in the permissive default", () => {
  const git = ["tcp:github.com:443"];
  // Strict → included.
  assert.ok(computeNetGuardSpecs({ ...base, strict: true, gitRemoteSpecs: git }).includes("tcp:github.com:443"));
  // Curated → included.
  assert.ok(computeNetGuardSpecs({ ...base, strict: false, explicitAllow: [], gitRemoteSpecs: git }).includes("tcp:github.com:443"));
  // Permissive non-strict default → omitted (the *:443 fallback covers it).
  assert.ok(!computeNetGuardSpecs({ ...base, strict: false, gitRemoteSpecs: git }).includes("tcp:github.com:443"));
});

// ── applyNetGuard: prepend / degrade / banners ───────────────────────────────

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid", tenant: "live", arbiterSock: "/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu", eventDir: "/e",
    cwd: "/w", humanCwd: "/w", noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, netGuard: true, ...over,
  };
}

test("applyNetGuard: off → no-op (no wrap, no log)", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyNetGuard(plan({ netGuard: false }), mut, { resolveBin: () => "/bin/g", log: (m) => logs.push(m) });
  assert.equal(r, null);
  assert.deepEqual(mut.launchPrefix, []);
  assert.equal(logs.length, 0);
});

test("applyNetGuard: bin missing → WARN + proceed WITHOUT (degrade, never throws)", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyNetGuard(plan(), mut, { resolveBin: () => null, log: (m) => logs.push(m) });
  assert.equal(r, null);
  assert.deepEqual(mut.launchPrefix, [], "no wrap prepended when the bin is absent");
  assert.ok(logs.some((l) => /not built/.test(l) && /WITHOUT/.test(l)));
});

test("applyNetGuard: the guard serves the command box's socket allow-list (exec-routing §4.2)", () => {
  const mut = emptyMutation();
  assert.ok(applyNetGuard(plan(), mut, { resolveBin: () => "/bin/g", log: () => {} }));
  assert.equal(mut.env[NET_GUARD_BOX_SOCKETS_ENV], "1", "one listener per chain: the guard serves the box");
  // No guard, no claim: a box then serves its own listener.
  for (const [p, bin] of [[plan({ netGuard: false }), "/bin/g"], [plan(), null]] as const) {
    const m = emptyMutation();
    applyNetGuard(p, m, { resolveBin: () => bin, log: () => {} });
    assert.equal(m.env[NET_GUARD_BOX_SOCKETS_ENV], undefined);
  }
});

test("applyNetGuard: the guard files its events under the launch's session (exec-routing.md §7.5, Whose session)", () => {
  assert.equal(NET_GUARD_SESSION_ENV, "MANDU_SESSION_ID", "the variable mandu-net-guard reads (events::guard_session_id)");
  const mut = emptyMutation();
  assert.ok(applyNetGuard(plan({ scopeId: "1700000000-42" }), mut, { resolveBin: () => "/bin/g", log: () => {} }));
  assert.equal(mut.env[NET_GUARD_SESSION_ENV], "1700000000-42", "the id the model proxy files the session's turns under");
  // An outer launch's value names that launch: this one's wins.
  const nested = emptyMutation();
  nested.env[NET_GUARD_SESSION_ENV] = "outer";
  applyNetGuard(plan({ scopeId: "inner" }), nested, { resolveBin: () => "/bin/g", log: () => {} });
  assert.equal(nested.env[NET_GUARD_SESSION_ENV], "inner");
  // No guard (off, or not built): nothing to tell.
  for (const [p, bin] of [[plan({ netGuard: false }), "/bin/g"], [plan(), null]] as const) {
    const m = emptyMutation();
    applyNetGuard(p, m, { resolveBin: () => bin, log: () => {} });
    assert.equal(m.env[NET_GUARD_SESSION_ENV], undefined);
  }
});

test("sessionProxyPorts: the net-proxy's port only, when it is live (exec-routing.md §7.5, 2026-10-01)", () => {
  assert.deepEqual(sessionProxyPorts({ netProxyPort: 8790 }), [8790]);
  assert.deepEqual(sessionProxyPorts({ netProxyPort: null }), []);
  assert.deepEqual(sessionProxyPorts({ netProxyPort: 0 }), [], "a port not yet bound is no exception");
});

test("applyNetGuard: the guard learns the session-proxy ports a secret holder may reach; never the model proxy", () => {
  const withProxy = emptyMutation();
  assert.ok(applyNetGuard(plan({ netProxy: { host: "127.0.0.1", port: 8790 } } as Partial<LaunchPlan>), withProxy, { resolveBin: () => "/bin/g", log: () => {} }));
  assert.equal(withProxy.env[NET_GUARD_PROXY_PORTS_ENV], "8790");
  // No net-proxy: set, and empty (no exception at all; the guard's own
  // default is none too, so a missing variable cannot widen anything).
  const none = emptyMutation();
  assert.ok(applyNetGuard(plan(), none, { resolveBin: () => "/bin/g", log: () => {} }));
  assert.equal(none.env[NET_GUARD_PROXY_PORTS_ENV], "");
  // The model proxy (8788) and the U-LLM forwarder never: neither judges a
  // process's taint.
  const fwd = emptyMutation();
  applyNetGuard(plan({ ullmForwarder: { host: "127.0.0.1", port: 8791 } } as Partial<LaunchPlan>), fwd, { resolveBin: () => "/bin/g", log: () => {} });
  assert.equal(fwd.env[NET_GUARD_PROXY_PORTS_ENV], "");
  // No guard: nothing set.
  const off = emptyMutation();
  applyNetGuard(plan({ netGuard: false }), off, { resolveBin: () => "/bin/g", log: () => {} });
  assert.equal(off.env[NET_GUARD_PROXY_PORTS_ENV], undefined);
});

test("applyNetGuard: an OpenCode 2 launch names its executable for the guard's private-server allowance; no other launch does (supported-agents.md §2.3.1)", () => {
  const exe = "/opt/oc/node_modules/@opencode/cli/bin/opencode.exe";
  const logs: string[] = [];
  const oc2 = emptyMutation();
  assert.ok(applyNetGuard(plan({ ownServerExe: exe } as Partial<LaunchPlan>), oc2, { resolveBin: () => "/bin/g", log: (m) => logs.push(m) }));
  assert.equal(oc2.env[NET_GUARD_OWN_SERVER_ENV], exe);
  assert.equal(NET_GUARD_OWN_SERVER_ENV, "MANDU_NET_GUARD_OWN_SERVER");
  assert.ok(logs.some((l) => l.includes("the agent's private server") && l.includes(exe)));
  for (const p of [plan(), plan({ target: "opencode" } as Partial<LaunchPlan>)]) {
    const m = emptyMutation();
    applyNetGuard(p, m, { resolveBin: () => "/bin/g", log: () => {} });
    assert.equal(m.env[NET_GUARD_OWN_SERVER_ENV], undefined, "not set for any other launch");
  }
  const off = emptyMutation();
  applyNetGuard(plan({ ownServerExe: exe, netGuard: false } as Partial<LaunchPlan>), off, { resolveBin: () => "/bin/g", log: () => {} });
  assert.equal(off.env[NET_GUARD_OWN_SERVER_ENV], undefined, "no guard, nothing to tell it");
});

test("applyNetGuard: a launch that depends on the guard (plan.netGuardRequired) gets a wrap without --skip-unsupported; every other keeps the degrade", () => {
  const req = applyNetGuard(plan({ ownServerExe: "/x/opencode", netGuardRequired: true } as Partial<LaunchPlan>), emptyMutation(), { resolveBin: () => "/bin/g", log: () => {} });
  assert.ok(req);
  assert.ok(!req.wrapArgv.includes("--skip-unsupported"));
  assert.equal(req.wrapArgv.at(-1), "--");
  const plainWrap = applyNetGuard(plan(), emptyMutation(), { resolveBin: () => "/bin/g", log: () => {} });
  assert.ok(plainWrap?.wrapArgv.includes("--skip-unsupported"));
});

test("applyNetGuard: a hosted clean box hands the guard its socket, session, box and environment, before `--` (§5.3)", () => {
  const mut = emptyMutation();
  const p = plan({ scopeId: "sid-7", cleanHost: { socket: "/run/sid-7/clean.sock", boxBin: "/usr/lib/mandu/mandu-exec-box", env: [["PATH", "/usr/bin"]] } });
  const r = applyNetGuard(p, mut, { resolveBin: () => "/bin/g", log: () => {} });
  assert.ok(r);
  const argv = r.wrapArgv;
  const dash = argv.indexOf("--");
  const at = (flag: string) => argv.indexOf(flag);
  assert.ok(at("--clean-socket") > 0 && at("--clean-socket") < dash);
  assert.equal(argv[at("--clean-socket") + 1], "/run/sid-7/clean.sock");
  assert.equal(argv[at("--clean-session") + 1], "sid-7");
  assert.equal(argv[at("--clean-box") + 1], "/usr/lib/mandu/mandu-exec-box");
  const envs = argv.flatMap((a, i) => (a === "--clean-env" ? [argv[i + 1]] : []));
  assert.deepEqual(envs, ["PATH=/usr/bin", `${NET_GUARD_BOX_SOCKETS_ENV}=1`], "the hosted box knows the guard serves its sockets");
  // Nothing hosted: no clean arguments.
  const plain = applyNetGuard(plan(), emptyMutation(), { resolveBin: () => "/bin/g", log: () => {} });
  assert.ok(plain && !plain.wrapArgv.some((a) => a.startsWith("--clean-")));
});

test("applyNetGuard: the guard records itself in the session's status file, cleared from a reused --id (rootless §12.2)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-ng-status-"));
  try {
    const p = plan({ eventDir: join(dir, "events") });
    mkdirSync(p.eventDir, { recursive: true });
    const file = netGuardStatusFile(p);
    assert.equal(file, join(dir, "net-guard.status"), "in the scope-run dir, next to launch.log");
    writeFileSync(file, "supervising 1 2\n"); // the last launch's record
    const mut = emptyMutation();
    assert.ok(applyNetGuard(p, mut, { resolveBin: () => "/bin/g", log: () => {} }));
    assert.equal(mut.env[NET_GUARD_STATUS_ENV], file);
    assert.equal(existsSync(file), false, "a stale record cannot make this launch look like a dead guard");
    const off = emptyMutation();
    applyNetGuard(plan({ netGuard: false }), off, { resolveBin: () => "/bin/g", log: () => {} });
    assert.equal(off.env[NET_GUARD_STATUS_ENV], undefined, "no guard, no status file");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("applyNetGuard: default-on (netGuard undefined) applies the wrap too", () => {
  const mut = emptyMutation();
  const r = applyNetGuard(plan({ netGuard: undefined }), mut, { resolveBin: () => "/bin/g", log: () => {} });
  assert.ok(r, "undefined = default-on, not off");
  assert.equal(mut.launchPrefix[0], "/bin/g");
});

test("applyNetGuard: PREPENDS the wrap outermost, ahead of an existing (landlock-net) prefix", () => {
  const mut = emptyMutation();
  // Stand-in for the landlock-net wrap already prepended by applyLandlockNet.
  mut.launchPrefix = ["/bin/landlock-apply", "--net-only", "--"];
  const r = applyNetGuard(plan(), mut, { resolveBin: () => "/bin/g", log: () => {} });
  assert.ok(r);
  assert.equal(mut.launchPrefix[0], "/bin/g", "net-guard is now OUTERMOST (its supervisor is outside Landlock)");
  // The landlock-net wrap stays AFTER (inner).
  assert.deepEqual(mut.launchPrefix.slice(-3), ["/bin/landlock-apply", "--net-only", "--"]);
});

test("applyNetGuard: non-strict default banners the open *:443/*:22 trade-off", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyNetGuard(plan(), mut, { resolveBin: () => "/bin/g", log: (m) => logs.push(m) });
  assert.ok(r);
  assert.ok(specsAdmitAnyHttps(r!.specs));
  assert.ok(logs.some((l) => /net-guard LIVE/.test(l)));
  assert.ok(logs.some((l) => /permissive fallback/.test(l) && /still possible/.test(l)));
});

test("applyNetGuard: strict banners the precise posture (API host only on 443)", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyNetGuard(plan({ landlockNetStrict: true }), mut, { resolveBin: () => "/bin/g", log: (m) => logs.push(m) });
  assert.ok(r);
  assert.ok(!specsAdmitAnyHttps(r!.specs));
  assert.ok(logs.some((l) => /STRICT/.test(l) && /api\.anthropic\.com/.test(l)));
});

test("applyNetGuard: codex target admits api.openai.com on 443, not anthropic", () => {
  const mut = emptyMutation();
  const r = applyNetGuard(plan({ target: "codex", landlockNetStrict: true }), mut, { resolveBin: () => "/bin/g", log: () => {} });
  assert.ok(r!.specs.includes("tcp:api.openai.com:443"));
  assert.ok(!r!.specs.includes("tcp:api.anthropic.com:443"));
  // codex uses the openai-proxy port for the loopback service rule.
  assert.ok(r!.specs.includes("tcp:127.0.0.0/8:8789"));
});

test("applyNetGuard: curated --net-allow banners CURATED + includes the user's specs", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyNetGuard(plan({ netGuardAllow: ["registry.npmjs.org:443"] }), mut, { resolveBin: () => "/bin/g", log: (m) => logs.push(m) });
  assert.ok(r!.specs.includes("registry.npmjs.org:443"));
  assert.ok(!specsAdmitAnyHttps(r!.specs));
  assert.ok(logs.some((l) => /CURATED/.test(l)));
});

test("applyNetGuard: strict auto-allows workspace git remotes (injected reader) + banners them", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyNetGuard(
    plan({ landlockNetStrict: true }),
    mut,
    {
      resolveBin: () => "/bin/g",
      gitRemotes: () => ["https://github.com/o/r.git", "git@gitlab.example:o/r.git"],
      log: (m) => logs.push(m),
    },
  );
  assert.ok(r!.specs.includes("tcp:github.com:443"), "https remote → :443");
  assert.ok(r!.specs.includes("tcp:gitlab.example:22"), "ssh remote → :22");
  assert.ok(logs.some((l) => /auto-allowed .* git-remote/.test(l)));
});

test("applyNetGuard: the git remotes are read from the USER's workspace, not the AgentView cwd", () => {
  // With fs-sync on, plan.cwd is the AgentView worktree of the shadow repo
  // (fs-sync.md §3), which has no remotes: reading it auto-allowed
  // nothing (launcher-kernel-tier.live test 3, red until 2026-09-28).
  const seen: string[] = [];
  const r = applyNetGuard(
    plan({ landlockNetStrict: true, cwd: "/state/agentview", humanCwd: "/w" }),
    emptyMutation(),
    {
      resolveBin: () => "/bin/g",
      gitRemotes: (cwd) => { seen.push(cwd); return cwd === "/w" ? ["https://github.com/o/r.git"] : []; },
      log: () => {},
    },
  );
  assert.deepEqual(seen, ["/w"]);
  assert.ok(r!.specs.includes("tcp:github.com:443"));
});

test("applyNetGuard: --no-net-guard-git suppresses the git auto-allow even in strict", () => {
  const mut = emptyMutation();
  const r = applyNetGuard(
    plan({ landlockNetStrict: true, netGuardGitRemotes: false }),
    mut,
    { resolveBin: () => "/bin/g", gitRemotes: () => ["https://github.com/o/r.git"], log: () => {} },
  );
  assert.ok(!r!.specs.includes("tcp:github.com:443"));
});

test("applyNetGuard: the permissive default does NOT invoke the git reader (fallback covers remotes)", () => {
  const mut = emptyMutation();
  let called = false;
  applyNetGuard(plan(), mut, {
    resolveBin: () => "/bin/g",
    gitRemotes: () => { called = true; return ["https://github.com/o/r.git"]; },
    log: () => {},
  });
  assert.equal(called, false, "no git subprocess in the permissive non-strict default");
});

// ── stage 4b (policy-surface.md §2.3): the law's extra allows ───────

const BASE_INPUT = { targetProxyPort: 8788, netProxyPort: null, ullmForwarderPort: null, apiHost: "api.anthropic.com" };

test("computeNetGuardSpecs: extraAllow is ADDITIVE — the permissive fallback stays (never narrows)", () => {
  const specs = computeNetGuardSpecs({ ...BASE_INPUT, strict: false, extraAllow: ["tcp:registry.npmjs.org:443", " udp:10.0.0.0/8:* ", ""] });
  assert.ok(specs.includes("tcp:*:443") && specs.includes("tcp:*:22"), "fallback kept");
  assert.ok(specs.includes("tcp:registry.npmjs.org:443") && specs.includes("udp:10.0.0.0/8:*"), "extras appended, trimmed, blanks dropped");
  assert.ok(specsAdmitAnyHttps(specs), "still the permissive posture");
});

test("computeNetGuardSpecs: extraAllow rides strict AND curated launches (the point: survive a narrowed guard)", () => {
  const strict = computeNetGuardSpecs({ ...BASE_INPUT, strict: true, extraAllow: ["tcp:registry.npmjs.org:443"] });
  assert.ok(!strict.includes("tcp:*:443") && strict.includes("tcp:registry.npmjs.org:443"));
  const curated = computeNetGuardSpecs({ ...BASE_INPUT, strict: false, explicitAllow: ["tcp:pypi.org:443"], extraAllow: ["tcp:registry.npmjs.org:443", "tcp:pypi.org:443"] });
  assert.ok(!curated.includes("tcp:*:443"), "curation still drops the fallback");
  assert.equal(curated.filter((s) => s === "tcp:pypi.org:443").length, 1, "deduped against the curated set");
  assert.ok(curated.includes("tcp:registry.npmjs.org:443"));
});

test("applyNetGuard: deps.lawAllow lands in the specs and is named in the banner; absent → no extra line", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyNetGuard(plan(), mut, { resolveBin: () => "/bin/g", log: (m) => logs.push(m), lawAllow: ["tcp:registry.npmjs.org:443"] });
  assert.ok(r && r.specs.includes("tcp:registry.npmjs.org:443") && r.specs.includes("tcp:*:443"));
  assert.ok(logs.some((l) => /policy\.yaml allows 1 extra destination\(s\) \[tcp:registry\.npmjs\.org:443\]/.test(l)));
  const quiet: string[] = [];
  applyNetGuard(plan(), emptyMutation(), { resolveBin: () => "/bin/g", log: (m) => quiet.push(m), lawAllow: [] });
  assert.ok(!quiet.some((l) => /policy\.yaml allows/.test(l)));
});

test("applyNetGuard: a STALE guard bin is WARNED about (attention line) and the wrap still applies", () => {
  const mut = emptyMutation();
  const logs: string[] = [];
  const r = applyNetGuard(plan(), mut, {
    resolveBin: () => "/bin/g",
    staleNote: (name, path) => `mandu: WARNING — ${name} at ${path} is STALE`,
    log: (m) => logs.push(m),
  });
  assert.ok(r, "stale is a warning, not a degrade");
  assert.ok(logs.some((l) => /WARNING/.test(l) && /mandu-net-guard at \/bin\/g is STALE/.test(l)), JSON.stringify(logs));
});

// ── policy.yaml models: (confidentiality-plan-11 D5) ─────────────────────────
import { stateAxes } from "../axes.js";
stateAxes("secrets"); // the plan-11 cases below run under the mode with local-model in play; the spec logic reads no axis

test("computeNetGuardSpecs: model endpoint specs are appended in every posture (strict and curated too)", () => {
  const base = { targetProxyPort: 8788, netProxyPort: null, ullmForwarderPort: null, apiHost: "api.anthropic.com", modelEndpointSpecs: ["tcp:127.0.0.0/8:11434", "tcp:[::1]:11434"] };
  for (const extra of [{ strict: false }, { strict: true }, { strict: false, explicitAllow: ["tcp:example.com:443"] }]) {
    const specs = computeNetGuardSpecs({ ...base, ...extra });
    assert.ok(specs.includes("tcp:127.0.0.0/8:11434") && specs.includes("tcp:[::1]:11434"), JSON.stringify(specs));
  }
});

test("applyNetGuard: plan.modelEndpoints → the helper's entry pinned to its host, other local and external ones absent, banner line", () => {
  const logs: string[] = [];
  const r = applyNetGuard(plan({
    landlockNetStrict: true,
    modelEndpoints: [
      { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", local: true },
      { name: "lan", url: "http://192.168.1.5:8000", wire: "openai-chat", local: true },
      { name: "cloud", url: "https://llm.example.com:8443", wire: "anthropic", local: false },
    ],
  }), emptyMutation(), { resolveBin: () => "/bin/g", staleNote: () => null, log: (m) => logs.push(m) });
  assert.ok(r);
  for (const s of ["tcp:127.0.0.0/8:11434", "tcp:[::1]:11434"]) assert.ok(r.specs.includes(s), s);
  assert.ok(!r.specs.some((s) => s.includes("192.168.1.5")), "a local entry that is not the helper is not admitted");
  assert.ok(!r.specs.some((s) => s.includes("llm.example.com")), "an external declared endpoint is not admitted");
  assert.ok(logs.some((l) => /your own model endpoint\(s\) allowed/.test(l)), logs.join("\n"));
});
