/**
 * doctor-secrets.test — `mandu doctor --secrets` (secret-discovery.md §1
 * §3): the dry run over mocked seams. Asserts the inventory, the "not covered"
 * ledger, the env names-only inventory, the launch verdict, and that the
 * rendering never carries contents.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  envCandidates, gatherSecrets, historyCallTimeoutMs, historyClass, historyHiddenHere, renderPreparation, renderSecrets, runDoctorSecrets, wantsSecrets,
  HISTORY_ADVICE, HISTORY_ADVICE_MACOS,
  type DoctorSecretsDeps, type DoctorSecretsReport, type HistoryScanWire,
} from "../../src/doctor-secrets.js";
import { notCoveredNotice, type DiscoveryReport } from "../../src/secret-setup.js";
import { Layout } from "../../src/services/layout.js";

const HOME = "/home/u";
const RAW = "AKIA_NEVER_PRINTED_9911";

function disc(over: Partial<DiscoveryReport> = {}): DiscoveryReport {
  return {
    files: [
      { path: `${HOME}/.aws/credentials`, level: "no-model", rule: "catalog:aws" },
      { path: `${HOME}/.ssh/id_ed25519`, level: "no-model", rule: "catalog:ssh" },
      { path: `${HOME}/ws/.env`, level: "no-model", rule: "catalog:dotenv" },
    ],
    skipped: [
      { path: `${HOME}/deep/a/b/c/d`, reason: "depth" },
      { path: `${HOME}/.ssh/id_locked`, reason: "unreadable" },
      { path: `${HOME}/tools/linux`, reason: "symlinked-directory" },
      { path: `${HOME}/.claude`, reason: "agent-auth" },
      { path: `${HOME}/.claude.json`, reason: "agent-login" },
    ],
    counts: { "agent-auth": 4, "agent-login": 2, "symlinked-directory": 1, "dangling-symlink": 0, "unreadable": 1, "depth": 1, "count": 0, "unreadable-dir": 0 },
    limits: { maxDepth: 4, maxFiles: 256 },
    truncated: false,
    ...over,
  };
}

function deps(over: Partial<DoctorSecretsDeps> & { stops?: string[] } = {}): DoctorSecretsDeps {
  const stops = over.stops ?? [];
  return {
    arbiter: async () => ({ sock: "/run/a.sock", kind: "resident", axisOn: true, stop: async () => { stops.push("stopped"); } }),
    discover: async () => disc(),
    envNames: async (_s, names) => names.filter((n) => /_TOKEN$|_PASSWORD$/.test(n)),
    confinement: () => ({ posture: "confined" }),
    resolveTarget: (p) => (p.endsWith("id_ed25519") ? "/mnt/keys/real-key" : p),
    now: (() => { let t = 1000; return () => (t += 37); })(),
    // Pinned: this host's platform must not decide the wording under test
    // (a macOS launch hides no git history; the darwin tests below).
    platform: "linux",
    ...over,
  };
}
const env = { HOME, PATH: "/bin", GH_TOKEN: RAW, DB_PASSWORD: "pw", EMPTY_TOKEN: "", ANTHROPIC_API_KEY: "sk" };
const layout = Layout.dev("/repo");

test("gather: the inventory, the real path of a symlinked secret, the ledger, the env names, the timings, the arbiter stopped", async () => {
  const stops: string[] = [];
  const r = await gatherSecrets(env, layout, deps({ stops }), { cwd: `${HOME}/ws` });
  assert.deepEqual(r.roots, [HOME, `${HOME}/ws`]);
  assert.equal(r.files.length, 3);
  const key = r.files.find((f) => f.path.endsWith("id_ed25519"))!;
  assert.equal(key.real, "/mnt/keys/real-key", "the twin binds on the resolved path; the report says so");
  assert.equal(key.bind, "bind");
  assert.equal(r.files.find((f) => f.path.endsWith("credentials"))!.real, undefined);
  assert.equal(r.notCovered.counts["depth"], 1);
  assert.equal(r.notCovered.limits.maxFiles, 256);
  assert.deepEqual(r.env.masked, ["DB_PASSWORD", "GH_TOKEN"], "names only, sorted as the candidates are");
  assert.equal(r.env.checked, 5, "EMPTY_TOKEN (empty) is not a candidate");
  assert.ok(r.timings.discoverMs > 0);
  assert.deepEqual(r.launch, { ok: true, reason: null });
  assert.deepEqual(r.arbiter, { kind: "resident", sock: "/run/a.sock", axisOn: true });
  assert.deepEqual(stops, ["stopped"], "the arbiter handle is always released");
});

test("gather: the planner's drops are reported per file (two spellings of one file bind once; a vanished file is skipped)", async () => {
  const d = deps({
    discover: async () => disc({ files: [
      { path: `${HOME}/.ssh/link`, level: "no-model", rule: "catalog:ssh" },
      { path: `${HOME}/.ssh/real`, level: "no-model", rule: "catalog:ssh" },
      { path: `${HOME}/.aws/gone`, level: "no-model", rule: "catalog:aws" },
    ] }),
    resolveTarget: (p) => (p.endsWith("gone") ? null : `${HOME}/.ssh/real`),
  });
  const r = await gatherSecrets(env, layout, d, { cwd: HOME });
  const by = Object.fromEntries(r.files.map((f) => [f.path.split("/").pop()!, f]));
  assert.equal(by["link"]!.bind, "bind");
  assert.equal(by["real"]!.bind, "skipped");
  assert.match(by["real"]!.skipReason ?? "", /same file as .*link/);
  assert.equal(by["gone"]!.bind, "skipped");
  assert.match(by["gone"]!.skipReason ?? "", /no longer exists/);
});

test("gather: the launch verdict mirrors the launch — a host gap refuses only under require-confinement; an arbiter that cannot start refuses; a discovery error refuses", async () => {
  const gated = deps({ confinement: () => ({ posture: "gated", gap: "apparmor-userns" }) });
  const lenient = await gatherSecrets(env, layout, gated, { cwd: HOME });
  assert.equal(lenient.launch.ok, true, "gated degrades by default (root stays optional)");
  const strict = await gatherSecrets({ ...env, MANDU_REQUIRE_CONFINEMENT: "1" }, layout, gated, { cwd: HOME });
  assert.equal(strict.launch.ok, false);
  assert.match(strict.launch.reason ?? "", /--require-confinement is set .*AppArmor.*fix: mandu setup/);
  const noArb = await gatherSecrets(env, layout, deps({ arbiter: async () => { throw new Error("did not come up"); } }), { cwd: HOME });
  assert.equal(noArb.launch.ok, false);
  assert.match(noArb.launch.reason ?? "", /no arbiter could answer .*did not come up/);
  const broken = await gatherSecrets(env, layout, deps({ discover: async () => { throw new Error("walk timed out"); } }), { cwd: HOME });
  assert.equal(broken.launch.ok, false);
  assert.match(broken.launch.reason ?? "", /could not discover secrets \(walk timed out\)/);
});

test("gather: a resident arbiter with the secrets axis OFF is a WARNING (a launch attaching to it masks nothing), the inventory still comes from a throwaway", async () => {
  const r = await gatherSecrets(env, layout, deps({ arbiter: async () => ({ sock: "/run/t.sock", kind: "throwaway", axisOn: false, stop: async () => {} }) }), { cwd: HOME });
  assert.equal(r.files.length, 3);
  assert.equal(r.launch.ok, true);
  const arbOff = await gatherSecrets(env, layout, deps({ arbiter: async () => ({ sock: "/run/r.sock", kind: "resident", axisOn: false, stop: async () => {} }) }), { cwd: HOME });
  assert.match(arbOff.warnings[0] ?? "", /secrets axis OFF: a launch attaching to it masks NOTHING/);
});

test("render: every section, tilde paths, the resolved spelling, the ledger with marks, the verdict — and NEVER a value", async () => {
  const r = await gatherSecrets(env, layout, deps(), { cwd: `${HOME}/ws` });
  const out = renderSecrets(r, HOME);
  assert.match(out, /a dry run: nothing registered, no agent started/);
  assert.match(out, /roots: ~, ~\/ws/);
  assert.match(out, /✓ credential files are protected \(posture: confined\)/);
  assert.match(out, /placeholder copy of each credential file/);
  assert.match(out, /Checked by: the running Mandu service at \/run\/a\.sock \(secret protection on\)/);
  assert.match(out, /Would be masked: 3 credential files/);
  assert.match(out, /✓ ~\/\.ssh\/id_ed25519 → \/mnt\/keys\/real-key\s+no AI\s+catalog:ssh/);
  assert.match(out, /Environment: 2 of 5 variables would be masked: DB_PASSWORD, GH_TOKEN/);
  assert.match(out, /✗ 1 directory below depth 4 not searched: ~\/deep\/a\/b\/c\/d/);
  assert.match(out, /✗ 1 unreadable candidate: ~\/\.ssh\/id_locked/);
  assert.match(out, /· 1 directory link not followed: ~\/tools\/linux/);
  // secret-discovery.md §1.10: an agent's own data is raw in every session; a
  // login only in a session that runs that agent (no --target: every agent's).
  assert.match(out, /· 4 AI agents' own data folders \(left raw in every session: the agent reads and writes it; a command that names the path is masked for the AI\): ~\/\.claude/);
  assert.match(out, /· 2 AI agent login files \(left raw in a session that runs that agent \(Claude Code's: mandu claude, a plain command \(mandu -- <command>\) and mandu openclaw, and mandu goose or mandu opencode while Mandu's AI helper runs claude \(neither ANTHROPIC_API_KEY nor MANDU_ULLM_API_KEY set, and no --no-mcp\); Codex's: mandu codex and mandu openclaw; OpenCode's: mandu opencode\); in any other session it is masked like any credential file .*MANDU_OTHER_AGENT_LOGINS=raw.*\): ~\/\.claude\.json/);
  assert.ok(!/never masked/.test(out), "no promise that an agent's login is never masked");
  assert.match(out, /Launch: would start \(posture: confined\)/);
  assert.ok(!out.includes(RAW), "an env VALUE never reaches the report");
  assert.ok(!out.includes("\"pw\""), "no value, ever");
  // the guard-only posture renders its lines; a gap renders cause + fix; a refusal renders the reason
  const guard = renderSecrets({ ...r, posture: { posture: "confined", bindGap: "apparmor-userns" } }, HOME);
  assert.match(guard, /✓ credential files are protected \(posture: confined, by the guard alone\)/);
  assert.match(guard, /optional second layer: mandu setup/);
  const gated = renderSecrets({ ...r, posture: { posture: "gated", gap: "no-bwrap" }, launch: { ok: false, reason: "no bwrap" } }, HOME);
  assert.match(gated, /✗ credential files are NOT protected from programs the AI runs \(posture: gated\)/);
  assert.match(gated, /programs the AI runs can still read your credential files/);
  assert.match(gated, /fix: sudo apt install bubblewrap/);
  assert.match(gated, /Launch: would REFUSE to start: no bwrap/);
  // the clean case
  const clean: DoctorSecretsReport = { ...r, notCovered: { counts: {}, skipped: [], limits: { maxDepth: 4, maxFiles: 256 }, truncated: false } };
  assert.match(renderSecrets(clean, HOME), /✓ nothing skipped/);
  const benign: DoctorSecretsReport = { ...r, notCovered: { ...r.notCovered, counts: { ...r.notCovered.counts, depth: 0, unreadable: 0 } } };
  assert.match(renderSecrets(benign, HOME), /✓ nothing consequential/);
  const trunc = renderSecrets({ ...r, notCovered: { ...r.notCovered, truncated: true } }, HOME);
  assert.match(trunc, /✗ the walk stopped at the 256-file cap/);
});

test("gather: the home's view state base reaches the walk (it moves with MANDU_HOME; the retired MANDU_VIEW_STATE does not move it); render: the state dir and fs-sync's own masks are benign ledger lines", async () => {
  const seen: Array<string | undefined> = [];
  const d = deps({ discover: async (_s, _r, _h, stateBase) => { seen.push(stateBase); return disc({ counts: { ...disc().counts, "mandu-state": 1, "agentview-symbolized": 2, depth: 0, unreadable: 0 }, skipped: [
    { path: `${HOME}/.mandu`, reason: "mandu-state" },
    { path: `${HOME}/.mandu/workspaces/ws-1234/agentview/.env`, reason: "agentview-symbolized" },
  ] }); } });
  await gatherSecrets({ ...env, MANDU_VIEW_STATE: `${HOME}/.local/state/mandu/view-state` }, layout, d, { cwd: `${HOME}/ws` });
  const r = await gatherSecrets({ ...env, MANDU_HOME: "/srv/mh" }, layout, d, { cwd: `${HOME}/ws` });
  assert.deepEqual(seen, [`${HOME}/.mandu/state`, "/srv/mh/state"]);
  const out = renderSecrets(r, HOME);
  assert.match(out, /· 1 Mandu data folder not searched \(Mandu already knows the working copies it keeps there\): ~\/\.mandu/);
  assert.match(out, /· 2 AI working copies already masked by Mandu \(only placeholders inside\): ~\/\.mandu\/workspaces\/ws-1234\/agentview\/\.env/);
  assert.match(out, /✓ nothing consequential/, "neither reason is consequential");
  assert.deepEqual(notCoveredNotice({ files: [], ...r.notCovered }), [], "and neither reaches the launch WARNING");
});

test("gather: the package caches the environment moves reach the walk, those variables only (secret-discovery.md §1.9 G)", async () => {
  const seen: Array<Record<string, string> | undefined> = [];
  const d = deps({ discover: async (_s, _r, _h, _b, cacheEnv) => { seen.push(cacheEnv); return disc(); } });
  await gatherSecrets({ ...env, CARGO_HOME: "/srv/cargo", GOMODCACHE: "/srv/gomod", OPENAI_API_KEY: "sk-x" }, layout, d, { cwd: `${HOME}/ws` });
  await gatherSecrets(env, layout, d, { cwd: `${HOME}/ws` });
  assert.deepEqual(seen, [{ CARGO_HOME: "/srv/cargo", GOMODCACHE: "/srv/gomod" }, {}]);
});

test("runDoctorSecrets --target: the walk of that agent's launch (its login raw, the AI helper's CLI too, the login variables), said in the report; a bad agent is a usage error", async () => {
  const seen: Array<Record<string, unknown> | undefined> = [];
  const d = deps({
    discover: async (_s, _r, _h, _b, _c, login) => {
      seen.push(login as Record<string, unknown> | undefined);
      return disc({
        files: [...disc().files, { path: `${HOME}/.codex/auth.json`, level: "no-model", rule: "prefix:~/.codex", agentLogin: "codex" }],
        skipped: [{ path: `${HOME}/.claude.json`, reason: "agent-login" }],
        counts: { "agent-login": 1 },
      });
    },
  });
  const outs: string[] = [];
  const noKey = { HOME, PATH: "/bin", CODEX_HOME: `${HOME}/.codex`, OPENAI_API_KEY: "sk-x" };
  assert.equal(await runDoctorSecrets(["--secrets", "--target", "goose", "--no-history"], noKey, layout, d, { out: (s) => outs.push(s), cwd: `${HOME}/ws` }), 0);
  assert.deepEqual(seen[0], { target: "goose", ullmBinary: "claude", loginEnv: { CODEX_HOME: `${HOME}/.codex` } },
    "Goose's AI helper runs `claude -p`: Claude Code's login stays raw too");
  const out = outs.join("");
  assert.match(out, /agent: Goose \(--target goose: the logins this launch runs on stay raw, listed below; every other agent's is masked\)/, "the name `mandu why` uses");
  assert.match(out, /✓ ~\/\.codex\/auth\.json\s+no AI\s+prefix:~\/\.codex/, "another agent's login is in the inventory");
  assert.match(out, /· 1 AI agent login file \(left raw: the agent this launch runs, or Mandu's AI helper running that agent's program, logs in with it; .*MANDU_OTHER_AGENT_LOGINS=raw/);
  assert.ok(!out.includes("sk-x"));
  // API mode (ANTHROPIC_API_KEY set): the helper runs no CLI.
  await runDoctorSecrets(["--secrets", "--target", "codex", "--no-history"], { HOME, ANTHROPIC_API_KEY: "sk-ant" }, layout, d, { out: () => {}, cwd: `${HOME}/ws` });
  assert.deepEqual(seen[1], { target: "codex" });
  // No --target: no keying, every agent's login stays raw (the arbiter's default).
  await runDoctorSecrets(["--secrets", "--no-history"], { HOME }, layout, d, { out: () => {}, cwd: `${HOME}/ws` });
  assert.deepEqual(seen[2], {});
  // --no-mcp, as on a launch: no AI helper, so its `claude -p` keeps nothing.
  await runDoctorSecrets(["--secrets", "--target", "goose", "--no-mcp", "--no-history"], { HOME }, layout, d, { out: () => {}, cwd: `${HOME}/ws` });
  assert.deepEqual(seen[3], { target: "goose" }, "agrees with `mandu --no-mcp --target goose`");
  // MANDU_ULLM_API_KEY selects the helper's API mode too.
  await runDoctorSecrets(["--secrets", "--target", "opencode", "--no-history"], { HOME, MANDU_ULLM_API_KEY: "sk-ant-u" }, layout, d, { out: () => {}, cwd: `${HOME}/ws` });
  assert.deepEqual(seen[4], { target: "opencode" });
  // MANDU_OTHER_AGENT_LOGINS=raw: such a launch leaves another agent's
  // login readable, so it is not among the masked files.
  const rawOut: string[] = [];
  await runDoctorSecrets(["--secrets", "--target", "goose", "--no-history"], { HOME, MANDU_OTHER_AGENT_LOGINS: "raw" }, layout, d, { out: (x) => rawOut.push(x), cwd: `${HOME}/ws` });
  const r = rawOut.join("");
  assert.ok(!/✓ ~\/\.codex\/auth\.json/.test(r), r);
  assert.match(r, /· ~\/\.codex\/auth\.json\s+left readable: Codex's login \(MANDU_OTHER_AGENT_LOGINS=raw\), its values masked in what reaches the AI/);
  const json: string[] = [];
  await runDoctorSecrets(["--secrets", "--json", "--target", "goose", "--no-history"], { HOME, MANDU_OTHER_AGENT_LOGINS: "raw" }, layout, d, { out: (x) => json.push(x), cwd: `${HOME}/ws` });
  const row = (JSON.parse(json.join("")) as { files: Array<{ path: string; agentLogin?: string; readable?: boolean }> }).files.find((f) => f.path.endsWith("/.codex/auth.json"));
  assert.deepEqual([row?.agentLogin, row?.readable], ["codex", true]);
  const errs: string[] = [];
  const write = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((s: string) => { errs.push(String(s)); return true; }) as typeof process.stderr.write;
  try {
    assert.equal(await runDoctorSecrets(["--secrets", "--target", "vim"], { HOME }, layout, d, { out: () => {}, cwd: `${HOME}/ws` }), 2);
    assert.equal(await runDoctorSecrets(["--secrets", "--target"], { HOME }, layout, d, { out: () => {}, cwd: `${HOME}/ws` }), 2);
  } finally {
    process.stderr.write = write;
  }
  assert.equal(seen.length, 7, "a bad --target never walks");
  assert.match(errs.join(""), /--target wants one of claude\|codex\|openclaw\|opencode\|goose\|shell/);
});

test("render: Mandu's own install trees (mandu-install, checklist a5) are a benign ledger line, never the launch WARNING", async () => {
  const d = deps({ discover: async () => disc({ counts: { ...disc().counts, "mandu-install": 2, depth: 0, unreadable: 0 }, skipped: [
    { path: `${HOME}/.local/share/mandu/node`, reason: "mandu-install" },
    { path: `${HOME}/.local/share/mandu/pkg`, reason: "mandu-install" },
  ] }) });
  const r = await gatherSecrets(env, layout, d, { cwd: `${HOME}/ws` });
  const out = renderSecrets(r, HOME);
  assert.match(out, /· 2 Mandu install directories not walked \(Mandu's own package and Node\): ~\/\.local\/share\/mandu\/node, ~\/\.local\/share\/mandu\/pkg/);
  assert.match(out, /✓ nothing consequential/);
  assert.doesNotMatch(out, /below depth/);
  assert.deepEqual(notCoveredNotice({ files: [], ...r.notCovered }), [], "no launch WARNING for Mandu's own install");
});

test("render: too-deep directories inside package caches (package-cache) and sockets named like a secret (special-file) are benign ledger lines, listed but never the launch WARNING (secret-discovery.md §1.9 F)", async () => {
  const d = deps({ discover: async () => disc({ counts: { ...disc().counts, "package-cache": 412, "special-file": 2, depth: 0, unreadable: 0 }, skipped: [
    { path: `${HOME}/.cargo/registry/src/index.crates.io-x/serde-1.0.0`, reason: "package-cache" },
    { path: `${HOME}/.ssh/agent/s.abc.agent.x`, reason: "special-file" },
    { path: `${HOME}/.ssh/agent/s.abc.agent.y`, reason: "special-file" },
  ] }) });
  const r = await gatherSecrets(env, layout, d, { cwd: `${HOME}/ws` });
  const out = renderSecrets(r, HOME);
  assert.match(out, /· 412 directories below depth 4 inside package caches not searched \(skipped package caches: downloaded third-party code\): ~\/\.cargo\/registry\/src\/index\.crates\.io-x\/serde-1\.0\.0/);
  assert.match(out, /· 2 sockets, pipes or devices named like secrets \(no file to mask\): ~\/\.ssh\/agent\/s\.abc\.agent\.x, ~\/\.ssh\/agent\/s\.abc\.agent\.y/);
  assert.match(out, /✓ nothing consequential/);
  assert.doesNotMatch(out, /✗ \d+ unreadable candidate/);
  assert.deepEqual(notCoveredNotice({ files: [], ...r.notCovered }), [], "no launch WARNING for package caches or sockets");
  // beside a real miss, only the real miss is counted
  const mixed = notCoveredNotice({ files: [], ...r.notCovered, counts: { ...r.notCovered.counts, depth: 1, unreadable: 1 } });
  assert.ok(mixed.some((l) => /1 directory below depth 4 not searched/.test(l)));
  assert.ok(mixed.some((l) => /1 unreadable candidate/.test(l)));
  assert.ok(!mixed.some((l) => /412|package|socket/.test(l)), mixed.join("\n"));
});

test("the dry run lists the too-deep directories by folder, all of them, as the arbiter grouped them (secret-discovery.md §1.9 H)", async () => {
  const areas = [{ path: `${HOME}/project/app`, count: 216 }, { path: `${HOME}/project/lib`, count: 91 }, { path: `${HOME}/.oh-my-zsh-custom/plugins`, count: 6 }];
  const d = deps({ discover: async () => disc({ counts: { ...disc().counts, depth: 320, unreadable: 0 }, depthAreas: areas }) });
  const r = await gatherSecrets(env, layout, d, { cwd: `${HOME}/ws` });
  assert.deepEqual(r.notCovered.depthAreas, areas);
  const out = renderSecrets(r, HOME);
  assert.match(out, /✗ 320 directories below depth 4 not searched/);
  assert.match(out, /\n {6}by folder: ~\/project\/app \(216\), ~\/project\/lib \(91\), ~\/\.oh-my-zsh-custom\/plugins \(6\) and 7 more elsewhere\n/);
  // An older arbiter sends no areas: no line, no field.
  const old = await gatherSecrets(env, layout, deps({ discover: async () => disc() }), { cwd: `${HOME}/ws` });
  assert.equal(old.notCovered.depthAreas, undefined);
  assert.doesNotMatch(renderSecrets(old, HOME), /by folder/);
});

test("notCoveredNotice (the launch-time WARNING) names the consequential skips only, with a few paths, and points at the dry run", () => {
  const lines = notCoveredNotice(disc());
  assert.match(lines[0]!, /^WARNING: mandu: secrets NOT covered by the walk/);
  assert.ok(lines.some((l) => /1 directory below depth 4 not searched: \/home\/u\/deep\/a\/b\/c\/d/.test(l)));
  assert.ok(lines.some((l) => /1 unreadable candidate: \/home\/u\/\.ssh\/id_locked/.test(l)));
  assert.ok(!lines.some((l) => /agent-auth|linux/.test(l)), "expected skips stay quiet at launch");
  assert.match(lines[lines.length - 1]!, /mandu doctor --secrets/);
  assert.deepEqual(notCoveredNotice({ files: [] }), [], "a bare (old-arbiter) reply warns about nothing");
  assert.deepEqual(notCoveredNotice(disc({ counts: { depth: 0, count: 0, unreadable: 0 }, truncated: false })), []);
  const cap = notCoveredNotice(disc({ counts: { count: 12 }, skipped: [{ path: "/a", reason: "count" }, { path: "/b", reason: "count" }, { path: "/c", reason: "count" }, { path: "/d", reason: "count" }], truncated: true }));
  assert.ok(cap.some((l) => /12 credential files beyond the 256-file cap: \/a, \/b, \/c, \+1 more/.test(l)));
  assert.ok(cap.some((l) => /the walk stopped at the 256-file cap/.test(l)));
});

test("envCandidates / wantsSecrets", () => {
  assert.deepEqual(envCandidates({ B: "1", A: "2", C: "", D: undefined }), ["A", "B"]);
  assert.equal(wantsSecrets(["--secrets", "--json"]), true);
  assert.equal(wantsSecrets(["--live"]), false);
});

test("gather (WSL): each Windows profile is probed as its own home, exactly as a launch probes it, and the report lists what it would mask there", async () => {
  const PROFILE = "/mnt/c/Users/bob";
  const calls: Array<{ roots: string[]; home: string }> = [];
  const d = deps({
    windowsProfiles: () => [PROFILE],
    discover: async (_s, roots, home) => {
      calls.push({ roots, home });
      if (home !== PROFILE) return disc();
      return {
        files: [
          { path: `${PROFILE}/.aws/credentials`, level: "no-model", rule: "catalog:aws" },
          { path: `${PROFILE}/_netrc`, level: "no-model", rule: "catalog:netrc" },
        ],
        skipped: [{ path: `${PROFILE}/.ssh/id_locked`, reason: "unreadable" }],
        counts: { unreadable: 1 },
        limits: { maxDepth: 4, maxFiles: 256 },
      };
    },
  });
  const r = await gatherSecrets(env, layout, d, { cwd: `${HOME}/ws` });
  assert.equal(calls.length, 2);
  assert.equal(calls[1]!.home, PROFILE, "the profile is the home its ~/ rules anchor to");
  assert.ok(calls[1]!.roots.includes(`${PROFILE}/.aws`) && calls[1]!.roots.includes(`${PROFILE}/_netrc`), "the catalog's paths, never the profile itself");
  assert.ok(!calls[1]!.roots.includes(PROFILE));
  assert.deepEqual(r.windowsProfiles, [PROFILE]);
  assert.equal(r.files.length, 5);
  assert.equal(r.files.find((f) => f.path === `${PROFILE}/_netrc`)?.profile, PROFILE);
  assert.equal(r.files.find((f) => f.path === `${HOME}/.aws/credentials`)?.profile, undefined);
  assert.equal(r.notCovered.counts["unreadable"], 2, "the profile's ledger adds to the HOME's");
  const out = renderSecrets(r, HOME);
  assert.match(out, /Windows profiles \(WSL, their credential stores only\): \/mnt\/c\/Users\/bob/);
  assert.match(out, /Would be masked: 5 credential files/);
  assert.match(out, /✓ \/mnt\/c\/Users\/bob\/_netrc\s+no AI\s+catalog:netrc/);
  // No guard around the launch: the dry run predicts the launch's refusal.
  const noGuard = await gatherSecrets(env, layout, { ...d, guardAvailable: () => false }, { cwd: `${HOME}/ws` });
  assert.equal(noGuard.launch.ok, false);
  assert.match(noGuard.launch.reason ?? "", /2 Windows credential file\(s\) sit on a drive that ignores case/);
  assert.equal((await gatherSecrets(env, layout, deps({ guardAvailable: () => false }), { cwd: `${HOME}/ws` })).launch.ok, true, "Linux files alone need no guard");
  // Off WSL (or a fixture without the seam): no profiles, no second walk, no line.
  const plain = await gatherSecrets(env, layout, deps(), { cwd: `${HOME}/ws` });
  assert.deepEqual(plain.windowsProfiles, []);
  assert.doesNotMatch(renderSecrets(plain, HOME), /Windows profiles/);
  // A profile the arbiter cannot walk fails the dry run the way it fails a launch.
  const broken = await gatherSecrets(env, layout, deps({ windowsProfiles: () => [PROFILE], discover: async (_s, _r, home) => { if (home === PROFILE) throw new Error("9p timed out"); return disc(); } }), { cwd: HOME });
  assert.equal(broken.launch.ok, false);
  assert.match(broken.launch.reason ?? "", /under \/mnt\/c\/Users\/bob \(9p timed out\)/);
});

// ── the git-history section (secret-discovery.md §3, phase 1) ────────────────────

/** A scan as the arbiter answers it: findings in each class, and a cap. */
function scanWire(over: Partial<HistoryScanWire> = {}): HistoryScanWire {
  const base = { repoRoot: `${HOME}/ws`, inHead: false, inIndex: false, stillPresent: false, pathStillSecretByCatalog: false };
  return {
    axis: true,
    repos: [{ root: `${HOME}/ws`, repoRoot: `${HOME}/ws` }],
    counts: { blobs: 40, scanned: 38, classified: 3 },
    capped: { tooBig: 2, overTotal: 0, overTime: 0, binary: 0, pathsUnchecked: 0, untraced: 0, unlisted: false, lines: ["2 blob(s) over 1 MiB not read (MANDU_HISTORY_SCAN_BLOB_MAX_KB)"] },
    findings: [
      {
        ...base, blob: "a".repeat(40), paths: ["deploy/id_ed25519"], firstCommit: "1".repeat(40), lastCommit: "2".repeat(40),
        detector: { kind: "content-shape", rule: "private-key", line: 1, preview: "-----BEGIN OPENSSH PRIVATE KEY-----…" },
        detectors: [{ kind: "content-shape", rule: "private-key", line: 1, preview: "-----BEGIN OPENSSH PRIVATE KEY-----…" }],
      },
      {
        ...base, blob: "b".repeat(40), paths: ["config.py", "old/config.py"], firstCommit: "3".repeat(40), lastCommit: "3".repeat(40), inHead: true, stillPresent: true,
        detector: { kind: "content-shape", rule: "stripe-key", line: 4, preview: "sk_live_…" },
        detectors: [{ kind: "content-shape", rule: "stripe-key", line: 4, preview: "sk_live_…" }, { kind: "content-shape", rule: "credential-assignment", line: 5, preview: "DB_PASSWORD=…" }],
      },
      {
        ...base, blob: "c".repeat(40), paths: [".env"], firstCommit: null, lastCommit: null, inIndex: true, stillPresent: true, pathStillSecretByCatalog: true,
        detector: { kind: "content-shape", rule: "github-token", line: 2, preview: "ghp_…" },
        detectors: [{ kind: "content-shape", rule: "github-token", line: 2, preview: "ghp_…" }],
      },
      {
        ...base, blob: "d".repeat(40), paths: [".env.old"], firstCommit: "4".repeat(40), lastCommit: "5".repeat(40),
        detector: { kind: "catalog-path", rule: "catalog:dotenv", path: ".env.old", level: "no-model" },
        detectors: [{ kind: "catalog-path", rule: "catalog:dotenv", path: ".env.old", level: "no-model" }],
      },
    ],
    limits: { blobMaxBytes: 1048576, totalMaxBytes: 268435456, timeoutMs: 60000, traceMax: 20, classifyMax: 5000 },
    ms: 420,
    ...over,
  };
}

test("gather: the history scan asks the arbiter for the workspace's history, classifies each finding, and times it", async () => {
  const asked: Array<{ sock: string; roots: string[]; home: string }> = [];
  const d = deps({ historyScan: async (sock, roots, home) => { asked.push({ sock, roots, home }); return scanWire(); } });
  const r = await gatherSecrets(env, layout, d, { cwd: `${HOME}/ws` });
  assert.deepEqual(asked, [{ sock: "/run/a.sock", roots: [`${HOME}/ws`], home: HOME }], "the dry run's arbiter, the workspace root, the launch's HOME");
  assert.equal(r.history?.status, "scanned");
  assert.deepEqual(r.history?.classes, ["history-only", "file-unprotected", "covered", "history-only"]);
  assert.ok(r.timings.historyMs > 0);
  assert.deepEqual(r.launch, { ok: true, reason: null }, "findings are advisory: never a launch verdict");
});

test("gather: --no-history skips the scan; an axis-OFF answer and a failed call are said, never a refusal", async () => {
  let called = 0;
  const skip = await gatherSecrets(env, layout, deps({ historyScan: async () => { called++; return scanWire(); } }), { cwd: HOME, history: false });
  assert.equal(called, 0);
  assert.deepEqual(skip.history, { status: "skipped", reason: "--no-history" });
  const off = await gatherSecrets(env, layout, deps({ historyScan: async () => scanWire({ axis: false }) }), { cwd: HOME });
  assert.equal(off.history?.status, "skipped");
  assert.match(off.history?.reason ?? "", /secret protection off/);
  const failed = await gatherSecrets(env, layout, deps({ historyScan: async () => { throw new Error("arbiter timed out"); } }), { cwd: HOME });
  assert.deepEqual(failed.history, { status: "failed", reason: "arbiter timed out" });
  assert.equal(failed.launch.ok, true);
  const none = await gatherSecrets(env, layout, deps(), { cwd: HOME });
  assert.equal(none.history, null, "no seam, no section");
  assert.match(renderSecrets(failed, HOME), /Git history: not scanned \(arbiter timed out\)/);
});

test("render: the history section groups findings by what would close them, with masks, commits and caps, never a value", async () => {
  const r = await gatherSecrets(env, layout, deps({ historyScan: async () => scanWire() }), { cwd: `${HOME}/ws` });
  const out = renderSecrets(r, HOME);
  assert.match(out, /Git history of ~\/ws \(38 of 40 file versions read in 0\.4 s; values are never shown\)/);
  assert.match(out, /✗ 2 files only in git history, not protected:/);
  assert.match(out, /deploy\/id_ed25519 {3}private key -----BEGIN OPENSSH PRIVATE KEY-----… \(line 1\)/);
  assert.match(out, /blob aaaaaaaa, added 11111111, last 22222222\n/);
  assert.match(out, /\.env\.old {3}a deleted file named like a credential file \(\.env\.old, catalog:dotenv\)/);
  assert.match(out, /what would close it: nothing hides these from the AI today .*Rotate the key: it is in every clone/);
  assert.match(out, /✗ 1 file still in the work tree, not protected:/);
  assert.match(out, /config\.py \(\+1 more name\) {3}Stripe live key sk_live_… \(line 4\)/);
  assert.match(out, /blob bbbbbbbb, added 33333333; 1 more hit in it\n/);
  assert.match(out, /what would close it: if the file still holds the key, protect it/);
  assert.match(out, /✓ 1 file covered \(protected now\):/);
  assert.match(out, /blob cccccccc, staged, in no commit/);
  assert.match(out, /· not scanned: 2 blob\(s\) over 1 MiB not read/);
  // The history section sits after the ledger and before the verdict.
  assert.ok(out.indexOf("Not covered") < out.indexOf("Git history") && out.indexOf("Git history") < out.indexOf("Launch:"));
  assert.ok(!out.includes(RAW), "never a value");
});

test("render: the versions of one file are one entry; past 20 files the rest are counted", async () => {
  const one = scanWire().findings[0]!;
  const versions = [0, 1, 2].map((i) => ({ ...one, blob: String(i).repeat(40) }));
  const many = Array.from({ length: 23 }, (_, i) => ({ ...one, blob: "e".repeat(39) + String(i % 10), paths: [`k/${String(i).padStart(2, "0")}`] }));
  const r = await gatherSecrets(env, layout, deps({ historyScan: async () => scanWire({ findings: [...versions, ...many] }) }), { cwd: `${HOME}/ws` });
  const out = renderSecrets(r, HOME);
  assert.match(out, /✗ 24 files only in git history, not protected \(26 versions\):/);
  assert.match(out, /blob 00000000, added 11111111, last 22222222; 2 other versions of this file too/);
  assert.match(out, /\+4 more files \(--json lists every version\)/);
});

test("render: a clean history, a directory in no repository", async () => {
  const noCaps = { tooBig: 0, overTotal: 0, overTime: 0, binary: 0, pathsUnchecked: 0, untraced: 0, unlisted: false, lines: [] };
  const clean = await gatherSecrets(env, layout, deps({ historyScan: async () => scanWire({ findings: [], capped: noCaps }) }), { cwd: `${HOME}/ws` });
  assert.match(renderSecrets(clean, HOME), /✓ no secret-shaped file version found/);
  const norepo = await gatherSecrets(env, layout, deps({ historyScan: async () => scanWire({ repos: [{ root: HOME, repoRoot: null, reason: "not in a git work tree" }], findings: [] }) }), { cwd: HOME });
  assert.match(renderSecrets(norepo, HOME), /Git history: not scanned \(not in a git work tree\)/);
});

test("runDoctorSecrets: --json carries the findings as the arbiter sent them, --no-history reaches the gather, the exit code ignores findings", async () => {
  const outs: string[] = [];
  let calls = 0;
  const d = deps({ historyScan: async () => { calls++; return scanWire(); } });
  const code = await runDoctorSecrets(["--secrets", "--json"], env, layout, d, { out: (s) => outs.push(s), cwd: `${HOME}/ws` });
  assert.equal(code, 0);
  const j = JSON.parse(outs.join("")) as DoctorSecretsReport;
  assert.equal(j.history?.scan?.findings.length, 4);
  assert.equal(j.history?.scan?.findings[0]!.detector.kind, "content-shape");
  await runDoctorSecrets(["--secrets", "--no-history"], env, layout, d, { out: (s) => outs.push(s), cwd: `${HOME}/ws` });
  assert.equal(calls, 1);
  assert.match(outs.join(""), /Git history: not scanned \(--no-history\)/);
  assert.equal(historyCallTimeoutMs({}), 90_000);
  assert.equal(historyCallTimeoutMs({ MANDU_HISTORY_SCAN_TIMEOUT_S: "300" }), 330_000);
});

test("historyClass: covered beats present; present beats history-only", () => {
  assert.deepEqual(scanWire().findings.map(historyClass), ["history-only", "file-unprotected", "covered", "history-only"]);
  assert.ok(HISTORY_ADVICE["history-only"].includes("Rotate"));
  // Plan 14 §5.3: the report stays read-only and points to the review.
  assert.ok(HISTORY_ADVICE["history-only"].includes("`mandu policy suggest`"));
  assert.ok(HISTORY_ADVICE["file-unprotected"].includes("`mandu policy suggest`"));
});

// ── Plan 14 §11.1 R3: the preparation of sanitized copies ──────────────────

const PREP = {
  ready: 2, pending: [`${HOME}/work/b`], capped: [{ root: `${HOME}/big`, reason: "a pack of 2000 MiB is over the 1024 MiB a cycle may rebuild" }],
  failed: [], bytes: 30 * 1048576, caps: { cycleBytes: 1024 * 1048576, totalBytes: 4096 * 1048576 }, at: 1,
};

test("gather + render: the resident arbiter's preparation is asked (no roots) and said in counts and paths; a throwaway, an old or a malformed answer adds no section", async () => {
  const asked: string[] = [];
  const r = await gatherSecrets(env, layout, deps({ gitLocks: async (sock) => { asked.push(sock); return { axis: true, preparation: PREP }; } }), { cwd: HOME });
  assert.deepEqual(asked, ["/run/a.sock"]);
  assert.deepEqual(r.preparation, PREP);
  const out = renderSecrets(r, HOME);
  assert.match(out, /Locked keys in other repositories' git history: 4 repositories Mandu knows hold one/);
  assert.match(out, / {2}2 prepared \(a launch anywhere serves their sanitized copies/);
  assert.match(out, / {2}1 pending \(being prepared; until then git there is refused in a launch\): ~\/work\/b/);
  assert.match(out, / {2}1 not prepared, over a size cap .*MANDU_GIT_PREP_CYCLE_MB 1024 MiB, MANDU_GIT_PREP_TOTAL_MB 4096 MiB\): ~\/big/);
  assert.ok(out.indexOf("Locked keys") < out.indexOf("Launch:"));
  assert.deepEqual(r.launch, { ok: true, reason: null }, "advisory: never a launch verdict");
  const throwaway = await gatherSecrets(env, layout, deps({
    arbiter: async () => ({ sock: "/tmp/x.sock", kind: "throwaway", axisOn: true, stop: async () => {} }),
    gitLocks: async () => { throw new Error("must not be asked"); },
  }), { cwd: HOME });
  assert.equal(throwaway.preparation, null, "a throwaway arbiter prepares nothing");
  const old = await gatherSecrets(env, layout, deps({ gitLocks: async () => ({ axis: true }) }), { cwd: HOME });
  assert.equal(old.preparation, null);
  const bad = await gatherSecrets(env, layout, deps({ gitLocks: async () => ({ axis: true, preparation: { ready: "x" } as never }) }), { cwd: HOME });
  assert.equal(bad.preparation, null);
  const failed = await gatherSecrets(env, layout, deps({ gitLocks: async () => { throw new Error("unknown op"); } }), { cwd: HOME });
  assert.equal(failed.preparation, null);
  const empty = await gatherSecrets(env, layout, deps({ gitLocks: async () => ({ axis: true, preparation: { ...PREP, ready: 0, pending: [], capped: [] } }) }), { cwd: HOME });
  assert.ok(!renderSecrets(empty, HOME).includes("Locked keys"), "nothing locked anywhere: no section");
  const paused = await gatherSecrets(env, layout, deps({ gitLocks: async () => ({ axis: true, preparation: { ...PREP, paused: "1 unconfined launch is live" } }) }), { cwd: HOME });
  assert.match(renderSecrets(paused, HOME), /paused: 1 unconfined launch is live/);
});

// ── macOS: a launch hides no git history (confidentiality.md §7.3) ───────────

test("historyHiddenHere: Linux yes, darwin no; a report without a platform is judged by its posture (read-blocked is macOS)", () => {
  assert.equal(historyHiddenHere({ platform: "linux", posture: { posture: "confined" } }), true);
  assert.equal(historyHiddenHere({ platform: "darwin", posture: { posture: "read-blocked" } }), false);
  assert.equal(historyHiddenHere({ platform: "darwin", posture: { posture: "gated", gap: "unsupported-os" } }), false, "a gated macOS hides none either");
  assert.equal(historyHiddenHere({ posture: { posture: "read-blocked" } }), false);
  assert.equal(historyHiddenHere({ posture: { posture: "confined" } }), true);
});

test("render, macOS: the history advice never says a launch hides a committed version; a protected file's history is not 'covered'; Linux wording unchanged", async () => {
  const mac = deps({ platform: "darwin", confinement: () => ({ posture: "read-blocked" }), historyScan: async () => scanWire() });
  const r = await gatherSecrets(env, layout, mac, { cwd: `${HOME}/ws` });
  assert.equal(r.platform, "darwin");
  const out = renderSecrets(r, HOME);
  assert.ok(!/a launch hides it|hides the file and every committed version|the rule that hides them from the AI/.test(out), out);
  assert.match(out, /✗ 1 file protected now, its git history still readable on macOS:/);
  assert.ok(!/✓ 1 file covered/.test(out), "no check mark for a history macOS leaves readable");
  assert.match(out, /what would close it: nothing hides these from the AI .*on macOS a rule does not either: only Linux hides a file's git history/);
  assert.match(out, /what would close it: if the file still holds the key, protect it .*makes the file unreadable to the AI, but on macOS its committed versions stay readable/);
  assert.match(out, /what would close it: the file is protected now, so a launch makes it unreadable to the AI, but on macOS its committed versions stay readable/);
  for (const advice of Object.values(HISTORY_ADVICE_MACOS)) assert.ok(!/launch hides/.test(advice), advice);
  // The same scan on Linux keeps its words.
  const linux = renderSecrets(await gatherSecrets(env, layout, deps({ historyScan: async () => scanWire() }), { cwd: `${HOME}/ws` }), HOME);
  assert.match(linux, /✓ 1 file covered \(protected now\):/);
  assert.ok(linux.includes(HISTORY_ADVICE["covered"]));
  assert.ok(!linux.includes("on macOS"));
});

test("render, macOS: the arbiter prepares no copies there (preparedCopiesOff), so its lock answer carries no preparation and the report has no such section; the macOS history wording holds; Linux wording unchanged", async () => {
  const asked: string[] = [];
  const r = await gatherSecrets(env, layout, deps({
    platform: "darwin", confinement: () => ({ posture: "read-blocked" }), historyScan: async () => scanWire(),
    gitLocks: async (sock) => { asked.push(sock); return { axis: true }; },
  }), { cwd: `${HOME}/ws` });
  assert.deepEqual(asked, ["/run/a.sock"], "the resident arbiter is still asked");
  assert.equal(r.preparation, null);
  const out = renderSecrets(r, HOME);
  assert.ok(!/Locked keys|prepared|sanitized copies|refused in a launch|git works there/.test(out), out);
  assert.match(out, /✗ 1 file protected now, its git history still readable on macOS:/);
  assert.match(out, /what would close it: the file is protected now, so a launch makes it unreadable to the AI, but on macOS its committed versions stay readable/);
  assert.ok(!/a launch hides it|hides the file and every committed version/.test(out), out);
  const linux = renderPreparation(PREP, HOME);
  assert.match(linux.join("\n"), /2 prepared \(a launch anywhere serves their sanitized copies: git works there/);
  assert.ok(!linux.join("\n").includes("macOS"));
});
