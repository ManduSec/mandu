/**
 * parse.test — argv+env → LaunchPlan parity with mandu-run.sh.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parse as parseIn, commandStart, batchMemberOf, ullmCliBinary } from "../../src/parse.js";
import { usageText } from "../../src/usage.js";
import { TARGETS, isTarget } from "../../src/types.js";
import { hermetic } from "../lib/test-runtime.js";

/** parse with this file's own runtime dir when the env names none: parse
 *  resolves (and checks) the runtime base, and a bare `{}` would make that
 *  the host's shared /tmp/mandu (test-runtime.ts). */
const parse = hermetic(parseIn, 1);

const BASE_ENV = { HOME: "/home/u", PWD: "/work", XDG_RUNTIME_DIR: "/run/u" };
/** The opt-in the FROZEN integrity axis needs (docs/design/architecture/protection-modes.md §10):
 *  the axis-resolution tests below still pin how injection/full resolve, so
 *  they carry it; the freeze itself is tested in its own section. */
const OPT_IN = { MANDU_EXPERIMENTAL_INTEGRITY: "1" };

// ── bare argv (packaging.md §1): the first non-flag token starts the agent argv ──

test("bare form: `mandu claude -p …` — no `--` needed, argv verbatim from the command", () => {
  const p = parse(["claude", "-p", "summarize ./notes.md"], BASE_ENV);
  assert.equal(p.target, "claude");
  assert.deepEqual(p.argv, ["claude", "-p", "summarize ./notes.md"]);
});

test("scope id: minted as <epochSec>-<pid> only when neither --id nor MANDU_SCOPE_ID names it (scopeIdGenerated)", () => {
  const minted = parse(["claude"], BASE_ENV);
  assert.equal(minted.scopeIdGenerated, true);
  assert.match(minted.scopeId, new RegExp(`^\\d+-${process.pid}$`));
  const flag = parse(["--id", "s1", "claude"], BASE_ENV);
  assert.equal(flag.scopeIdGenerated, false);
  assert.equal(flag.scopeId, "s1");
  const envNamed = parse(["claude"], { ...BASE_ENV, MANDU_SCOPE_ID: "s2" });
  assert.equal(envNamed.scopeIdGenerated, false);
  assert.equal(envNamed.scopeId, "s2");
});

test("scope id: REFUSED unless it is one folder name that is none of Mandu's own runtime entries (runtime-registry.ts; runtime-instances.md §2)", () => {
  // The scope's dir is <runtime base>/<id>: a registry name would put the
  // launch's files in a registry, and the macOS profile would have had to
  // leave that registry writable (it used to, with a WARNING).
  for (const bad of [
    "instances", "current", "arbiter.sock", "dashboards", "dashboard.log", "dashboard-4242.port", "dashboardX", "vm-guests", "logs", "test",
    "human", ".current.tmp-1", "instances/x", "a/b", "/abs", ".", "..", "x\0y",
  ]) {
    assert.throws(() => parse(["--id", bad, "claude"], BASE_ENV), /cannot name a session/, `--id ${JSON.stringify(bad)}`);
    assert.throws(() => parse(["claude"], { ...BASE_ENV, MANDU_SCOPE_ID: bad }), /cannot name a session/, `MANDU_SCOPE_ID=${JSON.stringify(bad)}`);
  }
  assert.throws(() => parse(["--id", "logs", "claude"], BASE_ENV), /"logs" cannot name a session: `logs` is one of Mandu's own entries in the runtime folder/);
  // Names beside them stay free, as does the minted form and an unset one.
  for (const ok of ["instances.old", "current-work", "logs2", "testing", "1790000000-4242", "named-scope", ".current.tmpX"]) {
    assert.equal(parse(["--id", ok, "claude"], BASE_ENV).scopeId, ok);
  }
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_SCOPE_ID: "" }).scopeIdGenerated, true);
});

test("codexAuth: a set key variable is `key`; none (or blank) is `sign-in` (agent-sign-in.md §2.4)", () => {
  assert.equal(parse(["codex"], BASE_ENV).codexAuth, "sign-in");
  assert.equal(parse(["codex"], { ...BASE_ENV, OPENAI_API_KEY: "  " }).codexAuth, "sign-in");
  assert.equal(parse(["codex"], { ...BASE_ENV, OPENAI_API_KEY: "sk-x" }).codexAuth, "key");
  const cx = parse(["codex"], { ...BASE_ENV, CODEX_API_KEY: "sk-x" });
  assert.deepEqual([cx.codexAuth, cx.openaiEnvKey], ["key", "CODEX_API_KEY"]);
});

test("bare form: launcher flags BEFORE the command are consumed; codex auto-detected", () => {
  const p = parse(["--no-scope", "--id", "sess1", "codex", "exec"], BASE_ENV);
  assert.equal(p.noScope, true);
  assert.equal(p.scopeId, "sess1");
  assert.equal(p.target, "codex");
  assert.deepEqual(p.argv, ["codex", "exec"]);
});

test("bare form: flags AFTER the command belong to the AGENT, not the launcher", () => {
  // `--no-scope` here is the agent's arg (it follows the command token), so the
  // launcher must NOT set noScope and must pass it through verbatim.
  const p = parse(["claude", "--no-scope", "-p", "hi"], BASE_ENV);
  assert.equal(p.noScope, false);
  assert.deepEqual(p.argv, ["claude", "--no-scope", "-p", "hi"]);
});

test("bare form: all-flags/no-command still throws the usage error", () => {
  assert.throws(() => parse(["--no-scope"], BASE_ENV), /no command/);
});

test("MANDU_BATCH_ID → plan.batchId (unset/empty → absent)", () => {
  const withBatch = parse(["claude"], { ...BASE_ENV, MANDU_BATCH_ID: "agent-123" });
  assert.equal(withBatch.batchId, "agent-123");
  assert.equal(parse(["claude"], BASE_ENV).batchId, undefined);
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_BATCH_ID: "" }).batchId, undefined);
});

test("MANDU_BATCH_MEMBER → plan.batchMember: scenario:<key> / posture:<key>; anything else absent, never an error", () => {
  assert.deepEqual(parse(["claude"], { ...BASE_ENV, MANDU_BATCH_MEMBER: "scenario:U1" }).batchMember, { kind: "scenario", key: "U1" });
  assert.deepEqual(parse(["claude"], { ...BASE_ENV, MANDU_BATCH_MEMBER: "posture:S1" }).batchMember, { kind: "posture", key: "S1" });
  assert.deepEqual(batchMemberOf("scenario:S3@claude-haiku-4.5#2"), { kind: "scenario", key: "S3@claude-haiku-4.5#2" });
  assert.equal(parse(["claude"], BASE_ENV).batchMember, undefined);
  for (const bad of ["", "U1", "group:S1", "scenario:", "scenario:-x", "scenario:a b", "scenario:a/b", "posture:" + "x".repeat(81)]) {
    assert.equal(batchMemberOf(bad), undefined, bad);
    assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_BATCH_MEMBER: bad }).batchMember, undefined, bad);
  }
});

test("tenant (policy-surface.md §2.7): live by default; --tenant / MANDU_TENANT set it; garbage is refused", () => {
  assert.equal(parse(["claude"], BASE_ENV).tenant, "live");
  assert.equal(parse(["--tenant", "test", "claude"], BASE_ENV).tenant, "test");
  assert.equal(parse(["--tenant=test", "claude"], BASE_ENV).tenant, "test");
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_TENANT: "test" }).tenant, "test");
  // The flag wins over the env, in both directions.
  assert.equal(parse(["--tenant", "live", "claude"], { ...BASE_ENV, MANDU_TENANT: "test" }).tenant, "live");
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_TENANT: "" }).tenant, "live", "empty env = unset");
  assert.throws(() => parse(["--tenant", "staging", "claude"], BASE_ENV), /must be "live" or "test"/);
  assert.throws(() => parse(["claude"], { ...BASE_ENV, MANDU_TENANT: "TEST" }), /must be "live" or "test"/);
  // `--tenant test claude`: the value is consumed, `claude` is still the command.
  assert.deepEqual(parse(["--tenant", "test", "claude", "-p", "hi"], BASE_ENV).argv, ["claude", "-p", "hi"]);
});

test("`--` still disambiguates: launch a program whose name collides with a flag", () => {
  // An unknown program name now ALSO needs an explicit --target (inference
  // refuses to guess — see below); the `--` keeps doing its one job of
  // marking where the agent argv begins.
  const p = parse(["--target", "claude", "--", "--no-scope"], BASE_ENV);
  assert.equal(p.noScope, false);
  assert.deepEqual(p.argv, ["--no-scope"]);
});

test("target inference: each known agent basename maps to itself", () => {
  assert.equal(parse(["claude"], BASE_ENV).target, "claude");
  assert.equal(parse(["codex"], BASE_ENV).target, "codex");
  assert.equal(parse(["openclaw", "agent", "--local"], BASE_ENV).target, "openclaw");
  assert.equal(parse(["opencode", "run", "hi"], BASE_ENV).target, "opencode");
  // Path form: inference is on the basename.
  assert.equal(parse(["/usr/local/bin/openclaw", "chat"], BASE_ENV).target, "openclaw");
  // OpenCode 2's own command is inferred as opencode, so it launches as OpenCode 2
  // or is refused with its reason (agent-versions.ts opencodeLaunchRefusal), not "cannot infer".
  assert.equal(parse(["opencode2", "run", "hi"], BASE_ENV).target, "opencode");
});

test("target inference REFUSES an unknown agent instead of guessing claude", () => {
  // The old default-to-claude was a silent-unprotected hole: openclaw/opencode
  // ignore ANTHROPIC_BASE_URL, so a claude-shaped env delta defends nothing —
  // the launch must fail loudly, naming the escape hatch.
  assert.throws(() => parse(["my-agent-wrapper.sh"], BASE_ENV), /cannot infer the target agent/);
  assert.throws(() => parse(["--", "node", "agent.mjs"], BASE_ENV), /--target claude\|codex\|openclaw\|opencode/);
});

test("--target accepts all four agents and rejects the rest", () => {
  assert.equal(parse(["--target", "openclaw", "--", "node", "openclaw.mjs", "chat"], BASE_ENV).target, "openclaw");
  assert.equal(parse(["--target", "opencode", "--", "oc-nightly"], BASE_ENV).target, "opencode");
  assert.throws(() => parse(["--target", "gemini", "--", "gemini"], BASE_ENV), /invalid --target 'gemini'/);
});

test("the targets are the agent registry's agents and `shell`, as they were (types.ts TARGETS; supported-agents.md §5.7)", () => {
  assert.deepEqual([...TARGETS], ["claude", "codex", "openclaw", "opencode", "goose", "shell"]);
  for (const t of TARGETS) assert.equal(isTarget(t), true, t);
  for (const t of ["", "gemini", "opencode2", "Claude", "bash"]) assert.equal(isTarget(t), false, t);
  assert.throws(() => parse(["--target", "gemini", "--", "gemini"], BASE_ENV), /\(want claude\|codex\|openclaw\|opencode\|goose\|shell\)$/);
  for (const t of TARGETS) assert.equal(parse(["--target", t, "--", "my-wrapper.sh"], BASE_ENV).target, t, `--target ${t}`);
  // Inferred from the agent's own basename (and OpenCode 2's command as opencode).
  for (const a of ["claude", "codex", "openclaw", "opencode", "goose"]) {
    let target: string | undefined;
    try { target = parse(["--", `/usr/bin/${a}`, "--version"], BASE_ENV).target; } catch (e) { assert.doesNotMatch(String(e), /cannot infer/, a); continue; }
    assert.equal(target, a);
  }
  assert.throws(() => parse(["--", "/usr/bin/aider"], BASE_ENV), /cannot infer the target agent/);
});

test("a POSIX shell infers the plain-command `shell` target (agent-e2e-harness.md §9.1)", () => {
  // The help promises `mandu -- <command>`; a shell is plainly not an agent.
  for (const sh of ["bash", "sh", "dash", "zsh", "ksh", "mksh", "ash", "fish"]) {
    assert.equal(parse(["--", sh, "-c", "echo hi"], BASE_ENV).target, "shell", sh);
  }
  assert.equal(parse(["--", "/bin/bash"], BASE_ENV).target, "shell", "inference is on the basename");
  assert.equal(parse(["bash"], BASE_ENV).target, "shell", "the bare form too");
  const p = parse(["--", "bash", "-c", "echo $X"], BASE_ENV);
  assert.deepEqual(p.argv, ["bash", "-c", "echo $X"], "argv verbatim");
  // An interpreter is NOT a shell: `node openclaw.mjs` is an agent, so the
  // refusal (and its hint) stays for everything else.
  assert.throws(() => parse(["--", "python3", "x.py"], BASE_ENV), /cannot infer the target agent from 'python3'.*--target shell/);
  assert.throws(() => parse(["--", "bash-agent-wrapper"], BASE_ENV), /cannot infer/, "a name that merely starts with a shell's name");
});

test("--target shell runs ANY command as a plain command, and an explicit agent target still wins over a shell", () => {
  assert.equal(parse(["--target", "shell", "--", "python3", "check.py"], BASE_ENV).target, "shell");
  assert.equal(parse(["--target", "shell", "--", "node", "x.mjs"], BASE_ENV).target, "shell");
  // The live oracles' shape: a bash stand-in under an explicit claude target.
  assert.equal(parse(["--target", "claude", "--", "bash", "-c", "x"], BASE_ENV).target, "claude");
  assert.match(
    String((() => { try { parse(["--target", "gemini", "--", "x"], BASE_ENV); } catch (e) { return (e as Error).message; } })()),
    /want claude\|codex\|openclaw\|opencode\|goose\|shell/,
  );
});

test("every launch form the --help usage lines show parses (the help promises only what works)", () => {
  const help = usageText();
  assert.match(help, /mandu -- bash/);
  assert.match(help, /--target shell -- <command…>/);
  assert.equal(parse(["--", "bash"], BASE_ENV).target, "shell");
  assert.equal(parse(["--target", "shell", "--", "make", "test"], BASE_ENV).target, "shell");
  assert.equal(parse(["claude"], BASE_ENV).target, "claude");
});

test("commandStart: skips flags + their space-form values, stops at the first bare token", () => {
  assert.equal(commandStart(["--no-scope", "--id", "x", "claude", "-p"]), 3);
  assert.equal(commandStart(["claude", "-p"]), 0);
  assert.equal(commandStart(["--no-scope"]), 1); // no command → past the end
});

test("reply-filter: default ON; --no-reply-filter and MANDU_REPLY_FILTER=0 opt out", () => {
  assert.equal(parse(["claude"], BASE_ENV).replyFilter, true);
  assert.equal(parse(["--no-reply-filter", "claude"], BASE_ENV).replyFilter, false);
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_REPLY_FILTER: "0" }).replyFilter, false);
  // Bash parity: only the exact "1" (or unset/empty) keeps it on.
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_REPLY_FILTER: "1" }).replyFilter, true);
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_REPLY_FILTER: "" }).replyFilter, true);
  // A flag wins over the env.
  assert.equal(parse(["--reply-filter", "claude"], { ...BASE_ENV, MANDU_REPLY_FILTER: "0" }).replyFilter, true);
});

test("session summary (the session's last line): default ON; --no-session-summary and MANDU_SESSION_SUMMARY=0 opt out; a flag wins", () => {
  assert.equal(parse(["claude"], BASE_ENV).sessionSummary, undefined, "absent = on");
  assert.equal(parse(["--no-session-summary", "claude"], BASE_ENV).sessionSummary, false);
  for (const v of ["0", "false", "off", "no", "OFF"]) assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_SESSION_SUMMARY: v }).sessionSummary, false, v);
  for (const v of ["1", "", "yes"]) assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_SESSION_SUMMARY: v }).sessionSummary, undefined, JSON.stringify(v));
  assert.equal(parse(["--session-summary", "claude"], { ...BASE_ENV, MANDU_SESSION_SUMMARY: "0" }).sessionSummary, undefined);
  assert.equal(parse(["--session-summary", "--no-session-summary", "claude"], BASE_ENV).sessionSummary, false, "the last flag wins");
});

test("auto-detects claude from argv[0], passes argv verbatim after --", () => {
  const p = parse(["--", "claude", "--dangerously-skip-permissions"], BASE_ENV);
  assert.equal(p.target, "claude");
  assert.deepEqual(p.argv, ["claude", "--dangerously-skip-permissions"]);
  assert.equal(p.writeMcp, true);
  assert.equal(p.noScope, false);
});

test("auto-detects codex from argv[0] basename", () => {
  const p = parse(["--", "/usr/bin/codex", "exec"], BASE_ENV);
  assert.equal(p.target, "codex");
});

test("--target overrides detection; invalid target throws", () => {
  assert.equal(parse(["--target", "codex", "--", "claude"], BASE_ENV).target, "codex");
  assert.throws(() => parse(["--target", "nope", "--", "x"], BASE_ENV), /target/);
});

test("=-form flags carry values; net-proxy-mitm implies net-proxy", () => {
  const p = parse(["--exec-wrap=curl,git", "--net-proxy-mitm", "--", "claude"], BASE_ENV);
  assert.deepEqual(p.execWrapCmds, ["curl", "git"]);
  assert.equal(p.requested.execWrap, true);
  assert.equal(p.requested.netProxy, true);
  assert.equal(p.requested.netProxyMitm, true);
});

test("unshare is retired: any request (flag or env) fails closed at parse time", () => {
  assert.throws(() => parse(["--unshare", "claude"], {}), /unshare was retired/);
  assert.throws(() => parse(["--unshare-net", "claude"], {}), /unshare was retired/);
  assert.throws(() => parse(["claude"], { MANDU_UNSHARE: "1" }), /unshare was retired/);
  assert.throws(() => parse(["claude"], { MANDU_UNSHARE_NET: "1" }), /unshare was retired/);
  // Falsy/unset stays harmless (a stale env export must not brick a launch).
  assert.ok(parse(["claude"], { MANDU_UNSHARE: "0", MANDU_UNSHARE_NET: "" }));
});

test("defaults: arbiter sock under runtime dir, scope id present, exec cmds default", () => {
  const p = parse(["--", "claude"], BASE_ENV);
  // Bare env with nothing live: the `current` SPELLING + mode "autostart" —
  // run.ts starts an instance-mode arbiter that promotes this rendezvous
  // (runtime-instances.md §5), never a second pinned resident daemon.
  assert.equal(p.arbiterSock, "/run/u/mandu/current/arbiter.sock");
  assert.equal(p.arbiterSockMode, "autostart");
  assert.equal(p.arbiterRuntimeBase, "/run/u/mandu");
  assert.match(p.scopeId, /.+/);
  assert.deepEqual(p.execWrapCmds, ["curl", "wget", "nc"]);
  // Release checklist a1: kernel-assigned by default, so a second user or a
  // resident stack on the same host never collides with this launch.
  assert.equal(p.proxy.port, 0);
  assert.equal(p.openaiProxy.port, 0);
});

test("scope run dir (runtime-instances.md §3b): <runtime base>/<scopeId> — MANDU_RUNTIME_DIR, XDG, a short TMPDIR, else the /tmp/mandu-<uid> fallback", () => {
  const events = (env: Record<string, string>): string =>
    parse(["--id", "sid", "--", "claude"], { HOME: "/home/u", PWD: "/work", ...env }).eventDir;
  assert.equal(events({ XDG_RUNTIME_DIR: "/run/u" }), "/run/u/mandu/sid/events", "Linux: unchanged");
  assert.equal(events({ XDG_RUNTIME_DIR: "/run/u", MANDU_RUNTIME_DIR: "/iso/rt" }), "/iso/rt/sid/events", "MANDU_RUNTIME_DIR moves the scope dirs with the instances (on-disk-layout.md §5)");
  assert.equal(events({ TMPDIR: "/t/" }), `/t/mandu-${process.getuid!()}/sid/events`);
  const uid = process.getuid?.();
  if (uid !== undefined) {
    // A TMPDIR too long for an instance socket on ANY platform (the macOS
    // per-user T/ dir is too long for darwin's 104 bytes): the scope dir
    // leaves it the same way the arbiter does. The fallback root is the test hook.
    const long = { TMPDIR: "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/" + "x".repeat(10), MANDU_RUNTIME_FALLBACK_ROOT: "/fbroot" };
    assert.equal(events(long), `/fbroot/mandu-${uid}/sid/events`);
    const p = parse(["--id", "sid", "--", "claude"], { HOME: "/home/u", PWD: "/work", ...long });
    assert.equal(p.arbiterRuntimeBase, `/fbroot/mandu-${uid}`, "the arbiter and the scope dirs share the base");
    assert.equal(p.arbiterSock, `/fbroot/mandu-${uid}/current/arbiter.sock`);
  }
});

test("proxy ports (a1): a pinned env/config port wins; an out-of-band proxy (NO_CONTEXT_PROXY) keeps the well-known 8788/8789 rendezvous", () => {
  const pinned = parse(["--", "claude"], { ...BASE_ENV, MANDU_PROXY_PORT: "18788", MANDU_OPENAI_PROXY_PORT: "18789" });
  assert.equal(pinned.proxy.port, 18788);
  assert.equal(pinned.openaiProxy.port, 18789);
  const oob = parse(["--", "claude"], { ...BASE_ENV, MANDU_NO_CONTEXT_PROXY: "1" });
  assert.equal(oob.proxy.port, 8788, "an out-of-band proxy has no port file: the well-known port is its only rendezvous");
  assert.equal(oob.openaiProxy.port, 8789);
  assert.equal(parse(["--", "claude"], { ...BASE_ENV, MANDU_NO_CONTEXT_PROXY: "1", MANDU_PROXY_PORT: "9999" }).proxy.port, 9999);
});

test("fs-sync off reason (a4): integrity OFF marks it `mode`; an explicit --no-fs-sync with integrity on carries no reason (the DEGRADED warning)", () => {
  const byMode = parse(["--mode", "secrets", "--", "claude"], BASE_ENV);
  assert.equal(byMode.fsSync, false);
  assert.equal(byMode.fsSyncOffReason, "mode");
  const both = parse(["--no-fs-sync", "--mode", "secrets", "--", "claude"], BASE_ENV);
  assert.equal(both.fsSyncOffReason, "mode", "the mode does not need the twin at all: no warning even with the flag");
  const optOut = parse(["--no-fs-sync", "--mode", "full", "--", "claude"], { ...BASE_ENV, ...OPT_IN });
  assert.equal(optOut.fsSync, false);
  assert.equal(optOut.fsSyncOffReason, undefined);
  assert.equal(parse(["--", "claude"], { ...BASE_ENV, ...OPT_IN, MANDU_FS_SYNC: "0", MANDU_MODE: "injection" }).fsSyncOffReason, undefined);
});

test("ephemeral proxy port (0) parses; combined with NO_CONTEXT_PROXY it refuses (no rendezvous)", () => {
  // Port 0 alone is a valid ask: the launcher-started proxy publishes the
  // kernel-assigned port back via the port file.
  const p = parse(["--", "claude"], { ...BASE_ENV, MANDU_PROXY_PORT: "0" });
  assert.equal(p.proxy.port, 0);
  // …but an out-of-band proxy (NO_CONTEXT_PROXY) can never rendezvous with
  // port 0 — the composed base URL would dial :0. Fail-closed at parse.
  assert.throws(
    () => parse(["--", "claude"], { ...BASE_ENV, MANDU_PROXY_PORT: "0", MANDU_NO_CONTEXT_PROXY: "1" }),
    /ephemeral.*requires the launcher-started context proxy/i,
  );
  assert.throws(
    () => parse(["--", "claude"], { ...BASE_ENV, MANDU_OPENAI_PROXY_PORT: "0", MANDU_NO_CONTEXT_PROXY: "1" }),
    /ephemeral/i,
  );
});

test("unknown option before -- throws (exit-2 parity)", () => {
  assert.throws(() => parse(["--bogus", "--", "claude"], BASE_ENV), /unknown option/);
});

test("empty command after -- throws (usage parity)", () => {
  assert.throws(() => parse(["--"], BASE_ENV), /no command/);
});

test("--no-mcp / --no-scope / --best-effort flip their flags", () => {
  const p = parse(["--no-mcp", "--no-scope", "--best-effort", "--", "claude"], BASE_ENV);
  assert.equal(p.writeMcp, false);
  assert.equal(p.noScope, true);
  assert.equal(p.bestEffort, true);
});

test("--no-policy-mcp / MANDU_POLICY_MCP=0 drop the policy server; default leaves the field absent (on)", () => {
  assert.equal(parse(["--", "claude"], BASE_ENV).writePolicyMcp, undefined);
  assert.equal(parse(["--no-policy-mcp", "--", "claude"], BASE_ENV).writePolicyMcp, false);
  assert.equal(parse(["--", "claude"], { ...BASE_ENV, MANDU_POLICY_MCP: "0" }).writePolicyMcp, false);
  assert.equal(parse(["--no-policy-mcp", "--", "claude"], BASE_ENV).writeMcp, true, "the inspect server stays");
});

test("net-proxy / exec-wrap tri-state: unset/empty → auto(undefined); env/flags on/off", () => {
  // Default-on posture: unset OR set-but-empty env ⇒ undefined (auto — the
  // manager starts the service, degrading on failure).
  const auto = parse(["--", "claude"], BASE_ENV);
  assert.equal(auto.requested.netProxy, undefined);
  assert.equal(auto.requested.execWrap, undefined);
  const empty = parse(["--", "claude"], { ...BASE_ENV, MANDU_NET_PROXY: "", MANDU_EXEC_WRAP: "" });
  assert.equal(empty.requested.netProxy, undefined);
  assert.equal(empty.requested.execWrap, undefined);
  // Explicit env: 1 ⇒ true (fail-closed), 0 ⇒ false (opt out).
  const envOn = parse(["--", "claude"], { ...BASE_ENV, MANDU_NET_PROXY: "1", MANDU_EXEC_WRAP: "1" });
  assert.equal(envOn.requested.netProxy, true);
  assert.equal(envOn.requested.execWrap, true);
  const envOff = parse(["--", "claude"], { ...BASE_ENV, MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0" });
  assert.equal(envOff.requested.netProxy, false);
  assert.equal(envOff.requested.execWrap, false);
  // The --no-* flags win over the env.
  const off = parse(["--no-net-proxy", "--no-exec-wrap", "--", "claude"], { ...BASE_ENV, MANDU_NET_PROXY: "1", MANDU_EXEC_WRAP: "1" });
  assert.equal(off.requested.netProxy, false);
  assert.equal(off.requested.execWrap, false);
});

test("captures the agent-facing PATH as basePath", () => {
  const p = parse(["--", "claude"], { ...BASE_ENV, PATH: "/opt/bin:/usr/bin" });
  assert.equal(p.basePath, "/opt/bin:/usr/bin");
});

test("ullm: cli mode by default (no key), binary mirrors target", () => {
  assert.equal(parse(["--", "claude"], BASE_ENV).ullm.mode, "cli");
  assert.equal(parse(["--", "claude"], BASE_ENV).ullm.binary, "claude");
  assert.equal(parse(["--", "codex"], BASE_ENV).ullm.binary, "codex");
  // The one rule, shared with `mandu doctor --secrets --target` (secret-discovery.md §1.10).
  for (const t of ["claude", "openclaw", "opencode", "goose", "shell"] as const) assert.equal(ullmCliBinary(t, {}), "claude", t);
  assert.equal(ullmCliBinary("codex", {}), "codex");
  assert.equal(ullmCliBinary("claude", { ANTHROPIC_API_KEY: "sk-ant" }), null, "API mode runs no CLI");
  assert.equal(ullmCliBinary("codex", { MANDU_ULLM_API_KEY: "sk-ant" }), null);
});

test("ullm: a codex U-LLM carries the launcher's CODEX_HOME; claude's and an api U-LLM never do", () => {
  assert.equal(parse(["--", "codex"], { ...BASE_ENV, CODEX_HOME: "/h/codex" }).ullm.codexHome, "/h/codex");
  assert.equal(parse(["--", "codex"], BASE_ENV).ullm.codexHome, undefined);
  assert.equal(parse(["--", "claude"], { ...BASE_ENV, CODEX_HOME: "/h/codex" }).ullm.codexHome, undefined);
  assert.equal(parse(["--", "codex"], { ...BASE_ENV, CODEX_HOME: "/h/codex", MANDU_ULLM_API_KEY: "sk-1" }).ullm.codexHome, undefined);
});

test("ullm: a codex U-LLM's forwarder pair comes from MANDU_ULLM_OPENAI_UPSTREAM / MANDU_ULLM_CHATGPT_UPSTREAM, absent otherwise", () => {
  assert.equal(parse(["--", "codex"], BASE_ENV).ullm.codexUpstreams, undefined);
  assert.deepEqual(parse(["--", "codex"], { ...BASE_ENV, MANDU_ULLM_OPENAI_UPSTREAM: "http://127.0.0.1:9" }).ullm.codexUpstreams,
    { api: "http://127.0.0.1:9", chatgpt: "https://chatgpt.com/backend-api/codex" });
  assert.deepEqual(parse(["--", "codex"], { ...BASE_ENV, MANDU_ULLM_CHATGPT_UPSTREAM: "http://127.0.0.1:9/backend-api/codex" }).ullm.codexUpstreams,
    { api: "https://api.openai.com", chatgpt: "http://127.0.0.1:9/backend-api/codex" });
  assert.equal(parse(["--", "claude"], { ...BASE_ENV, MANDU_ULLM_OPENAI_UPSTREAM: "http://127.0.0.1:9" }).ullm.codexUpstreams, undefined);
});

test("ullm: api mode when a key is present", () => {
  const p = parse(["--", "claude"], { ...BASE_ENV, MANDU_ULLM_API_KEY: "sk-1" });
  assert.equal(p.ullm.mode, "api");
  assert.equal(p.ullm.apiKey, "sk-1");
});

test("fs-sync tri-state: unset → auto(undefined); env/flag on/off; flags win over env", () => {
  assert.equal(parse(["--", "claude"], {}).fsSync, undefined);
  assert.equal(parse(["--", "claude"], { MANDU_FS_SYNC: "" }).fsSync, undefined);
  assert.equal(parse(["--", "claude"], { MANDU_FS_SYNC: "0" }).fsSync, false);
  assert.equal(parse(["--", "claude"], { MANDU_FS_SYNC: "1" }).fsSync, true);
  assert.equal(parse(["--fs-sync", "--", "claude"], { MANDU_FS_SYNC: "0" }).fsSync, true);
  assert.equal(parse(["--no-fs-sync", "--", "claude"], { MANDU_FS_SYNC: "1" }).fsSync, false);
});

test("fs-sync-eager: default ON (Phase 2); --no-fs-sync-eager / MANDU_FS_SYNC_EAGER=0 opt out; empty env stays on", () => {
  assert.equal(parse(["--", "claude"], {}).fsSyncEager, true);
  assert.equal(parse(["--fs-sync-eager", "--", "claude"], {}).fsSyncEager, true);
  assert.equal(parse(["--", "claude"], { MANDU_FS_SYNC_EAGER: "1" }).fsSyncEager, true);
  assert.equal(parse(["--", "claude"], { MANDU_FS_SYNC_EAGER: "" }).fsSyncEager, true);
  assert.equal(parse(["--", "claude"], { MANDU_FS_SYNC_EAGER: "0" }).fsSyncEager, false);
  assert.equal(parse(["--no-fs-sync-eager", "--", "claude"], {}).fsSyncEager, false);
  // The flag beats the env, both directions.
  assert.equal(parse(["--fs-sync-eager", "--", "claude"], { MANDU_FS_SYNC_EAGER: "0" }).fsSyncEager, true);
  assert.equal(parse(["--no-fs-sync-eager", "--", "claude"], { MANDU_FS_SYNC_EAGER: "1" }).fsSyncEager, false);
  // The eager flag does not touch the fs-sync tri-state itself.
  assert.equal(parse(["--fs-sync-eager", "--", "claude"], {}).fsSync, undefined);
});

test("context-proxy opt-out, humanCwd", () => {
  // The launch directory is the real cwd (launch-cwd.ts); an in-process
  // caller names it explicitly.
  const p = parse(["--", "claude"], {
    MANDU_NO_CONTEXT_PROXY: "1", PWD: "/w",
  }, "/w");
  assert.equal(p.noContextProxy, true);
  assert.equal(p.humanCwd, "/w");
  assert.equal(p.cwd, "/w");
  const q = parse(["--", "claude"], { PWD: "/w" });
  assert.equal(q.noContextProxy, false);
});

test("the event dir is always the scope run dir's; the retired MANDU_EVENT_DIR / MANDU_VIEW_STATE are not read", () => {
  const env = { PWD: "/w", MANDU_RUNTIME_DIR: "/rt", MANDU_ARBITER_SOCK: "/rt/a.sock" };
  const p = parse(["--", "claude"], { ...env, MANDU_EVENT_DIR: "/elsewhere/events", MANDU_VIEW_STATE: "/dv" });
  assert.equal(p.eventDir, `/rt/${p.scopeId}/events`);
  assert.ok(!("viewState" in p), "no view-state override rides in the plan");
  const q = parse(["--", "claude"], env);
  assert.equal(q.eventDir, `/rt/${q.scopeId}/events`);
});

// ── confidentiality axis flag (confidentiality.md §11 kill switch) ───────────

test("--confidentiality / --no-confidentiality set the tri-state; default undefined", () => {
  assert.equal(parse(["claude"], {}).confidentiality, undefined);
  assert.equal(parse(["--confidentiality", "claude"], {}).confidentiality, true);
  assert.equal(parse(["--no-confidentiality", "claude"], {}).confidentiality, false);
});

test("an exported MANDU_CONFIDENTIALITY is honored; an explicit flag overrides it", () => {
  assert.equal(parse(["claude"], { MANDU_CONFIDENTIALITY: "1" }).confidentiality, true);
  assert.equal(parse(["claude"], { MANDU_CONFIDENTIALITY: "0" }).confidentiality, false);
  // empty/unset ⇒ undefined (leave the arbiter's own default alone)
  assert.equal(parse(["claude"], { MANDU_CONFIDENTIALITY: "" }).confidentiality, undefined);
  // the flag wins over the env
  assert.equal(
    parse(["--no-confidentiality", "claude"], { MANDU_CONFIDENTIALITY: "1" }).confidentiality,
    false,
  );
});

// ── integrity axis flag (arbiter policy/integrity-flag.ts; two-axis dual) ────

test("--integrity / --no-integrity set the tri-state; default undefined (arbiter default ON)", () => {
  assert.equal(parse(["claude"], {}).integrity, undefined);
  assert.equal(parse(["--integrity", "claude"], OPT_IN).integrity, true);
  assert.equal(parse(["--no-integrity", "claude"], {}).integrity, false);
});

test("an exported MANDU_INTEGRITY is honored; an explicit flag overrides it", () => {
  assert.equal(parse(["claude"], { ...OPT_IN, MANDU_INTEGRITY: "1" }).integrity, true);
  assert.equal(parse(["claude"], { MANDU_INTEGRITY: "0" }).integrity, false);
  assert.equal(parse(["claude"], { MANDU_INTEGRITY: "" }).integrity, undefined);
  assert.equal(
    parse(["--integrity", "claude"], { ...OPT_IN, MANDU_INTEGRITY: "0" }).integrity,
    true,
  );
});

test("--no-integrity forces fsSync=false (the AgentView twin is integrity machinery)", () => {
  assert.equal(parse(["--no-integrity", "claude"], {}).fsSync, false);
  // …even against an explicit opt-in, in either order.
  assert.equal(parse(["--no-integrity", "--fs-sync", "claude"], {}).fsSync, false);
  assert.equal(parse(["--fs-sync", "--no-integrity", "claude"], {}).fsSync, false);
  assert.equal(parse(["--no-integrity", "claude"], { MANDU_FS_SYNC: "1" }).fsSync, false);
  // integrity ON (or default) leaves fsSync alone.
  assert.equal(parse(["--fs-sync", "claude"], {}).fsSync, true);
  assert.equal(parse(["--integrity", "claude"], OPT_IN).fsSync, undefined);
});

// ── landlock-net + exec-box flags (docs/design/integrity/exec-routing.md §7) ───────────

test("--landlock-net / --no-landlock-net + env; tri-state, ON by default", () => {
  // Default-on (non-root principle): unset/empty ⇒ undefined (auto — the wrap
  // applies, degrading when the bin/kernel is missing).
  assert.equal(parse(["claude"], {}).landlockNet, undefined);
  assert.equal(parse(["claude"], { MANDU_LANDLOCK_NET: "" }).landlockNet, undefined);
  assert.equal(parse(["--landlock-net", "claude"], {}).landlockNet, true);
  assert.equal(parse(["--no-landlock-net", "claude"], {}).landlockNet, false);
  assert.equal(parse(["claude"], { MANDU_LANDLOCK_NET: "1" }).landlockNet, true);
  assert.equal(parse(["claude"], { MANDU_LANDLOCK_NET: "0" }).landlockNet, false);
  // the flag wins over the env, both directions.
  assert.equal(parse(["--no-landlock-net", "claude"], { MANDU_LANDLOCK_NET: "1" }).landlockNet, false);
  assert.equal(parse(["--landlock-net", "claude"], { MANDU_LANDLOCK_NET: "0" }).landlockNet, true);
});

test("--landlock-net=ports overrides the port set and implies the flag", () => {
  const p = parse(["--landlock-net=8788,443", "claude"], {});
  assert.equal(p.landlockNet, true);
  assert.deepEqual(p.landlockNetPorts, [8788, 443]);
  // no explicit list ⇒ undefined (the computed default set is used downstream).
  assert.equal(parse(["--landlock-net", "claude"], {}).landlockNetPorts, undefined);
  // env form.
  assert.deepEqual(parse(["claude"], { MANDU_LANDLOCK_NET_PORTS: "9000" }).landlockNetPorts, [9000]);
});

test("--landlock-net-strict implies --landlock-net and sets strict", () => {
  const p = parse(["--landlock-net-strict", "claude"], {});
  assert.equal(p.landlockNet, true);
  assert.equal(p.landlockNetStrict, true);
  assert.equal(parse(["claude"], {}).landlockNetStrict, false);
});

test("--landlock-net-bind=ports / MANDU_LANDLOCK_NET_BIND: the bind allowance implies the wrap; absent = none", () => {
  const p = parse(["--landlock-net-bind=4096,5173", "claude"], {});
  assert.equal(p.landlockNet, true);
  assert.deepEqual(p.landlockNetBind, [4096, 5173]);
  assert.equal(p.landlockNetPorts, undefined, "the CONNECT set is still the computed default");
  assert.equal(parse(["claude"], {}).landlockNetBind, undefined);
  assert.deepEqual(parse(["claude"], { MANDU_LANDLOCK_NET_BIND: "4096" }).landlockNetBind, [4096]);
  // --no-kernel still drops the whole rung (the bind list is moot without it).
  assert.equal(parse(["--landlock-net-bind=4096", "--no-kernel", "claude"], {}).landlockNet, false);
  assert.throws(() => parse(["--landlock-net-bind=70000", "claude"], {}), /--landlock-net-bind port must be 1\.\.65535/);
});

test("an out-of-range landlock-net port is a loud parse error", () => {
  assert.throws(() => parse(["--landlock-net=0", "claude"], {}), /1\.\.65535/);
  assert.throws(() => parse(["--landlock-net=nope", "claude"], {}), /1\.\.65535/);
});

test("--exec-clean-box / --no-exec-clean-box + MANDU_EXEC_CLEAN_BOX: tri-state, OFF by default, dropped by --no-kernel", () => {
  assert.equal(parse(["claude"], {}).execCleanBox, undefined, "default-off (undecided ⇒ the setup bakes \"0\")");
  assert.equal(parse(["claude"], { MANDU_EXEC_CLEAN_BOX: "" }).execCleanBox, undefined);
  assert.equal(parse(["--exec-clean-box", "claude"], {}).execCleanBox, true);
  assert.equal(parse(["--no-exec-clean-box", "claude"], {}).execCleanBox, false);
  assert.equal(parse(["claude"], { MANDU_EXEC_CLEAN_BOX: "1" }).execCleanBox, true);
  assert.equal(parse(["claude"], { MANDU_EXEC_CLEAN_BOX: "0" }).execCleanBox, false);
  assert.equal(parse(["--exec-clean-box", "claude"], { MANDU_EXEC_CLEAN_BOX: "0" }).execCleanBox, true, "flag beats env");
  assert.equal(parse(["--no-kernel", "claude"], {}).execCleanBox, false, "the umbrella drops it with exec-box");
  assert.equal(parse(["--no-kernel", "--exec-clean-box", "claude"], {}).execCleanBox, true, "a later explicit flag re-enables");
});

test("--exec-box[=cmds] + env; tri-state, ON by default; the default set is read-only tools", () => {
  // Default-on (non-root principle): unset/empty ⇒ undefined (auto — boxing
  // applies, degrading without the bin / bwrap / userns).
  const auto = parse(["claude"], {});
  assert.equal(auto.execBox, undefined);
  assert.ok(auto.execBoxCmds!.includes("cat") && auto.execBoxCmds!.includes("jq"));
  assert.equal(parse(["claude"], { MANDU_EXEC_BOX: "" }).execBox, undefined);
  const on = parse(["--exec-box", "claude"], {});
  assert.equal(on.execBox, true);
  assert.ok(!on.execBoxCmds!.includes("curl"), "the default box set carries no network tools");
  // opt-out: flag and env, flag wins.
  assert.equal(parse(["--no-exec-box", "claude"], {}).execBox, false);
  assert.equal(parse(["claude"], { MANDU_EXEC_BOX: "0" }).execBox, false);
  assert.equal(parse(["--no-exec-box", "claude"], { MANDU_EXEC_BOX: "1" }).execBox, false);
  // override the set.
  const custom = parse(["--exec-box=cat,jq", "claude"], {});
  assert.equal(custom.execBox, true);
  assert.deepEqual(custom.execBoxCmds, ["cat", "jq"]);
  // env forms.
  assert.equal(parse(["claude"], { MANDU_EXEC_BOX: "1" }).execBox, true);
  assert.deepEqual(parse(["claude"], { MANDU_EXEC_BOX_CMDS: "sed, awk " }).execBoxCmds, ["sed", "awk"]);
});

// ── net-guard flags (docs/design/integrity/exec-routing.md §7.5) ───────────────────────

test("--net-guard / --no-net-guard + env; tri-state, ON by default", () => {
  assert.equal(parse(["claude"], {}).netGuard, undefined);
  assert.equal(parse(["claude"], { MANDU_NET_GUARD: "" }).netGuard, undefined);
  assert.equal(parse(["--net-guard", "claude"], {}).netGuard, true);
  assert.equal(parse(["--no-net-guard", "claude"], {}).netGuard, false);
  assert.equal(parse(["claude"], { MANDU_NET_GUARD: "1" }).netGuard, true);
  assert.equal(parse(["claude"], { MANDU_NET_GUARD: "0" }).netGuard, false);
  // the flag wins over the env, both directions.
  assert.equal(parse(["--no-net-guard", "claude"], { MANDU_NET_GUARD: "1" }).netGuard, false);
  assert.equal(parse(["--net-guard", "claude"], { MANDU_NET_GUARD: "0" }).netGuard, true);
});

test("--net-allow=specs curates the allow-list and implies the guard", () => {
  const p = parse(["--net-allow=10.0.0.0/8:*,registry.npmjs.org:443", "claude"], {});
  assert.equal(p.netGuard, true);
  assert.deepEqual(p.netGuardAllow, ["10.0.0.0/8:*", "registry.npmjs.org:443"]);
  // no --net-allow ⇒ undefined (the default permissive set is used downstream).
  assert.equal(parse(["--net-guard", "claude"], {}).netGuardAllow, undefined);
  // env form; whitespace trimmed, empties dropped.
  assert.deepEqual(parse(["claude"], { MANDU_NET_ALLOW: " a:443 , , b:22 " }).netGuardAllow, ["a:443", "b:22"]);
  // an EMPTY value = curated-but-empty (baseline rules only, no permissive fallback).
  assert.deepEqual(parse(["claude"], { MANDU_NET_ALLOW: "" }).netGuardAllow, []);
});

test("--net-guard-git / --no-net-guard-git + env; tri-state, default-on (auto-allow git remotes when narrowed)", () => {
  assert.equal(parse(["claude"], {}).netGuardGitRemotes, undefined);
  assert.equal(parse(["--net-guard-git", "claude"], {}).netGuardGitRemotes, true);
  assert.equal(parse(["--no-net-guard-git", "claude"], {}).netGuardGitRemotes, false);
  assert.equal(parse(["claude"], { MANDU_NET_GUARD_GIT: "0" }).netGuardGitRemotes, false);
  assert.equal(parse(["--net-guard-git", "claude"], { MANDU_NET_GUARD_GIT: "0" }).netGuardGitRemotes, true);
});

// ── --no-kernel / --portable: the umbrella kernel-tier opt-out ────────────────
test("--no-kernel drops every kernel-tier rung (exec-box + landlock-net + net-guard) in one switch", () => {
  const p = parse(["--no-kernel", "claude"], {});
  assert.equal(p.execBox, false);
  assert.equal(p.landlockNet, false);
  assert.equal(p.landlockNetStrict, false);
  assert.equal(p.netGuard, false);
  // The userspace cooperative rungs are UNTOUCHED — portable ≠ defenseless.
  assert.equal(p.requested.netProxy, undefined); // auto (default-on)
  assert.equal(p.requested.execWrap, undefined);
  assert.equal(p.replyFilter, true);
  assert.equal(p.fsSync, undefined); // auto
});

test("--portable is an alias for --no-kernel", () => {
  assert.equal(parse(["--portable", "claude"], {}).execBox, false);
  assert.equal(parse(["--portable", "claude"], {}).landlockNet, false);
});

test("MANDU_NO_KERNEL=1 is the env form; an explicit per-rung flag still wins over it", () => {
  const env = parse(["claude"], { MANDU_NO_KERNEL: "1" });
  assert.equal(env.execBox, false);
  assert.equal(env.landlockNet, false);
  // env < flag: a later --exec-box re-enables that one rung (sequential-wins).
  const reEnabled = parse(["--exec-box", "claude"], { MANDU_NO_KERNEL: "1" });
  assert.equal(reEnabled.execBox, true);
  assert.equal(reEnabled.landlockNet, false); // the others stay dropped
});

test("--no-kernel cancels a preceding --landlock-net / --exec-box (umbrella at its position)", () => {
  const p = parse(["--landlock-net", "--exec-box", "--no-kernel", "claude"], {});
  assert.equal(p.landlockNet, false);
  assert.equal(p.execBox, false);
});

// ── fs-preload: retired rung (2026-07-14) ─────────────────────────────────────
// Not a kernel-tier drop and not a Part-2 deferral: requesting it in ANY posture
// is a parse-time fail-closed error; opting it OFF (a stale config/env) stays
// harmless so old setups keep launching.
test("fs-preload is retired: any request fails closed at parse time", () => {
  assert.throws(() => parse(["--fs-preload", "claude"], {}), /fs-preload was retired/);
  assert.throws(() => parse(["--fs-preload=/tmp/ws", "claude"], {}), /fs-preload was retired/);
  assert.throws(() => parse(["claude"], { MANDU_FS_PRELOAD: "1" }), /fs-preload was retired/);
});

test("fs-preload off/unset stays harmless (stale `fs-preload = false` configs keep launching)", () => {
  assert.ok(parse(["claude"], { MANDU_FS_PRELOAD: "0" }));
  assert.ok(parse(["claude"], { MANDU_FS_PRELOAD: "" }));
});

test("--require-confinement: flag, env, and the negation (rootless-confinement-ubuntu-2404.md §3.1)", () => {
  const base = ["claude"];
  const get = (argv: string[], env: Record<string, string> = {}) =>
    parse(argv, { ...BASE_ENV, ...env }).requireConfinement === true;
  assert.equal(get(base), false, "default: degrade, not refuse");
  assert.equal(get(["--require-confinement", ...base]), true);
  assert.equal(get(base, { MANDU_REQUIRE_CONFINEMENT: "1" }), true);
  assert.equal(get(base, { MANDU_REQUIRE_CONFINEMENT: "0" }), false);
  assert.equal(get(["--no-require-confinement", ...base], { MANDU_REQUIRE_CONFINEMENT: "1" }), false, "the flag overrides env");
});

// ── protection mode (protection-modes.md §3.2; mode.ts holds the table) ──────

test("--mode names both axes; space and = forms; plan.mode carries the name", () => {
  const p = parse(["--mode", "secrets", "claude"], {});
  assert.deepEqual([p.mode, p.integrity, p.confidentiality], ["secrets", false, true]);
  const q = parse(["--mode=full", "claude"], OPT_IN);
  assert.deepEqual([q.mode, q.integrity, q.confidentiality], ["full", true, true]);
  assert.equal(parse(["--mode", "off", "claude"], {}).mode, "off");
  // the value of the space form is never mistaken for the agent command
  assert.deepEqual(parse(["--mode", "injection", "claude", "-p", "hi"], OPT_IN).argv, ["claude", "-p", "hi"]);
});

test("no mode anywhere: nothing requested, no mode name (the arbiter's posture stands)", () => {
  const p = parse(["claude"], {});
  assert.deepEqual([p.mode, p.integrity, p.confidentiality], [undefined, undefined, undefined]);
  // ONE axis named is not a mode name; the other axis stays with the arbiter
  assert.equal(parse(["--confidentiality", "claude"], {}).mode, undefined);
});

test("an unknown or missing mode is a usage error that lists the four", () => {
  assert.throws(() => parse(["--mode", "standard", "claude"], {}), /unknown mode 'standard'.*secrets\|injection\|full\|off/);
  assert.throws(() => parse(["--mode=", "claude"], {}), /--mode needs a value/);
  assert.throws(() => parse(["claude"], { MANDU_MODE: "paranoid" }), /MANDU_MODE.*unknown mode/);
});

test("MANDU_MODE is the env level; empty means unset", () => {
  assert.equal(parse(["claude"], { ...OPT_IN, MANDU_MODE: "full" }).mode, "full");
  assert.equal(parse(["claude"], { MANDU_MODE: "" }).mode, undefined);
});

test("an explicit axis flag beats --mode for THAT axis only, in either order", () => {
  for (const argv of [["--mode", "secrets", "--integrity", "claude"], ["--integrity", "--mode", "secrets", "claude"]]) {
    const p = parse(argv, OPT_IN);
    assert.deepEqual([p.mode, p.integrity, p.confidentiality], ["full", true, true]);
  }
});

test("flag level beats env level per axis: --mode beats exported axes; an axis flag leaves the other axis to env", () => {
  const p = parse(["--mode", "full", "claude"], { ...OPT_IN, MANDU_INTEGRITY: "0", MANDU_CONFIDENTIALITY: "0" });
  assert.deepEqual([p.integrity, p.confidentiality], [true, true]);
  const q = parse(["--no-confidentiality", "claude"], { ...OPT_IN, MANDU_MODE: "full" });
  assert.deepEqual([q.mode, q.integrity, q.confidentiality], ["injection", true, false]);
  // env axis beats env mode for that axis (the same in-level rule); integrity
  // resolves OFF, so this one needs no opt-in.
  const r = parse(["claude"], { MANDU_MODE: "full", MANDU_INTEGRITY: "0" });
  assert.deepEqual([r.mode, r.integrity, r.confidentiality], ["secrets", false, true]);
});

test("a mode with integrity OFF forces fsSync=false, like --no-integrity", () => {
  assert.equal(parse(["--mode", "secrets", "--fs-sync", "claude"], {}).fsSync, false);
  assert.equal(parse(["--mode", "off", "claude"], {}).fsSync, false);
  assert.equal(parse(["--mode", "full", "claude"], OPT_IN).fsSync, undefined);
});

// ── frozen integrity axis (docs/design/architecture/protection-modes.md §10) ─────────────────

const FROZEN = /integrity axis .* is frozen \(docs\/design\/architecture\/protection-modes\.md\).*MANDU_EXPERIMENTAL_INTEGRITY=1/s;

test("frozen integrity: a launch that asks for the integrity axis without the opt-in is REFUSED, naming the opt-in and the freeze doc", () => {
  const cases: Array<[string[], Record<string, string>]> = [
    [["--mode", "injection", "claude"], {}],
    [["--mode", "full", "claude"], {}],
    [["--mode=full", "claude"], {}],
    [["--integrity", "claude"], {}],
    [["--mode", "secrets", "--integrity", "claude"], {}],
    [["claude"], { MANDU_MODE: "full" }],
    [["claude"], { MANDU_MODE: "injection" }],
    [["claude"], { MANDU_INTEGRITY: "1" }],
    [["--no-confidentiality", "claude"], { MANDU_MODE: "full" }],
  ];
  for (const [argv, env] of cases) {
    for (const optIn of [undefined, "", "0", "false"]) {
      const e = { ...BASE_ENV, ...env, ...(optIn === undefined ? {} : { MANDU_EXPERIMENTAL_INTEGRITY: optIn }) };
      assert.throws(() => parse(argv, e), FROZEN, `${argv.join(" ")} ${JSON.stringify(env)} opt-in=${optIn}`);
    }
  }
  // The refusal names where the request came from.
  assert.throws(() => parse(["--mode", "full", "claude"], BASE_ENV), /asked for by this launch's flags/);
  assert.throws(() => parse(["claude"], { ...BASE_ENV, MANDU_MODE: "full" }), /asked for by MANDU_MODE \/ MANDU_INTEGRITY or config\.toml/);
});

test("frozen integrity: the same requests parse with MANDU_EXPERIMENTAL_INTEGRITY=1 (1/true/on/yes)", () => {
  for (const v of ["1", "true", "on", "yes", "TRUE"]) {
    const e = { ...BASE_ENV, MANDU_EXPERIMENTAL_INTEGRITY: v };
    assert.equal(parse(["--mode", "injection", "claude"], e).mode, "injection", v);
    assert.equal(parse(["--mode", "full", "claude"], e).mode, "full", v);
    assert.equal(parse(["--integrity", "claude"], e).integrity, true, v);
    assert.equal(parse(["claude"], { ...e, MANDU_MODE: "full" }).mode, "full", v);
    assert.equal(parse(["claude"], { ...e, MANDU_INTEGRITY: "1" }).integrity, true, v);
  }
});

test("frozen integrity: --no-integrity, secrets, off and no mode at all never need the opt-in", () => {
  assert.equal(parse(["--no-integrity", "claude"], BASE_ENV).integrity, false);
  assert.equal(parse(["--mode", "secrets", "claude"], BASE_ENV).mode, "secrets");
  assert.equal(parse(["--mode", "off", "claude"], BASE_ENV).mode, "off");
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_MODE: "secrets" }).mode, "secrets");
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_MODE: "off" }).mode, "off");
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_INTEGRITY: "0" }).integrity, false);
  assert.equal(parse(["claude"], BASE_ENV).integrity, undefined, "nothing requested: left to the arbiter");
  // A flag that turns integrity OFF beats an env level that would turn it on.
  assert.equal(parse(["--mode", "secrets", "claude"], { ...BASE_ENV, MANDU_MODE: "full" }).mode, "secrets");
  assert.equal(parse(["--no-integrity", "claude"], { ...BASE_ENV, MANDU_INTEGRITY: "1" }).integrity, false);
});

test("env-secrets: default on; --no-env-secrets and MANDU_ENV_SECRETS=0 turn it off; --env-secrets wins over the env", () => {
  assert.equal(parse(["claude"], BASE_ENV).envSecrets, undefined, "default on is the absent key");
  assert.equal(parse(["--no-env-secrets", "claude"], BASE_ENV).envSecrets, false);
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_ENV_SECRETS: "0" }).envSecrets, false);
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_ENV_SECRETS: "off" }).envSecrets, false);
  assert.equal(parse(["--env-secrets", "claude"], { ...BASE_ENV, MANDU_ENV_SECRETS: "0" }).envSecrets, undefined);
});

test("secret-bind (plan 10 §8 phase 6): default bind (absent key); --no-secret-bind / MANDU_SECRET_BIND=0 drop it; --secret-bind restores it", () => {
  assert.equal(parse(["claude"], BASE_ENV).secretBind, undefined);
  assert.equal(parse(["--no-secret-bind", "claude"], BASE_ENV).secretBind, false);
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_SECRET_BIND: "0" }).secretBind, false);
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_SECRET_BIND: "off" }).secretBind, false);
  assert.equal(parse(["--secret-bind", "claude"], { ...BASE_ENV, MANDU_SECRET_BIND: "0" }).secretBind, undefined);
});

test("net-proxy-mitm is tri-state (plan 10 §11.5): unset = auto, --net-proxy-mitm / env=1 = explicit, --no-net-proxy-mitm / env=0 = off", () => {
  assert.equal(parse(["claude"], BASE_ENV).requested.netProxyMitm, undefined);
  assert.equal(parse(["--net-proxy-mitm", "claude"], BASE_ENV).requested.netProxyMitm, true);
  assert.equal(parse(["--no-net-proxy-mitm", "claude"], BASE_ENV).requested.netProxyMitm, false);
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_NET_PROXY_MITM: "1" }).requested.netProxyMitm, true);
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_NET_PROXY_MITM: "0" }).requested.netProxyMitm, false);
});


test("--secrets-ask=known|always|never and MANDU_SECRETS_ASK; anything else is refused", () => {
  assert.equal(parse(["claude"], BASE_ENV).secretsAsk, undefined);
  assert.equal(parse(["--secrets-ask=always", "claude"], BASE_ENV).secretsAsk, "always");
  assert.equal(parse(["claude"], { ...BASE_ENV, MANDU_SECRETS_ASK: "never" }).secretsAsk, "never");
  assert.throws(() => parse(["--secrets-ask=maybe", "claude"], BASE_ENV), /known, always or never/);
});
