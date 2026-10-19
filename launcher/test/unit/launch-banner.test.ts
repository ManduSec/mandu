/**
 * launch-banner — the launch display policy (packaging.md §5, release
 * checklist a6; the quiet launch, 2026-10-18): ONE banner line by default,
 * TTY or not (the mode, what it masks, the dashboard, the notice count); a
 * notice counted, its text in the launch's log; one short posture line per
 * degrade; the must-hear notices and a wait printed; --verbose /
 * MANDU_VERBOSE=1 prints every rung line and every notice in full; the
 * WARNINGs about another launch beside this one held until the banner is
 * out (holdUntilBanner), the last thing before the agent.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { bannerLine, compactNotice, holdUntilBanner, isAttentionNote, launchDisplayMode, modeFacts, modeLine, mustHearNotice, noteShow, NOTICE_PREFIX, POSTURE_PREFIX, postureLine } from "../../src/launch-banner.js";
import { shellTargetNote } from "../../src/env-compose.js";
import { OPEN_NOTE } from "../../src/codex-shell-network.js";
import { updateNotice } from "../../src/update-check.js";
import { exposureLostLines } from "../../src/human-plane-watch.js";
import { concurrentLaunchNotice } from "../../src/cache-epoch.js";
import { checkAgentVersion, launchPreviewNotice, TESTED_AGENT_VERSIONS, versionWarning } from "../../src/agent-versions.js";
import { notCoveredNotice } from "../../src/secret-setup.js";
import { voidedCachesLine } from "../../src/cache-seals.js";
import { dashboardLine } from "../../src/launch-banner.js";
import { postureFindings } from "../../src/services/observe.js";
import { CODEX_SANDBOX_OFF_NOTE } from "../../src/codex-sandbox.js";
import { CLAUDE_SANDBOX_OFF_NOTE } from "../../src/claude-sandbox.js";
import { codexUploadsNote } from "../../src/env-compose.js";
import { nodeEnvProxyGap, nodeEnvProxyNotice } from "../../src/node-floor.js";
import { opencodeProjectCodeNotice } from "../../src/opencode-project-code.js";
import { opencodeGlobalCodeNotice, opencodeGlobalCodeOptInWarning, opencodeV1ProjectPluginsNotice } from "../../src/opencode-global-code.js";

/** A real 2026-09-17 launch banner (stderr of `mandu claude`), verbatim shapes. */
const HEALTHY = [
  "mandu: fs rung ACTIVE: cooperative — CWD→AgentView worktree + HumanView↔AgentView prefix map + sensitive-path gate + eager sync (tool-call cadence) (workspace /home/u/ws)",
  "mandu: net-proxy LIVE — cooperative egress gate on http://127.0.0.1:40031 (a symbol bound for an untrusted destination → 403 needs-approval)",
  "mandu: exec-wrap LIVE — PATH-shadowing [curl, wget, nc] through the arbiter (a symbol used as a command/arg → blocked, exit 77)",
  "mandu: ullm-forwarder LIVE on http://127.0.0.1:38791 — the U-LLM reaches https://api.anthropic.com via the launcher (outside the TCP confine), not a direct :443 dial",
  "mandu: exec-box LIVE — boxing [cat, grep, egrep, fgrep, sed, awk, cut, sort, uniq, head, tail, wc, tr, jq, find, xargs, comm, join, paste] through mandu-exec-box",
  "mandu: exec-box CLEAN BOX first — each boxed command is tried under the clean ruleset (reads only under system roots; the AgentView write-only) so a benign output reaches the AI UN-masked; a command the clean box refuses reruns in the ordinary box (its output masked as before). Cost: that rerun repeats the attempt's pre-failure side effects — the default read-only set fails at its first denied read, before any write. --no-exec-clean-box opts out.",
  "mandu: landlock-net LIVE — whole-agent TCP confined to CONNECT ports [22, 443, 33723, 34371, 44539] (deny all other TCP; --skip-unsupported degrades on kernel < 6.7)",
  "mandu: landlock-net — the workflow ports 443 + 22 stay allowed (direct TLS + git-ssh keep working; the U-LLM already rides the loopback forwarder). The honest trade-off: a 443/22-based exfil stays possible — --landlock-net-strict denies both.",
  "mandu: net-guard LIVE — whole-agent connect(2) confined by DESTINATION (IP/CIDR/host × port); 11 allow rule(s) (deny all other TCP/UDP connects in-kernel; --skip-unsupported degrades where seccomp is unavailable)",
  "mandu: net-guard — the permissive fallback tcp:*:443 + tcp:*:22 stays in the non-strict default (arbitrary HTTPS + git-ssh keep working). The honest trade-off: an any-host-:443/:22 exfil is still possible — --landlock-net-strict OR --net-allow=<host:port,...> drops the fallback and pins :443 to the API host + your curated set (still reachable via the guard's supervisor-connect).",
  "mandu: confidentiality — 21 secret(s) confined via symbolized twins (raw bytes are absent from the agent's world)",
  "reply-filter LIVE — the agent's stdout is desymbolized for the human (opaque symbols resolved to originals)",
];

/** Non-default postures the launcher emits (exact shapes from the source). */
const ATTENTION = [
  "mandu: fs-view: /tmp/x is not a git workspace — running with the RAW CWD (DEGRADED fs rung: no AgentView worktree, no HumanView↔AgentView prefix map, no sensitive-path gate; the context chokepoint backstop still applies)",
  "mandu: exec-box is on by default, but unprivileged user namespaces are unavailable (kernel.apparmor_restrict_unprivileged_userns=1 …), so the box cannot run — proceeding WITHOUT it (the listed commands run normally; --no-exec-box silences this).",
  "mandu: exec-box is on by default, but `bwrap` (bubblewrap) is not installed, so the box cannot run — proceeding WITHOUT it (the listed commands run normally; --no-exec-box silences this).",
  "mandu: exec-box is on by default, but the mandu-exec-box bin is not built. cd interceptors && cargo build — proceeding WITHOUT it",
  "mandu: secrets are GATED, not confined, on this host.\n  Ubuntu restricts unprivileged user namespaces (AppArmor).\n  Programs the agent runs can still read your credential files.\n  One-time upgrade:  mandu setup   (asks for sudo once)\n  Details:           mandu doctor",
  "WARNING: mandu: secrets are GATED, not confined, for this session: the arbiter could not discover secrets (boom). Proceeding (--best-effort).",
  "mandu: the arbiter could not discover secrets (boom); secrets stay GATED (no registry entry was added).",
  "mandu: service 'net-proxy' is on by default but failed to start: EADDRINUSE — proceeding WITHOUT it (opt out explicitly with --no-net-proxy to silence this)",
  "mandu: claude TUI PINNED to the inline renderer (MANDU_CLAUDE_TUI_PIN=1) — the reply-filter resolves the fullscreen renderer too since 2026-09-19 (differential-interactive.md §19); unset the variable to run whatever renderer the release / your `tui` setting picks",
  "mandu: landlock-net is on by default, but the mandu-landlock-apply bin is not built — proceeding WITHOUT it (all TCP stays reachable)",
  "mandu: mcp: could not write the inspect MCP config: EACCES",
  "mandu: exec-box is on by default, but the arbiter socket /run/x/arbiter.sock is absent (the box cannot gate without it) — proceeding WITHOUT it",
  // A resolved native bin older than its source (services/native-bins staleNativeBinNote).
  // macOS: Mandu turned an agent's own sandbox off for the session (codex-/claude-sandbox.ts).
  CODEX_SANDBOX_OFF_NOTE,
  CLAUDE_SANDBOX_OFF_NOTE,
  "mandu: WARNING — mandu-exec-box at /r/interceptors/target/debug/mandu-exec-box is STALE: built 2026-09-04T13:47:17Z, but /r/interceptors/exec-supervisor/src/sandbox.rs changed 2026-09-05T00:33:11Z; the launch uses the OLD bin (a fixed source is not in effect until rebuilt). build with: cd interceptors && cargo build -p exec-supervisor --features kernel --bins",
];

test("display mode: compact by default whether or not stderr is a terminal; --verbose / MANDU_VERBOSE=1 prints everything", () => {
  assert.equal(launchDisplayMode({ env: {} }), "compact", "a pipe gets the same one line a TTY does (a6)");
  assert.equal(launchDisplayMode({ verbose: true, env: {} }), "full");
  assert.equal(launchDisplayMode({ env: { MANDU_VERBOSE: "1" } }), "full");
  assert.equal(launchDisplayMode({ env: { MANDU_VERBOSE: "true" } }), "full");
  assert.equal(launchDisplayMode({ env: { MANDU_VERBOSE: "0" } }), "compact");
  assert.equal(launchDisplayMode({ env: { MANDU_VERBOSE: "" } }), "compact");
  assert.equal(launchDisplayMode({ env: { MANDU_VERBOSE: "false" } }), "compact");
});

test("every healthy rung line is NOT an attention note; every degrade / warning / refusal shape IS", () => {
  for (const n of HEALTHY) assert.equal(isAttentionNote(n), false, n);
  for (const n of ATTENTION) assert.equal(isAttentionNote(n), true, n);
});

test("fs-sync off BY MODE (integrity off) is informational, not an attention note or a dropped rung; an explicit --no-fs-sync opt-out still is (release checklist a4)", () => {
  const byMode = "mandu: fs rung off by mode: integrity is off in this protection mode, so the agent works in your folder directly (no AgentView copy is needed)";
  const optOut = "mandu: fs rung DEGRADED: fs-sync opted out (--no-fs-sync) — raw CWD, no prefix map, no sensitive-path gate; the context chokepoint backstop still applies";
  assert.equal(isAttentionNote(byMode), false, "never printed by default");
  assert.deepEqual(postureFindings([byMode]), { live: [], dropped: [] }, "neither a live rung nor a dropped one: the health chip stays green");
  assert.equal(isAttentionNote(optOut), true);
  assert.deepEqual(postureFindings([optOut]).dropped, [optOut]);
});

test("the egress-gate refusal (release checklist a1) is an attention note in plain words", () => {
  const refusal = "mandu: the egress gate (net-proxy) could not start: boom — refusing to launch without it. Fix the cause above, or launch without the egress gate on purpose with --no-net-proxy (or --best-effort).";
  assert.equal(isAttentionNote(refusal), true);
});

test("a gated launch: the GATED notice is an attention note, so the default display prints it in full (rootless-confinement-ubuntu-2404.md §2)", () => {
  const notice = "mandu: secrets are GATED, not confined, on this host.\n  Ubuntu restricts unprivileged user namespaces (AppArmor).";
  assert.equal(isAttentionNote(notice), true);
  assert.equal(modeLine("secrets", { confined: 0, posture: "gated" }), "mandu: mode secrets (credential files GATED, not masked)");
  // bind-only (finding 7): placeholders are up, the posture is gated
  assert.equal(modeLine("secrets", { confined: 3, posture: "gated" }), "mandu: mode secrets (credential files GATED (3 behind a placeholder, no file guard))");
  // the bind-only notice is an attention note too
  assert.equal(isAttentionNote("mandu: secrets are GATED, not confined, on this host.\n  Mandu's file guard (mandu-net-guard) is not available here."), true);
});

test("the mode line (protection-modes.md §3.2, plan 10 §12.5): files masked always; env vars and pinned readers only when non-zero", () => {
  assert.equal(modeLine("secrets", { confined: 14, posture: "confined" }), "mandu: mode secrets (14 credential files masked)");
  assert.equal(
    modeLine("secrets", { confined: 14, posture: "confined", envMasked: 3, readersPinned: 2 }),
    "mandu: mode secrets (14 credential files masked, 3 env vars masked, 2 readers pinned)",
  );
  assert.equal(modeLine("secrets", { confined: 1, posture: "confined", envMasked: 1, readersPinned: 1 }), "mandu: mode secrets (1 credential file masked, 1 env var masked, 1 reader pinned)");
  assert.equal(modeLine("secrets", { confined: 0, posture: "confined", envMasked: 0, readersPinned: 0 }), "mandu: mode secrets (0 credential files masked)");
  assert.equal(modeLine("full", { confined: 2, posture: "confined", readersPinned: 1 }), "mandu: mode full (2 credential files masked, 1 reader pinned, untrusted text masked)");
  assert.equal(modeLine("secrets", { confined: 0, posture: "gated" }), "mandu: mode secrets (credential files GATED, not masked)");
  assert.equal(modeLine("secrets", undefined), "mandu: mode secrets (credential files not checked)");
  assert.equal(modeLine("injection", undefined), "mandu: mode injection (untrusted text masked)");
  assert.equal(modeLine("off", undefined), "mandu: mode off (observing only, nothing is enforced)");
});

test("dashboardLine: the URL and what it is for; with none running, how to start one", () => {
  assert.equal(dashboardLine("http://127.0.0.1:4500/"), "mandu: dashboard http://127.0.0.1:4500/ (approve requests, see what was protected)");
  assert.match(dashboardLine(null), /^mandu: no dashboard is running; start one with `mandu dashboard`/);
});

test("the mode line on macOS (posture read-blocked, confidentiality.md §7.3): files unreadable, not masked; never a pinned reader", () => {
  assert.equal(modeLine("secrets", { confined: 3, posture: "read-blocked" }), "mandu: mode secrets (3 credential files unreadable (read-blocked))");
  assert.equal(modeLine("secrets", { confined: 1, posture: "read-blocked", envMasked: 2 }), "mandu: mode secrets (1 credential file unreadable (read-blocked), 2 env vars masked)");
  // An arbiter that counts readers (a Linux policy) never makes macOS claim one.
  assert.equal(modeLine("secrets", { confined: 2, posture: "read-blocked", readersPinned: 4 }), "mandu: mode secrets (2 credential files unreadable (read-blocked))");
  assert.equal(isAttentionNote(modeLine("secrets", { confined: 2, posture: "read-blocked" })), false);
});

test("compactNotice: each long advisory notice becomes ONE short `mandu: ! …` line, fed from the REAL producers (a reworded producer fails here)", () => {
  const { min, max } = TESTED_AGENT_VERSIONS.claude;
  const at = (version: string | null): string => versionWarning(checkAgentVersion("claude", version === null ? null : `${version} (Claude Code)`))!;
  assert.equal(compactNotice(at("99.0.0")), `${NOTICE_PREFIX}Claude Code 99.0.0 is newer than Mandu has tested (up to ${max}); see \`mandu doctor\``);
  assert.equal(compactNotice(at("0.0.1")), `${NOTICE_PREFIX}Claude Code 0.0.1 is older than Mandu has tested (from ${min}); see \`mandu doctor\``);
  assert.equal(compactNotice(at(null)), `${NOTICE_PREFIX}could not read the Claude Code version to check it; see \`mandu doctor\``);

  const walk = notCoveredNotice({
    files: [],
    skipped: [{ path: "/h/work/a/b/c/d", reason: "depth" }, { path: "/h/.ssh/id_locked", reason: "unreadable" }],
    counts: { depth: 380, unreadable: 2, "package-cache": 4000, "special-file": 3 },
    limits: { maxDepth: 4, maxFiles: 500 },
  }).join("\n");
  assert.ok(isAttentionNote(walk), "the full notice is still an attention note (it prints in full under --verbose)");
  assert.equal(compactNotice(walk), `${NOTICE_PREFIX}382 places were not searched for secrets; see \`mandu doctor --secrets\``,
    "package caches and sockets are not counted (secret-discovery.md §1.9 F)");
  // A walk whose only skips are package caches and sockets prints no notice at all.
  assert.deepEqual(notCoveredNotice({ files: [], counts: { "package-cache": 487, "special-file": 2 }, limits: { maxDepth: 4, maxFiles: 500 } }), []);
  const one = notCoveredNotice({ files: [], counts: { count: 1 }, limits: { maxDepth: 4, maxFiles: 500 } }).join("\n");
  assert.equal(compactNotice(one), `${NOTICE_PREFIX}1 place was not searched for secrets; see \`mandu doctor --secrets\``);
  const cut = notCoveredNotice({ files: [], truncated: true, limits: { maxDepth: 4, maxFiles: 500 } }).join("\n");
  assert.equal(compactNotice(cut), `${NOTICE_PREFIX}the search for secrets stopped early; see \`mandu doctor --secrets\``);
  // Grouped by folder (secret-discovery.md §1.9 H): a developer home's 447
  // deep folders were a few checkouts, and "447 places" named none of them.
  const areas = [
    { path: "/h/project/app", count: 216 }, { path: "/h/project/app-old", count: 107 }, { path: "/h/project/lib", count: 91 },
    { path: "/h/.oh-my-zsh-custom/plugins", count: 6 }, { path: "/h/zfold8/app2root", count: 1 },
  ];
  const deep = notCoveredNotice({ files: [], counts: { depth: 429 }, limits: { maxDepth: 4, maxFiles: 500 }, depthAreas: areas }, 3, "/h").join("\n");
  assert.match(deep, /429 directories below depth 4 not searched, in ~\/project\/app \(216\), ~\/project\/app-old \(107\), ~\/project\/lib \(91\) and 15 more elsewhere$/m);
  assert.equal(compactNotice(deep),
    `${NOTICE_PREFIX}429 places were not searched for secrets: folders more than 4 levels deep, in ~/project/app (216), ~/project/app-old (107), ~/project/lib (91) and 15 more elsewhere; see \`mandu doctor --secrets\``);
  // Beside an unreadable candidate, the deep folders are said as a part.
  const mixed = notCoveredNotice({ files: [], counts: { depth: 8, unreadable: 1 }, limits: { maxDepth: 4, maxFiles: 500 }, depthAreas: [{ path: "/h/a/b", count: 5 }, { path: "/h/c/d", count: 3 }] }, 3, "/h").join("\n");
  assert.equal(compactNotice(mixed),
    `${NOTICE_PREFIX}9 places were not searched for secrets, 8 of them folders more than 4 levels deep, in ~/a/b (5) and ~/c/d (3); see \`mandu doctor --secrets\``);
  const single = notCoveredNotice({ files: [], counts: { depth: 1 }, limits: { maxDepth: 4, maxFiles: 500 }, depthAreas: [{ path: "/h/a/b", count: 1 }] }, 3, "/h").join("\n");
  assert.equal(compactNotice(single), `${NOTICE_PREFIX}1 place was not searched for secrets: a folder more than 4 levels deep, in ~/a/b (1); see \`mandu doctor --secrets\``);

  // policy-suggest.ts launchSuggestionNotice (its real output: policy-suggest.test.ts).
  assert.equal(
    compactNotice("mandu: 40 possible keys in this project are not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard"),
    `${NOTICE_PREFIX}40 possible keys in this project are not protected; see \`mandu policy suggest\``,
  );

  // cache-seals.ts voidedCachesLine (plan 14 §11.2.1): the launch that costs
  // this one its git-history cache, by pid, workspace and why, and its end.
  const voided = voidedCachesLine([{ pid: 4242, mode: "secrets", posture: "gated", why: "no file guard", workspace: "/home/u/proj/.claude/worktrees/wt-a" }]);
  assert.equal(isAttentionNote(voided), false, "advice, not a degrade: shown only as its short line");
  assert.equal(
    compactNotice(voided),
    `${NOTICE_PREFIX}git history rebuilt (slower) while a Mandu launch runs without protection ` +
    "(pid 4242 in /home/u/proj/.claude/worktrees/wt-a: no file guard); to end it: quit its agent, or `kill 4242`",
  );
});

test("compactNotice: the preview notice (agent-versions.ts previewNotice) is already one short line and passes through as is", () => {
  for (const [target, argv, gen] of [["goose", ["goose"], null], ["opencode", ["opencode2"], 2]] as const) {
    const note = launchPreviewNotice(target, argv, gen, {})!;
    assert.ok(note.startsWith(NOTICE_PREFIX), note);
    assert.equal(compactNotice(note), note);
  }
});

test("compactNotice: the old-Node notice (node-floor.ts nodeEnvProxyNotice) is already one short line and passes through as is", () => {
  for (const v of ["v22.13.0", "v23.11.0", "v24.2.0"]) {
    const note = nodeEnvProxyNotice(nodeEnvProxyGap(v))!;
    assert.ok(note.startsWith(NOTICE_PREFIX), note);
    assert.equal(compactNotice(note), note);
    assert.equal(isAttentionNote(note), false, "advice: the launch is safe without it");
  }
});

test("compactNotice leaves every rung line, degrade and refusal alone: they keep their own display rule", () => {
  for (const l of [...HEALTHY, ...ATTENTION]) assert.equal(compactNotice(l), null, l);
  assert.equal(compactNotice(modeLine("secrets", { confined: 1, posture: "confined" })), null);
  assert.equal(compactNotice(dashboardLine(null)), null);
});

test("compactNotice: the Codex apps-off note (env-compose.ts codexUploadsNote) is one short line, fed from the real producer", () => {
  const note = codexUploadsNote({ target: "codex", argv: ["codex"], codexAuth: "sign-in" })!;
  assert.equal(compactNotice(note), `${NOTICE_PREFIX}ChatGPT apps and connectors are off in Codex (they upload local files around Mandu)`);
});

test("compactNotice: the OpenCode left-out notices are one short line that still names each file and the opt-in, fed from the real producers (first-session.md: the launch names what it left out)", () => {
  const files = [{ path: "/w/.opencode/plugin/x.ts", kind: "plugin" as const }, { path: "/w/opencode.json", kind: "config" as const }];
  const mine = [{ path: "/h/.config/opencode/plugin/y.ts", kind: "plugin" as const }];
  const cases: Array<[string, string]> = [
    [opencodeV1ProjectPluginsNotice(files), "this project's OpenCode plugins do not run under Mandu: /w/.opencode/plugin/x.ts, /w/opencode.json (names a plugin); MANDU_OPENCODE_PROJECT_PLUGINS=1 runs them unchecked"],
    [opencodeProjectCodeNotice(files), "this project's OpenCode plugins and custom tools do not run under Mandu: /w/.opencode/plugin/x.ts, /w/opencode.json (names a plugin); MANDU_OPENCODE_PROJECT_PLUGINS=1 runs them unchecked"],
    [opencodeGlobalCodeNotice(mine), "your own OpenCode plugins and custom tools do not run under Mandu: /h/.config/opencode/plugin/y.ts; MANDU_OPENCODE_GLOBAL_PLUGINS=1 runs them unchecked"],
  ];
  for (const [producer, short] of cases) {
    // services/manager.ts warn() prints each with the `mandu: ` prefix
    const note = `mandu: ${producer}`;
    assert.equal(isAttentionNote(note), false, "advice, not a degrade: without compactNotice the default display dropped it");
    assert.equal(compactNotice(note), `${NOTICE_PREFIX}${short}`);
    // One of the notices the default display still prints (packaging.md §5, 2026-10-18).
    assert.equal(mustHearNotice(note), `${NOTICE_PREFIX}${short}`);
    assert.deepEqual(noteShow(note, "compact"), { kind: "short", line: `${NOTICE_PREFIX}${short}` });
  }
  // an opt-in's WARNING keeps its full line (isAttentionNote)
  assert.equal(compactNotice(`mandu: ${opencodeGlobalCodeOptInWarning(mine)}`), null);
});

test("holdUntilBanner: the WARNINGs about another launch are held until the banner is out, then printed whole and in order, once; after that a line prints as it is said; a throwing print drops only itself", () => {
  const screen: string[] = [];
  const last = holdUntilBanner((l) => screen.push(l));
  // What run.ts says before the agent starts: the concurrent-launch lines,
  // then the human-plane watch's block (the producers' real output).
  const beside = concurrentLaunchNotice("confined", [{ pid: 4242, mode: "off", posture: "off", walled: false }], { requireConfinement: false }).lines;
  const block = exposureLostLines([{ pid: 4242, mode: "off", posture: "off", session: "claude-off-1" }]);
  for (const l of [...beside, ...block]) last.say(l);
  assert.equal(screen.length, 0, "nothing yet: the banner comes first");
  screen.push("mandu: mode secrets (1 credential file masked)", "mandu: dashboard http://127.0.0.1:4500/ (approve requests, see what was protected)");
  last.release();
  assert.deepEqual(screen.slice(2), [...beside, ...block], "whole, in order, below the banner: the last thing before the agent");
  assert.match(screen.at(-1)!, /To fix it: stop that launch/);
  last.release();
  assert.equal(screen.length, 2 + beside.length + block.length, "released once");
  last.say("WARNING: mandu: this session's file guard is still not believed; …");
  assert.equal(screen.at(-1), "WARNING: mandu: this session's file guard is still not believed; …", "a live line while the agent runs prints at once");

  let n = 0;
  const flaky = holdUntilBanner((l) => { n++; if (l === "b") throw new Error("EPIPE"); });
  flaky.say("a"); flaky.say("b"); flaky.say("c");
  assert.doesNotThrow(() => flaky.release());
  assert.equal(n, 3, "a failed print drops only that line");
  assert.doesNotThrow(() => flaky.say("b"));
});

// ── The quiet launch (packaging.md §5, 2026-10-18): one banner line, a short
//    posture line per warning, every other line in the launch's log. ──

test("noteShow (default display): an all-is-well line is kept for the log, a notice counted, a warning one short posture line, a wait printed now; --verbose prints all", () => {
  for (const l of HEALTHY) {
    assert.deepEqual(noteShow(l, "compact"), { kind: "keep" }, l);
    assert.deepEqual(noteShow(l, "full"), { kind: "print" }, l);
  }
  for (const l of ATTENTION) {
    assert.deepEqual(noteShow(l, "compact"), { kind: "short", line: postureLine(l) }, l);
    assert.deepEqual(noteShow(l, "full"), { kind: "print" }, l);
  }
  // A known notice is counted even when it carries WARNING (the version notice).
  const version = versionWarning(checkAgentVersion("claude", "99.0.0")!)!;
  assert.ok(isAttentionNote(version), "the version notice carries WARNING");
  assert.deepEqual(noteShow(version, "compact"), { kind: "notice" });
  const walk = notCoveredNotice({ files: [], counts: { depth: 3 }, limits: { maxDepth: 4, maxFiles: 500 } }).join("\n");
  assert.deepEqual(noteShow(walk, "compact"), { kind: "notice" });
  // The caller's own notice is counted; the caller's own wait prints now.
  assert.deepEqual(noteShow("mandu: something the caller wants counted", "compact", true), { kind: "notice" });
  assert.deepEqual(noteShow("mandu: the Mandu services running for you were older; restarting them as this build", "compact", "wait"), { kind: "print" });
  // Where the full text is, when the launch has no log.
  const gated = "WARNING: mandu: secrets are GATED, not confined, for this session";
  assert.deepEqual(noteShow(gated, "compact", false, "`--verbose`"), { kind: "short", line: `${POSTURE_PREFIX}secrets are GATED, not confined, for this session (more: \`--verbose\`)` });
});

test("the must-hear notices: Mandu turned Codex's own sandbox network ON, and a release with SECURITY fixes, each a short line under the banner; a plain update is only counted", () => {
  assert.equal(mustHearNotice(OPEN_NOTE), compactNotice(OPEN_NOTE));
  assert.deepEqual(noteShow(OPEN_NOTE, "compact"), { kind: "short", line: compactNotice(OPEN_NOTE)! });
  assert.equal(mustHearNotice(versionWarning(checkAgentVersion("claude", "99.0.0")!)!), null);
  const security = updateNotice("0.2.0", { newest: "0.2.1", security: true });
  assert.deepEqual(noteShow(security, "compact"), { kind: "short", line: security });
  const plain = updateNotice("0.2.0", { newest: "0.2.1", security: false });
  assert.equal(mustHearNotice(plain), null);
  assert.deepEqual(noteShow(plain, "compact"), { kind: "notice" });
});

test("postureLine: one short line that keeps the WARNING marker, drops the prefixes, starts at a later WARNING, shortens long paths, and points at the log", () => {
  const tail = " (more: `mandu log`)";
  for (const l of ATTENTION) {
    const p = postureLine(l);
    assert.ok(p.startsWith(POSTURE_PREFIX), p);
    assert.ok(p.endsWith(tail), p);
    assert.ok(isAttentionNote(p), `a posture line is itself an attention note: ${p}`);
    assert.ok(!p.includes("\n"), "one line");
    assert.ok(p.length <= POSTURE_PREFIX.length + 161 + tail.length, `short: ${p.length} ${p}`);
    assert.doesNotMatch(p.slice(POSTURE_PREFIX.length), /^(WARNING|mandu:)/, p);
  }
  // The first line of a multi-line block.
  assert.equal(
    postureLine("mandu: secrets are GATED, not confined, on this host.\n  Ubuntu restricts unprivileged user namespaces (AppArmor)."),
    `${POSTURE_PREFIX}secrets are GATED, not confined, on this host.${tail}`,
  );
  // A truth-in-labeling line whose warning is its second sentence: the warning is the gist.
  const shell = shellTargetNote({ target: "shell", argv: ["sh"] })!;
  assert.match(postureLine(shell), /^mandu: WARNING: codex, openclaw, opencode and goose started from it are NOT routed;/);
  // A long absolute path stands as its last name.
  assert.equal(
    postureLine("mandu: WARNING — mandu-exec-box at /r/interceptors/target/debug/mandu-exec-box is STALE: built 2026-09-04"),
    `${POSTURE_PREFIX}mandu-exec-box at …/mandu-exec-box is STALE: built 2026-09-04${tail}`,
  );
  // A helper's prefix goes too, and a long gist is cut at a word.
  assert.equal(postureLine(`WARNING: mandu-net-guard: ${"word ".repeat(40)}end`), `${POSTURE_PREFIX}${"word ".repeat(32).trimEnd()}…${tail}`);
});

test("bannerLine: ONE line with the mode, what it masks, the dashboard and the notice count (none: no count)", () => {
  assert.equal(
    bannerLine({ mode: "secrets", secrets: { confined: 33, posture: "confined", envMasked: 1 }, dashboard: "dashboard http://127.0.0.1:4500/", notices: 2 }),
    "mandu: secrets mode · 33 credential files, 1 env var masked · dashboard http://127.0.0.1:4500/ · 2 notices: `mandu log`",
  );
  assert.equal(
    bannerLine({ mode: "secrets", secrets: { confined: 1, posture: "confined", readersPinned: 3 }, dashboard: "dashboard http://h/", notices: 1, hint: "`--verbose`" }),
    "mandu: secrets mode · 1 credential file masked · dashboard http://h/ · 1 notice: `--verbose`",
  );
  assert.equal(
    bannerLine({ mode: "off", secrets: undefined, dashboard: "no dashboard (start one: `mandu dashboard`)", notices: 0 }),
    "mandu: off mode · observing only, nothing is enforced · no dashboard (start one: `mandu dashboard`)",
  );
  // A GATED posture reads as on the mode line: the fact that protection is not what the mode promises.
  const gated = bannerLine({ mode: "secrets", secrets: { confined: 0, posture: "gated", envMasked: 2 }, dashboard: "dashboard http://h/", notices: 0 });
  assert.equal(gated, "mandu: secrets mode · credential files GATED, not masked · 2 env vars masked · dashboard http://h/");
  assert.ok(isAttentionNote(gated));
  assert.ok(!isAttentionNote(bannerLine({ mode: "secrets", secrets: { confined: 3, posture: "confined" }, dashboard: "dashboard http://h/", notices: 4 })), "a healthy banner is not a warning");
});

test("modeFacts: the banner's short facts and the mode line's agree on every posture", () => {
  assert.deepEqual(modeFacts("secrets", { confined: 3, posture: "read-blocked", envMasked: 1 }, true), ["3 credential files unreadable", "1 env var masked"]);
  assert.deepEqual(modeFacts("secrets", { confined: 3, posture: "read-blocked", envMasked: 1 }, false), ["3 credential files unreadable (read-blocked)", "1 env var masked"]);
  assert.deepEqual(modeFacts("full", { confined: 2, posture: "confined", envMasked: 2, readersPinned: 1 }, true), ["2 credential files, 2 env vars masked", "untrusted text masked"]);
  assert.deepEqual(modeFacts("full", { confined: 2, posture: "confined", envMasked: 2, readersPinned: 1 }, false), ["2 credential files masked", "2 env vars masked", "1 reader pinned", "untrusted text masked"]);
  assert.deepEqual(modeFacts("secrets", undefined, true), ["credential files not checked"]);
  assert.deepEqual(modeFacts("injection", undefined, true), ["untrusted text masked"]);
});
