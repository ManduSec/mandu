/**
 * codex-argv.test — where the launcher's -c routing overrides land in a Codex
 * argv, and which user overrides a launch refuses (src/codex-argv.ts).
 *
 * The facts pinned here were probed on codex-cli 0.154 (2026-09-27): every
 * command level has its own -c list, the innermost non-empty list replaces
 * the outer ones, and within one list the last -c for a key wins. A root-only
 * splice therefore lost the routing under `codex exec -c …` and Codex talked
 * to api.openai.com directly (os-test-matrix.md §10.14).
 *
 * The `--no-daemon` facts were probed on codex-cli 0.159.1 (2026-09-30,
 * differential-interactive.md §16): the root and root-level resume / fork
 * take it, `exec` rejects it, and a second copy at one level is an error.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { CODEX_CONNECTORS_OFF, CODEX_NO_DAEMON, CODEX_UPLOADS_OFF, CODEX_UPLOADS_OFF_OVERRIDES, codexConfigNamesConnectors, codexTakesNoDaemon, codexUploadConflict, codexArgvCd, codexArgvLevels, codexBareAppServer, codexLaunchRefusal, codexOverridesReach, codexSpliceOverrides, codexSubcommand, isCodexBinary } from "../../src/codex-argv.js";

// Axes: none. Pure argv logic; no protection decision is made here.

const O = ["-c", "model_provider=mandu", "-c", "model_providers.mandu={…}"];

test("isCodexBinary: the codex binary by basename, never a wrapper", () => {
  assert.equal(isCodexBinary("codex"), true);
  assert.equal(isCodexBinary("/home/u/.local/bin/codex"), true);
  assert.equal(isCodexBinary("my-codex-wrapper.sh"), false);
  assert.equal(isCodexBinary(undefined), false);
});

test("splice: interactive codex gets the overrides after argv[0] only", () => {
  assert.deepEqual(codexSpliceOverrides(["codex"], O), ["codex", ...O]);
  assert.deepEqual(codexSpliceOverrides(["codex", "fix the bug"], O), ["codex", ...O, "fix the bug"]);
});

test("splice: exec gets its own copy, ahead of the user's exec-level -c", () => {
  assert.deepEqual(
    codexSpliceOverrides(["codex", "exec", "-c", "model_reasoning_effort=low", "hi"], O),
    ["codex", ...O, "exec", ...O, "-c", "model_reasoning_effort=low", "hi"],
  );
  // the alias `e`
  assert.deepEqual(codexSpliceOverrides(["codex", "e", "hi"], O), ["codex", ...O, "e", ...O, "hi"]);
});

test("splice: a nested subcommand (exec resume) gets a copy too", () => {
  assert.deepEqual(
    codexSpliceOverrides(["codex", "exec", "-c", "x=1", "resume", "-c", "model=q", "--last", "hi"], O),
    ["codex", ...O, "exec", ...O, "-c", "x=1", "resume", ...O, "-c", "model=q", "--last", "hi"],
  );
});

test("splice: root flags and their values are skipped; a flag VALUE is never a subcommand", () => {
  assert.deepEqual(
    codexSpliceOverrides(["codex", "-m", "exec", "-C", "/w", "exec", "hi"], O),
    ["codex", ...O, "-m", "exec", "-C", "/w", "exec", ...O, "hi"],
  );
});

test("splice: nothing after the first plain positional or after -- is touched", () => {
  assert.deepEqual(
    codexSpliceOverrides(["codex", "exec", "hi", "review"], O),
    ["codex", ...O, "exec", ...O, "hi", "review"],
  );
  assert.deepEqual(codexSpliceOverrides(["codex", "--", "exec"], O), ["codex", ...O, "--", "exec"]);
});

test("splice: a wrapper argv[0] keeps the old shape (after argv[0] only)", () => {
  assert.deepEqual(codexSpliceOverrides(["wrap.sh", "exec", "hi"], O), ["wrap.sh", ...O, "exec", "hi"]);
});

test("codexOverridesReach: codex and a wrapper get the routing options, a POSIX shell never does", () => {
  assert.equal(codexOverridesReach("codex"), true);
  assert.equal(codexOverridesReach("/opt/bin/codex"), true);
  assert.equal(codexOverridesReach("my-codex-wrapper.sh"), true, "a wrapper vouched for by --target: its only route");
  for (const sh of ["sh", "/bin/sh", "bash", "/usr/bin/zsh", "dash", "ksh", "fish"]) {
    assert.equal(codexOverridesReach(sh), false, sh);
  }
  assert.equal(codexOverridesReach(undefined), false);
});

test("splice: a shell argv with no overrides (what env-compose composes for it) is untouched", () => {
  const argv = ["/bin/sh", "-c", "printf '%s' \"$0\"", "x"];
  assert.deepEqual(codexSpliceOverrides(argv, []), argv);
});

test("splice: no overrides is a no-op", () => {
  assert.deepEqual(codexSpliceOverrides(["codex", "exec", "hi"], []), ["codex", "exec", "hi"]);
});

test("refusal: a user -c that re-points the model provider is refused, in every spelling", () => {
  for (const argv of [
    ["codex", "-c", "model_provider=openai"],
    ["codex", "exec", "-c", "model_provider=openai", "hi"],
    ["codex", "exec", "--config", "model_providers.x={base_url=\"http://evil\"}", "hi"],
    ["codex", "exec", "--config=model_provider=openai", "hi"],
    ["codex", "-cmodel_provider=openai"],
    // clap strips one `=` from an attached short value (review 2026-10-02)
    ["codex", "-c=model_provider=openai"],
    ["codex", "exec", '-c=model_providers.x={base_url="http://evil"}', "hi"],
    ["codex", "-c", " \"model_provider\" = \"openai\""],
    ["codex", "exec", "--oss", "hi"],
    ["codex", "--local-provider", "ollama"],
    ["codex", "--local-provider=lmstudio"],
  ]) {
    const r = codexLaunchRefusal(argv);
    assert.ok(r !== null, `refused: ${argv.join(" ")}`);
    assert.match(r!, /refusing to launch codex/);
  }
});

test("refusal: ordinary overrides, a model choice and wrappers launch", () => {
  assert.equal(codexLaunchRefusal(["codex", "exec", "-c", "model_reasoning_effort=low", "-m", "gpt-5.4", "hi"]), null);
  assert.equal(codexLaunchRefusal(["codex", "-c", "model=gpt-5.4"]), null);
  assert.equal(codexLaunchRefusal(["codex", "exec", "--", "-c", "model_provider=openai"]), null, "after -- it is prompt text");
  assert.equal(codexLaunchRefusal(["wrap.sh", "-c", "model_provider=openai"]), null, "a wrapper is vouched for by --target");
});

test("codexSubcommand: the root subcommand after root options and their values; null for the TUI, a prompt, or after --", () => {
  assert.equal(codexSubcommand(["codex"]), null);
  assert.equal(codexSubcommand(["codex", "fix the bug"]), null);
  assert.equal(codexSubcommand(["codex", "exec", "hi"]), "exec");
  assert.equal(codexSubcommand(["codex", "-c", "x=1", "-m", "o4", "app-server"]), "app-server");
  assert.equal(codexSubcommand(["codex", "--yolo", "sandbox", "--", "ls"]), "sandbox");
  assert.equal(codexSubcommand(["codex", "--", "exec"]), null);
});

test("codexArgvLevels: each flag's and subcommand's command level (0 the root, +1 per subcommand); a flag after the prompt is the innermost level's; values, positionals and what follows -- are -1", () => {
  assert.deepEqual(codexArgvLevels(["codex", "-c", "a=1", "exec", "-c", "b=2", "resume", "-c", "c=3", "id"]), [-1, 0, -1, 1, 1, -1, 2, 2, -1, -1]);
  assert.deepEqual(codexArgvLevels(["codex", "-m", "exec", "--yolo"]), [-1, 0, -1, 0], "a value is never a subcommand");
  assert.deepEqual(codexArgvLevels(["codex", "--", "-c", "x"]), [-1, -1, -1, -1]);
  assert.deepEqual(codexArgvLevels(["codex", "-c", "a", "exec", "fix it", "-c", "b", "exec"]), [-1, 0, -1, 1, -1, 1, -1, -1], "after the prompt: the innermost level, and no more subcommands");
});

test("codexArgvCd: the last -C / --cd (any spelling and level), before --", () => {
  assert.equal(codexArgvCd(["codex", "-C", "/a", "exec", "--cd", "/b", "hi"]), "/b");
  assert.equal(codexArgvCd(["codex", "--cd=/c"]), "/c");
  assert.equal(codexArgvCd(["codex", "-C/d"]), "/d");
  assert.equal(codexArgvCd(["codex", "-m", "-C", "exec"]), null, "a value is not a flag");
  assert.equal(codexArgvCd(["codex", "--", "-C", "/x"]), null);
});

test("codexBareAppServer: app-server serving sessions, its options allowed; not with a subcommand of its own (after options too) or help", () => {
  for (const a of [["codex", "app-server"], ["codex", "-c", "x=1", "app-server", "--listen", "stdio://"], ["codex", "app-server", "--listen", "ws://h:1", "--analytics-default-enabled"], ["codex", "app-server", "--"]]) {
    assert.equal(codexBareAppServer(a), true, JSON.stringify(a));
  }
  for (const a of [["codex"], ["codex", "exec", "app-server"], ["codex", "app-server", "proxy"], ["codex", "app-server", "--strict-config", "generate-ts", "--out", "d"],
    ["codex", "app-server", "-c", "x=1", "daemon", "start"], ["codex", "app-server", "--enable", "f", "proxy"], ["codex", "app-server", "--help"], ["codex", "-h", "app-server"],
    ["codex", "-m", "app-server"], ["wrap.sh", "app-server"]]) {
    assert.equal(codexBareAppServer(a), false, JSON.stringify(a));
  }
});
// ── --no-daemon: embedded mode by name (codex 0.159) ─────────────────────────

const N = [...O, CODEX_NO_DAEMON];

test("no-daemon gate: only a read Codex version at or past 0.159.1", () => {
  assert.equal(codexTakesNoDaemon("0.159.1"), true);
  assert.equal(codexTakesNoDaemon("0.160.0"), true);
  assert.equal(codexTakesNoDaemon("codex-cli 0.159.2"), true);
  assert.equal(codexTakesNoDaemon("0.159.0"), false, "not verified there: an older Codex refuses the flag outright");
  assert.equal(codexTakesNoDaemon("0.154.0"), false);
  assert.equal(codexTakesNoDaemon(null), false, "an unread version (wrapper, failed probe) gets no flag");
  assert.equal(codexTakesNoDaemon(undefined), false);
});

test("no-daemon splice: the TUI gets it at the root", () => {
  assert.deepEqual(codexSpliceOverrides(["codex"], N), ["codex", ...N]);
  assert.deepEqual(codexSpliceOverrides(["codex", "fix the bug"], N), ["codex", ...N, "fix the bug"]);
});

test("no-daemon splice: root and root-level resume / fork take it; exec and other subcommands do not", () => {
  assert.deepEqual(codexSpliceOverrides(["codex", "resume", "--last"], N), ["codex", ...N, "resume", ...N, "--last"]);
  assert.deepEqual(codexSpliceOverrides(["codex", "fork", "--last"], N), ["codex", ...N, "fork", ...N, "--last"]);
  assert.deepEqual(codexSpliceOverrides(["codex", "exec", "hi"], N), ["codex", ...N, "exec", ...O, "hi"]);
  assert.deepEqual(
    codexSpliceOverrides(["codex", "exec", "resume", "--last", "hi"], N),
    ["codex", ...N, "exec", ...O, "resume", ...O, "--last", "hi"],
    "exec resume is not the root-level resume",
  );
  assert.deepEqual(codexSpliceOverrides(["codex", "mcp", "list"], N), ["codex", ...N, "mcp", ...O, "list"]);
});

test("no-daemon splice: never twice at one level (clap refuses a repeat)", () => {
  assert.deepEqual(codexSpliceOverrides(["codex", "--no-daemon", "hi"], N), ["codex", ...O, "--no-daemon", "hi"]);
  assert.deepEqual(
    codexSpliceOverrides(["codex", "resume", "--no-daemon", "--last"], N),
    ["codex", ...N, "resume", ...O, "--no-daemon", "--last"],
    "the user's copy at resume, ours at the root",
  );
  assert.deepEqual(
    codexSpliceOverrides(["codex", "use --no-daemon"], N), ["codex", ...N, "use --no-daemon"],
    "prompt text is not the flag",
  );
  assert.deepEqual(codexSpliceOverrides(["codex", "--", "--no-daemon"], N), ["codex", ...N, "--", "--no-daemon"]);
  for (const argv of [["codex"], ["codex", "resume"], ["codex", "exec", "resume", "hi"], ["codex", "--no-daemon", "fork", "--no-daemon"]]) {
    const out = codexSpliceOverrides(argv, N);
    // Per level (split at subcommand tokens), at most one --no-daemon.
    const perLevel = out.join(" ").split(/ (?:resume|fork|exec|mcp) /).map((l) => l.split(" ").filter((t) => t === CODEX_NO_DAEMON).length);
    assert.ok(perLevel.every((n) => n <= 1), `${argv.join(" ")} → ${out.join(" ")}`);
  }
});

test("refusal: --remote and `codex agents` attach to a server Mandu did not start", () => {
  for (const argv of [
    ["codex", "--remote", "unix://"],
    ["codex", "--remote=ws://127.0.0.1:9000"],
    ["codex", "resume", "--remote", "unix://", "--last"],
    ["codex", "agents"],
    ["codex", "-m", "gpt-5.5", "agents"],
  ]) {
    const r = codexLaunchRefusal(argv);
    assert.ok(r !== null, `refused: ${argv.join(" ")}`);
    assert.match(r!, /refusing to launch codex with (--remote|`codex agents`): it attaches to a Codex server Mandu did not start/);
  }
  assert.equal(codexLaunchRefusal(["codex", "list the agents"]), null, "prompt text");
  assert.equal(codexLaunchRefusal(["codex", "-m", "agents"]), null, "a flag value is not a subcommand");
  assert.equal(codexLaunchRefusal(["codex", "exec", "--", "--remote"]), null, "after -- it is prompt text");
  assert.equal(codexLaunchRefusal(["codex", "--no-daemon", "hi"]), null);
});

test("refusal: the server subcommands (remote-control, app-server, exec-server, debug app-server), every form", () => {
  const cases: [string[], RegExp][] = [
    [["codex", "remote-control"], /`codex remote-control`: it starts or manages Codex's background server/],
    [["codex", "remote-control", "start"], /`codex remote-control`/],
    [["codex", "remote-control", "stop"], /`codex remote-control`/],
    [["codex", "remote-control", "pair", "--json"], /`codex remote-control`/],
    [["codex", "--enable", "x", "remote-control", "start"], /`codex remote-control`/],
    [["codex", "app-server"], /`codex app-server`: it runs Codex's agent server/],
    [["codex", "app-server", "--listen", "unix://"], /`codex app-server`/],
    [["codex", "app-server", "daemon", "start"], /`codex app-server`/],
    [["codex", "app-server", "proxy"], /`codex app-server`/],
    [["codex", "app-server", "generate-ts"], /`codex app-server`/],
    [["codex", "exec-server"], /`codex exec-server`: it runs Codex's command-execution server/],
    [["codex", "exec-server", "--listen", "ws://127.0.0.1:1"], /`codex exec-server`/],
    [["codex", "exec-server", "forward"], /`codex exec-server`/],
    [["codex", "debug", "app-server", "send-message-v2", "hi"], /`codex debug app-server`: .*skip Mandu's model proxy/],
    [["codex", "-c", "x=1", "debug", "--enable", "y", "app-server"], /`codex debug app-server`/],
    [["/usr/local/bin/codex", "-m", "gpt-5.5", "app-server"], /`codex app-server`/],
  ];
  for (const [argv, re] of cases) {
    const r = codexLaunchRefusal(argv);
    assert.ok(r !== null, `refused: ${argv.join(" ")}`);
    assert.match(r!, re, argv.join(" "));
    assert.match(r!, /under Mandu the agent runs in the process Mandu launched/);
  }
});

test("refusal: near-misses of the server subcommands still launch", () => {
  for (const argv of [
    ["codex", "start the app-server please"],
    ["codex", "exec", "app-server"],
    ["codex", "exec", "remote-control"],
    ["codex", "exec", "--", "debug", "app-server"],
    ["codex", "--", "exec-server"],
    ["codex", "-m", "app-server"],
    ["codex", "-p", "remote-control", "hi"],
    ["codex", "debug", "models"],
    ["codex", "debug", "prompt-input", "app-server"],
    ["codex", "resume", "app-server"],
    ["codex", "sandbox", "--", "ls"],
    ["codex", "mcp", "list"],
    ["codex", "queue", "--thread", "t", "--message", "m"],
    ["codex", "clouds"],
    ["codex", "doctor"],
    ["codex", "mcp-server"],
    ["wrap.sh", "app-server"],
  ]) {
    assert.equal(codexLaunchRefusal(argv), null, argv.join(" "));
  }
  assert.ok(codexLaunchRefusal(["codex", "queue", "--remote", "unix://", "--thread", "t", "--message", "m"]) !== null, "queue --remote attaches");
});

// ── Codex's own uploads (supported-agents.md §5.3.4 rule 1, §5.5) ───────────

test("uploads off: the exact switches, as -c tokens (codex-cli 0.160.0 / 0.136.0 key names)", () => {
  assert.deepEqual(CODEX_UPLOADS_OFF_OVERRIDES, [
    "-c", "analytics.enabled=false",
    "-c", "feedback.enabled=false",
    "-c", 'otel.exporter="none"',
    "-c", 'otel.trace_exporter="none"',
    "-c", 'otel.metrics_exporter="none"',
    "-c", "features.apps=false",
    "-c", "check_for_update_on_startup=false",
  ]);
  // The legacy `connectors` key is checked for conflicts but forced only
  // where the user's config names it (Codex prints a deprecation notice).
  assert.deepEqual(CODEX_CONNECTORS_OFF, ["-c", "features.connectors=false"]);
  assert.ok(CODEX_UPLOADS_OFF.some(([k]) => k === "features.connectors"));
  assert.equal((CODEX_UPLOADS_OFF.length - 1) * 2, CODEX_UPLOADS_OFF_OVERRIDES.length);
});

test("codexConfigNamesConnectors: the legacy key in every TOML spelling; not a comment, not another key", () => {
  for (const t of [
    "[features]\nconnectors = true", "features.connectors = false", "features = { apps = true, connectors = true }",
    "[profiles.work.features]\n  connectors=true", '[features]\n"connectors" = true',
  ]) assert.equal(codexConfigNamesConnectors(t), true, t);
  for (const t of ["[features]\napps = true", "# connectors = true", "[features]\nmy_connectors_x = true", "model = \"connectors\"", ""]) {
    assert.equal(codexConfigNamesConnectors(t), false, t);
  }
});

test("uploads off: spliced with the routing at every command level, so a user's exec-level -c cannot drop them", () => {
  const all = [...O, ...CODEX_UPLOADS_OFF_OVERRIDES];
  const out = codexSpliceOverrides(["codex", "exec", "-c", "model=x", "resume", "--last"], all);
  // Root, exec and exec resume each carry the whole list, routing first.
  assert.equal(out.filter((t) => t === "features.apps=false").length, 3, out.join(" "));
  const exec = out.indexOf("exec");
  assert.deepEqual(out.slice(exec + 1, exec + 1 + all.length), all);
  assert.ok(out.indexOf("model=x") > exec + all.length, "the user's exec -c comes after ours");
});

test("codexUploadConflict: another value, a key below, or a whole table undoes a switch; the same value and other keys do not", () => {
  for (const kv of [
    "features.apps=true", "features.connectors=true", "analytics.enabled=true", "feedback.enabled = true",
    "check_for_update_on_startup=true",
    'otel.exporter={otlp-http={endpoint="https://c.example/v1/logs",protocol="binary"}}',
    'otel.trace_exporter={otlp-grpc={endpoint="https://c.example"}}', "otel.metrics_exporter=statsig",
    'otel.exporter.otlp-http.endpoint="https://c.example"',
    "otel={}", "features={apps=true}", "analytics={enabled=true}", "feedback={}",
    '"features"."apps"=true',
  ]) assert.equal(codexUploadConflict(kv), true, kv);
  for (const kv of [
    "features.apps=false", "features.apps = false", "analytics.enabled=false", 'otel.exporter="none"', "otel.exporter=none",
    "otel.exporter='none'", "features.multi_agent=true", "otel.log_user_prompt=true", "model=o3", "features.apps_mcp_gateway=true",
    "analytics_extra=1",
  ]) assert.equal(codexUploadConflict(kv), false, kv);
});

test("refusal: a user override that turns one of Codex's own uploads back on is refused, in every spelling and level", () => {
  for (const argv of [
    ["codex", "-c", "features.apps=true"],
    ["codex", "exec", "--config", "feedback.enabled=true", "hi"],
    ["codex", "exec", "--config=analytics.enabled=true", "hi"],
    ["codex", "exec", "-cotel={}", "hi"],
    ["codex", "exec", "-c=features.connectors=true", "hi"],
    ["codex", "--enable", "apps"],
    ["codex", "exec", "--enable=connectors", "hi"],
    ["codex", "exec", "hi", "-c", 'otel.trace_exporter={otlp-http={endpoint="https://c.example",protocol="json"}}'],
  ]) {
    const r = codexLaunchRefusal(argv);
    assert.ok(r !== null, argv.join(" "));
    assert.match(r!, /Codex's own uploads/, argv.join(" "));
  }
  for (const argv of [
    ["codex", "-c", "features.apps=false"],
    ["codex", "--disable", "apps"],
    ["codex", "--enable", "multi_agent"],
    ["codex", "exec", "-c", "otel.log_user_prompt=true", "hi"],
    ["codex", "exec", "--", "-c", "features.apps=true"],
    ["wrap.sh", "-c", "features.apps=true"],
  ]) assert.equal(codexLaunchRefusal(argv), null, argv.join(" "));
});

test("refusal: `codex cloud` (and its alias) runs the agent in Codex Cloud, past every protection", () => {
  for (const argv of [["codex", "cloud"], ["codex", "cloud", "exec", "--env", "e", "hi"], ["codex", "-c", "model=x", "cloud-tasks", "list"]]) {
    const r = codexLaunchRefusal(argv);
    assert.ok(r !== null, argv.join(" "));
    assert.match(r!, /Codex Cloud/, argv.join(" "));
  }
  assert.equal(codexLaunchRefusal(["codex", "exec", "cloud"]), null, "a prompt that says cloud");
  assert.equal(codexLaunchRefusal(["codex", "--", "cloud"]), null);
});
