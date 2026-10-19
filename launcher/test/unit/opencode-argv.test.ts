/**
 * opencode-argv — the allowlist of OpenCode 2 launch shapes
 * (src/opencode-argv.ts) and the `--standalone` each allowed shape gets, so
 * the agent runs with a private server inside the wrap instead of joining
 * the user's background service. Facts read from OpenCode 2.0.23's `--help`
 * and probed on the binary (2026-10-05; supported-agents.md §2.3, part 1).
 * Pure: no binary runs here (the real-binary proof is
 * test/component/opencode-v2-standalone.test.ts).
 *
 * OpenCode 1 (`opencode1LaunchArgv`, 2026-10-11): the same refusal of the
 * server and management subcommands, read from 1.18.13's `opencode --help`;
 * the TUI and `run` pass unchanged.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { OPENCODE1_ARGV_VERSION, OPENCODE2_ARGV_VERSION, STANDALONE_FLAG, opencode1LaunchArgv, opencode2LaunchArgv, readOpencode2Argv } from "../../src/opencode-argv.js";

const ok = (argv: string[]): string[] => {
  const r = opencode2LaunchArgv(argv);
  assert.equal(r.refusal, null, `allowed: ${argv.join(" ")} (${r.refusal})`);
  return r.argv!;
};
const refused = (argv: string[]): string => {
  const r = opencode2LaunchArgv(argv);
  assert.ok(r.refusal !== null, `refused: ${argv.join(" ")}`);
  assert.equal(r.argv, null);
  assert.ok(!r.refusal.includes("\n"), "one line");
  assert.match(r.refusal, /^mandu: refusing `opencode2? ?[a-z]*`: /);
  return r.refusal;
};

test("readOpencode2Argv: opencode and opencode2 (any path); the subcommand is argv[1]; anything else is the TUI; a wrapper is not OpenCode", () => {
  assert.deepEqual(readOpencode2Argv(["opencode", "run", "hi"]), { sub: "run", subIndex: 1 });
  assert.deepEqual(readOpencode2Argv(["/usr/local/bin/opencode2", "mini"]), { sub: "mini", subIndex: 1 });
  assert.deepEqual(readOpencode2Argv(["opencode"]), { sub: "", subIndex: -1 });
  assert.deepEqual(readOpencode2Argv(["opencode", "./proj"]), { sub: "", subIndex: -1 });
  assert.deepEqual(readOpencode2Argv(["opencode", "--auto", "run"]), { sub: "", subIndex: -1 }, "a flag first: not a subcommand");
  assert.equal(readOpencode2Argv(["./run-opencode.sh", "run"]), null);
  assert.equal(readOpencode2Argv(["opencode.exe", "run"]), null);
  assert.equal(readOpencode2Argv([]), null);
});

test("the TUI, run and mini get --standalone where OpenCode reads it: after `opencode` for the TUI, after the subcommand otherwise", () => {
  assert.deepEqual(ok(["opencode"]), ["opencode", STANDALONE_FLAG]);
  assert.deepEqual(ok(["/opt/bin/opencode2"]), ["/opt/bin/opencode2", STANDALONE_FLAG]);
  assert.deepEqual(ok(["opencode", "./proj", "--auto", "-c"]), ["opencode", STANDALONE_FLAG, "./proj", "--auto", "-c"]);
  assert.deepEqual(ok(["opencode", "--session", "ses_1", "--prompt", "fix it"]), ["opencode", STANDALONE_FLAG, "--session", "ses_1", "--prompt", "fix it"]);
  assert.deepEqual(
    ok(["opencode", "run", "-m", "anthropic/claude-sonnet-4-5#high", "--format", "json", "say hi"]),
    ["opencode", "run", STANDALONE_FLAG, "-m", "anthropic/claude-sonnet-4-5#high", "--format", "json", "say hi"],
  );
  assert.deepEqual(ok(["opencode", "run", "--model=anthropic/x", "--title=t", "-f", "a.txt", "--thinking", "--fork", "-s", "s1", "hi"])[2], STANDALONE_FLAG);
  assert.deepEqual(ok(["opencode", "mini", "--replay-limit", "50", "--no-replay", "--agent", "build"]), ["opencode", "mini", STANDALONE_FLAG, "--replay-limit", "50", "--no-replay", "--agent", "build"]);
  // Global flags are every shape's.
  assert.deepEqual(ok(["opencode", "run", "--print-logs", "--log-level", "debug", "hi"])[2], STANDALONE_FLAG);
  // `--` ends the flags: what follows is the message, even when it looks like one.
  assert.deepEqual(ok(["opencode", "run", "--", "--server", "http://x", "serve"]), ["opencode", "run", STANDALONE_FLAG, "--", "--server", "http://x", "serve"]);
  // A message or a value that names a subcommand is not one.
  assert.deepEqual(ok(["opencode", "run", "serve", "the", "app"])[2], STANDALONE_FLAG);
  assert.deepEqual(ok(["opencode", "--prompt", "serve"]), ["opencode", STANDALONE_FLAG, "--prompt", "serve"]);
  // `help` is not a subcommand of OpenCode 2: `opencode help` is the TUI in a directory named help.
  assert.deepEqual(ok(["opencode", "help"]), ["opencode", STANDALONE_FLAG, "help"]);
});

test("an argv that already says --standalone is left as it is (no second copy)", () => {
  assert.deepEqual(ok(["opencode", "--standalone"]), ["opencode", "--standalone"]);
  assert.deepEqual(ok(["opencode", "run", "hi", "--standalone"]), ["opencode", "run", "hi", "--standalone"]);
  // ...but not one after `--` (that is message text).
  assert.deepEqual(ok(["opencode", "run", "--", "--standalone"]), ["opencode", "run", STANDALONE_FLAG, "--", "--standalone"]);
});

test("help and version pass unchanged: anywhere in an allowed shape (outside a value), right after a refused subcommand", () => {
  for (const argv of [
    ["opencode", "--help"], ["opencode", "-h"], ["opencode", "--version"], ["opencode", "-v"],
    ["opencode", "run", "--help"], ["opencode", "run", "hi", "--version"], ["opencode", "mini", "-h"],
    ["opencode", "serve", "--help"], ["opencode", "service", "-h"], ["opencode", "auth", "--version"],
  ]) {
    assert.deepEqual(ok(argv), argv, argv.join(" "));
  }
  // A value that reads like --help is a value: the shape still gets --standalone.
  assert.deepEqual(ok(["opencode", "run", "--title", "--help", "hi"]), ["opencode", "run", STANDALONE_FLAG, "--title", "--help", "hi"]);
  // Further on in a refused subcommand Mandu cannot tell a --help from a flag's value: refused.
  refused(["opencode", "serve", "--hostname", "--help"]);
});

test("--server is refused in every shape and spelling: the server it names runs the model calls and tools with its own settings", () => {
  for (const argv of [
    ["opencode", "--server", "http://127.0.0.1:49374"],
    ["opencode", "run", "--server", "http://127.0.0.1:4096", "hi"],
    ["opencode", "run", "hi", "--server=http://h:1"],
    ["opencode", "mini", "--standalone", "--server", "http://h:1"],
  ]) {
    assert.match(refused(argv), /--server joins that OpenCode server .*outside this launch\. Leave --server out: Mandu runs OpenCode with a private server \(--standalone\)/);
  }
});

test("the server shapes are refused: serve, service, pair, api, acp", () => {
  assert.match(refused(["opencode", "serve", "--port", "4096"]), /`opencode serve` starts an OpenCode server that other clients .*drive.*Use `mandu opencode` \(the TUI\) or `mandu opencode run …`/);
  assert.match(refused(["opencode", "serve", "--service"]), /`opencode serve`/);
  for (const s of ["start", "restart", "status", "stop", "set", "get"]) {
    assert.match(refused(["opencode", "service", s]), /`opencode service` manages the background service, which runs the model calls and tools .*Run it without `mandu`\./);
  }
  assert.match(refused(["opencode", "pair"]), /connect a browser or app to the background server/);
  assert.match(refused(["opencode", "api", "GET", "/api/info"]), /sends a request to a running server/);
  assert.match(refused(["opencode", "acp"]), /Agent Client Protocol/);
  assert.match(refused(["opencode2", "serve"]), /^mandu: refusing `opencode2 serve`/);
});

test("the management subcommands are refused with what to do instead (run them without mandu)", () => {
  for (const [sub, re] of [
    ["session", /saved sessions/], ["auth", /credentials \(`auth export` prints them\)/], ["mcp", /MCP server configuration/],
    ["plugin", /installs and removes plugins/], ["models", /background service/], ["stats", /background service/],
    ["reload", /background service/], ["debug", /troubleshooting/], ["upgrade", /installation/], ["update", /installation/],
    ["uninstall", /installation/],
  ] as const) {
    const r = refused(["opencode", sub, "list"]);
    assert.match(r, re, sub);
    assert.match(r, /Run it without `mandu`\.$/, sub);
  }
});

test("--wizard, an unknown flag, a switch given a value, and flags before a subcommand are refused (fail closed)", () => {
  assert.match(refused(["opencode", "--wizard"]), /--wizard builds a command interactively/);
  assert.match(refused(["opencode", "run", "--wizard"]), /--wizard/);
  const unknown = refused(["opencode", "run", "--port", "4096", "hi"]);
  assert.match(unknown, new RegExp(`--port is not a flag Mandu knows for \`opencode run\` \\(OpenCode ${OPENCODE2_ARGV_VERSION.replace(/\./g, "\\.")}\\)`));
  refused(["opencode", "--no-standalone"]);
  refused(["opencode", "run", "--standalone=false", "hi"]);
  refused(["opencode", "run", "-cs", "s1"]);
  refused(["opencode", "mini", "--format", "json"]); // run's flag, not mini's
  refused(["opencode", "--model", "x"]); // run's / mini's flag, not the TUI's
  assert.match(refused(["opencode", "--auto", "serve"]), /`serve` comes after other arguments; .*Write it as `opencode serve \[flags\]`/);
  refused(["opencode", "--auto", "run", "hi"]);
  refused(["opencode", "./proj", "service", "start"]);
});

test("a wrapper script (--target opencode) is not OpenCode's argv: unchanged, never refused here", () => {
  assert.deepEqual(ok(["node", "oc-wrapper.mjs", "serve"]), ["node", "oc-wrapper.mjs", "serve"]);
  assert.deepEqual(ok(["./my-opencode", "--server", "x"]), ["./my-opencode", "--server", "x"]);
});

// ── OpenCode 1 ───────────────────────────────────────────────────────────────

const ok1 = (argv: string[]): void => {
  const r = opencode1LaunchArgv(argv);
  assert.equal(r.refusal, null, `allowed: ${argv.join(" ")} (${r.refusal})`);
  assert.deepEqual(r.argv, argv, "unchanged");
};
const refused1 = (argv: string[]): string => {
  const r = opencode1LaunchArgv(argv);
  assert.ok(r.refusal !== null, `refused: ${argv.join(" ")}`);
  assert.equal(r.argv, null);
  assert.ok(!r.refusal.includes("\n"), "one line");
  assert.match(r.refusal, /^mandu: refusing `opencode ?[a-z]*`: /);
  return r.refusal;
};

test("OpenCode 1: the TUI and run pass unchanged (no --standalone: 1.x has no background service)", () => {
  assert.equal(OPENCODE1_ARGV_VERSION, "1.18.13");
  for (const argv of [
    ["opencode"], ["/usr/local/bin/opencode"], ["opencode", "./proj"], ["opencode", "--prompt", "serve"],
    ["opencode", "-m", "anthropic/x", "--auto", "."], ["opencode", "--session", "ses_1", "-c"], ["opencode", "help"],
    ["opencode", "run", "hi"], ["opencode", "run", "--port", "4096", "hi"],
    ["opencode", "run", "-m", "anthropic/x", "--format", "json", "serve", "the", "app"],
    ["opencode", "run", "--", "--attach", "http://h:1"], ["opencode", "--help"], ["opencode", "-v"], ["opencode", "run", "--help"],
    ["opencode", "serve", "--help"], ["opencode", "auth", "-h"],
  ]) ok1(argv);
});

test("OpenCode 1: the TUI flags that make its built-in server listen (--port, --hostname, --mdns) are refused in every spelling; the ones that only shape a listener pass", () => {
  for (const [argv, flag] of [
    [["opencode", "--port", "4096"], "--port"], [["opencode", "--port=4096"], "--port"], [["opencode", ".", "--port", "0"], "--port"],
    [["opencode", "--hostname", "0.0.0.0"], "--hostname"], [["opencode", "--hostname=127.0.0.1", "./proj"], "--hostname"],
    [["opencode", "--mdns"], "--mdns"], [["opencode", "--mdns=true"], "--mdns"], [["opencode", "--mdns", "true"], "--mdns"],
    [["opencode", "-c", "--prompt", "hi", "--mdns=false"], "--mdns"], [["opencode", "--port", "4096", "serve"], "--port"],
  ] as const) {
    const r = refused1([...argv]);
    assert.ok(r.startsWith("mandu: refusing `opencode`: "), r);
    assert.ok(r.includes(`${flag} makes OpenCode's built-in server listen on a network port`), r);
    assert.ok(r.includes("another client") && r.includes(`Leave ${flag} out`), r);
  }
  // A value that reads like one is a value; --no-mdns keeps mDNS off; the
  // listener's shape alone starts nothing.
  ok1(["opencode", "--prompt", "--port"]);
  ok1(["opencode", "--no-mdns"]);
  ok1(["opencode", "--mdns-domain", "x.local", "--cors", "http://a"]);
  // OpenCode 2: no such TUI flag; the allowlist refuses them on every shape.
  for (const argv of [["opencode", "--port", "4096"], ["opencode", "--hostname=0.0.0.0"], ["opencode", "--mdns"], ["opencode", "run", "--port", "1", "hi"]]) {
    assert.match(refused(argv), /is not a flag Mandu knows for/);
  }
});

test("OpenCode 1: every server and management subcommand of 1.18.13 is refused, named, with what to do instead", () => {
  const serverShapes: Array<[string, RegExp]> = [
    ["serve", /`opencode serve` starts an OpenCode server that other clients .*drive/],
    ["web", /web interface/], ["attach", /joins a running OpenCode server/], ["acp", /Agent Client Protocol/],
  ];
  for (const [sub, re] of serverShapes) {
    const r = refused1(["opencode", sub, "x"]);
    assert.ok(r.startsWith(`mandu: refusing \`opencode ${sub}\`: `), sub);
    assert.match(r, re, sub);
    assert.match(r, /Run it without `mandu`, or use `mandu opencode` \(the TUI\) or `mandu opencode run …` to work inside Mandu\.$/, sub);
  }
  const management: Array<[string, RegExp]> = [
    ["providers", /providers and their credentials/], ["auth", /providers and their credentials/], ["mcp", /MCP server configuration/],
    ["agent", /agent definitions/], ["session", /saved sessions/], ["export", /tool output included/], ["import", /from a file or URL/],
    ["db", /SQL shell/], ["models", /lists the available models/], ["stats", /token usage/], ["plugin", /installs a plugin/],
    ["plug", /installs a plugin/], ["debug", /troubleshooting/], ["upgrade", /installation/], ["uninstall", /installation/],
    ["completion", /completion script/], ["github", /GitHub agent/],
  ];
  for (const [sub, re] of management) {
    const r = refused1(["opencode", sub, "list"]);
    assert.ok(r.startsWith(`mandu: refusing \`opencode ${sub}\`: `), sub);
    assert.match(r, re, sub);
    assert.match(r, /Run it without `mandu`\.$/, sub);
  }
  assert.match(refused1(["opencode", "pr", "42"]), /checks out a GitHub pull request's branch .*`gh pr checkout <number>`\), then run `mandu opencode`\.$/);
  // Bare, as the live walk typed them.
  refused1(["opencode", "serve"]);
  refused1(["opencode", "auth"]);
  // Help only right after the subcommand: further on it may be a value.
  refused1(["opencode", "serve", "--hostname", "--help"]);
});

test("OpenCode 1: run --attach (any spelling) joins a running server: refused; after `--` it is message text", () => {
  for (const argv of [["opencode", "run", "--attach", "http://localhost:4096", "hi"], ["opencode", "run", "hi", "--attach=http://h:1"]]) {
    assert.match(refused1(argv), /^mandu: refusing `opencode run`: --attach joins a running OpenCode server.*Leave --attach out/);
  }
});

test("OpenCode 1 reads a subcommand after its flags (yargs): a TUI positional naming one is that subcommand, refused", () => {
  assert.match(refused1(["opencode", "--print-logs", "serve"]), /^mandu: refusing `opencode serve`: /);
  assert.match(refused1(["opencode", "--log-level", "DEBUG", "auth", "list"]), /^mandu: refusing `opencode auth`: /);
  assert.match(refused1(["opencode", "--no-mdns", "web"]), /^mandu: refusing `opencode web`: /);
  assert.match(refused1(["opencode", "--", "serve"]), /`opencode serve`/, "fail closed after --");
  assert.match(refused1(["opencode", "--auto", "run", "hi"]), /^mandu: refusing `opencode`: `run` comes after other arguments.*Write it as `opencode run \[flags\]`\.$/);
  // An unknown flag's value that names a subcommand: refused (only more is refused).
  refused1(["opencode", "--some-new-flag", "serve"]);
});

test("OpenCode 1: a wrapper script is not OpenCode's argv: unchanged, never refused here", () => {
  ok1(["node", "oc-wrapper.mjs", "serve"]);
  ok1(["./my-opencode", "auth", "list"]);
  ok1([]);
});
