/**
 * goose-argv — the allowlist of Goose launch shapes (src/goose-argv.ts), bare
 * `mandu goose` → `goose session`, and the `--with-extension` splice that
 * mounts Mandu's MCP servers. Facts read from goose 1.53.0's `--help` and
 * source (2026-10-05; supported-agents.md §5.6).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  gooseAcpLaunch,
  gooseDefaultArgv,
  gooseExtensionArg,
  gooseFlagValues,
  gooseLaunchRefusal,
  gooseQuoteToken,
  gooseSpliceExtensions,
  gooseValueFlags,
  isGooseBinary,
  readGooseArgv,
} from "../../src/goose-argv.js";
import { parse } from "../../src/parse.js";
import { testRuntimeDir } from "../lib/test-runtime.js";

const ENV = { HOME: "/home/u", XDG_RUNTIME_DIR: testRuntimeDir() }; // a private dir, never another account's /run/user/<uid> (test-organization.md §8.7)

test("readGooseArgv: the goose binary (any path), aliases resolved, a wrapper is not Goose", () => {
  assert.deepEqual(readGooseArgv(["goose", "session", "-n", "x"]), { sub: "session", command: "session", subIndex: 1, rest: ["-n", "x"], globals: [] });
  assert.deepEqual(readGooseArgv(["/usr/local/bin/goose", "s"]), { sub: "s", command: "session", subIndex: 1, rest: [], globals: [] });
  assert.equal(readGooseArgv(["goose", "gw"])!.command, "gateway");
  assert.equal(readGooseArgv(["goose", "sched", "list"])!.command, "schedule");
  assert.deepEqual(readGooseArgv(["goose"]), { sub: "", command: "", subIndex: -1, rest: [], globals: [] });
  assert.deepEqual(readGooseArgv(["goose", "--version"])!.globals, ["--version"]);
  assert.equal(readGooseArgv(["./run-goose.sh", "session"]), null);
  assert.equal(readGooseArgv([]), null);
  assert.ok(isGooseBinary("/opt/goose/bin/goose"));
  assert.ok(!isGooseBinary("goosed"));
});

test("gooseAcpLaunch: `goose acp` serving an editor (not its help, not a wrapper); parse turns the reply filter off for it", () => {
  assert.ok(gooseAcpLaunch(["goose", "acp"]));
  assert.ok(gooseAcpLaunch(["/opt/bin/goose", "acp", "--with-builtin", "developer"]));
  assert.ok(!gooseAcpLaunch(["goose", "acp", "--help"]));
  assert.ok(!gooseAcpLaunch(["goose", "session"]));
  assert.ok(!gooseAcpLaunch(["wrapper.sh", "acp"]));
  assert.equal(parse(["goose", "acp"], ENV).replyFilter, false, "line rewriting would break the JSON-RPC framing");
  assert.equal(parse(["goose", "acp"], { ...ENV, MANDU_REPLY_FILTER: "1" }).replyFilter, false);
  assert.equal(parse(["goose", "session"], ENV).replyFilter, true);
});

test("gooseDefaultArgv: bare `goose` runs `goose session` (not the configure setup); help, version, subcommands and wrappers unchanged", () => {
  assert.deepEqual(gooseDefaultArgv(["goose"]), ["goose", "session"]);
  assert.deepEqual(gooseDefaultArgv(["goose", "--help"]), ["goose", "--help"]);
  assert.deepEqual(gooseDefaultArgv(["goose", "run", "-t", "x"]), ["goose", "run", "-t", "x"]);
  assert.deepEqual(gooseDefaultArgv(["wrapper.sh"]), ["wrapper.sh"]);
});

test("allowed: session and run (with their ordinary flags), help and version", () => {
  for (const argv of [
    ["goose", "session"], ["goose", "s", "--resume"], ["goose", "session", "-n", "list"], ["goose", "session", "--name=export"],
    ["goose", "run", "-t", "hello"], ["goose", "run", "--no-session", "--output-format", "json", "-i", "-"],
    ["goose", "run", "--with-builtin", "developer,todo"], ["goose", "session", "--with-extension", "npx -y @x/server"],
    ["goose", "--help"], ["goose", "-V"], ["goose", "help"], ["goose", "serve", "--help"], ["goose", "run", "--help"],
    ["wrapper.sh", "serve"],
    // a recipe is read at launch (goose-recipe.ts), a review's children inherit the routing
    ["goose", "run", "--recipe", "r.yaml"], ["goose", "run", "--recipe=r.yaml", "--params", "k=v"],
    ["goose", "review"], ["goose", "review", "main...HEAD", "--model", "m", "-c", "secrets", "--dry-run"],
    // the editor's stream goes through the ACP relay (goose-acp-relay.ts)
    ["goose", "acp"], ["goose", "acp", "--with-builtin", "developer,todo"],
  ]) {
    assert.equal(gooseLaunchRefusal(argv), null, argv.join(" "));
  }
});

test("refused: the shapes whose loop or effect lands outside the launch, each with its reason", () => {
  const cases: Array<[string[], RegExp]> = [
    [["goose", "serve"], /desktop backend/],
    [["goose", "serve", "--enable-scheduler"], /scheduled jobs/],
    [["goose", "gateway", "start"], /chat platforms/],
    [["goose", "gw"], /chat platforms/],
    [["goose", "schedule", "add"], /fire later/],
    [["goose", "acp", "--enable-scheduler"], /scheduled recipes/],
    [["goose", "acp", "--with-builtin", "developer,code_execution"], /code mode/],
    [["goose", "roam"], /paired devices/],
    [["goose", "session", "export", "--nostr"], /Nostr relays/],
    [["goose", "session", "list"], /manages saved sessions/],
    [["goose", "session", "import", "x.json"], /manages saved sessions/],
    [["goose", "session", "--container", "c1"], /container/],
    [["goose", "run", "--container=c1", "-t", "x"], /container/],
    [["goose", "run", "-t", "x", "--sub-recipe", "s.yaml"], /delegate` with a `source`, which Mandu refuses on the wire/],
    [["goose", "run", "--recipe", "r.yaml", "--sub-recipe=s.yaml"], /could never run/],
    [["goose", "session", "--recipe", "r.yaml"], /takes no recipe/],
    [["goose", "recipe", "validate", "r.yaml"], /runs no agent/],
    [["goose", "recipe", "open", "r.yaml"], /Goose Desktop/],
    [["goose", "session", "--with-builtin", "developer,code_execution"], /code mode/],
    [["goose", "run", "--with-builtin=code_execution", "-t", "x"], /code mode/],
    [["goose", "configure"], /not an agent shape/],
    [["goose", "mcp", "developer"], /not an agent shape/],
    [["goose", "update"], /not an agent shape/],
    [["goose"], /configure/],
  ];
  for (const [argv, why] of cases) {
    const r = gooseLaunchRefusal(argv);
    assert.ok(r, `${argv.join(" ")} is refused`);
    assert.match(r!, /^mandu: refusing `goose/);
    assert.match(r!, why, argv.join(" "));
  }
});

test("parse: `goose` is inferred, bare `mandu goose` becomes `goose session`, a refused shape throws before anything launches", () => {
  const p = parse(["goose"], ENV);
  assert.equal(p.target, "goose");
  assert.deepEqual(p.argv, ["goose", "session"]);
  assert.equal(parse(["--target", "goose", "--", "./my-goose.sh", "serve"], ENV).target, "goose", "a wrapper is vouched for by --target");
  assert.throws(() => parse(["goose", "serve"], ENV), /refusing `goose serve`/);
  assert.throws(() => parse(["goose", "session", "export"], ENV), /Nostr/);
  assert.throws(() => parse(["--target", "gooze", "--", "x"], ENV), /claude\|codex\|openclaw\|opencode\|goose\|shell/);
});

test("parse: Goose's base-URL override is its own ANTHROPIC_HOST (not ANTHROPIC_BASE_URL); the official endpoint is no override", () => {
  assert.equal(parse(["goose"], { ...ENV, ANTHROPIC_BASE_URL: "http://127.0.0.1:9999" }).anthropicBaseUrl, undefined,
    "a claude base URL in the env must not skip Goose's proxy");
  assert.equal(parse(["goose"], { ...ENV, ANTHROPIC_HOST: "https://gw.corp.example" }).anthropicBaseUrl, "https://gw.corp.example");
  assert.equal(parse(["goose"], { ...ENV, ANTHROPIC_HOST: "https://api.anthropic.com/" }).anthropicBaseUrl, undefined);
  assert.equal(parse(["claude"], { ...ENV, ANTHROPIC_HOST: "https://gw.corp.example" }).anthropicBaseUrl, undefined);
});

test("gooseFlagValues: both spellings, other flags' values skipped, nothing after --", () => {
  assert.deepEqual(gooseFlagValues(["--provider", "openai", "-t", "--provider", "--provider=x"], "--provider"), ["openai", "x"]);
  assert.deepEqual(gooseFlagValues(["-t", "--provider", "--", "--provider", "y"], "--provider"), []);
});

test("gooseValueFlags: review's own value flags; `run -s` (interactive, no value) never hides the next flag", () => {
  assert.deepEqual(gooseFlagValues(["-s", "--provider", "openai"], "--provider", gooseValueFlags("run")), ["openai"]);
  assert.deepEqual(gooseFlagValues(["-s", "dir", "--provider", "openai"], "--provider", gooseValueFlags("review")), ["openai"]);
  assert.deepEqual(gooseFlagValues(["--prompt", "p.md", "--provider=google"], "--provider", gooseValueFlags("review")), ["google"]);
  assert.ok(gooseValueFlags("review").has("--override-model"));
  assert.ok(!gooseValueFlags("run").has("-s"));
});

test("gooseQuoteToken: tokens Goose's split_command_args reads back verbatim", () => {
  assert.equal(gooseQuoteToken("/usr/bin/node"), "/usr/bin/node");
  assert.equal(gooseQuoteToken("A=b c"), "'A=b c'");
  assert.equal(gooseQuoteToken('K={"a":1}'), `'K={"a":1}'`);
  assert.equal(gooseQuoteToken("'lead"), null, "a leading single quote opens a quote; it cannot be written");
  assert.equal(gooseQuoteToken("it's"), "it's", "a single quote mid-token is literal");
  assert.equal(gooseQuoteToken("it's here"), null, "cannot be written");
  assert.equal(gooseQuoteToken(""), "''");
});

/** A port of goose 1.53.0 crates/goose/src/utils.rs split_command_args, to
 *  prove the round trip. */
function splitCommandArgs(input: string): string[] {
  const parts: string[] = [];
  let cur = "";
  let dq = false;
  let sq = false;
  for (const c of input) {
    if (c === '"' && !sq) dq = !dq;
    else if (c === "'" && !dq && (sq || cur === "")) sq = !sq;
    else if (/\s/.test(c) && !dq && !sq) { if (cur !== "") { parts.push(cur); cur = ""; } }
    else cur += c;
  }
  if (dq || sq) throw new Error("Unmatched quote in command");
  if (cur !== "") parts.push(cur);
  return parts;
}

test("gooseExtensionArg: `name:ENV=… cmd args`, read back by Goose's parser into the same env, command and args", () => {
  const server = {
    command: "/opt/mandu/bin/node",
    args: ["/opt/mandu/inspect-mcp.mjs", "--flag"],
    env: { MANDU_ARBITER_SOCK: "/run/mandu/a.sock", NO_PROXY: "127.0.0.1,localhost", MANDU_MODEL_CLIENT_KEYS: '{"e": "-----BEGIN KEY-----"}' },
  };
  const arg = gooseExtensionArg("mandu-inspect", server)!;
  assert.ok(arg.startsWith("mandu-inspect:"));
  const parts = splitCommandArgs(arg.slice("mandu-inspect:".length));
  const env: Record<string, string> = {};
  while (parts.length && parts[0]!.includes("=")) { const t = parts.shift()!; env[t.slice(0, t.indexOf("="))] = t.slice(t.indexOf("=") + 1); }
  assert.deepEqual(env, server.env);
  assert.deepEqual(parts, [server.command, ...server.args]);
  // what cannot be mounted is left out, never mangled
  assert.equal(gooseExtensionArg("mandu-inspect", { ...server, env: { K: "it's a value" } }), null);
  assert.equal(gooseExtensionArg("x", server), null, "Goose reads a one-character prefix as no name");
  assert.equal(gooseExtensionArg("mandu-inspect", { ...server, command: "/opt/a=b/node" }), null);
});

test("gooseSpliceExtensions: right after session / run; nothing for a wrapper, bare, help or another subcommand", () => {
  const ext = ["--with-extension", "mandu-inspect:/n /s.mjs"];
  assert.deepEqual(gooseSpliceExtensions(["goose", "session", "-r"], ext), ["goose", "session", ...ext, "-r"]);
  assert.deepEqual(gooseSpliceExtensions(["goose", "run", "-t", "hi"], ext), ["goose", "run", ...ext, "-t", "hi"]);
  assert.deepEqual(gooseSpliceExtensions(["goose", "s"], ext), ["goose", "s", ...ext]);
  assert.deepEqual(gooseSpliceExtensions(["goose", "--version"], ext), ["goose", "--version"]);
  assert.deepEqual(gooseSpliceExtensions(["wrapper.sh", "run"], ext), ["wrapper.sh", "run"]);
  assert.deepEqual(gooseSpliceExtensions(["goose", "session"], []), ["goose", "session"]);
  assert.deepEqual(gooseSpliceExtensions(["goose", "review"], ext), ["goose", "review"], "review takes no --with-extension");
});
