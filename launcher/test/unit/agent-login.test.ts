/**
 * agent-login.test — the agent-login probe (launcher/src/agent-login.ts;
 * packaging.md §7): existence checks only, per agent, pure over injected
 * env / fileExists / platform. The launch line warns and never refuses.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CLAUDE_LOGIN_HOWTO,
  CODEX_LOGIN_HOWTO,
  GOOSE_KEYCHAIN_VIA,
  GOOSE_KEYRING_ATTRS,
  GOOSE_LOGIN_HOWTO,
  agentOwnCredentialFiles,
  launchLoginKeying,
  otherAgentLoginsRaw,
  sessionLogins,
  sessionMcpConfigs,
  sessionLoginsKey,
  loginKeptWhere,
  agentDisplayName,
  loginEnvOf,
  gooseKeyringDisabled,
  gooseKeyVar,
  gooseKeyVars,
  gooseKeyringNote,
  gooseSecretsFile,
  keychainSearchArgv,
  keyringSearchArgv,
  readKeychainSearch,
  readKeyringSearch,
  realGooseKeyringItem,
  type KeyringCommandRunner,
  codexKeyRefusal,
  launchLoginNote,
  loginAgentOf,
  probeAgentLogin,
  type LoginProbeDeps,
} from "../../src/agent-login.js";

function deps(over: Partial<LoginProbeDeps> & { files?: string[] } = {}): LoginProbeDeps {
  const files = new Set(over.files ?? []);
  return {
    env: over.env ?? {},
    home: over.home ?? "/home/u",
    fileExists: over.fileExists ?? ((p) => files.has(p)),
    platform: over.platform ?? "linux",
  };
}

test("claude: nothing set and no credentials file → missing, with the agent's own login as the fix", () => {
  const s = probeAgentLogin("claude", deps());
  assert.equal(s.state, "missing");
  assert.equal(s.via, undefined);
  assert.equal(s.howTo, CLAUDE_LOGIN_HOWTO);
  assert.match(s.howTo, /claude/);
  assert.match(s.howTo, /ANTHROPIC_API_KEY/);
});

test("claude: each login variable counts, and `via` names the VARIABLE, never its value", () => {
  for (const k of ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"]) {
    const s = probeAgentLogin("claude", deps({ env: { [k]: "sk-ant-SECRETVALUE" } }));
    assert.equal(s.state, "found", k);
    assert.equal(s.via, k);
    assert.doesNotMatch(JSON.stringify(s), /SECRETVALUE/);
  }
  // An empty or whitespace variable is not a login.
  assert.equal(probeAgentLogin("claude", deps({ env: { ANTHROPIC_API_KEY: " " } })).state, "missing");
});

test("claude: a third-party provider switch counts; =0 / false does not", () => {
  assert.equal(probeAgentLogin("claude", deps({ env: { CLAUDE_CODE_USE_BEDROCK: "1" } })).state, "found");
  assert.equal(probeAgentLogin("claude", deps({ env: { CLAUDE_CODE_USE_VERTEX: "true" } })).via, "CLAUDE_CODE_USE_VERTEX");
  assert.equal(probeAgentLogin("claude", deps({ env: { CLAUDE_CODE_USE_BEDROCK: "0" } })).state, "missing");
  assert.equal(probeAgentLogin("claude", deps({ env: { CLAUDE_CODE_USE_VERTEX: "false" } })).state, "missing");
});

test("claude: the subscription login file under ~/.claude, or under CLAUDE_CONFIG_DIR when set", () => {
  const s = probeAgentLogin("claude", deps({ files: ["/home/u/.claude/.credentials.json"] }));
  assert.deepEqual([s.state, s.via], ["found", "/home/u/.claude/.credentials.json"]);
  const moved = deps({ env: { CLAUDE_CONFIG_DIR: "/cfg" }, files: ["/home/u/.claude/.credentials.json"] });
  assert.equal(probeAgentLogin("claude", moved).state, "missing", "CLAUDE_CONFIG_DIR replaces ~/.claude");
  assert.equal(probeAgentLogin("claude", deps({ env: { CLAUDE_CONFIG_DIR: "/cfg" }, files: ["/cfg/.credentials.json"] })).via, "/cfg/.credentials.json");
});

test("claude on macOS: no variable and no file → unknown (the Keychain is invisible to an existence check), never missing", () => {
  const s = probeAgentLogin("claude", deps({ platform: "darwin" }));
  assert.equal(s.state, "unknown");
  // A variable still counts on macOS.
  assert.equal(probeAgentLogin("claude", deps({ platform: "darwin", env: { ANTHROPIC_API_KEY: "x" } })).state, "found");
});

test("codex: OPENAI_API_KEY / CODEX_API_KEY are found; a `codex login` (auth.json under CODEX_HOME or ~/.codex) is a sign-in the proxy relays", () => {
  assert.equal(probeAgentLogin("codex", deps()).state, "missing");
  assert.equal(probeAgentLogin("codex", deps()).howTo, CODEX_LOGIN_HOWTO);
  assert.match(CODEX_LOGIN_HOWTO, /codex login/);
  assert.match(CODEX_LOGIN_HOWTO, /CODEX_API_KEY/);
  assert.match(CODEX_LOGIN_HOWTO, /OPENAI_API_KEY/);
  const key = probeAgentLogin("codex", deps({ env: { OPENAI_API_KEY: "sk-x" } }));
  assert.deepEqual([key.state, key.via, key.signIn], ["found", "OPENAI_API_KEY", undefined]);
  assert.equal(probeAgentLogin("codex", deps({ env: { CODEX_API_KEY: "sk-x" } })).via, "CODEX_API_KEY");
  // The provider relays Codex's own sign-in when no key variable is set
  // (agent-sign-in.md §2.4): a ChatGPT sign-in or a saved key both work.
  const signedIn = probeAgentLogin("codex", deps({ files: ["/home/u/.codex/auth.json"] }));
  assert.deepEqual([signedIn.state, signedIn.via, signedIn.signIn], ["found", "/home/u/.codex/auth.json", true]);
  const moved = probeAgentLogin("codex", deps({ env: { CODEX_HOME: "/ch" }, files: ["/ch/auth.json"] }));
  assert.deepEqual([moved.state, moved.via, moved.signIn], ["found", "/ch/auth.json", true]);
  // A key variable wins over the file: the provider then reads the key.
  const both = probeAgentLogin("codex", deps({ env: { CODEX_API_KEY: "sk-x" }, files: ["/home/u/.codex/auth.json"] }));
  assert.deepEqual([both.state, both.via, both.signIn], ["found", "CODEX_API_KEY", undefined]);
  assert.equal(probeAgentLogin("codex", deps({ platform: "darwin" })).state, "missing", "codex keeps a file on macOS too");
});

test("codexKeyRefusal: only a model session with neither a key nor a sign-in is refused; never a value", () => {
  const signedIn = deps({ files: ["/home/u/.codex/auth.json"] });
  const modelRuns = [["codex"], ["codex", "exec", "hi"], ["codex", "-m", "gpt-5.4", "hi"], ["/opt/bin/codex", "e", "hi"],
    ["codex", "review"], ["codex", "resume", "--last"], ["codex", "exec", "resume", "--last"], ["codex", "fork"], ["codex", "--", "--help"]];
  for (const argv of modelRuns) {
    // A sign-in launches: the model proxy relays it.
    assert.equal(codexKeyRefusal("codex", argv, signedIn), null, `signed in: ${argv.join(" ")}`);
    const r = codexKeyRefusal("codex", argv, deps());
    assert.ok(r, `refused: ${argv.join(" ")}`);
    assert.match(r!, /^mandu: refusing to start Codex: it has no sign-in and no OpenAI API key/);
    assert.match(r!, /run `codex login`/);
    assert.match(r!, /CODEX_API_KEY/);
    assert.equal(r!.split("\n").length, 1, "one line");
  }

  // A key variable: launches. Its value never reaches a message.
  assert.equal(codexKeyRefusal("codex", ["codex", "exec", "hi"], deps({ env: { OPENAI_API_KEY: "sk-SECRET" }, files: ["/home/u/.codex/auth.json"] })), null);
  assert.equal(codexKeyRefusal("codex", ["codex"], deps({ env: { CODEX_API_KEY: "sk-SECRET" } })), null);

  // The user's own server (MANDU_OPENAI_BASE_URL): only a key variable
  // works, and a sign-in is never sent there.
  const own = { ownServer: true };
  assert.equal(codexKeyRefusal("codex", ["codex", "exec", "hi"], deps({ env: { OPENAI_API_KEY: "sk-SECRET" } }), own), null);
  const ownSigned = codexKeyRefusal("codex", ["codex", "exec", "hi"], signedIn, own);
  assert.match(ownSigned!, /^mandu: refusing to start Codex: MANDU_OPENAI_BASE_URL points it at your own model server/);
  assert.match(ownSigned!, /sign-in, \/home\/u\/\.codex\/auth\.json, is never sent to another server/);
  assert.match(codexKeyRefusal("codex", ["codex", "exec", "hi"], deps(), own)!, /neither is set\. Set the key/);
  for (const r of [ownSigned, codexKeyRefusal("codex", ["codex"], deps())]) assert.ok(!r!.includes("sk-SECRET"));

  // Commands that run no model turn, wrappers and other agents: never refused.
  const noModel = [["codex", "login"], ["codex", "logout"], ["codex", "mcp", "list"], ["codex", "--version"], ["codex", "-V"],
    ["codex", "--help"], ["codex", "exec", "--help"], ["codex", "exec", "hi", "-h"], ["codex", "completion", "bash"],
    ["codex", "app-server"], ["codex", "-c", "model=x", "features", "list"]];
  for (const argv of noModel) {
    assert.equal(codexKeyRefusal("codex", argv, deps()), null, argv.join(" "));
    assert.equal(codexKeyRefusal("codex", argv, deps(), own), null, argv.join(" "));
  }
  assert.equal(codexKeyRefusal("codex", ["/work/my-codex-wrapper.sh", "exec", "hi"], deps()), null, "a --target codex wrapper");
  assert.equal(codexKeyRefusal("claude", ["claude"], deps()), null);
  assert.equal(codexKeyRefusal("shell", ["bash"], deps()), null);
});

test("the probe only ever asks whether a path EXISTS", () => {
  const asked: string[] = [];
  probeAgentLogin("claude", deps({ fileExists: (p) => { asked.push(p); return false; } }));
  probeAgentLogin("codex", deps({ fileExists: (p) => { asked.push(p); return false; } }));
  assert.deepEqual(asked, ["/home/u/.claude/.credentials.json", "/home/u/.codex/auth.json"]);
});

test("loginAgentOf: only a real claude / codex / goose binary under its own target is probed", () => {
  assert.equal(loginAgentOf("goose", ["/usr/local/bin/goose", "session"]), "goose");
  assert.equal(loginAgentOf("goose", ["my-goose.sh", "session"]), null, "a --target goose wrapper");
  assert.equal(loginAgentOf("claude", ["claude"]), "claude");
  assert.equal(loginAgentOf("claude", ["/usr/local/bin/claude", "-p", "hi"]), "claude");
  assert.equal(loginAgentOf("codex", ["codex", "exec"]), "codex");
  assert.equal(loginAgentOf("claude", ["bash", "-c", "claude"]), null, "the live oracles' bash stand-in");
  assert.equal(loginAgentOf("shell", ["bash"]), null);
  assert.equal(loginAgentOf("openclaw", ["openclaw"]), null);
});

test("launchLoginNote: one plain WARNING line when missing; silent when found, unknown, or the launch IS a login", () => {
  const note = launchLoginNote("claude", ["claude"], deps());
  assert.ok(note);
  assert.match(note!, /^mandu: WARNING — no Claude Code login found/);
  assert.match(note!, /claude \/login/);
  assert.equal(note!.split("\n").length, 1, "one line");
  assert.match(launchLoginNote("codex", ["codex"], deps())!, /no Codex login found.*CODEX_API_KEY/);
  // Signed in to Codex itself: a usable login, so no line.
  assert.equal(launchLoginNote("codex", ["codex"], deps({ files: ["/home/u/.codex/auth.json"] })), null);

  assert.equal(launchLoginNote("claude", ["claude"], deps({ env: { ANTHROPIC_API_KEY: "k" } })), null);
  assert.equal(launchLoginNote("claude", ["claude"], deps({ platform: "darwin" })), null, "unknown is not a warning");
  assert.equal(launchLoginNote("codex", ["codex", "login"], deps()), null, "`codex login` is the fix itself");
  assert.equal(launchLoginNote("claude", ["claude", "/login"], deps()), null);
  assert.equal(launchLoginNote("claude", ["claude", "setup-token"], deps()), null);
  assert.equal(launchLoginNote("shell", ["bash"], deps()), null);
});

// ── Goose (supported-agents.md §5.6.1) ──────────────────────────────────────

test("goose: ANTHROPIC_API_KEY, then Goose's own secrets.yaml (where GOOSE_PATH_ROOT / XDG_CONFIG_HOME put it), named by NAME or PATH only", () => {
  const key = probeAgentLogin("goose", deps({ env: { ANTHROPIC_API_KEY: "sk-ant-SECRETVALUE" } }));
  assert.deepEqual([key.state, key.via], ["found", "ANTHROPIC_API_KEY"]);
  assert.doesNotMatch(JSON.stringify(key), /SECRETVALUE/);
  const file = probeAgentLogin("goose", deps({ files: ["/home/u/.config/goose/secrets.yaml"] }));
  assert.deepEqual([file.state, file.via, file.keyring], ["found", "/home/u/.config/goose/secrets.yaml", undefined]);
  assert.equal(probeAgentLogin("goose", deps({ env: { XDG_CONFIG_HOME: "/x" }, files: ["/x/goose/secrets.yaml"] })).via, "/x/goose/secrets.yaml");
  assert.equal(probeAgentLogin("goose", deps({ env: { GOOSE_PATH_ROOT: "/g" }, files: ["/g/config/secrets.yaml"] })).via, "/g/config/secrets.yaml");
  assert.equal(gooseSecretsFile({ HOME: "/home/u" }), "/home/u/.config/goose/secrets.yaml");
  assert.match(GOOSE_LOGIN_HOWTO, /ANTHROPIC_API_KEY/);
  assert.match(GOOSE_LOGIN_HOWTO, /GOOSE_DISABLE_KEYRING=1 goose configure/);
});

test("goose: with no variable and no file, the keyring decides: off → missing; asked → found / missing; not asked → unknown", () => {
  // Off by env (any value, as Goose reads it) or by config.yaml.
  assert.equal(probeAgentLogin("goose", deps({ env: { GOOSE_DISABLE_KEYRING: "" } })).state, "missing");
  const cfg = (text: string): LoginProbeDeps => ({ ...deps(), readGooseConfig: (p) => (p === "/home/u/.config/goose/config.yaml" ? text : null) });
  assert.equal(probeAgentLogin("goose", cfg("GOOSE_PROVIDER: anthropic\nGOOSE_DISABLE_KEYRING: true\n")).state, "missing");
  assert.equal(probeAgentLogin("goose", cfg("GOOSE_DISABLE_KEYRING: \"1\"\n")).state, "missing");
  assert.equal(gooseKeyringDisabled({ HOME: "/h" }, () => "GOOSE_DISABLE_KEYRING: false\n"), false);
  // On: the keyring item (existence only).
  const asked: Array<Record<string, string>> = [];
  const found = probeAgentLogin("goose", { ...deps(), keyringItem: (a) => { asked.push({ ...a }); return true; } });
  assert.deepEqual([found.state, found.via, found.keyring], ["found", "the system keyring", true]);
  assert.deepEqual(asked, [{ service: "goose", username: "secrets" }]);
  assert.deepEqual(GOOSE_KEYRING_ATTRS, { service: "goose", username: "secrets" });
  assert.equal(probeAgentLogin("goose", { ...deps(), keyringItem: () => false }).state, "missing");
  const unknown = probeAgentLogin("goose", { ...deps(), keyringItem: () => null });
  assert.deepEqual([unknown.state, unknown.keyring], ["unknown", true]);
  const notAsked = probeAgentLogin("goose", deps());
  assert.deepEqual([notAsked.state, notAsked.keyring], ["unknown", true], "no keyring dep: not asked");
  assert.equal(probeAgentLogin("goose", { ...deps({ platform: "win32" }), keyringItem: (): boolean => { throw new Error("asked"); } }).state, "unknown", "Windows: not asked");
  // A file outranks the keyring question (Goose falls back to it), and the keyring is never asked then.
  const withFile = { ...deps({ files: ["/home/u/.config/goose/secrets.yaml"] }), keyringItem: (): boolean => { throw new Error("asked"); } };
  assert.equal(probeAgentLogin("goose", withFile).state, "found");
});

test("goose launch lines: the early 'no login' line when nothing can log in; the keyring line (guarded launch) when only the keyring could", () => {
  const none = deps({ env: { GOOSE_DISABLE_KEYRING: "1" } });
  const note = launchLoginNote("goose", ["goose", "session"], none);
  assert.match(note!, /^mandu: WARNING — no Goose login found on this machine; to log in, set ANTHROPIC_API_KEY, or run `GOOSE_DISABLE_KEYRING=1 goose configure`/);
  assert.equal(note!.split("\n").length, 1);
  assert.match(launchLoginNote("goose", ["/opt/bin/goose", "run", "-t", "hi"], none)!, /no Goose login found/);
  assert.match(launchLoginNote("goose", ["goose", "review"], none)!, /no Goose login found/, "review's checks are goose run children");
  for (const argv of [["goose", "--version"], ["goose", "run", "--help"], ["goose", "configure"], ["goose-wrapper.sh", "session"]]) {
    assert.equal(launchLoginNote("goose", argv, none), null, argv.join(" "));
  }
  // Keyring on and nothing else: the early line stays quiet (the keyring may hold it) ...
  assert.equal(launchLoginNote("goose", ["goose", "session"], deps()), null);
  // ... and the guarded launch's line says it is out of reach, with both fixes.
  const kr = gooseKeyringNote("goose", ["goose", "session"], { ...deps(), keyringItem: () => false });
  assert.match(kr!, /^mandu: WARNING — Goose would read its key from the system keyring, which mandu keeps the agent from reaching/);
  assert.match(kr!, /Configuration value not found: ANTHROPIC_API_KEY/);
  assert.match(kr!, /ANTHROPIC_API_KEY, or run `GOOSE_DISABLE_KEYRING=1 goose configure`/);
  assert.equal(kr!.split("\n").length, 1);
  // Not when a variable, a file or a keyring-off setting decides; not on macOS; not for help.
  assert.equal(gooseKeyringNote("goose", ["goose", "session"], deps({ env: { ANTHROPIC_API_KEY: "k" } })), null);
  assert.equal(gooseKeyringNote("goose", ["goose", "session"], deps({ files: ["/home/u/.config/goose/secrets.yaml"] })), null);
  assert.equal(gooseKeyringNote("goose", ["goose", "session"], none), null);
  assert.equal(gooseKeyringNote("goose", ["goose", "session"], deps({ platform: "darwin" })), null);
  assert.equal(gooseKeyringNote("goose", ["goose", "--help"], deps()), null);
  assert.equal(gooseKeyringNote("claude", ["claude"], deps()), null);
});

test("goose on the openai provider (gooseRoutePlan): OPENAI_API_KEY is the variable, by env, config or --provider", () => {
  const none = { GOOSE_DISABLE_KEYRING: "1" };
  assert.equal(gooseKeyVar(undefined, { HOME: "/home/u" }), "ANTHROPIC_API_KEY");
  assert.equal(gooseKeyVar(undefined, { HOME: "/home/u", GOOSE_PROVIDER: "openai" }), "OPENAI_API_KEY");
  assert.equal(gooseKeyVar(undefined, { HOME: "/home/u" }, () => "GOOSE_PROVIDER: openai\n"), "OPENAI_API_KEY");
  assert.equal(gooseKeyVar(["goose", "run", "--provider", "openai", "-t", "hi"], { HOME: "/home/u" }), "OPENAI_API_KEY");
  assert.equal(gooseKeyVar(undefined, { HOME: "/home/u", GOOSE_PROVIDER: "groq" }), "ANTHROPIC_API_KEY", "a refused provider: the default");
  // the routed Chat Completions providers name their own key; ollama takes none
  assert.equal(gooseKeyVar(undefined, { HOME: "/home/u", GOOSE_PROVIDER: "openrouter" }), "OPENROUTER_API_KEY");
  assert.equal(gooseKeyVar(["goose", "run", "--provider", "xai", "-t", "hi"], { HOME: "/home/u" }), "XAI_API_KEY");
  assert.equal(gooseKeyVar(undefined, { HOME: "/home/u", GOOSE_PROVIDER: "ollama" }), null);
  assert.deepEqual(probeAgentLogin("goose", deps({ env: { GOOSE_DISABLE_KEYRING: "1", GOOSE_PROVIDER: "ollama" } })).state, "found", "no key to find");
  assert.match(probeAgentLogin("goose", deps({ env: { GOOSE_DISABLE_KEYRING: "1", GOOSE_PROVIDER: "tetrate" } })).howTo, /^set TETRATE_API_KEY/);
  // subagents on ollama: nothing to find, no warning for them
  const subOllama = probeAgentLogin("goose", deps({ env: { GOOSE_DISABLE_KEYRING: "1", ANTHROPIC_API_KEY: "k", GOOSE_SUBAGENT_PROVIDER: "ollama" } }));
  assert.deepEqual([subOllama.state, subOllama.subagent?.state, subOllama.subagent?.keyVar], ["found", "found", null]);
  assert.equal(launchLoginNote("goose", ["goose", "session"], deps({ env: { GOOSE_DISABLE_KEYRING: "1", ANTHROPIC_API_KEY: "k", GOOSE_SUBAGENT_PROVIDER: "ollama" } })), null);
  const found = probeAgentLogin("goose", deps({ env: { GOOSE_PROVIDER: "openai", OPENAI_API_KEY: "sk-SECRETVALUE" } }));
  assert.deepEqual([found.state, found.via], ["found", "OPENAI_API_KEY"]);
  // ANTHROPIC_API_KEY is not Goose's openai login.
  const wrong = probeAgentLogin("goose", deps({ env: { ...none, GOOSE_PROVIDER: "openai", ANTHROPIC_API_KEY: "k" } }));
  assert.equal(wrong.state, "missing");
  assert.match(wrong.howTo, /^set OPENAI_API_KEY, or run `GOOSE_DISABLE_KEYRING=1 goose configure`/);
  // The launch reads the argv's --provider.
  assert.match(launchLoginNote("goose", ["goose", "session", "--provider", "openai"], deps({ env: { ...none, ANTHROPIC_API_KEY: "k" } }))!, /set OPENAI_API_KEY/);
  assert.equal(launchLoginNote("goose", ["goose", "session", "--provider", "openai"], deps({ env: { ...none, OPENAI_API_KEY: "k" } })), null);
  const kr = gooseKeyringNote("goose", ["goose", "session"], deps({ env: { GOOSE_PROVIDER: "openai" } }));
  assert.match(kr!, /Configuration value not found: OPENAI_API_KEY"; to fix it, set OPENAI_API_KEY/);
  assert.equal(gooseKeyringNote("goose", ["goose", "session"], deps({ env: { GOOSE_PROVIDER: "openai", OPENAI_API_KEY: "k" } })), null);
});

test("agentOwnCredentialFiles: Goose's secrets.yaml under `mandu goose` only (wrapper included); none for the other agents", () => {
  assert.deepEqual(agentOwnCredentialFiles("goose", { HOME: "/home/u" }), ["/home/u/.config/goose/secrets.yaml"]);
  assert.deepEqual(agentOwnCredentialFiles("goose", { HOME: "/home/u", GOOSE_PATH_ROOT: "/g" }), ["/g/config/secrets.yaml"]);
  for (const t of ["claude", "codex", "opencode", "openclaw", "shell"]) assert.deepEqual(agentOwnCredentialFiles(t, { HOME: "/home/u" }), [], t);
});

test("launchLoginKeying: the launched agent, plus the AI helper's CLI when it runs one in the agent's world (CLI mode, helper on)", () => {
  const cli = (binary: string) => ({ mode: "cli" as const, binary });
  assert.deepEqual(launchLoginKeying({ target: "claude", writeMcp: true, ullm: cli("claude") }), { target: "claude", ullmBinary: "claude" });
  assert.deepEqual(launchLoginKeying({ target: "codex", writeMcp: true, ullm: cli("codex") }), { target: "codex", ullmBinary: "codex" });
  assert.deepEqual(launchLoginKeying({ target: "goose", writeMcp: true, ullm: cli("claude") }), { target: "goose", ullmBinary: "claude" },
    "Goose's helper runs `claude -p` in Goose's world: Claude Code's login stays raw there");
  assert.deepEqual(launchLoginKeying({ target: "goose", writeMcp: true, ullm: { mode: "api" } }), { target: "goose" }, "API mode runs no CLI");
  assert.deepEqual(launchLoginKeying({ target: "opencode", writeMcp: false, ullm: cli("claude") }), { target: "opencode" }, "--no-mcp: no helper");
  assert.deepEqual(launchLoginKeying({ target: "shell", writeMcp: true, ullm: { mode: "cli" } }), { target: "shell", ullmBinary: "claude" }, "the helper's default CLI");
});

test("otherAgentLoginsRaw: `raw` (any case) opts out; unset and `twin` keep the placeholder copy; another value warns and keeps it", () => {
  const warned: string[] = [];
  assert.equal(otherAgentLoginsRaw({ MANDU_OTHER_AGENT_LOGINS: "raw" }), true);
  assert.equal(otherAgentLoginsRaw({ MANDU_OTHER_AGENT_LOGINS: " RAW " }), true);
  assert.equal(otherAgentLoginsRaw({}), false);
  assert.equal(otherAgentLoginsRaw({ MANDU_OTHER_AGENT_LOGINS: "twin" }, (m) => warned.push(m)), false);
  assert.equal(warned.length, 0);
  assert.equal(otherAgentLoginsRaw({ MANDU_OTHER_AGENT_LOGINS: "1" }, (m) => warned.push(m)), false, "fails toward the placeholder copy");
  assert.equal(warned.length, 1);
  assert.match(warned[0]!, /MANDU_OTHER_AGENT_LOGINS=1 is not `raw` or `twin`/);
});

test("the keyring question is SearchItems (object paths only, never a secret), read as found / none / cannot tell", () => {
  const argv = keyringSearchArgv(GOOSE_KEYRING_ATTRS);
  assert.equal(argv[0], "dbus-send");
  assert.ok(argv.includes("org.freedesktop.Secret.Service.SearchItems"));
  assert.ok(argv.includes("dict:string:string:service,goose,username,secrets"));
  assert.ok(!argv.some((a) => /GetSecret|Unlock/.test(a)), "never reads or unlocks");
  const reply = (paths: string[], locked: string[]): string =>
    `method return time=1 sender=:1.2 -> destination=:1.3 serial=4 reply_serial=2\n   array [\n${paths.map((p) => `      object path "${p}"\n`).join("")}   ]\n` +
    `   array [\n${locked.map((p) => `      object path "${p}"\n`).join("")}   ]\n`;
  assert.equal(readKeyringSearch({ status: 0, stdout: reply(["/org/freedesktop/secrets/collection/login/1"], []), stderr: "" }), true);
  assert.equal(readKeyringSearch({ status: 0, stdout: reply([], ["/org/freedesktop/secrets/collection/login/7"]), stderr: "" }), true, "a locked item exists too");
  assert.equal(readKeyringSearch({ status: 0, stdout: reply([], []), stderr: "" }), false);
  assert.equal(
    readKeyringSearch({ status: 1, stdout: "", stderr: "Error org.freedesktop.DBus.Error.ServiceUnknown: The name org.freedesktop.secrets was not provided by any .service files" }),
    false, "no Secret Service: no keyring login",
  );
  assert.equal(readKeyringSearch({ status: 1, stdout: "", stderr: "Failed to open connection to \"session\" message bus: Unable to autolaunch" }), null);
});

// ── Goose's subagent provider (GOOSE_SUBAGENT_PROVIDER; supported-agents.md §5.6.1) ──

test("gooseKeyVars: the subagents' key variable follows GOOSE_SUBAGENT_PROVIDER (env, then config.yaml), else the session's", () => {
  assert.deepEqual(gooseKeyVars(undefined, { HOME: "/home/u" }), { main: "ANTHROPIC_API_KEY", sub: "ANTHROPIC_API_KEY", subProvider: "anthropic" });
  assert.deepEqual(gooseKeyVars(undefined, { HOME: "/home/u", GOOSE_SUBAGENT_PROVIDER: "openai" }), { main: "ANTHROPIC_API_KEY", sub: "OPENAI_API_KEY", subProvider: "openai" });
  assert.equal(gooseKeyVars(undefined, { HOME: "/home/u" }, () => "GOOSE_SUBAGENT_PROVIDER: openai\n").sub, "OPENAI_API_KEY");
  assert.deepEqual(
    gooseKeyVars(["goose", "run", "--provider", "openai", "-t", "hi"], { HOME: "/home/u" }),
    { main: "OPENAI_API_KEY", sub: "OPENAI_API_KEY", subProvider: "openai" },
    "the session's provider when none is named",
  );
  assert.deepEqual(
    gooseKeyVars(undefined, { HOME: "/home/u", GOOSE_PROVIDER: "openai", GOOSE_SUBAGENT_PROVIDER: "anthropic" }),
    { main: "OPENAI_API_KEY", sub: "ANTHROPIC_API_KEY", subProvider: "anthropic" },
  );
  assert.equal(gooseKeyVar(undefined, { HOME: "/home/u", GOOSE_SUBAGENT_PROVIDER: "openai" }), "ANTHROPIC_API_KEY", "gooseKeyVar stays the session's");
});

test("goose subagents: their own key variable is checked like the session's (variable, file, keyring), by NAME or PATH only", () => {
  const sub = { GOOSE_SUBAGENT_PROVIDER: "openai" };
  // The same provider: no subagent entry at all.
  assert.equal(probeAgentLogin("goose", deps({ env: { ANTHROPIC_API_KEY: "k" } })).subagent, undefined);
  // The session's variable set, the subagents' not, keyring off: the session found, the subagents missing.
  const s = probeAgentLogin("goose", deps({ env: { ...sub, ANTHROPIC_API_KEY: "sk-ant-SECRETVALUE", GOOSE_DISABLE_KEYRING: "1" } }));
  assert.deepEqual([s.state, s.via], ["found", "ANTHROPIC_API_KEY"]);
  assert.deepEqual([s.subagent?.provider, s.subagent?.keyVar, s.subagent?.state], ["openai", "OPENAI_API_KEY", "missing"]);
  assert.match(s.subagent!.howTo, /^set OPENAI_API_KEY, or run `GOOSE_DISABLE_KEYRING=1 goose configure`/);
  assert.doesNotMatch(JSON.stringify(s), /SECRETVALUE/);
  // Both variables set: both found.
  const both = probeAgentLogin("goose", deps({ env: { ...sub, ANTHROPIC_API_KEY: "k", OPENAI_API_KEY: "sk-SECRETVALUE" } }));
  assert.deepEqual([both.subagent?.state, both.subagent?.via], ["found", "OPENAI_API_KEY"]);
  assert.doesNotMatch(JSON.stringify(both), /SECRETVALUE/);
  // The file serves both (existence only: which keys it holds is not read).
  const file = probeAgentLogin("goose", deps({ env: { ...sub, ANTHROPIC_API_KEY: "k" }, files: ["/home/u/.config/goose/secrets.yaml"] }));
  assert.deepEqual([file.subagent?.state, file.subagent?.via], ["found", "/home/u/.config/goose/secrets.yaml"]);
  // The keyring: asked ONCE for both (one item holds every secret).
  let calls = 0;
  const kr = probeAgentLogin("goose", { ...deps({ env: sub }), keyringItem: () => { calls++; return true; } });
  assert.equal(calls, 1);
  assert.deepEqual([kr.state, kr.keyring, kr.subagent?.state, kr.subagent?.keyring], ["found", true, "found", true]);
  const krNot = probeAgentLogin("goose", deps({ env: { ...sub, ANTHROPIC_API_KEY: "k" } }));
  assert.deepEqual([krNot.subagent?.state, krNot.subagent?.keyring], ["unknown", true], "not asked: may be in the keyring");
});

test("goose subagents, launch lines: the early line and the keyring line name the subagents' variable", () => {
  const sub = { GOOSE_SUBAGENT_PROVIDER: "openai" };
  // The session logs in, the subagents cannot.
  const note = launchLoginNote("goose", ["goose", "session"], deps({ env: { ...sub, ANTHROPIC_API_KEY: "k", GOOSE_DISABLE_KEYRING: "1" } }));
  assert.match(note!, /^mandu: WARNING — no login found for Goose's subagents, which GOOSE_SUBAGENT_PROVIDER puts on openai, so a subagent would stop with "Configuration value not found: OPENAI_API_KEY"; to log in, set OPENAI_API_KEY/);
  assert.equal(note!.split("\n").length, 1);
  assert.equal(launchLoginNote("goose", ["goose", "session"], deps({ env: { ...sub, ANTHROPIC_API_KEY: "k", OPENAI_API_KEY: "k2" } })), null);
  assert.equal(launchLoginNote("goose", ["goose", "session"], deps({ env: { ...sub, ANTHROPIC_API_KEY: "k" }, files: ["/home/u/.config/goose/secrets.yaml"] })), null);
  assert.equal(launchLoginNote("goose", ["goose", "session"], deps({ env: { ...sub, ANTHROPIC_API_KEY: "k" } })), null, "keyring on: the early line stays quiet");
  // Neither can: one line naming both variables.
  const none = launchLoginNote("goose", ["goose", "session"], deps({ env: { ...sub, GOOSE_DISABLE_KEYRING: "1" } }));
  assert.match(none!, /no Goose login found on this machine; to log in, set ANTHROPIC_API_KEY, .* \(and OPENAI_API_KEY for its subagents, which GOOSE_SUBAGENT_PROVIDER puts on openai\)/);
  // The keyring line (guarded launch): the subagents alone ...
  const kr = gooseKeyringNote("goose", ["goose", "session"], deps({ env: { ...sub, ANTHROPIC_API_KEY: "k" } }));
  assert.match(kr!, /^mandu: WARNING — Goose's subagents, which GOOSE_SUBAGENT_PROVIDER puts on openai, would read their key from the system keyring/);
  assert.match(kr!, /Configuration value not found: OPENAI_API_KEY"; to fix it, set OPENAI_API_KEY/);
  // ... both (one line, both variables) ...
  const krBoth = gooseKeyringNote("goose", ["goose", "session"], deps({ env: sub }));
  assert.match(krBoth!, /Configuration value not found: ANTHROPIC_API_KEY".*\(and OPENAI_API_KEY for its subagents/);
  assert.equal(krBoth!.split("\n").length, 1);
  // ... and none once the subagents' variable is set.
  assert.equal(gooseKeyringNote("goose", ["goose", "session"], deps({ env: { ...sub, ANTHROPIC_API_KEY: "k", OPENAI_API_KEY: "k2" } })), null);
});

// ── The macOS Keychain (supported-agents.md §5.6.1) ─────────────────────────

test("goose on macOS: the login Keychain is asked like the Secret Service: found (reachable: no keyring flag) / missing / cannot tell", () => {
  const mac = (item: boolean | null, env: Record<string, string> = {}): ReturnType<typeof probeAgentLogin> =>
    probeAgentLogin("goose", { ...deps({ platform: "darwin", env }), keyringItem: () => item });
  const found = mac(true);
  assert.deepEqual([found.state, found.via, found.keyring], ["found", GOOSE_KEYCHAIN_VIA, undefined], "the Keychain stays reachable under mandu goose");
  assert.equal(mac(false).state, "missing");
  assert.deepEqual([mac(null).state, mac(null).keyring], ["unknown", true]);
  assert.equal(probeAgentLogin("goose", deps({ platform: "darwin" })).state, "unknown", "the launch never asks");
  // The keyring line is Linux's (the session bus): never on macOS.
  assert.equal(gooseKeyringNote("goose", ["goose", "session"], { ...deps({ platform: "darwin" }), keyringItem: () => true }), null);
  // The subagents share the Keychain's answer.
  assert.equal(mac(true, { GOOSE_SUBAGENT_PROVIDER: "openai" }).subagent?.via, GOOSE_KEYCHAIN_VIA);
});

test("the Keychain question is `security find-generic-password` WITHOUT -w or -g, by absolute path, read as found / none / cannot tell", () => {
  const argv = keychainSearchArgv(GOOSE_KEYRING_ATTRS);
  assert.deepEqual(argv, ["/usr/bin/security", "find-generic-password", "-s", "goose", "-a", "secrets"]);
  assert.ok(!argv.includes("-w") && !argv.includes("-g"), "NEVER prints the password");
  assert.equal(readKeychainSearch({ status: 0, stderr: "" }), true);
  assert.equal(readKeychainSearch({ status: 44, stderr: "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain." }), false);
  assert.equal(readKeychainSearch({ status: 1, stderr: "The specified item could not be found in the keychain." }), false);
  assert.equal(readKeychainSearch({ status: 51, stderr: "security: SecKeychainSearchCopyNext: User interaction is not allowed." }), null);
  assert.equal(readKeychainSearch({ status: null, stderr: "" }), null, "killed by the timeout");
});

test("realGooseKeyringItem (mocked runner): macOS runs the Keychain argv with a bare env; Linux the bus; elsewhere nothing", () => {
  const calls: Array<{ cmd: string; args: readonly string[]; env: Record<string, string> }> = [];
  const runner = (r: ReturnType<KeyringCommandRunner>): KeyringCommandRunner => (cmd, args, env) => { calls.push({ cmd, args, env }); return r; };
  const env = { HOME: "/Users/u", PATH: "/evil/bin:/usr/bin", ANTHROPIC_API_KEY: "sk-ant-SECRETVALUE", DBUS_SESSION_BUS_ADDRESS: "unix:path=/b" };
  // macOS.
  const ask = realGooseKeyringItem(env, { platform: "darwin", run: runner({ status: 0, stdout: "keychain: \"/Users/u/Library/Keychains/login.keychain-db\"\n", stderr: "" }) });
  assert.equal(ask(GOOSE_KEYRING_ATTRS), true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.cmd, "/usr/bin/security");
  assert.deepEqual(calls[0]!.args, ["find-generic-password", "-s", "goose", "-a", "secrets"]);
  assert.deepEqual(calls[0]!.env, { PATH: "/usr/bin:/bin", HOME: "/Users/u" }, "no key variable, no user PATH");
  assert.equal(realGooseKeyringItem(env, { platform: "darwin", run: runner({ status: 44, stdout: "", stderr: "could not be found in the keychain" }) })(GOOSE_KEYRING_ATTRS), false);
  const enoent = Object.assign(new Error("spawn /usr/bin/security ENOENT"), { code: "ENOENT" });
  assert.equal(realGooseKeyringItem(env, { platform: "darwin", run: runner({ status: null, stdout: "", stderr: "", error: enoent }) })(GOOSE_KEYRING_ATTRS), null);
  // Linux: the SearchItems argv on the user's bus.
  calls.length = 0;
  const linux = runner({ status: 0, stdout: 'array [\n object path "/org/freedesktop/secrets/collection/login/1"\n]\n', stderr: "" });
  assert.equal(realGooseKeyringItem(env, { platform: "linux", run: linux })(GOOSE_KEYRING_ATTRS), true);
  assert.equal(calls[0]!.cmd, "dbus-send");
  assert.deepEqual(calls[0]!.env, { PATH: "/evil/bin:/usr/bin", DBUS_SESSION_BUS_ADDRESS: "unix:path=/b" });
  calls.length = 0;
  assert.equal(realGooseKeyringItem({ HOME: "/h" }, { platform: "linux", run: linux })(GOOSE_KEYRING_ATTRS), null, "no bus address: not asked");
  assert.equal(realGooseKeyringItem(env, { platform: "win32", run: linux })(GOOSE_KEYRING_ATTRS), null);
  assert.equal(calls.length, 0);
});

test("sessionLogins: what the session's net-proxy is told (the walk's keying, the opt-out, HOME, the login variables only)", () => {
  const cli = (binary: string) => ({ mode: "cli" as const, binary });
  assert.deepEqual(sessionLogins({ target: "codex", writeMcp: true, ullm: cli("codex") }, { CODEX_HOME: "/srv/cx", OPENAI_API_KEY: "sk-x" }, "/home/u"),
    { home: "/home/u", target: "codex", ullmBinary: "codex", loginEnv: { CODEX_HOME: "/srv/cx" } });
  assert.deepEqual(sessionLogins({ target: "claude", writeMcp: false, ullm: cli("claude") }, { MANDU_OTHER_AGENT_LOGINS: "raw" }, "/h"),
    { home: "/h", target: "claude", otherLoginsRaw: true }, "--no-mcp: no helper CLI; the opt-out rides along");
  assert.deepEqual(sessionLogins({ target: "goose", ullm: { mode: "api" } }, { CODEX_HOME: "relative" }, "/h"), { home: "/h", target: "goose" });
  // The identity comparison: field order and extra fields do not matter, a
  // different session's logins (or none) do.
  const a = sessionLoginsKey({ home: "/h", target: "codex", ullmBinary: "codex", loginEnv: { XDG_DATA_HOME: "/x", CODEX_HOME: "/c" } });
  assert.equal(sessionLoginsKey({ loginEnv: { CODEX_HOME: "/c", XDG_DATA_HOME: "/x" }, ullmBinary: "codex", target: "codex", home: "/h", extra: 1 }), a);
  assert.notEqual(sessionLoginsKey({ home: "/h", target: "claude", ullmBinary: "claude" }), a);
  assert.notEqual(sessionLoginsKey({ home: "/h", target: "codex", ullmBinary: "codex", otherLoginsRaw: true, loginEnv: { XDG_DATA_HOME: "/x", CODEX_HOME: "/c" } }), a);
  assert.equal(sessionLoginsKey(undefined), "");
  assert.equal(sessionLoginsKey({ target: "codex" }), "");
  assert.deepEqual(loginEnvOf({ CLAUDE_CONFIG_DIR: "/c", CODEX_HOME: "rel", HOME: "/h" }), { CLAUDE_CONFIG_DIR: "/c" });
});

test("sessionLogins' mcpConfigs (secret-discovery.md §2.10): the project .mcp.json Claude Code reads where it runs, those that exist; part of the identity only when there are some", () => {
  const cli = (binary: string) => ({ mode: "cli" as const, binary });
  const exists = (p: string): boolean => p === "/w/human/.mcp.json" || p === "/w/agent/.mcp.json";
  assert.deepEqual(sessionMcpConfigs({ target: "claude", humanCwd: "/w/human", cwd: "/w/agent" }, exists), ["/w/human/.mcp.json", "/w/agent/.mcp.json"]);
  assert.deepEqual(sessionMcpConfigs({ target: "claude", humanCwd: "/w/human", cwd: "/w/human" }, exists), ["/w/human/.mcp.json"], "one directory, once");
  assert.deepEqual(sessionMcpConfigs({ target: "claude", humanCwd: "/w/none", cwd: "/w/none" }, exists), [], "no .mcp.json there: none");
  assert.deepEqual(sessionMcpConfigs({ target: "shell", humanCwd: "/w/human" }, exists), ["/w/human/.mcp.json"], "a plain command keeps Claude Code's");
  assert.deepEqual(sessionMcpConfigs({ target: "codex", humanCwd: "/w/human", cwd: "/w/agent" }, exists), [], "Codex does not read .mcp.json");
  assert.deepEqual(sessionMcpConfigs({ target: "claude", humanCwd: "relative" }, () => true), [], "absolute directories only");
  // OpenCode (2026-10-22): its opencode.json(c) in the session's
  // directories and each one above, up to the repository's top (OpenCode's
  // own lookup).
  const tree = new Set(["/r/opencode.json", "/r/.git", "/r/a/opencode.jsonc", "/r/a/b/.mcp.json", "/opencode.json"]);
  const inTree = (p: string): boolean => tree.has(p);
  assert.deepEqual(sessionMcpConfigs({ target: "opencode", humanCwd: "/r/a/b", cwd: "/r/a/b" }, inTree), ["/r/a/opencode.jsonc", "/r/opencode.json"], "up to the repository's top, never above it, never a .mcp.json");
  assert.deepEqual(sessionMcpConfigs({ target: "opencode", humanCwd: "/x/y" }, inTree), ["/opencode.json"], "no repository: up to /");
  assert.deepEqual(sessionMcpConfigs({ target: "claude", humanCwd: "/r/a" }, inTree), [], "Claude Code reads no opencode.json");
  assert.deepEqual(sessionMcpConfigs({ target: "goose", humanCwd: "/r/a" }, inTree), [], "Goose has no project config");
  assert.deepEqual(sessionLogins({ target: "claude", writeMcp: true, ullm: cli("claude"), humanCwd: "/w/human", cwd: "/w/human" }, {}, "/h", exists),
    { home: "/h", target: "claude", ullmBinary: "claude", mcpConfigs: ["/w/human/.mcp.json"] });
  const without = sessionLoginsKey({ home: "/h", target: "claude", ullmBinary: "claude" });
  assert.equal(without, JSON.stringify(["/h", "claude", "claude", false, []]), "no mcpConfigs: spelled as before, so an older proxy is adopted");
  assert.notEqual(sessionLoginsKey({ home: "/h", target: "claude", ullmBinary: "claude", mcpConfigs: ["/w/a/.mcp.json"] }), without);
  assert.equal(sessionLoginsKey({ home: "/h", target: "claude", ullmBinary: "claude", mcpConfigs: ["/b/.mcp.json", "/a/.mcp.json"] }),
    sessionLoginsKey({ home: "/h", target: "claude", ullmBinary: "claude", mcpConfigs: ["/a/.mcp.json", "/b/.mcp.json"] }), "order does not matter");
});

test("loginKeptWhere / agentDisplayName: one wording of the keep-raw rule and of the agents' names for `mandu why` and doctor", () => {
  assert.equal(loginKeptWhere("claude"),
    "mandu claude, a plain command (mandu -- <command>) and mandu openclaw, and mandu goose or mandu opencode while Mandu's AI helper runs claude (neither ANTHROPIC_API_KEY nor MANDU_ULLM_API_KEY set, and no --no-mcp)");
  assert.equal(loginKeptWhere("codex"), "mandu codex and mandu openclaw");
  assert.equal(loginKeptWhere("opencode"), "mandu opencode");
  assert.deepEqual(["claude", "codex", "opencode", "goose", "openclaw", "shell", "x"].map(agentDisplayName),
    ["Claude Code", "Codex", "OpenCode", "Goose", "OpenClaw", "a plain command", "x"]);
});
