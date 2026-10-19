import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync, symlinkSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  discoverSecretFiles,
  discoverSecretsReport,
  isAgentAuthPath,
  AGENT_STORES,
  AGENT_LOGIN_FILES,
  DARWIN_HOME_SKIP,
  darwinHomeSkipDirs,
  darwinPrune,
  discoveryPrunes,
  MAX_DEPTH,
  MAX_FILES,
  MAX_LABEL_FILES,
  MAX_SKIP_RECORDS,
  depthAreasOf,
  DEPTH_AREA_LEVELS,
  MAX_DEPTH_AREAS,
} from "../../policy/secret-discovery.js";
import { catalogPrefixesUnder, type LabelLookup } from "../../policy/secret-catalog.js";
import { SENSITIVE_PATHS } from "../../policy/fs-outbound.js";

/** A fake HOME with the shapes that matter. Returns { home, cleanup }. */
function fakeHome(): { home: string; cleanup: () => void } {
  // Canonical, like a real HOME (/home/u, /Users/u): discovery realpaths its
  // roots and install trees, and on darwin tmpdir() is a symlinked spelling
  // (/var/folders → /private/var/folders, /tmp → /private/tmp).
  const home = realpathSync(mkdtempSync(join(tmpdir(), "mandu-home-")));
  const put = (rel: string, body: string): void => {
    const p = join(home, rel);
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, body);
  };
  put(".ssh/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n");
  put(".ssh/config", "Host example\n");
  put(".aws/credentials", "[default]\naws_access_key_id=AKIA\n");
  put(".config/gcloud/creds.json", "{}");
  // agent's OWN auth — must NEVER be masked (it would brick the launch)
  put(".claude.json", '{"oauth":"real-token"}');
  put(".claude/settings.json", "{}");
  put(".codex/auth.json", "{}");
  // ordinary files
  put("notes.md", "hello");
  return { home, cleanup: () => rmSync(home, { recursive: true, force: true }) };
}

test("discovers catalog credential files under HOME", () => {
  const { home, cleanup } = fakeHome();
  try {
    const found = discoverSecretFiles([home], home).map((f) => f.path);
    assert.ok(found.includes(join(home, ".ssh/id_rsa")), "ssh key");
    assert.ok(found.includes(join(home, ".ssh/config")), "ssh dir is a catalog prefix");
    assert.ok(found.includes(join(home, ".aws/credentials")), "aws creds");
    assert.ok(found.includes(join(home, ".config/gcloud/creds.json")), "gcloud");
    assert.ok(!found.includes(join(home, "notes.md")), "ordinary file not masked");
  } finally {
    cleanup();
  }
});

test("THE FOOTGUN: the launched agent's own login and every agent's own data are NEVER discovered", () => {
  // Masking these makes the agent runtime unable to start — it reads them from
  // INSIDE the sandbox. Regression-guarded explicitly (plan decision 3). Since
  // 2026-10-09 the login files are keyed per launch (secret-discovery.md
  // §1.10): the launched agent's stay raw, another agent's are discovered
  // (agent-login-discovery.test.ts); a walk that names no launch keeps them all.
  const { home, cleanup } = fakeHome();
  try {
    const under = (target?: string): string[] => discoverSecretFiles([home], home, undefined, target === undefined ? {} : { target }).map((f) => f.path);
    const claude = under("claude");
    assert.ok(!claude.includes(join(home, ".claude.json")), "~/.claude.json must not be masked under mandu claude");
    assert.ok(!claude.some((p) => p.includes("/.claude/")), "~/.claude/* must not be masked under mandu claude");
    const codex = under("codex");
    assert.ok(!codex.some((p) => p.includes("/.codex/")), "~/.codex/* must not be masked under mandu codex");
    assert.ok(!codex.includes(join(home, ".claude", "settings.json")), "Claude Code's own data is not masked under mandu codex either");
    const none = under();
    assert.ok(!none.includes(join(home, ".claude.json")) && !none.some((p) => p.includes("/.claude/") || p.includes("/.codex/")),
      "a walk that names no launch masks no agent's login");
    // ...even though the fs-gate DOES (correctly) treat them as sensitive.
    assert.ok(AGENT_LOGIN_FILES.claude.includes("~/.claude.json"));
    assert.ok(AGENT_STORES.claude.includes("~/.claude"));
    assert.equal(isAgentAuthPath(join(home, ".claude/foo"), home), true);
    assert.equal(isAgentAuthPath(join(home, ".claude.json"), home), true, "a login file is an agent's own file to the walks that only prune");
    assert.equal(isAgentAuthPath(join(home, ".aws/credentials"), home), false);
  } finally {
    cleanup();
  }
});

test("Goose's own key file (~/.config/goose/secrets.yaml) IS discovered: a sensitive, no-model catalog path every agent but Goose gets twinned (supported-agents.md §5.6.1)", () => {
  const { home, cleanup } = fakeHome();
  try {
    const file = join(home, ".config/goose/secrets.yaml");
    mkdirSync(join(home, ".config/goose"), { recursive: true });
    writeFileSync(file, "ANTHROPIC_API_KEY: sk-ant-x\n");
    writeFileSync(join(home, ".config/goose/config.yaml"), "GOOSE_PROVIDER: anthropic\n");
    const found = discoverSecretFiles([home], home);
    const hit = found.find((f) => f.path === file);
    assert.ok(hit, "discovered: only `mandu goose` leaves it readable (the launcher's agentOwnFiles), per launch");
    assert.equal(hit!.level, "no-model");
    assert.equal(hit!.rule, "prefix:~/.config/goose/secrets.yaml");
    assert.ok(!found.some((f) => f.path.endsWith("/goose/config.yaml")), "Goose's config is not a secret");
    assert.equal(isAgentAuthPath(file, home), false, "not a global agent-auth exclusion, unlike ~/.claude");
    assert.ok(SENSITIVE_PATHS.includes("~/.config/goose/secrets.yaml"), "a tool's read of it asks (fs gate)");
  } finally {
    cleanup();
  }
});

test("discovers a workspace .env but not .env.example", () => {
  const ws = mkdtempSync(join(tmpdir(), "mandu-ws-"));
  const home = mkdtempSync(join(tmpdir(), "mandu-home2-"));
  try {
    writeFileSync(join(ws, ".env"), "API_KEY=AKIA-REAL");
    writeFileSync(join(ws, ".env.example"), "API_KEY=");
    mkdirSync(join(ws, "node_modules", "pkg"), { recursive: true });
    writeFileSync(join(ws, "node_modules", "pkg", ".env"), "SHOULD_NOT_BE_WALKED=1");

    const found = discoverSecretFiles([ws], home).map((f) => f.path);
    assert.ok(found.includes(join(ws, ".env")), "workspace .env is masked");
    assert.ok(!found.includes(join(ws, ".env.example")), "committed template is not");
    assert.ok(!found.some((p) => p.includes("node_modules")), "node_modules is not walked");
  } finally {
    rmSync(ws, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  }
});

test("unreadable files are skipped (masking them would be theater and the bind would fail)", () => {
  const home = mkdtempSync(join(tmpdir(), "mandu-home3-"));
  try {
    mkdirSync(join(home, ".aws"), { recursive: true });
    const p = join(home, ".aws", "credentials");
    writeFileSync(p, "secret");
    chmodSync(p, 0o000);
    const found = discoverSecretFiles([home], home).map((f) => f.path);
    // Running as root would still read it; skip the assertion in that case.
    if (process.getuid?.() !== 0) {
      assert.ok(!found.includes(p), "unreadable file is not masked");
    }
    chmodSync(p, 0o600); // so cleanup works
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("results are deterministic (sorted) and carry the matching rule", () => {
  const { home, cleanup } = fakeHome();
  try {
    const a = discoverSecretFiles([home], home);
    const b = discoverSecretFiles([home], home);
    assert.deepEqual(a.map((x) => x.path), b.map((x) => x.path), "stable order");
    assert.deepEqual([...a.map((x) => x.path)].sort(), a.map((x) => x.path), "sorted");
    for (const f of a) {
      assert.equal(f.level, "no-model");
      assert.ok(f.rule.length > 0);
    }
  } finally {
    cleanup();
  }
});

test("a missing root is ignored, not an error", () => {
  assert.deepEqual(discoverSecretFiles(["/nonexistent/path/xyz"], "/home/u"), []);
});

test("a SYMLINKED DIRECTORY is never descended (it points out of the root); a symlinked FILE still is a candidate", () => {
  // The 2026-09-05 bricked launch: `~/tools/linux → /mnt/…/linux` dragged a
  // kernel tree's `Documentation/security/credentials.rst` into the registry
  // via the `*credentials*` shape, and the twin bind over that spelling
  // failed under bwrap, refusing every launch fail-closed.
  const home = mkdtempSync(join(tmpdir(), "mandu-home4-"));
  const outside = mkdtempSync(join(tmpdir(), "mandu-outside-"));
  try {
    mkdirSync(join(outside, "Documentation", "security"), { recursive: true });
    writeFileSync(join(outside, "Documentation", "security", "credentials.rst"), "kernel doc\n");
    writeFileSync(join(outside, "real-key"), "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n");
    mkdirSync(join(home, "tools"), { recursive: true });
    symlinkSync(outside, join(home, "tools", "linux")); // directory link → not walked
    mkdirSync(join(home, ".ssh"), { recursive: true });
    symlinkSync(join(outside, "real-key"), join(home, ".ssh", "id_ed25519")); // file link → candidate
    symlinkSync(join(outside, "nope"), join(home, ".ssh", "dangling")); // dangling link → ignored

    const found = discoverSecretFiles([home], home).map((f) => f.path);
    assert.ok(!found.some((p) => p.includes("credentials.rst")), "a symlinked directory is not descended");
    assert.ok(found.includes(join(home, ".ssh", "id_ed25519")), "a symlinked secret FILE is discovered, under the path as seen");
    assert.ok(!found.includes(join(home, ".ssh", "dangling")), "a dangling link is not a file to mask");
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test("toolchain and editor caches are pruned from the walk; ~/.cargo is not", () => {
  const { home, cleanup } = fakeHome();
  try {
    // Shapes the catalog WOULD match, planted where the walk must not look.
    for (const dir of [".ccache", ".npm", ".nvm", ".rustup", ".vscode-server"]) {
      mkdirSync(join(home, dir, "deep"), { recursive: true });
      writeFileSync(join(home, dir, "deep", "credentials.json"), "{}");
    }
    // ... and one where it must: ~/.cargo/credentials.toml is a real secret.
    mkdirSync(join(home, ".cargo"), { recursive: true });
    writeFileSync(join(home, ".cargo", "credentials.toml"), "[registry]\ntoken = \"x\"\n");

    const found = discoverSecretFiles([home], home).map((f) => f.path);
    for (const dir of [".ccache", ".npm", ".nvm", ".rustup", ".vscode-server"]) {
      assert.ok(!found.some((p) => p.includes(`/${dir}/`)), `${dir} pruned: ${found.join(",")}`);
    }
    assert.ok(found.includes(join(home, ".cargo", "credentials.toml")), "~/.cargo still walked");
  } finally {
    cleanup();
  }
});

// ── macOS (2026-09-29): HOME's app-data and media folders are not walked ──

/** Catalog shapes planted inside each DARWIN_HOME_SKIP folder, at depth ≤ 4. */
function plantDarwinFolders(home: string): string[] {
  const planted: string[] = [];
  for (const dir of DARWIN_HOME_SKIP) {
    const p = join(home, dir, "Group Containers", "app", "credentials.json");
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, "{}");
    const env = join(home, dir, ".env");
    writeFileSync(env, "K=v\n");
    planted.push(p, env);
  }
  return planted;
}

test("darwin: ~/Library, ~/.Trash, ~/Pictures, ~/Music and ~/Movies are pruned from the HOME walk; Linux walks them as before", () => {
  const { home, cleanup } = fakeHome();
  try {
    const planted = plantDarwinFolders(home);
    const mac = discoverSecretFiles([home], home, undefined, { platform: "darwin" }).map((f) => f.path);
    for (const p of planted) assert.ok(!mac.includes(p), `pruned on darwin: ${p}`);
    assert.ok(mac.includes(join(home, ".aws/credentials")), "the rest of HOME is still walked");
    assert.ok(mac.includes(join(home, ".ssh/id_rsa")));
    const linux = discoverSecretFiles([home], home, undefined, { platform: "linux" }).map((f) => f.path);
    for (const p of planted) assert.ok(linux.includes(p), `walked on linux: ${p}`);
    // the prune is silent, like SKIP_DIRS: nothing in the ledger names them
    const r = discoverSecretsReport([home], home, undefined, { platform: "darwin" });
    assert.ok(!r.skipped.some((s) => DARWIN_HOME_SKIP.some((d) => s.path.startsWith(join(home, d)))));
  } finally {
    cleanup();
  }
});

test("darwin: only HOME's own folders are pruned: a project's Library/ is walked, and a workspace root inside ~/Library is walked as its own root", () => {
  const { home, cleanup } = fakeHome();
  try {
    const projEnv = join(home, "proj", "Library", ".env");
    mkdirSync(join(projEnv, ".."), { recursive: true });
    writeFileSync(projEnv, "K=v\n");
    const iCloud = join(home, "Library", "Mobile Documents", "proj");
    mkdirSync(iCloud, { recursive: true });
    writeFileSync(join(iCloud, ".env"), "K=v\n");
    const found = discoverSecretFiles([home, iCloud], home, undefined, { platform: "darwin" }).map((f) => f.path);
    assert.ok(found.includes(projEnv), "a project folder named Library is not HOME's");
    assert.ok(found.includes(join(iCloud, ".env")), "the workspace root is a root of its own");
  } finally {
    cleanup();
  }
});

test("darwin: every catalog path under a pruned folder is still visited (the SKIP_DIRS re-entry)", () => {
  const { home, cleanup } = fakeHome();
  try {
    const pinned = DARWIN_HOME_SKIP.flatMap((d) => catalogPrefixesUnder(join(home, d), home));
    for (const p of pinned) {
      mkdirSync(join(p, ".."), { recursive: true });
      writeFileSync(p, "secret\n");
    }
    const found = discoverSecretFiles([home], home, undefined, { platform: "darwin" }).map((f) => f.path);
    for (const p of pinned) assert.ok(found.includes(p), `catalog-pinned path under a pruned folder: ${p}`);
  } finally {
    cleanup();
  }
});

test("darwin: the prune never hides a LABELED file: a literal under a pruned folder is visited, a pattern or a folder label keeps it walked", () => {
  const { home, cleanup } = fakeHome();
  try {
    const labeled = join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
    mkdirSync(join(labeled, ".."), { recursive: true });
    writeFileSync(labeled, '{"mcpServers":{}}');
    const other = join(home, "Library", "Group Containers", "x", "credentials.json");
    mkdirSync(join(other, ".."), { recursive: true });
    writeFileSync(other, "{}");
    const lookup = (paths: string[]): LabelLookup => (p) => (paths.some((l) => p === l || p.startsWith(l + "/")) ? { level: "no-model", bindings: [], via: p } : null);
    // a literal label deep under ~/Library: visited, while the rest stays pruned
    const lit = discoverSecretFiles([home], home, lookup([labeled]), { platform: "darwin", labelPaths: [labeled] }).map((f) => f.path);
    assert.ok(lit.includes(labeled), "the labeled literal is visited");
    assert.ok(!lit.includes(other), "the rest of ~/Library stays pruned");
    // a pattern rooted inside ~/Library, or one that can match anywhere, keeps it walked
    for (const pattern of [join(home, "Library", "**", "credentials.json"), "**/credentials.json", join(home, "**", "x.json")]) {
      const pat = discoverSecretFiles([home], home, undefined, { platform: "darwin", labelPaths: [pattern] }).map((f) => f.path);
      assert.ok(pat.includes(other), `walked because of ${pattern}`);
    }
    // a label on the folder itself (via the lookup alone, no labelPaths): walked
    const dirLabel = discoverSecretFiles([home], home, lookup([join(home, "Library")]), { platform: "darwin" }).map((f) => f.path);
    assert.ok(dirLabel.includes(other) && dirLabel.includes(labeled));
  } finally {
    cleanup();
  }
});

test("darwinHomeSkipDirs: HOME's five folders by exact path on darwin, none elsewhere; discoveryPrunes exposes the same set for every HOME walk", () => {
  const mac = [...darwinHomeSkipDirs("/Users/u", "darwin")].sort();
  assert.deepEqual(mac, ["/Users/u/.Trash", "/Users/u/Library", "/Users/u/Movies", "/Users/u/Music", "/Users/u/Pictures"]);
  assert.deepEqual([...darwinHomeSkipDirs("/Users/u/", "darwin")].sort(), mac, "a trailing slash on HOME is the same HOME");
  assert.equal(darwinHomeSkipDirs("/home/u", "linux").size, 0, "Linux: nothing");
  assert.equal(darwinHomeSkipDirs("/home/u", "win32").size, 0);
  // The one source: discovery's prunes carry it for the other walks
  // (secret-workspace-scan.ts, known-repos.ts).
  const opts = { installEnv: {}, selfDir: null };
  assert.deepEqual([...discoveryPrunes("/Users/u", { ...opts, platform: "darwin" }).homeSkip].sort(), mac);
  assert.equal(discoveryPrunes("/home/u", { ...opts, platform: "linux" }).homeSkip.size, 0);
});

test("darwinPrune: pure decision over the label paths", () => {
  const L = "/Users/u/Library";
  assert.deepEqual(darwinPrune(L, undefined), { walk: false, visit: [] });
  assert.deepEqual(darwinPrune(L, ["/Users/u/.aws/credentials", "/Users/u/Libraryx/a"]), { walk: false, visit: [] }, "segment-aware");
  assert.deepEqual(darwinPrune(L, [`${L}/a/b.json`, `${L}/a/b.json`, `${L}/c/`]), { walk: false, visit: [`${L}/a/b.json`, `${L}/c`] });
  assert.deepEqual(darwinPrune(L, ["/Users/u"]), { walk: true }, "a label above the folder covers it");
  assert.deepEqual(darwinPrune(L, [L]), { walk: true });
  assert.deepEqual(darwinPrune(L, ["/Users/u/*.pem"]), { walk: true }, "a pattern rooted above may match inside");
  assert.deepEqual(darwinPrune(L, [`${L}/Containers/*/token`]), { walk: true });
  assert.deepEqual(darwinPrune(L, ["/Users/u/Documents/*.pem"]), { walk: false, visit: [] }, "a pattern elsewhere does not");
  assert.deepEqual(darwinPrune(L, ["*.pem"]), { walk: true }, "a relative pattern can match anywhere");
  assert.deepEqual(darwinPrune(L, undefined, (p) => (p === L ? { level: "no-model", bindings: [], via: L } : null)), { walk: true });
});

test("isAgentAuthPath: the exclude memo is keyed per HOME", () => {
  assert.equal(isAgentAuthPath("/home/u/.claude/settings.json", "/home/u"), true);
  assert.equal(isAgentAuthPath("/home/v/.claude/settings.json", "/home/v"), true);
  assert.equal(isAgentAuthPath("/home/v/.claude/settings.json", "/home/u"), false, "the other home's ~/.claude is not excluded");
  assert.equal(isAgentAuthPath("/home/u/.claude.json", "/home/v"), false);
});

// ── the "not covered" ledger (secret-discovery.md §1.3) ─────────────

test("report: the files equal discoverSecretFiles; agent-auth, symlinked dirs, dangling links and unreadable matches are named with a reason", () => {
  const { home, cleanup } = fakeHome();
  const outside = mkdtempSync(join(tmpdir(), "mandu-outside-"));
  try {
    mkdirSync(join(outside, "Documentation", "security"), { recursive: true });
    writeFileSync(join(outside, "Documentation", "security", "credentials.rst"), "kernel doc\n");
    symlinkSync(outside, join(home, "tools-linux"));                         // a directory link (the 2026-09-05 brick)
    symlinkSync(join(home, "nowhere"), join(home, ".aws", "config"));         // a dangling link named like a secret
    writeFileSync(join(home, ".ssh", "id_locked"), "-----BEGIN OPENSSH PRIVATE KEY-----\n");
    chmodSync(join(home, ".ssh", "id_locked"), 0o000);
    const r = discoverSecretsReport([home], home);
    assert.deepEqual(r.files, discoverSecretFiles([home], home), "the same files as the files-only view");
    assert.equal(r.truncated, false);
    assert.deepEqual(r.limits, { maxDepth: MAX_DEPTH, maxFiles: MAX_FILES, maxLabelFiles: MAX_LABEL_FILES });
    const by = (reason: string) => r.skipped.filter((s) => s.reason === reason).map((s) => s.path);
    // No launch named: every agent's login is kept (`agent-login`), each
    // store is skipped whole (`agent-auth`).
    assert.ok(by("agent-login").includes(join(home, ".claude.json")), "the agent's own login is in the ledger, never in files");
    assert.ok(by("agent-login").includes(join(home, ".codex", "auth.json")), "the login inside a store is judged on its own");
    assert.ok(by("agent-auth").includes(join(home, ".claude")) && by("agent-auth").includes(join(home, ".codex")), "each store is one record");
    assert.ok(r.counts["agent-auth"] >= 2, `agent-auth count ${r.counts["agent-auth"]}`);
    assert.deepEqual(by("symlinked-directory"), [join(home, "tools-linux")]);
    assert.deepEqual(by("dangling-symlink"), [join(home, ".aws", "config")]);
    if (process.getuid && process.getuid() !== 0) {
      assert.deepEqual(by("unreadable"), [join(home, ".ssh", "id_locked")]);
      assert.equal(r.counts["unreadable"], 1);
    }
    assert.ok(!r.files.some((f) => f.path.includes("credentials.rst")), "nothing behind the directory link was walked");
    // ordinary files and ordinary links are not in the ledger: it names candidates, not the whole HOME
    assert.ok(!r.skipped.some((s) => s.path.endsWith("notes.md")));
  } finally {
    chmodSync(join(home, ".ssh", "id_locked"), 0o600);
    rmSync(outside, { recursive: true, force: true });
    cleanup();
  }
});

test("report: a secret below MAX_DEPTH is not found and the directory is reported as `depth`", () => {
  const home = mkdtempSync(join(tmpdir(), "mandu-deep-"));
  try {
    const deep = join(home, "a", "b", "c", "d", "e"); // depth 5 under the root
    mkdirSync(deep, { recursive: true });
    writeFileSync(join(deep, ".env"), "KEY=1\n");
    const r = discoverSecretsReport([home], home);
    assert.equal(r.files.length, 0, "the depth cap leaves it raw — and the report must SAY so");
    assert.equal(r.counts["depth"], 1);
    assert.deepEqual(r.skipped.filter((s) => s.reason === "depth").map((s) => s.path), [deep]);
    assert.equal(r.truncated, false, "a depth skip is not a truncation of the walk");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("report: beyond MAX_FILES the walk is TRUNCATED, the matches it still saw are `count`, and the skip list is capped with complete counts", () => {
  const home = mkdtempSync(join(tmpdir(), "mandu-many-"));
  try {
    mkdirSync(join(home, ".ssh"));
    for (let i = 0; i < MAX_FILES + 30; i++) writeFileSync(join(home, ".ssh", `id_k${String(i).padStart(4, "0")}`), "-----BEGIN OPENSSH PRIVATE KEY-----\n");
    const r = discoverSecretsReport([home], home);
    assert.equal(r.files.length, MAX_FILES);
    assert.equal(r.truncated, true);
    assert.ok(r.counts["count"] >= 1, "at least one match beyond the cap was seen and recorded");
    assert.ok(r.skipped.length <= MAX_SKIP_RECORDS);
    // the same walk as before: files-only callers see exactly MAX_FILES
    assert.equal(discoverSecretFiles([home], home).length, MAX_FILES);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("report: the ledger never carries file CONTENTS, only paths and reasons", () => {
  const { home, cleanup } = fakeHome();
  try {
    const r = discoverSecretsReport([home], home);
    const text = JSON.stringify(r);
    assert.ok(!text.includes("AKIA"), "no secret bytes in the report");
    assert.ok(!text.includes("real-token"), "no agent-auth bytes in the report");
  } finally {
    cleanup();
  }
});

test("a symlink LOOP named like a secret (a → b → a) is a dangling link, never an ELOOP out of the walk", () => {
  const { home, cleanup } = fakeHome();
  try {
    symlinkSync(join(home, ".ssh", "id_b"), join(home, ".ssh", "id_a"));
    symlinkSync(join(home, ".ssh", "id_a"), join(home, ".ssh", "id_b"));
    mkdirSync(join(home, "loop"));
    symlinkSync(join(home, "loop"), join(home, "loop", "self"));
    const r = discoverSecretsReport([home, join(home, ".ssh", "id_a")], home);
    assert.ok(r.files.some((f) => f.path.endsWith("/.ssh/id_rsa")), "the real key beside the loop is still found");
    assert.ok(!r.files.some((f) => /id_[ab]$/.test(f.path)));
    assert.deepEqual(r.skipped.filter((s) => s.reason === "dangling-symlink").map((s) => s.path).sort(), [join(home, ".ssh", "id_a"), join(home, ".ssh", "id_b")]);
  } finally {
    cleanup();
  }
});

// ── Mandu's own state + the view map (secret-discovery.md §1.9) ──
import { agentViewRoots, defaultStateBase, AGENTVIEW_CONTENT_CAP } from "../../policy/secret-discovery.js";

/** A fake fs-sync state base: `<base>/workspaces/<id>/{workspace.json,agentview/}`
 *  plus the arbiter's DB and a shadow repo deep enough to trip the depth cap. */
function fakeStateBase(base: string, entries: Array<{ id: string; workspacePath?: string; meta?: string; agentview?: Record<string, string> | "symlink" | "none" }>): void {
  mkdirSync(join(base, "workspaces"), { recursive: true });
  writeFileSync(join(base, "mandu.db"), "sqlite bytes");
  for (const e of entries) {
    const dir = join(base, "workspaces", e.id);
    mkdirSync(dir, { recursive: true });
    if (e.meta !== undefined) writeFileSync(join(dir, "workspace.json"), e.meta);
    else if (e.workspacePath !== undefined) writeFileSync(join(dir, "workspace.json"), JSON.stringify({ schemaVersion: 1, workspacePath: e.workspacePath, workspaceId: e.id }));
    // the shadow repo: objects five levels down — the `depth` records the old walk flooded the ledger with
    mkdirSync(join(dir, "repo.git", "objects", "ab", "cd", "ef"), { recursive: true });
    if (e.agentview === "symlink") symlinkSync(join(base, "elsewhere"), join(dir, "agentview"));
    else if (e.agentview !== "none") {
      mkdirSync(join(dir, "agentview"), { recursive: true });
      for (const [rel, body] of Object.entries(e.agentview ?? {})) {
        mkdirSync(join(dir, "agentview", rel, ".."), { recursive: true });
        writeFileSync(join(dir, "agentview", rel), body);
      }
    }
  }
}
const TOKEN = "$MDU:nomodel_Read[9bbd1234].env";

test("Mandu's own state base is PRUNED from the HOME walk (the default ~/.mandu, or the base the launch sends): reported once as mandu-state, its stale AgentView copies and shadow repos never reach the inventory or the depth ledger", () => {
  const { home, cleanup } = fakeHome();
  try {
    // a stale workspace of a past session (its workspace.json names a path we are not launching from)
    fakeStateBase(defaultStateBase(home), [{ id: "old-ws-aaaaaaaaaaaa", workspacePath: "/somewhere/old", agentview: { ".env": `A=${"AKIA_STALE"}\n` } }]);
    const r = discoverSecretsReport([home], home);
    assert.ok(!r.files.some((f) => f.path.includes("/.mandu/")), `nothing under the state base is in the inventory: ${r.files.map((f) => f.path)}`);
    assert.equal(r.counts["mandu-state"], 1);
    assert.deepEqual(r.skipped.filter((s) => s.reason === "mandu-state").map((s) => s.path), [join(home, ".mandu")]);
    assert.equal(r.counts["depth"], 0, "the shadow repo's depth never lands in the ledger");
    assert.equal(r.counts["agentview-symbolized"], 0, "a stale workspace's copies are not walked at all");
    assert.ok(r.files.some((f) => f.path.endsWith("/.ssh/id_rsa")), "the rest of HOME is walked as before");
    // the launch's own base, deeper than the depth cap and spelled with ~: pruned too — and so is the
    // conventional ~/.mandu a moved base leaves behind (still Mandu's state, not the user's keys)
    const deep = join(home, ".local", "state", "mandu", "x", "view-state");
    fakeStateBase(deep, [{ id: "old-ws-bbbbbbbbbbbb", workspacePath: "/somewhere/old", agentview: { ".env": "A=AKIA_STALE_DEEP\n" } }]);
    const r2 = discoverSecretsReport([home], home, undefined, { stateBase: "~/.local/state/mandu/x/view-state" });
    assert.deepEqual(r2.skipped.filter((s) => s.reason === "mandu-state").map((s) => s.path).sort(), [join(home, ".mandu"), deep].sort());
    assert.equal(r2.counts["mandu-state"], 2);
    assert.ok(!r2.files.some((f) => f.path.startsWith(deep) || f.path.includes("/.mandu/")), "nothing under either base");
    assert.equal(r2.counts["depth"], 0);
    assert.ok(!JSON.stringify(r2).includes("AKIA_STALE"), "no contents in the report");
  } finally {
    cleanup();
  }
});

test("a MANDU_HOME moved deeper than the depth cap is pruned at the home itself (its state/ is the base), never left in the depth ledger", () => {
  const { home, cleanup } = fakeHome();
  try {
    // The home's own directory already sits at the cap, so the walk never reaches its state/.
    const moved = join(home, "a", "b", "c", "x", "mandu-home");
    fakeStateBase(join(moved, "state"), [{ id: "old-ws-cccccccccccc", workspacePath: "/somewhere/old", agentview: { ".env": "A=AKIA_STALE_MOVED\n" } }]);
    const r = discoverSecretsReport([home], home, undefined, { stateBase: join(moved, "state") });
    assert.ok(r.skipped.some((s) => s.reason === "mandu-state" && s.path === moved), JSON.stringify(r.skipped));
    assert.equal(r.counts["depth"], 0, "the moved home is Mandu's, not a depth miss");
    assert.ok(!JSON.stringify(r).includes("AKIA_STALE"), "no contents in the report");
  } finally {
    cleanup();
  }
});

test("the AgentView copies of the WORKSPACE ROOTS are found THROUGH the view map (workspace.json → agentview/), as roots of their own: a nested copy far below the depth cap from HOME is reached; a copy fs-sync symbolized is agentview-symbolized; a raw one (human-edited, raw beside a token) is DISCOVERED; a launch from a subdirectory matches its git root", () => {
  const { home, cleanup } = fakeHome();
  try {
    const ws = join(home, "proj");
    mkdirSync(join(ws, "sub"), { recursive: true });
    writeFileSync(join(ws, ".env"), "A=AKIA_HUMAN\n");
    const base = join(home, ".local", "state", "mandu", "x", "view-state"); // depth 5 under HOME: the old walk never got here
    fakeStateBase(base, [
      { id: "proj-cafecafecafe", workspacePath: ws, agentview: {
        ".env": `${TOKEN}\n`,                                    // fs-sync's seed: the whole content is one token
        "a/b/c/.env": `${TOKEN}\n`,                              // nested: depth 3 in the worktree (within the cap, as in the HumanView), 11 from HOME
        "svc/.env": `${TOKEN}\nB=AKIA_RAW_LINE\n`,               // a human edit put a raw line beside the token
        "notes.md": "no secret shape here",
      } },
      { id: "other-000000000000", workspacePath: "/elsewhere/other", agentview: { ".env": "A=AKIA_OTHER\n" } },
    ]);
    for (const root of [ws, join(ws, "sub")]) {
      const r = discoverSecretsReport([home, root], home, undefined, { stateBase: base });
      const av = join(base, "workspaces", "proj-cafecafecafe", "agentview");
      assert.deepEqual(agentViewRoots(base, [home, root]), [av]);
      assert.ok(r.files.some((f) => f.path === join(ws, ".env")), "the HumanView original");
      assert.ok(r.files.some((f) => f.path === join(av, "svc", ".env")), `the raw copy is discovered and will be twinned: ${r.files.map((f) => f.path)}`);
      assert.ok(!r.files.some((f) => f.path === join(av, ".env") || f.path === join(av, "a/b/c/.env")), "fs-sync's mask is not re-masked");
      assert.deepEqual(r.skipped.filter((s) => s.reason === "agentview-symbolized").map((s) => s.path).sort(), [join(av, ".env"), join(av, "a/b/c/.env")].sort());
      assert.equal(r.counts["agentview-symbolized"], 2);
      assert.ok(!r.files.some((f) => f.path.includes("other-000000000000")), "another workspace's copies are not this launch's business");
      assert.equal(r.counts["depth"], 0, "the worktree is walked from depth 0: nothing in it is out of reach, and the shadow repo is pruned");
      assert.equal(r.counts["mandu-state"], 1);
      assert.ok(!JSON.stringify(r).includes("AKIA_"), "no contents in the report");
    }
    // the default base, when the launch names none
    fakeStateBase(defaultStateBase(home), [{ id: "proj-cafecafecafe", workspacePath: ws, agentview: { ".env": `${TOKEN}\n`, "raw/.env": "A=AKIA_RAW_DEFAULT\n" } }]);
    const d = discoverSecretsReport([home, ws], home);
    assert.ok(d.files.some((f) => f.path === join(home, ".mandu", "state", "workspaces", "proj-cafecafecafe", "agentview", "raw", ".env")));
    assert.equal(d.counts["agentview-symbolized"], 1);
  } finally {
    cleanup();
  }
});

test("the view map is read defensively: a malformed or relative workspace.json, a missing or symlinked agentview, a workspace root that is the worktree itself, and an oversized or unreadable copy fail toward the safe side", () => {
  const { home, cleanup } = fakeHome();
  try {
    const ws = join(home, "proj");
    mkdirSync(ws, { recursive: true });
    const base = join(home, "state");
    fakeStateBase(base, [
      { id: "bad-json-000000000000", meta: "{not json", agentview: { ".env": "A=AKIA_BADJSON\n" } },
      { id: "relative-000000000000", meta: JSON.stringify({ workspacePath: "proj" }), agentview: { ".env": "A=AKIA_REL\n" } },
      { id: "no-av-000000000000", workspacePath: ws, agentview: "none" },
      { id: "link-av-000000000000", workspacePath: ws, agentview: "symlink" },
      { id: "good-000000000000", workspacePath: ws, agentview: { ".env": `${TOKEN}\n`, "big/.env": `${TOKEN}\n${" ".repeat(AGENTVIEW_CONTENT_CAP + 1)}`, "locked/.env": "A=AKIA_LOCKED\n" } },
    ]);
    const good = join(base, "workspaces", "good-000000000000", "agentview");
    chmodSync(join(good, "locked", ".env"), 0o000);
    assert.deepEqual(agentViewRoots(base, [home, ws]), [good], "only a well-formed entry with a real agentview directory");
    assert.deepEqual(agentViewRoots(join(home, "nowhere"), [ws]), [], "no state base: no roots, no error");
    const r = discoverSecretsReport([home, ws], home, undefined, { stateBase: base });
    assert.ok(r.files.some((f) => f.path === join(good, "big", ".env")), "an oversized copy is not content-checked: discovered (fail toward masking)");
    // Root reads a mode-000 file, so there is no unreadable copy to name when
    // the suite runs as root (the OS test matrix's VM guests do).
    if (process.getuid?.() !== 0) {
      assert.ok(r.skipped.some((s) => s.reason === "unreadable" && s.path === join(good, "locked", ".env")), "an unreadable copy is named as such");
    }
    assert.equal(r.counts["agentview-symbolized"], 1);
    assert.ok(!r.files.some((f) => /bad-json|relative-|link-av/.test(f.path)));
    // a root that IS the worktree (a launch from inside the AgentView): walked once, as a plain root
    const r2 = discoverSecretsReport([home, good], home, undefined, { stateBase: base });
    assert.equal(r2.files.filter((f) => f.path === join(good, "big", ".env")).length, 1);
    assert.ok(r2.files.some((f) => f.path === join(good, ".env")), "as a plain root the symbolic copy is a candidate like any file");
    // opts pass through the files-only view too
    assert.ok(discoverSecretFiles([home, ws], home, undefined, { stateBase: base }).some((f) => f.path === join(good, "big", ".env")));
  } finally {
    cleanup();
  }
});

// ── Mandu's own install trees (open-source-release checklist a5) ─────────────
import { manduInstallTrees, installedPackageRoot, defaultInstallPrefix, MANDU_PACKAGE_NAME } from "../../policy/secret-discovery.js";

/** Lay out what scripts/install.sh writes under `prefix`: the npm prefix
 *  `pkg/` (bin link + lib/node_modules/@mandusec/mandu with its dist/) and,
 *  optionally, the downloaded Node in `node/`. */
function fakeInstall(prefix: string, opts: { node?: boolean; name?: string } = {}): string {
  const pkgRoot = join(prefix, "pkg", "lib", "node_modules", "@mandusec", "mandu");
  mkdirSync(join(pkgRoot, "dist", "native", "linux-x64"), { recursive: true });
  mkdirSync(join(pkgRoot, "bin"), { recursive: true });
  writeFileSync(join(pkgRoot, "package.json"), JSON.stringify({ name: opts.name ?? MANDU_PACKAGE_NAME, version: "0.1.0" }));
  writeFileSync(join(pkgRoot, "bin", "mandu.mjs"), "// entry\n");
  writeFileSync(join(pkgRoot, "dist", "arbiter.mjs"), "// bundle\n");
  mkdirSync(join(prefix, "pkg", "bin"), { recursive: true });
  symlinkSync("../lib/node_modules/@mandusec/mandu/bin/mandu.mjs", join(prefix, "pkg", "bin", "mandu"));
  if (opts.node) {
    mkdirSync(join(prefix, "node", "bin"), { recursive: true });
    mkdirSync(join(prefix, "node", "include", "node"), { recursive: true });
    mkdirSync(join(prefix, "node", "lib", "node_modules", "npm"), { recursive: true });
    writeFileSync(join(prefix, "node", "bin", "node"), "ELF");
    writeFileSync(join(prefix, "node", "include", "node", "node_version.h"), "#define NODE_MAJOR_VERSION 22\n");
  }
  return pkgRoot;
}
const NO_ENV = { installEnv: {}, selfDir: null } as const;

test("Mandu's own install (the installer's ~/.local/share/mandu/pkg + node) is PRUNED as mandu-install: no depth records for pkg/bin, pkg/lib, node/*, while a secret elsewhere in HOME is still found", () => {
  const { home, cleanup } = fakeHome();
  try {
    fakeInstall(defaultInstallPrefix(home), { node: true });
    // the reproduction: without the prune these are exactly the `depth` records of a fresh install
    const r = discoverSecretsReport([home], home, undefined, NO_ENV);
    assert.equal(r.counts["depth"], 0, `no depth records: ${JSON.stringify(r.skipped.filter((s) => s.reason === "depth"))}`);
    assert.equal(r.counts["mandu-install"], 2);
    assert.deepEqual(
      r.skipped.filter((s) => s.reason === "mandu-install").map((s) => s.path).sort(),
      [join(defaultInstallPrefix(home), "node"), join(defaultInstallPrefix(home), "pkg")],
    );
    assert.ok(r.files.some((f) => f.path === join(home, ".aws", "credentials")), "a secret elsewhere is still found");
    assert.ok(r.files.some((f) => f.path === join(home, ".ssh", "id_rsa")));
  } finally {
    cleanup();
  }
});

test("the install prune cannot hide a secret: the prefix itself is walked, and a look-alike tree (no @mandusec/mandu package, a pkg LINK, a same-named dir elsewhere) is walked as before", () => {
  const { home, cleanup } = fakeHome();
  try {
    const prefix = defaultInstallPrefix(home);
    fakeInstall(prefix);
    // a stray secret in the prefix itself, beside the verified pkg: still found
    writeFileSync(join(prefix, ".env"), "API_KEY=AKIA_PREFIX\n");
    // a dir named `pkg` holding an @mandusec/mandu package, NOT at an installer prefix: walked
    const elsewhere = join(home, "work", "pkg");
    mkdirSync(join(elsewhere, "lib", "node_modules", "@mandusec", "mandu"), { recursive: true });
    writeFileSync(join(elsewhere, "lib", "node_modules", "@mandusec", "mandu", "package.json"), JSON.stringify({ name: MANDU_PACKAGE_NAME }));
    writeFileSync(join(elsewhere, ".env"), "API_KEY=AKIA_ELSEWHERE\n");
    const r = discoverSecretsReport([home], home, undefined, NO_ENV);
    const paths = r.files.map((f) => f.path);
    assert.ok(paths.includes(join(prefix, ".env")), `the prefix itself is walked: ${paths}`);
    assert.ok(paths.includes(join(elsewhere, ".env")), "a same-named tree elsewhere is walked");
    assert.equal(r.counts["mandu-install"], 1);

    // an impostor prefix: `pkg` without the Mandu package → walked, its secret found
    const { home: h2, cleanup: c2 } = fakeHome();
    try {
      const p2 = defaultInstallPrefix(h2);
      fakeInstall(p2, { name: "not-mandu" });
      writeFileSync(join(p2, "pkg", ".env"), "API_KEY=AKIA_IMPOSTOR\n");
      const r2 = discoverSecretsReport([h2], h2, undefined, NO_ENV);
      assert.equal(r2.counts["mandu-install"], 0);
      assert.ok(r2.files.some((f) => f.path === join(p2, "pkg", ".env")), "an unverified pkg is walked");
      // ...and its bin/ + lib/ are the depth records a fresh install used to WARN about (the reproduction)
      assert.deepEqual(
        r2.skipped.filter((s) => s.reason === "depth").map((s) => s.path).sort(),
        [join(p2, "pkg", "bin"), join(p2, "pkg", "lib")],
      );
      // `node/` is pruned only beside a VERIFIED pkg
      assert.deepEqual(manduInstallTrees(h2, { env: {}, selfDir: null }), []);
    } finally {
      c2();
    }

    // a `pkg` SYMLINK at the prefix names nothing (the walk never follows it either)
    const { home: h3, cleanup: c3 } = fakeHome();
    try {
      const real = join(h3, "elsewhere-real");
      fakeInstall(real);
      mkdirSync(defaultInstallPrefix(h3), { recursive: true });
      symlinkSync(join(real, "pkg"), join(defaultInstallPrefix(h3), "pkg"));
      assert.deepEqual(manduInstallTrees(h3, { env: {}, selfDir: null }), []);
    } finally {
      c3();
    }
  } finally {
    cleanup();
  }
});

test("install trees are matched by REALPATH: a HOME reached through a symlink still prunes its install; MANDU_PREFIX names a prefix, XDG_DATA_HOME does not (the path table); relative candidates are ignored", () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "mandu-inst-"))); // install trees come back as realpaths
  try {
    const realHome = join(base, "real-home");
    mkdirSync(realHome);
    fakeInstall(defaultInstallPrefix(realHome));
    const linkHome = join(base, "link-home");
    symlinkSync(realHome, linkHome);
    const r = discoverSecretsReport([linkHome], linkHome, undefined, NO_ENV);
    assert.equal(r.counts["mandu-install"], 1);
    assert.equal(r.counts["depth"], 0);

    const custom = join(base, "custom-prefix");
    fakeInstall(custom, { node: true });
    const xdg = join(base, "xdg");
    fakeInstall(join(xdg, "mandu"));
    const trees = manduInstallTrees(join(base, "nohome"), { env: { MANDU_PREFIX: custom, XDG_DATA_HOME: xdg }, selfDir: null });
    assert.deepEqual(trees, [join(custom, "node"), join(custom, "pkg")].sort());
    // Phase 3b (on-disk-layout.md §7): the table's install-prefix, like
    // scripts/install.sh, ignores XDG_DATA_HOME, so a tree there is walked.
    assert.deepEqual(manduInstallTrees(join(base, "nohome"), { env: { XDG_DATA_HOME: xdg }, selfDir: null }), []);
    // An empty MANDU_PREFIX counts as unset: the home default still applies.
    assert.deepEqual(manduInstallTrees(realHome, { env: { MANDU_PREFIX: "" }, selfDir: null }), [join(defaultInstallPrefix(realHome), "pkg")]);
    assert.deepEqual(manduInstallTrees(join(base, "nohome"), { env: { MANDU_PREFIX: "rel/prefix" }, selfDir: null }), []);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("the RUNNING package's own root is an install tree only when it is an installed @mandusec/mandu under node_modules; an installer layout around it names its prefix", () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "mandu-self-"))); // install trees come back as realpaths
  try {
    // installed by install.sh --prefix <custom>, running from dist/
    const custom = join(base, "opt-mandu");
    const pkgRoot = fakeInstall(custom);
    assert.equal(installedPackageRoot(join(pkgRoot, "dist")), pkgRoot);
    assert.deepEqual(manduInstallTrees(join(base, "h"), { env: {}, selfDir: join(pkgRoot, "dist") }), [join(custom, "pkg"), pkgRoot].sort());
    // a plain `npm install -g` into some other prefix: only the package root itself
    const npmGlobal = join(base, "npm-global", "lib", "node_modules", "@mandusec", "mandu");
    mkdirSync(join(npmGlobal, "dist"), { recursive: true });
    writeFileSync(join(npmGlobal, "package.json"), JSON.stringify({ name: MANDU_PACKAGE_NAME }));
    assert.deepEqual(manduInstallTrees(join(base, "h"), { env: {}, selfDir: join(npmGlobal, "dist") }), [npmGlobal]);
    // a repo checkout (launcher/ is @mandusec/mandu but not under node_modules): nothing
    const repo = join(base, "repo", "launcher");
    mkdirSync(join(repo, "dist"), { recursive: true });
    writeFileSync(join(repo, "package.json"), JSON.stringify({ name: MANDU_PACKAGE_NAME }));
    assert.equal(installedPackageRoot(join(repo, "dist")), null);
    // another package's code (the dev arbiter: @mandusec/arbiter): nothing
    const arb = join(base, "node_modules", "arb");
    mkdirSync(join(arb, "policy"), { recursive: true });
    writeFileSync(join(arb, "package.json"), JSON.stringify({ name: "@mandusec/arbiter" }));
    assert.equal(installedPackageRoot(join(arb, "policy")), null);
    // this very test runs from the repo checkout: the default self dir names nothing
    assert.equal(installedPackageRoot(join(import.meta.dirname, "..", "..", "policy")), null);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("WSL: a Windows profile handed as the HOME of its own roots has its stores discovered, Windows spellings included", () => {
  // The launcher (launcher/src/wsl.ts `windowsProfileSecretRoots`) passes the
  // catalog's paths under /mnt/<drive>/Users/<name> as roots, with the profile
  // as the home, so the `~/` rules anchor there (confidentiality.md §7.2).
  const root = mkdtempSync(join(tmpdir(), "mandu-winprof-"));
  try {
    const profile = join(root, "mnt", "c", "Users", "alice");
    const put = (rel: string, body: string): void => {
      const p = join(profile, rel);
      mkdirSync(join(p, ".."), { recursive: true });
      writeFileSync(p, body);
    };
    put(".aws/credentials", "[default]\naws_secret_access_key=WINRAW\n");
    put(".aws/config", "[default]\nregion=us-east-1\n");
    put("_netrc", "machine example.com login a password WINRAW\n");
    put("AppData/Roaming/gcloud/legacy_credentials/a@b.c/adc.json", "{}");
    put("AppData/Roaming/GitHub CLI/hosts.yml", "github.com:\n  oauth_token: WINRAW\n");
    put("AppData/Local/Packages/big/notes.txt", "not a root");
    const roots = [".aws", "_netrc", "AppData/Roaming/gcloud", "AppData/Roaming/GitHub CLI", ".kube"].map((r) => join(profile, r));
    const found = discoverSecretFiles(roots, profile).map((f) => f.path.slice(profile.length + 1));
    assert.deepEqual(found, [
      ".aws/config", ".aws/credentials", "AppData/Roaming/GitHub CLI/hosts.yml",
      "AppData/Roaming/gcloud/legacy_credentials/a@b.c/adc.json", "_netrc",
    ]);
    // Anchored to the Linux HOME instead, only the basename shapes survive:
    // the reason the launcher passes the profile as the home.
    const linuxHome = discoverSecretFiles(roots, join(root, "home", "u")).map((f) => f.path.slice(profile.length + 1));
    assert.deepEqual(linuxHome, [".aws/credentials"]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the default state base and install prefix are the path table's view-state and install-prefix, without their overrides", () => {
  assert.equal(defaultStateBase("/home/u"), "/home/u/.mandu/state");
  assert.equal(defaultStateBase("/home/u/"), "/home/u/.mandu/state");
  assert.equal(defaultInstallPrefix("/home/u"), "/home/u/.local/share/mandu");
});

// ── launch-notice noise (secret-discovery.md §1.9 F) ──────────────────────
// The ledger names WHY a place was not searched; the walk itself is unchanged.
import { isPackageCachePath, PACKAGE_CACHE_DIRS } from "../../policy/secret-discovery.js";
import { createServer, type Server } from "node:net";
import { spawnSync } from "node:child_process";

test("isPackageCachePath: strictly INSIDE a listed cache (a `*` within one segment), for the given HOME; the cache root, a look-alike and the tools' own credential files are not", () => {
  const h = "/home/u";
  for (const p of [
    "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde-1.0.0",
    "/home/u/.cargo/git/checkouts/foo-abc/1234567",
    "/home/u/go/pkg/mod/github.com/x/y@v1.2.3",
    "/home/u/.local/share/pnpm/store/v3/files/00",
    "/home/u/.m2/repository/org/apache/commons",
    "/home/u/.local/lib/python3.12/site-packages/numpy/core",
    "/home/u/.local/lib/python3/site-packages/a",
    "/home/u/.local/share/opentui/tree-sitter/languages", // OpenCode's TUI library (live 2026-10-11)
    // a developer home's launch notice, 2026-10-11 (§1.9 H)
    "/home/u/.oh-my-zsh/plugins/zsh-syntax-highlighting/highlighters/main",
    "/home/u/.oh-my-zsh/custom/plugins/zsh-autosuggestions/spec/options",
    "/home/u/.cargo/advisory-db/.github/actions/install-rustsec-admin",
    "/home/u/.ollama/models/manifests/registry.ollama.ai/library",
    "/home/u/.texlive2025/texmf-var/luatex-cache/generic/names",
  ]) assert.equal(isPackageCachePath(p, h), true, p);
  for (const p of [
    "/home/u/.cargo/registry", // the cache root itself is walked as usual
    "/home/u/.cargo/registry-old/src/a/b",
    "/home/u/.cargo/credentials.toml",
    "/home/u/.m2/settings.xml",
    "/home/u/.gem/credentials",
    "/home/u/.local/lib/python3.12/other/a",
    "/home/u/.local/lib/python3.12/x/site-packages/a", // `*` never spans a `/`
    "/home/u/project/.cargo/registry/src/a", // HOME-relative only
    "/home/v/.cargo/registry/src/a", // another HOME
    "/home/u/.oh-my-zsh/custom/my-secrets.zsh", // the user's own oh-my-zsh files
    "/home/u/.oh-my-zsh/custom/lib/a/b",
    "/home/u/.oh-my-zsh-custom/plugins/x/spec/y", // a custom folder of the user's own naming stays counted
    "/home/u/.ollama/id_ed25519", // Ollama's own key, outside its models
    "/home/u/.texlive2025/texmf-config/a/b", // TeX Live's per-user configuration
  ]) assert.equal(isPackageCachePath(p, h), false, p);
  // the memo is per HOME
  assert.equal(isPackageCachePath("/home/v/.cargo/registry/src/a", "/home/v"), true);
  assert.ok(PACKAGE_CACHE_DIRS.every((d) => d.startsWith("~/")), "every entry is HOME-relative");
});

test("report: a directory below the depth cap INSIDE a package cache is `package-cache`, not `depth`; one at the same depth outside a cache is still `depth`; a secret shallow in a cache is still discovered (the walk is unchanged)", () => {
  const home = mkdtempSync(join(tmpdir(), "mandu-caches-"));
  try {
    const crate = join(home, ".cargo", "registry", "src", "index.crates.io-x", "serde-1.0.0"); // depth 5
    mkdirSync(join(crate, "src"), { recursive: true });
    const gomod = join(home, "go", "pkg", "mod", "github.com", "x"); // depth 5
    mkdirSync(join(gomod, "y@v1"), { recursive: true });
    const site = join(home, ".local", "lib", "python3.12", "site-packages", "numpy"); // depth 5
    mkdirSync(site, { recursive: true });
    // OpenCode's TUI library unpacks its tree-sitter files at depth 5 (live 2026-10-11)
    const tui = join(home, ".local", "share", "opentui", "tree-sitter", "languages");
    mkdirSync(tui, { recursive: true });
    const outside = join(home, "work", "a", "b", "c", "d"); // depth 5, no cache
    mkdirSync(outside, { recursive: true });
    // depth 3 inside the registry: walked as before, so a catalog match is found
    writeFileSync(join(home, ".cargo", "registry", "src", ".env"), "TOKEN=x\n");
    const r = discoverSecretsReport([home], home);
    assert.equal(r.counts["package-cache"], 4);
    assert.deepEqual(r.skipped.filter((s) => s.reason === "package-cache").map((s) => s.path).sort(), [crate, gomod, site, tui].sort());
    assert.equal(r.counts["depth"], 1, "a deep directory outside the caches is still a consequential miss");
    assert.deepEqual(r.skipped.filter((s) => s.reason === "depth").map((s) => s.path), [outside]);
    assert.ok(r.files.some((f) => f.path === join(home, ".cargo", "registry", "src", ".env")), "the cache is still walked to the cap");
    assert.deepEqual(r.files.map((f) => f.path), discoverSecretFiles([home], home).map((f) => f.path));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("report: the `depth` records grouped by folder two levels below their walk root, over EVERY record (past the record cap), the most first; package caches not among them (§1.9 H)", () => {
  const home = mkdtempSync(join(tmpdir(), "mandu-areas-"));
  try {
    // A developer home's shape: two checkouts with many depth-5 folders, a
    // shell plugin clone, and the workspace (its own root) under HOME.
    for (let i = 0; i < 150; i++) mkdirSync(join(home, "project", "app", "src", "mod", `m${i}`), { recursive: true });
    for (let i = 0; i < 70; i++) mkdirSync(join(home, "project", "lib", "test", "fx", `f${i}`), { recursive: true });
    mkdirSync(join(home, ".zsh", "plugins", "x", "spec", "a"), { recursive: true });
    mkdirSync(join(home, ".oh-my-zsh", "plugins", "y", "tests", "_output"), { recursive: true });
    const ws = join(home, "ws");
    mkdirSync(join(ws, "a", "b", "c", "d", "e", "f"), { recursive: true });
    const r = discoverSecretsReport([home, ws], home);
    assert.equal(r.counts["depth"], 222);
    assert.equal(r.counts["package-cache"], 1, "oh-my-zsh's own plugins are a package cache");
    assert.ok(r.skipped.length <= 200, "the records are capped");
    assert.deepEqual(r.depthAreas, [
      { path: join(home, "project", "app"), count: 150 },
      { path: join(home, "project", "lib"), count: 70 },
      { path: join(home, ".zsh", "plugins"), count: 1 },
      { path: join(ws, "a", "b"), count: 1 },
    ], "each by its walk root: the workspace's own folder under its own root");
    assert.equal(r.depthAreas.reduce((n, a) => n + a.count, 0), r.counts["depth"]);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("depthAreasOf: the deepest root holding each directory; ties by path; capped at MAX_DEPTH_AREAS; a directory under no root is grouped from /", () => {
  const roots = ["/h", "/h/ws"];
  assert.deepEqual(depthAreasOf(["/h/b/x/1/2/3", "/h/a/y/1/2/3", "/h/ws/p/q/1/2/3", "/h/b/x/9/9/9"], roots), [
    { path: "/h/b/x", count: 2 }, { path: "/h/a/y", count: 1 }, { path: "/h/ws/p/q", count: 1 },
  ]);
  assert.deepEqual(depthAreasOf(["/srv/data/a/b/c/d"], roots), [{ path: "/srv/data", count: 1 }]);
  const many = Array.from({ length: MAX_DEPTH_AREAS + 5 }, (_, i) => `/h/p${String(i).padStart(2, "0")}/q/1/2/3`);
  const capped = depthAreasOf(many, roots);
  assert.equal(capped.length, MAX_DEPTH_AREAS);
  assert.equal(capped[0]!.path, "/h/p00/q");
  assert.equal(DEPTH_AREA_LEVELS, 2);
  assert.deepEqual(depthAreasOf([], roots), []);
});

test("report: a directory another root's walk reaches within the cap (the workspace under HOME) is walked, not a `depth` miss; one too deep for every root still is", () => {
  const home = mkdtempSync(join(tmpdir(), "mandu-overlap-"));
  try {
    const ws = join(home, "proj");
    const d4 = join(ws, "a", "b", "c", "d"); // depth 5 from HOME, 4 from the workspace
    const d5 = join(d4, "e"); // depth 6 from HOME, 5 from the workspace
    mkdirSync(d5, { recursive: true });
    writeFileSync(join(d4, ".env"), "TOKEN=x\n");
    const homeOnly = discoverSecretsReport([home], home);
    assert.deepEqual(homeOnly.skipped.filter((s) => s.reason === "depth").map((s) => s.path), [d4], "HOME alone: d4 is out of reach");
    const both = discoverSecretsReport([home, ws], home);
    assert.ok(both.files.some((f) => f.path === join(d4, ".env")), "the workspace walk finds the secret in d4");
    assert.deepEqual(both.skipped.filter((s) => s.reason === "depth").map((s) => s.path), [d5], "only what NO root reaches is a miss");
    assert.equal(both.counts["depth"], 1);
    // a root that is not a directory covers nothing
    const asFile = discoverSecretsReport([home, join(d4, ".env")], home);
    assert.deepEqual(asFile.skipped.filter((s) => s.reason === "depth").map((s) => s.path), [d4]);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("report: a socket or FIFO named like a secret (the ssh-agent socket under ~/.ssh) is `special-file`, never `unreadable`; an unreadable REGULAR file still is `unreadable`", async () => {
  const home = mkdtempSync(join(tmpdir(), "mandu-sock-"));
  let server: Server | undefined;
  try {
    mkdirSync(join(home, ".ssh", "agent"), { recursive: true });
    const sock = join(home, ".ssh", "agent", "s.x");
    server = createServer();
    await new Promise<void>((resolve, reject) => { server!.once("error", reject); server!.listen(sock, resolve); });
    const fifo = join(home, ".ssh", "id_pipe");
    const haveFifo = spawnSync("mkfifo", [fifo]).status === 0;
    writeFileSync(join(home, ".ssh", "id_ok"), "-----BEGIN OPENSSH PRIVATE KEY-----\n");
    const locked = join(home, ".ssh", "id_locked");
    writeFileSync(locked, "-----BEGIN OPENSSH PRIVATE KEY-----\n");
    chmodSync(locked, 0o000);
    const r = discoverSecretsReport([home], home);
    const by = (reason: string): string[] => r.skipped.filter((s) => s.reason === reason).map((s) => s.path).sort();
    assert.deepEqual(by("special-file"), (haveFifo ? [fifo, sock] : [sock]).sort());
    assert.equal(r.counts["special-file"], haveFifo ? 2 : 1);
    if (process.getuid && process.getuid() !== 0) {
      assert.deepEqual(by("unreadable"), [locked], "an unreadable regular file is still the consequential `unreadable`");
    }
    assert.deepEqual(r.files.map((f) => f.path), [join(home, ".ssh", "id_ok")]);
  } finally {
    await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
    try { chmodSync(join(home, ".ssh", "id_locked"), 0o600); } catch { /* not created */ }
    rmSync(home, { recursive: true, force: true });
  }
});


test("darwin: derived files below the depth cap or outside roots survive HOME pruning; a human public label still wins", () => {
  const { home, cleanup } = fakeHome();
  const outside = realpathSync(mkdtempSync(join(tmpdir(), "mandu-derived-outside-")));
  try {
    const deep = join(home, "Library", "Application Support", "a", "b", "c", "copy.txt");
    const elsewhere = join(outside, "other.txt");
    const publicFile = join(home, "Library", "Application Support", "a", "b", "c", "public.txt");
    const unrelated = join(home, "Library", ".env");
    for (const p of [deep, elsewhere, publicFile, unrelated]) {
      mkdirSync(join(p, ".."), { recursive: true }); writeFileSync(p, "DERIVED_COPY_CANARY\n");
    }
    const lookup: LabelLookup = (p) => p === publicFile
      ? { level: "public", bindings: [], via: p }
      : [deep, elsewhere].includes(p) ? { level: "no-model", bindings: [], via: p } : null;
    const report = discoverSecretsReport([home], home, lookup, {
      platform: "darwin", labelPaths: [deep, publicFile], derivedPaths: [deep, elsewhere, publicFile],
    });
    const paths = report.files.map((f) => f.path);
    assert.ok(paths.includes(deep), "the labeled literal under Library survives its prune");
    assert.ok(paths.includes(elsewhere), "a derived file is a direct candidate independently of the walk");
    assert.ok(!paths.includes(publicFile), "a human public label lifts the derived label");
    assert.ok(!paths.includes(unrelated), "the unrelated catalog-shaped file stays pruned");
    assert.equal(paths.filter((p) => p === deep).length, 1, "the prune re-entry and derived candidate deduplicate");
    assert.ok(!JSON.stringify(report).includes("DERIVED_COPY_CANARY"), "discovery reports no secret values");
  } finally { cleanup(); rmSync(outside, { recursive: true, force: true }); }
});

// ── the walk count (launch speed J, secret-discovery.md §1.9 G) ─────────────
import { pickPackageCacheEnv, PACKAGE_CACHE_ENV, relocatedPackageCaches } from "../../policy/secret-discovery.js";

test("report: a workspace that IS HOME is walked once (roots [home, home], any spelling): every count and record equals HOME alone", () => {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "mandu-wsishome-")));
  try {
    const deep = join(home, "a", "b", "c", "d", "e"); // depth 5
    mkdirSync(deep, { recursive: true });
    mkdirSync(join(home, ".ssh"), { recursive: true });
    writeFileSync(join(home, ".ssh", "id_rsa"), "-----BEGIN OPENSSH PRIVATE KEY-----\n");
    symlinkSync("/nonexistent/creds", join(home, ".ssh", "id_gone"));
    const alone = discoverSecretsReport([home], home);
    assert.equal(alone.counts["depth"], 1);
    assert.equal(alone.counts["dangling-symlink"], 1);
    for (const roots of [[home, home], [home, `${home}/`], ["~", home], [home, join(home, "a", "..")]]) {
      const r = discoverSecretsReport(roots, home);
      assert.deepEqual(r.counts, alone.counts, `roots ${JSON.stringify(roots)}: ${JSON.stringify(r.counts)}`);
      assert.deepEqual(r.skipped, alone.skipped);
      assert.deepEqual(r.files, alone.files);
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("report: a root INSIDE another (the workspace under HOME) is walked once, by its own root: its records are not counted twice, its secrets found once", () => {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "mandu-nested-")));
  try {
    const ws = join(home, "proj");
    mkdirSync(join(ws, "cfg"), { recursive: true });
    writeFileSync(join(ws, "cfg", ".env"), "TOKEN=x\n");
    symlinkSync("/nonexistent/creds", join(ws, "cfg", "credentials")); // a dangling link named like a secret
    symlinkSync(home, join(ws, "home-link")); // a symlinked directory
    const wsOnly = discoverSecretsReport([ws], home);
    assert.equal(wsOnly.counts["dangling-symlink"], 1);
    assert.equal(wsOnly.counts["symlinked-directory"], 1);
    const both = discoverSecretsReport([home, ws], home);
    assert.equal(both.counts["dangling-symlink"], 1, `once, not once per root: ${JSON.stringify(both.counts)}`);
    assert.equal(both.counts["symlinked-directory"], 1);
    assert.deepEqual(both.files.map((f) => f.path).filter((p) => p.startsWith(ws + "/")), [join(ws, "cfg", ".env")]);
    // the order of the roots does not matter
    assert.deepEqual(discoverSecretsReport([ws, home], home).counts, both.counts);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("relocatedPackageCaches: the trees each variable moves (GOPATH a `:` list); a relative value, HOME, a root or an ancestor of either is ignored", () => {
  const h = "/home/u";
  assert.deepEqual(relocatedPackageCaches({}, h), []);
  assert.deepEqual(relocatedPackageCaches({ CARGO_HOME: "/data/cargo/" }, h), ["/data/cargo/registry", "/data/cargo/git"]);
  assert.deepEqual(relocatedPackageCaches({ GOMODCACHE: "/home/u/dev/gomod" }, h), ["/home/u/dev/gomod"]);
  assert.deepEqual(relocatedPackageCaches({ GOPATH: "/g1:rel:/g2" }, h), ["/g1/pkg/mod", "/g2/pkg/mod"]);
  assert.deepEqual(relocatedPackageCaches({ GRADLE_USER_HOME: "/gr" }, h), ["/gr/caches", "/gr/wrapper/dists"]);
  assert.deepEqual(
    relocatedPackageCaches({ XDG_CACHE_HOME: "/home/u/c", npm_config_cache: "/n", NPM_CONFIG_CACHE: "/n", RUSTUP_HOME: "/r", NVM_DIR: "/v", PIP_CACHE_DIR: "/p", YARN_CACHE_FOLDER: "/y" }, h).sort(),
    ["/home/u/c", "/n", "/p", "/r", "/v", "/y"],
  );
  for (const bad of ["relative/mod", "~/gomod", "/", "/home", "/home/u", "/home/u/", "/home/u/proj", "/home/u/proj/../proj"]) {
    assert.deepEqual(relocatedPackageCaches({ GOMODCACHE: bad }, h, ["/home/u/proj"]), [], bad);
  }
  assert.deepEqual(relocatedPackageCaches({ GOMODCACHE: "/home/u/proj/gomod" }, h, ["/home/u/proj"]), ["/home/u/proj/gomod"], "a cache INSIDE a root is a cache");
});

test("pickPackageCacheEnv: the known variable names with non-empty string values only (the wire is untrusted in shape)", () => {
  assert.deepEqual(pickPackageCacheEnv(undefined), {});
  assert.deepEqual(pickPackageCacheEnv("CARGO_HOME=/c"), {});
  assert.deepEqual(pickPackageCacheEnv({ CARGO_HOME: "/c", GOMODCACHE: 7, PIP_CACHE_DIR: "", AWS_SECRET_ACCESS_KEY: "k" }), { CARGO_HOME: "/c" });
  assert.ok(PACKAGE_CACHE_ENV.includes("CARGO_HOME") && PACKAGE_CACHE_ENV.includes("GOMODCACHE"));
});

test("isPackageCachePath: strictly inside a moved cache too; the moved root itself and a look-alike are not", () => {
  const moved = ["/data/cargo/registry"];
  assert.equal(isPackageCachePath("/data/cargo/registry/src/a", "/home/u", moved), true);
  assert.equal(isPackageCachePath("/data/cargo/registry", "/home/u", moved), false);
  assert.equal(isPackageCachePath("/data/cargo/registry-old/src/a", "/home/u", moved), false);
  assert.equal(isPackageCachePath("/data/cargo/registry/src/a", "/home/u"), false, "without the move: not a cache");
});

test("report: caches moved by CARGO_HOME, GOMODCACHE and XDG_CACHE_HOME are `package-cache`, not `depth`, when the launch says so; still walked (a shallow secret inside is found); without the variables they stay `depth`", () => {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "mandu-moved-")));
  try {
    const cargo = join(home, "dev", "cargo");
    const crate = join(cargo, "registry", "src", "idx"); // depth 5
    mkdirSync(join(crate, "serde"), { recursive: true });
    const gomod = join(home, "dev", "gomod");
    const mod = join(gomod, "github.com", "x", "y@v1"); // depth 5
    mkdirSync(mod, { recursive: true });
    const xdg = join(home, "dev", "xdg-cache");
    const cached = join(xdg, "a", "b", "c"); // depth 5
    mkdirSync(cached, { recursive: true });
    const outside = join(home, "work", "a", "b", "c", "d"); // depth 5, no cache
    mkdirSync(outside, { recursive: true });
    writeFileSync(join(cargo, "registry", ".env"), "TOKEN=x\n"); // depth 3 inside the moved cache
    const plain = discoverSecretsReport([home], home);
    assert.equal(plain.counts["depth"], 4, `without the variables: ${JSON.stringify(plain.skipped)}`);
    assert.equal(plain.counts["package-cache"], 0);
    const cacheEnv = { CARGO_HOME: cargo, GOMODCACHE: gomod, XDG_CACHE_HOME: xdg, HOME: home };
    const r = discoverSecretsReport([home], home, undefined, { cacheEnv });
    assert.deepEqual(r.skipped.filter((s) => s.reason === "package-cache").map((s) => s.path).sort(), [crate, mod, cached].sort());
    assert.deepEqual(r.skipped.filter((s) => s.reason === "depth").map((s) => s.path), [outside], "only the user's own tree is still counted");
    assert.deepEqual(r.files, plain.files, "the walk is unchanged: the same files");
    assert.ok(r.files.some((f) => f.path === join(cargo, "registry", ".env")));
    // A variable pointing at HOME quiets nothing.
    assert.deepEqual(discoverSecretsReport([home], home, undefined, { cacheEnv: { GOMODCACHE: home } }).counts, plain.counts);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
