/**
 * first-session-fixture — the first-session tour's premise, from the tour's
 * own text (docs/first-session.md): the folder its "Set up the test folder"
 * block makes, run through the REAL arbiter as a launch runs it.
 *
 *   - `.env` is a secret file from its name (the catalog finds it);
 *   - the file of step 3 ("A secret Mandu did not know") is NOT found by the
 *     default catalog, by name or by the content tier: it stays `public`, so
 *     the AI reads it as it is until the person teaches Mandu;
 *   - the launch's suggestion notice counts it: "1 possible key in this
 *     project is not protected", the line the tour shows (`startLaunchSuggest`
 *     over the production wire);
 *   - `mandu policy suggest` shows the screen the tour's "What it looks like"
 *     shows, line for line, and `a` applies it (the production deps);
 *   - after the rule, the file is `no-model` and its copy for programs keeps
 *     the host line and holds the token only as a placeholder (the tour: "the
 *     AI now gets the file with the token's value as a placeholder");
 *   - the same lines in a `.conf` ARE found by the content tier (2026-10-19,
 *     secret-discovery.md §2.9): the check is not vacuous, and it is why the
 *     tour's file is a `.tfvars`.
 *
 * Why it exists: the content tier learned the INI family on 2026-10-19 and
 * the tour's `deploy/staging.conf` silently became a file Mandu masks at
 * launch, so a fresh user saw a placeholder and no notice. A catalog change
 * that finds the tour's file now fails here, and the tour moves with it
 * (secret-discovery.md §2.9 "The first-session tour").
 *
 * Oracle: no byte of the tour's token in the walk's report, the notice, the
 * terminal screen or the copy the AI reads. Axes stated: secrets.
 *
 * Mandu-new test (no reference origin).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { realPolicySuggestDeps, runPolicySuggest, startLaunchSuggest } from "../../launcher/src/policy-suggest.js";
import type { Layout } from "../../launcher/src/services/layout.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the default mode, the one the tour runs in

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const TOUR = readFileSync(join(REPO, "docs/first-session.md"), "utf8");

/** The body of the `## <title>` section (to the next `## `). */
function section(md: string, title: string): string {
  const at = md.indexOf(`\n## ${title}\n`);
  assert.ok(at >= 0, `docs/first-session.md has a "## ${title}" section`);
  const rest = md.slice(at + title.length + 5);
  const end = rest.search(/^## /m);
  return end < 0 ? rest : rest.slice(0, end);
}

/** The first fenced block of `kind` in `md`, its lines. */
function fence(md: string, kind: string): string[] {
  const m = new RegExp("^```" + kind + "\\n([\\s\\S]*?)^```", "m").exec(md);
  assert.ok(m, `a \`\`\`${kind} block`);
  return m[1]!.replace(/\n$/, "").split("\n");
}

/** The setup block's files: `printf '<text>' > <path>` with `\n` its only
 *  escape (anything else would need a shell to read it right). */
function tourFiles(): Map<string, string> {
  const lines = fence(section(TOUR, "Set up the test folder"), "sh");
  assert.equal(lines[0], "mkdir -p ~/mandu-try/deploy && cd ~/mandu-try && git init -q", "the folder is ~/mandu-try, a git repository");
  const files = new Map<string, string>();
  for (const l of lines.slice(1)) {
    const m = /^printf '([^']*)' > (\S+)$/.exec(l);
    assert.ok(m, `a setup line this test reads: ${l}`);
    assert.doesNotMatch(m[1]!.replace(/\\n/g, ""), /\\|%/, `only \\n escapes: ${l}`);
    files.set(m[2]!, m[1]!.replace(/\\n/g, "\n"));
  }
  return files;
}

/** Step 3's file, from its question ("What is in <file>? Show me its lines."). */
function stepThreeFile(): string {
  const claude = section(TOUR, "Claude Code");
  const at = claude.indexOf("### 3. A secret Mandu did not know");
  assert.ok(at >= 0, "Claude Code step 3");
  const m = /^> What is in (\S+)\? Show me its lines\.$/m.exec(claude.slice(at));
  assert.ok(m, "step 3's question");
  return m[1]!;
}

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

test("the first-session tour's premise holds: .env is found by name, step 3's file is not found by the default catalog yet the launch notice counts it, `mandu policy suggest` shows the tour's screen, and after `a` the AI's copy holds only a placeholder (secrets axes)", async () => {
  const files = tourFiles();
  const fixture = stepThreeFile();
  assert.ok(files.has(".env"), "the setup makes .env");
  assert.ok(files.has(fixture), `the setup makes step 3's file ${fixture}`);
  assert.equal(files.size, 2, "two files, two fake secrets");
  const token = /"(ghp_[^"]+)"/.exec(files.get(fixture)!)?.[1];
  assert.ok(token, `${fixture} holds the tour's token`);
  const noToken = (what: string, s: string): void => assert.ok(!s.includes(token) && !s.includes(token.slice(4, 16)), `${what} carries the tour's token`);

  const dir = mkdtempSync(join(tmpdir(), "mdu-tour-fixture-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const ws = join(home, "mandu-try");
  mkdirSync(join(ws, "deploy"), { recursive: true });
  execFileSync("git", ["init", "-q"], { cwd: ws, env: { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1" } });
  for (const [rel, text] of files) writeFileSync(join(ws, rel), text);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\n");

  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: policy, policyPollMs: 0, confidentiality: true, integrity: false, log: () => {},
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  try {
    // ── The launch's secret setup (launcher/src/secret-setup.ts): the walk, then a registration per file found.
    const report = await client.discoverSecretsReport([home, ws], home);
    noToken("the walk's report", JSON.stringify(report));
    const found = new Map(report.files.map((f) => [f.path, f.rule]));
    assert.ok(found.has(join(ws, ".env")), `.env is a secret file from its name: ${JSON.stringify([...found])}`);
    assert.ok(!found.has(join(ws, fixture)),
      `TOUR BROKEN: the default catalog now finds ${fixture} (${found.get(join(ws, fixture))}), so the tour's step 3 shows a placeholder from the start and no notice; move the tour's file (docs/first-session.md, secret-discovery.md §2.9)`);
    for (const f of report.files) assert.ok((await client.registerSecret({ path: f.path, home })).symbol, f.path);
    assert.equal((await client.pathLevel(join(ws, fixture))).level, "public", `${fixture}: the AI reads it as it is`);

    // ── The launch's notice: the tour's "1 notice", the line `mandu log` shows.
    const notice = await startLaunchSuggest({ sock, cwd: ws, home, env: { MANDU_SUGGEST_WAIT_MS: "20000" } });
    assert.equal(notice, "mandu: 1 possible key in this project is not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard");
    assert.ok(TOUR.includes('"1 possible key in this project is not protected"'), "the tour quotes the notice");
    assert.ok(TOUR.includes(`about\n\`${fixture}\``) || TOUR.includes(`about \`${fixture}\``), "the tour names the file the notice is about");

    // ── `mandu policy suggest`, `a`: the screen of step 3's "What it looks like".
    const out: string[] = [];
    const keys = ["a"];
    const code = await runPolicySuggest([], { HOME: home, NO_COLOR: "1", PATH: process.env["PATH"] ?? "/usr/bin:/bin" }, {} as Layout, {
      ...realPolicySuggestDeps(),
      arbiter: async () => ({ sock, kind: "resident" as const, axisOn: true, stop: async () => {} }),
      cwd: () => ws,
      isTTY: () => true,
      readKey: async () => keys.shift() ?? "",
      readLine: async () => "",
      out: (t) => out.push(t),
      err: (t) => out.push(t),
    });
    const screen = out.join("");
    assert.equal(code, 0, screen);
    noToken("the terminal", screen);
    const step3 = section(TOUR, "Claude Code").split("### 3. A secret Mandu did not know")[1]!;
    const shown = fence(step3, "text");
    assert.ok(shown[0]!.startsWith("[1/1] Make ~/mandu-try/"), shown[0]);
    for (const line of shown) {
      // The key the person pressed is echoed after the prompt; the rest is the screen as printed.
      const want = line.replace(/ \[\?\] a$/, " [?]");
      assert.ok(screen.includes(want), `the tour's line is on the screen: ${JSON.stringify(want)}\n--- screen ---\n${screen}`);
    }

    // ── After the rule: secret, and the AI's copy keeps the host and hides the token's value.
    assert.equal((await client.pathLevel(join(ws, fixture))).level, "no-model", `${fixture} is locked by the applied rule`);
    const reg = await client.registerSecret({ path: join(ws, fixture), home });
    assert.ok(reg.symbol, reg.reason);
    const twin = reg.twin;
    assert.equal(typeof twin, "string", `${fixture} has a copy with its lines (not one whole-file placeholder)`);
    noToken("the AI's copy", twin as string);
    const firstLine = files.get(fixture)!.split("\n")[0]!;
    assert.ok((twin as string).includes(firstLine), `the copy keeps ${firstLine}:\n${twin}`);
    assert.match(twin as string, /^token = "\$MDU:\S+"$/m, `the token is a placeholder, in its quotes:\n${twin}`);
  } finally {
    client.close();
    await server.close();
  }
});

test("not vacuous: the tour's same lines in a `.conf` are found by the content tier (secret-discovery.md §2.9), which is why the tour's file is not one (secrets axes)", async () => {
  const files = tourFiles();
  const text = files.get(stepThreeFile())!;
  const dir = mkdtempSync(join(tmpdir(), "mdu-tour-conf-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const ws = join(home, "mandu-try");
  mkdirSync(join(ws, "deploy"), { recursive: true });
  writeFileSync(join(ws, "deploy", "staging.conf"), text);
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPollMs: 0, confidentiality: true, integrity: false, log: () => {},
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  try {
    const report = await client.discoverSecretsReport([home, ws], home);
    const rule = new Map(report.files.map((f) => [f.path, f.rule])).get(join(ws, "deploy", "staging.conf"));
    assert.equal(rule, "content:secret-key", "the content tier finds the token in a .conf");
  } finally {
    client.close();
    await server.close();
  }
});
