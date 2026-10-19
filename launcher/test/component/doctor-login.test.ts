/**
 * doctor-login e2e — `mandu doctor` through the real CLI entry (a child
 * process: run.ts → runSubcommand → runDoctor with the REAL host probes) answers "is the agent
 * logged in?" (agent-login.ts). An empty HOME shows the missing login and
 * how to log in; a credential file flips the row to found without its
 * contents ever reaching the output. On macOS Claude Code keeps its login in
 * the Keychain, which an existence check cannot see: there the empty-HOME
 * claude row says "cannot tell", never "none found" (packaging.md §7).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCli } from "../lib/run-cli.js";

async function doctorOut(env: Record<string, string | undefined>): Promise<string> {
  const r = await runCli(["doctor"], env);
  assert.equal(r.code, 0, `doctor is a diagnostic: always exits 0\n${r.stderr}`);
  return r.stdout;
}

test("mandu doctor with an empty HOME: the login rows say none found (claude on macOS: cannot tell) and how to log in; a login file flips claude to found", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-doctor-login-"));
  const home = join(dir, "home");
  mkdirSync(home);
  const env = {
    HOME: home,
    PATH: process.env["PATH"],
    MANDU_HOME: join(dir, "mandu-home"),
    XDG_RUNTIME_DIR: dir,
    MANDU_ARBITER_SOCK: join(dir, "absent.sock"),
  };
  try {
    const empty = await doctorOut(env);
    if (process.platform === "darwin") {
      assert.match(empty, /claude login: cannot tell \(Claude Code keeps it in the macOS Keychain\); if it says "Not logged in": run `claude` once without mandu and log in \(or `claude \/login`\), or set ANTHROPIC_API_KEY/);
      assert.doesNotMatch(empty, /claude login: none found/, "a Keychain login is invisible to a file check: never reported missing");
    } else {
      assert.match(empty, /claude login: none found; run `claude` once without mandu and log in \(or `claude \/login`\), or set ANTHROPIC_API_KEY/);
    }
    assert.match(empty, /codex login: none found/);
    assert.match(empty, /run `codex login` once without mandu \(a ChatGPT plan\), or set CODEX_API_KEY \(or OPENAI_API_KEY\) to an OpenAI API key/);

    // Signed in with `codex login` only: a ✓ saying the model proxy relays it
    // (agent-sign-in.md §2.6); the file's contents never reach the output.
    mkdirSync(join(home, ".codex"));
    writeFileSync(join(home, ".codex", "auth.json"), '{"auth_mode":"chatgpt","tokens":{"access_token":"DOCTOR-E2E-CODEX-TOKEN"}}');
    const codexSignedIn = await doctorOut(env);
    assert.match(codexSignedIn, new RegExp(`✓ codex login: signed in \\(${join(home, ".codex", "auth.json").replace(/[.]/g, "\\.")}\\); \`mandu codex\` passes that sign-in through its model proxy`));
    assert.doesNotMatch(codexSignedIn, /DOCTOR-E2E-CODEX-TOKEN/);

    mkdirSync(join(home, ".claude"));
    writeFileSync(join(home, ".claude", ".credentials.json"), '{"claudeAiOauth":"DOCTOR-E2E-SECRET"}');
    const loggedIn = await doctorOut({ ...env, OPENAI_API_KEY: "sk-DOCTOR-E2E-KEY" });
    assert.match(loggedIn, new RegExp(`✓ claude login: found \\(${join(home, ".claude", ".credentials.json").replace(/[.]/g, "\\.")}\\)`));
    assert.match(loggedIn, /✓ codex login: found \(OPENAI_API_KEY\)/);
    assert.doesNotMatch(loggedIn, /DOCTOR-E2E-SECRET|sk-DOCTOR-E2E-KEY|DOCTOR-E2E-CODEX-TOKEN/, "existence checks only: no credential value is printed");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
