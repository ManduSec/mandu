/**
 * codex-routing.test — E2E: `mandu codex …` through main(), with a stand-in
 * binary NAMED `codex` that records the argv it received. Pins the fix for the
 * routing bypass the fresh-agents VM suite found (os-test-matrix.md §10
 * §14, src/codex-argv.ts): codex 0.154 keeps a separate -c list per command
 * level and the innermost non-empty list replaces the outer ones, so a user's
 * `exec -c …` dropped the launcher's root-level provider override and Codex
 * talked to api.openai.com directly. Also the fail-closed refusal of a user
 * override that re-points the provider: the agent never starts.
 *
 * PROJECT INVARIANT: the model traffic of a routed agent goes through the
 * context proxy, or the launch does not happen.
 */
import { test } from "node:test";
import "../lib/private-home.js"; // daemons' npm cache, the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { launchLogs } from "../lib/launch-log-read.js";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { CODEX_UPLOADS_OFF_OVERRIDES } from "../../src/codex-argv.js";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";

// Axes: stated per launch (MANDU_MODE: "off"); routing is axis-independent.

async function withStandInCodex(fn: (dir: string, sock: string, codex: string, argvFile: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-codex-e2e-"));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  const argvFile = join(dir, "argv.json");
  const codex = join(dir, "codex");
  writeFileSync(codex, `#!/usr/bin/env node\nrequire("fs").writeFileSync(${JSON.stringify(argvFile)}, JSON.stringify(process.argv.slice(2)));\n`, { mode: 0o755 });
  try { await fn(dir, sock, codex, argvFile); } finally {
    srv.close(); rmSync(dir, { recursive: true, force: true });
  }
}

// XDG_RUNTIME_DIR: the scope run dir lands in the test's own dir, not the
// shared /tmp/mandu/<scope> (test-organization.md §8.4). CODEX_HOME: the
// test's own (empty unless a test writes an auth.json), never the host's
// `codex login`. A model session needs a key variable or a sign-in under
// mandu (agent-login.ts codexKeyRefusal), so `keyed` adds a test-only key.
const env = (dir: string, sock: string, extra: Record<string, string> = {}) => ({
  HOME: process.env["HOME"], PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], CODEX_HOME: join(dir, "codex-home"),
  MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: dir, ...extra,
});
const keyed = (dir: string, sock: string) => env(dir, sock, { OPENAI_API_KEY: "sk-test-only" });

/** The provider (and its env_key) each command level would resolve to, read
 *  the way codex 0.154 does: per level, the last -c for a key wins, and the
 *  innermost level with ANY -c replaces the outer levels' lists. */
function effectiveProvider(argv: string[]): { provider?: string; envKey?: string; signIn?: boolean } {
  const levels: string[][] = [[]];
  const subs = new Set(["exec", "e", "resume", "fork", "review"]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "-c") { levels[levels.length - 1]!.push(argv[++i]!); continue; }
    if (subs.has(a)) levels.push([]);
  }
  const active = [...levels].reverse().find((l) => l.length > 0) ?? [];
  let provider: string | undefined, envKey: string | undefined, signIn: boolean | undefined;
  for (const kv of active) {
    if (kv.startsWith("model_provider=")) provider = kv.slice("model_provider=".length);
    const m = /env_key="([^"]+)"/.exec(kv);
    if (m) envKey = m[1];
    if (kv.startsWith("model_providers.")) signIn = /requires_openai_auth=true/.test(kv);
  }
  return { provider, envKey, signIn };
}

test("a user's exec-level -c keeps the Mandu provider in force (the routing survives)", async () => {
  await withStandInCodex(async (dir, sock, codex, argvFile) => {
    const code = await main(
      ["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, "exec", "-c", "model_reasoning_effort=low", "--skip-git-repo-check", "hi"],
      keyed(dir, sock),
    );
    assert.equal(code, 0);
    const got = JSON.parse(readFileSync(argvFile, "utf8")) as string[];
    const execAt = got.indexOf("exec");
    assert.ok(execAt > 0, `exec present: ${JSON.stringify(got)}`);
    assert.ok(got.slice(execAt + 1).includes("model_provider=mandu"), "the provider override is repeated at the exec level");
    assert.equal(effectiveProvider(got).provider, "mandu", `effective provider under codex's -c rules: ${JSON.stringify(got)}`);
    assert.ok(got.includes("model_reasoning_effort=low"), "the user's own override is kept");
    assert.equal(got[got.length - 1], "hi", "the prompt stays last");
  });
});

test("exec resume -c: the innermost level holds the Mandu provider too", async () => {
  await withStandInCodex(async (dir, sock, codex, argvFile) => {
    const code = await main(
      ["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, "exec", "resume", "-c", "model=q", "--last", "hi"],
      keyed(dir, sock),
    );
    assert.equal(code, 0);
    const got = JSON.parse(readFileSync(argvFile, "utf8")) as string[];
    assert.equal(effectiveProvider(got).provider, "mandu", JSON.stringify(got));
  });
});

test("a user -c that re-points the model provider is REFUSED: the agent never starts", async () => {
  await withStandInCodex(async (dir, sock, codex, argvFile) => {
    // `-c=kv`: clap strips one `=` from an attached short value, so Codex
    // reads it as `model_provider=openai` (review 2026-10-02)
    for (const bad of [["exec", "-c", "model_provider=openai", "hi"], ["--oss", "exec", "hi"], ["-c=model_provider=openai", "exec", "hi"]]) {
      let err: unknown;
      let code: number | undefined;
      try { code = await main(["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, ...bad], env(dir, sock)); }
      catch (e) { err = e; }
      assert.ok(err !== undefined || (code !== undefined && code !== 0), `refused: ${bad.join(" ")}`);
      if (err !== undefined) assert.match(String(err), /refusing to launch codex/);
      assert.equal(existsSync(argvFile), false, "the stand-in codex never ran");
    }
  });
});

test("Codex's own uploads are off at every command level of the launched argv; a user override that turns one back on, and `codex cloud`, are REFUSED", async () => {
  await withStandInCodex(async (dir, sock, codex, argvFile) => {
    const code = await main(
      ["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, "exec", "-c", "model=q", "resume", "--last", "hi"],
      keyed(dir, sock),
    );
    assert.equal(code, 0);
    const got = JSON.parse(readFileSync(argvFile, "utf8")) as string[];
    // Root, exec and exec resume: each level's own -c list carries every switch.
    for (const kv of CODEX_UPLOADS_OFF_OVERRIDES.filter((t) => t !== "-c")) {
      assert.equal(got.filter((t) => t === kv).length, 3, `${kv} at every level: ${JSON.stringify(got)}`);
    }
    assert.equal(effectiveProvider(got).provider, "mandu", "the routing is intact");
    assert.ok(!got.includes("features.connectors=false"), "no legacy key in the user's config: none forced (Codex would print a deprecation notice)");
  });
  // A user config naming the legacy `connectors` key (which would turn apps
  // back on after `apps = false`): the launch forces it off too, at every level.
  await withStandInCodex(async (dir, sock, codex, argvFile) => {
    const { mkdirSync } = await import("node:fs");
    mkdirSync(join(dir, "codex-home"));
    writeFileSync(join(dir, "codex-home", "config.toml"), "[features]\nconnectors = true\n");
    const code = await main(["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, "exec", "hi"], keyed(dir, sock));
    assert.equal(code, 0);
    const got = JSON.parse(readFileSync(argvFile, "utf8")) as string[];
    assert.equal(got.filter((t) => t === "features.connectors=false").length, 2, JSON.stringify(got));
  });
  await withStandInCodex(async (dir, sock, codex, argvFile) => {
    for (const bad of [["exec", "-c", "features.apps=true", "hi"], ["--enable", "apps"], ["exec", "-c", "otel.exporter={otlp-http={endpoint=\"http://c\",protocol=\"json\"}}", "hi"], ["cloud", "exec", "hi"]]) {
      let err: unknown;
      let code: number | undefined;
      try { code = await main(["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, ...bad], keyed(dir, sock)); }
      catch (e) { err = e; }
      assert.ok(err !== undefined || (code !== undefined && code !== 0), `refused: ${bad.join(" ")}`);
      if (err !== undefined) assert.match(String(err), /refusing to launch codex/);
      assert.equal(existsSync(argvFile), false, "the stand-in codex never ran");
    }
  });
});

test("CODEX_API_KEY alone: the routed provider reads CODEX_API_KEY (Codex would otherwise refuse with OPENAI_API_KEY missing)", async () => {
  await withStandInCodex(async (dir, sock, codex, argvFile) => {
    const code = await main(["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, "exec", "hi"], env(dir, sock, { CODEX_API_KEY: "sk-test-only" }));
    assert.equal(code, 0);
    assert.equal(effectiveProvider(JSON.parse(readFileSync(argvFile, "utf8"))).envKey, "CODEX_API_KEY");
  });
  await withStandInCodex(async (dir, sock, codex, argvFile) => {
    const code = await main(["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, "exec", "hi"], env(dir, sock, { OPENAI_API_KEY: "sk-test-only", CODEX_API_KEY: "sk-other" }));
    assert.equal(code, 0);
    assert.equal(effectiveProvider(JSON.parse(readFileSync(argvFile, "utf8"))).envKey, "OPENAI_API_KEY", "OPENAI_API_KEY wins when both are set");
  });
});

test("signed in with `codex login` only, no key variable: the session launches on the sign-in provider (relayed by the proxy); the file is never read", async () => {
  // agent-sign-in.md §2.4 item 1: with no key variable the routed
  // provider is `requires_openai_auth=true` and has no env_key, at every
  // command level, so codex sends its own sign-in to the model proxy.
  await withStandInCodex(async (dir, sock, codex, argvFile) => {
    const { mkdirSync } = await import("node:fs");
    mkdirSync(join(dir, "codex-home"));
    const auth = '{"auth_mode":"chatgpt","tokens":{"access_token":"E2E-CODEX-TOKEN-NOT-PRINTED"}}';
    writeFileSync(join(dir, "codex-home", "auth.json"), auth);
    for (const run of [["exec", "hi"], [], ["exec", "resume", "-c", "model=q", "--last", "hi"]]) {
      const { code, notes } = await mainCapturingNotes(["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, ...run], env(dir, sock));
      assert.equal(code, 0, `launched: codex ${run.join(" ")}`);
      const got = JSON.parse(readFileSync(argvFile, "utf8")) as string[];
      rmSync(argvFile);
      const eff = effectiveProvider(got);
      assert.deepEqual([eff.provider, eff.signIn, eff.envKey], ["mandu", true, undefined], JSON.stringify(got));
      assert.ok(got.some((a) => a.includes("supports_websockets=false")), "HTTP SSE, which the proxy parses");
      assert.doesNotMatch(notes, /E2E-CODEX-TOKEN-NOT-PRINTED/);
      assert.doesNotMatch(notes, /no Codex login found/);
    }
    assert.equal(readFileSync(join(dir, "codex-home", "auth.json"), "utf8"), auth, "the sign-in file is untouched");
    // A key variable wins: env_key, no sign-in shape.
    const code = await main(["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, "exec", "hi"], keyed(dir, sock));
    assert.equal(code, 0);
    const eff = effectiveProvider(JSON.parse(readFileSync(argvFile, "utf8")));
    assert.deepEqual([eff.signIn, eff.envKey], [false, "OPENAI_API_KEY"]);
  });
});

test("the user's own server (MANDU_OPENAI_BASE_URL) with only a sign-in: refused before codex starts; the sign-in never goes there", async () => {
  await withStandInCodex(async (dir, sock, codex, argvFile) => {
    const { mkdirSync } = await import("node:fs");
    mkdirSync(join(dir, "codex-home"));
    writeFileSync(join(dir, "codex-home", "auth.json"), '{"tokens":{"access_token":"E2E-CODEX-TOKEN-NOT-PRINTED"}}');
    let err: unknown;
    try {
      await main(["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, "exec", "hi"],
        env(dir, sock, { MANDU_OPENAI_BASE_URL: "http://127.0.0.1:9/v1" }));
    } catch (e) { err = e; }
    assert.match(String(err), /refusing to start Codex: MANDU_OPENAI_BASE_URL points it at your own model server/);
    assert.doesNotMatch(String(err), /E2E-CODEX-TOKEN-NOT-PRINTED/);
    assert.equal(existsSync(argvFile), false, "the stand-in codex never ran");
  });
});

test("no key variable and no sign-in: a model session is refused naming both fixes; `codex login` still runs", async () => {
  await withStandInCodex(async (dir, sock, codex, argvFile) => {
    let err: unknown;
    try { await main(["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, "exec", "hi"], env(dir, sock)); }
    catch (e) { err = e; }
    assert.match(String(err), /refusing to start Codex: it has no sign-in and no OpenAI API key/);
    assert.match(String(err), /run `codex login`.*CODEX_API_KEY/);
    assert.equal(existsSync(argvFile), false);
    for (const run of [["login"], ["--version"]]) {
      const code = await main(["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, ...run], env(dir, sock));
      assert.equal(code, 0, run.join(" "));
      assert.ok(existsSync(argvFile), `the stand-in ran: codex ${run.join(" ")}`);
      rmSync(argvFile);
    }
  });
});

/** Run main() with console.error captured, and the launch's own log (the
 *  launch notes' channels: the default display prints a banner and a short
 *  line per warning, the log holds every note in full; packaging.md §5). */
async function mainCapturingNotes(args: string[], e: Record<string, string | undefined>): Promise<{ code: number; notes: string }> {
  const orig = console.error;
  let notes = "";
  const before = launchLogs(e);
  console.error = (...a: unknown[]) => { notes += a.map(String).join(" ") + "\n"; };
  try {
    const code = await main(args, e);
    return { code, notes: notes + before.newLines().map((l) => l + "\n").join("") };
  } finally { console.error = orig; }
}

test("a wrapper under --target codex still receives the routing (after argv[0]): the codex it runs stays routed", async () => {
  await withStandInCodex(async (dir, sock, _codex, argvFile) => {
    const wrapper = join(dir, "my-codex-wrapper");
    writeFileSync(wrapper, `#!/usr/bin/env node\nrequire("fs").writeFileSync(${JSON.stringify(argvFile)}, JSON.stringify(process.argv.slice(2)));\n`, { mode: 0o755 });
    const { code, notes } = await mainCapturingNotes(["--target", "codex", "--no-scope", "--no-reply-filter", "--", wrapper, "exec", "hi"], env(dir, sock));
    assert.equal(code, 0);
    const got = JSON.parse(readFileSync(argvFile, "utf8")) as string[];
    assert.deepEqual(got.slice(0, 2), ["-c", "model_provider=mandu"], JSON.stringify(got));
    assert.deepEqual(got.slice(-2), ["exec", "hi"], "the wrapper's own arguments follow, untouched");
    assert.doesNotMatch(notes, /is a shell, not codex/);
  });
});

/** A stand-in `codex` that answers the launcher's version probe as
 *  `version` and records every other argv. */
function versionedStandIn(codex: string, argvFile: string, version: string): void {
  writeFileSync(codex, `#!/usr/bin/env node\nconst a = process.argv.slice(2);\nif (a[0] === "--version") { console.log(${JSON.stringify(`codex-cli ${version}`)}); process.exit(0); }\nrequire("fs").writeFileSync(${JSON.stringify(argvFile)}, JSON.stringify(a));\n`, { mode: 0o755 });
}

test("codex 0.159.1: the launch asks for embedded mode (--no-daemon) at the levels that take it, the routing intact", async () => {
  await withStandInCodex(async (dir, sock, codex, argvFile) => {
    versionedStandIn(codex, argvFile, "0.159.1");
    const run = async (argv: string[]): Promise<string[]> => {
      rmSync(argvFile, { force: true });
      const code = await main(["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, ...argv], keyed(dir, sock));
      assert.equal(code, 0, argv.join(" "));
      return JSON.parse(readFileSync(argvFile, "utf8")) as string[];
    };
    const tui = await run(["hi"]);
    assert.equal(tui.filter((t) => t === "--no-daemon").length, 1, JSON.stringify(tui));
    assert.equal(effectiveProvider(tui).provider, "mandu");
    assert.equal(tui.at(-1), "hi");
    const resume = await run(["resume", "--no-daemon", "--last"]);
    const at = resume.indexOf("resume");
    assert.equal(resume.slice(0, at).filter((t) => t === "--no-daemon").length, 1, `root: ours: ${JSON.stringify(resume)}`);
    assert.equal(resume.slice(at).filter((t) => t === "--no-daemon").length, 1, "resume: the user's only, never twice");
    const exec = await run(["exec", "hi"]);
    assert.ok(!exec.slice(exec.indexOf("exec")).includes("--no-daemon"), `exec rejects the flag: ${JSON.stringify(exec)}`);
    assert.equal(effectiveProvider(exec).provider, "mandu");
  });
});

test("a Codex whose version is older or unread gets no --no-daemon (it would refuse to start)", async () => {
  await withStandInCodex(async (dir, sock, codex, argvFile) => {
    versionedStandIn(codex, argvFile, "0.154.0");
    assert.equal(await main(["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, "hi"], keyed(dir, sock)), 0);
    const got = JSON.parse(readFileSync(argvFile, "utf8")) as string[];
    assert.ok(!got.includes("--no-daemon"), JSON.stringify(got));
    assert.equal(effectiveProvider(got).provider, "mandu", "still routed");
  });
});

test("--remote and `codex agents` are REFUSED: they attach to a Codex server Mandu did not start; the agent never starts", async () => {
  await withStandInCodex(async (dir, sock, codex, argvFile) => {
    versionedStandIn(codex, argvFile, "0.159.1");
    for (const bad of [["--remote", "unix://"], ["resume", "--remote=ws://127.0.0.1:1", "--last"], ["agents"]]) {
      let err: unknown;
      let code: number | undefined;
      try { code = await main(["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, ...bad], keyed(dir, sock)); }
      catch (e) { err = e; }
      assert.ok(err !== undefined || (code !== undefined && code !== 0), `refused: ${bad.join(" ")}`);
      if (err !== undefined) assert.match(String(err), /refusing to launch codex with .*Mandu did not start/);
      assert.equal(existsSync(argvFile), false, "the stand-in codex never ran");
    }
  });
});

test("the Codex server subcommands are REFUSED before launch (remote-control, app-server, exec-server, debug app-server); near-misses launch routed", async () => {
  await withStandInCodex(async (dir, sock, codex, argvFile) => {
    versionedStandIn(codex, argvFile, "0.159.1");
    for (const bad of [
      ["remote-control", "start"], ["remote-control"], ["app-server", "daemon", "start"], ["app-server", "--listen", "unix://"],
      ["exec-server", "--listen", "ws://127.0.0.1:1"], ["debug", "app-server", "send-message-v2", "hi"],
    ]) {
      let err: unknown;
      let code: number | undefined;
      try { code = await main(["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, ...bad], keyed(dir, sock)); }
      catch (e) { err = e; }
      assert.ok(err !== undefined || (code !== undefined && code !== 0), `refused: ${bad.join(" ")}`);
      if (err !== undefined) assert.match(String(err), new RegExp(`refusing to launch codex with \`codex ${bad[0] === "debug" ? "debug app-server" : bad[0]}\``));
      assert.equal(existsSync(argvFile), false, `the stand-in codex never ran: ${bad.join(" ")}`);
    }
    for (const ok of [["exec", "app-server"], ["debug", "models"], ["start the app-server please"]]) {
      rmSync(argvFile, { force: true });
      assert.equal(await main(["--target", "codex", "--no-scope", "--no-reply-filter", "--", codex, ...ok], keyed(dir, sock)), 0, ok.join(" "));
      const got = JSON.parse(readFileSync(argvFile, "utf8")) as string[];
      assert.equal(effectiveProvider(got).provider, "mandu", `still routed: ${ok.join(" ")}`);
      assert.equal(got.at(-1), ok.at(-1));
    }
  });
});

test("a POSIX shell under --target codex gets NO codex option: the user's script runs, and the launch says codex from it is not routed", async () => {
  await withStandInCodex(async (dir, sock, _codex, argvFile) => {
    // Before the fix the shell took `-c model_provider=…` as its script, so
    // this script never ran and argvFile was never written.
    const script = `printf '%s\\n' "$0" "$@" > ${JSON.stringify(argvFile)}`;
    const { code, notes } = await mainCapturingNotes(["--target", "codex", "--no-scope", "--no-reply-filter", "--", "/bin/sh", "-c", script, "zero", "a b"], env(dir, sock));
    assert.equal(code, 0);
    assert.equal(readFileSync(argvFile, "utf8"), "zero\na b\n", "the shell ran the user's script with the user's arguments");
    assert.match(notes, /'sh' is a shell, not codex/);
    assert.match(notes, /WARNING: a codex started from it is NOT routed through Mandu/);
  });
});
