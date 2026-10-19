/**
 * goose-delivery.test — E2E: `mandu goose …` through the REAL main(), with a
 * stand-in binary NAMED `goose` that records its argv and env
 * (supported-agents.md §5.6). Proves, for the shapes that launch:
 *   - bare `mandu goose` runs `goose session`;
 *   - the routing env reaches the agent: ANTHROPIC_HOST at the model proxy,
 *     GOOSE_PROVIDER and GOOSE_SUBAGENT_PROVIDER pinned to anthropic; on the
 *     openai provider, both pinned to openai and OPENAI_HOST at the proxy's
 *     /_mandu/openai/openai route, the user's own OPENAI_HOST never reaching
 *     the agent;
 *   - every upload Goose can make past the proxy is forced off even when the
 *     user's env turns it on (PostHog, Langfuse, OTLP, the classifiers;
 *     supported-agents.md §5.3.4 rule 1);
 *   - Mandu's MCP servers mount as `--with-extension 'mandu-inspect:…'` /
 *     `'mandu-policy:…'` right after the subcommand, the inspect server's
 *     model endpoint never the proxy;
 * and for the shapes that do not (serve, gateway, session export, --container,
 * a missing recipe, a sub-recipe, code mode, a provider Mandu does not route in argv, env or
 * config, for the session or its subagents): the launch is REFUSED, the
 * stand-in never runs and a counting upstream sees nothing.
 * The real goose binary's leg (traffic, uploads) is goose-real.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { createServer, type Server } from "node:net";
import { createServer as createHttpServer } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { answerUnavailable } from "../lib/unanswered-arbiter.js";

// Axes: stated per launch (MANDU_MODE: "off"); the delivery is axis-independent.

interface Rig { dir: string; sock: string; upstream: string; hits: () => number; bin: string; report: string }

async function withRig(fn: (r: Rig) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-goose-delivery-"));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  let n = 0;
  const up = createHttpServer((req, res) => { n++; req.resume(); res.writeHead(500); res.end(); });
  up.listen(0, "127.0.0.1");
  await once(up, "listening");
  const upstream = `http://127.0.0.1:${(up.address() as AddressInfo).port}`;
  // The stand-in: a binary named `goose` recording argv and the env keys under test.
  mkdirSync(join(dir, "bin"));
  const bin = join(dir, "bin", "goose");
  const report = join(dir, "goose-report.json");
  writeFileSync(bin, `#!/usr/bin/env node
const fs = require("fs");
fs.writeFileSync(${JSON.stringify(report)}, JSON.stringify({ argv: process.argv.slice(2), env: process.env }));
`, { mode: 0o755 });
  try { await fn({ dir, sock, upstream, hits: () => n, bin, report }); } finally {
    srv.close(); up.close(); rmSync(dir, { recursive: true, force: true });
  }
}

const env = (r: Rig, extra: Record<string, string> = {}) => ({
  HOME: r.dir, PWD: r.dir, MANDU_ARBITER_SOCK: r.sock, PATH: process.env["PATH"], XDG_RUNTIME_DIR: r.dir,
  MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", MANDU_UPSTREAM: r.upstream,
  MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0",
  // a hermetic Goose config home
  GOOSE_PATH_ROOT: join(r.dir, "goose-home"),
  ...extra,
});

async function expectRefused(run: () => Promise<number>, re: RegExp): Promise<void> {
  let err: unknown; let code: number | undefined;
  try { code = await run(); } catch (e) { err = e; }
  assert.ok(err !== undefined, `refused (got exit ${String(code)})`);
  assert.match(String(err), re);
}

/** The user turned every upload on in their own env. */
const UPLOADS_ON = {
  GOOSE_TELEMETRY_ENABLED: "true",
  LANGFUSE_PUBLIC_KEY: "pk-lf-user", LANGFUSE_SECRET_KEY: "sk-lf-user", LANGFUSE_URL: "https://cloud.langfuse.com",
  OTEL_EXPORTER_OTLP_ENDPOINT: "http://otel.corp:4318",
  SECURITY_PROMPT_CLASSIFIER_ENABLED: "true", SECURITY_PROMPT_CLASSIFIER_ENDPOINT: "https://clf.corp/v1",
};

test("bare `mandu goose` runs `goose session` routed at the proxy, every upload forced off, Mandu's MCP servers mounted after the subcommand", async () => {
  await withRig(async (r) => {
    const code = await main(["--no-scope", "--", r.bin], env(r, UPLOADS_ON));
    assert.equal(code, 0);
    const got = JSON.parse(readFileSync(r.report, "utf8")) as { argv: string[]; env: Record<string, string> };
    assert.equal(got.argv[0], "session", "bare goose → goose session");
    // routing
    assert.equal(got.env["ANTHROPIC_HOST"], "http://127.0.0.1:8788");
    assert.equal(got.env["GOOSE_PROVIDER"], "anthropic");
    assert.equal(got.env["GOOSE_SUBAGENT_PROVIDER"], "anthropic");
    assert.equal(got.env["ANTHROPIC_BASE_URL"], undefined);
    // uploads off, whatever the user's env said
    assert.equal(got.env["GOOSE_TELEMETRY_OFF"], "1");
    assert.equal(got.env["GOOSE_TELEMETRY_ENABLED"], "false");
    assert.equal(got.env["LANGFUSE_PUBLIC_KEY"], "");
    assert.equal(got.env["LANGFUSE_SECRET_KEY"], "");
    assert.equal(got.env["OTEL_SDK_DISABLED"], "true");
    assert.equal(got.env["SECURITY_PROMPT_CLASSIFIER_ENABLED"], "false");
    assert.equal(got.env["GOOSE_TOOLSHIM"], "false");
    assert.equal(got.env["GOOSE_STATE_MACHINE"], "false");
    // the U-LLM and policy mounts, in Goose's spelling, right after `session`
    const ext = got.argv.flatMap((a, i) => (got.argv[i - 1] === "--with-extension" ? [a] : []));
    assert.equal(got.argv[1], "--with-extension");
    assert.ok(ext.some((e) => e.startsWith("mandu-inspect:")), JSON.stringify(got.argv));
    assert.ok(ext.some((e) => e.startsWith("mandu-policy:")), JSON.stringify(got.argv));
    const inspect = ext.find((e) => e.startsWith("mandu-inspect:"))!;
    assert.match(inspect, /MANDU_ARBITER_SOCK=/);
    assert.ok(!/ANTHROPIC_BASE_URL=http:\/\/127\.0\.0\.1:8788/.test(inspect), "the quarantine's model channel is never the proxy");
    assert.equal(r.hits(), 0, "a stand-in makes no model call");
  });
});

test("`mandu goose run -t …`: the splice goes after `run`, the user's flags after it", async () => {
  await withRig(async (r) => {
    assert.equal(await main(["--no-scope", "--", r.bin, "run", "--no-session", "-t", "hello"], env(r)), 0);
    const got = JSON.parse(readFileSync(r.report, "utf8")) as { argv: string[] };
    assert.equal(got.argv[0], "run");
    assert.equal(got.argv[1], "--with-extension");
    assert.deepEqual(got.argv.slice(-3), ["--no-session", "-t", "hello"]);
  });
});

test("refused before anything starts: serve, gateway, session export --nostr, --container, a missing recipe, a sub-recipe, code mode", async () => {
  await withRig(async (r) => {
    const cases: Array<[string[], RegExp]> = [
      [["serve"], /refusing `goose serve`/],
      [["gateway", "start"], /refusing `goose gateway`/],
      [["session", "export", "--nostr"], /Nostr relays/],
      [["session", "--container", "c1"], /container/],
      [["run", "--recipe", "missing.yaml"], /recipe file .*missing\.yaml does not exist/],
      [["run", "-t", "x", "--sub-recipe", "s.yaml"], /sub-recipe/],
      [["session", "--with-builtin", "code_execution"], /code mode/],
    ];
    for (const [args, re] of cases) await expectRefused(() => main(["--no-scope", "--", r.bin, ...args], env(r)), re);
    assert.equal(existsSync(r.report), false, "the stand-in goose never ran");
    assert.equal(r.hits(), 0, "nothing reached the upstream");
  });
});

test("the openai provider launches ROUTED: both providers pinned to openai, OPENAI_HOST at the proxy's route, the user's own host kept from the agent", async () => {
  await withRig(async (r) => {
    assert.equal(await main(["--no-scope", "--", r.bin, "run", "--provider", "openai", "-t", "x"], env(r, { OPENAI_HOST: "https://llm.corp.example/openai" })), 0);
    const got = JSON.parse(readFileSync(r.report, "utf8")) as { env: Record<string, string> };
    assert.equal(got.env["GOOSE_PROVIDER"], "openai");
    assert.equal(got.env["GOOSE_SUBAGENT_PROVIDER"], "openai", "a delegate's provider is pinned the same way");
    assert.equal(got.env["OPENAI_HOST"], "http://127.0.0.1:8788/_mandu/openai/openai", "the proxy, never the user's endpoint");
    assert.equal(got.env["OPENAI_BASE_PATH"], "v1/chat/completions", "Goose's default path: it picks the wire per model");
    assert.equal(got.env["GOOSE_TELEMETRY_OFF"], "1", "the upload switches are the same on every provider");
    assert.equal(got.env["OTEL_SDK_DISABLED"], "true");
    assert.equal(r.hits(), 0, "a stand-in makes no model call");
  });
});

test("refused: a provider Mandu does not route, from argv, env or config, for the session or its subagents (the delegate bypass); openai at an endpoint the proxy cannot reach", async () => {
  await withRig(async (r) => {
    await expectRefused(() => main(["--no-scope", "--", r.bin, "run", "--provider", "google", "-t", "x"], env(r)), /--provider names the provider `google`/);
    await expectRefused(() => main(["--no-scope", "--", r.bin], env(r, { GOOSE_PROVIDER: "groq" })), /GOOSE_PROVIDER names the provider `groq`/);
    await expectRefused(() => main(["--no-scope", "--", r.bin], env(r, { GOOSE_SUBAGENT_PROVIDER: "lmstudio" })), /GOOSE_SUBAGENT_PROVIDER names the provider `lmstudio`/);
    await expectRefused(() => main(["--no-scope", "--", r.bin], env(r, { GOOSE_PROVIDER: "openai", OPENAI_HOST: "http://llm.corp.example:8000" })),
      /names the provider `openai`, but the environment's OPENAI_HOST .* is not an endpoint/);
    mkdirSync(join(r.dir, "goose-home", "config"), { recursive: true });
    writeFileSync(join(r.dir, "goose-home", "config", "config.yaml"), "GOOSE_PROVIDER: anthropic\nGOOSE_SUBAGENT_PROVIDER: databricks\nGOOSE_SUBAGENT_MODEL: dbrx\n");
    await expectRefused(() => main(["--no-scope", "--", r.bin], env(r)), /GOOSE_SUBAGENT_PROVIDER in .*config\.yaml names the provider `databricks`/);
    assert.equal(existsSync(r.report), false, "the stand-in goose never ran");
    assert.equal(r.hits(), 0, "nothing reached the upstream");
    // the config's anthropic provider launches
    writeFileSync(join(r.dir, "goose-home", "config", "config.yaml"), "GOOSE_PROVIDER: anthropic\nGOOSE_MODEL: claude-sonnet-4-5\n");
    assert.equal(await main(["--no-scope", "--", r.bin], env(r)), 0);
    assert.ok(existsSync(r.report));
  });
});

test("`mandu goose run --recipe <name>`: goose gets the file the launcher read (absolute) and `--provider anthropic` pinned after `run`", async () => {
  await withRig(async (r) => {
    // a recipe found by name in ./.goose/recipes, as goose's own lookup finds it
    mkdirSync(join(r.dir, ".goose", "recipes"), { recursive: true });
    const file = join(r.dir, ".goose", "recipes", "triage.yaml");
    writeFileSync(file, "version: 1.0.0\ntitle: Triage\ndescription: d\nprompt: triage\nsettings:\n  goose_model: claude-sonnet-4-5\n");
    assert.equal(await main(["--no-scope", "--", r.bin, "run", "--recipe", "triage", "--params", "k=v"], env(r)), 0);
    const got = JSON.parse(readFileSync(r.report, "utf8")) as { argv: string[]; env: Record<string, string> };
    assert.equal(got.argv[0], "run");
    const at = got.argv.indexOf("--provider");
    assert.ok(at > 0 && got.argv[at + 1] === "anthropic", `the provider is pinned: ${JSON.stringify(got.argv)}`);
    assert.equal(got.argv[got.argv.indexOf("--recipe") + 1], file, "goose reads the file Mandu checked");
    assert.deepEqual(got.argv.slice(-2), ["--params", "k=v"]);
    assert.equal(got.env["GOOSE_PROVIDER"], "anthropic");
  });
});

test("refused: a recipe naming another provider, a templated provider, sub_recipes or code mode; the stand-in never runs", async () => {
  await withRig(async (r) => {
    const cases: Array<[string, RegExp]> = [
      ["settings:\n  goose_provider: openai\n", /goose_provider names the provider `openai`/],
      ["settings:\n  goose_provider: \"{{ p }}\"\n", /goose_provider is a template/],
      ["sub_recipes:\n  - name: s\n    path: s.yaml\n", /sub_recipes/],
      ["extensions:\n  - type: builtin\n    name: code_execution\n", /code_execution/],
    ];
    for (const [i, [tail, re]] of cases.entries()) {
      const file = join(r.dir, `bad${i}.yaml`);
      writeFileSync(file, `version: 1.0.0\ntitle: T\ndescription: d\nprompt: p\n${tail}`);
      await expectRefused(() => main(["--no-scope", "--", r.bin, "run", "--recipe", file], env(r)), re);
    }
    assert.equal(existsSync(r.report), false, "the stand-in goose never ran");
    assert.equal(r.hits(), 0, "nothing reached the upstream");
  });
});

test("a RESUMED session (`-r` / `--resume`, session or run): `--provider` pinned to the routed provider, which outranks the provider saved with the session", async () => {
  await withRig(async (r) => {
    const argvOf = (): string[] => (JSON.parse(readFileSync(r.report, "utf8")) as { argv: string[] }).argv;
    const pinned = (argv: string[]): string | undefined => argv[argv.indexOf("--provider") + 1];
    assert.equal(await main(["--no-scope", "--", r.bin, "session", "-r", "--name", "old"], env(r)), 0);
    assert.equal(argvOf()[0], "session");
    assert.equal(pinned(argvOf()), "anthropic");
    assert.equal(await main(["--no-scope", "--", r.bin, "run", "--resume", "-t", "go"], env(r, { GOOSE_PROVIDER: "openai" })), 0);
    assert.equal(pinned(argvOf()), "openai", "an openai launch pins openai");
    assert.equal(await main(["--no-scope", "--", r.bin, "session"], env(r)), 0);
    assert.ok(!argvOf().includes("--provider"), "a new session needs no pin: the env routing holds");
    assert.equal(r.hits(), 0);
  });
});

test("`mandu goose review`: launches with the routing env (its `goose run` children inherit it), no --with-extension splice", async () => {
  await withRig(async (r) => {
    assert.equal(await main(["--no-scope", "--", r.bin, "review", "--model", "claude-sonnet-4-5"], env(r)), 0);
    const got = JSON.parse(readFileSync(r.report, "utf8")) as { argv: string[]; env: Record<string, string> };
    assert.deepEqual(got.argv, ["review", "--model", "claude-sonnet-4-5"]);
    assert.equal(got.env["ANTHROPIC_HOST"], "http://127.0.0.1:8788");
    assert.equal(got.env["GOOSE_PROVIDER"], "anthropic");
    assert.equal(got.env["OTEL_SDK_DISABLED"], "true");
    await expectRefused(() => main(["--no-scope", "--", r.bin, "review", "-s", "dir", "--provider", "google"], env(r)), /--provider names the provider `google`/);
  });
});
