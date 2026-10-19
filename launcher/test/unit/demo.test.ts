/**
 * demo.test — `mandu demo` (docs/design/distribution/mandu-demo.md): the sandbox env, the
 * fake project, both agents' wire shapes, the stand-in model and sites, the
 * rendering (plain, verbose, NO_COLOR) and the orchestration over fakes,
 * including a sabotage per check (the e2e, test/component/demo.test.ts, runs
 * the real services).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { request as httpRequest } from "node:http";
import { connect as tlsConnect } from "node:tls";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stateAxes } from "../axes.js";
import {
  basicAuth, BOUND_HOST, cellArgs, claudeAssistantMessage, claudeRequest, claudeToolResult, CMD_READ, CMD_SEND, CMD_USE,
  CODEX_ENVELOPE, codexCell, codexRequest, codexToolOutput, codexTurnItems, codexUserItem, ENV_COMMENT, envFileText, hideSymbols,
  lastToolResultText, makeFakeSecrets, parseClaudeSse, parseCodexSse, policyYaml, PROMPTS, randomTail, readRendering,
  secretForms, symbolsIn, UNBOUND_HOST, unrender, type FakeSecrets,
} from "../../src/demo/fixture.js";
import { longestSockPath, pickTempBase, sandboxEnv, sandboxPaths, sockPathFits, SOCK_PATH_MAX } from "../../src/demo/sandbox.js";
import {
  anthropicTextSse, anthropicToolSse, conversationState, openaiCellSse, openaiTextSse, scriptedAnswer, startStandInModel,
  type Captured, type StandInModel,
} from "../../src/demo/stand-in-model.js";
import { opensslAvailable, routesYaml, startStandInSites, type StandInSites } from "../../src/demo/stand-in-sites.js";
import {
  ANSI, compactLine, pickStyle, PLAIN, sceneLines, summaryLines, type SceneView,
} from "../../src/demo/render.js";
import { demoSigintNote, envRows, parseDemoArgs, runDemo, SERVICE_STOP_MS, stopAndWait, type DemoDeps } from "../../src/demo/demo.js";
import {
  AGENT_RUNNER, agentExeOf, agentGuard, demoHumanPlaneDirs, findDemoGuard, guardedRun, guardServed, parseRunnerOutput, wholeFileWhy,
  type DemoGuardFind, type GuardAbsence,
} from "../../src/demo/guard.js";
import { humanPlaneDirs } from "../../src/human-plane.js";
import { guardPolicyBase } from "../../src/guard-policy-file.js";
import { spawnSync } from "node:child_process";
import { Layout } from "../../src/services/layout.js";

// The demo itself pins `secrets` (sandbox.ts); this suite states the same.
stateAxes("secrets");

const SECRETS: FakeSecrets = { stripeKey: "sk_live_demo_fake_aaaabbbbccccdddd" };
const BASE = "$MDU:nomodel_Read[5627]";
const FIELD = `${BASE}.STRIPE_KEY`;
const TWIN = `STRIPE_KEY='${FIELD}'\nDEBUG=1\n`;
/** What the real model proxy forwards for a shell read of `.env` with no
 *  guard record (plan 10 §11.8): one placeholder for the whole output. */
const WHOLE = "$MDU:nomodel_exec_command[beef]";
const GUARD_BIN = "/opt/mandu/mandu-net-guard";
const AGENT_EXE = "/usr/bin/node";
const PROJECT = "/tmp/mandu-demo-test01/project";

// ── sandbox ──────────────────────────────────────────────────────────────────

test("sandboxEnv: HOME, every XDG root and every Mandu store live in the sandbox", () => {
  const p = sandboxPaths("/tmp/mandu-demo-abc123");
  const env = sandboxEnv({ PATH: "/usr/bin", HOME: "/home/someone" }, p);
  assert.equal(env["HOME"], p.home);
  for (const k of ["XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR", "TMPDIR",
    "MANDU_RUNTIME_DIR", "MANDU_HOME", "MANDU_ARBITER_SOCK", "MANDU_POLICY_FILE"]) {
    assert.ok(env[k]!.startsWith(p.root + "/"), `${k}=${env[k]} is outside the sandbox`);
  }
  // The whole Mandu home moves with MANDU_HOME (on-disk-layout.md §5): its
  // symbol DB and events are the table's, and it holds no config.toml.
  assert.equal(env["MANDU_HOME"], p.manduHome);
  assert.equal(p.symbolDb, `${p.manduHome}/state/mandu.db`);
  assert.equal(p.eventDir, `${p.manduHome}/events`);
  for (const k of ["MANDU_CONFIG", "MANDU_SYMBOL_DB", "MANDU_EVENT_DIR", "MANDU_VIEW_STATE", "MANDU_SECRETS"]) {
    assert.equal(env[k], undefined, `the retired ${k} is not set`);
  }
  assert.equal(env["MANDU_POLICY_FILE"], `${p.manduHome}/policy.yaml`);
  assert.equal(env["MANDU_RUNTIME_DIR"], `${p.run}/mandu`);
  // Every path the demo writes is inside the sandbox too.
  for (const k of ["project", "agentView", "claudeProxyPortFile", "codexProxyPortFile", "netProxyPortFile", "mitmCaDir", "sitesDir", "routesFile", "modelRequests", "replyFile"] as const) {
    assert.ok(p[k].startsWith(p.root + "/"), `${k} is outside the sandbox`);
  }
});

test("sandboxEnv: the mode is pinned to secrets, both as a name and as the axis pair", () => {
  const env = sandboxEnv({ MANDU_MODE: "off", MANDU_INTEGRITY: "1", MANDU_CONFIDENTIALITY: "0" }, sandboxPaths("/tmp/x"));
  assert.equal(env["MANDU_MODE"], "secrets");
  assert.equal(env["MANDU_CONFIDENTIALITY"], "1");
  assert.equal(env["MANDU_INTEGRITY"], "0");
});

test("sandboxEnv: nothing of the caller's Mandu stack, keys, proxies or HOME leaks in; PATH and the terminal do", () => {
  const caller = {
    PATH: "/opt/node/bin:/usr/bin", TERM: "xterm-256color", LANG: "C.UTF-8",
    HOME: "/home/someone", XDG_CONFIG_HOME: "/home/someone/.config",
    MANDU_ARBITER_SOCK: "/run/user/1/mandu/current/arbiter.sock", MANDU_UPSTREAM: "https://evil.example",
    ANTHROPIC_API_KEY: "sk-ant-real", ANTHROPIC_BASE_URL: "http://127.0.0.1:1", CLAUDE_CODE_OAUTH_TOKEN: "tok",
    OPENAI_API_KEY: "sk-real", HTTPS_PROXY: "http://corp:3128", CURL_CA_BUNDLE: "/etc/corp.pem",
  };
  const env = sandboxEnv(caller, sandboxPaths("/tmp/x"));
  assert.equal(env["PATH"], caller.PATH);
  assert.equal(env["TERM"], caller.TERM);
  assert.equal(env["LANG"], caller.LANG);
  for (const k of ["ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_OAUTH_TOKEN", "MANDU_UPSTREAM", "OPENAI_API_KEY", "HTTPS_PROXY", "CURL_CA_BUNDLE"]) {
    assert.equal(env[k], undefined, `${k} must not be inherited`);
  }
  assert.notEqual(env["MANDU_ARBITER_SOCK"], caller.MANDU_ARBITER_SOCK);
  assert.ok(!Object.values(env).some((v) => v.includes("/home/someone")), "no value points into the caller's HOME");
});

test("sandbox socket paths fit sun_path; a long TMPDIR falls back to /tmp", () => {
  assert.ok(sockPathFits(sandboxPaths("/tmp/mandu-demo-abc123").arbiterSock));
  assert.equal(pickTempBase("/tmp"), "/tmp");
  const long = "/tmp/" + "d".repeat(SOCK_PATH_MAX);
  assert.equal(pickTempBase(long), "/tmp");
  assert.equal(sockPathFits("/" + "x".repeat(SOCK_PATH_MAX)), false);
  // The arbiter's human-plane socket (<runtime>/human/<instance id>.sock) is
  // the longest: a base where only run/a.sock would fit falls back too (the
  // arbiter refused to start under such a TMPDIR before 2026-10-05).
  const mid = "/tmp/" + "m".repeat(40);
  assert.ok(sockPathFits(sandboxPaths(`${mid}/mandu-demo-XXXXXX`).arbiterSock));
  assert.equal(sockPathFits(longestSockPath(`${mid}/mandu-demo-XXXXXX`)), false);
  assert.equal(pickTempBase(mid), "/tmp");
  assert.ok(sockPathFits(longestSockPath("/tmp/mandu-demo-XXXXXX")));
  assert.match(longestSockPath("/r"), /^\/r\/run\/mandu\/human\/x{40}\.sock$/);
});

// ── fixture ──────────────────────────────────────────────────────────────────

test("the fake key is fresh per run, visibly fake, and off Stripe's token grammar", () => {
  const a = makeFakeSecrets();
  const b = makeFakeSecrets();
  assert.notEqual(a.stripeKey, b.stripeKey, "a random suffix per run");
  for (const s of [a, b]) {
    assert.match(s.stripeKey, /^sk_live_demo_fake_[a-z2-9]{16}$/);
    // Stripe's live secret key grammar (and gitleaks' stripe rule): a
    // scanner must never flag a recording.
    assert.doesNotMatch(s.stripeKey, /sk_live_[0-9a-zA-Z]{10,}/);
  }
  assert.equal(randomTail(8, () => Buffer.alloc(8, 0)), "aaaaaaaa");
});

test("the .env: a long comment, the key and an ordinary setting (a twin line is no fingerprint, plan 10 §11.8)", () => {
  const text = envFileText(SECRETS);
  assert.equal(text, `${ENV_COMMENT}\nSTRIPE_KEY=${SECRETS.stripeKey}\nDEBUG=1\n`);
  assert.ok(ENV_COMMENT.startsWith("# ") && ENV_COMMENT.length >= 24, "a line the value backstop once fingerprinted");
  assert.ok(!ENV_COMMENT.includes(SECRETS.stripeKey));
});

test("basicAuth and secretForms: the value and the Basic credential curl builds from it", () => {
  assert.equal(basicAuth("k"), `Basic ${Buffer.from("k:").toString("base64")}`);
  assert.deepEqual(secretForms(SECRETS), [SECRETS.stripeKey, Buffer.from(`${SECRETS.stripeKey}:`).toString("base64")]);
});

test("policyYaml binds the project's .env to the Stripe host only", () => {
  const y = policyYaml("/tmp/s/project/.env");
  assert.match(y, /path: "\/tmp\/s\/project\/\.env"/);
  assert.match(y, /level: no-model/);
  assert.match(y, new RegExp(`bindings: \\[${BOUND_HOST.replace(/\./g, "\\.")}\\]`));
  assert.ok(!y.includes(UNBOUND_HOST));
});

test("hideSymbols: a placeholder (and the quotes around it) becomes ‹hidden›; Mandu's notes drop out", () => {
  assert.equal(hideSymbols(TWIN), "STRIPE_KEY=‹hidden›\nDEBUG=1\n");
  assert.equal(hideSymbols(`${BASE}\n\n[mandu:secret] masked: …`), "‹hidden›\n");
  assert.deepEqual(envRows(hideSymbols(TWIN)), ["STRIPE_KEY=‹hidden›", "DEBUG=1"]);
  assert.deepEqual(envRows("# c\n‹hidden›\n"), ["‹hidden›"]);
});

test("readRendering is Claude Code's numbered Read rendering; unrender undoes it", () => {
  assert.equal(readRendering("a\nb\n"), "     1→a\n     2→b");
  assert.equal(readRendering("one"), "     1→one");
  assert.equal(unrender(readRendering(TWIN)), TWIN.trimEnd());
});

test("symbolsIn finds $MDU: tokens, field tails included", () => {
  assert.deepEqual(symbolsIn(`It holds '${FIELD}' and $MDU:Read[abcd].content too, and ${BASE}.`), [FIELD, "$MDU:Read[abcd].content", BASE]);
  assert.deepEqual(symbolsIn("no tokens"), []);
});

// ── Claude Code's wire ───────────────────────────────────────────────────────

test("Claude Code's wire: Messages with Read and Bash, no credential; the stand-in's SSE parses back to the call", () => {
  const req = claudeRequest([{ role: "user", content: PROMPTS[1] }]) as { stream: boolean; tools: Array<{ name: string }>; messages: unknown[] };
  assert.equal(req.stream, true);
  assert.deepEqual(req.tools.map((t) => t.name), ["Read", "Bash"]);
  assert.doesNotMatch(JSON.stringify(req), /api[_-]?key|authorization|bearer/i);

  const read = parseClaudeSse(anthropicToolSse("toolu_1", "Read", { file_path: `${PROJECT}/.env` }));
  assert.deepEqual(read.calls.map((c) => [c.id, c.name, c.filePath]), [["toolu_1", "Read", `${PROJECT}/.env`]]);
  const bash = parseClaudeSse(anthropicToolSse("toolu_2", "Bash", { command: CMD_USE }));
  assert.equal(bash.calls[0]!.command, CMD_USE);
  assert.deepEqual(parseClaudeSse(anthropicTextSse("hi")), { text: "hi", calls: [] });

  // The history the agent sends back: the tool_use, then its tool_result.
  assert.deepEqual(claudeAssistantMessage(read), { role: "assistant", content: [{ type: "tool_use", id: "toolu_1", name: "Read", input: { file_path: `${PROJECT}/.env` } }] });
  assert.deepEqual(claudeToolResult("toolu_1", "x"), { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_1", content: "x" }] });
});

// ── Codex's wire ─────────────────────────────────────────────────────────────

test("Codex's wire (codex-cli ≥ 0.154): the battery as additional_tools, exec cells, the output as an array of text parts", () => {
  const req = codexRequest([codexUserItem(PROMPTS[1])]) as { input: Array<Record<string, unknown>>; tools?: unknown; stream: boolean };
  assert.equal(req.stream, true);
  assert.equal(req.tools, undefined, "no top-level tools: the battery is inlined");
  assert.equal(req.input[0]!["type"], "additional_tools");
  assert.match(JSON.stringify(req.input[0]), /"type":"custom","name":"exec"/);
  assert.doesNotMatch(JSON.stringify(req), /api[_-]?key|authorization|bearer/i);

  const cell = codexCell(CMD_READ, PROJECT);
  assert.equal(cell, `const r = await tools.exec_command(${JSON.stringify({ cmd: CMD_READ, workdir: PROJECT, yield_time_ms: 10000, max_output_tokens: 2000 })});\ntext(r.output);\n`);
  assert.deepEqual(cellArgs(cell), { cmd: CMD_READ, workdir: PROJECT });
  assert.equal(cellArgs("const s = 1;"), null);

  const turn = parseCodexSse(openaiCellSse("call_1", codexCell(CMD_SEND, PROJECT)));
  assert.deepEqual(turn.calls.map((c) => [c.id, c.name, c.command, c.workdir]), [["call_1", "exec", CMD_SEND, PROJECT]]);
  assert.deepEqual(parseCodexSse(openaiTextSse("done")), { text: "done", calls: [] });
  assert.deepEqual(codexTurnItems(turn), [{ type: "custom_tool_call", status: "completed", call_id: "call_1", name: "exec", input: codexCell(CMD_SEND, PROJECT) }]);
  assert.deepEqual(codexToolOutput("call_1", "out"), {
    type: "custom_tool_call_output", call_id: "call_1",
    output: [{ type: "input_text", text: CODEX_ENVELOPE }, { type: "input_text", text: "out" }],
  });
  assert.match(CODEX_ENVELOPE, /^Script completed\nWall time [\d.]+ seconds\nOutput:\n$/);
});

test("lastToolResultText: the last tool result on either wire, Read's gutters and Codex's envelope off", () => {
  const claude = JSON.stringify(claudeRequest([claudeToolResult("t", readRendering(TWIN))]));
  assert.equal(lastToolResultText(claude), TWIN.trimEnd());
  const codex = JSON.stringify(codexRequest([codexToolOutput("c", BASE)]));
  assert.equal(lastToolResultText(codex), BASE);
  assert.equal(lastToolResultText("not json"), null);
  assert.equal(lastToolResultText(JSON.stringify({ messages: [] })), null);
});

// ── stand-in model ───────────────────────────────────────────────────────────

test("conversationState: the scene is the last prompt; a tool result after it means the tool ran", () => {
  const msgs = (...m: unknown[]): string => JSON.stringify(claudeRequest(m));
  assert.deepEqual(conversationState(msgs({ role: "user", content: PROMPTS[1] })), { scene: 1, afterTool: false });
  assert.deepEqual(conversationState(msgs({ role: "user", content: PROMPTS[1] }, claudeToolResult("t", "x"))), { scene: 1, afterTool: true });
  assert.deepEqual(conversationState(msgs({ role: "user", content: PROMPTS[1] }, claudeToolResult("t", "x"), { role: "user", content: PROMPTS[3] })), { scene: 3, afterTool: false });
  assert.deepEqual(conversationState(JSON.stringify(codexRequest([codexUserItem(PROMPTS[2]), codexToolOutput("c", "x")]))), { scene: 2, afterTool: true });
  assert.equal(conversationState(msgs({ role: "user", content: "something else" })), null);
});

test("scriptedAnswer, Claude Code: Read .env, then a reply echoing what the AI was shown; then the two curls", () => {
  const p1 = JSON.stringify(claudeRequest([{ role: "user", content: PROMPTS[1] }]));
  const t1 = parseClaudeSse(scriptedAnswer("anthropic", p1, PROJECT));
  assert.deepEqual(t1.calls.map((c) => [c.name, c.filePath]), [["Read", `${PROJECT}/.env`]]);
  const p2 = JSON.stringify(claudeRequest([{ role: "user", content: PROMPTS[1] }, claudeAssistantMessage(t1), claudeToolResult(t1.calls[0]!.id, readRendering(TWIN))]));
  const t2 = parseClaudeSse(scriptedAnswer("anthropic", p2, PROJECT));
  assert.equal(t2.text, `Your .env sets:\n${TWIN.trimEnd()}`, "the reply names only what the request showed");
  const bash = (k: 2 | 3): string | undefined => parseClaudeSse(scriptedAnswer("anthropic", JSON.stringify(claudeRequest([{ role: "user", content: PROMPTS[k] }])), PROJECT)).calls[0]?.command;
  assert.equal(bash(2), CMD_USE);
  assert.equal(bash(3), CMD_SEND);
});

test("scriptedAnswer, Codex: `cat .env` in the project, a reply without Mandu's note, the same curls", () => {
  const t1 = parseCodexSse(scriptedAnswer("openai", JSON.stringify(codexRequest([codexUserItem(PROMPTS[1])])), PROJECT));
  assert.deepEqual(t1.calls.map((c) => [c.command, c.workdir]), [[CMD_READ, PROJECT]]);
  const after = JSON.stringify(codexRequest([codexUserItem(PROMPTS[1]), ...codexTurnItems(t1), codexToolOutput(t1.calls[0]!.id, `${BASE}\n\n[mandu:secret] masked: the command names a secret file`)]));
  assert.equal(parseCodexSse(scriptedAnswer("openai", after, PROJECT)).text, `Your .env sets:\n${BASE}`);
  assert.equal(parseCodexSse(scriptedAnswer("openai", JSON.stringify(codexRequest([codexUserItem(PROMPTS[2])])), PROJECT)).calls[0]!.command, CMD_USE);
  // CMD_USE / CMD_SEND source the agent's copy and use $STRIPE_KEY: the
  // placeholder rides in curl's argv, the value goes in on the wire.
  assert.match(CMD_USE, /\. \.\/\.env.*curl -sS -u "\$STRIPE_KEY:" https:\/\/api\.stripe\.com\//);
  assert.match(CMD_SEND, /\. \.\/\.env.*curl .*"key=\$STRIPE_KEY" https:\/\/paste\.example\//);
});

function post(origin: string, path: string, body: string): Promise<{ status: number; body: string }> {
  const u = new URL(origin);
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: u.hostname, port: u.port, method: "POST", path }, (res) => {
      let b = ""; res.setEncoding("utf8"); res.on("data", (c) => (b += c)); res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

test("startStandInModel: loopback only, records each body with its wire, answers the two model APIs alone", async () => {
  const m = await startStandInModel(PROJECT);
  try {
    assert.match(m.origin, /^http:\/\/127\.0\.0\.1:\d+$/);
    const a = JSON.stringify(claudeRequest([{ role: "user", content: PROMPTS[2] }]));
    const r1 = await post(m.origin, "/v1/messages", a);
    assert.equal(r1.status, 200);
    assert.equal(parseClaudeSse(r1.body).calls[0]!.command, CMD_USE);
    const o = JSON.stringify(codexRequest([codexUserItem(PROMPTS[3])]));
    const r2 = await post(m.origin, "/v1/responses", o);
    assert.equal(parseCodexSse(r2.body).calls[0]!.command, CMD_SEND);
    assert.deepEqual(m.bodies, [{ wire: "anthropic", body: a }, { wire: "openai", body: o }]);
    assert.equal((await post(m.origin, "/v1/complete", "{}")).status, 404);
    assert.equal(m.bodies.length, 2, "only the two model APIs are recorded");
  } finally {
    await m.close();
  }
});

// ── stand-in sites ───────────────────────────────────────────────────────────

test("routesYaml: a loopback route per stand-in host and a catch-all, all verified against the demo CA", () => {
  const y = routesYaml({ bound: { port: 1001, received: [] }, unbound: { port: 1002, received: [] }, elsewhere: { port: 1003, received: [] }, caPath: "/s/ca.pem" });
  assert.match(y, /- host: "api\.stripe\.com"\n {4}tls_to: "127\.0\.0\.1:1001"/);
  assert.match(y, /- host: "paste\.example"\n {4}tls_to: "127\.0\.0\.1:1002"/);
  assert.match(y, /- host: "\*"\n {4}tls_to: "127\.0\.0\.1:1003"/);
  assert.equal((y.match(/tls_ca: "\/s\/ca\.pem"/g) ?? []).length, 3);
  for (const m of y.matchAll(/(?:tls_)?to: "([^"]+)"/g)) assert.match(m[1]!, /^127\.0\.0\.1:\d+$/, "every route stays on this machine");
});

test("startStandInSites: HTTPS listeners for each host name, recording the request bytes", { skip: !opensslAvailable() && "openssl is not installed" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdemo-sites-"));
  let s: StandInSites | undefined;
  try {
    s = await startStandInSites(join(dir, "sites"));
    const ca = readFileSync(s.caPath, "utf8");
    for (const [host, site] of [[BOUND_HOST, s.bound], [UNBOUND_HOST, s.unbound]] as const) {
      const got = await new Promise<string>((resolve, reject) => {
        const c = tlsConnect({ host: "127.0.0.1", port: site.port, servername: host, ca }, () => {
          c.write(`GET /x HTTP/1.1\r\nHost: ${host}\r\nAuthorization: ${basicAuth("k")}\r\n\r\n`);
        });
        let b = "";
        c.on("data", (d) => { b += d.toString(); if (b.includes("\r\n\r\n")) { c.end(); resolve(b); } });
        c.on("error", reject);
      });
      assert.match(got, /^HTTP\/1\.1 200 OK/);
      assert.equal(site.received.length, 1);
      assert.match(site.received[0]!.head, new RegExp(`Authorization: ${basicAuth("k").replace(/[+/=]/g, "\\$&")}`));
    }
    assert.equal(s.elsewhere.received.length, 0);
  } finally {
    await s?.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── render ───────────────────────────────────────────────────────────────────

const view = (scene: 1 | 2 | 3, ok = true, extra: Partial<SceneView> = {}): SceneView => ({
  scene, ok, verbose: [`the AI's placeholder: ${FIELD}`, "the model received 2 requests (1,234 bytes); none holds the key"],
  ...(scene === 1 ? { aiGot: ["STRIPE_KEY=‹hidden›", "DEBUG=1"], youSee: [`STRIPE_KEY='${SECRETS.stripeKey}'`, "DEBUG=1"] } : {}),
  ...extra,
});

test("sceneLines (plain): the approved layout, in plain words", () => {
  const all = [...sceneLines(view(1), PLAIN, false), ...sceneLines(view(2), PLAIN, false), ...sceneLines(view(3), PLAIN, false)];
  assert.deepEqual(all, [
    " 1  The agent reads .env",
    "      the AI got      STRIPE_KEY=‹hidden›",
    "                      DEBUG=1",
    `      you see         STRIPE_KEY='${SECRETS.stripeKey}'`,
    "                      DEBUG=1",
    " 2  The agent uses the key (curl to api.stripe.com, where it may go)",
    "      sent            api.stripe.com got the real key, filled in on the way out ✓",
    " 3  …and tries to send it somewhere else (paste.example)",
    "      stopped         nothing was sent to paste.example;",
    "                      in a real session the dashboard asks you ✓",
  ]);
  const text = all.join("\n");
  for (const word of ["arbiter", "proxy", "reply filter", "$MDU", "bytes"]) assert.ok(!text.includes(word), `default output names ${word}`);
});

test("sceneLines (verbose): the internals as dimmed · lines; a failure says why in plain words", () => {
  const v = sceneLines(view(1), PLAIN, true).join("\n");
  assert.match(v, /· the AI's placeholder: \$MDU:nomodel_Read\[5627\]\.STRIPE_KEY/);
  assert.match(v, /· the model received 2 requests \(1,234 bytes\)/);
  const bad = sceneLines(view(2, false, { why: "api.stripe.com received nothing" }), PLAIN, false).join("\n");
  assert.match(bad, /✗ failed\s+api\.stripe\.com received nothing/);
  assert.doesNotMatch(bad, /✓/);
  const skipped = sceneLines(view(3, true, { skipped: "this step needs curl, not found" }), PLAIN, false).join("\n");
  assert.match(skipped, /skipped\s+this step needs curl, not found/);
});

test("compactLine + summaryLines: one line for the second agent, one result line, then the pointer to the tour", () => {
  assert.equal(compactLine("codex", [view(1), view(2), view(3)], PLAIN), " 1 · 2 · 3            the same three steps, through Codex  ✓ ✓ ✓");
  const ok = summaryLines({ ok: true, failures: [], skippedNetwork: false }, PLAIN);
  assert.deepEqual(ok, [
    "✓ The AI never got the key. It went only to api.stripe.com, and you saw it.",
    "",
    "Next: try it with your own agent → https://github.com/mandusec/mandu/blob/main/docs/first-session.md",
  ]);
  assert.match(summaryLines({ ok: true, failures: [], skippedNetwork: true }, PLAIN)[0]!, /need curl and openssl/);
  assert.match(summaryLines({ ok: false, failures: ["Codex step 2: x", "y"], skippedNetwork: false }, PLAIN)[0]!, /^✗ FAILED: Codex step 2: x; y$/);
  assert.match(summaryLines({ ok: false, error: "boom", failures: [], skippedNetwork: false }, PLAIN)[0]!, /could not run: boom/);
});

test("pickStyle: color only on a terminal that allows it (NO_COLOR, TERM=dumb, a pipe)", () => {
  assert.equal(pickStyle(false, {}), PLAIN);
  assert.equal(pickStyle(true, { NO_COLOR: "1" }), PLAIN);
  assert.equal(pickStyle(true, { TERM: "dumb" }), PLAIN);
  assert.equal(pickStyle(true, { TERM: "xterm" }), ANSI);
  // PLAIN carries no escape at all.
  assert.ok(!sceneLines(view(1), PLAIN, true).join("").includes("\x1b"));
  assert.ok(sceneLines(view(1), ANSI, true).join("").includes("\x1b["));
});

test("parseDemoArgs: --keep, --verbose/-v, --agent claude|codex (both by default); anything else is a usage error", () => {
  assert.deepEqual(parseDemoArgs([]), { keep: false, verbose: false, agents: ["claude", "codex"] });
  assert.deepEqual(parseDemoArgs(["--keep", "-v", "--agent", "codex"]), { keep: true, verbose: true, agents: ["codex"] });
  assert.deepEqual(parseDemoArgs(["--agent=claude", "--verbose"]), { keep: false, verbose: true, agents: ["claude"] });
  assert.match(parseDemoArgs(["--agent", "goose"]) as string, /--agent takes claude or codex, not 'goose'/);
  assert.match(parseDemoArgs(["--agent"]) as string, /--agent takes claude or codex$/);
  assert.match(parseDemoArgs(["--live"]) as string, /unknown option '--live'/);
});

// ── orchestration ────────────────────────────────────────────────────────────

interface Sabotage {
  /** The model proxy of this wire forwards the real key (a leaking proxy). */
  leak?: "anthropic" | "openai";
  /** The reply filter prints the model's text unchanged. */
  noRestore?: boolean;
  /** The egress proxy does not put the value in at the bound host. */
  noRelease?: boolean;
  /** The egress proxy lets the send to the unbound host through. */
  unboundThrough?: boolean;
  /** The arbiter raises no approval for the refused send. */
  noApproval?: boolean;
  arbiterUp?: boolean;
  proxyStatus?: number;
  tools?: { curl: boolean; openssl: boolean };
  /** The guard found for the run (default: a built guard). */
  guard?: DemoGuardFind;
  /** The guard ran but could not attach: it ran the command unguarded and
   *  wrote no status file (`--skip-unsupported`). */
  guardDegrades?: boolean;
  /** The guard's stand-in printed nothing (the guard failed to set up). */
  guardSetupFails?: boolean;
  /** The model proxy masks Codex's read whole even though the guard served it. */
  wholeUnderGuard?: boolean;
}

interface Fake {
  deps: DemoDeps;
  out: string[];
  started: Array<{ name: string; env: Record<string, string> }>;
  stopped: string[];
  removed: string[];
  files: Map<string, string>;
  rfEnvs: Array<Record<string, string>>;
  cmdEnvs: Array<Record<string, string>>;
  cmdArgvs: string[][];
  modelClosed: () => boolean;
  sitesClosed: () => boolean;
}

const P = sandboxPaths("/tmp/mandu-demo-test01");

function fakeDeps(sab: Sabotage = {}): Fake {
  const out: string[] = [];
  const started: Fake["started"] = [];
  const stopped: string[] = [];
  const removed: string[] = [];
  const files = new Map<string, string>();
  const bodies: Captured[] = [];
  const rfEnvs: Array<Record<string, string>> = [];
  const cmdEnvs: Array<Record<string, string>> = [];
  const cmdArgvs: string[][] = [];
  /** Whether the last `cat .env` ran under a guard that served it. */
  let readGuarded: boolean | null = null;
  let modelClosed = false;
  let sitesClosed = false;
  const approvals: Array<{ id: string; symbol: string; destination: string; status: string; count: number }> = [];
  const sites: StandInSites = {
    bound: { port: 2001, received: [] }, unbound: { port: 2002, received: [] }, elsewhere: { port: 2003, received: [] },
    caPath: `${P.sitesDir}/ca.pem`, close: async () => { sitesClosed = true; },
  };
  const model: StandInModel = { origin: "http://127.0.0.1:4999", bodies, close: async () => { modelClosed = true; } };
  const portOf: Record<string, number> = { "anthropic-proxy": 4321, "openai-proxy": 4322 };
  const deps: DemoDeps = {
    tmpBase: () => "/tmp",
    createSandbox: () => P,
    removeSandbox: (root) => { removed.push(root); },
    writeFile: (path, text) => { files.set(path, text); },
    secrets: () => SECRETS,
    startModel: async (project) => { assert.equal(project, P.project); return model; },
    startSites: async () => sites,
    tools: () => sab.tools ?? { curl: true, openssl: true },
    startService: (name, env) => {
      started.push({ name, env });
      if (name === "anthropic-proxy") files.set(P.claudeProxyPortFile, "4321\n");
      if (name === "openai-proxy") files.set(P.codexProxyPortFile, "4322\n");
      if (name === "net-proxy") { files.set(P.netProxyPortFile, "4400\n"); files.set(`${P.mitmCaDir}/mandu-egress-ca.pem`, "PEM"); }
      return { stop: () => { stopped.push(name); } };
    },
    waitForPath: async (path) => (path === P.arbiterSock ? sab.arbiterUp !== false : files.has(path)),
    readText: (path) => files.get(path) ?? null,
    arbiterCall: async (sock, op) => {
      assert.equal(sock, P.arbiterSock);
      if (op === "registerSecret") return { symbol: BASE, twin: TWIN, reason: "registered" };
      if (op === "egressApprovals") return { approvals: approvals.map((a) => ({ ...a })) };
      throw new Error(`unexpected op ${op}`);
    },
    postModel: async (port, wire, body) => {
      assert.equal(port, wire === "anthropic" ? portOf["anthropic-proxy"] : portOf["openai-proxy"]);
      // The real proxy forwards the agent's copy as it is (placeholders
      // only); a leaking one puts the value back in. A shell read of it
      // reaches the model per key only on the guard's record (plan 10
      // §11.8): without one, one placeholder for the whole output.
      let fwd = sab.leak === wire ? body.split(FIELD).join(SECRETS.stripeKey) : body;
      if (wire === "openai" && (readGuarded === false || sab.wholeUnderGuard)) fwd = fwd.split(JSON.stringify(TWIN)).join(JSON.stringify(WHOLE));
      bodies.push({ wire, body: fwd });
      const status = sab.proxyStatus ?? 200;
      return { status, body: status === 200 ? scriptedAnswer(wire, fwd, P.project) : '{"error":{"type":"mandu_fail_closed"}}' };
    },
    runCommand: async (argv, cwd, env) => {
      assert.equal(cwd, P.agentView, "commands run in the agent's view of the project");
      cmdEnvs.push(env);
      cmdArgvs.push(argv);
      // Unguarded: `sh -c <cmd>`. Under the guard: the guard's wrap, the agent
      // stand-in, the command last; the stand-in answers one JSON line.
      const guarded = argv[0] !== "sh";
      const cmd = argv[argv.length - 1]!;
      if (guarded) {
        if (sab.guardSetupFails) return { code: 71, stdout: "", stderr: "mandu-net-guard: child failed to hand off the listener fd (exit Some(92))" };
        if (!sab.guardDegrades) files.set(env["MANDU_NET_GUARD_STATUS"]!, "exited 0\n");
      }
      if (cmd === CMD_READ) readGuarded = guarded && !sab.guardDegrades;
      const r = await scripted(cmd);
      return guarded
        ? { code: r.code, stdout: JSON.stringify(r), stderr: sab.guardDegrades ? "mandu-net-guard: seccomp connect-trap unavailable — proceeding WITHOUT the IP-aware guard" : "" }
        : r;
    },
    findGuard: () => sab.guard ?? { bin: GUARD_BIN, stale: null },
    agentExe: () => AGENT_EXE,
    readHumanSock: async (sock) => (sock === P.arbiterSock ? "/tmp/mandu-demo-test01/run/mandu/human/i.sock" : null),
    runReplyFilter: async (env, replyFile) => {
      rfEnvs.push(env);
      const reply = files.get(replyFile) ?? "";
      return { code: 0, stdout: sab.noRestore ? reply : reply.split(FIELD).join(SECRETS.stripeKey).split(WHOLE).join(envFileText(SECRETS).trimEnd()), stderr: "" };
    },
    now: () => 0,
    out: (s) => { out.push(s); },
    style: PLAIN,
  };
  /** The agent's three commands, as the real services answer them. */
  async function scripted(cmd: string): Promise<{ code: number; stdout: string; stderr: string }> {
      if (cmd === CMD_READ) return { code: 0, stdout: files.get(`${P.agentView}/.env`) ?? "", stderr: "" };
      if (cmd === CMD_USE) {
        if (!sab.noRelease) sites.bound.received.push({ head: `GET /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nAuthorization: ${basicAuth(SECRETS.stripeKey)}\r\n\r\n`, body: "" });
        return { code: 0, stdout: sab.noRelease ? '{"error":{"type":"mandu_fail_closed"}}' : '{"object":"list","data":[]}', stderr: "" };
      }
      if (cmd === CMD_SEND) {
        if (sab.unboundThrough) {
          sites.unbound.received.push({ head: "POST /new HTTP/1.1\r\nHost: paste.example\r\n\r\n", body: `key=${SECRETS.stripeKey}` });
          return { code: 0, stdout: '{"ok":true}', stderr: "" };
        }
        if (!sab.noApproval) {
          const row = approvals.find((a) => a.destination === UNBOUND_HOST);
          if (row) row.count++;
          else approvals.push({ id: `egr-${approvals.length + 1}`, symbol: FIELD, destination: UNBOUND_HOST, status: "pending", count: 1 });
        }
        return { code: 0, stdout: '{"error":{"type":"mandu_fail_closed","message":"egress withheld 1 symbol(s) → block (fail-closed) [egress:secret-unbound]"}}', stderr: "" };
      }
      throw new Error(`unexpected command ${cmd}`);
  }
  return { deps, out, started, stopped, removed, files, rfEnvs, cmdEnvs, cmdArgvs, modelClosed: () => modelClosed, sitesClosed: () => sitesClosed };
}

const layout = Layout.dev("/repo");

test("runDemo: both agents, the services wired as a launch wires them; three plain scenes, Codex folded; exit 0", async () => {
  const f = fakeDeps();
  const code = await runDemo([], {}, layout, f.deps);
  const text = f.out.join("");
  assert.equal(code, 0, text);
  assert.deepEqual(f.started.map((s) => s.name), ["arbiter", "net-proxy", "anthropic-proxy", "openai-proxy"]);
  const by = (n: string): Record<string, string> => f.started.find((s) => s.name === n)!.env;
  assert.equal(by("arbiter")["MANDU_MODE"], "secrets");
  assert.equal(by("arbiter")["HOME"], P.home);
  // The sandbox's policy binds .env to the Stripe host; the agent's copy is the twin.
  assert.equal(f.files.get(by("arbiter")["MANDU_POLICY_FILE"]!), policyYaml(`${P.project}/.env`));
  assert.equal(f.files.get(`${P.project}/.env`), envFileText(SECRETS));
  assert.equal(f.files.get(`${P.agentView}/.env`), TWIN);
  for (const proxy of ["anthropic-proxy", "openai-proxy"]) {
    assert.equal(by(proxy)["MANDU_UPSTREAM"], "http://127.0.0.1:4999", `${proxy} → the loopback stand-in`);
    assert.equal(by(proxy)["MANDU_PROXY_PORT"], "0");
    assert.equal(by(proxy)["MANDU_ARBITER_SOCK"], P.arbiterSock);
  }
  // The egress proxy: TLS inspection on, routed to the stand-in sites, resolving over the human plane.
  assert.equal(by("net-proxy")["MANDU_NET_PROXY_MITM"], "1");
  assert.equal(by("net-proxy")["MANDU_NET_PROXY_MOCK_SITES"], P.routesFile);
  assert.equal(by("net-proxy")["MANDU_ARBITER_HUMAN_SOCK"], "/tmp/mandu-demo-test01/run/mandu/human/i.sock");
  assert.match(f.files.get(P.routesFile)!, /host: "\*"/);
  // The commands the agent runs go through the session's egress proxy and trust its CA.
  for (const e of f.cmdEnvs) {
    assert.equal(e["HTTPS_PROXY"], "http://127.0.0.1:4400");
    assert.equal(e["CURL_CA_BUNDLE"], `${P.mitmCaDir}/mandu-egress-ca.pem`);
    assert.equal(e["NO_PROXY"], "");
  }
  // The reply filter resolves over the arbiter's HUMAN plane.
  assert.equal(f.rfEnvs[0]!["MANDU_ARBITER_HUMAN_SOCK"], "/tmp/mandu-demo-test01/run/mandu/human/i.sock");
  assert.equal(f.rfEnvs.length, 2, "one reply per agent's scene 1");

  assert.match(text, /^Mandu demo: your agent works with your secrets without ever seeing them$/m);
  assert.match(text, /^Claude Code ─+$/m);
  assert.match(text, /^ {6}the AI got {6}STRIPE_KEY=‹hidden›$/m);
  assert.ok(text.includes(`      you see         STRIPE_KEY='${SECRETS.stripeKey}'`), text);
  assert.match(text, /^Codex ─+\n 1 · 2 · 3 +the same three steps, through Codex {2}✓ ✓ ✓$/m);
  assert.ok(text.trimEnd().endsWith("Next: try it with your own agent → https://github.com/mandusec/mandu/blob/main/docs/first-session.md"), text);
  for (const word of ["arbiter", "proxy", "reply filter", "$MDU", "bytes"]) assert.ok(!text.includes(word), `the default output names ${word}`);
  // Teardown: every service stopped (reverse order), the model and sites closed, the sandbox removed.
  assert.deepEqual(f.stopped, ["openai-proxy", "anthropic-proxy", "net-proxy", "arbiter"]);
  assert.ok(f.modelClosed() && f.sitesClosed());
  assert.deepEqual(f.removed, ["/tmp/mandu-demo-test01"]);
});

test("runDemo --verbose: services, placeholders, requests and the approval row, both agents in full", async () => {
  const f = fakeDeps();
  assert.equal(await runDemo(["--verbose"], {}, layout, f.deps), 0);
  const text = f.out.join("");
  assert.match(text, /· started the protection service \(arbiter\)/);
  assert.match(text, /· started the egress proxy with TLS inspection \(net-proxy\)/);
  assert.match(text, /· started the model-API proxy for Codex \(openai-proxy\)/);
  assert.ok(text.includes(`· the AI's placeholder: ${FIELD}`));
  assert.match(text, /· api\.stripe\.com received 1 request\(s\): Authorization: Basic /);
  assert.match(text, /· Approvals row egr-1: .* → paste\.example, pending, asked 1 time\(s\)/);
  assert.match(text, /· Approvals row egr-1: .*asked 2 time\(s\)/, "Codex's attempt bumps the same row");
  assert.equal((text.match(/^ 1 {2}The agent reads \.env$/gm) ?? []).length, 2, "Codex in full under --verbose");
});

test("runDemo --agent codex: only Codex's proxy starts, shown in full", async () => {
  const f = fakeDeps();
  assert.equal(await runDemo(["--agent", "codex"], {}, layout, f.deps), 0, f.out.join(""));
  assert.deepEqual(f.started.map((s) => s.name), ["arbiter", "net-proxy", "openai-proxy"]);
  const text = f.out.join("");
  assert.doesNotMatch(text, /Claude Code/);
  assert.match(text, /^Codex ─+\n 1 {2}The agent reads \.env$/m);
});

const SABOTAGE: Array<[string, Sabotage, RegExp]> = [
  ["a model proxy that leaks the key (Claude Code)", { leak: "anthropic" }, /Claude Code step 1: the AI received the real key/],
  ["a model proxy that leaks the key (Codex)", { leak: "openai" }, /Codex step 1: the AI received the real key/],
  ["a reply filter that does not restore", { noRestore: true }, /step 1: your screen did not show the real key/],
  ["no release at the bound host", { noRelease: true }, /step 2: api\.stripe\.com received nothing/],
  ["an unbound send that gets through", { unboundThrough: true }, /step 3: paste\.example received the request; no approval was raised for you/],
  ["a refusal with no approval for you", { noApproval: true }, /step 3: no approval was raised for you/],
];

for (const [name, sab, why] of SABOTAGE) {
  test(`runDemo sabotage: ${name} fails the run (exit 1) and says why`, async () => {
    const f = fakeDeps(sab);
    assert.equal(await runDemo([], {}, layout, f.deps), 1, f.out.join(""));
    const text = f.out.join("");
    assert.match(text, why);
    assert.match(text, /✗ FAILED: /);
    assert.match(text, /✗ failed/, "the failed step is marked where it happened");
    assert.deepEqual(f.removed, ["/tmp/mandu-demo-test01"], "cleanup still runs");
  });
}

test("runDemo: no curl or openssl skips steps 2 and 3 in plain words (exit 0), and starts no egress proxy", async () => {
  const f = fakeDeps({ tools: { curl: false, openssl: true } });
  assert.equal(await runDemo(["--agent", "claude"], {}, layout, f.deps), 0);
  const text = f.out.join("");
  assert.match(text, /skipped\s+this step needs curl, not found/);
  assert.match(text, /Steps 2 and 3 need curl and openssl/);
  assert.deepEqual(f.started.map((s) => s.name), ["arbiter", "anthropic-proxy"]);
});

test("runDemo: an arbiter that never starts ends the run cleanly (exit 1, nothing left behind)", async () => {
  const f = fakeDeps({ arbiterUp: false });
  assert.equal(await runDemo([], {}, layout, f.deps), 1);
  assert.match(f.out.join(""), /could not run: the protection service \(arbiter\) did not start/);
  assert.deepEqual(f.started.map((s) => s.name), ["arbiter"], "nothing else starts without an arbiter");
  assert.deepEqual(f.stopped, ["arbiter"]);
  assert.ok(f.modelClosed());
  assert.deepEqual(f.removed, ["/tmp/mandu-demo-test01"]);
});

test("runDemo: the sandbox is removed only after every service's stop has resolved (it has exited)", async () => {
  const f = fakeDeps();
  const order: string[] = [];
  const start = f.deps.startService;
  f.deps.startService = (name, env, log) => {
    const s = start(name, env, log);
    return { stop: async () => { await s.stop(); await new Promise((r) => setTimeout(r, 15)); order.push(`exited ${name}`); } };
  };
  const remove = f.deps.removeSandbox;
  f.deps.removeSandbox = (root) => { order.push("removed"); remove(root); };
  assert.equal(await runDemo([], {}, layout, f.deps), 0);
  assert.equal(order.at(-1), "removed", order.join(", "));
  assert.equal(order.at(-2), "exited arbiter", "the arbiter, started first, is stopped last");
  assert.equal(order.filter((o) => o.startsWith("exited ")).length, f.started.length, "every service exited first");
});

/** A fake service process: `exitsAfter` polls of `exited()` until it is gone (Infinity: never). */
function fakeHandle(exitsAfter: number): { h: Parameters<typeof stopAndWait>[0]; stops: () => number } {
  let polls = 0, stops = 0;
  return {
    h: { pid: 4242, stop: () => { stops++; }, exited: () => (++polls > exitsAfter ? { code: 0, signal: null } : null) },
    stops: () => stops,
  };
}

test("stopAndWait: SIGTERM (stop) once, then resolves when the process has exited, no SIGKILL", async () => {
  const { h, stops } = fakeHandle(3);
  const kills: Array<[number, string]> = [];
  let t = 0;
  await stopAndWait(h, 1_000, { sleep: async (d) => { t += d; }, now: () => t, kill: (p, sig) => { kills.push([p, sig]); } });
  assert.equal(stops(), 1);
  assert.deepEqual(kills, []);
  assert.ok(t > 0 && t < 1_000, `waited ${t} ms`);
});

test("stopAndWait: a service that outlives the budget gets its group SIGKILLed; one with no exit status is only signalled", async () => {
  const { h } = fakeHandle(Infinity);
  const kills: Array<[number, string]> = [];
  let t = 0;
  await stopAndWait(h, 500, { sleep: async (d) => { t += d; }, now: () => t, kill: (p, sig) => { kills.push([p, sig]); } });
  assert.deepEqual(kills, [[-4242, "SIGKILL"]], "the whole group");
  assert.ok(t >= 500 && t <= 500 + 2_000 + 20, `gave up after ${t} ms`);
  let stopped = 0;
  await stopAndWait({ pid: 1, stop: () => { stopped++; } }, 500, { kill: () => assert.fail("no status, no kill") });
  assert.equal(stopped, 1);
  assert.ok(SERVICE_STOP_MS >= 5_000, "a loaded guest's graceful shutdown fits");
});

test("runDemo: a fail-closed model proxy (502) is reported, not papered over", async () => {
  const f = fakeDeps({ proxyStatus: 502 });
  assert.equal(await runDemo([], {}, layout, f.deps), 1);
  assert.match(f.out.join(""), /proxy answered 502/);
});

test("runDemo: --keep keeps the sandbox; an unknown option is a usage error", async () => {
  const f = fakeDeps();
  assert.equal(await runDemo(["--keep"], {}, layout, f.deps), 0);
  assert.deepEqual(f.removed, []);
  assert.match(f.out.join(""), /kept the sandbox: \/tmp\/mandu-demo-test01/);

  const g = fakeDeps();
  const origErr = process.stderr.write.bind(process.stderr);
  let err = "";
  process.stderr.write = ((s: string) => { err += s; return true; }) as typeof process.stderr.write;
  try {
    assert.equal(await runDemo(["--live"], {}, layout, g.deps), 2);
  } finally {
    process.stderr.write = origErr;
  }
  assert.match(err, /unknown option '--live'/);
  assert.deepEqual(g.started, [], "nothing starts on a usage error");
});

// ── the guard around the agent's commands (mandu-demo.md §3 "The guard") ────

test("findDemoGuard: Linux only, the launch's opt-out (MANDU_NET_GUARD=0), the launch's resolver; the stale note rides along", () => {
  const found = (): string => GUARD_BIN;
  assert.deepEqual(findDemoGuard("darwin", {}, found), { absent: "linux-only" });
  assert.deepEqual(findDemoGuard("linux", { MANDU_NET_GUARD: "0" }, found), { absent: "turned-off" });
  assert.deepEqual(findDemoGuard("linux", { MANDU_NET_GUARD: "" }, found, () => null), { bin: GUARD_BIN, stale: null }, "empty is unset, as in parse.ts");
  assert.deepEqual(findDemoGuard("linux", {}, () => null), { absent: "not-built" });
  assert.deepEqual(findDemoGuard("linux", { MANDU_NET_GUARD: "1" }, found, () => null), { bin: GUARD_BIN, stale: null });
  assert.deepEqual(findDemoGuard("linux", {}, found, () => "WARNING: stale"), { bin: GUARD_BIN, stale: "WARNING: stale" });
});

test("wholeFileWhy: one plain line per reason, no internals, fits the recording's 100 columns", () => {
  for (const a of ["linux-only", "not-built", "turned-off", "kernel"] as GuardAbsence[]) {
    const line = wholeFileWhy(a);
    assert.match(line, /^the keys show only under Mandu's guard, /);
    for (const word of ["arbiter", "proxy", "reply filter", "$MDU", "bytes", "seccomp", "net-guard"]) assert.ok(!line.includes(word), `${a}: names ${word}`);
    assert.ok(22 + line.length <= 100, `${a}: ${line.length} chars`);
  }
  assert.match(wholeFileWhy("linux-only"), /Linux only/);
  assert.match(wholeFileWhy("kernel"), /this kernel cannot run/);
});

test("agentGuard: the launch's allow rules, wrap and policy shape, for this agent's session and the registered .env", () => {
  const g = agentGuard({
    bin: GUARD_BIN, agent: "codex", agentExe: AGENT_EXE, session: "mandu-demo-codex", policyPath: `${P.run}/guard-policy-codex.json`,
    modelProxyPort: 4322, netProxyPort: 4400, envPath: `${PROJECT}/.env`, agentEnvPath: `${P.agentView}/.env`,
  });
  // net-guard.ts planNetGuard: the bin, --allow per rule, --skip-unsupported, --.
  assert.equal(g.wrapArgv[0], GUARD_BIN);
  assert.deepEqual(g.wrapArgv.slice(-2), ["--skip-unsupported", "--"]);
  const allows = g.wrapArgv.flatMap((a, i) => (a === "--allow" ? [g.wrapArgv[i + 1]!] : []));
  for (const r of ["tcp:127.0.0.0/8:4322", "tcp:127.0.0.0/8:4400", "tcp:api.openai.com:443"]) assert.ok(allows.includes(r), `missing ${r}: ${allows.join(" ")}`);
  // guard-policy-file.ts's base, plus applySecretTwins's secret entry.
  assert.deepEqual(JSON.parse(g.policy), {
    ...guardPolicyBase({ agentExe: AGENT_EXE, session: "mandu-demo-codex" }),
    secrets: [{ path: `${PROJECT}/.env`, twin: `${P.agentView}/.env`, level: "no-model" }],
  });
  assert.equal(g.env["MANDU_NET_GUARD_SECRETS"], `${P.run}/guard-policy-codex.json`);
  assert.equal(g.env["MANDU_NET_GUARD_PROXY_PORTS"], "4400", "the session's egress proxy, as sessionProxyPorts");
  assert.equal(g.env["MANDU_SESSION_ID"], "mandu-demo-codex");
  assert.equal(g.env["MANDU_ARBITER_HUMAN_SOCK"], undefined, "the guard finds the human plane itself, as in a launch");
  // One command: the wrap, the agent stand-in, the command last; a status file.
  const run = guardedRun(g, AGENT_EXE, CMD_READ, `${P.run}/s`, { PATH: "/usr/bin" });
  assert.deepEqual(run.argv, [...g.wrapArgv, AGENT_EXE, "-e", AGENT_RUNNER, CMD_READ]);
  assert.equal(run.env["MANDU_NET_GUARD_STATUS"], `${P.run}/s`);
  assert.equal(run.env["PATH"], "/usr/bin");
  // Claude Code's guard admits its own model proxy and API host.
  const c = agentGuard({ bin: GUARD_BIN, agent: "claude", agentExe: AGENT_EXE, session: "mandu-demo-claude", policyPath: "/p", modelProxyPort: 4321, netProxyPort: null, envPath: "/e", agentEnvPath: "/t" });
  assert.ok(c.wrapArgv.includes("tcp:api.anthropic.com:443") && c.wrapArgv.includes("tcp:127.0.0.0/8:4321"));
  assert.equal(c.env["MANDU_NET_GUARD_PROXY_PORTS"], "");
});

// arbiter-human-plane.md §5.2 (2026-10-17): the guard believes its human
// socket only in a directory its policy walls off (`unixDeny`), as a launch's
// applyHumanPlaneDeny writes it. Without it the demo's guard reported on the
// data socket and Codex's `.env` read came back one placeholder.
test("agentGuard: the launch's human-plane wall (unixDeny), from the human socket's directory and <runtime>/human", () => {
  const dirs = demoHumanPlaneDirs("/rt/human/i1.sock", "/rt");
  assert.deepEqual(dirs, ["/rt/human"]);
  assert.deepEqual(dirs, humanPlaneDirs("/rt/human/i1.sock", "/rt"), "the launch's own computation");
  assert.deepEqual(demoHumanPlaneDirs("/a/human/i1.sock", "/rt"), ["/a/human", "/rt/human"]);
  assert.deepEqual(demoHumanPlaneDirs("/a/human/i1.sock", undefined), ["/a/human"]);
  assert.deepEqual(demoHumanPlaneDirs(null, undefined), []);
  const g = agentGuard({
    bin: GUARD_BIN, agent: "codex", agentExe: AGENT_EXE, session: "mandu-demo-codex", policyPath: "/p",
    modelProxyPort: 4322, netProxyPort: 4400, envPath: "/e", agentEnvPath: "/t", humanPlaneDirs: dirs,
  });
  assert.deepEqual(JSON.parse(g.policy).unixDeny, ["/rt/human"]);
  const none = agentGuard({ bin: GUARD_BIN, agent: "codex", agentExe: AGENT_EXE, session: "s", policyPath: "/p", modelProxyPort: 1, netProxyPort: null, envPath: "/e", agentEnvPath: "/t", humanPlaneDirs: [] });
  assert.equal(JSON.parse(none.policy).unixDeny, undefined);
});

test("guardServed: only the guard's own record that it supervised the tree", () => {
  assert.equal(guardServed("supervising 10 11\n"), true);
  assert.equal(guardServed("exited 0\n"), true);
  assert.equal(guardServed("exited 3\n"), true);
  assert.equal(guardServed(null), false, "no file: the guard ran the command unguarded (--skip-unsupported)");
  assert.equal(guardServed(""), false);
  assert.equal(guardServed("garbage"), false);
});

test("AGENT_RUNNER: runs the command as `sh -c`, returns its exit, stdout and stderr as one JSON line", () => {
  const r = spawnSync(agentExeOf(), ["-e", AGENT_RUNNER, "echo out; echo err 1>&2; exit 3"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(parseRunnerOutput(r.stdout), { code: 3, stdout: "out\n", stderr: "err\n" });
  assert.equal(parseRunnerOutput(""), null);
  assert.equal(parseRunnerOutput("mandu-net-guard: setup failed"), null);
  assert.equal(parseRunnerOutput('{"code":"0","stdout":"","stderr":""}'), null);
});

test("runDemo under the guard: every agent command runs inside it as the agent's child; Codex's `cat .env` reaches the AI per key; folded", async () => {
  const f = fakeDeps();
  assert.equal(await runDemo([], {}, layout, f.deps), 0, f.out.join(""));
  const text = f.out.join("");
  assert.equal(f.cmdArgvs.length, 5, "Claude Code's two curls, Codex's cat and two curls");
  for (const [i, argv] of f.cmdArgvs.entries()) {
    assert.equal(argv[0], GUARD_BIN, `command ${i} ran without the guard`);
    const at = argv.indexOf("--");
    assert.deepEqual(argv.slice(at + 1, at + 4), [AGENT_EXE, "-e", AGENT_RUNNER]);
    const env = f.cmdEnvs[i]!;
    const policy = JSON.parse(f.files.get(env["MANDU_NET_GUARD_SECRETS"]!)!) as { agentExe: string; session: string; secrets: Array<{ path: string; twin: string }> };
    assert.equal(policy.agentExe, AGENT_EXE);
    assert.equal(policy.session, i < 2 ? "mandu-demo-claude" : "mandu-demo-codex", "the session the agent's model proxy files calls under");
    assert.deepEqual(policy.secrets.map((s) => [s.path, s.twin]), [[`${P.project}/.env`, `${P.agentView}/.env`]]);
    assert.equal(env["HTTPS_PROXY"], "http://127.0.0.1:4400", "and still through the session's egress proxy");
  }
  assert.match(text, /^Codex ─+\n 1 · 2 · 3 +the same three steps, through Codex {2}✓ ✓ ✓$/m);
  assert.doesNotMatch(text, /the whole file/);

  const g = fakeDeps();
  assert.equal(await runDemo(["--agent", "codex", "--verbose"], {}, layout, g.deps), 0, g.out.join(""));
  const v = g.out.join("");
  assert.match(v, /^ {6}the AI got {6}STRIPE_KEY=‹hidden›\n {22}DEBUG=1$/m, "Codex's shell read, per key");
  assert.match(v, /· Mandu's guard \(mandu-net-guard\) runs around the agent's commands: \/opt\/mandu\/mandu-net-guard/);
  assert.match(v, /· ran: cat \.env\n.*· {3}under Mandu's guard \(mandu-net-guard\), which recorded the command's processes/);
});

const ABSENT: Array<[GuardAbsence, Sabotage]> = [
  ["linux-only", { guard: { absent: "linux-only" } }],
  ["not-built", { guard: { absent: "not-built" } }],
  ["turned-off", { guard: { absent: "turned-off" } }],
  ["kernel", { guardDegrades: true }],
];

for (const [why, sab] of ABSENT) {
  test(`runDemo with no guard (${why}): Codex's read is hidden whole and the screen says why in plain words; Codex is not folded; exit 0`, async () => {
    const f = fakeDeps(sab);
    assert.equal(await runDemo([], {}, layout, f.deps), 0, f.out.join(""));
    const text = f.out.join("");
    assert.ok(text.includes(`      the AI got      ‹hidden› (the whole file)\n                      ${wholeFileWhy(why)}\n`), text);
    assert.ok(text.includes(`      you see         STRIPE_KEY='${SECRETS.stripeKey}'`), "you still see the key");
    assert.doesNotMatch(text, /the same three steps, through Codex/, "a different step 1 is not folded into 'the same three steps'");
    assert.equal((text.match(/^ 1 {2}The agent reads \.env$/gm) ?? []).length, 2);
    assert.match(text, /The AI never got the key/);
    for (const word of ["arbiter", "proxy", "reply filter", "$MDU", "bytes"]) assert.ok(!text.includes(word), `the default output names ${word}`);
    // Without a guard bin the commands run as before; a guard that could not
    // attach still wraps them (it ran them unguarded).
    for (const argv of f.cmdArgvs) assert.equal(argv[0], why === "kernel" ? GUARD_BIN : "sh");

    const g = fakeDeps(sab);
    assert.equal(await runDemo(["--agent", "codex", "--verbose"], {}, layout, g.deps), 0);
    assert.match(g.out.join(""), new RegExp(`· {3}without Mandu's guard \\(${why}`));
  });
}

test("runDemo sabotage: the guard served Codex's read but the AI got the whole file: the run FAILS (the demo shows the real thing)", async () => {
  const f = fakeDeps({ wholeUnderGuard: true });
  assert.equal(await runDemo([], {}, layout, f.deps), 1, f.out.join(""));
  const text = f.out.join("");
  assert.match(text, /Codex step 1: the AI got the whole file, not each key, under Mandu's guard/);
  assert.match(text, /✗ failed/);
});

test("runDemo: a guard that cannot set up ends the run (exit 1), never falls back silently", async () => {
  const f = fakeDeps({ guardSetupFails: true });
  assert.equal(await runDemo(["--agent", "codex"], {}, layout, f.deps), 1);
  assert.match(f.out.join(""), /could not run: the agent's command did not run under Mandu's guard \(exit 71: mandu-net-guard: child failed/);
  assert.deepEqual(f.removed, ["/tmp/mandu-demo-test01"]);
});

// ── ^C-safe cleanup (mandu-demo.md §3; teardown-signals.ts) ─────────────────

class FakeSignals extends EventEmitter { readonly pid = 4242; }

test("demoSigintNote: says what is happening and how to end it now", () => {
  const line = demoSigintNote(77);
  assert.match(line, /^mandu demo: cleaning up/);
  assert.match(line, /\^C is ignored until that is done/);
  assert.match(line, /kill 77$/);
});

test("runDemo: a ^C during the normal cleanup is swallowed and the sandbox is still removed", async () => {
  const f = fakeDeps();
  const host = new FakeSignals();
  const notes: string[] = [];
  const exits: number[] = [];
  const seen: number[] = [];
  const pressDuring = (): void => {
    // SIGINT must have a handler at every step of the cleanup (else: the
    // default action, the demo dies and the sandbox stays behind).
    seen.push(host.listenerCount("SIGINT"));
    host.emit("SIGINT");
    host.emit("SIGINT");
  };
  const base = f.deps;
  f.deps = {
    ...base,
    signals: host,
    note: (l) => { notes.push(l); },
    exit: (c) => { exits.push(c); },
    startService: (name, env, log) => {
      const s = base.startService(name, env, log);
      return { stop: () => { pressDuring(); s.stop(); } };
    },
    removeSandbox: (root) => { pressDuring(); base.removeSandbox(root); },
  };
  // While the run is on, the run-time handler is installed for both signals.
  const run = runDemo(["--agent", "claude"], {}, layout, f.deps);
  assert.equal(host.listenerCount("SIGINT"), 1);
  assert.equal(host.listenerCount("SIGTERM"), 1);
  assert.equal(await run, 0, f.out.join(""));
  assert.deepEqual(seen, [1, 1, 1, 1], "a SIGINT handler at each stop and at the removal");
  assert.deepEqual(exits, [], "a ^C during cleanup does not abort it");
  assert.deepEqual(f.stopped, ["anthropic-proxy", "net-proxy", "arbiter"]);
  assert.deepEqual(f.removed, ["/tmp/mandu-demo-test01"]);
  assert.deepEqual(notes, [demoSigintNote(4242)], "one plain line for eight presses");
  assert.match(f.out.join(""), /The AI never got the key/, "the result still prints");
  // Afterwards nothing is left installed (the caller exits).
  assert.equal(host.listenerCount("SIGINT"), 0);
  assert.equal(host.listenerCount("SIGTERM"), 0);
});

test("runDemo: a ^C mid-run aborts it (stop, remove, exit 130); a 2nd ^C during that cleanup is swallowed", async () => {
  const f = fakeDeps();
  const host = new FakeSignals();
  const notes: string[] = [];
  const exits: number[] = [];
  const seen: Array<[number, number]> = [];
  const base = f.deps;
  f.deps = {
    ...base,
    signals: host,
    note: (l) => { notes.push(l); },
    exit: (c) => { exits.push(c); },
    // The ^C lands while the demo waits for the arbiter; the wait never ends
    // (the real exit does not return), so the run is aborted, not finished.
    waitForPath: () => { host.emit("SIGINT"); return new Promise<boolean>(() => {}); },
    removeSandbox: (root) => {
      seen.push([host.listenerCount("SIGINT"), host.listenerCount("SIGTERM")]);
      host.emit("SIGINT");
      base.removeSandbox(root);
    },
  };
  void runDemo([], {}, layout, f.deps);
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(exits, [130], "exit 130 once: the 2nd ^C did not re-enter the abort");
  assert.deepEqual(f.stopped, ["arbiter"]);
  assert.ok(f.modelClosed());
  assert.deepEqual(f.removed, ["/tmp/mandu-demo-test01"]);
  // During the abort's cleanup: SIGINT guarded, SIGTERM back to its default.
  assert.deepEqual(seen, [[1, 0]]);
  assert.deepEqual(notes, [demoSigintNote(4242)]);
});

test("runDemo: SIGTERM mid-run aborts too; --keep keeps the sandbox on that path", async () => {
  const f = fakeDeps();
  const host = new FakeSignals();
  const exits: number[] = [];
  f.deps = {
    ...f.deps,
    signals: host,
    note: () => {},
    exit: (c) => { exits.push(c); },
    waitForPath: () => { host.emit("SIGTERM"); return new Promise<boolean>(() => {}); },
  };
  void runDemo(["--keep"], {}, layout, f.deps);
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(exits, [130]);
  assert.deepEqual(f.stopped, ["arbiter"]);
  assert.deepEqual(f.removed, [], "--keep keeps it");
  assert.equal(host.listenerCount("SIGTERM"), 0, "a 2nd SIGTERM has its default action");
  assert.equal(host.listenerCount("SIGINT"), 1, "SIGINT stays guarded until the exit");
});
