/**
 * other-agent-logins.test.ts — another AI agent's login file reads as a
 * placeholder copy inside a launch that does not run that agent, and the
 * launched agent's own login stays raw (secret-discovery.md §1.10).
 *
 * Before (2026-10-09) one global exclusion left every agent's login raw in
 * every launch: a shell launch read `~/.codex/auth.json` (an OpenAI key)
 * raw, and a `mandu codex` launch read `~/.claude.json` (MCP server tokens)
 * raw, neither registered, so nothing recognized the value leaving.
 *
 * The real launcher, a private arbiter in `secrets` (withStack's throwaway
 * HOME), `--no-reply-filter` so stdout is what the AGENT sees, absolute
 * `/bin/cat` past the exec-box shims. Two launches over one HOME:
 *   - `--target shell`: Codex's login reads as the twin (its keys, a
 *     placeholder, never the key); Claude Code's subscription login reads
 *     raw (a `claude` started in a shell launch must log in);
 *   - `--target codex`: the reverse for `~/.claude.json` and
 *     `~/.codex/auth.json`.
 * The dry run (`mandu doctor --secrets --target <agent>`) agrees with each
 * launch.
 *
 * Each launch's agent also sends Codex's token as a Bearer header through
 * the session's HTTP_PROXY (bash's /dev/tcp, plain HTTP) to auth.openai.com,
 * a mock-sites host route to a recording listener. Registration is global
 * and durable: the shell launch registered the token, and before the
 * session's own logins reached its net-proxy (2026-10-10) the codex launch's
 * tripwire refused Codex its own token. Now the shell launch is refused
 * (403, the tripwire: it does not run Codex) and the codex launch gets
 * through (200); the listener sees the codex launch's request only.
 * GATED on Linux + bwrap + an unprivileged userns; zero API budget.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import { join } from "node:path";

import { withStack, runLauncher, probeKernelTier } from "../../lib/launcher-live.js";
import { installExitGuard } from "../../lib/exit-guard.js";
import { stateAxes } from "../../lib/axes.js";
import { doctorSecretsReport } from "../../lib/doctor-secrets-report.js";

installExitGuard("other-agent-logins");

// This suite STATES its axes (protection-modes.md §4): `secrets`. withStack
// brings its private arbiter up in the same mode.
stateAxes("secrets");

const probe = process.platform === "linux" ? probeKernelTier() : null;
const GATE = process.platform !== "linux"
  ? "Linux only (bwrap secret twins)"
  : !probe!.bwrap
    ? "`bwrap` not installed"
    : !probe!.userns
      ? "unprivileged user namespaces unavailable"
      : false;

const CODEX_KEY = "sk-proj-E2EOTHERLOGINCODEX0123456789abcdef";
const OAUTH = "sk-ant-oat01-E2EOTHERLOGINOAUTH0123456789ab";
const MCP_TOKEN = "ghp_E2EOTHERLOGINMCPTOKEN0123456789abcd";

test("LIVE: a shell launch reads Codex's login as a placeholder and Claude Code's raw; a codex launch reads ~/.claude.json as a placeholder and Codex's raw", { skip: GATE, timeout: 300_000 }, async () => {
  await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
    // The recording listener behind the proxy's host route for auth.openai.com.
    const got: string[] = [];
    const listener: Server = createServer((req, res) => {
      req.resume();
      req.on("end", () => { got.push(`${req.headers.host} ${req.headers.authorization ?? ""}`); res.writeHead(200); res.end("ok"); });
    });
    listener.listen(0, "127.0.0.1");
    await once(listener, "listening");
    listener.unref(); // never what keeps the run alive after a failed assertion
    const sites = join(tmp, "mock-sites.yaml");
    writeFileSync(sites, `hosts:\n  - host: auth.openai.com\n    to: 127.0.0.1:${(listener.address() as AddressInfo).port}\n`);
    // The agent's request: Codex's token (as a value it holds), through the
    // session's HTTP_PROXY, by hand so no client of its own is involved.
    const sendScript = join(tmp, "send.sh");
    writeFileSync(sendScript, [
      "p=\"${HTTP_PROXY:-$http_proxy}\"; p=\"${p#http://}\"; p=\"${p%%/*}\"",
      "exec 3<>\"/dev/tcp/${p%:*}/${p##*:}\" || { echo \"$1 STATUS noconnect\"; exit 0; }",
      `printf 'GET http://auth.openai.com/oauth/token HTTP/1.1\\r\\nHost: auth.openai.com\\r\\nAuthorization: Bearer %s\\r\\nConnection: close\\r\\n\\r\\n' '${CODEX_KEY}' >&3`,
      "IFS= read -r line <&3; echo \"$1 STATUS ${line%$'\\r'}\"",
      "",
    ].join("\n"));
    const put = (rel: string, body: string): string => {
      const p = join(home, rel);
      mkdirSync(join(p, ".."), { recursive: true });
      writeFileSync(p, body, { mode: 0o600 });
      return p;
    };
    const codexAuth = put(".codex/auth.json", JSON.stringify({ OPENAI_API_KEY: CODEX_KEY, tokens: null }));
    const claudeCreds = put(".claude/.credentials.json", JSON.stringify({ claudeAiOauth: { accessToken: OAUTH } }));
    const claudeJson = put(".claude.json", JSON.stringify({ mcpServers: { gh: { env: { GITHUB_TOKEN: MCP_TOKEN } } } }));
    const env = { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home, MANDU_NET_PROXY_MOCK_SITES: sites };
    const status = (out: string, tag: string): string | undefined => out.split("\n").find((l) => l.startsWith(`${tag} STATUS `))?.slice(tag.length + 8);
    const read = (tag: string, p: string): string => `echo "BEGIN_${tag}"; /bin/cat ${p}; echo; echo "END_${tag}"`;
    const section = (out: string, tag: string): string => {
      const m = new RegExp(`BEGIN_${tag}\\n([\\s\\S]*?)\\nEND_${tag}`).exec(out);
      return m ? m[1]! : "";
    };
    const args = ["--no-scope", "--no-mcp", "--no-reply-filter"];

    // ── a plain command: Codex's login is a placeholder, Claude Code's raw ──
    const shell = await runLauncher([...args, "--target", "shell", "--", "/bin/bash", "-c", [read("CODEX", codexAuth), read("CREDS", claudeCreds), `/bin/bash ${sendScript} SHELLSEND`].join("; ")], env, workspace, 240_000);
    const diag = `\n--- launch output (tail) ---\n${shell.out.slice(-4000)}`;
    // THE LEAK ORACLE first.
    assert.ok(!shell.out.includes(CODEX_KEY), `CONFIDENTIALITY VIOLATION: Codex's key reached a shell launch raw${diag}`);
    assert.equal(shell.code, 0, `the launch failed${diag}`);
    const codexRead = section(shell.out, "CODEX");
    assert.match(codexRead, /"OPENAI_API_KEY"/, `the twin keeps the file's keys${diag}`);
    assert.match(codexRead, /\$MDU:nomodel_/, `and holds a placeholder${diag}`);
    assert.ok(section(shell.out, "CREDS").includes(OAUTH), `Claude Code's login stays readable in a shell launch (a claude started there logs in with it)${diag}`);
    assert.match(shell.out, /Codex's login, a placeholder copy in this session, which does not run Codex/, `the launch says so${diag}`);
    // The value itself, to Codex's own service, from a session that does
    // not run Codex: the tripwire refuses it, nothing reaches the host.
    assert.match(status(shell.out, "SHELLSEND") ?? "", /^HTTP\/1\.1 403/, `a shell launch is refused Codex's token${diag}`);
    assert.deepEqual(got, [], "auth.openai.com saw nothing from the shell launch");

    // ── mandu codex: ~/.claude.json is a placeholder, Codex's login raw ──
    const codex = await runLauncher([...args, "--target", "codex", "--", "/bin/bash", "-c", [read("CLAUDEJSON", claudeJson), read("CODEXOWN", codexAuth), `/bin/bash ${sendScript} CODEXSEND`].join("; ")], env, workspace, 240_000);
    const diag2 = `\n--- launch output (tail) ---\n${codex.out.slice(-4000)}`;
    assert.ok(!codex.out.includes(MCP_TOKEN), `CONFIDENTIALITY VIOLATION: ~/.claude.json's MCP token reached a codex launch raw${diag2}`);
    assert.equal(codex.code, 0, `the launch failed${diag2}`);
    assert.match(section(codex.out, "CLAUDEJSON"), /"GITHUB_TOKEN":\s*"\$MDU:nomodel_/, `Claude Code's config is a placeholder copy under codex${diag2}`);
    assert.ok(section(codex.out, "CODEXOWN").includes(CODEX_KEY), `Codex's own login stays readable to it${diag2}`);
    // THE BLOCKER (2026-10-10): the shell launch registered this token; the
    // codex launch still sends it to its own service.
    assert.match(status(codex.out, "CODEXSEND") ?? "", /^HTTP\/1\.1 200/, `mandu codex is not refused its own login${diag2}`);
    assert.equal(got.length, 1, `auth.openai.com got the codex launch's request: ${got.join(" | ")}`);
    listener.close();

    // ── the dry run agrees with each launch ──
    for (const [target, confined, raw] of [["shell", codexAuth, claudeCreds], ["codex", claudeJson, codexAuth]] as const) {
      const d = await runLauncher(["doctor", "--secrets", "--json", "--no-history", "--target", target], env, workspace);
      assert.equal(d.code, 0, d.out.slice(-2000));
      const rep = doctorSecretsReport(d.out);
      const files = rep.files.map((f) => f.path);
      assert.ok(files.includes(confined), `doctor --target ${target} lists ${confined}: ${files.join(", ")}`);
      assert.ok(!files.includes(raw), `doctor --target ${target} leaves ${raw} raw`);
      assert.ok(rep.notCovered.skipped.some((s) => s.reason === "agent-login" && s.path === raw), JSON.stringify(rep.notCovered.skipped));
      for (const v of [CODEX_KEY, OAUTH, MCP_TOKEN]) assert.ok(!d.out.includes(v), "the dry run printed a value");
    }
  }, { mode: "secrets" });
});
