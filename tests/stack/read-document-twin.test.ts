/**
 * read-document-twin — plan 10 §11.8, "A document's own twin", the read leg
 * (2026-10-12), over the REAL components: a built-in read of a labelled
 * document that the agent was served as its whole-file twin reaches the
 * model as the document's OWN base token, for Claude Code's `Read`,
 * OpenClaw's `read` and OpenCode's `read` (1 and 2), through the real
 * arbiter and the real anthropic-proxy over HTTP in its production wiring.
 * Goose has no read tool (it reads with `shell`): its `cat` takes the shell
 * leg of the same rule (!1422), checked here too.
 *
 * Before: under `secrets` the rendering was symbolized as a NEW row
 * (`$MDU:anymodel_Read[new]`) whose value was the twin token: a token for a
 * token.
 *
 * Negatives, each still masked whole (a new symbol, the document's token not
 * shown): the raw document; a rendering with any other line or byte; two
 * tokens; a CRLF byte after a LF file's token; another document's token read
 * at this path; the token of an older registration of the same path; an
 * offset read whose line number is not 1; OpenClaw's and OpenCode's read
 * with a byte beside the token, or the token read at another path.
 *
 * THE ORACLE: no request to the model carries a byte of either document.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const DOC_CANARY = "READ_DOC_TWIN_CANARY_1979";
const PLAN_CANARY = "READ_PLAN_TWIN_CANARY_1984";
const STRIPE = "sk_live_read_doc_twin_0123456789";
const CANARIES = [DOC_CANARY, PLAN_CANARY, STRIPE, "Deal brief", "Plan B"];
const SYMBOL_ONLY = /^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]$/;

function post(port: number, body: string, session: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

const claudeRead = (token: string): string => `     1\t${token}\n`;
const opencode1 = (path: string, token: string): string => [`<path>${path}</path>`, "<type>file</type>", "<content>", `1: ${token}`, "", "(End of file - total 1 lines)", "</content>"].join("\n");
const opencode2 = (path: string, token: string): string => [`Read file ${path}, lines 1-1`, `1: ${token}`].join("\n");

test("a built-in read of a labelled document's whole-file twin reaches the model as the document's own token (Claude Code, OpenClaw, OpenCode 1 and 2; Goose's shell); every other shape stays masked whole; no document byte reaches the model (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-read-doc-twin-"));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "memo"), { recursive: true });
  const brief = join(ws, "memo", "brief.md");
  const plan = join(ws, "memo", "plan.md");
  const env = join(ws, ".env");
  writeFileSync(brief, `Deal brief. Reference code: ${DOC_CANARY}.\n`);
  writeFileSync(plan, `Plan B. Codeword ${PLAN_CANARY}.\n`);
  writeFileSync(env, `PORT=3000\nSTRIPE_KEY=${STRIPE}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, ["version: 1", "paths:", `  - path: ${brief}`, "    level: any-model", "    bindings: [example.com]", `  - path: ${plan}`, "    level: no-model", ""].join("\n"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const real = await open(socketPath);
  const guard = await open(humanPath);
  const proxies: AnthropicProxy[] = [];
  const seen: string[] = [];
  try {
    // An OLD registration of the brief (an earlier text), then the launch's
    // own (registerSecret as secret-setup.ts calls it: no session key).
    writeFileSync(brief, `Deal brief, draft. Reference code: ${DOC_CANARY}.\n`);
    const old = String((await real.registerSecret({ path: brief })).symbol);
    writeFileSync(brief, `Deal brief. Reference code: ${DOC_CANARY}.\n`);
    const reg = await real.registerSecret({ path: brief });
    const tok = String(reg.symbol);
    assert.match(tok, /^\$MDU:anymodel_Read\[[0-9a-f]{4,8}\]$/, JSON.stringify(reg));
    assert.notEqual(tok, old, "two registrations, two base rows");
    assert.equal(reg.twin, undefined, "a document: the whole-file twin");
    const tokPlan = String((await real.registerSecret({ path: plan })).symbol);
    const envBase = String((await real.registerSecret({ path: env })).symbol);

    /** One read turn through a fresh real proxy for `session`; the forwarded tool_result text. */
    const forwarded = async (session: string, tool: string, input: Record<string, unknown>, content: string, id: string): Promise<string> => {
      const up = new MockUpstream({ sse: buildTextSse("ok") });
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(socketPath), await open(humanPath)), upstream: up.fetcher, sessionKey: session, log: () => {} });
      proxies.push(proxy);
      const body = JSON.stringify({
        model: "claude-sonnet-5", stream: true,
        messages: [
          { role: "user", content: "read the brief" },
          { role: "assistant", content: [{ type: "tool_use", id, name: tool, input }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
        ],
      });
      const r = await post(await proxy.listen(0), body, session);
      assert.equal(r.status, 200, r.body);
      seen.push(up.requests[up.requests.length - 1]!.bodyText);
      const sent = up.requests[up.requests.length - 1]!.json() as { messages: Array<{ content: unknown }> };
      const block = (sent.messages[2]!.content as Array<{ content: unknown }>)[0]!.content;
      return typeof block === "string" ? block : (block as Array<{ text?: string }>).map((b) => b.text ?? "").join("");
    };
    const bind = async (session: string, spec: string) => assert.equal((await real.setSessionSpec({ sessionKey: session, spec, requestedBy: "read-document-twin e2e" })).bound, spec);
    const maskedWhole = (out: string, what: string) => {
      assert.match(out.split("\n")[0]!, SYMBOL_ONLY, `${what}: masked whole: ${out}`);
      assert.ok(!out.includes(tok) && !out.includes("Deal brief"), `${what}: neither the document's token nor its text: ${out}`);
    };

    // ── Claude Code's Read ────────────────────────────────────────────────────
    const cc = `read-doc-cc-${process.pid}`;
    await bind(cc, "claude-code");
    assert.equal(await forwarded(cc, "Read", { file_path: brief }, claudeRead(tok), "tu_cc_1"), claudeRead(tok), "the document's own token, as Claude Code rendered it");
    assert.equal(await forwarded(cc, "Read", { file_path: brief }, `     1\t${tok}\n     2\t`, "tu_cc_2"), `     1\t${tok}\n     2\t`, "with the harness's empty row after the final newline");
    for (const [content, what, id] of [
      [`     1\tDeal brief. Reference code: ${DOC_CANARY}.\n`, "the raw document", "tu_cc_raw"],
      [`     1\t${tok}\n     2\tmore\n`, "a second line", "tu_cc_more"],
      [`     1\t${tok} ${tok}\n`, "two tokens", "tu_cc_two"],
      [`     1\t${tok}\r\n`, "a CRLF byte after a LF file's token", "tu_cc_cr"],
      [claudeRead(tokPlan), "another document's token at this path", "tu_cc_other"],
      [claudeRead(old), "an older registration's token", "tu_cc_old"],
      [`     2\t${tok}\n`, "an offset read (line 2)", "tu_cc_offset"],
    ] as const) {
      maskedWhole(await forwarded(cc, "Read", { file_path: brief }, content, id), what);
    }
    // (A structured file's base token read alone at its own path is the
    // structured rule's business: it is a prefix of the twin's field tokens,
    // so that rule takes it as a piece of the twin. Harmless, a token; the
    // whole-file rule itself never answers for it: the unit tests.)
    assert.ok(envBase.startsWith("$MDU:"));

    // ── OpenClaw's read ───────────────────────────────────────────────────────
    const oc = `read-doc-oc-${process.pid}`;
    await bind(oc, "openclaw-agent");
    assert.equal(await forwarded(oc, "read", { path: brief }, `${tok}\n`, "tu_oc_1"), `${tok}\n`);
    maskedWhole(await forwarded(oc, "read", { path: brief }, `${tok}\nDeal brief\n`, "tu_oc_more"), "OpenClaw: a second line");
    maskedWhole(await forwarded(oc, "read", { path: plan }, `${tok}\n`, "tu_oc_other"), "OpenClaw: the brief's token read at another path");

    // ── OpenCode's read (1 and 2) ─────────────────────────────────────────────
    const od = `read-doc-od-${process.pid}`;
    await bind(od, "opencode");
    assert.equal(await forwarded(od, "read", { filePath: brief }, opencode1(brief, tok), "tu_od_1"), opencode1(brief, tok));
    assert.equal(await forwarded(od, "read", { path: brief }, opencode2(brief, tok), "tu_od_2"), opencode2(brief, tok));
    maskedWhole(await forwarded(od, "read", { filePath: brief }, opencode1(brief, `${tok} x`), "tu_od_more"), "OpenCode: a byte beside the token");

    // ── Goose: `shell` + `cat`, the shell leg (!1422) ─────────────────────────
    const gs = `read-doc-gs-${process.pid}`;
    await bind(gs, "goose");
    const cmd = `cat ${brief}`;
    const gooseAdapter = new ArbiterClientAdapter(await open(socketPath), await open(humanPath));
    await gooseAdapter.recordCallCommand!({ callId: "tu_gs_1", command: cmd, sessionKey: gs });
    await guard.recordExecRoot({ procKey: "gs-sh-1", ancestors: ["gs-agent-0"], argv: ["/bin/bash", "-c", cmd], session: gs, callRoot: true });
    const gooseOut = await forwarded(gs, "shell", { command: cmd }, `${tok}\n`, "tu_gs_1");
    assert.ok(gooseOut.startsWith(`${tok}\n`), `Goose's cat: the document's own token: ${gooseOut}`);
    assert.match(gooseOut, /twin: this is .*brief\.md as you see it: the whole file is one symbol/);

    // The released token keeps the document's law.
    assert.equal((await guard.desymbolizationDecision({ symbol: tok, boundary: "network", destination: "example.com" })).allow, true);
    assert.equal((await guard.desymbolizationDecision({ symbol: tok, boundary: "network", destination: "attacker.test" })).allow, false);

    // THE ORACLE: no request to the model carried a byte of either document.
    const wire = seen.join("\n");
    for (const c of CANARIES) assert.ok(!wire.includes(c), `CONFIDENTIALITY VIOLATION: ${c} reached the model`);
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
