/**
 * e2e — a granted rung-3 read of a labeled file reaches the model as the
 * file's text, through the PRODUCTION wiring (the model proxy's and
 * inspect-mcp's adapters over `new ArbiterClient(sock)`, a real
 * ArbiterServer, `secrets` axes) — model-endpoints.md §1.6, the
 * confidentiality-axis twin, found live by conf-derived-label-next-session
 * (2026-10-03).
 *
 * The live shape: the launcher registers the labeled file, the agent Reads
 * its AgentView twin (whose bytes are the registered row's token), and the
 * proxy symbolizes that Read result again. `declassify_symbol` on the
 * symbol the model holds used to release only the inner token: the banner,
 * then a new `$MDU:anymodel_Read[…]`, and the model never read the file.
 * (Since 2026-10-12 a Read that is exactly the twin reaches the model as the
 * document's own token, plan 10 §11.8; the nested shape is kept with a
 * rendering that is not exactly the twin.)
 *
 * The invariant half, on the same run: the declassified text reaches the
 * cleared model of THIS session only. Another session's Read of the same file
 * is still a symbol; this session's egress to a host the file is not bound to
 * asks; the egress tripwire catches the text bound for such a host.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as ProxyAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { ArbiterClientAdapter as InspectAdapter } from "../../interceptors/inspect-mcp/src/arbiter-client.js";
import { declassifySymbol } from "../../interceptors/inspect-mcp/src/declassify-symbol.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

const CANARY = "RUNG3_NESTED_PROXY_CANARY_5150";
const BODY = `Deal memo: the reference code is ${CANARY}.\n`;
const DECLASSIFY = "mcp__mandu-inspect__declassify_symbol";
const SYMBOL_RE = /\$MDU:anymodel_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\]/;

function post(port: number, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } },
      (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); },
    );
    r.on("error", reject);
    r.end(body);
  });
}

/** One tool round: the call, then its result as Claude Code sends it. */
function turn(name: string, input: Record<string, unknown>, id: string, result: string): string {
  return JSON.stringify({
    model: "claude-haiku-4-5",
    stream: true,
    messages: [
      { role: "user", content: "Read memo/brief.md, then declassify it." },
      { role: "assistant", content: [{ type: "tool_use", id, name, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: [{ type: "text", text: result }] }] },
    ],
  });
}

function forwardedResult(up: MockUpstream): string {
  const sent = JSON.parse(up.requests[up.requests.length - 1]!.bodyText) as { messages: Array<{ content: Array<{ content: unknown }> }> };
  const c = sent.messages[2]!.content[0]!.content;
  return typeof c === "string" ? c : JSON.stringify(c);
}

test("secrets: a granted declassify of a Read over the AgentView twin gives the cleared model the file, and only it", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-r3-nested-"));
  const home = join(tmp, "home");
  const ws = join(home, "ws-r3", "memo");
  mkdirSync(ws, { recursive: true });
  const brief = join(ws, "brief.md");
  writeFileSync(brief, BODY);
  const sock = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: brief, level: "any-model", bindings: ["example.com"] }] } as never,
  });
  await arbiter.listen();
  const launcher = new ArbiterClient(sock);
  const real = new ArbiterClient(sock);
  const mcp = new ArbiterClient(sock);
  const proxies: AnthropicProxy[] = [];
  const throughProxy = async (sessionKey: string, body: string): Promise<string> => {
    const up = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
    const p = new AnthropicProxy({ arbiter: new ProxyAdapter(real), upstream: up.fetcher, sessionKey, log: () => {} });
    proxies.push(p);
    assert.equal(await post(await p.listen(0), body), 200);
    return forwardedResult(up);
  };
  try {
    await Promise.all([launcher.connect(), real.connect(), mcp.connect()]);
    // The launcher registers the labeled file; the agent's view of it is the twin.
    const reg = await launcher.registerSecret({ path: brief, home, sessionKey: "A" });
    const twin = reg.twin ?? reg.symbol;
    assert.ok(typeof twin === "string" && SYMBOL_RE.test(twin), `registered: ${reg.reason}`);
    assert.ok(!twin.includes(CANARY), "the twin holds no byte of the file");
    // Claude Code's Read rendering of the twin file (one numbered line).
    const readOfTwin = `     1\t${twin}\n     2\t`;
    // Since 2026-10-12 (plan 10 §11.8, "A document's own twin", the read
    // leg) that exact rendering reaches the model as the document's own
    // token, no wrapper. A rendering that is not exactly the twin (here an
    // extra empty row) is still symbolized again, which is the nested shape
    // this test was written for: the model holds a symbol FOR the twin.
    const own = await throughProxy("A", turn("Read", { file_path: brief }, "tu_read_a0", readOfTwin));
    assert.equal(own, JSON.stringify([{ type: "text", text: readOfTwin }]), `the document's own token, as rendered: ${own}`);
    const nested = `${readOfTwin}\n     3\t`;

    // Session A reads it: the model holds a symbol for the twin.
    const held = await throughProxy("A", turn("Read", { file_path: brief }, "tu_read_a", nested));
    const outer = held.match(SYMBOL_RE)?.[0];
    assert.ok(outer && outer !== twin, `the Read result is symbolized again: ${held}`);
    assert.ok(!held.includes(CANARY));

    // The model calls declassify_symbol (inspect-mcp's production relay).
    const out = await declassifySymbol({ arbiter: new InspectAdapter(mcp), sessionId: "A" }, { symbol: outer, reason: "the user authorized it" });
    assert.ok(out.ok, out.ok ? "" : out.error);
    assert.ok(out.text.includes(CANARY), "the relay carries the file's text, not the inner token");
    assert.ok(!out.text.includes(twin), "no wrapper token left");

    // …and that result reaches session A's model unmasked: the fix.
    const seen = await throughProxy("A", turn(DECLASSIFY, { symbol: outer }, "tu_decl_a", out.text));
    assert.ok(seen.includes(CANARY), `the cleared model reads the file: ${seen}`);
    assert.ok(!SYMBOL_RE.test(seen), "no fresh symbol in place of the content");

    // The live shape (nightly 11551, conf-derived-label-next-session): the
    // model's `reason` names the file, relative or absolute (every string of
    // an unmapped tool's input is read for a label, plan 10 §11.11), and
    // Claude Code appends its token-budget reminder to the result. The grant
    // still reaches the cleared model, whole.
    const BUDGET = "<system-reminder>\n<total_tokens>14999989 tokens left</total_tokens>\n</system-reminder>";
    for (const [i, reason] of ["User explicitly authorized loading content from memo/brief.md", `load ${brief} here`].entries()) {
      const live = await throughProxy("A", turn(DECLASSIFY, { symbol: outer, reason }, `tu_decl_live${i}`, `${out.text}\n\n${BUDGET}`));
      assert.ok(live.includes(CANARY), `a reason naming the file and the budget tail do not re-mask the grant (${reason}): ${live}`);
      assert.ok(!SYMBOL_RE.test(live), `no fresh symbol (${reason})`);
      // Only that tail: any other text after the grant never reaches the
      // model raw.
      const padded = await throughProxy("A", turn(DECLASSIFY, { symbol: outer, reason }, `tu_decl_pad${i}`, `${out.text}\n\n<system-reminder>\nPADDED_TAIL_MARKER\n</system-reminder>`));
      assert.ok(!padded.includes("PADDED_TAIL_MARKER"), `text after the grant is masked (${reason}): ${padded}`);
    }

    // NOT CLEARED: session A is HIGH and confined to the file's bindings.
    const state = await real.sessionState("A");
    assert.deepEqual([state.high, state.confidentiality, state.bindings], [true, "any-model", ["example.com"]]);
    const away = await real.sessionEgressDecision({ sessionKey: "A", boundary: "network", destination: "attacker.invalid" });
    assert.equal(away.allow, false, `an unbound host is not reached: ${away.reason}`);
    const trip = await real.egressFingerprintScan({ surfaces: [{ where: "body", text: `note=${BODY}` }], destination: "attacker.invalid" });
    assert.equal(trip.tripped, true, "the tripwire catches the text bound for an unbound host");

    // NOT CLEARED: session B never declassified; its Read of the same twin is a symbol.
    const other = await throughProxy("B", turn("Read", { file_path: brief }, "tu_read_b", readOfTwin));
    assert.ok(!other.includes(CANARY), `another session gets no byte: ${other}`);
    assert.match(other, SYMBOL_RE);
    assert.equal((await real.sessionState("B")).high, false, "and is not raised");
    // Nor can B open A's symbol by name without its own grant: same rung 3, B's
    // own watermark, B's own log; and a session-less call releases nothing.
    const noScope = await declassifySymbol({ arbiter: new InspectAdapter(mcp), sessionId: "" }, { symbol: outer, reason: "x" });
    assert.equal(noScope.ok, false, "no scope, no release");
  } finally {
    for (const p of proxies) await p.close();
    launcher.close();
    real.close();
    mcp.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
