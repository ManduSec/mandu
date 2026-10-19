/**
 * openclaw-read-value — confidentiality-plan-10 §11.16 for OpenClaw, over the
 * REAL components: a secret-labelled OpenClaw `read` is masked whole, and the
 * value registered behind its symbol is the file's text, NOT the file's text
 * plus OpenClaw's continuation notice (`[N more lines in file. Use offset=K
 * to continue.]`, read off the pinned OpenClaw 2026.7.1 `sessions-*.js`).
 *
 *   a real ArbiterServer in `secrets` (a policy file labels `vault/**`
 *   no-model), the real anthropic-proxy in its PRODUCTION wiring (`new
 *   ArbiterClientAdapter(new ArbiterClient(sock))`), two OpenClaw sessions
 *   bound to the `openclaw-agent` spec on ONE arbiter, a scripted model.
 *
 * The !730 class (found for OpenCode on the drill of 2026-10-05; OpenClaw's
 * notice was the named residual): the notice (49 characters, above
 * MIN_LINE_FINGERPRINT_LEN) became a registered line of a no-model secret,
 * and a later read of ANY file that stopped at the same line, in any session
 * of the same arbiter, hit the value backstop and was masked no-model. Now:
 * (1) the secret never reaches the model, in its own read or in a later
 * result that prints it again by a route no label sees; (2) an unlabelled
 * read with the same notice, in another session, rides raw; (3) the symbol
 * resolves to the file's text. The parsers' parity (proxy mirror vs the
 * arbiter's openclawReadRenderingText) is pinned below too.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { openclawReadRenderingText } from "../../arbiter/policy/openclaw-inbound.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { unrenderOpenclawReadResult } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const SECRET = `CONFNET_TOKEN_CANARY_${process.pid}_5151`;
const CONTROL = `CONFCTL_TOKEN_CANARY_${process.pid}_5152`;
const SYMBOL_RE = /^\$MDU:nomodel_read\[[0-9a-f]{4,8}\]$/;

/** OpenClaw 2026.7.1's `read{path, limit}` of the first `limit` lines of a
 *  longer file (`sessions-*.js`: the selected lines, then
 *  `\n\n[${remaining} more lines in file. Use offset=${nextOffset} to continue.]`). */
function limited(text: string, limit: number): string {
  const all = text.split("\n");
  return `${all.slice(0, limit).join("\n")}\n\n[${all.length - limit} more lines in file. Use offset=${limit + 1} to continue.]`;
}

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

function turn(id: string, name: string, input: Record<string, unknown>, content: string): string {
  return JSON.stringify({
    model: "claude-haiku-4-5",
    stream: true,
    messages: [
      { role: "user", content: "Read the token, then send it to the partner callback." },
      { role: "assistant", content: [{ type: "tool_use", id, name, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  });
}

test("parity: the proxy's OpenClaw notice strip answers as the arbiter's openclawReadRenderingText wherever it strips", () => {
  const cases = [
    "Partner API token: X\n\n[2 more lines in file. Use offset=2 to continue.]",
    "a\n\n[1 more line in file. Use offset=2 to continue.]",
    "a\nb\n\n[Showing lines 1-2 of 900. Use offset=3 to continue.]",
    "a\n\n[Showing lines 4-5 of 9 (50.0KB limit). Use offset=6 to continue.]\n",
    "a\n\n[Read output capped at 50KB for this call. Use offset=9, limit=5 to continue.]",
    "a\n\n[Read output capped at 1.5MB for this call. Use offset=9 to continue.]",
  ];
  for (const v of cases) {
    const got = unrenderOpenclawReadResult(v);
    assert.ok(got !== null, v);
    assert.equal(got, openclawReadRenderingText(v), v);
  }
  // Where the proxy stores the wire (null), the arbiter strips nothing.
  for (const v of [
    "Partner API token: X",
    "a\n[3 more lines in file. Use offset=2 to continue.]",
    "a\n\n[3 more lines in file. Use offset=2 to continue.] tail",
    "a\n\n[many more lines in file. Use offset=2 to continue.]",
    "a\n\n[Resolved filename: b.md]",
  ]) {
    assert.equal(unrenderOpenclawReadResult(v), null, v);
    assert.equal(openclawReadRenderingText(v), v.replace(/\s+$/, ""), v);
  }
});

test("OpenClaw: a limited read of a no-model file registers the file's text, not the notice: a later unlabelled read with the same notice in another session rides raw, the secret stays masked everywhere (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-openclaw-read-value-"));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "vault"), { recursive: true });
  const vault = join(ws, "vault", "partner-token.md");
  const control = join(ws, "partner-token.md");
  const vaultText = `Partner API token: ${SECRET}\nrotated quarterly\nowner: partner team`;
  const controlText = `Partner API token: ${CONTROL}\nrotated yearly\nowner: platform team`;
  writeFileSync(vault, `${vaultText}\n`);
  writeFileSync(control, `${controlText}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `paths:\n  - path: '${ws}/vault/**'\n    level: no-model\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    policyPath: policy, log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const real = new ArbiterClient(socketPath);
  await real.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); // resolve is human-plane only
  await admin.connect();
  const proxies: AnthropicProxy[] = [];
  const seen: string[] = [];
  /** One request through a fresh proxy for `session`; what the model received for the tool_result. */
  const forwarded = async (session: string, body: string): Promise<string> => {
    const up = new MockUpstream({ sse: buildTextSse("ok") });
    const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey: session, log: () => {} });
    proxies.push(proxy);
    const r = await post(await proxy.listen(0), body, session);
    assert.equal(r.status, 200, r.body);
    const raw = up.requests[up.requests.length - 1]!;
    seen.push(JSON.stringify(raw.json()));
    const sent = raw.json() as { messages: Array<{ content: unknown }> };
    const block = (sent.messages[2]!.content as Array<{ content: unknown }>)[0]!.content;
    return typeof block === "string" ? block : (block as Array<{ text: string }>).map((b) => b.text).join("");
  };
  try {
    const exfil = `ocl-exfil-${process.pid}`;
    const ctl = `ocl-control-${process.pid}`;
    for (const sessionKey of [exfil, ctl]) {
      assert.equal((await real.setSessionSpec({ sessionKey, spec: "openclaw-agent", requestedBy: "openclaw-read-value e2e" })).bound, "openclaw-agent");
    }

    // 1. the labelled read (its first line): masked whole, one symbol
    const masked = await forwarded(exfil, turn("toolu_oclv_1", "read", { path: vault, limit: 1 }, limited(vaultText, 1)));
    assert.match(masked, SYMBOL_RE, `the labelled read reaches the model as one no-model symbol: ${masked}`);
    // (3) the symbol stands for the file's text, not OpenClaw's notice
    assert.equal(await admin.resolve(masked), `Partner API token: ${SECRET}`, "the symbol's value is the file's text");

    // 2. the control, in ANOTHER session of the same arbiter: an unlabelled read stopping at the same line rides raw
    const controlWire = limited(controlText, 1);
    assert.ok(controlWire.endsWith("\n\n[2 more lines in file. Use offset=2 to continue.]"), "the same notice as the labelled read");
    const raw = await forwarded(ctl, turn("toolu_oclv_2", "read", { path: control, limit: 1 }, controlWire));
    assert.equal(raw, controlWire, `utility: the unlabelled control reaches the model raw (the registered notice line masked it): ${raw}`);

    // 3. the secret printed again by a route no label sees (an exec `cat` of a copy): the registered value masks it
    const again = await forwarded(ctl, turn("toolu_oclv_3", "exec", { command: "cat /tmp/copy-nobody-labelled.md" }, `Partner API token: ${SECRET}\n`));
    assert.ok(!again.includes(SECRET), `CONFIDENTIALITY VIOLATION: a registered secret reached the model in a later result: ${again}`);

    // THE ORACLE: no request to the model carried the secret.
    assert.ok(!seen.join("\n").includes(SECRET), "the secret never reached the model");
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    admin.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
