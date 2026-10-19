/**
 * opencode-read-value — confidentiality-plan-10 §11.16 over the REAL
 * components: a secret-labelled OpenCode `read` is masked whole, and the value
 * registered behind its symbol is the text of the file's lines, NOT OpenCode's
 * rendering of them (`<path>…</path>`, `<type>file</type>`, `n: ` gutters,
 * `(End of file - total N lines)`).
 *
 *   a real ArbiterServer in `secrets` (a policy file labels `vault/**`
 *   no-model), the real anthropic-proxy in its PRODUCTION wiring (`new
 *   ArbiterClientAdapter(new ArbiterClient(sock))`, the proxy fetching each
 *   session's gate surface itself), two OpenCode sessions bound to the
 *   `opencode` spec on ONE arbiter, a scripted model behind the proxy.
 *
 * The live finding (OpenCode drill run 2026-10-05): conf-read-exfil read the
 * labelled `vault/partner-token.md`; the row registered behind its symbol was
 * OpenCode's whole rendering, so its trailer `(End of file - total 1 lines)`
 * (29 characters, above MIN_LINE_FINGERPRINT_LEN) became a registered line of
 * a no-model secret, and the next session's read of the UNLABELLED
 * `partner-token.md` (the drill's control, another token) hit the value
 * backstop and reached the model as `$MDU:nomodel_read[…]`. Now: (1) the
 * secret never reaches the model, in its own read or in a later result that
 * prints it again by a route no label sees; (2) an unlabelled one-line file
 * read later, in another session of the same arbiter, rides raw; (3) the
 * symbol resolves to the file's text. Red with symbolValueFor's OpenCode
 * branch removed (2 fails). The parsers' parity (proxy mirror vs the
 * arbiter's opencodeReadRenderingText) is pinned below too.
 *
 * OpenCode 2 (2.0.23, supported-agents.md §2.3) frames a read differently
 * (`Read file <path>, lines A-B`, then `n: <line>`, no trailer; its header
 * would be the registered line now) and names the file `path`: the same
 * scenario runs for both generations.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { opencodeReadRenderingText } from "../../arbiter/policy/opencode-inbound.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { unrenderOpencodeReadResult } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const SECRET = `CONFNET_TOKEN_CANARY_${process.pid}_4242`;
const CONTROL = `CONFCTL_TOKEN_CANARY_${process.pid}_4243`;
const SYMBOL_RE = /^\$MDU:nomodel_read\[[0-9a-f]{4,8}\]$/;

/** OpenCode 1.18.13's `read` rendering of a whole text file (read off the
 *  compiled binary and the live capture of 2026-10-05). */
function rendering(path: string, text: string): string {
  const lines = text.replace(/\n$/, "").split("\n");
  return [`<path>${path}</path>`, "<type>file</type>", "<content>", ...lines.map((l, i) => `${i + 1}: ${l}`), "", `(End of file - total ${lines.length} lines)`, "</content>"].join("\n");
}

/** OpenCode 2.0.23's `read` frame of a whole text file (captured 2026-10-05). */
function frame2(path: string, text: string): string {
  const lines = text.replace(/\n$/, "").split("\n");
  return [`Read file ${path}, lines 1-${lines.length}`, ...lines.map((l, i) => `${i + 1}: ${l}`)].join("\n");
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

test("parity: the proxy's OpenCode read un-render answers exactly as the arbiter's opencodeReadRenderingText", () => {
  const p = "/w/vault/partner-token.md";
  const cases: Array<[string, string[]]> = [
    [rendering(p, "Partner API token: X\n"), [p]],
    [rendering(p, "a\n\nb c\n"), [p]],
    [rendering(p, "one\n"), ["/elsewhere"]], // a path the call did not name
    [rendering("rel/p.md", "one\n"), ["rel/p.md"]], // not absolute
    [`<path>${p}</path>\n<type>file</type>\n<content>\n5: x\n6: y\n\n(Showing lines 5-6 of 9. Use offset=7 to continue.)\n</content>`, [p]],
    [`<path>${p}</path>\n<type>file</type>\n<content>\n1: x\n3: y\n\n(End of file - total 3 lines)\n</content>`, [p]], // a gap
    [`<path>${p}</path>\n<type>file</type>\n<content>\n1: x\n\n(Output capped at 50 KB. Showing lines 1-1. Use offset=2 to continue.)\n</content>`, [p]],
    [`${rendering(p, "x\n")}\n<system-reminder>\nInstructions from: /w/AGENTS.md\n</system-reminder>`, [p]],
    [`<path>${p}</path>\n<type>directory</type>\n<entries>\na\n(1 entries)\n</entries>`, [p]],
    ["Partner API token: X", [p]],
    // OpenCode 2.0.23's frame (supported-agents.md §2.3; the arbiter fixture
    // opencode2-tool-surface-2026-10-05.json): whole, relative as called,
    // an offset piece, and each form the parsers refuse
    [frame2(p, "Partner API token: X\n"), [p]],
    [frame2("rel/p.md", "a\n\nb c\n"), ["rel/p.md"]],
    [frame2(p, "one\n"), ["/elsewhere"]],
    ["Read file notes.txt, lines 2-2\n2: second line", ["notes.txt"]],
    [`${frame2(p, "x\n")}\n[Output truncated. Continue reading with offset: 2]`, [p]],
    [`Read file ${p}, lines 1-1\n1: ${"x".repeat(2000)}... (line truncated to 2000 chars)`, [p]],
    [`Read file ${p}, 0 lines`, [p]],
    ["Read directory sub, entries 1-1\na.md", ["sub"]],
    [`Read file ${p}, lines 1-2\n1: x\n3: y`, [p]],
    ['{"error":{"type":"tool.execution","message":"File not found: missing.txt"},"content":[]}', ["missing.txt"]],
  ];
  for (const [value, paths] of cases) {
    assert.equal(unrenderOpencodeReadResult(value, paths), opencodeReadRenderingText(value, paths), value);
  }
  assert.equal(unrenderOpencodeReadResult(rendering(p, "Partner API token: X\n"), [p]), "Partner API token: X");
  assert.equal(unrenderOpencodeReadResult(frame2(p, "Partner API token: X\n"), [p]), "Partner API token: X");
});

/** One generation's wire: OpenCode 1's `read{filePath}` + `bash`, OpenCode
 *  2's `read{path}` + `shell` (2.0.23; one session spec serves both). */
const GENERATIONS = {
  1: { readInput: (f: string) => ({ filePath: f }), frame: rendering, shell: "bash" },
  2: { readInput: (f: string) => ({ path: f }), frame: frame2, shell: "shell" },
} as const;

for (const gen of [1, 2] as const) test(`OpenCode ${gen}: a read of a no-model file registers the file's text, not OpenCode's frame: a later unlabelled one-line read in another session of the same arbiter rides raw, the secret stays masked everywhere (secrets axes, explicit)`, async () => {
  const g = GENERATIONS[gen];
  const tmp = mkdtempSync(join(tmpdir(), "mandu-opencode-read-value-"));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "vault"), { recursive: true });
  const vault = join(ws, "vault", "partner-token.md");
  const control = join(ws, "partner-token.md");
  writeFileSync(vault, `Partner API token: ${SECRET}\n`);
  writeFileSync(control, `Partner API token: ${CONTROL}\n`);
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
    const exfil = `oc-exfil-${process.pid}`;
    const ctl = `oc-control-${process.pid}`;
    for (const sessionKey of [exfil, ctl]) {
      assert.equal((await real.setSessionSpec({ sessionKey, spec: "opencode", requestedBy: "opencode-read-value e2e" })).bound, "opencode");
    }

    // 1. the labelled read: masked whole, one symbol
    const masked = await forwarded(exfil, turn("toolu_ocv_1", "read", g.readInput(vault), g.frame(vault, `Partner API token: ${SECRET}\n`)));
    assert.match(masked, SYMBOL_RE, `the labelled read reaches the model as one no-model symbol: ${masked}`);
    // (3) the symbol stands for the file's text, not OpenCode's frame
    assert.equal(await admin.resolve(masked), `Partner API token: ${SECRET}`, "the symbol's value is the file's text");

    // 2. the control, in ANOTHER session of the same arbiter: an unlabelled one-line file rides raw
    const controlWire = g.frame(control, `Partner API token: ${CONTROL}\n`);
    const raw = await forwarded(ctl, turn("toolu_ocv_2", "read", g.readInput(control), controlWire));
    assert.equal(raw, controlWire, `utility: the unlabelled control reaches the model raw (was masked by the registered trailer line): ${raw}`);

    // 3. the secret printed again by a route no label sees (a bash `cat` of a copy): the registered value masks it
    const again = await forwarded(ctl, turn("toolu_ocv_3", g.shell, { command: "cat /tmp/copy-nobody-labelled.md" }, `Partner API token: ${SECRET}\n`));
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
