/**
 * human-plane-parity — the PRODUCTION wiring of the reply filter's adapter
 * (CONTRIBUTING.md arbiter-client pattern): `new ArbiterClientAdapter(new
 * ArbiterClient(humanSock))` over a REAL ArbiterServer serving the human plane
 * (docs/design/architecture/arbiter-human-plane.md), no test bridge. Every forwarded op is
 * called:
 *   - desymbolize over the HUMAN socket → the original (a `no-model` secret:
 *     the human owns it, the reply channel faces the human);
 *   - emit → persisted (read back over the human socket, where `events` lives);
 *   - the SAME adapter over the DATA socket → desymbolize is refused, and the
 *     stream filter built on it passes the token through OPAQUE. That is the
 *     posture if a misconfiguration ever pointed the filter at the data
 *     socket: fidelity is lost, nothing leaks.
 * Mandu-new (no reference origin).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterClientAdapter, type RealArbiterClient } from "../../src/arbiter-client.js";
import { ReplyStreamFilter } from "../../src/filter.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis mints the no-model row

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const SECRET = "ghp_HumanPlaneParity0123456789abcdefABCD";

interface Srv { listen(): Promise<void>; close(): Promise<void> }
interface Cli extends RealArbiterClient {
  registerEnvSecrets(a: { vars: Array<{ name: string; value: string }>; sessionKey?: string }): Promise<{ vars: Array<{ symbol: string | null }> }>;
  events(sessionId: string): Promise<Array<{ id?: string; kind?: string }>>;
  emit(event: unknown): Promise<number>;
  noteReserveBlock(a: { sessionKey: string; token: string; n: number; width?: number; first?: number }): Promise<void>;
}

test("parity: the production adapter over the human socket resolves; over the data socket it is refused and the filter passes through", async () => {
  const { ArbiterServer } = (await import(join(REPO, "arbiter/ipc/server.ts"))) as {
    ArbiterServer: new (o: Record<string, unknown>) => Srv;
  };
  const { ArbiterClient } = (await import(join(REPO, "arbiter/ipc/client.ts"))) as {
    ArbiterClient: new (path: string) => Cli;
  };
  const dir = mkdtempSync(join(tmpdir(), "mdu-rf-parity-"));
  const dataSock = join(dir, "arbiter.sock");
  const humanSock = join(dir, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: dataSock, humanSocketPath: humanSock,
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    adminPolicyDir: null, packDir: null, log: () => {},
  });
  await server.listen();
  const humanClient = new ArbiterClient(humanSock);
  const dataClient = new ArbiterClient(dataSock);
  try {
    const reg = await dataClient.registerEnvSecrets({ vars: [{ name: "GITHUB_TOKEN", value: SECRET }], sessionKey: "rf-parity" });
    const symbol = reg.vars[0]?.symbol;
    assert.ok(symbol && !symbol.includes(SECRET), `a no-model symbol was minted (${JSON.stringify(reg)})`);

    // The production wiring: adapter over a client of the HUMAN socket.
    const human = new ArbiterClientAdapter(humanClient);
    assert.equal(await human.desymbolize(`token: ${symbol}`), `token: ${SECRET}`, "the human sees the original");
    const seq = await human.emit({ sessionId: "rf-parity", id: "p1", kind: "desymbolize" });
    assert.ok(seq > 0, "emit is forwarded and persisted");
    assert.ok((await humanClient.events("rf-parity")).some((e) => e.id === "p1"), "the event is readable on the human plane");
    // reserveBlock (reply-row-reservation.md §3.8): what the proxy recorded,
    // read back by the hash a continuation row carries.
    const hash = /\[([0-9a-f]{4,8})\]/.exec(symbol)![1]!;
    assert.equal(await human.reserveBlock("rf-parity", hash), null, "nothing recorded yet");
    await humanClient.noteReserveBlock({ sessionKey: "rf-parity", token: symbol, n: 3, width: 78, first: 78 });
    assert.deepEqual(await human.reserveBlock("rf-parity", hash), { token: symbol, n: 3, width: 78, first: 78 });

    // The same adapter over the DATA socket: refused, never an original.
    const data = new ArbiterClientAdapter(dataClient);
    await assert.rejects(data.desymbolize(`token: ${symbol}`), /human-plane/);
    await assert.rejects(data.reserveBlock("rf-parity", hash), /human-plane/);
    const filter = new ReplyStreamFilter(data, {});
    const out = (await filter.write(`reply ${symbol}\n`)) + (await filter.flush());
    assert.ok(out.includes(symbol), "the token passes through opaque");
    assert.ok(!out.includes(SECRET), "no original crosses the data socket");
  } finally {
    humanClient.close();
    dataClient.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
