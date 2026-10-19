/**
 * bindings-across-files — one secret value held by two labelled files, each
 * bound to its own host (confidentiality.md §2.1 "One value, several
 * sources", 2026-10-19), over the REAL components: an ArbiterServer reading
 * a policy FILE, the REAL net-proxy and the REAL DevTools relay, each in its
 * production wiring (`new ArbiterClientAdapter(new ArbiterClient(data), new
 * ArbiterClient(human))`).
 *
 * `my-details.yaml` holds the card number and is bound to the vehicle
 * registry; `wallet.yaml` holds the same card number and is bound to the
 * expense tool. The bug (found building the browser demos): the value got
 * the bindings of whichever file was registered first, so the other file's
 * host was refused. Now, in either registration order:
 *
 *   1. net-proxy: each file's placeholder reaches BOTH bound hosts as the
 *      real value, and an unbound host not at all; the raw value sent by a
 *      clean process passes the tripwire at either bound host and trips it
 *      at an unbound one.
 *   2. After an arbiter restart over the same SQLite table: the same.
 *   3. The wallet deleted: its host no longer gets the value; the registry
 *      still does.
 *   4. The files disagree on the level (the wallet `any-model`): the
 *      wallet's placeholder is refused to the quarantined helper's model
 *      and to the in-context read, as the details file's `no-model` says;
 *      before the details file is registered the helper's ask is admitted
 *      (the control).
 *   5. DevTools relay: the agent reads the page's card number as a
 *      placeholder (the real prompt filter picks one file's row), and typing
 *      it lands the real value on the registry's page and on the expense
 *      tool's, and on an unbound page nothing.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy, type HttpForwarder } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { ArbiterClientAdapter as RelayAdapter, type RealArbiterClient as RelayRealClient } from "../../interceptors/cdp-relay/src/arbiter-client.js";
import { CdpRelay } from "../../interceptors/cdp-relay/src/relay.js";
import { FakeChrome } from "../../interceptors/cdp-relay/test/fake-chrome.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const CARD = "4111111111111111";
const LICENCE = "DLX4471902BB";
const SESSION = "s-bindings-across-files";
const REGISTRY = "vehicles.example";
const EXPENSES = "expenses.example";
const EVIL = "evil.example";

type Which = "details" | "wallet";

interface World {
  tmp: string;
  details: string;
  wallet: string;
  start(): Promise<{ server: ArbiterServer; human: ArbiterClient; data: ArbiterClient; close(): Promise<void> }>;
}

function world(walletLevel = "no-model"): World {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-across-files-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws);
  const details = join(ws, "my-details.yaml");
  const wallet = join(ws, "wallet.yaml");
  writeFileSync(details, `driving_licence_number: ${LICENCE}\ncard_number: ${CARD}\n`);
  writeFileSync(wallet, `company_card_number: ${CARD}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, [
    "version: 1",
    "paths:",
    `  - path: ${details}`, "    level: no-model", "    extract: ':[ \\t]*(\\S+)'", `    bindings: [${REGISTRY}]`,
    `  - path: ${wallet}`, `    level: ${walletLevel}`, "    extract: ':[ \\t]*(\\S+)'", `    bindings: [${EXPENSES}]`,
    "",
  ].join("\n"));
  const sock = join(tmp, "a.sock");
  const humanSock = join(tmp, "h", "h.sock");
  return {
    tmp, details, wallet,
    async start() {
      const server = new ArbiterServer({
        socketPath: sock, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanSock,
        dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
        confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
      });
      await server.listen();
      const human = new ArbiterClient(humanSock); await human.connect();
      const data = new ArbiterClient(sock); await data.connect();
      return { server, human, data, close: async () => { human.close(); data.close(); await server.close().catch(() => undefined); } };
    },
  };
}

/** The launcher's registration, in `order`: each file's card placeholder. */
async function register(w: World, human: ArbiterClient, order: Which[]): Promise<Record<Which, string>> {
  const out = {} as Record<Which, string>;
  for (const which of order) {
    const r = await human.registerSecret({ path: w[which], sessionKey: SESSION });
    assert.match(String(r.symbol), /^\$MDU:(nomodel|anymodel)_Read\[/, JSON.stringify(r));
    // An `extract:` label names its values by position: the card is the
    // details file's second value and the wallet's first.
    out[which] = `${r.symbol}.${which === "details" ? "extract_2" : "extract_1"}`;
    assert.ok(String(r.twin).includes(out[which]), `${which}: the twin carries ${out[which]}`);
  }
  return out;
}

/** A plain-HTTP POST through the forward proxy. */
function post(port: number, url: string, auth: string, body = ""): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: url, headers: { host: u.host, authorization: `Bearer ${auth}`, "content-length": Buffer.byteLength(body) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    r.on("error", reject);
    r.end(body);
  });
}

async function netProxy(sock: { data: ArbiterClient; human: ArbiterClient }, reached: string[]): Promise<{ net: NetProxy; port: number }> {
  const forwarder: HttpForwarder = async (req) => {
    reached.push(`${req.url} ${JSON.stringify(req.headers)} ${req.body?.toString("utf8") ?? ""}`);
    return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
  };
  const net = new NetProxy({
    arbiter: new NetProxyAdapter(sock.data as unknown as NetProxyRealClient, sock.human as never), forwarder, log: () => {}, sessionId: SESSION,
    attributeHolders: () => [{ procKey: "curl-clean", ancestors: ["bash-1", "agent-0"] }],
  });
  return { net, port: await net.listen(0) };
}

for (const order of [["details", "wallet"], ["wallet", "details"]] as Which[][]) {
  test(`net-proxy (registered ${order.join(" then ")}): each file's placeholder reaches both bound hosts, an unbound one nothing; a restart keeps it; the wallet deleted drops only its host`, async () => {
    const w = world();
    let a = await w.start();
    const reached: string[] = [];
    let p = await netProxy(a, reached);
    try {
      const sym = await register(w, a.human, order);
      const send = async (symbol: string, host: string, released: boolean, why: string) => {
        const before = reached.length;
        const r = await post(p.port, `http://${host}/v1/charge`, symbol);
        if (released) {
          assert.equal(r.status, 200, `${why}: ${r.body}`);
          assert.equal(reached.length, before + 1, `${why}: reached ${host}`);
          assert.ok(reached.at(-1)!.includes(CARD), `${why}: ${host} received the real value`);
          assert.ok(!reached.at(-1)!.includes("$MDU:"), `${why}: not the placeholder`);
        } else {
          assert.equal(r.status, 403, `${why}: refused (${r.body})`);
          assert.equal(reached.length, before, `${why}: nothing reached ${host}`);
        }
        assert.ok(!r.body.includes(CARD), `${why}: the answer carries no secret`);
      };
      const raw = async (host: string, released: boolean, why: string) => {
        const before = reached.length;
        const r = await post(p.port, `http://${host}/v1/charge`, "no-placeholder", `card=${CARD}`);
        assert.equal(r.status, released ? 200 : 403, `${why}: ${r.body}`);
        assert.equal(reached.length, before + (released ? 1 : 0), why);
      };
      const all = async (stage: string) => {
        for (const which of ["details", "wallet"] as Which[]) {
          await send(sym[which], REGISTRY, true, `${stage}: the ${which} placeholder at the registry`);
          await send(sym[which], EXPENSES, true, `${stage}: the ${which} placeholder at the expense tool`);
          await send(sym[which], EVIL, false, `${stage}: the ${which} placeholder at an unbound host`);
        }
        await raw(REGISTRY, true, `${stage}: the raw card at the registry passes the tripwire`);
        await raw(EXPENSES, true, `${stage}: the raw card at the expense tool passes the tripwire`);
        await raw(EVIL, false, `${stage}: the raw card at an unbound host trips it`);
      };

      // 1. Live.
      await all("live");
      // A value only the details file holds keeps that file's host alone.
      const licence = sym.details.replace(/\.extract_2$/, ".extract_1");
      const r = await post(p.port, `http://${EXPENSES}/v1/charge`, licence);
      assert.equal(r.status, 403, `the licence at the expense tool: refused (${r.body})`);

      // 2. Restart over the same table.
      await p.net.close();
      await a.close();
      a = await w.start();
      p = await netProxy(a, reached);
      await all("after a restart");

      // 3. The wallet deleted: it no longer holds the value.
      unlinkSync(w.wallet);
      await send(sym.details, EXPENSES, false, "wallet deleted: the details placeholder at the expense tool");
      await send(sym.details, REGISTRY, true, "wallet deleted: the details placeholder at the registry");
      await send(sym.details, EVIL, false, "wallet deleted: an unbound host");
      for (const line of reached) if (line.startsWith(`http://${EVIL}`)) assert.fail(`nothing reaches ${EVIL}: ${line}`);
    } finally {
      await p.net.close();
      await a.close();
      rmSync(w.tmp, { recursive: true, force: true });
    }
  });
}

/** A DevTools client over Node's built-in WebSocket. */
async function agent(wsUrl: string) {
  const ws = new WebSocket(wsUrl);
  await new Promise<void>((resolve, reject) => {
    ws.addEventListener("open", () => resolve(), { once: true });
    ws.addEventListener("error", () => reject(new Error(`no relay at ${wsUrl}`)), { once: true });
  });
  const waiting = new Map<number, (m: any) => void>();
  const all: any[] = [];
  ws.addEventListener("message", (ev) => {
    const m = JSON.parse(String(ev.data));
    all.push(m);
    if (typeof m.id === "number") waiting.get(m.id)?.(m);
  });
  let id = 1;
  return {
    all,
    send(method: string, params: Record<string, unknown> = {}): Promise<any> {
      const my = id++;
      return new Promise((resolve) => { waiting.set(my, resolve); ws.send(JSON.stringify({ id: my, method, params })); });
    },
    close: () => ws.close(),
  };
}

for (const order of [["details", "wallet"], ["wallet", "details"]] as Which[][]) {
  test(`DevTools relay (registered ${order.join(" then ")}): the card read off a page is typed into either file's bound page as the real value, an unbound page nothing`, async () => {
    const w = world();
    const a = await w.start();
    const adapter = new RelayAdapter(a.data as unknown as RelayRealClient, a.human as unknown as RelayRealClient);
    const pages = {
      wallet: new FakeChrome({ url: "https://wallet.local.test/cards", pageText: `Card: ${CARD}` }),
      registry: new FakeChrome({ url: `https://${REGISTRY}/renew`, pageText: "Renew" }),
      expenses: new FakeChrome({ url: `https://${EXPENSES}/new`, pageText: "New expense" }),
      evil: new FakeChrome({ url: `https://${EVIL}/collect`, pageText: "nothing" }),
    };
    const relays: CdpRelay[] = [];
    const agents: Array<Awaited<ReturnType<typeof agent>>> = [];
    try {
      await register(w, a.human, order);
      const open = async (page: FakeChrome) => {
        await page.listen();
        const relay = new CdpRelay({ upstream: page.url, arbiter: adapter, session: SESSION });
        relays.push(relay);
        const ag = await agent(`ws://${new URL((await relay.listen()).url).host}/devtools/page/PAGE1`);
        agents.push(ag);
        return ag;
      };
      const reader = await open(pages.wallet);
      const read = await reader.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
      const text = String(read.result?.result?.value);
      assert.ok(!text.includes(CARD), `no raw value: ${text}`);
      const placeholder = /\$MDU:[A-Za-z0-9_]+\[[0-9a-f]+\]\.[A-Za-z0-9_]+/.exec(text)?.[0];
      assert.ok(placeholder, `the real filter put a placeholder in its place: ${text}`);

      for (const [name, page] of [["registry", pages.registry], ["expenses", pages.expenses]] as const) {
        const ag = await open(page);
        const typed = await ag.send("Input.insertText", { text: placeholder });
        assert.deepEqual(typed.result, {}, `${name}: ${JSON.stringify(typed)}`);
        assert.deepEqual(page.typed, [CARD], `the ${name} page (bound by one of the two files) got the real value`);
      }
      const ev = await open(pages.evil);
      const refused = await ev.send("Input.insertText", { text: placeholder });
      assert.match(String(refused.error?.message), /evil\.example/, JSON.stringify(refused));
      assert.deepEqual(pages.evil.typed, []);
      assert.ok(!JSON.stringify(pages.evil.received).includes(CARD), "nothing raw reached the unbound page");
      assert.ok(!JSON.stringify(agents.flatMap((g) => g.all)).includes(CARD), "the agent never saw the value");
    } finally {
      for (const g of agents) g.close();
      for (const r of relays) await r.close();
      for (const page of Object.values(pages)) await page.close().catch(() => undefined);
      await a.close();
      rmSync(w.tmp, { recursive: true, force: true });
    }
  });
}

test("levels disagree: the strictest file governs clearance to a model (the helper's deep resolve, the in-context read)", async () => {
  const w = world("any-model");
  const a = await w.start();
  try {
    // The control first: the wallet alone is any-model, and a model may read it.
    const alone = await register(w, a.human, ["wallet"]);
    const admitted = await a.data.resolveFull(alone.wallet, { deep: true });
    assert.equal(admitted.value, CARD, "the control: an any-model value alone reaches the helper's model");

    // The details file holds the same card at no-model.
    await register(w, a.human, ["details"]);
    const refused = await a.data.resolveFull(alone.wallet, { deep: true });
    assert.equal(refused.value, null, "the wallet's placeholder no longer reaches any model");
    const read = await a.human.declassifySymbol({ symbol: alone.wallet, sessionKey: SESSION });
    assert.equal(read.value, null, JSON.stringify(read));
    assert.equal(read.allowed, false);
    assert.match(String(read.reason), /no-model/, "refused as no-model, with no approval path");
  } finally {
    await a.close();
    rmSync(w.tmp, { recursive: true, force: true });
  }
});
