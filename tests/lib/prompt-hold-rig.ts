/**
 * prompt-hold-rig — the shared rig of the prompt filter's `ask` stack tests
 * (confidentiality-plan-15-prompt-filter.md §13.6): a real ArbiterServer in
 * `secrets` with data, human and admin sockets, a pack that finds a code name
 * the policy asks about, a registered key, and the oracles each agent
 * family's test runs over the REAL proxy (stack/prompt-filter-hold.test.ts,
 * stack/prompt-filter-ask-openclaw-opencode.test.ts).
 *
 * Mandu-new test helper (no reference origin).
 */
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import type { PolicyFileConfig } from "../../arbiter/policy/load-policy.js";

export const KEY = "sk-live-HoldCanary7Hq2Zx9Lw4Rt8Kd";
// Long enough (8+) that the default's own row would match it as a value:
// the hold must still ask and "send as written" must still send it.
export const CODENAME = "falconridgeproject";
/** OpenClaw's wall-clock envelope before the human's text. */
export const ENVELOPE = "[Thu 2026-10-02 10:48 GMT+9] ";
/** OpenClaw's sender header, before the envelope (harness text). */
export const OPENCLAW_SENDER = 'Sender (untrusted metadata):\n```json\n{"id":"gateway-client"}\n```\n\n';
export const typed = (n: number): string => `deploy ${CODENAME} build ${n} with ${KEY}`;

const PACK = `pack: acme-dlp
version: 1
keywords:
  - category: acme.codename
    words: [${CODENAME}]
    level: local-model
`;
/** The policy: the pack on, its category at `action` (`ask` by default). */
const policyFor = (action: "ask" | "block"): PolicyFileConfig => ({ version: 1, prompt_filters: { filters: { "acme-dlp": "on" }, actions: { "acme.codename": action } } });

export interface Rig {
  data: ArbiterClient;
  human: ArbiterClient;
  admin: ArbiterClient;
  stop(): Promise<void>;
}

/** The arbiter, `secrets` axes explicit; `holdMs` is its hold deadline;
 *  `action` the code name's policy action (`ask` by default). */
export async function boot(holdMs = 20_000, opts: { lockedAsk?: boolean; action?: "ask" | "block" } = {}): Promise<Rig> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-prompt-hold-"));
  const packs = join(tmp, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "acme.yaml"), PACK);
  // The administrator's layer: `acme.codename` locked to ask.
  let adminPolicyDir: string | null = null;
  if (opts.lockedAsk) {
    adminPolicyDir = join(tmp, "policy.d");
    mkdirSync(adminPolicyDir);
    writeFileSync(join(adminPolicyDir, "10-org.yaml"), "prompt_filters:\n  actions:\n    acme.codename: { action: ask, locked: true }\n");
  }
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const adminSock = join(tmp, "admin.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, adminSocketPath: adminSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyDocument: policyFor(opts.action ?? "ask"), policyPollMs: 0,
    promptPackDir: packs, adminPromptPackDir: null, adminPolicyDir, packDir: null, promptHoldMs: holdMs,
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  const reg = await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
  assert.match(reg.vars[0]!.symbol ?? "", /^\$MDU:/, "the key is registered");
  return {
    data, human, admin,
    async stop() {
      data.close();
      human.close();
      admin.close();
      await server.close().catch(() => {});
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

function request(port: number, path: string, body: unknown, session: string): { req: http.ClientRequest; done: Promise<{ status: number; body: string }> } {
  const data = Buffer.from(JSON.stringify(body));
  let req!: http.ClientRequest;
  const done = new Promise<{ status: number; body: string }>((resolve, reject) => {
    req = http.request(
      { host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": "application/json", "content-length": String(data.length), "x-mandu-session-id": session, authorization: "Bearer sk-test-not-real" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(data);
  });
  return { req, done };
}

/** POST a JSON body as the agent does and read the whole answer. */
export function post(port: number, path: string, body: unknown, session: string): Promise<{ status: number; body: string }> {
  return request(port, path, body, session).done;
}

/** POST a JSON body and hang up when told: the agent killed (or its user
 *  pressed Esc) while the request waits. */
export function postThenDrop(port: number, path: string, body: unknown, session: string): { drop(): void } {
  const { req, done } = request(port, path, body, session);
  done.catch(() => {}); // the reset the hang-up causes
  return { drop: () => req.destroy() };
}

/** A fake Chat Completions provider on loopback that records every body. */
export async function startFakeChat(): Promise<{ origin: string; requests: string[]; close(): Promise<void> }> {
  const requests: string[] = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      requests.push(body);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ id: "c1", object: "chat.completion", created: 1, model: "m", choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }] }));
    });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  return {
    origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    requests,
    close: () => new Promise<void>((ok) => { server.closeAllConnections(); server.close(() => ok()); }),
  };
}

export async function waitFor<T>(what: string, f: () => Promise<T | undefined>, ms = 10_000): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = await f();
    if (v !== undefined) return v;
    if (Date.now() > until) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** The pending hold for this session (the Inbox's view, human plane). */
export async function pendingHold(r: Rig, session: string, seen: Set<string>): Promise<string> {
  const id = await waitFor("a pending prompt hold", async () => {
    const h = (await r.human.promptHolds()).holds.find((x) => x.session === session && !seen.has(x.approvalId));
    return h?.approvalId;
  });
  seen.add(id);
  const view = (await r.human.promptHolds()).holds.find((x) => x.approvalId === id)!;
  assert.equal(view.span, CODENAME, "the Inbox card (human plane) shows the human's own found text");
  assert.equal(view.category, "acme.codename");
  return id;
}

/** One agent family on one wire: how it sends a prompt and what the model received. */
export interface Family {
  name: string;
  session: string;
  send(text: string, history?: string[]): Promise<{ status: number; body: string }>;
  /** Send, and hang up when told (the disconnect oracle). */
  sendThenDrop?(text: string, history?: string[]): { drop(): void };
  /** How many times the proxy has asked `filterPrompt` (the production
   *  adapter, counted). */
  asks?(): number;
  /** The bodies the model received for the main route. */
  received(): string[];
  /** A side call quoting the prompt (no tools), where the family has one. */
  sideCall?(text: string): Promise<{ status: number; body: string }>;
  close(): Promise<void>;
}

/** Count the `filterPrompt` asks of a production adapter (the object the
 *  proxy is wired with; only this one method is wrapped). */
export function countAsks<A extends { filterPrompt(req: never): Promise<unknown> }>(adapter: A): { adapter: A; asks(): number } {
  let n = 0;
  const orig = adapter.filterPrompt.bind(adapter) as (req: never) => Promise<unknown>;
  (adapter as { filterPrompt: (req: never) => Promise<unknown> }).filterPrompt = (req: never) => {
    n++;
    return orig(req);
  };
  return { adapter, asks: () => n };
}

export const noRaw = (bodies: string[], where: string): void => {
  for (const b of bodies) assert.ok(!b.includes(KEY), `CONFIDENTIALITY VIOLATION (${where}): the registered key reached the model raw`);
};

/** The shared oracle: held until an admin answer; send as written / masked. */
export async function heldThenAnswered(r: Rig, f: Family): Promise<void> {
  const seen = new Set<string>();
  // 1. Send as written.
  const n0 = f.received().length;
  const p1 = f.send(typed(1));
  const id1 = await pendingHold(r, f.session, seen);
  assert.equal(f.received().length, n0, `${f.name}: nothing reaches the model while the prompt is held`);
  // An answer from the agent's world (the data socket) or the human socket is refused.
  await assert.rejects(() => r.data.resolvePromptHold({ approvalId: id1, answer: "send" }), /admin-only/);
  await assert.rejects(() => r.human.resolvePromptHold({ approvalId: id1, answer: "send" }), /admin-only/);
  await assert.rejects(() => r.data.resolveEgressApproval(id1, true), /admin-only/);
  await sleep(700);
  assert.equal(f.received().length, n0, `${f.name}: a claimed answer releases nothing`);
  await r.admin.resolvePromptHold({ approvalId: id1, answer: "send", scope: "once" });
  const ok1 = await p1;
  assert.equal(ok1.status, 200, ok1.body);
  const sent = f.received().at(-1)!;
  assert.ok(sent.includes(`deploy ${CODENAME} build 1 with $MDU:`), `${f.name}: sent as written, the registered key as its symbol: ${sent}`);
  noRaw(f.received(), f.name);
  // 2. Send masked.
  const p2 = f.send(typed(2));
  const id2 = await pendingHold(r, f.session, seen);
  await r.admin.resolvePromptHold({ approvalId: id2, answer: "mask", scope: "once" });
  const ok2 = await p2;
  assert.equal(ok2.status, 200, ok2.body);
  const masked = f.received().at(-1)!;
  assert.ok(!masked.includes(`${CODENAME} build 2`), `${f.name}: masked: the code name did not reach the model: ${masked}`);
  assert.match(masked, /deploy \$MDU:\S+ build 2 with \$MDU:/);
  noRaw(f.received(), f.name);
}

/** Cancel: a 400 the agent shows, nothing sent; the next turn carries the
 *  message masked. */
export async function cancelled(r: Rig, f: Family, n = 4): Promise<void> {
  const before = f.received().length;
  const p = f.send(typed(n));
  const id = await pendingHold(r, f.session, new Set());
  await r.admin.resolvePromptHold({ approvalId: id, answer: "cancel" });
  const c = await p;
  assert.equal(c.status, 400, c.body);
  assert.match(c.body, /You cancelled this message in Mandu's Inbox/);
  assert.equal(f.received().length, before, `${f.name}: nothing was sent for a cancelled message`);
  const next = await f.send("say hi", [typed(n)]);
  assert.equal(next.status, 200, next.body);
  assert.ok(!f.received().at(-1)!.includes(`${CODENAME} build ${n}`), `${f.name}: the cancelled message is resent masked`);
  for (const b of f.received()) {
    assert.ok(!b.includes(`${CODENAME} build ${n}`), `CONFIDENTIALITY VIOLATION (${f.name}): a message the human cancelled reached the model`);
  }
  noRaw(f.received(), f.name);
}

/**
 * The agent hangs up while its prompt is held (plan 15 §13.6 item 13): the
 * proxy stops asking at once and sends nothing; the hold stays pending in the
 * Inbox (pending asks are not expired), an answer given then releases
 * nothing (no orphaned wait is left to forward it), and it decides the
 * agent's next try, which carries the message again.
 */
export async function disconnectWhileHeld(r: Rig, f: Family, n = 7): Promise<void> {
  const { sendThenDrop, asks } = f;
  assert.ok(sendThenDrop && asks, `${f.name}: the family can hang up and count its asks`);
  const before = f.received().length;
  const call = sendThenDrop(typed(n));
  const id = await pendingHold(r, f.session, new Set());
  // Still waiting: the proxy asks again every half second.
  const a0 = asks();
  await waitFor(`${f.name}: the proxy polls the hold`, async () => (asks() > a0 ? true : undefined), 5_000);
  call.drop();
  await sleep(300); // the hang-up reaches the proxy; an ask on the wire comes back
  const a1 = asks();
  await sleep(1_500); // three poll intervals
  assert.equal(asks(), a1,`${f.name}: no ask after the agent hung up (the poll stopped)`);
  assert.equal(f.received().length, before, `${f.name}: nothing of a held request is sent when the agent hangs up`);
  const pending = (await r.human.promptHolds()).holds.find((h) => h.approvalId === id);
  assert.ok(pending, `${f.name}: the hold stays in the Inbox for a later answer`);
  // The human answers after the agent went: nothing is waiting to forward it.
  await r.admin.resolvePromptHold({ approvalId: id, answer: "send", scope: "once" });
  await sleep(700);
  assert.equal(f.received().length, before, `${f.name}: an answer to an abandoned hold releases nothing by itself`);
  // The agent's next try carries the message: the answer decides it, with no new hold.
  const again = await f.send(typed(n));
  assert.equal(again.status, 200, again.body);
  assert.ok(f.received().at(-1)!.includes(`deploy ${CODENAME} build ${n} with $MDU:`), `${f.name}: the retry goes as the human answered: ${f.received().at(-1)}`);
  assert.equal((await r.human.promptHolds()).holds.filter((h) => h.session === f.session).length, 0, `${f.name}: the retry asked nothing new`);
  noRaw(f.received(), f.name);
}
