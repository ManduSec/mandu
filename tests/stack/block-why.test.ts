/**
 * block-why — a blocked step on the product's session page says why, from
 * the rule its event recorded (dashboard.md §4.25b, "A block says why"),
 * across the REAL components.
 *
 *   L1  a `.env` registered as a secret with no rule letting it go anywhere;
 *       the REAL net-proxy, wired as production wires it
 *       (`new ArbiterClientAdapter(new ArbiterClient(data), human)`),
 *       refuses a request that carries its key's placeholder to
 *       api.stripe.com: 403, nothing forwarded;
 *   L2  the block's `net_action`, as the arbiter stored it, names the rule
 *       that decided it (`policy.ruleRef`, `egress:secret-unbound`) and the
 *       Approvals row the arbiter queued for the person (`policy.approvalId`,
 *       the pending row's id);
 *   L3  the REAL dashboard over the arbiter's store words that rule on the
 *       blocked step (`/api/home/agent`): "No rule lets this secret go to
 *       `api.stripe.com`. Mandu sends a secret only where a rule lets it
 *       go, or with your OK.", with no token and no value anywhere, and
 *       says Mandu asked for your OK in Approvals by that row's id (§4.25b,
 *       "A stop says Mandu asked you"); the key's *Your secrets* card says
 *       the same of its block, linking the same row (§4.25b, "A block says
 *       Mandu asked you"), and its time opens that blocked step (§4.25b,
 *       "A time opens its step");
 *   L3b the REAL dashboard's inspector payload (`/api/events`, the trace's
 *       view-model) carries the same words and the same row on the blocked
 *       send's step (dashboard.md §4.2f, "A check says why", "…says it
 *       asked"), and its counts read 1 blocked and 1 asked (§4.33); the
 *       Secrets tab's lineage edge for that block names the same row
 *       (§4.15, "A block says Mandu asked");
 *   L4  the words cannot drift from the law: every `egress:`, `exec:`,
 *       `fs:` and `session:` id the dashboard words is in the arbiter's
 *       catalog (`RULES`) with an outcome that stops (deny, or deny pending
 *       the person), and every `proxy:` id is one an interceptor still
 *       emits.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm test  (tests/)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { RULES } from "../../arbiter/policy/rule-ref.js";
import { NetProxy, type HttpForwarder } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AgentPageVM, StoryStep } from "../../dashboard/src/view-model/agent-page.js";
import { WHY_RULE_IDS } from "../../dashboard/src/view-model/block-why.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = "s-block-why";
const KEY = "sk_live_fake_BLOCKWHY_5c1d07";
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

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

const words = (parts: { kind: string; text: string }[]) => parts.map((p) => (p.kind === "code" ? `\`${p.text}\`` : p.text)).join("");

test("a send the real net-proxy refused says why on the real session page, from the rule the arbiter recorded", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-block-why-"));
  const ws = join(tmp, "ws"); mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY}\nDEBUG=1\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await arbiter.listen();
  const human = new ArbiterClient(humanPath); await human.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const data = new ArbiterClient(socketPath); await data.connect();
  const netHuman = new ArbiterClient(humanPath); await netHuman.connect();
  const forwarded: string[] = [];
  const forwarder: HttpForwarder = async (req) => {
    forwarded.push(`${req.url} ${JSON.stringify(req.headers)}`);
    return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
  };
  const proxy = new NetProxy({
    arbiter: new ArbiterClientAdapter(data as unknown as RealArbiterClient, netHuman as never),
    forwarder, log: () => {}, sessionId: SESSION, attributeHolders: () => [],
  });
  const proxyPort = await proxy.listen(0);
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath }), log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;

  try {
    // ── L1: the key's placeholder, refused at a host no rule lets it go to ──
    const reg = await human.registerSecret({ path: env, sessionKey: SESSION });
    assert.match(String(reg.symbol), /^\$MDU:nomodel_Read\[/, JSON.stringify(reg));
    const field = `${reg.symbol}.STRIPE_KEY`;
    const res = await viaProxy(proxyPort, "http://api.stripe.com/v1/customers", field);
    assert.equal(res.status, 403, res.body);
    assert.deepEqual(forwarded, [], "nothing reached api.stripe.com");
    assert.ok(!res.body.includes(KEY), "the refusal carries no secret");

    // ── L2: the stored block names the rule that decided it ──────────────────
    let ruleId: string | undefined;
    let approvalId: string | undefined;
    for (let i = 0; i < 50 && !ruleId; i++) {
      // emission is best-effort and asynchronous
      const events = (await human.events(SESSION)) as unknown as { kind: string; action?: string; policy?: { ruleRef?: { id?: string }; approvalId?: string } }[];
      const blocked = events.find((e) => e.kind === "net_action" && e.action === "blocked");
      ruleId = blocked?.policy?.ruleRef?.id;
      approvalId = blocked?.policy?.approvalId;
      if (!ruleId) await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(ruleId, "egress:secret-unbound", "the block's net_action carries its rule");
    const pending = await admin.egressApprovals("pending");
    const row = pending.find((a) => a.destination === "api.stripe.com");
    assert.ok(row, `the block queued an ask for the person: ${JSON.stringify(pending)}`);
    assert.equal(approvalId, row!.id, "the block's net_action names the queued row");

    // ── L3: the session page says why, in the product's words ────────────────
    let step: Extract<StoryStep, { kind: "action" }> | undefined;
    let page: AgentPageVM | undefined;
    for (let i = 0; i < 50 && !step; i++) {
      const r = await fetch(`${base}/api/home/agent?session=${SESSION}`);
      assert.equal(r.status, 200);
      page = (await r.json()) as AgentPageVM;
      step = page.story.flatMap((t) => t.steps).find((s): s is Extract<StoryStep, { kind: "action" }> => s.kind === "action" && s.outcome === "blocked");
      if (!step) await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(step, "the blocked send is a step of the page");
    assert.match(step.sentence.map((p) => p.text).join(""), /^Mandu blocked a request to api\.stripe\.com that carried /);
    assert.equal(step.note, "The request never left this machine.");
    assert.equal(words(step.why!), "No rule lets this secret go to `api.stripe.com`. Mandu sends a secret only where a rule lets it go, or with your OK.");
    assert.equal(step.askId, row!.id, "the step says Mandu asked you, by the row it queued");
    const card = page!.secrets!.secrets.find((s) => s.what.some((p) => p.text === "STRIPE_KEY"));
    assert.ok(card, `Your secrets lists the key: ${JSON.stringify(page!.secrets)}`);
    const blockLine = card.lines.find((l) => /^Mandu blocked 1 attempt to send it to /.test(l.parts.map((p) => p.text).join("")));
    assert.ok(blockLine, `the key's card has its block: ${JSON.stringify(card.lines)}`);
    assert.match(words(blockLine.parts), /^Mandu blocked 1 attempt to send it to `api\.stripe\.com`, at \S+, and asked for your OK in Approvals\. The request never left this machine\.$/);
    assert.deepEqual(blockLine.parts.filter((p) => p.ask), [{ kind: "text", text: "Approvals", ask: row!.id }], "the card's block links the row the arbiter queued");
    // Its time opens that very step under What happened (§4.25b, "A time
    // opens its step"): the block the arbiter stored, by the page's own id.
    assert.deepEqual(blockLine.parts.filter((p) => p.kind === "time").map((p) => p.step), [step.id], "the card's block time opens the blocked step");
    const all = JSON.stringify(page);
    assert.ok(!all.includes("$MDU:") && !all.includes(KEY), "no token and no value on the product page");

    // ── L3b: the inspector's trace says the same, on the same block ──────────
    const ev = await fetch(`${base}/api/events?session=${SESSION}`);
    assert.equal(ev.status, 200);
    const { viewModel, counts } = (await ev.json()) as {
      counts?: { asks?: number; blocked?: number };
      viewModel: {
        dualLanes: { steps: { step: string; kind?: string; action?: string | null; askId?: string; why?: { kind: string; text: string }[] }[] };
        lineage: { flows: { root: string; edges: { kind: string; to: string; verdict?: string; askId?: string }[] }[] };
      };
    };
    const traced = viewModel.dualLanes.steps.filter((s) => s.why);
    assert.equal(traced.length, 1, "one step in the trace says why");
    assert.equal(traced[0]!.kind, "net_action");
    assert.equal(traced[0]!.action, "blocked");
    assert.deepEqual(traced[0]!.why, step.why, "the inspector's words are the session page's");
    assert.equal(traced[0]!.askId, row!.id, "…and its row");
    assert.deepEqual({ asks: counts?.asks, blocked: counts?.blocked }, { asks: 1, blocked: 1 }, "the header counts the block as asked");
    assert.ok(!JSON.stringify(traced[0]!.why).includes(KEY), "no value in the why");
    // The Secrets tab's row for the key names the same row on its block.
    const asked = viewModel.lineage.flows.flatMap((f) => f.edges.filter((e) => e.askId).map((e) => [f.root, e.kind, e.to, e.verdict, e.askId]));
    assert.deepEqual(asked, [[field, "egress", "snk:net:api.stripe.com", "blocked", row!.id]], "the lineage's block names the queued row");
  } finally {
    await dashboard.close();
    await proxy.close();
    human.close(); admin.close(); data.close(); netHuman.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("every rule the session page words stops in the law: a catalog id with a deny outcome, or an id an interceptor still emits", () => {
  const catalog = RULES as Record<string, { outcome: string }>;
  // the proxy's fail-closed legs that name their own ids: the net gate's and
  // the upload legs' (upload-gate.ts, unmapped-upload.ts)
  const netGate = ["net-gate.ts", "upload-gate.ts", "unmapped-upload.ts"]
    .map((f) => readFileSync(join(REPO, "interceptors", "anthropic-proxy", "src", f), "utf8")).join("\n");
  assert.ok(WHY_RULE_IDS.includes("egress:secret-unbound"));
  for (const id of WHY_RULE_IDS) {
    if (/^(egress|exec|fs|session):/.test(id)) {
      assert.ok(Object.prototype.hasOwnProperty.call(catalog, id), `${id} is in the arbiter's catalog`);
      assert.notEqual(catalog[id]!.outcome, "allow", `${id} stops something`);
    } else {
      assert.match(id, /^proxy:/, `${id}: an id of the proxies' own fail-closed legs`);
      assert.ok(Object.prototype.hasOwnProperty.call(catalog, id) || netGate.includes(`"${id}"`), `${id} is still emitted`);
    }
  }
});
