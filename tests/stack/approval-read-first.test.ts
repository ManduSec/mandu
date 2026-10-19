/**
 * approval-read-first.test — a waiting send of a secret the AI read as it
 * was before its label never says "the AI never read it", across the REAL
 * components (dashboard.md §4.34 "Read before it was marked"). Mandu-new.
 *
 * A real ArbiterServer (`secrets` axes). The session's events reach its real
 * event store through the real human-plane socket, as the model-API proxy
 * records them: a file's result delivered to the AI as it was, then the
 * file labelled a secret (the admin socket's labelling act) and registered,
 * then a later request carrying that same
 * result masked; and a second secret registered first, masked from its
 * first delivery. The real egress gate asks about each at a host no rule
 * binds it to. A real DashboardServer over a real ArbiterEventSource, with
 * the real admin-socket client behind its approval routes, serves them:
 *
 *   R1  /api/home: the card about the file read first says the AI read its
 *       real value before it was marked a secret, never "never read"; the
 *       card about the secret masked first keeps "the AI never read it";
 *   R2  /api/policy/panel: the inspector's row carries the raw delivery's
 *       time and the same words;
 *   R3  neither route carries either secret's value or a `$MDU` token on the
 *       product side;
 *   R4  a program asks to read each file (the guard's held open): the card
 *       about the file read first says the AI read the file as it was before
 *       it was marked a secret, never "has not seen the real file", and the
 *       inspector's row carries the raw delivery's time; the card about
 *       `.env` keeps its words.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer, type ApprovalsArbiter } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { PolicyPanelVM } from "../../dashboard/src/view-model/policy-panel.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const FILE_VALUE = "stg_readFirstStackCanary0000000000000001";
const KEY_VALUE = "sk_live_readFirstStackCanary000000000002";
const SESSION = "1791200000-654";

test("a send of, or a program's read of, a secret the AI read before its label never says the AI never read it or has not seen it; one masked first keeps the claim", { timeout: 60_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-approval-read-first-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj", "deploy"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(socketPath); await gate.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const human = new ArbiterClient(humanPath); await human.connect();
  const approvalsArbiter: ApprovalsArbiter = {
    egressApprovals: (status) => admin.egressApprovals(status),
    resolveEgressApproval: (approvalId, approve, scope) => admin.resolveEgressApproval(approvalId, approve, scope),
  };
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") },
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  try {
    const t0 = Date.now() - 60_000;
    const at = (s: number): string => new Date(t0 + s * 1000).toISOString();
    const text = (symbolized: string) => ({ symbolized, original: null, differs: false, symbols: [] });
    const emit = (e: Record<string, unknown>) =>
      human.emit({ sessionId: SESSION, view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy", ...e } as never);

    // The file's result reaches the AI as it was: nothing marked it yet.
    const conf = join(home, "proj", "deploy", "staging.conf");
    writeFileSync(conf, `token = ${FILE_VALUE}\n`);
    await emit({ id: "rf-call-1", ts: at(1), kind: "tllm_call", input: text("What is in deploy/staging.conf?") });
    await emit({ id: "rf-result-1", ts: at(2), kind: "tool_result", callId: "c-conf", output: text(`token = ${FILE_VALUE}\n`) });
    // Then the human marks it a secret (the labelling act, on the admin
    // socket), and the next request carries the same result masked.
    await admin.setPathLabel({ path: conf, confidentiality: "no-model", recursive: false });
    const confReg = await gate.registerSecret({ path: conf, sessionKey: SESSION });
    const confSym = String(confReg.symbol);
    assert.match(confSym, /^\$MDU:nomodel_/, JSON.stringify(confReg));
    const masked = (name: string, origin: string, value: string) => ({ symbolized: name, original: value, differs: true, symbols: [{ name, tool: "Read", field: null, origin, value, confidentiality: "no-model" }] });
    await emit({ id: "rf-call-2", ts: at(10), kind: "tllm_call", input: text("Mark it a secret.") });
    await emit({ id: "rf-result-1b", ts: at(11), kind: "tool_result", callId: "c-conf", output: masked(confSym, conf, `token = ${FILE_VALUE}\n`) });

    // A secret marked first: masked from its first delivery.
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    await emit({ id: "rf-call-3", ts: at(20), kind: "tllm_call", input: text("What is in .env?") });
    await emit({ id: "rf-result-2", ts: at(21), kind: "tool_result", callId: "c-env", output: masked(keySym!, env, `STRIPE_KEY=${KEY_VALUE}`) });

    // The real gate asks about each at a host no rule binds it to.
    const asked: Record<string, string> = {};
    for (const [sym, dest] of [[confSym, "paste.example"], [keySym!, "api.stripe.com"]] as const) {
      const d = await gate.desymbolizationDecision({ symbol: sym, boundary: "network", destination: dest, sessionKey: SESSION, scheme: "https" });
      assert.equal(d.allow, false, dest);
      assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, dest);
      asked[dest] = String((d as { approvalId?: string }).approvalId);
    }
    // A program asks to read each file (the guard's held open, on the human
    // socket, plan 13 D9): the file read first, and .env, masked from its
    // first delivery and labelled now.
    await admin.setPathLabel({ path: env, confidentiality: "no-model", recursive: false });
    const held: Record<string, string> = {};
    for (const [name, path] of [["conf", conf], ["env", env]] as const) {
      const open = await human.decideSecretOpen({ path, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: `mytool-rf-${name}`, session: SESSION, ask: "always" });
      assert.equal(open.verdict, "ask", `${name}: ${JSON.stringify(open)}`);
      held[name] = String(open.approvalId);
    }

    // R1: the product's cards.
    const vm = (await (await fetch(`${base}/api/home`)).json()) as HomeVM;
    const card = (dest: string) => vm.waiting.find((a) => a.id === asked[dest])!;
    assert.equal(card("paste.example").why, "Mandu masks it now, but the AI read its real value before it was marked a secret. Sending it would show the real secret to paste.example.");
    assert.equal(card("paste.example").aiNow, "The AI read the real value before it was marked a secret. Since then it gets the masked version, but Mandu does not mask what the AI wrote itself.");
    assert.equal(card("api.stripe.com").why, "STRIPE_KEY comes from ~/proj/.env. Mandu masked it, so the AI never read it. Sending it would show the real secret to api.stripe.com.");
    assert.equal(card("api.stripe.com").aiNow, "The AI has only the masked version. It has never read the real one.");

    // R2: the inspector's row, from the same session record.
    const panel = ((await (await fetch(`${base}/api/policy/panel`)).json()) as { panel: PolicyPanelVM }).panel;
    const row = (dest: string) => panel.queue.find((r) => r.id === asked[dest])!;
    assert.equal(row("paste.example").readFirst, at(2), "the raw delivery's time");
    assert.equal(row("paste.example").words.why, card("paste.example").why);
    assert.ok(!("readFirst" in row("api.stripe.com")));
    assert.match(row("api.stripe.com").words.why ?? "", /Mandu masked it, so the AI never read it\./);

    // R4: a program's read of the file read first never says the AI has
    // not seen the file; the read of .env keeps its words.
    const pending = await admin.egressApprovals("pending");
    assert.equal(pending.find((a) => a.id === held.conf)?.destination, conf, "the row's destination is the file");
    const prog = (name: string) => vm.waiting.find((a) => a.id === held[name])!;
    assert.equal(prog("conf").aiNow, "The AI read the file as it was before it was marked a secret, and its program /usr/bin/mytool has not read it. Since then the AI gets the masked version, but Mandu does not mask what the AI wrote itself.");
    assert.equal(prog("env").aiNow, "The AI has not seen the real file, and its program /usr/bin/mytool has not read it.");
    const progRow = (name: string) => panel.queue.find((r) => r.id === held[name])!;
    assert.equal(progRow("conf").readFirst, at(2), "the raw delivery's time, by the file");
    assert.equal(progRow("conf").words.aiNow, prog("conf").aiNow);
    assert.ok(!("readFirst" in progRow("env")));

    // R3: words and times, never a value; the product side never a token.
    const bodies = {
      home: await (await fetch(`${base}/api/home`)).text(),
      panel: await (await fetch(`${base}/api/policy/panel`)).text(),
    };
    for (const [route, body] of Object.entries(bodies)) {
      assert.ok(!body.includes(FILE_VALUE) && !body.includes(KEY_VALUE), `${route} carries no secret value`);
    }
    assert.doesNotMatch(bodies.home, /\$MDU/, "the product's home carries no token");
  } finally {
    await dashboard.close();
    gate.close(); admin.close(); human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
