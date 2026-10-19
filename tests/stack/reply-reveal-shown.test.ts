/**
 * reply-reveal-shown — the reply filter putting a secret's real value on the
 * person's own screen is "shown to you", never a send off the machine
 * (dashboard.md §4.15, "Shown to you is not a send"), across the REAL
 * components.
 *
 *   L1  a `.env` registered as a secret (the launcher's call), its twin
 *       printed by a command run under the REAL reply-filter CLI, wired as
 *       the launcher wires it (the human-plane socket, the session's scope
 *       id): the person's terminal shows the original, the agent's world
 *       holds only placeholders;
 *   L2  the arbiter stored the filter's `desymbolize` events for the session
 *       (emitter `reply-filter`), and nothing else released the value;
 *   L3  the REAL dashboard over the arbiter's store (`/api/events`, the
 *       inspector's Secrets tab): each item the reply showed ends "shown",
 *       its edge into the person's terminal keeps the filter's "allowed",
 *       and the tally counts it under `shown`, never `allowed`, so the
 *       summary line says "shown to you in replies" and not "left with
 *       permission";
 *   L4  the product's session page (`/api/home/agent`) says the same of the
 *       same secret: the person saw it in the agent's reply, and Mandu sent
 *       its real value nowhere.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm test  (tests/)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { flowsSummaryLine, type SessionLineage } from "../../dashboard/src/view-model/lineage.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = "s-reply-reveal-shown";
const KEY = "sk_live_fake_REVEALSHOWN_7e21c4";
const RF_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "interceptors", "reply-filter");
const RUN_TS = join(RF_ROOT, "src", "run.ts");
const TSX_BIN = join(RF_ROOT, "node_modules", ".bin", "tsx");

async function runCapture(cmd: string, args: string[], env: NodeJS.ProcessEnv): Promise<string> {
  const child = spawn(cmd, args, { env, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (c: string) => (out += c));
  child.stderr.resume();
  const [code] = (await once(child, "close")) as [number | null];
  assert.equal(code, 0, `exit code of ${cmd}`);
  return out;
}

const sentence = (parts: { text: string }[]) => parts.map((p) => p.text).join("");

test("a secret the real reply filter showed on the person's screen is 'shown to you' on the real dashboard, never 'left with permission'", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-reveal-shown-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const envPath = join(home, "proj", ".env");
  writeFileSync(envPath, `STRIPE_KEY=${KEY}\nDEBUG=1\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath }), log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;

  try {
    // ── L1: the agent's world prints the twin; the person sees the original ──
    const reg = await data.registerSecret({ path: envPath, home });
    assert.ok(reg.twin, `.env gets a twin: ${reg.reason}`);
    assert.ok(!reg.twin!.includes(KEY), "the twin holds no secret byte");
    const twinPath = join(tmp, "twin-env");
    writeFileSync(twinPath, reg.twin!);
    const token = /\$MDU:nomodel_[A-Za-z]+\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin!)?.[0];
    assert.ok(token, `the twin carries the key's placeholder: ${reg.twin}`);
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      MANDU_ARBITER_SOCK: socketPath,
      MANDU_ARBITER_HUMAN_SOCK: humanSock,
      MANDU_SCOPE_ID: SESSION,
      MANDU_REPLY_FILTER_PTY: "0",
      ENV_TWIN: twinPath,
    };
    const screen = await runCapture(TSX_BIN, [RUN_TS, "--", "bash", "-c", 'cat "$ENV_TWIN"; echo done'], env);
    assert.ok(screen.includes(KEY), "the person's terminal shows the original");
    assert.ok(!screen.includes("$MDU:"), "and no placeholder");

    // ── L2: the arbiter stored the reply filter's reveal, and nothing else ──
    let kinds: string[] = [];
    for (let i = 0; i < 100; i++) {
      // emission is best-effort and asynchronous
      const events = (await human.events(SESSION)) as unknown as { kind: string; emitter?: string }[];
      kinds = events.map((e) => `${e.kind}:${e.emitter}`);
      if (kinds.includes("desymbolize:reply-filter")) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(kinds.includes("desymbolize:reply-filter"), `the filter's reveal is on record: ${kinds.join(", ")}`);
    assert.ok(!kinds.some((k) => k.startsWith("net_action") || k.startsWith("egress_")), "nothing sent the value anywhere");
    // Its AgentView form names the placeholders and nothing else: the
    // terminal output around them (`DEBUG=1`, `done`) is the human's, and
    // the dashboard's signed-out projection keeps every `symbolized`
    // (dashboard.md §6). What the person saw is its original.
    const reveals = ((await human.events(SESSION)) as unknown as Array<{ kind: string; emitter?: string; input?: { symbolized: string }; output?: { symbolized: string; original: string | null } }>)
      .filter((e) => e.kind === "desymbolize" && e.emitter === "reply-filter");
    for (const e of reveals) {
      for (const form of [e.input?.symbolized ?? "", e.output?.symbolized ?? ""]) {
        assert.match(form, /^\$MDU:\S+( \$MDU:\S+)*$/, `only placeholder names: ${JSON.stringify(form)}`);
        assert.ok(!form.includes("DEBUG=1") && !form.includes(KEY));
      }
    }
    assert.ok(reveals.some((e) => e.input?.symbolized.split(" ").includes(token!)), "the key's placeholder is named");
    assert.ok(reveals.some((e) => (e.output?.original ?? "").includes(KEY)), "the person's screen is the original");

    // ── L3: the inspector's payload: shown, never a release ────────────────
    const ev = await fetch(`${base}/api/events?session=${SESSION}`);
    assert.equal(ev.status, 200);
    const { viewModel } = (await ev.json()) as { viewModel: { lineage: SessionLineage } };
    const { flows, stats } = viewModel.lineage;
    const flow = flows.find((f) => f.nodes.some((n) => n.id === `sym:${token}`));
    assert.ok(flow, `the key's flow: ${JSON.stringify(flows.map((f) => f.root))}`);
    assert.equal(flow!.summary.terminal, "shown", "the reply's reveal alone is 'shown', not 'allowed'");
    assert.deepEqual(flow!.edges.filter((e) => e.kind === "revealed_reply").map((e) => [e.to, e.verdict]), [["snk:human", "allowed"]],
      "the evidence edge into the person's terminal keeps the filter's verdict");
    assert.ok(flows.every((f) => f.summary.terminal === "shown"), `every item only shown: ${JSON.stringify(flows.map((f) => f.summary.terminal))}`);
    assert.equal(stats.outcomes?.allowed, 0, "no release counted");
    assert.equal(stats.outcomes?.shown, flows.length, "each item counted as shown");
    assert.equal(stats.egressAllowed, 0);
    const line = flowsSummaryLine(stats);
    assert.match(line, / · 1 shown to you in replies$/, line);
    assert.doesNotMatch(line, /left/, line);

    // ── L4: the product's session page says the same of the same secret ───
    const r = await fetch(`${base}/api/home/agent?session=${SESSION}`);
    assert.equal(r.status, 200);
    const page = (await r.json()) as AgentPageVM;
    const lines = page.secrets.secrets.flatMap((s) => s.lines.map((l) => sentence(l.parts)));
    assert.ok(lines.some((l) => /^You saw its real value in the agent's repl(y|ies)\. The AI kept the placeholder\.$/.test(l)), lines.join(" | "));
    assert.ok(!lines.some((l) => /sent its real value/.test(l)), lines.join(" | "));
    assert.ok(!JSON.stringify(page).includes(KEY), "no value on the product page");
  } finally {
    await dashboard.close();
    data.close(); human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
